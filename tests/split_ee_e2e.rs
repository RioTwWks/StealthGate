//! E2E: split ee + SGFB v2 encrypted relay + mock Telegram DC.

use stealth_gate::config::{decode_secret, Config, SecretMode, SplitMode};
use stealth_gate::mtproto_obfuscate::{self, ObfuscatedStream, HANDSHAKE_LEN};
use stealth_gate::sgfb_crypto::{derive_session_keys, EncryptedStream};
use stealth_gate::split::{
  encode_opening_frame, handle_back_connection, relay_from_front, ACK_OK,
};
use stealth_gate::state::AppState;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AUTH_TOKEN: &str = "split-ee-e2e-token-1234";
const EE_SECRET: &str = "ee0123456789abcdef0123456789abcdef";
const FAKE_DOMAIN: &str = "www.cloudflare.com";

fn ee_test_config(users_file: &str, dc_addr: &str, back_listen: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.tls.fake_domain = FAKE_DOMAIN.into();
  config.mtproto.secret = EE_SECRET.into();
  config.mtproto.backend = dc_addr.into();
  config.split.mode = SplitMode::Back;
  config.split.auth_token = Some(AUTH_TOKEN.into());
  config.split.encrypt_relay = true;
  let (host, port) = back_listen.split_once(':').expect("back addr");
  config.split.back_listen_host = Some(host.into());
  config.split.back_listen_port = port.parse().ok();
  config.split.front_allowlist = vec!["127.0.0.1".into()];
  config.drs.ee_relay = false;
  config.drs.jitter_ms = 0;
  config
}

fn ee_test_config_with_drs(users_file: &str, dc_addr: &str, back_listen: &str) -> Config {
  let mut config = ee_test_config(users_file, dc_addr, back_listen);
  config.drs.enabled = true;
  config.drs.ee_relay = true;
  config.drs.record_sizes = vec![512, 1024, 256];
  config.drs.jitter_ms = 5;
  config
}

fn front_test_config(users_file: &str, back_addr: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.tls.fake_domain = FAKE_DOMAIN.into();
  config.mtproto.secret = EE_SECRET.into();
  config.mtproto.backend = "149.154.167.99:443".into();
  config.split.mode = SplitMode::Front;
  config.split.auth_token = Some(AUTH_TOKEN.into());
  config.split.back_servers = vec![back_addr.into()];
  config.split.encrypt_relay = true;
  config.split.connect_timeout_secs = 5;
  config.drs.ee_relay = false;
  config
}

fn front_test_config_with_drs(users_file: &str, back_addr: &str) -> Config {
  let mut config = front_test_config(users_file, back_addr);
  config.drs.enabled = true;
  config.drs.ee_relay = true;
  config.drs.record_sizes = vec![512, 1024, 256];
  config.drs.jitter_ms = 5;
  config
}

fn wrap_tls_app_data(payload: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(5 + payload.len());
  out.push(0x17);
  out.extend_from_slice(&[0x03, 0x03]);
  out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  out.extend_from_slice(payload);
  out
}

async fn spawn_mock_dc() -> std::net::SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("dc bind");
  let addr = listener.local_addr().expect("dc addr");
  tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("dc accept");
    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await;
    let _ = stream.write_all(b"telegram-dc-pong").await;
    let _ = stream.shutdown().await;
  });
  addr
}

/// Mock DC: принимает relay init (64 байта), отвечает obfuscated2-кадром как настоящий DC.
async fn spawn_mock_dc_relay() -> std::net::SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("dc bind");
  let addr = listener.local_addr().expect("dc addr");
  tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("dc accept");
    let mut relay_hs = [0u8; HANDSHAKE_LEN];
    if stream.read_exact(&mut relay_hs).await.is_err() {
      return;
    }

    let mut reversed = [0u8; HANDSHAKE_LEN];
    for i in 0..HANDSHAKE_LEN {
      reversed[i] = relay_hs[HANDSHAKE_LEN - 1 - i];
    }
    let enc_key: [u8; 32] = relay_hs[8..40].try_into().expect("enc key");
    let enc_iv: [u8; 16] = relay_hs[40..56].try_into().expect("enc iv");
    let dec_key: [u8; 32] = reversed[8..40].try_into().expect("dec key");
    let dec_iv: [u8; 16] = reversed[40..56].try_into().expect("dec iv");

    use cipher::KeyIvInit;
    use ctr::Ctr128BE;
    use aes::Aes256;
    type AesCtr256 = Ctr128BE<Aes256>;

    let relay_keys = mtproto_obfuscate::RelayKeys {
      enc: AesCtr256::new_from_slices(&enc_key, &enc_iv).expect("relay enc"),
      dec: AesCtr256::new_from_slices(&dec_key, &dec_iv).expect("relay dec"),
    };

    let mut dc_stream = ObfuscatedStream::from_relay_keys(stream, relay_keys);
    let mut buf = [0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut dc_stream, &mut buf)
      .await
      .unwrap_or(0);
    if n == 0 {
      return;
    }

    let response = vec![0xABu8; 309];
    let _ = tokio::io::AsyncWriteExt::write_all(&mut dc_stream, &response).await;
    let _ = dc_stream.shutdown().await;
  });
  addr
}

#[tokio::test]
async fn split_ee_encrypted_back_to_mock_dc() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");

  let dc_addr = spawn_mock_dc().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let config = ee_test_config(&users_file, &dc_backend, &back_addr.to_string());
  config.save_to_file(&config_path).expect("save config");
  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let split_cfg = state.config.read().expect("read").split.clone();

  let back_task = tokio::spawn(async move {
    let (stream, peer) = back_listener.accept().await.expect("back accept");
    handle_back_connection(stream, peer.ip(), &state, &split_cfg)
      .await
      .expect("back session")
  });

  let frame = encode_opening_frame(
    AUTH_TOKEN,
    SecretMode::Classic,
    &dc_backend,
    b"classic-initial-bytes",
    true,
  )
  .expect("encode");

  let mut front = tokio::net::TcpStream::connect(back_addr)
    .await
    .expect("connect back");
  front.write_all(&frame).await.expect("write frame");
  front.flush().await.expect("flush frame");

  let mut ack = [0u8; 1];
  front.read_exact(&mut ack).await.expect("read ack");
  assert_eq!(ack[0], ACK_OK);

  let keys = derive_session_keys(AUTH_TOKEN, &frame);
  let mut encrypted = EncryptedStream::client_side(front, keys);
  encrypted
    .write_all(b"post-handshake-client-bytes")
    .await
    .expect("encrypted write");
  encrypted.flush().await.expect("encrypted flush");
  encrypted.shutdown().await.expect("encrypted shutdown");

  tokio::time::timeout(
    std::time::Duration::from_secs(5),
    back_task,
  )
  .await
  .expect("back timeout")
  .expect("back join");
}

#[tokio::test]
async fn split_ee_front_reaches_sgfb_ack() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let dc_addr = spawn_mock_dc().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let back_config_path = dir.path().join("back.toml");
  let back_config = ee_test_config(&users_file, &dc_backend, &back_addr.to_string());
  back_config
    .save_to_file(&back_config_path)
    .expect("save back");
  let back_state = AppState::new(back_config, back_config_path.to_string_lossy()).expect("back state");
  let back_split = back_state.config.read().expect("read").split.clone();

  tokio::spawn(async move {
    loop {
      let (stream, peer) = back_listener.accept().await.expect("back accept");
      let state = back_state.clone();
      let split_cfg = back_split.clone();
      tokio::spawn(async move {
        let _ = handle_back_connection(stream, peer.ip(), &state, &split_cfg).await;
      });
    }
  });
  // Дать accept-loop стартовать до connect с front.
  tokio::task::yield_now().await;

  let front_config_path = dir.path().join("front.toml");
  let front_config = front_test_config(&users_file, &back_addr.to_string());
  front_config
    .save_to_file(&front_config_path)
    .expect("save front");
  let front_state = AppState::new(front_config, front_config_path.to_string_lossy()).expect("front state");
  let front_split = front_state.config.read().expect("read").split.clone();

  let secret_bytes = decode_secret(EE_SECRET).expect("secret");
  let client_hello = stealth_gate::faketls::build_signed_client_hello(FAKE_DOMAIN, &secret_bytes);
  let obf2 =
    mtproto_obfuscate::generate_test_handshake(&secret_bytes, 2, [0xdd, 0xdd, 0xdd, 0xdd]);

  let (mut tg_client, server_end) = tokio::io::duplex(65536);

  let client_task = tokio::spawn(async move {
    let mut server_hello_buf = vec![0u8; 8192];
    let n = tg_client.read(&mut server_hello_buf).await.expect("read sh");
    assert!(n > 100, "ожидался Fake TLS ServerHello");
    tg_client
      .write_all(&wrap_tls_app_data(&obf2))
      .await
      .expect("write obf2");
  });

  let relay_result = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    relay_from_front(
      server_end,
      &client_hello,
      &dc_backend,
      SecretMode::Ee,
      None,
      &front_split,
      &front_state,
    ),
  )
  .await;

  client_task.await.expect("client join");

  match relay_result {
    Ok(Ok(())) => {}
    Ok(Err(err)) => {
      let msg = err.to_string();
      assert!(
        msg.contains("copy_bidirectional") || msg.contains("broken pipe"),
        "unexpected relay error: {msg}"
      );
    }
    Err(_) => panic!("relay_from_front timeout"),
  }
}

/// Имитирует acceptor peek=1334 при needed≈1728: хвост ClientHello приходит после ServerHello.
#[tokio::test]
async fn split_ee_partial_client_hello_handshake() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let dc_addr = spawn_mock_dc().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let back_config_path = dir.path().join("back.toml");
  let back_config = ee_test_config(&users_file, &dc_backend, &back_addr.to_string());
  back_config
    .save_to_file(&back_config_path)
    .expect("save back");
  let back_state = AppState::new(back_config, back_config_path.to_string_lossy()).expect("back state");
  let back_split = back_state.config.read().expect("read").split.clone();

  tokio::spawn(async move {
    loop {
      let (stream, peer) = back_listener.accept().await.expect("back accept");
      let state = back_state.clone();
      let split_cfg = back_split.clone();
      tokio::spawn(async move {
        let _ = handle_back_connection(stream, peer.ip(), &state, &split_cfg).await;
      });
    }
  });
  tokio::task::yield_now().await;

  let front_config_path = dir.path().join("front.toml");
  let front_config = front_test_config(&users_file, &back_addr.to_string());
  front_config
    .save_to_file(&front_config_path)
    .expect("save front");
  let front_state = AppState::new(front_config, front_config_path.to_string_lossy()).expect("front state");
  let front_split = front_state.config.read().expect("read").split.clone();

  let secret_bytes = decode_secret(EE_SECRET).expect("secret");
  let full_client_hello =
    stealth_gate::faketls::build_signed_client_hello_min_len(FAKE_DOMAIN, &secret_bytes, 1760);
  let needed = stealth_gate::tls::tls_record_total_len(&full_client_hello).expect("record len");
  assert!(
    full_client_hello.len() > 1334 && needed > 1334,
    "test needs a ClientHello larger than 1334 bytes"
  );
  let partial_client_hello = full_client_hello[..1334].to_vec();
  let client_hello_tail = full_client_hello[1334..].to_vec();
  let obf2 =
    mtproto_obfuscate::generate_test_handshake(&secret_bytes, 2, [0xdd, 0xdd, 0xdd, 0xdd]);

  let (mut tg_client, server_end) = tokio::io::duplex(65536);

  let client_task = tokio::spawn(async move {
    let mut server_hello_buf = vec![0u8; 8192];
    let n = tg_client.read(&mut server_hello_buf).await.expect("read sh");
    assert!(n > 100, "ожидался Fake TLS ServerHello");
    tg_client
      .write_all(&client_hello_tail)
      .await
      .expect("write ch tail");
    tg_client
      .write_all(&wrap_tls_app_data(&obf2))
      .await
      .expect("write obf2");
  });

  let relay_result = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    relay_from_front(
      server_end,
      &partial_client_hello,
      &dc_backend,
      SecretMode::Ee,
      None,
      &front_split,
      &front_state,
    ),
  )
  .await;

  client_task.await.expect("client join");

  match relay_result {
    Ok(Ok(())) => {}
    Ok(Err(err)) => {
      let msg = err.to_string();
      assert!(
        msg.contains("copy_bidirectional") || msg.contains("broken pipe"),
        "unexpected relay error: {msg}"
      );
    }
    Err(_) => panic!("relay_from_front timeout on partial ClientHello"),
  }
}

/// Клиент не досылает хвост ClientHello, сразу шлёт obfuscated2 как TLS App Data (0x17).
#[tokio::test]
async fn split_ee_partial_client_hello_obf2_without_tail() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let dc_addr = spawn_mock_dc().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let back_config_path = dir.path().join("back.toml");
  let back_config = ee_test_config(&users_file, &dc_backend, &back_addr.to_string());
  back_config
    .save_to_file(&back_config_path)
    .expect("save back");
  let back_state = AppState::new(back_config, back_config_path.to_string_lossy()).expect("back state");
  let back_split = back_state.config.read().expect("read").split.clone();

  tokio::spawn(async move {
    loop {
      let (stream, peer) = back_listener.accept().await.expect("back accept");
      let state = back_state.clone();
      let split_cfg = back_split.clone();
      tokio::spawn(async move {
        let _ = handle_back_connection(stream, peer.ip(), &state, &split_cfg).await;
      });
    }
  });
  tokio::task::yield_now().await;

  let front_config_path = dir.path().join("front.toml");
  let front_config = front_test_config(&users_file, &back_addr.to_string());
  front_config
    .save_to_file(&front_config_path)
    .expect("save front");
  let front_state = AppState::new(front_config, front_config_path.to_string_lossy()).expect("front state");
  let front_split = front_state.config.read().expect("read").split.clone();

  let secret_bytes = decode_secret(EE_SECRET).expect("secret");
  let full_client_hello =
    stealth_gate::faketls::build_signed_client_hello_min_len(FAKE_DOMAIN, &secret_bytes, 1760);
  let partial_client_hello = full_client_hello[..1334].to_vec();
  let obf2 =
    mtproto_obfuscate::generate_test_handshake(&secret_bytes, 2, [0xdd, 0xdd, 0xdd, 0xdd]);

  let (mut tg_client, server_end) = tokio::io::duplex(65536);

  let client_task = tokio::spawn(async move {
    let mut server_hello_buf = vec![0u8; 8192];
    let n = tg_client.read(&mut server_hello_buf).await.expect("read sh");
    assert!(n > 100, "ожидался Fake TLS ServerHello");
    tg_client
      .write_all(&wrap_tls_app_data(&obf2))
      .await
      .expect("write obf2 without ch tail");
  });

  let relay_result = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    relay_from_front(
      server_end,
      &partial_client_hello,
      &dc_backend,
      SecretMode::Ee,
      None,
      &front_split,
      &front_state,
    ),
  )
  .await;

  client_task.await.expect("client join");

  match relay_result {
    Ok(Ok(())) => {}
    Ok(Err(err)) => {
      let msg = err.to_string();
      assert!(
        msg.contains("copy_bidirectional") || msg.contains("broken pipe"),
        "unexpected relay error: {msg}"
      );
    }
    Err(_) => panic!("relay_from_front timeout on obf2 without ch tail"),
  }
}

/// DC отвечает 309 байт через relay obfuscation — клиент должен получить ответ (b2c>0).
#[tokio::test]
async fn split_ee_dc_response_reaches_client() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let dc_addr = spawn_mock_dc_relay().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let back_config_path = dir.path().join("back.toml");
  let back_config = ee_test_config(&users_file, &dc_backend, &back_addr.to_string());
  back_config
    .save_to_file(&back_config_path)
    .expect("save back");
  let back_state = AppState::new(back_config, back_config_path.to_string_lossy()).expect("back state");
  let back_split = back_state.config.read().expect("read").split.clone();

  tokio::spawn(async move {
    loop {
      let (stream, peer) = back_listener.accept().await.expect("back accept");
      let state = back_state.clone();
      let split_cfg = back_split.clone();
      tokio::spawn(async move {
        let _ = handle_back_connection(stream, peer.ip(), &state, &split_cfg).await;
      });
    }
  });
  tokio::task::yield_now().await;

  let front_config_path = dir.path().join("front.toml");
  let front_config = front_test_config(&users_file, &back_addr.to_string());
  front_config
    .save_to_file(&front_config_path)
    .expect("save front");
  let front_state = AppState::new(front_config, front_config_path.to_string_lossy()).expect("front state");
  let front_split = front_state.config.read().expect("read").split.clone();

  let secret_bytes = decode_secret(EE_SECRET).expect("secret");
  let full_client_hello =
    stealth_gate::faketls::build_signed_client_hello_min_len(FAKE_DOMAIN, &secret_bytes, 1760);
  let partial_client_hello = full_client_hello[..1334].to_vec();
  let obf2 =
    mtproto_obfuscate::generate_test_handshake(&secret_bytes, 2, [0xdd, 0xdd, 0xdd, 0xdd]);
  let post_obf2 = vec![0xCDu8; 331];
  let mut obf2_payload = obf2.to_vec();
  obf2_payload.extend_from_slice(&post_obf2);

  let (mut tg_client, server_end) = tokio::io::duplex(65536);
  let response_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

  let response_bytes_task = response_bytes.clone();
  let client_task = tokio::spawn(async move {
    let mut server_hello_buf = vec![0u8; 8192];
    let n = tg_client.read(&mut server_hello_buf).await.expect("read sh");
    assert!(n > 100, "ожидался Fake TLS ServerHello");
    tg_client
      .write_all(&wrap_tls_app_data(&obf2_payload))
      .await
      .expect("write obf2");

    let mut resp = vec![0u8; 8192];
    let read_n = tokio::time::timeout(std::time::Duration::from_secs(5), tg_client.read(&mut resp))
      .await
      .expect("timeout waiting DC response")
      .expect("read response");
    response_bytes_task.store(read_n, std::sync::atomic::Ordering::Relaxed);
    let _ = tg_client.shutdown().await;
  });

  let relay_handle = tokio::spawn(async move {
    relay_from_front(
      server_end,
      &partial_client_hello,
      &dc_backend,
      SecretMode::Ee,
      None,
      &front_split,
      &front_state,
    )
    .await
  });

  client_task.await.expect("client join");

  assert!(
    response_bytes.load(std::sync::atomic::Ordering::Relaxed) > 0,
    "клиент не получил ответ от DC через relay"
  );

  match tokio::time::timeout(std::time::Duration::from_secs(3), relay_handle).await {
    Ok(Ok(Ok(()))) => {}
    Ok(Ok(Err(err))) => {
      let msg = err.to_string();
      assert!(
        msg.contains("copy_bidirectional") || msg.contains("broken pipe") || msg.contains("UnexpectedEof"),
        "unexpected relay error: {msg}"
      );
    }
    _ => {
      // после shutdown клиента relay может ещё завершаться — главное, что ответ дошёл
    }
  }
}

/// Как split_ee_dc_response_reaches_client, но с production-like DRS (ee_relay + jitter).
#[tokio::test]
async fn split_ee_dc_response_with_drs_reaches_client() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let dc_addr = spawn_mock_dc_relay().await;
  let dc_backend = format!("{dc_addr}");

  let back_listener = TcpListener::bind("127.0.0.1:0").await.expect("back bind");
  let back_addr = back_listener.local_addr().expect("back addr");

  let back_config_path = dir.path().join("back.toml");
  let back_config = ee_test_config_with_drs(&users_file, &dc_backend, &back_addr.to_string());
  back_config
    .save_to_file(&back_config_path)
    .expect("save back");
  let back_state = AppState::new(back_config, back_config_path.to_string_lossy()).expect("back state");
  let back_split = back_state.config.read().expect("read").split.clone();

  tokio::spawn(async move {
    loop {
      let (stream, peer) = back_listener.accept().await.expect("back accept");
      let state = back_state.clone();
      let split_cfg = back_split.clone();
      tokio::spawn(async move {
        let _ = handle_back_connection(stream, peer.ip(), &state, &split_cfg).await;
      });
    }
  });
  tokio::task::yield_now().await;

  let front_config_path = dir.path().join("front.toml");
  let front_config = front_test_config_with_drs(&users_file, &back_addr.to_string());
  front_config
    .save_to_file(&front_config_path)
    .expect("save front");
  let front_state = AppState::new(front_config, front_config_path.to_string_lossy()).expect("front state");
  let front_split = front_state.config.read().expect("read").split.clone();

  let secret_bytes = decode_secret(EE_SECRET).expect("secret");
  let full_client_hello =
    stealth_gate::faketls::build_signed_client_hello_min_len(FAKE_DOMAIN, &secret_bytes, 1760);
  let partial_client_hello = full_client_hello[..1334].to_vec();
  let obf2 =
    mtproto_obfuscate::generate_test_handshake(&secret_bytes, 2, [0xdd, 0xdd, 0xdd, 0xdd]);
  let post_obf2 = vec![0xCDu8; 331];
  let mut obf2_payload = obf2.to_vec();
  obf2_payload.extend_from_slice(&post_obf2);

  let (mut tg_client, server_end) = tokio::io::duplex(65536);
  let response_bytes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

  let response_bytes_task = response_bytes.clone();
  let client_task = tokio::spawn(async move {
    let mut server_hello_buf = vec![0u8; 8192];
    let n = tg_client.read(&mut server_hello_buf).await.expect("read sh");
    assert!(n > 100, "ожидался Fake TLS ServerHello");
    tg_client
      .write_all(&wrap_tls_app_data(&obf2_payload))
      .await
      .expect("write obf2");

    let mut resp = vec![0u8; 8192];
    let read_n = tokio::time::timeout(std::time::Duration::from_secs(5), tg_client.read(&mut resp))
      .await
      .expect("timeout waiting DC response")
      .expect("read response");
    response_bytes_task.store(read_n, std::sync::atomic::Ordering::Relaxed);
    let _ = tg_client.shutdown().await;
  });

  let relay_handle = tokio::spawn(async move {
    relay_from_front(
      server_end,
      &partial_client_hello,
      &dc_backend,
      SecretMode::Ee,
      None,
      &front_split,
      &front_state,
    )
    .await
  });

  client_task.await.expect("client join");

  assert!(
    response_bytes.load(std::sync::atomic::Ordering::Relaxed) > 0,
    "клиент не получил ответ от DC через relay с DRS"
  );

  let _ = tokio::time::timeout(std::time::Duration::from_secs(3), relay_handle).await;
}
