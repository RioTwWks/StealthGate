//! Front/Back split — разделение edge (front) и Telegram relay (back).

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{SecretMode, SplitConfig, SplitMode};
use crate::error::{Result, StealthGateError};
use crate::proxy;
use crate::state::AppState;

const MAGIC: &[u8; 4] = b"SGFB";
const VERSION: u8 = 1;
const MAX_BACKEND_LEN: usize = 256;
const MAX_INITIAL_LEN: usize = 65_536;
const ACK_OK: u8 = 0;
const ACK_ERR: u8 = 1;

/// Метаданные opening-кадра Front → Back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitOpeningFrame {
  pub secret_mode: SecretMode,
  pub backend: String,
  pub initial_data: Vec<u8>,
}

/// SHA-256 токена авторизации front/back.
pub fn hash_auth_token(token: &str) -> [u8; 32] {
  let digest = Sha256::digest(token.as_bytes());
  digest.into()
}

/// Кодирует opening-кадр SGFB.
pub fn encode_opening_frame(
  token: &str,
  secret_mode: SecretMode,
  backend: &str,
  initial_data: &[u8],
) -> Result<Vec<u8>> {
  if backend.len() > MAX_BACKEND_LEN {
    return Err(StealthGateError::Config(format!(
      "split backend слишком длинный (>{MAX_BACKEND_LEN})"
    )));
  }
  if initial_data.len() > MAX_INITIAL_LEN {
    return Err(StealthGateError::Config(format!(
      "split initial_data слишком большой (>{MAX_INITIAL_LEN})"
    )));
  }

  let mut out = Vec::with_capacity(44 + backend.len() + initial_data.len());
  out.extend_from_slice(MAGIC);
  out.push(VERSION);
  out.extend_from_slice(&hash_auth_token(token));
  out.push(secret_mode_to_byte(secret_mode));
  out.extend_from_slice(&(backend.len() as u16).to_be_bytes());
  out.extend_from_slice(backend.as_bytes());
  out.extend_from_slice(&(initial_data.len() as u32).to_be_bytes());
  out.extend_from_slice(initial_data);
  Ok(out)
}

/// Декодирует opening-кадр SGFB.
pub fn decode_opening_frame(data: &[u8]) -> Result<SplitOpeningFrame> {
  if data.len() < 44 {
    return Err(StealthGateError::Proxy("короткий split opening-кадр".into()));
  }
  if &data[0..4] != MAGIC {
    return Err(StealthGateError::Proxy("неверный split magic".into()));
  }
  if data[4] != VERSION {
    return Err(StealthGateError::Proxy(format!(
      "неподдерживаемая split version: {}",
      data[4]
    )));
  }

  let secret_mode = byte_to_secret_mode(data[37])?;
  let backend_len = u16::from_be_bytes([data[38], data[39]]) as usize;
  let backend_start: usize = 40;
  let backend_end = backend_start
    .checked_add(backend_len)
    .ok_or_else(|| StealthGateError::Proxy("overflow backend_len".into()))?;
  if backend_end + 4 > data.len() {
    return Err(StealthGateError::Proxy("обрезанный split opening-кадр".into()));
  }

  let backend = std::str::from_utf8(&data[backend_start..backend_end])
    .map_err(|err| StealthGateError::Proxy(format!("backend utf8: {err}")))?
    .to_string();

  let initial_len = u32::from_be_bytes([
    data[backend_end],
    data[backend_end + 1],
    data[backend_end + 2],
    data[backend_end + 3],
  ]) as usize;
  let initial_start = backend_end + 4;
  let initial_end = initial_start
    .checked_add(initial_len)
    .ok_or_else(|| StealthGateError::Proxy("overflow initial_len".into()))?;
  if initial_end != data.len() {
    return Err(StealthGateError::Proxy("неверная длина initial_data".into()));
  }

  Ok(SplitOpeningFrame {
    secret_mode,
    backend,
    initial_data: data[initial_start..initial_end].to_vec(),
  })
}

fn secret_mode_to_byte(mode: SecretMode) -> u8 {
  match mode {
    SecretMode::Classic => 0,
    SecretMode::Dd => 1,
    SecretMode::Ee => 2,
  }
}

fn byte_to_secret_mode(value: u8) -> Result<SecretMode> {
  match value {
    0 => Ok(SecretMode::Classic),
    1 => Ok(SecretMode::Dd),
    2 => Ok(SecretMode::Ee),
    other => Err(StealthGateError::Proxy(format!(
      "неизвестный secret_mode: {other}"
    ))),
  }
}

/// Front: проксирует MTProto-сессию на back-узел.
pub async fn relay_from_front<C>(
  client: C,
  initial_data: &[u8],
  preferred_backend: &str,
  secret_mode: SecretMode,
  split: &SplitConfig,
  state: &AppState,
) -> Result<()>
where
  C: AsyncRead + AsyncWrite + Unpin,
{
  let token = split
    .auth_token
    .as_deref()
    .ok_or_else(|| StealthGateError::Config("split.auth_token не задан".into()))?;

  if split.back_servers.is_empty() {
    return Err(StealthGateError::Config(
      "split.back_servers пуст для front-режима".into(),
    ));
  }

  let frame = encode_opening_frame(token, secret_mode, preferred_backend, initial_data)?;
  let timeout = Duration::from_secs(split.connect_timeout_secs);
  let mut last_error = None;

  for back_addr in &split.back_servers {
    match tokio::time::timeout(timeout, TcpStream::connect(back_addr)).await {
      Ok(Ok(mut back_stream)) => {
        if let Err(err) = back_stream.write_all(&frame).await {
          last_error = Some(StealthGateError::Proxy(format!(
            "split write к {back_addr}: {err}"
          )));
          continue;
        }

        let mut ack = [0u8; 1];
        match tokio::time::timeout(timeout, back_stream.read_exact(&mut ack)).await {
          Ok(Ok(_)) if ack[0] == ACK_OK => {
            state.stats.split_relayed.fetch_add(1, Ordering::Relaxed);
            let (c2b, b2c) = proxy::copy_bidirectional(client, back_stream).await?;
            state
              .stats
              .bytes_to_backend
              .fetch_add(c2b + initial_data.len() as u64, Ordering::Relaxed);
            state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);
            tracing::debug!(
              back = %back_addr,
              c2b,
              b2c,
              "split front-сессия завершена"
            );
            return Ok(());
          }
          Ok(Ok(_)) => {
            let mut err_buf = vec![0u8; 512];
            let n = back_stream.read(&mut err_buf).await.unwrap_or(0);
            let msg = String::from_utf8_lossy(&err_buf[..n]);
            last_error = Some(StealthGateError::Proxy(format!(
              "split back {back_addr} отклонил: {msg}"
            )));
          }
          Ok(Err(err)) => {
            last_error = Some(StealthGateError::Proxy(format!(
              "split ack read {back_addr}: {err}"
            )));
          }
          Err(_) => {
            last_error = Some(StealthGateError::Proxy(format!(
              "split ack timeout {back_addr}"
            )));
          }
        }
      }
      Ok(Err(err)) => {
        tracing::warn!(back = %back_addr, error = %err, "back недоступен");
        last_error = Some(StealthGateError::Proxy(format!(
          "split connect {back_addr}: {err}"
        )));
      }
      Err(_) => {
        last_error = Some(StealthGateError::Proxy(format!(
          "split connect timeout {back_addr}"
        )));
      }
    }
  }

  Err(last_error.unwrap_or_else(|| {
    StealthGateError::Proxy("нет доступных split back_servers".into())
  }))
}

async fn read_opening_frame(
  stream: &mut (impl AsyncRead + Unpin),
  max_bytes: usize,
) -> Result<Vec<u8>> {
  let mut header = vec![0u8; 40];
  stream
    .read_exact(&mut header)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split opening header: {err}")))?;

  if header[0..4] != *MAGIC {
    return Err(StealthGateError::Proxy("неверный split magic".into()));
  }

  let backend_len = u16::from_be_bytes([header[38], header[39]]) as usize;
  let mut backend = vec![0u8; backend_len];
  if backend_len > 0 {
    stream
      .read_exact(&mut backend)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("split backend: {err}")))?;
  }
  header.extend_from_slice(&backend);

  let mut initial_len_buf = [0u8; 4];
  stream
    .read_exact(&mut initial_len_buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split initial_len: {err}")))?;
  header.extend_from_slice(&initial_len_buf);

  let initial_len = u32::from_be_bytes(initial_len_buf) as usize;
  if initial_len > max_bytes {
    return Err(StealthGateError::Proxy(format!(
      "split initial_data > {max_bytes}"
    )));
  }

  if initial_len > 0 {
    let mut initial = vec![0u8; initial_len];
    stream
      .read_exact(&mut initial)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("split initial payload: {err}")))?;
    header.extend_from_slice(&initial);
  }

  Ok(header)
}

async fn send_ack(stream: &mut (impl AsyncWrite + Unpin), ok: bool, message: Option<&str>) -> Result<()> {
  if ok {
    stream
      .write_all(&[ACK_OK])
      .await
      .map_err(|err| StealthGateError::Proxy(format!("split ack write: {err}")))?;
    return Ok(());
  }

  let msg = message.unwrap_or("ошибка split relay");
  let msg_bytes = msg.as_bytes();
  if msg_bytes.len() > u16::MAX as usize {
    return Err(StealthGateError::Proxy("слишком длинное split сообщение".into()));
  }
  let mut buf = Vec::with_capacity(3 + msg_bytes.len());
  buf.push(ACK_ERR);
  buf.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
  buf.extend_from_slice(msg_bytes);
  stream
    .write_all(&buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split err write: {err}")))?;
  Ok(())
}

fn peer_allowed(peer_ip: IpAddr, allowlist: &[String]) -> bool {
  if allowlist.is_empty() {
    return true;
  }
  allowlist.iter().any(|entry| {
    entry
      .parse::<IpAddr>()
      .is_ok_and(|allowed| allowed == peer_ip)
  })
}

/// Back: обрабатывает соединение от front-узла.
pub async fn handle_back_connection<S>(
  mut front_stream: S,
  peer_ip: IpAddr,
  state: &AppState,
  split: &SplitConfig,
) -> Result<()>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  if !peer_allowed(peer_ip, &split.front_allowlist) {
    state.stats.split_auth_failed.fetch_add(1, Ordering::Relaxed);
    send_ack(&mut front_stream, false, Some("front IP не в allowlist"))
      .await?;
    return Err(StealthGateError::Proxy(format!(
      "split front IP {peer_ip} не разрешён"
    )));
  }

  let token = split
    .auth_token
    .as_deref()
    .ok_or_else(|| StealthGateError::Config("split.auth_token не задан".into()))?;

  let raw = read_opening_frame(&mut front_stream, MAX_INITIAL_LEN).await?;
  let frame = decode_opening_frame(&raw)?;

  if frame.initial_data.len() > MAX_INITIAL_LEN {
    state.stats.split_auth_failed.fetch_add(1, Ordering::Relaxed);
    send_ack(&mut front_stream, false, Some("initial_data слишком большой")).await?;
    return Err(StealthGateError::Proxy("initial_data слишком большой".into()));
  }

  let expected = hash_auth_token(token);
  if raw[5..37] != expected {
    state.stats.split_auth_failed.fetch_add(1, Ordering::Relaxed);
    send_ack(&mut front_stream, false, Some("неверный auth_token")).await?;
    return Err(StealthGateError::Proxy("неверный split auth_token".into()));
  }

  let (fragmentation, drs, dd, webhooks, network) = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    (
      config.fragmentation.clone(),
      config.drs.clone(),
      config.dd.clone(),
      config.webhooks.clone(),
      config.network.clone(),
    )
  };

  let pool = state
    .backend_pool
    .read()
    .map_err(|_| StealthGateError::Config("блокировка backend_pool poisoned".into()))?
    .clone();

  let (mut upstream, connected_backend) = match pool
    .connect(&network, Some(&frame.backend), &state.stats)
    .await
  {
    Ok(value) => value,
    Err(err) => {
      send_ack(&mut front_stream, false, Some(&err.to_string())).await?;
      return Err(err);
    }
  };

  if connected_backend != frame.backend {
    crate::webhooks::dispatch(
      &webhooks,
      crate::webhooks::WebhookEvent::BackendFailover,
      Some(serde_json::json!({
        "preferred": frame.backend,
        "connected": connected_backend,
      })),
    );
  }

  if let Err(err) = proxy::write_initial_to_backend(
    &mut upstream,
    &frame.initial_data,
    frame.secret_mode,
    &fragmentation,
    &drs,
    &dd,
    &state.stats,
  )
  .await
  {
    send_ack(&mut front_stream, false, Some(&err.to_string())).await?;
    return Err(err);
  }

  send_ack(&mut front_stream, true, None).await?;
  state.stats.split_relayed.fetch_add(1, Ordering::Relaxed);
  state
    .stats
    .bytes_to_backend
    .fetch_add(frame.initial_data.len() as u64, Ordering::Relaxed);

  let (c2b, b2c) = proxy::copy_bidirectional(front_stream, upstream).await?;
  state.stats.bytes_to_backend.fetch_add(c2b, Ordering::Relaxed);
  state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);

  tracing::debug!(
    backend = %connected_backend,
    peer = %peer_ip,
    c2b,
    b2c,
    "split back-сессия завершена"
  );

  Ok(())
}

/// Запускает internal listener для back-режима.
pub async fn run_back_listener(state: Arc<AppState>) -> Result<()> {
  let (addr, split_cfg) = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    if config.split.mode != SplitMode::Back {
      return Ok(());
    }
    (
      config.split.back_socket_addr()?,
      config.split.clone(),
    )
  };

  let listener = TcpListener::bind(addr)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("bind split back {addr}: {err}")))?;

  tracing::info!(%addr, "split back listener для front-узлов");

  loop {
    tokio::select! {
      accept = listener.accept() => {
        let (stream, peer) = accept
          .map_err(|err| StealthGateError::Proxy(format!("split accept: {err}")))?;
        let peer_ip = peer.ip();
        let state = Arc::clone(&state);
        let split_cfg = split_cfg.clone();
        tokio::spawn(async move {
          if let Err(err) = handle_back_connection(stream, peer_ip, &state, &split_cfg).await {
            tracing::warn!(%peer_ip, error = %err, "ошибка split back-соединения");
          }
        });
      }
      _ = crate::acceptor::shutdown_signal() => {
        tracing::info!("split back listener останавливается");
        break;
      }
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn opening_frame_roundtrip() {
    let token = "shared-secret-token-1234";
    let backend = "149.154.167.99:443";
    let initial = b"hello-mtproto";
    let encoded =
      encode_opening_frame(token, SecretMode::Ee, backend, initial).expect("encode");
    let decoded = decode_opening_frame(&encoded).expect("decode");
    assert_eq!(decoded.secret_mode, SecretMode::Ee);
    assert_eq!(decoded.backend, backend);
    assert_eq!(decoded.initial_data, initial);
  }

  #[test]
  fn rejects_bad_magic() {
    let mut data = encode_opening_frame("token", SecretMode::Classic, "1.1.1.1:443", b"x")
      .expect("encode");
    data[0] = b'X';
    assert!(decode_opening_frame(&data).is_err());
  }

  #[test]
  fn peer_allowlist_matches() {
    assert!(peer_allowed(
      "10.0.0.1".parse().expect("ip"),
      &["10.0.0.1".into()]
    ));
    assert!(!peer_allowed(
      "10.0.0.2".parse().expect("ip"),
      &["10.0.0.1".into()]
    ));
    assert!(peer_allowed("10.0.0.9".parse().expect("ip"), &[]));
  }

  #[tokio::test]
  async fn tcp_opening_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token = "integration-split-token-123";

    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.expect("accept");
      let raw = read_opening_frame(&mut stream, MAX_INITIAL_LEN)
        .await
        .expect("read frame");
      assert_eq!(&raw[5..37], hash_auth_token(token));
      send_ack(&mut stream, true, None).await.expect("ack");
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    let frame = encode_opening_frame(token, SecretMode::Ee, "149.154.167.99:443", b"payload")
      .expect("encode");
    client.write_all(&frame).await.expect("write");
    let mut ack = [0u8; 1];
    client.read_exact(&mut ack).await.expect("read ack");
    assert_eq!(ack[0], ACK_OK);

    server.await.expect("join");
  }
}
