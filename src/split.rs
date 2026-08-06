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
use crate::faketls::FakeTlsStream;
use crate::io_util::PrefixedStream;
use crate::mtproto_obfuscate::{self, ObfuscatedStream};
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

/// Дочитывает TLS ClientHello, если первый read вернул неполную запись.
async fn complete_client_hello_buffer<C: AsyncRead + Unpin>(
  client: &mut C,
  initial: &[u8],
) -> Result<Vec<u8>> {
  let mut buf = initial.to_vec();
  let Some(needed) = crate::tls::tls_record_total_len(&buf) else {
    return Ok(buf);
  };
  if buf.len() >= needed {
    return Ok(buf);
  }

  let deadline = Duration::from_millis(2000);
  let started = tokio::time::Instant::now();
  while buf.len() < needed && started.elapsed() < deadline {
    let mut chunk = [0u8; 1024];
    let wait = deadline.saturating_sub(started.elapsed());
    match tokio::time::timeout(wait, client.read(&mut chunk)).await {
      Ok(Ok(0)) => break,
      Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
      Ok(Err(err)) => {
        return Err(StealthGateError::Proxy(format!("ClientHello read: {err}")));
      }
      Err(_) => break,
    }
  }

  if buf.len() < needed {
    return Err(StealthGateError::Proxy(format!(
      "неполный ClientHello: {} из {needed} байт",
      buf.len()
    )));
  }
  Ok(buf)
}

/// Front: проксирует MTProto-сессию на back-узел.
pub async fn relay_from_front<C>(
  mut client: C,
  initial_data: &[u8],
  preferred_backend: &str,
  secret_mode: SecretMode,
  secret_label: Option<&str>,
  split: &SplitConfig,
  state: &AppState,
) -> Result<()>
where
  C: AsyncRead + AsyncWrite + Unpin,
{
  // Для ee: ServerHello на front, handshake читается параллельно connect к back
  // (как monolith ждёт DC connect перед accept_handshake), затем SGFB initial_data.
  enum FrontRelay<C> {
    Plain {
      initial: Vec<u8>,
      client: C,
    },
    EePlain {
      obf2_prefix: Vec<u8>,
      tls_io: FakeTlsStream<PrefixedStream<C>>,
    },
  }

  let (sgfb_initial, front_relay, preconnected_back) = if secret_mode == SecretMode::Ee {
    let secret = proxy::resolve_secret_bytes(state, secret_label)?;
    let client_hello_buf = complete_client_hello_buffer(&mut client, initial_data).await?;
    let client_hello = crate::faketls::parse_client_hello_record(&client_hello_buf)?;
    crate::faketls::validate_client_hello(&client_hello, &secret)?;
    crate::faketls::send_server_hello(&mut client, &client_hello, &secret).await?;

    let tls_tail = client_hello_buf[client_hello.raw.len()..].to_vec();
    let tls_tail_bytes = tls_tail.len();
    let timeout = Duration::from_secs(split.connect_timeout_secs);
    let first_back = split.back_servers.first().cloned();
    let mut tls_io = FakeTlsStream::new(PrefixedStream::new(tls_tail, client));

    let (handshake, obf2_prefix, tls_io, preconnect) = if let Some(back_addr) = first_back {
      let (io_result, preconnect) = tokio::join!(
        async {
          let mut handshake = [0u8; mtproto_obfuscate::HANDSHAKE_LEN];
          tokio::time::timeout(timeout, tls_io.read_exact(&mut handshake))
            .await
            .map_err(|_| {
              StealthGateError::Proxy("split front ee handshake timeout".into())
            })?
            .map_err(|err| {
              StealthGateError::Proxy(format!("split front ee handshake: {err}"))
            })?;
          mtproto_obfuscate::parse_handshake(&handshake, &secret).ok_or_else(|| {
            StealthGateError::Proxy("split front: невалидный obfuscated2 handshake".into())
          })?;
          let obf2_prefix = tls_io.take_read_buf();
          Ok::<_, StealthGateError>((handshake, obf2_prefix, tls_io))
        },
        async {
          match tokio::time::timeout(timeout, TcpStream::connect(&back_addr)).await {
            Ok(Ok(stream)) => Some((back_addr, stream)),
            _ => None,
          }
        }
      );
      let (handshake, obf2_prefix, tls_io) = io_result?;
      (handshake, obf2_prefix, tls_io, preconnect)
    } else {
      let (handshake, obf2_prefix, tls_io) = async {
        let mut handshake = [0u8; mtproto_obfuscate::HANDSHAKE_LEN];
        tls_io
          .read_exact(&mut handshake)
          .await
          .map_err(|err| StealthGateError::Proxy(format!("split front ee handshake: {err}")))?;
        mtproto_obfuscate::parse_handshake(&handshake, &secret).ok_or_else(|| {
          StealthGateError::Proxy("split front: невалидный obfuscated2 handshake".into())
        })?;
        let obf2_prefix = tls_io.take_read_buf();
        Ok::<_, StealthGateError>((handshake, obf2_prefix, tls_io))
      }
      .await?;
      (handshake, obf2_prefix, tls_io, None)
    };

    tracing::debug!(
      sni = ?client_hello.sni,
      tls_tail_bytes,
      handshake_bytes = handshake.len(),
      obf2_prefix_bytes = obf2_prefix.len(),
      preconnected = preconnect.is_some(),
      "split front: прочитан obfuscated2 handshake, передаём в SGFB initial_data"
    );

    (
      handshake.to_vec(),
      FrontRelay::EePlain { obf2_prefix, tls_io },
      preconnect,
    )
  } else {
    (
      initial_data.to_vec(),
      FrontRelay::Plain {
        initial: initial_data.to_vec(),
        client,
      },
      None,
    )
  };

  let token = split
    .auth_token
    .as_deref()
    .ok_or_else(|| StealthGateError::Config("split.auth_token не задан".into()))?;

  if split.back_servers.is_empty() {
    return Err(StealthGateError::Config(
      "split.back_servers пуст для front-режима".into(),
    ));
  }

  let frame = encode_opening_frame(token, secret_mode, preferred_backend, &sgfb_initial)?;
  let timeout = Duration::from_secs(split.connect_timeout_secs);
  let mut last_error = None;
  let mut preconnected_back = preconnected_back;

  for (idx, back_addr) in split.back_servers.iter().enumerate() {
    let back_stream_result = if idx == 0 {
      if let Some((pre_addr, stream)) = preconnected_back.take() {
        if &pre_addr == back_addr {
          Ok(Ok(stream))
        } else {
          tokio::time::timeout(timeout, TcpStream::connect(back_addr)).await
        }
      } else {
        tokio::time::timeout(timeout, TcpStream::connect(back_addr)).await
      }
    } else {
      tokio::time::timeout(timeout, TcpStream::connect(back_addr)).await
    };

    match back_stream_result {
      Ok(Ok(mut back_stream)) => {
        tracing::info!(
          back = %back_addr,
          secret_mode = ?secret_mode,
          backend = %preferred_backend,
          frame_bytes = frame.len(),
          "split front: отправка SGFB opening-кадра на back"
        );
        if let Err(err) = back_stream.write_all(&frame).await {
          last_error = Some(StealthGateError::Proxy(format!(
            "split write к {back_addr}: {err}"
          )));
          continue;
        }

        let mut ack = [0u8; 1];
        let ack_result = tokio::time::timeout(timeout, back_stream.read_exact(&mut ack))
          .await
          .map_err(|_| StealthGateError::Proxy(format!("split ack timeout {back_addr}")))
          .and_then(|result| {
            result.map_err(|err| {
              StealthGateError::Proxy(format!("split ack read {back_addr}: {err}"))
            })
          })
          .and_then(|_| {
            if ack[0] == ACK_OK {
              Ok(())
            } else {
              Err(StealthGateError::Proxy(format!(
                "split back {back_addr} отклонил сессию"
              )))
            }
          });

        match ack_result {
          Ok(()) => {
            state.stats.split_relayed.fetch_add(1, Ordering::Relaxed);
            let (c2b, b2c) = match front_relay {
              FrontRelay::EePlain {
                obf2_prefix,
                tls_io,
              } => {
                tracing::debug!(
                  obf2_prefix_bytes = obf2_prefix.len(),
                  "split front ee: ACK получен, старт plaintext obfuscated2 relay"
                );
                let client_io = PrefixedStream::new(obf2_prefix, tls_io);
                proxy::copy_bidirectional(client_io, back_stream).await?
              }
              FrontRelay::Plain { initial, client } => {
                let client_io = PrefixedStream::new(initial, client);
                proxy::copy_bidirectional(client_io, back_stream).await?
              }
            };
            state
              .stats
              .bytes_to_backend
              .fetch_add(c2b + sgfb_initial.len() as u64, Ordering::Relaxed);
            state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);
            tracing::debug!(
              back = %back_addr,
              c2b,
              b2c,
              "split front-сессия завершена"
            );
            return Ok(());
          }
          Err(err) => {
            last_error = Some(err);
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
  peer_ip: IpAddr,
  front_allowlist: &[String],
) -> Result<Vec<u8>> {
  let mut header = vec![0u8; 40];
  stream
    .read_exact(&mut header)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split opening header: {err}")))?;

  if header[0..4] != *MAGIC {
    let from_allowed_front = peer_allowed(peer_ip, front_allowlist);
    tracing::warn!(
      %peer_ip,
      peer_prefix = %hex::encode(&header[..header.len().min(16)]),
      from_allowed_front,
      "split back: ожидался SGFB (53474642), получены другие байты"
    );
    if from_allowed_front {
      tracing::warn!(
        %peer_ip,
        "похоже на сырой TCP port-forward с front-узла (socat/iptables) вместо SGFB от StealthGate front. \
         Уберите DNAT/socat на RU:14443→EU:14443; front должен слать SGFB только после детекции MTProto"
      );
    } else {
      tracing::warn!(
        "возможен прямой TLS/HTTP на split-порт или port-forward без SGFB"
      );
    }
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

async fn handle_back_ee_connection<S>(
  mut front_stream: S,
  peer_ip: IpAddr,
  frame: SplitOpeningFrame,
  state: &AppState,
) -> Result<()>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let secret = proxy::resolve_secret_bytes(state, None)?;

  let relay_dc_id = if frame.initial_data.len() == mtproto_obfuscate::HANDSHAKE_LEN {
    let handshake: [u8; mtproto_obfuscate::HANDSHAKE_LEN] = frame
      .initial_data
      .as_slice()
      .try_into()
      .expect("handshake len checked");
    if mtproto_obfuscate::parse_handshake(&handshake, &secret).is_none() {
      send_ack(
        &mut front_stream,
        false,
        Some("невалидный obfuscated2 handshake в initial_data"),
      )
      .await?;
      return Err(StealthGateError::Proxy(
        "невалидный obfuscated2 handshake в initial_data".into(),
      ));
    }
    mtproto_obfuscate::handshake_dc_index(&handshake, &secret)
      .filter(|&id| id != 0)
      .unwrap_or_else(|| mtproto_obfuscate::dc_id_from_backend(&frame.backend))
  } else {
    send_ack(
      &mut front_stream,
      false,
      Some("ee initial_data должен быть 64-байтным obfuscated2 handshake"),
    )
    .await?;
    return Err(StealthGateError::Proxy(
      "ee initial_data должен быть 64-байтным obfuscated2 handshake".into(),
    ));
  };

  let network = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.network.clone()
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
      tracing::warn!(
        %peer_ip,
        backend = %frame.backend,
        error = %err,
        "split back ee: не удалось подключиться к Telegram DC"
      );
      send_ack(&mut front_stream, false, Some(&err.to_string())).await?;
      return Err(err);
    }
  };

  if connected_backend != frame.backend {
    tracing::info!(
      preferred = %frame.backend,
      connected = %connected_backend,
      "split back ee: failover на другой Telegram DC"
    );
  }

  // Как в monolith relay_ee_streams: accept_handshake → relay init → ACK → copy.
  let prefixed = PrefixedStream::new(frame.initial_data, front_stream);
  let mut accepted = mtproto_obfuscate::accept_handshake(prefixed, &secret).await?;

  let (header, relay_keys) = mtproto_obfuscate::generate_relay_init(relay_dc_id)?;
  upstream
    .write_all(&header)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split ee relay header to DC: {err}")))?;

  tracing::debug!(
    %peer_ip,
    relay_dc_id,
    backend = %connected_backend,
    "split back ee: relay init в DC, ACK front для старта obfuscated2 relay"
  );

  send_ack(accepted.stream.inner_mut(), true, None).await?;
  state.stats.split_relayed.fetch_add(1, Ordering::Relaxed);

  let dc_stream = ObfuscatedStream::from_relay_keys(upstream, relay_keys);
  let (c2b, b2c) = proxy::copy_bidirectional(accepted.stream, dc_stream).await?;
  state
    .stats
    .bytes_to_backend
    .fetch_add(c2b + mtproto_obfuscate::HANDSHAKE_LEN as u64, Ordering::Relaxed);
  state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);
  tracing::debug!(
    backend = %connected_backend,
    peer = %peer_ip,
    c2b,
    b2c,
    "split back ee-сессия завершена"
  );

  Ok(())
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

  let raw = read_opening_frame(
    &mut front_stream,
    MAX_INITIAL_LEN,
    peer_ip,
    &split.front_allowlist,
  )
  .await?;
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

  tracing::info!(
    %peer_ip,
    backend = %frame.backend,
    secret_mode = ?frame.secret_mode,
    initial_bytes = frame.initial_data.len(),
    "split back: принят SGFB opening-кадр, подключение к Telegram DC"
  );

  if frame.secret_mode == SecretMode::Ee {
    return handle_back_ee_connection(front_stream, peer_ip, frame, state).await;
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
      tracing::warn!(
        %peer_ip,
        backend = %frame.backend,
        error = %err,
        socks5 = network.socks5_proxy.is_some(),
        "split back: не удалось подключиться к Telegram DC"
      );
      send_ack(&mut front_stream, false, Some(&err.to_string())).await?;
      return Err(err);
    }
  };

  if connected_backend != frame.backend {
    tracing::info!(
      preferred = %frame.backend,
      connected = %connected_backend,
      "split back: failover на другой Telegram DC"
    );
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
      let raw = read_opening_frame(
        &mut stream,
        MAX_INITIAL_LEN,
        "127.0.0.1".parse().expect("ip"),
        &[],
      )
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
