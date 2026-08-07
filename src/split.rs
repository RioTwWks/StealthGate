//! Front/Back split — разделение edge (front) и Telegram relay (back).

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
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
use crate::sgfb_crypto::{self, EncryptedStream, SessionKeys};
use crate::state::AppState;

const MAGIC: &[u8; 4] = b"SGFB";
const VERSION_PLAIN: u8 = sgfb_crypto::PROTOCOL_VERSION_PLAIN;
const VERSION_ENCRYPTED: u8 = sgfb_crypto::PROTOCOL_VERSION_ENCRYPTED;
const MAX_BACKEND_LEN: usize = 256;
const MAX_INITIAL_LEN: usize = 65_536;
pub const ACK_OK: u8 = 0;
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
  encrypt_relay: bool,
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
  out.push(if encrypt_relay {
    VERSION_ENCRYPTED
  } else {
    VERSION_PLAIN
  });
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
  if data[4] != VERSION_PLAIN && data[4] != VERSION_ENCRYPTED {
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

/// Дочитывает TLS ClientHello; при неполной записи шлёт ServerHello, чтобы разблокировать клиента.
/// Хвост записи и obfuscated2 дочитывает FakeTlsStream во время read handshake (до connect_timeout).
async fn prepare_ee_client_hello<C: AsyncRead + AsyncWrite + Unpin>(
  client: &mut C,
  initial: &[u8],
  secret: &[u8],
) -> Result<(Vec<u8>, crate::faketls::ParsedClientHello)> {
  let buf = initial.to_vec();
  let needed = crate::tls::tls_record_total_len(&buf);

  if let Some(needed) = needed {
    if buf.len() < needed {
      let partial = crate::faketls::parse_client_hello_prefix(&buf)?;
      crate::faketls::send_server_hello(client, &partial, secret).await?;
      tracing::debug!(
        peek_len = buf.len(),
        needed,
        "split front ee: неполный ClientHello, отправлен ранний ServerHello"
      );

      if crate::faketls::validate_client_hello(&partial, secret).is_err() {
        tracing::debug!(
          "split front ee: partial ClientHello без полной HMAC-проверки (probable ee на acceptor)"
        );
      }
      tracing::debug!(
        peek_len = buf.len(),
        needed,
        remaining = needed - buf.len(),
        "split front ee: хвост ClientHello/obf2 дочитается в FakeTlsStream"
      );
      return Ok((buf, partial));
    }
  }

  let client_hello = crate::faketls::parse_client_hello_record(&buf)?;
  crate::faketls::validate_client_hello(&client_hello, secret)?;
  crate::faketls::send_server_hello(client, &client_hello, secret).await?;

  Ok((buf, client_hello))
}

fn opening_frame_encrypted(frame_bytes: &[u8]) -> bool {
  frame_bytes.get(4).copied() == Some(VERSION_ENCRYPTED)
}

fn wrap_relay_stream<S>(
  stream: S,
  keys: SessionKeys,
  encrypted: bool,
  client_side: bool,
) -> EitherRelayStream<S> {
  if encrypted {
    if client_side {
      EitherRelayStream::Encrypted(EncryptedStream::client_side(stream, keys))
    } else {
      EitherRelayStream::Encrypted(EncryptedStream::server_side(stream, keys))
    }
  } else {
    EitherRelayStream::Plain(stream)
  }
}

enum EitherRelayStream<S> {
  Plain(S),
  Encrypted(EncryptedStream<S>),
}

impl<S: AsyncRead + Unpin> AsyncRead for EitherRelayStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match &mut *self {
      EitherRelayStream::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
      EitherRelayStream::Encrypted(inner) => Pin::new(inner).poll_read(cx, buf),
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EitherRelayStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    match &mut *self {
      EitherRelayStream::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
      EitherRelayStream::Encrypted(inner) => Pin::new(inner).poll_write(cx, buf),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match &mut *self {
      EitherRelayStream::Plain(inner) => Pin::new(inner).poll_flush(cx),
      EitherRelayStream::Encrypted(inner) => Pin::new(inner).poll_flush(cx),
    }
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match &mut *self {
      EitherRelayStream::Plain(inner) => Pin::new(inner).poll_shutdown(cx),
      EitherRelayStream::Encrypted(inner) => Pin::new(inner).poll_shutdown(cx),
    }
  }
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
  let drs = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.drs.clone()
  };
  let write_opts = crate::faketls::FakeTlsWriteOptions::from_drs(&drs);

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
    let timeout = Duration::from_secs(split.connect_timeout_secs);
    let first_back = split.back_servers.first().cloned();

    let (client_hello_buf, client_hello) =
      prepare_ee_client_hello(&mut client, initial_data, &secret).await?;

    // Весь peek-буфер (в т.ч. partial ClientHello 1334/1728): после ServerHello клиент
    // досылает хвост той же TLS-записи без нового заголовка — без префикса FakeTlsStream
    // сбивает разбор кадров и obfuscated2 handshake не читается.
    let tls_prefix = client_hello_buf.clone();
    let tls_prefix_bytes = tls_prefix.len();
    let mut tls_io = FakeTlsStream::with_write_options(
      PrefixedStream::new(tls_prefix, client),
      write_opts.clone(),
    );

    // Сначала obfuscated2 handshake от клиента; connect к back только после успеха —
    // иначе каждая неудачная попытка открывает TCP на EU без SGFB (early eof).
    let (handshake, obf2_prefix, tls_io) = async {
      let mut handshake = [0u8; mtproto_obfuscate::HANDSHAKE_LEN];
      tokio::time::timeout(timeout, tls_io.read_exact(&mut handshake))
        .await
        .map_err(|_| StealthGateError::Proxy("split front ee handshake timeout".into()))?
        .map_err(|err| StealthGateError::Proxy(format!("split front ee handshake: {err}")))?;
      mtproto_obfuscate::parse_handshake(&handshake, &secret).ok_or_else(|| {
        StealthGateError::Proxy("split front: невалидный obfuscated2 handshake".into())
      })?;
      let obf2_prefix = tls_io.take_read_buf();
      Ok::<_, StealthGateError>((handshake, obf2_prefix, tls_io))
    }
    .await?;

    let preconnect = if let Some(back_addr) = first_back {
      match tokio::time::timeout(timeout, TcpStream::connect(&back_addr)).await {
        Ok(Ok(stream)) => Some((back_addr, stream)),
        _ => None,
      }
    } else {
      None
    };

    tracing::debug!(
      sni = ?client_hello.sni,
      tls_prefix_bytes,
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

  let frame = encode_opening_frame(
    token,
    secret_mode,
    preferred_backend,
    &sgfb_initial,
    split.encrypt_relay,
  )?;
  let session_keys = sgfb_crypto::derive_session_keys(token, &frame);
  let relay_encrypted = split.encrypt_relay && opening_frame_encrypted(&frame);
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
            let back_io =
              wrap_relay_stream(back_stream, session_keys.clone(), relay_encrypted, true);
            let (c2b, b2c) = match front_relay {
              FrontRelay::EePlain {
                obf2_prefix,
                tls_io,
              } => {
                tracing::debug!(
                  obf2_prefix_bytes = obf2_prefix.len(),
                  encrypted = relay_encrypted,
                  "split front ee: ACK получен, старт obfuscated2 relay"
                );
                let client_io = PrefixedStream::new(obf2_prefix, tls_io);
                proxy::copy_bidirectional_graceful(client_io, back_io).await?
              }
              FrontRelay::Plain { initial, client } => {
                let client_io = PrefixedStream::new(initial, client);
                proxy::copy_bidirectional_graceful(client_io, back_io).await?
              }
            };
            state
              .stats
              .bytes_to_backend
              .fetch_add(c2b + sgfb_initial.len() as u64, Ordering::Relaxed);
            state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);
            tracing::info!(
              back = %back_addr,
              c2b,
              b2c,
              "split front-сессия завершена"
            );
            if b2c == 0 && c2b > 0 {
              tracing::warn!(
                back = %back_addr,
                c2b,
                "split front: данные ушли на back, но ответ не вернулся (b2c=0)"
              );
            }
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

async fn read_first_obf2_from_front<S>(stream: &mut S, timeout: Duration) -> Result<Vec<u8>>
where
  S: AsyncRead + Unpin,
{
  let mut buf = vec![0u8; 8192];
  let n = tokio::time::timeout(timeout, stream.read(&mut buf))
    .await
    .map_err(|_| {
      StealthGateError::Proxy("split back ee: timeout ожидания obf2 от front".into())
    })?
    .map_err(|err| StealthGateError::Proxy(format!("split back ee: read obf2 от front: {err}")))?;
  if n == 0 {
    return Err(StealthGateError::Proxy(
      "split back ee: front закрыл соединение до obf2 данных".into(),
    ));
  }
  buf.truncate(n);
  Ok(buf)
}

async fn handle_back_ee_connection<S>(
  mut front_stream: S,
  peer_ip: IpAddr,
  frame: SplitOpeningFrame,
  state: &AppState,
  split: &SplitConfig,
  relay_encrypted: bool,
  session_keys: SessionKeys,
) -> Result<()>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  let secret = proxy::resolve_secret_bytes(state, None)?;

  let (relay_dc_id, proto_tag) = if frame.initial_data.len() == mtproto_obfuscate::HANDSHAKE_LEN {
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
    let proto_tag = mtproto_obfuscate::handshake_proto_tag(&handshake, &secret)
      .ok_or_else(|| StealthGateError::Proxy("не удалось извлечь proto tag".into()))?;
    let dc_id = mtproto_obfuscate::handshake_dc_index(&handshake, &secret)
      .filter(|&id| id != 0)
      .unwrap_or_else(|| mtproto_obfuscate::dc_id_from_backend(&frame.backend));
    (dc_id, proto_tag)
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

  // ACK сразу — front может начать SGFB relay, пока back подключается к DC.
  send_ack(&mut front_stream, true, None).await?;

  let front_io = wrap_relay_stream(front_stream, session_keys, relay_encrypted, false);
  let prefixed = PrefixedStream::new(frame.initial_data, front_io);
  let accepted = mtproto_obfuscate::accept_handshake(prefixed, &secret).await?;

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

  let client_stream = accepted.stream;
  let backend = frame.backend.clone();
  let timeout = Duration::from_secs(split.connect_timeout_secs);

  // Параллельно: connect к DC и первый obf2-чанк от front (после ACK front шлёт obf2_prefix).
  let ((mut upstream, connected_backend), (stream, first_obf2)) = tokio::try_join!(
    pool.connect(&network, Some(&backend), &state.stats),
    async {
      let mut stream = client_stream;
      let chunk = read_first_obf2_from_front(&mut stream, timeout).await?;
      Ok::<_, StealthGateError>((stream, chunk))
    }
  )
  .map_err(|err| {
    if let StealthGateError::Proxy(msg) = &err {
      tracing::warn!(
        %peer_ip,
        backend = %frame.backend,
        error = %msg,
        "split back ee: не удалось подготовить relay (DC или obf2 от front)"
      );
    }
    err
  })?;

  if connected_backend != frame.backend {
    tracing::info!(
      preferred = %frame.backend,
      connected = %connected_backend,
      "split back ee: failover на другой Telegram DC"
    );
  }

  // relay_init только после первых obf2-данных от front (как monolith после handshake).
  let (header, relay_keys) = mtproto_obfuscate::generate_relay_init(relay_dc_id, proto_tag)?;
  upstream
    .write_all(&header)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split ee relay header to DC: {err}")))?;
  upstream
    .flush()
    .await
    .map_err(|err| StealthGateError::Proxy(format!("split ee relay flush to DC: {err}")))?;

  tracing::debug!(
    %peer_ip,
    relay_dc_id,
    proto_tag = %hex::encode(proto_tag),
    backend = %connected_backend,
    first_obf2_bytes = first_obf2.len(),
    encrypted = relay_encrypted,
    "split back ee: obf2 от front, relay init в DC, старт copy"
  );

  state.stats.split_relayed.fetch_add(1, Ordering::Relaxed);

  let client_io = PrefixedStream::new(first_obf2, stream);
  let dc_stream = ObfuscatedStream::from_relay_keys(upstream, relay_keys);
  let (c2b, b2c) = proxy::copy_bidirectional_graceful(client_io, dc_stream).await?;
  state
    .stats
    .bytes_to_backend
    .fetch_add(c2b + mtproto_obfuscate::HANDSHAKE_LEN as u64, Ordering::Relaxed);
  state.stats.bytes_from_backend.fetch_add(b2c, Ordering::Relaxed);
  tracing::info!(
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
  let _ = split;
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

  let relay_encrypted = split.encrypt_relay && opening_frame_encrypted(&raw);
  let session_keys = sgfb_crypto::derive_session_keys(token, &raw);

  tracing::info!(
    %peer_ip,
    backend = %frame.backend,
    secret_mode = ?frame.secret_mode,
    initial_bytes = frame.initial_data.len(),
    encrypted = relay_encrypted,
    "split back: принят SGFB opening-кадр, подключение к Telegram DC"
  );

  if frame.secret_mode == SecretMode::Ee {
    return handle_back_ee_connection(
      front_stream,
      peer_ip,
      frame,
      state,
      split,
      relay_encrypted,
      session_keys,
    )
    .await;
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

  let front_io = wrap_relay_stream(front_stream, session_keys, relay_encrypted, false);
  let (c2b, b2c) = proxy::copy_bidirectional(front_io, upstream).await?;
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
      encode_opening_frame(token, SecretMode::Ee, backend, initial, true).expect("encode");
    let decoded = decode_opening_frame(&encoded).expect("decode");
    assert_eq!(decoded.secret_mode, SecretMode::Ee);
    assert_eq!(decoded.backend, backend);
    assert_eq!(decoded.initial_data, initial);
  }

  #[test]
  fn opening_frame_v2_marks_encrypted_protocol() {
    let token = "shared-secret-token-1234";
    let encoded = encode_opening_frame(token, SecretMode::Ee, "1.1.1.1:443", b"hs", true)
      .expect("encode");
    assert_eq!(encoded[4], sgfb_crypto::PROTOCOL_VERSION_ENCRYPTED);
    let plain = encode_opening_frame(token, SecretMode::Ee, "1.1.1.1:443", b"hs", false)
      .expect("encode");
    assert_eq!(plain[4], sgfb_crypto::PROTOCOL_VERSION_PLAIN);
  }

  #[test]
  fn rejects_bad_magic() {
    let mut data = encode_opening_frame("token", SecretMode::Classic, "1.1.1.1:443", b"x", false)
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
    let frame = encode_opening_frame(token, SecretMode::Ee, "149.154.167.99:443", b"payload", true)
      .expect("encode");
    client.write_all(&frame).await.expect("write");
    let mut ack = [0u8; 1];
    client.read_exact(&mut ack).await.expect("read ack");
    assert_eq!(ack[0], ACK_OK);

    server.await.expect("join");
  }
}
