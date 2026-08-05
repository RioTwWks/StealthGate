//! Распознавание и генерация 64-байтного obfuscated2 handshake MTProto-прокси.
//!
//! Клиент отправляет 64 случайных байта; байты [8..40] — prekey, [40..56] — IV.
//! Ключ: `SHA-256(prekey || secret)`. После AES-256-CTR в [56..60] — тег протокола.

use std::pin::Pin;
use std::task::{Context, Poll};

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

type AesCtr256 = Ctr128BE<Aes256>;

/// Результат разбора obfuscated2 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInfo {
  pub dc_id: u16,
  pub is_media: bool,
}

/// Проверяет, что первые 64 байта — валидный obfuscated2 handshake с данным секретом.
pub fn matches_obfuscated2(data: &[u8], secret: &[u8]) -> bool {
  if data.len() < HANDSHAKE_LEN || secret.len() != 16 {
    return false;
  }
  let handshake: &[u8; HANDSHAKE_LEN] = data[..HANDSHAKE_LEN].try_into().expect("64 bytes");
  parse_handshake(handshake, secret).is_some()
}

/// Пробует расшифровать 64-байтный handshake; `None` — неверный секрет или мусор.
pub fn parse_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<HandshakeInfo> {
  if secret.len() != 16 {
    return None;
  }

  let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
  let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

  let key = {
    let mut h = Sha256::new();
    h.update(prekey);
    h.update(secret);
    h.finalize()
  };

  let mut buf = *handshake;
  let mut cipher = make_cipher(&key, iv);
  cipher.apply_keystream(&mut buf);

  if !is_valid_proto_tag(&buf[PROTO_TAG_POS..PROTO_TAG_POS + 4]) {
    return None;
  }

  let dc_idx = i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]);
  Some(HandshakeInfo {
    dc_id: dc_idx.unsigned_abs(),
    is_media: dc_idx < 0,
  })
}

/// Возвращает подписанный DC index из obfuscated2 handshake (для relay init к Telegram).
pub fn handshake_dc_index(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<i16> {
  if secret.len() != 16 {
    return None;
  }

  let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
  let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
  let key = {
    let mut h = Sha256::new();
    h.update(prekey);
    h.update(secret);
    h.finalize()
  };

  let mut buf = *handshake;
  let mut cipher = make_cipher(&key, iv);
  cipher.apply_keystream(&mut buf);

  if !is_valid_proto_tag(&buf[PROTO_TAG_POS..PROTO_TAG_POS + 4]) {
    return None;
  }

  Some(i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]))
}

fn is_valid_proto_tag(tag: &[u8]) -> bool {
  tag == PROTO_TAG_ABRIDGED || tag == PROTO_TAG_INTERMEDIATE || tag == PROTO_TAG_SECURE
}

fn make_cipher(key: &[u8], iv: &[u8]) -> AesCtr256 {
  AesCtr256::new_from_slices(key, iv).expect("AES-256-CTR key/iv length")
}

/// Производный AES-CTR ключ для obfuscated2 с секретом прокси.
pub fn derive_key_with_secret(prekey: &[u8], secret: &[u8]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.update(prekey);
  h.update(secret);
  h.finalize().into()
}

/// Результат приёма obfuscated2 handshake от клиента.
pub struct AcceptedHandshake<S> {
  pub stream: ObfuscatedStream<S>,
  pub dc_id: i16,
}

/// Принимает 64-байтный obfuscated2 handshake из потока (например, внутри Fake TLS).
pub async fn accept_handshake<S>(
  mut reader: S,
  secret: &[u8],
) -> crate::error::Result<AcceptedHandshake<S>>
where
  S: AsyncRead + Unpin,
{
  let mut header = [0u8; HANDSHAKE_LEN];
  reader
    .read_exact_obfuscated_header(&mut header)
    .await?;

  let info = parse_handshake(&header, secret).ok_or_else(|| {
    crate::error::StealthGateError::Proxy(
      "невалидный obfuscated2 handshake от клиента".into(),
    )
  })?;

  let mut reversed = [0u8; HANDSHAKE_LEN];
  for i in 0..HANDSHAKE_LEN {
    reversed[i] = header[HANDSHAKE_LEN - 1 - i];
  }

  let dec_key = derive_key_with_secret(&header[SKIP_LEN..SKIP_LEN + PREKEY_LEN], secret);
  let dec_iv: [u8; 16] = header[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
    .try_into()
    .expect("iv len");
  let mut dec = make_cipher(&dec_key, &dec_iv);
  let mut sink = header;
  dec.apply_keystream(&mut sink);
  let dc_idx = i16::from_le_bytes([sink[DC_IDX_POS], sink[DC_IDX_POS + 1]]);

  let _ = info;

  let enc_key = derive_key_with_secret(&reversed[SKIP_LEN..SKIP_LEN + PREKEY_LEN], secret);
  let enc_iv: [u8; 16] = reversed[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
    .try_into()
    .expect("iv len");
  let enc = make_cipher(&enc_key, &enc_iv);

  Ok(AcceptedHandshake {
    stream: ObfuscatedStream {
      inner: reader,
      enc,
      dec,
      pending_write: Vec::new(),
    },
    dc_id: dc_idx,
  })
}

trait ReadExactHeader {
  async fn read_exact_obfuscated_header(&mut self, buf: &mut [u8; HANDSHAKE_LEN]) -> crate::error::Result<()>;
}

impl<S> ReadExactHeader for S
where
  S: AsyncRead + Unpin,
{
  async fn read_exact_obfuscated_header(
    &mut self,
    buf: &mut [u8; HANDSHAKE_LEN],
  ) -> crate::error::Result<()> {
    use tokio::io::AsyncReadExt;
    self
      .read_exact(buf)
      .await
      .map(|_| ())
      .map_err(|err| crate::error::StealthGateError::Proxy(format!("obfuscated2 header: {err}")))
  }
}

/// Генерирует исходящий 64-байтный handshake для подключения к Telegram DC (без секрета).
pub fn generate_relay_init(dc_id: i16) -> crate::error::Result<([u8; HANDSHAKE_LEN], RelayKeys)> {
  let proto_tag = PROTO_TAG_SECURE;
  let dc_bytes = dc_id.to_le_bytes();

  loop {
    let mut raw = [0u8; HANDSHAKE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);

    if RESERVED_FIRST_BYTES.contains(&raw[0]) {
      continue;
    }
    if RESERVED_STARTS.iter().any(|s| &raw[..4] == s) {
      continue;
    }
    if raw[4..8] == RESERVED_CONTINUE {
      continue;
    }

    let enc_key: [u8; PREKEY_LEN] = raw[SKIP_LEN..SKIP_LEN + PREKEY_LEN]
      .try_into()
      .expect("enc key");
    let enc_iv: [u8; IV_LEN] = raw[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
      .try_into()
      .expect("enc iv");

    let mut reversed = [0u8; HANDSHAKE_LEN];
    for i in 0..HANDSHAKE_LEN {
      reversed[i] = raw[HANDSHAKE_LEN - 1 - i];
    }
    let dec_key: [u8; PREKEY_LEN] = reversed[SKIP_LEN..SKIP_LEN + PREKEY_LEN]
      .try_into()
      .expect("dec key");
    let dec_iv: [u8; IV_LEN] =
      reversed[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .try_into()
        .expect("dec iv");

    let mut enc = make_cipher(&enc_key, &enc_iv);
    let mut plaintext = raw;
    plaintext[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag);
    plaintext[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_bytes);

    let mut encrypted = plaintext;
    enc.apply_keystream(&mut encrypted);
    let mut header = raw;
    header[PROTO_TAG_POS..].copy_from_slice(&encrypted[PROTO_TAG_POS..]);

    let dec = make_cipher(&dec_key, &dec_iv);
    return Ok((
      header,
      RelayKeys {
        enc,
        dec,
      },
    ));
  }
}

/// AES-CTR ключи для relay-соединения с Telegram DC.
pub struct RelayKeys {
  pub enc: AesCtr256,
  pub dec: AesCtr256,
}

/// Оборачивает поток AES-256-CTR шифрованием obfuscated2.
pub struct ObfuscatedStream<S> {
  inner: S,
  enc: AesCtr256,
  dec: AesCtr256,
  /// Недописанный ciphertext (при partial write во внутренний поток).
  pending_write: Vec<u8>,
}

impl<S> ObfuscatedStream<S> {
  pub fn from_relay_keys(inner: S, keys: RelayKeys) -> Self {
    Self {
      inner,
      enc: keys.enc,
      dec: keys.dec,
      pending_write: Vec::new(),
    }
  }

  pub fn into_inner(self) -> S {
    self.inner
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfuscatedStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let filled_before = buf.filled().len();
    let inner = Pin::new(&mut self.inner);
    match inner.poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        let filled = buf.filled_mut();
        let n = filled.len() - filled_before;
        if n > 0 {
          self.dec.apply_keystream(&mut filled[filled_before..]);
        }
        Poll::Ready(Ok(()))
      }
      other => other,
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfuscatedStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    loop {
      if !self.pending_write.is_empty() {
        let pending = std::mem::take(&mut self.pending_write);
        match Pin::new(&mut self.inner).poll_write(cx, &pending) {
          Poll::Ready(Ok(0)) => {
            self.pending_write = pending;
            return Poll::Ready(Err(std::io::Error::new(
              std::io::ErrorKind::WriteZero,
              "write zero",
            )));
          }
          Poll::Ready(Ok(n)) => {
            if n < pending.len() {
              self.pending_write = pending[n..].to_vec();
              return Poll::Pending;
            }
          }
          Poll::Ready(Err(err)) => {
            self.pending_write = pending;
            return Poll::Ready(Err(err));
          }
          Poll::Pending => {
            self.pending_write = pending;
            return Poll::Pending;
          }
        }
      }

      if buf.is_empty() {
        return Poll::Ready(Ok(0));
      }

      let mut out = buf.to_vec();
      self.enc.apply_keystream(&mut out);

      match Pin::new(&mut self.inner).poll_write(cx, &out) {
        Poll::Ready(Ok(0)) => {
          return Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "write zero",
          )));
        }
        Poll::Ready(Ok(n)) if n < out.len() => {
          self.pending_write = out[n..].to_vec();
          return Poll::Ready(Ok(buf.len()));
        }
        Poll::Ready(Ok(_)) => return Poll::Ready(Ok(buf.len())),
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => {
          self.pending_write = out;
          return Poll::Pending;
        }
      }
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    if !self.pending_write.is_empty() {
      match self.as_mut().poll_write(cx, &[]) {
        Poll::Ready(Ok(_)) => {}
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => return Poll::Pending,
      }
    }
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

/// Оценивает DC id по адресу backend (fallback).
pub fn dc_id_from_backend(backend: &str) -> i16 {
  let host = backend.split(':').next().unwrap_or(backend);
  match host {
    "149.154.175.50" => 4,
    "149.154.167.51" => 3,
    "149.154.175.100" => 1,
    "149.154.167.99" | "149.154.167.40" => 2,
    "91.108.56.100" => 5,
    _ => 2,
  }
}

const RESERVED_FIRST_BYTES: &[u8] = &[0xef];
const RESERVED_STARTS: &[[u8; 4]] = &[
  [0x48, 0x45, 0x41, 0x44],
  [0x50, 0x4f, 0x53, 0x54],
  [0x47, 0x45, 0x54, 0x20],
  [0xee, 0xee, 0xee, 0xee],
  [0xdd, 0xdd, 0xdd, 0xdd],
  [0x16, 0x03, 0x01, 0x02],
];
const RESERVED_CONTINUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[cfg(test)]
pub fn generate_test_handshake(secret: &[u8], dc_idx: i16, proto_tag: [u8; 4]) -> [u8; HANDSHAKE_LEN] {
  let dc_bytes = dc_idx.to_le_bytes();
  loop {
    let mut raw = [0u8; HANDSHAKE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);

    if RESERVED_FIRST_BYTES.contains(&raw[0]) {
      continue;
    }
    if RESERVED_STARTS.iter().any(|s| &raw[..4] == s) {
      continue;
    }
    if raw[4..8] == RESERVED_CONTINUE {
      continue;
    }

    let key = derive_key_with_secret(&raw[SKIP_LEN..SKIP_LEN + PREKEY_LEN], secret);
    let iv = &raw[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut keystream = [0u8; HANDSHAKE_LEN];
    make_cipher(&key, iv).apply_keystream(&mut keystream);

    let mut handshake = raw;
    for i in 0..4 {
      handshake[PROTO_TAG_POS + i] = proto_tag[i] ^ keystream[PROTO_TAG_POS + i];
    }
    for i in 0..2 {
      handshake[DC_IDX_POS + i] = dc_bytes[i] ^ keystream[DC_IDX_POS + i];
    }

    return handshake;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_valid_padded_intermediate_handshake() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let handshake = generate_test_handshake(&secret, 2, PROTO_TAG_SECURE);
    let info = parse_handshake(&handshake, &secret).expect("handshake");
    assert_eq!(info.dc_id, 2);
    assert!(!info.is_media);
    assert_eq!(handshake_dc_index(&handshake, &secret), Some(2));
  }

  #[test]
  fn rejects_wrong_secret() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let wrong = hex::decode("ffffffffffffffffffffffffffffffff").expect("wrong");
    let handshake = generate_test_handshake(&secret, 2, PROTO_TAG_SECURE);
    assert!(parse_handshake(&handshake, &wrong).is_none());
  }

  #[test]
  fn matches_with_extra_peek_bytes() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let handshake = generate_test_handshake(&secret, -4, PROTO_TAG_INTERMEDIATE);
    let mut payload = handshake.to_vec();
    payload.extend_from_slice(&[0xAA; 200]);
    assert!(matches_obfuscated2(&payload, &secret));
  }

  #[test]
  fn rejects_random_noise() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let noise = vec![0u8; 128];
    assert!(!matches_obfuscated2(&noise, &secret));
  }

  #[tokio::test]
  async fn obfuscated_stream_write_all_completes() {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let handshake = generate_test_handshake(&secret, 2, PROTO_TAG_SECURE);
    let (client_io, proxy_io) = duplex(4096);
    let prefixed = crate::io_util::PrefixedStream::new(handshake.to_vec(), client_io);
    let mut client_stream = accept_handshake(prefixed, &secret)
      .await
      .expect("accept")
      .stream;

    let payload = vec![0xABu8; 512];
    let reader = tokio::spawn(async move {
      let mut proxy_read = proxy_io;
      let mut total = 0usize;
      let mut buf = [0u8; 64];
      loop {
        match proxy_read.read(&mut buf).await {
          Ok(0) => break,
          Ok(n) => total += n,
          Err(err) => panic!("proxy read: {err}"),
        }
      }
      total
    });

    client_stream
      .write_all(&payload)
      .await
      .expect("client write");
    drop(client_stream);

    let total = reader.await.expect("reader join");
    assert_eq!(total, payload.len());
  }
}
