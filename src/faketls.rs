//! Fake TLS (ee-секрет) — ClientHello/ServerHello и TLS Application Data framing.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Result, StealthGateError};
use crate::tls::{parse_client_hello, parse_record, RecordType};

type HmacSha256 = Hmac<Sha256>;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_APPLICATION_DATA: u8 = 0x17;
const MAX_TLS_PAYLOAD: usize = 16_384;
const HELLO_TIMESTAMP_SKEW_SECS: u64 = 120;
const SERVER_HELLO_RANDOM_OFFSET: usize = 11;

/// Параметры записи TLS Application Data (DRS + padding).
#[derive(Debug, Clone)]
pub struct FakeTlsWriteOptions {
  pub record_sizes: Vec<usize>,
  pub padding: bool,
}

impl Default for FakeTlsWriteOptions {
  fn default() -> Self {
    Self {
      record_sizes: vec![512, 1024, 1398, 256],
      padding: true,
    }
  }
}

impl FakeTlsWriteOptions {
  pub fn from_drs(drs: &crate::config::DrsConfig) -> Option<Self> {
    if !drs.enabled && !drs.ee_relay {
      return None;
    }
    let record_sizes = if drs.record_sizes.is_empty() {
      vec![512, 1024, 1398, 256]
    } else {
      drs.record_sizes.clone()
    };
    Some(Self {
      record_sizes,
      padding: true,
    })
  }
}

/// Разобранный TLS ClientHello с полной записью.
#[derive(Debug, Clone)]
pub struct ParsedClientHello {
  pub raw: Vec<u8>,
  pub random: [u8; 32],
  pub session_id: Vec<u8>,
  pub cipher_suite: u16,
  pub sni: Option<String>,
}

/// Парсит поля ClientHello из полной или частичной TLS-записи (для раннего ServerHello).
pub fn parse_client_hello_prefix(data: &[u8]) -> Result<ParsedClientHello> {
  if data.len() < SERVER_HELLO_RANDOM_OFFSET + 32 {
    return Err(StealthGateError::Proxy(
      "недостаточно данных для partial ClientHello".into(),
    ));
  }
  if data[0] != TLS_HANDSHAKE {
    return Err(StealthGateError::Proxy(
      "ожидалась TLS handshake-запись".into(),
    ));
  }

  let payload = &data[5..];
  if payload.len() < 4 + 2 + 32 {
    return Err(StealthGateError::Proxy(
      "partial ClientHello: нет random".into(),
    ));
  }

  let mut cursor = 4usize;
  cursor += 2;
  let random: [u8; 32] = payload[cursor..cursor + 32]
    .try_into()
    .map_err(|_| StealthGateError::Proxy("partial ClientHello: random".into()))?;
  cursor += 32;
  if cursor >= payload.len() {
    return Err(StealthGateError::Proxy(
      "partial ClientHello: нет session_id".into(),
    ));
  }
  let session_id_len = payload[cursor] as usize;
  cursor += 1;
  if cursor + session_id_len > payload.len() {
    return Err(StealthGateError::Proxy(
      "partial ClientHello: обрезан session_id".into(),
    ));
  }
  let session_id = payload[cursor..cursor + session_id_len].to_vec();
  cursor += session_id_len;

  let cipher_suite = if cursor + 2 <= payload.len() {
    u16::from_be_bytes([payload[cursor], payload[cursor + 1]])
  } else {
    0
  };

  let sni = crate::tls::try_client_hello_sni(data);

  Ok(ParsedClientHello {
    raw: data.to_vec(),
    random,
    session_id,
    cipher_suite,
    sni,
  })
}

/// Парсит TLS ClientHello из уже прочитанного буфера.
pub fn parse_client_hello_record(data: &[u8]) -> Result<ParsedClientHello> {
  let record = parse_record(data).map_err(|err| {
    StealthGateError::Proxy(format!("fake TLS ClientHello: {err}"))
  })?;
  if record.record_type != RecordType::Handshake {
    return Err(StealthGateError::Proxy(
      "ожидалась TLS handshake-запись".into(),
    ));
  }

  let hello = parse_client_hello(record.payload).map_err(|err| {
    StealthGateError::Proxy(format!("fake TLS parse ClientHello: {err}"))
  })?;

  if hello.random.len() != 32 {
    return Err(StealthGateError::Proxy(
      "ClientHello random должен быть 32 байта".into(),
    ));
  }

  let cipher_suite = if hello.cipher_suites.len() >= 2 {
    u16::from_be_bytes([hello.cipher_suites[0], hello.cipher_suites[1]])
  } else {
    0
  };

  let record_len = 5 + record.payload.len();
  if data.len() < record_len {
    return Err(StealthGateError::Proxy(
      "неполная TLS-запись ClientHello".into(),
    ));
  }

  Ok(ParsedClientHello {
    raw: data[..record_len].to_vec(),
    random: hello.random.try_into().expect("random len"),
    session_id: hello.session_id.to_vec(),
    cipher_suite,
    sni: hello.sni.clone(),
  })
}

/// Проверяет HMAC в поле random ClientHello.
pub fn validate_client_hello(ch: &ParsedClientHello, secret: &[u8]) -> Result<()> {
  if ch.raw.len() < SERVER_HELLO_RANDOM_OFFSET + 32 {
    return Err(StealthGateError::Proxy(
      "ClientHello слишком короткий для HMAC".into(),
    ));
  }

  let mut modified = ch.raw.clone();
  modified[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_OFFSET + 32]
    .fill(0);

  let mut mac = HmacSha256::new_from_slice(secret)
    .map_err(|err| StealthGateError::Proxy(format!("HMAC key: {err}")))?;
  mac.update(&modified);
  let mut expected = mac.finalize().into_bytes();

  for i in 0..32 {
    expected[i] ^= ch.random[i];
  }

  if expected[..28].iter().any(|&b| b != 0) {
    return Err(StealthGateError::Proxy(
      "fake TLS HMAC verification failed".into(),
    ));
  }

  let ts = u32::from_le_bytes(expected[28..32].try_into().expect("ts"));
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();
  let diff = ts as i64 - now as i64;
  if diff.unsigned_abs() > HELLO_TIMESTAMP_SKEW_SECS {
    return Err(StealthGateError::Proxy(
      "fake TLS timestamp out of range".into(),
    ));
  }

  Ok(())
}

/// Собирает ClientHello с валидным ee HMAC (для тестов и E2E).
pub fn build_signed_client_hello(sni: &str, secret: &[u8]) -> Vec<u8> {
  let mut data = crate::tls::test_support::build_client_hello(sni);
  sign_client_hello_record(&mut data, secret);
  data
}

/// Крупный ee ClientHello (как у Telegram: ~1700+ байт) с валидным HMAC.
pub fn build_signed_client_hello_min_len(sni: &str, secret: &[u8], min_len: usize) -> Vec<u8> {
  let mut data = crate::tls::test_support::build_client_hello_padded(sni, min_len);
  sign_client_hello_record(&mut data, secret);
  data
}

fn sign_client_hello_record(data: &mut [u8], secret: &[u8]) {
  let mut modified = data.to_vec();
  modified[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_OFFSET + 32].fill(0);

  let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
  mac.update(&modified);
  let digest = mac.finalize().into_bytes();

  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as u32;
  let ts_bytes = now.to_le_bytes();

  for i in 0..28 {
    data[SERVER_HELLO_RANDOM_OFFSET + i] = digest[i];
  }
  for i in 0..4 {
    data[SERVER_HELLO_RANDOM_OFFSET + 28 + i] = digest[28 + i] ^ ts_bytes[i];
  }
}

/// Отправляет синтетический TLS ServerHello + ChangeCipherSpec + padding.
pub async fn send_server_hello<S>(
  stream: &mut S,
  ch: &ParsedClientHello,
  secret: &[u8],
) -> Result<()>
where
  S: AsyncWrite + Unpin,
{
  use tokio::io::AsyncWriteExt;

  let mut packet = build_server_hello_packet(ch);

  for byte in &mut packet[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_OFFSET + 32] {
    *byte = 0;
  }

  let mut mac = HmacSha256::new_from_slice(secret)
    .map_err(|err| StealthGateError::Proxy(format!("HMAC key: {err}")))?;
  mac.update(&ch.random);
  mac.update(&packet);
  let digest = mac.finalize().into_bytes();
  packet[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_OFFSET + 32]
    .copy_from_slice(&digest);

  stream
    .write_all(&packet)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("send ServerHello: {err}")))?;
  stream
    .flush()
    .await
    .map_err(|err| StealthGateError::Proxy(format!("flush ServerHello: {err}")))?;
  Ok(())
}

fn build_server_hello_packet(ch: &ParsedClientHello) -> Vec<u8> {
  let mut out = Vec::new();

  let server_hello = build_server_hello(ch);
  write_tls_record(&mut out, TLS_HANDSHAKE, &server_hello);
  write_tls_record(&mut out, TLS_CHANGE_CIPHER_SPEC, &[0x01]);

  let pad_len = 1024 + (rand::thread_rng().next_u32() as usize % 3072);
  let mut pad = vec![0u8; pad_len];
  rand::thread_rng().fill_bytes(&mut pad);
  write_tls_record(&mut out, TLS_APPLICATION_DATA, &pad);

  out
}

fn build_server_hello(ch: &ParsedClientHello) -> Vec<u8> {
  let mut hello = Vec::new();
  hello.push(0x02);
  hello.extend_from_slice(&[0, 0, 0]);
  hello.extend_from_slice(&[0x03, 0x03]);

  let mut server_random = [0u8; 32];
  rand::thread_rng().fill_bytes(&mut server_random);
  hello.extend_from_slice(&server_random);

  hello.push(ch.session_id.len() as u8);
  hello.extend_from_slice(&ch.session_id);
  hello.extend_from_slice(&ch.cipher_suite.to_be_bytes());
  hello.push(0x00);

  let mut extensions = Vec::new();
  extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

  let mut pub_key = [0u8; 32];
  rand::thread_rng().fill_bytes(&mut pub_key);
  let mut key_share = Vec::new();
  key_share.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]);
  key_share.extend_from_slice(&pub_key);
  extensions.extend_from_slice(&[0x00, 0x33]);
  extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
  extensions.extend_from_slice(&key_share);

  hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
  hello.extend_from_slice(&extensions);

  let body_len = hello.len() - 4;
  hello[1] = ((body_len >> 16) & 0xff) as u8;
  hello[2] = ((body_len >> 8) & 0xff) as u8;
  hello[3] = (body_len & 0xff) as u8;

  hello
}

fn write_tls_record(buf: &mut Vec<u8>, record_type: u8, payload: &[u8]) {
  buf.push(record_type);
  buf.extend_from_slice(&[0x03, 0x03]);
  buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  buf.extend_from_slice(payload);
}

/// Поток с TLS Application Data framing поверх TCP.
pub struct FakeTlsStream<S> {
  inner: S,
  read_buf: Vec<u8>,
  write_opts: Option<FakeTlsWriteOptions>,
  write_size_idx: usize,
  /// Буфер для сборки TLS-записей (peek + хвост ClientHello + следующие кадры).
  tls_stash: Vec<u8>,
}

impl<S> FakeTlsStream<S> {
  pub fn new(inner: S) -> Self {
    Self::with_write_options(inner, None)
  }

  pub fn with_write_options(inner: S, write_opts: Option<FakeTlsWriteOptions>) -> Self {
    Self {
      inner,
      read_buf: Vec::new(),
      write_opts,
      write_size_idx: 0,
      tls_stash: Vec::new(),
    }
  }

  /// Забирает байты, оставшиеся после разбора TLS Application Data (например, хвост кадра с handshake).
  pub fn take_read_buf(&mut self) -> Vec<u8> {
    std::mem::take(&mut self.read_buf)
  }

  fn next_chunk_size(&mut self, remaining: usize) -> usize {
    let Some(opts) = &self.write_opts else {
      return remaining.min(MAX_TLS_PAYLOAD);
    };
    if opts.record_sizes.is_empty() {
      return remaining.min(MAX_TLS_PAYLOAD);
    }
    let size = opts.record_sizes[self.write_size_idx % opts.record_sizes.len()].max(1);
    self.write_size_idx += 1;
    remaining.min(size).min(MAX_TLS_PAYLOAD)
  }

  fn maybe_pad_payload(&self, payload: &mut Vec<u8>) {
    let Some(opts) = &self.write_opts else {
      return;
    };
    if !opts.padding || payload.is_empty() {
      return;
    }
    let pad_budget = MAX_TLS_PAYLOAD.saturating_sub(payload.len());
    if pad_budget == 0 {
      return;
    }
    let pad_len = rand::thread_rng().next_u32() as usize % pad_budget.min(64 + 1);
    if pad_len > 0 {
      let mut pad = vec![0u8; pad_len];
      rand::thread_rng().fill_bytes(&mut pad);
      payload.extend_from_slice(&pad);
    }
  }
}

fn looks_like_tls_record_header(data: &[u8]) -> bool {
  data.len() >= 3
    && matches!(
      data[0],
      TLS_HANDSHAKE | TLS_APPLICATION_DATA | TLS_CHANGE_CIPHER_SPEC
    )
    && data[1] == 0x03
    && matches!(data[2], 0x01 | 0x03)
}

impl<S: AsyncRead + Unpin> FakeTlsStream<S> {
  fn poll_fill_tls_stash(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<usize>> {
    let mut tmp = [0u8; 2048];
    let mut tmp_buf = ReadBuf::new(&mut tmp);
    match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
      Poll::Ready(Ok(())) => {
        let n = tmp_buf.filled().len();
        if n > 0 {
          self.tls_stash.extend_from_slice(&tmp[..n]);
        }
        Poll::Ready(Ok(n))
      }
      Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
      Poll::Pending => Poll::Pending,
    }
  }

  /// Если клиент не дослал хвост ClientHello (0x16), а сразу шлёт obfuscated2 (0x17),
  /// отбрасываем неполную handshake-запись и продолжаем с Application Data.
  fn abandon_incomplete_handshake_if_app_data_follows(stash: &mut Vec<u8>, before: usize) {
    if stash.is_empty() || stash[0] != TLS_HANDSHAKE || before >= stash.len() {
      return;
    }
    if stash[before] == TLS_APPLICATION_DATA && stash.get(before + 1) == Some(&0x03) {
      stash.drain(..before);
    }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for FakeTlsStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    loop {
      if !self.read_buf.is_empty() {
        let to_copy = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..to_copy]);
        self.read_buf.drain(..to_copy);
        return Poll::Ready(Ok(()));
      }

      while self.tls_stash.len() >= 5 {
        let payload_len = u16::from_be_bytes([self.tls_stash[3], self.tls_stash[4]]) as usize;
        if payload_len > MAX_TLS_PAYLOAD + 2048 {
          return Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record too large",
          )));
        }
        let total = 5 + payload_len;

        if self.tls_stash.len() >= total {
          let record_type = self.tls_stash[0];
          let payload = self.tls_stash[5..total].to_vec();
          self.tls_stash.drain(..total);
          if record_type == TLS_APPLICATION_DATA {
            self.read_buf = payload;
            break;
          }
          continue;
        }

        let before = self.tls_stash.len();
        match self.as_mut().poll_fill_tls_stash(cx) {
          Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
          Poll::Ready(Ok(_)) => {
            Self::abandon_incomplete_handshake_if_app_data_follows(&mut self.tls_stash, before);
            if self.tls_stash.len() == before {
              return Poll::Pending;
            }
          }
          Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
          Poll::Pending => return Poll::Pending,
        }
      }

      if !self.read_buf.is_empty() {
        continue;
      }

      if self.tls_stash.len() < 5 {
        match self.as_mut().poll_fill_tls_stash(cx) {
          Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
          Poll::Ready(Ok(_)) => {}
          Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
          Poll::Pending => return Poll::Pending,
        }
      }

      if self.tls_stash.len() >= 5 && !looks_like_tls_record_header(&self.tls_stash) {
        if let Some(pos) = self
          .tls_stash
          .windows(3)
          .position(looks_like_tls_record_header)
        {
          self.tls_stash.drain(..pos);
        }
      }
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FakeTlsStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let mut offset = 0usize;
    while offset < buf.len() {
      let chunk_end = offset + self.next_chunk_size(buf.len() - offset);
      let chunk = &buf[offset..chunk_end];
      let mut payload = chunk.to_vec();
      self.maybe_pad_payload(&mut payload);
      let mut record = Vec::with_capacity(5 + payload.len());
      write_tls_record(&mut record, TLS_APPLICATION_DATA, &payload);
      let mut written = 0usize;
      while written < record.len() {
        match Pin::new(&mut self.inner).poll_write(cx, &record[written..]) {
          Poll::Ready(Ok(0)) => {
            return Poll::Ready(Err(std::io::Error::new(
              std::io::ErrorKind::WriteZero,
              "write zero",
            )));
          }
          Poll::Ready(Ok(n)) => written += n,
          Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
          Poll::Pending => {
            if offset > 0 || written > 0 {
              return Poll::Ready(Ok(offset));
            }
            return Poll::Pending;
          }
        }
      }
      offset = chunk_end;
    }
    Poll::Ready(Ok(buf.len()))
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tls::test_support::build_client_hello;

  #[test]
  fn parses_client_hello_record() {
    let data = build_client_hello("www.cloudflare.com");
    let ch = parse_client_hello_record(&data).expect("parse");
    assert_eq!(ch.sni.as_deref(), Some("www.cloudflare.com"));
    assert_eq!(ch.raw.len(), data.len());
  }
}
