//! Decoy TLS — ответ на probe без раскрытия MTProto Fake TLS.

use rand::RngCore;
use tokio::io::AsyncWriteExt;

use crate::error::{Result, StealthGateError};
use crate::tls::looks_like_tls_client_hello;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_ALERT: u8 = 0x15;

/// Отвечает на чужой TLS ClientHello обычным ServerHello + alert (не ee MTProto).
pub async fn serve_decoy<S>(mut stream: S, initial_data: &[u8]) -> Result<()>
where
  S: tokio::io::AsyncWrite + Unpin,
{
  if !looks_like_tls_client_hello(initial_data) {
    return Ok(());
  }

  let packet = build_decoy_response(initial_data);
  stream
    .write_all(&packet)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("decoy TLS write: {err}")))?;
  stream
    .flush()
    .await
    .map_err(|err| StealthGateError::Proxy(format!("decoy TLS flush: {err}")))?;
  Ok(())
}

/// Собирает ServerHello (без MTProto HMAC) + handshake_failure alert.
pub fn build_decoy_response(client_hello: &[u8]) -> Vec<u8> {
  let session_id_len = client_hello
    .get(43)
    .copied()
    .unwrap_or(0) as usize;
  let session_id = if client_hello.len() > 44 + session_id_len {
    &client_hello[44..44 + session_id_len]
  } else {
    &[]
  };

  let mut out = Vec::new();

  let mut server_hello = Vec::new();
  server_hello.push(0x02);
  server_hello.extend_from_slice(&[0x00, 0x00, 0x00]);
  server_hello.extend_from_slice(&[0x03, 0x03]);

  let mut server_random = [0u8; 32];
  rand::thread_rng().fill_bytes(&mut server_random);
  server_hello.extend_from_slice(&server_random);

  server_hello.push(session_id.len() as u8);
  server_hello.extend_from_slice(session_id);
  server_hello.extend_from_slice(&[0x13, 0x01]);
  server_hello.push(0x00);

  let extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
  server_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
  server_hello.extend_from_slice(&extensions);

  let body_len = server_hello.len() - 4;
  server_hello[1] = ((body_len >> 16) & 0xff) as u8;
  server_hello[2] = ((body_len >> 8) & 0xff) as u8;
  server_hello[3] = (body_len & 0xff) as u8;

  write_tls_record(&mut out, TLS_HANDSHAKE, &server_hello);
  write_tls_record(&mut out, TLS_ALERT, &[0x02, 0x28]);

  out
}

fn write_tls_record(buf: &mut Vec<u8>, record_type: u8, payload: &[u8]) {
  buf.push(record_type);
  buf.extend_from_slice(&[0x03, 0x03]);
  buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  buf.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tls::test_support::build_client_hello;

  #[test]
  fn decoy_does_not_use_mtproto_padding_record() {
    let ch = build_client_hello("www.cloudflare.com");
    let response = build_decoy_response(&ch);
    assert!(response.starts_with(&[TLS_HANDSHAKE, 0x03, 0x03]));
    assert!(response.windows(2).any(|w| w == [0x02, 0x28]));
    assert!(response.len() < 512, "decoy should be compact, not ee padding blob");
  }
}
