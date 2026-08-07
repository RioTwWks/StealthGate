//! ChaCha20-Poly1305 шифрование SGFB relay (v2) после opening frame + ACK.

use std::pin::Pin;
use std::task::{Context, Poll};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Result, StealthGateError};

pub const PROTOCOL_VERSION_PLAIN: u8 = 1;
pub const PROTOCOL_VERSION_ENCRYPTED: u8 = 2;

const MAX_FRAME_PLAIN: usize = 16_384;
const MAX_FRAME_CIPHER: usize = MAX_FRAME_PLAIN + 16;

/// Пара ключей для bidirectional SGFB v2.
#[derive(Clone)]
pub struct SessionKeys {
  pub client_to_server: Key,
  pub server_to_client: Key,
}

/// Выводит симметричные ключи из auth_token и полного opening-кадра.
pub fn derive_session_keys(auth_token: &str, opening_frame: &[u8]) -> SessionKeys {
  let frame_hash = Sha256::digest(opening_frame);

  let mut c2s = Sha256::new();
  c2s.update(b"SGFB-v2-c2s");
  c2s.update(auth_token.as_bytes());
  c2s.update(frame_hash);

  let mut s2c = Sha256::new();
  s2c.update(b"SGFB-v2-s2c");
  s2c.update(auth_token.as_bytes());
  s2c.update(frame_hash);

  SessionKeys {
    client_to_server: Key::from_slice(&c2s.finalize()).to_owned(),
    server_to_client: Key::from_slice(&s2c.finalize()).to_owned(),
  }
}

struct DirectionCipher {
  cipher: ChaCha20Poly1305,
  nonce: u64,
}

impl DirectionCipher {
  fn new(key: &Key) -> Self {
    Self {
      cipher: ChaCha20Poly1305::new(key),
      nonce: 0,
    }
  }

  fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = build_nonce(self.nonce);
    self.nonce = self.nonce.saturating_add(1);
    self
      .cipher
      .encrypt(&nonce, plaintext)
      .map_err(|err| StealthGateError::Proxy(format!("SGFB encrypt: {err}")))
  }

  fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce = build_nonce(self.nonce);
    self.nonce = self.nonce.saturating_add(1);
    self
      .cipher
      .decrypt(&nonce, ciphertext)
      .map_err(|err| StealthGateError::Proxy(format!("SGFB decrypt: {err}")))
  }
}

fn build_nonce(counter: u64) -> Nonce {
  let mut bytes = [0u8; 12];
  bytes[4..12].copy_from_slice(&counter.to_be_bytes());
  Nonce::from_slice(&bytes).to_owned()
}

/// Оборачивает TCP-поток в AEAD-фреймы: `u16_be len | ciphertext`.
pub struct EncryptedStream<S> {
  inner: S,
  encrypt: DirectionCipher,
  decrypt: DirectionCipher,
  read_buf: Vec<u8>,
  pending_plain: Vec<u8>,
  header_buf: [u8; 2],
  header_filled: usize,
  frame_len: Option<usize>,
  frame_filled: usize,
  frame_buf: Vec<u8>,
  write_pending: Vec<u8>,
}

impl<S> EncryptedStream<S> {
  /// Front: шифрует исходящий трафик ключом c2s, расшифровывает входящий s2c.
  pub fn client_side(inner: S, keys: SessionKeys) -> Self {
    Self::new(
      inner,
      DirectionCipher::new(&keys.client_to_server),
      DirectionCipher::new(&keys.server_to_client),
    )
  }

  /// Back: зеркально front.
  pub fn server_side(inner: S, keys: SessionKeys) -> Self {
    Self::new(
      inner,
      DirectionCipher::new(&keys.server_to_client),
      DirectionCipher::new(&keys.client_to_server),
    )
  }

  fn new(inner: S, encrypt: DirectionCipher, decrypt: DirectionCipher) -> Self {
    Self {
      inner,
      encrypt,
      decrypt,
      read_buf: Vec::new(),
      pending_plain: Vec::new(),
      header_buf: [0u8; 2],
      header_filled: 0,
      frame_len: None,
      frame_filled: 0,
      frame_buf: Vec::new(),
      write_pending: Vec::new(),
    }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    loop {
      if !self.pending_plain.is_empty() {
        let to_copy = self.pending_plain.len().min(buf.remaining());
        buf.put_slice(&self.pending_plain[..to_copy]);
        self.pending_plain.drain(..to_copy);
        return Poll::Ready(Ok(()));
      }

      if self.read_buf.is_empty() {
        if self.frame_len.is_none() {
          while self.header_filled < 2 {
            let mut tmp = [0u8; 1];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
              Poll::Ready(Ok(())) => {
                if tmp_buf.filled().is_empty() {
                  return Poll::Ready(Ok(()));
                }
                let idx = self.header_filled;
                self.header_buf[idx] = tmp[0];
                self.header_filled += 1;
              }
              Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
              Poll::Pending => return Poll::Pending,
            }
          }
          let len = u16::from_be_bytes(self.header_buf) as usize;
          self.header_filled = 0;
          if len == 0 || len > MAX_FRAME_CIPHER {
            return Poll::Ready(Err(std::io::Error::new(
              std::io::ErrorKind::InvalidData,
              format!("SGFB invalid frame len: {len}"),
            )));
          }
          self.frame_len = Some(len);
          self.frame_buf.resize(len, 0);
          self.frame_filled = 0;
        }

        let needed = self.frame_len.expect("frame len");
        if self.frame_filled < needed {
          let mut tmp = [0u8; 1024];
          let to_read = (needed - self.frame_filled).min(tmp.len());
          let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
          match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
              let n = tmp_buf.filled().len();
              if n == 0 {
                return Poll::Ready(Ok(()));
              }
              let filled = self.frame_filled;
              self.frame_buf[filled..filled + n].copy_from_slice(&tmp[..n]);
              self.frame_filled += n;
              if self.frame_filled < needed {
                return Poll::Pending;
              }
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
          }
        }

        let ciphertext = std::mem::take(&mut self.frame_buf);
        self.frame_len = None;
        self.frame_filled = 0;

        match self.decrypt.open(&ciphertext) {
          Ok(plain) => self.read_buf = plain,
          Err(err) => {
            return Poll::Ready(Err(std::io::Error::new(
              std::io::ErrorKind::InvalidData,
              err.to_string(),
            )));
          }
        }
        continue;
      }

      if !self.read_buf.is_empty() {
        let to_copy = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..to_copy]);
        self.read_buf.drain(..to_copy);
        return Poll::Ready(Ok(()));
      }
    }
  }
}

impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
  fn drain_write_pending(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    while !self.write_pending.is_empty() {
      let pending = std::mem::take(&mut self.write_pending);
      match Pin::new(&mut self.inner).poll_write(cx, &pending) {
        Poll::Ready(Ok(0)) => {
          self.write_pending = pending;
          return Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "write zero",
          )));
        }
        Poll::Ready(Ok(n)) if n < pending.len() => {
          self.write_pending = pending[n..].to_vec();
          return Poll::Pending;
        }
        Poll::Ready(Ok(_)) => {}
        Poll::Ready(Err(err)) => {
          self.write_pending = pending;
          return Poll::Ready(Err(err));
        }
        Poll::Pending => {
          self.write_pending = pending;
          return Poll::Pending;
        }
      }
    }
    Poll::Ready(Ok(()))
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    match self.as_mut().drain_write_pending(cx) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
      Poll::Pending => return Poll::Pending,
    }

    if buf.is_empty() {
      return Poll::Ready(Ok(0));
    }

    let chunk_end = buf.len().min(MAX_FRAME_PLAIN);
    let chunk = &buf[..chunk_end];
    let ciphertext = match self.encrypt.seal(chunk) {
      Ok(value) => value,
      Err(err) => {
        return Poll::Ready(Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          err.to_string(),
        )));
      }
    };

    let mut frame = Vec::with_capacity(2 + ciphertext.len());
    frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    self.write_pending = frame;

    match self.as_mut().drain_write_pending(cx) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk_end)),
      Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
      Poll::Pending => Poll::Pending,
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.as_mut().drain_write_pending(cx) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
      Poll::Pending => return Poll::Pending,
    }
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    match self.as_mut().poll_flush(cx) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
      Poll::Pending => return Poll::Pending,
    }
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[tokio::test]
  async fn encrypted_stream_roundtrip() {
    let keys = derive_session_keys("test-token-12345678", b"opening-frame-bytes");

    let (client_io, server_io) = tokio::io::duplex(8192);
    let (mut client, mut server) = (
      EncryptedStream::client_side(client_io, keys.clone()),
      EncryptedStream::server_side(server_io, keys),
    );

    let payload = b"obfuscated2-mtproto-payload";
    client.write_all(payload).await.expect("client write");
    client.flush().await.expect("client flush");

    let mut server_buf = vec![0u8; payload.len()];
    server
      .read_exact(&mut server_buf)
      .await
      .expect("server read");
    assert_eq!(&server_buf, payload);

    server.write_all(b"pong").await.expect("server write");
    server.flush().await.expect("server flush");

    let mut client_buf = [0u8; 4];
    client.read_exact(&mut client_buf).await.expect("client read");
    assert_eq!(&client_buf, b"pong");
  }

  #[test]
  fn derive_keys_differs_by_frame() {
    let k1 = derive_session_keys("token", b"frame-a");
    let k2 = derive_session_keys("token", b"frame-b");
    assert_ne!(k1.client_to_server, k2.client_to_server);
  }

  #[tokio::test]
  async fn encrypted_stream_handles_split_frame_header() {
    let payload = b"mtproto-init-payload";

    // Собираем полный AEAD-кадр и режем заголовок на 2 части по 1 байту.
    let mut wire = Vec::new();
    {
      let (left, right) = tokio::io::duplex(8192);
      let (mut enc, mut raw) = (
        EncryptedStream::client_side(left, derive_session_keys("test-token-12345678", b"opening-frame-bytes")),
        right,
      );
      enc.write_all(payload).await.expect("encode");
      enc.flush().await.expect("flush");
      drop(enc);
      raw.read_to_end(&mut wire).await.expect("read wire");
    }
    assert!(wire.len() > 2);

    let (left, right) = tokio::io::duplex(wire.len() + 16);
    tokio::spawn(async move {
      use tokio::io::AsyncWriteExt;
      let mut left = left;
      left.write_all(&wire[..1]).await.expect("byte 0");
      left.write_all(&wire[1..2]).await.expect("byte 1");
      left.write_all(&wire[2..]).await.expect("body");
      left.shutdown().await.ok();
    });

    let mut split_server = EncryptedStream::server_side(right, derive_session_keys("test-token-12345678", b"opening-frame-bytes"));
    let mut server_buf = vec![0u8; payload.len()];
    split_server
      .read_exact(&mut server_buf)
      .await
      .expect("split header read");
    assert_eq!(&server_buf, payload);
  }
}
