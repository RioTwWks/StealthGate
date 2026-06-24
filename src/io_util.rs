use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Поток с уже прочитанным префиксом (для TLS handshake после peek).
pub struct PrefixedStream<S> {
  prefix: io::Cursor<Vec<u8>>,
  inner: S,
}

impl<S> PrefixedStream<S> {
  /// Создаёт поток с буфером, прочитанным до основного сокета.
  pub fn new(prefix: Vec<u8>, inner: S) -> Self {
    Self {
      prefix: io::Cursor::new(prefix),
      inner,
    }
  }

  /// Возвращает внутренний поток.
  pub fn into_inner(self) -> S {
    self.inner
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.prefix.position() < self.prefix.get_ref().len() as u64 {
      let pos = self.prefix.position() as usize;
      let data = &self.prefix.get_ref()[pos..];
      let to_copy = data.len().min(buf.remaining());
      buf.put_slice(&data[..to_copy]);
      self.prefix.set_position((pos + to_copy) as u64);
      return Poll::Ready(Ok(()));
    }

    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::AsyncReadExt;

  #[tokio::test]
  async fn prefixed_stream_reads_prefix_first() {
    let (client, server) = tokio::io::duplex(64);
    tokio::spawn(async move {
      use tokio::io::AsyncWriteExt;
      let mut server = server;
      server.write_all(b"world").await.ok();
    });

    let mut prefixed = PrefixedStream::new(b"hello".to_vec(), client);
    let mut buf = String::new();
    prefixed.read_to_string(&mut buf).await.expect("read");
    assert_eq!(buf, "helloworld");
  }
}
