use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::{FragmentationConfig, NetworkConfig};
use crate::error::{Result, StealthGateError};
use crate::fragmentation;
use crate::network;
use crate::state::Stats;

/// Проксирует MTProto-трафик на backend Telegram.
pub async fn proxy_mtproto(
  client: TcpStream,
  initial_data: &[u8],
  backend: &str,
  frag_config: &FragmentationConfig,
  network: &NetworkConfig,
  stats: &Stats,
) -> Result<()> {
  let mut upstream = network::connect_backend(backend, network).await?;

  fragmentation::write_to_backend(&mut upstream, initial_data, frag_config, stats).await?;
  stats
    .bytes_to_backend
    .fetch_add(initial_data.len() as u64, std::sync::atomic::Ordering::Relaxed);

  let (client_to_upstream, upstream_to_client) =
    copy_bidirectional(client, upstream).await?;

  stats
    .bytes_to_backend
    .fetch_add(client_to_upstream, std::sync::atomic::Ordering::Relaxed);
  stats
    .bytes_from_backend
    .fetch_add(upstream_to_client, std::sync::atomic::Ordering::Relaxed);

  tracing::debug!(
    client_to_upstream,
    upstream_to_client,
    "MTProto-сессия завершена"
  );

  Ok(())
}

/// Двунаправленное копирование между двумя потоками.
pub async fn copy_bidirectional<L, R>(left: L, right: R) -> Result<(u64, u64)>
where
  L: AsyncRead + AsyncWrite + Unpin,
  R: AsyncRead + AsyncWrite + Unpin,
{
  let (mut left_read, mut left_write) = tokio::io::split(left);
  let (mut right_read, mut right_write) = tokio::io::split(right);

  let client_to_server = tokio::io::copy(&mut left_read, &mut right_write);
  let server_to_client = tokio::io::copy(&mut right_read, &mut left_write);

  let (c2s, s2c) = tokio::try_join!(client_to_server, server_to_client).map_err(|err| {
    StealthGateError::Proxy(format!("ошибка copy_bidirectional: {err}"))
  })?;

  Ok((c2s, s2c))
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

  #[tokio::test]
  async fn copy_bidirectional_transfers_data() {
    let (mut client_a, server_a) = duplex(1024);
    let (server_b, mut client_b) = duplex(1024);

    client_a
      .write_all(b"ping")
      .await
      .expect("write client_a");

    let handle = tokio::spawn(async move {
      copy_bidirectional(server_a, server_b)
        .await
        .expect("copy")
    });

    let mut buf = [0u8; 4];
    client_b.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"ping");

    drop(client_a);
    drop(client_b);
    let (c2s, s2c) = handle.await.expect("join");
    assert_eq!(c2s, 4);
    assert_eq!(s2c, 0);
  }
}
