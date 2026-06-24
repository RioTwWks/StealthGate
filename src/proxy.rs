use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::{
  DdConfig, DrsConfig, FragmentationConfig, NetworkConfig, SecretMode, WebhooksConfig,
};
use crate::dd_protocol;
use crate::drs;
use crate::error::Result;
use crate::fragmentation;
use crate::state::AppState;
use crate::webhooks::{dispatch, WebhookEvent};

/// Параметры MTProto-проксирования для одного соединения.
pub struct MtprotoProxyOptions<'a> {
  pub preferred_backend: &'a str,
  pub secret_mode: SecretMode,
  pub fragmentation: &'a FragmentationConfig,
  pub drs: &'a DrsConfig,
  pub dd: &'a DdConfig,
  pub network: &'a NetworkConfig,
  pub webhooks: &'a WebhooksConfig,
}

/// Проксирует MTProto-трафик на backend Telegram с failover.
pub async fn proxy_mtproto(
  client: TcpStream,
  initial_data: &[u8],
  state: &AppState,
  options: &MtprotoProxyOptions<'_>,
) -> Result<()> {
  let pool = state
    .backend_pool
    .read()
    .map_err(|_| crate::error::StealthGateError::Config("блокировка backend_pool poisoned".into()))?
    .clone();
  let (mut upstream, connected_backend) = pool
    .connect(options.network, Some(options.preferred_backend), &state.stats)
    .await?;

  if connected_backend != options.preferred_backend {
    dispatch(
      options.webhooks,
      WebhookEvent::BackendFailover,
      Some(serde_json::json!({
        "preferred": options.preferred_backend,
        "connected": connected_backend,
      })),
    );
  }

  write_initial_to_backend(
    &mut upstream,
    initial_data,
    options.secret_mode,
    options.fragmentation,
    options.drs,
    options.dd,
    &state.stats,
  )
  .await?;

  state
    .stats
    .bytes_to_backend
    .fetch_add(initial_data.len() as u64, std::sync::atomic::Ordering::Relaxed);

  let (client_to_upstream, upstream_to_client) =
    copy_bidirectional(client, upstream).await?;

  state
    .stats
    .bytes_to_backend
    .fetch_add(client_to_upstream, std::sync::atomic::Ordering::Relaxed);
  state
    .stats
    .bytes_from_backend
    .fetch_add(upstream_to_client, std::sync::atomic::Ordering::Relaxed);

  tracing::debug!(
    backend = %connected_backend,
    client_to_upstream,
    upstream_to_client,
    secret_mode = ?options.secret_mode,
    "MTProto-сессия завершена"
  );

  Ok(())
}

/// Записывает начальный пакет с учётом режима секрета и DRS.
pub async fn write_initial_to_backend(
  stream: &mut TcpStream,
  data: &[u8],
  secret_mode: SecretMode,
  fragmentation: &FragmentationConfig,
  drs_config: &DrsConfig,
  dd_config: &DdConfig,
  stats: &crate::state::Stats,
) -> Result<()> {
  match secret_mode {
    SecretMode::Dd => dd_protocol::write_dd_randomized(stream, data, dd_config, stats).await,
    _ if drs_config.enabled => drs::write_with_drs(stream, data, drs_config, stats).await,
    _ => fragmentation::write_to_backend(stream, data, fragmentation, stats).await,
  }
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
    crate::error::StealthGateError::Proxy(format!("ошибка copy_bidirectional: {err}"))
  })?;

  Ok((c2s, s2c))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::backend_pool::BackendPool;
  use crate::config::{BackendFailoverStrategy, MtprotoConfig};
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

  #[test]
  fn backend_pool_collects_primary_and_extra() {
    let mtproto = MtprotoConfig {
      secret: "ee0123456789abcdef0123456789abcdef".into(),
      backend: "1.1.1.1:443".into(),
      backends: vec!["2.2.2.2:443".into()],
      failover_strategy: BackendFailoverStrategy::Priority,
      secrets: Vec::new(),
    };
    assert_eq!(mtproto.all_backends().len(), 2);
    let _pool = BackendPool::from_config(&mtproto);
  }
}
