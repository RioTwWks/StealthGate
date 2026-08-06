use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{
  decode_secret, DdConfig, DrsConfig, FragmentationConfig, NetworkConfig, SecretMode,
  WebhooksConfig,
};
use crate::dd_protocol;
use crate::drs;
use crate::error::{Result, StealthGateError};
use crate::faketls::{self, FakeTlsStream};
use crate::fragmentation;
use crate::mtproto_obfuscate::{self, ObfuscatedStream};
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
  if options.secret_mode == SecretMode::Ee {
    return proxy_mtproto_ee(client, initial_data, state, options).await;
  }

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

/// Проксирует ee Fake TLS: ServerHello клиенту, obfuscated2 к Telegram DC.
pub async fn proxy_mtproto_ee(
  mut client: TcpStream,
  initial_data: &[u8],
  state: &AppState,
  options: &MtprotoProxyOptions<'_>,
) -> Result<()> {
  let secret = resolve_secret_bytes(state, None)?;

  let client_hello = faketls::parse_client_hello_record(initial_data)?;
  faketls::validate_client_hello(&client_hello, &secret)?;
  faketls::send_server_hello(&mut client, &client_hello, &secret).await?;

  let pool = state
    .backend_pool
    .read()
    .map_err(|_| StealthGateError::Config("блокировка backend_pool poisoned".into()))?
    .clone();
  let (upstream, connected_backend) = pool
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

  let (c2s, s2c) = relay_ee_streams(
    FakeTlsStream::with_write_options(
      client,
      crate::faketls::FakeTlsWriteOptions::from_drs(options.drs),
    ),
    upstream,
    &secret,
    options.preferred_backend,
    options.drs,
  )
  .await?;

  state
    .stats
    .bytes_to_backend
    .fetch_add(c2s + initial_data.len() as u64, std::sync::atomic::Ordering::Relaxed);
  state
    .stats
    .bytes_from_backend
    .fetch_add(s2c, std::sync::atomic::Ordering::Relaxed);

  tracing::debug!(
    backend = %connected_backend,
    client_to_upstream = c2s,
    upstream_to_client = s2c,
    secret_mode = ?options.secret_mode,
    "ee MTProto-сессия завершена"
  );

  Ok(())
}

/// Мост ee Fake TLS (front/back) ↔ obfuscated2 Telegram DC.
pub async fn relay_ee_streams<C, U>(
  client_io: C,
  mut upstream: U,
  secret: &[u8],
  preferred_backend: &str,
  _drs: &DrsConfig,
) -> Result<(u64, u64)>
where
  C: AsyncRead + AsyncWrite + Unpin,
  U: AsyncRead + AsyncWrite + Unpin,
{
  let accepted = mtproto_obfuscate::accept_handshake(client_io, secret).await?;
  let dc_id = if accepted.dc_id != 0 {
    accepted.dc_id
  } else {
    mtproto_obfuscate::dc_id_from_backend(preferred_backend)
  };

  let (header, relay_keys) = mtproto_obfuscate::generate_relay_init(dc_id, accepted.proto_tag)?;
  upstream
    .write_all(&header)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("ee relay header to DC: {err}")))?;
  upstream
    .flush()
    .await
    .map_err(|err| StealthGateError::Proxy(format!("ee relay flush to DC: {err}")))?;

  let dc_stream = ObfuscatedStream::from_relay_keys(upstream, relay_keys);
  copy_bidirectional_graceful(accepted.stream, dc_stream).await
}

/// Мост ee Fake TLS → уже инициализированный obfuscated2-поток к DC (relay init уже отправлен).
pub async fn relay_ee_to_prepared_dc<C, U>(
  client_io: C,
  dc_stream: ObfuscatedStream<U>,
  secret: &[u8],
) -> Result<(u64, u64)>
where
  C: AsyncRead + AsyncWrite + Unpin,
  U: AsyncRead + AsyncWrite + Unpin,
{
  let accepted = mtproto_obfuscate::accept_handshake(client_io, secret).await?;
  copy_bidirectional(accepted.stream, dc_stream).await
}

pub(crate) fn resolve_secret_bytes(state: &AppState, label: Option<&str>) -> Result<Vec<u8>> {
  let routes = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.mtproto.all_secrets()
  };

  let route = label
    .and_then(|name| routes.iter().find(|route| route.label == name))
    .or(routes.first())
    .ok_or_else(|| StealthGateError::Config("не задан MTProto-секрет".into()))?;

  decode_secret(&route.secret)
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
  copy_bidirectional_graceful(left, right).await
}

fn is_benign_copy_error(err: &std::io::Error) -> bool {
  matches!(
    err.kind(),
    std::io::ErrorKind::BrokenPipe
      | std::io::ErrorKind::ConnectionReset
      | std::io::ErrorKind::UnexpectedEof
  )
}

/// Как copy_bidirectional, но не падает, если одна сторона закрыла соединение.
pub async fn copy_bidirectional_graceful<L, R>(left: L, right: R) -> Result<(u64, u64)>
where
  L: AsyncRead + AsyncWrite + Unpin,
  R: AsyncRead + AsyncWrite + Unpin,
{
  let (mut left_read, mut left_write) = tokio::io::split(left);
  let (mut right_read, mut right_write) = tokio::io::split(right);

  let client_to_server = async {
    match tokio::io::copy(&mut left_read, &mut right_write).await {
      Ok(n) => Ok(n),
      Err(err) if is_benign_copy_error(&err) => Ok(0),
      Err(err) => Err(err),
    }
  };
  let server_to_client = async {
    match tokio::io::copy(&mut right_read, &mut left_write).await {
      Ok(n) => Ok(n),
      Err(err) if is_benign_copy_error(&err) => Ok(0),
      Err(err) => Err(err),
    }
  };

  let (c2s, s2c) = tokio::try_join!(client_to_server, server_to_client).map_err(|err| {
    StealthGateError::Proxy(format!("ошибка copy_bidirectional: {err}"))
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
