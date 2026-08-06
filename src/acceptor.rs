use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::admin;
use crate::antireplay::client_hello_fingerprint;
use crate::config::{Config, SecretMode, SplitMode};
use crate::detector::{
  classify_peek, fallback_diagnostic_message, DetectionResult, Detector, TrafficType,
};
use crate::domain_fronting::{forward_tcp, resolve_fronting_target};
use crate::error::{Result, StealthGateError};
use crate::fallback;
use crate::metrics;
use crate::proxy;
use crate::split;
use crate::state::AppState;
use crate::tls::{
  compute_ja4, ja4_matches_any, looks_like_tls_client_hello, parse_client_hello, parse_record,
  tls_record_total_len,
};
use crate::tls_server;

const PEEK_BUFFER_SIZE: usize = 4096;
const PEEK_READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Читает начальный буфер, дочитывая неполные TLS-записи (крупный ee ClientHello).
async fn read_initial_peek(client: &mut TcpStream) -> Result<Vec<u8>> {
  let mut buf = vec![0u8; PEEK_BUFFER_SIZE];
  let n = client
    .read(&mut buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("чтение начальных данных: {err}")))?;
  if n == 0 {
    return Ok(Vec::new());
  }
  let mut total = n;

  if let Some(needed) = tls_record_total_len(&buf[..total]) {
    if needed > PEEK_BUFFER_SIZE {
      return Err(StealthGateError::Proxy(format!(
        "TLS-запись слишком большая для peek: {needed} > {PEEK_BUFFER_SIZE}"
      )));
    }
    // ClientHello: клиент ждёт ServerHello перед остатком записи — не блокируем peek.
    if looks_like_tls_client_hello(&buf[..total]) && total < needed {
      tracing::trace!(
        peek_len = total,
        needed,
        "peek: неполный ClientHello, дочитывание отложено до ServerHello в relay"
      );
    } else if total < needed {
      while total < needed {
        let to_read = (needed - total).min(PEEK_BUFFER_SIZE - total);
        match tokio::time::timeout(PEEK_READ_TIMEOUT, client.read(&mut buf[total..total + to_read]))
          .await
        {
          Ok(Ok(0)) => break,
          Ok(Ok(n)) => total += n,
          Ok(Err(err)) => {
            return Err(StealthGateError::Proxy(format!(
              "дочитывание TLS-записи: {err}"
            )));
          }
          Err(_) => break,
        }
      }
    }
    if total < needed {
      tracing::debug!(
        peek_len = total,
        needed,
        "неполная TLS-запись после таймаута дочитывания"
      );
    }
  }

  buf.truncate(total);
  Ok(buf)
}

struct ConnectionContext {
  fake_domains: Vec<String>,
  default_backend: String,
  fragmentation: crate::config::FragmentationConfig,
  fallback_cfg: crate::config::FallbackConfig,
  network: crate::config::NetworkConfig,
  tls_enabled: bool,
  ja4_profiles: Vec<String>,
  ja4_enforce: bool,
  max_connections_per_ip: u32,
}

/// Обрабатывает одно входящее соединение.
pub async fn handle_connection(mut client: TcpStream, state: Arc<AppState>) -> Result<()> {
  let peer_ip = client
    .peer_addr()
    .ok()
    .map(|addr| addr.ip())
    .unwrap_or(IpAddr::from([0, 0, 0, 0]));

  state.stats.total_connections.fetch_add(1, Ordering::Relaxed);

  let peek_buf = read_initial_peek(&mut client).await?;

  if peek_buf.is_empty() {
    return Ok(());
  }

  let ctx = load_connection_context(&state)?;
  let blacklist = state.ip_blacklist()?;

  let detection = detect_with_security(
    &state,
    &peek_buf,
    &ctx.fake_domains,
    &ctx.ja4_profiles,
    ctx.ja4_enforce,
  )?;

  tracing::debug!(
    traffic = ?detection.traffic_type,
    sni = ?detection.sni,
    peek_len = peek_buf.len(),
    peek_prefix = %hex::encode(&peek_buf[..peek_buf.len().min(8)]),
    "детекция входящего соединения"
  );

  if detection.traffic_type == TrafficType::Mtproto {
    let label = detection.secret_label.as_deref().unwrap_or("default");
    state.limits.acquire(
      peer_ip,
      label,
      ctx.max_connections_per_ip,
      detection.max_connections,
      &blacklist,
    )?;
  }

  let result = match detection.traffic_type {
    TrafficType::Mtproto => {
      handle_mtproto(client, &peek_buf, &ctx, &detection, &state).await
    }
    TrafficType::Fallback => {
      handle_fallback_path(client, peek_buf, &ctx, &detection, &state).await
    }
  };

  if detection.traffic_type == TrafficType::Mtproto {
    let label = detection.secret_label.as_deref().unwrap_or("default");
    state.limits.release(
      peer_ip,
      label,
      ctx.max_connections_per_ip,
      detection.max_connections,
    );
  }

  result
}

fn load_connection_context(state: &AppState) -> Result<ConnectionContext> {
  let config = state
    .config
    .read()
    .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
  Ok(ConnectionContext {
    fake_domains: config.tls.all_sni_domains(),
    default_backend: config.mtproto.backend.clone(),
    fragmentation: config.fragmentation.clone(),
    fallback_cfg: config.fallback.clone(),
    network: config.network.clone(),
    tls_enabled: config.tls.is_enabled(),
    ja4_profiles: config.tls.all_fingerprint_profiles(),
    ja4_enforce: config.security.ja4_enforce,
    max_connections_per_ip: config.security.max_connections_per_ip,
  })
}

fn detect_with_security(
  state: &AppState,
  peek_buf: &[u8],
  fake_domains: &[String],
  ja4_profiles: &[String],
  ja4_enforce: bool,
) -> Result<DetectionResult> {
  if looks_like_tls_client_hello(peek_buf) {
    let fingerprint = client_hello_fingerprint(peek_buf);
    if state.antireplay.is_replay(fingerprint) {
      state.stats.replay_blocked.fetch_add(1, Ordering::Relaxed);
      tracing::debug!("replay ClientHello — domain fronting");
      let sni = extract_sni(peek_buf);
      return Ok(DetectionResult {
        traffic_type: TrafficType::Fallback,
        sni,
        secret_label: None,
        secret_mode: None,
        backend: None,
        max_connections: 0,
      });
    }
  }

  let routes = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.mtproto.all_secrets()
  };

  let detector = Detector::from_routes(&routes, fake_domains)?;
  let mut detection = detector.detect(peek_buf);

  log_ja4(peek_buf, ja4_profiles);

  if detection.traffic_type == TrafficType::Mtproto
    && ja4_enforce
    && !ja4_allowed(peek_buf, ja4_profiles)
  {
    tracing::info!("JA4 enforce: соединение переведено в fallback");
    detection.traffic_type = TrafficType::Fallback;
    detection.secret_label = None;
    detection.secret_mode = None;
    detection.backend = None;
    detection.max_connections = 0;
  }

  Ok(detection)
}

async fn handle_mtproto(
  client: TcpStream,
  peek_buf: &[u8],
  ctx: &ConnectionContext,
  detection: &DetectionResult,
  state: &AppState,
) -> Result<()> {
  state.stats.mtproto_connections.fetch_add(1, Ordering::Relaxed);
  let backend = detection
    .backend
    .as_deref()
    .filter(|value| !value.is_empty())
    .unwrap_or(&ctx.default_backend);
  let secret_mode = detection
    .secret_mode
    .unwrap_or(SecretMode::Classic);

  let (drs, dd, webhooks, split_cfg) = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    (
      config.drs.clone(),
      config.dd.clone(),
      config.webhooks.clone(),
      config.split.clone(),
    )
  };

  tracing::info!(
    sni = ?detection.sni,
    backend = %backend,
    secret = ?detection.secret_label,
    ?secret_mode,
    split = ?split_cfg.mode,
    fragmented = ctx.fragmentation.enabled,
    drs = drs.enabled,
    "MTProto-соединение"
  );

  if split_cfg.mode == SplitMode::Front {
    return split::relay_from_front(
      client,
      peek_buf,
      backend,
      secret_mode,
      detection.secret_label.as_deref(),
      &split_cfg,
      state,
    )
    .await;
  }

  proxy::proxy_mtproto(
    client,
    peek_buf,
    state,
    &proxy::MtprotoProxyOptions {
      preferred_backend: backend,
      secret_mode,
      fragmentation: &ctx.fragmentation,
      drs: &drs,
      dd: &dd,
      network: &ctx.network,
      webhooks: &webhooks,
    },
  )
  .await
}

async fn handle_fallback_path(
  client: TcpStream,
  peek_buf: Vec<u8>,
  ctx: &ConnectionContext,
  detection: &DetectionResult,
  state: &AppState,
) -> Result<()> {
  state.stats.fallback_connections.fetch_add(1, Ordering::Relaxed);

  let hint = classify_peek(&peek_buf);
  let has_ee_route = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config
      .mtproto
      .all_secrets()
      .iter()
      .any(|route| route.mode == SecretMode::Ee)
  };

  tracing::debug!(
    sni = ?detection.sni,
    tls_termination = ctx.tls_enabled,
    traffic_hint = ?hint,
    "fallback-соединение"
  );

  if let Some(message) = fallback_diagnostic_message(hint, has_ee_route) {
    tracing::warn!(
      peek_prefix = %hex::encode(&peek_buf[..peek_buf.len().min(8)]),
      peek_len = peek_buf.len(),
      %message,
      "MTProto не распознан"
    );
  }

  if let Some(target) = resolve_fronting_target(&ctx.fallback_cfg, detection.sni.as_deref()) {
    state.stats.domain_fronted.fetch_add(1, Ordering::Relaxed);
    return forward_tcp(client, &peek_buf, &target).await;
  }

  if ctx.tls_enabled && looks_like_tls_client_hello(&peek_buf) {
    let tls_cfg = {
      let config = state
        .config
        .read()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.tls.clone()
    };
    let server_config = tls_server::load_server_config(&tls_cfg)?;
    let acceptor = TlsAcceptor::from(server_config);
    return tls_server::serve_tls_fallback(
      client,
      peek_buf,
      &acceptor,
      &ctx.fallback_cfg,
      &state.stats,
    )
    .await;
  }

  fallback::handle_fallback(
    client,
    &peek_buf,
    &ctx.fallback_cfg,
    detection.sni.as_deref(),
    &state.stats,
  )
  .await
}

fn ja4_allowed(data: &[u8], profiles: &[String]) -> bool {
  if profiles.is_empty() {
    return true;
  }
  if !looks_like_tls_client_hello(data) {
    return true;
  }
  let Ok(record) = parse_record(data) else {
    return false;
  };
  let Ok(hello) = parse_client_hello(record.payload) else {
    return false;
  };
  ja4_matches_any(&compute_ja4(&hello), profiles)
}

fn extract_sni(data: &[u8]) -> Option<String> {
  crate::tls::try_client_hello_sni(data)
}

fn log_ja4(data: &[u8], profiles: &[String]) {
  if !looks_like_tls_client_hello(data) {
    return;
  }

  let Ok(record) = parse_record(data) else {
    return;
  };
  let Ok(hello) = parse_client_hello(record.payload) else {
    return;
  };

  let ja4 = compute_ja4(&hello);
  if profiles.is_empty() {
    tracing::debug!(%ja4, "JA4 фингерпринт ClientHello");
    return;
  }

  if ja4_matches_any(&ja4, profiles) {
    tracing::info!(%ja4, profiles = ?profiles, "JA4 совпадает с профилем из пула");
  } else {
    tracing::debug!(%ja4, profiles = ?profiles, "JA4 не совпадает с пулом профилей");
  }
}

/// Принимает соединения на указанном адресе.
pub async fn run_acceptor(state: Arc<AppState>) -> Result<()> {
  let listen_addr = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.listen.socket_addr()?
  };

  if let Some(socket_path) = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.admin.socket.clone()
  } {
    let admin_state = Arc::clone(&state);
    tokio::spawn(async move {
      if let Err(err) = admin::run_admin_socket(admin_state, &socket_path).await {
        tracing::error!(error = %err, "admin socket завершился с ошибкой");
      }
    });
  }

  crate::web::spawn_webui(Arc::clone(&state));
  metrics::spawn_metrics(Arc::clone(&state));

  {
    let split_mode = {
      let config = state
        .config
        .read()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.split.mode
    };
    if split_mode == SplitMode::Back {
      let back_state = Arc::clone(&state);
      tokio::spawn(async move {
        if let Err(err) = split::run_back_listener(back_state).await {
          tracing::error!(error = %err, "split back listener завершился с ошибкой");
        }
      });
    }
  }

  {
    let webhooks = {
      let config = state
        .config
        .read()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.webhooks.clone()
    };
    crate::webhooks::dispatch(&webhooks, crate::webhooks::WebhookEvent::ProxyStarted, None);
  }

  let listener = tokio::net::TcpListener::bind(listen_addr)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("bind {listen_addr}: {err}")))?;

  tracing::info!(%listen_addr, "StealthGate слушает соединения");

  loop {
    tokio::select! {
      result = listener.accept() => {
        let (stream, peer) = result
          .map_err(|err| StealthGateError::Proxy(format!("accept: {err}")))?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
          if let Err(err) = handle_connection(stream, state).await {
            tracing::warn!(%peer, error = %err, "ошибка обработки соединения");
          }
        });
      }
      _ = shutdown_signal() => {
        tracing::info!("получен сигнал завершения, останавливаем accept loop");
        break;
      }
    }
  }

  Ok(())
}

pub(crate) async fn shutdown_signal() {
  let ctrl_c = async {
    tokio::signal::ctrl_c()
      .await
      .expect("не удалось установить Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
      .expect("не удалось установить SIGTERM handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
    _ = ctrl_c => {}
    _ = terminate => {}
  }
}

/// Утилита для тестов: детекция без сети.
pub fn detect_traffic(data: &[u8], secret: &str, fake_domains: &[String]) -> Result<DetectionResult> {
  let detector = Detector::from_routes(
    &[crate::config::SecretRoute {
      label: "default".into(),
      secret: secret.into(),
      mode: crate::config::secret_mode(secret),
      backend: String::new(),
      max_connections: 0,
    }],
    fake_domains,
  )?;
  Ok(detector.detect(data))
}

/// Обёртка для тестирования проксирования с произвольными потоками.
pub async fn copy_bidirectional<L, R>(left: L, right: R) -> Result<(u64, u64)>
where
  L: AsyncRead + AsyncWrite + Unpin,
  R: AsyncRead + AsyncWrite + Unpin,
{
  proxy::copy_bidirectional(left, right).await
}

/// Запускает прокси с конфигурацией (удобно для тестов).
pub async fn run_with_config(config: Config, config_path: &str) -> Result<()> {
  let state = AppState::new(config, config_path)?;
  run_acceptor(state).await
}
