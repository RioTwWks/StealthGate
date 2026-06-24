use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::admin;
use crate::config::Config;
use crate::detector::{DetectionResult, Detector, TrafficType};
use crate::error::{Result, StealthGateError};
use crate::fallback;
use crate::proxy;
use crate::state::AppState;
use crate::tls::{compute_ja4, ja4_matches, looks_like_tls_client_hello, parse_client_hello, parse_record};
use crate::tls_server;

const PEEK_BUFFER_SIZE: usize = 4096;

/// Обрабатывает одно входящее соединение.
pub async fn handle_connection(mut client: TcpStream, state: Arc<AppState>) -> Result<()> {
  state.stats.total_connections.fetch_add(1, Ordering::Relaxed);

  let mut peek_buf = vec![0u8; PEEK_BUFFER_SIZE];
  let n = client
    .read(&mut peek_buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("чтение начальных данных: {err}")))?;

  if n == 0 {
    return Ok(());
  }

  peek_buf.truncate(n);

  let (secret, fake_domain, backend, fragmentation, fallback_cfg, tls_enabled, ja4_profile) = {
    let config = state
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    (
      config.mtproto.secret.clone(),
      config.tls.fake_domain.clone(),
      config.mtproto.backend.clone(),
      config.fragmentation.clone(),
      config.fallback.clone(),
      config.tls.is_enabled(),
      config.tls.ja4_profile.clone(),
    )
  };

  log_ja4(&peek_buf, ja4_profile.as_deref());

  let detector = Detector::new(&secret, &fake_domain)?;
  let detection = detector.detect(&peek_buf);

  match detection.traffic_type {
    TrafficType::Mtproto => {
      state.stats.mtproto_connections.fetch_add(1, Ordering::Relaxed);
      tracing::info!(
        sni = ?detection.sni,
        backend = %backend,
        fragmented = fragmentation.enabled,
        "MTProto-соединение"
      );
      proxy::proxy_mtproto(client, &peek_buf, &backend, &fragmentation, &state.stats).await?;
    }
    TrafficType::Fallback => {
      state.stats.fallback_connections.fetch_add(1, Ordering::Relaxed);
      tracing::debug!(sni = ?detection.sni, tls = tls_enabled, "fallback-соединение");

      if tls_enabled && looks_like_tls_client_hello(&peek_buf) {
        let tls_cfg = {
          let config = state
            .config
            .read()
            .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
          config.tls.clone()
        };
        let server_config = tls_server::load_server_config(&tls_cfg)?;
        let acceptor = TlsAcceptor::from(server_config);
        tls_server::serve_tls_fallback(client, peek_buf, &acceptor, &fallback_cfg, &state.stats)
          .await?;
      } else {
        fallback::handle_fallback(client, &peek_buf, &fallback_cfg).await?;
      }
    }
  }

  Ok(())
}

fn log_ja4(data: &[u8], expected_profile: Option<&str>) {
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
  if let Some(profile) = expected_profile {
  if ja4_matches(&ja4, profile) {
      tracing::info!(%ja4, "JA4 совпадает с профилем");
    } else {
      tracing::debug!(%ja4, expected = profile, "JA4 не совпадает с профилем");
    }
  } else {
    tracing::debug!(%ja4, "JA4 фингерпринт ClientHello");
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

  let listener = tokio::net::TcpListener::bind(listen_addr)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("bind {listen_addr}: {err}")))?;

  tracing::info!(%listen_addr, "StealthGate слушает соединения");

  loop {
    let (stream, peer) = listener
      .accept()
      .await
      .map_err(|err| StealthGateError::Proxy(format!("accept: {err}")))?;

    let state = Arc::clone(&state);
    tokio::spawn(async move {
      if let Err(err) = handle_connection(stream, state).await {
        tracing::warn!(%peer, error = %err, "ошибка обработки соединения");
      }
    });
  }
}

/// Утилита для тестов: детекция без сети.
pub fn detect_traffic(data: &[u8], secret: &str, fake_domain: &str) -> Result<DetectionResult> {
  let detector = Detector::new(secret, fake_domain)?;
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
  let state = AppState::new(config, config_path);
  run_acceptor(state).await
}
