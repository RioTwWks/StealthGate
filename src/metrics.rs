use std::sync::Arc;

use crate::state::AppState;

/// Prometheus text exposition для метрик прокси.
pub fn render_prometheus(state: &AppState) -> String {
  let stats = state.stats.snapshot();
  let summary = state.config_summary().ok();

  let mut out = String::new();
  append_counter(&mut out, "stealthgate_connections_total", stats.total_connections);
  append_counter(
    &mut out,
    "stealthgate_connections_mtproto_total",
    stats.mtproto_connections,
  );
  append_counter(
    &mut out,
    "stealthgate_connections_fallback_total",
    stats.fallback_connections,
  );
  append_counter(
    &mut out,
    "stealthgate_bytes_to_backend_total",
    stats.bytes_to_backend,
  );
  append_counter(
    &mut out,
    "stealthgate_bytes_from_backend_total",
    stats.bytes_from_backend,
  );
  append_counter(
    &mut out,
    "stealthgate_tls_handshakes_total",
    stats.tls_handshakes,
  );
  append_counter(
    &mut out,
    "stealthgate_fragmented_writes_total",
    stats.fragmented_writes,
  );
  append_counter(&mut out, "stealthgate_drs_writes_total", stats.drs_writes);
  append_counter(&mut out, "stealthgate_dd_writes_total", stats.dd_writes);
  append_counter(
    &mut out,
    "stealthgate_backend_failovers_total",
    stats.backend_failovers,
  );
  append_counter(
    &mut out,
    "stealthgate_replay_blocked_total",
    stats.replay_blocked,
  );
  append_counter(
    &mut out,
    "stealthgate_domain_fronted_total",
    stats.domain_fronted,
  );
  append_counter(&mut out, "stealthgate_split_relayed_total", stats.split_relayed);
  append_counter(
    &mut out,
    "stealthgate_split_auth_failed_total",
    stats.split_auth_failed,
  );

  if let Some(summary) = summary {
  append_gauge(
    &mut out,
    "stealthgate_tls_enabled",
    if summary.tls_enabled { 1 } else { 0 },
  );
  append_gauge(
    &mut out,
    "stealthgate_fragmentation_enabled",
    if summary.fragmentation_enabled {
      1
    } else {
      0
    },
  );
  append_gauge(
    &mut out,
    "stealthgate_drs_enabled",
    if summary.drs_enabled { 1 } else { 0 },
  );
  append_gauge(
    &mut out,
    "stealthgate_webhooks_enabled",
    if summary.webhooks_enabled { 1 } else { 0 },
  );
  }

  out
}

fn append_counter(out: &mut String, name: &str, value: u64) {
  out.push_str("# TYPE ");
  out.push_str(name);
  out.push_str(" counter\n");
  out.push_str(name);
  out.push(' ');
  out.push_str(&value.to_string());
  out.push('\n');
}

fn append_gauge(out: &mut String, name: &str, value: u64) {
  out.push_str("# TYPE ");
  out.push_str(name);
  out.push_str(" gauge\n");
  out.push_str(name);
  out.push(' ');
  out.push_str(&value.to_string());
  out.push('\n');
}

/// Запускает HTTP-сервер Prometheus metrics.
pub async fn run_metrics_server(state: Arc<AppState>) -> crate::error::Result<()> {
  use axum::response::IntoResponse;
  use axum::routing::get;
  use axum::Router;

  let host = {
    let config = state
      .config
      .read()
      .map_err(|_| crate::error::StealthGateError::Config("блокировка config poisoned".into()))?;
    if !config.metrics.enabled {
      return Ok(());
    }
    format!("{}:{}", config.metrics.host, config.metrics.port)
  };

  let app = Router::new()
    .route(
      "/metrics",
      get({
        let state = Arc::clone(&state);
        move || {
          let state = Arc::clone(&state);
          async move {
            (
              [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
              )],
              render_prometheus(&state),
            )
              .into_response()
          }
        }
      }),
    )
    .route("/healthz", get(|| async { "ok" }));

  let addr: std::net::SocketAddr = host
    .parse()
    .map_err(|err| crate::error::StealthGateError::Config(format!("metrics addr: {err}")))?;
  let listener = tokio::net::TcpListener::bind(addr).await.map_err(|err| {
    crate::error::StealthGateError::Proxy(format!("bind metrics {addr}: {err}"))
  })?;
  tracing::info!(%addr, "Prometheus metrics доступны на /metrics");

  axum::serve(listener, app).await.map_err(|err| {
    crate::error::StealthGateError::Proxy(format!("metrics server: {err}"))
  })?;
  Ok(())
}

/// Запускает metrics server в фоне.
pub fn spawn_metrics(state: Arc<AppState>) {
  tokio::spawn(async move {
    if let Err(err) = run_metrics_server(state).await {
      tracing::error!(error = %err, "metrics server завершился с ошибкой");
    }
  });
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::Config;
  use tempfile::tempdir;

  fn sample_config(users_file: &str) -> Config {
    Config::test_minimal(users_file)
  }

  #[test]
  fn renders_prometheus_counters() {
    let dir = tempdir().expect("tempdir");
    let users = dir.path().join("users.json").to_string_lossy().to_string();
    let config = sample_config(&users);
    let state = AppState::new(config, "config.toml").expect("state");
    let body = render_prometheus(&state);
    assert!(body.contains("stealthgate_connections_total"));
  }
}
