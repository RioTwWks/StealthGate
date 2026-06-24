use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::cookie::Key;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use sha2::Digest;

use crate::config::WebuiConfig;
use crate::error::{Result, StealthGateError};
use crate::state::AppState;
use crate::web::api;

/// Собирает Axum-приложение WebUI (используется в тестах и `run_webui`).
pub fn build_webui_app(state: Arc<AppState>, session_secret: &str) -> Router {
  let session_key = {
    // Key::from требует 64 байта — используем SHA-512 от секрета.
    let digest = sha2::Sha512::digest(session_secret.as_bytes());
    Key::from(digest.as_slice())
  };
  let session_layer = SessionManagerLayer::new(MemoryStore::default())
    .with_secure(false)
    .with_expiry(Expiry::OnInactivity(CookieDuration::hours(12)))
    .with_name("stealthgate_session")
    .with_signed(session_key);

  Router::new()
    .route("/", get(|| async { Redirect::to("/ui/login.html") }))
    .nest("/api", api::router(state))
    .nest_service("/ui", ServeDir::new("web/dashboard"))
    .layer(session_layer)
    .layer(TraceLayer::new_for_http())
}

/// Запускает WebUI HTTP-сервер.
pub async fn run_webui(state: Arc<AppState>, config: WebuiConfig) -> Result<()> {
  let addr: SocketAddr = config.socket_addr()?;
  let app = build_webui_app(Arc::clone(&state), &config.session_secret);

  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("bind webui {addr}: {err}")))?;

  tracing::info!(%addr, "WebUI дашборд доступен");

  axum::serve(listener, app)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("webui server: {err}")))?;

  Ok(())
}

/// Запускает WebUI в фоне.
pub fn spawn_webui(state: Arc<AppState>) {
  let webui = match state.config.read() {
    Ok(config) => {
      if !config.webui.enabled {
        return;
      }
      config.webui.clone()
    }
    Err(_) => {
      tracing::error!("не удалось прочитать config для webui");
      return;
    }
  };

  tokio::spawn(async move {
    loop {
      if let Err(err) = run_webui(Arc::clone(&state), webui.clone()).await {
        tracing::error!(error = %err, "WebUI завершился с ошибкой, перезапуск через 3с");
        tokio::time::sleep(Duration::from_secs(3)).await;
      }
    }
  });
}
