//! Простой HTTP-приёмник webhook-уведомлений StealthGate.
//!
//! Запуск:
//! ```bash
//! cargo run --example webhook-receiver -- --port 9999
//! ```
//!
//! В `config.toml`:
//! ```toml
//! [webhooks]
//! enabled = true
//! urls = ["http://127.0.0.1:9999/hook"]
//! ```

use std::net::SocketAddr;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(name = "webhook-receiver", about = "Пример приёмника webhook StealthGate")]
struct Args {
  /// Порт HTTP-сервера.
  #[arg(short, long, default_value_t = 9999)]
  port: u16,

  /// Адрес bind.
  #[arg(long, default_value = "127.0.0.1")]
  host: String,
}

#[derive(Debug, Deserialize)]
struct WebhookPayload {
  event: String,
  detail: Option<Value>,
  timestamp: u64,
}

#[derive(Clone, Default)]
struct AppState {
  received: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

async fn hook(
  State(state): State<AppState>,
  Json(payload): Json<WebhookPayload>,
) -> &'static str {
  let count = state
    .received
    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    + 1;

  println!(
    "[{count}] event={} timestamp={}{}",
    payload.event,
    payload.timestamp,
    payload
      .detail
      .as_ref()
      .map(|detail| format!(" detail={detail}"))
      .unwrap_or_default()
  );

  "ok"
}

#[tokio::main]
async fn main() {
  let args = Args::parse();
  let addr: SocketAddr = format!("{}:{}", args.host, args.port)
    .parse()
    .expect("некорректный адрес");

  let state = AppState::default();
  let app = Router::new()
    .route("/hook", post(hook))
    .with_state(state);

  println!("Webhook receiver слушает http://{addr}/hook");
  println!("Добавь URL в [webhooks].urls и включи enabled = true");

  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .expect("bind");
  axum::serve(listener, app)
    .await
    .expect("serve");
}
