//! Интеграционные тесты webhook-уведомлений.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use stealth_gate::state::AppState;
use stealth_gate::Config;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct WebhookCapture {
  payloads: Arc<Mutex<Vec<Value>>>,
}

async fn capture_hook(
  State(capture): State<WebhookCapture>,
  Json(payload): Json<Value>,
) -> &'static str {
  capture.payloads.lock().await.push(payload);
  "ok"
}

async fn spawn_webhook_server() -> (String, WebhookCapture, CancellationToken) {
  let capture = WebhookCapture::default();
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("bind webhook");
  let addr = listener.local_addr().expect("addr");
  let base_url = format!("http://{addr}/hook");

  let ct = CancellationToken::new();
  let handle_ct = ct.clone();
  let app = Router::new()
    .route("/hook", post(capture_hook))
    .with_state(capture.clone());

  tokio::spawn(async move {
    axum::serve(listener, app)
      .with_graceful_shutdown(async move { handle_ct.cancelled_owned().await })
      .await
      .expect("serve webhook");
  });

  (base_url, capture, ct)
}

fn sample_config(users_file: &str, webhook_url: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.webhooks.enabled = true;
  config.webhooks.urls = vec![webhook_url.into()];
  config.webhooks.events = vec![
    "config_reloaded".into(),
    "secret_updated".into(),
    "backend_failover".into(),
    "proxy_started".into(),
  ];
  config
}

async fn wait_for_webhook(capture: &WebhookCapture, event: &str) -> Value {
  let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
  loop {
    {
      let payloads = capture.payloads.lock().await;
      if let Some(payload) = payloads.iter().find(|item| item["event"] == event) {
        return payload.clone();
      }
    }
    if tokio::time::Instant::now() >= deadline {
      panic!("webhook {event} не получен за 5с");
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  }
}

#[tokio::test]
async fn webhook_receives_config_reloaded() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");

  let (webhook_url, capture, ct) = spawn_webhook_server().await;
  let config = sample_config(&users_file, &webhook_url);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  state.reload_config().expect("reload");

  let payload = wait_for_webhook(&capture, "config_reloaded").await;
  assert_eq!(payload["event"], "config_reloaded");
  assert!(payload.get("timestamp").is_some());

  ct.cancel();
}

#[tokio::test]
async fn webhook_receives_secret_updated() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");

  let (webhook_url, capture, ct) = spawn_webhook_server().await;
  let config = sample_config(&users_file, &webhook_url);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  state
    .update_secret("dd0123456789abcdef0123456789abcdef".into())
    .expect("update secret");

  let payload = wait_for_webhook(&capture, "secret_updated").await;
  assert_eq!(payload["event"], "secret_updated");

  ct.cancel();
}

#[tokio::test]
async fn webhook_respects_event_filter() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");

  let (webhook_url, capture, ct) = spawn_webhook_server().await;
  let mut config = sample_config(&users_file, &webhook_url);
  config.webhooks.events = vec!["secret_updated".into()];
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  state.reload_config().expect("reload");
  tokio::time::sleep(std::time::Duration::from_millis(300)).await;

  let payloads = capture.payloads.lock().await;
  assert!(
    payloads.is_empty(),
    "config_reloaded не должен отправляться при фильтре secret_updated"
  );

  drop(payloads);
  state
    .update_secret("ee0123456789abcdef0123456789abcdef".into())
    .expect("update secret");

  let payload = wait_for_webhook(&capture, "secret_updated").await;
  assert_eq!(payload["event"], "secret_updated");

  ct.cancel();
}
