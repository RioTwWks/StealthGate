//! Тест streamable HTTP transport MCP.

use std::sync::Arc;

use rmcp::transport::streamable_http_server::{
  session::local::LocalSessionManager, tower::StreamableHttpService, StreamableHttpServerConfig,
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use stealth_gate::config::WebuiConfig;
use stealth_gate::{AppState, Config, StealthGateMcp};

fn sample_config(users_file: &str) -> Config {
  Config {
    listen: stealth_gate::config::ListenConfig {
      host: "127.0.0.1".into(),
      port: 8443,
    },
    tls: stealth_gate::config::TlsConfig {
      cert_file: None,
      key_file: None,
      fake_domain: "example.com".into(),
      ja4_profile: None,
    },
    mtproto: stealth_gate::config::MtprotoConfig {
      secret: "0123456789abcdef0123456789abcdef".into(),
      backend: "127.0.0.1:443".into(),
    },
    fallback: stealth_gate::config::FallbackConfig {
      upstream: None,
      static_html: None,
    },
    fragmentation: stealth_gate::config::FragmentationConfig::default(),
    admin: stealth_gate::config::AdminConfig::default(),
    webui: WebuiConfig {
      users_file: users_file.into(),
      ..Default::default()
    },
  }
}

#[tokio::test]
async fn mcp_streamable_http_initialize() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let config = sample_config(&users_file);
  config.save_to_file(&config_path).expect("save");
  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");

  let ct = CancellationToken::new();
  let service = StreamableHttpService::new(
    move || Ok(StealthGateMcp::new(Arc::clone(&state))),
    Arc::new(LocalSessionManager::default()),
    StreamableHttpServerConfig {
      stateful_mode: true,
      sse_keep_alive: None,
      cancellation_token: ct.child_token(),
      ..Default::default()
    },
  );

  let router = axum::Router::new().nest_service("/mcp", service);
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let addr = listener.local_addr().expect("addr");

  let handle = tokio::spawn({
    let ct = ct.clone();
    async move {
      axum::serve(listener, router)
        .with_graceful_shutdown(async move { ct.cancelled_owned().await })
        .await
        .expect("serve");
    }
  });

  let client = reqwest::Client::new();
  let response = client
    .post(format!("http://{addr}/mcp"))
    .header("Content-Type", "application/json")
    .header("Accept", "application/json, text/event-stream")
    .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#)
    .send()
    .await
    .expect("request");

  assert_eq!(response.status(), 200);
  let body = response.text().await.expect("body");
  assert!(body.contains("stealth-gate-mcp") || body.contains("jsonrpc"));

  ct.cancel();
  handle.await.expect("join");
}
