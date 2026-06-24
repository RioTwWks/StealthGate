//! Тесты admin API и TLS.

use std::sync::Arc;
use std::time::Duration;

use stealth_gate::config::TlsConfig;
use stealth_gate::admin;
use stealth_gate::state::AppState;
use stealth_gate::tls_server;
use stealth_gate::Config;
use tempfile::tempdir;

fn sample_config(users_file: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.tls.cert_file = Some("certs/cert.pem".into());
  config.tls.key_file = Some("certs/key.pem".into());
  config.tls.fake_domain = "www.cloudflare.com".into();
  config
}

#[tokio::test]
async fn admin_socket_stats_and_reload() {
  let dir = tempdir().expect("tempdir");
  let socket_path = dir.path().join("admin.sock");
  let config_path = dir.path().join("config.toml");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();

  let mut config = sample_config(&users_file);
  config.admin.socket = Some(socket_path.to_string_lossy().to_string());
  config.save_to_file(&config_path).expect("save");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let socket = socket_path.to_string_lossy().to_string();

  let admin_task = {
    let state = Arc::clone(&state);
    let socket = socket.clone();
    tokio::spawn(async move { admin::run_admin_socket(state, &socket).await })
  };

  tokio::time::sleep(Duration::from_millis(50)).await;

  let stats = admin::admin_request(&socket, "GET", "/stats", None)
    .await
    .expect("stats");
  assert!(stats.contains("total_connections"));

  let reload = admin::admin_request(&socket, "POST", "/reload", None)
    .await
    .expect("reload");
  assert!(reload.contains("reloaded"));

  admin_task.abort();
}

#[test]
fn tls_server_loads_generated_cert() {
  if !std::path::Path::new("certs/cert.pem").exists() {
    return;
  }
  let tls = TlsConfig {
    cert_file: Some("certs/cert.pem".into()),
    key_file: Some("certs/key.pem".into()),
    fake_domain: "www.cloudflare.com".into(),
    ja4_profile: None,
  };
  assert!(tls.is_enabled());
  tls_server::load_server_config(&tls).expect("load tls config");
}
