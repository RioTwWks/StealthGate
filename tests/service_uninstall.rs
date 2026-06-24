//! Интеграционные тесты удаления сервиса через WebUI API.

use std::sync::Arc;

use serde_json::Value;
use stealth_gate::state::AppState;
use stealth_gate::web::build_webui_app;
use stealth_gate::Config;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

const SESSION_SECRET: &str = "uninstall-test-session-secret";
const ADMIN_PASSWORD: &str = "admin123";

fn sample_config(users_file: &str, uninstall_script: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.webui.session_secret = SESSION_SECRET.into();
  config.admin.uninstall_enabled = true;
  config.admin.uninstall_script = Some(uninstall_script.into());
  config.admin.uninstall_use_sudo = false;
  config
}

async fn spawn_webui_test_server(state: Arc<AppState>) -> (String, CancellationToken) {
  let app = build_webui_app(state, SESSION_SECRET);
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("bind webui");
  let addr = listener.local_addr().expect("local addr");
  let base_url = format!("http://{addr}");

  let ct = CancellationToken::new();
  let handle_ct = ct.clone();
  tokio::spawn(async move {
    axum::serve(listener, app)
      .with_graceful_shutdown(async move { handle_ct.cancelled_owned().await })
      .await
      .expect("serve webui");
  });

  (base_url, ct)
}

fn http_client() -> reqwest::Client {
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("http client")
}

fn session_cookie_header(response: &reqwest::Response) -> String {
  response
    .headers()
    .get_all("set-cookie")
    .iter()
    .filter_map(|value| value.to_str().ok())
    .map(|value| value.split(';').next().unwrap_or(value))
    .collect::<Vec<_>>()
    .join("; ")
}

async fn login_admin(client: &reqwest::Client, base_url: &str) -> String {
  let login = client
    .post(format!("{base_url}/api/auth/login"))
    .json(&serde_json::json!({
      "username": "admin",
      "password": ADMIN_PASSWORD
    }))
    .send()
    .await
    .expect("login");
  session_cookie_header(&login)
}

#[tokio::test]
async fn uninstall_requires_admin() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let script = dir.path().join("mock-uninstall.sh");
  std::fs::write(&script, "#!/bin/sh\nexit 0\n").expect("script");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
  }

  let config = sample_config(&users_file, &script.to_string_lossy());
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();

  let response = client
    .post(format!("{base_url}/api/system/uninstall"))
    .json(&serde_json::json!({ "confirm": "UNINSTALL", "purge": false }))
    .send()
    .await
    .expect("unauth uninstall");
  assert_eq!(response.status(), 401);

  ct.cancel();
}

#[tokio::test]
async fn uninstall_rejects_bad_confirm() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let script = dir.path().join("mock-uninstall.sh");
  std::fs::write(&script, "#!/bin/sh\nexit 0\n").expect("script");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
  }

  let config = sample_config(&users_file, &script.to_string_lossy());
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();
  let cookie = login_admin(&client, &base_url).await;

  let response = client
    .post(format!("{base_url}/api/system/uninstall"))
    .header("cookie", cookie)
    .json(&serde_json::json!({ "confirm": "DELETE", "purge": false }))
    .send()
    .await
    .expect("bad confirm");
  assert_eq!(response.status(), 400);

  ct.cancel();
}

#[tokio::test]
async fn uninstall_disabled_in_config() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let mut config = sample_config(&users_file, "/tmp/uninstall.sh");
  config.admin.uninstall_enabled = false;
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();
  let cookie = login_admin(&client, &base_url).await;

  let response = client
    .post(format!("{base_url}/api/system/uninstall"))
    .header("cookie", cookie)
    .json(&serde_json::json!({ "confirm": "UNINSTALL", "purge": false }))
    .send()
    .await
    .expect("disabled uninstall");
  assert_eq!(response.status(), 400);

  ct.cancel();
}

#[tokio::test]
async fn uninstall_schedules_when_enabled() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let marker = dir.path().join("uninstall-ran.marker");
  let script = dir.path().join("mock-uninstall.sh");
  if marker.exists() {
    std::fs::remove_file(&marker).ok();
  }
  std::fs::write(
    &script,
    format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
  )
  .expect("script");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
  }

  let config = sample_config(&users_file, &script.to_string_lossy());
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();
  let cookie = login_admin(&client, &base_url).await;

  let response = client
    .post(format!("{base_url}/api/system/uninstall"))
    .header("cookie", cookie)
    .json(&serde_json::json!({ "confirm": "UNINSTALL", "purge": true }))
    .send()
    .await
    .expect("uninstall");
  assert_eq!(response.status(), 200);
  let body: Value = response.json().await.expect("json");
  assert_eq!(body["status"], "uninstall_scheduled");

  tokio::time::sleep(std::time::Duration::from_millis(300)).await;
  assert!(marker.exists(), "mock uninstall должен был выполниться");

  ct.cancel();
}
