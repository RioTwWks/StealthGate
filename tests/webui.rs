//! Интеграционные тесты WebUI: login, сессия и REST API.

use std::sync::Arc;

use serde_json::Value;
use stealth_gate::state::AppState;
use stealth_gate::web::build_webui_app;
use stealth_gate::Config;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

const SESSION_SECRET: &str = "integration-test-session-secret";
const ADMIN_PASSWORD: &str = "admin123";

fn sample_config(users_file: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.mtproto.secret = "ee0123456789abcdef0123456789abcdef".into();
  config.webui.session_secret = SESSION_SECRET.into();
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

/// Извлекает значение заголовка Cookie из Set-Cookie ответа login.
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

#[tokio::test]
async fn webui_rejects_unauthenticated_api() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let config = sample_config(&users_file);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();

  let response = client
    .get(format!("{base_url}/api/stats"))
    .send()
    .await
    .expect("stats request");

  assert_eq!(response.status(), 401);
  let body: Value = response.json().await.expect("json");
  assert_eq!(body["error"], "требуется авторизация");

  ct.cancel();
}

#[tokio::test]
async fn webui_login_and_protected_api() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let config = sample_config(&users_file);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();

  let bad_login = client
    .post(format!("{base_url}/api/auth/login"))
    .json(&serde_json::json!({
      "username": "admin",
      "password": "wrong-password"
    }))
    .send()
    .await
    .expect("bad login");
  assert_eq!(bad_login.status(), 401);

  let login = client
    .post(format!("{base_url}/api/auth/login"))
    .json(&serde_json::json!({
      "username": "admin",
      "password": ADMIN_PASSWORD
    }))
    .send()
    .await
    .expect("login");
  assert_eq!(login.status(), 200);
  let session_cookie = session_cookie_header(&login);

  let login_body: Value = login.json().await.expect("login json");
  assert_eq!(login_body["user"]["username"], "admin");
  assert_eq!(login_body["user"]["role"], "admin");

  let me = client
    .get(format!("{base_url}/api/auth/me"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("me");
  assert_eq!(me.status(), 200);
  let me_body: Value = me.json().await.expect("me json");
  assert_eq!(me_body["username"], "admin");

  let stats = client
    .get(format!("{base_url}/api/stats"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("stats");
  assert_eq!(stats.status(), 200);
  let stats_body: Value = stats.json().await.expect("stats json");
  assert!(stats_body.get("total_connections").is_some());

  let config_summary = client
    .get(format!("{base_url}/api/config"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("config");
  assert_eq!(config_summary.status(), 200);
  let config_body: Value = config_summary.json().await.expect("config json");
  assert_eq!(config_body["backend"], "127.0.0.1:443");

  let config_full = client
    .get(format!("{base_url}/api/config/full"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("config full");
  assert_eq!(config_full.status(), 200);

  let users = client
    .get(format!("{base_url}/api/users"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("users");
  assert_eq!(users.status(), 200);
  let users_body: Value = users.json().await.expect("users json");
  assert!(users_body.as_array().is_some_and(|list| !list.is_empty()));

  let logout = client
    .post(format!("{base_url}/api/auth/logout"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("logout");
  assert_eq!(logout.status(), 204);

  let me_after_logout = client
    .get(format!("{base_url}/api/auth/me"))
    .send()
    .await
    .expect("me after logout");
  assert_eq!(me_after_logout.status(), 401);

  ct.cancel();
}

#[tokio::test]
async fn webui_serves_dashboard_static() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let config = sample_config(&users_file);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();

  let login_page = client
    .get(format!("{base_url}/ui/login.html"))
    .send()
    .await
    .expect("login page");
  assert_eq!(login_page.status(), 200);
  let html = login_page.text().await.expect("html");
  assert!(html.contains("login") || html.contains("StealthGate"));

  let root = client
    .get(format!("{base_url}/"))
    .send()
    .await
    .expect("root redirect");
  assert!(
    root.status().is_redirection(),
    "ожидался редирект, получен {}",
    root.status()
  );
  assert!(
    root.headers()
      .get("location")
      .and_then(|value| value.to_str().ok())
      .is_some_and(|location| location.contains("/ui/login.html"))
  );

  ct.cancel();
}

#[tokio::test]
async fn webui_proxy_link_qr_requires_auth_and_returns_svg() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");
  let config = sample_config(&users_file);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let (base_url, ct) = spawn_webui_test_server(state).await;
  let client = http_client();

  let unauth = client
    .get(format!("{base_url}/api/proxy-link/qr"))
    .send()
    .await
    .expect("qr unauth");
  assert_eq!(unauth.status(), 401);

  let login = client
    .post(format!("{base_url}/api/auth/login"))
    .json(&serde_json::json!({
      "username": "admin",
      "password": ADMIN_PASSWORD
    }))
    .send()
    .await
    .expect("login");
  let session_cookie = session_cookie_header(&login);

  let proxy_link = client
    .get(format!("{base_url}/api/proxy-link"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("proxy link");
  assert_eq!(proxy_link.status(), 200);
  let link_body: Value = proxy_link.json().await.expect("link json");
  let link = link_body["link"]
    .as_str()
    .expect("link string");
  assert!(link.starts_with("tg://proxy?"));

  let qr = client
    .get(format!("{base_url}/api/proxy-link/qr"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("qr");
  assert_eq!(qr.status(), 200);
  let content_type = qr
    .headers()
    .get("content-type")
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  assert!(
    content_type.contains("image/svg+xml"),
    "ожидался SVG, получен {content_type}"
  );

  let svg = qr.text().await.expect("svg body");
  assert!(svg.contains("<svg"), "ответ должен содержать SVG");
  assert!(
    svg.contains("viewBox") || svg.contains("width"),
    "SVG должен содержать размеры"
  );

  let qr_again = client
    .get(format!("{base_url}/api/proxy-link/qr"))
    .header("cookie", &session_cookie)
    .send()
    .await
    .expect("qr again");
  let svg_again = qr_again.text().await.expect("svg again");
  assert_eq!(svg, svg_again);

  let _ = link;
  ct.cancel();
}
