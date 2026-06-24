use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{Result, StealthGateError};
use crate::state::AppState;

/// Запускает admin API на Unix-сокете.
pub async fn run_admin_socket(state: Arc<AppState>, socket_path: &str) -> Result<()> {
  let path = Path::new(socket_path);
  if path.exists() {
    std::fs::remove_file(path).map_err(|err| {
      StealthGateError::Config(format!("не удалось удалить старый сокет {socket_path}: {err}"))
    })?;
  }

  if let Some(parent) = path.parent() {
    if !parent.as_os_str().is_empty() {
      std::fs::create_dir_all(parent).map_err(|err| {
        StealthGateError::Config(format!("не удалось создать каталог {}: {err}", parent.display()))
      })?;
    }
  }

  let listener = UnixListener::bind(path).map_err(|err| {
    StealthGateError::Config(format!("bind admin socket {socket_path}: {err}"))
  })?;

  tracing::info!(socket = socket_path, "admin API слушает Unix-сокет");

  loop {
    let (stream, _) = listener
      .accept()
      .await
      .map_err(|err| StealthGateError::Proxy(format!("admin accept: {err}")))?;
    let state = Arc::clone(&state);
    tokio::spawn(async move {
      if let Err(err) = handle_admin_connection(stream, state).await {
        tracing::debug!(error = %err, "ошибка admin-соединения");
      }
    });
  }
}

async fn handle_admin_connection(mut stream: UnixStream, state: Arc<AppState>) -> Result<()> {
  let mut buf = vec![0u8; 8192];
  let n = stream
    .read(&mut buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("admin read: {err}")))?;
  if n == 0 {
    return Ok(());
  }

  let request = String::from_utf8_lossy(&buf[..n]);
  let response = dispatch_admin_request(&request, &state)?;
  stream
    .write_all(response.as_bytes())
    .await
    .map_err(|err| StealthGateError::Proxy(format!("admin write: {err}")))?;
  Ok(())
}

fn dispatch_admin_request(request: &str, state: &AppState) -> Result<String> {
  let first_line = request.lines().next().unwrap_or_default();
  let mut parts = first_line.split_whitespace();
  let method = parts.next().unwrap_or_default();
  let path = parts.next().unwrap_or_default();

  match (method, path) {
    ("GET", "/stats") => {
      let body = serde_json::to_string(&state.stats.snapshot())
        .map_err(|err| StealthGateError::Config(format!("сериализация stats: {err}")))?;
      Ok(http_response(200, "application/json", &body))
    }
    ("GET", "/config") => {
      let body = serde_json::to_string(&state.config_summary()?)
        .map_err(|err| StealthGateError::Config(format!("сериализация config: {err}")))?;
      Ok(http_response(200, "application/json", &body))
    }
    ("POST", "/reload") => {
      state.reload_config()?;
      Ok(http_response(200, "application/json", r#"{"status":"reloaded"}"#))
    }
    ("POST", "/secret") => {
      let body = request
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| request.split("\n\n").nth(1))
        .unwrap_or_default();
      let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|err| StealthGateError::Config(format!("некорректный JSON: {err}")))?;
      let secret = parsed
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StealthGateError::Config("поле secret обязательно".into()))?;
      state.update_secret(secret.to_string())?;
      Ok(http_response(200, "application/json", r#"{"status":"secret_updated"}"#))
    }
    _ => Ok(http_response(404, "text/plain", "not found")),
  }
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
  let reason = match status {
    200 => "OK",
    404 => "Not Found",
    _ => "Error",
  };
  format!(
    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
    body.len()
  )
}

/// HTTP-клиент для MCP: выполняет запрос к admin-сокету.
pub async fn admin_request(socket_path: &str, method: &str, path: &str, body: Option<&str>) -> Result<String> {
  let mut stream = UnixStream::connect(socket_path)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("подключение к admin socket: {err}")))?;

  let payload = body.unwrap_or("");
  let request = if payload.is_empty() {
    format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
  } else {
    format!(
      "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
      payload.len()
    )
  };

  stream
    .write_all(request.as_bytes())
    .await
    .map_err(|err| StealthGateError::Proxy(format!("admin request write: {err}")))?;

  let mut response = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let n = stream
      .read(&mut chunk)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("admin request read: {err}")))?;
    if n == 0 {
      break;
    }
    response.extend_from_slice(&chunk[..n]);
  }

  let text = String::from_utf8_lossy(&response);
  Ok(text
    .split("\r\n\r\n")
    .nth(1)
    .or_else(|| text.split("\n\n").nth(1))
    .unwrap_or(&text)
    .to_string())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    AdminConfig, FallbackConfig, FragmentationConfig, ListenConfig, MtprotoConfig, TlsConfig,
  };
  use crate::state::AppState;
  use crate::Config;

  fn sample_config() -> Config {
    Config {
      listen: ListenConfig {
        host: "127.0.0.1".into(),
        port: 8443,
      },
      tls: TlsConfig {
        cert_file: None,
        key_file: None,
        fake_domain: "example.com".into(),
        ja4_profile: None,
      },
      mtproto: MtprotoConfig {
        secret: "0123456789abcdef0123456789abcdef".into(),
        backend: "127.0.0.1:443".into(),
      },
      fallback: FallbackConfig {
        upstream: None,
        static_html: None,
      },
      fragmentation: FragmentationConfig::default(),
      admin: AdminConfig::default(),
    }
  }

  #[test]
  fn dispatch_stats_returns_json() {
    let state = AppState::new(sample_config(), "configs/config.toml");
    let response = dispatch_admin_request("GET /stats HTTP/1.1", &state).expect("stats");
    assert!(response.contains("200 OK"));
    assert!(response.contains("total_connections"));
  }
}
