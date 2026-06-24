use serde::Deserialize;
use serde_json::Value;

use crate::config::{FragmentationConfig, MtprotoConfig};
use crate::error::{Result, StealthGateError};
use crate::state::AppState;

/// HTTP-ответ admin API.
#[derive(Debug, Clone)]
pub struct AdminResponse {
  pub status: u16,
  pub content_type: &'static str,
  pub body: String,
}

/// Обрабатывает admin-запрос по методу и пути.
pub fn handle_admin(method: &str, path: &str, body: Option<&str>, state: &AppState) -> Result<AdminResponse> {
  match (method, path) {
    ("GET", "/stats") => json_response(&state.stats.snapshot()),
    ("GET", "/config") => json_response(&state.config_summary()?),
    ("GET", "/config/full") => json_response(&state.full_config()?),
    ("POST", "/reload") => {
      state.reload_config()?;
      ok_message("reloaded", Ok(()))
    }
    ("POST", "/secret") => {
      let secret = parse_secret_body(body)?;
      state.update_secret(secret)?;
      ok_message("secret_updated", Ok(()))
    }
    ("PUT", "/config/mtproto") => {
      let mtproto: MtprotoConfig = parse_json_body(body)?;
      state.update_mtproto(mtproto)?;
      ok_message("mtproto_updated", Ok(()))
    }
    ("PUT", "/config/fragmentation") => {
      let fragmentation: FragmentationConfig = parse_json_body(body)?;
      state.update_fragmentation(fragmentation)?;
      ok_message("fragmentation_updated", Ok(()))
    }
    _ => Ok(AdminResponse {
      status: 404,
      content_type: "text/plain",
      body: "not found".into(),
    }),
  }
}

fn json_response<T: serde::Serialize>(value: &T) -> Result<AdminResponse> {
  let body = serde_json::to_string(value)
    .map_err(|err| StealthGateError::Config(format!("сериализация JSON: {err}")))?;
  Ok(AdminResponse {
    status: 200,
    content_type: "application/json",
    body,
  })
}

fn ok_message(status: &str, result: Result<()>) -> Result<AdminResponse> {
  result?;
  Ok(AdminResponse {
    status: 200,
    content_type: "application/json",
    body: format!(r#"{{"status":"{status}"}}"#),
  })
}

fn parse_json_body<T: for<'de> Deserialize<'de>>(body: Option<&str>) -> Result<T> {
  let body = body.unwrap_or_default();
  serde_json::from_str(body)
    .map_err(|err| StealthGateError::Config(format!("некорректный JSON: {err}")))
}

fn parse_secret_body(body: Option<&str>) -> Result<String> {
  let parsed: Value = parse_json_body(body)?;
  parsed
    .get("secret")
    .and_then(|value| value.as_str())
    .map(str::to_string)
    .ok_or_else(|| StealthGateError::Config("поле secret обязательно".into()))
}

pub fn to_http_response(response: &AdminResponse) -> String {
  let reason = match response.status {
    200 => "OK",
    404 => "Not Found",
    _ => "Error",
  };
  format!(
    "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
    response.status,
    reason,
    response.content_type,
    response.body.len(),
    response.body
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    AdminConfig, FallbackConfig, FragmentationConfig, ListenConfig, MtprotoConfig, TlsConfig,
    WebuiConfig,
  };
  use crate::Config;
  use tempfile::tempdir;

  fn sample_config(users_file: &str) -> Config {
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
      webui: WebuiConfig {
        users_file: users_file.into(),
        ..Default::default()
      },
    }
  }

  #[test]
  fn dispatch_stats_returns_json() {
    let dir = tempdir().expect("tempdir");
    let users = dir.path().join("users.json").to_string_lossy().to_string();
    let config_path = dir.path().join("config.toml");
    let config = sample_config(&users);
    config.save_to_file(&config_path).expect("save");
    let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
    let response = handle_admin("GET", "/stats", None, &state).expect("stats");
    assert_eq!(response.status, 200);
    assert!(response.body.contains("total_connections"));
  }
}
