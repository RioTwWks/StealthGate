//! Webhook-уведомления о событиях прокси.

use serde::Serialize;

use crate::config::WebhooksConfig;

/// События, о которых можно уведомлять webhook.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
  ConfigReloaded,
  SecretUpdated,
  BackendFailover,
  ProxyStarted,
}

#[derive(Serialize)]
struct WebhookPayload<'a> {
  event: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  detail: Option<serde_json::Value>,
  timestamp: u64,
}

/// Отправляет webhook-уведомления в фоне.
pub fn dispatch(config: &WebhooksConfig, event: WebhookEvent, detail: Option<serde_json::Value>) {
  if !config.enabled || config.urls.is_empty() {
    return;
  }

  let event_name = event.as_str();
  if !config.events.is_empty() && !config.events.iter().any(|e| e == event_name) {
    return;
  }

  let urls = config.urls.clone();
  let payload = WebhookPayload {
    event: event_name,
    detail,
    timestamp: std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0),
  };

  tokio::spawn(async move {
    if let Err(err) = send_webhooks(&urls, &payload).await {
      tracing::warn!(error = %err, event = event_name, "ошибка отправки webhook");
    }
  });
}

impl WebhookEvent {
  fn as_str(self) -> &'static str {
    match self {
      Self::ConfigReloaded => "config_reloaded",
      Self::SecretUpdated => "secret_updated",
      Self::BackendFailover => "backend_failover",
      Self::ProxyStarted => "proxy_started",
    }
  }
}

async fn send_webhooks(urls: &[String], payload: &WebhookPayload<'_>) -> Result<(), String> {
  let body = serde_json::to_string(payload).map_err(|err| err.to_string())?;
  let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(10))
    .build()
    .map_err(|err| err.to_string())?;

  for url in urls {
    let response = client
      .post(url)
      .header("Content-Type", "application/json")
      .header("User-Agent", "StealthGate-Webhook/1.0")
      .body(body.clone())
      .send()
      .await
      .map_err(|err| format!("POST {url}: {err}"))?;

    if !response.status().is_success() {
      tracing::warn!(url = %url, status = %response.status(), "webhook вернул ошибку");
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn event_names_match_config() {
    assert_eq!(WebhookEvent::SecretUpdated.as_str(), "secret_updated");
  }
}
