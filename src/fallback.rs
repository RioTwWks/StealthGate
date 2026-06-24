use std::path::Path;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::FallbackConfig;
use crate::domain_fronting::{forward_tcp, resolve_fronting_target};
use crate::error::{Result, StealthGateError};
use crate::state::Stats;

const DEFAULT_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 40rem; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.75rem; }
    p { line-height: 1.6; color: #444; }
  </style>
</head>
<body>
  <h1>Welcome</h1>
  <p>The site is up and running.</p>
</body>
</html>
"#;

/// Обрабатывает не-MTProto соединение.
pub async fn handle_fallback(
  client: TcpStream,
  initial_data: &[u8],
  config: &FallbackConfig,
  sni: Option<&str>,
  stats: &Stats,
) -> Result<()> {
  if let Some(target) = resolve_fronting_target(config, sni) {
    stats
      .domain_fronted
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::debug!(target = %target, "domain fronting");
    return forward_tcp(client, initial_data, &target).await;
  }

  if let Some(upstream) = &config.upstream {
    return proxy_to_upstream(client, initial_data, upstream).await;
  }

  serve_static_html(client, initial_data, config.static_html.as_deref()).await
}

/// Возвращает HTML-контент для заглушки.
pub fn resolve_html_content(static_html: Option<&str>) -> String {
  resolve_html(static_html)
}

async fn serve_static_html(
  mut client: TcpStream,
  initial_data: &[u8],
  static_html: Option<&str>,
) -> Result<()> {
  let html = resolve_html(static_html);
  let body = html.as_bytes();

  let is_http = initial_data.starts_with(b"GET ")
    || initial_data.starts_with(b"HEAD ")
    || initial_data.starts_with(b"POST ");

  if is_http {
    let response = format!(
      "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
      body.len()
    );

    client
      .write_all(response.as_bytes())
      .await
      .map_err(|err| StealthGateError::Proxy(format!("запись HTTP-ответа: {err}")))?;
    client
      .write_all(body)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("запись HTML: {err}")))?;
    return Ok(());
  }

  if initial_data.first() == Some(&0x16) {
    let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a];
    client
      .write_all(&alert)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("запись TLS alert: {err}")))?;
    return Ok(());
  }

  let response = format!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
    body.len()
  );
  client
    .write_all(response.as_bytes())
    .await
    .map_err(|err| StealthGateError::Proxy(format!("запись ответа: {err}")))?;
  client
    .write_all(body)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("запись тела: {err}")))?;

  Ok(())
}

fn resolve_html(static_html: Option<&str>) -> String {
  let Some(value) = static_html else {
    return DEFAULT_HTML.to_string();
  };

  let path = Path::new(value);
  if path.extension().is_some_and(|ext| ext == "html") {
    if let Ok(content) = std::fs::read_to_string(path) {
      return content;
    }
  }

  value.to_string()
}

async fn proxy_to_upstream(
  client: TcpStream,
  initial_data: &[u8],
  upstream: &str,
) -> Result<()> {
  forward_tcp(client, initial_data, upstream).await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_html_is_valid() {
    assert!(DEFAULT_HTML.contains("<html"));
  }
}
