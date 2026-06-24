use std::path::Path;
use std::sync::Arc;
use std::sync::Once;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::FallbackConfig;
use crate::error::{Result, StealthGateError};
use crate::io_util::PrefixedStream;
use crate::state::Stats;

static RUSTLS_INIT: Once = Once::new();

/// Инициализирует crypto provider rustls (нужно вызвать до TLS-операций).
pub fn init_rustls() {
  RUSTLS_INIT.call_once(|| {
    rustls::crypto::ring::default_provider()
      .install_default()
      .expect("установка rustls crypto provider");
  });
}

/// Загружает TLS ServerConfig из PEM-файлов.
pub fn load_server_config(tls: &crate::config::TlsConfig) -> Result<Arc<rustls::ServerConfig>> {
  init_rustls();
  use rustls::ServerConfig;

  let cert_path = tls
    .cert_file
    .as_ref()
    .ok_or_else(|| StealthGateError::Config("cert_file не задан".into()))?;
  let key_path = tls
    .key_file
    .as_ref()
    .ok_or_else(|| StealthGateError::Config("key_file не задан".into()))?;

  let cert_chain = load_certs(cert_path)?;
  let key = load_private_key(key_path)?;

  let mut config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|err| StealthGateError::Config(format!("ошибка сборки TLS-конфига: {err}")))?;

  config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];

  Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
  let file = std::fs::File::open(path)
    .map_err(|err| StealthGateError::Config(format!("не удалось открыть {path}: {err}")))?;
  let mut reader = std::io::BufReader::new(file);
  let certs = rustls_pemfile::certs(&mut reader)
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|err| StealthGateError::Config(format!("ошибка чтения cert: {err}")))?;
  if certs.is_empty() {
    return Err(StealthGateError::Config("файл cert пуст".into()));
  }
  Ok(certs)
}

fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
  use rustls::pki_types::PrivateKeyDer;

  let file = std::fs::File::open(path)
    .map_err(|err| StealthGateError::Config(format!("не удалось открыть {path}: {err}")))?;
  let mut reader = std::io::BufReader::new(file);

  if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
    .next()
    .transpose()
    .map_err(|err| StealthGateError::Config(format!("ошибка чтения key: {err}")))?
  {
    return Ok(PrivateKeyDer::Pkcs8(key));
  }

  let file = std::fs::File::open(path)
    .map_err(|err| StealthGateError::Config(format!("не удалось открыть {path}: {err}")))?;
  let mut reader = std::io::BufReader::new(file);
  if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
    .next()
    .transpose()
    .map_err(|err| StealthGateError::Config(format!("ошибка чтения RSA key: {err}")))?
  {
    return Ok(PrivateKeyDer::Pkcs1(key));
  }

  Err(StealthGateError::Config(
    "не найден приватный ключ (PKCS#8 или RSA)".into(),
  ))
}

/// Выполняет TLS-терминацию и отдаёт HTTP-заглушку.
pub async fn serve_tls_fallback(
  client: TcpStream,
  initial_data: Vec<u8>,
  acceptor: &TlsAcceptor,
  fallback: &FallbackConfig,
  stats: &Stats,
) -> Result<()> {
  let prefixed = PrefixedStream::new(initial_data, client);
  let mut tls_stream = acceptor
    .accept(prefixed)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("TLS handshake: {err}")))?;

  stats.tls_handshakes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

  let mut request_buf = vec![0u8; 4096];
  let _ = tls_stream
    .read(&mut request_buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("чтение HTTP поверх TLS: {err}")))?;

  let html = crate::fallback::resolve_html_content(fallback.static_html.as_deref());
  let body = html.as_bytes();
  let response = format!(
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
    body.len()
  );

  tls_stream
    .write_all(response.as_bytes())
    .await
    .map_err(|err| StealthGateError::Proxy(format!("запись HTTP-заголовка: {err}")))?;
  tls_stream
    .write_all(body)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("запись HTML: {err}")))?;

  Ok(())
}

/// Проверяет, что PEM-файлы существуют.
pub fn cert_files_exist(tls: &crate::config::TlsConfig) -> bool {
  tls
    .cert_file
    .as_ref()
    .zip(tls.key_file.as_ref())
    .is_some_and(|(cert, key)| Path::new(cert).exists() && Path::new(key).exists())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::TlsConfig;

  #[test]
  fn cert_files_exist_requires_both_paths() {
    let tls = TlsConfig {
      cert_file: Some("missing.pem".into()),
      key_file: Some("missing.key".into()),
      fake_domain: "example.com".into(),
      ja4_profile: None,
    };
    assert!(!cert_files_exist(&tls));
  }
}
