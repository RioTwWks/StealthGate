use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, StealthGateError};

/// Секция прослушивания.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
  pub host: String,
  pub port: u16,
}

impl ListenConfig {
  /// Возвращает адрес для bind.
  pub fn socket_addr(&self) -> Result<SocketAddr> {
    format!("{}:{}", self.host, self.port)
      .parse()
      .map_err(|err| StealthGateError::Config(format!("некорректный listen-адрес: {err}")))
  }
}

/// TLS-настройки для маскировки.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
  pub cert_file: Option<String>,
  pub key_file: Option<String>,
  pub fake_domain: String,
}

/// MTProto-настройки.
#[derive(Debug, Clone, Deserialize)]
pub struct MtprotoConfig {
  pub secret: String,
  pub backend: String,
}

/// Fallback для не-MTProto трафика.
#[derive(Debug, Clone, Deserialize)]
pub struct FallbackConfig {
  pub upstream: Option<String>,
  pub static_html: Option<String>,
}

/// Корневая конфигурация прокси.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
  pub listen: ListenConfig,
  pub tls: TlsConfig,
  pub mtproto: MtprotoConfig,
  pub fallback: FallbackConfig,
}

impl Config {
  /// Загружает конфигурацию из TOML-файла.
  pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
    let content = fs::read_to_string(path.as_ref()).map_err(|err| {
      StealthGateError::Config(format!(
        "не удалось прочитать {}: {err}",
        path.as_ref().display()
      ))
    })?;

    toml::from_str(&content)
      .map_err(|err| StealthGateError::Config(format!("ошибка парсинга TOML: {err}")))
  }

  /// Декодирует hex-секрет MTProto (с опциональным префиксом `dd`/`ee`).
  pub fn mtproto_secret_bytes(&self) -> Result<Vec<u8>> {
    decode_secret(&self.mtproto.secret)
  }
}

/// Декодирует hex-секрет MTProto.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
  let normalized = secret.trim().to_ascii_lowercase();
  let hex_part = normalized
    .strip_prefix("dd")
    .or_else(|| normalized.strip_prefix("ee"))
    .unwrap_or(&normalized);

  if hex_part.len() != 32 || !hex_part.chars().all(|ch| ch.is_ascii_hexdigit()) {
    return Err(StealthGateError::Config(
      "секрет должен быть 16 байт в hex (32 символа), опционально с префиксом dd/ee".into(),
    ));
  }

  hex::decode(hex_part)
    .map_err(|err| StealthGateError::Config(format!("некорректный hex-секрет: {err}")))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decode_secret_with_ee_prefix() {
    let bytes = decode_secret("ee0123456789abcdef0123456789abcdef").expect("декодирование");
    assert_eq!(bytes.len(), 16);
    assert_eq!(bytes[0], 0x01);
  }

  #[test]
  fn decode_secret_without_prefix() {
    let bytes = decode_secret("0123456789abcdef0123456789abcdef").expect("декодирование");
    assert_eq!(bytes.len(), 16);
  }
}
