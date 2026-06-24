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

/// TLS-настройки для маскировки и терминации.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
  pub cert_file: Option<String>,
  pub key_file: Option<String>,
  pub fake_domain: String,
  /// Ожидаемый JA4-профиль для логирования/валидации (опционально).
  pub ja4_profile: Option<String>,
}

impl TlsConfig {
  /// TLS-терминация доступна, если заданы оба PEM-файла.
  pub fn is_enabled(&self) -> bool {
    self
      .cert_file
      .as_ref()
      .zip(self.key_file.as_ref())
      .is_some_and(|(cert, key)| Path::new(cert).exists() && Path::new(key).exists())
  }
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

/// Динамическая фрагментация начального пакета.
#[derive(Debug, Clone, Deserialize)]
pub struct FragmentationConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_chunk_sizes")]
  pub chunk_sizes: Vec<usize>,
  #[serde(default)]
  pub delay_ms: u64,
}

fn default_chunk_sizes() -> Vec<usize> {
  vec![1, 2, 1]
}

impl Default for FragmentationConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      chunk_sizes: default_chunk_sizes(),
      delay_ms: 0,
    }
  }
}

/// Admin API через Unix-сокет.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AdminConfig {
  pub socket: Option<String>,
}

/// Корневая конфигурация прокси.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
  pub listen: ListenConfig,
  pub tls: TlsConfig,
  pub mtproto: MtprotoConfig,
  pub fallback: FallbackConfig,
  #[serde(default)]
  pub fragmentation: FragmentationConfig,
  #[serde(default)]
  pub admin: AdminConfig,
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

  #[test]
  fn fragmentation_defaults() {
    let config: FragmentationConfig = toml::from_str("").expect("default");
    assert!(!config.enabled);
    assert_eq!(config.chunk_sizes, vec![1, 2, 1]);
  }
}
