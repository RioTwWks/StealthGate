use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, StealthGateError};

/// Секция прослушивания.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Режим domain fronting для fallback-трафика.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DomainFrontingMode {
  #[default]
  None,
  /// Форвард на хост из SNI ClientHello.
  Sni,
  /// Форвард на фиксированный `fronting_host`.
  Fixed,
}

/// TLS-настройки для маскировки и терминации.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
  pub fake_domain: String,
  pub cert_file: Option<String>,
  pub key_file: Option<String>,
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

/// Дополнительный MTProto-секрет с опциональным backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
  pub label: String,
  pub secret: String,
  #[serde(default)]
  pub backend: Option<String>,
  /// 0 = без лимита.
  #[serde(default)]
  pub max_connections: u32,
}

/// MTProto-настройки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtprotoConfig {
  pub secret: String,
  pub backend: String,
  #[serde(default)]
  pub secrets: Vec<SecretEntry>,
}

impl MtprotoConfig {
  /// Все секреты: основной + дополнительные.
  pub fn all_secrets(&self) -> Vec<SecretRoute> {
    let mut result = vec![SecretRoute {
      label: "default".into(),
      secret: self.secret.clone(),
      backend: self.backend.clone(),
      max_connections: 0,
    }];
    for entry in &self.secrets {
      result.push(SecretRoute {
        label: entry.label.clone(),
        secret: entry.secret.clone(),
        backend: entry
          .backend
          .clone()
          .unwrap_or_else(|| self.backend.clone()),
        max_connections: entry.max_connections,
      });
    }
    result
  }
}

/// Маршрут для конкретного секрета.
#[derive(Debug, Clone)]
pub struct SecretRoute {
  pub label: String,
  pub secret: String,
  pub backend: String,
  pub max_connections: u32,
}

/// Fallback для не-MTProto трафика.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
  pub upstream: Option<String>,
  pub static_html: Option<String>,
  #[serde(default)]
  pub domain_fronting: DomainFrontingMode,
  pub fronting_host: Option<String>,
  #[serde(default = "default_fronting_port")]
  pub fronting_port: u16,
}

fn default_fronting_port() -> u16 {
  443
}

/// Динамическая фрагментация начального пакета.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Безопасность и лимиты.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
  #[serde(default = "default_antireplay_cache")]
  pub antireplay_cache_size: usize,
  #[serde(default)]
  pub ja4_enforce: bool,
  /// 0 = без лимита.
  #[serde(default)]
  pub max_connections_per_ip: u32,
  #[serde(default)]
  pub ip_blacklist: Vec<String>,
}

fn default_antireplay_cache() -> usize {
  65_536
}

impl Default for SecurityConfig {
  fn default() -> Self {
    Self {
      antireplay_cache_size: default_antireplay_cache(),
      ja4_enforce: false,
      max_connections_per_ip: 0,
      ip_blacklist: Vec::new(),
    }
  }
}

/// Сетевые настройки исходящих соединений.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
  pub socks5_proxy: Option<String>,
  #[serde(default = "default_backend_timeout")]
  pub backend_timeout_secs: u64,
}

fn default_backend_timeout() -> u64 {
  30
}

/// Prometheus metrics endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_metrics_host")]
  pub host: String,
  #[serde(default = "default_metrics_port")]
  pub port: u16,
}

fn default_metrics_host() -> String {
  "127.0.0.1".into()
}

fn default_metrics_port() -> u16 {
  9091
}

impl Default for MetricsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      host: default_metrics_host(),
      port: default_metrics_port(),
    }
  }
}

/// Admin API через Unix-сокет.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminConfig {
  pub socket: Option<String>,
}

/// WebUI-дашборд управления.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebuiConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_webui_host")]
  pub host: String,
  #[serde(default = "default_webui_port")]
  pub port: u16,
  #[serde(default = "default_session_secret")]
  pub session_secret: String,
  #[serde(default = "default_users_file")]
  pub users_file: String,
}

fn default_webui_host() -> String {
  "127.0.0.1".into()
}

fn default_webui_port() -> u16 {
  8088
}

fn default_session_secret() -> String {
  "change-me-in-production".into()
}

fn default_users_file() -> String {
  "data/users.json".into()
}

impl Default for WebuiConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      host: default_webui_host(),
      port: default_webui_port(),
      session_secret: default_session_secret(),
      users_file: default_users_file(),
    }
  }
}

impl WebuiConfig {
  /// Адрес HTTP-сервера WebUI.
  pub fn socket_addr(&self) -> Result<SocketAddr> {
    format!("{}:{}", self.host, self.port)
      .parse()
      .map_err(|err| StealthGateError::Config(format!("некорректный webui-адрес: {err}")))
  }
}

/// Корневая конфигурация прокси.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
  pub listen: ListenConfig,
  pub tls: TlsConfig,
  pub mtproto: MtprotoConfig,
  pub fallback: FallbackConfig,
  #[serde(default)]
  pub fragmentation: FragmentationConfig,
  #[serde(default)]
  pub security: SecurityConfig,
  #[serde(default)]
  pub network: NetworkConfig,
  #[serde(default)]
  pub metrics: MetricsConfig,
  #[serde(default)]
  pub admin: AdminConfig,
  #[serde(default)]
  pub webui: WebuiConfig,
}

impl Config {
  /// Загружает и валидирует конфигурацию из TOML-файла.
  pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
    let content = fs::read_to_string(path.as_ref()).map_err(|err| {
      StealthGateError::Config(format!(
        "не удалось прочитать {}: {err}",
        path.as_ref().display()
      ))
    })?;

    let config: Self = toml::from_str(&content)
      .map_err(|err| StealthGateError::Config(format!("ошибка парсинга TOML: {err}")))?;
    config.validate()?;
    Ok(config)
  }

  /// Сохраняет конфигурацию в TOML-файл.
  pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
    self.validate()?;
    let content = toml::to_string_pretty(self)
      .map_err(|err| StealthGateError::Config(format!("сериализация TOML: {err}")))?;
    fs::write(path.as_ref(), content).map_err(|err| {
      StealthGateError::Config(format!(
        "не удалось записать {}: {err}",
        path.as_ref().display()
      ))
    })
  }

  /// Валидирует конфигурацию.
  pub fn validate(&self) -> Result<()> {
    decode_secret(&self.mtproto.secret)?;
    for entry in &self.mtproto.secrets {
      decode_secret(&entry.secret)?;
      if entry.label.trim().is_empty() {
        return Err(StealthGateError::Config(
          "mtproto.secrets[].label не может быть пустым".into(),
        ));
      }
    }

    if self.fallback.domain_fronting == DomainFrontingMode::Fixed
      && self
        .fallback
        .fronting_host
        .as_ref()
        .is_none_or(|host| host.trim().is_empty())
    {
      return Err(StealthGateError::Config(
        "fallback.fronting_host обязателен при domain_fronting = \"fixed\"".into(),
      ));
    }

    if !self.fragmentation.chunk_sizes.is_empty()
      && self.fragmentation.chunk_sizes.contains(&0)
    {
      return Err(StealthGateError::Config(
        "fragmentation.chunk_sizes не может содержать 0".into(),
      ));
    }

    for ip in &self.security.ip_blacklist {
      ip.parse::<std::net::IpAddr>().map_err(|err| {
        StealthGateError::Config(format!("некорректный IP в blacklist: {ip}: {err}"))
      })?;
    }

    Ok(())
  }

  /// Минимальная конфигурация для unit/integration тестов.
  pub fn test_minimal(users_file: impl Into<String>) -> Self {
    Self {
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
        secrets: Vec::new(),
      },
      fallback: FallbackConfig {
        upstream: None,
        static_html: None,
        domain_fronting: DomainFrontingMode::None,
        fronting_host: None,
        fronting_port: 443,
      },
      fragmentation: FragmentationConfig::default(),
      security: SecurityConfig::default(),
      network: NetworkConfig::default(),
      metrics: MetricsConfig::default(),
      admin: AdminConfig::default(),
      webui: WebuiConfig {
        users_file: users_file.into(),
        ..Default::default()
      },
    }
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
  }

  #[test]
  fn fragmentation_defaults() {
    let config: FragmentationConfig = toml::from_str("").expect("default");
    assert!(!config.enabled);
    assert_eq!(config.chunk_sizes, vec![1, 2, 1]);
  }

  #[test]
  fn validate_fixed_fronting_requires_host() {
    let config = Config {
      listen: ListenConfig {
        host: "127.0.0.1".into(),
        port: 443,
      },
      tls: TlsConfig {
        fake_domain: "example.com".into(),
        cert_file: None,
        key_file: None,
        ja4_profile: None,
      },
      mtproto: MtprotoConfig {
        secret: "0123456789abcdef0123456789abcdef".into(),
        backend: "127.0.0.1:443".into(),
        secrets: Vec::new(),
      },
      fallback: FallbackConfig {
        upstream: None,
        static_html: None,
        domain_fronting: DomainFrontingMode::Fixed,
        fronting_host: None,
        fronting_port: 443,
      },
      fragmentation: FragmentationConfig::default(),
      security: SecurityConfig::default(),
      network: NetworkConfig::default(),
      metrics: MetricsConfig::default(),
      admin: AdminConfig::default(),
      webui: WebuiConfig::default(),
    };
    assert!(config.validate().is_err());
  }
}
