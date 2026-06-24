use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::Serialize;

use crate::config::Config;
use crate::error::{Result, StealthGateError};

/// Счётчики прокси в реальном времени.
#[derive(Debug, Default)]
pub struct Stats {
  pub total_connections: AtomicU64,
  pub mtproto_connections: AtomicU64,
  pub fallback_connections: AtomicU64,
  pub bytes_to_backend: AtomicU64,
  pub bytes_from_backend: AtomicU64,
  pub tls_handshakes: AtomicU64,
  pub fragmented_writes: AtomicU64,
}

impl Stats {
  /// Снимок статистики для API/MCP.
  pub fn snapshot(&self) -> StatsSnapshot {
    StatsSnapshot {
      total_connections: self.total_connections.load(Ordering::Relaxed),
      mtproto_connections: self.mtproto_connections.load(Ordering::Relaxed),
      fallback_connections: self.fallback_connections.load(Ordering::Relaxed),
      bytes_to_backend: self.bytes_to_backend.load(Ordering::Relaxed),
      bytes_from_backend: self.bytes_from_backend.load(Ordering::Relaxed),
      tls_handshakes: self.tls_handshakes.load(Ordering::Relaxed),
      fragmented_writes: self.fragmented_writes.load(Ordering::Relaxed),
    }
  }
}

/// Сериализуемый снимок статистики.
#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
  pub total_connections: u64,
  pub mtproto_connections: u64,
  pub fallback_connections: u64,
  pub bytes_to_backend: u64,
  pub bytes_from_backend: u64,
  pub tls_handshakes: u64,
  pub fragmented_writes: u64,
}

/// Разделяемое состояние прокси.
#[derive(Debug)]
pub struct AppState {
  pub config: RwLock<Config>,
  pub config_path: String,
  pub stats: Stats,
}

impl AppState {
  /// Создаёт состояние из загруженной конфигурации.
  pub fn new(config: Config, config_path: impl Into<String>) -> Arc<Self> {
    Arc::new(Self {
      config: RwLock::new(config),
      config_path: config_path.into(),
      stats: Stats::default(),
    })
  }

  /// Перечитывает конфигурацию с диска.
  pub fn reload_config(&self) -> Result<()> {
    let fresh = Config::from_file(&self.config_path)?;
    *self
      .config
      .write()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))? = fresh;
    Ok(())
  }

  /// Обновляет MTProto-секрет в памяти.
  pub fn update_secret(&self, secret: String) -> Result<()> {
    crate::config::decode_secret(&secret)?;
    let mut config = self
      .config
      .write()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.mtproto.secret = secret;
    Ok(())
  }

  /// Краткая сводка конфигурации для admin/MCP.
  pub fn config_summary(&self) -> Result<ConfigSummary> {
    let config = self
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    Ok(ConfigSummary {
      listen: format!("{}:{}", config.listen.host, config.listen.port),
      fake_domain: config.tls.fake_domain.clone(),
      backend: config.mtproto.backend.clone(),
      secret_prefix: config.mtproto.secret.chars().take(4).collect(),
      tls_enabled: config.tls.is_enabled(),
      fragmentation_enabled: config.fragmentation.enabled,
      admin_socket: config.admin.socket.clone(),
    })
  }
}

/// Краткая сводка конфигурации.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigSummary {
  pub listen: String,
  pub fake_domain: String,
  pub backend: String,
  pub secret_prefix: String,
  pub tls_enabled: bool,
  pub fragmentation_enabled: bool,
  pub admin_socket: Option<String>,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    AdminConfig, FallbackConfig, FragmentationConfig, ListenConfig, MtprotoConfig, TlsConfig,
  };

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
  fn update_secret_validates_hex() {
    let state = AppState::new(sample_config(), "configs/config.toml");
    assert!(state.update_secret("bad".into()).is_err());
    assert!(state
      .update_secret("0123456789abcdef0123456789abcdef".into())
      .is_ok());
  }
}
