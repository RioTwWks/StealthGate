use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::{Config, FragmentationConfig, MtprotoConfig};
use crate::error::{Result, StealthGateError};
use crate::users::UserStore;

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
pub struct AppState {
  pub config: RwLock<Config>,
  pub config_path: String,
  pub stats: Stats,
  pub users: Arc<UserStore>,
}

impl AppState {
  /// Создаёт состояние из загруженной конфигурации.
  pub fn new(config: Config, config_path: impl Into<String>) -> Result<Arc<Self>> {
    let config_path = config_path.into();
    let users = UserStore::load(&config.webui.users_file)?;
    Ok(Arc::new(Self {
      config: RwLock::new(config),
      config_path,
      stats: Stats::default(),
      users,
    }))
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

  /// Сохраняет текущую конфигурацию на диск.
  pub fn save_config(&self) -> Result<()> {
    let config = self
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.save_to_file(&self.config_path)
  }

  /// Обновляет MTProto-секрет в памяти и на диске.
  pub fn update_secret(&self, secret: String) -> Result<()> {
    crate::config::decode_secret(&secret)?;
    {
      let mut config = self
        .config
        .write()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.mtproto.secret = secret;
    }
    self.save_config()
  }

  /// Обновляет MTProto backend и домен маскировки.
  pub fn update_proxy_settings(
    &self,
    secret: String,
    backend: String,
    fake_domain: String,
  ) -> Result<()> {
    crate::config::decode_secret(&secret)?;
    {
      let mut config = self
        .config
        .write()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.mtproto.secret = secret;
      config.mtproto.backend = backend;
      config.tls.fake_domain = fake_domain;
    }
    self.save_config()
  }

  /// Обновляет только MTProto-секцию (admin API).
  pub fn update_mtproto(&self, mtproto: MtprotoConfig) -> Result<()> {
    crate::config::decode_secret(&mtproto.secret)?;
    {
      let mut config = self
        .config
        .write()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.mtproto = mtproto;
    }
    self.save_config()
  }

  /// Обновляет настройки фрагментации.
  pub fn update_fragmentation(&self, fragmentation: FragmentationConfig) -> Result<()> {
    let mut config = self
      .config
      .write()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config.fragmentation = fragmentation;
    drop(config);
    self.save_config()
  }

  /// Краткая сводка конфигурации для admin/MCP/WebUI.
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
      fragmentation_delay_ms: config.fragmentation.delay_ms,
      fragmentation_chunk_sizes: config.fragmentation.chunk_sizes.clone(),
      admin_socket: config.admin.socket.clone(),
      webui_enabled: config.webui.enabled,
      webui_listen: format!("{}:{}", config.webui.host, config.webui.port),
    })
  }

  /// Полная конфигурация для редактирования в WebUI.
  pub fn full_config(&self) -> Result<Config> {
    self
      .config
      .read()
      .map(|config| config.clone())
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))
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
  pub fragmentation_delay_ms: u64,
  pub fragmentation_chunk_sizes: Vec<usize>,
  pub admin_socket: Option<String>,
  pub webui_enabled: bool,
  pub webui_listen: String,
}

/// Данные сессии WebUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
  pub username: String,
  pub display_name: String,
  pub role: crate::users::UserRole,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    AdminConfig, FallbackConfig, FragmentationConfig, ListenConfig, MtprotoConfig, TlsConfig,
    WebuiConfig,
  };
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
  fn update_secret_validates_hex() {
    let dir = tempdir().expect("tempdir");
    let users = dir.path().join("users.json").to_string_lossy().to_string();
    let config = sample_config(&users);
    let config_path = dir.path().join("config.toml");
    config.save_to_file(&config_path).expect("save");
    let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
    assert!(state.update_secret("bad".into()).is_err());
    assert!(state
      .update_secret("0123456789abcdef0123456789abcdef".into())
      .is_ok());
  }
}
