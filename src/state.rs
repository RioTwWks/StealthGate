use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::antireplay::AntiReplayCache;
use crate::backend_pool::BackendPool;
use crate::config::{Config, FragmentationConfig, MtprotoConfig, WebhooksConfig};
use crate::error::{Result, StealthGateError};
use crate::limits::ConnectionLimiter;
use crate::users::UserStore;
use crate::webhooks::{dispatch, WebhookEvent};

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
  pub drs_writes: AtomicU64,
  pub dd_writes: AtomicU64,
  pub backend_failovers: AtomicU64,
  pub replay_blocked: AtomicU64,
  pub domain_fronted: AtomicU64,
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
      drs_writes: self.drs_writes.load(Ordering::Relaxed),
      dd_writes: self.dd_writes.load(Ordering::Relaxed),
      backend_failovers: self.backend_failovers.load(Ordering::Relaxed),
      replay_blocked: self.replay_blocked.load(Ordering::Relaxed),
      domain_fronted: self.domain_fronted.load(Ordering::Relaxed),
    }
  }
}

/// Сериализуемый снимок статистики.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
  pub total_connections: u64,
  pub mtproto_connections: u64,
  pub fallback_connections: u64,
  pub bytes_to_backend: u64,
  pub bytes_from_backend: u64,
  pub tls_handshakes: u64,
  pub fragmented_writes: u64,
  pub drs_writes: u64,
  pub dd_writes: u64,
  pub backend_failovers: u64,
  pub replay_blocked: u64,
  pub domain_fronted: u64,
}

/// Разделяемое состояние прокси.
pub struct AppState {
  pub config: RwLock<Config>,
  pub config_path: String,
  pub stats: Stats,
  pub users: Arc<UserStore>,
  pub antireplay: AntiReplayCache,
  pub limits: ConnectionLimiter,
  pub backend_pool: RwLock<Arc<BackendPool>>,
}

impl AppState {
  /// Создаёт состояние из загруженной конфигурации.
  pub fn new(config: Config, config_path: impl Into<String>) -> Result<Arc<Self>> {
    let config_path = config_path.into();
    let users = UserStore::load(&config.webui.users_file)?;
    let antireplay = AntiReplayCache::new(config.security.antireplay_cache_size);
    let backend_pool = Arc::new(BackendPool::from_config(&config.mtproto));
    Ok(Arc::new(Self {
      config: RwLock::new(config),
      config_path,
      stats: Stats::default(),
      users,
      antireplay,
      limits: ConnectionLimiter::default(),
      backend_pool: RwLock::new(backend_pool),
    }))
  }

  fn webhooks_config(&self) -> Result<WebhooksConfig> {
    let config = self
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    Ok(config.webhooks.clone())
  }

  fn sync_backend_pool(&self) -> Result<()> {
    let mtproto = {
      let config = self
        .config
        .read()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.mtproto.clone()
    };
    let mut pool = self
      .backend_pool
      .write()
      .map_err(|_| StealthGateError::Config("блокировка backend_pool poisoned".into()))?;
    *pool = Arc::new(BackendPool::from_config(&mtproto));
    Ok(())
  }

  /// IP blacklist из конфигурации.
  pub fn ip_blacklist(&self) -> Result<Vec<IpAddr>> {
    let config = self
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    config
      .security
      .ip_blacklist
      .iter()
      .map(|ip| {
        ip.parse()
          .map_err(|err| StealthGateError::Config(format!("blacklist IP {ip}: {err}")))
      })
      .collect()
  }

  /// Перечитывает конфигурацию с диска.
  pub fn reload_config(&self) -> Result<()> {
    let fresh = Config::from_file(&self.config_path)?;
    *self
      .config
      .write()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))? = fresh;
    self.sync_backend_pool()?;
    dispatch(
      &self.webhooks_config()?,
      WebhookEvent::ConfigReloaded,
      None,
    );
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
    self.save_config()?;
    dispatch(
      &self.webhooks_config()?,
      WebhookEvent::SecretUpdated,
      None,
    );
    Ok(())
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
    self.save_config()?;
    self.sync_backend_pool()?;
    dispatch(
      &self.webhooks_config()?,
      WebhookEvent::SecretUpdated,
      None,
    );
    Ok(())
  }

  /// Обновляет только MTProto-секцию (admin API).
  pub fn update_mtproto(&self, mtproto: MtprotoConfig) -> Result<()> {
    crate::config::decode_secret(&mtproto.secret)?;
    for entry in &mtproto.secrets {
      crate::config::decode_secret(&entry.secret)?;
    }
    {
      let mut config = self
        .config
        .write()
        .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
      config.mtproto = mtproto;
    }
    self.save_config()?;
    self.sync_backend_pool()?;
    Ok(())
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

  /// Ссылка tg://proxy для текущего listen/secret.
  pub fn proxy_link(&self) -> Result<String> {
    let config = self
      .config
      .read()
      .map_err(|_| StealthGateError::Config("блокировка config poisoned".into()))?;
    Ok(format!(
      "tg://proxy?server={}&port={}&secret={}",
      config.listen.host, config.listen.port, config.mtproto.secret
    ))
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
      secrets_count: 1 + config.mtproto.secrets.len(),
      tls_enabled: config.tls.is_enabled(),
      fragmentation_enabled: config.fragmentation.enabled,
      fragmentation_delay_ms: config.fragmentation.delay_ms,
      fragmentation_chunk_sizes: config.fragmentation.chunk_sizes.clone(),
      drs_enabled: config.drs.enabled,
      backends_count: config.mtproto.all_backends().len(),
      failover_strategy: format!("{:?}", config.mtproto.failover_strategy).to_lowercase(),
      webhooks_enabled: config.webhooks.enabled,
      domain_fronting: format!("{:?}", config.fallback.domain_fronting).to_lowercase(),
      socks5_proxy: config.network.socks5_proxy.clone(),
      admin_socket: config.admin.socket.clone(),
      webui_enabled: config.webui.enabled,
      webui_listen: format!("{}:{}", config.webui.host, config.webui.port),
      metrics_enabled: config.metrics.enabled,
      metrics_listen: format!("{}:{}", config.metrics.host, config.metrics.port),
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
  pub secrets_count: usize,
  pub tls_enabled: bool,
  pub fragmentation_enabled: bool,
  pub fragmentation_delay_ms: u64,
  pub fragmentation_chunk_sizes: Vec<usize>,
  pub drs_enabled: bool,
  pub backends_count: usize,
  pub failover_strategy: String,
  pub webhooks_enabled: bool,
  pub domain_fronting: String,
  pub socks5_proxy: Option<String>,
  pub admin_socket: Option<String>,
  pub webui_enabled: bool,
  pub webui_listen: String,
  pub metrics_enabled: bool,
  pub metrics_listen: String,
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
  use crate::config::Config;
  use tempfile::tempdir;

  fn sample_config(users_file: &str) -> Config {
    Config::test_minimal(users_file)
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
