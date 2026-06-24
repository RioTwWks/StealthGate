//! Пул backend-серверов с failover.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::config::{BackendFailoverStrategy, MtprotoConfig, NetworkConfig};
use crate::error::{Result, StealthGateError};
use crate::network;
use crate::state::Stats;

const UNHEALTHY_COOLDOWN: Duration = Duration::from_secs(30);

/// Пул Telegram DC с failover.
#[derive(Debug)]
pub struct BackendPool {
  backends: Vec<String>,
  strategy: BackendFailoverStrategy,
  round_robin: AtomicUsize,
  unhealthy: Mutex<HashMap<String, Instant>>,
}

impl BackendPool {
  /// Создаёт пул из конфигурации MTProto.
  pub fn from_config(mtproto: &MtprotoConfig) -> Self {
    Self {
      backends: mtproto.all_backends(),
      strategy: mtproto.failover_strategy,
      round_robin: AtomicUsize::new(0),
      unhealthy: Mutex::new(HashMap::new()),
    }
  }

  /// Подключается к backend с failover.
  pub async fn connect(
    &self,
    network: &NetworkConfig,
    preferred: Option<&str>,
    stats: &Stats,
  ) -> Result<(TcpStream, String)> {
    let order = self.connection_order(preferred);
    let mut last_error = None;

    for backend in order {
      if self.is_unhealthy(&backend) {
        continue;
      }

      match network::connect_backend(&backend, network).await {
        Ok(stream) => {
          tracing::debug!(backend = %backend, "backend подключён");
          return Ok((stream, backend));
        }
        Err(err) => {
          tracing::warn!(backend = %backend, error = %err, "backend недоступен");
          self.mark_unhealthy(&backend);
          stats
            .backend_failovers
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
          last_error = Some(err);
        }
      }
    }

    Err(last_error.unwrap_or_else(|| {
      StealthGateError::Proxy("нет доступных backend-серверов".into())
    }))
  }

  /// Количество backend в пуле.
  pub fn backend_count(&self) -> usize {
    self.backends.len()
  }

  fn connection_order(&self, preferred: Option<&str>) -> Vec<String> {
    if self.backends.len() <= 1 {
      return self.backends.clone();
    }

    let start_idx = match self.strategy {
      BackendFailoverStrategy::Priority => 0,
      BackendFailoverStrategy::RoundRobin => {
        self.round_robin.fetch_add(1, Ordering::Relaxed) % self.backends.len()
      }
    };

    let mut order: Vec<String> = (0..self.backends.len())
      .map(|offset| self.backends[(start_idx + offset) % self.backends.len()].clone())
      .collect();

    if let Some(preferred_backend) = preferred {
      if let Some(pos) = order.iter().position(|b| b == preferred_backend) {
        let item = order.remove(pos);
        order.insert(0, item);
      }
    }

    order
  }

  fn is_unhealthy(&self, backend: &str) -> bool {
    let unhealthy = self.unhealthy.lock().expect("unhealthy lock");
    unhealthy
      .get(backend)
      .is_some_and(|since| since.elapsed() < UNHEALTHY_COOLDOWN)
  }

  fn mark_unhealthy(&self, backend: &str) {
    let mut unhealthy = self.unhealthy.lock().expect("unhealthy lock");
    unhealthy.insert(backend.to_string(), Instant::now());
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::MtprotoConfig;

  #[test]
  fn collects_all_backends() {
    let mtproto = MtprotoConfig {
      secret: "0123456789abcdef0123456789abcdef".into(),
      backend: "1.1.1.1:443".into(),
      backends: vec!["2.2.2.2:443".into(), "1.1.1.1:443".into()],
      failover_strategy: BackendFailoverStrategy::Priority,
      secrets: Vec::new(),
    };
    let pool = BackendPool::from_config(&mtproto);
    assert_eq!(pool.backend_count(), 2);
  }

  #[test]
  fn round_robin_rotates_start() {
    let mtproto = MtprotoConfig {
      secret: "0123456789abcdef0123456789abcdef".into(),
      backend: "a:443".into(),
      backends: vec!["a:443".into(), "b:443".into()],
      failover_strategy: BackendFailoverStrategy::RoundRobin,
      secrets: Vec::new(),
    };
    let pool = BackendPool::from_config(&mtproto);
    let first = pool.connection_order(None);
    let second = pool.connection_order(None);
    assert_ne!(first[0], second[0]);
  }
}
