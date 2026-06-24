use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::error::{Result, StealthGateError};

/// Лимиты одновременных соединений по IP и секрету.
#[derive(Debug, Default)]
pub struct ConnectionLimiter {
  per_ip: Mutex<HashMap<IpAddr, u32>>,
  per_secret: Mutex<HashMap<String, u32>>,
}

impl ConnectionLimiter {
  /// Проверяет лимиты и увеличивает счётчики.
  pub fn acquire(
    &self,
    ip: IpAddr,
    secret_label: &str,
    max_per_ip: u32,
    max_per_secret: u32,
    blacklist: &[IpAddr],
  ) -> Result<()> {
    if blacklist.contains(&ip) {
      return Err(StealthGateError::Proxy(format!("IP {ip} в blacklist")));
    }

    if max_per_ip > 0 {
      let mut per_ip = self.per_ip.lock().expect("per_ip");
      let count = per_ip.entry(ip).or_insert(0);
      if *count >= max_per_ip {
        return Err(StealthGateError::Proxy(format!(
          "превышен лимит соединений для IP {ip}"
        )));
      }
      *count += 1;
    }

    if max_per_secret > 0 {
      let mut per_secret = self.per_secret.lock().expect("per_secret");
      let count = per_secret.entry(secret_label.to_string()).or_insert(0);
      if *count >= max_per_secret {
        if max_per_ip > 0 {
          self.release_ip(ip, max_per_ip);
        }
        return Err(StealthGateError::Proxy(format!(
          "превышен лимит соединений для секрета {secret_label}"
        )));
      }
      *count += 1;
    }

    Ok(())
  }

  /// Уменьшает счётчики после завершения соединения.
  pub fn release(&self, ip: IpAddr, secret_label: &str, max_per_ip: u32, max_per_secret: u32) {
    if max_per_ip > 0 {
      self.release_ip(ip, max_per_ip);
    }
    if max_per_secret > 0 {
      let mut per_secret = self.per_secret.lock().expect("per_secret");
      if let Some(count) = per_secret.get_mut(secret_label) {
        *count = count.saturating_sub(1);
        if *count == 0 {
          per_secret.remove(secret_label);
        }
      }
    }
  }

  fn release_ip(&self, ip: IpAddr, max_per_ip: u32) {
    if max_per_ip == 0 {
      return;
    }
    let mut per_ip = self.per_ip.lock().expect("per_ip");
    if let Some(count) = per_ip.get_mut(&ip) {
      *count = count.saturating_sub(1);
      if *count == 0 {
        per_ip.remove(&ip);
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;

  #[test]
  fn enforces_per_ip_limit() {
    let limiter = ConnectionLimiter::default();
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    limiter.acquire(ip, "default", 1, 0, &[]).expect("first");
    assert!(limiter.acquire(ip, "default", 1, 0, &[]).is_err());
    limiter.release(ip, "default", 1, 0);
    limiter.acquire(ip, "default", 1, 0, &[]).expect("after release");
  }
}
