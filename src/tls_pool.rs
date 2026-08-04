//! Пулы SNI и JA4-фингерпринтов с ротацией.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::config::RotationMode;

const DEFAULT_ROTATION_INTERVAL_SECS: u64 = 300;

/// Селектор значений из пула с поддержкой ротации.
#[derive(Debug)]
pub struct RotationSelector {
  items: Vec<String>,
  mode: RotationMode,
  interval: Duration,
  counter: AtomicU64,
  started: Instant,
}

impl RotationSelector {
  /// Создаёт селектор из дополнительных элементов пула.
  pub fn new(items: Vec<String>, mode: RotationMode, interval_secs: Option<u64>) -> Self {
    Self {
      items,
      mode,
      interval: Duration::from_secs(interval_secs.unwrap_or(DEFAULT_ROTATION_INTERVAL_SECS).max(1)),
      counter: AtomicU64::new(0),
      started: Instant::now(),
    }
  }

  /// Все уникальные значения: primary + пул (без учёта регистра).
  pub fn all_items(&self, primary: &str) -> Vec<String> {
    merge_unique(primary, &self.items)
  }

  /// Активное значение для proxy-link и UI (с учётом режима ротации).
  pub fn active_item(&self, primary: &str) -> String {
    let items = self.all_items(primary);
    if items.is_empty() {
      return primary.to_string();
    }
    if items.len() == 1 || self.mode == RotationMode::None {
      return items[0].clone();
    }

    match self.mode {
      RotationMode::None => items[0].clone(),
      RotationMode::PerConnection => {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % items.len();
        items[idx].clone()
      }
      RotationMode::TimeBased => {
        let slot = self.started.elapsed().as_secs() / self.interval.as_secs();
        items[(slot as usize) % items.len()].clone()
      }
    }
  }

  /// Случайный элемент из пула (для per-connection выбора).
  pub fn random_item(&self, primary: &str) -> String {
    let items = self.all_items(primary);
    if items.is_empty() {
      return primary.to_string();
    }
    if items.len() == 1 {
      return items[0].clone();
    }
    let idx = rand::thread_rng().gen_range(0..items.len());
    items[idx].clone()
  }

  /// Выбирает значение согласно режиму ротации.
  pub fn select(&self, primary: &str) -> String {
    match self.mode {
      RotationMode::None => primary.to_string(),
      RotationMode::PerConnection => self.random_item(primary),
      RotationMode::TimeBased => self.active_item(primary),
    }
  }
}

/// Объединяет primary и пул без дубликатов (case-insensitive).
pub fn merge_unique(primary: &str, pool: &[String]) -> Vec<String> {
  let mut result = Vec::new();
  let primary = primary.trim();
  if !primary.is_empty() {
    result.push(primary.to_string());
  }
  for item in pool {
    let trimmed = item.trim();
    if trimmed.is_empty() {
      continue;
    }
    if result
      .iter()
      .any(|existing| existing.eq_ignore_ascii_case(trimmed))
    {
      continue;
    }
    result.push(trimmed.to_string());
  }
  result
}

/// Проверяет, входит ли домен в пул SNI.
pub fn sni_matches_pool(domain: &str, primary: &str, pool: &[String]) -> bool {
  merge_unique(primary, pool)
    .iter()
    .any(|candidate| candidate.eq_ignore_ascii_case(domain))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn merge_unique_deduplicates_case_insensitive() {
    let merged = merge_unique(
      "Cloudflare.com",
      &["cloudflare.com".into(), "google.com".into()],
    );
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0], "Cloudflare.com");
    assert_eq!(merged[1], "google.com");
  }

  #[test]
  fn sni_matches_any_domain_in_pool() {
    assert!(sni_matches_pool(
      "google.com",
      "cloudflare.com",
      &["google.com".into(), "microsoft.com".into()]
    ));
    assert!(!sni_matches_pool(
      "example.com",
      "cloudflare.com",
      &["google.com".into()]
    ));
  }

  #[test]
  fn per_connection_rotation_cycles() {
    let selector = RotationSelector::new(
      vec!["b.com".into(), "c.com".into()],
      RotationMode::PerConnection,
      None,
    );
    let first = selector.active_item("a.com");
    let second = selector.active_item("a.com");
    assert_ne!(first, second);
    assert!(["a.com", "b.com", "c.com"].contains(&first.as_str()));
  }
}
