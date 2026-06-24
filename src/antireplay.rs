use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// LRU-кэш ClientHello для защиты от replay-атак DPI.
#[derive(Debug)]
pub struct AntiReplayCache {
  capacity: usize,
  order: Mutex<VecDeque<u64>>,
  seen: Mutex<HashSet<u64>>,
}

impl AntiReplayCache {
  /// Создаёт кэш заданной ёмкости.
  pub fn new(capacity: usize) -> Self {
    Self {
      capacity: capacity.max(1),
      order: Mutex::new(VecDeque::new()),
      seen: Mutex::new(HashSet::new()),
    }
  }

  /// Возвращает `true`, если запись уже встречалась (replay).
  pub fn is_replay(&self, fingerprint: u64) -> bool {
    let mut seen = self.seen.lock().expect("antireplay seen");
    if seen.contains(&fingerprint) {
      return true;
    }

    let mut order = self.order.lock().expect("antireplay order");
    seen.insert(fingerprint);
    order.push_back(fingerprint);

    while order.len() > self.capacity {
      if let Some(old) = order.pop_front() {
        seen.remove(&old);
      }
    }

    false
  }
}

/// Вычисляет fingerprint ClientHello для anti-replay.
pub fn client_hello_fingerprint(data: &[u8]) -> u64 {
  use std::collections::hash_map::DefaultHasher;
  let mut hasher = DefaultHasher::new();
  data.hash(&mut hasher);
  hasher.finish()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn detects_replay() {
    let cache = AntiReplayCache::new(4);
    assert!(!cache.is_replay(42));
    assert!(cache.is_replay(42));
    assert!(!cache.is_replay(43));
  }

  #[test]
  fn evicts_old_entries() {
    let cache = AntiReplayCache::new(2);
    assert!(!cache.is_replay(1));
    assert!(!cache.is_replay(2));
    assert!(!cache.is_replay(3));
    assert!(!cache.is_replay(1));
  }
}
