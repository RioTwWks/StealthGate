use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;

use crate::config::FragmentationConfig;
use crate::error::{Result, StealthGateError};
use crate::state::Stats;

/// Записывает данные на поток с опциональной фрагментацией.
pub async fn write_to_backend(
  stream: &mut TcpStream,
  data: &[u8],
  config: &FragmentationConfig,
  stats: &Stats,
) -> Result<()> {
  if !config.enabled || config.chunk_sizes.is_empty() {
    stream
      .write_all(data)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("запись в backend: {err}")))?;
    return Ok(());
  }

  let mut offset = 0usize;
  let mut size_idx = 0usize;
  let mut chunks_sent = 0u64;

  while offset < data.len() {
    let chunk_size = config.chunk_sizes[size_idx % config.chunk_sizes.len()].max(1);
    size_idx += 1;
    let end = (offset + chunk_size).min(data.len());
    stream
      .write_all(&data[offset..end])
      .await
      .map_err(|err| StealthGateError::Proxy(format!("фрагментированная запись: {err}")))?;
    offset = end;
    chunks_sent += 1;

    if offset < data.len() && config.delay_ms > 0 {
      sleep(Duration::from_millis(config.delay_ms)).await;
    }
  }

  if chunks_sent > 1 {
    stats
      .fragmented_writes
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
  }

  Ok(())
}

/// Разбивает буфер на чанки без записи (для тестов).
pub fn split_chunks(data: &[u8], config: &FragmentationConfig) -> Vec<Vec<u8>> {
  if !config.enabled || config.chunk_sizes.is_empty() {
    return vec![data.to_vec()];
  }

  let mut chunks = Vec::new();
  let mut offset = 0usize;
  let mut size_idx = 0usize;

  while offset < data.len() {
    let chunk_size = config.chunk_sizes[size_idx % config.chunk_sizes.len()].max(1);
    size_idx += 1;
    let end = (offset + chunk_size).min(data.len());
    chunks.push(data[offset..end].to_vec());
    offset = end;
  }

  chunks
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn split_chunks_disabled_returns_single_chunk() {
    let data = vec![1, 2, 3, 4, 5];
    let config = FragmentationConfig {
      enabled: false,
      chunk_sizes: vec![1],
      delay_ms: 0,
    };
    assert_eq!(split_chunks(&data, &config), vec![data]);
  }

  #[test]
  fn split_chunks_cycles_sizes() {
    let data: Vec<u8> = (0..10).collect();
    let config = FragmentationConfig {
      enabled: true,
      chunk_sizes: vec![2, 3],
      delay_ms: 0,
    };
    let chunks = split_chunks(&data, &config);
    assert_eq!(chunks, vec![vec![0, 1], vec![2, 3, 4], vec![5, 6], vec![7, 8, 9]]);
  }
}
