//! Dynamic Record Sizing — имитация размеров TLS application records.

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::DrsConfig;
use crate::error::{Result, StealthGateError};
use crate::state::Stats;

/// Записывает буфер чанками DRS (имитация TLS record sizing).
pub async fn write_with_drs(
  stream: &mut TcpStream,
  data: &[u8],
  config: &DrsConfig,
  stats: &Stats,
) -> Result<()> {
  if !config.enabled || config.record_sizes.is_empty() {
    stream
      .write_all(data)
      .await
      .map_err(|err| StealthGateError::Proxy(format!("DRS write: {err}")))?;
    return Ok(());
  }

  let mut offset = 0usize;
  let mut size_idx = 0usize;
  let mut chunks_sent = 0u64;

  while offset < data.len() {
    let chunk_size = config.record_sizes[size_idx % config.record_sizes.len()].max(1);
    size_idx += 1;
    let end = (offset + chunk_size).min(data.len());
    stream
      .write_all(&data[offset..end])
      .await
      .map_err(|err| StealthGateError::Proxy(format!("DRS chunk write: {err}")))?;
    offset = end;
    chunks_sent += 1;
  }

  if chunks_sent > 1 {
    stats
      .drs_writes
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
  }

  Ok(())
}

/// Разбивает буфер на DRS-чанки (для тестов).
pub fn split_drs_chunks(data: &[u8], config: &DrsConfig) -> Vec<Vec<u8>> {
  if !config.enabled || config.record_sizes.is_empty() {
    return vec![data.to_vec()];
  }

  let mut chunks = Vec::new();
  let mut offset = 0usize;
  let mut size_idx = 0usize;

  while offset < data.len() {
    let chunk_size = config.record_sizes[size_idx % config.record_sizes.len()].max(1);
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
  fn split_drs_chunks_cycles_sizes() {
    let data: Vec<u8> = (0..10).collect();
    let config = DrsConfig {
      enabled: true,
      record_sizes: vec![3, 2],
    };
    assert_eq!(
      split_drs_chunks(&data, &config),
      vec![vec![0, 1, 2], vec![3, 4], vec![5, 6, 7], vec![8, 9]]
    );
  }
}
