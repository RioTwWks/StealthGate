//! Dynamic Record Sizing — имитация размеров TLS application records.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

  write_chunks_with_jitter(stream, data, config, Some(stats)).await
}

/// Двунаправленное копирование с DRS/jitter (для ee relay).
pub async fn copy_bidirectional_shaped<L, R>(
  left: L,
  right: R,
  config: &DrsConfig,
) -> Result<(u64, u64)>
where
  L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
  R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
  if !config.ee_relay {
    return crate::proxy::copy_bidirectional(left, right).await;
  }

  let (mut left_read, mut left_write) = tokio::io::split(left);
  let (mut right_read, mut right_write) = tokio::io::split(right);

  let c2s = shaped_copy(&mut left_read, &mut right_write, config);
  let s2c = shaped_copy(&mut right_read, &mut left_write, config);

  let (c2s, s2c) = tokio::try_join!(c2s, s2c).map_err(|err| {
    StealthGateError::Proxy(format!("ошибка shaped copy_bidirectional: {err}"))
  })?;

  Ok((c2s, s2c))
}

async fn shaped_copy<R, W>(reader: &mut R, writer: &mut W, config: &DrsConfig) -> std::io::Result<u64>
where
  R: tokio::io::AsyncRead + Unpin,
  W: tokio::io::AsyncWrite + Unpin,
{
  let mut buf = vec![0u8; 8192];
  let mut total = 0u64;
  loop {
    let n = reader.read(&mut buf).await?;
    if n == 0 {
      break;
    }
    write_chunks_with_jitter(writer, &buf[..n], config, None)
      .await
      .map_err(|err| std::io::Error::other(err.to_string()))?;
    total += n as u64;
  }
  Ok(total)
}

async fn write_chunks_with_jitter<W>(
  writer: &mut W,
  data: &[u8],
  config: &DrsConfig,
  stats: Option<&Stats>,
) -> Result<()>
where
  W: tokio::io::AsyncWrite + Unpin,
{
  let sizes = if config.record_sizes.is_empty() {
    vec![512, 1024, 1398, 256]
  } else {
    config.record_sizes.clone()
  };

  let mut offset = 0usize;
  let mut size_idx = 0usize;
  let mut chunks_sent = 0u64;

  while offset < data.len() {
    let chunk_size = sizes[size_idx % sizes.len()].max(1);
    size_idx += 1;
    let end = (offset + chunk_size).min(data.len());
    writer
      .write_all(&data[offset..end])
      .await
      .map_err(|err| StealthGateError::Proxy(format!("DRS chunk write: {err}")))?;
    offset = end;
    chunks_sent += 1;

    if config.jitter_ms > 0 && offset < data.len() {
      let delay = rand::random::<u64>() % (config.jitter_ms + 1);
      if delay > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
      }
    }
  }

  if chunks_sent > 1 {
    if let Some(stats) = stats {
      stats
        .drs_writes
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
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
      ee_relay: true,
      jitter_ms: 0,
    };
    assert_eq!(
      split_drs_chunks(&data, &config),
      vec![vec![0, 1, 2], vec![3, 4], vec![5, 6, 7], vec![8, 9]]
    );
  }
}
