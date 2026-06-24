//! Протокол dd (secure) — рандомизированные размеры пакетов для обхода DPI.

use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::DdConfig;
use crate::error::{Result, StealthGateError};
use crate::state::Stats;

/// Записывает буфер с рандомизированными размерами чанков (dd-режим).
pub async fn write_dd_randomized(
  stream: &mut TcpStream,
  data: &[u8],
  config: &DdConfig,
  stats: &Stats,
) -> Result<()> {
  if data.is_empty() {
    return Ok(());
  }

  let ranges = plan_dd_chunks(data.len(), config);
  let mut chunks_sent = 0u64;

  for (start, end) in ranges {
    stream
      .write_all(&data[start..end])
      .await
      .map_err(|err| StealthGateError::Proxy(format!("dd write: {err}")))?;
    chunks_sent += 1;
  }

  if chunks_sent > 1 {
    stats
      .dd_writes
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
  }

  Ok(())
}

/// Планирует границы dd-чанков синхронно (без await с ThreadRng).
pub fn plan_dd_chunks(data_len: usize, config: &DdConfig) -> Vec<(usize, usize)> {
  if data_len == 0 {
    return Vec::new();
  }

  let min = config.min_chunk_size.max(1);
  let max = config.max_chunk_size.max(min);
  let mut offset = 0usize;
  let mut ranges = Vec::new();
  let mut rng = rand::thread_rng();

  while offset < data_len {
    let remaining = data_len - offset;
    let chunk_size = if remaining <= min {
      remaining
    } else {
      rng.gen_range(min..=max.min(remaining))
    };
    let end = offset + chunk_size;
    ranges.push((offset, end));
    offset = end;
  }

  ranges
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn plan_dd_chunks_covers_all_bytes() {
    let config = DdConfig {
      min_chunk_size: 3,
      max_chunk_size: 7,
    };
    let ranges = plan_dd_chunks(20, &config);
    let total: usize = ranges.iter().map(|(s, e)| e - s).sum();
    assert_eq!(total, 20);
    assert!(ranges.len() > 1);
  }

  #[tokio::test]
  async fn dd_write_covers_all_bytes() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
      .await
      .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.expect("accept");
      let mut buf = vec![0u8; 64];
      let mut total = 0usize;
      while total < 20 {
        let n = stream.read(&mut buf[total..]).await.expect("read");
        if n == 0 {
          break;
        }
        total += n;
      }
      total
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    let config = DdConfig {
      min_chunk_size: 3,
      max_chunk_size: 7,
    };
    let stats = Stats::default();
    let data: Vec<u8> = (0..20).collect();
    write_dd_randomized(&mut client, &data, &config, &stats)
      .await
      .expect("write");

    assert_eq!(server.await.expect("join"), 20);
  }
}
