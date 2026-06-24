use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::Config;
use crate::detector::{DetectionResult, Detector, TrafficType};
use crate::error::{Result, StealthGateError};
use crate::fallback;
use crate::proxy;

const PEEK_BUFFER_SIZE: usize = 4096;

/// Обрабатывает одно входящее соединение.
pub async fn handle_connection(mut client: TcpStream, config: Arc<Config>) -> Result<()> {
  let mut peek_buf = vec![0u8; PEEK_BUFFER_SIZE];
  let n = client
    .read(&mut peek_buf)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("чтение начальных данных: {err}")))?;

  if n == 0 {
    return Ok(());
  }

  peek_buf.truncate(n);

  let detector = Detector::new(&config.mtproto.secret, &config.tls.fake_domain)?;
  let detection = detector.detect(&peek_buf);

  match detection.traffic_type {
    TrafficType::Mtproto => {
      tracing::info!(
        sni = ?detection.sni,
        backend = %config.mtproto.backend,
        "MTProto-соединение"
      );
      proxy::proxy_mtproto(client, &peek_buf, &config.mtproto.backend).await?;
    }
    TrafficType::Fallback => {
      tracing::debug!(sni = ?detection.sni, "fallback-соединение");
      fallback::handle_fallback(client, &peek_buf, &config.fallback).await?;
    }
  }

  Ok(())
}

/// Принимает соединения на указанном адресе.
pub async fn run_acceptor(config: Arc<Config>) -> Result<()> {
  let addr = config.listen.socket_addr()?;
  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .map_err(|err| StealthGateError::Proxy(format!("bind {addr}: {err}")))?;

  tracing::info!(%addr, "StealthGate слушает соединения");

  loop {
    let (stream, peer) = listener
      .accept()
      .await
      .map_err(|err| StealthGateError::Proxy(format!("accept: {err}")))?;

    let cfg = Arc::clone(&config);
    tokio::spawn(async move {
      if let Err(err) = handle_connection(stream, cfg).await {
        tracing::warn!(%peer, error = %err, "ошибка обработки соединения");
      }
    });
  }
}

/// Утилита для тестов: детекция без сети.
pub fn detect_traffic(data: &[u8], secret: &str, fake_domain: &str) -> Result<DetectionResult> {
  let detector = Detector::new(secret, fake_domain)?;
  Ok(detector.detect(data))
}

/// Обёртка для тестирования проксирования с произвольными потоками.
pub async fn copy_bidirectional<L, R>(left: L, right: R) -> Result<(u64, u64)>
where
  L: AsyncRead + AsyncWrite + Unpin,
  R: AsyncRead + AsyncWrite + Unpin,
{
  proxy::copy_bidirectional(left, right).await
}
