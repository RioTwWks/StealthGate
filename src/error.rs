use std::io;
use thiserror::Error;

/// Ошибки StealthGate.
#[derive(Debug, Error)]
pub enum StealthGateError {
  #[error("ошибка конфигурации: {0}")]
  Config(String),

  #[error("ошибка TLS-парсинга: {0}")]
  TlsParse(String),

  #[error("ошибка детектора: {0}")]
  Detector(String),

  #[error("ошибка прокси: {0}")]
  Proxy(String),

  #[error(transparent)]
  Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, StealthGateError>;
