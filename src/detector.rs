use crate::config::decode_secret;
use crate::error::Result;
use crate::tls::{looks_like_tls_client_hello, parse_client_hello, parse_record};

/// Тип входящего соединения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficType {
  /// MTProto-клиент с валидным секретом.
  Mtproto,
  /// Обычный TLS/HTTP трафик.
  Fallback,
}

/// Результат детекции трафика.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
  pub traffic_type: TrafficType,
  pub sni: Option<String>,
}

/// Детектор MTProto-трафика по начальному буферу.
#[derive(Debug, Clone)]
pub struct Detector {
  secret: Vec<u8>,
  fake_domain: String,
}

impl Detector {
  /// Создаёт детектор из hex-секрета и домена маскировки.
  pub fn new(secret_hex: &str, fake_domain: impl Into<String>) -> Result<Self> {
    Ok(Self {
      secret: decode_secret(secret_hex)?,
      fake_domain: fake_domain.into(),
    })
  }

  /// Анализирует начальный буфер соединения.
  pub fn detect(&self, data: &[u8]) -> DetectionResult {
    let mut sni = None;

    if looks_like_tls_client_hello(data) {
      if let Ok(record) = parse_record(data) {
        if let Ok(hello) = parse_client_hello(record.payload) {
          sni = hello.sni.clone();
        }
      }
    }

    if self.contains_secret(data) {
      return DetectionResult {
        traffic_type: TrafficType::Mtproto,
        sni,
      };
    }

    // Дополнительная эвристика: TLS ClientHello с ожидаемым SNI
    if looks_like_tls_client_hello(data) {
      if let Some(ref domain) = sni {
        if domain.eq_ignore_ascii_case(&self.fake_domain) {
          return DetectionResult {
            traffic_type: TrafficType::Mtproto,
            sni,
          };
        }
      }
    }

    DetectionResult {
      traffic_type: TrafficType::Fallback,
      sni,
    }
  }

  fn contains_secret(&self, data: &[u8]) -> bool {
    if data.len() < self.secret.len() {
      return false;
    }

    data.windows(self.secret.len())
      .any(|window| window == self.secret.as_slice())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn detects_mtproto_by_secret_in_buffer() {
    let secret = "0123456789abcdef0123456789abcdef";
    let detector = Detector::new(secret, "example.com").expect("detector");

    let secret_bytes = decode_secret(secret).expect("bytes");
    let mut payload = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01];
    payload.extend_from_slice(&secret_bytes);
    payload.extend_from_slice(&[0u8; 32]);

    let result = detector.detect(&payload);
    assert_eq!(result.traffic_type, TrafficType::Mtproto);
  }

  #[test]
  fn classifies_unknown_as_fallback() {
    let detector = Detector::new("0123456789abcdef0123456789abcdef", "example.com")
      .expect("detector");
    let result = detector.detect(b"GET / HTTP/1.1\r\n");
    assert_eq!(result.traffic_type, TrafficType::Fallback);
  }
}
