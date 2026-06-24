use crate::config::{decode_secret, SecretRoute};
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
  pub secret_label: Option<String>,
  pub backend: Option<String>,
  pub max_connections: u32,
}

impl DetectionResult {
  fn mtproto(
    sni: Option<String>,
    label: impl Into<String>,
    backend: impl Into<String>,
    max_connections: u32,
  ) -> Self {
    Self {
      traffic_type: TrafficType::Mtproto,
      sni,
      secret_label: Some(label.into()),
      backend: Some(backend.into()),
      max_connections,
    }
  }

  fn fallback(sni: Option<String>) -> Self {
    Self {
      traffic_type: TrafficType::Fallback,
      sni,
      secret_label: None,
      backend: None,
      max_connections: 0,
    }
  }
}

/// Детектор MTProto-трафика по начальному буферу.
#[derive(Debug, Clone)]
pub struct Detector {
  routes: Vec<SecretRouteBytes>,
  fake_domain: String,
}

#[derive(Debug, Clone)]
struct SecretRouteBytes {
  label: String,
  secret: Vec<u8>,
  backend: String,
  max_connections: u32,
}

impl Detector {
  /// Создаёт детектор из списка секретов.
  pub fn from_routes(routes: &[SecretRoute], fake_domain: impl Into<String>) -> Result<Self> {
    let fake_domain = fake_domain.into();
    let mut parsed = Vec::new();
    for route in routes {
      parsed.push(SecretRouteBytes {
        label: route.label.clone(),
        secret: decode_secret(&route.secret)?,
        backend: route.backend.clone(),
        max_connections: route.max_connections,
      });
    }
    Ok(Self {
      routes: parsed,
      fake_domain,
    })
  }

  /// Создаёт детектор из одного секрета (совместимость).
  pub fn new(secret_hex: &str, fake_domain: impl Into<String>) -> Result<Self> {
    Self::from_routes(
      &[SecretRoute {
        label: "default".into(),
        secret: secret_hex.into(),
        backend: String::new(),
        max_connections: 0,
      }],
      fake_domain,
    )
  }

  /// Анализирует начальный буфер соединения.
  pub fn detect(&self, data: &[u8]) -> DetectionResult {
    let sni = extract_sni(data);

    for route in &self.routes {
      if self.contains_secret(data, &route.secret) {
        return DetectionResult::mtproto(
          sni.clone(),
          route.label.clone(),
          route.backend.clone(),
          route.max_connections,
        );
      }
    }

    if looks_like_tls_client_hello(data) {
      if let Some(ref domain) = sni {
        if domain.eq_ignore_ascii_case(&self.fake_domain) {
          let route = self.routes.first();
          return DetectionResult::mtproto(
            sni.clone(),
            route.map(|r| r.label.clone()).unwrap_or_else(|| "default".into()),
            route.map(|r| r.backend.clone()).unwrap_or_default(),
            route.map(|r| r.max_connections).unwrap_or(0),
          );
        }
      }
    }

    DetectionResult::fallback(sni)
  }

  fn contains_secret(&self, data: &[u8], secret: &[u8]) -> bool {
    if data.len() < secret.len() {
      return false;
    }
    data.windows(secret.len())
      .any(|window| window == secret)
  }
}

fn extract_sni(data: &[u8]) -> Option<String> {
  if !looks_like_tls_client_hello(data) {
    return None;
  }
  let record = parse_record(data).ok()?;
  let hello = parse_client_hello(record.payload).ok()?;
  hello.sni
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

  #[test]
  fn detects_additional_secret_route() {
    let routes = vec![
      SecretRoute {
        label: "default".into(),
        secret: "0123456789abcdef0123456789abcdef".into(),
        backend: "1.1.1.1:443".into(),
        max_connections: 0,
      },
      SecretRoute {
        label: "friends".into(),
        secret: "eeabcdefabcdefabcdefabcdefabcdefab".into(),
        backend: "2.2.2.2:443".into(),
        max_connections: 10,
      },
    ];
    let detector = Detector::from_routes(&routes, "example.com").expect("detector");
    let secret_bytes = decode_secret("eeabcdefabcdefabcdefabcdefabcdefab").expect("bytes");
    let mut payload = vec![0u8; 64];
    payload.extend_from_slice(&secret_bytes);

    let result = detector.detect(&payload);
    assert_eq!(result.secret_label.as_deref(), Some("friends"));
    assert_eq!(result.backend.as_deref(), Some("2.2.2.2:443"));
    assert_eq!(result.max_connections, 10);
  }
}
