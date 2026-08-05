use crate::config::{decode_secret, SecretMode, SecretRoute};
use crate::error::Result;
use crate::tls::{looks_like_tls_client_hello, parse_client_hello, parse_record};

/// Подсказка о формате нераспознанного трафика (для диагностики).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficHint {
  /// TLS ClientHello (`16 03 01/02/03`).
  TlsClientHello,
  /// Другая TLS-запись.
  TlsOther,
  /// HTTP-запрос.
  Http,
  /// Похоже на обфусцированный MTProto (dd / random), не ee Fake TLS.
  ObfuscatedMtproto,
  /// Не удалось классифицировать.
  Unknown,
}

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
  pub secret_mode: Option<SecretMode>,
  pub backend: Option<String>,
  pub max_connections: u32,
}

impl DetectionResult {
  fn mtproto(
    sni: Option<String>,
    label: impl Into<String>,
    mode: SecretMode,
    backend: impl Into<String>,
    max_connections: u32,
  ) -> Self {
    Self {
      traffic_type: TrafficType::Mtproto,
      sni,
      secret_label: Some(label.into()),
      secret_mode: Some(mode),
      backend: Some(backend.into()),
      max_connections,
    }
  }

  fn fallback(sni: Option<String>) -> Self {
    Self {
      traffic_type: TrafficType::Fallback,
      sni,
      secret_label: None,
      secret_mode: None,
      backend: None,
      max_connections: 0,
    }
  }
}

/// Детектор MTProto-трафика по начальному буферу.
#[derive(Debug, Clone)]
pub struct Detector {
  routes: Vec<SecretRouteBytes>,
  fake_domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct SecretRouteBytes {
  label: String,
  secret: Vec<u8>,
  mode: SecretMode,
  backend: String,
  max_connections: u32,
}

impl Detector {
  /// Создаёт детектор из списка секретов.
  pub fn from_routes(routes: &[SecretRoute], fake_domains: &[String]) -> Result<Self> {
    if fake_domains.is_empty() {
      return Err(crate::error::StealthGateError::Config(
        "нужен хотя бы один SNI-домен для детектора".into(),
      ));
    }
    let mut parsed = Vec::new();
    for route in routes {
      parsed.push(SecretRouteBytes {
        label: route.label.clone(),
        secret: decode_secret(&route.secret)?,
        mode: route.mode,
        backend: route.backend.clone(),
        max_connections: route.max_connections,
      });
    }
    Ok(Self {
      routes: parsed,
      fake_domains: fake_domains.to_vec(),
    })
  }

  /// Создаёт детектор из одного секрета (совместимость).
  pub fn new(secret_hex: &str, fake_domain: impl Into<String>) -> Result<Self> {
    Self::from_routes(
      &[SecretRoute {
        label: "default".into(),
        secret: secret_hex.into(),
        mode: crate::config::secret_mode(secret_hex),
        backend: String::new(),
        max_connections: 0,
      }],
      &[fake_domain.into()],
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
          route.mode,
          route.backend.clone(),
          route.max_connections,
        );
      }
    }

    if looks_like_tls_client_hello(data) {
      if let Some(ref domain) = sni {
        if self.matches_fake_domain(domain) {
          let route = self.routes.first();
          return DetectionResult::mtproto(
            sni.clone(),
            route.map(|r| r.label.clone()).unwrap_or_else(|| "default".into()),
            route.map(|r| r.mode).unwrap_or(SecretMode::Ee),
            route.map(|r| r.backend.clone()).unwrap_or_default(),
            route.map(|r| r.max_connections).unwrap_or(0),
          );
        }
      }
    }

    DetectionResult::fallback(sni)
  }

  fn matches_fake_domain(&self, domain: &str) -> bool {
    self
      .fake_domains
      .iter()
      .any(|candidate| candidate.eq_ignore_ascii_case(domain))
  }

  fn contains_secret(&self, data: &[u8], secret: &[u8]) -> bool {
    if data.len() < secret.len() {
      return false;
    }
    data.windows(secret.len())
      .any(|window| window == secret)
  }
}

/// Классифицирует начальный буфер для диагностики fallback-соединений.
pub fn classify_peek(data: &[u8]) -> TrafficHint {
  if data.is_empty() {
    return TrafficHint::Unknown;
  }

  if data.starts_with(b"GET ")
    || data.starts_with(b"HEAD ")
    || data.starts_with(b"POST ")
    || data.starts_with(b"PUT ")
    || data.starts_with(b"OPTIONS ")
  {
    return TrafficHint::Http;
  }

  if looks_like_tls_client_hello(data) {
    return TrafficHint::TlsClientHello;
  }

  if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 {
    return TrafficHint::TlsOther;
  }

  // ee Fake TLS всегда начинается с TLS ClientHello. Случайные байты — типичный dd/obfuscated.
  if data.len() >= 64 {
    return TrafficHint::ObfuscatedMtproto;
  }

  TrafficHint::Unknown
}

/// Текст подсказки для оператора при нераспознанном MTProto-трафике.
pub fn fallback_diagnostic_message(hint: TrafficHint, has_ee_route: bool) -> Option<&'static str> {
  match hint {
    TrafficHint::ObfuscatedMtproto if has_ee_route => Some(
      "похоже на обфусцированный MTProto (dd/random), а не ee Fake TLS (ожидается префикс 160301). \
       Проверьте секрет в Telegram: нужен полный ee-секрет с hex-доменом fake_domain",
    ),
    TrafficHint::TlsClientHello if has_ee_route => Some(
      "TLS ClientHello без совпадения SNI с fake_domain/sni_pool — проверьте домен в ee-секрете Telegram",
    ),
    TrafficHint::TlsOther if has_ee_route => Some(
      "получена TLS-запись, но не ClientHello — клиент может использовать неверный режим прокси",
    ),
    _ => None,
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
  use crate::config::secret_mode;

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
  fn detects_dd_secret_mode() {
    let routes = vec![SecretRoute {
      label: "secure".into(),
      secret: "dd0123456789abcdef0123456789abcdef".into(),
      mode: secret_mode("dd0123456789abcdef0123456789abcdef"),
      backend: "1.1.1.1:443".into(),
      max_connections: 0,
    }];
    let detector = Detector::from_routes(&routes, &["example.com".into()]).expect("detector");
    let secret_bytes = decode_secret("dd0123456789abcdef0123456789abcdef").expect("bytes");
    let mut payload = vec![0u8; 64];
    payload.extend_from_slice(&secret_bytes);
    let result = detector.detect(&payload);
    assert_eq!(result.secret_mode, Some(SecretMode::Dd));
  }

  #[test]
  fn detects_additional_secret_route() {
    let routes = vec![
      SecretRoute {
        label: "default".into(),
        secret: "0123456789abcdef0123456789abcdef".into(),
        mode: SecretMode::Classic,
        backend: "1.1.1.1:443".into(),
        max_connections: 0,
      },
      SecretRoute {
        label: "friends".into(),
        secret: "eeabcdefabcdefabcdefabcdefabcdefab".into(),
        mode: SecretMode::Ee,
        backend: "2.2.2.2:443".into(),
        max_connections: 10,
      },
    ];
    let detector = Detector::from_routes(&routes, &["example.com".into()]).expect("detector");
    let secret_bytes = decode_secret("eeabcdefabcdefabcdefabcdefabcdefab").expect("bytes");
    let mut payload = vec![0u8; 64];
    payload.extend_from_slice(&secret_bytes);

    let result = detector.detect(&payload);
    assert_eq!(result.secret_label.as_deref(), Some("friends"));
    assert_eq!(result.secret_mode, Some(SecretMode::Ee));
    assert_eq!(result.backend.as_deref(), Some("2.2.2.2:443"));
    assert_eq!(result.max_connections, 10);
  }

  #[test]
  fn classifies_obfuscated_peek_hint() {
    let short = vec![0xC0, 0x14, 0x46, 0x9A, 0xDD, 0xA4, 0x67, 0x01];
    assert_eq!(classify_peek(&short), TrafficHint::Unknown);
    let long = vec![0u8; 128];
    assert_eq!(classify_peek(&long), TrafficHint::ObfuscatedMtproto);
  }

  #[test]
  fn detects_ee_by_any_sni_in_pool() {
    use crate::tls::test_support::build_client_hello;

    let routes = vec![SecretRoute {
      label: "default".into(),
      secret: "ee0123456789abcdef0123456789abcdef".into(),
      mode: SecretMode::Ee,
      backend: "1.1.1.1:443".into(),
      max_connections: 0,
    }];
    let detector = Detector::from_routes(
      &routes,
      &["cloudflare.com".into(), "google.com".into()],
    )
    .expect("detector");

    let payload = build_client_hello("google.com");
    let result = detector.detect(&payload);
    assert_eq!(result.traffic_type, TrafficType::Mtproto);

    let payload = build_client_hello("example.com");
    let result = detector.detect(&payload);
    assert_eq!(result.traffic_type, TrafficType::Fallback);
  }
}
