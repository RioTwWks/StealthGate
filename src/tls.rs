use crate::error::{Result, StealthGateError};

/// Тип TLS-записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
  ChangeCipherSpec = 20,
  Alert = 21,
  Handshake = 22,
  ApplicationData = 23,
}

impl TryFrom<u8> for RecordType {
  type Error = StealthGateError;

  fn try_from(value: u8) -> Result<Self> {
    match value {
      20 => Ok(Self::ChangeCipherSpec),
      21 => Ok(Self::Alert),
      22 => Ok(Self::Handshake),
      23 => Ok(Self::ApplicationData),
      _ => Err(StealthGateError::TlsParse(format!(
        "неизвестный тип TLS-записи: {value}"
      ))),
    }
  }
}

/// Тип TLS handshake-сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
  ClientHello,
  ServerHello,
  Other(u8),
}

impl HandshakeType {
  fn from_byte(value: u8) -> Self {
    match value {
      1 => Self::ClientHello,
      2 => Self::ServerHello,
      other => Self::Other(other),
    }
  }
}

/// Разобранная TLS-запись.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord<'a> {
  pub record_type: RecordType,
  pub version: [u8; 2],
  pub payload: &'a [u8],
}

/// Разобранный ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello<'a> {
  pub client_version: [u8; 2],
  pub random: &'a [u8],
  pub session_id: &'a [u8],
  pub cipher_suites: &'a [u8],
  pub compression_methods: &'a [u8],
  pub extensions: &'a [u8],
  pub sni: Option<String>,
}

/// Парсит TLS record layer.
pub fn parse_record(data: &[u8]) -> Result<TlsRecord<'_>> {
  if data.len() < 5 {
    return Err(StealthGateError::TlsParse(
      "недостаточно данных для TLS-записи".into(),
    ));
  }

  let record_type = RecordType::try_from(data[0])?;
  let version = [data[1], data[2]];
  let length = u16::from_be_bytes([data[3], data[4]]) as usize;

  if data.len() < 5 + length {
    return Err(StealthGateError::TlsParse(
      "неполная TLS-запись".into(),
    ));
  }

  Ok(TlsRecord {
    record_type,
    version,
    payload: &data[5..5 + length],
  })
}

/// Парсит ClientHello из handshake payload.
pub fn parse_client_hello(payload: &[u8]) -> Result<ClientHello<'_>> {
  if payload.is_empty() {
    return Err(StealthGateError::TlsParse(
      "пустой handshake payload".into(),
    ));
  }

  let handshake_type = HandshakeType::from_byte(payload[0]);
  if handshake_type != HandshakeType::ClientHello {
    return Err(StealthGateError::TlsParse(
      "ожидался ClientHello".into(),
    ));
  }

  if payload.len() < 4 {
    return Err(StealthGateError::TlsParse(
      "недостаточно данных для ClientHello".into(),
    ));
  }

  let handshake_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
  if payload.len() < 4 + handshake_len {
    return Err(StealthGateError::TlsParse(
      "неполный ClientHello".into(),
    ));
  }

  let mut cursor = 4usize;

  if cursor + 2 > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let client_version = [payload[cursor], payload[cursor + 1]];
  cursor += 2;

  if cursor + 32 > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let random = &payload[cursor..cursor + 32];
  cursor += 32;

  if cursor >= payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let session_id_len = payload[cursor] as usize;
  cursor += 1;

  if cursor + session_id_len > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let session_id = &payload[cursor..cursor + session_id_len];
  cursor += session_id_len;

  if cursor + 2 > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let cipher_suites_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
  cursor += 2;

  if cursor + cipher_suites_len > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let cipher_suites = &payload[cursor..cursor + cipher_suites_len];
  cursor += cipher_suites_len;

  if cursor >= payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let compression_len = payload[cursor] as usize;
  cursor += 1;

  if cursor + compression_len > payload.len() {
    return Err(StealthGateError::TlsParse(
      "выход за границы ClientHello".into(),
    ));
  }
  let compression_methods = &payload[cursor..cursor + compression_len];
  cursor += compression_len;

  let extensions = if cursor + 2 <= payload.len() {
    let extensions_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + extensions_len > payload.len() {
      return Err(StealthGateError::TlsParse(
        "выход за границы ClientHello".into(),
      ));
    }
    &payload[cursor..cursor + extensions_len]
  } else {
    &[]
  };

  let sni = extract_sni(extensions);

  Ok(ClientHello {
    client_version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
    extensions,
    sni,
  })
}

/// Извлекает SNI из TLS extensions.
pub fn extract_sni(extensions: &[u8]) -> Option<String> {
  let mut offset = 0usize;

  while offset + 4 <= extensions.len() {
    let ext_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
    let ext_len =
      u16::from_be_bytes([extensions[offset + 2], extensions[offset + 3]]) as usize;
    offset += 4;

    if offset + ext_len > extensions.len() {
      break;
    }

    let ext_data = &extensions[offset..offset + ext_len];
    offset += ext_len;

    // server_name (0)
    if ext_type == 0 {
      return parse_sni_extension(ext_data);
    }
  }

  None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
  if data.len() < 5 {
    return None;
  }

  let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
  if data.len() < 2 + list_len {
    return None;
  }

  let mut offset = 2usize;
  while offset + 3 <= 2 + list_len {
    let name_type = data[offset];
    let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
    offset += 3;

    if offset + name_len > data.len() {
      break;
    }

    if name_type == 0 {
      return String::from_utf8(data[offset..offset + name_len].to_vec()).ok();
    }

    offset += name_len;
  }

  None
}

/// Возвращает полный размер первой TLS-записи (5 + payload_len) по заголовку.
pub fn tls_record_total_len(data: &[u8]) -> Option<usize> {
  if data.len() < 5 {
    return None;
  }
  RecordType::try_from(data[0]).ok()?;
  let payload_len = u16::from_be_bytes([data[3], data[4]]) as usize;
  5usize.checked_add(payload_len)
}

/// Пытается извлечь SNI из полной или частичной TLS ClientHello-записи.
pub fn try_client_hello_sni(data: &[u8]) -> Option<String> {
  if !looks_like_tls_client_hello(data) {
    return None;
  }
  if let Ok(record) = parse_record(data) {
    if let Ok(hello) = parse_client_hello(record.payload) {
      return hello.sni;
    }
    return try_client_hello_sni_from_payload(record.payload);
  }
  if data.len() > 5 {
    if let Ok(hello) = parse_client_hello(&data[5..]) {
      return hello.sni;
    }
    return try_client_hello_sni_from_payload(&data[5..]);
  }
  None
}

/// Извлекает SNI из частичного handshake payload (без проверки полной длины ClientHello).
pub fn try_client_hello_sni_from_payload(payload: &[u8]) -> Option<String> {
  if payload.is_empty() || HandshakeType::from_byte(payload[0]) != HandshakeType::ClientHello {
    return None;
  }
  if payload.len() < 4 {
    return None;
  }

  let mut cursor = 4usize;
  if cursor + 2 > payload.len() {
    return None;
  }
  cursor += 2; // client_version

  if cursor + 32 > payload.len() {
    return None;
  }
  cursor += 32; // random

  if cursor >= payload.len() {
    return None;
  }
  let session_id_len = payload[cursor] as usize;
  cursor += 1;
  if cursor + session_id_len > payload.len() {
    return None;
  }
  cursor += session_id_len;

  if cursor + 2 > payload.len() {
    return None;
  }
  let cipher_suites_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
  cursor += 2;
  if cursor + cipher_suites_len > payload.len() {
    return None;
  }
  cursor += cipher_suites_len;

  if cursor >= payload.len() {
    return None;
  }
  let compression_len = payload[cursor] as usize;
  cursor += 1;
  if cursor + compression_len > payload.len() {
    return None;
  }
  cursor += compression_len;

  if cursor + 2 > payload.len() {
    return None;
  }
  let extensions_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
  cursor += 2;
  let extensions_end = cursor.saturating_add(extensions_len).min(payload.len());
  if cursor >= extensions_end {
    return None;
  }
  extract_sni(&payload[cursor..extensions_end])
}

/// Проверяет, похожи ли байты на TLS ClientHello.
pub fn looks_like_tls_client_hello(data: &[u8]) -> bool {
  if data.len() < 6 {
    return false;
  }
  if data[0] != RecordType::Handshake as u8 {
    return false;
  }
  if !matches!(
    HandshakeType::from_byte(data[5]),
    HandshakeType::ClientHello
  ) {
    return false;
  }

  if let Ok(record) = parse_record(data) {
    return !record.payload.is_empty();
  }

  // Неполная запись — заголовок уже указывает на ClientHello.
  true
}

/// Вычисляет JA4-подобный фингерпринт ClientHello для эмуляции/логирования.
pub fn compute_ja4(hello: &ClientHello<'_>) -> String {
  use sha2::{Digest, Sha256};

  let version = format!("{:02x}{:02x}", hello.client_version[0], hello.client_version[1]);
  let sni_marker = if hello.sni.is_some() { 'd' } else { 'i' };
  let cipher_count = (hello.cipher_suites.len() / 2).min(99);
  let ext_count = count_extensions(hello.extensions).min(99);

  let mut cipher_hasher = Sha256::new();
  cipher_hasher.update(hello.cipher_suites);
  let cipher_hash = hex::encode(&cipher_hasher.finalize()[..6]);

  let mut ext_hasher = Sha256::new();
  ext_hasher.update(hello.extensions);
  let ext_hash = hex::encode(&ext_hasher.finalize()[..6]);

  format!(
    "t{version}{sni_marker}{cipher_count:02}{ext_count:02}_{cipher_hash}_{ext_hash}"
  )
}

fn count_extensions(extensions: &[u8]) -> usize {
  let mut offset = 0usize;
  let mut count = 0usize;
  while offset + 4 <= extensions.len() {
    let ext_len = u16::from_be_bytes([extensions[offset + 2], extensions[offset + 3]]) as usize;
    offset += 4;
    if offset + ext_len > extensions.len() {
      break;
    }
    offset += ext_len;
    count += 1;
  }
  count
}

/// Проверяет соответствие JA4 ожидаемому профилю (префикс или полное совпадение).
pub fn ja4_matches(fingerprint: &str, profile: &str) -> bool {
  let resolved = resolve_fingerprint_alias(profile);
  fingerprint == resolved || fingerprint.starts_with(&resolved)
}

/// Проверяет соответствие JA4 любому профилю из пула.
pub fn ja4_matches_any(fingerprint: &str, profiles: &[String]) -> bool {
  if profiles.is_empty() {
    return true;
  }
  profiles
    .iter()
    .any(|profile| ja4_matches(fingerprint, profile))
}

/// Разрешает алиас fingerprint (chrome_120 и т.д.) в JA4-префикс.
pub fn resolve_fingerprint_alias(profile: &str) -> String {
  match profile.trim().to_ascii_lowercase().as_str() {
    "chrome_120" | "chrome_121" | "chrome_122" => "t13d".into(),
    "firefox_122" | "firefox_123" => "t13d".into(),
    "edge_120" | "edge_121" => "t13d".into(),
    "safari_17" => "t13d".into(),
    other => other.to_string(),
  }
}

#[doc(hidden)]
pub mod test_support {
  /// Собирает минимальный TLS ClientHello с SNI для unit-тестов.
  pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
    handshake.extend_from_slice(&[0x03, 0x03]);
    handshake.extend_from_slice(&[0u8; 32]);
    handshake.push(0x00);
    handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    handshake.push(0x01);
    handshake.push(0x00);

    let host = sni.as_bytes();
    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&((host.len() as u16 + 3).to_be_bytes()));
    sni_list.push(0x00);
    sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(host);

    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&0u16.to_be_bytes());
    sni_extension.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_extension.extend_from_slice(&sni_list);

    handshake.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&sni_extension);

    let hs_len = handshake.len() - 4;
    handshake[1] = ((hs_len >> 16) & 0xff) as u8;
    handshake[2] = ((hs_len >> 8) & 0xff) as u8;
    handshake[3] = (hs_len & 0xff) as u8;

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
  }

  /// ClientHello с padding extension (имитация крупного ee ClientHello ≈1700+ байт).
  pub fn build_client_hello_padded(sni: &str, min_record_len: usize) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
    handshake.extend_from_slice(&[0x03, 0x03]);
    handshake.extend_from_slice(&[0u8; 32]);
    handshake.push(0x00);
    handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    handshake.push(0x01);
    handshake.push(0x00);

    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&((host.len() as u16 + 3).to_be_bytes()));
    sni_list.push(0x00);
    sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(host);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_list);

    let handshake_fixed = handshake.len() + 2;
    let target_handshake = min_record_len.saturating_sub(5);
    if target_handshake > handshake_fixed + extensions.len() {
      let pad_len = target_handshake - handshake_fixed - extensions.len() - 4;
      extensions.extend_from_slice(&[0x00, 0x15]);
      extensions.extend_from_slice(&(pad_len as u16).to_be_bytes());
      extensions.extend_from_slice(&vec![0u8; pad_len]);
    }

    handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&extensions);

    let hs_len = handshake.len() - 4;
    handshake[1] = ((hs_len >> 16) & 0xff) as u8;
    handshake[2] = ((hs_len >> 8) & 0xff) as u8;
    handshake[3] = (hs_len & 0xff) as u8;

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use super::test_support::build_client_hello;

  #[test]
  fn parse_tls_client_hello_with_sni() {
    let data = build_client_hello("www.cloudflare.com");
    let record = parse_record(&data).expect("record");
    let hello = parse_client_hello(record.payload).expect("client hello");
    assert_eq!(hello.sni.as_deref(), Some("www.cloudflare.com"));
    assert!(looks_like_tls_client_hello(&data));
    let ja4 = compute_ja4(&hello);
    assert!(ja4.starts_with('t'));
    assert!(ja4.contains('_'));
  }

  #[test]
  fn detects_partial_tls_client_hello() {
    let data = build_client_hello("www.cloudflare.com");
    let total = tls_record_total_len(&data).expect("record len");
    assert!(total > 6);
    let partial = &data[..total.saturating_sub(1).max(6)];
    assert!(
      looks_like_tls_client_hello(partial),
      "partial ClientHello must be recognized by header"
    );
    if partial.len() < total {
      assert!(parse_record(partial).is_err());
    }
  }

  #[test]
  fn tls_record_total_len_matches_parse() {
    let data = build_client_hello("example.com");
    assert_eq!(tls_record_total_len(&data), Some(data.len()));
  }

  #[test]
  fn partial_client_hello_sni_from_payload() {
    let data = build_client_hello("www.cloudflare.com");
    let payload = &data[5..];
    let sni = try_client_hello_sni_from_payload(payload).expect("sni from full payload");
    assert_eq!(sni, "www.cloudflare.com");
  }

  #[test]
  fn ja4_alias_resolves_to_prefix() {
    assert_eq!(resolve_fingerprint_alias("chrome_120"), "t13d");
    assert!(ja4_matches(
      "t13d1516h2_abc123_def456",
      "chrome_120"
    ));
  }
}
