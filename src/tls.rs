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

/// Проверяет, похожи ли байты на TLS ClientHello.
pub fn looks_like_tls_client_hello(data: &[u8]) -> bool {
  let Ok(record) = parse_record(data) else {
    return false;
  };

  if record.record_type != RecordType::Handshake {
    return false;
  }

  if record.payload.is_empty() {
    return false;
  }

  matches!(HandshakeType::from_byte(record.payload[0]), HandshakeType::ClientHello)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    handshake.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    handshake.extend_from_slice(&[0u8; 32]); // random
    handshake.push(0x00); // session id length

    handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    handshake.push(0x01);
    handshake.push(0x00); // compression

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
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
  }

  #[test]
  fn parse_tls_client_hello_with_sni() {
    let data = build_client_hello("www.cloudflare.com");
    let record = parse_record(&data).expect("record");
    let hello = parse_client_hello(record.payload).expect("client hello");
    assert_eq!(hello.sni.as_deref(), Some("www.cloudflare.com"));
    assert!(looks_like_tls_client_hello(&data));
  }
}
