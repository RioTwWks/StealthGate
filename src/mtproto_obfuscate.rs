//! Распознавание 64-байтного obfuscated2 handshake MTProto-прокси.
//!
//! Клиент отправляет 64 случайных байта; байты [8..40] — prekey, [40..56] — IV.
//! Ключ: `SHA-256(prekey || secret)`. После AES-256-CTR в [56..60] — тег протокола.

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use sha2::{Digest, Sha256};

pub const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

type AesCtr256 = Ctr128BE<Aes256>;

/// Результат разбора obfuscated2 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInfo {
  pub dc_id: u16,
  pub is_media: bool,
}

/// Проверяет, что первые 64 байта — валидный obfuscated2 handshake с данным секретом.
pub fn matches_obfuscated2(data: &[u8], secret: &[u8]) -> bool {
  if data.len() < HANDSHAKE_LEN || secret.len() != 16 {
    return false;
  }
  let handshake: &[u8; HANDSHAKE_LEN] = data[..HANDSHAKE_LEN].try_into().expect("64 bytes");
  parse_handshake(handshake, secret).is_some()
}

/// Пробует расшифровать 64-байтный handshake; `None` — неверный секрет или мусор.
pub fn parse_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<HandshakeInfo> {
  if secret.len() != 16 {
    return None;
  }

  let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
  let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

  let key = {
    let mut h = Sha256::new();
    h.update(prekey);
    h.update(secret);
    h.finalize()
  };

  let mut buf = *handshake;
  let mut cipher = make_cipher(&key, iv);
  cipher.apply_keystream(&mut buf);

  if !is_valid_proto_tag(&buf[PROTO_TAG_POS..PROTO_TAG_POS + 4]) {
    return None;
  }

  let dc_idx = i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]);
  Some(HandshakeInfo {
    dc_id: dc_idx.unsigned_abs(),
    is_media: dc_idx < 0,
  })
}

fn is_valid_proto_tag(tag: &[u8]) -> bool {
  tag == PROTO_TAG_ABRIDGED || tag == PROTO_TAG_INTERMEDIATE || tag == PROTO_TAG_SECURE
}

fn make_cipher(key: &[u8], iv: &[u8]) -> AesCtr256 {
  AesCtr256::new_from_slices(key, iv).expect("AES-256-CTR key/iv length")
}

#[cfg(test)]
pub fn generate_test_handshake(secret: &[u8], dc_idx: i16, proto_tag: [u8; 4]) -> [u8; HANDSHAKE_LEN] {
  use rand::RngCore;

  let dc_bytes = dc_idx.to_le_bytes();
  loop {
    let mut raw = [0u8; HANDSHAKE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);

    if RESERVED_FIRST_BYTES.contains(&raw[0]) {
      continue;
    }
    if RESERVED_STARTS.iter().any(|s| &raw[..4] == s) {
      continue;
    }
    if raw[4..8] == RESERVED_CONTINUE {
      continue;
    }

    let key = {
      let mut h = Sha256::new();
      h.update(&raw[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
      h.update(secret);
      h.finalize()
    };
    let iv = &raw[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut keystream = [0u8; HANDSHAKE_LEN];
    make_cipher(&key, iv).apply_keystream(&mut keystream);

    let mut handshake = raw;
    for i in 0..4 {
      handshake[PROTO_TAG_POS + i] = proto_tag[i] ^ keystream[PROTO_TAG_POS + i];
    }
    for i in 0..2 {
      handshake[DC_IDX_POS + i] = dc_bytes[i] ^ keystream[DC_IDX_POS + i];
    }

    return handshake;
  }
}

#[cfg(test)]
const RESERVED_FIRST_BYTES: &[u8] = &[0xef];
#[cfg(test)]
const RESERVED_STARTS: &[[u8; 4]] = &[
  [0x48, 0x45, 0x41, 0x44],
  [0x50, 0x4f, 0x53, 0x54],
  [0x47, 0x45, 0x54, 0x20],
  [0xee, 0xee, 0xee, 0xee],
  [0xdd, 0xdd, 0xdd, 0xdd],
  [0x16, 0x03, 0x01, 0x02],
];
#[cfg(test)]
const RESERVED_CONTINUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_valid_padded_intermediate_handshake() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let handshake = generate_test_handshake(&secret, 2, PROTO_TAG_SECURE);
    let info = parse_handshake(&handshake, &secret).expect("handshake");
    assert_eq!(info.dc_id, 2);
    assert!(!info.is_media);
  }

  #[test]
  fn rejects_wrong_secret() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let wrong = hex::decode("ffffffffffffffffffffffffffffffff").expect("wrong");
    let handshake = generate_test_handshake(&secret, 2, PROTO_TAG_SECURE);
    assert!(parse_handshake(&handshake, &wrong).is_none());
  }

  #[test]
  fn matches_with_extra_peek_bytes() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let handshake = generate_test_handshake(&secret, -4, PROTO_TAG_INTERMEDIATE);
    let mut payload = handshake.to_vec();
    payload.extend_from_slice(&[0xAA; 200]);
    assert!(matches_obfuscated2(&payload, &secret));
  }

  #[test]
  fn rejects_random_noise() {
    let secret = hex::decode("0123456789abcdef0123456789abcdef").expect("secret");
    let noise = vec![0u8; 128];
    assert!(!matches_obfuscated2(&noise, &secret));
  }
}
