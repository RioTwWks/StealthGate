use stealth_gate::config::decode_secret;
use stealth_gate::detector::{Detector, TrafficType};
use stealth_gate::tls::looks_like_tls_client_hello;

#[test]
fn secret_decoding_roundtrip() {
  let secret = "ee0123456789abcdef0123456789abcdef";
  let bytes = decode_secret(secret).expect("decode");
  assert_eq!(bytes.len(), 16);
}

#[test]
fn detector_mtproto_vs_http() {
  let secret = "0123456789abcdef0123456789abcdef";
  let detector = Detector::new(secret, "www.cloudflare.com").expect("detector");

  let secret_bytes = decode_secret(secret).expect("bytes");
  let mut mtproto_packet = vec![0x16, 0x03, 0x01, 0x00, 0x20];
  mtproto_packet.extend_from_slice(&secret_bytes);
  mtproto_packet.extend_from_slice(&[0u8; 16]);

  assert_eq!(
    detector.detect(&mtproto_packet).traffic_type,
    TrafficType::Mtproto
  );
  assert_eq!(
    detector.detect(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").traffic_type,
    TrafficType::Fallback
  );
}

#[test]
fn tls_hello_heuristic() {
  let http = b"GET / HTTP/1.1\r\n";
  assert!(!looks_like_tls_client_hello(http));

  // Минимально валидная структура record + ClientHello type
  let tls = vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
  assert!(looks_like_tls_client_hello(&tls));

  // TLS Application Data — не ClientHello
  let app_data = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
  assert!(!looks_like_tls_client_hello(&app_data));
}
