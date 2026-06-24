//! Интеграционный тест domain fronting (TCP relay).

use stealth_gate::config::{DomainFrontingMode, FallbackConfig};
use stealth_gate::domain_fronting::resolve_fronting_target;
use stealth_gate::Config;

#[test]
fn resolve_fronting_modes() {
  let sni = FallbackConfig {
    upstream: None,
    static_html: None,
    domain_fronting: DomainFrontingMode::Sni,
    fronting_host: None,
    fronting_port: 8443,
  };
  assert_eq!(
    resolve_fronting_target(&sni, Some("example.com")),
    Some("example.com:8443".into())
  );
}

#[tokio::test]
async fn antireplay_blocks_duplicate_client_hello() {
  use stealth_gate::antireplay::client_hello_fingerprint;
  use stealth_gate::state::AppState;
  use tempfile::tempdir;

  let dir = tempdir().expect("tempdir");
  let users = dir.path().join("users.json").to_string_lossy().to_string();
  let mut config = Config::test_minimal(&users);
  config.security.antireplay_cache_size = 16;
  let state = AppState::new(config, "config.toml").expect("state");

  let hello = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01";
  let fp = client_hello_fingerprint(hello);
  assert!(!state.antireplay.is_replay(fp));
  assert!(state.antireplay.is_replay(fp));
}
