//! E2E тест Front/Back split (SGFB протокол).

use stealth_gate::config::{Config, SecretMode, SplitMode};
use stealth_gate::split::{decode_opening_frame, encode_opening_frame, hash_auth_token, handle_back_connection};
use stealth_gate::state::AppState;
use tempfile::tempdir;

const AUTH_TOKEN: &str = "integration-split-token-123";

fn front_config(users_file: &str, back_addr: &str) -> Config {
  let mut config = Config::test_minimal(users_file);
  config.split.mode = SplitMode::Front;
  config.split.auth_token = Some(AUTH_TOKEN.into());
  config.split.back_servers = vec![back_addr.into()];
  config.split.connect_timeout_secs = 5;
  config
}

#[test]
fn split_opening_frame_contains_token_hash() {
  let frame = encode_opening_frame(
    AUTH_TOKEN,
    SecretMode::Ee,
    "149.154.167.99:443",
    b"payload",
  )
  .expect("encode");
  assert_eq!(&frame[5..37], hash_auth_token(AUTH_TOKEN));
  let decoded = decode_opening_frame(&frame).expect("decode");
  assert_eq!(decoded.initial_data, b"payload");
}

#[test]
fn front_config_validates() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config = front_config(&users_file, "127.0.0.1:8444");
  config.validate().expect("front config valid");
}

#[test]
fn back_config_validates() {
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let mut config = Config::test_minimal(&users_file);
  config.split.mode = SplitMode::Back;
  config.split.auth_token = Some(AUTH_TOKEN.into());
  config.split.back_listen_host = Some("127.0.0.1".into());
  config.split.back_listen_port = Some(8444);
  config.validate().expect("back config valid");
}

#[tokio::test]
async fn back_rejects_invalid_token() {
use tokio::io::{AsyncReadExt, AsyncWriteExt};
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json").to_string_lossy().to_string();
  let config_path = dir.path().join("config.toml");

  let mut config = Config::test_minimal(&users_file);
  config.split.mode = SplitMode::Back;
  config.split.auth_token = Some(AUTH_TOKEN.into());
  config.split.back_listen_host = Some("127.0.0.1".into());
  config.split.back_listen_port = Some(8444);
  config.save_to_file(&config_path).expect("save config");

  let state = AppState::new(config, config_path.to_string_lossy()).expect("state");
  let split_cfg = state.config.read().expect("read").split.clone();

  let (mut front, back) = tokio::io::duplex(8192);
  let bad_frame = encode_opening_frame(
    "wrong-token-xxxxxxxx",
    SecretMode::Classic,
    "127.0.0.1:443",
    b"x",
  )
  .expect("encode");
  front.write_all(&bad_frame).await.expect("write");

  let result = handle_back_connection(back, "127.0.0.1".parse().unwrap(), &state, &split_cfg).await;
  assert!(result.is_err());

  let mut ack = [0u8; 1];
  front.read_exact(&mut ack).await.expect("ack");
  assert_eq!(ack[0], 1);
}
