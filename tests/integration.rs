//! Интеграционные тесты StealthGate.
//!
//! Запуск: `cargo test --test integration -- --ignored`

use std::sync::Arc;
use std::time::Duration;

use stealth_gate::config::Config;
use stealth_gate::fallback;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn test_config() -> Arc<Config> {
  Arc::new(Config {
    listen: stealth_gate::config::ListenConfig {
      host: "127.0.0.1".into(),
      port: 0,
    },
    tls: stealth_gate::config::TlsConfig {
      cert_file: None,
      key_file: None,
      fake_domain: "www.cloudflare.com".into(),
      ja4_profile: None,
    },
    mtproto: stealth_gate::config::MtprotoConfig {
      secret: "ee0123456789abcdef0123456789abcdef".into(),
      backend: "127.0.0.1:1".into(),
    },
    fallback: stealth_gate::config::FallbackConfig {
      upstream: None,
      static_html: None,
    },
    fragmentation: stealth_gate::config::FragmentationConfig::default(),
    admin: stealth_gate::config::AdminConfig::default(),
  })
}

#[tokio::test]
#[ignore = "требует свободный порт и сетевой стек"]
async fn fallback_serves_http_stub() {
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let addr = listener.local_addr().expect("addr");
  let config = test_config();

  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("accept");
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.expect("read");
    buf.truncate(n);
    fallback::handle_fallback(stream, &buf, &config.fallback)
      .await
      .expect("fallback");
  });

  let mut client = tokio::net::TcpStream::connect(addr)
    .await
    .expect("connect");
  client
    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    .await
    .expect("write");

  let mut response = vec![0u8; 4096];
  let n = timeout(Duration::from_secs(2), client.read(&mut response))
    .await
    .expect("timeout")
    .expect("read");
  response.truncate(n);

  let text = String::from_utf8_lossy(&response);
  assert!(text.contains("HTTP/1.1 200"));
  assert!(text.contains("<html") || text.contains("Welcome"));

  server.await.expect("server");
}
