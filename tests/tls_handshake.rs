//! Интеграционный тест полного TLS handshake.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use stealth_gate::config::{FallbackConfig, WebuiConfig};
use stealth_gate::tls_server;
use stealth_gate::Config;

fn write_generated_cert(
  dir: &tempfile::TempDir,
) -> (String, String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
  let key_pair = KeyPair::generate().expect("key pair");
  let mut params = CertificateParams::new(["localhost".into()]).expect("cert params");
  params.distinguished_name.push(
    rcgen::DnType::CommonName,
    rcgen::DnValue::Utf8String("localhost".into()),
  );
  let cert = params.self_signed(&key_pair).expect("self signed");
  let cert_pem = cert.pem();
  let key_pem = key_pair.serialize_pem();

  let cert_path = dir.path().join("cert.pem");
  let key_path = dir.path().join("key.pem");
  std::fs::write(&cert_path, cert_pem).expect("write cert");
  std::fs::write(&key_path, key_pem).expect("write key");

  let cert_der = CertificateDer::from(cert.der().to_vec());
  let key_der = PrivateKeyDer::Pkcs8(
    rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
  );

  (
    cert_path.to_string_lossy().to_string(),
    key_path.to_string_lossy().to_string(),
    vec![cert_der],
    key_der,
  )
}

#[tokio::test]
async fn full_tls_handshake_serves_html() {
  stealth_gate::tls_server::init_rustls();
  let dir = tempdir().expect("tempdir");
  let users_file = dir.path().join("users.json");
  let config_path = dir.path().join("config.toml");

  let (cert_file, key_file, cert_chain, key_der) = write_generated_cert(&dir);

  let config = Config {
    listen: stealth_gate::config::ListenConfig {
      host: "127.0.0.1".into(),
      port: 0,
    },
    tls: stealth_gate::config::TlsConfig {
      cert_file: Some(cert_file),
      key_file: Some(key_file),
      fake_domain: "localhost".into(),
      ja4_profile: None,
    },
    mtproto: stealth_gate::config::MtprotoConfig {
      secret: "0123456789abcdef0123456789abcdef".into(),
      backend: "127.0.0.1:1".into(),
    },
    fallback: FallbackConfig {
      upstream: None,
      static_html: None,
    },
    fragmentation: stealth_gate::config::FragmentationConfig::default(),
    admin: stealth_gate::config::AdminConfig::default(),
    webui: WebuiConfig {
      users_file: users_file.to_string_lossy().to_string(),
      ..Default::default()
    },
  };
  config.save_to_file(&config_path).expect("save config");

  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key_der)
    .expect("server config");
  let acceptor = TlsAcceptor::from(Arc::new(server_config));

  let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let addr = listener.local_addr().expect("addr");
  let fallback = config.fallback.clone();
  let stats = stealth_gate::state::Stats::default();

  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("accept");
    let mut peek = vec![0u8; 4096];
    let n = stream.read(&mut peek).await.expect("read peek");
    peek.truncate(n);
    tls_server::serve_tls_fallback(stream, peek, &acceptor, &fallback, &stats)
      .await
      .expect("tls fallback");
  });

  let client_config = rustls::ClientConfig::builder()
    .with_root_certificates({
      let mut store = rustls::RootCertStore::empty();
      let cert_file = std::fs::read_to_string(dir.path().join("cert.pem")).expect("read cert");
      let mut reader = std::io::BufReader::new(cert_file.as_bytes());
      let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert");
      for cert in certs {
        store.add(cert).expect("add cert");
      }
      store
    })
    .with_no_client_auth();
  let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

  let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
  let server_name = ServerName::try_from("localhost".to_string()).expect("server name");
  let mut tls = connector.connect(server_name, tcp).await.expect("tls connect");

  tls
    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    .await
    .expect("write http");

  let mut response = Vec::new();
  let mut buf = [0u8; 1024];
  loop {
    match tls.read(&mut buf).await {
      Ok(0) => break,
      Ok(n) => response.extend_from_slice(&buf[..n]),
      Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => break,
      Err(err) => panic!("read response: {err}"),
    }
  }

  let text = String::from_utf8_lossy(&response);
  assert!(text.contains("HTTP/1.1 200"));
  assert!(text.contains("<html") || text.contains("Welcome"));

  server.await.expect("server join");
}
