use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use stealth_gate::{run_acceptor, Config, Result};

/// Fake TLS MTProto-прокси.
#[derive(Debug, Parser)]
#[command(name = "stealth-gate", about = "StealthGate — Fake TLS MTProto-прокси")]
struct Args {
  /// Путь к TOML-конфигурации.
  #[arg(short, long, default_value = "configs/config.toml")]
  config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(
      EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    )
    .init();

  let args = Args::parse();
  let config = Arc::new(Config::from_file(&args.config)?);

  tracing::info!(
    listen = %config.listen.socket_addr()?,
    backend = %config.mtproto.backend,
    fake_domain = %config.tls.fake_domain,
    "запуск StealthGate"
  );

  run_acceptor(config).await
}
