use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use stealth_gate::{run_acceptor, AppState, Config, Result};

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
  stealth_gate::tls_server::init_rustls();
  let config = Config::from_file(&args.config)?;
  let config_path = args.config.to_string_lossy().to_string();
  let state = AppState::new(config, config_path);

  {
    let cfg = state
      .config
      .read()
      .map_err(|_| stealth_gate::StealthGateError::Config("блокировка config poisoned".into()))?;
    tracing::info!(
      listen = %cfg.listen.socket_addr()?,
      backend = %cfg.mtproto.backend,
      fake_domain = %cfg.tls.fake_domain,
      tls_termination = cfg.tls.is_enabled(),
      fragmentation = cfg.fragmentation.enabled,
      admin_socket = ?cfg.admin.socket,
      "запуск StealthGate"
    );
  }

  run_acceptor(state).await
}
