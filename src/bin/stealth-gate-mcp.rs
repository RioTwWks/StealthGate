use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use rmcp::{
  transport::streamable_http_server::{
    session::local::LocalSessionManager, tower::StreamableHttpService, StreamableHttpServerConfig,
  },
  ServiceExt,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use stealth_gate::{AppState, Config, StealthGateMcp};

#[derive(Debug, Clone, ValueEnum)]
enum Transport {
  Stdio,
  Http,
}

/// MCP-сервер StealthGate.
#[derive(Debug, Parser)]
#[command(name = "stealth-gate-mcp", about = "MCP-интерфейс управления StealthGate")]
struct Args {
  /// Транспорт MCP: stdio или streamable HTTP.
  #[arg(long, value_enum, default_value_t = Transport::Stdio)]
  transport: Transport,

  /// HTTP-хост для streamable MCP.
  #[arg(long, default_value = "127.0.0.1")]
  http_host: String,

  /// HTTP-порт для streamable MCP.
  #[arg(long, default_value_t = 8090)]
  http_port: u16,

  /// Путь к TOML-конфигурации прокси.
  #[arg(short, long, default_value = "configs/config.toml")]
  config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(
      EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    )
    .init();

  let args = Args::parse();
  let config = Config::from_file(&args.config).context("загрузка config.toml")?;
  let config_path = args.config.to_string_lossy().to_string();
  let state = AppState::new(config, config_path).context("инициализация состояния")?;

  match args.transport {
    Transport::Stdio => run_stdio(state).await?,
    Transport::Http => run_http(state, &args.http_host, args.http_port).await?,
  }

  Ok(())
}

async fn run_stdio(state: Arc<AppState>) -> anyhow::Result<()> {
  let service = StealthGateMcp::new(state);
  let running = service
    .serve(rmcp::transport::stdio())
    .await
    .context("запуск MCP stdio transport")?;
  running.waiting().await.context("MCP server stopped")?;
  Ok(())
}

async fn run_http(state: Arc<AppState>, host: &str, port: u16) -> anyhow::Result<()> {
  let addr: SocketAddr = format!("{host}:{port}")
    .parse()
    .context("некорректный HTTP-адрес MCP")?;
  let ct = CancellationToken::new();
  let service = StreamableHttpService::new(
    move || Ok(StealthGateMcp::new(Arc::clone(&state))),
    Arc::new(LocalSessionManager::default()),
    StreamableHttpServerConfig {
      stateful_mode: true,
      sse_keep_alive: None,
      cancellation_token: ct.child_token(),
      ..Default::default()
    },
  );

  let router = axum::Router::new().nest_service("/mcp", service);
  let listener = tokio::net::TcpListener::bind(addr)
    .await
    .context("bind MCP HTTP listener")?;

  tracing::info!(%addr, "MCP streamable HTTP доступен на /mcp");

  let server = axum::serve(listener, router).with_graceful_shutdown(async move {
    tokio::signal::ctrl_c().await.ok();
    ct.cancel();
  });

  server.await.context("MCP HTTP server stopped")?;
  Ok(())
}
