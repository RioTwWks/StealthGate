use std::borrow::Cow;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use rmcp::{
  handler::server::{tool::ToolRouter, wrapper::Parameters},
  model::{CallToolResult, Content, ErrorCode, ErrorData, Implementation, ServerCapabilities, ServerInfo},
  schemars, tool, tool_router, ServerHandler, ServiceExt,
};
use serde::Deserialize;

/// MCP-сервер управления StealthGate.
#[derive(Clone)]
pub struct StealthGateMcp {
  admin_socket: String,
  #[allow(dead_code)]
  tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateSecretRequest {
  /// Новый hex-секрет MTProto (32 символа, опционально с префиксом ee/dd).
  secret: String,
}

impl StealthGateMcp {
  fn new(admin_socket: impl Into<String>) -> Self {
    Self {
      admin_socket: admin_socket.into(),
      tool_router: Self::tool_router(),
    }
  }
}

#[tool_router]
impl StealthGateMcp {
  #[tool(description = "Получить статистику работающего прокси StealthGate")]
  async fn get_stats(&self) -> Result<CallToolResult, ErrorData> {
    let body = stealth_gate::admin::admin_request(&self.admin_socket, "GET", "/stats", None)
      .await
      .map_err(admin_error)?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Получить краткую сводку конфигурации прокси")]
  async fn get_config(&self) -> Result<CallToolResult, ErrorData> {
    let body = stealth_gate::admin::admin_request(&self.admin_socket, "GET", "/config", None)
      .await
      .map_err(admin_error)?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Перезагрузить конфигурацию прокси с диска")]
  async fn reload_config(&self) -> Result<CallToolResult, ErrorData> {
    let body =
      stealth_gate::admin::admin_request(&self.admin_socket, "POST", "/reload", None)
        .await
        .map_err(admin_error)?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Обновить MTProto-секрет без перезапуска прокси")]
  async fn update_secret(
    &self,
    Parameters(request): Parameters<UpdateSecretRequest>,
  ) -> Result<CallToolResult, ErrorData> {
    let payload = serde_json::json!({ "secret": request.secret }).to_string();
    let body = stealth_gate::admin::admin_request(
      &self.admin_socket,
      "POST",
      "/secret",
      Some(&payload),
    )
    .await
    .map_err(admin_error)?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }
}

impl ServerHandler for StealthGateMcp {
  fn get_info(&self) -> ServerInfo {
    ServerInfo {
      instructions: Some(
        "Управление StealthGate: статистика, перезагрузка конфигурации, смена секрета".into(),
      ),
      capabilities: ServerCapabilities::builder().enable_tools().build(),
      server_info: Implementation {
        name: "stealth-gate-mcp".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
      },
      ..Default::default()
    }
  }
}

fn admin_error(err: stealth_gate::StealthGateError) -> ErrorData {
  ErrorData {
    code: ErrorCode(-32603),
    message: Cow::from(format!("admin API: {err}")),
    data: None,
  }
}

/// MCP-сервер StealthGate.
#[derive(Debug, Parser)]
#[command(name = "stealth-gate-mcp", about = "MCP-интерфейс управления StealthGate")]
struct Args {
  /// Путь к Unix-сокету admin API прокси.
  #[arg(long, env = "STEALTHGATE_ADMIN_SOCKET")]
  admin_socket: Option<PathBuf>,

  /// Путь к TOML-конфигурации (для определения admin socket).
  #[arg(short, long, default_value = "configs/config.toml")]
  config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let args = Args::parse();

  let admin_socket = if let Some(socket) = args.admin_socket {
    socket
  } else if let Ok(config) = stealth_gate::Config::from_file(&args.config) {
    config
      .admin
      .socket
      .map(PathBuf::from)
      .unwrap_or_else(|| PathBuf::from("/tmp/stealth-gate.sock"))
  } else {
    PathBuf::from("/tmp/stealth-gate.sock")
  };

  let service = StealthGateMcp::new(admin_socket.to_string_lossy());
  let running = service
    .serve(rmcp::transport::stdio())
    .await
    .context("запуск MCP stdio transport")?;
  running.waiting().await.context("MCP server stopped")?;
  Ok(())
}
