use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
  handler::server::{tool::ToolRouter, wrapper::Parameters},
  model::{CallToolResult, Content, ErrorCode, ErrorData, Implementation, ServerCapabilities, ServerInfo},
  schemars, tool, tool_router, ServerHandler,
};
use serde::Deserialize;

use crate::state::AppState;

/// MCP-сервер управления StealthGate.
#[derive(Clone)]
pub struct StealthGateMcp {
  state: Arc<AppState>,
  #[allow(dead_code)]
  tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateSecretRequest {
  secret: String,
}

impl StealthGateMcp {
  pub fn new(state: Arc<AppState>) -> Self {
    Self {
      state,
      tool_router: Self::tool_router(),
    }
  }
}

#[tool_router]
impl StealthGateMcp {
  #[tool(description = "Получить статистику работающего прокси StealthGate")]
  async fn get_stats(&self) -> Result<CallToolResult, ErrorData> {
    let body = serde_json::to_string(&self.state.stats.snapshot())
      .map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Получить краткую сводку конфигурации прокси")]
  async fn get_config(&self) -> Result<CallToolResult, ErrorData> {
    let summary = self
      .state
      .config_summary()
      .map_err(|err| internal_error(err.to_string()))?;
    let body = serde_json::to_string(&summary).map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Перезагрузить конфигурацию прокси с диска")]
  async fn reload_config(&self) -> Result<CallToolResult, ErrorData> {
    self
      .state
      .reload_config()
      .map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(r#"{"status":"reloaded"}"#)]))
  }

  #[tool(description = "Обновить MTProto-секрет без перезапуска прокси")]
  async fn update_secret(
    &self,
    Parameters(request): Parameters<UpdateSecretRequest>,
  ) -> Result<CallToolResult, ErrorData> {
    self
      .state
      .update_secret(request.secret)
      .map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(
      r#"{"status":"secret_updated"}"#,
    )]))
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

fn internal_error(message: String) -> ErrorData {
  ErrorData {
    code: ErrorCode(-32603),
    message: Cow::from(message),
    data: None,
  }
}
