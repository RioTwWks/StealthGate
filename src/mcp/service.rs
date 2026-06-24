use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
  handler::server::{tool::ToolRouter, wrapper::Parameters},
  model::{CallToolResult, Content, ErrorCode, ErrorData, Implementation, ServerCapabilities, ServerInfo},
  schemars, tool, tool_router, ServerHandler,
};
use serde::Deserialize;

use crate::admin;
use crate::state::{AppState, StatsSnapshot};

/// MCP-сервер управления StealthGate.
#[derive(Clone)]
pub struct StealthGateMcp {
  local: Option<Arc<AppState>>,
  admin_socket: Option<String>,
  #[allow(dead_code)]
  tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateSecretRequest {
  secret: String,
}

impl StealthGateMcp {
  /// MCP с локальным состоянием (в процессе прокси или автономно).
  pub fn new(state: Arc<AppState>) -> Self {
    let admin_socket = state
      .config
      .read()
      .ok()
      .and_then(|cfg| cfg.admin.socket.clone());
    Self {
      local: Some(state),
      admin_socket,
      tool_router: Self::tool_router(),
    }
  }

  /// MCP только через admin Unix-sокет работающего прокси.
  pub fn from_admin_socket(admin_socket: String) -> Self {
    Self {
      local: None,
      admin_socket: Some(admin_socket),
      tool_router: Self::tool_router(),
    }
  }

  async fn fetch_stats(&self) -> Result<StatsSnapshot, ErrorData> {
    if let Some(socket) = &self.admin_socket {
      if let Some(local) = &self.local {
        if local.stats.total_connections.load(std::sync::atomic::Ordering::Relaxed) > 0 {
          return Ok(local.stats.snapshot());
        }
      }
      let body = admin::admin_request(socket, "GET", "/stats", None)
        .await
        .map_err(|err| internal_error(err.to_string()))?;
      return serde_json::from_str(&body).map_err(|err| internal_error(err.to_string()));
    }

    self
      .local
      .as_ref()
      .map(|state| state.stats.snapshot())
      .ok_or_else(|| internal_error("нет локального состояния и admin socket".into()))
  }

  async fn with_local<F, T>(&self, f: F) -> Result<T, ErrorData>
  where
    F: FnOnce(&AppState) -> Result<T, crate::error::StealthGateError>,
  {
    if let Some(socket) = &self.admin_socket {
      let _ = socket;
    }
    let state = self
      .local
      .as_ref()
      .ok_or_else(|| internal_error("операция требует локальный config/state".into()))?;
    f(state).map_err(|err| internal_error(err.to_string()))
  }
}

#[tool_router]
impl StealthGateMcp {
  #[tool(description = "Получить статистику работающего прокси StealthGate")]
  async fn get_stats(&self) -> Result<CallToolResult, ErrorData> {
    let snapshot = self.fetch_stats().await?;
    let body = serde_json::to_string(&snapshot).map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Получить краткую сводку конфигурации прокси")]
  async fn get_config(&self) -> Result<CallToolResult, ErrorData> {
    let summary = self
      .with_local(|state| state.config_summary())
      .await?;
    let body = serde_json::to_string(&summary).map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Получить tg://proxy ссылку")]
  async fn get_proxy_link(&self) -> Result<CallToolResult, ErrorData> {
    let link = self.with_local(|state| state.proxy_link()).await?;
    let body = serde_json::to_string(&serde_json::json!({ "link": link }))
      .map_err(|err| internal_error(err.to_string()))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
  }

  #[tool(description = "Перезагрузить конфигурацию прокси с диска")]
  async fn reload_config(&self) -> Result<CallToolResult, ErrorData> {
    self
      .with_local(|state| state.reload_config())
      .await?;
    Ok(CallToolResult::success(vec![Content::text(
      r#"{"status":"reloaded"}"#,
    )]))
  }

  #[tool(description = "Обновить MTProto-секрет без перезапуска прокси")]
  async fn update_secret(
    &self,
    Parameters(request): Parameters<UpdateSecretRequest>,
  ) -> Result<CallToolResult, ErrorData> {
    self
      .with_local(|state| state.update_secret(request.secret))
      .await?;
    Ok(CallToolResult::success(vec![Content::text(
      r#"{"status":"secret_updated"}"#,
    )]))
  }
}

impl ServerHandler for StealthGateMcp {
  fn get_info(&self) -> ServerInfo {
    ServerInfo {
      instructions: Some(
        "Управление StealthGate: статистика, конфиг, reload, смена секрета, proxy link".into(),
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
