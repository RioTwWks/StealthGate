use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::config::FragmentationConfig;
use crate::state::{AppState, SessionUser, StatsSnapshot};
use crate::system_ops::{schedule_uninstall, UninstallSettings, UNINSTALL_CONFIRM_PHRASE};
use crate::web::session::{
  parse_role, require_admin, require_editor, require_user, ApiError,
};

#[derive(Deserialize)]
pub struct LoginRequest {
  pub username: String,
  pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
  pub user: SessionUser,
}

#[derive(Deserialize)]
pub struct ProxySettingsRequest {
  pub secret: String,
  pub backend: String,
  pub fake_domain: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
  pub username: String,
  pub password: String,
  pub role: String,
  pub display_name: String,
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
  pub password: String,
}

#[derive(Deserialize)]
pub struct UninstallRequest {
  pub confirm: String,
  #[serde(default)]
  pub purge: bool,
}

pub fn router(state: Arc<AppState>) -> Router {
  Router::new()
    .route("/auth/login", post(login))
    .route("/auth/logout", post(logout))
    .route("/auth/me", get(me))
    .route("/stats", get(stats))
    .route("/config", get(config_summary))
    .route("/config/full", get(config_full))
    .route("/config/reload", post(reload_config))
    .route("/config/mtproto", put(update_proxy_settings))
    .route("/config/fragmentation", put(update_fragmentation))
    .route("/proxy-link", get(proxy_link))
    .route("/proxy-link/qr", get(proxy_link_qr))
    .route("/metrics", get(api_metrics))
    .route("/users", get(list_users).post(create_user))
    .route("/users/{username}", delete(delete_user))
    .route("/users/{username}/password", put(update_password))
    .route("/system/uninstall", post(uninstall_service))
    .with_state(state)
}

async fn login(
  State(state): State<Arc<AppState>>,
  session: Session,
  Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
  let user = state
    .users
    .authenticate(&payload.username, &payload.password)
    .map_err(ApiError::from_stealth_gate)?
    .ok_or_else(|| ApiError::unauthorized("неверный логин или пароль"))?;

  let session_user = SessionUser {
    username: user.username.clone(),
    display_name: user.display_name.clone(),
    role: user.role,
  };
  session
    .insert("user", session_user.clone())
    .await
    .map_err(|err| ApiError::bad_request(format!("ошибка сессии: {err}")))?;

  Ok(Json(LoginResponse { user: session_user }))
}

async fn logout(session: Session) -> Result<StatusCode, ApiError> {
  session
    .flush()
    .await
    .map_err(|err| ApiError::bad_request(format!("ошибка сессии: {err}")))?;
  Ok(StatusCode::NO_CONTENT)
}

async fn me(session: Session) -> Result<Json<SessionUser>, ApiError> {
  let user = require_user(session).await?;
  Ok(Json(user))
}

async fn stats(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<Json<StatsSnapshot>, ApiError> {
  require_user(session).await?;
  Ok(Json(state.stats.snapshot()))
}

async fn config_summary(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  require_user(session).await?;
  let summary = state.config_summary().map_err(ApiError::from_stealth_gate)?;
  Ok(Json(summary))
}

async fn config_full(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  let user = require_user(session).await?;
  require_editor(&user)?;
  let config = state.full_config().map_err(ApiError::from_stealth_gate)?;
  Ok(Json(config))
}

async fn reload_config(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<Json<serde_json::Value>, ApiError> {
  let user = require_user(session).await?;
  require_editor(&user)?;
  state.reload_config().map_err(ApiError::from_stealth_gate)?;
  Ok(Json(serde_json::json!({ "status": "reloaded" })))
}

async fn update_proxy_settings(
  State(state): State<Arc<AppState>>,
  session: Session,
  Json(payload): Json<ProxySettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
  let user = require_user(session).await?;
  require_editor(&user)?;
  state
    .update_proxy_settings(payload.secret, payload.backend, payload.fake_domain)
    .map_err(ApiError::from_stealth_gate)?;
  Ok(Json(serde_json::json!({ "status": "proxy_settings_updated" })))
}

async fn update_fragmentation(
  State(state): State<Arc<AppState>>,
  session: Session,
  Json(payload): Json<FragmentationConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
  let user = require_user(session).await?;
  require_editor(&user)?;
  state
    .update_fragmentation(payload)
    .map_err(ApiError::from_stealth_gate)?;
  Ok(Json(serde_json::json!({ "status": "fragmentation_updated" })))
}

async fn list_users(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  let user = require_user(session).await?;
  require_admin(&user)?;
  let users = state.users.list_users().map_err(ApiError::from_stealth_gate)?;
  Ok(Json(users))
}

async fn create_user(
  State(state): State<Arc<AppState>>,
  session: Session,
  Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
  let user = require_user(session).await?;
  require_admin(&user)?;
  let created = state
    .users
    .create_user(
      &payload.username,
      &payload.password,
      parse_role(&payload.role)?,
      &payload.display_name,
    )
    .map_err(ApiError::from_stealth_gate)?;
  Ok((StatusCode::CREATED, Json(created)))
}

async fn delete_user(
  State(state): State<Arc<AppState>>,
  session: Session,
  Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
  let user = require_user(session).await?;
  require_admin(&user)?;
  if user.username == username {
    return Err(ApiError::bad_request("нельзя удалить себя"));
  }
  state
    .users
    .delete_user(&username)
    .map_err(ApiError::from_stealth_gate)?;
  Ok(StatusCode::NO_CONTENT)
}

async fn update_password(
  State(state): State<Arc<AppState>>,
  session: Session,
  Path(username): Path<String>,
  Json(payload): Json<UpdatePasswordRequest>,
) -> Result<StatusCode, ApiError> {
  let user = require_user(session).await?;
  if user.username != username && !user.role.can_manage_users() {
    return Err(ApiError::forbidden("недостаточно прав"));
  }
  state
    .users
    .update_password(&username, &payload.password)
    .map_err(ApiError::from_stealth_gate)?;
  Ok(StatusCode::NO_CONTENT)
}

async fn proxy_link(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  require_user(session).await?;
  let link = state.proxy_link().map_err(ApiError::from_stealth_gate)?;
  Ok(Json(serde_json::json!({ "link": link })))
}

fn render_proxy_qr_svg(link: &str) -> Result<String, ApiError> {
  let code = qrcode::QrCode::new(link.as_bytes())
    .map_err(|err| ApiError::bad_request(format!("QR: {err}")))?;
  Ok(code
    .render()
    .min_dimensions(200, 200)
    .dark_color(qrcode::render::svg::Color("#0f172a"))
    .light_color(qrcode::render::svg::Color("#ffffff"))
    .build())
}

async fn proxy_link_qr(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  require_user(session).await?;
  let link = state.proxy_link().map_err(ApiError::from_stealth_gate)?;
  let svg = render_proxy_qr_svg(&link)?;
  Ok((
    [(axum::http::header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
    svg,
  ))
}

async fn api_metrics(
  State(state): State<Arc<AppState>>,
  session: Session,
) -> Result<impl IntoResponse, ApiError> {
  require_user(session).await?;
  Ok((
    [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
    crate::metrics::render_prometheus(&state),
  ))
}

async fn uninstall_service(
  State(state): State<Arc<AppState>>,
  session: Session,
  Json(payload): Json<UninstallRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
  let user = require_user(session).await?;
  require_admin(&user)?;

  if payload.confirm != UNINSTALL_CONFIRM_PHRASE {
    return Err(ApiError::bad_request(format!(
      "для подтверждения введи {UNINSTALL_CONFIRM_PHRASE}"
    )));
  }

  let settings = {
    let config = state
      .full_config()
      .map_err(ApiError::from_stealth_gate)?;
    UninstallSettings::from_config(&config)
  };

  schedule_uninstall(&settings, payload.purge)
    .await
    .map_err(ApiError::from_stealth_gate)?;

  Ok(Json(serde_json::json!({
    "status": "uninstall_scheduled",
    "purge": payload.purge,
    "message": "Сервис будет остановлен и удалён. Соединение с WebUI может оборваться."
  })))
}
