use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Serialize;
use tower_sessions::Session;

use crate::error::StealthGateError;
use crate::state::SessionUser;
use crate::users::UserRole;

/// Текущий пользователь из сессии.
pub async fn current_user(session: &Session) -> Option<SessionUser> {
  session.get("user").await.ok().flatten()
}

/// Требует авторизованного пользователя.
pub async fn require_user(session: Session) -> Result<SessionUser, ApiError> {
  current_user(&session)
    .await
    .ok_or_else(|| ApiError::unauthorized("требуется авторизация"))
}

/// Требует роль с правами редактирования конфигурации.
pub fn require_editor(user: &SessionUser) -> Result<(), ApiError> {
  if user.role.can_edit_config() {
    Ok(())
  } else {
    Err(ApiError::forbidden("недостаточно прав"))
  }
}

/// Требует роль администратора.
pub fn require_admin(user: &SessionUser) -> Result<(), ApiError> {
  if user.role.can_manage_users() {
    Ok(())
  } else {
    Err(ApiError::forbidden("только для администратора"))
  }
}

/// JSON-ошибка API.
#[derive(Debug)]
pub struct ApiError {
  status: StatusCode,
  message: String,
}

impl ApiError {
  pub fn unauthorized(message: impl Into<String>) -> Self {
    Self {
      status: StatusCode::UNAUTHORIZED,
      message: message.into(),
    }
  }

  pub fn forbidden(message: impl Into<String>) -> Self {
    Self {
      status: StatusCode::FORBIDDEN,
      message: message.into(),
    }
  }

  pub fn bad_request(message: impl Into<String>) -> Self {
    Self {
      status: StatusCode::BAD_REQUEST,
      message: message.into(),
    }
  }

  pub fn from_stealth_gate(err: StealthGateError) -> Self {
    Self {
      status: StatusCode::BAD_REQUEST,
      message: err.to_string(),
    }
  }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
  error: &'a str,
}

impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    let body = serde_json::to_string(&ErrorBody {
      error: &self.message,
    })
    .unwrap_or_else(|_| r#"{"error":"internal"}"#.into());
    (
      self.status,
      [(header::CONTENT_TYPE, "application/json")],
      body,
    )
      .into_response()
  }
}

/// Редирект на страницу логина.
pub fn redirect_login() -> Response {
  Redirect::to("/ui/login").into_response()
}

/// Проверяет, что роль допустима для создания пользователя.
pub fn parse_role(role: &str) -> Result<UserRole, ApiError> {
  match role {
    "admin" => Ok(UserRole::Admin),
    "operator" => Ok(UserRole::Operator),
    "viewer" => Ok(UserRole::Viewer),
    _ => Err(ApiError::bad_request("неизвестная роль")),
  }
}
