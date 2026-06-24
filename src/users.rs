use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use argon2::{
  password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
  Argon2,
};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StealthGateError};

/// Роль пользователя WebUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
  Admin,
  Operator,
  Viewer,
}

impl UserRole {
  pub fn can_manage_users(self) -> bool {
    matches!(self, Self::Admin)
  }

  pub fn can_edit_config(self) -> bool {
    matches!(self, Self::Admin | Self::Operator)
  }
}

/// Запись пользователя в хранилище.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
  pub username: String,
  pub password_hash: String,
  pub role: UserRole,
  pub display_name: String,
}

/// Публичное представление пользователя (без хеша пароля).
#[derive(Debug, Clone, Serialize)]
pub struct UserView {
  pub username: String,
  pub role: UserRole,
  pub display_name: String,
}

/// Файл пользователей WebUI.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsersFile {
  pub users: Vec<UserRecord>,
}

/// Хранилище пользователей с файловой персистентностью.
#[derive(Debug)]
pub struct UserStore {
  path: PathBuf,
  data: RwLock<UsersFile>,
}

impl UserStore {
  /// Загружает или создаёт хранилище пользователей.
  pub fn load(path: impl AsRef<Path>) -> Result<Arc<Self>> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
      if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|err| {
          StealthGateError::Config(format!("не удалось создать каталог {}: {err}", parent.display()))
        })?;
      }
    }

    let data = if path.exists() {
      let content = fs::read_to_string(&path).map_err(|err| {
        StealthGateError::Config(format!("не удалось прочитать {}: {err}", path.display()))
      })?;
      serde_json::from_str(&content)
        .map_err(|err| StealthGateError::Config(format!("ошибка парсинга users.json: {err}")))?
    } else {
      let default = UsersFile::default();
      let store = Self {
        path: path.clone(),
        data: RwLock::new(default),
      };
      store.ensure_default_admin()?;
      return Ok(Arc::new(store));
    };

    let store = Arc::new(Self {
      path,
      data: RwLock::new(data),
    });
    if store.list_users()?.is_empty() {
      store.ensure_default_admin()?;
    }
    Ok(store)
  }

  fn ensure_default_admin(&self) -> Result<()> {
    let password = std::env::var("STEALTHGATE_ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".into());
    if std::env::var("STEALTHGATE_ADMIN_PASSWORD").is_err() {
      tracing::warn!("используется пароль admin123 по умолчанию — задайте STEALTHGATE_ADMIN_PASSWORD");
    }
    self.create_user("admin", &password, UserRole::Admin, "Administrator")?;
    Ok(())
  }

  fn read_data(&self) -> Result<UsersFile> {
    self
      .data
      .read()
      .map(|data| data.clone())
      .map_err(|_| StealthGateError::Config("блокировка users poisoned".into()))
  }

  fn write_data(&self, data: UsersFile) -> Result<()> {
    let content = serde_json::to_string_pretty(&data)
      .map_err(|err| StealthGateError::Config(format!("сериализация users: {err}")))?;
    fs::write(&self.path, content).map_err(|err| {
      StealthGateError::Config(format!("не удалось записать {}: {err}", self.path.display()))
    })?;
    *self
      .data
      .write()
      .map_err(|_| StealthGateError::Config("блокировка users poisoned".into()))? = data;
    Ok(())
  }

  /// Список пользователей без паролей.
  pub fn list_users(&self) -> Result<Vec<UserView>> {
    Ok(
      self
        .read_data()?
        .users
        .iter()
        .map(|user| UserView {
          username: user.username.clone(),
          role: user.role,
          display_name: user.display_name.clone(),
        })
        .collect(),
    )
  }

  /// Проверяет логин и пароль.
  pub fn authenticate(&self, username: &str, password: &str) -> Result<Option<UserView>> {
    let data = self.read_data()?;
    let Some(user) = data.users.iter().find(|u| u.username == username) else {
      return Ok(None);
    };

    let parsed = PasswordHash::new(&user.password_hash).map_err(|err| {
      StealthGateError::Config(format!("некорректный password hash: {err}"))
    })?;
    if Argon2::default()
      .verify_password(password.as_bytes(), &parsed)
      .is_err()
    {
      return Ok(None);
    }

    Ok(Some(UserView {
      username: user.username.clone(),
      role: user.role,
      display_name: user.display_name.clone(),
    }))
  }

  /// Создаёт нового пользователя.
  pub fn create_user(
    &self,
    username: &str,
    password: &str,
    role: UserRole,
    display_name: &str,
  ) -> Result<UserView> {
    if username.trim().is_empty() {
      return Err(StealthGateError::Config("username не может быть пустым".into()));
    }
    if password.len() < 6 {
      return Err(StealthGateError::Config(
        "пароль должен быть не короче 6 символов".into(),
      ));
    }

    let mut data = self.read_data()?;
    if data.users.iter().any(|u| u.username == username) {
      return Err(StealthGateError::Config(format!(
        "пользователь {username} уже существует"
      )));
    }

    let hash = hash_password(password)?;
    data.users.push(UserRecord {
      username: username.to_string(),
      password_hash: hash,
      role,
      display_name: display_name.to_string(),
    });
    self.write_data(data)?;

    Ok(UserView {
      username: username.to_string(),
      role,
      display_name: display_name.to_string(),
    })
  }

  /// Удаляет пользователя.
  pub fn delete_user(&self, username: &str) -> Result<()> {
    let mut data = self.read_data()?;
    let before = data.users.len();
    data.users.retain(|user| user.username != username);
    if data.users.len() == before {
      return Err(StealthGateError::Config(format!(
        "пользователь {username} не найден"
      )));
    }
    if data.users.is_empty() {
      return Err(StealthGateError::Config(
        "нельзя удалить последнего пользователя".into(),
      ));
    }
    self.write_data(data)
  }

  /// Меняет пароль пользователя.
  pub fn update_password(&self, username: &str, password: &str) -> Result<()> {
    if password.len() < 6 {
      return Err(StealthGateError::Config(
        "пароль должен быть не короче 6 символов".into(),
      ));
    }
    let mut data = self.read_data()?;
    let Some(user) = data.users.iter_mut().find(|u| u.username == username) else {
      return Err(StealthGateError::Config(format!(
        "пользователь {username} не найден"
      )));
    };
    user.password_hash = hash_password(password)?;
    self.write_data(data)
  }
}

fn hash_password(password: &str) -> Result<String> {
  let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
  Argon2::default()
    .hash_password(password.as_bytes(), &salt)
    .map(|hash| hash.to_string())
    .map_err(|err| StealthGateError::Config(format!("ошибка хеширования пароля: {err}")))
}

#[cfg(test)]
mod tests {
  use super::*;
  use tempfile::tempdir;

  #[test]
  fn create_and_authenticate_user() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("users.json");
    let store = UserStore::load(&path).expect("load");
    store
      .create_user("operator", "secret12", UserRole::Operator, "Operator")
      .expect("create");
    let user = store
      .authenticate("operator", "secret12")
      .expect("auth")
      .expect("some");
    assert_eq!(user.username, "operator");
    assert!(store.authenticate("operator", "wrong").expect("auth").is_none());
  }
}
