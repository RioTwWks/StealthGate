//! Установка и удаление systemd-сервиса (вызов внешнего скрипта).

use std::path::Path;
use std::process::Stdio;

use crate::config::Config;
use crate::error::{Result, StealthGateError};

/// Фраза подтверждения для удаления сервиса.
pub const UNINSTALL_CONFIRM_PHRASE: &str = "UNINSTALL";

/// Настройки удаления из конфигурации.
pub struct UninstallSettings {
  pub enabled: bool,
  pub script: String,
  pub use_sudo: bool,
}

impl UninstallSettings {
  /// Читает настройки uninstall из конфигурации.
  pub fn from_config(config: &Config) -> Self {
    Self {
      enabled: config.admin.uninstall_enabled,
      script: config
        .admin
        .uninstall_script
        .clone()
        .unwrap_or_else(default_uninstall_script),
      use_sudo: config.admin.uninstall_use_sudo,
    }
  }
}

fn default_uninstall_script() -> String {
  "/opt/stealth-gate/bin/uninstall".into()
}

/// Планирует удаление сервиса через внешний скрипт (отсоединённый процесс).
pub async fn schedule_uninstall(settings: &UninstallSettings, purge: bool) -> Result<()> {
  if !settings.enabled {
    return Err(StealthGateError::Config(
      "удаление сервиса отключено (admin.uninstall_enabled = false)".into(),
    ));
  }

  let script = Path::new(&settings.script);
  if !script.exists() {
    return Err(StealthGateError::Config(format!(
      "скрипт uninstall не найден: {}",
      script.display()
    )));
  }

  let mut command = if settings.use_sudo {
    let mut cmd = tokio::process::Command::new("sudo");
    cmd.arg(script);
    cmd
  } else {
    tokio::process::Command::new(script)
  };

  command
    .arg("--from-webui")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());

  if purge {
    command.arg("--purge");
  }

  command.spawn().map_err(|err| {
    StealthGateError::Proxy(format!(
      "не удалось запустить uninstall{}: {err}",
      if settings.use_sudo { " (нужен sudo)" } else { "" }
    ))
  })?;

  tracing::warn!(
    script = %settings.script,
    purge,
    "запланировано удаление StealthGate"
  );

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::AdminConfig;

  #[test]
  fn default_script_path() {
    let config = crate::config::Config::test_minimal("data/users.json");
    let settings = UninstallSettings::from_config(&config);
    assert_eq!(settings.script, "/opt/stealth-gate/bin/uninstall");
    assert!(!settings.enabled);
  }

  #[test]
  fn reads_custom_script() {
    let mut config = crate::config::Config::test_minimal("data/users.json");
    config.admin = AdminConfig {
      socket: None,
      uninstall_enabled: true,
      uninstall_script: Some("/tmp/custom-uninstall".into()),
      uninstall_use_sudo: true,
    };
    let settings = UninstallSettings::from_config(&config);
    assert!(settings.enabled);
    assert_eq!(settings.script, "/tmp/custom-uninstall");
  }
}
