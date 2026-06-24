# Деплой StealthGate (systemd)

## Быстрая установка

```bash
cargo build --release
sudo bash deploy/install.sh
```

Или через `just`:

```bash
just install-service
```

Скрипт:
- создаёт пользователя `stealthgate`
- копирует бинарник в `/opt/stealth-gate/bin/`
- устанавливает unit `deploy/stealth-gate.service`
- включает `admin.uninstall_enabled` в `/etc/stealth-gate/config.toml`
- настраивает sudo для удаления из WebUI

## Удаление одной командой

```bash
# Только systemd unit (данные сохраняются)
sudo bash deploy/uninstall.sh

# Полное удаление
sudo bash deploy/uninstall.sh --purge
```

Или:

```bash
just uninstall-service
```

## Удаление из WebUI

После `install.sh` в дашборде (роль **admin**) появляется секция «Удаление сервиса»:

1. Опционально включи `--purge`
2. Введи `UNINSTALL`
3. Нажми **Удалить сервис**

Требования:
- `admin.uninstall_enabled = true` в конфиге
- скрипт `/opt/stealth-gate/bin/uninstall` и sudoers (настраивается install.sh)

## Пути по умолчанию

| Путь | Назначение |
|------|------------|
| `/opt/stealth-gate/bin/stealth-gate` | бинарник |
| `/opt/stealth-gate/bin/uninstall` | скрипт удаления |
| `/opt/stealth-gate/data/` | users.json и данные |
| `/etc/stealth-gate/config.toml` | конфигурация |
| `/etc/systemd/system/stealth-gate.service` | unit |

Переменные окружения для скриптов: `INSTALL_PREFIX`, `CONFIG_DIR`, `SERVICE_NAME`.
