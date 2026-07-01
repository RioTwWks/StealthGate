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

## Front/Back split в production

Для split-деploy запусти **два** экземпляра с разными конфигами:

| Узел | Конфиг | Роль |
|------|--------|------|
| Публичный VPS | `configs/config.front.toml` | `[split].mode = "front"` |
| Internal relay | `configs/config.back.toml` | `[split].mode = "back"` |

Back слушает SGFB на internal interface (`back_listen_port`, по умолчанию 8444). Front подключается к `back_servers`. Подробнее: [SPLIT.md](./SPLIT.md).

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

API: `POST /api/system/uninstall` — см. [WEBUI.md](./WEBUI.md).

## Пути по умолчанию

| Путь | Назначение |
|------|------------|
| `/opt/stealth-gate/bin/stealth-gate` | бинарник |
| `/opt/stealth-gate/bin/uninstall` | скрипт удаления |
| `/opt/stealth-gate/data/` | users.json и данные |
| `/etc/stealth-gate/config.toml` | конфигурация |
| `/etc/systemd/system/stealth-gate.service` | unit |

Переменные окружения для скриптов: `INSTALL_PREFIX`, `CONFIG_DIR`, `SERVICE_NAME`.
