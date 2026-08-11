# Деплой StealthGate (systemd)

## Быстрая установка (monolith)

```bash
cargo build --release
sudo bash deploy/install.sh
```

## Front/Back split в production

Для split-деплоя на **двух** серверах используй разные роли — не один `config.toml`:

| Сервер | Роль | Команда | Шаблон |
|--------|------|---------|--------|
| RU (публичный edge) | front | `sudo bash deploy/install.sh --front` | `configs/config.front.toml` |
| EU (relay к Telegram DC) | back | `sudo bash deploy/install.sh --back` | `configs/config.back.toml` |

Или через переменную окружения:

```bash
# RU
sudo INSTALL_ROLE=front bash deploy/install.sh

# EU
sudo INSTALL_ROLE=back bash deploy/install.sh
```

После установки **обязательно** согласуй в обоих `config.toml`:
- одинаковый `split.auth_token` (минимум 16 символов)
- на front: `split.back_servers` = IP EU:8444
- на back: `split.front_allowlist` = IP RU

Back слушает SGFB на `back_listen_port` (по умолчанию 8444). Порт не должен быть доступен из интернета. Подробнее: [SPLIT.md](./SPLIT.md).

> Если `config.toml` уже создан при monolith-установке, install не перезапишет его — удали `/etc/stealth-gate/config.toml` и переустанови с нужной ролью, либо скопируй шаблон вручную.

Или через `just`:

```bash
just install-service
```

Скрипт:
- создаёт пользователя `stealthgate`
- копирует бинарник в `/opt/stealth-gate/bin/`
- выдаёт `cap_net_bind_service` бинарнику (слушать порт 443 без root)
- копирует `web/` и TLS-сертификаты в `/opt/stealth-gate/`
- устанавливает unit `deploy/stealth-gate.service`
- включает `admin.uninstall_enabled` в `/etc/stealth-gate/config.toml`
- настраивает sudo для удаления из WebUI

Зависимости на хосте: `openssl`, `libcap2-bin` (для `setcap`).

## Диагностика

Если сервис падает с `status=1/FAILURE`:

```bash
sudo journalctl -u stealth-gate -e --no-pager
```

Типичные причины:
- **Permission denied на bind :443** — unit должен содержать `AmbientCapabilities=CAP_NET_BIND_SERVICE` (без `NoNewPrivileges=true`, иначе `setcap` не работает под systemd)
- **ошибка конфигурации** — проверь `/etc/stealth-gate/config.toml`
- **split: front/back перепутаны** — на RU нужен `--front`, на EU `--back` (см. выше)

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
