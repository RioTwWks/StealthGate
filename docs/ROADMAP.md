# Roadmap StealthGate

Статус реализации по фазам. **Текущая версия: 0.6.0.**

| Документ | Содержание |
|----------|------------|
| [CURSOR.md](./CURSOR.md) | MCP и workflow в Cursor |
| [WEBUI.md](./WEBUI.md) | REST API, QR, uninstall |
| [MCP.md](./MCP.md) | MCP транспорты и инструменты |
| [DEPLOY.md](./DEPLOY.md) | systemd install/uninstall |
| [SPLIT.md](./SPLIT.md) | Front/Back split (SGFB) |

## Phase 0 — Базовый прокси (MVP)

| Фича | Статус | Описание |
|------|--------|----------|
| Fake TLS MTProto proxy | ✅ | `detector` + `proxy`, `tokio::io::copy_bidirectional` |
| TLS fallback / заглушка | ✅ | `tls_server`, `fallback.static_html` |
| Фрагментация ClientHello | ✅ | `[fragmentation]` chunk_sizes, delay_ms |
| WebUI дашборд | ✅ | axum, роли admin/operator/viewer |
| Admin Unix-socket API | ✅ | `[admin].socket` — stats, reload, proxy-link |
| MCP stdio + HTTP | ✅ | `stealth-gate-mcp`, rmcp |
| Hot-reload конфига | ✅ | WebUI / MCP / admin |

## Phase 1 — DPI-устойчивость

| Фича | Статус | Описание |
|------|--------|----------|
| Domain fronting (SNI/fixed) | ✅ | `fallback.domain_fronting`, `fronting_port` |
| Anti-replay cache | ✅ | `security.antireplay_cache_size` |
| JA4 enforce | ✅ | `security.ja4_enforce`, `tls.ja4_profile` |
| Dynamic Record Sizing | ✅ | `[drs]` — имитация TLS record boundaries |
| Полный dd-режим MTProto | ✅ | префикс `dd` + `[dd]` min/max chunk |

## Phase 2 — Production

| Фича | Статус | Описание |
|------|--------|----------|
| Graceful shutdown | ✅ | SIGINT/SIGTERM |
| Prometheus `/metrics` | ✅ | `[metrics]` порт 9091 |
| Health `/healthz` | ✅ | metrics server |
| Multi-secret | ✅ | `[[mtproto.secrets]]` с лимитами |
| Лимиты per IP / secret | ✅ | `security.max_connections_per_ip`, `max_connections` |
| IP blacklist | ✅ | `security.ip_blacklist` |
| SOCKS5 chaining | ✅ | `network.socks5_proxy` |
| Config validate | ✅ | при load/save |
| CI GitHub Actions | ✅ | `.github/workflows/ci.yml` |
| systemd unit | ✅ | `deploy/stealth-gate.service` |
| install / uninstall scripts | ✅ | `deploy/install.sh`, `deploy/uninstall.sh` |
| WebUI удаление сервиса | ✅ | кнопка admin + `POST /api/system/uninstall` |
| Multi-backend failover | ✅ | `mtproto.backends`, `failover_strategy` |

## Phase 3 — Differentiation

| Фича | Статус | Описание |
|------|--------|----------|
| MCP через admin socket | ✅ | live stats из работающего прокси |
| MCP `get_proxy_link` | ✅ | tg:// ссылка для Telegram |
| WebUI `/api/proxy-link` | ✅ | REST JSON |
| WebUI `/api/proxy-link/qr` | ✅ | SVG QR-код |
| WebUI `/api/metrics` | ✅ | Prometheus для авторизованных |
| Webhook alerts | ✅ | `[webhooks]` — config/secret/failover/start |
| Front/Back split | ✅ | `[split]` mode front/back, протокол SGFB |
| Пример webhook-receiver | ✅ | `examples/webhook_receiver.rs` |

## Phase 4 — Документация и DX

| Фича | Статус | Описание |
|------|--------|----------|
| README v0.6 | ✅ | фичи, split, таблица docs |
| docs/CURSOR.md | ✅ | MCP, split/uninstall workflow |
| docs/WEBUI.md | ✅ | API, stats, QR, uninstall |
| docs/MCP.md | ✅ | инструменты, поля stats |
| docs/DEPLOY.md | ✅ | systemd + split в production |
| docs/SPLIT.md | ✅ | протокол SGFB, конфиги front/back |
| `.cursor/rules/stealthgate.md` | ✅ | модули, тесты, just-команды |
| `.cursor/mcp.json` | ✅ | stdio MCP для Cursor |
| `justfile` | ✅ | run-front/back, test-split, install/uninstall |

## Покрытие тестами

| Тест | Покрытие |
|------|----------|
| `tests/unit.rs` | unit-тесты модулей |
| `tests/webui.rs` | login, REST API, proxy-link, QR |
| `tests/webhooks.rs` | webhook-уведомления |
| `tests/split.rs` | SGFB handshake, front/back |
| `tests/service_uninstall.rs` | uninstall API |
| `tests/tls_handshake.rs` | полный TLS handshake |
| `tests/mcp_http.rs` | MCP HTTP initialize |
| `tests/admin_tls.rs` | Unix admin + TLS load |
| `tests/domain_fronting.rs` | domain fronting E2E |
| `tests/integration.rs` | сетевые (`#[ignore]`) |

```bash
cargo test                    # ~62 теста
cargo clippy -- -D warnings
```

## Запуск возможностей v0.5

```toml
# Dynamic Record Sizing (альтернатива fragmentation для classic/ee)
[drs]
enabled = true
record_sizes = [512, 1024, 1398, 256]

# dd-секрет (рандомные размеры чанков)
[mtproto]
secret = "dd0123456789abcdef0123456789abcdef"

[dd]
min_chunk_size = 64
max_chunk_size = 1024

# Multi-backend failover
[mtproto]
backend = "149.154.167.99:443"
backends = ["149.154.175.50:443"]
failover_strategy = "priority"  # или round_robin

# Webhooks
[webhooks]
enabled = true
urls = ["https://hooks.example.com/stealthgate"]
events = ["config_reloaded", "secret_updated", "backend_failover", "proxy_started"]
```

Пример приёмника: `cargo run --example webhook-receiver -- --port 9999`.

## Front/Back split (v0.6)

Примеры конфигов: `configs/config.front.toml`, `configs/config.back.toml`.

```toml
# Back relay (internal, ближе к Telegram DC)
[split]
mode = "back"
auth_token = "shared-secret-min-16-chars"
back_listen_host = "0.0.0.0"
back_listen_port = 8444
front_allowlist = ["10.0.0.1"]

# Front edge (публичный VPS)
[split]
mode = "front"
auth_token = "shared-secret-min-16-chars"
back_servers = ["10.0.0.2:8444"]
connect_timeout_secs = 10
```

```bash
just run-back     # терминал 1
just run-front    # терминал 2
just test-split   # проверка SGFB
```

Метрики: `split_relayed`, `split_auth_failed`. Подробнее: [SPLIT.md](./SPLIT.md).
