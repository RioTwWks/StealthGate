# StealthGate — контекст для Cursor Agent

## Проект

Асинхронный Rust-прокси (Tokio, v0.6.0): маскирует MTProto под TLS, fallback на HTML-заглушку, WebUI, MCP, Front/Back split (SGFB).

## Режимы работы

| `[split].mode` | Описание |
|----------------|----------|
| `monolith` | Всё в одном процессе (по умолчанию) |
| `front` | Публичный edge: детекция + relay на back |
| `back` | Внутренний relay на Telegram DC |

Подробнее: `docs/SPLIT.md`, примеры: `configs/config.front.toml`, `configs/config.back.toml`.

## Ключевые модули

| Путь | Назначение |
|------|------------|
| `src/acceptor.rs` | TCP listener, маршрутизация (monolith/front/back) |
| `src/detector.rs` | MTProto vs fallback по TLS ClientHello |
| `src/split.rs` | Протокол SGFB, relay front→back |
| `src/proxy.rs` | `copy_bidirectional` к backend |
| `src/backend_pool.rs` | Multi-backend failover (`priority` / `round_robin`) |
| `src/drs.rs` | Dynamic Record Sizing (TLS record boundaries) |
| `src/dd_protocol.rs` | dd-секрет: случайные размеры чанков |
| `src/fragmentation.rs` | DPI-фрагментация первого пакета (ee/classic) |
| `src/domain_fronting.rs` | SNI / fixed domain fronting |
| `src/antireplay.rs` | Anti-replay cache |
| `src/tls_server.rs` | TLS-терминация fallback (rustls) |
| `src/webhooks.rs` | HTTP-уведомления (config/secret/failover/start) |
| `src/system_ops.rs` | Удаление systemd-сервиса из WebUI |
| `src/web/` | WebUI (axum, sessions, REST `/api`) |
| `src/admin/` | Unix-socket admin API |
| `src/mcp/` | MCP stdio + HTTP transport |
| `src/state.rs` | `AppState`, stats, reload конфига |
| `src/metrics.rs` | Prometheus `/metrics` на :9091 |

## Бинарники

- `stealth-gate` — основной прокси + WebUI (если `[webui].enabled`)
- `stealth-gate-mcp` — MCP-сервер

## Команды (just)

```bash
just build              # release-сборка
just test               # все тесты
just run                # monolith с configs/config.toml
just run-front          # configs/config.front.toml
just run-back           # configs/config.back.toml
just test-split         # tests/split.rs
just test-webui         # tests/webui.rs
just mcp                # MCP stdio
just mcp-http           # MCP HTTP :8090
just certs              # self-signed TLS
just install-service    # deploy/install.sh
just uninstall-service  # deploy/uninstall.sh --purge
just lint               # clippy -D warnings
```

## Тесты

| Файл | Покрытие |
|------|----------|
| `tests/webui.rs` | login, REST API, proxy-link, QR |
| `tests/webhooks.rs` | webhook-уведомления |
| `tests/split.rs` | SGFB handshake, front/back |
| `tests/service_uninstall.rs` | uninstall API |
| `tests/tls_handshake.rs` | полный TLS handshake |
| `tests/mcp_http.rs` | MCP HTTP initialize |
| `tests/admin_tls.rs` | Unix admin + TLS load |
| `tests/domain_fronting.rs` | domain fronting |
| `tests/integration.rs` | сетевые (часть `#[ignore]`) |
| `tests/unit.rs` | unit-тесты модулей |

## Документация

| Файл | Содержание |
|------|------------|
| `docs/CURSOR.md` | MCP и workflow в Cursor |
| `docs/WEBUI.md` | дашборд и REST API |
| `docs/MCP.md` | инструменты и транспорты |
| `docs/DEPLOY.md` | systemd install/uninstall |
| `docs/SPLIT.md` | Front/Back split (SGFB) |
| `docs/ROADMAP.md` | статус фич v0.6.0 |

## Конфигурация (ключевые секции)

`[listen]`, `[tls]`, `[mtproto]` (+ `backends`, `failover_strategy`, `[[secrets]]`),
`[fallback]`, `[fragmentation]`, `[drs]`, `[dd]`, `[split]`, `[webhooks]`,
`[security]`, `[network]`, `[metrics]`, `[admin]`, `[webui]`.

Пример: `configs/config.toml`.

## Стиль

- Комментарии и ответы — на русском
- Без `unwrap()` в production-коде
- Ошибки через `thiserror`, логи через `tracing`
