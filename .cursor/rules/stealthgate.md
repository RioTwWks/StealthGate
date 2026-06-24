# StealthGate — контекст для Cursor Agent

## Проект

Асинхронный Rust-прокси (Tokio): маскирует MTProto под TLS, fallback на HTML-заглушку.

## Ключевые модули

| Путь | Назначение |
|------|------------|
| `src/acceptor.rs` | TCP listener, маршрутизация соединений |
| `src/detector.rs` | MTProto vs fallback по TLS ClientHello |
| `src/tls_server.rs` | TLS-терминация fallback (rustls) |
| `src/fragmentation.rs` | DPI-фрагментация первого пакета |
| `src/web/` | WebUI (axum, sessions, REST `/api`) |
| `src/admin/` | Unix-socket admin API |
| `src/mcp/` | MCP stdio + HTTP transport |
| `src/state.rs` | `AppState`, stats, reload конфига |

## Бинарники

- `stealth-gate` — основной прокси + WebUI (если `[webui].enabled`)
- `stealth-gate-mcp` — MCP-сервер

## Команды

```bash
just build    # release-сборка
just test     # все тесты
just run      # прокси с configs/config.toml
just mcp      # MCP stdio
just mcp-http # MCP HTTP :8090
just certs    # self-signed TLS
```

## Тесты

- `tests/webui.rs` — login + REST API
- `tests/tls_handshake.rs` — полный TLS handshake
- `tests/mcp_http.rs` — MCP HTTP initialize
- `tests/admin_tls.rs` — Unix admin + TLS load

## Документация

- `docs/WEBUI.md` — дашборд и REST API
- `docs/MCP.md` — инструменты и транспорты
- `docs/CURSOR.md` — настройка MCP в Cursor

## Стиль

- Комментарии и ответы — на русском
- Без `unwrap()` в production-коде
- Ошибки через `thiserror`, логи через `tracing`
