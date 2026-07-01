# MCP — управление StealthGate из AI-ассистента

Бинарник `stealth-gate-mcp` реализует [Model Context Protocol](https://modelcontextprotocol.io/) и позволяет Cursor/Claude запрашивать статистику, ссылку для Telegram и менять настройки прокси.

## Сборка

```bash
cargo build --release --bin stealth-gate-mcp
# или: just mcp
```

## Транспорты

### stdio (рекомендуется для Cursor)

Процесс общается через stdin/stdout. Конфиг читается с диска при старте; для live-статистики MCP подключается к admin Unix-сокету работающего прокси (`[admin].socket`).

```bash
./target/release/stealth-gate-mcp --config configs/config.toml
```

Готовый конфиг: [`.cursor/mcp.json`](../.cursor/mcp.json).

### streamable HTTP

Отдельный HTTP-сервер на порту 8090 (по умолчанию), endpoint `POST /mcp`:

```bash
./target/release/stealth-gate-mcp \
  --transport http \
  --http-port 8090 \
  --config configs/config.toml
```

Проверка:

```bash
curl -X POST http://127.0.0.1:8090/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'
```

Пример HTTP-конфига: [`.cursor/mcp.http.example.json`](../.cursor/mcp.http.example.json).

## Инструменты MCP

| Инструмент | Описание |
|------------|----------|
| `get_stats` | Снимок счётчиков прокси (JSON) |
| `get_config` | Текущая конфигурация (сводка) |
| `get_proxy_link` | `tg://proxy?server=...&port=...&secret=...` |
| `reload_config` | Перечитать `config.toml` с диска |
| `update_secret` | Обновить MTProto secret (hex, префикс `ee` или `dd`) |

### Поля `get_stats`

`total_connections`, `mtproto_connections`, `fallback_connections`,
`bytes_to_backend`, `bytes_from_backend`, `tls_handshakes`,
`fragmented_writes`, `drs_writes`, `dd_writes`, `backend_failovers`,
`replay_blocked`, `domain_fronted`, `split_relayed`, `split_auth_failed`.

## Архитектура

```
┌─────────────┐     stdio/HTTP      ┌──────────────────┐
│ Cursor/CLI  │ ◄──────────────────►│ stealth-gate-mcp │
└─────────────┘                     └────────┬─────────┘
                                             │ admin socket / AppState
                                             ▼
                                    ┌──────────────────┐
                                    │  stealth-gate    │
                                    │  (TCP-прокси)    │
                                    └──────────────────┘
```

MCP может работать:
- **Автономно** — читает конфиг, stats через admin Unix-sокет (`/tmp/stealth-gate.sock`).
- **В процессе прокси** — прямой доступ к `AppState` (если встроен).

Admin Unix-сокет (`[admin].socket`) — альтернативный канал для скриптов (`GET /stats`, `GET /proxy-link`).

## Тесты

```bash
cargo test --test mcp_http
```

## См. также

- [Настройка Cursor](./CURSOR.md)
- [WebUI](./WEBUI.md) — REST-аналоги (`/api/stats`, `/api/proxy-link`)
