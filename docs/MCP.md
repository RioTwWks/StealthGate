# MCP — управление StealthGate из AI-ассистента

Бинарник `stealth-gate-mcp` реализует [Model Context Protocol](https://modelcontextprotocol.io/) и позволяет Cursor/Claude запрашивать статистику и менять настройки прокси.

## Сборка

```bash
cargo build --release --bin stealth-gate-mcp
```

## Транспорты

### stdio (рекомендуется для Cursor)

Процесс общается через stdin/stdout. Конфиг читается с диска при старте; для live-статистики MCP подключается к тому же `AppState`, что и прокси, если указан общий `--config`.

```bash
./target/release/stealth-gate-mcp --config configs/config.toml
```

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

## Инструменты MCP

| Инструмент | Описание |
|------------|----------|
| `get_stats` | Снимок счётчиков прокси |
| `get_config` | Текущая конфигурация (сводка) |
| `reload_config` | Перечитать `config.toml` |
| `update_secret` | Обновить MTProto secret (hex, с префиксом `ee`) |

## Архитектура

```
┌─────────────┐     stdio/HTTP      ┌──────────────────┐
│ Cursor/CLI  │ ◄──────────────────►│ stealth-gate-mcp │
└─────────────┘                     └────────┬─────────┘
                                             │ AppState
                                             ▼
                                    ┌──────────────────┐
                                    │  stealth-gate    │
                                    │  (TCP-прокси)    │
                                    └──────────────────┘
```

MCP и прокси могут работать в одном процессе (через общий конфиг) или раздельно. Admin Unix-сокет (`[admin].socket`) — альтернативный канал для скриптов.

## Тесты

```bash
cargo test --test mcp_http
```

## См. также

- [Настройка Cursor](./CURSOR.md)
- [WebUI](./WEBUI.md)
