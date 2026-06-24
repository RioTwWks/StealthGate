# Настройка Cursor для StealthGate

Этот репозиторий содержит готовые служебные файлы в каталоге `.cursor/`.

## MCP-сервер

Файл [`.cursor/mcp.json`](../.cursor/mcp.json) подключает:

| Сервер | Назначение |
|--------|------------|
| `stealth-gate` | MCP stdio — статистика, конфиг, reload, смена secret |
| `filesystem` | Чтение файлов проекта |
| `fetch` | HTTP-запросы к WebUI/MCP API |

Основной сервер — `stealth-gate-mcp` через **stdio**:

```json
{
  "mcpServers": {
    "stealth-gate": {
      "command": "cargo",
      "args": [
        "run",
        "--quiet",
        "--bin",
        "stealth-gate-mcp",
        "--",
        "--config",
        "configs/config.toml"
      ]
    }
  }
}
```

`cargo run` не требует предварительной сборки release-бинарника. Для production можно заменить на:

```json
{
  "mcpServers": {
    "stealth-gate": {
      "command": "./target/release/stealth-gate-mcp",
      "args": ["--config", "configs/config.toml"]
    }
  }
}
```

### MCP через HTTP

Если предпочитаешь streamable HTTP, сначала запусти:

```bash
just mcp-http
# или: ./target/release/stealth-gate-mcp --transport http --http-port 8090 --config configs/config.toml
```

Затем в **глобальном** или **проектном** `mcp.json`:

```json
{
  "mcpServers": {
    "stealth-gate-http": {
      "url": "http://127.0.0.1:8090/mcp"
    }
  }
}
```

Пример: [`.cursor/mcp.http.example.json`](../.cursor/mcp.http.example.json).

## Правила агента

Файл [`.cursor/rules/stealthgate.md`](../.cursor/rules/stealthgate.md) дополняет корневой `.cursorrules` контекстом проекта (модули, тесты, команды).

## Типичный workflow в Cursor

1. **Сборка:** `just build` или `cargo build --release`
2. **Сертификаты:** `just certs` (первый запуск)
3. **Прокси + WebUI:** `just run` → http://127.0.0.1:8088/ui/login.html
4. **MCP:** включи сервер `stealth-gate` в Cursor Settings → MCP
5. **Тесты:** `just test` или `cargo test`

## Примеры запросов к ассистенту

- «Покажи статистику StealthGate через MCP»
- «Перезагрузи конфиг прокси»
- «Обнови MTProto secret на `ee...`»
- «Запусти интеграционные тесты WebUI»

## Игнорирование файлов

[`.cursorignore`](../.cursorignore) исключает `target/`, сертификаты и секреты из индексации Cursor.
