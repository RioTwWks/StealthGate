# Настройка Cursor для StealthGate

Этот репозиторий содержит готовые служебные файлы в каталоге `.cursor/`.

## MCP-сервер

Файл [`.cursor/mcp.json`](../.cursor/mcp.json) подключает:

| Сервер | Назначение |
|--------|------------|
| `stealth-gate` | MCP stdio — stats, config, proxy link, reload, secret |
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

### Инструменты MCP

| Инструмент | Описание |
|------------|----------|
| `get_stats` | Снимок счётчиков (включая split, DRS, dd, failover) |
| `get_config` | Краткая сводка конфигурации |
| `get_proxy_link` | `tg://proxy?...` ссылка для Telegram |
| `reload_config` | Перечитать `config.toml` с диска |
| `update_secret` | Обновить MTProto secret (hex, префикс `ee`/`dd`) |

Подробнее: [MCP.md](./MCP.md).

## Правила агента

| Файл | Назначение |
|------|------------|
| [`.cursorrules`](../.cursorrules) | Общие Rust-правила и архитектура проекта |
| [`.cursor/rules/stealthgate.md`](../.cursor/rules/stealthgate.md) | Модули, тесты, команды just, ссылки на docs |

## Типичный workflow в Cursor

1. **Сертификаты:** `just certs` (первый запуск)
2. **Сборка:** `just build`
3. **Monolith:** `just run` → http://127.0.0.1:8088/ui/login.html
4. **Front/Back split:**
   ```bash
   just run-back    # терминал 1 — internal relay
   just run-front   # терминал 2 — публичный edge
   just test-split  # проверка SGFB
   ```
5. **MCP:** включи сервер `stealth-gate` в Cursor Settings → MCP
6. **Тесты:** `just test` или выборочно:
   ```bash
   just test-webui
   cargo test --test webhooks
   cargo test --test split
   cargo test --test service_uninstall
   ```
7. **Deploy:** `just install-service` / `just uninstall-service`

## Примеры запросов к ассистенту

- «Покажи статистику StealthGate через MCP»
- «Сгенерируй tg:// ссылку через get_proxy_link»
- «Перезагрузи конфиг прокси»
- «Обнови MTProto secret на `ee...`»
- «Объясни протокол SGFB в split.rs»
- «Запусти интеграционные тесты WebUI и split»

## Документация проекта

| Документ | Содержание |
|----------|------------|
| [WEBUI.md](./WEBUI.md) | REST API, QR, uninstall |
| [MCP.md](./MCP.md) | транспорты и инструменты |
| [DEPLOY.md](./DEPLOY.md) | systemd install/uninstall |
| [SPLIT.md](./SPLIT.md) | Front/Back split (v0.6) |
| [ROADMAP.md](./ROADMAP.md) | статус фич |

## Игнорирование файлов

[`.cursorignore`](../.cursorignore) исключает `target/`, сертификаты (`*.pem`, `*.key`) и `.env` из индексации Cursor.
