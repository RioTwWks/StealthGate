# Roadmap StealthGate

Статус реализации по фазам (v0.5.0).

## Phase 1 — DPI-устойчивость

| Фича | Статус | Описание |
|------|--------|----------|
| Domain fronting (SNI/fixed) | ✅ | `fallback.domain_fronting` |
| Anti-replay cache | ✅ | `security.antireplay_cache_size` |
| JA4 enforce | ✅ | `security.ja4_enforce` |
| Dynamic Record Sizing | ✅ | `[drs]` — имитация TLS record boundaries |
| Полный dd-режим MTProto | ✅ | префикс `dd` + `[dd]` min/max chunk |

## Phase 2 — Production

| Фича | Статус | Описание |
|------|--------|----------|
| Graceful shutdown | ✅ | SIGINT/SIGTERM |
| Prometheus `/metrics` | ✅ | `[metrics]` порт 9091 |
| Health `/healthz` | ✅ | metrics server |
| Multi-secret | ✅ | `[[mtproto.secrets]]` |
| Лимиты per IP / secret | ✅ | `security.max_connections_per_ip`, `max_connections` |
| SOCKS5 chaining | ✅ | `network.socks5_proxy` |
| Config validate | ✅ | при load/save |
| CI GitHub Actions | ✅ | `.github/workflows/ci.yml` |
| systemd unit | ✅ | `deploy/stealth-gate.service` |
| Multi-backend failover | ✅ | `mtproto.backends`, `failover_strategy` |

## Phase 3 — Differentiation

| Фича | Статус | Описание |
|------|--------|----------|
| MCP через admin socket | ✅ | live stats из прокси |
| MCP `get_proxy_link` | ✅ | tg:// ссылка |
| WebUI `/api/proxy-link` | ✅ | REST |
| WebUI `/api/metrics` | ✅ | Prometheus для авторизованных |
| E2E domain fronting test | ✅ | `tests/domain_fronting.rs` |
| WebUI QR-код | ✅ | `GET /api/proxy-link/qr` (SVG) |
| Webhook alerts | ✅ | `[webhooks]` config/secret/failover/start |
| Front/Back split | ⏳ | v0.6 |

## Запуск новых возможностей v0.5

```bash
# Dynamic Record Sizing (вместо фрагментации для classic/ee)
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

См. также: [WEBUI.md](./WEBUI.md), [MCP.md](./MCP.md), [CURSOR.md](./CURSOR.md).
