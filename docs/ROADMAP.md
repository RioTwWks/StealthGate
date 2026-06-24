# Roadmap StealthGate

Статус реализации по фазам (v0.4.0).

## Phase 1 — DPI-устойчивость

| Фича | Статус | Описание |
|------|--------|----------|
| Domain fronting (SNI/fixed) | ✅ | `fallback.domain_fronting` |
| Anti-replay cache | ✅ | `security.antireplay_cache_size` |
| JA4 enforce | ✅ | `security.ja4_enforce` |
| Dynamic Record Sizing | ⏳ | Планируется v0.5 |
| Полный dd-режим MTProto | ⏳ | Планируется v0.5 |

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
| Multi-backend failover | ⏳ | v0.5 |

## Phase 3 — Differentiation

| Фича | Статус | Описание |
|------|--------|----------|
| MCP через admin socket | ✅ | live stats из прокси |
| MCP `get_proxy_link` | ✅ | tg:// ссылка |
| WebUI `/api/proxy-link` | ✅ | REST |
| WebUI `/api/metrics` | ✅ | Prometheus для авторизованных |
| E2E domain fronting test | ✅ | `tests/domain_fronting.rs` |
| WebUI QR-код | ⏳ | v0.5 |
| Webhook alerts | ⏳ | v0.5 |
| Front/Back split | ⏳ | v0.6 |

## Запуск новых возможностей

```bash
# Domain fronting на реальный HTTPS из SNI
[fallback]
domain_fronting = "sni"

# Anti-replay + лимиты
[security]
antireplay_cache_size = 65536
max_connections_per_ip = 50

# SOCKS5 к Telegram через Tor
[network]
socks5_proxy = "socks5://127.0.0.1:9050"

# Prometheus
[metrics]
enabled = true
```

См. также: [WEBUI.md](./WEBUI.md), [MCP.md](./MCP.md), [CURSOR.md](./CURSOR.md).
