# Сборка в релизном режиме
build:
    cargo build --release

# Запуск тестов
test:
    cargo test -- --nocapture

# Только WebUI-интеграция
test-webui:
    cargo test --test webui -- --nocapture

# Запуск линтера
lint:
    cargo clippy -- -D warnings

# Форматирование
fmt:
    cargo fmt

# Запуск с конфигом
run: build
    ./target/release/stealth-gate --config configs/config.toml

# MCP stdio transport
mcp:
    cargo build --release --bin stealth-gate-mcp
    ./target/release/stealth-gate-mcp --config configs/config.toml

# MCP streamable HTTP transport
mcp-http:
    cargo build --release --bin stealth-gate-mcp
    ./target/release/stealth-gate-mcp --transport http --http-port 8090 --config configs/config.toml

# Генерация TLS-сертификатов
certs:
    bash scripts/gen-cert.sh

# Очистка
clean:
    cargo clean