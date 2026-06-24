# Сборка в релизном режиме
build:
    cargo build --release

# Запуск тестов
test:
    cargo test -- --nocapture

# Запуск линтера
lint:
    cargo clippy -- -D warnings

# Форматирование
fmt:
    cargo fmt

# Запуск с конфигом
run: build
    ./target/release/stealth-gate --config configs/config.toml

# MCP-сервер управления
mcp:
    cargo build --release --bin stealth-gate-mcp
    ./target/release/stealth-gate-mcp --config configs/config.toml

# Генерация TLS-сертификатов
certs:
    bash scripts/gen-cert.sh

# Очистка
clean:
    cargo clean