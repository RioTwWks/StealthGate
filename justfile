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

# Очистка
clean:
    cargo clean