# WebUI — дашборд управления StealthGate

WebUI — встроенный HTTP-интерфейс для мониторинга прокси, изменения настроек MTProto и управления пользователями.

## Включение

В `configs/config.toml`:

```toml
[webui]
enabled = true
host = "127.0.0.1"          # в production слушай только loopback или за reverse proxy
port = 8088
session_secret = "длинный-случайный-секрет"
users_file = "data/users.json"
```

Переменные окружения:

| Переменная | Назначение |
|------------|------------|
| `STEALTHGATE_ADMIN_PASSWORD` | Пароль первого admin при создании `users.json` (иначе `admin123`) |

## Первый вход

1. Собери и запусти прокси: `cargo run --release --bin stealth-gate -- --config configs/config.toml`
2. Открой http://127.0.0.1:8088/ui/login.html
3. Логин по умолчанию: `admin` / `admin123` (или значение `STEALTHGATE_ADMIN_PASSWORD`)

Сразу смени пароль и `session_secret` в production.

## Страницы

| URL | Описание |
|-----|----------|
| `/ui/login.html` | Вход |
| `/ui/dashboard.html` | Статистика и настройки прокси |
| `/ui/users.html` | Управление пользователями (только admin) |

## Роли

| Роль | Просмотр stats | Редактирование конфига | Управление пользователями |
|------|----------------|------------------------|---------------------------|
| `admin` | да | да | да |
| `operator` | да | да | нет |
| `viewer` | да | нет | нет |

## REST API

Базовый префикс: `/api`. Все защищённые эндпоинты требуют cookie-сессию после `POST /api/auth/login`.

### Аутентификация

```bash
# Вход
curl -c cookies.txt -X POST http://127.0.0.1:8088/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'

# Текущий пользователь
curl -b cookies.txt http://127.0.0.1:8088/api/auth/me

# Выход
curl -b cookies.txt -X POST http://127.0.0.1:8088/api/auth/logout
```

### Мониторинг

| Метод | Путь | Роль | Описание |
|-------|------|------|----------|
| `GET` | `/api/stats` | любая | Счётчики соединений и трафика |
| `GET` | `/api/config` | любая | Краткая сводка конфигурации |
| `GET` | `/api/config/full` | operator+ | Полный конфиг |
| `POST` | `/api/config/reload` | operator+ | Перечитать `config.toml` с диска |

### Настройки прокси

```bash
# MTProto: secret, backend, fake_domain
curl -b cookies.txt -X PUT http://127.0.0.1:8088/api/config/mtproto \
  -H 'Content-Type: application/json' \
  -d '{"secret":"ee0123...","backend":"149.154.167.99:443","fake_domain":"www.cloudflare.com"}'

# Фрагментация
curl -b cookies.txt -X PUT http://127.0.0.1:8088/api/config/fragmentation \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"chunk_sizes":[1,2,3],"delay_ms":0}'
```

### Пользователи (admin)

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/api/users` | Список пользователей |
| `POST` | `/api/users` | Создать пользователя |
| `DELETE` | `/api/users/{username}` | Удалить (нельзя удалить себя) |
| `PUT` | `/api/users/{username}/password` | Сменить пароль |

## Безопасность

- Сессии: signed cookies (`stealthgate_session`), срок неактивности 12 часов.
- Пароли: Argon2, хранятся в `data/users.json` (файл в `.gitignore`).
- В production:
  - уникальный `session_secret`;
  - `host = "127.0.0.1"` + SSH-туннель или reverse proxy с TLS;
  - смена пароля admin после первого входа.

## Тесты

```bash
cargo test --test webui
```
