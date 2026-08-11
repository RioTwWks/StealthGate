#!/usr/bin/env bash
# Установка StealthGate как systemd-сервиса.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/stealth-gate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/stealth-gate}"
SERVICE_NAME="${SERVICE_NAME:-stealth-gate}"
SERVICE_USER="${SERVICE_USER:-stealthgate}"
BINARY_SRC="${BINARY_SRC:-$ROOT/target/release/stealth-gate}"
UNINSTALL_SCRIPT="${INSTALL_PREFIX}/bin/uninstall"

log() {
  printf '[install] %s\n' "$*"
}

die() {
  printf '[install] ошибка: %s\n' "$*" >&2
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  die "запусти от root: sudo bash deploy/install.sh"
fi

[[ -x "${BINARY_SRC}" ]] || die "сначала собери бинарник: cargo build --release"

if ! id "${SERVICE_USER}" &>/dev/null; then
  log "создаю пользователя ${SERVICE_USER}"
  useradd --system --home "${INSTALL_PREFIX}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

log "каталоги ${INSTALL_PREFIX}, ${CONFIG_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 755 "${INSTALL_PREFIX}/bin" "${INSTALL_PREFIX}/data"
install -d -o root -g "${SERVICE_USER}" -m 750 "${CONFIG_DIR}"

log "копирую бинарник и uninstall"
install -m 755 "${BINARY_SRC}" "${INSTALL_PREFIX}/bin/stealth-gate"
install -m 755 "${ROOT}/deploy/uninstall.sh" "${UNINSTALL_SCRIPT}"

if command -v setcap &>/dev/null; then
  log "выдаю cap_net_bind_service (для ручного запуска вне systemd)"
  setcap 'cap_net_bind_service=+ep' "${INSTALL_PREFIX}/bin/stealth-gate" || \
    log "предупреждение: setcap не применился (nosuid на разделе?) — systemd unit использует AmbientCapabilities"
else
  log "предупреждение: setcap не найден (пакет libcap2-bin) — bind на :443 через AmbientCapabilities в unit"
fi

log "копирую статику WebUI и fallback HTML"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 755 "${INSTALL_PREFIX}/web"
cp -a "${ROOT}/web/." "${INSTALL_PREFIX}/web/"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_PREFIX}/web"

log "TLS-сертификаты"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${INSTALL_PREFIX}/certs"
if [[ ! -f "${INSTALL_PREFIX}/certs/cert.pem" || ! -f "${INSTALL_PREFIX}/certs/key.pem" ]]; then
  if [[ -f "${ROOT}/certs/cert.pem" && -f "${ROOT}/certs/key.pem" ]]; then
    log "копирую сертификаты из репозитория"
    install -m 640 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${ROOT}/certs/cert.pem" "${INSTALL_PREFIX}/certs/cert.pem"
    install -m 640 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${ROOT}/certs/key.pem" "${INSTALL_PREFIX}/certs/key.pem"
  else
    command -v openssl &>/dev/null || die "openssl не найден — установи openssl или запусти scripts/gen-cert.sh до install"
    log "генерирую self-signed TLS-сертификат"
    openssl req -x509 -newkey rsa:2048 \
      -keyout "${INSTALL_PREFIX}/certs/key.pem" \
      -out "${INSTALL_PREFIX}/certs/cert.pem" \
      -days 365 -nodes \
      -subj "/CN=www.cloudflare.com"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_PREFIX}/certs/cert.pem" "${INSTALL_PREFIX}/certs/key.pem"
    chmod 640 "${INSTALL_PREFIX}/certs/cert.pem" "${INSTALL_PREFIX}/certs/key.pem"
  fi
fi

if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
  log "копирую шаблон config.toml"
  install -m 640 "${ROOT}/configs/config.toml" "${CONFIG_DIR}/config.toml"
  chown root:"${SERVICE_USER}" "${CONFIG_DIR}/config.toml"
fi

patch_config_path() {
  local key="$1"
  local value="$2"
  local cfg="${CONFIG_DIR}/config.toml"
  if grep -q "^${key} = " "${cfg}"; then
    sed -i "s|^${key} = .*|${key} = \"${value}\"|" "${cfg}"
  fi
}

log "обновляю пути в config.toml для production"
patch_config_path cert_file "${INSTALL_PREFIX}/certs/cert.pem"
patch_config_path key_file "${INSTALL_PREFIX}/certs/key.pem"
patch_config_path static_html "${INSTALL_PREFIX}/web/index.html"
patch_config_path users_file "${INSTALL_PREFIX}/data/users.json"

if grep -q '^uninstall_enabled' "${CONFIG_DIR}/config.toml"; then
  sed -i 's/^uninstall_enabled = .*/uninstall_enabled = true/' "${CONFIG_DIR}/config.toml"
else
  sed -i "/^\[admin\]/a uninstall_enabled = true" "${CONFIG_DIR}/config.toml"
fi

if grep -q '^uninstall_script' "${CONFIG_DIR}/config.toml"; then
  sed -i "s|^uninstall_script = .*|uninstall_script = \"${UNINSTALL_SCRIPT}\"|" "${CONFIG_DIR}/config.toml"
else
  sed -i "/^\[admin\]/a uninstall_script = \"${UNINSTALL_SCRIPT}\"" "${CONFIG_DIR}/config.toml"
fi

log "устанавливаю systemd unit"
install -m 644 "${ROOT}/deploy/stealth-gate.service" "/etc/systemd/system/${SERVICE_NAME}.service"

log "настраиваю sudo для uninstall из WebUI"
cat >"/etc/sudoers.d/${SERVICE_NAME}-uninstall" <<EOF
${SERVICE_USER} ALL=(root) NOPASSWD: ${UNINSTALL_SCRIPT}
EOF
chmod 440 "/etc/sudoers.d/${SERVICE_NAME}-uninstall"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

sleep 1
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  log "сервис ${SERVICE_NAME} запущен"
else
  log "предупреждение: сервис не запустился — смотри: journalctl -u ${SERVICE_NAME} -e --no-pager"
  journalctl -u "${SERVICE_NAME}" -n 8 --no-pager 2>/dev/null || true
fi

log "готово"
log "  статус: systemctl status ${SERVICE_NAME}"
log "  WebUI:  http://127.0.0.1:8088/ui/login.html"
log "  удаление: sudo ${UNINSTALL_SCRIPT} [--purge]"
