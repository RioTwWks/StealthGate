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

if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
  log "копирую шаблон config.toml"
  install -m 640 "${ROOT}/configs/config.toml" "${CONFIG_DIR}/config.toml"
  chown root:"${SERVICE_USER}" "${CONFIG_DIR}/config.toml"
fi

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

log "готово"
log "  статус: systemctl status ${SERVICE_NAME}"
log "  WebUI:  http://127.0.0.1:8088/ui/login.html"
log "  удаление: sudo ${UNINSTALL_SCRIPT} [--purge]"
