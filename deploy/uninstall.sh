#!/usr/bin/env bash
# Удаление StealthGate systemd-сервиса одной командой.
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/stealth-gate}"
CONFIG_DIR="${CONFIG_DIR:-/etc/stealth-gate}"
SERVICE_NAME="${SERVICE_NAME:-stealth-gate}"
SERVICE_USER="${SERVICE_USER:-stealthgate}"
PURGE=false
FROM_WEBUI=false

log() {
  printf '[uninstall] %s\n' "$*"
}

usage() {
  cat <<EOF
Удаление StealthGate из systemd.

Использование:
  sudo bash deploy/uninstall.sh [--purge] [--from-webui]

Опции:
  --purge       Удалить ${INSTALL_PREFIX}, ${CONFIG_DIR} и пользователя ${SERVICE_USER}
  --from-webui  Вызов из WebUI/API (без интерактивного подтверждения)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)
      PURGE=true
      ;;
    --from-webui)
      FROM_WEBUI=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'неизвестный аргумент: %s\n' "$1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ "${EUID}" -ne 0 ]]; then
  printf 'запусти от root: sudo %s [--purge]\n' "$0" >&2
  exit 1
fi

if [[ "${FROM_WEBUI}" != true && "${PURGE}" != true ]]; then
  read -r -p "Удалить systemd-сервис ${SERVICE_NAME}? [y/N] " answer
  if [[ "${answer}" != "y" && "${answer}" != "Y" ]]; then
    log "отменено"
    exit 0
  fi
fi

log "останавливаю ${SERVICE_NAME}"
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  log "удалён unit-файл"
fi

if [[ -f "/etc/sudoers.d/${SERVICE_NAME}-uninstall" ]]; then
  rm -f "/etc/sudoers.d/${SERVICE_NAME}-uninstall"
  log "удалён sudoers"
fi

systemctl daemon-reload
systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

if [[ "${PURGE}" == true ]]; then
  log "purge: удаляю файлы и пользователя"
  rm -rf "${INSTALL_PREFIX}"
  rm -rf "${CONFIG_DIR}"
  if id "${SERVICE_USER}" &>/dev/null; then
    userdel --remove "${SERVICE_USER}" 2>/dev/null || userdel "${SERVICE_USER}" 2>/dev/null || true
  fi
else
  log "данные сохранены: ${INSTALL_PREFIX}, ${CONFIG_DIR}"
  log "для полного удаления: sudo $0 --purge"
fi

log "StealthGate удалён"
