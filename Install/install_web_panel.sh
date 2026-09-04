#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta como root: sudo bash install_web_panel.sh"
  exit 1
fi

REPO_URL="https://github.com/DiegoPintoTeam/VPNPro.git"
BASE_DIR="/opt/vpnpro-web-panel"
PANEL_DIR="${BASE_DIR}/web_panel"
VENV_DIR="${BASE_DIR}/.venv"
SERVICE_FILE="/etc/systemd/system/vpnpro-web.service"
ENV_FILE="/etc/default/vpnpro-web"

AUTO_SYNC_ENABLED="${AUTO_SYNC_ENABLED:-true}"
AUTO_SYNC_INTERVAL_MINUTES="${AUTO_SYNC_INTERVAL_MINUTES:-30}"
AUTO_LIMITER_ENABLED="${AUTO_LIMITER_ENABLED:-true}"
AUTO_LIMITER_INTERVAL_SECONDS="${AUTO_LIMITER_INTERVAL_SECONDS:-30}"
ONLINE_CHECK_INTERVAL_MS="${ONLINE_CHECK_INTERVAL_MS:-60000}"
WEB_PANEL_PORT="${WEB_PANEL_PORT:-80}"
PANEL_DATA_DIR="${PANEL_DATA_DIR:-/var/lib/vpnpro-web}"
WEB_PANEL_WORKERS="${WEB_PANEL_WORKERS:-4}"
WEB_PANEL_THREADS="${WEB_PANEL_THREADS:-4}"
WEB_PANEL_TIMEOUT="${WEB_PANEL_TIMEOUT:-180}"

export DEBIAN_FRONTEND=noninteractive

wait_apt_lock() {
  local attempts="${1:-60}"
  local delay="${2:-3}"
  local i=0
  while [[ "$i" -lt "$attempts" ]]; do
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
       fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
       fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
       fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
      ((i+=1))
      sleep "$delay"
      continue
    fi
    return 0
  done
  return 1
}

apt_safe() {
  apt-get -o DPkg::Lock::Timeout=300 "$@"
}

echo "[*] Instalando dependencias del sistema..."
if ! wait_apt_lock; then
  echo "[!] No se libero el lock de apt/dpkg a tiempo. Reintenta en unos minutos."
  exit 1
fi
apt_safe update -y
apt_safe install -y git python3 python3-venv python3-pip

echo "[*] Descargando/actualizando VPNPro..."
if [[ -d "${BASE_DIR}/.git" ]]; then
  git -C "${BASE_DIR}" fetch --all --prune
  git -C "${BASE_DIR}" reset --hard origin/main
else
  rm -rf "${BASE_DIR}"
  git clone --depth 1 "${REPO_URL}" "${BASE_DIR}"
fi

echo "[*] Creando entorno virtual Python..."
python3 -m venv "${VENV_DIR}"

echo "[*] Instalando dependencias Python del panel..."
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${PANEL_DIR}/requirements.txt"

echo "[*] Preparando almacenamiento persistente del panel..."
mkdir -p "${PANEL_DATA_DIR}"

echo "[*] Configurando servicio systemd..."
cat > "${ENV_FILE}" <<EOF
AUTO_SYNC_ENABLED=${AUTO_SYNC_ENABLED}
AUTO_SYNC_INTERVAL_MINUTES=${AUTO_SYNC_INTERVAL_MINUTES}
AUTO_LIMITER_ENABLED=${AUTO_LIMITER_ENABLED}
AUTO_LIMITER_INTERVAL_SECONDS=${AUTO_LIMITER_INTERVAL_SECONDS}
ONLINE_CHECK_INTERVAL_MS=${ONLINE_CHECK_INTERVAL_MS}
WEB_PANEL_PORT=${WEB_PANEL_PORT}
PANEL_DATA_DIR=${PANEL_DATA_DIR}
WEB_PANEL_WORKERS=${WEB_PANEL_WORKERS}
WEB_PANEL_THREADS=${WEB_PANEL_THREADS}
WEB_PANEL_TIMEOUT=${WEB_PANEL_TIMEOUT}
EOF

cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VPNPro Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${VENV_DIR}/bin/gunicorn --worker-class gthread --threads ${WEB_PANEL_THREADS} --workers ${WEB_PANEL_WORKERS} --bind 0.0.0.0:${WEB_PANEL_PORT} --timeout ${WEB_PANEL_TIMEOUT} --graceful-timeout 30 --keep-alive 5 --worker-tmp-dir /dev/shm "app:create_app()"
Restart=always
RestartSec=3
User=root
EnvironmentFile=-${ENV_FILE}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpnpro-web.service
systemctl restart vpnpro-web.service

if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${WEB_PANEL_PORT}/tcp" || true
  echo "[+] Regla UFW añadida para puerto ${WEB_PANEL_PORT}/tcp"
fi

IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "[+] Instalacion finalizada"
echo "[+] Servicio activo: vpnpro-web.service"
echo "[+] Auto-sync: ${AUTO_SYNC_ENABLED} | intervalo: ${AUTO_SYNC_INTERVAL_MINUTES} min"
echo "[+] Limitador background: ${AUTO_LIMITER_ENABLED} | intervalo: ${AUTO_LIMITER_INTERVAL_SECONDS} s"
echo "[+] Datos persistentes del panel: ${PANEL_DATA_DIR}"
if [[ -n "${IP_ADDR}" ]]; then
  echo "[+] Accede en: http://${IP_ADDR}:${WEB_PANEL_PORT}"
else
  echo "[+] Accede en: http://TU_IP_VPS:${WEB_PANEL_PORT}"
fi
echo "[+] Usuario: VPNPro"
echo "[+] Clave: 123456"
