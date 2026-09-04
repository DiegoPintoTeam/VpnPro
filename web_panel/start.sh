#!/usr/bin/env bash
# ============================================================
#  VPNPro Web Panel — Lanzador de desarrollo
# ============================================================

set -euo pipefail
cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"
INSTALL_DEPS_ON_START="${INSTALL_DEPS_ON_START:-false}"

if [[ -z "${PYTHON_BIN}" ]]; then
	echo "[!] python3 no está instalado o no está en PATH"
	exit 1
fi

# Auto-sync de usuarios servidor -> panel
export AUTO_SYNC_ENABLED="${AUTO_SYNC_ENABLED:-true}"
export AUTO_SYNC_INTERVAL_MINUTES="${AUTO_SYNC_INTERVAL_MINUTES:-30}"
export PANEL_DATA_DIR="${PANEL_DATA_DIR:-$(pwd)/instance}"
export WEB_PANEL_PORT="${WEB_PANEL_PORT:-80}"

if [[ "${INSTALL_DEPS_ON_START,,}" == "true" ]]; then
	echo "[*] Instalando dependencias Python (modo bajo demanda)..."
	"${PYTHON_BIN}" -m pip install -r requirements.txt -q
fi

echo "[*] Iniciando VPNPro Web Panel en puerto ${WEB_PANEL_PORT}..."
echo "[*] Directorio de datos del panel: ${PANEL_DATA_DIR}"
"${PYTHON_BIN}" app.py
