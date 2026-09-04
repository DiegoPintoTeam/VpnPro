#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta este script como root"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_INSTALLER="${REPO_DIR}/Install/install_web_panel.sh"

if [[ ! -f "${CANONICAL_INSTALLER}" ]]; then
  echo "[!] No se encontro el instalador canónico en: ${CANONICAL_INSTALLER}"
  exit 1
fi

echo "[*] install_service.sh es compatibilidad legacy."
echo "[*] Delegando al instalador canónico: Install/install_web_panel.sh"

# Reutiliza el instalador oficial para evitar divergencia de lógica.
bash "${CANONICAL_INSTALLER}"