#!/usr/bin/env bash
# ==============================================================================
# Nordic Shadow Hunter - Environment Setup Script for Ubuntu 24.04 LTS
# Idempotent script to bootstrap the Python virtual environment and dependencies.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "[+] Starting Nordic Shadow Hunter environment setup on Ubuntu 24.04..."

# 1. Ensure required system packages are present
echo "[+] Checking system packages..."
PACKAGES_TO_INSTALL=()

for pkg in python3 python3-venv python3-pip git fonts-dejavu-core; do
    if ! dpkg -s "${pkg}" &>/dev/null; then
        PACKAGES_TO_INSTALL+=("${pkg}")
    fi
done

if [ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]; then
    echo "[+] Installing missing system packages: ${PACKAGES_TO_INSTALL[*]}"
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo &>/dev/null; then
            sudo apt-get update -y
            sudo apt-get install -y "${PACKAGES_TO_INSTALL[@]}"
        else
            echo "[-] Error: Root privileges required to install packages: ${PACKAGES_TO_INSTALL[*]}" >&2
            exit 1
        fi
    else
        apt-get update -y
        apt-get install -y "${PACKAGES_TO_INSTALL[@]}"
    fi
else
    echo "[+] Required system packages are already installed."
fi

# 2. Ensure project directory structure exists
echo "[+] Verifying project directory structure..."
mkdir -p data kql docs/screenshots reports tests .streamlit

for dir in data kql docs/screenshots reports tests; do
    if [ ! -f "${dir}/.gitkeep" ]; then
        touch "${dir}/.gitkeep"
    fi
done

# 3. Create Python virtual environment if it does not exist
if [ ! -d ".venv" ]; then
    echo "[+] Creating Python virtual environment in .venv..."
    python3 -m venv .venv
else
    echo "[+] Virtual environment .venv already exists."
fi

# 4. Upgrade pip and install requirements
echo "[+] Upgrading pip inside .venv..."
.venv/bin/python3 -m pip install -U pip

if [ -f "requirements.txt" ]; then
    echo "[+] Installing project dependencies from requirements.txt..."
    .venv/bin/pip install -r requirements.txt
else
    echo "[-] Warning: requirements.txt not found!" >&2
fi

# 5. Check if dataset exists in data/
XLSX_FILES=(data/*.xlsx)
if [ -e "${XLSX_FILES[0]}" ]; then
    echo "[+] Official dataset found in data/."
else
    echo "[!] Warning: No .xlsx dataset found in data/."
    echo "    Please copy SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx into the data/ directory."
fi

echo "[+] Setup complete! To launch the dashboard, run:"
echo "    source .venv/bin/activate && streamlit run app.py"
