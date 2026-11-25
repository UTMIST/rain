#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Rain: Slurm Provisioning & Compute Access Web Portal Deployment Script
# ==============================================================================
# Usage:
#   sudo ./deploy/deploy.sh              # Local deployment on Slurm host
#   ./deploy/deploy.sh <user@host>       # Remote deployment via SSH
#
# Environment variables recognized:
#   PYTHON_BIN       System python binary (default: /usr/bin/python3)
#   INSTALL_DIR      Target directory (default: /usr/local/lib/misty-slurm-sync)
#   CONFIG_DIR       Config directory (default: /etc/misty-slurm-sync)
#   KEYS_DIR         SSH keys directory (default: /var/lib/rain/keys)
#   NO_RESTART       If set to 1, skip restarting systemd services
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/lib/misty-slurm-sync}"
CONFIG_DIR="${CONFIG_DIR:-/etc/misty-slurm-sync}"
KEYS_DIR="${KEYS_DIR:-/var/lib/rain/keys}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
NO_RESTART="${NO_RESTART:-0}"

# ------------------------------------------------------------------------------
# Remote deployment mode
# ------------------------------------------------------------------------------
if [[ $# -gt 0 && "$1" != "--"* ]]; then
  REMOTE_TARGET="$1"
  shift

  echo "==> Deploying Rain to remote host: ${REMOTE_TARGET}"
  echo "--> Ensuring package is built..."
  (cd "${REPO_ROOT}" && uv build)

  WHEEL_FILE="$(find "${REPO_ROOT}/dist" -name "rain-*.whl" | sort -V | tail -n 1)"
  if [[ -z "${WHEEL_FILE}" || ! -f "${WHEEL_FILE}" ]]; then
    echo "ERROR: Could not locate built wheel in ${REPO_ROOT}/dist" >&2
    exit 1
  fi

  echo "--> Uploading release files to ${REMOTE_TARGET}:/tmp/rain-deploy..."
  ssh "${REMOTE_TARGET}" "mkdir -p /tmp/rain-deploy"
  scp "${WHEEL_FILE}" \
      "${SCRIPT_DIR}/rain.service" \
      "${SCRIPT_DIR}/rain-web.service" \
      "${SCRIPT_DIR}/sync.env.example" \
      "${SCRIPT_DIR}/deploy.sh" \
      "${REMOTE_TARGET}:/tmp/rain-deploy/"

  echo "--> Executing remote installer with sudo..."
  ssh -t "${REMOTE_TARGET}" "cd /tmp/rain-deploy && sudo ./deploy.sh $* && rm -rf /tmp/rain-deploy"
  echo "==> Remote deployment to ${REMOTE_TARGET} finished successfully!"
  exit 0
fi

# ------------------------------------------------------------------------------
# Local deployment mode
# ------------------------------------------------------------------------------
if [[ $(id -u) -ne 0 ]]; then
  echo "==> Elevation required: re-running with sudo..."
  exec sudo "$0" "$@"
fi

echo "======================================================================"
echo " Starting Rain Deployment on $(hostname)"
echo "======================================================================"

# 1. Locate wheel
WHEEL_PATH=""
SEARCH_DIRS=("${REPO_ROOT}/dist" "${SCRIPT_DIR}" "${PWD}" "/tmp/rain-deploy")
for dir in "${SEARCH_DIRS[@]}"; do
  if [[ -d "$dir" ]]; then
    CANDIDATE="$(find "$dir" -maxdepth 1 -name "rain-*.whl" 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "$CANDIDATE" && -f "$CANDIDATE" ]]; then
      WHEEL_PATH="$CANDIDATE"
      break
    fi
  fi
done

if [[ -z "${WHEEL_PATH}" ]]; then
  if command -v uv >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/pyproject.toml" ]]; then
    echo "--> Building fresh wheel with uv..."
    (cd "${REPO_ROOT}" && uv build)
    WHEEL_PATH="$(find "${REPO_ROOT}/dist" -name "rain-*.whl" | sort -V | tail -n 1)"
  fi
fi

if [[ -z "${WHEEL_PATH}" || ! -f "${WHEEL_PATH}" ]]; then
  echo "ERROR: Could not find rain-*.whl to install." >&2
  exit 1
fi

echo "--> Using package: ${WHEEL_PATH}"

# 2. Setup install directory and virtual environment
echo "--> Setting up virtualenv in ${INSTALL_DIR}..."
install -d -m 0755 "${INSTALL_DIR}"
VENV_DIR="${INSTALL_DIR}/venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --no-project --python "${PYTHON_BIN}" "${VENV_DIR}"
  else
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  fi
fi

# 3. Install wheel
echo "--> Installing Rain package into virtual environment..."
if command -v uv >/dev/null 2>&1; then
  uv --offline pip install --reinstall-package rain --python "${VENV_PYTHON}" "${WHEEL_PATH}" || \
    uv pip install --reinstall-package rain --python "${VENV_PYTHON}" "${WHEEL_PATH}"
else
  if ! "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
    echo "--> Bootstrapping pip in ${VENV_DIR}..."
    if ! "${VENV_PYTHON}" -m ensurepip --upgrade; then
      echo "ERROR: Could not bootstrap pip. Install venv support for ${PYTHON_BIN} (python3-venv on Debian/Ubuntu), or make uv available to sudo, then rerun." >&2
      exit 1
    fi
  fi
  "${VENV_PYTHON}" -m pip install "${WHEEL_PATH}"
  "${VENV_PYTHON}" -m pip install --force-reinstall --no-deps "${WHEEL_PATH}"
fi

# 4. Setup directories
echo "--> Ensuring directories exist..."
install -d -m 0700 "${CONFIG_DIR}"
install -d -m 0755 "${KEYS_DIR}"

# 5. Seed sync.env if absent
if [[ ! -f "${CONFIG_DIR}/sync.env" ]]; then
  ENV_SOURCE=""
  for candidate in "${SCRIPT_DIR}/sync.env.example" "${REPO_ROOT}/deploy/sync.env.example" "/tmp/rain-deploy/sync.env.example"; do
    if [[ -f "$candidate" ]]; then
      ENV_SOURCE="$candidate"
      break
    fi
  done
  if [[ -n "$ENV_SOURCE" ]]; then
    echo "--> Seeding default ${CONFIG_DIR}/sync.env (mode 0600)..."
    install -m 0600 "$ENV_SOURCE" "${CONFIG_DIR}/sync.env"
  fi
fi

# 6. Install systemd services
echo "--> Installing systemd services..."
RAIN_SERVICE_SRC=""
WEB_SERVICE_SRC=""

for candidate in "${SCRIPT_DIR}/rain.service" "${REPO_ROOT}/deploy/rain.service" "/tmp/rain-deploy/rain.service"; do
  if [[ -f "$candidate" ]]; then
    RAIN_SERVICE_SRC="$candidate"
    break
  fi
done

for candidate in "${SCRIPT_DIR}/rain-web.service" "${REPO_ROOT}/deploy/rain-web.service" "/tmp/rain-deploy/rain-web.service"; do
  if [[ -f "$candidate" ]]; then
    WEB_SERVICE_SRC="$candidate"
    break
  fi
done

if [[ -n "$RAIN_SERVICE_SRC" && -f "$RAIN_SERVICE_SRC" ]]; then
  install -m 0644 "$RAIN_SERVICE_SRC" /etc/systemd/system/rain.service
fi

if [[ -n "$WEB_SERVICE_SRC" && -f "$WEB_SERVICE_SRC" ]]; then
  install -m 0644 "$WEB_SERVICE_SRC" /etc/systemd/system/rain-web.service
fi

# 7. Reload and restart systemd
if [[ "$NO_RESTART" -ne 1 ]] && command -v systemctl >/dev/null 2>&1; then
  echo "--> Reloading systemd daemon..."
  systemctl daemon-reload

  echo "--> Enabling and restarting services..."
  for service in rain.service rain-web.service; do
    if [[ $(systemctl show --property=LoadState --value "${service}") == loaded ]]; then
      systemctl enable "${service}"
      systemctl restart "${service}"
    fi
  done
fi

echo "======================================================================"
echo " Rain Deployment Complete!"
echo " Binaries:"
echo "   ${INSTALL_DIR}/venv/bin/rain"
echo "   ${INSTALL_DIR}/venv/bin/rain-web"
echo " Config:"
echo "   ${CONFIG_DIR}/sync.env"
echo " SSH Keys Store:"
echo "   ${KEYS_DIR}"
echo " Services:"
echo "   rain.service (sync daemon)"
echo "   rain-web.service (access portal)"
echo "======================================================================"
