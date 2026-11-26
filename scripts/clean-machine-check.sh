#!/usr/bin/env bash
set -euo pipefail

export MSYS_NO_PATHCONV=1
export URGUARD_IN_CLEAN_CHECK=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t urguard-clean)"
CLONE_DIR="$TMP_DIR/urGuard"
RESULTS=()
OVERALL_FAIL=0

record_result() {
  local status="$1"
  local label="$2"
  RESULTS+=("$status | $label")
  if [ "$status" = "FAIL" ]; then
    OVERALL_FAIL=1
  fi
  echo "[$status] $label"
}

cleanup() {
  if [ -d "$CLONE_DIR" ] && [ -f "$CLONE_DIR/deployments/docker-compose.yml" ] && command -v docker >/dev/null 2>&1; then
    (cd "$CLONE_DIR" && make down >/dev/null 2>&1 || true)
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# 1. Clone repo into temporary clean directory
CLONE_SOURCE="$REPO_ROOT"
if command -v cygpath >/dev/null 2>&1; then
  CLONE_SOURCE="$(cygpath -m "$REPO_ROOT")"
fi

if git clone --no-hardlinks "$CLONE_SOURCE" "$CLONE_DIR" >/dev/null 2>&1; then
  record_result "PASS" "git clone into temp dir ($CLONE_DIR)"
else
  record_result "FAIL" "git clone into temp dir"
fi

cd "$CLONE_DIR"

# 2. Copy .env.example to .env
if cp .env.example .env; then
  record_result "PASS" "copy .env.example to .env"
else
  record_result "FAIL" "copy .env.example to .env"
fi

# Load non-secret defaults from .env
set -a
# shellcheck disable=SC1091
. ./.env
set +a

# 3. Zero AI/ML dependency check
if bash scripts/check-no-ai-deps.sh; then
  record_result "PASS" "scripts/check-no-ai-deps.sh"
else
  record_result "FAIL" "scripts/check-no-ai-deps.sh"
fi

# 4. Install frontend dependencies and run tests/build
if [ -f "frontend/package-lock.json" ]; then
  if npm --prefix frontend ci >/dev/null 2>&1; then
    record_result "PASS" "npm --prefix frontend ci"
  else
    record_result "FAIL" "npm --prefix frontend ci"
  fi
else
  if npm --prefix frontend install >/dev/null 2>&1; then
    record_result "PASS" "npm --prefix frontend install"
  else
    record_result "FAIL" "npm --prefix frontend install"
  fi
fi

if make test && make build; then
  record_result "PASS" "make test && make build"
else
  record_result "FAIL" "make test && make build"
fi

# 5. Run make verify (runs scripts/verify.sh when implemented)
if make verify; then
  record_result "PASS" "make verify"
else
  record_result "FAIL" "make verify"
fi

# 6. Validate and start Docker Compose stack (requires backend/go.mod from Engineer A)
if [ ! -f "backend/go.mod" ]; then
  record_result "FAIL" "make up (blocked: Engineer A backend/go.mod and cmd/{controlplane,node} not merged yet)"
else
  if make up; then
    record_result "PASS" "make up"

    probe_url() {
      local name="$1"
      local url="$2"
      local attempts=0
      while [ "$attempts" -lt 30 ]; do
        if curl -fsS "$url" >/dev/null 2>&1; then
          record_result "PASS" "health probe $name ($url)"
          return 0
        fi
        attempts=$((attempts + 1))
        sleep 2
      done
      record_result "FAIL" "health probe $name ($url)"
      return 1
    }

    probe_url "controlplane" "http://127.0.0.1:${URGUARD_CONTROLPLANE_PORT:-8080}/healthz" || true
    probe_url "node-a" "http://127.0.0.1:${URGUARD_NODE_A_PORT:-8081}/healthz" || true
    probe_url "node-b" "http://127.0.0.1:${URGUARD_NODE_B_PORT:-8082}/healthz" || true
    probe_url "node-c" "http://127.0.0.1:${URGUARD_NODE_C_PORT:-8083}/healthz" || true
    probe_url "frontend" "http://127.0.0.1:${URGUARD_FRONTEND_PORT:-5173}/healthz" || true
  else
    record_result "FAIL" "make up"
  fi

  if make down; then
    record_result "PASS" "make down"
  else
    record_result "FAIL" "make down"
  fi
fi

echo ""
echo "=== Clean-Machine Verification Summary ==="
for line in "${RESULTS[@]}"; do
  echo "  $line"
done

exit "$OVERALL_FAIL"
