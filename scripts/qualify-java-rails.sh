#!/usr/bin/env bash

set -euo pipefail

rail_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
rail_registry_root="$(cd -- "$rail_script_dir/.." && pwd -P)"
rail_backend_root="${MYSCOUTEE_BACKEND_ROOT:-$rail_registry_root/../myscoutee-backend}"
rail_scope="${REGISTRY_E2E_SCOPE:-qualification:java-go-rails}"
rail_tmp_root="${TMPDIR:-/tmp}"
rail_tmp_dir="$(mktemp -d "$rail_tmp_root/myscoutee-java-go-rails.XXXXXX")"

cleanup_rail_tmp() {
  if [[ -n "${rail_tmp_dir:-}" && -d "$rail_tmp_dir" ]]; then
    rm -rf -- "$rail_tmp_dir"
  fi
}
trap cleanup_rail_tmp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.25 or newer is required." >&2
  exit 1
fi
if [[ ! -x "$rail_backend_root/server/gradlew" ]]; then
  echo "MyScoutee backend Gradle wrapper not found at $rail_backend_root/server/gradlew" >&2
  echo "Set MYSCOUTEE_BACKEND_ROOT to the backend repository root." >&2
  exit 1
fi

rail_binary="$rail_tmp_dir/myscoutee-registry"
(
  cd -- "$rail_registry_root"
  go build -trimpath -o "$rail_binary" ./cmd/registry
)

(
  cd -- "$rail_backend_root/server"
  REGISTRY_E2E_BINARY="$rail_binary" \
  REGISTRY_E2E_SCOPE="$rail_scope" \
    ./gradlew --no-daemon --rerun-tasks \
      :projects:profile:test \
      --tests \
      'com.raxim.myscoutee.profile.service.operator.OperatorGoRegistryRailQualificationTest'
)
