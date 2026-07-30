#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'offline-stack-contract-test: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
package_script="$repository_root/tools/package-offline-stack.sh"
source_compose="$repository_root/compose.production.yaml"
source_env="$repository_root/.env.production.example"
offline_compose="$repository_root/tools/docker/offline/compose.yaml"
offline_env="$repository_root/tools/docker/offline/registry.env.example"
build_context_contract="$repository_root/tools/docker-build-context-contract-test.sh"

bash -n "$package_script"
bash -n "$0"
bash "$build_context_contract"

[[ "$(grep -c 'pull_policy: never' "$offline_compose")" == "2" ]] ||
  fail "offline Compose must disable pulls for both services"
if grep -Eq '^[[:space:]]*build:' "$offline_compose"; then
  fail "offline Compose must not contain a build section"
fi
grep -q 'read_only: true' "$offline_compose" ||
  fail "offline Compose lost read-only filesystems"
grep -q 'no-new-privileges:true' "$offline_compose" ||
  fail "offline Compose lost no-new-privileges"
grep -q 'internal: true' "$offline_compose" ||
  fail "offline Compose lost its internal backend network"
grep -q 'myscoutee-registry-edge:1.0.0-prod' "$offline_compose" ||
  fail "offline Compose does not use the first-party edge image"
grep -q '/etc/nginx/templates/registry.conf.template' \
  "$repository_root/tools/docker/registry-edge.Dockerfile" ||
  fail "edge image does not embed the reviewed Nginx template"
grep -Fq \
  'COPY --chown=root:root --chmod=0444 tools/docker/registry.conf.template' \
  "$repository_root/tools/docker/registry-edge.Dockerfile" ||
  fail "edge image does not copy the canonical tools/docker template"
grep -Fq 'dockerfile: tools/docker/registry-edge.Dockerfile' "$source_compose" ||
  fail "source production Compose does not build the first-party edge"
grep -Fq \
  'image: ${REGISTRY_EDGE_IMAGE:-myscoutee-registry-edge:1.0.0-prod}' \
  "$source_compose" ||
  fail "source production Compose does not use the versioned edge image"
if grep -Eq 'source:.*registry\.conf\.template|target:.*registry\.conf\.template' \
  "$source_compose"; then
  fail "source production Compose must use the template embedded in the edge image"
fi
grep -Fq \
  'REGISTRY_EDGE_IMAGE=myscoutee-registry-edge:${MYSCOUTEE_VERSION}-prod' \
  "$source_env" ||
  fail "production environment example lost the edge image reference"

if command -v docker >/dev/null 2>&1 &&
  docker compose version >/dev/null 2>&1; then
  docker compose \
    --env-file "$source_env" \
    -f "$source_compose" \
    config --quiet
  docker compose \
    --env-file "$offline_env" \
    -f "$offline_compose" \
    config --quiet
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/offline-stack-test.XXXXXXXX")"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

fixture_dir="$test_root/fixtures"
mkdir -p "$fixture_dir/registry/rootfs" \
  "$fixture_dir/edge/rootfs" \
  "$fixture_dir/secret/rootfs"

printf 'registry-layer\n' >"$fixture_dir/registry/rootfs/layer.txt"
printf 'edge-layer\n' >"$fixture_dir/edge/rootfs/layer.txt"
printf '%s\n' \
  '-----BEGIN PRIVATE KEY-----' \
  'offline-stack-secret-canary' \
  '-----END PRIVATE KEY-----' \
  >"$fixture_dir/secret/rootfs/private-key.pem"

tar -C "$fixture_dir/registry/rootfs" \
  -cf "$fixture_dir/registry-image.tar" .
tar -C "$fixture_dir/edge/rootfs" \
  -cf "$fixture_dir/edge-image.tar" .
tar -C "$fixture_dir/secret/rootfs" \
  -cf "$fixture_dir/secret-image.tar" .

fake_docker="$test_root/docker"
cat >"$fake_docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

reference="${*: -1}"
component="registry"
if [[ "$reference" == *edge* ]]; then
  component="edge"
fi

if [[ "$1" == "image" && "$2" == "inspect" ]]; then
  case "$4" in
    '{{.Id}}')
      if [[ "$component" == "registry" ]]; then
        printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
      else
        printf 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
      fi
      ;;
    '{{.Os}}/{{.Architecture}}')
      printf 'linux/amd64\n'
      ;;
    '{{json .Config}}')
      printf '{"Env":[],"Labels":{}}\n'
      ;;
    *)
      printf 'unexpected inspect format: %s\n' "$4" >&2
      exit 64
      ;;
  esac
  exit 0
fi

if [[ "$1" == "image" && "$2" == "history" ]]; then
  printf 'safe deterministic fixture history\n'
  exit 0
fi

if [[ "$1" == "image" && "$2" == "save" && "$3" == "--output" ]]; then
  source_archive="$FAKE_FIXTURE_DIR/${component}-image.tar"
  if [[ "${FAKE_SECRET_REGISTRY_IMAGE:-false}" == "true" &&
    "$component" == "registry" ]]; then
    source_archive="$FAKE_FIXTURE_DIR/secret-image.tar"
  fi
  cp "$source_archive" "$4"
  exit 0
fi

printf 'unexpected fake Docker command: %s\n' "$*" >&2
exit 64
EOF
chmod 0700 "$fake_docker"

run_package() {
  local destination="$1"
  mkdir -p "$destination"
  env \
    DOCKER_BIN="$fake_docker" \
    FAKE_FIXTURE_DIR="$fixture_dir" \
    OUTPUT_DIR="$destination" \
    SOURCE_DATE_EPOCH=1700000000 \
    SOURCE_REVISION=0123456789abcdef0123456789abcdef01234567 \
    "$package_script" 1.0.0
}

run_package "$test_root/output-one"
run_package "$test_root/output-two"

artifact_name="myscoutee-registry-stack_1.0.0_linux_amd64.tar.gz"
artifact_one="$test_root/output-one/$artifact_name"
artifact_two="$test_root/output-two/$artifact_name"
[[ -f "$artifact_one" ]] || fail "packaging did not create the expected artifact"
cmp "$artifact_one" "$artifact_two" ||
  fail "identical image inputs did not produce a reproducible bundle"

extract_root="$test_root/extracted"
mkdir -p "$extract_root"
tar -xzf "$artifact_one" -C "$extract_root"
bundle_root="$extract_root/${artifact_name%.tar.gz}"

expected_files=(
  IMAGE-MANIFEST.json
  README.md
  SHA256SUMS
  VERSION
  compose.yaml
  images/myscoutee-registry-edge.tar
  images/myscoutee-registry.tar
  nginx/registry.conf.template
  registry.env.example
)
mapfile -t actual_files < <(
  find "$bundle_root" -type f -printf '%P\n' | LC_ALL=C sort
)
[[ "${actual_files[*]}" == "${expected_files[*]}" ]] ||
  fail "bundle file contract changed: ${actual_files[*]}"
cmp \
  "$repository_root/tools/docker/registry.conf.template" \
  "$bundle_root/nginx/registry.conf.template" ||
  fail "bundle Nginx audit copy differs from the edge image source template"

(
  cd "$bundle_root"
  sha256sum --check SHA256SUMS
)
grep -q '"stack_version": "1.0.0"' "$bundle_root/IMAGE-MANIFEST.json" ||
  fail "image manifest lost the stack version"
grep -q '"platform": "linux/amd64"' "$bundle_root/IMAGE-MANIFEST.json" ||
  fail "image manifest lost the target platform"
grep -q 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  "$bundle_root/IMAGE-MANIFEST.json" ||
  fail "image manifest lost the registry image ID"
grep -q 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  "$bundle_root/IMAGE-MANIFEST.json" ||
  fail "image manifest lost the edge image ID"

mkdir -p "$test_root/output-secret"
if env \
  DOCKER_BIN="$fake_docker" \
  FAKE_FIXTURE_DIR="$fixture_dir" \
  FAKE_SECRET_REGISTRY_IMAGE=true \
  OUTPUT_DIR="$test_root/output-secret" \
  SOURCE_DATE_EPOCH=1700000000 \
  SOURCE_REVISION=0123456789abcdef0123456789abcdef01234567 \
  "$package_script" 1.0.0 >"$test_root/secret.stdout" 2>"$test_root/secret.stderr"; then
  fail "packaging accepted an image containing a private-key marker"
fi
grep -q 'private credential marker' "$test_root/secret.stderr" ||
  fail "secret rejection did not report the expected reason"

printf 'offline stack contract: PASS\n'
