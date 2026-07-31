#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'docker-build-context-test: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/../.." && pwd -P)"
root_dockerfile="$repository_root/Dockerfile"
root_ignore="$repository_root/Dockerfile.dockerignore"
production_dockerfile="$repository_root/packaging/templates/registry.Dockerfile"
build_script="$repository_root/packaging/scripts/build-production.sh"

for copy_contract in \
  'COPY go.mod go.sum ./' \
  'COPY cmd/ ./cmd/' \
  'COPY internal/ ./internal/'; do
  grep -Fq "$copy_contract" "$root_dockerfile" ||
    fail "development Dockerfile lost restricted input: $copy_contract"
  grep -Fq "$copy_contract" "$production_dockerfile" ||
    fail "production Dockerfile lost restricted input: $copy_contract"
done
if grep -Eq '^COPY[[:space:]]+\.[[:space:]]+\.[[:space:]]*$' \
  "$root_dockerfile" "$production_dockerfile"; then
  fail "a Registry Dockerfile copies the entire repository"
fi
grep -Fxq '**' "$root_ignore" ||
  fail "development Docker context is not deny-by-default"
grep -Fq 'cp -a "$repository_root/cmd" "$registry_context/cmd"' \
  "$build_script" ||
  fail "production build does not create a restricted temporary context"
grep -Fq 'cp -a "$repository_root/internal" "$registry_context/internal"' \
  "$build_script" ||
  fail "production build does not create a restricted temporary context"
grep -Fq \
  'github.com/fssrepository/myscoutee-registry/internal/buildinfo.Version=${MYSCOUTEE_VERSION}' \
  "$production_dockerfile" ||
  fail "production build does not embed the release version"

printf 'Docker build context contract: PASS\n'
