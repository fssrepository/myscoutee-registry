#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'docker-build-context-contract-test: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
root_dockerfile="$repository_root/Dockerfile"
root_ignore="$repository_root/Dockerfile.dockerignore"
edge_dockerfile="$repository_root/tools/docker/registry-edge.Dockerfile"
edge_template="tools/docker/registry.conf.template"

bash -n "$0"

grep -Eq '^COPY[[:space:]]+go\.mod[[:space:]]+go\.sum[[:space:]]+\./$' \
  "$root_dockerfile" ||
  fail "root Dockerfile must copy go.mod and go.sum explicitly"
grep -Eq '^COPY[[:space:]]+cmd/[[:space:]]+\./cmd/$' "$root_dockerfile" ||
  fail "root Dockerfile must copy cmd/ explicitly"
grep -Eq '^COPY[[:space:]]+internal/[[:space:]]+\./internal/$' \
  "$root_dockerfile" ||
  fail "root Dockerfile must copy internal/ explicitly"
if grep -Eq '^COPY[[:space:]]+\.[[:space:]]+\.[[:space:]]*$' \
  "$root_dockerfile"; then
  fail "root Dockerfile must not copy the whole repository"
fi
if grep -Eq 'deploy/|registry\.conf\.template' "$root_dockerfile"; then
  fail "root Dockerfile must not consume edge deployment configuration"
fi

expected_rules=(
  '**'
  '!go.mod'
  '!go.sum'
  '!cmd/'
  '!cmd/**'
  '!internal/'
  '!internal/**'
  '**/*_test.go'
  '**/.env*'
  '**/*.db'
  '**/*.db-shm'
  '**/*.db-wal'
  '**/*.pem'
  '**/*.key'
  '**/*.p8'
  '**/*private*key*'
  '**/secrets'
  '**/secrets/**'
)
mapfile -t actual_rules < <(
  sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$root_ignore"
)
[[ "${actual_rules[*]}" == "${expected_rules[*]}" ]] ||
  fail "root Dockerfile ignore allowlist changed: ${actual_rules[*]}"

grep -Fq "COPY --chown=root:root --chmod=0444 $edge_template" \
  "$edge_dockerfile" ||
  fail "standalone edge Dockerfile must copy its own reviewed template"
[[ -f "$repository_root/$edge_template" ]] ||
  fail "standalone edge template is missing"

printf 'Docker build-context contract: PASS\n'
