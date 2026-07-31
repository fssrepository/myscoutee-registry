#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'image-content-fingerprint-test: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
helper="$script_dir/../scripts/image-content-fingerprint.sh"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/registry-fingerprint-test.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

cat >"$work_dir/a.json" <<'JSON'
{
  "architecture": "amd64",
  "os": "linux",
  "created": "2026-01-01T00:00:00Z",
  "config": {
    "User": "65532:65532",
    "Env": ["A=B"],
    "Entrypoint": ["/registry"],
    "Cmd": [],
    "WorkingDir": "/",
    "Labels": {"service": "registry"},
    "ExposedPorts": {"8080/tcp": {}},
    "Volumes": {"/data": {}}
  },
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    ]
  }
}
JSON
sed 's/2026-01-01T00:00:00Z/2030-12-31T23:59:59Z/' \
  "$work_dir/a.json" >"$work_dir/b.json"
sed 's/"A=B"/"A=C"/' "$work_dir/a.json" >"$work_dir/changed.json"

first="$("$helper" config "$work_dir/a.json")"
second="$("$helper" config "$work_dir/b.json")"
changed="$("$helper" config "$work_dir/changed.json")"
[[ "$first" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail "helper returned an invalid digest"
[[ "$first" == "$second" ]] ||
  fail "daemon-irrelevant creation metadata changed the digest"
[[ "$first" != "$changed" ]] ||
  fail "runtime configuration change did not change the digest"

printf 'Image content fingerprint contract: PASS\n'
