#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

die() {
  printf 'build-production: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/../.." && pwd -P)"
version="${1:-${MYSCOUTEE_VERSION:-$(sed -n '1p' "$repository_root/packaging/VERSION")}}"
registry_image="${REGISTRY_PRODUCTION_IMAGE:-myscoutee-registry:${version}-prod}"
nginx_image="${REGISTRY_NGINX_PRODUCTION_IMAGE:-myscoutee-registry-nginx:${version}-prod}"
docker_bin="${DOCKER_BIN:-docker}"

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die "version must be a plain SemVer core"
[[ "$registry_image" == "myscoutee-registry:${version}-prod" ]] ||
  die "REGISTRY_PRODUCTION_IMAGE must use the canonical version-derived tag"
[[ "$nginx_image" == "myscoutee-registry-nginx:${version}-prod" ]] ||
  die "REGISTRY_NGINX_PRODUCTION_IMAGE must use the canonical version-derived tag"
command -v "$docker_bin" >/dev/null 2>&1 ||
  die "Docker is unavailable: $docker_bin"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/myscoutee-registry-build.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

registry_context="$work_dir/registry"
nginx_context="$work_dir/nginx"
install -d "$registry_context" "$nginx_context"
install -m 0644 "$repository_root/go.mod" "$registry_context/go.mod"
install -m 0644 "$repository_root/go.sum" "$registry_context/go.sum"
cp -a "$repository_root/cmd" "$registry_context/cmd"
cp -a "$repository_root/internal" "$registry_context/internal"
install -m 0644 "$repository_root/packaging/templates/registry.Dockerfile" \
  "$registry_context/Dockerfile"
install -m 0644 "$repository_root/packaging/templates/nginx.Dockerfile" \
  "$nginx_context/Dockerfile"
install -m 0644 "$repository_root/packaging/templates/nginx.conf.template" \
  "$nginx_context/nginx.conf.template"

"$docker_bin" build \
  --platform linux/amd64 \
  --build-arg "MYSCOUTEE_VERSION=$version" \
  --tag "$registry_image" \
  "$registry_context"
"$docker_bin" build \
  --platform linux/amd64 \
  --build-arg "MYSCOUTEE_VERSION=$version" \
  --tag "$nginx_image" \
  "$nginx_context"

printf 'Built %s and %s\n' "$registry_image" "$nginx_image"
