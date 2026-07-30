#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

die() {
  printf 'package-production: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/../.." && pwd -P)"
packaging_root="$repository_root/packaging"
version="${1:-${MYSCOUTEE_VERSION:-$(sed -n '1p' "$packaging_root/VERSION")}}"
architecture="${DEB_ARCHITECTURE:-amd64}"
dist_dir="${MYSCOUTEE_REGISTRY_DIST_DIR:-${MYSCOUTEE_DIST_DIR:-$packaging_root/dist}}"
docker_bin="${DOCKER_BIN:-docker}"
registry_image="${REGISTRY_PRODUCTION_IMAGE:-myscoutee-registry:${version}-prod}"
nginx_image="${REGISTRY_NGINX_PRODUCTION_IMAGE:-myscoutee-registry-nginx:${version}-prod}"
artifact_name="myscoutee-registry_${version}_${architecture}.deb"
artifact_path="$dist_dir/$artifact_name"
fingerprint_helper="$script_dir/image-content-fingerprint.sh"

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die "version must be a plain SemVer core"
dpkg --validate-version "$version" >/dev/null 2>&1 ||
  die "version is invalid for dpkg"
[[ "$architecture" == "amd64" ]] ||
  die "the production package supports DEB_ARCHITECTURE=amd64"
[[ "$registry_image" == "myscoutee-registry:${version}-prod" ]] ||
  die "REGISTRY_PRODUCTION_IMAGE must use the canonical version-derived tag"
[[ "$nginx_image" == "myscoutee-registry-nginx:${version}-prod" ]] ||
  die "REGISTRY_NGINX_PRODUCTION_IMAGE must use the canonical version-derived tag"

for required_command in \
  "$docker_bin" dpkg dpkg-deb find grep gzip install jq sed sha256sum \
  tar touch xargs; do
  command -v "$required_command" >/dev/null 2>&1 ||
    die "required command is unavailable: $required_command"
done

build_images="${BUILD_IMAGES:-${BUILD_ARTIFACTS:-true}}"
package_images="${PACKAGE_IMAGES:-true}"
if [[ "$build_images" == "true" ]]; then
  DOCKER_BIN="$docker_bin" \
  REGISTRY_PRODUCTION_IMAGE="$registry_image" \
  REGISTRY_NGINX_PRODUCTION_IMAGE="$nginx_image" \
    "$script_dir/build-production.sh" "$version"
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/myscoutee-registry-package.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
stage_root="$work_dir/deb-root"
client_stage="$work_dir/client-tools"
packaged_client_dir="$stage_root/usr/share/myscoutee-registry"
install -d \
  "$stage_root/DEBIAN" \
  "$stage_root/etc/myscoutee-registry" \
  "$stage_root/lib/systemd/system" \
  "$stage_root/opt/myscoutee-registry/images" \
  "$stage_root/opt/myscoutee-registry/packaging/scripts" \
  "$stage_root/opt/myscoutee-registry/packaging/templates" \
  "$stage_root/usr/share/doc/myscoutee-registry" \
  "$packaged_client_dir" \
  "$client_stage/verify-deployment"

sed \
  -e "s/^Version:.*/Version: $version/" \
  -e "s/^Architecture:.*/Architecture: $architecture/" \
  "$packaging_root/debian/control" >"$stage_root/DEBIAN/control"
install -m 0755 "$packaging_root/debian/postinst" "$stage_root/DEBIAN/postinst"
install -m 0755 "$packaging_root/debian/prerm" "$stage_root/DEBIAN/prerm"
install -m 0755 "$packaging_root/debian/postrm" "$stage_root/DEBIAN/postrm"
install -m 0644 "$packaging_root/systemd/myscoutee-registry.service" \
  "$stage_root/lib/systemd/system/myscoutee-registry.service"
install -m 0644 "$packaging_root/compose/compose.yaml" \
  "$stage_root/opt/myscoutee-registry/compose.yaml"
install -m 0644 "$packaging_root/README.md" \
  "$stage_root/usr/share/doc/myscoutee-registry/README.Debian"
printf '%s\n' "$version" \
  >"$stage_root/opt/myscoutee-registry/packaging/VERSION"
chmod 0644 "$stage_root/opt/myscoutee-registry/packaging/VERSION"

for host_script in \
  image-content-fingerprint.sh \
  qualify-deployment.sh \
  registry-compose.sh; do
  install -m 0755 "$packaging_root/scripts/$host_script" \
    "$stage_root/opt/myscoutee-registry/packaging/scripts/$host_script"
done
sed \
  -e "s/^MYSCOUTEE_REGISTRY_VERSION=.*/MYSCOUTEE_REGISTRY_VERSION=$version/" \
  -e "s|^REGISTRY_PRODUCTION_IMAGE=.*|REGISTRY_PRODUCTION_IMAGE=$registry_image|" \
  -e "s|^REGISTRY_NGINX_PRODUCTION_IMAGE=.*|REGISTRY_NGINX_PRODUCTION_IMAGE=$nginx_image|" \
  "$packaging_root/templates/registry.env" \
  >"$stage_root/opt/myscoutee-registry/packaging/templates/registry.env"
chmod 0600 \
  "$stage_root/opt/myscoutee-registry/packaging/templates/registry.env"

for client_file in \
  README.md \
  deployment.env.example \
  install.env.example \
  install.sh \
  purge.sh \
  forward-localhost.sh \
  remote-transport.sh \
  verify-release.sh; do
  [[ -f "$packaging_root/client-tools/$client_file" ]] ||
    die "client tool is missing: $client_file"
  mode=0644
  [[ -x "$packaging_root/client-tools/$client_file" ]] && mode=0755
  if [[ "$client_file" == "deployment.env.example" ]]; then
    sed \
      -e "s/^MYSCOUTEE_REGISTRY_VERSION=.*/MYSCOUTEE_REGISTRY_VERSION=$version/" \
      -e "s|^REGISTRY_PRODUCTION_IMAGE=.*|REGISTRY_PRODUCTION_IMAGE=$registry_image|" \
      -e "s|^REGISTRY_NGINX_PRODUCTION_IMAGE=.*|REGISTRY_NGINX_PRODUCTION_IMAGE=$nginx_image|" \
      "$packaging_root/client-tools/$client_file" \
      >"$client_stage/$client_file"
    chmod "$mode" \
      "$client_stage/$client_file"
  else
    install -m "$mode" "$packaging_root/client-tools/$client_file" \
      "$client_stage/$client_file"
  fi
done
for verifier_file in \
  README.md \
  run.mjs \
  checks.mjs \
  lib/assertions.mjs \
  lib/http.mjs; do
  [[ -f "$packaging_root/verify-deployment/$verifier_file" ]] ||
    die "deployment verifier file is missing: $verifier_file"
  install -d \
    "$(dirname "$client_stage/verify-deployment/$verifier_file")"
  mode=0644
  [[ -x "$packaging_root/verify-deployment/$verifier_file" ]] && mode=0755
  install -m "$mode" "$packaging_root/verify-deployment/$verifier_file" \
    "$client_stage/verify-deployment/$verifier_file"
done
printf '%s\n' "$version" \
  >"$client_stage/VERSION"
chmod 0644 "$client_stage/VERSION"

private_key_pattern='-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'
credential_pattern="$private_key_pattern|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}"

inspect_image() {
  local reference="$1"
  local label="$2"
  local image_id platform

  image_id="$("$docker_bin" image inspect --format '{{.Id}}' "$reference")" ||
    die "$label production image is unavailable: $reference"
  platform="$(
    "$docker_bin" image inspect --format '{{.Os}}/{{.Architecture}}' "$reference"
  )" || die "cannot inspect $label image platform"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "$label image ID is invalid"
  [[ "$platform" == "linux/amd64" ]] ||
    die "$label image is $platform, expected linux/amd64"
  if "$docker_bin" image inspect --format '{{json .Config}}' "$reference" |
    grep -aEq -- "$credential_pattern"; then
    die "$label image configuration contains a credential marker"
  fi
  if "$docker_bin" image history --no-trunc --format '{{.CreatedBy}}' \
    "$reference" | grep -aEq -- "$credential_pattern"; then
    die "$label image history contains a credential marker"
  fi
  printf '%s' "$image_id"
}

save_image() {
  local reference="$1"
  local destination="$2"

  "$docker_bin" image save --output "$destination" "$reference"
  tar -tf "$destination" >/dev/null ||
    die "Docker produced an invalid image archive"
  if grep -aEq -- "$private_key_pattern" "$destination"; then
    die "image archive contains a private-key marker"
  fi
}

if [[ "$package_images" == "true" ]]; then
  registry_id="$(inspect_image "$registry_image" registry)"
  nginx_id="$(inspect_image "$nginx_image" nginx)"
  registry_archive="images/myscoutee-registry-${version}-prod.tar"
  nginx_archive="images/myscoutee-registry-nginx-${version}-prod.tar"
  save_image "$registry_image" \
    "$stage_root/opt/myscoutee-registry/$registry_archive"
  save_image "$nginx_image" \
    "$stage_root/opt/myscoutee-registry/$nginx_archive"

  registry_fingerprint="$(
    DOCKER_BIN="$docker_bin" "$fingerprint_helper" docker "$registry_image"
  )"
  nginx_fingerprint="$(
    DOCKER_BIN="$docker_bin" "$fingerprint_helper" docker "$nginx_image"
  )"
  registry_archive_sha="sha256:$(
    sha256sum "$stage_root/opt/myscoutee-registry/$registry_archive" |
      awk '{print $1}'
  )"
  nginx_archive_sha="sha256:$(
    sha256sum "$stage_root/opt/myscoutee-registry/$nginx_archive" |
      awk '{print $1}'
  )"

  jq -n \
    --arg version "$version" \
    --arg registryReference "$registry_image" \
    --arg registryId "$registry_id" \
    --arg registryFingerprint "$registry_fingerprint" \
    --arg registryArchive "$registry_archive" \
    --arg registryArchiveSha "$registry_archive_sha" \
    --arg nginxReference "$nginx_image" \
    --arg nginxId "$nginx_id" \
    --arg nginxFingerprint "$nginx_fingerprint" \
    --arg nginxArchive "$nginx_archive" \
    --arg nginxArchiveSha "$nginx_archive_sha" \
    '{
      schemaVersion: 1,
      releaseVersion: $version,
      bundled: true,
      images: [
        {
          service: "registry",
          container: "registry",
          reference: $registryReference,
          imageId: $registryId,
          contentFingerprint: $registryFingerprint,
          archive: $registryArchive,
          archiveSha256: $registryArchiveSha
        },
        {
          service: "nginx",
          container: "nginx",
          reference: $nginxReference,
          imageId: $nginxId,
          contentFingerprint: $nginxFingerprint,
          archive: $nginxArchive,
          archiveSha256: $nginxArchiveSha
        }
      ]
    }' >"$stage_root/opt/myscoutee-registry/packaging/IMAGE-MANIFEST.json"
elif [[ "${ALLOW_UNBUNDLED_IMAGES_FOR_TESTS:-false}" == "true" ]]; then
  jq -n --arg version "$version" '
    {
      schemaVersion: 1,
      releaseVersion: $version,
      bundled: false,
      images: []
    }
  ' >"$stage_root/opt/myscoutee-registry/packaging/IMAGE-MANIFEST.json"
else
  die "release packages must bundle both production images"
fi
chmod 0644 \
  "$stage_root/opt/myscoutee-registry/packaging/IMAGE-MANIFEST.json"

if find "$stage_root" -type f \
  ! -path "$stage_root/opt/myscoutee-registry/images/*" -print0 |
  xargs -0 -r grep -aEl -- "$credential_pattern" |
  grep -q .; then
  die "package payload contains a private credential marker"
fi
if find "$stage_root" -type f \
  \( -name '*.pem' -o -name '*.key' -o -name '*.p8' -o -name '*.p12' \
    -o -name '*.jks' -o -name '*.db' -o -name '*.db-wal' \
    -o -name '*.db-shm' -o -name '*.sqlite' \) \
  -print -quit | grep -q .; then
  die "private-key or runtime-state file entered the package"
fi
if find "$client_stage" -type f -print0 |
  xargs -0 -r grep -aEl -- "$credential_pattern" |
  grep -q .; then
  die "client-tools archive input contains a private credential marker"
fi
if find "$client_stage" -type f \
  \( -name '*.pem' -o -name '*.key' -o -name '*.p8' -o -name '*.p12' \
    -o -name '*.jks' -o -name '*.db' -o -name '*.db-wal' \
    -o -name '*.db-shm' -o -name '*.sqlite' \) \
  -print -quit | grep -q .; then
  die "private-key or runtime-state file entered the client-tools archive"
fi

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "$source_date_epoch" ]] &&
  command -v git >/dev/null 2>&1 &&
  git -C "$repository_root" show -s --format=%ct HEAD >/dev/null 2>&1; then
  source_date_epoch="$(git -C "$repository_root" show -s --format=%ct HEAD)"
fi
source_date_epoch="${source_date_epoch:-0}"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] ||
  die "SOURCE_DATE_EPOCH must be a non-negative integer"

client_archive_name="myscoutee-registry-client-tools_${version}.tar.gz"
client_partial="$work_dir/$client_archive_name"
tar --sort=name \
  --mtime="@$source_date_epoch" \
  --owner=0 --group=0 --numeric-owner \
  -C "$client_stage" \
  -cf - . | gzip -n -9 >"$client_partial"
install -m 0644 "$client_partial" \
  "$packaged_client_dir/$client_archive_name"

find "$stage_root" -print0 |
  xargs -0 touch --no-dereference --date="@$source_date_epoch"

install -d "$dist_dir"
partial_artifact="$work_dir/$artifact_name.partial"
SOURCE_DATE_EPOCH="$source_date_epoch" \
  dpkg-deb --root-owner-group -Zxz -z9 \
    --build "$stage_root" "$partial_artifact" >/dev/null
dpkg-deb --info "$partial_artifact" >/dev/null
dpkg-deb --contents "$partial_artifact" >/dev/null
mv -f "$partial_artifact" "$artifact_path"
chmod 0644 "$artifact_path"

client_archive="$dist_dir/$client_archive_name"
install -m 0644 "$client_partial" "$client_archive"

printf 'Created %s\n' "$artifact_path"
printf 'SHA256 %s\n' "$(sha256sum "$artifact_path" | awk '{print $1}')"
