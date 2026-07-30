#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

die() {
  printf 'package-debian: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
debian_source="$repository_root/tools/debian"

version="${1:-${MYSCOUTEE_VERSION:-1.0.0}}"
architecture="${DEB_ARCHITECTURE:-amd64}"
output_dir="${OUTPUT_DIR:-$repository_root/dist}"
input_bundle="${INPUT_BUNDLE:-}"
artifact_name="myscoutee-registry_${version}_${architecture}.deb"
artifact_path="$output_dir/$artifact_name"

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die "version must be a plain SemVer core such as 1.0.0"
dpkg --validate-version "$version" >/dev/null 2>&1 ||
  die "version is not valid for a Debian package"
[[ "$architecture" == "amd64" ]] ||
  die "the current package contract supports DEB_ARCHITECTURE=amd64 only"
[[ ! -e "$artifact_path" ]] ||
  die "refusing to overwrite existing artifact: $artifact_path"

for required_command in dpkg-deb jq sha256sum tar gzip find install sed; do
  command -v "$required_command" >/dev/null 2>&1 ||
    die "required command is unavailable: $required_command"
done

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/myscoutee-registry-deb.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

bundle_output="$work_dir/bundle-output"
bundle_extract="$work_dir/bundle-extract"
stage_root="$work_dir/deb-root"
mkdir -p "$bundle_output" "$bundle_extract" "$stage_root" "$output_dir"

if [[ -z "$input_bundle" ]]; then
  OUTPUT_DIR="$bundle_output" \
    "$repository_root/tools/package-offline-stack.sh" "$version" >/dev/null
  input_bundle="$bundle_output/myscoutee-registry-stack_${version}_linux_amd64.tar.gz"
else
  input_bundle="$(realpath -e -- "$input_bundle")" ||
    die "input bundle does not exist"
fi
[[ -f "$input_bundle" && ! -L "$input_bundle" ]] ||
  die "input bundle must be a regular non-symbolic-link file"

bundle_root_name="myscoutee-registry-stack_${version}_linux_amd64"
if tar -tzf "$input_bundle" |
  LC_ALL=C grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  die "input bundle contains an unsafe path"
fi
mapfile -t bundle_entries < <(
  tar -tzf "$input_bundle" |
    sed 's|/$||' |
    sed '/^$/d' |
    LC_ALL=C sort -u
)
expected_entries=(
  "$bundle_root_name"
  "$bundle_root_name/IMAGE-MANIFEST.json"
  "$bundle_root_name/README.md"
  "$bundle_root_name/SHA256SUMS"
  "$bundle_root_name/VERSION"
  "$bundle_root_name/compose.yaml"
  "$bundle_root_name/images"
  "$bundle_root_name/images/myscoutee-registry-edge.tar"
  "$bundle_root_name/images/myscoutee-registry.tar"
  "$bundle_root_name/nginx"
  "$bundle_root_name/nginx/registry.conf.template"
  "$bundle_root_name/registry.env.example"
)
[[ "${bundle_entries[*]}" == "${expected_entries[*]}" ]] ||
  die "input bundle file contract differs from the reviewed offline stack"

tar -xzf "$input_bundle" -C "$bundle_extract"
bundle_root="$bundle_extract/$bundle_root_name"
(
  cd "$bundle_root"
  sha256sum --check SHA256SUMS >/dev/null
) || die "input bundle checksum validation failed"
[[ "$(sed -n '1p' "$bundle_root/VERSION")" == "$version" ]] ||
  die "input bundle version does not match the requested package version"
jq -e \
  --arg version "$version" '
    .schema_version == 1
    and .stack_version == $version
    and .platform == "linux/amd64"
    and (.images | length == 2)
    and ([.images[].service] | sort == ["nginx", "registry"])
  ' "$bundle_root/IMAGE-MANIFEST.json" >/dev/null ||
  die "input bundle image manifest is invalid"

install -d \
  "$stage_root/DEBIAN" \
  "$stage_root/etc/myscoutee-registry" \
  "$stage_root/lib/systemd/system" \
  "$stage_root/opt/myscoutee-registry/images" \
  "$stage_root/usr/sbin" \
  "$stage_root/usr/share/doc/myscoutee-registry" \
  "$stage_root/usr/share/myscoutee-registry"

sed \
  -e "s/^Version:.*/Version: $version/" \
  -e "s/^Architecture:.*/Architecture: $architecture/" \
  "$debian_source/control" >"$stage_root/DEBIAN/control"
install -m 0755 "$debian_source/postinst" "$stage_root/DEBIAN/postinst"
install -m 0755 "$debian_source/prerm" "$stage_root/DEBIAN/prerm"
install -m 0755 "$debian_source/postrm" "$stage_root/DEBIAN/postrm"

install -m 0644 "$bundle_root/compose.yaml" \
  "$stage_root/opt/myscoutee-registry/compose.yaml"
install -m 0644 "$bundle_root/IMAGE-MANIFEST.json" \
  "$stage_root/opt/myscoutee-registry/IMAGE-MANIFEST.json"
install -m 0644 "$bundle_root/VERSION" \
  "$stage_root/opt/myscoutee-registry/VERSION"
install -m 0644 "$bundle_root/images/myscoutee-registry.tar" \
  "$stage_root/opt/myscoutee-registry/images/myscoutee-registry.tar"
install -m 0644 "$bundle_root/images/myscoutee-registry-edge.tar" \
  "$stage_root/opt/myscoutee-registry/images/myscoutee-registry-edge.tar"

install -m 0755 "$debian_source/myscoutee-registry-stack" \
  "$stage_root/usr/sbin/myscoutee-registry-stack"
install -m 0644 "$debian_source/myscoutee-registry.service" \
  "$stage_root/lib/systemd/system/myscoutee-registry.service"
install -m 0644 "$debian_source/README.md" \
  "$stage_root/usr/share/doc/myscoutee-registry/README.Debian"
sed \
  -e "s/^MYSCOUTEE_VERSION=.*/MYSCOUTEE_VERSION=$version/" \
  -e "s|^REGISTRY_PRODUCTION_IMAGE=.*|REGISTRY_PRODUCTION_IMAGE=myscoutee-registry:${version}-prod|" \
  -e "s|^REGISTRY_EDGE_IMAGE=.*|REGISTRY_EDGE_IMAGE=myscoutee-registry-edge:${version}-prod|" \
  "$debian_source/registry.env.example" \
  >"$stage_root/usr/share/myscoutee-registry/registry.env.example"

# The empty package-owned /etc directory documents the protected location.
# postinst creates the initial mode-0600 environment only when absent; neither
# it nor operator TLS files are package-owned conffiles that could be replaced.
chmod 0700 "$stage_root/etc/myscoutee-registry"

if find "$stage_root" -type f \
  ! -path "$stage_root/opt/myscoutee-registry/images/*" -print0 |
  LC_ALL=C xargs -0 -r grep -aEl -- \
    '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}' |
  grep -q .; then
  die "a Debian payload file contains a private credential marker"
fi
for image_archive in "$stage_root"/opt/myscoutee-registry/images/*.tar; do
  if LC_ALL=C grep -aEq -- \
    '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' "$image_archive"; then
    die "a bundled image contains a private-key marker"
  fi
done
if find "$stage_root" -type f \
  \( -name '*.pem' -o -name '*.key' -o -name '*.p8' -o -name '*.p12' \
    -o -name '*.jks' -o -name '*.db' -o -name '*.db-wal' \
    -o -name '*.db-shm' \) -print -quit |
  grep -q .; then
  die "a private-key or runtime-state filename entered the Debian payload"
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

find "$stage_root" -print0 |
  xargs -0 touch --no-dereference --date="@$source_date_epoch"

partial_artifact="$work_dir/$artifact_name.partial"
SOURCE_DATE_EPOCH="$source_date_epoch" \
  dpkg-deb --root-owner-group -Zxz -z9 --build \
    "$stage_root" "$partial_artifact" >/dev/null
dpkg-deb --info "$partial_artifact" >/dev/null ||
  die "built artifact failed Debian metadata validation"
dpkg-deb --contents "$partial_artifact" >/dev/null ||
  die "built artifact failed Debian payload validation"

mv "$partial_artifact" "$artifact_path"
chmod 0644 "$artifact_path"
artifact_sha256="$(sha256sum "$artifact_path" | awk '{print $1}')"

printf 'Created %s\n' "$artifact_path"
printf 'SHA256 %s\n' "$artifact_sha256"
