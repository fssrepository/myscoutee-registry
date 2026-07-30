#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

die() {
  printf 'package-offline-stack: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"

version="${1:-${MYSCOUTEE_VERSION:-1.0.0}}"
platform="${TARGET_PLATFORM:-linux/amd64}"
docker_bin="${DOCKER_BIN:-docker}"
output_dir="${OUTPUT_DIR:-$repository_root/dist}"
registry_image="${REGISTRY_IMAGE:-myscoutee-registry:${version}-prod}"
edge_image="${REGISTRY_EDGE_IMAGE:-myscoutee-registry-edge:${version}-prod}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die "version must be a filesystem-safe semantic version"
[[ "$platform" == "linux/amd64" ]] ||
  die "the current offline release contract supports TARGET_PLATFORM=linux/amd64 only"
[[ "$registry_image" =~ ^[0-9A-Za-z][0-9A-Za-z._/:@-]+$ ]] ||
  die "REGISTRY_IMAGE contains unsupported characters"
[[ "$edge_image" =~ ^[0-9A-Za-z][0-9A-Za-z._/:@-]+$ ]] ||
  die "REGISTRY_EDGE_IMAGE contains unsupported characters"
command -v "$docker_bin" >/dev/null 2>&1 ||
  die "Docker command is unavailable: $docker_bin"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

source_revision="${SOURCE_REVISION:-}"
if [[ -z "$source_revision" ]] &&
  command -v git >/dev/null 2>&1 &&
  git -C "$repository_root" rev-parse --verify HEAD >/dev/null 2>&1; then
  source_revision="$(git -C "$repository_root" rev-parse HEAD)"
fi
source_revision="${source_revision:-unknown}"
[[ "$source_revision" == "unknown" ||
  "$source_revision" =~ ^[0-9a-f]{7,64}$ ]] ||
  die "SOURCE_REVISION must be a lowercase hexadecimal revision or unknown"

source_date_epoch="${SOURCE_DATE_EPOCH:-}"
if [[ -z "$source_date_epoch" ]] &&
  command -v git >/dev/null 2>&1 &&
  git -C "$repository_root" show -s --format=%ct HEAD >/dev/null 2>&1; then
  source_date_epoch="$(git -C "$repository_root" show -s --format=%ct HEAD)"
fi
source_date_epoch="${source_date_epoch:-0}"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] ||
  die "SOURCE_DATE_EPOCH must be a non-negative integer"

bundle_name="myscoutee-registry-stack_${version}_linux_amd64"
artifact_path="$output_dir/${bundle_name}.tar.gz"
[[ ! -e "$artifact_path" ]] ||
  die "refusing to overwrite existing artifact: $artifact_path"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/myscoutee-registry-stack.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

stage_dir="$work_dir/$bundle_name"
mkdir -p "$stage_dir/images" "$stage_dir/nginx" "$output_dir"

private_key_pattern='-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'
credential_pattern="$private_key_pattern|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}"

inspect_image() {
  local reference="$1"
  local component="$2"
  local image_id
  local image_platform

  image_id="$("$docker_bin" image inspect --format '{{.Id}}' "$reference")" ||
    die "$component image is not available locally: $reference"
  image_platform="$("$docker_bin" image inspect \
    --format '{{.Os}}/{{.Architecture}}' "$reference")" ||
    die "cannot inspect $component image platform: $reference"

  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "$component image has an unexpected image ID: $image_id"
  [[ "$image_platform" == "$platform" ]] ||
    die "$component image platform is $image_platform, expected $platform"

  if "$docker_bin" image inspect --format '{{json .Config}}' "$reference" |
    LC_ALL=C grep -aEq -- "$credential_pattern"; then
    die "$component image configuration contains a private credential marker"
  fi
  if "$docker_bin" image history --no-trunc \
    --format '{{.CreatedBy}}' "$reference" |
    LC_ALL=C grep -aEq -- "$credential_pattern"; then
    die "$component image history contains a private credential marker"
  fi

  printf '%s\n' "$image_id"
}

canonical_image_archive() {
  local reference="$1"
  local component="$2"
  local destination="$3"
  local raw_archive="$work_dir/${component}.raw.tar"
  local unpack_dir="$work_dir/${component}.unpacked"

  mkdir -p "$unpack_dir"
  "$docker_bin" image save --output "$raw_archive" "$reference" ||
    die "cannot export $component image: $reference"
  tar -tf "$raw_archive" >/dev/null ||
    die "$component image export is not a valid tar archive"
  if tar -tf "$raw_archive" |
    LC_ALL=C grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    die "$component image export contains an unsafe path"
  fi
  tar -xf "$raw_archive" -C "$unpack_dir"
  tar --sort=name \
    --mtime="@$source_date_epoch" \
    --owner=0 --group=0 --numeric-owner \
    --pax-option=delete=atime,delete=ctime \
    -C "$unpack_dir" -cf "$destination" .
  tar -tf "$destination" >/dev/null ||
    die "canonical $component image archive is invalid"
  # Binary libraries can contain access-key-like byte sequences by chance.
  # A complete PEM private-key boundary is unambiguous even in an image tar.
  if LC_ALL=C grep -aEq -- "$private_key_pattern" "$destination"; then
    die "$component image filesystem contains a private credential marker"
  fi
}

registry_image_id="$(inspect_image "$registry_image" "registry")"
edge_image_id="$(inspect_image "$edge_image" "edge")"

canonical_image_archive \
  "$registry_image" \
  "registry" \
  "$stage_dir/images/myscoutee-registry.tar"
canonical_image_archive \
  "$edge_image" \
  "edge" \
  "$stage_dir/images/myscoutee-registry-edge.tar"

cp "$repository_root/tools/docker/offline/compose.yaml" "$stage_dir/compose.yaml"
cp "$repository_root/tools/docker/offline/README.md" "$stage_dir/README.md"
cp "$repository_root/tools/docker/registry.conf.template" \
  "$stage_dir/nginx/registry.conf.template"
sed \
  -e "s|^MYSCOUTEE_VERSION=.*$|MYSCOUTEE_VERSION=$version|" \
  -e "s|^REGISTRY_PRODUCTION_IMAGE=.*$|REGISTRY_PRODUCTION_IMAGE=$registry_image|" \
  -e "s|^REGISTRY_EDGE_IMAGE=.*$|REGISTRY_EDGE_IMAGE=$edge_image|" \
  "$repository_root/tools/docker/offline/registry.env.example" \
  >"$stage_dir/registry.env.example"
printf '%s\n' "$version" >"$stage_dir/VERSION"

registry_archive_sha256="$(
  sha256sum "$stage_dir/images/myscoutee-registry.tar" |
    awk '{print $1}'
)"
edge_archive_sha256="$(
  sha256sum "$stage_dir/images/myscoutee-registry-edge.tar" |
    awk '{print $1}'
)"

cat >"$stage_dir/IMAGE-MANIFEST.json" <<EOF
{
  "schema_version": 1,
  "stack_version": "$version",
  "platform": "$platform",
  "source_revision": "$source_revision",
  "source_date_epoch": $source_date_epoch,
  "images": [
    {
      "service": "registry",
      "reference": "$registry_image",
      "image_id": "$registry_image_id",
      "archive": "images/myscoutee-registry.tar",
      "archive_sha256": "sha256:$registry_archive_sha256"
    },
    {
      "service": "nginx",
      "reference": "$edge_image",
      "image_id": "$edge_image_id",
      "archive": "images/myscoutee-registry-edge.tar",
      "archive_sha256": "sha256:$edge_archive_sha256"
    }
  ]
}
EOF

while IFS= read -r -d '' staged_file; do
  case "$staged_file" in
    *.pem | *.key | *.p8 | *.p12 | *.jks | *.db | *.db-shm | *.db-wal | \
      */.env | */.env.*)
      die "credential or runtime-state filename entered the bundle: $staged_file"
      ;;
  esac
done < <(find "$stage_dir" -type f -print0)

if find "$stage_dir" -type f \
  ! -path "$stage_dir/images/*" -print0 |
  LC_ALL=C xargs -0 -r grep -aEl -- "$credential_pattern" |
  grep -q .; then
  die "a release payload file contains a private credential marker"
fi

(
  cd "$stage_dir"
  while IFS= read -r -d '' payload; do
    sha256sum "$payload"
  done < <(find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z)
) >"$stage_dir/SHA256SUMS"

temporary_artifact="$work_dir/${bundle_name}.tar.gz"
tar --sort=name \
  --mtime="@$source_date_epoch" \
  --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' \
  --pax-option=delete=atime,delete=ctime \
  -C "$work_dir" -cf - "$bundle_name" |
  gzip -n -9 >"$temporary_artifact"

mv "$temporary_artifact" "$artifact_path"
artifact_sha256="$(sha256sum "$artifact_path" | awk '{print $1}')"

printf 'Created %s\n' "$artifact_path"
printf 'SHA256 %s\n' "$artifact_sha256"
