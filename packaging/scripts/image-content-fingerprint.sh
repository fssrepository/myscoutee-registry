#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  image-content-fingerprint.sh docker IMAGE
  image-content-fingerprint.sh config FILE|-

Prints a daemon-storage-independent SHA-256 fingerprint of image runtime
configuration and root filesystem layer content digests.
USAGE
  exit 2
}

for command_name in jq sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'image-content-fingerprint: missing command: %s\n' \
      "$command_name" >&2
    exit 2
  }
done

canonicalize() {
  jq -ceS '
    {
      schemaVersion: 1,
      architecture: .architecture,
      os: .os,
      config: {
        user: (.user // ""),
        env: (.env // []),
        entrypoint: (.entrypoint // []),
        cmd: (.cmd // []),
        workingDir: (.workingDir // ""),
        labels: (.labels // {}),
        exposedPorts: (.exposedPorts // {}),
        volumes: (.volumes // {}),
        healthcheck: (.healthcheck // null),
        stopSignal: (.stopSignal // ""),
        shell: (.shell // [])
      },
      rootfsLayers: .rootfsLayers
    }
    | . as $value
    | if
        ($value.architecture | type == "string" and length > 0)
        and ($value.os | type == "string" and length > 0)
        and ($value.config.user | type == "string")
        and ($value.config.env | type == "array" and all(.[]; type == "string"))
        and ($value.config.entrypoint | type == "array" and all(.[]; type == "string"))
        and ($value.config.cmd | type == "array" and all(.[]; type == "string"))
        and ($value.config.workingDir | type == "string")
        and ($value.config.labels | type == "object")
        and ($value.config.exposedPorts | type == "object")
        and ($value.config.volumes | type == "object")
        and (($value.config.healthcheck == null) or ($value.config.healthcheck | type == "object"))
        and ($value.config.stopSignal | type == "string")
        and ($value.config.shell | type == "array" and all(.[]; type == "string"))
        and ($value.rootfsLayers | type == "array"
          and all(.[]; type == "string" and test("^sha256:[0-9a-f]{64}$")))
      then $value
      else error("invalid image content metadata")
      end
  '
}

[[ "$#" -eq 2 ]] || usage
mode="$1"
source_value="$2"
canonical=""

case "$mode" in
  docker)
    [[ -n "$source_value" && "$source_value" != *$'\n'* ]] || usage
    docker_bin="${DOCKER_BIN:-docker}"
    command -v "$docker_bin" >/dev/null 2>&1 || {
      printf '%s\n' 'image-content-fingerprint: Docker is unavailable' >&2
      exit 2
    }
    canonical="$(
      "$docker_bin" image inspect -- "$source_value" |
        jq -ce '
          if type == "array" and length == 1 then .[0]
          else error("expected one Docker image")
          end
          | {
              architecture: (.Architecture // ""),
              os: (.Os // ""),
              user: (.Config.User // ""),
              env: (.Config.Env // []),
              entrypoint: (.Config.Entrypoint // []),
              cmd: (.Config.Cmd // []),
              workingDir: (.Config.WorkingDir // ""),
              labels: (.Config.Labels // {}),
              exposedPorts: (.Config.ExposedPorts // {}),
              volumes: (.Config.Volumes // {}),
              healthcheck: (.Config.Healthcheck // null),
              stopSignal: (.Config.StopSignal // ""),
              shell: (.Config.Shell // []),
              rootfsLayers: (.RootFS.Layers // [])
            }
        ' | canonicalize
    )"
    ;;
  config)
    if [[ "$source_value" == "-" ]]; then
      input_command=(cat)
    elif [[ -f "$source_value" && ! -L "$source_value" ]]; then
      input_command=(cat "$source_value")
    else
      printf '%s\n' \
        'image-content-fingerprint: config must be a regular file or -' >&2
      exit 2
    fi
    canonical="$(
      "${input_command[@]}" |
        jq -ce '
          if type == "object" then .
          else error("expected an OCI image config object")
          end
          | {
              architecture: (.architecture // ""),
              os: (.os // ""),
              user: (.config.User // ""),
              env: (.config.Env // []),
              entrypoint: (.config.Entrypoint // []),
              cmd: (.config.Cmd // []),
              workingDir: (.config.WorkingDir // ""),
              labels: (.config.Labels // {}),
              exposedPorts: (.config.ExposedPorts // {}),
              volumes: (.config.Volumes // {}),
              healthcheck: (.config.Healthcheck // null),
              stopSignal: (.config.StopSignal // ""),
              shell: (.config.Shell // []),
              rootfsLayers: (.rootfs.diff_ids // [])
            }
        ' | canonicalize
    )"
    ;;
  *)
    usage
    ;;
esac

digest="$(printf '%s\n' "$canonical" | sha256sum | awk 'NR == 1 {print $1}')"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'image-content-fingerprint: could not calculate digest' >&2
  exit 1
}
printf 'sha256:%s\n' "$digest"
