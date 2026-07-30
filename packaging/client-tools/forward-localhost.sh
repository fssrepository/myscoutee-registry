#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd "$(dirname "$0")" && pwd)"
TRANSPORT_SCRIPT="${SCRIPT_DIR}/remote-transport.sh"

usage() {
  cat >&2 <<'USAGE'
Usage:
  packaging/client-tools/forward-localhost.sh

The helper reads its SSH target from packaging/client-tools/install.env, or
CONFIG_FILE. The default loopback mappings are 127.0.0.1:18443 to remote
127.0.0.1:443 and 127.0.0.1:18080 to remote 127.0.0.1:80. For a deployment
using custom public ports, override both mappings explicitly. The Registry
backend remains internal and is not a tunnel target. Privileged local ports
are refused.
USAGE
}

fail() {
  echo "fail $1" >&2
  exit 1
}

LOCAL_FORWARD_PORTS_OVERRIDE_VALUE="${LOCAL_FORWARD_PORTS_OVERRIDE:-}"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/install.env}"
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
[ -f "$CONFIG_FILE" ] || fail "config file not found: $CONFIG_FILE"
[ -f "$TRANSPORT_SCRIPT" ] || fail "transport helper not found: $TRANSPORT_SCRIPT"

# shellcheck source=/dev/null
. "$CONFIG_FILE"
# shellcheck source=/dev/null
. "$TRANSPORT_SCRIPT"

REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-}"
LOCAL_FORWARD_HOST="${LOCAL_FORWARD_HOST:-127.0.0.1}"
LOCAL_FORWARD_REMOTE_HOST="${LOCAL_FORWARD_REMOTE_HOST:-127.0.0.1}"
LOCAL_FORWARD_PORTS="${LOCAL_FORWARD_PORTS_OVERRIDE_VALUE:-${LOCAL_FORWARD_PORTS:-18443:443,18080:80}}"

[ -n "$LOCAL_FORWARD_PORTS" ] || fail "LOCAL_FORWARD_PORTS is empty"
printf '%s\n' "$LOCAL_FORWARD_HOST" \
  | grep -Eq '^(127\.0\.0\.1|::1|localhost)$' \
  || fail "LOCAL_FORWARD_HOST must remain loopback-only"
printf '%s\n' "$LOCAL_FORWARD_REMOTE_HOST" \
  | grep -Eq '^(127\.0\.0\.1|::1|localhost)$' \
  || fail "LOCAL_FORWARD_REMOTE_HOST must remain loopback-only"

validate_port() {
  port="$1"
  label="$2"

  case "$port" in
    ""|*[!0-9]*)
      fail "${label} must be numeric: ${port:-empty}"
      ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    fail "${label} is outside 1..65535: $port"
  fi
}

parse_forward_spec() {
  forward_mapping="$1"

  case "$forward_mapping" in
    *:*:*)
      fail "forward mapping has more than one colon: $forward_mapping"
      ;;
    *:*)
      PARSED_LOCAL_PORT="${forward_mapping%%:*}"
      PARSED_REMOTE_PORT="${forward_mapping#*:}"
      ;;
    *)
      PARSED_LOCAL_PORT="$forward_mapping"
      PARSED_REMOTE_PORT="$forward_mapping"
      ;;
  esac
  validate_port "$PARSED_LOCAL_PORT" "local forward port"
  validate_port "$PARSED_REMOTE_PORT" "remote forward port"
  if [ "$PARSED_LOCAL_PORT" -lt 1024 ]; then
    fail "local forward ports must be non-privileged (1024..65535): $PARSED_LOCAL_PORT"
  fi
}

start_forward() {
  local_port="$1"
  remote_port="$2"
  forward_spec="${LOCAL_FORWARD_HOST}:${local_port}:${LOCAL_FORWARD_REMOTE_HOST}:${remote_port}"

  echo "Target: $REMOTE_TRANSPORT_TARGET"
  echo "Forward: ${LOCAL_FORWARD_HOST}:${local_port}->${LOCAL_FORWARD_REMOTE_HOST}:${remote_port}"

  if [ -n "$REMOTE_KEY_FILE" ]; then
    # REMOTE_SSH_OPTIONS is trusted local configuration and intentionally split.
    # shellcheck disable=SC2086
    remote_transport_with_auth ssh \
      -p "$REMOTE_PORT" \
      -o "ConnectTimeout=${REMOTE_CONNECT_TIMEOUT_SECONDS}" \
      -o "StrictHostKeyChecking=${REMOTE_HOST_KEY_CHECKING}" \
      -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=3 \
      -i "$REMOTE_KEY_FILE" \
      $REMOTE_SSH_OPTIONS \
      -fN \
      -L "$forward_spec" \
      "$REMOTE_TRANSPORT_TARGET"
    return
  fi

  # REMOTE_SSH_OPTIONS is trusted local configuration and intentionally split.
  # shellcheck disable=SC2086
  remote_transport_with_auth ssh \
    -p "$REMOTE_PORT" \
    -o "ConnectTimeout=${REMOTE_CONNECT_TIMEOUT_SECONDS}" \
    -o "StrictHostKeyChecking=${REMOTE_HOST_KEY_CHECKING}" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    $REMOTE_SSH_OPTIONS \
    -fN \
    -L "$forward_spec" \
    "$REMOTE_TRANSPORT_TARGET"
}

matching_forward_pids() {
  local_port="$1"
  remote_port="$2"
  expected_spec="${LOCAL_FORWARD_HOST}:${local_port}:${LOCAL_FORWARD_REMOTE_HOST}:${remote_port}"

  ps -ww -eo pid=,args= | awk \
    -v self="$$" \
    -v parent="${PPID:-}" \
    -v spec="$expected_spec" \
    -v target="$REMOTE_TRANSPORT_TARGET" '
      $1 != self && $1 != parent {
        pid = $1
        $1 = ""
        args = $0
        if (args ~ /(^|[[:space:]])ssh([[:space:]]|$)/ &&
            (index(args, "-L " spec) || index(args, "-L" spec)) &&
            index(args, target)) {
          print pid
        }
      }
    '
}

replace_existing_forward() {
  local_port="$1"
  remote_port="$2"
  pids="$(matching_forward_pids "$local_port" "$remote_port")"
  [ -n "$pids" ] || return 0

  echo "Replacing existing forward on ${LOCAL_FORWARD_HOST}:${local_port} to remote port ${remote_port}"
  for pid in $pids; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  pids="$(matching_forward_pids "$local_port" "$remote_port")"
  [ -z "$pids" ] \
    || fail "existing forward did not stop on ${LOCAL_FORWARD_HOST}:${local_port}"
}

case "$LOCAL_FORWARD_PORTS" in
  ,*|*,|*,,*|*[!0-9,:]*)
    fail "LOCAL_FORWARD_PORTS must be comma-separated local[:remote] numeric mappings"
    ;;
esac

OLD_IFS="$IFS"
IFS=","
for spec in $LOCAL_FORWARD_PORTS; do
  parse_forward_spec "$spec"
done
IFS="$OLD_IFS"

remote_transport_setup "$CONFIG_FILE"
trap remote_transport_cleanup EXIT

OLD_IFS="$IFS"
IFS=","
for spec in $LOCAL_FORWARD_PORTS; do
  parse_forward_spec "$spec"
  replace_existing_forward "$PARSED_LOCAL_PORT" "$PARSED_REMOTE_PORT"
  start_forward "$PARSED_LOCAL_PORT" "$PARSED_REMOTE_PORT"
done
IFS="$OLD_IFS"

echo "Forward active"
