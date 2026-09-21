#!/bin/sh
# Maps environment variables to openflux flags and, for the exit node,
# installs the kernel-RST-drop rule *inside this container's netns*.
#
# Why the rule: the exit node's TCP connections live in a userspace (gVisor)
# stack, so the kernel has no socket for them and answers every inbound
# SYN-ACK with an RST, tearing the tunnel down. Confining the DROP to the
# container netns is the scoped variant of upstream's host-wide rule — it
# cannot affect the host or other containers.
set -eu

role="${ROLE:-client}"
transport="${TRANSPORT:-yandex}"
listen="${SOCKS5_LISTEN:-:1080}"

case "$role" in
  client|exit-node) ;;
  *)
    echo "ROLE must be 'client' or 'exit-node' (got '$role')" >&2
    exit 2
    ;;
esac
# Canonical flag value for the exit role is 'exit' ('exit-node' names the
# deprecated flag alias, not the value).
[ "$role" = exit-node ] && role=exit

case "$transport" in
  yandex|vyandex|oneme|cupsonline|mailru) ;;
  *)
    echo "TRANSPORT must be one of yandex, vyandex, oneme, cupsonline, mailru (got '$transport')" >&2
    exit 2
    ;;
esac

mode="${MODE:-}"
case "$mode" in
  ""|l3|l4) ;;
  *)
    echo "MODE must be l3 or l4 (got '$mode')" >&2
    exit 2
    ;;
esac

codec="${CODEC:-}"
case "$codec" in
  ""|batched|legacy) ;;
  *)
    echo "CODEC must be batched or legacy (got '$codec')" >&2
    exit 2
    ;;
esac

set -- "--role" "$role" --transport "$transport"

if [ "$role" = client ]; then
  set -- "$@" --inbound socks5 --socks5 "$listen"
elif [ -n "$mode" ]; then
  set -- "$@" --mode "$mode"
fi

if [ -n "${URL:-}" ]; then
  set -- "$@" --url "$URL"
fi
if [ -n "${MAX_TOKEN:-}" ]; then
  set -- "$@" --maxToken "$MAX_TOKEN"
fi
if [ -n "${MAX_UID:-}" ]; then
  set -- "$@" --maxUid "$MAX_UID"
fi
if [ -n "${LOCAL_IP:-}" ]; then
  # Optional: pin the egress IP (alias IP) so the RST drop could be scoped
  # with `-s <ip>` too; inside a dedicated container netns it's usually
  # unnecessary.
  set -- "$@" --local-ip "$LOCAL_IP"
fi
if [ -n "$codec" ]; then
  set -- "$@" --codec "$codec"
fi
if [ -n "${ENCRYPTION_KEY:-}" ]; then
  # The binary reads the AES-256-GCM secret from a file; materialize the env
  # value into one (trimmed, no trailing newline) so no volume mount is needed.
  keyfile="/tmp/openflux.key"
  printf '%s' "$ENCRYPTION_KEY" > "$keyfile"
  set -- "$@" --encryption-key-file "$keyfile"
fi
case "${DEBUG:-0}" in
  1|true|yes) set -- "$@" --debug ;;
esac

if [ "$role" = exit ]; then
  echo "[entrypoint] dropping outbound TCP RSTs inside the container netns"
  if ! iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP; then
    echo "[entrypoint] WARNING: iptables failed (missing NET_ADMIN?); kernel RSTs will kill tunnel connections" >&2
  fi
fi

echo "[entrypoint] exec: openflux $*"
exec openflux "$@"
