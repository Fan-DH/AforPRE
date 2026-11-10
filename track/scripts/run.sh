#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
pin_root=${PIN_ROOT:-$root/.deps/pin}
if [[ ! -f "$root/obj-intel64/pretrace.so" ]]; then
    printf 'Build first: make -C %q\n' "$root" >&2
    exit 1
fi
# Eager symbol binding avoids the unsupported XSAVE/XRSTOR lazy resolver path.
export LD_BIND_NOW=1
exec "$pin_root/pin" -t "$root/obj-intel64/pretrace.so" "$@"
