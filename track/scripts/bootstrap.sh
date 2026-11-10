#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .deps
archive=.deps/pin.tar.gz
url=https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-4.4-99977-g54fbb8814-gcc-linux.tar.gz
hash=3138183a5d2b51ea5c8f29edd148b67ac9c249e2c510cc0e9e2a5880f523a34c
if [[ ! -f "$archive" ]]; then
    curl --fail --location --retry 3 "$url" -o "$archive.part"
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$hash" "$archive" | sha256sum --check
if [[ ! -x .deps/pin/pin ]]; then
    tar -xzf "$archive" -C .deps
    mv .deps/pin-external-4.4-99977-g54fbb8814-gcc-linux .deps/pin
fi
printf 'Pin SDK ready: %s/.deps/pin\n' "$PWD"
