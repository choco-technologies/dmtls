#!/bin/sh
# Metadata tools must understand the same module format as the SDK and runtime.
set -eu
sdk=${1:-.ci-sdk}
build=${2:-.ci-tools}
cmake -S "$sdk" -B "$build" -DDMOD_MODE=DMOD_SYSTEM \
    -DDMOD_BUILD_TOOLS=ON -DDMOD_BUILD_TESTS=OFF -DDMOD_BUILD_EXAMPLES=ON
cmake --build "$build" --parallel 4 --target todmd dmf-get todmp dmod_loader
if [ -n "${GITHUB_PATH:-}" ]; then
    for path in tools/system/todmd tools/system/dmf-get tools/system/todmp examples/system/dmod_loader; do
        realpath "$build/$path" >> "$GITHUB_PATH"
    done
fi
