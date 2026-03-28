#!/usr/bin/env bash
# Run test binaries directly (they live in .../deps/); everything else via sudo.
if [[ "$1" == */deps/* ]]; then
    exec "$@"
else
    exec sudo -E "$@"
fi
