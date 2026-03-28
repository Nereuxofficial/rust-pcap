#!/usr/bin/env bash
# Run test binaries directly (they live in .../deps/); everything else needs
# CAP_BPF + CAP_NET_ADMIN to load eBPF programs, so grant them via setcap and
# then execute the binary as the current user.
if [[ "$1" == */deps/* ]]; then
    exec "$@"
else
    echo "Granting CAP_BPF + CAP_NET_RAW to $1"
    sudo setcap 'cap_bpf,cap_net_raw+eip' "$1"
    exec "$@"
fi
