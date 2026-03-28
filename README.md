# rust-pcap

> PCAP capturing via Rust with zero C dependencies, powered by [aya](https://github.com/aya-rs/aya) and eBPF.

[![Build](https://img.shields.io/github/actions/workflow/status/Nereuxofficial/rust-pcap/ci.yml?branch=main&style=flat-square)](https://github.com/Nereuxofficial/rust-pcap/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](#license)
[![Rust](https://img.shields.io/badge/rust-stable%20%2B%20nightly-orange?style=flat-square)](https://www.rust-lang.org)
[![eBPF](https://img.shields.io/badge/eBPF-powered-blueviolet?style=flat-square)](https://ebpf.io)

---

## Overview

`rust-pcap` captures network packets at the kernel level using an eBPF program loaded via `aya`, writing them to a `.pcap` file — no `libpcap` or C toolchain required.

## Prerequisites

1. **Stable Rust toolchain**: `rustup toolchain install stable`
2. **Nightly Rust toolchain** (for eBPF): `rustup toolchain install nightly --component rust-src`
3. **bpf-linker**: `cargo install bpf-linker` (use `--no-default-features` on macOS)
4. *(cross-compiling only)* rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. *(cross-compiling only)* LLVM: e.g. `brew install llvm`
6. *(cross-compiling only)* musl C toolchain: e.g. [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross)

> **Note:** The program must be run as **root** (or with `CAP_BPF` + `CAP_NET_ADMIN`) because it loads an eBPF program into the kernel.

## Usage

### Run directly with Cargo

```shell
sudo cargo run --release -- <output.pcap>
```

For example, to capture packets into `capture.pcap`:

```shell
sudo cargo run --release -- capture.pcap
```

Press **Ctrl-C** to stop the capture. The output file can then be opened in [Wireshark](https://www.wireshark.org/) or inspected with `tcpdump -r capture.pcap`.

### Build and run the binary

```shell
cargo build --release
sudo ./target/release/rust-pcap <output.pcap>
```

### Enable logging

Set `RUST_LOG` to see debug output:

```shell
sudo RUST_LOG=info cargo run --release -- capture.pcap
```

## Cross-compiling on macOS

Cross-compilation works on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package rust-pcap --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

Copy the resulting binary to a Linux server or VM and run it there:

```shell
scp target/${ARCH}-unknown-linux-musl/release/rust-pcap user@host:~/
ssh user@host sudo ./rust-pcap capture.pcap
```

## License

With the exception of eBPF code, rust-pcap is distributed under the terms of either the
[MIT license] or the [Apache License] (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

### eBPF code

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this project by you, as defined in the GPL-2 license, shall be dual licensed as above,
without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

## References

- [aya-rs/aya](https://github.com/aya-rs/aya) — eBPF library for Rust
- [pythops/oryx](https://github.com/pythops/oryx) — great documentation
