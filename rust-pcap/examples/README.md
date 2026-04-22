# capture example

A ready-to-use CLI that captures packets to a `.pcap` file using `rust-pcap`.

## Usage

```
cargo run --example capture -- <output.pcap> [interface]
```

| Argument | Description |
|---|---|
| `<output.pcap>` | Path to write the capture file to. |
| `[interface]` | Optional interface name (e.g. `eth0`). Omit to capture from all interfaces. |

## Examples

```shell
# Capture all interfaces
sudo cargo run --example capture -- capture.pcap

# Capture a specific interface
sudo cargo run --example capture -- capture.pcap eth0
```

Press **Ctrl-C** to stop.

### Enable logging

```shell
sudo RUST_LOG=info cargo run --example capture -- capture.pcap
```

### Build and run a release binary

```shell
cargo build --example capture --release
sudo ./target/release/examples/capture capture.pcap eth0
```
