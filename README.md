# nsave

nsave is a tool for capturing and saving data packets. It continuously captures packets and saves them locally. You can query connections and packets based on conditions and export them as pcap files.

It is currently in the development stage; do not utilize it in critical production environments.


# Operating Environment

Linux


# Configuration

```shell
cp nsave_conf.toml ~/.nsave_conf.toml
```

# Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)


# Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
RUST_LOG=info cargo run --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
cargo run --release --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.


# Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package nsave --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/nsave` can be
copied to a Linux server or VM and run there.

 
# Querying
You can query connections or packets based on time, five-tuple, or BPF filters.

Querying connections by five-tuple:
```bash
nsave-cli search -s 2024-03-28-12:00:00 -e 2024-03-28-22:00:00 --sip 111.206.208.245 -D 10.11.20.13 -P tcp -p 443 -d 64024
``` 
Dump the query results to a pcap file:
```bash
nsave-cli search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47 --sip 10.11.20.255 -D 10.11.20.14 -P udp -p 137 -d 137 -f ~/misc/nsave_data/dump.pcap
```
Querying packets with a BPF filter:
```bash
nsave-cli bpf_search -s 2024-07-28-21:10:00 -e 2024-07-28-21:15:00 --bpf "udp and arp"
```

BPF queries can also be dumped to a pcap file:
```bash
nsave-cli -c nsave_conf.toml bpf_search -s 2024-07-28-21:10:00 -e 2024-07-28-21:15:00 --bpf "tcp or udp" -f ~/misc/nsave_data/dump.pcap
```
