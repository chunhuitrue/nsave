# nsave

Nsave is a tool for capturing and saving network packets. It continuously captures packets and saves them locally. It can query connections and packets based on conditions and export them as pcap files. It can capture packets through pcap or af_xdp. The main feature is that it doesn't index based on individual packets, but rather based on flows, which can significantly reduce the disk space occupied by indexes.

# Important Notes

1. Currently in development stage, do not use in critical production environments.
2. A dedicated network interface for packet capture must be configured. The management network interface cannot be used for packet capture, otherwise you will lose connection, because the loaded XDP program will intercept all packets on the network interface and they will no longer flow into the kernel.


# Operating Environment

Linux


# Configuration

```shell
cp nsave_conf.toml ~/.nsave_conf.toml
```

# Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)


# Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
RUST_LOG=info cargo run --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
cargo run --release --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.


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
