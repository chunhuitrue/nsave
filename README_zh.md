# nsave

nsave 是一个抓取并保存数据包的工具。它持续不断地抓取数据包，并保存到本地。可以根据条件查询链接、数据包并导出成pcap文件。

目前是开发阶段，不要应用在关键的生产环境。


# 运行环境

Linux


# 配置

```shell
cp nsave_conf.toml ~/.nsave_conf.toml
```


# 前置要求

1. stable rust 工具链：`rustup toolchain install stable`
1. nightly rust 工具链：`rustup toolchain install nightly --component rust-src`
1. （如果交叉编译）rustup target：`rustup target add ${ARCH}-unknown-linux-musl`
1. （如果交叉编译）LLVM：（例如）`brew install llvm`（在 macOS 上）
1. （如果交叉编译）C 工具链：（例如）[`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross)（在 macOS 上）
1. bpf-linker：`cargo install bpf-linker`（在 macOS 上使用 `--no-default-features`）


# 构建和运行

正常使用 `cargo build`、`cargo check` 等命令。运行程序使用：

```shell
RUST_LOG=info cargo run --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
cargo run --release --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
```

Cargo 构建脚本会自动正确构建 eBPF 并将其包含在程序中。


# 在 macOS 上交叉编译

交叉编译在 Intel 和 Apple Silicon Mac 上都应该可以工作。

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package nsave --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
交叉编译的程序 `target/${ARCH}-unknown-linux-musl/release/nsave` 可以
复制到 Linux 服务器或虚拟机上运行。


# 查询

可以根据时间，五元祖，bfp过滤器来查询链接或数据包。

查询五元祖的链接：
``` bash
nsave-cli search -s 2024-03-28-12:00:00 -e 2024-03-28-22:00:00  --sip 111.206.208.245 -D 10.11.20.13 -P tcp -p 443 -d 64024
``` 

将查询结果dump成pcap文件：
``` bash
nsave-cli search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47  --sip 10.11.20.255 -D 10.11.20.14 -P udp -p 137 -d 137 -f ~/misc/nsave_data/dump.pcap
```

以bpf过滤器来查询数据包：
``` bash
nsave-cli bpf_search  -s 2024-07-28-21:10:00 -e 2024-07-28-21:15:00 --bpf  “udp and arp”
```

bpf查询也可以dump成pcap文件：
``` bash
nsave-cli -c nsave_conf.toml bpf_search  -s 2024-07-28-21:10:00 -e 2024-07-28-21:15:00 --bpf "tcp or udp" -f ~/misc/nsave_data/dump.pcap
```
