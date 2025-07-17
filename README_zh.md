# nsave

Nsave 是一个抓取并保存数据包的工具。它持续不断地抓取数据包，并保存到本地。可以根据条件查询链接、数据包并导出成pcap文件。可以通过pcap 或者af_xdp来捕获数据包。主要特点是它不基于单个数据包，而是基于流来作索引，可以大幅减少索引所占的磁盘空间。


# 提醒
1. 目前是开发阶段，不要应用在关键的生产环境。
1. 需要配置单独的抓包网卡。管理网卡不能用于抓包，否则你会失去连接，因为加载的xdp程序会把网卡上所有的数据包都截获，不再流入内核。


# 运行环境

Linux


# 配置

```shell
cp nsave_conf.toml ~/.nsave_conf.toml
```


# 前置要求

1. stable rust 工具链：`rustup toolchain install stable`
1. nightly rust 工具链：`rustup toolchain install nightly --component rust-src`
1. bpf-linker：`cargo install bpf-linker`（在 macOS 上使用 `--no-default-features`）


# 构建和运行

正常使用 `cargo build`、`cargo check` 等命令。运行程序使用：

```shell
RUST_LOG=info cargo run --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
cargo run --release --bin nsave --config 'target."cfg(all())".runner="sudo -E"' -- --iface ens192
```

Cargo 构建脚本会自动正确构建 eBPF 并将其包含在程序中。


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
