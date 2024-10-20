# nsave
nsave 是一个抓取并保存数据包的工具。它持续不断地抓取数据包，并保存到本地。可以根据条件查询链接、数据包并导出成pcap文件。

目前是原型阶段，不要应用在关键的生产环境。

# 运行环境
Linux，MacOS。

# 配置
配置项如下：
``` toml
interface = "en1"
pkt_len = 2000
filter = "tcp"
daemon = true

# pcap_file = "~/misc/https.pcap"
store_path = "/Users/lch/misc/nsave_data/"

# 写磁盘线程个数
thread_num = 2

pkt_channel_size = 2048
msg_channel_size = 1024
# 微秒。500毫秒
timer_intervel = 500000000
# 毫秒
writer_empty_sleep = 5
# 毫秒
clean_empty_sleep = 100

# 16M 1024 * 1024 * 16
pool_size = 16777216
# 2M 1024 * 1024 * 2
file_size = 2097152
# 80k 1024 * 80
chunk_size = 81920

ci_buff_size = 1024
ti_buff_size = 1024

flow_max_table_capacity = 1024
# 微妙。 10秒
flow_node_timeout = 10000000000
flow_max_seq_gap = 8
```
然后把配置文件.nsave.toml 放到当前用户目录下。

# 运行
执行nsave，nsave就开始持续不断地抓取数据包，并保存到本地。

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
