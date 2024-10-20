# nsave
nsave is a tool for capturing and saving data packets. It continuously captures packets and saves them locally. You can query connections and packets based on conditions and export them as pcap files.

It is currently in the prototype stage and should not be used in critical production environments.

# Operating Environment
Linux, macOS.

# Configuration
The configuration items are as follows:
```toml
interface = "en1"
pkt_len = 2000
filter = "tcp"
daemon = true

# pcap_file = "~/misc/https.pcap"
store_path = "/Users/lch/misc/nsave_data/"

# Number of threads writing to disk
thread_num = 2

pkt_channel_size = 2048
msg_channel_size = 1024
# Microseconds. 500 milliseconds
timer_interval = 500000000
# Milliseconds
writer_empty_sleep = 5
# Milliseconds
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
# Microseconds. 10 seconds
flow_node_timeout = 10000000000
flow_max_seq_gap = 8
```
Place the configuration file `.nsave.toml` in the current user's directory.

# Running
Execute nsave, and it will start continuously capturing packets and saving them locally.

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
