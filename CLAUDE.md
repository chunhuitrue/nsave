# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

nsave is a high-performance network packet capture and storage tool written in Rust. It continuously captures packets and stores them locally with efficient querying capabilities. The project is currently in prototype stage and should not be used in critical production environments.

## Build Commands

```bash
# 日常开发调试时只需用如下命令编译
cargo build 

# Build with debug features enabled
cargo build --features debug_mode

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy linter
cargo clippy --tests
```

## Running Commands

```bash
# Run the packet capture daemon
cargo run --bin nsave --config 'target."cfg(all())".runner="sudo -E"'

# Run CLI queries (5-tuple search)
nsave-cli search -s 2024-03-28-12:00:00 -e 2024-03-28-22:00:00 --sip 192.168.1.1 -D 192.168.1.2 -P tcp

# Run BPF filter queries
nsave-cli bpf_search -s 2024-07-28-21:10:00 -e 2024-07-28-21:15:00 --bpf "tcp or udp"

# Export to pcap file
nsave-cli search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47 --sip 10.11.20.255 -D 10.11.20.14 -P udp -f ~/dump.pcap
```

## Configuration

The tool requires a TOML configuration file (typically `.nsave_conf.toml` in the user's home directory). Key configuration sections:

- **Capture**: Interface, packet length, filtering
- **Storage**: Store path, file/chunk sizes, thread configuration
- **Performance**: Channel sizes, timer intervals, memory pool settings
- **Flow tracking**: Connection timeout, table capacity, sequence gap handling

## Architecture Overview

### Multi-crate Structure
- **`nsave/`**: Main application with capture engine and CLI tools
- **`ebpf/`**: eBPF program for high-performance packet filtering using AF_XDP
- **`common/`**: Shared data structures and utilities

### Core Components

**Packet Capture Layer**:
- AF_XDP support for high-performance capture with eBPF integration
- PCAP fallback for traditional packet capture
- Automatic promiscuous mode management

**Multi-threaded Processing**:
- Main thread: Packet capture and distribution
- Writer threads: Configurable number of disk storage threads
- Clean thread: Background cleanup of old data

**Storage System**:
- Chunk-based storage (default 80KB chunks)
- Time-based hierarchical indexing
- Connection-based indexing using 5-tuple
- Memory-mapped file I/O for efficiency

**Flow Management**:
- Connection tracking with 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol)
- TCP state tracking with sequence numbers
- Automatic timeout handling for stale connections

### Key Data Structures
- `PacketKey`: 5-tuple for connection identification
- `FlowNode`: Connection state and metadata
- `ChunkPool`: Memory management for packet storage
- `TimeIndex`: Time-based indexing for temporal queries
- `ChunkIndex`: Connection-based indexing for tuple queries

### eBPF Integration
The project uses eBPF for high-performance packet processing:
- XDP program redirects packets to AF_XDP sockets
- Custom build process compiles eBPF programs during build
- Uses `XskMap` for managing multiple socket queues

## Common Development Tasks

### Testing Individual Components
```bash
# Test specific module
cargo test --package nsave mmapbuf

# Test with output
cargo test -- --nocapture

# Test eBPF components
cargo test --package ebpf
```

## Code Organization

### Main Entry Points
- `nsave/src/main.rs`: Main daemon process
- `nsave/src/bin/cli/main.rs`: CLI query tool
- `ebpf/src/main.rs`: eBPF program

### Key Modules
- `capture.rs`: Packet capture abstraction (AF_XDP/PCAP)
- `flow.rs`: Connection tracking and management
- `store.rs`: Storage layer with indexing
- `mmapbuf.rs`: Memory-mapped buffer management
- `timeindex.rs`: Time-based indexing
- `chunkindex.rs`: Connection-based indexing

### Configuration
- `configure.rs`: Configuration parsing and validation
- `nsave_conf.toml`: Example configuration file

## Build Process Notes

The build process includes automatic eBPF compilation:
- Custom build script (`build.rs`) compiles eBPF programs
- Requires unstable Rust features for cross-compilation
- eBPF binaries are embedded in the main executable
- Uses `cargo -Z build-std` for eBPF target compilation

## Platform Support

Supports Linux and macOS with the following requirements:
- AF_XDP support requires Linux kernel 4.18+
- PCAP fallback works on both platforms
- Root privileges typically required for packet capture

## Error Handling

The codebase uses comprehensive error handling:
- Custom `StoreError` type for storage operations
- `anyhow` for error propagation in main application
- Graceful handling of Ctrl-C interruption with proper cleanup
- Promiscuous mode is automatically disabled on exit

## 修改规则

每次修改都要首先把需要修改的地方列出来，等审核确认之后再逐一询问并改动。
