use crate::configure::*;
use anyhow::Result;
use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Timelike};
use libc::timeval;
use log::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use serde::{Deserialize, Serialize};
use std::convert::From;
use std::ffi::CString;
use std::hash::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum TransProto {
    Udp,
    Tcp,
    Icmp4,
    Icmp6,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct PacketKey {
    pub addr1: IpAddr,
    pub port1: u16,
    pub addr2: IpAddr,
    pub port2: u16,
    pub trans_proto: TransProto,
}

const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const IFF_PROMISC: libc::c_short = 0x100;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct ifreq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
}

pub fn set_promiscuous_mode(interface_name: &str, enable: bool) -> Result<()> {
    // 创建一个socket用于ioctl调用
    let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock_fd < 0 {
        return Err(anyhow::anyhow!("Failed to create socket for ioctl"));
    }

    // 确保在函数结束时关闭socket
    let _guard = scopeguard::guard((), |_| {
        unsafe { libc::close(sock_fd) };
    });

    // 准备ifreq结构体
    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let interface_cstr = CString::new(interface_name)?;
    let interface_bytes = interface_cstr.as_bytes();

    if interface_bytes.len() >= IFNAMSIZ {
        return Err(anyhow::anyhow!("Interface name too long"));
    }

    // 复制接口名称
    unsafe {
        ptr::copy_nonoverlapping(
            interface_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            interface_bytes.len(),
        );
    }

    // 获取当前标志
    let ret = unsafe { libc::ioctl(sock_fd, SIOCGIFFLAGS, &mut ifr) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "Failed to get interface flags: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 设置或清除混杂模式标志
    if enable {
        ifr.ifr_flags |= IFF_PROMISC;
    } else {
        ifr.ifr_flags &= !IFF_PROMISC;
    }

    // 设置新的标志
    let ret = unsafe { libc::ioctl(sock_fd, SIOCSIFFLAGS, &ifr) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "Failed to set interface flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    info!(
        "Info: Successfully {} promiscuous mode on {}",
        if enable { "enabled" } else { "disabled" },
        interface_name
    );

    Ok(())
}

/// VLAN tag header structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VlanHdr {
    /// First 2 bytes containing PCP (3 bits), DEI (1 bit), and VLAN ID (12 bits)
    pub tci: [u8; 2],
    /// EtherType field indicating the protocol encapsulated in the payload
    pub eth_type: EtherType,
}

impl VlanHdr {
    pub const LEN: usize = mem::size_of::<VlanHdr>();

    /// Extract the Priority Code Point (PCP) from the VLAN header
    #[inline]
    pub fn pcp(&self) -> u8 {
        (u16::from_be_bytes(self.tci) >> 13) as u8
    }

    /// Extract the Drop Eligible Indicator (DEI) from the VLAN header
    #[inline]
    pub fn dei(&self) -> u8 {
        ((u16::from_be_bytes(self.tci) >> 12) & 1) as u8
    }

    /// Extract the VLAN ID from the VLAN header
    #[inline]
    pub fn vid(&self) -> u16 {
        u16::from_be_bytes(self.tci) & 0xFFF
    }

    /// Get the EtherType value
    #[inline]
    pub fn eth_type(&self) -> EtherType {
        self.eth_type
    }
}

#[inline(always)]
pub fn ptr_at<T>(data: &[u8], offset: usize) -> Result<*const T, PacketParseError> {
    if offset + std::mem::size_of::<T>() > data.len() {
        Err(PacketParseError::InvalidOffset)
    } else {
        Ok(&data[offset] as *const u8 as *const T)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PacketParseError {
    InvalidOffset,
    UnknownIpProtocol,
    UnknownTransportProtocol,
}

pub struct PacketOffsets {
    pub l3_offset: usize,
    pub l4_offset: usize,
    pub real_packet_len: Option<usize>, // Some for AF_XDP, None for PCAP
}

pub fn decode_packet(packet: &[u8]) -> Result<PacketOffsets, PacketParseError> {
    let mut offset = 0;
    let ethhdr_ptr: *const EthHdr = ptr_at(packet, 0)?;
    let ethhdr = unsafe { ptr::read_unaligned(ethhdr_ptr) };

    let mut ether_type_val = ethhdr.ether_type as u16;
    offset += EthHdr::LEN;

    while ether_type_val == 0x8100 {
        let vlanhdr_ptr: *const VlanHdr = ptr_at(packet, offset)?;
        let vlanhdr = unsafe { ptr::read_unaligned(vlanhdr_ptr) };
        ether_type_val = vlanhdr.eth_type as u16;
        offset += VlanHdr::LEN;
    }

    let l3_offset = offset;
    let final_ether_type = unsafe { std::mem::transmute::<u16, EtherType>(ether_type_val) };

    match final_ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr_ptr: *const Ipv4Hdr = ptr_at(packet, l3_offset)?;
            let ipv4hdr = unsafe { ptr::read_unaligned(ipv4hdr_ptr) };

            if ipv4hdr.version() != 4 {
                return Err(PacketParseError::UnknownIpProtocol);
            }

            let ip_header_len = ipv4hdr.ihl() as usize * 4;
            if ip_header_len < Ipv4Hdr::LEN {
                return Err(PacketParseError::InvalidOffset);
            }

            let l4_offset = l3_offset + ip_header_len;
            let real_packet_len = u16::from_be_bytes(ipv4hdr.tot_len) as usize;

            if l4_offset > packet.len() || (l3_offset + real_packet_len) > packet.len() {
                return Err(PacketParseError::InvalidOffset);
            }

            Ok(PacketOffsets {
                l3_offset,
                l4_offset,
                real_packet_len: Some(EthHdr::LEN + real_packet_len),
            })
        }
        EtherType::Ipv6 => {
            let ipv6hdr_ptr: *const Ipv6Hdr = ptr_at(packet, l3_offset)?;
            let ipv6hdr = unsafe { ptr::read_unaligned(ipv6hdr_ptr) };

            if ipv6hdr.version() != 6 {
                return Err(PacketParseError::UnknownIpProtocol);
            }

            let l4_offset = l3_offset + Ipv6Hdr::LEN;
            let payload_len = u16::from_be_bytes(ipv6hdr.payload_len) as usize;
            let real_packet_len = Ipv6Hdr::LEN + payload_len;

            if l4_offset > packet.len() || (l3_offset + real_packet_len) > packet.len() {
                return Err(PacketParseError::InvalidOffset);
            }

            Ok(PacketOffsets {
                l3_offset,
                l4_offset,
                real_packet_len: Some(EthHdr::LEN + real_packet_len),
            })
        }
        _ => {
            // Not IPv4 or IPv6, return default offsets
            Ok(PacketOffsets {
                l3_offset: 0,
                l4_offset: 0,
                real_packet_len: None,
            })
        }
    }
}

pub fn l3_proto(packet: &[u8]) -> Result<EtherType, PacketParseError> {
    let ethhdr_ptr: *const EthHdr = ptr_at(packet, 0)?;
    let ethhdr = unsafe { ptr::read_unaligned(ethhdr_ptr) };
    Ok(ethhdr.ether_type)
}

pub fn src_ip(packet: &[u8], l3_offset: usize) -> Result<IpAddr, PacketParseError> {
    match l3_proto(packet)? {
        EtherType::Ipv4 => {
            let ipv4hdr_ptr: *const Ipv4Hdr = ptr_at(packet, l3_offset)?;
            let ipv4hdr = unsafe { ptr::read_unaligned(ipv4hdr_ptr) };
            let src_addr = ipv4hdr.src_addr;
            Ok(IpAddr::V4(Ipv4Addr::from(src_addr)))
        }
        EtherType::Ipv6 => {
            let ipv6hdr_ptr: *const Ipv6Hdr = ptr_at(packet, l3_offset)?;
            let ipv6hdr = unsafe { ptr::read_unaligned(ipv6hdr_ptr) };
            let src_addr = ipv6hdr.src_addr;
            Ok(IpAddr::V6(Ipv6Addr::from(src_addr)))
        }
        _ => Err(PacketParseError::UnknownIpProtocol),
    }
}

pub fn dst_ip(packet: &[u8], l3_offset: usize) -> Result<IpAddr, PacketParseError> {
    match l3_proto(packet)? {
        EtherType::Ipv4 => {
            let ipv4hdr_ptr: *const Ipv4Hdr = ptr_at(packet, l3_offset)?;
            let ipv4hdr = unsafe { ptr::read_unaligned(ipv4hdr_ptr) };
            let dst_addr = ipv4hdr.dst_addr;
            Ok(IpAddr::V4(Ipv4Addr::from(dst_addr)))
        }
        EtherType::Ipv6 => {
            let ipv6hdr_ptr: *const Ipv6Hdr = ptr_at(packet, l3_offset)?;
            let ipv6hdr = unsafe { ptr::read_unaligned(ipv6hdr_ptr) };
            let dst_addr = ipv6hdr.dst_addr;
            Ok(IpAddr::V6(Ipv6Addr::from(dst_addr)))
        }
        _ => Err(PacketParseError::UnknownIpProtocol),
    }
}

pub fn l4_proto(packet: &[u8], l3_offset: usize) -> Result<IpProto, PacketParseError> {
    match l3_proto(packet)? {
        EtherType::Ipv4 => {
            let ipv4hdr_ptr: *const Ipv4Hdr = ptr_at(packet, l3_offset)?;
            let ipv4hdr = unsafe { ptr::read_unaligned(ipv4hdr_ptr) };
            Ok(ipv4hdr.proto)
        }
        EtherType::Ipv6 => {
            let ipv6hdr_ptr: *const Ipv6Hdr = ptr_at(packet, l3_offset)?;
            let ipv6hdr = unsafe { ptr::read_unaligned(ipv6hdr_ptr) };
            Ok(ipv6hdr.next_hdr)
        }
        _ => Err(PacketParseError::UnknownIpProtocol),
    }
}

pub fn src_port(
    packet: &[u8],
    l3_offset: usize,
    l4_offset: usize,
) -> Result<u16, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
            let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
            Ok(u16::from_be(tcphdr.source))
        }
        IpProto::Udp => {
            let udphdr_ptr: *const UdpHdr = ptr_at(packet, l4_offset)?;
            let udphdr = unsafe { ptr::read_unaligned(udphdr_ptr) };
            Ok(u16::from_be_bytes(udphdr.source))
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn dest_port(
    packet: &[u8],
    l3_offset: usize,
    l4_offset: usize,
) -> Result<u16, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
            let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
            Ok(u16::from_be(tcphdr.dest))
        }
        IpProto::Udp => {
            let udphdr_ptr: *const UdpHdr = ptr_at(packet, l4_offset)?;
            let udphdr = unsafe { ptr::read_unaligned(udphdr_ptr) };
            Ok(u16::from_be_bytes(udphdr.dest))
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn seq(packet: &[u8], l3_offset: usize, l4_offset: usize) -> Result<u32, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
            let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
            Ok(tcphdr.seq)
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn syn(packet: &[u8], l3_offset: usize, l4_offset: usize) -> Result<bool, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
            let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
            Ok(tcphdr.syn() != 0)
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn fin(packet: &[u8], l3_offset: usize, l4_offset: usize) -> Result<bool, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
            let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
            Ok(tcphdr.fin() != 0)
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn payload_len(
    packet: &[u8],
    l3_offset: usize,
    l4_offset: usize,
) -> Result<u32, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => {
            match l3_proto(packet)? {
                EtherType::Ipv4 => {
                    let ipv4hdr_ptr: *const Ipv4Hdr = ptr_at(packet, l3_offset)?;
                    let ipv4hdr = unsafe { ptr::read_unaligned(ipv4hdr_ptr) };
                    let total_len = u16::from_be_bytes(ipv4hdr.tot_len) as u32;
                    let ip_header_len = ipv4hdr.ihl() as u32 * 4;

                    let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
                    let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
                    let tcp_header_len = tcphdr.doff() as u32 * 4;

                    let payload_len = total_len - ip_header_len - tcp_header_len;
                    Ok(payload_len)
                }
                EtherType::Ipv6 => {
                    let ipv6hdr_ptr: *const Ipv6Hdr = ptr_at(packet, l3_offset)?;
                    let ipv6hdr = unsafe { ptr::read_unaligned(ipv6hdr_ptr) };
                    let payload_len = u16::from_be_bytes(ipv6hdr.payload_len) as u32;

                    let tcphdr_ptr: *const TcpHdr = ptr_at(packet, l4_offset)?;
                    let tcphdr = unsafe { ptr::read_unaligned(tcphdr_ptr) };
                    let tcp_header_len = tcphdr.doff() as u32 * 4;

                    // IPv6的payload_len不包括IPv6头，所以直接减去TCP头长度
                    let tcp_payload_len = payload_len - tcp_header_len;
                    Ok(tcp_payload_len)
                }
                _ => Err(PacketParseError::UnknownIpProtocol),
            }
        }
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn trans_proto(packet: &[u8], l3_offset: usize) -> Result<TransProto, PacketParseError> {
    match l4_proto(packet, l3_offset)? {
        IpProto::Tcp => Ok(TransProto::Tcp),
        IpProto::Udp => Ok(TransProto::Udp),
        IpProto::Icmp => Ok(TransProto::Icmp4),
        IpProto::Ipv6Icmp => Ok(TransProto::Icmp6),
        _ => Err(PacketParseError::UnknownTransportProtocol),
    }
}

pub fn hash_key(
    packet: &[u8],
    l3_offset: usize,
    l4_offset: usize,
) -> Result<PacketKey, PacketParseError> {
    let src_ip = src_ip(packet, l3_offset)?;
    let dst_ip = dst_ip(packet, l3_offset)?;
    let src_port = src_port(packet, l3_offset, l4_offset).unwrap_or(0);
    let dst_port = dest_port(packet, l3_offset, l4_offset).unwrap_or(0);
    let trans_proto = trans_proto(packet, l3_offset)?;

    if src_ip > dst_ip {
        Ok(PacketKey {
            addr1: src_ip,
            port1: src_port,
            addr2: dst_ip,
            port2: dst_port,
            trans_proto,
        })
    } else if src_ip < dst_ip {
        Ok(PacketKey {
            addr1: dst_ip,
            port1: dst_port,
            addr2: src_ip,
            port2: src_port,
            trans_proto,
        })
    } else if src_port >= dst_port {
        Ok(PacketKey {
            addr1: src_ip,
            port1: src_port,
            addr2: dst_ip,
            port2: dst_port,
            trans_proto,
        })
    } else {
        Ok(PacketKey {
            addr1: dst_ip,
            port1: dst_port,
            addr2: src_ip,
            port2: src_port,
            trans_proto,
        })
    }
}

pub fn hash_val<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

#[derive(Debug)]
pub enum StoreError {
    IoError(std::io::Error),
    InitError(String),
    FormatError(String),
    ReadError(String),
    WriteError(String),
    CliError(String),
    LockError(String),
    OpenError(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(err) => write!(f, "IO error: {err}"),
            StoreError::InitError(msg) => write!(f, "Init error: {msg}"),
            StoreError::FormatError(msg) => write!(f, "Format error: {msg}"),
            StoreError::ReadError(msg) => write!(f, "Read error: {msg}"),
            StoreError::WriteError(msg) => write!(f, "Write error: {msg}"),
            StoreError::CliError(msg) => write!(f, "Write error: {msg}"),
            StoreError::LockError(msg) => write!(f, "lock error: {msg}"),
            StoreError::OpenError(msg) => write!(f, "open error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        StoreError::IoError(err)
    }
}

impl From<String> for StoreError {
    fn from(err: String) -> Self {
        StoreError::InitError(err)
    }
}

impl From<StoreError> for io::Error {
    fn from(error: StoreError) -> io::Error {
        io::Error::other(error)
    }
}

#[derive(Debug)]
pub enum Msg {
    CoverChunk(PathBuf, u128),
}

pub fn ts_date(timestamp: u128) -> DateTime<Local> {
    let naive_datetime = DateTime::from_timestamp(
        (timestamp / 1_000_000_000).try_into().unwrap(),
        (timestamp % 1_000_000_000) as u32,
    );
    Local.from_utc_datetime(
        &naive_datetime
            .expect("Failed to convert to local time")
            .naive_utc(),
    )
}

pub fn date_ts(time: Option<NaiveDateTime>) -> Option<u128> {
    time.map(|t| {
        let datetime_local: DateTime<Local> = Local.from_local_datetime(&t).unwrap();
        datetime_local.timestamp_nanos_opt().map(|ts| ts as u128)
    })?
}

pub fn ts_timeval(timestamp: u128) -> timeval {
    let seconds = (timestamp / 1_000_000_000) as i64;
    let nanoseconds = (timestamp % 1_000_000_000) as i64;
    timeval {
        tv_sec: seconds,
        tv_usec: (nanoseconds * 1000) as _,
    }
}

pub fn timenow() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

pub fn date2dir(configure: &'static Configure, dir_id: u64, date: NaiveDateTime) -> PathBuf {
    let mut path = PathBuf::new();
    path.push(configure.main.store_path.clone());
    path.push(format!("{dir_id:03}"));
    path.push(format!("{:04}", date.year()));
    path.push(format!("{:02}", date.month()));
    path.push(format!("{:02}", date.day()));
    path.push(format!("{:02}", date.hour()));
    path.push(format!("{:02}", date.minute()));
    path
}
