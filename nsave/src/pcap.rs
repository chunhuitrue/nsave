use crate::common::*;
use anyhow::{Result, anyhow};
use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use network_types::{eth::EtherType, ip::IpProto};
use pcap::{Activated, Capture as PcapCap, Device};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

pub struct Pcap {
    cap: PcapCap<dyn Activated>,
    recycle_rx: Receiver<Vec<u8>>,
    recycle_tx: Sender<Vec<u8>>,
    buffer_pool: Vec<Vec<u8>>,
}

impl Pcap {
    pub fn new(iface: &str) -> Result<Self> {
        Self::new_with_config(iface, PcapConfig::default())
    }

    pub fn new_with_config(iface: &str, config: PcapConfig) -> Result<Self> {
        let mut cap: PcapCap<dyn Activated> = if let Some(pcap_file) = &config.pcap_file {
            pcap::Capture::from_file(pcap_file)
                .map_err(|e| anyhow!("pcap from_file error: {}", e))?
                .into()
        } else {
            let device = Self::get_device(Some(&iface.to_string()))?;
            pcap::Capture::from_device(device)
                .map_err(|e| anyhow!("pcap from_device error: {}", e))?
                .promisc(true)
                .snaplen(config.buffer_size as i32)
                .immediate_mode(true)
                .open()
                .map_err(|e| anyhow!("pcap open error: {}", e))?
                .into()
        };

        if config.filter.is_some() {
            let res = cap.filter(config.filter.as_ref().unwrap(), true);
            if res.is_err() {
                return Err(anyhow!("filter set error"));
            }
        }

        let (recycle_tx, recycle_rx) = bounded(config.pkt_recycle_channel_size);

        let mut buffer_pool = Vec::with_capacity(config.buffer_pool_size);
        for _ in 0..config.buffer_pool_size {
            buffer_pool.push(vec![0u8; config.buffer_size]);
        }

        Ok(Self {
            cap,
            recycle_rx,
            recycle_tx,
            buffer_pool,
        })
    }

    fn get_device(interface: Option<&String>) -> Result<Device> {
        if let Some(name) = interface {
            for dev in pcap::Device::list().map_err(|e| anyhow!("pcap list error: {}", e))? {
                if dev.name == *name {
                    return Ok(dev);
                }
            }
            Err(anyhow!("device not found"))
        } else {
            let dev = pcap::Device::lookup()
                .map_err(|e| anyhow!("pcap lookup error: {}", e))?
                .ok_or_else(|| anyhow!("no device available"))?;
            Ok(dev)
        }
    }

    pub fn acquire_packets<F>(&mut self, mut packet_handler: F) -> Result<()>
    where
        F: FnMut(Arc<PcapPacket>),
    {
        self.recycle_packets()?;

        match self.cap.next_packet() {
            Ok(pcap_pkt) => {
                if let Some(mut buffer) = self.buffer_pool.pop() {
                    let timestamp = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();
                    buffer.clear();
                    buffer.extend_from_slice(pcap_pkt.data);
                    let packet =
                        Arc::new(PcapPacket::new(buffer, timestamp, self.recycle_tx.clone()));
                    packet_handler(packet);
                }
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    fn recycle_packets(&mut self) -> Result<()> {
        loop {
            match self.recycle_rx.try_recv() {
                Ok(data) => self.buffer_pool.push(data),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(anyhow!("recycle channel disconnected"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PcapConfig {
    pub filter: Option<String>,
    pub pcap_file: Option<String>,
    pub pkt_recycle_channel_size: usize,
    pub buffer_pool_size: usize,
    pub buffer_size: usize,
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            filter: None,
            pcap_file: None,
            pkt_recycle_channel_size: 1024,
            buffer_pool_size: 1024,
            buffer_size: 2048,
        }
    }
}

pub struct PcapBuilder {
    config: PcapConfig,
}

impl PcapBuilder {
    pub fn new() -> Self {
        Self {
            config: PcapConfig::default(),
        }
    }

    pub fn filter<S: Into<String>>(mut self, filter: S) -> Self {
        self.config.filter = Some(filter.into());
        self
    }

    pub fn pcap_file<S: Into<String>>(mut self, file_path: S) -> Self {
        self.config.pcap_file = Some(file_path.into());
        self
    }

    pub fn recycle_channel_size(mut self, size: usize) -> Self {
        self.config.pkt_recycle_channel_size = size;
        self
    }

    pub fn buff_pool_size(mut self, size: usize) -> Self {
        self.config.buffer_pool_size = size;
        self
    }

    pub fn buff_size(mut self, size: usize) -> Self {
        self.config.buffer_size = size;
        self
    }

    pub fn build(self, iface: &str) -> Result<Pcap> {
        Pcap::new_with_config(iface, self.config)
    }
}

impl Default for PcapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PcapPacket {
    timestamp: u128,
    data: Vec<u8>,
    recycle_tx: Sender<Vec<u8>>,
    l3_offset: usize, // ip头相对于数据包开始的偏移
    l4_offset: usize, // tcp/udp/icpm相对于数据包开始的偏移
}

impl PcapPacket {
    pub fn new(data: Vec<u8>, ts: u128, recycle_tx: Sender<Vec<u8>>) -> Self {
        let mut s = Self {
            timestamp: ts,
            data,
            recycle_tx,
            l3_offset: 0,
            l4_offset: 0,
        };
        let _ = s.decode().ok();
        s
    }

    pub fn frame(&self) -> &[u8] {
        &[]
    }

    pub fn frame_size(&self) -> usize {
        0
    }

    pub fn headroom(&self) -> &[u8] {
        &[]
    }

    pub fn headroom_size(&self) -> usize {
        0
    }

    pub fn timestamp(&self) -> u128 {
        self.timestamp
    }

    pub fn packet(&self) -> &[u8] {
        &self.data
    }

    pub fn packet_len(&self) -> usize {
        self.data.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn decode(&mut self) -> Result<(), PacketParseError> {
        let offsets = decode_packet(self.packet())?;

        self.l3_offset = offsets.l3_offset;
        self.l4_offset = offsets.l4_offset;
        Ok(())
    }

    pub fn decode_ok(&self) -> bool {
        self.l4_offset != 0
    }

    pub fn l3_proto(&self) -> Result<EtherType, PacketParseError> {
        l3_proto(self.packet())
    }

    pub fn src_ip(&self) -> Result<IpAddr, PacketParseError> {
        src_ip(self.packet(), self.l3_offset)
    }

    pub fn dst_ip(&self) -> Result<IpAddr, PacketParseError> {
        dst_ip(self.packet(), self.l3_offset)
    }

    pub fn l4_proto(&self) -> Result<IpProto, PacketParseError> {
        l4_proto(self.packet(), self.l3_offset)
    }

    pub fn src_port(&self) -> Result<u16, PacketParseError> {
        src_port(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn dest_port(&self) -> Result<u16, PacketParseError> {
        dest_port(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn seq(&self) -> Result<u32, PacketParseError> {
        seq(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn syn(&self) -> Result<bool, PacketParseError> {
        syn(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn fin(&self) -> Result<bool, PacketParseError> {
        fin(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn payload_len(&self) -> Result<u32, PacketParseError> {
        payload_len(self.packet(), self.l3_offset, self.l4_offset)
    }

    pub fn hash_value(&self) -> u64 {
        hash_val(self)
    }

    // 按照StorePacket格式写入
    pub fn serialize_size(&self) -> u32 {
        22 + self.packet_len() as u32
    }

    // 按照StorePacket格式写入
    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        let next_offset: u32 = 0;
        writer.write_all(&next_offset.to_le_bytes())?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&((self.packet_len() as u16).to_le_bytes()))?;
        writer.write_all(self.packet())?;
        Ok(())
    }

    pub fn hash_key(&self) -> PacketKey {
        hash_key(self.packet(), self.l3_offset, self.l4_offset).unwrap_or(PacketKey {
            addr1: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
            port1: 0,
            addr2: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
            port2: 0,
            trans_proto: TransProto::Icmp6,
        })
    }
}

impl Drop for PcapPacket {
    fn drop(&mut self) {
        let _ = self.recycle_tx.send(std::mem::take(&mut self.data));
    }
}

impl Hash for PcapPacket {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_key().hash(state)
    }
}
