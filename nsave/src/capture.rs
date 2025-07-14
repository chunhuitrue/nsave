use crate::af_xdp::*;
use crate::common::*;
use crate::pcap::*;
use anyhow::Result;
use network_types::{eth::EtherType, ip::IpProto};
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

macro_rules! impl_pkt_methods {
    ($self:ident, $method:ident, $($args:ident),*) => {
        match $self {
            Packet::AfXdp(pkt) => pkt.$method($($args),*),
            Packet::Pcap(pkt) => pkt.$method($($args),*),
        }
    };
}

#[derive(Clone)]
pub enum Packet {
    AfXdp(AfXdpPacket),
    Pcap(Arc<PcapPacket>),
}

impl Packet {
    pub fn as_af_xdp(&self) -> Option<&AfXdpPacket> {
        match self {
            Packet::AfXdp(pkt) => Some(pkt),
            _ => None,
        }
    }

    pub fn as_pcap(&self) -> Option<&Arc<PcapPacket>> {
        match self {
            Packet::Pcap(pkt) => Some(pkt),
            _ => None,
        }
    }

    pub fn frame(&self) -> &[u8] {
        impl_pkt_methods!(self, frame,)
    }

    pub fn frame_size(&self) -> usize {
        impl_pkt_methods!(self, frame_size,)
    }

    pub fn headroom(&self) -> &[u8] {
        impl_pkt_methods!(self, headroom,)
    }

    pub fn headroom_size(&self) -> usize {
        impl_pkt_methods!(self, headroom_size,)
    }

    pub fn timestamp(&self) -> u128 {
        impl_pkt_methods!(self, timestamp,)
    }

    pub fn packet(&self) -> &[u8] {
        impl_pkt_methods!(self, packet,)
    }

    pub fn packet_len(&self) -> usize {
        impl_pkt_methods!(self, packet_len,)
    }

    pub fn as_bytes(&self) -> &[u8] {
        impl_pkt_methods!(self, as_bytes,)
    }

    pub fn decode_ok(&mut self) -> bool {
        impl_pkt_methods!(self, decode_ok,)
    }

    pub fn l3_proto(&self) -> Result<EtherType, PacketParseError> {
        impl_pkt_methods!(self, l3_proto,)
    }

    pub fn src_ip(&self) -> Result<IpAddr, PacketParseError> {
        impl_pkt_methods!(self, src_ip,)
    }

    pub fn dst_ip(&self) -> Result<IpAddr, PacketParseError> {
        impl_pkt_methods!(self, dst_ip,)
    }

    pub fn l4_proto(&self) -> Result<IpProto, PacketParseError> {
        impl_pkt_methods!(self, l4_proto,)
    }

    pub fn src_port(&self) -> Result<u16, PacketParseError> {
        impl_pkt_methods!(self, src_port,)
    }

    pub fn dst_port(&self) -> Result<u16, PacketParseError> {
        impl_pkt_methods!(self, dest_port,)
    }

    pub fn seq(&self) -> Result<u32, PacketParseError> {
        impl_pkt_methods!(self, seq,)
    }

    pub fn syn(&self) -> Result<bool, PacketParseError> {
        impl_pkt_methods!(self, syn,)
    }

    pub fn fin(&self) -> Result<bool, PacketParseError> {
        impl_pkt_methods!(self, fin,)
    }

    pub fn payload_len(&self) -> Result<u32, PacketParseError> {
        impl_pkt_methods!(self, payload_len,)
    }

    pub fn hash_value(&self) -> u64 {
        impl_pkt_methods!(self, hash_value,)
    }

    pub fn serialize_size(&self) -> u32 {
        impl_pkt_methods!(self, serialize_size,)
    }

    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        impl_pkt_methods!(self, serialize_into, writer)
    }

    pub fn hash_key(&self) -> PacketKey {
        impl_pkt_methods!(self, hash_key,)
    }
}

pub enum CaptureInstance {
    AfXdp(Box<AfXdp>),
    Pcap(Pcap),
}

impl CaptureInstance {
    pub fn acquire_packets<F>(&mut self, mut packet_handler: F) -> Result<()>
    where
        F: FnMut(Packet),
    {
        match self {
            CaptureInstance::AfXdp(af_xdp) => af_xdp.acquire_packets(|packet| {
                packet_handler(Packet::AfXdp(packet));
            }),
            CaptureInstance::Pcap(pcap) => pcap.acquire_packets(|packet| {
                packet_handler(Packet::Pcap(packet));
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CaptureMode {
    AfXdp,
    PcapLive,
    PcapFile,
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub mode: CaptureMode,
    pub interface: String,
    pub af_xdp_config: Option<AfXdpConfig>,
    pub pcap_config: Option<PcapConfig>,
}

impl CaptureConfig {
    pub fn af_xdp(interface: String) -> Self {
        Self {
            mode: CaptureMode::AfXdp,
            interface,
            af_xdp_config: Some(AfXdpConfig::default()),
            pcap_config: None,
        }
    }

    pub fn pcap_live(interface: String) -> Self {
        Self {
            mode: CaptureMode::PcapLive,
            interface,
            af_xdp_config: None,
            pcap_config: Some(PcapConfig::default()),
        }
    }

    pub fn pcap_file(file_path: String) -> Self {
        Self {
            mode: CaptureMode::PcapFile,
            interface: String::new(),
            af_xdp_config: None,
            pcap_config: Some(PcapConfig {
                pcap_file: Some(file_path),
                ..Default::default()
            }),
        }
    }

    pub fn with_af_xdp_config(mut self, config: AfXdpConfig) -> Self {
        self.af_xdp_config = Some(config);
        self
    }

    pub fn with_pcap_config(mut self, config: PcapConfig) -> Self {
        self.pcap_config = Some(config);
        self
    }

    pub fn with_pcap_filter<S: Into<String>>(mut self, filter: S) -> Result<Self> {
        match &self.mode {
            CaptureMode::PcapLive | CaptureMode::PcapFile => {
                let mut pcap_config = self.pcap_config.unwrap_or_default();
                pcap_config.filter = Some(filter.into());
                self.pcap_config = Some(pcap_config);
                Ok(self)
            }
            CaptureMode::AfXdp => Err(anyhow::anyhow!("Filter is not supported for AF_XDP mode")),
        }
    }
}

pub fn create_capture(config: &CaptureConfig) -> Result<CaptureInstance> {
    match &config.mode {
        CaptureMode::AfXdp => {
            let af_xdp_config = config.af_xdp_config.clone().unwrap_or_default();
            let af_xdp = AfXdp::new_with_config(&config.interface, af_xdp_config)?;
            Ok(CaptureInstance::AfXdp(Box::new(af_xdp)))
        }
        CaptureMode::PcapLive => {
            let pcap_config = config.pcap_config.clone().unwrap_or_default();
            let pcap = Pcap::new_with_config(&config.interface, pcap_config)?;
            Ok(CaptureInstance::Pcap(pcap))
        }
        CaptureMode::PcapFile => {
            let pcap_config = config.pcap_config.clone().unwrap_or_default();
            let pcap = Pcap::new_with_config("", pcap_config)?;
            Ok(CaptureInstance::Pcap(pcap))
        }
    }
}
