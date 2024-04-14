#![allow(dead_code)]

use crate::common::*;
use etherparse::{Ethernet2Header, IpHeader, PacketHeaders, TransportHeader, VlanHeader};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::ops::Deref;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct PktHeader {
    link: Option<Ethernet2Header>,
    vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    transport: Option<TransportHeader>,
    payload_offset: usize,
    payload_len: usize,
}

unsafe impl Send for PktHeader {}
unsafe impl Sync for PktHeader {}

pub enum PacketError {
    DecodeErr,
}

#[derive(Eq, PartialEq, Clone)]
pub struct Packet {
    pub timestamp: u128,
    pub header: RefCell<Option<PktHeader>>,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(data: Vec<u8>, ts: u128) -> Self {
        Packet {
            timestamp: ts,
            data,
            header: RefCell::new(None),
        }
    }

    pub fn decode(&self) -> Result<(), PacketError> {
        match PacketHeaders::from_ethernet_slice(self) {
            Ok(headers) => {
                if headers.ip.is_none() || headers.transport.is_none() {
                    return Err(PacketError::DecodeErr);
                }

                self.header.replace(Some(PktHeader {
                    link: headers.link,
                    vlan: headers.vlan,
                    ip: headers.ip,
                    transport: headers.transport,
                    payload_offset: headers.payload.as_ptr() as usize - self.data.as_ptr() as usize,
                    payload_len: self.data.len()
                        - (headers.payload.as_ptr() as usize - self.data.as_ptr() as usize),
                }));
                Ok(())
            }
            Err(_) => Err(PacketError::DecodeErr),
        }
    }

    pub fn sport(&self) -> u16 {
        match &self.header.borrow().as_ref().unwrap().transport {
            Some(TransportHeader::Udp(udph)) => udph.source_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.source_port,
            _ => 0,
        }
    }

    pub fn dport(&self) -> u16 {
        match &self.header.borrow().as_ref().unwrap().transport {
            Some(TransportHeader::Udp(udph)) => udph.destination_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.destination_port,
            _ => 0,
        }
    }

    pub fn seq(&self) -> u32 {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.sequence_number
        } else {
            0
        }
    }

    pub fn syn(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.syn
        } else {
            false
        }
    }

    pub fn fin(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.fin
        } else {
            false
        }
    }

    pub fn payload(&self) -> &[u8] {
        let offset = self.header.borrow().as_ref().unwrap().payload_offset;
        let len = self.header.borrow().as_ref().unwrap().payload_len;
        &self.data[offset..offset + len]
    }

    pub fn payload_len(&self) -> u32 {
        self.header
            .borrow()
            .as_ref()
            .unwrap()
            .payload_len
            .try_into()
            .unwrap()
    }

    pub fn trans_proto(&self) -> TransProto {
        match self.header.borrow().as_ref().unwrap().transport {
            Some(TransportHeader::Udp(_)) => TransProto::Udp,
            Some(TransportHeader::Tcp(_)) => TransProto::Tcp,
            Some(TransportHeader::Icmpv4(_)) => TransProto::Icmp4,
            Some(TransportHeader::Icmpv6(_)) => TransProto::Icmp6,
            None => panic!("unknown transport protocol."),
        }
    }

    pub fn hash_key(&self) -> PacketKey {
        match &self.header.borrow().as_ref().unwrap().ip {
            Some(IpHeader::Version4(ipv4h, _)) => {
                if ipv4h.source > ipv4h.destination {
                    PacketKey {
                        addr1: ipv4h.source.into(),
                        port1: self.sport(),
                        addr2: ipv4h.destination.into(),
                        port2: self.dport(),
                        trans_proto: self.trans_proto(),
                    }
                } else if ipv4h.source < ipv4h.destination {
                    PacketKey {
                        addr1: ipv4h.destination.into(),
                        port1: self.dport(),
                        addr2: ipv4h.source.into(),
                        port2: self.sport(),
                        trans_proto: self.trans_proto(),
                    }
                } else if self.sport() >= self.dport() {
                    PacketKey {
                        addr1: ipv4h.source.into(),
                        port1: self.sport(),
                        addr2: ipv4h.destination.into(),
                        port2: self.dport(),
                        trans_proto: self.trans_proto(),
                    }
                } else {
                    PacketKey {
                        addr1: ipv4h.destination.into(),
                        port1: self.dport(),
                        addr2: ipv4h.source.into(),
                        port2: self.sport(),
                        trans_proto: self.trans_proto(),
                    }
                }
            }
            Some(IpHeader::Version6(ipv6h, _)) => {
                if ipv6h.source > ipv6h.destination {
                    PacketKey {
                        addr1: ipv6h.source.into(),
                        port1: self.sport(),
                        addr2: ipv6h.destination.into(),
                        port2: self.dport(),
                        trans_proto: self.trans_proto(),
                    }
                } else if ipv6h.source < ipv6h.destination {
                    PacketKey {
                        addr1: ipv6h.destination.into(),
                        port1: self.dport(),
                        addr2: ipv6h.source.into(),
                        port2: self.sport(),
                        trans_proto: self.trans_proto(),
                    }
                } else if self.sport() >= self.dport() {
                    PacketKey {
                        addr1: ipv6h.source.into(),
                        port1: self.sport(),
                        addr2: ipv6h.destination.into(),
                        port2: self.dport(),
                        trans_proto: self.trans_proto(),
                    }
                } else {
                    PacketKey {
                        addr1: ipv6h.destination.into(),
                        port1: self.dport(),
                        addr2: ipv6h.source.into(),
                        port2: self.sport(),
                        trans_proto: self.trans_proto(),
                    }
                }
            }
            None => PacketKey {
                addr1: Ipv4Addr::new(0, 0, 0, 0).into(),
                port1: 0,
                addr2: Ipv4Addr::new(0, 0, 0, 0).into(),
                port2: 0,
                trans_proto: TransProto::Icmp6,
            },
        }
    }

    pub fn hash_value(&self) -> u64 {
        hash_val(self)
    }

    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        let next_offset: u32 = 0;
        writer.write_all(&next_offset.to_le_bytes())?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&((self.data.len() as u16).to_le_bytes()))?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    pub fn serialize_size(&self) -> u32 {
        22 + self.data.len() as u32
    }
}

impl Deref for Packet {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("timestamp", &self.timestamp)
            .field("header", &self.header)
            .field("data", &self.data)
            .finish()
    }
}

unsafe impl Send for Packet {}
unsafe impl Sync for Packet {}

impl Hash for Packet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_key().hash(state)
    }
}

fn hash_val<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::*;

    #[test]
    fn test_decode() {
        let pkt = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        let _ = pkt.decode();

        if let Some(IpHeader::Version4(ipv4h, _)) = &pkt.header.borrow().as_ref().unwrap().ip {
            assert_eq!(
                Ipv4Addr::new(1, 1, 1, 1),
                <[u8; 4] as std::convert::Into<IpAddr>>::into(ipv4h.source)
            );
            assert_eq!(
                Ipv4Addr::new(2, 2, 2, 2),
                <[u8; 4] as std::convert::Into<IpAddr>>::into(ipv4h.destination)
            );
        }
        assert_eq!(TransProto::Tcp, pkt.trans_proto());
        assert_eq!(1, pkt.sport());
        assert_eq!(2, pkt.dport());
        assert!(!pkt.syn());
        assert_eq!(1234, pkt.seq());
        assert!(pkt.fin());
        assert_eq!(10, pkt.payload_len());
        assert_eq!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], pkt.payload());
    }

    #[test]
    fn test_key() {
        let pkt = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        let _ = pkt.decode();
        let key = PacketKey {
            addr1: Ipv4Addr::new(2, 2, 2, 2).into(),
            port1: 2,
            addr2: Ipv4Addr::new(1, 1, 1, 1).into(),
            port2: 1,
            trans_proto: TransProto::Tcp,
        };
        assert_eq!(key, pkt.hash_key());

        let pkt = build_tcp([1, 1, 1, 1], [1, 1, 1, 1], 1, 2);
        let _ = pkt.decode();
        let key = PacketKey {
            addr1: Ipv4Addr::new(1, 1, 1, 1).into(),
            port1: 2,
            addr2: Ipv4Addr::new(1, 1, 1, 1).into(),
            port2: 1,
            trans_proto: TransProto::Tcp,
        };
        assert_eq!(key, pkt.hash_key());

        let pkt = build_tcp([1, 1, 1, 1], [1, 1, 1, 1], 1, 1);
        let _ = pkt.decode();
        let key = PacketKey {
            addr1: Ipv4Addr::new(1, 1, 1, 1).into(),
            port1: 1,
            addr2: Ipv4Addr::new(1, 1, 1, 1).into(),
            port2: 1,
            trans_proto: TransProto::Tcp,
        };
        assert_eq!(key, pkt.hash_key());
    }

    #[test]
    fn test_hash() {
        let pkt_c2s = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        let _ = pkt_c2s.decode();
        let pkt_s2c = build_tcp([2, 2, 2, 2], [1, 1, 1, 1], 2, 1);
        let _ = pkt_s2c.decode();
        let pkt_other = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 3);
        let _ = pkt_other.decode();

        assert_eq!(pkt_c2s.hash_key(), pkt_s2c.hash_key());
        assert_eq!(hash_val(&pkt_c2s), hash_val(&pkt_s2c));
        assert_ne!(hash_val(&pkt_c2s), hash_val(&pkt_other));
    }

    fn build_tcp(sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16) -> Packet {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        .ipv4(
            sip, //source ip
            dip, //desitionation ip
            20,
        ) //time to life
        .tcp(
            sport, //source port
            dport, //desitnation port
            1234,  //sequence number
            1024,
        ) //window size
        //set additional tcp header fields
        .ns() //set the ns flag
        //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
        .fin()
        .ack(123) //ack flag + the ack number
        .urg(23) //urg flag + urgent pointer
        .options(&[
            TcpOptionElement::Noop,
            TcpOptionElement::MaximumSegmentSize(1234),
        ])
        .unwrap();

        //payload of the tcp packet
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        //serialize
        //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        builder.write(&mut result, &payload).unwrap();
        println!("result len:{}", result.len());

        let pkt = Packet::new(result, 1);
        let _ = pkt.decode();
        pkt
    }
}
