#![allow (dead_code)]

use crate::packet::{Packet, PacketKey};
// use std::net::IpAddr;
use tmohash::TmoHash;

const MAX_TABLE_CAPACITY: usize = 1024;
const NODE_TIMEOUT: u128        = 10_000_000_000; // 10秒

#[derive(Debug, Clone, Copy)]
pub enum KeyDir {
    Addr1Client,
    Addr2Client,
    Unknown
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    C2s,
    S2c,
    Unknown
}

#[derive(Debug)]
pub struct FlowNode {
    pub key: PacketKey,
    // pub key_dir: KeyDir,
    pub last_time: u128,
    // pub relate_pkt_dir: Direction,
}

impl FlowNode {
    // fn new2(pkt: &Packet, now: u128) -> Self {
    //     let key = pkt.hash_key();
    //     let mut node = FlowNode {
    //         key,
    //         // key_dir: KeyDir::Unknown,
    //         last_time: now,
    //         // relate_pkt_dir: Direction::Unknown
    //     };
    //     node.update(pkt, now);
    //     node
    // }

    fn new(pkt_key: PacketKey, now: u128) -> Self {
        FlowNode {
            key: pkt_key,
            // key_dir: KeyDir::Unknown,
            last_time: now,
            // relate_pkt_dir: Direction::Unknown
        }
    }

    pub fn update(&self, _pkt: &Packet, _now: u128) {
        todo!()
    }

    pub fn streams_fin(&self) -> bool {
        todo!()
    }

    // fn client_ip(&self) -> Option<IpAddr> {
    //     match self.key_dir {
    //         KeyDir::Addr1Client => Some(self.key.addr1),
    //         KeyDir::Addr2Client => Some(self.key.addr2),
    //         KeyDir::Unknown => None
    //     }
    // }

    // fn client_port(&self) -> u16 {
    //     match self.key_dir {
    //         KeyDir::Addr1Client => self.key.port1,
    //         KeyDir::Addr2Client => self.key.port2,
    //         KeyDir::Unknown => 0
    //     }
    // }

    // fn server_ip(&self) -> Option<IpAddr> {
    //     match self.key_dir {
    //         KeyDir::Addr1Client => Some(self.key.addr2),
    //         KeyDir::Addr2Client => Some(self.key.addr1),
    //         KeyDir::Unknown => None
    //     }
    // }

    // fn server_port(&self) -> u16 {
    //     match self.key_dir {
    //         KeyDir::Addr1Client => self.key.port2,
    //         KeyDir::Addr2Client => self.key.port2,
    //         KeyDir::Unknown => 0
    //     }
    // }

    // pub fn update(&mut self, pkt: &Packet, now: u128) {
    //     self.last_time = now;
    //     // key_dir


    //     // pkt_dir
    //     match self.key_dir {
    //         KeyDir::Addr1Client => {

    //         }
    //         KeyDir::Addr2Client => {

    //         }
    //         KeyDir::Unknown => {
    //             self.relate_pkt_dir = Direction::Unknown;
    //         }
    //     }
    // }
}

pub struct Flow {
    table: TmoHash<PacketKey, FlowNode>
}

impl Flow {
    pub fn new() -> Self {
        Flow {table: TmoHash::new(MAX_TABLE_CAPACITY)}
    }

    pub fn contains_key(&self, key: &PacketKey) -> bool {
        self.table.contains_key(key)
    }

    // 返回插入节点的引用。如果已经存在，返回None
    fn insert(&mut self, pkt: &Packet, now: u128) -> Option<&FlowNode> {
        let key = pkt.hash_key();
        if self.contains_key(&key) {
            return None;
        }
        self.table.insert(key, FlowNode::new(key, now))
    }

    // 返回插入节点的可变引用。如果已经存在，返回None
    fn insert_mut(&mut self, pkt: &Packet, now: u128) -> Option<&mut FlowNode> {
        let key = pkt.hash_key();
        if self.contains_key(&key) {
            return None;
        }
        self.table.insert_mut(key, FlowNode::new(key, now))
    }

    // 返回packet所在节点的引用。如果不存在，返回None
    pub fn get(&self, pkt: &Packet) -> Option<&FlowNode> {
        let key = pkt.hash_key();
        self.table.get(&key)
    }

    // 返回node的引用。如果table中没有，新建node
    pub fn get_or_new(&mut self, pkt: &Packet, now: u128) -> Option<&FlowNode> {
        let key = pkt.hash_key();
        if self.contains_key(&key) {
            return self.get(pkt);
        }
        self.insert(pkt, now)
    }

    // 返回packet所在节点的可变引用。如果不存在，返回None
    pub fn get_mut(&mut self, pkt: &Packet) -> Option<&mut FlowNode> {
        let key = pkt.hash_key();
        self.table.get_mut(&key)
    }

    // 返回node的可变引用。如果table中没有，新建node
    pub fn get_mut_or_new(&mut self, pkt: &Packet, now: u128) -> Option<&mut FlowNode> {
        let key = pkt.hash_key();
        if self.contains_key(&key) {
            return self.get_mut(pkt);
        }
        self.insert_mut(pkt, now)
    }

    pub fn get_from_key(&self, key: &PacketKey) -> Option<&FlowNode> {
        self.table.get(key)
    }

    pub fn get_mut_from_key(&mut self, key: &PacketKey) -> Option<&mut FlowNode> {
        self.table.get_mut(key)
    }

    // 删除一个节点
    pub fn remove(&mut self, key: &PacketKey) {
        self.table.remove(key)
    }

    pub fn capacity(&self) -> usize {
        self.table.capacity()
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.table.is_full()
    }

    pub fn clear(&mut self) {
        self.table.clear();
    }

    pub fn timeout(&mut self, now: u128) {
        self.table.timeout(|_key, node| now - node.last_time >= NODE_TIMEOUT)
    }
}
