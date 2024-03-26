#![allow(dead_code)]

use crate::packet::{Packet, PacketKey, TransProto};
use etherparse::IpHeader;
use std::net::IpAddr;
use tmohash::TmoHash;

const MAX_TABLE_CAPACITY: usize = 1024;
const NODE_TIMEOUT: u128 = 10_000_000_000; // 10
const MAX_SEQ_GAP: usize = 8;

#[derive(Debug)]
pub struct FlowNode {
    pub key: PacketKey,
    pub start_time: u128,
    pub last_time: u128,
    seq_strm1: SeqStream,
    seq_strm2: SeqStream,
}

impl FlowNode {
    fn new(key: PacketKey, now: u128) -> Self {
        FlowNode {
            key,
            start_time: now,
            last_time: now,
            seq_strm1: SeqStream::new(),
            seq_strm2: SeqStream::new(),
        }
    }

    pub fn update(&mut self, pkt: &Packet, now: u128) {
        self.last_time = now;
        if pkt.trans_proto() == TransProto::Tcp {
            match &pkt.header.borrow().as_ref().unwrap().ip {
                Some(IpHeader::Version4(ipv4h, _)) => {
                    if self.key.addr1 == <[u8; 4] as std::convert::Into<IpAddr>>::into(ipv4h.source)
                        && self.key.port1 == pkt.sport()
                    {
                        self.seq_strm1.update(pkt);
                    } else if self.key.addr2
                        == <[u8; 4] as std::convert::Into<IpAddr>>::into(ipv4h.source)
                        && self.key.port2 == pkt.sport()
                    {
                        self.seq_strm2.update(pkt);
                    }
                }
                Some(IpHeader::Version6(ipv6h, _)) => {
                    if self.key.addr1
                        == <[u8; 16] as std::convert::Into<IpAddr>>::into(ipv6h.source)
                        && self.key.port1 == pkt.sport()
                    {
                        self.seq_strm1.update(pkt);
                    } else if self.key.addr2
                        == <[u8; 16] as std::convert::Into<IpAddr>>::into(ipv6h.source)
                        && self.key.port2 == pkt.sport()
                    {
                        self.seq_strm2.update(pkt);
                    }
                }
                None => {}
            }
        }
    }

    pub fn is_fin(&self) -> bool {
        self.seq_strm1.is_fin() && self.seq_strm2.is_fin()
    }
}

#[derive(Debug)]
struct SeqSeg {
    start: u32,
    next: u32,
}

#[derive(Debug)]
struct SeqStream {
    segment: Vec<SeqSeg>,
    fin: bool,
}

impl SeqStream {
    fn new() -> Self {
        SeqStream {
            segment: Vec::with_capacity(MAX_SEQ_GAP),
            fin: false,
        }
    }

    fn update(&mut self, pkt: &Packet) {
        if self.segment.len() > MAX_SEQ_GAP {
            return;
        }

        if pkt.fin() {
            self.fin = true
        }

        let new_seg = if pkt.syn() && pkt.payload_len() == 0 {
            SeqSeg {
                start: pkt.seq(),
                next: pkt.seq() + 1,
            }
        } else {
            SeqSeg {
                start: pkt.seq(),
                next: pkt.seq() + pkt.payload_len(),
            }
        };

        if self.segment.is_empty() {
            self.segment.push(new_seg);
            return;
        }

        // case 1
        // vec:                  start,next  start,next
        // new_seg: start,next
        if new_seg.next < self.segment[0].start {
            self.segment.insert(0, new_seg);
            return;
        }

        // case 2
        // vec:           start,next  start,next
        // new_seg: start,next
        if new_seg.next == self.segment[0].start {
            self.segment[0].start = new_seg.start;
            return;
        }

        // case 3
        // vec:     start,next  start,next
        // new_seg:                   start,next
        if new_seg.start == self.segment[self.segment.len() - 1].next {
            let last_index = self.segment.len() - 1;
            self.segment[last_index].next = new_seg.next;
            return;
        }

        // case 4
        // vec:     start,next  start,next
        // new_seg:                          start,next
        if new_seg.start > self.segment[self.segment.len() - 1].next {
            self.segment.push(new_seg);
            return;
        }

        // 段之间段空洞情况
        let mut i = 0;
        while i < self.segment.len() - 1 {
            // case 5
            // vec:     start,next  start,next
            // new_seg:       start,next
            if new_seg.start == self.segment[i].next && new_seg.next == self.segment[i + 1].start {
                self.segment[i].next = self.segment[i + 1].next;
                self.segment.remove(i + 1);
                return;
            }

            // case 6
            // vec:     start,next        start,next
            // new_seg:       start,next
            if new_seg.start == self.segment[i].next && new_seg.next < self.segment[i + 1].start {
                self.segment[i].next = new_seg.next;
                return;
            }

            // case 7
            // vec:     start,next        start,next
            // new_seg:             start,next
            if new_seg.start > self.segment[i].next && new_seg.next == self.segment[i + 1].start {
                self.segment[i + 1].start = new_seg.start;
                return;
            }

            // case 8
            // vec:     start,next              start,next
            // new_seg:             start,next
            if new_seg.start > self.segment[i].next && new_seg.next < self.segment[i + 1].start {
                self.segment.insert(i + 1, new_seg);
                return;
            }

            i += 1;
        }
    }

    fn is_fin(&self) -> bool {
        self.fin && self.segment.len() == 1
    }
}

pub struct Flow {
    table: TmoHash<PacketKey, FlowNode>,
}

impl Flow {
    pub fn new() -> Self {
        Flow {
            table: TmoHash::new(MAX_TABLE_CAPACITY),
        }
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

    pub fn timeout<F>(&mut self, now: u128, fun: F)
    where
        F: Fn(&FlowNode),
    {
        self.table.timeout(|_key, node| {
            if now - node.last_time >= NODE_TIMEOUT {
                fun(node);
                true
            } else {
                false
            }
        })
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::*;

    #[test]
    fn test_seqstream_new() {
        let seq_stm = SeqStream::new();
        assert_eq!(seq_stm.segment.len(), 0);
        assert!(!seq_stm.fin);
    }

    #[test]
    fn test_seqstream_fin() {
        let mut seq_stm = SeqStream::new();
        let pkt_fin = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 10, true);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_fin);
        assert!(seq_stm.fin);
        assert_eq!(1, seq_stm.segment.len());
        assert!(seq_stm.is_fin());
    }

    // case 1.
    #[test]
    fn test_seqstream_pre() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt3);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(22, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);

        seq_stm.update(&pkt1);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt2);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(2, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);

        seq_stm.update(&pkt_syn);
        seq_stm.update(&pkt_fin);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert!(seq_stm.is_fin());
        assert_eq!(32, seq_stm.segment[0].next);
    }

    // case 2.
    #[test]
    fn test_seqstream_case2() {
        let mut seq_stm = SeqStream::new();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();

        seq_stm.update(&pkt3);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(22, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);

        seq_stm.update(&pkt2);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(12, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);

        seq_stm.update(&pkt1);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(2, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);
    }

    // case 3. syn, 三个连续，最后一个空fin
    #[test]
    fn test_seqstream_normal() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_syn);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);

        seq_stm.update(&pkt1);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(12, seq_stm.segment[0].next);

        seq_stm.update(&pkt2);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(22, seq_stm.segment[0].next);

        seq_stm.update(&pkt3);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(32, seq_stm.segment[0].next);

        seq_stm.update(&pkt_fin);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert!(seq_stm.is_fin());
        assert_eq!(32, seq_stm.segment[0].next);
    }

    // case 4
    #[test]
    fn test_seqstream_case4() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt4 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32, false);
        let _ = pkt4.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 42);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_syn);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);

        seq_stm.update(&pkt2);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt4);
        assert_eq!(3, seq_stm.segment.len());

        seq_stm.update(&pkt1);
        seq_stm.update(&pkt3);
        seq_stm.update(&pkt_fin);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(42, seq_stm.segment[0].next);
    }

    // case 5 见case 1

    // case 6
    #[test]
    fn test_seqstream_case6() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt4 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32, false);
        let _ = pkt4.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 42);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_syn);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);

        seq_stm.update(&pkt4);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt1);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt2);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt3);
        assert_eq!(1, seq_stm.segment.len());

        seq_stm.update(&pkt_fin);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(42, seq_stm.segment[0].next);
    }

    // case 7
    #[test]
    fn test_seqstream_case7() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt4 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32, false);
        let _ = pkt4.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 42);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_syn);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);

        seq_stm.update(&pkt_fin);
        assert_eq!(2, seq_stm.segment.len());
        assert!(!seq_stm.is_fin());

        seq_stm.update(&pkt4);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt3);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt2);
        assert_eq!(2, seq_stm.segment.len());

        seq_stm.update(&pkt1);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(42, seq_stm.segment[0].next);
    }

    // case 8
    #[test]
    fn test_seqstream_case8() {
        let mut seq_stm = SeqStream::new();
        let pkt_syn = build_syn([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 1);
        let _ = pkt_syn.decode();
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let pkt3 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 22, false);
        let _ = pkt3.decode();
        let pkt4 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 32, false);
        let _ = pkt4.decode();
        let pkt_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 42);
        let _ = pkt_fin.decode();

        seq_stm.update(&pkt_syn);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);

        seq_stm.update(&pkt_fin);
        assert!(!seq_stm.is_fin());
        assert_eq!(2, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);
        assert_eq!(42, seq_stm.segment[1].start);
        assert_eq!(42, seq_stm.segment[1].next);

        dbg!("before update pkt2. segment: {}", &seq_stm.segment);
        seq_stm.update(&pkt2);
        dbg!("update pkt2. segment: {}", &seq_stm.segment);
        assert_eq!(3, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);
        assert_eq!(12, seq_stm.segment[1].start);
        assert_eq!(22, seq_stm.segment[1].next);
        assert_eq!(42, seq_stm.segment[2].start);
        assert_eq!(42, seq_stm.segment[2].next);

        seq_stm.update(&pkt4);
        assert_eq!(3, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(2, seq_stm.segment[0].next);
        assert_eq!(12, seq_stm.segment[1].start);
        assert_eq!(22, seq_stm.segment[1].next);
        assert_eq!(32, seq_stm.segment[2].start);
        assert_eq!(42, seq_stm.segment[2].next);

        seq_stm.update(&pkt1);
        assert_eq!(2, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(22, seq_stm.segment[0].next);
        assert_eq!(32, seq_stm.segment[1].start);
        assert_eq!(42, seq_stm.segment[1].next);

        seq_stm.update(&pkt3);
        assert_eq!(1, seq_stm.segment.len());
        assert_eq!(1, seq_stm.segment[0].start);
        assert_eq!(42, seq_stm.segment[0].next);
        assert!(seq_stm.is_fin());
    }

    #[test]
    fn test_node_update() {
        let pkt_c2s = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt_c2s.decode();
        let pkt_c2s_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12);
        let _ = pkt_c2s_fin.decode();
        let pkt_s2c = build_tcp([2, 2, 2, 2], [1, 1, 1, 1], 80, 333, 2, false);
        let _ = pkt_s2c.decode();
        let pkt_s2c_fin = build_fin([2, 2, 2, 2], [1, 1, 1, 1], 80, 333, 12);
        let _ = pkt_s2c_fin.decode();
        let mut node = FlowNode::new(pkt_c2s.hash_key(), 888);

        assert_eq!(888, node.last_time);
        assert_eq!(pkt_c2s.hash_key(), node.key);
        assert_eq!(pkt_s2c.hash_key(), node.key);

        node.update(&pkt_c2s, 1000);
        assert_eq!(1000, node.last_time);
        assert_eq!(0, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert_eq!(2, node.seq_strm2.segment[0].start);
        assert_eq!(12, node.seq_strm2.segment[0].next);

        node.update(&pkt_s2c, 1001);
        assert_eq!(1001, node.last_time);
        assert_eq!(1, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert_eq!(2, node.seq_strm1.segment[0].start);
        assert_eq!(12, node.seq_strm1.segment[0].next);

        node.update(&pkt_c2s_fin, 1002);
        assert_eq!(1, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert!(node.seq_strm2.is_fin());
        assert!(!node.is_fin());

        node.update(&pkt_s2c_fin, 1003);
        assert_eq!(1, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert!(node.seq_strm2.is_fin());
        assert!(node.seq_strm1.is_fin());
        assert!(node.is_fin());
    }

    #[test]
    fn test_flow() {
        let pkt_c2s = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt_c2s.decode();
        let pkt_c2s_fin = build_fin([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12);
        let _ = pkt_c2s_fin.decode();
        let pkt_s2c = build_tcp([2, 2, 2, 2], [1, 1, 1, 1], 80, 333, 2, false);
        let _ = pkt_s2c.decode();
        let pkt_s2c_fin = build_fin([2, 2, 2, 2], [1, 1, 1, 1], 80, 333, 12);
        let _ = pkt_s2c_fin.decode();
        let mut flow = Flow::new();

        let node = flow.get_mut_or_new(&pkt_c2s, 1000).unwrap();
        node.update(&pkt_c2s, 1000);
        assert_eq!(1000, node.last_time);
        assert_eq!(0, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert_eq!(2, node.seq_strm2.segment[0].start);
        assert_eq!(12, node.seq_strm2.segment[0].next);
        assert_eq!(1, flow.len());

        let node = flow.get_mut_or_new(&pkt_s2c, 1001).unwrap();
        node.update(&pkt_s2c, 1001);
        assert_eq!(1001, node.last_time);
        assert_eq!(1, node.seq_strm1.segment.len());
        assert_eq!(1, node.seq_strm2.segment.len());
        assert_eq!(2, node.seq_strm1.segment[0].start);
        assert_eq!(12, node.seq_strm1.segment[0].next);
        assert_eq!(1, flow.len());

        let node = flow.get_mut_or_new(&pkt_c2s_fin, 1002).unwrap();
        node.update(&pkt_c2s_fin, 1002);
        let node = flow.get_mut_or_new(&pkt_s2c_fin, 1003).unwrap();
        node.update(&pkt_s2c_fin, 1003);
        assert!(node.is_fin());
        let key = node.key;
        flow.remove(&key);
        assert_eq!(0, flow.len());
    }

    #[test]
    fn test_flow_timeout() {
        let pkt1 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 2, false);
        let _ = pkt1.decode();
        let pkt2 = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 333, 80, 12, false);
        let _ = pkt2.decode();
        let mut flow = Flow::new();
        let mut now = 1000;

        let node = flow.get_mut_or_new(&pkt1, now).unwrap();
        node.update(&pkt1, now);
        assert_eq!(now, node.start_time);
        assert_eq!(now, node.last_time);

        now += 100;
        let node = flow.get_mut_or_new(&pkt2, now).unwrap();
        node.update(&pkt2, now);
        assert_eq!(now, node.last_time);

        now += NODE_TIMEOUT;
        flow.timeout(now, |node| {
            test_call_node(node);
        });
        assert!(flow.is_empty());
    }

    fn test_call_node(node: &FlowNode) {
        assert_eq!(node.start_time, 1000);
    }

    fn build_tcp(
        sip: [u8; 4],
        dip: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        fin: bool,
    ) -> Packet {
        let mut builder = PacketBuilder::ethernet2(
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
            seq,   //sequence number
            1024,
        ) //window size
        //set additional tcp header fields
        .ns() //set the ns flag
        //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
        .ack(123) //ack flag + the ack number
        .urg(23) //urg flag + urgent pointer
        .options(&[
            TcpOptionElement::Noop,
            TcpOptionElement::MaximumSegmentSize(1234),
        ])
        .unwrap();
        if fin {
            builder = builder.fin();
        }

        //payload of the tcp packet
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        //serialize
        //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        builder.write(&mut result, &payload).unwrap();
        // println!("result len:{}", result.len());

        let pkt = Packet::new(result, 1);
        let _ = pkt.decode();
        pkt
    }

    // sync包，不带载荷
    fn build_syn(sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16, seq: u32) -> Packet {
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
            seq,   //sequence number
            1024,
        ) //window size
        //set additional tcp header fields
        .ns() //set the ns flag
        //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
        .syn()
        .ack(123) //ack flag + the ack number
        .urg(23) //urg flag + urgent pointer
        .options(&[
            TcpOptionElement::Noop,
            TcpOptionElement::MaximumSegmentSize(1234),
        ])
        .unwrap();

        //payload of the tcp packet
        let payload = [];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        //serialize
        //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        builder.write(&mut result, &payload).unwrap();
        // println!("result len:{}", result.len());

        let pkt = Packet::new(result, 1);
        let _ = pkt.decode();
        pkt
    }

    // fin包，不带载荷
    fn build_fin(sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16, seq: u32) -> Packet {
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
            seq,   //sequence number
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
        let payload = [];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        //serialize
        //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        builder.write(&mut result, &payload).unwrap();
        // println!("result len:{}", result.len());

        let pkt = Packet::new(result, 1);
        let _ = pkt.decode();
        pkt
    }
}
