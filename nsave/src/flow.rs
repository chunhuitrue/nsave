use crate::capture::Packet;
use crate::common::*;
use crate::store::*;
use crate::tmohash::TmoHash;
use network_types::ip::IpProto;

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

    pub store_ctx: Option<StoreCtx>,
}

impl FlowNode {
    fn new(key: PacketKey, now: u128, max_seq_gap: usize) -> Self {
        FlowNode {
            key,
            start_time: now,
            last_time: now,
            seq_strm1: SeqStream::new_with_arg(max_seq_gap),
            seq_strm2: SeqStream::new_with_arg(max_seq_gap),
            store_ctx: None,
        }
    }

    pub fn update(&mut self, pkt: &Packet, now: u128) {
        self.last_time = now;
        if matches!(pkt.l4_proto(), Ok(IpProto::Tcp)) {
            if let (Ok(src_ip), Ok(src_port)) = (pkt.src_ip(), pkt.src_port()) {
                if self.key.addr1 == src_ip && self.key.port1 == src_port {
                    self.seq_strm1.update(pkt);
                } else if self.key.addr2 == src_ip && self.key.port2 == src_port {
                    self.seq_strm2.update(pkt);
                }
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
    #[allow(dead_code)]
    fn new() -> Self {
        SeqStream {
            segment: Vec::with_capacity(MAX_SEQ_GAP),
            fin: false,
        }
    }

    fn new_with_arg(max_seq_gap: usize) -> Self {
        SeqStream {
            segment: Vec::with_capacity(max_seq_gap),
            fin: false,
        }
    }

    fn update(&mut self, pkt: &Packet) {
        if self.segment.len() > MAX_SEQ_GAP {
            return;
        }

        if pkt.fin().unwrap_or(false) {
            self.fin = true
        }

        let seq = pkt.seq().unwrap_or(0);
        let payload_len = pkt.payload_len().unwrap_or(0);

        let new_seg = if pkt.syn().unwrap_or(false) && payload_len == 0 {
            SeqSeg {
                start: seq,
                next: seq + 1,
            }
        } else {
            SeqSeg {
                start: seq,
                next: seq + payload_len,
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
    node_timeout: u128,
    max_seq_gap: usize,
    table: TmoHash<PacketKey, FlowNode>,
}

impl Flow {
    pub fn new() -> Self {
        Flow {
            node_timeout: NODE_TIMEOUT,
            max_seq_gap: MAX_SEQ_GAP,
            table: TmoHash::new(MAX_TABLE_CAPACITY),
        }
    }

    pub fn new_with_arg(max_table_capacity: usize, node_timeout: u128, max_seq_gap: usize) -> Self {
        Flow {
            node_timeout,
            max_seq_gap,
            table: TmoHash::new(max_table_capacity),
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
        self.table
            .insert(key, FlowNode::new(key, now, self.max_seq_gap))
    }

    // 返回插入节点的可变引用。如果已经存在，返回None
    fn insert_mut(&mut self, pkt: &Packet, now: u128) -> Option<&mut FlowNode> {
        let key = pkt.hash_key();
        if self.contains_key(&key) {
            return None;
        }
        self.table
            .insert_mut(key, FlowNode::new(key, now, self.max_seq_gap))
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

    pub fn timeout<F>(&mut self, now: u128, fun: F)
    where
        F: Fn(&FlowNode),
    {
        self.table.timeout(|_key, node| {
            if now - node.last_time >= self.node_timeout {
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

    #[test]
    fn test_seqstream_new() {
        let seq_stm = SeqStream::new();
        assert_eq!(seq_stm.segment.len(), 0);
        assert!(!seq_stm.fin);
    }
}
