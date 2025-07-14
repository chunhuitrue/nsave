use crate::common::*;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags as AyaXdpFlags};
use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use log::debug;
use log::error;
#[cfg(feature = "debug_mode")]
use log::warn;
use network_types::{eth::EtherType, ip::IpProto};
use s2n_quic_xdp::{
    if_xdp::{self, UmemDescriptor, XdpFlags},
    ring, socket, syscall, umem,
};
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

pub struct NicQueue {
    queue_id: u32,
    socket: socket::Fd,
    fill: ring::Fill,
    rx: ring::Rx,
    _completion: ring::Completion,
    _tx: ring::Tx,
}

pub struct AfXdp {
    umem: umem::Umem,
    queues: Vec<NicQueue>,
    recycle_rx: Receiver<RecyclePkt>,
    recycle_tx: Sender<RecyclePkt>,
    recycle_bufs: Vec<Vec<RecyclePkt>>,
    packet_count: u64,
    headroom_size: u32,
    config: AfXdpConfig,
    _ebpf: aya::Ebpf,
    _xsks_map: XskMap<aya::maps::MapData>,
}

impl AfXdp {
    pub fn new(iface: &str) -> Result<Self> {
        Self::new_with_config(iface, AfXdpConfig::default())
    }

    pub fn new_with_config(iface: &str, config: AfXdpConfig) -> Result<Self> {
        env_logger::init();

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        let meta_size = std::mem::size_of::<AfXdpPacketMeta>();
        if config.headroom_size < meta_size as u32 {
            return Err(anyhow::anyhow!(
                "headroom_size must be larger than meta_size"
            ));
        }

        let frame_size = config.frame_size;
        let frame_headroom = config.headroom_size;
        let hugepage = config.hugepage;
        let max_queues = syscall::max_queues(iface);
        let frame_count = (config.fill_queue_len + config.tx_queue_len) * max_queues;

        let umem = umem::Builder {
            frame_count,
            frame_size,
            frame_headroom,
            hugepage,
            ..Default::default()
        }
        .build()?;

        println!(
            "Shared UMEM created with {} frames for {} queues",
            umem.frame_count(),
            max_queues
        );

        // 设置基础地址
        let flag_copy = if config.zcopy {
            XdpFlags::ZEROCOPY
        } else {
            XdpFlags::COPY
        };
        let mut address = if_xdp::Address {
            flags: flag_copy | XdpFlags::USE_NEED_WAKEUP,
            ..Default::default()
        };
        address.set_if_name(&CString::new(iface)?)?;

        let mut shared_umem_fd = None;
        let mut queues = Vec::new();
        let mut desc = umem.frames();

        // 为每个队列创建socket和ring buffers
        for queue_id in 0..max_queues {
            let socket = socket::Fd::open()?;

            // 共享UMEM的关键：第一个socket attach UMEM，后续socket使用shared_umem
            if let Some(fd) = shared_umem_fd {
                address.set_shared_umem(&fd);
            } else {
                socket.attach_umem(&umem)?;
                shared_umem_fd = Some(socket.as_raw_fd());
            }

            // 设置当前队列ID
            address.queue_id = queue_id;

            let offsets = syscall::offsets(&socket)?;

            // 创建ring buffers
            let mut fill = ring::Fill::new(socket.clone(), &offsets, config.fill_queue_len)?;
            let rx = ring::Rx::new(socket.clone(), &offsets, config.rx_queue_len)?;
            let mut completion =
                ring::Completion::new(socket.clone(), &offsets, config.completion_queue_len)?;
            let tx = ring::Tx::new(socket.clone(), &offsets, config.tx_queue_len)?;

            // 从共享的UMEM中分配描述符给每个队列
            fill.init((&mut desc).take(config.fill_queue_len as _));
            completion.init((&mut desc).take(config.tx_queue_len as _));

            // 绑定到队列
            match syscall::bind(&socket, &mut address) {
                Ok(_) => println!("Queue {queue_id}: Successfully bound with shared UMEM"),
                Err(e) => {
                    error!("Queue {queue_id}: Failed to bind: {e}");
                    return Err(e.into());
                }
            }

            queues.push(NicQueue {
                queue_id,
                socket,
                fill,
                rx,
                _completion: completion,
                _tx: tx,
            });
        }

        // 加载xdp
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/nsave"
        )))?;

        // 同步方式不需要
        #[cfg(feature = "debug_mode")]
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }

        let program: &mut Xdp = ebpf.program_mut("nsave").unwrap().try_into()?;
        program.load()?;
        program.attach(iface, AyaXdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        // 获取XSK map的引用
        let mut xsks_map: XskMap<_> = ebpf.take_map("XSKS_MAP").unwrap().try_into()?;

        // 将AF_XDP socket插入到map中
        let queue_sockets: Vec<(u32, i32)> = queues
            .iter()
            .map(|queue| (queue.queue_id, queue.socket.as_raw_fd()))
            .collect();
        for (queue_id, socket_fd) in queue_sockets {
            println!("Inserting queue {queue_id} with socket fd {socket_fd} into XSK map");
            xsks_map.set(queue_id, socket_fd, 0)?;
        }

        let (recycle_tx, recycle_rx) = bounded(config.pkt_recycle_channel_size);
        Ok(Self {
            umem,
            queues,
            packet_count: 0,
            recycle_rx,
            recycle_tx,
            recycle_bufs: vec![Vec::with_capacity(config.recycle_buf_size); max_queues as usize],
            headroom_size: frame_headroom,
            config,
            _ebpf: ebpf,
            _xsks_map: xsks_map,
        })
    }

    pub fn acquire_packets<F>(&mut self, mut packet_handler: F) -> Result<()>
    where
        F: FnMut(AfXdpPacket),
    {
        self.recycle_packets()?;

        for queue in &mut self.queues {
            let rx_count = queue.rx.acquire(self.config.rx_queue_len);
            if rx_count == 0 {
                continue;
            }

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos();

            let (rx_data1, rx_data2) = queue.rx.data();
            for desc in rx_data1
                .iter()
                .chain(rx_data2.iter())
                .take(rx_count as usize)
            {
                let umem_desc = UmemDescriptor {
                    address: desc.address - self.headroom_size as u64, // 注意：需要减去headroom偏移
                };
                // frame和配置的大小一样（包含headroom + 数据包）
                let frame = unsafe { self.umem.get_mut(umem_desc) };
                let frame_ptr = NonNull::new(frame.as_mut_ptr()).unwrap();
                // // // headroom
                // // let mut headroom = &frame[0..self.headroom as usize];
                // // // 数据包
                // // let mut packet =
                // //     &frame[self.headroom as usize..self.headroom as usize + desc.len as usize];
                // // headroom + packet
                // let mut headroom_packet = &frame[0..self.headroom as usize + desc.len as usize];
                // // // 数据包也可以直接获取
                // // let tmp_pkt = unsafe { self.umem.get_mut(*desc) };

                let packet = AfXdpPacket::new(AfXdpPacketConfig {
                    frame_ptr,
                    frame_size: frame.len(),
                    headroom_size: self.headroom_size as usize,
                    desc_addr: desc.address,
                    queue_id: queue.queue_id,
                    packet_buff_len: desc.len,
                    recycle_tx: self.recycle_tx.clone(),
                    timestamp,
                });
                packet_handler(packet);
            }
            queue.rx.release(rx_count);
            self.packet_count += rx_count as u64;
        }
        Ok(())
    }

    fn recycle_packets(&mut self) -> Result<()> {
        loop {
            match self.recycle_rx.try_recv() {
                Ok(pkt) => {
                    let queue_buf = &mut self.recycle_bufs[pkt.queue_id as usize];
                    let queue_id = pkt.queue_id;
                    queue_buf.push(pkt);
                    if queue_buf.len() >= self.config.recycle_buf_size {
                        self.fill_queue(queue_id);
                    }
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(anyhow!("recycle channel disconnected"));
                }
            }
        }

        for queue_id in 0..self.queues.len() {
            self.fill_queue(queue_id as u32);
        }
        Ok(())
    }

    fn fill_queue(&mut self, queue_id: u32) {
        let queue_buf = &mut self.recycle_bufs[queue_id as usize];
        if queue_buf.is_empty() {
            return;
        }

        let queue = &mut self.queues[queue_id as usize];
        let avl_count = queue.fill.acquire(queue_buf.len() as u32);
        let fill_count = std::cmp::min(avl_count, queue_buf.len() as u32);
        if fill_count > 0 {
            let (fill_data1, fill_data2) = queue.fill.data();
            for (i, pkt) in queue_buf.drain(..fill_count as usize).enumerate() {
                if i < fill_data1.len() {
                    fill_data1[i].address = pkt.desc_addr;
                } else {
                    fill_data2[i - fill_data1.len()].address = pkt.desc_addr;
                }
            }
            queue.fill.release(fill_count);

            if queue.fill.needs_wakeup() {
                if let Err(e) = syscall::busy_poll(&queue.socket) {
                    error!("Queue {}: Busy poll error: {}", queue.queue_id, e);
                }
            }
        }
    }

    pub fn builder() -> AfXdpBuilder {
        AfXdpBuilder::new()
    }

    /// 获取所有队列的queue_id和socket对
    /// 返回Vec<(queue_id, socket_fd)>，用于添加到内核XDP map
    pub fn get_queue_sockets(&self) -> Vec<(u32, i32)> {
        self.queues
            .iter()
            .map(|queue| (queue.queue_id, queue.socket.as_raw_fd()))
            .collect()
    }

    /// 获取指定队列的socket文件描述符
    #[allow(unused)]
    pub fn get_socket_fd(&self, queue_id: u32) -> Option<i32> {
        self.queues
            .iter()
            .find(|queue| queue.queue_id == queue_id)
            .map(|queue| queue.socket.as_raw_fd())
    }
}

#[derive(Debug, Clone)]
pub struct AfXdpConfig {
    pub rx_queue_len: u32,
    pub tx_queue_len: u32,
    pub fill_queue_len: u32,
    pub completion_queue_len: u32,
    pub frame_size: u32,
    pub headroom_size: u32,
    pub hugepage: bool,
    pub zcopy: bool,
    pub pkt_recycle_channel_size: usize,
    pub recycle_buf_size: usize,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            rx_queue_len: 1024,
            tx_queue_len: 8,
            fill_queue_len: 2048,    // rx_queue_len * 2
            completion_queue_len: 8, // tx_queue_len
            frame_size: 2048,
            headroom_size: std::mem::size_of::<AfXdpPacketMeta>() as u32,
            hugepage: false,
            zcopy: false,
            pkt_recycle_channel_size: 1024,
            recycle_buf_size: 128,
        }
    }
}

pub struct AfXdpBuilder {
    config: AfXdpConfig,
}

impl AfXdpBuilder {
    pub fn new() -> Self {
        Self {
            config: AfXdpConfig::default(),
        }
    }

    pub fn rx_queue_len(mut self, len: u32) -> Self {
        self.config.rx_queue_len = len;
        self
    }

    pub fn tx_queue_len(mut self, len: u32) -> Self {
        self.config.tx_queue_len = len;
        self
    }

    pub fn frame_size(mut self, size: u32) -> Self {
        self.config.frame_size = size;
        self
    }

    pub fn frame_headroom(mut self, headroom: u32) -> Self {
        self.config.headroom_size = headroom;
        self
    }

    pub fn hugepage(mut self, hugepage: bool) -> Self {
        self.config.hugepage = hugepage;
        self
    }

    pub fn zcopy(mut self, zcopy: bool) -> Self {
        self.config.zcopy = zcopy;
        self
    }

    pub fn recycle_channel_size(mut self, size: usize) -> Self {
        self.config.pkt_recycle_channel_size = size;
        self
    }

    pub fn recycle_buff_size(mut self, size: usize) -> Self {
        self.config.recycle_buf_size = size;
        self
    }

    pub fn build(self, iface: &str) -> Result<AfXdp> {
        AfXdp::new_with_config(iface, self.config)
    }
}

impl Default for AfXdpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RecyclePkt {
    desc_addr: u64,
    queue_id: u32,
}

#[repr(C)]
struct AfXdpPacketMeta {
    ref_count: AtomicU32,
}

#[derive(Debug, Clone)]
pub struct AfXdpPacketConfig {
    pub frame_ptr: NonNull<u8>,
    pub frame_size: usize,
    pub headroom_size: usize,
    pub desc_addr: u64,
    pub queue_id: u32,
    pub packet_buff_len: u32,
    pub recycle_tx: Sender<RecyclePkt>,
    pub timestamp: u128,
}

pub struct AfXdpPacket {
    frame_ptr: NonNull<u8>,
    frame_size: usize,
    headroom_size: usize,
    desc_addr: u64,
    queue_id: u32,
    packet_buff_len: u32, // afxdp返回的packet长度，但不一定是真正的数据包长度。通常是1522（最大帧长）
    recycle_tx: Sender<RecyclePkt>,
    l3_offset: usize,       // ip头相对于数据包开始的偏移
    l4_offset: usize,       // tcp/udp/icpm相对于数据包开始的偏移
    real_packet_len: usize, // 数据包的实际长度，因为af xdp返回的长度始终是1522，并不是实际数据帧的长度，所以需要解析ip头然后得到正确长度
    timestamp: u128,
}

impl AfXdpPacket {
    fn new(config: AfXdpPacketConfig) -> Self {
        let meta = AfXdpPacketMeta {
            ref_count: AtomicU32::new(1),
        };
        unsafe {
            let meta_ptr = config.frame_ptr.as_ptr() as *mut AfXdpPacketMeta;
            std::ptr::write(meta_ptr, meta);
        }

        let mut s = Self {
            frame_ptr: config.frame_ptr,
            frame_size: config.frame_size,
            headroom_size: config.headroom_size,
            desc_addr: config.desc_addr,
            queue_id: config.queue_id,
            packet_buff_len: config.packet_buff_len,
            recycle_tx: config.recycle_tx,
            l3_offset: 0,
            l4_offset: 0,
            real_packet_len: 0,
            timestamp: config.timestamp,
        };
        let _ = s.decode().ok();
        s
    }

    pub fn frame(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.frame_ptr.as_ptr(), self.frame_size) }
    }

    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn meta(&self) -> &AfXdpPacketMeta {
        unsafe {
            let meta_ptr = self.frame_ptr.as_ptr() as *const AfXdpPacketMeta;
            &*meta_ptr
        }
    }

    #[allow(unused)]
    fn meta_mut(&mut self) -> &mut AfXdpPacketMeta {
        unsafe {
            let meta_ptr = self.frame_ptr.as_ptr() as *mut AfXdpPacketMeta;
            &mut *meta_ptr
        }
    }

    pub fn headroom(&self) -> &[u8] {
        let meta_size = std::mem::size_of::<AfXdpPacketMeta>();
        unsafe {
            std::slice::from_raw_parts(
                self.frame_ptr.as_ptr().add(meta_size),
                self.headroom_size - meta_size,
            )
        }
    }

    pub fn headroom_size(&self) -> usize {
        self.headroom_size - std::mem::size_of::<AfXdpPacketMeta>()
    }

    pub fn timestamp(&self) -> u128 {
        self.timestamp
    }

    // 数据包所在的buff，是xdp传递上了的帧减headroom，但不一定是真正的数据包长度
    fn packet_frame(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.frame_ptr.as_ptr().add(self.headroom_size),
                self.frame_size - self.headroom_size,
            )
        }
    }

    pub fn packet(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.frame_ptr.as_ptr().add(self.headroom_size),
                self.real_packet_len,
            )
        }
    }

    // 数据包的实际长度
    pub fn packet_len(&self) -> usize {
        self.real_packet_len
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.packet_frame()
    }

    fn decode(&mut self) -> Result<(), PacketParseError> {
        let offsets = decode_packet(self.packet_frame())?;

        self.l3_offset = offsets.l3_offset;
        self.l4_offset = offsets.l4_offset;
        if let Some(real_len) = offsets.real_packet_len {
            self.real_packet_len = real_len;
        }
        Ok(())
    }

    pub fn decode_ok(&self) -> bool {
        self.l4_offset != 0
    }

    pub fn l3_proto(&self) -> Result<EtherType, PacketParseError> {
        l3_proto(self.packet_frame())
    }

    pub fn src_ip(&self) -> Result<IpAddr, PacketParseError> {
        src_ip(self.packet_frame(), self.l3_offset)
    }

    pub fn dst_ip(&self) -> Result<IpAddr, PacketParseError> {
        dst_ip(self.packet_frame(), self.l3_offset)
    }

    pub fn l4_proto(&self) -> Result<IpProto, PacketParseError> {
        l4_proto(self.packet_frame(), self.l3_offset)
    }

    pub fn src_port(&self) -> Result<u16, PacketParseError> {
        src_port(self.packet_frame(), self.l3_offset, self.l4_offset)
    }

    pub fn dest_port(&self) -> Result<u16, PacketParseError> {
        dest_port(self.packet_frame(), self.l3_offset, self.l4_offset)
    }

    pub fn seq(&self) -> Result<u32, PacketParseError> {
        seq(self.packet_frame(), self.l3_offset, self.l4_offset)
    }

    pub fn syn(&self) -> Result<bool, PacketParseError> {
        syn(self.packet_frame(), self.l3_offset, self.l4_offset)
    }

    pub fn fin(&self) -> Result<bool, PacketParseError> {
        fin(self.packet_frame(), self.l3_offset, self.l4_offset)
    }

    pub fn payload_len(&self) -> Result<u32, PacketParseError> {
        payload_len(self.packet_frame(), self.l3_offset, self.l4_offset)
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
        hash_key(self.packet_frame(), self.l3_offset, self.l4_offset).unwrap_or(PacketKey {
            addr1: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
            port1: 0,
            addr2: std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
            port2: 0,
            trans_proto: TransProto::Icmp6,
        })
    }
}

impl Clone for AfXdpPacket {
    fn clone(&self) -> Self {
        let meta = self.meta();
        meta.ref_count.fetch_add(1, Ordering::Relaxed);

        Self {
            frame_ptr: self.frame_ptr,
            frame_size: self.frame_size,
            headroom_size: self.headroom_size,
            desc_addr: self.desc_addr,
            queue_id: self.queue_id,
            packet_buff_len: self.packet_buff_len,
            recycle_tx: self.recycle_tx.clone(),
            l3_offset: self.l3_offset,
            l4_offset: self.l4_offset,
            real_packet_len: self.real_packet_len,
            timestamp: self.timestamp,
        }
    }
}

impl Drop for AfXdpPacket {
    fn drop(&mut self) {
        let meta = self.meta();
        let count = meta.ref_count.fetch_sub(1, Ordering::Relaxed);

        if count == 1 {
            let release_item = RecyclePkt {
                desc_addr: self.desc_addr,
                queue_id: self.queue_id,
            };
            let _ = self.recycle_tx.send(release_item);
        }
    }
}

unsafe impl Send for AfXdpPacket {}

impl Hash for AfXdpPacket {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_key().hash(state)
    }
}

impl fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketParseError::InvalidOffset => write!(f, "Invalid packet offset"),
            PacketParseError::UnknownIpProtocol => write!(f, "Unknown IP protocol"),
            PacketParseError::UnknownTransportProtocol => write!(f, "Unknown transport protocol"),
        }
    }
}

impl Error for PacketParseError {}
