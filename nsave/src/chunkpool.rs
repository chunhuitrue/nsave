use crate::capture::Packet;
use crate::common::*;
use chrono::{DateTime, Datelike, Local, Timelike};
use libc::{F_SETLK, F_SETLKW, fcntl};
use memmap2::{Mmap, MmapMut, MmapOptions};
use pcap::Capture as PcapCapture;
use pcap::Linktype;
use pcap::Packet as CapPacket;
use pcap::PacketHeader as CapPacketHeader;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::{cell::RefCell, path::PathBuf};

#[derive(Debug)]
pub struct ChunkPool {
    pool_path: PathBuf,
    pool_size: u64,
    file_size: u64,
    chunk_size: u32,

    actual_file_size: u64,
    actual_file_num: u32,
    file_chunk_num: u32,
    chunk_num: u32,

    pool_head_fd: RefCell<Option<File>>,
    pool_head_map: RefCell<Option<MmapMut>>,
    pool_head: RefCell<Option<PoolHead>>,

    chunk_file_id: RefCell<Option<u32>>,
    chunk_file_fd: RefCell<Option<File>>,
    chunk_offset: RefCell<u32>,
    chunk_map: RefCell<Option<MmapMut>>,
    chunk_head: RefCell<Option<ChunkHead>>,

    last_cover_minute: RefCell<DateTime<Local>>,
}

impl ChunkPool {
    pub fn new(store_dir: PathBuf, pool_size: u64, file_size: u64, chunk_size: u32) -> Self {
        let mut path = PathBuf::new();
        path.push(store_dir);
        path.push("chunk_pool");
        let actual_size = ActualSize::new(pool_size, file_size, chunk_size);
        ChunkPool {
            pool_path: path,
            pool_size,
            file_size,
            chunk_size,

            actual_file_size: actual_size.actual_file_size,
            actual_file_num: actual_size.actual_file_num,
            file_chunk_num: actual_size.file_chunk_num,
            chunk_num: actual_size.chunk_num,

            pool_head_fd: RefCell::new(None),
            pool_head_map: RefCell::new(None),
            pool_head: RefCell::new(None),

            chunk_file_id: RefCell::new(None),
            chunk_file_fd: RefCell::new(None),
            chunk_offset: RefCell::new(0),
            chunk_map: RefCell::new(None),
            chunk_head: RefCell::new(None),

            last_cover_minute: RefCell::new(ts_date(0)),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        if !self.pool_path.exists() && fs::create_dir_all(&self.pool_path).is_err() {
            return Err(StoreError::InitError(
                "chunk pool create dir error".to_string(),
            ));
        }

        let pool_file_path = self.pool_path.join("pool.pl");
        if !pool_file_path.exists() {
            self.create_pool_file(&pool_file_path)?;
            self.create_chunk_file()?;
        }

        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(pool_file_path);
        match result {
            Ok(pool_file_fd) => {
                *self.pool_head_fd.borrow_mut() = Some(pool_file_fd);
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }

        let mmap = unsafe {
            MmapOptions::new()
                .offset(0)
                .len(PoolHead::serialize_size())
                .map_mut(self.pool_head_fd.borrow_mut().as_mut().unwrap().as_raw_fd())?
        };
        *self.pool_head_map.borrow_mut() = Some(mmap);

        let pool_head_map = self.pool_head_map.borrow_mut();
        let mut cursor = Cursor::new(pool_head_map.as_ref().unwrap());
        let pool_file = PoolHead::deserialize_from(&mut cursor).unwrap();
        *self.pool_head.borrow_mut() = Some(pool_file);
        self.check_conf()?;

        self.next_chunk(|_, _| {})?;
        Ok(())
    }

    fn check_conf(&self) -> Result<(), StoreError> {
        if self.pool_size == self.pool_head.borrow().as_ref().unwrap().pool_size
            && self.file_size == self.pool_head.borrow().as_ref().unwrap().file_size
            && self.chunk_size == self.pool_head.borrow().as_ref().unwrap().chunk_size
        {
            Ok(())
        } else {
            Err(StoreError::InitError("conf size error".to_string()))
        }
    }

    pub fn write<F>(
        &self,
        pkt: Packet,
        now: u128,
        cover_chunk_fn: F,
    ) -> Result<ChunkOffset, StoreError>
    where
        F: Fn(PathBuf, u128),
    {
        if self.chunk_head.borrow().as_ref().unwrap().start_time == 0 {
            self.chunk_head.borrow_mut().as_mut().unwrap().start_time = now;
        }

        if self.chunk_size - self.chunk_head.borrow().as_ref().unwrap().filled_size
            < pkt.serialize_size()
        {
            self.flush()?;
            self.next_chunk(cover_chunk_fn)?;
        }

        let pkt_start = self.chunk_head.borrow().as_ref().unwrap().filled_size;
        let mut chunk_map = self.chunk_map.borrow_mut();
        let chunk_u8: &mut [u8] = chunk_map.as_mut().unwrap();
        let mut chunk_offset = &mut chunk_u8[pkt_start as usize..];

        println!("chunkpool write 222...");
        pkt.serialize_into(&mut chunk_offset)?;
        self.chunk_head.borrow_mut().as_mut().unwrap().filled_size += pkt.serialize_size();
        self.chunk_head.borrow_mut().as_mut().unwrap().end_time = now;

        let mut chunk_id = self.pool_head.borrow().as_ref().unwrap().next_chunk_id;
        if chunk_id != 0 {
            chunk_id -= 1;
        } else {
            chunk_id = self.chunk_num - 1;
        }

        Ok(ChunkOffset {
            chunk_id,
            start_offset: pkt_start,
        })
    }

    pub fn update(&self, offset: &ChunkOffset, value: &ChunkOffset) -> Result<(), StoreError> {
        let offset = offset.start_offset;
        let value = value.start_offset;

        let mut chunk_map = self.chunk_map.borrow_mut();
        let chunk_u8: &mut [u8] = chunk_map.as_mut().unwrap();
        let mut chunk_offset = &mut chunk_u8[offset as usize..];
        self.serialize_update(&mut chunk_offset, value)?;
        Ok(())
    }

    fn serialize_update<W: Write>(&self, writer: &mut W, value: u32) -> Result<(), StoreError> {
        writer.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn create_pool_file(&self, file_path: &PathBuf) -> Result<(), StoreError> {
        let result = OpenOptions::new()
            .read(false)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path);
        match result {
            Ok(mut pool_file_fd) => {
                let pool_file = PoolHead {
                    pool_size: self.pool_size,
                    file_size: self.file_size,
                    chunk_size: self.chunk_size,
                    next_chunk_id: 0,
                };
                pool_file.serialize_into(&mut pool_file_fd)?;
                pool_file_fd.flush()?;
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
        Ok(())
    }

    fn create_chunk_file(&self) -> Result<(), StoreError> {
        for i in 0..self.actual_file_num {
            let path = self.pool_path.join(format!("{i:03}.da"));
            let data_file = File::create(path)?;
            data_file.set_len(self.actual_file_size)?;
        }
        Ok(())
    }

    fn next_chunk<F>(&self, cover_chunk_fn: F) -> Result<(), StoreError>
    where
        F: Fn(PathBuf, u128),
    {
        println!("chunkpool next chunk...");

        let chunk_id = self.pool_head.borrow().as_ref().unwrap().next_chunk_id;
        let file_id = chunk_id / self.file_chunk_num;
        if self.chunk_file_id.borrow().is_none() || self.chunk_file_id.borrow().unwrap() != file_id
        {
            let path = self.pool_path.join(format!("{file_id:03}.da"));
            let result = OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .truncate(false)
                .open(path);
            match result {
                Ok(file_fd) => {
                    *self.chunk_file_id.borrow_mut() = Some(file_id);
                    *self.chunk_file_fd.borrow_mut() = Some(file_fd);
                }
                Err(e) => {
                    return Err(StoreError::IoError(e));
                }
            }
        }

        let inner_chunk_id = chunk_id - file_id * self.file_chunk_num;
        let chunk_offset = inner_chunk_id * self.chunk_size;
        let mmap = unsafe {
            MmapOptions::new()
                .offset(chunk_offset.into())
                .len(self.chunk_size as usize)
                .map_mut(
                    self.chunk_file_fd
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .as_raw_fd(),
                )?
        };
        *self.chunk_offset.borrow_mut() = chunk_offset;
        *self.chunk_map.borrow_mut() = Some(mmap);

        let chunk_map = self.chunk_map.borrow_mut();
        let mut cursor = Cursor::new(chunk_map.as_ref().unwrap());
        let old_chunk_head = ChunkHead::deserialize_from(&mut cursor)?;
        let cover_minute = ts_date(old_chunk_head.end_time);
        let last_minute = *self.last_cover_minute.borrow();
        if !(cover_minute.year() == last_minute.year()
            && cover_minute.month() == last_minute.month()
            && cover_minute.day() == last_minute.day()
            && cover_minute.hour() == last_minute.hour()
            && cover_minute.minute() == last_minute.minute())
        {
            *self.last_cover_minute.borrow_mut() = cover_minute;
            cover_chunk_fn(self.pool_path.clone(), old_chunk_head.end_time);
        }

        *self.chunk_head.borrow_mut() = Some(ChunkHead::new());
        self.pool_head.borrow_mut().as_mut().unwrap().next_chunk_id += 1;
        if self.pool_head.borrow().as_ref().unwrap().next_chunk_id >= self.chunk_num {
            self.pool_head.borrow_mut().as_mut().unwrap().next_chunk_id = 0;
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.wlock_chunk()?;
        {
            let mut chunk_head_map = self.chunk_map.borrow_mut();
            let mut chunk_head_map_u8: &mut [u8] = chunk_head_map.as_mut().unwrap();
            self.chunk_head
                .borrow()
                .as_ref()
                .unwrap()
                .serialize_into(&mut chunk_head_map_u8)?;
        }
        self.chunk_map.borrow().as_ref().unwrap().flush()?;
        self.unlock_chunk()?;

        self.wlock_pool_head()?;
        {
            let mut pool_head_map = self.pool_head_map.borrow_mut();
            let mut pool_head_map_u8: &mut [u8] = pool_head_map.as_mut().unwrap();
            self.pool_head
                .borrow()
                .as_ref()
                .unwrap()
                .serialize_into(&mut pool_head_map_u8)?;
        }
        self.pool_head_map.borrow().as_ref().unwrap().flush()?;
        self.unlock_pool_head()?;
        Ok(())
    }

    fn wlock_pool_head(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: PoolHead::serialize_size() as i64,
            l_pid: 0,
        };
        let result = unsafe {
            fcntl(
                self.pool_head_fd.borrow().as_ref().unwrap().as_raw_fd(),
                F_SETLK,
                &mut lock,
            )
        };
        if result == -1 {
            return Err(StoreError::LockError("lock_pool_head error".to_string()));
        }
        Ok(())
    }

    fn unlock_pool_head(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: PoolHead::serialize_size() as i64,
            l_pid: 0,
        };
        let result = unsafe {
            fcntl(
                self.pool_head_fd.borrow().as_ref().unwrap().as_raw_fd(),
                F_SETLKW,
                &mut lock,
            )
        };
        if result == -1 {
            return Err(StoreError::LockError("unlock_pool_head error".to_string()));
        }
        Ok(())
    }

    fn wlock_chunk(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.chunk_offset.borrow() as i64,
            l_len: self.chunk_size as i64,
            l_pid: 0,
        };
        let result = unsafe {
            fcntl(
                self.chunk_file_fd.borrow().as_ref().unwrap().as_raw_fd(),
                F_SETLKW,
                &mut lock,
            )
        };
        if result == -1 {
            return Err(StoreError::LockError("lock_chunk error".to_string()));
        }
        Ok(())
    }

    fn unlock_chunk(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.chunk_offset.borrow() as i64,
            l_len: self.chunk_size as i64,
            l_pid: 0,
        };
        let result = unsafe {
            fcntl(
                self.chunk_file_fd.borrow().as_ref().unwrap().as_raw_fd(),
                F_SETLK,
                &mut lock,
            )
        };
        if result == -1 {
            return Err(StoreError::LockError("unlock_chunk error".to_string()));
        }
        Ok(())
    }

    pub fn finish(&self) {
        let _ = self.flush();
    }
}

impl Drop for ChunkPool {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActualSize {
    pub actual_file_size: u64,
    pub actual_file_num: u32,
    pub file_chunk_num: u32,
    pub chunk_num: u32,
}

impl ActualSize {
    pub fn new(pool_size: u64, file_size: u64, chunk_size: u32) -> Self {
        let actual_file_size = ((file_size - 1) / (chunk_size as u64) + 1) * (chunk_size as u64);
        let actual_file_num = pool_size.div_ceil(actual_file_size) as u32;
        let file_chunk_num = (actual_file_size / (chunk_size as u64)) as u32;
        let chunk_num = actual_file_num * file_chunk_num;
        ActualSize {
            actual_file_size,
            actual_file_num,
            file_chunk_num,
            chunk_num,
        }
    }
}

impl fmt::Display for ActualSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActualSize {{ actual_file_size: {} M, file_num: {}, file_chunk_num: {}, chunk_num: {} }}",
            self.actual_file_size / 1024 / 1024,
            self.actual_file_num,
            self.file_chunk_num,
            self.chunk_num
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PoolHead {
    pub pool_size: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub next_chunk_id: u32,
}

impl PoolHead {
    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        writer.write_all(&self.pool_size.to_le_bytes())?;
        writer.write_all(&self.file_size.to_le_bytes())?;
        writer.write_all(&self.chunk_size.to_le_bytes())?;
        writer.write_all(&self.next_chunk_id.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: Read>(reader: &mut R) -> Result<Self, StoreError> {
        let mut pool_size_bytes = [0; 8];
        let mut file_size_bytes = [0; 8];
        let mut chunk_size_bytes = [0; 4];
        let mut current_chunk_bytes = [0; 4];

        reader.read_exact(&mut pool_size_bytes)?;
        reader.read_exact(&mut file_size_bytes)?;
        reader.read_exact(&mut chunk_size_bytes)?;
        reader.read_exact(&mut current_chunk_bytes)?;

        Ok(PoolHead {
            pool_size: u64::from_le_bytes(pool_size_bytes),
            file_size: u64::from_le_bytes(file_size_bytes),
            chunk_size: u32::from_le_bytes(chunk_size_bytes),
            next_chunk_id: u32::from_le_bytes(current_chunk_bytes),
        })
    }

    pub fn serialize_size() -> usize {
        24
    }
}

impl fmt::Display for PoolHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PoolHead {{ pool_size: {} M, file_size: {} M, chunk_size: {} K, next_chunk_id: {} }}",
            self.pool_size / 1024 / 1024,
            self.file_size / 1024 / 1024,
            self.chunk_size / 1024,
            self.next_chunk_id
        )
    }
}

#[derive(Debug)]
pub struct ChunkHead {
    pub start_time: u128,
    pub end_time: u128,
    pub filled_size: u32, // 包括chunkhead在内
}

impl ChunkHead {
    pub fn new() -> Self {
        ChunkHead {
            start_time: 0,
            end_time: 0,
            filled_size: Self::serialize_size() as u32,
        }
    }

    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        writer.write_all(&self.start_time.to_le_bytes())?;
        writer.write_all(&self.end_time.to_le_bytes())?;
        writer.write_all(&self.filled_size.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: Read>(reader: &mut R) -> Result<Self, StoreError> {
        let mut start_time_bytes = [0; 16];
        let mut end_time_bytes = [0; 16];
        let mut data_size_bytes = [0; 4];

        reader.read_exact(&mut start_time_bytes)?;
        reader.read_exact(&mut end_time_bytes)?;
        reader.read_exact(&mut data_size_bytes)?;

        Ok(ChunkHead {
            start_time: u128::from_le_bytes(start_time_bytes),
            end_time: u128::from_le_bytes(end_time_bytes),
            filled_size: u32::from_le_bytes(data_size_bytes),
        })
    }

    pub fn serialize_size() -> usize {
        36
    }
}

impl Default for ChunkHead {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChunkHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChunkHead {{ start_time: {}, end_time: {}, filled_size: {} K }}",
            ts_date(self.start_time),
            ts_date(self.end_time),
            self.filled_size / 1024,
        )
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub struct ChunkOffset {
    pub chunk_id: u32,
    pub start_offset: u32,
}

impl ChunkOffset {
    pub fn new() -> Self {
        ChunkOffset {
            chunk_id: 0,
            start_offset: 0,
        }
    }
}

impl Default for ChunkOffset {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct StorePacket {
    pub next_offset: u32,
    pub timestamp: u128,
    pub data_len: u16,
    pub data: Vec<u8>,
}

impl StorePacket {
    pub fn deserialize_from<R: Read>(reader: &mut R) -> Result<Self, StoreError> {
        let mut next_offset_bytes = [0; 4];
        let mut timestamp_bytes = [0; 16];
        let mut data_len_bytes = [0; 2];

        reader.read_exact(&mut next_offset_bytes)?;
        reader.read_exact(&mut timestamp_bytes)?;
        reader.read_exact(&mut data_len_bytes)?;

        let next_offset = u32::from_le_bytes(next_offset_bytes);
        let timestamp = u128::from_le_bytes(timestamp_bytes);
        let data_len = u16::from_le_bytes(data_len_bytes);
        let mut data = vec![0; data_len.into()];
        reader.read_exact(&mut data)?;

        Ok(StorePacket {
            next_offset,
            timestamp,
            data_len,
            data,
        })
    }
}

impl fmt::Display for StorePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StorePacket {{ next_offset: {}, timestamp: {}, data_len: {} }}",
            self.next_offset,
            ts_date(self.timestamp),
            self.data_len,
        )
    }
}

pub fn read_pool_head(path: &PathBuf) -> Result<PoolHead, StoreError> {
    match path.extension() {
        Some(ext) => {
            if !ext.to_str().unwrap().eq("pl") {
                return Err(StoreError::CliError("not pool file".to_string()));
            }
        }
        None => return Err(StoreError::CliError("not pool file".to_string())),
    };

    let mut fd = File::open(path)?;
    let mut lock = libc::flock {
        l_type: libc::F_RDLCK as _,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: PoolHead::serialize_size() as i64,
        l_pid: 0,
    };
    let result = unsafe { fcntl(fd.as_raw_fd(), F_SETLK, &mut lock) };
    if result == -1 {
        return Err(StoreError::LockError(
            "read lock pool head error".to_string(),
        ));
    }

    let pool_head = PoolHead::deserialize_from(&mut fd)?;

    lock.l_type = libc::F_UNLCK as _;
    let result = unsafe { fcntl(fd.as_raw_fd(), F_SETLK, &mut lock) };
    if result == -1 {
        return Err(StoreError::LockError("unlock pool head error".to_string()));
    }

    Ok(pool_head)
}

pub fn dump_pool_file(path: PathBuf) -> Result<(), StoreError> {
    if let Ok(pool_head) = read_pool_head(&path) {
        let actual_size = ActualSize::new(
            pool_head.pool_size,
            pool_head.file_size,
            pool_head.chunk_size,
        );
        println!("pool file {path:?}:\n{pool_head}");
        println!("actual size: {actual_size}");
        Ok(())
    } else {
        println!("open pool file: {path:?} error");
        Err(StoreError::CliError("open pool file error".to_string()))
    }
}

pub fn dump_data_file(da_path: PathBuf) -> Result<(), StoreError> {
    match da_path.extension() {
        Some(ext) => {
            if !ext.to_str().unwrap().eq("da") {
                return Err(StoreError::CliError("not data file".to_string()));
            }
        }
        None => return Err(StoreError::CliError("not data file".to_string())),
    };

    let file_stem = da_path
        .file_stem()
        .ok_or(StoreError::CliError("filename error".to_string()))?;
    let file_stem_str = file_stem.to_string_lossy();
    let file_id = file_stem_str
        .parse::<u32>()
        .map_err(|_| StoreError::CliError("filename error".to_string()))?;

    let pool_path = da_path.parent();
    if pool_path.is_none() {
        println!("can not find parent path");
        return Err(StoreError::ReadError(
            "can not find parent path".to_string(),
        ));
    }
    let pool_path = pool_path.unwrap();
    let pool_file_path = pool_path.join("pool.pl");
    let pool_head = read_pool_head(&pool_file_path)?;
    let actual_size = ActualSize::new(
        pool_head.pool_size,
        pool_head.file_size,
        pool_head.chunk_size,
    );
    println!("pool file {pool_file_path:?}:\n{pool_head}");
    println!("actual size: {actual_size}");

    let data_file = match OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(da_path)
    {
        Ok(file_fd) => file_fd,
        Err(e) => {
            return Err(StoreError::CliError(format!("open file error: {e}")));
        }
    };

    for chunk in 0..actual_size.file_chunk_num {
        let offset = chunk * pool_head.chunk_size;
        if let Ok(mmap) = get_rlk_chunk(&data_file, offset, pool_head.chunk_size as usize) {
            let chunk_id = chunk + file_id * actual_size.file_chunk_num;
            dump_chunk_head(chunk_id, &mmap, &pool_head)?;
            free_rlk_chunk(&data_file, offset, pool_head.chunk_size as usize)?;
        } else {
            break;
        }
    }
    Ok(())
}

pub fn get_rlk_chunk(fd: &File, offset: u32, len: usize) -> Result<Mmap, StoreError> {
    let mut lock = libc::flock {
        l_type: libc::F_RDLCK as _,
        l_whence: libc::SEEK_SET as i16,
        l_start: offset as i64,
        l_len: len as i64,
        l_pid: 0,
    };
    let result = unsafe { fcntl(fd.as_raw_fd(), F_SETLK, &mut lock) };
    if result == -1 {
        return Err(StoreError::LockError("read lock chunk error".to_string()));
    }

    let mmap = unsafe { MmapOptions::new().offset(offset as u64).len(len).map(fd)? };
    Ok(mmap)
}

pub fn free_rlk_chunk(fd: &File, offset: u32, len: usize) -> Result<(), StoreError> {
    let mut lock = libc::flock {
        l_type: libc::F_UNLCK as _,
        l_whence: libc::SEEK_SET as i16,
        l_start: offset as i64,
        l_len: len as i64,
        l_pid: 0,
    };
    let result = unsafe { fcntl(fd.as_raw_fd(), F_SETLK, &mut lock) };
    if result == -1 {
        return Err(StoreError::LockError("unlock chunk error".to_string()));
    }
    Ok(())
}

pub fn dump_chunk(
    chunk_pool_path: PathBuf,
    chunk_id: u32,
    pcap_file: Option<PathBuf>,
) -> Result<(), StoreError> {
    let pool_file_path = chunk_pool_path.join("pool.pl");
    let pool_head = read_pool_head(&pool_file_path)?;
    let actual_size = ActualSize::new(
        pool_head.pool_size,
        pool_head.file_size,
        pool_head.chunk_size,
    );
    println!("pool head: {pool_head}");
    println!("actual size: {actual_size}");

    let data_file_id = chunk_id / actual_size.file_chunk_num;
    let data_file_path = chunk_pool_path.join(format!("{data_file_id:03}.da"));
    let data_file = match OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(data_file_path)
    {
        Ok(file_fd) => file_fd,
        Err(e) => {
            return Err(StoreError::CliError(format!("open data file error: {e}")));
        }
    };
    let inner_chunk_id = chunk_id - data_file_id * actual_size.file_chunk_num;
    let offset = inner_chunk_id * pool_head.chunk_size;
    if let Ok(mmap) = get_rlk_chunk(&data_file, offset, pool_head.chunk_size as usize) {
        if let Some(file) = pcap_file {
            dump_chunk_pcap(chunk_id, &mmap, &pool_head, file)?;
        } else {
            dump_chunk_info(chunk_id, &mmap, &pool_head)?;
        }
        free_rlk_chunk(&data_file, offset, pool_head.chunk_size as usize)?;
    }
    Ok(())
}

fn dump_chunk_head(id: u32, chunk: &[u8], pool_head: &PoolHead) -> Result<(), StoreError> {
    let mut cursor = Cursor::new(chunk);
    let head = ChunkHead::deserialize_from(&mut cursor)?;
    println!(
        "id: {:04}, {}, remain size: {} B",
        id,
        head,
        pool_head.chunk_size - head.filled_size
    );
    Ok(())
}

fn dump_chunk_info(id: u32, chunk: &[u8], pool_head: &PoolHead) -> Result<(), StoreError> {
    let mut cursor = Cursor::new(chunk);
    let head = ChunkHead::deserialize_from(&mut cursor)?;
    println!(
        "id: {:04}, {}, remain size: {} B",
        id,
        head,
        pool_head.chunk_size - head.filled_size
    );

    println!("in chunk packet:");
    if head.filled_size > ChunkHead::serialize_size() as u32 {
        while cursor.position() < head.filled_size.into() {
            let store_pkt = StorePacket::deserialize_from(&mut cursor)?;
            println!("{store_pkt}");
        }
    } else {
        println!("no packet\n");
    }
    Ok(())
}

fn dump_chunk_pcap(
    id: u32,
    chunk: &[u8],
    pool_head: &PoolHead,
    pcap_file: PathBuf,
) -> Result<(), StoreError> {
    let mut cursor = Cursor::new(chunk);
    let head = ChunkHead::deserialize_from(&mut cursor)?;
    println!(
        "chunk id: {:04}, {}, remain size: {} B",
        id,
        head,
        pool_head.chunk_size - head.filled_size
    );

    println!("dump packet to pcap: {pcap_file:?}");
    if head.filled_size > ChunkHead::serialize_size() as u32 {
        let capture = PcapCapture::dead(Linktype::ETHERNET);
        if capture.is_err() {
            return Err(StoreError::WriteError("pcap open error".to_string()));
        }
        let capture = capture.unwrap();
        let mut savefile = capture.savefile(pcap_file).unwrap();
        let mut pkt_num: u32 = 0;

        while cursor.position() < head.filled_size.into() {
            let store_pkt = StorePacket::deserialize_from(&mut cursor)?;
            println!("save pkt: {store_pkt}");

            let header = CapPacketHeader {
                ts: ts_timeval(store_pkt.timestamp),
                caplen: store_pkt.data_len as u32,
                len: store_pkt.data_len as u32,
            };
            let cap_pkt = CapPacket {
                header: &header,
                data: &store_pkt.data,
            };
            savefile.write(&cap_pkt);
            pkt_num += 1;
        }
        let _ = savefile.flush();
        println!("save packet num: {pkt_num}");
    } else {
        println!("no packet\n");
    }
    Ok(())
}
