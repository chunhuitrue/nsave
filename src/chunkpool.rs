#![allow(dead_code)]

use crate::common::*;
use crate::packet::*;
use memmap2::{MmapMut, MmapOptions};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::{cell::RefCell, path::PathBuf, sync::Arc};

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
    chunk_map: RefCell<Option<MmapMut>>,
    chunk_head: RefCell<Option<ChunkHead>>,
}

impl ChunkPool {
    pub fn new(store_dir: PathBuf, pool_size: u64, file_size: u64, chunk_size: u32) -> Self {
        let mut path = PathBuf::new();
        path.push(store_dir);
        path.push("chunk_pool");
        let actual_file_size = ((file_size - 1) / (chunk_size as u64) + 1) * (chunk_size as u64);
        let actual_file_num = ((pool_size + actual_file_size - 1) / actual_file_size) as u32;
        let file_chunk_num = (actual_file_size / (chunk_size as u64)) as u32;
        let chunk_num = actual_file_num * file_chunk_num;
        ChunkPool {
            pool_path: path,
            pool_size,
            file_size,
            chunk_size,

            actual_file_size,
            actual_file_num,
            file_chunk_num,
            chunk_num,

            pool_head_fd: RefCell::new(None),
            pool_head_map: RefCell::new(None),
            pool_head: RefCell::new(None),

            chunk_file_id: RefCell::new(None),
            chunk_file_fd: RefCell::new(None),
            chunk_map: RefCell::new(None),
            chunk_head: RefCell::new(None),
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

        dbg!("init up next chunk");
        self.next_chunk(|_, _| {})?;
        Ok(())
    }

    pub fn write<F>(
        &self,
        pkt: Arc<Packet>,
        now: u128,
        cover_chunk_fn: F,
    ) -> Result<ChunkOffset, StoreError>
    where
        F: Fn(u128, u128),
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

        chunk_offset.write_all(&value.to_be_bytes())?;
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
            let path = self.pool_path.join(format!("{:03}.da", i));
            let data_file = File::create(path)?;
            data_file.set_len(self.actual_file_size)?;
        }
        Ok(())
    }

    fn next_chunk<F>(&self, cover_chunk_fn: F) -> Result<(), StoreError>
    where
        F: Fn(u128, u128),
    {
        let chunk_id = self.pool_head.borrow().as_ref().unwrap().next_chunk_id;
        let file_id = chunk_id / self.file_chunk_num;
        dbg!(chunk_id, file_id, self.file_chunk_num);
        if self.chunk_file_id.borrow().is_none() || self.chunk_file_id.borrow().unwrap() != file_id
        {
            let path = self.pool_path.join(format!("{:03}.da", file_id));
            dbg!(&path);
            let result = OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .truncate(false)
                .open(path);
            match result {
                Ok(file_fd) => {
                    dbg!(" open 222");
                    *self.chunk_file_id.borrow_mut() = Some(file_id);
                    *self.chunk_file_fd.borrow_mut() = Some(file_fd);
                }
                Err(e) => {
                    return Err(StoreError::IoError(e));
                }
            }
        }
        dbg!("after open");

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
        *self.chunk_map.borrow_mut() = Some(mmap);
        dbg!("222");

        let chunk_map = self.chunk_map.borrow_mut();
        let mut cursor = Cursor::new(chunk_map.as_ref().unwrap());
        let old_chunk_head = ChunkHead::deserialize_from(&mut cursor).unwrap();
        cover_chunk_fn(old_chunk_head.start_time, old_chunk_head.end_time);
        dbg!("333");

        *self.chunk_head.borrow_mut() = Some(ChunkHead::new());
        self.pool_head.borrow_mut().as_mut().unwrap().next_chunk_id += 1;
        if self.pool_head.borrow().as_ref().unwrap().next_chunk_id >= self.chunk_num {
            self.pool_head.borrow_mut().as_mut().unwrap().next_chunk_id = 0;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        {
            let mut chunk_head_map = self.chunk_map.borrow_mut();
            let mut chunk_head_map_offset: &mut [u8] = chunk_head_map.as_mut().unwrap();
            self.chunk_head
                .borrow()
                .as_ref()
                .unwrap()
                .serialize_into(&mut chunk_head_map_offset)?;
        }
        self.chunk_map.borrow().as_ref().unwrap().flush()?;

        {
            let mut pool_head_map = self.pool_head_map.borrow_mut();
            let mut pool_head_map_offset: &mut [u8] = pool_head_map.as_mut().unwrap();
            self.pool_head
                .borrow()
                .as_ref()
                .unwrap()
                .serialize_into(&mut pool_head_map_offset)?;
        }
        self.pool_head_map.borrow().as_ref().unwrap().flush()?;
        Ok(())
    }
}

#[derive(Debug)]
struct PoolHead {
    pool_size: u64,
    file_size: u64,
    chunk_size: u32,
    next_chunk_id: u32,
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
            pool_size: u64::from_be_bytes(pool_size_bytes),
            file_size: u64::from_be_bytes(file_size_bytes),
            chunk_size: u32::from_be_bytes(chunk_size_bytes),
            next_chunk_id: u32::from_be_bytes(current_chunk_bytes),
        })
    }

    pub fn serialize_size() -> usize {
        24
    }
}

#[derive(Debug)]
struct ChunkHead {
    start_time: u128,
    end_time: u128,
    filled_size: u32,
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
            start_time: u128::from_be_bytes(start_time_bytes),
            end_time: u128::from_be_bytes(end_time_bytes),
            filled_size: u32::from_be_bytes(data_size_bytes),
        })
    }

    pub fn serialize_size() -> usize {
        36
    }
}

#[derive(Debug)]
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
    next_offset: u32,
    timestamp: u128,
    data_len: u16,
    data: Vec<u8>,
}

impl StorePacket {
    pub fn deserialize_from<R: Read>(reader: &mut R) -> Result<Self, StoreError> {
        let mut next_offset_bytes = [0; 4];
        let mut timestamp_bytes = [0; 16];
        let mut data_len_bytes = [0; 2];

        reader.read_exact(&mut next_offset_bytes)?;
        reader.read_exact(&mut timestamp_bytes)?;
        reader.read_exact(&mut data_len_bytes)?;

        let next_offset = u32::from_be_bytes(next_offset_bytes);
        let timestamp = u128::from_be_bytes(timestamp_bytes);
        let data_len = u16::from_be_bytes(data_len_bytes);
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
