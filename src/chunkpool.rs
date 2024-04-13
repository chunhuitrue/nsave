#![allow(dead_code)]

use crate::common::*;
use memmap2::{MmapMut, MmapOptions};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ChunkPool {
    pool_path: PathBuf,
    pool_head_fd: RefCell<Option<File>>,
    pool_head_map: RefCell<Option<MmapMut>>,
    pool_head: RefCell<Option<PoolHead>>,
    chunk_file_id: RefCell<Option<u32>>,
    chunk_file_fd: RefCell<Option<File>>,
    chunk_map: RefCell<Option<MmapMut>>,
    chunk_head: RefCell<Option<ChunkHead>>,
}

impl ChunkPool {
    pub fn new(store_dir: PathBuf) -> Self {
        let mut path = PathBuf::new();
        path.push(store_dir);
        path.push("chunk_pool");
        ChunkPool {
            pool_path: path,
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

        let binding = self.pool_head_map.borrow_mut();
        let mut cursor = Cursor::new(binding.as_ref().unwrap());
        let pool_file = PoolHead::deserialize_from(&mut cursor).unwrap();
        *self.pool_head.borrow_mut() = Some(pool_file);

        self.next_chunk()?;

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
                    pool_size: POOL_SIZE,
                    file_size: FILE_SIZE,
                    chunk_size: CHUNK_SIZE,
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
        let actual_file_size = ((FILE_SIZE - 1) / (CHUNK_SIZE as u64) + 1) * (CHUNK_SIZE as u64);
        let actual_file_num = (POOL_SIZE + actual_file_size - 1) / actual_file_size;
        for i in 0..actual_file_num {
            let path = self.pool_path.join(format!("{:03}.da", i));
            let data_file = File::create(path)?;
            data_file.set_len(actual_file_size)?;
        }
        Ok(())
    }

    fn next_chunk(&self) -> Result<(), StoreError> {
        let actual_file_size = ((FILE_SIZE - 1) / (CHUNK_SIZE as u64) + 1) * (CHUNK_SIZE as u64);
        let file_chunk_num = actual_file_size / (CHUNK_SIZE as u64);
        let chunk_id = self.pool_head.borrow().as_ref().unwrap().next_chunk_id;
        let file_id = chunk_id / (file_chunk_num as u32);

        if self.chunk_file_id.borrow().is_none() || self.chunk_file_id.borrow().unwrap() != file_id
        {
            let path = self.pool_path.join(format!("{:03}.da", file_id));
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
                Err(e) => return Err(StoreError::IoError(e)),
            }
        }

        let inner_chunk_id = chunk_id - file_id * (file_chunk_num as u32);
        let chunk_offset = inner_chunk_id * CHUNK_SIZE;
        let mmap = unsafe {
            MmapOptions::new()
                .offset(chunk_offset.into())
                .len(CHUNK_SIZE as usize)
                .map_mut(
                    self.chunk_file_fd
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .as_raw_fd(),
                )?
        };
        *self.chunk_map.borrow_mut() = Some(mmap);

        *self.chunk_head.borrow_mut() = Some(ChunkHead::new());
        self.pool_head.borrow_mut().as_mut().unwrap().next_chunk_id += 1;
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        let mut chunk_head_map = self.chunk_map.borrow_mut();
        let mut chunk_head_map_offset: &mut [u8] = chunk_head_map.as_mut().unwrap();
        self.chunk_head
            .borrow()
            .as_ref()
            .unwrap()
            .serialize_into(&mut chunk_head_map_offset)?;
        self.chunk_map.borrow().as_ref().unwrap().flush()?;

        let mut pool_head_map = self.pool_head_map.borrow_mut();
        let mut pool_head_map_offset: &mut [u8] = pool_head_map.as_mut().unwrap();
        self.pool_head
            .borrow()
            .as_ref()
            .unwrap()
            .serialize_into(&mut pool_head_map_offset)?;
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
