#![allow(dead_code)]

use crate::common::StoreError;
use crate::packet::*;
use bincode::serialized_size;
use libc::{fcntl, F_SETLK, F_SETLKW};
use memmap2::{MmapMut, MmapOptions};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;

const BUFF_SIZE: u32 = 1024 * 8; // 8k

#[derive(Debug)]
pub struct ChunkIndex {
    file: RefCell<Option<File>>,
    file_len: RefCell<u64>,

    buff_offset: RefCell<u64>,
    buff_map: RefCell<Option<MmapMut>>,
    buff_len: u32,
    write_len: RefCell<u32>,
}

impl ChunkIndex {
    pub fn new() -> Self {
        ChunkIndex {
            file: RefCell::new(None),
            file_len: RefCell::new(0),

            buff_offset: RefCell::new(0),
            buff_len: BUFF_SIZE,
            buff_map: RefCell::new(None),
            write_len: RefCell::new(0),
        }
    }

    pub fn init_time_dir(&self, dir: &Path) -> Result<(), StoreError> {
        let mut path = PathBuf::new();
        path.push(dir);
        path.push("chunkindex");
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path);
        match result {
            Ok(fd) => {
                let meta = fd.metadata()?;
                *self.file_len.borrow_mut() = meta.len();
                *self.file.borrow_mut() = Some(fd);
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }

        self.next_buff()?;
        Ok(())
    }

    fn next_buff(&self) -> Result<(), StoreError> {
        let binding = self.file.borrow_mut();
        let file = binding.as_ref().unwrap();
        *self.buff_offset.borrow_mut() = *self.file_len.borrow();
        let mmap = unsafe {
            MmapOptions::new()
                .offset(*self.buff_offset.borrow())
                .len(self.buff_len as usize)
                .map_mut(file.as_raw_fd())?
        };
        *self.buff_map.borrow_mut() = Some(mmap);
        *self.write_len.borrow_mut() = 0;

        self.lock_buff()?;
        Ok(())
    }

    pub fn change_time_dir(&self) -> Result<(), StoreError> {
        self.flush()?;
        *self.file.borrow_mut() = None;
        *self.file_len.borrow_mut() = 0;
        Ok(())
    }

    fn lock_buff(&self) -> Result<(), StoreError> {
        let binding = self.file.borrow_mut();
        let file = binding.as_ref().unwrap();
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.buff_offset.borrow() as i64,
            l_len: self.buff_len as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(file.as_raw_fd(), F_SETLK, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError(
                "lock chunkindex buff error".to_string(),
            ));
        }
        Ok(())
    }

    fn unlock_buff(&self) -> Result<(), StoreError> {
        let binding = self.file.borrow_mut();
        let file = binding.as_ref().unwrap();
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.buff_offset.borrow() as i64,
            l_len: self.buff_len as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(file.as_raw_fd(), F_SETLKW, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError(
                "unlock chunk index error".to_string(),
            ));
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        self.buff_map
            .borrow()
            .as_ref()
            .unwrap()
            .flush_range(0, *self.write_len.borrow() as usize)?;
        *self.file_len.borrow_mut() += *self.write_len.borrow() as u64;
        *self.write_len.borrow_mut() = 0;

        self.unlock_buff()?;
        Ok(())
    }

    pub fn write(&self, record: ChunkIndexRd) -> Result<(), StoreError> {
        let record_seri_size = serialized_size(&record).unwrap() as u32;
        if cfg!(debug_assertions) {
            let seri_record = bincode::serialize(&record).unwrap();
            assert_eq!(seri_record.len(), record_seri_size as usize);
        }
        if self.buff_len - *self.write_len.borrow() < record_seri_size {
            self.flush()?;
            self.next_buff()?;
        }

        let mut buf_map = self.buff_map.borrow_mut();
        let buf_u8: &mut [u8] = buf_map.as_mut().unwrap();
        let buf_write = &mut buf_u8[*self.write_len.borrow() as usize..];
        if bincode::serialize_into(buf_write, &record).is_err() {
            return Err(StoreError::WriteError(
                "chunk index write error".to_string(),
            ));
        }
        *self.write_len.borrow_mut() += record_seri_size;
        Ok(())
    }
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ChunkIndex {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct ChunkIndexRd {
    pub start_time: u128,
    pub end_time: u128,
    pub chunk_id: u32,
    pub chunk_offset: u32,
    pub tuple5: PacketKey,
}
