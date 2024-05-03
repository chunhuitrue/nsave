use crate::common::StoreError;
use libc::{fcntl, F_SETLK, F_SETLKW};
use memmap2::{MmapMut, MmapOptions};
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
    actual_buff_len: u32,
    buff_map: RefCell<Option<MmapMut>>,
}

impl ChunkIndex {
    pub fn new() -> Self {
        let record_size = ChunkIndexRd::serialize_size();
        let actual_buff_len = ((BUFF_SIZE - 1) / (record_size as u32) + 1) * (record_size as u32);

        ChunkIndex {
            file: RefCell::new(None),
            file_len: RefCell::new(0),

            buff_offset: RefCell::new(0),
            actual_buff_len,
            buff_map: RefCell::new(None),
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

        *self.file_len.borrow_mut() += self.actual_buff_len as u64;
        file.set_len(*self.file_len.borrow())?;

        let mmap = unsafe {
            MmapOptions::new()
                .offset(*self.buff_offset.borrow())
                .len(self.actual_buff_len as usize)
                .map_mut(file.as_raw_fd())?
        };
        *self.buff_map.borrow_mut() = Some(mmap);

        let mut lock = libc::flock {
            l_type: libc::F_WRLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.buff_offset.borrow() as i64,
            l_len: self.actual_buff_len as i64,
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

    pub fn change_time_dir(&self) -> Result<(), StoreError> {
        self.buff_map.borrow().as_ref().unwrap().flush()?;
        self.unlock_buff()?;

        *self.file.borrow_mut() = None;
        *self.file_len.borrow_mut() = 0;
        *self.buff_offset.borrow_mut() = 0;
        *self.buff_map.borrow_mut() = None;
        Ok(())
    }

    pub fn unlock_buff(&self) -> Result<(), StoreError> {
        let binding = self.file.borrow_mut();
        let file = binding.as_ref().unwrap();
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: *self.buff_offset.borrow() as i64,
            l_len: self.actual_buff_len as i64,
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

    pub fn write(&self) -> Result<(), StoreError> {
        // todo
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
        let _ = self.buff_map.borrow().as_ref().unwrap().flush();
        let _ = self.unlock_buff();
    }
}

// todo
struct ChunkIndexRd {}

impl ChunkIndexRd {
    // todo
    pub fn serialize_size() -> usize {
        24
    }
}
