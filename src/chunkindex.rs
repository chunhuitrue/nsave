use crate::common::StoreError;
use crate::mmapbuf::*;
use crate::packet::*;
// use bincode::serialized_size;
// use libc::{fcntl, F_SETLK, F_SETLKW};
// use memmap2::{MmapMut, MmapOptions};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    fs::OpenOptions,
    path::{Path, PathBuf},
};

const BUFF_SIZE: u64 = 1024;

#[derive(Debug)]
pub struct ChunkIndex {
    map_buf: RefCell<Option<MmapBufWriter>>,
    // // todo del
    // file: RefCell<Option<File>>,
    // extend_file_len: RefCell<u64>,
    // buff_offset: RefCell<u64>,
    // buff_map: RefCell<Option<MmapMut>>,
    // write_buff_len: RefCell<u64>,
    // buff_len: u64,
}

impl ChunkIndex {
    pub fn new() -> Self {
        ChunkIndex {
            map_buf: RefCell::new(None),
            // // todo del
            // file: RefCell::new(None),
            // extend_file_len: RefCell::new(0),
            // buff_offset: RefCell::new(0),
            // buff_len: BUFF_SIZE,
            // buff_map: RefCell::new(None),
            // write_buff_len: RefCell::new(0),
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
                *self.map_buf.borrow_mut() =
                    Some(MmapBufWriter::with_arg(fd, meta.len(), BUFF_SIZE));

                // // todo del
                // let meta = fd.metadata()?;
                // *self.extend_file_len.borrow_mut() = meta.len();
                // *self.file.borrow_mut() = Some(fd);
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }

        // self.next_buff()?; // todo del
        Ok(())
    }

    // // todo del
    // fn next_buff(&self) -> Result<(), StoreError> {
    //     if let Some(file) = self.file.borrow().as_ref() {
    //         if *self.buff_offset.borrow() + self.buff_len >= *self.extend_file_len.borrow() {
    //             *self.extend_file_len.borrow_mut() += EXTEN_BUFF_NUM * *self.buff_len.borrow();
    //             file.set_len(*self.extend_file_len.borrow())?;
    //         }

    //         let mmap = unsafe {
    //             MmapOptions::new()
    //                 .offset(*self.buff_offset.borrow())
    //                 .len(self.buff_len as usize)
    //                 .map_mut(file.as_raw_fd())?
    //         };
    //         *self.buff_map.borrow_mut() = Some(mmap);
    //         *self.write_buff_len.borrow_mut() = 0;

    //         self.lock_buff()?;
    //         return Ok(());
    //     }
    //     Err(StoreError::OpenError("file not open".to_string()))
    // }

    pub fn change_time_dir(&self) -> Result<(), StoreError> {
        *self.map_buf.borrow_mut() = None;
        Ok(())

        // // todo del
        // self.flush()?;

        // if let Some(file) = self.file.borrow().as_ref() {
        //     file.set_len(*self.buff_offset.borrow() + *self.write_buff_len.borrow())?;

        //     *self.file.borrow_mut() = None;
        //     *self.extend_file_len.borrow_mut() = 0;
        //     *self.buff_offset.borrow_mut() = 0;
        //     return Ok(());
        // }
        // Err(StoreError::OpenError("file not open".to_string()))
    }

    // // todo del
    // fn lock_buff(&self) -> Result<(), StoreError> {
    //     if let Some(file) = self.file.borrow().as_ref() {
    //         let mut lock = libc::flock {
    //             l_type: libc::F_WRLCK,
    //             l_whence: libc::SEEK_SET as i16,
    //             l_start: *self.buff_offset.borrow() as i64,
    //             l_len: self.buff_len as i64,
    //             l_pid: 0,
    //         };
    //         let result = unsafe { fcntl(file.as_raw_fd(), F_SETLK, &mut lock) };
    //         if result == -1 {
    //             return Err(StoreError::LockError(
    //                 "lock chunkindex buff error".to_string(),
    //             ));
    //         }
    //         return Ok(());
    //     }
    //     Err(StoreError::OpenError("file not open".to_string()))
    // }

    // // todo del
    // fn unlock_buff(&self) -> Result<(), StoreError> {
    //     if let Some(file) = self.file.borrow().as_ref() {
    //         let mut lock = libc::flock {
    //             l_type: libc::F_UNLCK,
    //             l_whence: libc::SEEK_SET as i16,
    //             l_start: *self.buff_offset.borrow() as i64,
    //             l_len: self.buff_len as i64,
    //             l_pid: 0,
    //         };
    //         let result = unsafe { fcntl(file.as_raw_fd(), F_SETLKW, &mut lock) };
    //         if result == -1 {
    //             return Err(StoreError::LockError(
    //                 "unlock chunk index error".to_string(),
    //             ));
    //         }
    //         return Ok(());
    //     }
    //     Err(StoreError::OpenError("file not open".to_string()))
    // }

    // // todo del
    // fn flush(&self) -> Result<(), StoreError> {
    //     self.buff_map
    //         .borrow()
    //         .as_ref()
    //         .unwrap()
    //         .flush_range(0, *self.write_buff_len.borrow() as usize)?;

    //     *self.buff_offset.borrow_mut() += *self.write_buff_len.borrow();
    //     *self.buff_map.borrow_mut() = None;
    //     *self.write_buff_len.borrow_mut() = 0;

    //     self.unlock_buff()?;
    //     Ok(())
    // }

    pub fn write(&self, record: ChunkIndexRd) -> Result<(), StoreError> {
        let mut buf_writer = self.map_buf.borrow_mut();
        if let Some(writer) = buf_writer.as_mut() {
            if bincode::serialize_into(writer, &record).is_err() {
                return Err(StoreError::WriteError(
                    "chunk index write error".to_string(),
                ));
            }
        }
        Ok(())

        // // todo del
        // let record_seri_size = serialized_size(&record).unwrap();
        // if cfg!(debug_assertions) {
        //     let seri_record = bincode::serialize(&record).unwrap();
        //     assert_eq!(seri_record.len(), record_seri_size as usize);
        // }
        // if self.buff_len - *self.write_buff_len.borrow() < record_seri_size {
        //     self.flush()?;
        //     self.next_buff()?;
        // }

        // let mut buf_map = self.buff_map.borrow_mut();
        // let buf_u8: &mut [u8] = buf_map.as_mut().unwrap();
        // let buf_write = &mut buf_u8[*self.write_buff_len.borrow() as usize..];
        // if bincode::serialize_into(buf_write, &record).is_err() {
        //     return Err(StoreError::WriteError(
        //         "chunk index write error".to_string(),
        //     ));
        // }
        // *self.write_buff_len.borrow_mut() += record_seri_size;
        // Ok(())
    }
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self::new()
    }
}

// // todo del
// impl Drop for ChunkIndex {
//     fn drop(&mut self) {
//         let _ = self.flush();
//     }
// }

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct ChunkIndexRd {
    pub start_time: u128,
    pub end_time: u128,
    pub chunk_id: u32,
    pub chunk_offset: u32,
    pub tuple5: PacketKey,
}
