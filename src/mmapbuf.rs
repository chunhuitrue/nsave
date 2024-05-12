#![allow(dead_code)]

use crate::common::StoreError;
use libc::{fcntl, F_SETLK, F_SETLKW};
use memmap2::{MmapMut, MmapOptions};
use std::borrow::Borrow;
use std::io::{Read, Write};
use std::{cell::RefCell, fs::File, os::fd::AsRawFd};

const DEFAULT_WRITER_BUFF_SIZE: u64 = 1024;

#[derive(Debug)]
pub struct MmapBufWriter {
    file: File,
    file_len: RefCell<u64>,
    mmap: RefCell<Option<MmapMut>>,
    buff_write_len: RefCell<u64>,
    conf_buff_len: u64,
}

impl MmapBufWriter {
    pub fn new(file: File) -> Self {
        MmapBufWriter::with_arg(file, 0, DEFAULT_WRITER_BUFF_SIZE)
    }

    pub fn with_arg(file: File, file_len: u64, buf_size: u64) -> Self {
        MmapBufWriter {
            file,
            file_len: RefCell::new(file_len),
            mmap: RefCell::new(None),
            buff_write_len: RefCell::new(0),
            conf_buff_len: buf_size,
        }
    }

    fn next_mmap(&self) -> Result<(), StoreError> {
        let offset = *self.file_len.borrow();
        *self.file_len.borrow_mut() += self.conf_buff_len;
        self.file.set_len(*self.file_len.borrow())?;

        let mmap = unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(*self.conf_buff_len.borrow() as usize)
                .map_mut(self.file.as_raw_fd())?
        };
        *self.mmap.borrow_mut() = Some(mmap);
        *self.buff_write_len.borrow_mut() = 0;

        self.lock_mmap()?;
        Ok(())
    }

    fn lock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: (*self.file_len.borrow() - self.conf_buff_len) as i64,
            l_len: self.conf_buff_len as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(self.file.as_raw_fd(), F_SETLK, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError("lock mmap buff error".to_string()));
        }
        Ok(())
    }

    fn unlock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: (*self.file_len.borrow() - self.conf_buff_len) as i64,
            l_len: self.conf_buff_len as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(self.file.as_raw_fd(), F_SETLKW, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError("unlock mmap buff error".to_string()));
        }
        Ok(())
    }
}

impl Drop for MmapBufWriter {
    fn drop(&mut self) {
        let _ = self.flush();
        let _ = self.file.set_len(
            *self.file_len.borrow() - (self.conf_buff_len - *self.buff_write_len.borrow()),
        );
    }
}

impl Write for MmapBufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.mmap.borrow().is_none() {
            self.next_mmap()?;
        }

        let write_len;
        {
            let mut buf_map = self.mmap.borrow_mut();
            let buf_u8: &mut [u8] = buf_map.as_mut().unwrap();
            let mut buf_write = &mut buf_u8[*self.buff_write_len.borrow() as usize..];
            write_len = std::io::Write::write(&mut buf_write, buf)?;
            *self.buff_write_len.borrow_mut() += write_len as u64;
        }
        if *self.buff_write_len.borrow() >= self.conf_buff_len {
            self.flush()?;
        }
        Ok(write_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.mmap.borrow().as_ref().unwrap().flush()?;
        *self.mmap.borrow_mut() = None;
        self.unlock_mmap()?;
        Ok(())
    }
}

const DEFAULT_READEER_BUFF_SIEZ: u64 = 1024;

#[derive(Debug)]
pub struct MmapBufReader {
    file: File,
    file_len: u64,
    mmap: RefCell<Option<MmapMut>>,
    next_offset: RefCell<usize>,
    map_len: RefCell<usize>,
    buff_read_len: RefCell<usize>,
    conf_buff_len: u64,
}

impl MmapBufReader {
    pub fn new(file: File) -> Self {
        MmapBufReader::with_arg(file, DEFAULT_READEER_BUFF_SIEZ)
    }

    pub fn with_arg(file: File, conf_buff_len: u64) -> Self {
        let file_len = match file.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        MmapBufReader {
            file,
            file_len,
            mmap: RefCell::new(None),
            next_offset: RefCell::new(0),
            map_len: RefCell::new(0),
            buff_read_len: RefCell::new(0),
            conf_buff_len,
        }
    }

    fn next_mmap(&self) -> Result<(), StoreError> {
        *self.mmap.borrow_mut() = None;

        let remain = self.file_len - *self.next_offset.borrow() as u64;
        *self.map_len.borrow_mut() = if remain >= self.conf_buff_len {
            self.conf_buff_len as usize
        } else {
            remain as usize
        };
        if *self.map_len.borrow() == 0 {
            return Ok(());
        }

        let mmap = unsafe {
            MmapOptions::new()
                .offset(*self.next_offset.borrow() as u64)
                .len(*self.map_len.borrow())
                .map_mut(self.file.as_raw_fd())?
        };
        *self.mmap.borrow_mut() = Some(mmap);
        *self.next_offset.borrow_mut() += *self.map_len.borrow();
        *self.buff_read_len.borrow_mut() = 0;

        self.lock_mmap()?;
        Ok(())
    }

    fn lock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_RDLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: (*self.next_offset.borrow() - *self.map_len.borrow()) as i64,
            l_len: *self.map_len.borrow() as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(self.file.as_raw_fd(), F_SETLK, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError("lock mmap buff error".to_string()));
        }
        Ok(())
    }

    fn unlock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_UNLCK,
            l_whence: libc::SEEK_SET as i16,
            l_start: (*self.next_offset.borrow() - *self.map_len.borrow()) as i64,
            l_len: *self.map_len.borrow() as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(self.file.as_raw_fd(), F_SETLKW, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError("unlock mmap buff error".to_string()));
        }
        Ok(())
    }
}

impl Drop for MmapBufReader {
    fn drop(&mut self) {
        let _ = self.unlock_mmap();
    }
}

impl Read for MmapBufReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chunkindex::ChunkIndexRd,
        packet::{PacketKey, TransProto},
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;

    #[test]
    fn test_mmapbuf_writer() {
        let file = NamedTempFile::new().expect("can not create tmp file");
        let temp_file_path = file.path();
        println!("tmp file path: {}", temp_file_path.display());
        let file: File = file.into_file();
        let mmap_writer = MmapBufWriter::new(file);

        let tuple5 = PacketKey {
            addr1: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port1: 111,
            addr2: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            port2: 222,
            trans_proto: TransProto::Tcp,
        };
        let index = ChunkIndexRd {
            start_time: 111,
            end_time: 222,
            chunk_id: 12,
            chunk_offset: 100,
            tuple5,
        };
        let result = bincode::serialize_into(mmap_writer, &index);
        assert!(result.is_ok());
    }
}
