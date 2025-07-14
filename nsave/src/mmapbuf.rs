use crate::common::StoreError;
use libc::{F_SETLK, F_SETLKW, fcntl};
use memmap2::{MmapMut, MmapOptions};
use std::io::{Read, Write};
use std::{cell::RefCell, fs::File, os::fd::AsRawFd};

const DEFAULT_WRITER_BUFF_SIZE: u64 = 1024;

#[derive(Debug)]
pub struct MmapBufWriter {
    file: File,
    file_len: u64,
    mmap: Option<MmapMut>,
    buf_write_len: u64,
    conf_buf_len: u64,
}

impl MmapBufWriter {
    pub fn new(file: File) -> Self {
        MmapBufWriter::with_arg(file, 0, DEFAULT_WRITER_BUFF_SIZE)
    }

    pub fn with_arg(file: File, file_len: u64, buf_size: u64) -> Self {
        MmapBufWriter {
            file,
            file_len,
            mmap: None,
            buf_write_len: 0,
            conf_buf_len: buf_size,
        }
    }

    fn next_mmap(&mut self) -> Result<(), StoreError> {
        let offset = self.file_len;
        self.file_len += self.conf_buf_len;
        self.file.set_len(self.file_len)?;

        let mmap = unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(self.conf_buf_len as usize)
                .map_mut(self.file.as_raw_fd())?
        };

        self.mmap = Some(mmap);
        self.buf_write_len = 0;

        self.lock_mmap()?;
        Ok(())
    }

    fn lock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: (self.file_len - self.conf_buf_len) as i64,
            l_len: self.conf_buf_len as i64,
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
            l_type: libc::F_UNLCK as _,
            l_whence: libc::SEEK_SET as i16,
            l_start: (self.file_len - self.conf_buf_len) as i64,
            l_len: self.conf_buf_len as i64,
            l_pid: 0,
        };
        let result = unsafe { fcntl(self.file.as_raw_fd(), F_SETLKW, &mut lock) };
        if result == -1 {
            return Err(StoreError::LockError("unlock mmap buff error".to_string()));
        }
        Ok(())
    }

    pub fn next_offset(&self) -> u64 {
        if self.mmap.is_none() {
            self.file_len
        } else {
            self.file_len - (self.conf_buf_len - self.buf_write_len)
        }
    }
}

impl Drop for MmapBufWriter {
    fn drop(&mut self) {
        let _ = self.flush();
        let _ = self
            .file
            .set_len(self.file_len - (self.conf_buf_len - self.buf_write_len));
    }
}

impl Write for MmapBufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.mmap.is_none() {
            self.next_mmap()?;
        }

        let write_len;
        {
            let buf_map = &mut self.mmap;
            let buf_u8: &mut [u8] = buf_map.as_mut().unwrap();
            let mut buf_write = &mut buf_u8[self.buf_write_len as usize..];
            write_len = std::io::Write::write(&mut buf_write, buf)?;
            self.buf_write_len += write_len as u64;
        }
        if self.buf_write_len >= self.conf_buf_len {
            self.flush()?;
        }
        Ok(write_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.mmap.as_ref().unwrap().flush()?;
        self.mmap = None;
        self.unlock_mmap()?;
        Ok(())
    }
}

pub const DEFAULT_READEER_BUFF_SIEZ: u64 = 1024;

#[derive(Debug)]
pub struct MmapBufReader {
    file: File,
    file_len: u64,
    mmap: RefCell<Option<MmapMut>>,
    next_offset: RefCell<usize>,
    map_len: RefCell<usize>,
    buf_read_len: RefCell<usize>,
    conf_buf_len: u64,
}

impl MmapBufReader {
    pub fn new(file: File) -> Self {
        MmapBufReader::new_with_arg(file, 0, DEFAULT_READEER_BUFF_SIEZ)
    }

    pub fn new_with_arg(file: File, offset: usize, conf_buff_len: u64) -> Self {
        let file_len = match file.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };
        MmapBufReader {
            file,
            file_len,
            mmap: RefCell::new(None),
            next_offset: RefCell::new(offset),
            map_len: RefCell::new(0),
            buf_read_len: RefCell::new(0),
            conf_buf_len: conf_buff_len,
        }
    }

    fn next_mmap(&self) -> Result<(), StoreError> {
        let remain = self.file_len - *self.next_offset.borrow() as u64;
        *self.map_len.borrow_mut() = if remain >= self.conf_buf_len {
            self.conf_buf_len as usize
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
        *self.buf_read_len.borrow_mut() = 0;

        self.lock_mmap()?;
        Ok(())
    }

    fn lock_mmap(&self) -> Result<(), StoreError> {
        let mut lock = libc::flock {
            l_type: libc::F_RDLCK as _,
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
            l_type: libc::F_UNLCK as _,
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
        if self.mmap.borrow().is_none() {
            self.next_mmap()?;
        }
        if *self.map_len.borrow() == 0 {
            return Ok(0);
        }

        let read_len;
        {
            let buf_map = self.mmap.borrow();
            let buf_u8: &[u8] = buf_map.as_ref().unwrap();
            let buf_read = &buf_u8[*self.buf_read_len.borrow()..];
            read_len = std::cmp::min(buf.len(), buf_read.len());

            buf[..read_len].copy_from_slice(&buf_read[..read_len]);
            *self.buf_read_len.borrow_mut() += read_len;
        }

        if *self.buf_read_len.borrow() >= *self.map_len.borrow() {
            self.unlock_mmap()?;
            *self.mmap.borrow_mut() = None;
        }
        Ok(read_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chunkindex::ChunkIndexRd,
        common::{PacketKey, TransProto},
    };
    use bincode::deserialize_from;
    use std::fs::OpenOptions;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::OpenOptionsExt;
    use tempfile::Builder;
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

    #[test]
    fn test_mmapbuf_reader() {
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().join("nsavechunkindex.test");
        println!("file path: {:?}", &path);
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

        // write
        let write_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let mmap_writer = MmapBufWriter::with_arg(write_file, 0, 100);
        let result = bincode::serialize_into(mmap_writer, &index);
        assert!(result.is_ok());

        // read
        let read_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(&path)
            .unwrap();
        let mut mmap_reader = MmapBufReader::new(read_file);
        let read_index = deserialize_from::<_, ChunkIndexRd>(&mut mmap_reader).unwrap();
        assert_eq!(read_index, index);
    }

    #[test]
    fn test_mmapbuf_many() {
        let index_num = 10;
        let dir = Builder::new().tempdir().unwrap();
        let path = dir.path().join("nsavechunkindex.test");
        println!("file path: {:?}", &path);

        // write
        let write_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let mut mmap_writer = MmapBufWriter::with_arg(write_file, 0, 100);
        for n in 0..index_num {
            let tuple5 = PacketKey {
                addr1: IpAddr::V4(Ipv4Addr::new(n, 1, 1, 1)),
                port1: 111,
                addr2: IpAddr::V4(Ipv4Addr::new(n, 2, 2, 2)),
                port2: 222,
                trans_proto: TransProto::Tcp,
            };
            let index = ChunkIndexRd {
                start_time: 111 + n as u128,
                end_time: 222,
                chunk_id: 12,
                chunk_offset: 100,
                tuple5,
            };

            let result = bincode::serialize_into(&mut mmap_writer, &index);
            assert!(result.is_ok());
        }

        // read
        let read_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(&path)
            .unwrap();
        let mut mmap_reader = MmapBufReader::new(read_file);
        for n in 0..index_num + 1 {
            let tuple5 = PacketKey {
                addr1: IpAddr::V4(Ipv4Addr::new(n, 1, 1, 1)),
                port1: 111,
                addr2: IpAddr::V4(Ipv4Addr::new(n, 2, 2, 2)),
                port2: 222,
                trans_proto: TransProto::Tcp,
            };
            let index = ChunkIndexRd {
                start_time: 111 + n as u128,
                end_time: 222,
                chunk_id: 12,
                chunk_offset: 100,
                tuple5,
            };

            let read_index = deserialize_from::<_, ChunkIndexRd>(&mut mmap_reader);
            if read_index.is_err() {
                let _ = dbg!(read_index);
            } else {
                assert_eq!(read_index.unwrap(), index);
            }
        }
    }
}
