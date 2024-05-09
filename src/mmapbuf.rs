#![allow(dead_code)]

use std::io::Write;
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
};

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub struct MmapBufWriter {
    file: File,
}

impl MmapBufWriter {
    pub fn new(file: File) -> MmapBufWriter {
        MmapBufWriter::with_capacity(DEFAULT_BUF_SIZE, file)
    }

    pub fn with_capacity(_capacity: usize, file: File) -> MmapBufWriter {
        MmapBufWriter { file }
    }
}

impl Write for MmapBufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        chunkindex::ChunkIndexRd,
        packet::{PacketKey, TransProto},
    };

    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_mmapbufwriter() {
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
