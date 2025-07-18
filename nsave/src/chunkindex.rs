use crate::common::*;
use crate::configure::*;
use crate::mmapbuf::*;
use bincode::deserialize_from;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt;
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct ChunkIndex {
    configure: &'static Configure,
    buf_writer: Option<MmapBufWriter>,
}

impl ChunkIndex {
    pub fn new(configure: &'static Configure) -> Self {
        ChunkIndex {
            configure,
            buf_writer: None,
        }
    }

    pub fn init_dir(&mut self, dir: &Path) -> Result<(), StoreError> {
        let mut path = PathBuf::new();
        path.push(dir);
        path.push("chunkindex.ci");
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path);
        match result {
            Ok(fd) => {
                let meta = fd.metadata()?;
                self.buf_writer = Some(MmapBufWriter::with_arg(
                    fd,
                    meta.len(),
                    self.configure.main.ci_buff_size,
                ));
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
        Ok(())
    }

    pub fn change_dir(&mut self) -> Result<(), StoreError> {
        self.buf_writer = None;
        Ok(())
    }

    pub fn write(&mut self, record: ChunkIndexRd) -> Result<u64, StoreError> {
        let ci_offset = self.buf_writer.borrow().as_ref().unwrap().next_offset();
        if let Some(ref mut writer) = self.buf_writer {
            if bincode::serialize_into(writer, &record).is_err() {
                return Err(StoreError::WriteError(
                    "chunk index write error".to_string(),
                ));
            }
        }
        Ok(ci_offset)
    }

    pub fn finish(&mut self) {
        self.buf_writer = None;
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

impl fmt::Display for ChunkIndexRd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChunkIndexRd {{ start_time: {}, end_time: {}, chunk_id: {}, chunk_offset: {}, tuple5: {:?} }}",
            ts_date(self.start_time),
            ts_date(self.end_time),
            self.chunk_id,
            self.chunk_offset,
            self.tuple5,
        )
    }
}

pub fn dump_chunkindex_file(path: PathBuf) -> Result<(), StoreError> {
    match path.extension() {
        Some(ext) => {
            if !ext.to_str().unwrap().eq("ci") {
                return Err(StoreError::CliError("not chunkindex file".to_string()));
            }
        }
        None => return Err(StoreError::CliError("not chunkindex file".to_string())),
    };

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(&path)
    {
        Ok(fd) => fd,
        Err(e) => {
            return Err(StoreError::CliError(format!("open file error: {e}")));
        }
    };
    let mut mmap_reader = MmapBufReader::new(file);
    println!("dump chunkid file: {path:?}");
    while let Ok(record) = deserialize_from::<_, ChunkIndexRd>(&mut mmap_reader) {
        println!("record: {record}");
    }
    Ok(())
}
