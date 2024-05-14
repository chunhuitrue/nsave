use crate::common::StoreError;
use crate::mmapbuf::*;
use crate::packet::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

const BUFF_SIZE: u64 = 1024;

#[derive(Debug)]
pub struct ChunkIndex {
    map_buf: Option<MmapBufWriter>,
}

impl ChunkIndex {
    pub fn new() -> Self {
        ChunkIndex { map_buf: None }
    }

    pub fn init_time_dir(&mut self, dir: &Path) -> Result<(), StoreError> {
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
                self.map_buf = Some(MmapBufWriter::with_arg(fd, meta.len(), BUFF_SIZE));
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
        Ok(())
    }

    pub fn change_time_dir(&mut self) -> Result<(), StoreError> {
        self.map_buf = None;
        Ok(())
    }

    pub fn write(&mut self, record: ChunkIndexRd) -> Result<(), StoreError> {
        if let Some(ref mut writer) = self.map_buf {
            if bincode::serialize_into(writer, &record).is_err() {
                return Err(StoreError::WriteError(
                    "chunk index write error".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self::new()
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
