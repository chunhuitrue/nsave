use crate::{chunkindex::*, common::*, configure::*, mmapbuf::*};
use chrono::NaiveDateTime;
use std::{fs::OpenOptions, path::PathBuf};

#[derive(Debug)]
pub struct SearchCi {
    reader: Option<MmapBufReader>,
}

impl SearchCi {
    pub fn new(
        configure: &'static Configure,
        date: NaiveDateTime,
        offset: u64,
        dir_id: u64,
    ) -> Self {
        let dir = date2dir(configure, dir_id, date);
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
            Ok(file) => SearchCi {
                reader: Some(MmapBufReader::new_with_arg(
                    file,
                    offset as usize,
                    DEFAULT_READEER_BUFF_SIEZ,
                )),
            },
            Err(_e) => SearchCi { reader: None },
        }
    }

    pub fn next_ci(&mut self) -> Option<ChunkIndexRd> {
        if let Some(ref mut reader) = self.reader {
            if let Ok(rd) = bincode::deserialize_from(reader) {
                return Some(rd);
            }
        }
        None
    }
}
