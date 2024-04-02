#![allow(dead_code)]

use crate::packet::*;
use std::fs::OpenOptions;
use std::{
    cell::RefCell,
    fs::{self, File},
    path::PathBuf,
    sync::Arc,
};

const STORE_FILE_SIZE: u64 = 1024 * 1024 * 4; // 4M
const STORE_CHUNK_SIZE: u16 = 1024 * 4; // 4k

#[derive(Debug)]
pub struct StoreCtx {}

impl StoreCtx {
    pub fn new() -> Self {
        StoreCtx {}
    }
}

impl Default for StoreCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct PktStore {
    store_dir: PathBuf,
    cur_store_file: RefCell<Option<File>>,
}

impl PktStore {
    pub fn new(store_dir: PathBuf) -> Self {
        PktStore {
            store_dir,
            cur_store_file: RefCell::new(None),
        }
    }

    pub fn init(&self) -> Result<(), PktStoreError> {
        self.init_store_file()?;
        Ok(())
    }

    pub fn store_pkt(&self, _ctx: &StoreCtx, _pkt: Arc<Packet>, _now: u128) {
        // dbg!("store_pkt");
    }

    pub fn link_fin(&self, _now: u128) {
        // dbg!("link_fin");
    }

    pub fn timer(&self, _now: u128) {
        dbg!("timer");
    }

    fn init_store_file(&self) -> Result<(), PktStoreError> {
        let mut file_name = self.store_dir.clone();
        file_name.push(format!("{}.da", "store"));
        if !file_name.exists() {
            fs::File::create(&file_name)?;
            let result = OpenOptions::new().read(true).write(true).open(&file_name);
            match result {
                Ok(file) => {
                    *self.cur_store_file.borrow_mut() = Some(file);
                }
                Err(e) => return Err(PktStoreError::IoError(e)),
            }
            self.format_store_file()?;
        }
        Ok(())
    }

    fn format_store_file(&self) -> Result<(), PktStoreError> {
        // let file = self.cur_store_file.borrow();
        todo!()
    }
}

#[derive(Debug)]
struct FileHead {
    chunk_num: u32,
    head_chunk: u32,
    tail_chunk: u32,
}

impl FileHead {
    pub fn new() -> Self {
        FileHead {
            chunk_num: 0,
            head_chunk: 0,
            tail_chunk: 0,
        }
    }
}

struct ChunkHead {}

#[derive(Debug)]
pub enum PktStoreError {
    IoError(std::io::Error),
    InitError(String),
    FormatError(String),
}

impl std::fmt::Display for PktStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PktStoreError::IoError(err) => write!(f, "IO error: {}", err),
            PktStoreError::InitError(msg) => write!(f, "Init error: {}", msg),
            PktStoreError::FormatError(msg) => write!(f, "Format error: {}", msg),
        }
    }
}

impl std::error::Error for PktStoreError {}

impl From<std::io::Error> for PktStoreError {
    fn from(err: std::io::Error) -> Self {
        PktStoreError::IoError(err)
    }
}

impl From<String> for PktStoreError {
    fn from(err: String) -> Self {
        PktStoreError::InitError(err)
    }
}
