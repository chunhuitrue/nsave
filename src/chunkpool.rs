#![allow(dead_code)]

use crate::common::*;
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ChunkPool {
    pool_dir: PathBuf,
}

impl ChunkPool {
    pub fn new(store_dir: PathBuf) -> Self {
        let mut dir = PathBuf::new();
        dir.push(store_dir);
        dir.push("chunk_pool");
        ChunkPool { pool_dir: dir }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        if !self.pool_dir.exists() && fs::create_dir_all(&self.pool_dir).is_err() {
            return Err(StoreError::InitError(
                "chunk pool create dir error".to_string(),
            ));
        }

        Ok(())
    }
}
