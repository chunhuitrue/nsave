#![allow(dead_code)]

use crate::data::*;
use crate::packet::*;
use std::{path::PathBuf, sync::Arc};

#[derive(Debug)]
pub struct StoreCtx {
    data_ctx: DataCtx,
}

impl StoreCtx {
    pub fn new() -> Self {
        StoreCtx {
            data_ctx: DataCtx::new(),
        }
    }
}

impl Default for StoreCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    data: Data,
}

impl Store {
    pub fn new(store_dir: PathBuf) -> Self {
        Store {
            dir: store_dir,
            data: Data::new(),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        self.data.init(&self.dir)?;
        Ok(())
    }

    pub fn store(&self, ctx: &StoreCtx, pkt: Arc<Packet>, now: u128) {
        self.data.store(&ctx.data_ctx, pkt, now);
    }

    pub fn link_fin(&self, tuple5: &PacketKey, now: u128) {
        self.data.link_fin(tuple5, now);
    }

    pub fn timer(&self, now: u128) {
        self.data.timer(now);
    }
}

#[derive(Debug)]
pub enum StoreError {
    IoError(std::io::Error),
    InitError(String),
    FormatError(String),
    ReadError(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(err) => write!(f, "IO error: {}", err),
            StoreError::InitError(msg) => write!(f, "Init error: {}", msg),
            StoreError::FormatError(msg) => write!(f, "Format error: {}", msg),
            StoreError::ReadError(msg) => write!(f, "Read error: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        StoreError::IoError(err)
    }
}

impl From<String> for StoreError {
    fn from(err: String) -> Self {
        StoreError::InitError(err)
    }
}
