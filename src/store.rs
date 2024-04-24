#![allow(dead_code)]

use crate::chunkpool::*;
use crate::common::*;
use crate::packet::*;
use chrono::{Datelike, Timelike};
use std::fs;
use std::sync::mpsc::SyncSender;
use std::{cell::RefCell, path::PathBuf, sync::Arc};

const POOL_SIZE: u64 = 1024 * 1024 * 4; // 4M
const FILE_SIZE: u64 = 1024 * 1024; // 1M
const CHUNK_SIZE: u32 = 1024 * 80; // 80k

#[derive(Debug)]
pub struct StoreCtx {
    prev_pkt_offset: RefCell<ChunkOffset>,
}

impl StoreCtx {
    pub fn new() -> Self {
        StoreCtx {
            prev_pkt_offset: RefCell::new(ChunkOffset::new()),
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
    store_dir: PathBuf,
    current_dir: RefCell<Option<PathBuf>>,
    current_scale: RefCell<u32>,
    chunk_pool: ChunkPool,
    msg_channel: SyncSender<Msg>,
}

impl Store {
    pub fn new(store_dir: PathBuf, msg_channel: SyncSender<Msg>) -> Self {
        Store {
            store_dir: store_dir.clone(),
            current_dir: RefCell::new(None),
            current_scale: RefCell::new(0),
            chunk_pool: ChunkPool::new(store_dir, POOL_SIZE, FILE_SIZE, CHUNK_SIZE),
            msg_channel,
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        self.chunk_pool.init()?;
        Ok(())
    }

    pub fn store(&self, ctx: &StoreCtx, pkt: Arc<Packet>, now: u128) -> Result<(), StoreError> {
        if self.current_dir.borrow().is_none() {
            self.mk_time_scale_dir(now)?;
        }

        let pkt_offset = self.chunk_pool.write(pkt, now, |start_time, end_time| {
            let msg = Msg::CoverChunk(start_time, end_time);
            let _ = self.msg_channel.try_send(msg);
        })?;
        if ctx.prev_pkt_offset.borrow().chunk_id == pkt_offset.chunk_id {
            self.chunk_pool
                .update(&ctx.prev_pkt_offset.borrow(), &pkt_offset)?;
        }
        *ctx.prev_pkt_offset.borrow_mut() = pkt_offset;
        Ok(())
    }

    pub fn link_fin(
        &self,
        _tuple5: &PacketKey,
        _start_time: u128,
        _end_time: u128,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    pub fn timer(&self, now: u128) -> Result<(), StoreError> {
        if self.current_dir.borrow().is_none() {
            return Ok(());
        }

        let now_scale = ts_date(now).second() / TIME_SCALE;
        if now_scale != *self.current_scale.borrow() {
            self.time_scale_change(now)?;
            *self.current_dir.borrow_mut() = None;
        }
        Ok(())
    }

    fn time_scale_change(&self, _now: u128) -> Result<(), StoreError> {
        dbg!("flush data index to disk ...");
        Ok(())
    }

    fn mk_time_scale_dir(&self, timestamp: u128) -> Result<(), StoreError> {
        let date = ts_date(timestamp);
        let scale = date.second() / TIME_SCALE;
        let mut path = PathBuf::new();
        path.push(&self.store_dir);
        path.push(format!("{:04}", date.year()));
        path.push(format!("{:02}", date.month()));
        path.push(format!("{:02}", date.day()));
        path.push(format!("{:02}", date.hour()));
        path.push(format!("{:02}", date.minute()));
        path.push(format!("{:02}", scale));

        if !path.exists() && fs::create_dir_all(&path).is_err() {
            return Err(StoreError::WriteError("create dir error".to_string()));
        }

        *self.current_dir.borrow_mut() = Some(path);
        *self.current_scale.borrow_mut() = scale;
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.chunk_pool.flush();
    }
}
