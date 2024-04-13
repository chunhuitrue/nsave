#![allow(dead_code)]

use crate::chunkpool::*;
use crate::common::*;
use crate::packet::*;
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use std::fs;
use std::{cell::RefCell, path::PathBuf, sync::Arc};

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
pub struct Store {
    store_dir: PathBuf,
    current_dir: RefCell<Option<PathBuf>>,
    current_scale: RefCell<u32>,
    chunk_pool: ChunkPool,
}

impl Store {
    pub fn new(store_dir: PathBuf) -> Self {
        Store {
            store_dir: store_dir.clone(),
            current_dir: RefCell::new(None),
            current_scale: RefCell::new(0),
            chunk_pool: ChunkPool::new(store_dir),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        self.chunk_pool.init()?;
        Ok(())
    }

    pub fn store(&self, _ctx: &StoreCtx, _pkt: Arc<Packet>, now: u128) -> Result<(), StoreError> {
        if self.current_dir.borrow().is_none() {
            self.mk_time_scale_dir(now)?;
        }

        // todo 写入数据包，回填之前的数据包的偏移，记录当前数据包的偏移到ctx

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

fn ts_date(timestamp: u128) -> DateTime<Local> {
    let naive_datetime = DateTime::from_timestamp(
        (timestamp / 1_000_000_000).try_into().unwrap(),
        (timestamp % 1_000_000_000) as u32,
    );
    Local.from_utc_datetime(
        &naive_datetime
            .expect("Failed to convert to local time")
            .naive_utc(),
    )
}
