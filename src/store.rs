#![allow(dead_code)]

// use crate::data::*;
use crate::common::*;
use crate::packet::*;
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use std::fs;
use std::{cell::RefCell, path::PathBuf, sync::Arc};

#[derive(Debug)]
pub struct StoreCtx {
    // data_ctx: DataCtx,
}

impl StoreCtx {
    pub fn new() -> Self {
        StoreCtx {
            // data_ctx: DataCtx::new(),
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
    // data: Data,
    current_dir: RefCell<Option<PathBuf>>,
    current_scale: RefCell<u32>,
}

impl Store {
    pub fn new(store_dir: PathBuf) -> Self {
        Store {
            store_dir,
            // data: Data::new(),
            current_dir: RefCell::new(None),
            current_scale: RefCell::new(0),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        // self.data.init(&self.dir)?;
        Ok(())
    }

    pub fn store(&self, _ctx: &StoreCtx, _pkt: Arc<Packet>, now: u128) -> Result<(), StoreError> {
        // self.data.store(&ctx.data_ctx, pkt, now);
        if self.current_dir.borrow().is_none() {
            self.mk_time_scale_dir(now)?;
        }
        Ok(())
    }

    pub fn link_fin(
        &self,
        _tuple5: &PacketKey,
        _start_time: u128,
        _end_time: u128,
    ) -> Result<(), StoreError> {
        // self.data.link_fin(tuple5, now);
        Ok(())
    }

    pub fn timer(&self, now: u128) -> Result<(), StoreError> {
        // self.data.timer(now);

        if self.current_dir.borrow().is_none() {
            return Ok(());
        }

        let now_scale = ts_date(now).second() / TIME_SCALE;
        if now_scale != *self.current_scale.borrow() {
            self.flush(now)?;
            *self.current_dir.borrow_mut() = None;
        }
        Ok(())
    }

    // 当时间刻度scal变化时，新建新的dir或文件之前，需要刷新现有的到磁盘
    fn flush(&self, _now: u128) -> Result<(), StoreError> {
        // todo
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
