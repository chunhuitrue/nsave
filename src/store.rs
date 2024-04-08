#![allow(dead_code)]

// use crate::data::*;
use crate::common::*;
use crate::packet::*;
use chrono::{DateTime, Datelike, Duration, Local, NaiveDateTime, TimeZone, Timelike};
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
    current_scale_minute: RefCell<u32>, // 刻度对应的分钟值,判断时间刻度变化不能值判断scale值，因为下一个分钟内的刻度值会和当前的一样，如果跨越一分钟都没有数据包，那么就会出现scale值相等但实际上已经时间变化了的情况。
}

impl Store {
    pub fn new(store_dir: PathBuf) -> Self {
        Store {
            store_dir,
            // data: Data::new(),
            current_dir: RefCell::new(None),
            current_scale: RefCell::new(0),
            current_scale_minute: RefCell::new(0),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        // self.data.init(&self.dir)?;
        Ok(())
    }

    pub fn store(&self, _ctx: &StoreCtx, _pkt: Arc<Packet>, now: u128) -> Result<(), StoreError> {
        // self.data.store(&ctx.data_ctx, pkt, now);
        if self.current_dir.borrow().is_none() {
            self.flush(now)?;
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

        let (now_scale, now_scale_minute) = ts_scale(now);
        if now_scale != *self.current_scale.borrow()
            && now_scale_minute != *self.current_scale_minute.borrow()
        {
            *self.current_dir.borrow_mut() = None;
        }

        Ok(())
    }

    // 当时间刻度scal变化时，新建新的dir或文件之前，需要刷新现有的到磁盘
    fn flush(&self, _now: u128) -> Result<(), StoreError> {
        // todo
        dbg!("flush");
        Ok(())
    }

    fn mk_time_scale_dir(&self, _timestamp: u128) -> Result<PathBuf, StoreError> {
        // let minute = ts_date_local(timestamp).minute();
        // if minute != *self.current_minute.borrow() {
        //     *self.current_minute.borrow_mut() = minute;
        // }

        todo!()
    }
}

fn ts_date_local(timestamp: u128) -> DateTime<Local> {
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

fn ts_scale(_timestamp: u128) -> (u32, u32) {
    todo!()
}
