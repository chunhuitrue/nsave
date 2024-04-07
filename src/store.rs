#![allow(dead_code)]

// use crate::data::*;
use crate::common::*;
use crate::packet::*;
use chrono::Timelike;
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
    current_minute: RefCell<u32>,
}

impl Store {
    pub fn new(store_dir: PathBuf) -> Self {
        Store {
            store_dir,
            // data: Data::new(),
            current_dir: RefCell::new(None),
            current_minute: RefCell::new(0),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        // self.data.init(&self.dir)?;
        Ok(())
    }

    pub fn store(&self, _ctx: &StoreCtx, _pkt: Arc<Packet>, now: u128) -> Result<(), StoreError> {
        // self.data.store(&ctx.data_ctx, pkt, now);
        if self.current_dir.borrow().is_none() {
            mk_minute_dir(now)?;
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
        let minute = ts_date_local(now).minute();
        if minute != *self.current_minute.borrow() {
            *self.current_minute.borrow_mut() = minute;
        }

        Ok(())
    }
}
