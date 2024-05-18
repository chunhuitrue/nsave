use crate::chunkindex::*;
use crate::chunkpool::*;
use crate::common::*;
use crate::flow::FlowNode;
use crate::packet::*;
use crate::timeindex::*;
use chrono::{DateTime, Datelike, Local, Timelike};
use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    sync::{mpsc::SyncSender, Arc},
};

const POOL_SIZE: u64 = 1024 * 1024 * 16; // 16M
const FILE_SIZE: u64 = 1024 * 1024 * 2; // 2M
const CHUNK_SIZE: u32 = 1024 * 80; // 80k

#[derive(Debug)]
pub struct StoreCtx {
    prev_pkt_offset: RefCell<ChunkOffset>,
    flow_key: RefCell<Option<PacketKey>>,
    chunk_id: RefCell<Option<u32>>,

    ti_write: RefCell<bool>,
}

impl StoreCtx {
    pub fn new() -> Self {
        StoreCtx {
            prev_pkt_offset: RefCell::new(ChunkOffset::new()),
            flow_key: RefCell::new(None),
            chunk_id: RefCell::new(None),
            ti_write: RefCell::new(false),
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
    current_dir_date: RefCell<DateTime<Local>>,
    chunk_pool: ChunkPool,
    msg_channel: SyncSender<Msg>,
    chunk_index: RefCell<ChunkIndex>,
    time_index: RefCell<TimeIndex>,
}

impl Store {
    pub fn new(store_dir: PathBuf, msg_channel: SyncSender<Msg>) -> Self {
        Store {
            store_dir: store_dir.clone(),
            current_dir: RefCell::new(None),
            current_dir_date: RefCell::new(ts_date(0)),
            chunk_pool: ChunkPool::new(store_dir, POOL_SIZE, FILE_SIZE, CHUNK_SIZE),
            msg_channel,
            chunk_index: RefCell::new(ChunkIndex::new()),
            time_index: RefCell::new(TimeIndex::new()),
        }
    }

    pub fn init(&self) -> Result<(), StoreError> {
        self.chunk_pool.init()?;
        Ok(())
    }

    pub fn store(
        &self,
        flow_node: &FlowNode,
        pkt: Arc<Packet>,
        now: u128,
    ) -> Result<(), StoreError> {
        if self.current_dir.borrow().is_none() {
            self.mk_time_dir(now)?;
            self.chunk_index
                .borrow_mut()
                .init_dir(self.current_dir.borrow().as_ref().unwrap())?;
            self.time_index
                .borrow_mut()
                .init_dir(self.current_dir.borrow().as_ref().unwrap())?;
        }

        let ctx = flow_node.store_ctx.as_ref().unwrap();
        let pkt_offset = self.chunk_pool.write(pkt, now, |pool_path, end_time| {
            let msg = Msg::CoverChunk(pool_path, end_time);
            let _ = self.msg_channel.try_send(msg);
        })?;
        if ctx.prev_pkt_offset.borrow().chunk_id == pkt_offset.chunk_id {
            self.chunk_pool
                .update(&ctx.prev_pkt_offset.borrow(), &pkt_offset)?;
        }
        *ctx.prev_pkt_offset.borrow_mut() = pkt_offset;

        let ci_offset = if ctx.flow_key.borrow().is_none()
            || pkt_offset.chunk_id != ctx.chunk_id.borrow().unwrap()
        {
            *ctx.flow_key.borrow_mut() = Some(flow_node.key);
            *ctx.chunk_id.borrow_mut() = Some(pkt_offset.chunk_id);
            let offset = self.chunk_index.borrow_mut().write(ChunkIndexRd {
                start_time: flow_node.start_time,
                end_time: 0,
                chunk_id: pkt_offset.chunk_id,
                chunk_offset: pkt_offset.start_offset,
                tuple5: ctx.flow_key.borrow().unwrap(),
            })?;
            Some(offset)
        } else {
            None
        };

        if let Some(offset) = ci_offset {
            let mut ti_write = ctx.ti_write.borrow_mut();
            if !*ti_write {
                *ti_write = true;
                self.time_index.borrow_mut().write(LinkRecord {
                    start_time: flow_node.start_time,
                    end_time: 0,
                    tuple5: ctx.flow_key.borrow().unwrap(),
                    ci_offset: offset,
                })?;
            }
        }
        Ok(())
    }

    pub fn link_fin(
        &self,
        tuple5: &PacketKey,
        start_time: u128,
        end_time: u128,
    ) -> Result<(), StoreError> {
        let ci_offset = self.chunk_index.borrow_mut().write(ChunkIndexRd {
            start_time,
            end_time,
            chunk_id: 0,
            chunk_offset: 0,
            tuple5: *tuple5,
        });

        if let Ok(offset) = ci_offset {
            self.time_index.borrow_mut().write(LinkRecord {
                start_time,
                end_time,
                tuple5: *tuple5,
                ci_offset: offset,
            })?;
        }
        Ok(())
    }

    pub fn timer(&self, now: u128) -> Result<(), StoreError> {
        if self.current_dir.borrow().is_none() {
            return Ok(());
        }

        let date_now = ts_date(now);
        let cur_dir_date = *self.current_dir_date.borrow();
        if !(date_now.year() == cur_dir_date.year()
            && date_now.month() == cur_dir_date.month()
            && date_now.day() == cur_dir_date.day()
            && date_now.hour() == cur_dir_date.hour()
            && date_now.minute() == cur_dir_date.minute())
        {
            self.chunk_index.borrow_mut().change_dir()?;
            self.time_index.borrow_mut().change_dir()?;

            *self.current_dir.borrow_mut() = None;
        }
        Ok(())
    }

    fn mk_time_dir(&self, timestamp: u128) -> Result<(), StoreError> {
        let date = ts_date(timestamp);
        let mut path = PathBuf::new();
        path.push(&self.store_dir);
        path.push(format!("{:04}", date.year()));
        path.push(format!("{:02}", date.month()));
        path.push(format!("{:02}", date.day()));
        path.push(format!("{:02}", date.hour()));
        path.push(format!("{:02}", date.minute()));

        if !path.exists() && fs::create_dir_all(&path).is_err() {
            return Err(StoreError::WriteError("create dir error".to_string()));
        }

        *self.current_dir.borrow_mut() = Some(path);
        *self.current_dir_date.borrow_mut() = date;
        Ok(())
    }
}

pub fn clean_index_dir(pool_path: PathBuf, end_date: DateTime<Local>) -> Result<(), StoreError> {
    let now_date = ts_date(timenow());
    if now_date.minute() == end_date.minute() {
        return Ok(());
    }

    clean_minute_dir(&pool_path, end_date)?;
    clean_hour_dir(&pool_path, end_date)?;
    clean_day_dir(&pool_path, end_date)?;
    clean_month_dir(&pool_path, end_date)?;
    clean_year_dir(&pool_path, end_date)?;
    Ok(())
}

fn clean_minute_dir(pool_path: &Path, end_date: DateTime<Local>) -> Result<(), StoreError> {
    for minute in (0..=end_date.minute()).rev() {
        let mut path = PathBuf::new();
        path.push(pool_path);
        path.pop();
        path.push(format!("{:04}", end_date.year()));
        path.push(format!("{:02}", end_date.month()));
        path.push(format!("{:02}", end_date.day()));
        path.push(format!("{:02}", end_date.hour()));
        path.push(format!("{:02}", minute));
        if path.exists() {
            println!("minute path: {:?}", path);
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn clean_hour_dir(pool_path: &Path, end_date: DateTime<Local>) -> Result<(), StoreError> {
    let mut path = PathBuf::new();
    path.push(pool_path);
    path.pop();
    path.push(format!("{:04}", end_date.year()));
    path.push(format!("{:02}", end_date.month()));
    path.push(format!("{:02}", end_date.day()));
    path.push(format!("{:02}", end_date.hour()));
    if is_empty_dir(&path) {
        println!("hour path: {:?}", path);
        fs::remove_dir_all(path)?;
    }

    for hour in (0..end_date.hour()).rev() {
        let mut path = PathBuf::new();
        path.push(pool_path);
        path.pop();
        path.push(format!("{:04}", end_date.year()));
        path.push(format!("{:02}", end_date.month()));
        path.push(format!("{:02}", end_date.day()));
        path.push(format!("{:02}", hour));
        if path.exists() {
            println!("hour before path: {:?}", path);
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn clean_day_dir(pool_path: &Path, end_date: DateTime<Local>) -> Result<(), StoreError> {
    let mut path = PathBuf::new();
    path.push(pool_path);
    path.pop();
    path.push(format!("{:04}", end_date.year()));
    path.push(format!("{:02}", end_date.month()));
    path.push(format!("{:02}", end_date.day()));
    if is_empty_dir(&path) {
        println!("day path: {:?}", path);
        fs::remove_dir_all(path)?;
    }

    for day in (1..end_date.day()).rev() {
        let mut path = PathBuf::new();
        path.push(pool_path);
        path.pop();
        path.push(format!("{:04}", end_date.year()));
        path.push(format!("{:02}", end_date.month()));
        path.push(format!("{:02}", day));
        if path.exists() {
            println!("day before path: {:?}", path);
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn clean_month_dir(pool_path: &Path, end_date: DateTime<Local>) -> Result<(), StoreError> {
    let mut path = PathBuf::new();
    path.push(pool_path);
    path.pop();
    path.push(format!("{:04}", end_date.year()));
    path.push(format!("{:02}", end_date.month()));
    if is_empty_dir(&path) {
        println!("moutn path: {:?}", path);
        fs::remove_dir_all(path)?;
    }

    for month in (1..end_date.month()).rev() {
        let mut path = PathBuf::new();
        path.push(pool_path);
        path.pop();
        path.push(format!("{:04}", end_date.year()));
        path.push(format!("{:02}", month));
        if path.exists() {
            println!("month before path: {:?}", path);
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn clean_year_dir(pool_path: &Path, end_date: DateTime<Local>) -> Result<(), StoreError> {
    let mut path = PathBuf::new();
    path.push(pool_path);
    path.pop();
    path.push(format!("{:04}", end_date.year()));
    if is_empty_dir(&path) {
        fs::remove_dir_all(path)?;
    }

    let mut path = PathBuf::new();
    path.push(pool_path);
    path.pop();
    path.push(format!("{:04}", end_date.year() - 1));
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn is_empty_dir(dir_path: &Path) -> bool {
    let mut entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(_) => return false, // 如果读取目录失败，可能是因为没有权限等原因，不视为空
    };
    entries.next().is_none()
}
