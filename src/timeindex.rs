#![allow(dead_code)]

use crate::packet::PacketKey;
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

const TIMER_INTERVEL: u128 = 1_000_000_000; // 1秒
const DATA_PATH: &str = "/Users/lch/misc/nsava_data/";
static mut PREV_TS: u128 = 0;

#[derive(Debug)]
pub struct TimeIndex {
    index_file: RefCell<Option<File>>,
    current_minute: RefCell<u32>,
}

impl TimeIndex {
    pub fn new() -> Self {
        TimeIndex {
            index_file: RefCell::new(None),
            current_minute: RefCell::new(0),
        }
    }

    pub fn save_index(&self, _link: &PacketKey, now: u128) -> Result<(), TimeIndexError> {
        if self.index_file.borrow().is_none() {
            if let Ok((file, cur_minute)) = current_index_file(now) {
                *self.index_file.borrow_mut() = Some(file);
                *self.current_minute.borrow_mut() = cur_minute;
            } else {
                return Err(TimeIndexError::TimeIndex);
            }
        }

        // todo
        dbg!("TimeIndex. save_index");

        Ok(())
    }

    pub fn timer(&self, now: u128) {
        unsafe {
            if PREV_TS == 0 {
                PREV_TS = now;
                return;
            }

            if now > PREV_TS + TIMER_INTERVEL {
                PREV_TS = now;

                dbg!("TimeIndex. 切换目录");
                if let Ok((file, cur_minute)) = current_index_file(now) {
                    // todo 刷新写入文件
                    if *self.current_minute.borrow() != cur_minute {
                        *self.index_file.borrow_mut() = Some(file);
                        *self.current_minute.borrow_mut() = cur_minute;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum TimeIndexError {
    CreatePath,
    CreateFile,
    TimeIndex,
}

// 如果文件不存在，就创建。如果已经存在，就open。
fn current_index_file(timestamp: u128) -> Result<(File, u32), TimeIndexError> {
    let date = ts_date_local(timestamp);
    let mut path = PathBuf::new();
    path.push(DATA_PATH);
    path.push(format!("{:04}", date.year()));
    path.push(format!("{:02}", date.month()));
    path.push(format!("{:02}", date.day()));
    path.push(format!("{:02}", date.hour()));
    path.push(format!("{:02}", date.minute()));
    if !path.exists() && fs::create_dir_all(&path).is_err() {
        return Err(TimeIndexError::CreatePath);
    }

    path.push(format!("{:02}.ti", date.minute()));
    let result = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path);
    match result {
        Ok(file) => Ok((file, date.minute())),
        Err(_) => Err(TimeIndexError::CreateFile),
    }
}

fn ts_date_local(timestamp_nanos: u128) -> DateTime<Local> {
    let naive_datetime = DateTime::from_timestamp(
        (timestamp_nanos / 1_000_000_000).try_into().unwrap(),
        (timestamp_nanos % 1_000_000_000) as u32,
    );
    Local.from_utc_datetime(
        &naive_datetime
            .expect("Failed to convert to local time")
            .naive_utc(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ts_data_local() {
        let timestamp = 1711256627183244000; // 2024/03/24 13:03:47
        let date_local = ts_date_local(timestamp);

        assert_eq!(2024, date_local.year());
        assert_eq!(3, date_local.month());
        assert_eq!(24, date_local.day());
        assert_eq!(13, date_local.hour());
        assert_eq!(3, date_local.minute());
        assert_eq!(47, date_local.second());
    }

    #[test]
    fn test_current_index_file() {
        let timestamp = 1711256627183244000; // 2024/03/24 13:03:47
        let result = current_index_file(timestamp);
        assert!(result.is_ok());
    }
}
