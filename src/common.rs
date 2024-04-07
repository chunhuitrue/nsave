#![allow(dead_code)]

use chrono::{DateTime, Datelike, Duration, Local, NaiveDateTime, TimeZone, Timelike};

pub const THREAD_NUM: u64 = 2;
pub const STORE_PATH: &str = "/Users/lch/misc/nsave_data/";

pub fn ts_date_local(timestamp_nanos: u128) -> DateTime<Local> {
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

pub fn mk_minute_dir(_timestamp_nanos: u128) -> Result<(), StoreError> {
    todo!()
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
