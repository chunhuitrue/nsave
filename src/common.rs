use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Timelike};
use libc::timeval;
use std::convert::From;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const THREAD_NUM: u64 = 2;
pub const STORE_PATH: &str = "/Users/lch/misc/nsave_data/";
pub const MINUTE_NS: u128 = 1_000_000_000 * 60; // 一分钟

#[derive(Debug)]
pub enum StoreError {
    IoError(std::io::Error),
    InitError(String),
    FormatError(String),
    ReadError(String),
    WriteError(String),
    CliError(String),
    LockError(String),
    OpenError(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(err) => write!(f, "IO error: {}", err),
            StoreError::InitError(msg) => write!(f, "Init error: {}", msg),
            StoreError::FormatError(msg) => write!(f, "Format error: {}", msg),
            StoreError::ReadError(msg) => write!(f, "Read error: {}", msg),
            StoreError::WriteError(msg) => write!(f, "Write error: {}", msg),
            StoreError::CliError(msg) => write!(f, "Write error: {}", msg),
            StoreError::LockError(msg) => write!(f, "lock error: {}", msg),
            StoreError::OpenError(msg) => write!(f, "open error: {}", msg),
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

impl From<StoreError> for io::Error {
    fn from(error: StoreError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, error)
    }
}

#[derive(Debug)]
pub enum Msg {
    CoverChunk(PathBuf, u128),
}

pub fn ts_date(timestamp: u128) -> DateTime<Local> {
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

pub fn date_ts(time: Option<NaiveDateTime>) -> Option<u128> {
    time.map(|t| {
        let datetime_local: DateTime<Local> = Local.from_local_datetime(&t).unwrap();
        datetime_local.timestamp_nanos_opt().map(|ts| ts as u128)
    })?
}

pub fn ts_timeval(timestamp: u128) -> timeval {
    let seconds = (timestamp / 1_000_000_000) as i64;
    let nanoseconds = (timestamp % 1_000_000_000) as i64;
    timeval {
        tv_sec: seconds,
        tv_usec: (nanoseconds * 1000) as i32,
    }
}

pub fn timenow() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

pub fn date2dir(dir_id: u64, date: NaiveDateTime) -> PathBuf {
    let mut path = PathBuf::new();
    path.push(STORE_PATH);
    path.push(format!("{:03}", dir_id));
    path.push(format!("{:04}", date.year()));
    path.push(format!("{:02}", date.month()));
    path.push(format!("{:02}", date.day()));
    path.push(format!("{:02}", date.hour()));
    path.push(format!("{:02}", date.minute()));
    path
}
