#![allow(dead_code)]

pub const THREAD_NUM: u64 = 2;
pub const STORE_PATH: &str = "/Users/lch/misc/nsave_data/";
pub const MINUTE_NS: u128 = 1_000_000_000 * 60; // 一分钟
pub const TIME_SCALE: u128 = 1_000_000_000 * 20; // 20秒

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
