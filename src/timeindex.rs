#![allow(dead_code)]

use crate::packet::PacketKey;
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

const DATA_PATH: &str = "~/misct7/nsava_data/";

pub struct TimeIndex {
    index_file: Option<IndexFile>,
}

impl TimeIndex {
    pub fn new() -> Self {
        TimeIndex { index_file: None }
    }

    pub fn save_index(&self, _link: &PacketKey, _now: u128) {
        dbg!("TimeIndex. make_index");
    }

    pub fn timer(&self, _now: u128) {
        dbg!("TimeIndex. timeout");
    }
}

struct IndexFile {
    file: File,
}

// 如果文件不存在，就创建。如果已经存在，就open。
fn current_index_file(timestamp: u128) -> Result<File, TimeIndexError> {
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
        Ok(file) => Ok(file),
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

// pub fn test_time(now: u128) {
//     let timestamp_nanos = now;
//     let naive_datetime = DateTime::from_timestamp(
//         (timestamp_nanos / 1_000_000_000).try_into().unwrap(),
//         (timestamp_nanos % 1_000_000_000) as u32,
//     );
//     let datetime_local = Local.from_utc_datetime(
//         &naive_datetime
//             .expect("Failed to convert to local time")
//             .naive_utc(),
//     );

//     let year = datetime_local.year();
//     let month = datetime_local.month();
//     let day = datetime_local.day();
//     let hour = datetime_local.hour();
//     let minute = datetime_local.minute();
//     let second = datetime_local.second();

//     println!("timestamp: {}", now);
//     println!("年：{}", year);
//     println!("月：{}", month);
//     println!("日：{}", day);
//     println!("时：{}", hour);
//     println!("分：{}", minute);
//     println!("秒：{}", second);

//     let mut path = PathBuf::new();
//     path.push("~/misct7/data/"); // 替换为你的基础目录
//     path.push(format!("{:04}", year));
//     path.push(format!("{:02}", month));
//     path.push(format!("{:02}", day));
//     path.push(format!("{:02}", hour));
//     path.push(format!("{:02}", minute));
//     println!("path: {:?}", path);
// }

enum TimeIndexError {
    CreatePath,
    CreateFile,
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

    // #[test]
    // fn test_path() {
    //     let now = SystemTime::now()
    //         .duration_since(UNIX_EPOCH)
    //         .unwrap()
    //         .as_nanos();
    //     test_time(now)
    // }
}
