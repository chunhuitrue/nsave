// #![allow(dead_code)]

use crate::packet::PacketKey;
// use bincode::{deserialize, serialize};
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

const DATA_PATH: &str = "/Users/lch/misc/nsava_data/";
const MINUTE_NANO: u128 = 1_000_000_000 * 60;

#[derive(Debug)]
pub struct TimeIndex {
    index_file: RefCell<Option<File>>,
    current_minute: RefCell<u32>,
    prev_ts: RefCell<u128>,
}

impl TimeIndex {
    pub fn new() -> Self {
        TimeIndex {
            index_file: RefCell::new(None),
            current_minute: RefCell::new(0),
            prev_ts: RefCell::new(0),
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

        dbg!("TimeIndex. save_index");

        Ok(())
    }

    pub fn timer(&self, now: u128) {
        if now > *self.prev_ts.borrow() + MINUTE_NANO {
            dbg!("TimeIndex. 切换目录");
            *self.prev_ts.borrow_mut() = now;
            if let Ok((file, cur_minute)) = current_index_file(now) {
                if *self.current_minute.borrow() != cur_minute {
                    *self.index_file.borrow_mut() = Some(file);
                    *self.current_minute.borrow_mut() = cur_minute;
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
struct LinkRecord {
    start_time: u128,
    end_tiem: u128,
    tuple5: PacketKey,
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
    use crate::Packet;
    use bincode::{deserialize, serialize};
    use etherparse::*;

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

    #[test]
    fn test_serialize_linkrecord() {
        let pkt = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        let _ = pkt.decode();
        let record = LinkRecord {
            start_time: 100,
            end_tiem: 200,
            tuple5: pkt.hash_key(),
        };

        let encode: Vec<u8> = serialize(&record).unwrap();
        let decode: LinkRecord = deserialize(&encode[..]).unwrap();
        assert_eq!(record, decode);
    }

    fn build_tcp(sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16) -> Packet {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        .ipv4(
            sip, //source ip
            dip, //desitionation ip
            20,
        ) //time to life
        .tcp(
            sport, //source port
            dport, //desitnation port
            1234,  //sequence number
            1024,
        ) //window size
        //set additional tcp header fields
        .ns() //set the ns flag
        //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
        .fin()
        .ack(123) //ack flag + the ack number
        .urg(23) //urg flag + urgent pointer
        .options(&[
            TcpOptionElement::Noop,
            TcpOptionElement::MaximumSegmentSize(1234),
        ])
        .unwrap();

        //payload of the tcp packet
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        //serialize
        //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        builder.write(&mut result, &payload).unwrap();
        // println!("result len:{}", result.len());

        let pkt = Packet::new(result, 1);
        let _ = pkt.decode();
        pkt
    }
}
