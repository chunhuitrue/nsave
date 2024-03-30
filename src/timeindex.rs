#![allow(dead_code)]

use crate::common::*;
use crate::packet::*;
use bincode::deserialize_from;
use chrono::{DateTime, Datelike, Duration, Local, NaiveDateTime, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::BufReader;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;

const DATA_PATH: &str = "/Users/lch/misc/nsave_data/";
const BUFF_SIZE: usize = 8 * 1024;
const FLASH_TIMEOUT: u128 = 1_000_000_000 * 10;

#[derive(Debug)]
pub struct TimeIndex {
    dir_id: u64,
    buff_writer: RefCell<Option<BufWriter<File>>>,
    last_write_ts: RefCell<u128>, // 上次写文件的时间戳
    current_minute: RefCell<u32>, // 当前分钟数值
}

impl TimeIndex {
    pub fn new(dir_id: u64) -> Self {
        TimeIndex {
            buff_writer: RefCell::new(None),
            last_write_ts: RefCell::new(0),
            dir_id,
            current_minute: RefCell::new(0),
        }
    }

    pub fn save_index(
        &self,
        tuple5: &PacketKey,
        start_time: u128,
        now: u128,
    ) -> Result<(), TimeIndexError> {
        // 如果没有文件，就新建一个
        if self.buff_writer.borrow().is_none() {
            self.new_file(now)?;
        }

        // 记录写入文件
        println!("TimeIndex {}. 保存索引记录", self.dir_id);
        let record = LinkRecord {
            start_time,
            end_tiem: now,
            tuple5: *tuple5,
        };
        let mut buff_writer = self.buff_writer.borrow_mut();
        if let Some(writer) = buff_writer.as_mut() {
            if bincode::serialize_into(writer, &record).is_err() {
                println!("timeindex write to file error");
                return Err(TimeIndexError::TimeIndex);
            }
        } else {
            println!("timeindex. no writer");
            return Err(TimeIndexError::TimeIndex);
        }
        *self.last_write_ts.borrow_mut() = now;

        Ok(())
    }

    pub fn timer(&self, now: u128) {
        println!("in timer {}", self.dir_id);
        // 如果文件长时间没有写入，刷新
        if now > *self.last_write_ts.borrow() + FLASH_TIMEOUT {
            let _ = self.flush(now);
            *self.last_write_ts.borrow_mut() = now;
        }

        // 如果当前分钟数已过，关闭现有文件
        let minute = ts_date_local(now).minute();
        if minute != *self.current_minute.borrow() {
            println!("in timer {}. next minute", self.dir_id);
            *self.current_minute.borrow_mut() = minute;
            let _ = self.close_file(now);
        }
    }

    fn flush(&self, now: u128) -> io::Result<()> {
        *self.last_write_ts.borrow_mut() = now;
        let mut buff_writer = self.buff_writer.borrow_mut();
        if let Some(writer) = buff_writer.as_mut() {
            return writer.flush();
        }
        Ok(())
    }

    // 刷新现有文件，关闭现有文件，新建新文件
    fn new_file(&self, now: u128) -> Result<(), TimeIndexError> {
        let _ = self.close_file(now);
        if let Ok((file, minute)) = current_index_file(self.dir_id, now) {
            *self.buff_writer.borrow_mut() = Some(BufWriter::with_capacity(BUFF_SIZE, file));
            *self.last_write_ts.borrow_mut() = now;
            *self.current_minute.borrow_mut() = minute;
            Ok(())
        } else {
            Err(TimeIndexError::CreateFile)
        }
    }

    fn close_file(&self, now: u128) -> io::Result<()> {
        let ret = self.flush(now);
        *self.buff_writer.borrow_mut() = None;
        ret
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct LinkRecord {
    pub start_time: u128,
    pub end_tiem: u128,
    pub tuple5: PacketKey,
}

#[derive(Debug)]
pub enum TimeIndexError {
    CreatePath,
    CreateFile,
    TimeIndex,
}

pub fn dump_ti_file(path: PathBuf) {
    println!("dump {:?}:", path);
    let result = File::open(path.clone());
    match result {
        Ok(file) => {
            let mut reader = BufReader::new(&file);
            loop {
                match deserialize_from::<_, LinkRecord>(&mut reader) {
                    Ok(record) => {
                        // 处理反序列化的值
                        println!("get a record: {:?}", record);
                    }
                    // 如果遇到EOF，则退出循环
                    Err(err) => {
                        if let bincode::ErrorKind::Io(ref io_err) = *err {
                            if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                                println!("dump ok");
                                break;
                            }
                        }
                        // 处理其他类型的错误
                        println!("read error: {}", err);
                        return;
                    }
                }
            }
        }
        Err(err) => {
            println!("open file error: {}", err);
        }
    };
}

pub fn search_ti_file(
    stime: Option<NaiveDateTime>,
    etime: Option<NaiveDateTime>,
    sip: Option<IpAddr>,
    dip: Option<IpAddr>,
    protocol: Option<TransProto>,
    sport: Option<u16>,
    dport: Option<u16>,
) -> Vec<LinkRecord> {
    println!("start time: {:?}, end time: {:?}", stime, etime);
    println!(
        "sip: {:?}, sport: {:?} -- dip: {:?}, dport: {:?}, protocol: {:?}",
        sip, sport, dip, dport, protocol
    );

    let mut record: Vec<LinkRecord> = Vec::new();
    let mut current_time = stime.unwrap();
    while current_time < etime.unwrap() {
        for dir in 0..THREAD_NUM {
            if let Ok((file_ti, file_ti_path)) = time2file_ti(current_time, dir) {
                println!("find a time index file: {:?}", file_ti_path);
                let mut file_record =
                    search_ti(file_ti, stime, etime, sip, dip, protocol, sport, dport);
                record.append(&mut file_record);
            } else {
                continue;
            }
        }

        current_time += Duration::try_minutes(1).unwrap();
    }
    record
}

#[allow(clippy::too_many_arguments)]
fn search_ti(
    file_ti: File,
    stime: Option<NaiveDateTime>,
    etime: Option<NaiveDateTime>,
    sip: Option<IpAddr>,
    dip: Option<IpAddr>,
    protocol: Option<TransProto>,
    sport: Option<u16>,
    dport: Option<u16>,
) -> Vec<LinkRecord> {
    let mut record: Vec<LinkRecord> = Vec::new();
    let mut reader = BufReader::new(&file_ti);
    while let Ok(ti) = deserialize_from::<_, LinkRecord>(&mut reader) {
        if match_ti(
            to_timestamp(stime),
            to_timestamp(etime),
            sip,
            dip,
            protocol,
            sport,
            dport,
            &ti,
        ) {
            record.push(ti);
        }
    }
    record
}

fn to_timestamp(time: Option<NaiveDateTime>) -> Option<u128> {
    time?;
    time.unwrap()
        .and_utc()
        .timestamp_nanos_opt()
        .map(|ts| ts as u128)
}

#[allow(clippy::too_many_arguments)]
fn match_ti(
    stime: Option<u128>,
    etime: Option<u128>,
    sip: Option<IpAddr>,
    dip: Option<IpAddr>,
    protocol: Option<TransProto>,
    sport: Option<u16>,
    dport: Option<u16>,
    record: &LinkRecord,
) -> bool {
    let match0 = match_stime(record.start_time, stime)
        && match_etime(record.end_tiem, etime)
        && match_protocol(record.tuple5.trans_proto, protocol);
    let match1 = match_ip(record.tuple5.addr1, sip)
        && match_port(record.tuple5.port1, sport)
        && match_ip(record.tuple5.addr2, dip)
        && match_port(record.tuple5.port2, dport);
    let match2 = match_ip(record.tuple5.addr1, dip)
        && match_port(record.tuple5.port1, dport)
        && match_ip(record.tuple5.addr2, sip)
        && match_port(record.tuple5.port2, sport);

    match0 && (match1 || match2)
}

fn match_stime(rd_start: u128, op_start: Option<u128>) -> bool {
    if let Some(ts) = op_start {
        ts <= rd_start
    } else {
        true
    }
}

fn match_etime(rd_end: u128, op_end: Option<u128>) -> bool {
    if let Some(ts) = op_end {
        ts >= rd_end
    } else {
        true
    }
}

fn match_ip(rd_ip: IpAddr, op_ip: Option<IpAddr>) -> bool {
    if let Some(ip) = op_ip {
        ip == rd_ip
    } else {
        true
    }
}

fn match_protocol(rd_proto: TransProto, op_proto: Option<TransProto>) -> bool {
    if let Some(proto) = op_proto {
        proto == rd_proto
    } else {
        true
    }
}

fn match_port(rd_port: u16, op_port: Option<u16>) -> bool {
    if let Some(port) = op_port {
        port == rd_port
    } else {
        true
    }
}

pub fn time2file_ti(time: NaiveDateTime, dir: u64) -> Result<(File, PathBuf), TimeIndexError> {
    let mut path = PathBuf::new();
    path.push(DATA_PATH);
    path.push(format!("{:03}", dir));
    path.push(format!("{:04}", time.year()));
    path.push(format!("{:02}", time.month()));
    path.push(format!("{:02}", time.day()));
    path.push(format!("{:02}", time.hour()));
    path.push(format!("{:02}", time.minute()));
    path.push(format!("{:02}.ti", time.minute()));

    match File::open(path.clone()) {
        Ok(file) => Ok((file, path)),
        Err(_) => Err(TimeIndexError::TimeIndex),
    }
}

// 如果文件不存在，就创建。如果已经存在，就open。
fn current_index_file(dir_id: u64, timestamp: u128) -> Result<(File, u32), TimeIndexError> {
    let date = ts_date_local(timestamp);
    let mut path = PathBuf::new();
    path.push(DATA_PATH);
    path.push(format!("{:03}", dir_id));
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
        .read(false)
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
    use crate::packet::Packet;
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
        let result = current_index_file(1, timestamp);
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
        println!("len: {}, vec: {:?}", encode.len(), encode);
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
