use crate::common::*;
use crate::mmapbuf::*;
use crate::packet::*;
use bincode::deserialize_from;
use chrono::{Datelike, Duration, NaiveDateTime, Timelike};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt;
use std::net::IpAddr;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

const BUFF_SIZE: u64 = 1024;

#[derive(Debug)]
pub struct TimeIndex {
    buf_writer: Option<MmapBufWriter>,
}

impl TimeIndex {
    pub fn new() -> Self {
        TimeIndex { buf_writer: None }
    }

    pub fn init_dir(&mut self, dir: &Path) -> Result<(), StoreError> {
        let mut path = PathBuf::new();
        path.push(dir);
        path.push("timeindex.ti");
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path);
        match result {
            Ok(fd) => {
                let meta = fd.metadata()?;
                self.buf_writer = Some(MmapBufWriter::with_arg(fd, meta.len(), BUFF_SIZE));
            }
            Err(e) => return Err(StoreError::IoError(e)),
        }
        Ok(())
    }

    pub fn change_dir(&mut self) -> Result<(), StoreError> {
        self.buf_writer = None;
        Ok(())
    }

    pub fn write(&mut self, record: LinkRecord) -> Result<u64, StoreError> {
        let ci_offset = self.buf_writer.borrow().as_ref().unwrap().next_offset();
        if let Some(ref mut writer) = self.buf_writer {
            if bincode::serialize_into(writer, &record).is_err() {
                return Err(StoreError::WriteError("time index write error".to_string()));
            }
        }
        Ok(ci_offset)
    }
}

impl Default for TimeIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct LinkRecord {
    pub start_time: u128,
    pub end_time: u128,
    pub tuple5: PacketKey,
    pub ci_offset: u64,
}

impl fmt::Display for LinkRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LinkRecord {{ start_time: {}, end_time: {}, tuple5: {:?}, ci_offset: {} }}",
            ts_date(self.start_time),
            ts_date(self.end_time),
            self.tuple5,
            self.ci_offset
        )
    }
}

pub fn dump_timeindex_file(path: PathBuf) -> Result<(), StoreError> {
    match path.extension() {
        Some(ext) => {
            if !ext.to_str().unwrap().eq("ti") {
                return Err(StoreError::CliError("not timeindex file".to_string()));
            }
        }
        None => return Err(StoreError::CliError("not timeindex file".to_string())),
    };

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(&path)
    {
        Ok(fd) => fd,
        Err(e) => {
            return Err(StoreError::CliError(format!("open file error: {}", e)));
        }
    };
    let mut mmap_reader = MmapBufReader::new(file);
    println!("dump timeindex file: {:?}", path);
    while let Ok(record) = deserialize_from::<_, LinkRecord>(&mut mmap_reader) {
        println!("{}", record);
    }
    Ok(())
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
    println!(
        "search for start time: {:?}, end time: {:?}, sip: {:?}, sport: {:?} -- dip: {:?}, dport: {:?}, protocol: {:?}",
        stime, etime, sip, sport, dip, dport, protocol
    );

    let mut record: Vec<LinkRecord> = Vec::new();
    for dir in 0..THREAD_NUM {
        let mut search_time = stime.unwrap();
        while search_time < etime.unwrap() {
            if let Ok((file_ti, file_ti_path)) = time2file_ti(search_time, dir) {
                println!("find a time index file: {:?}", file_ti_path);
                let mut file_record =
                    search_ti(file_ti, stime, etime, sip, dip, protocol, sport, dport);
                record.append(&mut file_record);
            } else {
                continue;
            }
            search_time += Duration::try_minutes(1).unwrap();
        }
    }
    record
}

pub fn time2file_ti(time: NaiveDateTime, dir: u64) -> Result<(File, PathBuf), StoreError> {
    let mut path = PathBuf::new();
    path.push(STORE_PATH);
    path.push(format!("{:03}", dir));
    path.push(format!("{:04}", time.year()));
    path.push(format!("{:02}", time.month()));
    path.push(format!("{:02}", time.day()));
    path.push(format!("{:02}", time.hour()));
    path.push(format!("{:02}", time.minute()));
    path.push("timeindex.ti");

    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => Ok((file, path)),
        Err(e) => Err(StoreError::CliError(format!("open file error: {}", e))),
    }
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
    let mut reader = MmapBufReader::new(file_ti);
    while let Ok(ti) = deserialize_from::<_, LinkRecord>(&mut reader) {
        if match_ti(
            date_ts(stime),
            date_ts(etime),
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
    println!(
        "\n{}, stime:{:?}, etime:{:?}",
        record, record.start_time, record.end_time
    );
    println!(
        "stime: {:?}, etime: {:?}, sip: {:?}, dip: {:?}, sport: {:?}, dport: {:?}, proto: {:?}",
        stime, etime, sip, dip, sport, dport, protocol
    );
    let stime_m = match_stime(record.start_time, stime);
    dbg!(stime_m);

    let match0 = match_stime(record.start_time, stime)
        && match_etime(record.end_time, etime)
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
