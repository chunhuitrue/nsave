use crate::common::*;
use crate::configure::*;
use crate::mmapbuf::*;
use crate::packet::*;
use crate::search_ti::*;
use bincode::deserialize_from;
use chrono::{Duration, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct TimeIndex {
    configure: &'static Configure,
    buf_writer: Option<MmapBufWriter>,
}

impl TimeIndex {
    pub fn new(configure: &'static Configure) -> Self {
        TimeIndex {
            configure,
            buf_writer: None,
        }
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
                self.buf_writer = Some(MmapBufWriter::with_arg(
                    fd,
                    meta.len(),
                    self.configure.ti_buff_size,
                ));
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct LinkRecord {
    pub start_time: u128,
    pub end_time: u128,
    pub tuple5: PacketKey,
    pub ci_offset: u64,
}

impl PartialEq for LinkRecord {
    fn eq(&self, other: &Self) -> bool {
        self.start_time == other.start_time && self.tuple5 == other.tuple5
    }
}

impl Eq for LinkRecord {}

impl Hash for LinkRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start_time.hash(state);
        self.tuple5.hash(state);
    }
}

impl fmt::Display for LinkRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LinkRecord {{ start_time: {} ({}), end_time: {} ({}), tuple5: {:?}, ci_offset: {} }}",
            ts_date(self.start_time),
            self.start_time,
            ts_date(self.end_time),
            self.end_time,
            self.tuple5,
            self.ci_offset
        )
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct SearchKey {
    pub start_time: Option<NaiveDateTime>,
    pub end_time: Option<NaiveDateTime>,
    pub sip: Option<IpAddr>,
    pub dip: Option<IpAddr>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub protocol: Option<TransProto>,
}

impl fmt::Display for SearchKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SearchKey {{ start_time: {:?} ({:?}), end_time: {:?} ({:?}), sport: {:?}, dport: {:?}, protocol: {:?} }}",
            self.start_time,
            date_ts(self.start_time),
            self.end_time,
            date_ts(self.end_time),
            self.sport,
            self.dport,
            self.protocol
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

pub fn ti_search(
    configure: &'static Configure,
    search_key: SearchKey,
    dir_id: u64,
) -> Vec<LinkRecord> {
    let mut ti_set = HashSet::new();
    let mut search_date = search_key.start_time.unwrap();
    while search_date < search_key.end_time.unwrap() {
        if let Ok((ti_file, _ti_file_path)) = date2ti_file(configure, search_date, dir_id) {
            ti_set = search_ti(search_key, ti_file)
                .into_iter()
                .collect::<HashSet<_>>();
        }
        search_date += Duration::try_minutes(1).unwrap();
    }
    ti_set.into_iter().collect()
}

fn search_ti(search_key: SearchKey, ti_file: File) -> Vec<LinkRecord> {
    let mut record: Vec<LinkRecord> = Vec::new();
    let mut reader = MmapBufReader::new(ti_file);
    while let Ok(ti) = deserialize_from::<_, LinkRecord>(&mut reader) {
        if match_ti(search_key, &ti) {
            record.push(ti);
        }
    }
    record
}

fn match_ti(search_key: SearchKey, record: &LinkRecord) -> bool {
    let SearchKey {
        start_time,
        end_time,
        sip,
        dip,
        sport,
        dport,
        protocol,
    } = search_key;
    let stime = date_ts(start_time);
    let etime = date_ts(end_time);

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

pub fn search_lr(dir: &Path, tuple5: PacketKey) -> Option<LinkRecord> {
    let mut path = PathBuf::new();
    path.push(dir);
    path.push("timeindex.ti");
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .truncate(false)
        .open(&path)
    {
        Ok(ti_file) => {
            let mut reader = MmapBufReader::new(ti_file);
            while let Ok(ti) = deserialize_from::<_, LinkRecord>(&mut reader) {
                if tuple5 == ti.tuple5 {
                    return Some(ti);
                }
            }
            None
        }
        Err(_e) => None,
    }
}
