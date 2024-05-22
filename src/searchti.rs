#![allow(dead_code)]

use crate::common::*;
// use crate::mmapbuf::*;
use crate::packet::*;
use chrono::NaiveDateTime;
// use chrono::{Datelike, Duration, NaiveDateTime, Timelike};
use std::fmt;
use std::net::IpAddr;
use std::{cell::RefCell, fs::File, os::fd::AsRawFd};

pub struct SearchTi {
    dir_id: u64,
    current_date: RefCell<NaiveDateTime>,
}

impl SearchTi {
    pub fn new(dir_id: u64, date: NaiveDateTime) -> Self {
        SearchTi {
            dir_id,
            current_date: RefCell::new(date),
        }
    }

    pub fn next_dir() -> Option<NaiveDateTime> {
        todo!()
    }
}

// impl Default for SearchTi {
//     fn default() -> Self {
//         Self::new()
//     }
// }

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
