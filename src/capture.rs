#![allow (dead_code)]

use pcap::Capture as PcapCap;
use pcap::Offline;
use std::path::Path;
use std::sync::Arc;
use crate::packet::*;

#[derive(Debug)]
pub enum CaptureError {
    CapErr
}

pub struct Capture {
    cap: PcapCap<Offline>
}

impl Capture {
    pub fn init<P: AsRef<Path>>(path: P) -> Result<Capture, CaptureError> {
        let capture = Capture {
            cap: PcapCap::from_file(path).unwrap(),
        };
        Ok(capture)
    }

    pub fn next_packet(&mut self, timestamp: u128) -> Result<Arc<Packet>, CaptureError> {
        match self.cap.next_packet() {
            Ok(pcap_pkt) => {
                Ok( Arc::new(Packet::new(pcap_pkt.data.to_vec(), timestamp))  )
            }
            Err(_) => Err(CaptureError::CapErr)
        }
    }
}
