use crate::common::*;
use crate::packet::*;
use pcap::Activated;
use pcap::Capture as PcapCap;
use pcap::Device;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub enum CaptureError {
    CapErr,
}

pub struct Capture {
    cap: PcapCap<dyn Activated>,
}

impl Capture {
    pub fn init_capture<P: AsRef<Path>>(
        interface: Option<&String>,
        path: Option<P>,
    ) -> Result<Capture, CaptureError> {
        if let Some(pcap_file) = path {
            return Ok(Self::init_from_file(pcap_file).unwrap());
        }
        Self::init_interface(interface)
    }

    fn init_from_file<P: AsRef<Path>>(path: P) -> Result<Capture, CaptureError> {
        let capture = Capture {
            cap: PcapCap::from_file(path).unwrap().into(),
        };
        Ok(capture)
    }

    fn init_interface(interface: Option<&String>) -> Result<Capture, CaptureError> {
        let device = Self::get_device(interface)?;
        let cap = pcap::Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(PACKET_LEN)
            .immediate_mode(true)
            .open()
            .unwrap();
        let capture = Capture { cap: cap.into() };
        Ok(capture)
    }

    fn get_device(interface: Option<&String>) -> Result<Device, CaptureError> {
        if let Some(name) = interface {
            for dev in pcap::Device::list().expect("device lookup failed") {
                if dev.name == *name {
                    return Ok(dev);
                }
            }
            Err(CaptureError::CapErr)
        } else {
            let dev = pcap::Device::lookup()
                .expect("device lookup failed")
                .expect("no device available");
            Ok(dev)
        }
    }

    pub fn next_packet(&mut self, timestamp: u128) -> Result<Arc<Packet>, CaptureError> {
        match self.cap.next_packet() {
            Ok(pcap_pkt) => Ok(Arc::new(Packet::new(pcap_pkt.data.to_vec(), timestamp))),
            Err(_) => Err(CaptureError::CapErr),
        }
    }
}
