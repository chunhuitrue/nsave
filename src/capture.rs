use crate::configure::*;
use crate::packet::*;
use pcap::Activated;
use pcap::Capture as PcapCap;
use pcap::Device;
use std::sync::Arc;

#[derive(Debug)]
pub enum CaptureError {
    CapErr,
}

pub struct Capture {
    cap: PcapCap<dyn Activated>,
}

impl Capture {
    pub fn init_capture(configure: &'static Configure) -> Result<Capture, CaptureError> {
        if configure.pcap_file.is_some() {
            return Ok(Self::init_from_file(configure).unwrap());
        }
        Self::init_interface(configure)
    }

    fn init_from_file(configure: &'static Configure) -> Result<Capture, CaptureError> {
        let capture = Capture {
            cap: PcapCap::from_file(configure.pcap_file.as_ref().unwrap())
                .unwrap()
                .into(),
        };
        Ok(capture)
    }

    fn init_interface(configure: &'static Configure) -> Result<Capture, CaptureError> {
        let device = Self::get_device(Some(&configure.interface))?;
        let cap = pcap::Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(configure.pkt_len)
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
