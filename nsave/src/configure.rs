use crate::af_xdp::AfXdpConfig;
use crate::common::StoreError;
use crate::pcap::PcapConfig;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

pub const VERSION: &str = "0.2";
pub const AUTHOR: &str = "LiChunhui <chunhui_true@163.com>";
pub const DEFAULT_CONFIG_FILE: &str = ".nsave_conf.toml";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureType {
    Pcap,
    AfXdp,
}

#[derive(Debug, Deserialize)]
pub struct MainConfig {
    pub interface: String,
    pub capture: Option<CaptureType>,
    pub pcap_file: Option<String>,
    pub filter: Option<String>,
    pub daemon: bool,
    pub store_path: String,
    pub thread_num: u64,
    pub pkt_channel_size: usize,
    pub msg_channel_size: usize,
    pub timer_intervel: usize,
    pub writer_empty_sleep: usize,
    pub clean_empty_sleep: usize,
    pub pool_size: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub ci_buff_size: u64,
    pub ti_buff_size: u64,
    pub flow_max_table_capacity: usize,
    pub flow_node_timeout: usize,
    pub flow_max_seq_gap: usize,
}

#[derive(Debug, Deserialize)]
pub struct Configure {
    pub main: MainConfig,
    pub af_xdp: AfXdpConfig,
    pub pcap: PcapConfig,
}

impl Configure {
    pub fn load(file_path: &Path) -> Result<&'static Configure, StoreError> {
        let toml_str = fs::read_to_string(file_path).expect("Failed to read configure file");
        let mut configure: Configure =
            toml::from_str(&toml_str).expect("Failed to deserialize configure file");

        configure.main.store_path = expand_tilde_path(&configure.main.store_path);

        if let Some(ref pcap_file) = configure.main.pcap_file {
            configure.main.pcap_file = Some(expand_tilde_path(pcap_file));
        }

        if let Some(ref pcap_file) = configure.pcap.pcap_file {
            configure.pcap.pcap_file = Some(expand_tilde_path(pcap_file));
        }

        Ok(Box::leak(Box::new(configure)))
    }
}

fn expand_tilde_path(path: &str) -> String {
    if path.starts_with("~/") {
        let home = env::var("HOME").expect("Failed to get HOME environment variable");
        format!("{}{}", home, &path[1..])
    } else if path == "~" {
        env::var("HOME").expect("Failed to get HOME environment variable")
    } else {
        path.to_string()
    }
}
