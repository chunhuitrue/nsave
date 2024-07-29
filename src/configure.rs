use crate::common::StoreError;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Configure {
    pub interface: String,
    pub pkt_len: i32,
    pub pcap_file: Option<String>,
    pub store_path: String,
    pub thread_num: u64,
    pub pkt_channel_size: usize,
    pub msg_channel_size: usize,
    pub timer_intervel: usize,
    pub writer_empty_sleep: usize,
    pub aide_empty_sleep: usize,
    pub pool_size: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub ci_buff_size: u64,
    pub ti_buff_size: u64,
    pub flow_max_table_capacity: usize,
    pub flow_node_timeout: usize,
    pub flow_max_seq_gap: usize,
}

impl Configure {
    pub fn load(file_path: &Path) -> Result<&'static Configure, StoreError> {
        let toml_str = fs::read_to_string(file_path).expect("Failed to read configure file");
        let configure: Configure =
            toml::from_str(&toml_str).expect("Failed to deserialize configure file");
        return Ok(Box::leak(Box::new(configure)));
    }
}
