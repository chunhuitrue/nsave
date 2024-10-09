use crate::{chunkpool::*, common::*, configure::*};
use memmap2::Mmap;
use std::cmp;
use std::fs::File;
use std::io::Cursor;
use std::{fs::OpenOptions, path::PathBuf};

#[derive(Debug)]
pub struct SearchCp {
    pool_path: PathBuf,
    pool_head: Option<PoolHead>,
    actual_size: Option<ActualSize>,
    chunk_id: Option<u32>,
    chunk_map: Option<Mmap>,
    chunk_head: Option<ChunkHead>,
    next_pkt_offset: Option<u32>,
    data_file: Option<File>,
}

impl SearchCp {
    pub fn new(configure: &'static Configure, dir_id: u64) -> Self {
        let mut path = PathBuf::new();
        path.push(configure.store_path.clone());
        path.push(format!("{:03}", dir_id));
        path.push("chunk_pool");

        SearchCp {
            pool_path: path,
            pool_head: None,
            actual_size: None,
            chunk_id: None,
            chunk_map: None,
            chunk_head: None,
            next_pkt_offset: None,
            data_file: None,
        }
    }

    pub fn load_chunk(&mut self, chunk_id: u32, offset_in_chunk: u32) -> Result<(), StoreError> {
        let pkt_offset = cmp::max(offset_in_chunk, ChunkHead::serialize_size() as u32);

        if self.chunk_map.is_some() && self.chunk_id.unwrap() == chunk_id {
            self.next_pkt_offset = Some(pkt_offset);
            return Ok(());
        }
        self.free_chunk()?;

        if self.pool_head.is_none() {
            let mut head_path = PathBuf::new();
            head_path.push(&self.pool_path);
            head_path.push("pool.pl");
            let pool_head = read_pool_head(&head_path)?;
            let actual_size = ActualSize::new(
                pool_head.pool_size,
                pool_head.file_size,
                pool_head.chunk_size,
            );
            self.pool_head = Some(pool_head);
            self.actual_size = Some(actual_size);
        }
        self.chunk_id = Some(chunk_id);
        self.next_pkt_offset = Some(pkt_offset);

        let file_chunk_num = self.actual_size.unwrap().file_chunk_num;
        let data_file_id = chunk_id / file_chunk_num;
        let data_file_path = self.pool_path.join(format!("{:03}.da", data_file_id));
        let data_file = match OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .truncate(false)
            .open(data_file_path)
        {
            Ok(file_fd) => file_fd,
            Err(e) => {
                return Err(StoreError::CliError(format!("open data file error: {}", e)));
            }
        };
        self.data_file = Some(data_file);

        let inner_chunk_id = chunk_id - data_file_id * file_chunk_num;
        let chunk_size = self.pool_head.unwrap().chunk_size;
        let chunk_offset = inner_chunk_id * chunk_size;
        match get_lk_chunk(
            self.data_file.as_ref().unwrap(),
            chunk_offset,
            chunk_size as usize,
        ) {
            Ok(mmap) => self.chunk_map = Some(mmap),
            Err(e) => {
                return Err(StoreError::CliError(format!("map chunk error: {}", e)));
            }
        }

        let mut cursor = Cursor::new(self.chunk_map.as_ref().unwrap());
        let chunk_head = ChunkHead::deserialize_from(&mut cursor)?;
        self.chunk_head = Some(chunk_head);
        Ok(())
    }

    fn free_chunk(&mut self) -> Result<(), StoreError> {
        if self.chunk_id.is_none()
            || self.actual_size.is_none()
            || self.data_file.is_none()
            || self.pool_head.is_none()
        {
            return Ok(());
        }

        let chunk_id = self.chunk_id.unwrap();
        let file_chunk_num = self.actual_size.unwrap().file_chunk_num;
        let data_file_id = chunk_id / file_chunk_num;
        let inner_chunk_id = chunk_id - data_file_id * file_chunk_num;
        let chunk_size = self.pool_head.unwrap().chunk_size;
        let chunk_offset = inner_chunk_id * chunk_size;

        free_lk_chunk(
            self.data_file.as_ref().unwrap(),
            chunk_offset,
            self.pool_head.unwrap().chunk_size as usize,
        )
    }

    pub fn next_link_pkt(&mut self) -> Option<StorePacket> {
        self.next_pkt_offset?;

        let offset = self.next_pkt_offset.unwrap() as usize;
        let chunk = self.chunk_map.as_ref().unwrap();
        let mut cursor = Cursor::new(&chunk[offset..]);

        if let Ok(pkt) = StorePacket::deserialize_from(&mut cursor) {
            if pkt.next_offset == 0 {
                self.next_pkt_offset = None;
            } else {
                self.next_pkt_offset = Some(pkt.next_offset);
            }
            return Some(pkt);
        }
        None
    }

    pub fn next_pkt(&mut self) -> Option<StorePacket> {
        self.next_pkt_offset?;
        self.chunk_head.as_ref()?;

        if self.next_pkt_offset.unwrap() >= self.chunk_head.as_ref().unwrap().filled_size {
            return None;
        }

        let offset = self.next_pkt_offset.unwrap() as usize;
        let chunk = self.chunk_map.as_ref().unwrap();
        let mut cursor = Cursor::new(&chunk[offset..]);
        let before_position = cursor.position();
        if let Ok(pkt) = StorePacket::deserialize_from(&mut cursor) {
            let after_position = cursor.position();
            self.next_pkt_offset =
                Some(offset as u32 + after_position as u32 - before_position as u32);
            Some(pkt)
        } else {
            None
        }
    }
}
