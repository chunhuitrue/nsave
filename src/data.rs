#![allow(dead_code)]

use crate::packet::*;
use crate::store::*;
use memmap::{MmapMut, MmapOptions};
use std::io::Cursor;
use std::io::{Read, Write};
use std::path::Path;
use std::usize;
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    sync::Arc,
};

const DATA_FILE_SIZE: u64 = 1024 * 1024 * 4; // 4M
const DATA_FILE_MAIGC: [u8; 4] = *b"nsvd";
const MAX_MAP_CHUNK_SIZE: u64 = 1024 * 1024 * 40; // 40k

#[derive(Debug)]
pub struct DataCtx {}

impl DataCtx {
    pub fn new() -> Self {
        DataCtx {}
    }
}

impl Default for DataCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Data {
    fd: RefCell<Option<File>>,
    map_head: RefCell<Option<MapDataHead>>,
    map_chunk: RefCell<Option<MapDateChunk>>,
}

impl Data {
    pub fn new() -> Self {
        Data {
            fd: RefCell::new(None),
            map_head: RefCell::new(None),
            map_chunk: RefCell::new(None),
        }
    }

    pub fn init(&self, dir: &Path) -> Result<(), StoreError> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        let mut need_format = false;
        let data_file = dir.join("data.da");
        if !data_file.exists() {
            fs::File::create(&data_file)?;
            need_format = true;
        }

        if self.fd.borrow().is_none() {
            let result = OpenOptions::new().read(true).write(true).open(&data_file);
            match result {
                Ok(file) => {
                    file.set_len(DATA_FILE_SIZE)?;
                    *self.fd.borrow_mut() = Some(file);
                }
                Err(e) => return Err(StoreError::IoError(e)),
            }
        }

        if need_format {
            self.format()?;
        }
        self.map_file_head()?;
        self.map_next_chunk()?;

        Ok(())
    }

    pub fn store(&self, _ctx: &DataCtx, _pkt: Arc<Packet>, _now: u128) {
        // dbg!("store_pkt");
    }

    pub fn link_fin(&self, _tuple5: &PacketKey, _now: u128) {
        // dbg!("link_fin");
    }

    pub fn timer(&self, _now: u128) {
        // dbg!("timer");
    }

    fn format(&self) -> Result<(), StoreError> {
        let file_head = DataFileHead::new();
        file_head.serialize_into(self.fd.borrow_mut().as_mut().unwrap())?;
        self.fd.borrow_mut().as_mut().unwrap().flush()?;
        Ok(())
    }

    fn map_file_head(&self) -> Result<(), StoreError> {
        let mmap = unsafe {
            MmapOptions::new()
                .len(DataFileHead::serizlize_size())
                .map_mut(self.fd.borrow_mut().as_mut().unwrap())?
        };

        let mut cursor = Cursor::new(&mmap);
        let file_head = DataFileHead::deserialize_from(&mut cursor).unwrap();

        let map_file_head = MapDataHead {
            mmap,
            head: file_head,
        };
        *self.map_head.borrow_mut() = Some(map_file_head);

        Ok(())
    }

    fn map_next_chunk(&self) -> Result<(), StoreError> {
        let head = self.map_head.borrow().as_ref().unwrap().head.head_offset;
        let tail = self.map_head.borrow().as_ref().unwrap().head.tail_offset;
        let size: usize;

        // ==== tail ==== head -----|
        if head >= tail {
            if DATA_FILE_SIZE - head >= MAX_MAP_CHUNK_SIZE {
                size = MAX_MAP_CHUNK_SIZE.try_into().unwrap();
            } else {
                size = (DATA_FILE_SIZE - head).try_into().unwrap();
            }
        } else {
            // ==== head ---- tail =====|
            if tail - head < MAX_MAP_CHUNK_SIZE {
                self.expan_space();
            }
            size = MAX_MAP_CHUNK_SIZE.try_into().unwrap();
        }

        let mmap = unsafe {
            MmapOptions::new()
                .offset(head)
                .len(size)
                .map_mut(self.fd.borrow_mut().as_mut().unwrap())?
        };

        let map_chunk = MapDateChunk {
            mmap,
            start_offset: head.try_into().unwrap(),
            size,
            current_offset: 0,
        };
        *self.map_chunk.borrow_mut() = Some(map_chunk);
        Ok(())
    }

    // 删除旧的时间节点。扩展到足够一个chunk为止
    fn expan_space(&self) {
        todo!()
    }
}

impl Default for Data {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
struct DataFileHead {
    magic: [u8; 4],
    head_offset: u64,
    tail_offset: u64,
}

impl DataFileHead {
    pub fn new() -> Self {
        DataFileHead {
            magic: DATA_FILE_MAIGC,
            head_offset: 0,
            tail_offset: 0,
        }
    }

    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<(), StoreError> {
        writer.write_all(&self.magic)?;
        writer.write_all(&self.head_offset.to_le_bytes())?;
        writer.write_all(&self.tail_offset.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: Read>(reader: &mut R) -> Result<Self, StoreError> {
        let mut magic = [0; 4];
        let mut head_offset_bytes = [0; 8];
        let mut tail_offset_bytes = [0; 8];

        reader.read_exact(&mut magic)?;
        reader.read_exact(&mut head_offset_bytes)?;
        reader.read_exact(&mut tail_offset_bytes)?;

        let head_offset = u64::from_le_bytes(head_offset_bytes);
        let tail_offset = u64::from_le_bytes(tail_offset_bytes);

        Ok(DataFileHead {
            magic,
            head_offset,
            tail_offset,
        })
    }

    pub fn serialize_size(&self) -> usize {
        Self::serizlize_size()
    }

    pub fn serizlize_size() -> usize {
        20
    }
}

#[derive(Debug)]
struct MapDataHead {
    mmap: MmapMut,
    head: DataFileHead,
}

#[derive(Debug)]
struct MapDateChunk {
    mmap: MmapMut,
    start_offset: usize,
    size: usize,
    current_offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn test_data_serialize_into() {
        let mut file_head = DataFileHead::new();
        file_head.head_offset = 42;
        file_head.tail_offset = 100;

        let mut vec = Vec::new();
        file_head.serialize_into(&mut vec).unwrap();

        let head_offset: [u8; 8] = 42u64.to_le_bytes();
        let tail_offset: [u8; 8] = 100u64.to_le_bytes();
        let concatenated = DATA_FILE_MAIGC
            .iter()
            .chain(head_offset.iter())
            .chain(tail_offset.iter())
            .copied() // 将迭代器的元素从 &u8 转换为 u8
            .collect::<Vec<u8>>();

        assert_eq!(vec, concatenated);
    }

    #[test]
    fn test_data_deserialize_from() {
        let mut expected = DataFileHead::new();
        expected.head_offset = 42;
        expected.tail_offset = 100;

        let mut vec = Vec::new();
        vec.write_all(&DATA_FILE_MAIGC).unwrap();
        vec.write_all(&42u64.to_le_bytes()).unwrap();
        vec.write_all(&100u64.to_le_bytes()).unwrap();

        let mut cursor = Cursor::new(vec);
        let deserialized: DataFileHead = DataFileHead::deserialize_from(&mut cursor).unwrap();

        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_data_se_de() {
        let mut file_head = DataFileHead::new();
        file_head.head_offset = 42;
        file_head.tail_offset = 100;

        let mut vec = Vec::new();
        file_head.serialize_into(&mut vec).unwrap();
        dbg!(vec.len());

        let mut cursor = Cursor::new(vec);
        let deserialized: DataFileHead = DataFileHead::deserialize_from(&mut cursor).unwrap();

        assert_eq!(file_head, deserialized);
    }
}
