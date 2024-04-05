#![allow(dead_code)]

use crate::packet::*;
use crate::store::*;
use std::io::{Read, Write};
use std::path::Path;
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    sync::Arc,
};

const DATA_FILE_SIZE: u64 = 1024 * 1024 * 4; // 4M
const DATA_FILE_MAIGC: [u8; 4] = *b"nsvd";

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
}

impl Data {
    pub fn new() -> Self {
        Data {
            fd: RefCell::new(None),
        }
    }

    pub fn init(&self, dir: &Path) -> Result<(), StoreError> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }

        let data_file = dir.join("data.da");
        if !data_file.exists() {
            fs::File::create(&data_file)?;
            let result = OpenOptions::new().read(true).write(true).open(&data_file);
            match result {
                Ok(file) => {
                    file.set_len(DATA_FILE_SIZE)?;
                    *self.fd.borrow_mut() = Some(file);
                }
                Err(e) => return Err(StoreError::IoError(e)),
            }
            self.format()?;
        }
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
}

impl Default for Data {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq)]
struct DataFileHead {
    magic: [u8; 4],
    head_offset: u32,
    tail_offset: u32,
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
        let mut head_offset_bytes = [0; 4];
        let mut tail_offset_bytes = [0; 4];

        reader.read_exact(&mut magic)?;
        reader.read_exact(&mut head_offset_bytes)?;
        reader.read_exact(&mut tail_offset_bytes)?;

        let head_offset = u32::from_le_bytes(head_offset_bytes);
        let tail_offset = u32::from_le_bytes(tail_offset_bytes);

        Ok(DataFileHead {
            magic,
            head_offset,
            tail_offset,
        })
    }

    pub fn serialize_size(&self) -> usize {
        12
    }
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

        assert_eq!(
            vec,
            [DATA_FILE_MAIGC, 42u32.to_le_bytes(), 100u32.to_le_bytes()].concat()
        );
    }

    #[test]
    fn test_data_deserialize_from() {
        let mut expected = DataFileHead::new();
        expected.head_offset = 42;
        expected.tail_offset = 100;

        let mut vec = Vec::new();
        vec.write_all(&DATA_FILE_MAIGC).unwrap();
        vec.write_all(&42u32.to_le_bytes()).unwrap();
        vec.write_all(&100u32.to_le_bytes()).unwrap();

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
