// #![allow(dead_code)]

use bincode::{deserialize_from, ErrorKind};
use libnsave::timeindex::*;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::{env, result};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <timeindex_file>", args[0]);
        std::process::exit(1);
    }

    dump_ti((&args[0]).into());
}

fn dump_ti(path: PathBuf) {
    let result = File::open(path);
    match result {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            loop {
                match deserialize_from::<_, LinkRecord>(&mut reader) {
                    Ok(record) => {
                        // 处理反序列化的值
                        println!("get a record: {:?}", record);
                    }
                    // 如果遇到EOF，则退出循环
                    Err(err) => {
                        if let bincode::ErrorKind::Io(ref io_err) = *err {
                            if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                                println!("dump ok");
                                break;
                            }
                        }
                        // 处理其他类型的错误
                        println!("read error: {}", err);
                        return;
                    }
                }
            }
        }
        Err(err) => {
            println!("open file error: {}", err);
        }
    };
}
