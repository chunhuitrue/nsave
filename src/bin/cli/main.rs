// #![allow(dead_code)]

use bincode::deserialize_from;
use clap::{arg, Command};
use libnsave::timeindex::*;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

fn main() {
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("dump", sub_matches)) => {
            let file = sub_matches.get_one::<String>("FILENAME").expect("required");
            dump_ti(file.into());
        }
        _ => {
            println!("unknown command.")
        }
    }
}

fn cli() -> Command {
    Command::new("nsave-cli")
        .about("nsave cli")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("dump")
                .about("dump a file. .ti .ci .ne")
                .arg(arg!(<FILENAME> "the file name. .ti .ci .ne"))
                .arg_required_else_help(true),
        )
}

fn dump_ti(path: PathBuf) {
    println!("dump {:?}:", path);
    let result = File::open(path.clone());
    match result {
        Ok(file) => {
            let mut reader = BufReader::new(&file);
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
