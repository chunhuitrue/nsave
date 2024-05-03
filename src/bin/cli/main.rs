use chrono::NaiveDateTime;
use clap::{arg, value_parser, Command};
use libnsave::chunkpool::*;
use libnsave::common::*;
use libnsave::packet::*;
use libnsave::timeindex::*;
use std::net::IpAddr;
use std::path::PathBuf;

fn main() -> Result<(), StoreError> {
    let matches = cli().get_matches();
    if let Some(config_path) = matches.get_one::<PathBuf>("config") {
        println!("config file: {}", config_path.display());
    }
    // let mut debug_level: u8 = 0;
    // match matches
    //     .get_one::<u8>("debug")
    //     .expect("Count's are defaulted")
    // {
    //     0 => {}
    //     1 => debug_level = 1,
    //     2 => debug_level = 2,
    //     3 => debug_level = 3,
    //     _ => {}
    // }
    match matches.subcommand() {
        Some(("dump", sub_matches)) => {
            if let Some(pool_file) = sub_matches.get_one::<String>("pool_file") {
                return dump_pool_file(pool_file.into());
            }

            if let Some(data_file) = sub_matches.get_one::<String>("data_file") {
                return dump_data_file(data_file.into());
            }

            match (
                sub_matches.get_one::<String>("chunk_pool_path"),
                sub_matches.get_one::<u32>("chunk_id"),
            ) {
                (Some(path), Some(chunk_id)) => {
                    if let Some(pcap_file) = sub_matches.get_one::<String>("pcap_file") {
                        dump_chunk(path.into(), *chunk_id, Some(pcap_file.into()))
                    } else {
                        dump_chunk(path.into(), *chunk_id, None)
                    }
                }
                (_, _) => Err(StoreError::CliError("path or chunk_id error".to_string())),
            }
        }
        Some(("search", sub_matches)) => {
            let start_time = sub_matches.get_one::<NaiveDateTime>("start_time");
            let end_time = sub_matches.get_one::<NaiveDateTime>("end_time");
            if start_time >= end_time {
                println!("The start time must be younger than the end time.");
                return Err(StoreError::ReadError(
                    "can not find parent path".to_string(),
                ));
            }
            let sip = sub_matches.get_one::<IpAddr>("sip");
            let dip = sub_matches.get_one::<IpAddr>("dip");
            let protocol = sub_matches.get_one::<TransProto>("protocol");
            let sport = sub_matches.get_one::<u16>("sport");
            let dport = sub_matches.get_one::<u16>("dport");
            search(
                start_time.copied(),
                end_time.copied(),
                sip.copied(),
                dip.copied(),
                protocol.copied(),
                sport.copied(),
                dport.copied(),
            );
            Ok(())
        }
        _ => {
            println!("unknown command.");
            Err(StoreError::CliError("unknown command".to_string()))
        }
    }
}

fn cli() -> Command {
    Command::new("nsave-cli")
        .about("nsave cli")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .arg(
            arg!(-c --config <FILE> "Sets a custom config file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-d --debug ... "Turn debugging information on"))
        .subcommand(
            Command::new("dump")
                .about("dump a file. .pl .ti .ci .da or chunk")
                .arg(
                    arg!(-p - -pool_file <FILENAME>)
                        .help("dump pool file")
                        .required(false),
                )
                .arg(
                    arg!(-d - -data_file <FILENAME>)
                        .help("dump data file")
                        .required(false),
                )
                .arg(
                    arg!(-P - -chunk_pool_path <PATH>)
                        .help("chunk_pool path")
                        .required(false),
                )
                .arg(
                    arg!(-c - -chunk_id <CHUNKID>)
                        .help("dump chunk")
                        .value_parser(value_parser!(u32))
                        .required(false),
                )
                .arg(
                    arg!(-f - -pcap_file <PCAPFILE>)
                        .help("dump to pcap file")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("search")
                .about("search a link")
                .arg(
                    arg!(-s - -start_time <STARTTIME>)
                        .help("link start time")
                        .value_parser(parse_datetime)
                        .required(true),
                )
                .arg(
                    arg!(-e - -end_time <ENDTIME>)
                        .help("link end time")
                        .value_parser(parse_datetime)
                        .required(true),
                )
                .arg(
                    arg!(-S - -sip <SIP>)
                        .help("source ip")
                        .value_parser(parse_ip)
                        .required(false),
                )
                .arg(
                    arg!(-D - -dip <DIP>)
                        .help("destinatioo ip")
                        .value_parser(parse_ip)
                        .required(false),
                )
                .arg(
                    arg!(-P - -protocol <PROTOCOL>)
                        .help("protocol. tcp udp icmpv4 icmpv6")
                        .value_parser(parse_protocol)
                        .required(false),
                )
                .arg(
                    arg!(-p - -sport <SPORT>)
                        .help("source port")
                        .value_parser(value_parser!(u16).range(1..))
                        .required(false),
                )
                .arg(
                    arg!(-d - -dport <DPORT>)
                        .help("destination port")
                        .value_parser(value_parser!(u16).range(1..))
                        .required(false),
                ),
        )
}

fn parse_datetime(s: &str) -> Result<NaiveDateTime, String> {
    let fmt = "%Y-%m-%d-%H:%M:%S";
    NaiveDateTime::parse_from_str(s, fmt).map_err(|e| e.to_string())
}

fn parse_ip(ip: &str) -> Result<IpAddr, String> {
    match ip.parse() {
        Ok(addr) => Ok(addr),
        Err(_) => Err(String::from("Invalid IP address")),
    }
}

fn parse_protocol(protocol: &str) -> Result<TransProto, String> {
    match protocol.to_lowercase().as_str() {
        "tcp" => Ok(TransProto::Tcp),
        "udp" => Ok(TransProto::Udp),
        "icmpv4" => Ok(TransProto::Icmp4),
        "icmpv6" => Ok(TransProto::Icmp6),
        _ => Err("unknown protocol".to_string()),
    }
}

fn search(
    stime: Option<NaiveDateTime>,
    etime: Option<NaiveDateTime>,
    sip: Option<IpAddr>,
    dip: Option<IpAddr>,
    protocol: Option<TransProto>,
    sport: Option<u16>,
    dport: Option<u16>,
) {
    let ti_record = search_ti_file(stime, etime, sip, dip, protocol, sport, dport);
    if ti_record.is_empty() {
        println!("no link found");
        return;
    }

    println!("find these link:");
    for record in &ti_record {
        println!("link: {:?}", record);
    }
}
