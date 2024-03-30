// #![allow(dead_code)]

use chrono::NaiveDateTime;
use clap::{arg, value_parser, Command};
use libnsave::packet::*;
use libnsave::timeindex::*;
use std::net::IpAddr;
use std::path::PathBuf;

fn main() {
    let matches = cli().get_matches();
    if let Some(config_path) = matches.get_one::<PathBuf>("config") {
        println!("config file: {}", config_path.display());
    }
    match matches
        .get_one::<u8>("debug")
        .expect("Count's are defaulted")
    {
        0 => {}
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }
    match matches.subcommand() {
        Some(("dump", sub_matches)) => {
            let file = sub_matches
                .get_one::<String>("FILENAME")
                .expect("required file name");
            dump_ti_file(file.into());
        }
        Some(("search", sub_matches)) => {
            let start_time = sub_matches.get_one::<NaiveDateTime>("start_time");
            let end_time = sub_matches.get_one::<NaiveDateTime>("end_time");
            if start_time >= end_time {
                println!("The start time must be younger than the end time.");
                return;
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
        .arg(
            arg!(-c --config <FILE> "Sets a custom config file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-d --debug ... "Turn debugging information on"))
        .subcommand(
            Command::new("dump")
                .about("dump a file. .ti .ci .ne")
                .arg(arg!(<FILENAME> "the file name. .ti .ci .ne"))
                .arg_required_else_help(true),
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
