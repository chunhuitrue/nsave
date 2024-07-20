use chrono::{Duration, Local, NaiveDateTime};
use clap::{arg, value_parser, Command};
use libnsave::chunkindex::*;
use libnsave::chunkpool::*;
use libnsave::common::*;
use libnsave::packet::*;
use libnsave::timeindex::*;
use pcap::Capture as PcapCapture;
use pcap::Linktype;
use pcap::Packet as CapPacket;
use pcap::PacketHeader as CapPacketHeader;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
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
            if let Some(timeindex_file) = sub_matches.get_one::<String>("timeindex_file") {
                return dump_timeindex_file(timeindex_file.into());
            }

            if let Some(chunkid_file) = sub_matches.get_one::<String>("chunkindex_file") {
                return dump_chunkid_file(chunkid_file.into());
            }

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
            let search_key = SearchKey {
                start_time: start_time.copied(),
                end_time: end_time.copied(),
                sip: sip.copied(),
                dip: dip.copied(),
                sport: sport.copied(),
                dport: dport.copied(),
                protocol: protocol.copied(),
            };

            if let Some(file) = sub_matches.get_one::<String>("pcap_file") {
                search_dump(search_key, file.into())?;
            } else {
                search_only(search_key);
            };
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
                    arg!(-t - -timeindex_file <FILENAME>)
                        .help("dump time index file")
                        .required(false),
                )
                .arg(
                    arg!(-C - -chunkindex_file <FILENAME>)
                        .help("dump chunk index file")
                        .required(false),
                )
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
                .about(
                    "search a link.\n\
                       example: nsave-cli search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47 \
                        --sip 10.11.20.255 -D 10.11.20.14 -P udp -p 137 -d 137",
                )
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
                )
                .arg(
                    arg!(-f - -pcap_file <PCAPFILE>)
                        .help("dump search result to pcap file")
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

fn search_only(search_key: SearchKey) {
    for dir_id in 0..THREAD_NUM {
        let dir_ti = ti_search(search_key, dir_id);
        if dir_ti.is_empty() {
            continue;
        }

        println!("find link:");
        for ti in dir_ti {
            println!("{}", ti);
        }
    }
}

fn search_dump(search_key: SearchKey, pcap_file: PathBuf) -> Result<(), StoreError> {
    for dir_id in 0..THREAD_NUM {
        let dir_ti = ti_search(search_key, dir_id);
        if dir_ti.is_empty() {
            continue;
        }

        println!("find link:");
        for ti in &dir_ti {
            println!("{}", ti);
        }
        dump(dir_ti, &pcap_file, dir_id)?;
    }
    Ok(())
}

fn dump(ti: Vec<LinkRecord>, pcap_file: &Path, dir_id: u64) -> Result<(), StoreError> {
    if let Some(mini_ti) = &ti.iter().min_by_key(|ti| ti.start_time) {
        let capture = PcapCapture::dead(Linktype::ETHERNET);
        if capture.is_err() {
            return Err(StoreError::WriteError("pcap open error".to_string()));
        }
        let capture = capture.unwrap();
        let mut savefile = capture.savefile(pcap_file).unwrap();

        let cp_search = ChunkPoolSearch::new(dir_id);
        let mut rd_set: HashSet<PacketKey> = ti.iter().map(|rd| rd.tuple5).collect();
        let mut search_date = ts_date(mini_ti.start_time).naive_local();
        let date_end = Local::now().naive_local();
        while search_date < date_end && !rd_set.is_empty() {
            let dir = date2dir(dir_id, search_date);
            if dir.exists() {
                if let Some(link_rd) = search_lr(&dir, mini_ti.tuple5) {
                    let mut ci_search = ChunkIndexSearch::new(&dir, link_rd.ci_offset);
                    while let Some(rd) = ci_search.next_rd() {
                        if !rd_set.contains(&rd.tuple5) {
                            continue;
                        }

                        if rd.end_time != 0 {
                            rd_set.remove(&rd.tuple5);
                            continue;
                        }
                        cp_search.load_chunk(rd.chunk_id, rd.chunk_offset)?;
                        while let Some(pkt) = cp_search.next_pkt() {
                            println!("write pkt:{}", pkt);
                            let header = CapPacketHeader {
                                ts: ts_timeval(pkt.timestamp),
                                caplen: pkt.data_len as u32,
                                len: pkt.data_len as u32,
                            };
                            let cap_pkt = CapPacket {
                                header: &header,
                                data: &pkt.data,
                            };
                            savefile.write(&cap_pkt);
                        }
                    }
                }
            }
            search_date += Duration::try_minutes(1).unwrap();
        }
    }
    Ok(())
}
