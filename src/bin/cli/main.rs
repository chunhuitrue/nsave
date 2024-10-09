use chrono::{Duration, Local, NaiveDateTime};
use clap::{arg, value_parser, Command};
use libnsave::chunkindex::*;
use libnsave::chunkpool::*;
use libnsave::common::*;
use libnsave::configure::*;
use libnsave::packet::*;
use libnsave::search_ci::*;
use libnsave::search_cp::*;
use libnsave::search_ti::*;
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
    let configure;

    let matches = cli().get_matches();
    if let Some(config_path) = matches.get_one::<PathBuf>("config") {
        println!("config file: {}", config_path.display());
        configure = Configure::load(config_path)?;
    } else {
        return Err(StoreError::OpenError("configure file error".to_string()));
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
                return dump_chunkindex_file(chunkid_file.into());
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
                search_dump(configure, search_key, file.into())?;
            } else {
                search_only(configure, search_key);
            };
            Ok(())
        }
        Some(("bpf_search", sub_matches)) => {
            let start_time = sub_matches.get_one::<NaiveDateTime>("start_time");
            let end_time = sub_matches.get_one::<NaiveDateTime>("end_time");
            if start_time > end_time {
                println!("The start time must be younger than the end time.");
                return Err(StoreError::ReadError(
                    "can not find parent path".to_string(),
                ));
            }
            let bpf_program = sub_matches.get_one::<String>("bpf");
            if bpf_program.is_none() {
                println!("no bpf filter");
                return Err(StoreError::ReadError("no bpf filter".to_string()));
            }

            if let Some(file) = sub_matches.get_one::<String>("pcap_file") {
                bpf_search_dump(
                    configure,
                    *start_time.unwrap(),
                    *end_time.unwrap(),
                    bpf_program.unwrap(),
                    Some(file.into()),
                )?;
            } else {
                bpf_search_dump(
                    configure,
                    *start_time.unwrap(),
                    *end_time.unwrap(),
                    bpf_program.unwrap(),
                    None,
                )?;
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
                .required(true)
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
                     example: nsave-cli -c nsave_conf.toml \
                     search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47 \
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
        .subcommand(
            Command::new("bpf_search")
                .about(
                    "search a link with bpf filter.\n\
                     example: nsave-cli -c nsave_conf.toml \
                     bpf_search -s 2024-05-18-15:36:36 -e 2024-05-18-15:36:47 \
                     --bpf \"localhost and tcp\"",
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
                .arg(arg!(-b - -bpf <BPF>).help("bpf filter").required(true))
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

fn search_only(configure: &'static Configure, search_key: SearchKey) {
    for dir_id in 0..configure.thread_num {
        let dir_ti = ti_search(configure, search_key, dir_id);
        if dir_ti.is_empty() {
            continue;
        }

        println!("find link:");
        for ti in dir_ti {
            println!("{}", ti);
        }
    }
}

fn search_dump(
    configure: &'static Configure,
    search_key: SearchKey,
    pcap_file: PathBuf,
) -> Result<(), StoreError> {
    for dir_id in 0..configure.thread_num {
        let dir_ti = ti_search(configure, search_key, dir_id);
        if dir_ti.is_empty() {
            continue;
        }

        println!("find link:");
        for ti in &dir_ti {
            println!("{}", ti);
        }
        dump(configure, dir_ti, &pcap_file, dir_id)?;
    }
    Ok(())
}

fn bpf_search_dump(
    configure: &'static Configure,
    start_time: NaiveDateTime,
    end_time: NaiveDateTime,
    filter: &str,
    pcap_file: Option<PathBuf>,
) -> Result<(), StoreError> {
    for dir_id in 0..configure.thread_num {
        let _ = bpf_search_dump_dir(
            configure,
            start_time,
            end_time,
            filter,
            pcap_file.clone(),
            dir_id,
        );
    }
    Ok(())
}

fn bpf_search_dump_dir(
    configure: &'static Configure,
    start_date: NaiveDateTime,
    end_date: NaiveDateTime,
    filter: &str,
    pcap_file: Option<PathBuf>,
    dir_id: u64,
) -> Result<(), StoreError> {
    println!("start search from dir_id: {:?}", dir_id);

    let search_ti = SearchTi::new(configure, start_date, Some(end_date), dir_id);
    let res = search_ti.next_ti();
    if res.is_none() {
        println!("find nothing in this time scope");
        return Err(StoreError::WriteError(
            "find nothing in this time scope".to_string(),
        ));
    }
    let (ti, dir_date) = res.unwrap();

    let mut search_ci = SearchCi::new(configure, dir_date, ti.ci_offset, dir_id);
    let ci = search_ci.next_ci();
    if ci.is_none() {
        println!("start time have no chunk index.");
        return Err(StoreError::WriteError(
            "start time have no chunk index".to_string(),
        ));
    }
    let ci = ci.unwrap();

    if configure.filter.is_none() {
        println!("bpf filter is none");
        return Err(StoreError::WriteError("bpf filter is none".to_string()));
    }
    let capture = PcapCapture::dead(Linktype::ETHERNET);
    if capture.is_err() {
        return Err(StoreError::WriteError("capture error".to_string()));
    }
    let capture = capture.unwrap();
    let bpf_program = capture.compile(filter, false);
    if bpf_program.is_err() {
        println!("bpf error: {:?}", bpf_program.err());
        return Err(StoreError::WriteError("bpf error".to_string()));
    }
    let bpf_program = bpf_program.unwrap();

    let mut savefile = if pcap_file.is_some() {
        let file = capture.savefile(pcap_file.unwrap());
        if file.is_err() {
            println!("savefile error: {:?}", file.err());
            return Err(StoreError::WriteError("savefile error".to_string()));
        }
        Some(file.unwrap())
    } else {
        None
    };

    let mut search_cp = SearchCp::new(configure, dir_id);
    if let Err(err) = search_cp.load_chunk(ci.chunk_id, ci.chunk_offset) {
        println!("cp search err: {:?}", err);
        return Err(StoreError::WriteError("cp search err".to_string()));
    }
    while let Some(pkt) = search_cp.next_pkt() {
        let pkt_date = ts_date(pkt.timestamp).naive_local();
        if pkt_date > end_date {
            break;
        }

        if bpf_program.filter(&pkt.data) {
            println!("find packet : {:?}", pkt);
            if let Some(ref mut savefile) = savefile {
                println!("save packet");
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

    println!("end search from dir_id: {:?}", dir_id);
    Ok(())
}

fn dump(
    configure: &'static Configure,
    ti: Vec<LinkRecord>,
    pcap_file: &Path,
    dir_id: u64,
) -> Result<(), StoreError> {
    if let Some(mini_ti) = &ti.iter().min_by_key(|ti| ti.start_time) {
        let capture = PcapCapture::dead(Linktype::ETHERNET);
        if capture.is_err() {
            return Err(StoreError::WriteError("pcap open error".to_string()));
        }
        let capture = capture.unwrap();
        let savefile = capture.savefile(pcap_file);
        if savefile.is_err() {
            return Err(StoreError::WriteError("capture savefile error".to_string()));
        }
        let mut savefile = savefile.unwrap();

        let mut search_cp = SearchCp::new(configure, dir_id);
        let mut rd_set: HashSet<PacketKey> = ti.iter().map(|rd| rd.tuple5).collect();
        let mut search_date = ts_date(mini_ti.start_time).naive_local();
        let date_end = Local::now().naive_local();
        while search_date < date_end && !rd_set.is_empty() {
            let dir = date2dir(configure, dir_id, search_date);
            if dir.exists() {
                if let Some(link_rd) = search_lr(&dir, mini_ti.tuple5) {
                    let mut search_ci =
                        SearchCi::new(configure, search_date, link_rd.ci_offset, dir_id);
                    while let Some(rd) = search_ci.next_ci() {
                        if !rd_set.contains(&rd.tuple5) {
                            continue;
                        }

                        if rd.end_time != 0 {
                            rd_set.remove(&rd.tuple5);
                            continue;
                        }
                        search_cp.load_chunk(rd.chunk_id, rd.chunk_offset)?;
                        while let Some(pkt) = search_cp.next_link_pkt() {
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
