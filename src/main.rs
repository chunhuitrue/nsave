use capture::*;
use clap::{arg, value_parser, Command};
use common::*;
use flow::*;
use libnsave::*;
use packet::Packet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::{self, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::*;
// use timeindex::*;

const CHANNEL_BUFF: usize = 2048;
// const TIMER_INTERVEL: u128 = 1_000_000_000; // 1秒
const TIMER_INTERVEL: u128 = 500_000_000; // 500毫秒
const EMPTY_SLEEP: u64 = 5;

fn main() {
    let pcap_file;

    let matches = cli().get_matches();
    if let Some(pcap) = matches.get_one::<PathBuf>("pcap") {
        println!("pcap file: {}", pcap.display());
        pcap_file = pcap;
    } else {
        return;
    }
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

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    let mut statis = (0..THREAD_NUM)
        .map(|_| Statis::new())
        .collect::<Vec<Statis>>();
    let mut txs = vec![];
    let mut threads = vec![];
    for i in 0..THREAD_NUM {
        let running_clone = running.clone();
        let (tx, rx) = mpsc::sync_channel::<Arc<Packet>>(CHANNEL_BUFF);
        let thread_hd = thread::spawn(move || {
            writer_thread(running_clone, i, rx);
        });
        threads.push(thread_hd);
        txs.push(tx);
    }

    let mut capture = Capture::init(pcap_file).unwrap();
    while running.load(Ordering::Relaxed) {
        let now = timenow();
        let pkt = capture.next_packet(now);
        if pkt.is_err() {
            continue;
        }
        let pkt = pkt.unwrap();
        if pkt.decode().is_err() {
            continue;
        }

        let index = (pkt.hash_value() % THREAD_NUM) as usize;
        match &txs[index].try_send(pkt) {
            Ok(()) => {
                statis[index].send_ok += 1;
            }
            Err(TrySendError::Full(_)) => {
                statis[index].send_err += 1;
            }
            Err(TrySendError::Disconnected(_)) => {
                break;
            }
        }

        // thread::sleep(Duration::from_millis(100)); // todo: del.调试用
    }

    running.store(false, Ordering::Relaxed);
    for thread_hd in threads {
        thread_hd.join().unwrap();
    }
    for i in 0..THREAD_NUM {
        let i: usize = i.try_into().unwrap();
        println!(
            "statis[{}] send_ok:{}, send_err:{}",
            i, statis[i].send_ok, statis[i].send_err
        );
    }
    std::process::exit(0);
}

fn cli() -> Command {
    Command::new("nsave")
        .about("nsave server")
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .arg(
            arg!(-c --config <FILE> "Sets a custom config file")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-d --debug ... "Turn debugging information on").required(false))
        .arg(
            arg!(-p --pcap <PCAPFILE> "load pcapfile")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
}

fn writer_thread(running: Arc<AtomicBool>, writer_id: u64, rx: Receiver<Arc<Packet>>) {
    let mut flow = Flow::new();
    // let time_index = TimeIndex::new(writer_id);
    let mut now;
    let mut prev_ts = timenow();
    let mut recv_num: u64 = 0;
    let mut flow_err: u64 = 0;

    let mut data_path = PathBuf::new();
    data_path.push(STORE_PATH);
    data_path.push(format!("{:03}", writer_id));
    let store = Store::new(data_path);
    if let Err(e) = store.init() {
        println!("packet store init error: {}", e);
        return;
    }

    println!("writer: {:?} running...", writer_id);
    while running.load(Ordering::Relaxed) {
        match rx.try_recv() {
            Ok(pkt) => {
                recv_num += 1;
                now = pkt.timestamp;
                let mut remove_key = None;
                if let Some(node) = flow.get_mut_or_new(&pkt, now) {
                    node.update(&pkt, now);

                    if node.store_ctx.is_none() {
                        node.store_ctx = Some(StoreCtx::new());
                    }
                    if store
                        .store(node.store_ctx.as_ref().unwrap(), pkt, now)
                        .is_err()
                    {
                        break;
                    }

                    if node.is_fin() {
                        println!("thread {}. node is fin", writer_id);
                        remove_key = Some(node.key);

                        let _ = store.link_fin(&node.key, node.start_time, now);
                        // if time_index
                        //     .save_index(&node.key, node.start_time, now)
                        //     .is_err()
                        // {
                        //     println!("Failed to save index. node key{:?}", &node.key);
                        // }
                    }
                } else {
                    flow_err += 1;
                    continue;
                }
                if let Some(key) = remove_key {
                    flow.remove(&key);
                }
            }
            Err(TryRecvError::Empty) => {
                thread::sleep(Duration::from_millis(EMPTY_SLEEP));
                now = timenow();
            }
            Err(TryRecvError::Disconnected) => {
                println!("writer: {:?} recv desconnected", writer_id);
                break;
            }
        }

        if now > prev_ts + TIMER_INTERVEL {
            prev_ts = now;

            if store.timer(now).is_err() {
                break;
            }
            flow.timeout(now, |node| {
                if store.link_fin(&node.key, node.start_time, now).is_err() {
                    println!("store link fin error. node key{:?}", &node.key);
                }
            });
            // flow.timeout(now, |node| {
            //     if time_index
            //         .save_index(&node.key, node.start_time, now)
            //         .is_err()
            //     {
            //         println!("Failed to save index. node key{:?}", &node.key);
            //     }
            // });
            // time_index.timer(now);
        }
    }
    println!(
        "writer: {:?} exit. recv pkt: {}, flow_err: {}",
        writer_id, recv_num, flow_err
    );
}

struct Statis {
    send_ok: usize,
    send_err: usize,
}

impl Statis {
    pub fn new() -> Statis {
        Statis {
            send_ok: 0,
            send_err: 0,
        }
    }
}

fn timenow() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
