use capture::*;
use clap::{arg, value_parser, Command};
use common::*;
use configure::*;
use flow::*;
use libnsave::*;
use packet::Packet;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc, Barrier,
    },
    thread,
    time::Duration,
};
use store::*;

fn main() {
    let configure;

    let matches = cli().get_matches();
    if let Some(config_path) = matches.get_one::<PathBuf>("config") {
        println!("configure file: {}", config_path.display());
        if let Ok(conf) = Configure::load(config_path) {
            configure = conf;
        } else {
            return;
        }
    } else {
        println!("need set configure file");
        return;
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    let barrier = Arc::new(Barrier::new((configure.thread_num + 2) as usize));
    let mut statis = (0..configure.thread_num)
        .map(|_| Statis::new())
        .collect::<Vec<Statis>>();
    let mut msg_rxs = vec![];
    let mut pkt_txs = vec![];
    let mut writer_thds = vec![];

    for i in 0..configure.thread_num {
        let barrier_writer = barrier.clone();
        let running_writer = running.clone();
        let (msg_tx, msg_rx) = mpsc::sync_channel::<Msg>(configure.msg_channel_size);
        let (pkt_tx, pkt_rx) = mpsc::sync_channel::<Arc<Packet>>(configure.pkt_channel_size);
        let writer_thd = thread::spawn(move || {
            writer_thread(configure, barrier_writer, running_writer, i, pkt_rx, msg_tx);
        });
        msg_rxs.push(msg_rx);
        pkt_txs.push(pkt_tx);
        writer_thds.push(writer_thd);
    }

    let barrier_aide = barrier.clone();
    let running_aide = running.clone();
    let aide_thd = thread::spawn(move || {
        aide_thread(configure, barrier_aide, running_aide, msg_rxs);
    });

    let mut capture = match Capture::init_capture(configure) {
        Ok(cap) => cap,
        Err(e) => {
            println!("capture error {:?}", e);
            return;
        }
    };
    barrier.wait();

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

        let index = (pkt.hash_value() % configure.thread_num) as usize;
        match &pkt_txs[index].try_send(pkt) {
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

        if configure.pcap_file.is_some() {
            thread::sleep(Duration::from_millis(1));
        }
    }

    running.store(false, Ordering::Relaxed);
    for writer_thd in writer_thds {
        writer_thd.join().unwrap();
    }
    aide_thd.join().unwrap();
    for i in 0..configure.thread_num {
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
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
}

fn writer_thread(
    configure: &'static Configure,
    barrier: Arc<Barrier>,
    running: Arc<AtomicBool>,
    writer_id: u64,
    pkt_rx: Receiver<Arc<Packet>>,
    msg_tx: SyncSender<Msg>,
) {
    let mut flow = Flow::new_with_arg(
        configure.flow_max_table_capacity,
        configure.flow_node_timeout as u128,
        configure.flow_max_seq_gap,
    );
    let mut now;
    let mut prev_ts = timenow();
    let mut recv_num: u64 = 0;
    let mut flow_err: u64 = 0;

    let mut data_path = PathBuf::new();
    data_path.push(&configure.store_path);
    data_path.push(format!("{:03}", writer_id));
    let store = Store::new(configure, data_path, msg_tx);
    if let Err(e) = store.init() {
        println!("packet store init error: {}", e);
        return;
    }

    barrier.wait();
    println!("writer: {:?} running...", writer_id);
    while running.load(Ordering::Relaxed) {
        match pkt_rx.try_recv() {
            Ok(pkt) => {
                recv_num += 1;
                now = pkt.timestamp;
                let mut remove_key = None;
                if let Some(node) = flow.get_mut_or_new(&pkt, now) {
                    node.update(&pkt, now);

                    if node.store_ctx.is_none() {
                        node.store_ctx = Some(StoreCtx::new());
                    }
                    if store.store(node, pkt, now).is_err() {
                        break;
                    }

                    if node.is_fin() {
                        // println!("thread {}. node is fin", writer_id);
                        remove_key = Some(node.key);

                        let _ = store.link_fin(&node.key, node.start_time, now);
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
                thread::sleep(Duration::from_millis(configure.writer_empty_sleep as u64));
                now = timenow();
            }
            Err(TryRecvError::Disconnected) => {
                println!("writer_thread: {:?} recv disconnected", writer_id);
                break;
            }
        }

        if now > prev_ts + configure.timer_intervel as u128 {
            prev_ts = now;

            if store.timer(now).is_err() {
                break;
            }
            flow.timeout(now, |node| {
                if store.link_fin(&node.key, node.start_time, now).is_err() {
                    println!("store link fin error. node key{:?}", &node.key);
                }
            });
        }
    }
    println!(
        "writer: {:?} exit. recv pkt: {}, flow_err: {}",
        writer_id, recv_num, flow_err
    );
}

fn aide_thread(
    configure: &'static Configure,
    barrier: Arc<Barrier>,
    running: Arc<AtomicBool>,
    msg_rxs: Vec<Receiver<Msg>>,
) {
    barrier.wait();
    println!("aide thread running...");
    while running.load(Ordering::Relaxed) {
        for msg_rx in msg_rxs.iter() {
            match msg_rx.try_recv() {
                Ok(Msg::CoverChunk(pool_path, end_time)) => {
                    let _ = clean_index_dir(pool_path, ts_date(end_time));
                }
                Err(TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(configure.aide_empty_sleep as u64));
                }
                Err(TryRecvError::Disconnected) => {
                    println!("aide_thread: {:?} recv disconnected", msg_rx);
                    return;
                }
            }
        }
    }
    println!("aide thread end...");
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
