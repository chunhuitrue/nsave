mod capture;
mod flow;
mod packet;
mod timeindex;

use crate::packet::Packet;
use crate::timeindex::*;
use capture::*;
use flow::*;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::{self, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const THREAD_NUM: u64 = 2;
const CHANNEL_BUFF: usize = 2048;
const TIMER_INTERVEL: u128 = 1_000_000_000; // 1秒
const EMPTY_SLEEP: u64 = 5;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        std::process::exit(1);
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

    let mut capture = Capture::init(&args[1]).unwrap();
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

fn writer_thread(running: Arc<AtomicBool>, writer_id: u64, rx: Receiver<Arc<Packet>>) {
    let mut flow = Flow::new();
    let time_index = TimeIndex::new();
    let mut now;
    let mut prev_ts = timenow();
    let mut recv_num: u64 = 0;
    let mut flow_err: u64 = 0;

    println!("writer: {:?} running...", writer_id);
    while running.load(Ordering::Relaxed) {
        match rx.try_recv() {
            Ok(pkt) => {
                recv_num += 1;
                now = pkt.timestamp;
                let mut remove_key = None;
                if let Some(node) = flow.get_mut_or_new(&pkt, now) {
                    node.update(&pkt, now);

                    if node.is_fin() {
                        time_index.save_index(&node.key, now);
                        remove_key = Some(node.key);
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
                return;
            }
        }

        if now > prev_ts + TIMER_INTERVEL {
            prev_ts = now;
            flow.timeout(now, |node| time_index.save_index(&node.key, now));
            time_index.timer(now);
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
