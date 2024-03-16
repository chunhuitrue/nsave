mod packet;
mod capture;
mod flow;

use flow::*;
use capture::*;
use crate::packet::{Packet, PacketKey};
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::mpsc::{self, TrySendError};
use std::thread;
use std::time::Duration;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;

const THREAD_NUM: u64 = 2;
const CHANNEL_BUFF: usize = 1024;
const TIMER_INTERVEL: u128 = 1_000_000_000; // 1秒

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
    }).expect("Error setting Ctrl-C handler");

    let mut statis = (0..THREAD_NUM).map(|_| Statis::new()).collect::<Vec<Statis>>();
    let mut txs = vec![];
    let mut threads = vec![];
    for _ in 0..THREAD_NUM {
        let running_clone = running.clone();
        let (tx, rx) = mpsc::sync_channel::<Arc<Packet>>(CHANNEL_BUFF);
        let thread_hd = thread::spawn(move || {
            writer_thread(running_clone, rx);
        });
        threads.push(thread_hd);
        txs.push(tx);
    }
    
    let mut capture = Capture::init(&args[1]).unwrap();
    while running.load(Ordering::Relaxed) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
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
        println!("statis[{}] send_ok:{}, send_err:{}", i, statis[i].send_ok, statis[i].send_err);
    }
    std::process::exit(0);
}

fn writer_thread(running: Arc<AtomicBool>, rx: Receiver<Arc<Packet>>) {
    let mut recv_num: usize = 0;
    let mut flow_err: usize = 0;
    let mut flow = Flow::new();
    let mut now: u128;
    let mut prev_ts: u128 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();

    while running.load(Ordering::Relaxed) {
        match rx.try_recv() {
            Ok(pkt) => {
                println!("thread: {:?} recv a pkt: {:?}", thread::current().id(), pkt);
                recv_num += 1;
                now = pkt.timestamp;
                let mut remove_key: std::option::Option<PacketKey> = None;
                if let Some(node) = flow.get_mut_or_new(&pkt, now) {
                    node.update(&pkt, now);
                    // node中挂载的其他功能，如memerge，拿出来在此次处理。不要在node process内部处理
                    if node.streams_fin() {
                        remove_key = Some(node.key);
                    }
                } else {
                    flow_err += 1;
                    continue;
                }
                if let Some(key) = remove_key {
                    // node中挂载的他其功能，结束调用。但是需要再查一次表: node = flow.get_mut_from_key(&key)
                    flow.remove(&key);
                }
            }
            Err(TryRecvError::Empty) => {
                println!("thread: {:?} recv empty", thread::current().id());
                now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            }
            Err(TryRecvError::Disconnected) => {
                println!("thread: {:?} recv desconnected", thread::current().id());
                return;
            }
        }

        // timer
        if now - prev_ts > TIMER_INTERVEL  {
            prev_ts = now;
            flow.timeout(now);
        }

        println!("thread: {:?} running...", thread::current().id());
        thread::sleep(Duration::from_millis(100));
    }
    println!("thread: {:?} exit. recv pkt: {}, flow_err: {}", thread::current().id(), recv_num, flow_err);
}

struct Statis {
    send_ok: usize,
    send_err: usize,
}

impl Statis {
    pub fn new() -> Statis {
        Statis { send_ok: 0, send_err: 0 }
    }
}
