mod packet;
mod capture;

use capture::*;
use packet::Packet;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;

static THREAD_NUM: u64 = 2;
static CHANNEL_BUFF: usize = 1024;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        std::process::exit(1);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
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
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let pkt = capture.next_packet(now);
        if pkt.is_err() {
            continue;
        }
        let pkt = pkt.unwrap();
        if pkt.decode().is_err() {
            continue;
        }

        let index = (pkt.hash_value() % THREAD_NUM) as usize;
        if let Err(_e) = &txs[index].try_send(pkt) {
            statis[index].send_err += 1;
        }
        statis[index].send_ok += 1;

        // println!("decode a packet ok! {:?}", pkt);
    }

    for thread_hd in threads {
        thread_hd.join().unwrap();
    }
    for i in 0..THREAD_NUM {
        let i: usize = i.try_into().unwrap();
        println!("statis[{}] send_ok:{}, send_err:{}", i, statis[i].send_ok, statis[i].send_err);
    }
    std::process::exit(0);
}

fn writer_thread(running: Arc<AtomicBool>,  rx: Receiver<Arc<Packet>>) {
    let thread_id = thread::current().id();
    let mut recv_num: usize = 0;

    while running.load(Ordering::Relaxed) {
        match rx.try_recv() {
            Ok(pkt) => {
                recv_num += 1;
                println!("thread: {:?} recv a pkt: {:?}", thread_id, pkt);
            }
            Err(TryRecvError::Empty) => {
                println!("thread: {:?} recv empty", thread_id);
            }
            Err(TryRecvError::Disconnected) => {
                println!("thread: {:?} recv desconnected", thread_id);
            }
        }

        println!("thread: {:?} running...", thread_id);
        thread::sleep(Duration::from_millis(100));
    }

    println!("thread: {:?} exit. recv pkt: {}", thread_id, recv_num);
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
