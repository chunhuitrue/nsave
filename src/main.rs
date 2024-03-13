mod packet;
mod capture;

use capture::*;
use packet::Packet;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::Receiver;

static THREAD_NUM: i32 = 2;

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

    let mut txs = vec![];
    let mut threads = vec![];
    for _ in 0..THREAD_NUM {
        let running_clone = running.clone();
        let (tx, rx) = mpsc::channel::<Arc<Packet>>();        
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

        // println!("decode a packet ok! {:?}", pkt);
    }

    for thread_hd in threads {
        thread_hd.join().unwrap();
    }
    std::process::exit(0);
}

fn writer_thread(running: Arc<AtomicBool>,  rx: Receiver<Arc<Packet>>) {
    let thread_id = thread::current().id();

    while running.load(Ordering::Relaxed) {
        println!("thread: {:?} running...\n", thread_id);
        thread::sleep(Duration::from_secs(1));
    }

    println!("thread: {:?} exit.\n", thread_id);    
}

fn hash_value<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}
