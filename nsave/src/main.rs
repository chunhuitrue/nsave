use crate::af_xdp::*;
use crate::capture::*;
use crate::common::*;
use crate::configure::*;
use crate::flow::*;
use crate::pcap::PcapConfig;
use crate::store::*;
use anyhow::anyhow;
use clap::{Command, arg, value_parser};
use crossbeam_channel::{self, Receiver, Sender, TryRecvError, TrySendError};
use daemonize::Daemonize;
use libnsave::*;
use log::{error, info, warn};
use std::fs::File;
use std::{
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(feature = "debug_mode")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    main_internal()
}

#[cfg(not(feature = "debug_mode"))]
fn main() -> anyhow::Result<()> {
    main_internal()
}

fn main_internal() -> anyhow::Result<()> {
    let matches = cli().get_matches();

    let conf_file = if let Some(cli_conf) = matches.get_one::<PathBuf>("config") {
        cli_conf.clone()
    } else {
        let home_dir = std::env::var("HOME").expect("Failed to get HOME environment variable");
        let mut path = PathBuf::from(home_dir);
        path.push(DEFAULT_CONFIG_FILE);
        path
    };
    let configure = if let Ok(conf) = Configure::load(&conf_file) {
        conf
    } else {
        error!("Error: Need set configure file");
        return Err(anyhow!(""));
    };

    env_logger::init();

    if configure.main.daemon {
        let mut std_out_path = PathBuf::from(configure.main.store_path.clone());
        std_out_path.push("nsave.out");
        let stdout = File::create(std_out_path).unwrap();
        let mut std_err_path = PathBuf::from(configure.main.store_path.clone());
        std_err_path.push("nsave.err");
        let stderr = File::create(std_err_path).unwrap();
        let mut pid_file = PathBuf::from(configure.main.store_path.clone());
        pid_file.push("nsave.pid");
        let work_dir = PathBuf::from(configure.main.store_path.clone());

        Daemonize::new()
            .pid_file(pid_file)
            .working_directory(work_dir)
            .stdout(stdout)
            .stderr(stderr)
            .start()
            .expect("Failed to start daemon");
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
        let _ = set_promiscuous_mode(&configure.main.interface.clone(), false);
    })
    .expect("Error setting Ctrl-C handler");

    let barrier = Arc::new(Barrier::new((configure.main.thread_num + 2) as usize));
    let mut decode_err: usize = 0;
    let mut statis = (0..configure.main.thread_num)
        .map(|_| Statis::new())
        .collect::<Vec<Statis>>();
    let mut msg_rxs = vec![];
    let mut pkt_txs = vec![];
    let mut writer_thds = vec![];

    // 写盘线程
    for i in 0..configure.main.thread_num {
        let barrier_writer = barrier.clone();
        let running_writer = running.clone();
        let (msg_tx, msg_rx) = crossbeam_channel::bounded::<Msg>(configure.main.msg_channel_size);
        let (pkt_tx, pkt_rx) =
            crossbeam_channel::bounded::<Packet>(configure.main.pkt_channel_size);
        let writer_thd = thread::spawn(move || {
            writer_thread(configure, barrier_writer, running_writer, i, pkt_rx, msg_tx);
        });
        msg_rxs.push(msg_rx);
        pkt_txs.push(pkt_tx);
        writer_thds.push(writer_thd);
    }

    // 清理线程
    let barrier_clean = barrier.clone();
    let running_clean = running.clone();
    let clean_thd = thread::spawn(move || {
        clean_thread(configure, barrier_clean, running_clean, msg_rxs);
    });

    // 设置混杂模式
    let iface = configure.main.interface.clone();
    set_promiscuous_mode(&iface, true)?;

    // 创建capture
    let config = match configure.main.capture {
        Some(crate::configure::CaptureType::AfXdp) => CaptureConfig::af_xdp(iface.clone())
            .with_af_xdp_config(AfXdpConfig {
                rx_queue_len: configure.af_xdp.rx_queue_len,
                tx_queue_len: configure.af_xdp.tx_queue_len,
                fill_queue_len: configure.af_xdp.fill_queue_len,
                completion_queue_len: configure.af_xdp.completion_queue_len,
                frame_size: configure.af_xdp.frame_size,
                headroom_size: default_headroom_size(),
                hugepage: configure.af_xdp.hugepage,
                zcopy: configure.af_xdp.zcopy,
                pkt_recycle_channel_size: configure.af_xdp.pkt_recycle_channel_size,
                recycle_buff_size: configure.af_xdp.recycle_buff_size,
            }),
        Some(crate::configure::CaptureType::Pcap) => {
            let pcap_config = PcapConfig {
                filter: configure.pcap.filter.clone(),
                pcap_file: configure.pcap.pcap_file.clone(),
                pkt_recycle_channel_size: configure.pcap.pkt_recycle_channel_size,
                buffer_pool_size: configure.pcap.buffer_pool_size,
                buffer_size: configure.pcap.buffer_size,
            };
            if let Some(ref pcap_file) = configure.pcap.pcap_file {
                CaptureConfig::pcap_file(pcap_file.clone()).with_pcap_config(pcap_config)
            } else {
                CaptureConfig::pcap_live(iface.clone()).with_pcap_config(pcap_config)
            }
        }
        None => {
            warn!("Warning: No capture type specified in config, defaulting to AF_XDP");
            CaptureConfig::af_xdp(iface.clone()).with_af_xdp_config(crate::af_xdp::AfXdpConfig {
                rx_queue_len: configure.af_xdp.rx_queue_len,
                tx_queue_len: configure.af_xdp.tx_queue_len,
                fill_queue_len: configure.af_xdp.fill_queue_len,
                completion_queue_len: configure.af_xdp.completion_queue_len,
                frame_size: configure.af_xdp.frame_size,
                headroom_size: default_headroom_size(),
                hugepage: configure.af_xdp.hugepage,
                zcopy: configure.af_xdp.zcopy,
                pkt_recycle_channel_size: configure.af_xdp.pkt_recycle_channel_size,
                recycle_buff_size: configure.af_xdp.recycle_buff_size,
            })
        }
    };
    let mut capture = create_capture(&config)?;

    // 分发线程
    let thread_num = configure.main.thread_num;
    barrier.wait();
    while running.load(Ordering::Relaxed) {
        capture.acquire_packets(|mut packet| {
            if packet.decode_ok() {
                let index = (packet.hash_value() % thread_num) as usize;
                match &pkt_txs[index].try_send(packet) {
                    Ok(()) => {
                        statis[index].send_ok += 1;
                    }
                    Err(TrySendError::Full(_)) => {
                        statis[index].send_err += 1;
                    }
                    Err(TrySendError::Disconnected(_)) => {}
                }
            } else {
                decode_err += 1;
            }
        })?;
    }
    running.store(false, Ordering::Relaxed);

    for writer_thd in writer_thds {
        writer_thd.join().unwrap();
    }
    clean_thd.join().unwrap();
    for i in 0..configure.main.thread_num {
        let i: usize = i.try_into().unwrap();
        info!(
            "Info: Statis[{}] send_ok:{}, send_err:{}",
            i, statis[i].send_ok, statis[i].send_err
        );
    }
    std::process::exit(0);
}

fn cli() -> Command {
    Command::new("nsave")
        .version(VERSION)
        .author(AUTHOR)
        .about("nsave server")
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .arg(
            arg!(-c --config <FILE> "Sets a custom config file")
                .value_parser(value_parser!(PathBuf)),
        )
}

fn writer_thread(
    configure: &'static Configure,
    barrier: Arc<Barrier>,
    running: Arc<AtomicBool>,
    writer_id: u64,
    pkt_rx: Receiver<Packet>,
    msg_tx: Sender<Msg>,
) {
    let mut flow = Box::new(Flow::new_with_arg(
        configure.main.flow_max_table_capacity,
        configure.main.flow_node_timeout as u128,
        configure.main.flow_max_seq_gap,
    ));
    let mut now;
    let mut prev_ts = timenow();
    let mut recv_num: u64 = 0;
    let mut flow_err: u64 = 0;

    let mut data_path = PathBuf::new();
    data_path.push(&configure.main.store_path);
    data_path.push(format!("{writer_id:03}"));
    let store = Store::new(configure, data_path, msg_tx);
    if let Err(e) = store.init() {
        error!("Error: Store init error: {e}");
        return;
    }

    barrier.wait();
    info!("Info: Writer: {writer_id:?} start");
    while running.load(Ordering::Relaxed) {
        match pkt_rx.try_recv() {
            Ok(pkt) => {
                info!("Info: Writer: {writer_id:?} recv num : {recv_num}"); // todo del
                recv_num += 1;
                now = pkt.timestamp();
                let mut remove_key = None;
                if let Some(node) = flow.get_mut_or_new(&pkt, now) {
                    node.update(&pkt, now);

                    if node.store_ctx.is_none() {
                        node.store_ctx = Some(StoreCtx::new());
                    }
                    let store_ret = store.store(node, pkt, now);
                    if store_ret.is_err() {
                        error!(
                            "Error: Writer {writer_id:?}, store err: {store_ret:?}, break while."
                        );
                        break;
                    }

                    if node.is_fin() {
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
                thread::sleep(Duration::from_millis(
                    configure.main.writer_empty_sleep as u64,
                ));
                now = timenow();
            }
            Err(TryRecvError::Disconnected) => {
                error!("Error: Writer: {writer_id:?} recv disconnected.");
                break;
            }
        }

        if now > prev_ts + configure.main.timer_intervel as u128 {
            prev_ts = now;

            if store.timer(now).is_err() {
                break;
            }
            flow.timeout(now, |node| {
                if store.link_fin(&node.key, node.start_time, now).is_err() {
                    error!("Error: Store link fin error. node key{:?}", &node.key);
                }
            });
        }
    }
    running.store(false, Ordering::Relaxed);
    store.finish();
    info!("Info: Writer: {writer_id:?} exit. recv pkt: {recv_num}, flow_err: {flow_err}");
}

fn clean_thread(
    configure: &'static Configure,
    barrier: Arc<Barrier>,
    running: Arc<AtomicBool>,
    msg_rxs: Vec<Receiver<Msg>>,
) {
    barrier.wait();
    info!("Info: Clean thread start");
    while running.load(Ordering::Relaxed) {
        for msg_rx in msg_rxs.iter() {
            match msg_rx.try_recv() {
                Ok(Msg::CoverChunk(pool_path, end_time)) => {
                    let _ = clean_index_dir(pool_path, ts_date(end_time));
                }
                Err(TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(
                        configure.main.clean_empty_sleep as u64,
                    ));
                }
                Err(TryRecvError::Disconnected) => {
                    error!("Error: Clean thread: {msg_rx:?} recv disconnected");
                    return;
                }
            }
        }
    }
    running.store(false, Ordering::Relaxed);
    info!("Info: Clean thread end");
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
