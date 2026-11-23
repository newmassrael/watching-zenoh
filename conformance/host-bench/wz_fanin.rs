// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The fan-in probe of the host comparison (`scripts/pico-compare.sh fanin`, run by
// `scripts/host-bench/fanin.py`): several publishers of large samples to one subscriber, the shape of
// a vehicle's camera and lidar streams converging on one consumer. It uses only the public API of the
// `zenoh` crate, so the SAME source is built once over upstream's `zenoh` (arm P) and once with the
// family patched in (arm W), as upstream's own examples are for the parity matrix
// (`scripts/lib/z8_upstream_suite.py examples`).
//
// Role `pub` puts `--size` bytes `--hz` times a second for `--seconds`, on a schedule of absolute
// deadlines that does not burst to catch up: a put that returns after its next deadline has passed
// makes the publisher put the next one at once, and the deadlines it missed are counted (`late`).
// Each sample starts with a header the subscriber reads: a magic word, the publisher's `--id`, the
// sample's sequence number and the wall-clock time of the put. The rest of the sample is a fill whose
// every byte is a function of its offset, so a corrupted sample is told from a whole one.
//
// Role `sub` counts, per publisher: the samples received, the sequence numbers missing between two
// received ones (`gaps`), the samples that came at or below a number already seen (`behind`, a
// duplicate or a reordering), the samples whose fill did not check (`corrupt`) and the bytes. The
// one-way latency is the subscriber's wall clock less the header's, so it means something only when
// both sides read one clock (one host, or hosts whose clocks are disciplined); the runner says which.
//
// Each role prints one line of JSON when it ends, and nothing else on its standard output.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use zenoh::{bytes::ZBytes, qos::CongestionControl, Wait};
use zenoh_examples::CommonArgs;

/// The first four bytes of every sample.
const MAGIC: u32 = 0x5a46_4e49;
/// magic (4) + publisher id (4) + sequence number (8) + wall-clock nanoseconds of the put (8).
const HEADER: usize = 24;
/// The fill is checked at this stride and over its last bytes, so the check costs the subscriber a
/// small fraction of a copy of the sample while a lost or shifted fragment still shows.
const CHECK_STRIDE: usize = 1021;

#[derive(Parser, Debug)]
struct Args {
    /// `pub` or `sub`.
    #[arg(long)]
    role: String,
    /// The key the samples are put on.
    #[arg(long, default_value = "bench/fanin")]
    key: String,
    /// pub: this publisher's number, carried in every sample.
    #[arg(long, default_value = "0")]
    id: u32,
    /// pub: the bytes of a sample, the header included.
    #[arg(long, default_value = "1024")]
    size: usize,
    /// pub: the samples a second.
    #[arg(long, default_value = "10")]
    hz: f64,
    /// pub: the seconds of putting. sub: the seconds of counting after the first sample.
    #[arg(long, default_value = "10")]
    seconds: f64,
    /// pub: the seconds to wait after the session opens before the first put.
    #[arg(long, default_value = "2")]
    settle: f64,
    /// pub: `block` or `drop`, the congestion control of the publisher.
    #[arg(long, default_value = "block")]
    cc: String,
    /// sub: the seconds to wait for a first sample before giving up.
    #[arg(long, default_value = "30")]
    first_within: f64,
    #[command(flatten)]
    common: CommonArgs,
}

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The fill byte at `offset` of a sample.
fn fill(offset: usize) -> u8 {
    (offset % 251) as u8
}

/// The peak resident set of this process, in KiB (`VmHWM` of /proc/self/status), or 0 where there is none.
fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// The `q`-quantile of sorted values, by nearest rank; 0 for none.
fn quantile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn publish(args: &Args) -> i32 {
    if args.size < HEADER {
        eprintln!("wz_fanin: --size must be at least {HEADER}");
        return 2;
    }
    if !(args.hz > 0.0) {
        eprintln!("wz_fanin: --hz must be positive");
        return 2;
    }
    let cc = match args.cc.as_str() {
        "block" => CongestionControl::Block,
        "drop" => CongestionControl::Drop,
        other => {
            eprintln!("wz_fanin: --cc {other} is neither block nor drop");
            return 2;
        }
    };
    let session = match zenoh::open(zenoh::Config::from(&args.common)).wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wz_fanin: open: {e}");
            return 1;
        }
    };
    let publisher = match session
        .declare_publisher(args.key.clone())
        .congestion_control(cc)
        .wait()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("wz_fanin: declare_publisher: {e}");
            return 1;
        }
    };
    // The fill is made once and shared by every sample; each sample is its own header in front of it.
    let body: ZBytes = (HEADER..args.size).map(fill).collect::<Vec<u8>>().into();
    std::thread::sleep(Duration::from_secs_f64(args.settle));

    let period = Duration::from_secs_f64(1.0 / args.hz);
    let total = (args.seconds * args.hz).round() as u64;
    let mut put_ns: Vec<u64> = Vec::with_capacity(total as usize);
    let (mut errors, mut late) = (0u64, 0u64);
    let start = Instant::now();
    for seq in 0..total {
        let deadline = start + period * (seq as u32);
        let now = Instant::now();
        if deadline > now {
            std::thread::sleep(deadline - now);
        } else if now - deadline >= period {
            late += 1;
        }
        let mut header = [0u8; HEADER];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&args.id.to_le_bytes());
        header[8..16].copy_from_slice(&seq.to_le_bytes());
        header[16..24].copy_from_slice(&wall_ns().to_le_bytes());
        let mut writer = ZBytes::writer();
        writer.write_all(&header).expect("a header fits a writer");
        writer.append(body.clone());
        let began = Instant::now();
        if publisher.put(writer.finish()).wait().is_err() {
            errors += 1;
        }
        put_ns.push(began.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed().as_secs_f64();
    put_ns.sort_unstable();
    println!(
        "{{\"role\":\"pub\",\"id\":{},\"size\":{},\"hz\":{},\"cc\":\"{}\",\"sent\":{},\"put_errors\":{},\"late\":{},\"elapsed_s\":{:.3},\"put_us_p50\":{},\"put_us_p99\":{},\"put_us_max\":{},\"rss_kib\":{}}}",
        args.id,
        args.size,
        args.hz,
        args.cc,
        total,
        errors,
        late,
        elapsed,
        quantile(&put_ns, 0.5) / 1000,
        quantile(&put_ns, 0.99) / 1000,
        put_ns.last().copied().unwrap_or(0) / 1000,
        peak_rss_kib(),
    );
    // Undeclared before the session closes, as upstream's examples leave it to the drop order.
    drop(publisher);
    drop(session);
    0
}

#[derive(Default)]
struct PerPublisher {
    received: u64,
    gaps: u64,
    behind: u64,
    corrupt: u64,
    bytes: u64,
    last_seq: Option<u64>,
    first_seq: Option<u64>,
}

#[derive(Default)]
struct Tally {
    publishers: BTreeMap<u32, PerPublisher>,
    foreign: u64,
    latency_ns: Vec<u64>,
    first: Option<Instant>,
    last: Option<Instant>,
}

/// Whether the fill of `sample` is whole, at the stride and over the last bytes.
fn fill_checks(sample: &[u8]) -> bool {
    let tail = sample.len().saturating_sub(64).max(HEADER);
    (HEADER..sample.len())
        .step_by(CHECK_STRIDE)
        .chain(tail..sample.len())
        .all(|i| sample[i] == fill(i))
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

fn read_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

fn subscribe(args: &Args) -> i32 {
    let session = match zenoh::open(zenoh::Config::from(&args.common)).wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wz_fanin: open: {e}");
            return 1;
        }
    };
    let tally = Arc::new(Mutex::new(Tally::default()));
    let seen = tally.clone();
    let subscriber = match session
        .declare_subscriber(args.key.clone())
        .callback(move |sample| {
            let arrived = wall_ns();
            let bytes = sample.payload().to_bytes();
            let mut t = seen.lock().expect("the tally is not poisoned");
            let now = Instant::now();
            t.first.get_or_insert(now);
            t.last = Some(now);
            if bytes.len() < HEADER || read_u32(&bytes, 0) != MAGIC {
                t.foreign += 1;
                return;
            }
            let id = read_u32(&bytes, 4);
            let seq = read_u64(&bytes, 8);
            let sent = read_u64(&bytes, 16);
            t.latency_ns.push(arrived.saturating_sub(sent));
            let whole = fill_checks(&bytes);
            let p = t.publishers.entry(id).or_default();
            p.received += 1;
            p.bytes += bytes.len() as u64;
            if !whole {
                p.corrupt += 1;
            }
            p.first_seq.get_or_insert(seq);
            match p.last_seq {
                Some(last) if seq <= last => p.behind += 1,
                Some(last) => {
                    p.gaps += seq - last - 1;
                    p.last_seq = Some(seq);
                }
                None => p.last_seq = Some(seq),
            }
        })
        .wait()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wz_fanin: declare_subscriber: {e}");
            return 1;
        }
    };
    let opened = Instant::now();
    let first = loop {
        if let Some(first) = tally.lock().expect("the tally is not poisoned").first {
            break Some(first);
        }
        if opened.elapsed() >= Duration::from_secs_f64(args.first_within) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if let Some(first) = first {
        let until = first + Duration::from_secs_f64(args.seconds);
        let now = Instant::now();
        if until > now {
            std::thread::sleep(until - now);
        }
    }
    drop(subscriber);
    let mut t = tally.lock().expect("the tally is not poisoned");
    let span = match (t.first, t.last) {
        (Some(a), Some(b)) => (b - a).as_secs_f64(),
        _ => 0.0,
    };
    t.latency_ns.sort_unstable();
    let pubs: Vec<String> = t
        .publishers
        .iter()
        .map(|(id, p)| {
            format!(
                "{{\"id\":{},\"received\":{},\"gaps\":{},\"behind\":{},\"corrupt\":{},\"bytes\":{},\"first_seq\":{},\"last_seq\":{}}}",
                id,
                p.received,
                p.gaps,
                p.behind,
                p.corrupt,
                p.bytes,
                p.first_seq.unwrap_or(0),
                p.last_seq.unwrap_or(0),
            )
        })
        .collect();
    println!(
        "{{\"role\":\"sub\",\"first_seen\":{},\"span_s\":{:.3},\"foreign\":{},\"lat_us_p50\":{},\"lat_us_p99\":{},\"lat_us_max\":{},\"rss_kib\":{},\"publishers\":[{}]}}",
        first.is_some(),
        span,
        t.foreign,
        quantile(&t.latency_ns, 0.5) / 1000,
        quantile(&t.latency_ns, 0.99) / 1000,
        t.latency_ns.last().copied().unwrap_or(0) / 1000,
        peak_rss_kib(),
        pubs.join(","),
    );
    drop(t);
    drop(session);
    if first.is_some() {
        0
    } else {
        3
    }
}

fn main() {
    zenoh::init_log_from_env_or("error");
    let args = Args::parse();
    let rc = match args.role.as_str() {
        "pub" => publish(&args),
        "sub" => subscribe(&args),
        other => {
            eprintln!("wz_fanin: --role {other} is neither pub nor sub");
            2
        }
    };
    std::process::exit(rc);
}
