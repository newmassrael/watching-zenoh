// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session's batch size is what its configuration document states, read at open, and the
//! frames on its link follow it; zenoh-pico fixes the same number when it is built
//! (`vendor/zenoh-pico/cmake/feature_config.cmake` @
//! `set(BATCH_UNICAST_SIZE 2048 CACHE STRING "Use this to override the maximum unicast batch size")`).
//!
//! Three pairs of sessions are open at once in this one process, each a listening session and a
//! dialling one joined through a relay in this test: one pair states `PICO_UNICAST_BATCH_BYTES`
//! as `SMALL` in the `wz/limits` of both configs' documents, one as `LARGE`, and one states
//! nothing and runs on the build's value. The relay reads the stream link's framing, two
//! little-endian length bytes before each batch, so what is held is the bytes on the wire and
//! not a number a session reports about itself. Each dialling session opens a batching window and
//! puts a burst of small samples, many batches' worth: every batch the relay carries from it,
//! its length bytes counted, is at most the pair's size, the largest is within one message of
//! it, and its InitSyn advertised that size. The two sides take the smaller of their two
//! advertisements, so both sides of a pair state the same document.
//!
//! A document stating a size past the build's ceiling (the domain's largest value: 65535, the
//! two bytes the InitSyn carries it in, or the build's own value in a build that keeps its
//! defaults) is refused by the document door, the reader it judges with names the limit, and a
//! config handed it opens as if it had not been: its InitSyn advertises the build's value.
//!
//! zenoh-pico's half of the comparison, a library built once per size, is
//! `scripts/pico-compare.sh batch`, which measures both on the wire the same way.

#![cfg(all(feature = "config-document", feature = "peer"))]

use std::ffi::{c_void, CStr, CString};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_pico::config_policy::wz_ext_config_document;
use wz_capi_pico::result::Z_ERR_CONFIG_INVALID_VALUE;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber, z_loaned_sample_t,
    z_open, z_owned_bytes_t, z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_put,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    zp_batch_start, zp_batch_stop, zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::caps::PICO_UNICAST_BATCH_BYTES;
use wz_session_core::json5;
use wz_session_core::limit_binding::LimitSpec;
use wz_session_core::limits::{PicoUnicastBatchBytes, SessionLimits};
use wz_session_core::policy::SessionPolicy;
use wz_session_core::policy_document::{self, Reason};

/// The two sizes the documents state: one below pico's default and one above it, so that a
/// size the build fixed would fail one of the two pairs whichever it is.
const SMALL: usize = 512;
const LARGE: usize = 8192;
/// The puts of one burst: a few batches of the largest size, and many of the smallest.
const BURST: usize = 1200;
/// How far below its size the largest batch of a burst may stay: a batch is sent when the next
/// message does not fit, so what is left unused is less than one message, and a message of the
/// burst (a frame's share of a short key and a fifteen-byte payload) is well inside this.
const ONE_MESSAGE_AT_MOST: usize = 128;
/// The bytes a stream link writes before each batch, which the batch size counts.
const LENGTH_BYTES: usize = 2;

const PROBE_KEY: &CStr = c"batch/size/probe";
const BURST_KEY: &CStr = c"batch/size/burst";

/// zenoh's INIT message id, the low five bits of the header.
const MID_INIT: u8 = 0x01;
/// The header's `A` flag: an InitAck, not an InitSyn.
const FLAG_ACK: u8 = 0x20;
/// The header's `S` flag: the resolutions and the batch size follow the zid.
const FLAG_SIZE: u8 = 0x40;
/// The batch size an InitSyn without `S` stands for: zenoh's protocol default.
const PROTOCOL_DEFAULT_BATCH: u16 = 65535;

/// The document whose `wz/limits` states `batch` as the session's batch size.
fn document(batch: usize) -> String {
    format!(r#"{{"wz": {{"limits": {{"PICO_UNICAST_BATCH_BYTES": {batch}}}}}}}"#)
}

/// Whether the build lets a later stage state `batch` as the session's batch size: a build that
/// keeps its defaults alone (`WZ_LIMIT_DOMAINS`) admits only its own value.
fn admits(batch: usize) -> bool {
    let mut limits = SessionLimits::defaults();
    limits.select_pico_unicast_batch_bytes(batch).is_ok()
}

/// The batch size an InitSyn advertises, or `None` for a batch that is not an InitSyn. The
/// layout is zenoh's: a header byte `|Z|S|A| INIT`, the version, a byte whose high nibble is the
/// zid's length less one, the zid, and, when `S` is set, the resolutions and the batch size as two
/// little-endian bytes.
fn init_syn_batch(batch: &[u8]) -> Option<u16> {
    let header = *batch.first()?;
    if header & 0x1F != MID_INIT || header & FLAG_ACK != 0 {
        return None;
    }
    if header & FLAG_SIZE == 0 {
        return Some(PROTOCOL_DEFAULT_BATCH);
    }
    let zid_len = usize::from(*batch.get(2)? >> 4) + 1;
    let at = 3 + zid_len + 1;
    Some(u16::from_le_bytes([*batch.get(at)?, *batch.get(at + 1)?]))
}

/// What the relay saw a dialling session send.
#[derive(Clone, Debug, Default)]
struct Seen {
    /// Each batch's bytes on the wire, its length bytes counted, in the order they were sent.
    batches: Vec<usize>,
    /// The batch size the InitSyn of the last connection advertised.
    advertised: Option<u16>,
}

/// The stream link's framing read back from the bytes as they pass.
struct Framing {
    pending: Vec<u8>,
    first: bool,
}

impl Framing {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            first: true,
        }
    }

    fn feed(&mut self, bytes: &[u8], seen: &mut Seen) {
        self.pending.extend_from_slice(bytes);
        while self.pending.len() >= LENGTH_BYTES {
            let len = usize::from(u16::from_le_bytes([self.pending[0], self.pending[1]]));
            let whole = LENGTH_BYTES + len;
            if self.pending.len() < whole {
                return;
            }
            if self.first {
                self.first = false;
                seen.advertised = init_syn_batch(&self.pending[LENGTH_BYTES..whole]);
            }
            seen.batches.push(whole);
            self.pending.drain(..whole);
        }
    }
}

/// Copies what `from` sends to `to` until either end closes, reading the framing of what it
/// copies into `seen` when it is given one.
fn pump(mut from: TcpStream, mut to: TcpStream, seen: Option<Arc<Mutex<Seen>>>) {
    let mut framing = Framing::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(seen) = &seen {
            framing.feed(&buf[..n], &mut seen.lock().unwrap());
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// A relay on a port of its own that carries each connection to the listening session's port.
struct Relay {
    port: u16,
    seen: Arc<Mutex<Seen>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Relay {
    fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the relay's listener");
        let port = listener.local_addr().expect("the relay's port").port();
        listener
            .set_nonblocking(true)
            .expect("a listener the relay can stop");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let seen = seen.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let dialler = match listener.accept() {
                        Ok((dialler, _)) => dialler,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(_) => break,
                    };
                    let Ok(server) = TcpStream::connect(("127.0.0.1", upstream)) else {
                        continue;
                    };
                    let _ = dialler.set_nonblocking(false);
                    let _ = dialler.set_nodelay(true);
                    let _ = server.set_nodelay(true);
                    let (Ok(dialler_back), Ok(server_back)) =
                        (dialler.try_clone(), server.try_clone())
                    else {
                        continue;
                    };
                    let seen = seen.clone();
                    std::thread::spawn(move || pump(dialler, server, Some(seen)));
                    std::thread::spawn(move || pump(server_back, dialler_back, None));
                }
            })
        };
        Self {
            port,
            seen,
            stop,
            accept: Some(accept),
        }
    }

    fn seen(&self) -> Seen {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

unsafe extern "C" fn count_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn release_counter(ctx: *mut c_void) {
    drop(Arc::from_raw(ctx as *const AtomicUsize));
}

/// A config with `endpoint` under `key`, handed the document that states `stated` when there
/// is one.
unsafe fn config(key: u8, endpoint: &str, stated: Option<usize>) -> z_owned_config_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    let endpoint = CString::new(endpoint).unwrap();
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    if let Some(batch) = stated {
        let text = CString::new(document(batch)).unwrap();
        assert_eq!(
            wz_ext_config_document(z_config_loan_mut(&mut cfg), text.as_ptr()),
            Z_OK,
            "the document door takes a batch size of {batch}"
        );
    }
    cfg
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, text: &CStr) -> ZResult {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        z_bytes_move(&mut payload),
        std::ptr::null(),
    )
}

unsafe fn subscribe(
    session: &z_owned_session_t,
    key: &CStr,
    heard: &Arc<AtomicUsize>,
) -> z_owned_subscriber_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(count_sample),
            Some(release_counter),
            Arc::into_raw(heard.clone()) as *mut c_void,
        ),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    subscriber
}

/// A listening session and a dialling one through a relay, both handed the same document.
struct Pair {
    /// The batch size the documents state, or `None` for configs handed no document.
    stated: Option<usize>,
    listener: z_owned_session_t,
    dialler: z_owned_session_t,
    subscribers: Vec<z_owned_subscriber_t>,
    probes: Arc<AtomicUsize>,
    samples: Arc<AtomicUsize>,
    relay: Relay,
}

impl Pair {
    unsafe fn open(stated: Option<usize>) -> Self {
        let port = free_port();
        let endpoint = format!("tcp/127.0.0.1:{port}");
        let mut listener: z_owned_session_t = std::mem::zeroed();
        let mut cfg = config(Z_CONFIG_LISTEN_KEY, &endpoint, stated);
        assert_eq!(
            z_open(&mut listener, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "the listening session stating {stated:?} opens"
        );
        let probes = Arc::new(AtomicUsize::new(0));
        let samples = Arc::new(AtomicUsize::new(0));
        let subscribers = vec![
            subscribe(&listener, PROBE_KEY, &probes),
            subscribe(&listener, BURST_KEY, &samples),
        ];
        let relay = Relay::start(port);
        let through = format!("tcp/127.0.0.1:{}", relay.port);
        let mut dialler: z_owned_session_t = std::mem::zeroed();
        let mut opened = false;
        for _ in 0..50 {
            let mut cfg = config(Z_CONFIG_CONNECT_KEY, &through, stated);
            if z_open(&mut dialler, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(opened, "the dialling session stating {stated:?} opens");
        Self {
            stated,
            listener,
            dialler,
            subscribers,
            probes,
            samples,
            relay,
        }
    }

    /// The batch size both sides advertise, which is the one they take.
    fn batch(&self) -> usize {
        self.stated.unwrap_or(PICO_UNICAST_BATCH_BYTES)
    }

    /// Puts until the listening session hears one, then a burst inside a batching window, and
    /// waits until every sample of the burst has arrived.
    unsafe fn burst(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.probes.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the pair stating {:?} never carried a put",
                self.stated
            );
            let _ = put(&self.dialler, PROBE_KEY, c"probe");
            std::thread::sleep(Duration::from_millis(25));
        }
        let session = z_session_loan(&self.dialler);
        assert_eq!(zp_batch_start(session), Z_OK);
        for n in 0..BURST {
            let text = CString::new(format!("sample-{n:08}")).unwrap();
            assert_eq!(put(&self.dialler, BURST_KEY, &text), Z_OK);
        }
        assert_eq!(zp_batch_stop(session), Z_OK);
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.samples.load(Ordering::SeqCst) < BURST {
            assert!(
                Instant::now() < deadline,
                "the pair stating {:?} delivered {} of {BURST} samples",
                self.stated,
                self.samples.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The batches the dialling session sent are held to the pair's size.
    fn check(&self) {
        let batch = self.batch();
        let seen = self.relay.seen();
        assert_eq!(
            seen.advertised.map(usize::from),
            Some(batch),
            "the dialling session stating {:?} advertises {batch} in its InitSyn",
            self.stated
        );
        let over: Vec<usize> = seen
            .batches
            .iter()
            .copied()
            .filter(|&bytes| bytes > batch)
            .collect();
        assert!(
            over.is_empty(),
            "the pair stating {:?} sent batches past {batch} bytes: {over:?}",
            self.stated
        );
        let largest = seen.batches.iter().copied().max().unwrap_or(0);
        assert!(
            largest + ONE_MESSAGE_AT_MOST >= batch,
            "the pair stating {:?} sent no batch within one message of {batch} bytes under a \
             burst of {BURST}: its largest was {largest} of {} batches",
            self.stated,
            seen.batches.len()
        );
        eprintln!(
            "batch size {batch} ({}): {} batches, the largest {largest} bytes",
            if self.stated.is_some() {
                "stated"
            } else {
                "the build's"
            },
            seen.batches.len()
        );
    }

    unsafe fn close(mut self) {
        for subscriber in &mut self.subscribers {
            z_undeclare_subscriber(z_subscriber_move(subscriber));
        }
        close(&mut self.dialler);
        close(&mut self.listener);
    }
}

#[test]
fn each_session_frames_its_link_to_the_batch_its_document_states() {
    if !admits(SMALL) || !admits(LARGE) {
        // A build that keeps its defaults refuses both documents at the door, and its sessions
        // run on the build's value; that refusal is what such a build is checked for.
        for batch in [SMALL, LARGE].into_iter().filter(|&batch| !admits(batch)) {
            unsafe {
                let mut cfg: z_owned_config_t = std::mem::zeroed();
                assert_eq!(z_config_default(&mut cfg), Z_OK);
                let text = CString::new(document(batch)).unwrap();
                assert_eq!(
                    wz_ext_config_document(z_config_loan_mut(&mut cfg), text.as_ptr()),
                    Z_ERR_CONFIG_INVALID_VALUE
                );
                wz_capi_pico::z_config_drop(z_config_move(&mut cfg));
            }
        }
        return;
    }
    unsafe {
        // Every pair is open before the first burst, so each size is a session's and not the
        // process's.
        let pairs = [
            Pair::open(Some(SMALL)),
            Pair::open(Some(LARGE)),
            Pair::open(None),
        ];
        for pair in &pairs {
            pair.burst();
        }
        for pair in &pairs {
            pair.check();
        }
        for pair in pairs {
            pair.close();
        }
    }
}

#[test]
fn a_document_stating_a_batch_past_the_builds_ceiling_is_refused_by_name() {
    let (_, ceiling) = PicoUnicastBatchBytes::DOMAIN
        .integers()
        .expect("the batch size is a parameter with whole values");
    let text = document(ceiling + 1);

    // The reader the document door judges with names the limit it refuses.
    let tree = json5::parse(&text).expect("the document is JSON5");
    let refusals = match policy_document::resolve_document(SessionPolicy::from_build(), &tree) {
        Ok(_) => panic!("a batch size of {} past the ceiling is taken", ceiling + 1),
        Err(refusals) => refusals,
    };
    assert!(
        refusals.iter().any(|refusal| matches!(
            refusal.reason,
            Reason::LimitOutsideDomain {
                limit: "PICO_UNICAST_BATCH_BYTES",
                ..
            }
        )),
        "the refusal names the batch size: {refusals}"
    );
    assert!(
        refusals.to_string().contains("PICO_UNICAST_BATCH_BYTES"),
        "{refusals}"
    );

    // The door refuses the document and leaves the config as it was, so the session it opens
    // advertises the build's batch size. The peer is a bare listener that reads the InitSyn and
    // closes, so the open fails and what it sent is the subject.
    let peer = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = peer.local_addr().expect("its port").port();
    let (done_tx, done_rx) = channel();
    let opener = std::thread::spawn(move || unsafe {
        let mut cfg = config(Z_CONFIG_CONNECT_KEY, &format!("tcp/127.0.0.1:{port}"), None);
        let refused = CString::new(text).unwrap();
        assert_eq!(
            wz_ext_config_document(z_config_loan_mut(&mut cfg), refused.as_ptr()),
            Z_ERR_CONFIG_INVALID_VALUE,
            "the document door refuses a batch size past the ceiling"
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
            z_session_drop(z_session_move(&mut session));
        }
        let _ = done_tx.send(());
    });
    let (mut stream, _) = peer.accept().expect("the session dials");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    let mut len = [0u8; LENGTH_BYTES];
    stream
        .read_exact(&mut len)
        .expect("the first batch's length");
    let mut first = vec![0u8; usize::from(u16::from_le_bytes(len))];
    stream.read_exact(&mut first).expect("the first batch");
    drop(stream);
    drop(peer);
    done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the open returns once its peer is gone");
    opener.join().expect("the opener thread");
    assert_eq!(
        init_syn_batch(&first).map(usize::from),
        Some(PICO_UNICAST_BATCH_BYTES),
        "a config whose document was refused opens on the build's batch size: {first:02x?}"
    );
}
