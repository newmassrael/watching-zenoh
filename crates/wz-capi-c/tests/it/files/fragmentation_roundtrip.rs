// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A `z_put` larger than the negotiated batch size leaves as FRAGMENTS, driven
//! through the exported `z_*` symbols exactly as a C program would.
//!
//! # What was measured, and why the gate is on the wire
//!
//! A consumer put a 3027-byte value through this ABI to a device whose InitAck
//! advertised a 1450-byte batch. The value left as ONE batch of 3056 bytes, the
//! process reported `sent` and `Z_OK`, and the device saw nothing; a 4-byte
//! control value went through. Genuine zenoh-c splits the same value into
//! fragments of 1448, 1448 and 152. The cause was a build that never selected
//! `transport-fragmentation` on the runtime, so the frame writer had no fragment
//! path and a frame past the budget "leaves whole" (`session_actions.rs`,
//! `emit_frame_or_fragments`). `wz-capi-pico` had been measured with the same
//! symptom and selects the feature; this crate had not.
//!
//! So the gate is not "the subscriber's closure fired": a drop-in that reassembled
//! only because both ends are this very build would pass with the defect in place
//! if the other end happened to accept an oversize batch. The gate is what a
//! device sees: the TCP stream the dialer writes, read through a recording relay,
//! carries NO batch longer than the negotiated batch size.
//!
//! A batch there is the frame AND its 2-byte length. zenoh and zenoh-pico size
//! the buffer they read a batch into at the negotiated batch size and read the
//! length into it too, which is why genuine zenoh-c's fragments are 1448 bytes
//! against a 1450 batch. This gate once compared the frame alone with the batch
//! size, and so passed a frame of the whole 1450 bytes that the device dropped; a
//! consumer measured that at 2048, on puts just below the fragmenting point. The
//! sizes now include that point.
//!
//! The delivery half (every size arrives whole, byte for byte, at the subscriber)
//! is checked as well, so a fragmenter that split correctly and a reassembler that
//! did not rejoin cannot pass.

#![cfg(feature = "peer")]

use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::{z_bytes_copy_from_buf, z_bytes_to_slice};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::z_sample_payload;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::slice::{z_slice_data, z_slice_drop, z_slice_len, z_slice_loan};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_runtime_tokio_test_support::free_port;

/// The batch size both ends are configured to, standing in for the 1450 a device
/// advertised in its InitAck.
const BATCH: u16 = 1450;
/// The two sizes of the report, and one that needs more than two fragments.
const SIZES: &[usize] = &[3027, 4123, 20_000];
/// The values whose single frame comes within its encoding's few dozen bytes of
/// the batch: the largest frame that leaves whole, and the first values that must
/// fragment, are in this range whatever the key costs.
const AT_THE_BATCH: std::ops::RangeInclusive<usize> = BATCH as usize - 64..=BATCH as usize;
/// The length zenoh writes in front of every batch on a stream link, inside the
/// batch size.
const LENGTH: usize = 2;
const KEYEXPR: &str = "wz/fragmentation/demo";

/// A size-dependent, position-dependent filler: a truncated or reordered delivery
/// cannot pass for a whole one.
fn payload_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

type Delivered = Arc<Mutex<HashMap<usize, Vec<u8>>>>;

struct Ctx {
    delivered: Delivered,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let payload = z_sample_payload(sample);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(payload, &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let (data, len) = (z_slice_data(loaned), z_slice_len(loaned));
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data, len).to_vec();
            ctx.delivered.lock().unwrap().insert(len, bytes);
        }
        z_slice_drop((&mut slice as *mut z_owned_slice_t).cast());
    }
}

unsafe fn open(key: &str, endpoint: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (k, v) in [
        ("scouting/multicast/enabled", "false".to_string()),
        ("transport/link/tx/batch_size", BATCH.to_string()),
        (key, format!("[\"{endpoint}\"]")),
    ] {
        let (k, v) = (CString::new(k).unwrap(), CString::new(v).unwrap());
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null()
        ),
        Z_OK
    );
    session
}

/// A one-connection TCP relay between the dialer and the acceptor that records every
/// byte the DIALER wrote, so the test reads what a device on the far end would see.
struct Relay {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Relay {
    fn start(front: u16, back: u16) -> Relay {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let listener = TcpListener::bind(("127.0.0.1", front)).expect("the relay binds");
        std::thread::spawn(move || {
            let Ok((mut from_dialer, _)) = listener.accept() else {
                return;
            };
            let mut to_acceptor = TcpStream::connect(("127.0.0.1", back)).expect("relay dials");
            let (mut back_reader, mut back_writer) = (
                to_acceptor.try_clone().expect("clone"),
                from_dialer.try_clone().expect("clone"),
            );
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n) = back_reader.read(&mut buf) {
                    if n == 0 || back_writer.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
            let mut buf = [0u8; 8192];
            while let Ok(n) = from_dialer.read(&mut buf) {
                if n == 0 {
                    return;
                }
                record.lock().unwrap().extend_from_slice(&buf[..n]);
                if to_acceptor.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        Relay { seen }
    }
}

/// The lengths of the transport frames in a TCP stream, which zenoh frames with a
/// 2-byte little-endian length prefix.
fn frame_lengths(stream: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut at = 0;
    while at + 2 <= stream.len() {
        let len = u16::from_le_bytes([stream[at], stream[at + 1]]) as usize;
        if at + 2 + len > stream.len() {
            break;
        }
        lengths.push(len);
        at += 2 + len;
    }
    lengths
}

#[test]
fn a_put_past_the_negotiated_batch_leaves_as_fragments_and_arrives_whole() {
    let (acceptor_port, relay_port) = (free_port(), free_port());
    let delivered: Delivered = Arc::new(Mutex::new(HashMap::new()));
    let relay = Relay::start(relay_port, acceptor_port);

    unsafe {
        let acceptor = open(
            "listen/endpoints",
            &format!("tcp/127.0.0.1:{acceptor_port}"),
        );
        let ctx = Box::into_raw(Box::new(Ctx {
            delivered: delivered.clone(),
        })) as *mut c_void;
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&acceptor),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let dialer = open("connect/endpoints", &format!("tcp/127.0.0.1:{relay_port}"));
        let put = |size: usize| {
            let data = payload_of(size);
            let mut payload: z_owned_bytes_t = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut payload, data.as_ptr(), data.len()),
                Z_OK
            );
            let mut opts: z_put_options_t = std::mem::zeroed();
            z_put_options_default(&mut opts);
            z_put(
                z_session_loan(&dialer),
                z_view_keyexpr_loan(&view),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                &mut opts,
            )
        };

        // Each size is republished until the subscriber reports it, bounded, so the
        // time the subscription takes to propagate retries and a loss fails.
        for size in SIZES.iter().copied().chain(AT_THE_BATCH) {
            let want = payload_of(size);
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                assert_eq!(put(size), Z_OK, "the put of {size} bytes was refused");
                std::thread::sleep(Duration::from_millis(100));
                if delivered.lock().unwrap().get(&size) == Some(&want) {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "{size} bytes never arrived whole at the subscriber"
                );
            }
        }

        let wire = relay.seen.lock().unwrap().clone();
        let lengths = frame_lengths(&wire);
        let longest = lengths.iter().copied().max().unwrap_or(0);
        assert!(
            lengths.len() > SIZES.len(),
            "the dialer wrote only {} frame(s) for {} oversize puts",
            lengths.len(),
            SIZES.len()
        );
        assert!(
            longest + LENGTH <= usize::from(BATCH),
            "a transport frame of {longest} bytes, {} with its {LENGTH}-byte length, left a \
             session whose negotiated batch is {BATCH}: the value was not fragmented to fit \
             (frame lengths {lengths:?})",
            longest + LENGTH
        );

        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(acceptor);
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}

/// Chains of many fragments, up to the largest message a session sends, arrive
/// whole: the receiver rejoins what the sender let through.
///
/// 1044480 was the boundary case while the sender refused a chain past the AP
/// reassembly slot (1 MiB): it sat 4 KiB under the slot, in the band a sender and
/// a receiver that measured different things would have disagreed on. 4000000 is
/// the fan-in lane's camera sample (Round 4617), which the slot made every wz
/// receiver drop and every wz sender refuse; with the slot no longer a message's
/// bound it must arrive like the rest. The receiver is this ABI's because it
/// rejoins up to zenoh's `transport/link/rx/max_message_size` default (1 GiB);
/// zenoh-pico's ABI rejoins no message past pico's `FRAG_MAX_SIZE`, as pico, and
/// its own test holds that.
#[test]
fn a_chain_up_to_the_largest_message_sent_arrives_whole() {
    const LONG: &[usize] = &[131_072, 262_144, 1_044_480, 4_000_000];
    let port = free_port();
    let delivered: Delivered = Arc::new(Mutex::new(HashMap::new()));
    unsafe {
        let acceptor = open("listen/endpoints", &format!("tcp/127.0.0.1:{port}"));
        let ctx = Box::into_raw(Box::new(Ctx {
            delivered: delivered.clone(),
        })) as *mut c_void;
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&acceptor),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let dialer = open("connect/endpoints", &format!("tcp/127.0.0.1:{port}"));
        for &size in LONG {
            let want = payload_of(size);
            let until = Instant::now() + Duration::from_secs(30);
            loop {
                let mut payload: z_owned_bytes_t = std::mem::zeroed();
                assert_eq!(
                    z_bytes_copy_from_buf(&mut payload, want.as_ptr(), want.len()),
                    Z_OK
                );
                let mut opts: z_put_options_t = std::mem::zeroed();
                z_put_options_default(&mut opts);
                assert_eq!(
                    z_put(
                        z_session_loan(&dialer),
                        z_view_keyexpr_loan(&view),
                        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                        &mut opts,
                    ),
                    Z_OK,
                    "the put of {size} bytes was refused"
                );
                std::thread::sleep(Duration::from_millis(200));
                if delivered.lock().unwrap().get(&size) == Some(&want) {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "{size} bytes never arrived whole at the subscriber"
                );
            }
        }
        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(acceptor);
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}

/// The sequence numbers of the reliable Frame and Fragment batches in a stream the
/// dialer wrote, in order. A transport batch opens with its message header: Frame
/// is `0x05` and Fragment `0x06`, each with the R flag (`0x20`) for the reliable
/// channel, then the sequence number as a variable-length integer.
fn reliable_sequence_numbers(stream: &[u8]) -> Vec<u64> {
    batches(stream)
        .into_iter()
        .filter_map(|(_, _, sn)| sn)
        .collect()
}

/// Whether the extension chain at the head of `exts` holds a QoS extension (id 1).
/// Each extension is a header byte (id in the low nibble, encoding in bits 5-6,
/// another follows when bit 7 is set) and a body: none for a unit, a varint for a
/// Z64, a varint length and that many bytes for a ZBuf.
fn carries_qos(exts: &[u8]) -> bool {
    let varint = |at: &mut usize| -> u64 {
        let (mut value, mut shift) = (0u64, 0);
        while let Some(&byte) = exts.get(*at) {
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        value
    };
    let mut at = 0;
    while let Some(&head) = exts.get(at) {
        at += 1;
        if head & 0x0f == 0x01 {
            return true;
        }
        match (head >> 5) & 0x03 {
            0 => {}
            1 => {
                varint(&mut at);
            }
            _ => {
                let len = varint(&mut at) as usize;
                at += len;
            }
        }
        if head & 0x80 == 0 {
            break;
        }
    }
    false
}

/// Every transport batch of the stream as `(header byte, length, reliable SN)`, so a
/// failure shows the whole writing and not only the numbers it judged.
fn batches(stream: &[u8]) -> Vec<(u8, usize, Option<u64>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 2 <= stream.len() {
        let len = u16::from_le_bytes([stream[at], stream[at + 1]]) as usize;
        if at + 2 + len > stream.len() {
            break;
        }
        let batch = &stream[at + 2..at + 2 + len];
        at += 2 + len;
        let Some(&header) = batch.first() else {
            continue;
        };
        let mut reliable_sn = None;
        if matches!(header & 0x1f, 0x05 | 0x06) && header & 0x20 != 0 {
            let (mut sn, mut shift, mut at) = (0u64, 0, 1);
            while let Some(&byte) = batch.get(at) {
                at += 1;
                sn |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            // A batch whose extensions carry a QoS one (id 1) rides another
            // priority's conduit, which counts from its own start (the
            // declarations, here). Only a batch without one is a value's, on the
            // default priority conduit this test judges: a fragment's chain
            // markers (`0x2 First`, `0x3 Drop`) are extensions too, and the first
            // fragment of every chain carries one.
            if header & 0x80 == 0 || !carries_qos(&batch[at..]) {
                reliable_sn = Some(sn);
            }
        }
        out.push((header, len, reliable_sn));
    }
    out
}

/// A value past the AP reassembly slot is sent and arrives whole, the door says the
/// session refuses no message for its size, and the long chain leaves no hole in
/// the reliable sequence.
///
/// Until the fan-in lane measured it (Round 4617) the slot, 1 MiB, was the
/// sender's bound, and this value was refused with `WZ_CAPI_C_E_VALUE_TOO_LARGE`
/// while every peer configured as upstream would have taken it. The bound is gone,
/// as upstream's sender has none. What a refusal must not do to the sequence
/// (MEASURED on a device: after a 1 MiB value was refused, the next value's frame
/// went out one sequence number ahead and the device closed the session) is held
/// where a refusal can still be made, the session's own
/// (`layer3_reassembly_tx`, a send past a declared bound). Here the wire is the
/// gate for the chain: every reliable frame and fragment the dialer writes carries
/// the number after the one before it, across the value that used to be refused.
#[test]
fn a_value_past_the_old_slot_arrives_whole_and_leaves_no_hole() {
    use wz_capi_c::limits::wz_capi_c_session_max_message_bytes;

    let (acceptor_port, relay_port) = (free_port(), free_port());
    let delivered: Delivered = Arc::new(Mutex::new(HashMap::new()));
    let relay = Relay::start(relay_port, acceptor_port);
    // The values are told apart by their length; the long one is past the old
    // 1 MiB cap whatever the key adds.
    const BEFORE: usize = 4;
    const AFTER: usize = 5;
    let long = 1_048_576 + 1024;

    unsafe {
        let acceptor = open(
            "listen/endpoints",
            &format!("tcp/127.0.0.1:{acceptor_port}"),
        );
        let ctx = Box::into_raw(Box::new(Ctx {
            delivered: delivered.clone(),
        })) as *mut c_void;
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&acceptor),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let dialer = open("connect/endpoints", &format!("tcp/127.0.0.1:{relay_port}"));
        let put = |size: usize| {
            let data = payload_of(size);
            let mut payload: z_owned_bytes_t = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_buf(&mut payload, data.as_ptr(), data.len()),
                Z_OK
            );
            let mut opts: z_put_options_t = std::mem::zeroed();
            z_put_options_default(&mut opts);
            z_put(
                z_session_loan(&dialer),
                z_view_keyexpr_loan(&view),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                &mut opts,
            )
        };
        let arrive = |size: usize| {
            let want = payload_of(size);
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                assert_eq!(put(size), Z_OK, "the put of {size} bytes was refused");
                std::thread::sleep(Duration::from_millis(100));
                if delivered.lock().unwrap().get(&size) == Some(&want) {
                    return;
                }
                assert!(Instant::now() < until, "{size} bytes never arrived");
            }
        };

        // The door says the limit, and says it for a session that is open only.
        let mut cap = 0usize;
        assert_eq!(
            wz_capi_c_session_max_message_bytes(z_session_loan(&dialer), &mut cap),
            Z_OK
        );
        assert_eq!(
            cap,
            usize::MAX,
            "the session refuses no message for its size"
        );

        arrive(BEFORE);
        arrive(long);
        arrive(AFTER);

        let wire = relay.seen.lock().unwrap().clone();
        let sns = reliable_sequence_numbers(&wire);
        assert!(
            sns.len() >= 2,
            "the dialer wrote {} reliable frame(s) around the refusal",
            sns.len()
        );
        for pair in sns.windows(2) {
            assert_eq!(
                pair[1].wrapping_sub(pair[0]) & 0xffff_ffff,
                1,
                "a reliable frame skipped a sequence number across the long value: {sns:?}; the \
                 peer closes the session at the hole. Every batch the dialer wrote, as \
                 (header, length, reliable SN): {:?}",
                batches(&wire)
            );
        }

        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(acceptor);
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}
