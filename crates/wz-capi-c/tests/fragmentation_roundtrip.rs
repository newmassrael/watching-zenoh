// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! carries NO transport frame longer than the negotiated batch size.
//!
//! The delivery half (every size arrives whole, byte for byte, at the subscriber)
//! is checked as well, so a fragmenter that split correctly and a reassembler that
//! did not rejoin cannot pass.

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
        for &size in SIZES {
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
            longest <= usize::from(BATCH),
            "a transport frame of {longest} bytes left a session whose negotiated batch is \
             {BATCH}: the value was not fragmented (frame lengths {lengths:?})"
        );

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
