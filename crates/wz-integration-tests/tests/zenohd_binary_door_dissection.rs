// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2221 (open-debt item 569) — the BINARY DOOR against a genuine `zenohd`:
//! the `wz_dissect_live_*` C ABI driven over bytes a real router wrote, and
//! graded on the NUMBERS its fixed-layout records carry.
//!
//! ## The gap, stated as the consuming surface stated it
//!
//! Every dissection witness in this tree reads `wz_capture::Dissection`. A
//! framework that LINKS this library reads [`WzDissectRecord`] — the
//! fixed-layout struct one level above it — and nothing in
//! `crates/wz-integration-tests/` had ever touched that door: `grep -rlE
//! 'wz_dissect_live|wz-capi-dissect'` over this directory read ZERO, and this
//! crate's `Cargo.toml` carried `wz-capi-pico` and not `wz-capi-dissect`.
//!
//! Four candidate reasons for that omission were measured and none holds:
//! the crate has an `rlib`; its 23 `#[no_mangle]` exports are all
//! `wz_dissect_*` with zero `z_*`, so the symbol collision that deliberately
//! keeps `wz-capi-c` out does not reach it; its dependencies point at
//! `wz-capture` / `wz-session-core` and cannot cycle; and three sibling crates
//! already depend on it. Nor is there PROSE recording a decision — the first
//! move of the round that wrote this file was to sweep for one, and the only
//! exclusion note in this crate's manifest is `wz-capi-c`'s, whose stated
//! reason is the zenoh-pico symbols. So: an omission, not a design.
//!
//! ## Why EXISTENCE is not the grade, and this file's sibling says so
//!
//! `zenohd_wire_dissection.rs` records its own limit in one line —
//! "Existence is asserted, never an offset" — and existence is exactly the
//! grade that cannot fail here. A door that reported a plausible-looking wrong
//! offset still produces records, and every count still moves with the
//! handshake. The consuming surface's list stands on `offset`, `length` and
//! `time`, so those three are what this file grades, SEPARATELY, so the weak
//! one cannot pass behind the strong one.
//!
//! ## The oracle is the BYTES, not a second decoder
//!
//! Comparing the C door against `wz_capture::Dissection` would prove the two
//! AGREE. They are the same engine, so agreement is cheap and proves nothing
//! about correctness — the same reason the consuming surface's own fixture
//! comparison could not close this: the fixture's maker is our `wz-ap-demo`,
//! so encoder and decoder are one tree.
//!
//! The oracle here is the recorded byte stream itself, re-derived from the tap
//! without any decoder:
//!
//! * `anchor` names the framing unit's LENGTH PREFIX in that direction's
//!   stream (`wz-capi-dissect/src/live.rs`, `message_bytes`' own docs), so the
//!   two bytes at `anchor` ARE the wire's declaration of the unit's length.
//!   Reading them back and comparing to `unit_len` grades the LENGTH axis
//!   against the wire and not against us.
//! * the message's header byte then sits at `anchor + prefix + unit_offset`,
//!   and its low five bits are the transport MID. Comparing that MID to the
//!   record's `kind` grades the OFFSET axis: a record whose offset is wrong
//!   points at a byte that is not a message header.
//! * `ts_ns` must be the pushed nanosecond truncated to its millisecond, and
//!   this leg pushes a DISTINCT millisecond per packet with a deliberate
//!   sub-millisecond remainder, so both halves of that rule are graded.
//!
//! ## The control that makes those three assertions non-vacuous
//!
//! Each axis is re-run against a DELIBERATELY SHIFTED copy of the same records
//! — every `unit_offset`, then every `unit_len`, then every `anchor`, moved by
//! one — and the oracle must REJECT each. That is the leg demonstrating, in
//! the leg, that a door reporting numbers one byte off does not pass it. An
//! assertion that cannot be made to fail is not evidence, and offsets are
//! numbers: they always look plausible.
//!
//! ## And the damage sweep, judged by THIS door
//!
//! `sweep_single_byte_damage` in the shared harness classifies through
//! `wz_capture::Dissection`. That is the other door. So the sweep here is the
//! same idea pointed at this one: every byte of the ROUTER's half is flipped
//! in turn, the C door is re-driven over the damaged capture, and the leg
//! asserts (a) that the numbers MOVE — a flipped length prefix changes the
//! `unit_len` the door reports, which is what says that field is read from the
//! bytes rather than invented — and (b) that over every damaged input the
//! door's records still satisfy the byte oracle. The second is the strong one:
//! it is the offset/length contract held against hundreds of inputs nobody
//! chose.
//!
//! ## MEASURED — three mutations of the DOOR, and which test each reddens
//!
//! Applied to `wz-capi-dissect/src/live.rs`'s `record_of`, run against a real
//! zenohd, and reverted. Listed because an assertion nobody has made fail is
//! not evidence, and because the split is what says the three axes are graded
//! SEPARATELY:
//!
//! | mutation | red |
//! |---|---|
//! | `unit_offset + 1` | the offset test, at `MID 0x09 (kind None) vs kind 1` — and the sweep, on all 166 damaged inputs |
//! | `unit_len + 1` | the same two, at `the prefix at anchor 0 declares 12 and the door reports unit_len 13` |
//! | `ts_ns + 1` | the TIME test ALONE, at "not a whole millisecond". The offset test and the sweep stay green |
//!
//! The first two leave the time test green and the third leaves the other two
//! green, so no axis is passing behind another.
//!
//! ## Stock and synthesised
//!
//! STOCK: every byte above TCP, both directions, the acceptor half written by
//! stock zenohd. SYNTHESISED: the Ethernet / IPv4 / TCP envelope, because a
//! userspace relay cannot see headers the kernel wrote. The envelope comes
//! from `wire_tap::synthesise_packets`, the same function `synthesise_pcap`
//! builds on, so this witness and the pcap ones cannot disagree about what the
//! wire looked like.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd is an external binary. The
//! test names carry `zenohd` because Layer E's skip filter is a name substring.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_capi_dissect::live::{KIND_UNDECODABLE, NO_TIMESTAMP};
use wz_capi_dissect::{
    wz_dissect_live_close, wz_dissect_live_drain, wz_dissect_live_lost, wz_dissect_live_open,
    wz_dissect_live_push, WzDissectRecord, WZ_DISSECT_LIMITS_NONE, WZ_DISSECT_OK,
};
use wz_capture::link::LINKTYPE_ETHERNET;
use wz_codecs::wire_const::{
    T_MID_CLOSE, T_MID_FRAGMENT, T_MID_FRAME, T_MID_INIT, T_MID_JOIN, T_MID_KEEP_ALIVE, T_MID_OAM,
    T_MID_OPEN,
};
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, spawn_publishing_zpub, spawn_zenohd_on_ephemeral_tcp,
    wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_integration_tests::wire_tap::{synthesise_packets, tap_proxy, Side};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
/// What WZ publishes into the router — the dialer half's record layer.
const PUBLISH_KEYEXPR: &str = "demo/binary-door";
/// What PICO publishes into the router, and what wz subscribes to. This is what
/// puts a RECORD layer on the ROUTER's half of the capture: without it a stock
/// zenohd sends an idle face nothing past `[Init, Open]`, and the genuine half
/// this leg exists to grade would be the handshake alone (the finding
/// `zenohd_wire_dissection.rs` records as its own R311y764 correction).
const PICO_KEYEXPR: &str = "demo/binary-door-from-pico";
const SUB_KEYEXPR: &str = "demo/**";
/// The value pico's `z_pub` example publishes, prefixed by its own `"[%4d] "`
/// counter (`vendor/zenoh-pico/examples/unix/c11/z_pub.c:98`).
const PICO_VALUE: &str = "binary-door-from-pico-value";
/// The synthesised endpoints. They are NOT the real ones (the real dialer port
/// is ephemeral and the proxy sits between). Which half `Direction::A` names is
/// DERIVED from them below rather than written down — `FlowKey` orders its
/// endpoints by `(addr, port)` and both addresses are 127.0.0.1, so these two
/// numbers decide it (the R311y761 correction).
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;
/// The 5-bit transport-message-id field of a zenoh transport header.
const TRANSPORT_MID_MASK: u8 = 0x1F;
/// The universal stream framing prefix. Not a guess: the length assertion below
/// reads the prefix AT `anchor` and compares it to the door's own `unit_len`,
/// so a stream framed some other way reds there rather than being assumed away.
const PREFIX_WIDTH: usize = 2;
/// Nanoseconds per millisecond — the reader's clock resolution.
const MS: u64 = 1_000_000;
/// The sub-millisecond remainder every push carries, so the truncation half of
/// the timestamp rule is graded and not merely satisfied by round numbers.
const SUB_MS_REMAINDER: u64 = 123_456;
/// Where the pushed clock starts. Arbitrary, and deliberately not zero: zero is
/// a legal instant and would not tell a real reading from an unset one.
const BASE_MS: u64 = 1_700_000_000_000;

/// One captured session, plus everything needed to grade a door over it.
struct Capture {
    /// The tap's recording, in forwarding order.
    recording: Vec<(Side, Vec<u8>)>,
}

/// `kind_code` for a transport MID, or `None` for a MID this mapping does not
/// name.
///
/// EXPLICIT and not `mid as u8`, because the two numbering schemes are NOT the
/// same function: `InboundFrame::kind_code` gives `Oam` the code 8 while its
/// wire MID is `T_MID_OAM = 0x00` (`wz-codecs/src/lib.rs:528`), and every other
/// pair happens to coincide. A leg that assumed the identity would grade OAM
/// wrongly and only ever find out on a capture that carried one.
fn kind_of_mid(mid: u8) -> Option<u8> {
    match mid {
        T_MID_INIT => Some(1),
        T_MID_OPEN => Some(2),
        T_MID_CLOSE => Some(3),
        T_MID_KEEP_ALIVE => Some(4),
        T_MID_FRAME => Some(5),
        T_MID_FRAGMENT => Some(6),
        T_MID_JOIN => Some(7),
        T_MID_OAM => Some(8),
        _ => None,
    }
}

/// Which `WzDissectRecord::direction` code the DIALER's half carries.
///
/// Derived from the two synthesised ports rather than written down: `A` is the
/// half whose segments arrive from the LESSER endpoint by `(addr, port)`, and
/// with one address the ports decide it.
fn dialer_direction_code() -> u8 {
    if DIALER_PORT < LISTENER_PORT {
        0
    } else {
        1
    }
}

/// Reassemble one direction's byte stream from the recording — the ORACLE.
///
/// This is the whole point of the file: a byte sequence built by concatenation,
/// with no decoder anywhere in it. The synthesised TCP sequence numbers start
/// at 1 and advance by each segment's length, so a direction's stream offsets
/// are exactly the concatenation offsets.
fn stream_of(recording: &[(Side, Vec<u8>)], side: Side) -> Vec<u8> {
    let mut out = Vec::new();
    for (s, bytes) in recording {
        if *s == side {
            out.extend_from_slice(bytes);
        }
    }
    out
}

/// The stream a record's `direction` names.
fn stream_for(recording: &[(Side, Vec<u8>)], direction: u8) -> Vec<u8> {
    let side = if direction == dialer_direction_code() {
        Side::FromDialer
    } else {
        Side::FromListener
    };
    stream_of(recording, side)
}

/// The nanosecond reading pushed with packet `index`.
fn pushed_ts_ns(index: usize) -> u64 {
    (BASE_MS + index as u64) * MS + SUB_MS_REMAINDER
}

/// Drive the C door over one capture and return what it handed back.
///
/// Everything crossing the boundary is exactly what a linking framework does:
/// open, push each packet with its own clock reading, drain into a buffer this
/// caller sized, close.
fn drive_binary_door(recording: &[(Side, Vec<u8>)]) -> (Vec<WzDissectRecord>, u64) {
    let packets = synthesise_packets(recording, DIALER_PORT, LISTENER_PORT);
    let mut handle: *mut wz_capi_dissect::live::LiveDissection = std::ptr::null_mut();
    // SAFETY: `handle` is a writable local.
    let rc = unsafe { wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &mut handle) };
    assert_eq!(rc, WZ_DISSECT_OK, "wz_dissect_live_open refused");
    assert!(!handle.is_null(), "wz_dissect_live_open returned null");

    let mut records: Vec<WzDissectRecord> = Vec::new();
    for (index, (_, _, bytes)) in packets.iter().enumerate() {
        // SAFETY: live handle, and `bytes` is a live slice of `len` bytes.
        let rc = unsafe {
            wz_dissect_live_push(
                handle,
                LINKTYPE_ETHERNET,
                pushed_ts_ns(index),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        assert_eq!(
            rc, WZ_DISSECT_OK,
            "wz_dissect_live_push refused packet {index}"
        );
        drain_into(handle, &mut records);
    }
    // SAFETY: live handle.
    let lost = unsafe { wz_dissect_live_lost(handle) };
    // SAFETY: opened above, closed exactly once.
    unsafe { wz_dissect_live_close(handle) };
    (records, lost)
}

/// Drain until the door returns a short count, appending as we go — the loop
/// the ABI's own docs prescribe.
fn drain_into(handle: *mut wz_capi_dissect::live::LiveDissection, out: &mut Vec<WzDissectRecord>) {
    const CAP: usize = 16;
    loop {
        let mut buf = [WzDissectRecord {
            ts_ns: 0,
            flow_id: 0,
            list_id: 0,
            anchor: 0,
            unit_len: 0,
            batch_index: 0,
            unit_offset: 0,
            direction: 0,
            anchor_space: 0,
            origin: 0,
            kind: 0,
            flags: 0,
        }; CAP];
        let mut written: usize = 0;
        // SAFETY: live handle, `buf` holds CAP records, `written` is writable.
        let rc = unsafe { wz_dissect_live_drain(handle, buf.as_mut_ptr(), CAP, &mut written) };
        assert_eq!(rc, WZ_DISSECT_OK, "wz_dissect_live_drain refused");
        out.extend_from_slice(&buf[..written]);
        if written < CAP {
            return;
        }
    }
}

/// Grade every record's OFFSET and LENGTH against the raw bytes.
///
/// `Err` on the first violation, with the record named. Returned rather than
/// asserted so the SHIFTED controls can require it to fail — an oracle that
/// could only panic could not be shown to discriminate.
fn grade_against_bytes(
    records: &[WzDissectRecord],
    recording: &[(Side, Vec<u8>)],
) -> Result<usize, String> {
    if records.is_empty() {
        return Err("no records at all — a population of zero grades nothing".to_string());
    }
    let mut named = 0usize;
    for (i, rec) in records.iter().enumerate() {
        let stream = stream_for(recording, rec.direction);
        let anchor = rec.anchor as usize;
        // LENGTH — the wire's own declaration, at the offset the door reported.
        if anchor + PREFIX_WIDTH > stream.len() {
            return Err(format!(
                "record {i}: anchor {anchor} leaves no room for a length prefix \
                 in a {}-byte stream",
                stream.len()
            ));
        }
        let declared = u64::from(u16::from_le_bytes([stream[anchor], stream[anchor + 1]]));
        if declared != rec.unit_len {
            return Err(format!(
                "record {i}: the prefix at anchor {anchor} declares {declared} \
                 and the door reports unit_len {}",
                rec.unit_len
            ));
        }
        // OFFSET — containment first, so an out-of-range read is a NAMED
        // failure rather than a panic.
        let unit_body = anchor + PREFIX_WIDTH;
        let at = unit_body + rec.unit_offset as usize;
        if rec.unit_offset as u64 >= rec.unit_len || at >= stream.len() {
            return Err(format!(
                "record {i}: unit_offset {} is not inside a {}-byte unit at \
                 anchor {anchor}",
                rec.unit_offset, rec.unit_len
            ));
        }
        // OFFSET — the byte there must be a transport message header whose MID
        // is the kind the door reported. `KIND_UNDECODABLE` and `Unknown` name
        // no MID, so they are counted and not graded here.
        if rec.kind != KIND_UNDECODABLE && rec.kind != 255 {
            let mid = stream[at] & TRANSPORT_MID_MASK;
            match kind_of_mid(mid) {
                Some(kind) if kind == rec.kind => named += 1,
                other => {
                    return Err(format!(
                        "record {i}: the byte at anchor {anchor} + {PREFIX_WIDTH} + \
                         offset {} has MID 0x{mid:02X} (kind {other:?}), but the \
                         door reports kind {}",
                        rec.unit_offset, rec.kind
                    ));
                }
            }
        }
    }
    Ok(named)
}

/// Capture one genuine zenohd session through the tap.
async fn capture_zenohd_session() -> Capture {
    // The demo is not the subject here — this leg opens its own in-process
    // session — but `spawn_zenohd_on_ephemeral_tcp` spawns it as the
    // handshake-readiness probe, and a stale one makes that probe fail to
    // detect a router that IS ready. Asserted rather than exempted, for the
    // reason R2200 recorded: repaying is the right side of that fork.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let (proxy_port, recording) = tap_proxy(zenohd_port);

    let params = zenohd_interop_session_init_params();
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("wz dials the tap proxy");
    let opened = initiate_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let mut opened = match opened {
        Ok(opened) => opened,
        Err(e) => {
            let _ = zenohd.child_mut().kill();
            let _ = zenohd.child_mut().wait();
            panic!("wz did not reach Established against zenohd through the tap: {e:?}");
        }
    };

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    // Bound to a named `_subscriber` (NOT `_`) so the RAII handle stays alive
    // through the drive; a `_`-drop emits `Declare(UndeclSubscriber)` and
    // withdraws the route from zenohd before pico publishes.
    let deliveries = Arc::new(AtomicUsize::new(0));
    let _subscriber = {
        let deliveries = Arc::clone(&deliveries);
        session
            .declare_subscriber(SUB_KEYEXPR, SubscribeOptions::default(), move |_sample| {
                deliveries.fetch_add(1, Ordering::SeqCst);
            })
            .expect("wz declares the routed subscriber (emits Declare(DeclSubscriber))")
    };

    let timeouts = SessionTimeouts::spec_defaults();
    let drive = {
        let session_drive = session.clone();
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| session_drive.dispatch_iteration_event(event),
        )
    };

    let z_pub = zenoh_pico_cli_binary("z_pub");
    let endpoint = format!("tcp/127.0.0.1:{zenohd_port}");
    let scenario = async {
        // pico is spawned only AFTER wz's routed subscriber has been declared,
        // so zenohd installs the route first. The spawn helper BLOCKS until the
        // child prints "Putting Data", so it runs on a blocking thread: holding
        // the async executor there would stall the drive loop above.
        let _z_pub_child = tokio::task::spawn_blocking(move || {
            spawn_publishing_zpub(
                &z_pub,
                PICO_KEYEXPR,
                PICO_VALUE,
                &endpoint,
                "zenohd",
                || tempfile::tempfile().expect("tempfile for z_pub stdout"),
            )
        })
        .await
        .expect("z_pub spawn task");

        // wz publishes on its own cadence so the DIALER half carries a record
        // layer too, and waits for at least one routed Sample so the ROUTER
        // half does. Both halves matter: the leg asserts a record from each.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            session
                .publish(
                    PUBLISH_KEYEXPR,
                    b"binary-door-payload",
                    PublishOptions::put(),
                )
                .expect("publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(120)).await;
            if deliveries.load(Ordering::SeqCst) >= 2 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "zenohd routed {} Sample(s) to wz's subscriber within 20s; \
                     the ROUTER half of this capture would be the handshake \
                     alone and the leg would grade the wrong thing",
                    deliveries.load(Ordering::SeqCst)
                ));
            }
        }
    };
    let routed = tokio::select! {
        _ = drive => Err("wz drive loop reached a terminal state during capture".to_string()),
        r = scenario => r,
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    routed.unwrap_or_else(|e| panic!("{e}"));

    let recording = recording.lock().expect("recording lock").clone();
    assert!(
        recording.iter().any(|(s, _)| *s == Side::FromDialer)
            && recording.iter().any(|(s, _)| *s == Side::FromListener),
        "the tap never saw both directions — the dial bypassed the proxy, and \
         nothing below would be about a genuine router's bytes"
    );
    Capture { recording }
}

/// Every byte position, in the ROUTER half's stream, that is part of a framing
/// unit's LENGTH PREFIX — derived by walking that stream's own framing, not
/// listed.
///
/// This is the sweep population for the length claim. A prefix byte is the one
/// place a flip must move what the door reports about lengths, so requiring
/// EVERY one of them to change the door's output is a sharper claim than "some
/// flip somewhere moved something" — and one whose population cannot silently
/// be empty, because the walk fails loudly if the stream is not framed.
fn prefix_byte_positions(stream: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + PREFIX_WIDTH <= stream.len() {
        let len = usize::from(u16::from_le_bytes([stream[at], stream[at + 1]]));
        if at + PREFIX_WIDTH + len > stream.len() {
            // A trailing partial unit: the capture ended mid-frame. Its prefix
            // is still on the wire, so it still counts.
            out.push(at);
            out.push(at + 1);
            break;
        }
        out.push(at);
        out.push(at + 1);
        at += PREFIX_WIDTH + len;
    }
    out
}

/// Map a byte position in one side's concatenated stream back to
/// `(segment index, byte index)` in the recording.
fn locate(recording: &[(Side, Vec<u8>)], side: Side, position: usize) -> Option<(usize, usize)> {
    let mut seen = 0usize;
    for (i, (s, bytes)) in recording.iter().enumerate() {
        if *s != side {
            continue;
        }
        if position < seen + bytes.len() {
            return Some((i, position - seen));
        }
        seen += bytes.len();
    }
    None
}

// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-frame zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn the_binary_door_reports_offsets_a_genuine_zenohd_capture_confirms() {
    let capture = capture_zenohd_session().await;
    let (records, lost) = drive_binary_door(&capture.recording);

    // The population, before anything is claimed over it.
    assert!(
        records.len() >= 4,
        "the door drained only {} record(s) from a genuine handshake plus \
         publications; there is nothing to grade",
        records.len()
    );
    assert_eq!(
        lost, 0,
        "the door DISCARDED {lost} decoded message(s) before they were drained, \
         so the graded set is a floor and not the total"
    );

    // Both halves of the conversation reached the door. Without this the leg
    // could grade the router's half alone, or wz's, and report on the wire.
    let dialer = dialer_direction_code();
    assert!(
        records.iter().any(|r| r.direction == dialer),
        "no record came from wz's half of the wire"
    );
    assert!(
        records.iter().any(|r| r.direction != dialer),
        "no record came from the ROUTER's half — the genuineness of this leg is \
         exactly that half"
    );

    // Every record is in the coordinate space this oracle can read. An anchor
    // that were a packet INDEX would still be a small plausible number, which
    // is why the record carries the space and why it is checked and not assumed.
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(
            rec.anchor_space, 1,
            "record {i}: anchor is not a byte offset, so the byte oracle below \
             would be reading the stream at a packet index"
        );
        assert_eq!(
            rec.origin, 1,
            "record {i}: not a Stream-origin record; this leg taps TCP"
        );
    }

    // THE OFFSET + LENGTH GRADE, against the recorded bytes.
    let named = grade_against_bytes(&records, &capture.recording)
        .unwrap_or_else(|e| panic!("the door's coordinates do not match the wire: {e}"));
    assert!(
        named > 0,
        "every drained record was UNDECODABLE or Unknown, so the offset grade \
         ran over nothing"
    );

    // THE CONTROLS. Each moves one field of every record by one byte, and the
    // oracle must REJECT the result. A door reporting numbers one byte off
    // would produce exactly these sets, and a grade that accepted them would be
    // measuring nothing.
    for (what, shifted) in [
        ("unit_offset", shift(&records, |r| r.unit_offset += 1)),
        ("unit_len", shift(&records, |r| r.unit_len += 1)),
        ("anchor", shift(&records, |r| r.anchor += 1)),
    ] {
        assert!(
            grade_against_bytes(&shifted, &capture.recording).is_err(),
            "the oracle ACCEPTED a record set whose {what} is one byte off. It \
             cannot then be evidence that the door's {what} is right."
        );
    }
}

/// Copy the records with one field moved. The controls' only tool.
fn shift(records: &[WzDissectRecord], f: impl Fn(&mut WzDissectRecord)) -> Vec<WzDissectRecord> {
    let mut out = records.to_vec();
    for r in &mut out {
        f(r);
    }
    out
}

// wz-proves: none -- the TIME axis of the door, graded against the clock this
// leg supplied rather than against a foreign implementation. The bytes are
// zenohd's, but the timestamps are the harness's, so nothing about a foreign
// impl is witnessed here and claiming an atom would over-report.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn the_zenohd_binary_door_reports_the_millisecond_a_push_fell_in() {
    let capture = capture_zenohd_session().await;
    let (records, _) = drive_binary_door(&capture.recording);
    assert!(!records.is_empty(), "no records to grade");

    let packets = capture.recording.len();
    let first = BASE_MS * MS;
    let last = (BASE_MS + packets as u64 - 1) * MS;

    for (i, rec) in records.iter().enumerate() {
        assert_ne!(
            rec.ts_ns, NO_TIMESTAMP,
            "record {i} reports NO_TIMESTAMP, but every push carried a clock \
             reading"
        );
        // The TRUNCATION rule: the sub-millisecond digits this leg deliberately
        // pushed are gone, and what comes back is a whole millisecond.
        assert_eq!(
            rec.ts_ns % MS,
            0,
            "record {i} carries {} ns, which is not a whole millisecond — the \
             reader's clock is milliseconds and the narrowing happens at the \
             boundary",
            rec.ts_ns
        );
        assert_ne!(
            rec.ts_ns,
            pushed_ts_ns(0),
            "record {i} carries the pushed nanosecond VERBATIM, remainder and \
             all"
        );
        // And inside the window this leg actually pushed. A clock left at zero,
        // or one running on wall time, lands outside.
        assert!(
            rec.ts_ns >= first && rec.ts_ns <= last,
            "record {i} carries {} ns, outside the pushed window [{first}, {last}]",
            rec.ts_ns
        );
    }

    // The clock MOVED. One distinct value would satisfy every assertion above
    // and would mean the door stamps a constant — the population-of-one shape
    // this tree keeps paying for.
    let mut seen: Vec<u64> = records.iter().map(|r| r.ts_ns).collect();
    seen.sort_unstable();
    seen.dedup();
    assert!(
        seen.len() >= 2,
        "every record carries the same instant ({seen:?}), so the timestamp \
         tracks nothing"
    );
}

// wz-proves: none -- a DAMAGE sweep. It grades the door's own numbers against
// mutated bytes; the bytes started genuine but no message in the sweep is one a
// foreign implementation would send, so no cross-impl claim can rest on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn the_zenohd_binary_doors_offsets_survive_a_single_byte_damage_sweep() {
    let capture = capture_zenohd_session().await;
    let (clean, _) = drive_binary_door(&capture.recording);
    assert!(
        !clean.is_empty(),
        "the clean run decoded nothing to compare against"
    );

    let mut swept = 0usize;
    let mut records_moved = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for seg in 0..capture.recording.len() {
        // The ROUTER's half: the genuine bytes, and the same half
        // `zenohd_wire_dissection.rs` sweeps.
        if capture.recording[seg].0 != Side::FromListener {
            continue;
        }
        for byte in 0..capture.recording[seg].1.len() {
            let mut damaged = capture.recording.clone();
            damaged[seg].1[byte] ^= 0xFF;
            swept += 1;
            let (records, _) = drive_binary_door(&damaged);
            if records != clean {
                records_moved += 1;
            }
            // THE STRONG HALF: whatever the bytes now say, the door's
            // coordinates must still name what is at them. This is the
            // offset/length contract held over inputs nobody chose.
            if !records.is_empty() {
                if let Err(e) = grade_against_bytes(&records, &damaged) {
                    violations.push(format!("segment {seg} byte {byte}: {e}"));
                }
            }
        }
    }

    // THE LENGTH HALF, aimed rather than scattered. Every byte of every length
    // prefix in the router's stream, derived by walking that stream's framing:
    // flipping one must change what the door reports, because that byte IS the
    // length it reports. A door that invented `unit_len` — or read it from
    // anywhere else — leaves at least one of these unchanged.
    let router_stream = stream_of(&capture.recording, Side::FromListener);
    let prefixes = prefix_byte_positions(&router_stream);
    let mut prefix_swept = 0usize;
    let mut prefix_inert: Vec<usize> = Vec::new();
    for position in &prefixes {
        let Some((seg, byte)) = locate(&capture.recording, Side::FromListener, *position) else {
            panic!("prefix byte at stream position {position} maps to no segment");
        };
        let mut damaged = capture.recording.clone();
        damaged[seg].1[byte] ^= 0xFF;
        prefix_swept += 1;
        let (records, _) = drive_binary_door(&damaged);
        if records == clean {
            prefix_inert.push(*position);
        }
    }

    eprintln!(
        "door damage sweep: swept={swept} records_moved={records_moved} \
         violations={} | prefix bytes swept={prefix_swept} inert={}",
        violations.len(),
        prefix_inert.len()
    );

    assert!(
        swept > 0,
        "the sweep had no population — no router-half segment"
    );
    assert!(
        records_moved > 0,
        "flipping any of {swept} router bytes changed NOTHING the door reports, \
         so its records are not derived from these bytes at all"
    );
    assert!(
        violations.is_empty(),
        "the door's coordinates stopped naming what is at them under damage \
         ({} case(s)); first: {}",
        violations.len(),
        violations[0]
    );
    assert!(
        prefix_swept > 0,
        "the router's stream yielded no length prefix at all, so the length \
         claim below has no population"
    );
    assert!(
        prefix_inert.is_empty(),
        "{} of {prefix_swept} LENGTH-PREFIX byte flips left the door's records \
         byte-identical (stream positions {prefix_inert:?}). A `unit_len` that \
         does not move when its own prefix moves is not read from the wire.",
        prefix_inert.len()
    );
}
