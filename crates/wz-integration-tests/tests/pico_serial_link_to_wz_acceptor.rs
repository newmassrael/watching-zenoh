// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A real zenoh-pico client opens a SERIAL link against a watching-zenoh
//! acceptor over a PTY pair, and publishes across it. This is the foreign
//! witness for the `locator-serial` atom: BOTH stacks are handed a
//! `serial/<device>#baudrate=<n>` string and must split it the same way, or
//! no device opens and no link comes up.
//!
//! ## Why this test is possible at all (a prior claim, refuted)
//!
//! `tests/layer3_serial_framing.rs:29-33` states "zenoh-pico has NO unix
//! serial LINK backend — `_z_open_serial_*` exists only for MCU targets
//! (RPi Pico / esp-idf / zephyr; `src/system/unix/` has no serial)", and
//! concludes a live pico serial process is impossible. That was true of the
//! layout it described, and is FALSE of the current vendor pin:
//! `vendor/zenoh-pico/src/link/transport/serial/tty_posix.c` (Copyright
//! 2026) implements the POSIX termios driver under
//! `Z_FEATURE_LINK_SERIAL == 1 && (ZENOH_LINUX || ZENOH_MACOS || ZENOH_BSD)`,
//! and `vendor/zenoh-pico/cmake/platforms/linux.cmake:9` adds it to the
//! Linux platform sources. The serial link moved out of
//! `src/system/<plat>/` into `src/link/transport/serial/`, which is why a
//! search of the old location kept coming back empty. The feature is
//! default-OFF (`CMakeLists.txt:333`), so it is turned ON explicitly in
//! `scripts/build-zenoh-pico-cli.sh`.
//!
//! ## Roles are FORCED by pico's implementation, not chosen
//!
//! pico implements only the CONNECT half of the serial-link handshake:
//! `_z_connect_serial` (`serial_protocol.c:255`) sends
//! `_Z_FLAG_SERIAL_INIT` and loops until it reads back `INIT|ACK`.
//! `_z_serial_protocol_listen` (`serial_protocol.c:249`) opens the tty and
//! returns — nothing in pico ever EMITS `_Z_FLAG_SERIAL_ACK`. So pico must
//! be the serial-link Initiator and wz must be the Responder
//! (`drive_serial_handshake(.., SerialRole::Responder)`), which is also the
//! zenoh-session direction this corpus already uses for pico (client opens,
//! wz accepts).
//!
//! ## Why TWO PTY pairs and a bridge
//!
//! Both stacks open a serial endpoint BY DEVICE PATH — that is the whole
//! point, since the path is what the locator grammar has to produce. A
//! single `openpty` yields one path (the slave) plus a master fd that has
//! no reusable path, so it cannot feed two path-opening processes. Two
//! pairs whose masters are pumped into each other give each side a real
//! device path and keep the locator parse load-bearing on both ends. No
//! external tool (socat) is involved, so the test has no host dependency
//! beyond the pico binary.
//!
//! ## What would break it
//!
//! wz's `parse_serial_locator` (`wz-session-core/src/locator.rs`) takes the
//! ADDRESS span — cut at whichever of `?` / `#` comes first — and the pin
//! form at `.`; pico's `_z_serial_endpoint_parse` (`serial_protocol.c:79`)
//! takes its address from `_z_locator_t::_address` — cut at `?` or `#`
//! (`endpoint.c:123-127`) — and its baudrate from the `#`-delimited
//! ENDPOINT CONFIG map (`endpoint.c:388`, key `"baudrate"`,
//! `link/config/serial.h:31`). Had wz cut the tail anywhere else, the
//! device path it opens would carry the tail and the open would fail ENOENT.
//!
//! ## Both locator SHAPES are driven — the R311y467 residual, closed
//!
//! R311y466 hardened ONE shape and R311y467 had to downgrade the claim to
//! `partial`, because handing the SAME string to both stacks across the
//! shape SPACE found a real divergence. Measured then, and the reason this
//! file now runs two arms rather than one:
//!
//! - `serial/<dev>#baudrate=115200` — pico opens the device and writes
//!   `020101010101010100` (COBS of header INIT / len 0 / crc32 0); wz
//!   parsed `Device("<dev>")`. AGREE.
//! - `serial/<dev>` (no tail) — pico writes nothing and prints "Unable to
//!   open session!", i.e. its baudrate genuinely comes from the
//!   `#`-delimited config map and is REQUIRED.
//! - `serial/<dev>?meta=x#baudrate=115200` — pico still opened `<dev>` (it
//!   cuts the address at `?`); wz yielded `Device("<dev>?meta=x")` and
//!   `accept_serial` failed `NotFound`. DIVERGED.
//!
//! R311y469 closed that by giving EVERY leaf zenoh's canon three-way split
//! (`split_locator_parts`), so the shape space is now driven rather than
//! described: [`pico_serial_client_establishes_and_publishes_to_wz_acceptor`]
//! runs the `#config` shape and
//! [`pico_serial_client_establishes_over_a_metadata_bearing_locator`] runs the
//! `?metadata#config` shape, both handing the identical string to pico and to
//! wz. A cross-impl grammar claim needs the shape SPACE enumerated, which is
//! the lesson R311y467 recorded and this file now implements.
//!
//! That the split is load-bearing HERE — and not merely asserted here — was
//! measured, not argued: with `parse_serial_locator` changed to leave the
//! tail on the address AND this file's parse assertions bypassed, the run
//! still fails, at `accept_serial` (`Device("/dev/pts/N#baudrate=115200")`,
//! no such device). The grammar itself is separately pinned in the atom's
//! own crate by `wz-session-core/src/locator.rs::parses_serial_device`,
//! which reds under that same damage; this file does not duplicate it.

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio_serial::SerialStream;

use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::serial_pipeline::accept_serial;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::{parse_any_locator, AnyLocator, SerialTarget};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/serial-interop";
const BAUDRATE: u32 = 115_200;

/// One PTY pair, reduced to what the test needs: the master (pumped by the
/// bridge) and the slave's device PATH (handed to a stack as a locator).
/// The slave handle itself is retained so the pty never loses its last
/// slave fd — a master read would otherwise fail EIO the moment the only
/// slave closes. It is never read from, so it steals no bytes from the
/// stack that opens the same path.
struct PtyEnd {
    master: SerialStream,
    path: String,
    _slave_keepalive: SerialStream,
}

fn pty_end() -> PtyEnd {
    let (master, slave) = SerialStream::pair().expect("openpty pair");
    let path = tokio_serial::SerialPort::name(&slave).expect("pty slave has a device path");
    PtyEnd {
        master,
        path,
        _slave_keepalive: slave,
    }
}

/// Pump bytes both ways between two pty masters, making the two slave
/// devices behave as the two ends of one wire.
async fn bridge(a: SerialStream, b: SerialStream) {
    let (mut a_rd, mut a_wr) = tokio::io::split(a);
    let (mut b_rd, mut b_wr) = tokio::io::split(b);
    let a_to_b = async { tokio::io::copy(&mut a_rd, &mut b_wr).await };
    let b_to_a = async { tokio::io::copy(&mut b_rd, &mut a_wr).await };
    tokio::select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }
}

/// Fields wz reads back off the delivered `Sample`.
#[derive(Default)]
struct Captured {
    keyexpr_ok: bool,
    payload: Vec<u8>,
    fired: usize,
}

/// The shape both stacks already agreed on before R311y469: no metadata span.
const METADATA_ABSENT: &str = "";
/// The `?metadata` span R311y467 measured as DIVERGENT. pico cut the address
/// at `?` and opened the device; wz carried `?meta=x` into the device path and
/// failed the open. Driving it is what closes that residual.
const METADATA_PRESENT: &str = "?meta=x";

// wz-proves: locator-serial pico->wz
// wz-proves: transport-link-serial pico->wz partial
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_pub built with Z_FEATURE_LINK_SERIAL); Layer E runs via --ignored"]
async fn pico_serial_client_establishes_and_publishes_to_wz_acceptor() {
    serial_interop_over_metadata_span(METADATA_ABSENT).await;
}

// wz-proves: locator-serial pico->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_pub built with Z_FEATURE_LINK_SERIAL); Layer E runs via --ignored"]
async fn pico_serial_client_establishes_over_a_metadata_bearing_locator() {
    serial_interop_over_metadata_span(METADATA_PRESENT).await;
}

/// One pico->wz serial interop run, parameterised on the `?metadata` span so
/// the two arms differ in NOTHING else: the `#baudrate=` config span is built
/// identically from [`BAUDRATE`] in both, because that is where pico reads the
/// speed from. The metadata span is therefore the only variable, which is what
/// makes the second arm a measurement of the grammar rather than of the link.
async fn serial_interop_over_metadata_span(metadata: &str) {
    let z_pub = zenoh_pico_cli_binary("z_pub");

    // ── The wire: two pty pairs, masters pumped into each other. wz takes
    //    one slave path, pico the other; neither side ever sees the other's
    //    file descriptor.
    let wz_end = pty_end();
    let pico_end = pty_end();
    let wz_locator = format!("serial/{}{metadata}#baudrate={BAUDRATE}", wz_end.path);
    let pico_locator = format!("serial/{}{metadata}#baudrate={BAUDRATE}", pico_end.path);
    tokio::spawn(bridge(wz_end.master, pico_end.master));

    // ── THE ATOM'S OWN CODE. `parse_serial_locator` must cut the tail exactly
    //    where pico's endpoint parser cuts it; the assertions name the split
    //    rather than trusting the open to imply it.
    let parsed = parse_any_locator(&wz_locator).expect("wz parses its own serial locator");
    let endpoint = match parsed {
        AnyLocator::Serial(ep) => ep,
        other => panic!("`serial/...` must classify as AnyLocator::Serial, got {other:?}"),
    };
    assert_eq!(
        endpoint.target,
        SerialTarget::Device(wz_end.path.clone()),
        "the device path stops at the first `?` or `#` — no tail is part of it \
         (locator `{wz_locator}`)"
    );
    assert_eq!(
        endpoint.baudrate, BAUDRATE,
        "the baudrate comes off the `#`-delimited config tail, pico's SERIAL_CONFIG_BAUDRATE_KEY"
    );

    // ── Foreign initiator FIRST. `accept_serial` opens the tty AND blocks
    //    in the Responder half of the serial-link handshake waiting for an
    //    INIT, so pico has to be running before it is called or the two
    //    sides deadlock. pico's INIT is not lost by starting early: it goes
    //    into the wz pty's input queue (which retains it — the keepalive fd
    //    keeps a slave open) and `_z_connect_serial` blocks on the read
    //    rather than re-sending, so the byte MUST survive the gap.
    //    `-n 1` makes pico publish exactly once then close, so the wz drive
    //    loop reaches a terminal state after the single Put.
    let mut z_pub_child = ChildGuard::wrap(
        "z_pub (zenoh-pico serial initiator)",
        Command::new(&z_pub)
            .args([
                "-k",
                KEYEXPR,
                "-e",
                &pico_locator,
                "-m",
                "client",
                "-n",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenoh-pico z_pub"),
    );

    // ── The wz end of the wire, opened FROM THE PARSE (not from the path
    //    string), so a mis-split would open the wrong device here. This is
    //    also the serial-LINK handshake, which sits below the zenoh
    //    transport and has no TCP analogue: pico sends INIT, wz answers
    //    INIT|ACK.
    let wz_serial = tokio::time::timeout(Duration::from_secs(20), accept_serial(&endpoint))
        .await
        .expect("the pico serial initiator reaches wz within 20s")
        .expect("wz opens its serial endpoint and answers INIT|ACK");

    // ── Zenoh transport open over the handshaked serial link — the same
    //    accept path the TCP pico legs use; only the framing differs.
    let mut opened = tokio::time::timeout(
        Duration::from_secs(20),
        accept_and_open_session(
            // R311y475 — the variant carries the dialled endpoint since R311y474 (a
            // tty's address is not readable off the stream, and the adminspace
            // `{src,dst}` view needs it). This site has the REAL one in hand: it is
            // the endpoint `accept_serial` just opened.
            DialedLink::Serial {
                stream: wz_serial,
                endpoint: endpoint.clone(),
            },
            fixture_session_init_params(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        ),
    )
    .await
    .expect("session open completes within 20s")
    .expect("wz acceptor reaches Established against the pico serial client");

    // ── The subscription is declared through the full `TokioSession` so its
    //    `Declare(DeclSubscriber)` ships on the wire: pico's
    //    `z_declare_publisher` arms a write filter that SUPPRESSES the Put
    //    until it observes a matching subscriber, and that interest is
    //    matched by EXACT keyexpr equality on the client side — so the
    //    literal must be identical, and a local-only register would deliver
    //    nothing. Same constraint as the TCP `pico_pub_attachment` leg.
    let captured = Arc::new(StdMutex::new(Captured::default()));
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    // Named binding (NOT `_`): a `_`-drop would immediately emit
    // `Declare(UndeclSubscriber)` and re-arm pico's filter before the Put.
    let _subscriber = {
        let captured = captured.clone();
        session
            .declare_subscriber(KEYEXPR, SubscribeOptions::default(), move |sample| {
                let mut c = captured.lock().unwrap();
                c.keyexpr_ok = sample.keyexpr() == KEYEXPR;
                c.payload = sample.payload().to_vec();
                c.fired += 1;
            })
            .expect("wz declares the subscriber over the serial link")
    };

    let timeouts = SessionTimeouts::spec_defaults();
    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            panic!(
                "wz drive did not terminate within 30s — the pico serial client never \
                 published+closed"
            )
        }
    }

    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();

    let c = captured.lock().unwrap();
    assert_eq!(
        c.fired, 1,
        "exactly one pico Put delivered across the serial link"
    );
    assert!(
        c.keyexpr_ok,
        "the delivered sample carries the pico keyexpr"
    );
    assert!(
        !c.payload.is_empty(),
        "the delivered sample carries pico's payload bytes"
    );
}
