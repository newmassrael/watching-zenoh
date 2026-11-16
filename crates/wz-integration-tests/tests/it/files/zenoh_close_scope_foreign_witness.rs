// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 175 — the scope bit of the Close a stock zenoh session writes
//! when it closes a session that was ESTABLISHED, read off the wire.
//!
//! `close_scope_zenohd_witness.rs` measures one Close a real zenohd writes: the
//! establishment reject, provoked by a KeepAlive where an InitSyn is due. The
//! other unicast Close site, a session closing every transport it holds, was
//! supported only by a reading of upstream's transport code, and wz's
//! `close_scope_is_session` derivation rests on both sites agreeing that the
//! scope bit is clear on a link that is the transport's last.
//!
//! ## The provocation
//!
//! A stock zenoh session closes its transports when the application drops it,
//! and every stock example drops its session on the way out. `z_get` is the
//! one that exits by itself: asked a key nothing answers, it waits out its own
//! query timeout, drops the session and ends. Its transport to zenohd was
//! established (an Open went each way first), so the Close it writes on the way
//! out is the whole-transport close of an established session.
//!
//! ```text
//!   zenoh_z_get ──► [tap] ──► zenohd
//!   (stock zenoh client)      (stock router)
//! ```
//!
//! No wz process is on the wire; wz is only the reader of the synthesised
//! capture, as in the other foreign witnesses of this lane.
//!
//! ## What this does not reach
//!
//! zenohd itself never closes an established session on its own initiative:
//! it parks its main thread until it is killed, and a lease that runs out
//! drops the link without a Close. The session that closes here is the same
//! transport code in a client, which is the closest a stock binary comes.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    wait_for_tcp_accept_alive, zenoh_core_example_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. They decide which half is `Direction::A`
/// (`FlowKey` orders endpoints by `(addr, port)` on one address): the
/// listener, zenohd, is the LOW endpoint and therefore `A`, and the dialer,
/// `z_get`, is `B`. Asserted below rather than assumed.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// A key no queryable answers, so `z_get` runs to its own timeout and exits.
const QUERY_KEY: &str = "demo/close-scope/unanswered";

/// `z_get -o`, in milliseconds: how long the client waits before it gives up
/// on the query, drops its session and exits.
const GET_TIMEOUT_MS: &str = "1000";

/// The wall clock the client gets to run to its end; a bound on a stall, not a
/// measure of speed.
const GET_WALL_CLOCK: Duration = Duration::from_secs(60);

/// How long the tap gets to relay the client's last bytes after it exited.
const CLOSE_RELAY_BUDGET: Duration = Duration::from_secs(10);

/// `close::reason::GENERIC`: the reason a session passes to each transport it
/// closes. Pinned so that a Close for another cause cannot stand in for this
/// one.
const REASON_GENERIC: u8 = 0x00;

/// A transport message one half of the relayed session carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Open,
    Close { reason: u8, session: bool },
}

/// The Opens and Closes on the `side` half of the recording, in wire order.
fn transport_events(recording: &Recording, side: Direction) -> Vec<Seen> {
    let segments = recording.lock().expect("recording lock").clone();
    if segments.is_empty() {
        return Vec::new();
    }
    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "zenohd (the listener) must be the LOW endpoint, so the client is B"
    );
    flow.frames()
        .iter()
        .filter(|frame| frame.direction == side)
        .filter_map(|frame| match &frame.frame {
            Ok(InboundFrame::Open { .. }) => Some(Seen::Open),
            Ok(InboundFrame::Close {
                reason, session, ..
            }) => Some(Seen::Close {
                reason: *reason,
                session: *session,
            }),
            _ => None,
        })
        .collect()
}

/// Poll the client's half until a Close has been relayed or the budget runs
/// out, and return what that half carried.
fn wait_for_client_close(recording: &Recording, budget: Duration) -> Vec<Seen> {
    let deadline = Instant::now() + budget;
    loop {
        let seen = transport_events(recording, Direction::B);
        if seen.iter().any(|s| matches!(s, Seen::Close { .. })) || Instant::now() >= deadline {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// THE WITNESS. The `zenohd` in the name is load-bearing: Layer C0's skip-token
/// rule reads the function name, and this test spawns zenohd.
// wz-proves: codec-close zenoh->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_get); Layer Ewirez runs via --ignored"]
fn a_stock_zenoh_session_clears_the_close_scope_flag_closing_an_established_session_to_zenohd() {
    let z_get = zenoh_core_example_binary("z_get");

    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();
    let mut zenohd = ChildGuard::wrap(
        "zenohd (the router a stock client closes its session to)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{zenohd_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) =
        wait_for_tcp_accept_alive(zenohd.child_mut(), zenohd_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("zenohd never accepted: {e}");
    }
    // zenohd holds the port now; the reservation's window is over.
    drop(reservation);

    let (tap_port, recording) = tap_proxy(zenohd_port);

    // THE SUBJECT: a stock client that establishes, asks, gives up and drops
    // its session, which closes the transport it holds.
    let run = Command::new(z_get)
        .args([
            "-s",
            QUERY_KEY,
            "-o",
            GET_TIMEOUT_MS,
            "-m",
            "client",
            "-e",
            &format!("tcp/127.0.0.1:{tap_port}"),
            "--no-multicast-scouting",
        ])
        .output_within(GET_WALL_CLOCK)
        .expect("start z_get");
    let client = wait_for_client_close(&recording, CLOSE_RELAY_BUDGET);
    let router = transport_events(&recording, Direction::A);

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let z_get_out = format!(
        "--- z_get ({}) stdout ---\n{}\n--- z_get stderr ---\n{}",
        run.status,
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // ESTABLISHED, not merely attempted: the router answered with an Open, and
    // the client's Open precedes its Close on its own half.
    assert!(
        router.contains(&Seen::Open),
        "zenohd never answered with an Open, so no session was established and a Close \
         here would be an establishment one: router={router:?} client={client:?}\n{z_get_out}"
    );
    let first_open = client.iter().position(|s| *s == Seen::Open);
    let closes: Vec<(usize, u8, bool)> = client
        .iter()
        .enumerate()
        .filter_map(|(at, s)| match s {
            Seen::Close { reason, session } => Some((at, *reason, *session)),
            Seen::Open => None,
        })
        .collect();
    assert!(
        !closes.is_empty(),
        "the stock client exited without a Close on the wire, so there is no byte to read: \
         client={client:?}\n{z_get_out}"
    );
    let Some(first_open) = first_open else {
        panic!("the client wrote no Open before closing: client={client:?}\n{z_get_out}");
    };
    for (at, reason, session) in closes {
        assert!(
            at > first_open,
            "a Close before the client's Open is an establishment Close, not this one: \
             client={client:?}"
        );
        assert_eq!(
            reason, REASON_GENERIC,
            "a session closing its transport passes the GENERIC reason; another reason is \
             another close: client={client:?}"
        );
        assert!(
            !session,
            "MEASURED, not read: a stock zenoh session closing its established transport \
             (its only link) must clear the close scope flag, the second site wz's \
             `close_scope_is_session` derivation rests on. client={client:?}"
        );
    }
}
