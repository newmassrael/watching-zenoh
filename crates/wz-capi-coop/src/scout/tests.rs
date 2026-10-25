//! The blocking scouting window over sockets a test owns: a responder on loopback stands in for a
//! node that answers the group, so the window's reading, sending and ending are checked without a
//! multicast host.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_runtime_posix::PosixClock;
use wz_session_core::scout_initiator::ScoutRxIgnored;
use wz_session_core::scouting_host::decode_scouted_hello;

use super::*;

const WHAT: u8 = 0x03;

/// A Hello datagram `[S_MID_HELLO | L][version][cbyte][zid][n][len][locator]...`: `whatami` in the
/// low two bits of the cbyte and the zid length less one in the high nibble, as the wire spells
/// them. Checked through the decode the window itself uses.
fn hello_datagram(whatami: u8, zid: &[u8], locators: &[&str]) -> Vec<u8> {
    const S_MID_HELLO: u8 = 0x02;
    const L_FLAG: u8 = 0x20;
    let header = S_MID_HELLO | if locators.is_empty() { 0 } else { L_FLAG };
    let cbyte = (whatami & 0x03) | (((zid.len() - 1) as u8) << 4);
    let mut bytes = vec![header, 0x09, cbyte];
    bytes.extend_from_slice(zid);
    if !locators.is_empty() {
        bytes.push(locators.len() as u8);
        for locator in locators {
            bytes.push(locator.len() as u8);
            bytes.extend_from_slice(locator.as_bytes());
        }
    }
    assert!(
        decode_scouted_hello(&bytes).is_some(),
        "the test's own Hello must decode: {bytes:02x?}"
    );
    bytes
}

/// A node that answers: it reads Scouts on a loopback socket, counts them, and answers each with
/// every datagram in `reply`, written back to whoever asked.
struct Responder {
    at: SocketAddr,
    scouts: Arc<AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Responder {
    fn start(reply: Vec<Vec<u8>>) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the responder");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("a read timeout");
        let at = socket.local_addr().expect("the responder's address");
        let scouts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, halted) = (scouts.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while !halted.load(Ordering::Acquire) {
                let Ok((n, asker)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                // A Scout is the scouting MID with the version after it.
                if n >= 2 && buffer[0] & 0x1f == 0x01 {
                    seen.fetch_add(1, Ordering::SeqCst);
                    for datagram in &reply {
                        let _ = socket.send_to(datagram, asker);
                    }
                }
            }
        });
        Self {
            at,
            scouts,
            stop,
            thread: Some(thread),
        }
    }

    fn scouts(&self) -> usize {
        self.scouts.load(Ordering::SeqCst)
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A window member on a fresh loopback socket that writes its Scout to `peer`.
fn asking(peer: SocketAddr) -> Member {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a member");
    socket.set_nonblocking(true).expect("non-blocking");
    Member {
        socket,
        peer,
        asks: true,
    }
}

fn params(timeout_ms: u64, exit_on_first: bool) -> ScoutParams {
    ScoutParams {
        what: WHAT,
        zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
        timeout_ms,
        exit_on_first,
    }
}

/// The survey asks once and keeps listening for its whole budget: every responder is recorded, in
/// arrival order, and the window ends at its deadline and not before. Two responders' worth of
/// Hellos from one node, with different zids, are two peers.
#[test]
fn a_survey_collects_every_answer_for_its_whole_budget() {
    let responder = Responder::start(vec![
        hello_datagram(0, &[0x11; 4], &["tcp/10.0.0.1:7447"]),
        hello_datagram(1, &[0x22; 4], &["tcp/10.0.0.2:7447", "udp/10.0.0.2:7447"]),
    ]);
    let members = Members::from_parts(None, vec![asking(responder.at)]);
    let started = Instant::now();
    let actions = run_window(&PosixClock, members, params(300, false));
    let took = started.elapsed();

    let hellos = actions.scouted_hellos();
    assert_eq!(
        hellos.iter().map(|h| h.zid[0]).collect::<Vec<_>>(),
        [0x11, 0x22],
        "both answered, in arrival order"
    );
    assert_eq!(
        hellos[1].locators,
        ["tcp/10.0.0.2:7447", "udp/10.0.0.2:7447"],
        "every locator the Hello advertised"
    );
    assert_eq!(responder.scouts(), 1, "one Scout for the whole window");
    // The window reads the clock in whole milliseconds, so it can end up to one short of its budget.
    assert!(
        took + Duration::from_millis(1) >= Duration::from_millis(300),
        "a survey runs to its deadline, ended after {took:?}"
    );
}

/// The open-time lookup ends at the FIRST Hello, well before its budget, and records only it.
#[test]
fn a_lookup_ends_at_the_first_answer() {
    let responder = Responder::start(vec![
        hello_datagram(0, &[0x11; 4], &["tcp/10.0.0.1:7447"]),
        hello_datagram(0, &[0x22; 4], &["tcp/10.0.0.2:7447"]),
    ]);
    let members = Members::from_parts(None, vec![asking(responder.at)]);
    let started = Instant::now();
    let actions = run_window(&PosixClock, members, params(5_000, true));
    let took = started.elapsed();

    assert_eq!(
        actions.discovered_locator().as_deref(),
        Some("tcp/10.0.0.1:7447")
    );
    assert_eq!(
        actions.scouted_hellos().len(),
        1,
        "the window stopped at the first"
    );
    assert!(
        took < Duration::from_millis(2_000),
        "the lookup did not wait out its 5 s budget: {took:?}"
    );
}

/// A window nobody answers ends at its deadline with nothing, and says it asked once.
#[test]
fn a_window_nobody_answers_ends_empty_at_its_deadline() {
    let responder = Responder::start(Vec::new());
    let members = Members::from_parts(None, vec![asking(responder.at)]);
    let started = Instant::now();
    let actions = run_window(&PosixClock, members, params(200, false));

    assert!(actions.scouted_hellos().is_empty());
    assert_eq!(actions.discovered_locator(), None);
    assert_eq!(responder.scouts(), 1);
    assert!(started.elapsed() + Duration::from_millis(1) >= Duration::from_millis(200));
}

/// A datagram that is not an answer is named and dropped, and neither ends an exit-on-first window
/// nor counts as a Hello: our own Scout looped back, a Hello that does not decode, and one that
/// advertises no address. Every datagram lands in exactly one of the two records.
#[test]
fn a_datagram_that_is_not_an_answer_is_named_and_the_window_goes_on() {
    // The Scout the window itself sends, as a host that loops its multicast back hears it.
    let own_scout = ScoutWindow::<CoopRuntime<PosixClock>>::new(params(3_000, true))
        .open()
        .expect("a window opens with a Scout");
    let truncated = vec![0x22, 0x09];
    let locatorless = hello_datagram(0, &[0x33; 4], &[]);
    let answer = hello_datagram(0, &[0x44; 4], &["tcp/10.0.0.4:7447"]);
    let responder = Responder::start(vec![own_scout, truncated, locatorless, answer]);
    let members = Members::from_parts(None, vec![asking(responder.at)]);
    let actions = run_window(&PosixClock, members, params(3_000, true));

    assert_eq!(
        actions.discovered_locator().as_deref(),
        Some("tcp/10.0.0.4:7447"),
        "the window went past all three and took the real answer"
    );
    let ignored = actions.ignored_datagrams();
    assert!(
        ignored.contains(&ScoutRxIgnored::SelfEcho),
        "our own Scout: {ignored:?}"
    );
    assert!(
        ignored.contains(&ScoutRxIgnored::Undecodable),
        "the truncated Hello: {ignored:?}"
    );
    assert!(
        ignored.contains(&ScoutRxIgnored::LocatorlessHello),
        "the Hello with no address: {ignored:?}"
    );
    assert_eq!(
        actions.scouted_hellos().len(),
        1,
        "only the answer was recorded"
    );
}

/// The Scout counts as sent when ONE ask member sent it, and a member that cannot send does not
/// end the window: a node with one dead interface among two still discovers.
#[test]
fn a_dead_ask_member_does_not_end_the_window() {
    let responder = Responder::start(vec![hello_datagram(0, &[0x55; 4], &["tcp/10.0.0.5:7447"])]);
    // A member whose peer is an address nothing can be sent to from an IPv4 socket.
    let dead = asking(SocketAddr::from(([0, 0, 0, 0], 0)));
    let members = Members::from_parts(None, vec![dead, asking(responder.at)]);
    let actions = run_window(&PosixClock, members, params(3_000, true));

    assert_eq!(
        actions.discovered_locator().as_deref(),
        Some("tcp/10.0.0.5:7447")
    );
}

/// With no ask member the group socket asks, the floor a host whose interface enumeration fails
/// still scouts on; with no member at all there is no window, and it ends at once with nothing.
#[test]
fn the_group_socket_asks_when_nothing_else_can_and_no_member_is_no_window() {
    let responder = Responder::start(vec![hello_datagram(0, &[0x66; 4], &["tcp/10.0.0.6:7447"])]);
    let mut group = asking(responder.at);
    group.asks = false;
    let members = Members::from_parts(Some(group), Vec::new());
    assert!(
        members.members[0].asks,
        "the group socket asks because there is no ask socket"
    );
    let actions = run_window(&PosixClock, members, params(3_000, true));
    assert_eq!(
        actions.discovered_locator().as_deref(),
        Some("tcp/10.0.0.6:7447")
    );

    let started = Instant::now();
    let none = run_window(
        &PosixClock,
        Members::from_parts(None, Vec::new()),
        params(5_000, false),
    );
    assert!(none.scouted_hellos().is_empty());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "no member, no window: it ended at once"
    );
}

/// The public entry points hand the peers over after the window, last responder first, and count
/// them. Over the host's own multicast sockets, so it runs where a group can be joined; it asserts
/// only what must hold anywhere: a window nobody answers delivers nothing and returns on time.
#[test]
fn the_public_window_finds_nothing_on_a_group_nobody_answers() {
    let started = Instant::now();
    let mut seen = 0usize;
    // A group and port nothing else is expected to use.
    let delivered = run_scout(
        &PosixClock,
        IpAddr::V4(Ipv4Addr::new(239, 255, 91, 77)),
        47_477,
        WHAT,
        vec![0x77; 16],
        150,
        |_| seen += 1,
    );
    assert_eq!((delivered, seen), (0, 0));
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(scout_first(
        &PosixClock,
        IpAddr::V4(Ipv4Addr::new(239, 255, 91, 77)),
        47_477,
        WHAT,
        vec![0x77; 16],
        100,
    )
    .is_none());
}
