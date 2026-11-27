// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A member whose group socket fills: the session's puts follow the stage rule the tokio
//! engine's group does, on a queue bounded by its lanes. Nothing reads the session until a test
//! says so, so what moves the group's stage is the session's own puts. Each test but one runs in
//! both forms of the engine's calls: where a read task steps the session (`threads`), and where
//! the program's own reads step each group's session itself.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramEvent, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{AppPort, AppTransport, SessionTransport};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::session_init_params::TxQueueConf;

use super::client_config;
use super::group_stack::{member_config, Engine, Table, GROUP};
use crate::tests::app_links;
use crate::{CoopConfig, EngineHold};

/// What a droppable put waits for room, at most.
const DROP_WAIT: Duration = Duration::from_millis(20);
/// What a blocking put waits for room, at most.
const CLOSE_WAIT: Duration = Duration::from_millis(300);
/// A payload two of which fill a lane of one 2 KiB batch.
const PAYLOAD: [u8; 1_500] = [0x5a; 1_500];

/// A stack whose group socket takes every datagram until it is told it is full, and then
/// none, answering would-block, until it is told it is writable again.
#[derive(Default)]
struct Filling {
    full: AtomicBool,
    sent: AtomicUsize,
    closes: AtomicUsize,
    link: Mutex<Option<LinkHandle>>,
}

struct FillingPort(Arc<Filling>);

impl AppPort for FillingPort {
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
        if kind != AppLinkKind::Group || locator != GROUP {
            return ProgramOpen::Refused;
        }
        *self.0.link.lock().unwrap() = Some(link);
        ProgramOpen::Up
    }

    fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        if self.0.full.load(Ordering::SeqCst) {
            return ProgramSend::WouldBlock;
        }
        self.0.sent.fetch_add(1, Ordering::SeqCst);
        ProgramSend::Wrote(bytes.len())
    }

    fn close(&self, _link: LinkHandle) {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
    }
}

/// A member over a filling stack whose lanes hold one batch each, with the two waits above.
fn open_filling() -> (EngineHold<Engine>, Arc<Filling>, Arc<AppTransport>) {
    let stack = Arc::new(Filling::default());
    let transport = Arc::new(AppTransport::new(
        Box::new(Table(Mutex::new(AppLinkTable::new()))),
        Box::new(FillingPort(Arc::clone(&stack))),
    ));
    let config = CoopConfig {
        tx_queue: TxQueueConf {
            sizes: [1; Priority::NUM],
            wait_before_drop_us: DROP_WAIT.as_micros() as u64,
            wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
            no_progress_us: None,
            ..client_config().tx_queue
        },
        ..member_config(1, GROUP)
    };
    let engine = Engine::open(
        app_links(SessionTransport::new(
            Arc::clone(&transport),
            &config.limits,
        )),
        PosixClock,
        PosixEntropy,
        config,
    )
    .expect("the member joins");
    (engine, stack, transport)
}

/// Put [`PAYLOAD`] on the group with `congestion`, and how long the put took.
fn put_with(engine: &Engine, congestion: CongestionControl) -> Duration {
    let started = Instant::now();
    let sent = engine.publish_on_wire_all(
        "demo/group/full",
        &WireKey::literal(),
        &PAYLOAD,
        &PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_congestion_control(congestion),
    );
    assert_eq!(sent, Ok(0), "a dropped put succeeds, as zenoh's does");
    started.elapsed()
}

/// Read `member` until `done`, for at most five seconds, as its form reads it: by its read task
/// where its reads run beside the program's calls (`threads`), and by the test's own reads, on
/// the thread that opened and calls it, where they do not.
fn read_until(member: &Engine, what: &str, mut done: impl FnMut() -> bool) {
    #[cfg(feature = "threads")]
    SessionDrive::start_read_task(member).expect("the read task starts");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        #[cfg(feature = "threads")]
        std::thread::sleep(Duration::from_millis(5));
        #[cfg(not(feature = "threads"))]
        let _ = SessionDrive::read(member, false);
    }
}

/// The stack takes datagrams again and says so.
fn writable(stack: &Filling, transport: &AppTransport) {
    stack.full.store(false, Ordering::SeqCst);
    let link = stack.link.lock().unwrap().expect("the group was joined");
    let _ = transport.event(link, ProgramEvent::Writable);
}

/// On a full socket the lane fills with what the session puts, and a droppable put that
/// finds it full waits its `wait_before_drop` for room and is dropped and counted; the lane's
/// mark then drops the next one at once. Once the socket takes datagrams again, the group's
/// session, stepped by the session's read, drains what was queued. Turned red, in either form,
/// by a group leg that drops a put uncounted.
#[test]
fn a_droppable_put_on_a_full_group_is_dropped_within_its_wait_and_counted() {
    let (member, stack, transport) = open_filling();
    stack.full.store(true, Ordering::SeqCst);

    // The first put's own write takes it off its lane, and the socket keeps it from writing
    // it; the two after it fill the lane.
    for _ in 0..3 {
        let took = put_with(&member, CongestionControl::Drop);
        assert!(
            took < Duration::from_secs(1),
            "a put on a lane with room took {took:?}"
        );
    }
    assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 0);

    let took = put_with(&member, CongestionControl::Drop);
    assert_eq!(
        member.group_congestion_drops(Priority::DEFAULT),
        1,
        "a droppable put on the full lane is dropped and counted"
    );
    assert!(took >= DROP_WAIT, "dropped after {took:?}, before its wait");
    assert!(
        took < Duration::from_secs(1),
        "a droppable put waited {took:?}"
    );

    let took = put_with(&member, CongestionControl::Drop);
    assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 2);
    #[cfg(feature = "transport-stats")]
    assert_eq!(
        member.transport_stats().tx.n_dropped,
        2,
        "the group's drops are the transport's, as the tokio group counts them"
    );
    assert!(
        took < DROP_WAIT,
        "the lane's mark drops a put at once, not after {took:?}"
    );

    let before = stack.sent.load(Ordering::SeqCst);
    writable(&stack, &transport);
    read_until(&member, "what was queued to leave", || {
        stack.sent.load(Ordering::SeqCst) >= before + 3
    });
    SessionDrive::close(&*member);
}

/// The replies a group's dispatch stages past the reply limit are dropped and charged to the
/// transport's drops, beside the session's own messages its lanes had no room for, as the tokio
/// engine's group charges every message it drops. No read runs, so nothing staged leaves.
#[cfg(feature = "transport-stats")]
#[test]
fn replies_past_the_reply_limit_are_the_transports_drops() {
    use wz_session_core::caps::MAX_MULTICAST_REPLIES;
    use wz_session_core::multicast_tx::MulticastTxItem;
    let (member, _stack, _transport) = open_filling();
    let reply = || {
        let push = wz_session_core::push_build::build_push_literal_with_meta(
            "demo/group/reply",
            b"r",
            &wz_session_core::metadata::PushMetadata::default(),
        )
        .expect("a push of a short key");
        MulticastTxItem::Push {
            push: Box::new(push),
            reliable: true,
            priority: Priority::DEFAULT,
        }
    };
    member.stage_group_replies(MAX_MULTICAST_REPLIES, reply);
    assert_eq!(
        member.transport_stats().tx.n_dropped,
        0,
        "CONTROL: the reply limit holds this many"
    );
    member.stage_group_replies(2, reply);
    assert_eq!(
        member.transport_stats().tx.n_dropped,
        2,
        "the replies past the limit are the transport's drops"
    );
    SessionDrive::close(&*member);
}

/// A droppable put that finds the session held asks the group's socket for room as it asks a
/// link's: the session's waits for room hold the group's, which answers congestion while the
/// socket is full and room once it takes datagrams again.
#[cfg(feature = "tx-held-wait")]
#[test]
fn a_held_session_asks_the_group_socket_for_room() {
    use crate::engine::Room;
    let (member, stack, transport) = open_filling();
    assert_eq!(
        member.rooms().within(1_000),
        Room::Free,
        "CONTROL: a socket with room"
    );
    stack.full.store(true, Ordering::SeqCst);
    // Each put offers the socket a datagram, which it refuses.
    for _ in 0..3 {
        put_with(&member, CongestionControl::Drop);
    }
    assert!(
        matches!(member.rooms().within(1_000), Room::Congested(faces) if faces.len() == 1),
        "the group's socket is the congestion, and the session's only face"
    );
    writable(&stack, &transport);
    assert_eq!(member.rooms().within(1_000), Room::Free);
    SessionDrive::close(&*member);
}

/// Under the pico profile a droppable put that finds the session held, here by a blocking put
/// waiting for room on the full group, is dropped at once and its caller is told, as pico's
/// put fails when its held transmit lock drops the message: the group's leg reports the held
/// session as a link's does.
// The session is held by a put of another thread, which only a session of several threads has.
#[cfg(feature = "threads")]
#[test]
fn under_the_pico_profile_a_put_behind_a_held_group_session_is_told() {
    let (member, stack, _transport) = open_filling();
    stack.full.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        put_with(&member, CongestionControl::Drop);
    }
    let blocking = {
        let member = member.clone();
        std::thread::spawn(move || put_with(&member, CongestionControl::Block))
    };
    // Long enough for the blocking put to take the session, well inside its wait.
    std::thread::sleep(CLOSE_WAIT / 3);
    let started = Instant::now();
    let dropped = member.publish_on_wire_all(
        "demo/group/full",
        &WireKey::literal(),
        b"behind",
        &PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_congestion_control(CongestionControl::Drop),
    );
    assert_eq!(dropped, Err(wz_capi_port::FanoutError::HeldConduit));
    assert!(
        started.elapsed() < CLOSE_WAIT / 3,
        "the droppable put waited {:?}",
        started.elapsed()
    );
    assert!(
        !blocking.is_finished(),
        "the blocking put still holds the session"
    );
    let waited = blocking.join().expect("the blocking put");
    assert!(
        waited >= CLOSE_WAIT,
        "the blocking put returned after {waited:?}"
    );
    SessionDrive::close(&*member);
}

/// A blocking put that finds the lane full waits its whole `wait_before_close` for room, and
/// is then dropped and counted, as the tokio engine's group drops it: a multicast transport
/// closes nothing on a congestion drop. The group is still joined, and carries the next put
/// once the socket takes datagrams again.
#[test]
fn a_blocking_put_on_a_full_group_waits_its_close_wait_and_closes_nothing() {
    let (member, stack, transport) = open_filling();
    stack.full.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        put_with(&member, CongestionControl::Drop);
    }

    let took = put_with(&member, CongestionControl::Block);
    assert!(took >= CLOSE_WAIT, "a blocking put returned after {took:?}");
    assert!(
        took < Duration::from_secs(5),
        "a blocking put waited {took:?}"
    );
    assert_eq!(member.group_congestion_drops(Priority::DEFAULT), 1);
    assert!(!SessionDrive::is_closed(&*member), "the session is open");
    assert_eq!(
        stack.closes.load(Ordering::SeqCst),
        0,
        "the group was not left"
    );

    let before = stack.sent.load(Ordering::SeqCst);
    writable(&stack, &transport);
    put_with(&member, CongestionControl::Block);
    assert!(stack.sent.load(Ordering::SeqCst) >= before + 2);
    SessionDrive::close(&*member);
}
