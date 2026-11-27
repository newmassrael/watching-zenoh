// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A dial under way does not hold the session. The read task redials a lost link inside its step,
//! with the session held; a dial is begun there and asked at each step, never waited for, so a
//! call that takes the session (a close, a question about the peers) gets it while the dial's
//! connection is still being made. A program of one thread redials in its own read, the same
//! step, which a dial under way holds no longer than a step that dials nothing.
//!
//! The links here dial the router for the session's open and, once the test says so, begin dials
//! that are never answered: the way of a connect to a host that does not answer, or one that
//! refuses only after retries of its own. Their dial that waits for its answer
//! (`SessionLinks::open_initiator`) takes [`DIAL_MS`], so a session that dialled that way would
//! hold its step, and every caller behind it, for as long.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::tests::{host_links, PosixLinks};
use crate::LinkCount;
use wz_capi_port::{PeerLists, SessionDrive};
use wz_runtime_coop::link_cells::CountKind;
use wz_runtime_coop::session_drive::{
    LinkOpenError, Locator, OpenedLink, PendingDial, SessionLinks,
};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::link_life::LinkPhase;

use super::{config, CatchAll, Command, Router, LOOPBACK};
use crate::{CoopConfig, CoopEngine};

/// How long a dial made the waiting way takes to be refused.
const DIAL_MS: u64 = 3_000;

/// What a call behind the read task may take while a dial is under way: far below [`DIAL_MS`].
const PROMPT: Duration = Duration::from_millis(1_000);

/// What the host's links pump.
type Pump = <PosixLinks as SessionLinks<LinkCount>>::Pump;

/// A dial of [`SlowDials`]: the host's own, or, with none, one whose connection is never made nor
/// refused.
struct SlowDial(Option<<PosixLinks as SessionLinks<LinkCount>>::Dial>);

impl PendingDial<Pump, LinkCount> for SlowDial {
    fn poll(&mut self) -> Option<Result<OpenedLink<Pump, LinkCount>, LinkOpenError>> {
        self.0.as_mut()?.poll()
    }
}

impl From<OpenedLink<Pump, LinkCount>> for SlowDial {
    fn from(opened: OpenedLink<Pump, LinkCount>) -> Self {
        SlowDial(Some(opened.into()))
    }
}

/// The host's links, whose dials, once `slow` is set, are never answered when begun and refused
/// after [`DIAL_MS`] when made the waiting way; each is counted.
struct SlowDials {
    inner: PosixLinks,
    slow: Arc<AtomicBool>,
    dials: Arc<AtomicUsize>,
}

impl SessionLinks<LinkCount> for SlowDials {
    type Pump = Pump;

    type Dial = SlowDial;

    type Waits = <PosixLinks as SessionLinks<LinkCount>>::Waits;

    fn waits(&self) -> Self::Waits {
        self.inner.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump, LinkCount>, LinkOpenError> {
        self.inner.open_acceptor(port)
    }

    // The session's tables reach the links it dials through, as they reach the host's links.
    fn lend_buffers(&mut self, tables: <LinkCount as CountKind>::Buffers) {
        self.inner.lend_buffers(tables);
    }

    fn open_initiator(
        &self,
        to: Locator,
    ) -> Result<OpenedLink<Self::Pump, LinkCount>, LinkOpenError> {
        if !self.slow.load(Ordering::SeqCst) {
            return self.inner.open_initiator(to);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(DIAL_MS));
        Err(LinkOpenError::Refused)
    }

    fn begin_initiator(&self, to: Locator) -> Result<SlowDial, LinkOpenError> {
        if !self.slow.load(Ordering::SeqCst) {
            return self
                .inner
                .begin_initiator(to)
                .map(|dial| SlowDial(Some(dial)));
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        Ok(SlowDial(None))
    }
}

/// The session opens over a `tcp/` dial begun without waiting; its router goes, and the read task
/// redials it with a dial that is never answered. Asked about its peers from another thread, the
/// session answers promptly, and its close, which stops the read task first, returns promptly.
#[cfg(feature = "threads")]
#[test]
fn a_dial_under_way_holds_neither_the_session_nor_its_close() {
    let router = Router::start(CatchAll::None);
    let slow = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let engine = CoopEngine::open(
        SlowDials {
            inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            slow: slow.clone(),
            dials: dials.clone(),
        },
        PosixClock,
        PosixEntropy,
        CoopConfig {
            redial_ms: Some(50),
            ..config(&router)
        },
    )
    .expect("the session opens over a dial begun without waiting");
    assert!(
        SessionDrive::start_read_task(&*engine).is_ok(),
        "a host gives the read task a thread"
    );

    slow.store(true, Ordering::SeqCst);
    router.send(Command::Close);
    drop(router);
    let until = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < until,
            "the lost link was not dialled again"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    // The lost link is dialled again at once from the first endpoint, and the dial under way is
    // the life of the face's record: a read that drove a life of its own, or backed off before
    // dialling a link that was up, leaves the face's life elsewhere.
    assert_eq!(
        engine.dial_phase(),
        Some(LinkPhase::Dialing { row: 0 }),
        "the face's life dials the first endpoint again"
    );

    let asked = Instant::now();
    assert!(engine.peer_identities().is_empty(), "the link is lost");
    assert!(
        asked.elapsed() < PROMPT,
        "a question about the peers waited {:?} behind a dial under way",
        asked.elapsed()
    );

    let closing = Instant::now();
    SessionDrive::close(&*engine);
    assert!(
        closing.elapsed() < PROMPT,
        "the close waited {:?} behind a dial under way",
        closing.elapsed()
    );
    assert!(SessionDrive::is_closed(&*engine));
}

/// The same in the form of one thread, which starts no read task: the program's own reads redial
/// the lost link with a dial that is never answered, and each returns promptly while the dial is
/// under way, as does the session's close. Turned red by a read that redials the waiting way
/// (`SessionLinks::open_initiator`), which holds it for [`DIAL_MS`].
#[cfg(not(feature = "threads"))]
#[test]
fn a_dial_under_way_holds_no_read_of_one_thread() {
    let router = Router::start(CatchAll::None);
    let slow = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let engine = CoopEngine::open(
        SlowDials {
            inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            slow: slow.clone(),
            dials: dials.clone(),
        },
        PosixClock,
        PosixEntropy,
        CoopConfig {
            redial_ms: Some(50),
            ..config(&router)
        },
    )
    .expect("the session opens over a dial begun without waiting");

    slow.store(true, Ordering::SeqCst);
    router.send(Command::Close);
    drop(router);
    let until = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < until,
            "the lost link was not dialled again"
        );
        let read = Instant::now();
        let _ = SessionDrive::read(&*engine, false);
        assert!(
            read.elapsed() < PROMPT,
            "a read took {:?} with a dial under way",
            read.elapsed()
        );
    }
    // The lost link is dialled again at once from the first endpoint, and the dial under way is
    // the life of the face's record: a read that drove a life of its own, or backed off before
    // dialling a link that was up, leaves the face's life elsewhere.
    assert_eq!(
        engine.dial_phase(),
        Some(LinkPhase::Dialing { row: 0 }),
        "the face's life dials the first endpoint again"
    );

    // The dial begun, a read asks it and goes on.
    let read = Instant::now();
    let _ = SessionDrive::read(&*engine, false);
    assert!(
        read.elapsed() < PROMPT,
        "a read waited {:?} behind a dial under way",
        read.elapsed()
    );
    assert!(engine.peer_identities().is_empty(), "the link is lost");

    let closing = Instant::now();
    SessionDrive::close(&*engine);
    assert!(
        closing.elapsed() < PROMPT,
        "the close waited {:?} behind a dial under way",
        closing.elapsed()
    );
    assert!(SessionDrive::is_closed(&*engine));
}

/// A face an attach dials with a dial that is never answered is given up once the open's time is
/// over, though nothing its dial brings moves its life: the read looks at that life by the time
/// the attach left it, and the face is dialled once. CONTROL: the dial role's link, up over the
/// router, stands. Turned red by a read that keeps no time for a dial it did not begin, whose
/// face then dials for good (`DirectSlot::wake_for_record_dial`).
#[cfg(all(feature = "listen", not(wz_round)))]
#[test]
fn an_attached_dial_never_answered_is_given_up_in_its_time() {
    let router = Router::start(CatchAll::None);
    let slow = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let engine = CoopEngine::open(
        SlowDials {
            inner: host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            slow: slow.clone(),
            dials: dials.clone(),
        },
        PosixClock,
        PosixEntropy,
        CoopConfig {
            open_timeout_ms: 300,
            ..config(&router)
        },
    )
    .expect("the session opens over a dial begun without waiting");
    #[cfg(feature = "threads")]
    assert!(
        SessionDrive::start_read_task(&*engine).is_ok(),
        "a host gives the read task a thread"
    );

    slow.store(true, Ordering::SeqCst);
    engine
        .attach_face("tcp/127.0.0.1:7")
        .expect("the attach begins its dial");
    assert_eq!(dials.load(Ordering::SeqCst), 1, "the attach began one dial");
    assert!(
        matches!(engine.face_phase(1), Some(LinkPhase::Dialing { .. })),
        "the attached face dials"
    );

    let until = Instant::now() + Duration::from_secs(5);
    while matches!(engine.face_phase(1), Some(LinkPhase::Dialing { .. })) {
        assert!(
            Instant::now() < until,
            "the attached dial was never given up"
        );
        #[cfg(feature = "threads")]
        std::thread::sleep(Duration::from_millis(5));
        #[cfg(not(feature = "threads"))]
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "an attached face is dialled once"
    );
    assert_eq!(
        engine.dial_phase(),
        Some(LinkPhase::Up),
        "CONTROL: the dial role's link stands"
    );
    SessionDrive::close(&*engine);
}
