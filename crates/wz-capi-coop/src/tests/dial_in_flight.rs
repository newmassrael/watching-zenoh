// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A dial under way does not hold the session. The read task redials a lost link inside its step,
//! with the session held; a dial is begun there and asked at each step, never waited for, so a
//! call that takes the session (a close, a question about the peers) gets it while the dial's
//! connection is still being made.
//!
//! The links here dial the router for the session's open and, once the test says so, begin dials
//! that are never answered: the way of a connect to a host that does not answer, or one that
//! refuses only after retries of its own. Their dial that waits for its answer
//! (`SessionLinks::open_initiator`) takes [`DIAL_MS`], so a session that dialled that way would
//! hold its step, and every caller behind it, for as long.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{PeerLists, SessionDrive};
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::session_drive::{
    LinkOpenError, Locator, OpenedLink, PendingDial, SessionLinks,
};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};

use super::{config, CatchAll, Command, Router, LOOPBACK};
use crate::{CoopConfig, CoopEngine};

/// How long a dial made the waiting way takes to be refused.
const DIAL_MS: u64 = 3_000;

/// What a call behind the read task may take while a dial is under way: far below [`DIAL_MS`].
const PROMPT: Duration = Duration::from_millis(1_000);

/// What the host's links pump.
type Pump = <PosixLinks as SessionLinks>::Pump;

/// A dial of [`SlowDials`]: the host's own, or one whose connection is never made nor refused.
enum SlowDial {
    Host(<PosixLinks as SessionLinks>::Dial),
    Unanswered,
}

impl PendingDial<Pump> for SlowDial {
    fn poll(&mut self) -> Option<Result<OpenedLink<Pump>, LinkOpenError>> {
        match self {
            SlowDial::Host(dial) => dial.poll(),
            SlowDial::Unanswered => None,
        }
    }
}

impl From<OpenedLink<Pump>> for SlowDial {
    fn from(opened: OpenedLink<Pump>) -> Self {
        SlowDial::Host(opened.into())
    }
}

/// The host's links, whose dials, once `slow` is set, are never answered when begun and refused
/// after [`DIAL_MS`] when made the waiting way; each is counted.
struct SlowDials {
    inner: PosixLinks,
    slow: Arc<AtomicBool>,
    dials: Arc<AtomicUsize>,
}

impl SessionLinks for SlowDials {
    type Pump = Pump;

    type Dial = SlowDial;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        self.inner.open_acceptor(port)
    }

    // The session's tables reach the links it dials through, as they reach the host's links.
    fn lend_buffers(&mut self, tables: LinkTables) {
        self.inner.lend_buffers(tables);
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        if !self.slow.load(Ordering::SeqCst) {
            return self.inner.open_initiator(to);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(DIAL_MS));
        Err(LinkOpenError::Refused)
    }

    fn begin_initiator(&self, to: Locator) -> Result<SlowDial, LinkOpenError> {
        if !self.slow.load(Ordering::SeqCst) {
            return self.inner.begin_initiator(to).map(SlowDial::Host);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        Ok(SlowDial::Unanswered)
    }
}

/// The session opens over a `tcp/` dial begun without waiting; its router goes, and the read task
/// redials it with a dial that is never answered. Asked about its peers from another thread, the
/// session answers promptly, and its close, which stops the read task first, returns promptly.
#[test]
fn a_dial_under_way_holds_neither_the_session_nor_its_close() {
    let router = Router::start(CatchAll::None);
    let slow = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let engine = CoopEngine::open(
        SlowDials {
            inner: PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
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
