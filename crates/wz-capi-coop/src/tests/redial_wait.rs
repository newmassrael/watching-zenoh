// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The wait between two dials of a lost link is counted from the end of the dial that failed. A
//! dial runs in the read step, which holds the session, and a host may take a while to refuse one
//! (Windows retries a refused loopback connect for about two seconds); a wait counted from before
//! the dial would be over by then, and the read task would dial again at once, holding the session
//! through dial after dial so that no publish and no close could take it.
//!
//! The links here refuse every dial once the test says so, and each refusal moves the session's
//! clock on by [`DIAL_US`], longer than the redial wait, as such a host's would; nothing else
//! moves the clock.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine};
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::session_drive::{LinkOpenError, Locator, OpenedLink, SessionLinks};
use wz_runtime_coop::ClockSource;
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::PosixEntropy;

use super::{config, CatchAll, Command, Router, LOOPBACK};
use crate::{CoopConfig, CoopEngine};

/// The session's wait between two rounds of dials, in milliseconds.
const REDIAL_MS: u64 = 1_000;

/// How far the clock moves while one refused dial blocks: past the redial wait.
const DIAL_US: u64 = 2_000_000;

/// A clock that reads what the test and the links set, in microseconds.
#[derive(Clone)]
struct SetClock(Arc<AtomicU64>);

impl ClockSource for SetClock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The host's links, whose dials, once `refusing` is set, are each refused after [`DIAL_US`] of
/// the session's clock, and counted.
struct SlowRefusals {
    inner: PosixLinks,
    clock: Arc<AtomicU64>,
    refusing: Arc<AtomicBool>,
    dials: Arc<AtomicUsize>,
}

impl SessionLinks for SlowRefusals {
    type Pump = <PosixLinks as SessionLinks>::Pump;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        self.inner.open_acceptor(port)
    }

    // The session's tables reach the links it dials through, as they reach the host's links.
    fn lend_buffers(&mut self, tables: LinkTables) {
        self.inner.lend_buffers(tables);
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        if !self.refusing.load(Ordering::SeqCst) {
            return self.inner.open_initiator(to);
        }
        self.dials.fetch_add(1, Ordering::SeqCst);
        self.clock.fetch_add(DIAL_US, Ordering::SeqCst);
        Err(LinkOpenError::Refused)
    }
}

/// A lost link whose dials are each refused after longer than the redial wait is dialled once and
/// then waited for: ten reads later, with the clock where the refusal left it, there has been one
/// dial. Once the clock has run the whole wait past the end of that dial, the next read dials
/// again, so the wait is the session's and not a link that is never dialled.
#[test]
fn a_dial_slower_than_the_redial_wait_is_still_followed_by_the_wait() {
    let router = Router::start(CatchAll::None);
    let now_us = Arc::new(AtomicU64::new(0));
    let refusing = Arc::new(AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let links = SlowRefusals {
        inner: PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        clock: now_us.clone(),
        refusing: refusing.clone(),
        dials: dials.clone(),
    };
    let engine = CoopEngine::open(
        links,
        SetClock(now_us.clone()),
        PosixEntropy,
        CoopConfig {
            redial_ms: Some(REDIAL_MS),
            ..config(&router)
        },
    )
    .expect("the session opens");

    refusing.store(true, Ordering::SeqCst);
    router.send(Command::Close);
    drop(router);
    let until = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < until,
            "the lost link was not dialled again"
        );
        let _ = SessionDrive::read(&*engine, false);
    }
    assert!(engine.peer_identities().is_empty(), "the link is lost");

    for _ in 0..10 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "a refusal that took longer than the redial wait was dialled again without a wait"
    );
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the session outlives its link"
    );

    now_us.fetch_add(REDIAL_MS * 1000, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < until,
            "the wait past the end of the dial ran out and nothing was dialled"
        );
        let _ = SessionDrive::read(&*engine, false);
    }
}
