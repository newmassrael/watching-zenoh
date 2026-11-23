// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session on a clock the program sets, as the pico ABI's time base is: every timer of the
//! engine reads the clock it was opened with, so a lease runs on the program's time alone. The
//! router stand-in hangs (it reads and sends nothing and keeps its socket), so nothing but the
//! session's lease can end the session.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{PeerLists, SessionDrive, SessionEngine};
use wz_runtime_coop::ClockSource;
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};

use super::{config, CatchAll, Command, Router, LOOPBACK, ROUTER_ZID};
use crate::{CoopConfig, CoopEngine};

/// The session's lease, in milliseconds: short, so the wall clock passes it several times over
/// in a test.
const LEASE_MS: u64 = 500;

/// A clock that reads what the test set, in microseconds, and moves only when the test moves it.
#[derive(Clone)]
struct SetClock(Arc<AtomicU64>);

impl ClockSource for SetClock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A session of [`LEASE_MS`] dialled to `router` on `clock`; it redials none, so it ends with
/// its link.
fn open_on<C: ClockSource + Clone>(router: &Router, clock: C) -> Arc<CoopEngine<PosixLinks, C>> {
    CoopEngine::open(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        clock,
        PosixEntropy,
        CoopConfig {
            lease_ms: LEASE_MS,
            ..config(router)
        },
    )
    .expect("the session opens")
}

/// Three of its leases of the wall clock with the program's clock standing still, and the silent
/// router is still the session's peer; then the program's clock passes the lease and runs on, and
/// the router is expired and the session ends.
#[test]
fn a_lease_on_the_programs_clock_runs_on_that_clock_alone() {
    let router = Router::start(CatchAll::None);
    let now_us = Arc::new(AtomicU64::new(0));
    let engine = open_on(&router, SetClock(now_us.clone()));
    router.send(Command::Freeze);

    let quiet = Instant::now() + Duration::from_millis(3 * LEASE_MS + 100);
    while Instant::now() < quiet {
        SessionDrive::read(&*engine, false)
            .expect("the session stays open while the program's clock stands still");
    }
    assert_eq!(engine.peer_identities(), vec![(vec![ROUTER_ZID; 4], 0)]);

    now_us.store((LEASE_MS + 100) * 1000, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(5);
    while !SessionDrive::is_closed(&*engine) {
        assert!(
            Instant::now() < until,
            "the session outlived its lease once the program's clock passed it"
        );
        let _ = SessionDrive::read(&*engine, false);
        // The program's time runs on, past the bound of the close that follows the expiry.
        now_us.fetch_add(50_000, Ordering::SeqCst);
    }
}

/// The CONTROL: the same hanging router and lease on the system's clock, which runs. The session
/// ends within a few leases, so the harness sees an expiry when there is one, and the first test's
/// session standing is the program's clock's doing.
#[test]
fn a_lease_on_the_systems_clock_runs_out_with_the_wall_clock() {
    let router = Router::start(CatchAll::None);
    let engine = open_on(&router, PosixClock);
    router.send(Command::Freeze);
    let until = Instant::now() + Duration::from_secs(5);
    while !SessionDrive::is_closed(&*engine) {
        assert!(
            Instant::now() < until,
            "a hanging router was not expired by the wall clock"
        );
        let _ = SessionDrive::read(&*engine, false);
    }
}
