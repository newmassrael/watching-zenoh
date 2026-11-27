// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session on a clock the program sets, as the pico ABI's time base is: every timer of the
//! engine reads the clock it was opened with, so a lease runs on the program's time alone. The
//! router stand-in hangs (it reads and sends nothing and keeps its end), so nothing but the
//! session's lease can end the session.
//!
//! The session runs in the simulated world (`tests::sim`), whose one clock is the program's: it
//! moves only when the test moves it, and a read's wait takes none of it. What a test here holds
//! is that the lease is read against that clock, and that no read and no wait counts as time;
//! that the engine names no clock of the host is held by its build without `std`, which has none
//! to name.

use wz_capi_port::{PeerLists, SessionDrive};

use super::sim::{Sim, SimEngine};
use super::{CatchAll, ROUTER_ZID};
use crate::{CoopConfig, EngineHold};

/// The seed every test here runs on: the session's and the stand-in's entropy.
const SEED: u64 = 0x5eed_c10c;

/// The session's lease, in milliseconds.
const LEASE_MS: u64 = 500;

/// The reads made with the program's clock standing still: at the config's wait of 100 ms each,
/// a dozen leases of a clock that ran.
const STILL_READS: usize = 64;

/// How far the program's clock moves after each read once it has passed the lease: past the
/// bound of the close that follows the expiry within a few reads.
const STEP_MS: u64 = 50;

/// The most reads a test makes waiting for the session to end: a bound against a lease that
/// never runs out, which no expiry a test waits for comes near.
const MOST_READS: usize = 1_000;

/// A session of [`LEASE_MS`] dialled to a stand-in that hangs from the open on; it redials none,
/// so it ends with its link.
fn hung(sim: &Sim) -> (super::sim::StandIn, EngineHold<SimEngine>) {
    let router = sim.stand_in(CatchAll::None);
    let engine = sim.open(CoopConfig {
        lease_ms: LEASE_MS,
        ..sim.config()
    });
    router.freeze();
    (router, engine)
}

/// Read `engine` until it ends, the program's clock moved on by [`STEP_MS`] after each read:
/// how many reads that took.
fn reads_until_closed(sim: &Sim, engine: &SimEngine, what: &str) -> usize {
    let mut reads = 0;
    while !SessionDrive::is_closed(engine) {
        assert!(reads < MOST_READS, "{what}");
        let _ = SessionDrive::read(engine, false);
        sim.advance_ms(STEP_MS);
        reads += 1;
    }
    reads
}

/// Reads with the program's clock standing still, as many as a dozen leases of a clock that ran
/// would take, and the silent stand-in is still the session's peer; then the program's clock
/// passes the lease and runs on, and the stand-in is expired and the session ends.
#[test]
fn a_lease_on_the_programs_clock_runs_on_that_clock_alone() {
    let sim = Sim::new(SEED);
    let (_router, engine) = hung(&sim);

    for _ in 0..STILL_READS {
        SessionDrive::read(&*engine, false)
            .expect("the session stays open while the program's clock stands still");
    }
    assert_eq!(engine.peer_identities(), vec![(vec![ROUTER_ZID; 4], 0)]);

    sim.advance_ms(LEASE_MS + 100);
    reads_until_closed(
        &sim,
        &engine,
        "the session outlived its lease once the program's clock passed it",
    );
}

/// The CONTROL: the same hanging stand-in and lease, on the program's clock running from the
/// open on. The session ends once the clock has passed its lease and not before, so the reads see
/// an expiry when there is one, and the first test's session standing is the still clock's doing.
#[test]
fn a_lease_on_a_running_clock_runs_out_with_that_clock() {
    let sim = Sim::new(SEED);
    let (_router, engine) = hung(&sim);
    let reads = reads_until_closed(
        &sim,
        &engine,
        "a hanging stand-in was not expired by the running clock",
    );
    assert!(
        reads as u64 * STEP_MS >= LEASE_MS,
        "the session ended after {reads} reads of {STEP_MS} ms, inside its {LEASE_MS} ms lease"
    );
}
