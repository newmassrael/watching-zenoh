// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The acceptor e2e on the fixed-memory profile, on the host's real lwIP build
//! (fixed-memory step S9c): the SAME scenario `host_acceptor_e2e` runs on the heap
//! form (`InitSyn` -> `InitAck` -> `OpenSyn` with the real round-tripped cookie ->
//! `OpenAck` -> `Established`, then an application `Frame` dispatched), over statics
//! the image declares, with the session opened by the listener's admission and run as
//! a task of a static runtime.
//!
//! What it adds is the heap counted over the WHOLE run, from the listener's bind to the
//! verdict: the sockets, the session's slot, its pump and task, the handshake with its
//! cookie minted and echoed, the reactive peer's frames and the Frame's dispatch. The
//! count is ZERO. When it is not, the allocations are read back to the crate that asked
//! for each (`Measurement::owners`), so a regression names the crate it came from.
//!
//! One run per process: lwIP is process-global and the listener's socket stays bound
//! for the life of its statics, so a second run on another set of statics would find
//! the port taken. A run on statics that already ran is refused and is checked here,
//! since it touches nothing.
#![cfg(all(feature = "fixed-memory", lwip_real_build))]

use wz_mcu_session_acceptor::{
    run_acceptor_e2e_fixed, AcceptorE2eOutcome, AcceptorStage, AcceptorStatics, ClockSource,
    DataMode, FixtureEntropy,
};

#[path = "../../wz-session-lwip/tests/support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// Frozen host clock: no handshake or lease deadline ever elapses, so the handshake
/// advances purely on crafted-frame arrival and the verdict is decided by the cookie
/// round-trip and the Frame dispatch, never by a timing race.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn the_fixed_acceptor_reaches_established_with_the_heap_asked_for_nothing() {
    static STATICS: AcceptorStatics<FrozenClock, FixtureEntropy> = AcceptorStatics::new();

    // The stage log is a fixed array: a `Vec` here would be the test's own allocation
    // inside the window it counts.
    let mut stages = [None::<AcceptorStage>; 4];
    let mut entered = 0;
    let m = Measurement::attributing();
    let (report, n) = m.count("the whole run", || {
        run_acceptor_e2e_fixed(
            &STATICS,
            FrozenClock,
            FixtureEntropy,
            DataMode::WholeFrame,
            || {},
            |stage| {
                stages[entered] = Some(stage);
                entered += 1;
            },
        )
    });
    let owners = m.owners();
    println!("the whole run: {n} allocation(s), by crate: {owners:?}");

    assert_eq!(
        report.outcome,
        AcceptorE2eOutcome::EstablishedAndDispatched,
        "the acceptor must reach Established over lwIP loopback and dispatch the \
         post-handshake application Frame; report = {report:#?}"
    );
    assert_eq!(
        stages[..entered],
        [
            Some(AcceptorStage::AwaitInitAck),
            Some(AcceptorStage::AwaitOpenAck),
            Some(AcceptorStage::AwaitDispatch),
        ],
        "a clean WholeFrame run enters each peer stage once, in order"
    );
    assert_eq!(
        (report.init_ack_action_fired, report.open_ack_action_fired),
        (1, 1),
        "one InitAck and one OpenAck were sent by the acceptor's actions"
    );
    assert!(
        report.peer_cookie_len > 0,
        "the peer echoed the cookie the acceptor really minted"
    );
    assert_eq!(
        n, 0,
        "the whole acceptor e2e costs the heap nothing; the allocations were asked for by \
         {owners:?}"
    );

    // THE REFUSAL: a second run on statics that already ran is refused by the
    // runtime's cell, answers the report of a run that never established, and
    // touches nothing (no port is bound a second time).
    let again = run_acceptor_e2e_fixed(
        &STATICS,
        FrozenClock,
        FixtureEntropy,
        DataMode::WholeFrame,
        || {},
        |_| {},
    );
    assert_eq!(
        again.outcome,
        AcceptorE2eOutcome::NotEstablished,
        "a second run on one set of statics is refused: {again:#?}"
    );
}
