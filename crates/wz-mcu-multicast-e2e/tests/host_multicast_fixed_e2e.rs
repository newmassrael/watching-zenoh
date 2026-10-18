// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast e2e on the fixed-memory profile, on the host's real lwIP build
//! (fixed-memory step S9c): the SAME scenario `host_multicast_e2e` runs on the heap form
//! (a peer JOIN admitted, an oversize Put split into a fragment chain, reassembled into
//! one `Push`, then the graceful departure), with the group socket, the pump and the
//! runtime in statics.
//!
//! What it adds is the heap counted over the WHOLE run and read back to the crate that
//! asked for each allocation. Built without the `heap` feature (fixed-memory step S9e,
//! `--no-default-features --features fixed-memory,loopif-multicast`) no crate of the
//! graph links `alloc` for the session tier: the JOIN is written into an array, the
//! queued `Put` is framed into one lent buffer, and each record received is lent where
//! its datagram lies. The count over the whole run is then ZERO, which is what is held.
//! Built with `heap` the session tier's owned forms are in play and still allocate, so
//! what is held is the weaker claim the step before this one held: that none of it is
//! asked for by a SHELL crate (the e2e, the lwIP session glue, the link or the
//! cooperative runtime).
//!
//! One run per process: lwIP is process-global and its group membership is the
//! process's. A run on statics that already ran is refused and is checked here, since
//! it touches nothing.
#![cfg(all(
    feature = "fixed-memory",
    feature = "loopif-multicast",
    lwip_real_build
))]

use wz_mcu_multicast_e2e::{
    run_multicast_e2e_fixed, ClockSource, LwipLink, MulticastE2eStatics, MulticastOutcome,
    MulticastStage,
};

#[path = "../../wz-session-lwip/tests/support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// Frozen host clock, as the heap form's test has: no JOIN-interval or lease deadline
/// ever elapses, so the fragment chain reassembles purely on arrival order.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

/// The crates that may still ask the heap for memory when the build names `heap`: the
/// session tier's owned forms. Everything else is the shell (the e2e, the lwIP session
/// glue, the link, the cooperative runtime) or an allocation no workspace frame owns,
/// and neither may ask. The list is the allowed set and not the shell's names so that
/// an allocation whose frames carry no owner is a failure and not a pass.
#[cfg(feature = "heap")]
const SESSION_TIER: [&str; 4] = [
    "crates/wz-session-core",
    "crates/wz-codecs",
    "backends/rust/forge-runtime",
    "backends/rust/portable-bytes",
];

#[test]
fn the_fixed_multicast_profile_round_trips_with_no_shell_crate_asking_the_heap() {
    static STATICS: MulticastE2eStatics<FrozenClock> = MulticastE2eStatics::new();

    let link = LwipLink::init_static();
    link.route_multicast_over_loopback()
        .expect("the loopif-multicast build routes multicast TX over the loop netif");

    let mut stages = [None::<MulticastStage>; 4];
    let mut entered = 0;
    let m = Measurement::attributing();
    let (report, n) = m.count("the whole run", || {
        run_multicast_e2e_fixed(&STATICS, link, FrozenClock, |stage| {
            stages[entered] = Some(stage);
            entered += 1;
        })
    });
    let owners = m.owners();
    println!("the whole run: {n} allocation(s), by crate: {owners:?}");

    assert_eq!(
        stages[..entered],
        [
            Some(MulticastStage::JoinGroup),
            Some(MulticastStage::RoundTrip),
            Some(MulticastStage::Departure),
        ],
        "a clean run enters each stage once, in order"
    );
    assert!(
        report.join_ok,
        "the group socket binds and joins; {report:#?}"
    );
    assert_eq!(
        report.outcome,
        Some(MulticastOutcome::IterationLimit),
        "the bounded drive runs to its iteration limit; {report:#?}"
    );
    assert!(
        report.tx_fragmented,
        "the Put splits at the 64-byte budget; {report:#?}"
    );
    assert!(
        report.peer_admitted,
        "the crafted peer JOIN is admitted; {report:#?}"
    );
    assert!(
        !report.saw_drop,
        "the in-order chain reassembles cleanly; {report:#?}"
    );
    assert!(
        report.saw_push,
        "the fragmented Put reassembles into one Push; {report:#?}"
    );
    assert!(
        report.departed,
        "the same pump, asked to stop, leaves the group announced; {report:#?}"
    );

    // With the heap named the session tier's owned forms are in play, and the claim is
    // that no SHELL crate asks for memory.
    #[cfg(feature = "heap")]
    {
        let asked_by_the_shell: Vec<_> = owners
            .keys()
            .filter(|owner| !SESSION_TIER.iter().any(|tier| owner.ends_with(tier)))
            .collect();
        assert!(
            asked_by_the_shell.is_empty(),
            "no shell crate may ask the heap for memory, and {asked_by_the_shell:?} did; \
             every owner: {owners:?}"
        );
    }
    // Without it nothing is in play that could ask: the whole run, the session tier
    // included, takes nothing from the allocator.
    #[cfg(not(feature = "heap"))]
    assert_eq!(
        n, 0,
        "a build with no heap feature allocates nothing over the whole run; by crate: \
         {owners:?}"
    );

    // THE REFUSAL: a second run on statics that already ran is refused by the
    // runtime's cell, answers the report of a run that never joined, and touches nothing.
    let again = run_multicast_e2e_fixed(&STATICS, link, FrozenClock, |_| {});
    assert!(
        !again.join_ok && again.outcome.is_none(),
        "a second run on one set of statics is refused: {again:#?}"
    );
}
