// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The state of a session whose shape the build fixes, opened as the head of the one block its
//! open reserves: a config the region admits takes one reservation, the region zeroed at its start
//! and the arena after it, given back once when both are let go, and a config it refuses, or a
//! memory with none to give, takes nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use wz_session_core::bounded::Arena;
use wz_session_core::limit_binding::{Quota, UnlentRows};

use super::client_config;
use crate::arena::{
    AllocatorMemory, ArenaLimit, ArenaMemory, ArenaPlan, ArenaRefused, ArenaRegion, PlanShape,
    SessionArena,
};
use crate::region::{RegionBlock, StateRegion};
use crate::CoopConfig;

/// The allocator, counting its reservations and what it is given back, and keeping the bytes it
/// was last asked for.
struct Counted {
    reserves: AtomicUsize,
    releases: AtomicUsize,
    last: AtomicUsize,
}

impl Counted {
    const fn new() -> Self {
        Self {
            reserves: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            last: AtomicUsize::new(0),
        }
    }

    /// The reservations and the releases so far.
    fn counts(&self) -> (usize, usize) {
        (
            self.reserves.load(Ordering::SeqCst),
            self.releases.load(Ordering::SeqCst),
        )
    }
}

impl ArenaMemory for Counted {
    fn reserve(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        self.last.store(layout.size(), Ordering::SeqCst);
        AllocatorMemory.reserve(layout)
    }

    unsafe fn release(&self, base: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
        self.releases.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the caller's contract: the allocator gave `base` for `layout`, given back once.
        unsafe { AllocatorMemory.release(base, layout) }
    }
}

/// A memory with none to give.
struct NoMemory;

impl ArenaMemory for NoMemory {
    fn reserve(&self, _layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        None
    }

    unsafe fn release(&self, _base: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
        unreachable!("a memory that gave nothing is given nothing back");
    }
}

/// The region a client of `config`'s own shape and limits lays out.
fn region_of(config: &CoopConfig) -> ArenaRegion {
    ArenaRegion::of(PlanShape::of(config), config.limits)
        .expect("the client's limits lay a region out")
}

/// The plan `region` lays out for `config`, or the limit it refuses the config under.
fn plan_of(region: &ArenaRegion, config: &CoopConfig) -> Result<ArenaPlan, ArenaRefused> {
    let mut plan = ArenaPlan::vacant();
    region.lay_out_on(&mut plan, config)?;
    Ok(plan)
}

/// The state of a config its region admits lies at the head of one reservation, placed over its
/// rows there, and is given back once, with the arena after it, when both are let go: the region
/// first, dropped in place, then the arena. Turned red by an open that reserves the state apart
/// from its arena, or by a region's drop that gives the block back too.
#[test]
fn a_state_opens_at_the_head_of_one_reservation_given_back_once() {
    static OPENED: Counted = Counted::new();
    let config = client_config();
    let region = region_of(&config);
    let plan = plan_of(&region, &config).expect("the region admits its own");
    let (arena, at) =
        SessionArena::reserve_after::<StateRegion>(&plan, &OPENED).expect("the host has it");
    // SAFETY: the head is a zeroed `StateRegion` this test alone reaches, held before the arena
    // and dropped first.
    let state = unsafe { RegionBlock::within(at) };
    // SAFETY: as above; no key or table of the region outlives the block.
    let _keys = unsafe { StateRegion::place(state.as_ptr(), region.limits()) };
    assert_eq!(
        OPENED.counts(),
        (1, 0),
        "one block, the region's and the arena's"
    );
    drop(state);
    assert_eq!(
        OPENED.counts(),
        (1, 0),
        "the region gives nothing back itself"
    );
    drop(arena);
    assert_eq!(
        OPENED.counts(),
        (1, 1),
        "the arena gives the block back once"
    );
}

/// A config that dials more endpoints than the region holds rows for, or holds limits it was not
/// laid out for, is refused under the limit that differs before anything is reserved; a memory
/// with none to give refuses the open with the bytes of the whole block, the region's and the
/// arena's. Turned red by a region that lays a plan out for a config it was not laid out for, or by
/// a refusal that names the arena's bytes alone.
#[test]
fn a_state_refused_by_its_region_or_its_memory_reserves_nothing() {
    static REFUSED: Counted = Counted::new();
    let config = client_config();
    let region = region_of(&config);
    let dials = config.endpoints.len();
    let more = CoopConfig {
        endpoints: vec![String::from("udp/127.0.0.1:7447"); dials + 1],
        ..client_config()
    };
    assert_eq!(
        plan_of(&region, &more).err(),
        Some(ArenaRefused::Limit {
            limit: ArenaLimit::MaxStaticConnect,
            why: UnlentRows::OverCeiling {
                value: dials + 1,
                ceiling: dials,
            },
        })
    );
    let mut limits = config.limits;
    let fewer = if limits.max_subscriptions() == Quota::at_most(1) {
        2
    } else {
        1
    };
    limits
        .select_max_subscriptions(Quota::at_most(fewer))
        .expect("the build admits a few subscribers");
    assert_ne!(limits, config.limits, "CONTROL: the limits differ");
    let other = CoopConfig {
        limits,
        ..client_config()
    };
    assert_eq!(
        plan_of(&region, &other).err(),
        Some(ArenaRefused::Limit {
            limit: ArenaLimit::LimitsDifferFromBuild,
            why: UnlentRows::NoCeiling,
        })
    );
    assert_eq!(REFUSED.counts(), (0, 0));
    let plan = plan_of(&region, &config).expect("the region admits its own");
    let bytes = plan.reserved_bytes().expect("within the address space");
    let head = Arena::span(core::mem::size_of::<StateRegion>()).expect("a region in the space");
    assert_eq!(
        SessionArena::reserve_after::<StateRegion>(&plan, &NoMemory).err(),
        Some(ArenaRefused::NoMemory {
            bytes: head + bytes,
        })
    );
}

/// An open of a session whose shape the build fixes reserves one block, and its size is the
/// region's span at its head and the arena the open's plan lays out after it: the region asks
/// nothing apart, and the arena holds nothing the region does. Turned red by an open that reserves
/// the region or a table apart from the block, or a block sized by anything but the two.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_open_reserves_one_block_of_its_region_and_its_plan() {
    use super::{CatchAll, Engine, Router, LOOPBACK};
    use crate::arena::{HeldPlaces, OpenStorage, PlanFrom};
    use wz_runtime_posix::links::PosixLinks;
    use wz_runtime_posix::stream::PosixTcpDial;
    use wz_runtime_posix::{PosixClock, PosixEntropy};
    use wz_session_core::bounded::ARENA_ALIGN;

    static BLOCK: Counted = Counted::new();
    let router = Router::start(CatchAll::None);
    let region: &'static ArenaRegion = Box::leak(Box::new(region_of(&super::config(&router))));
    let engine = Engine::open_made_in(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || super::config(&router),
        wz_session_core::policy::SessionPolicy::defaults(),
        crate::OpenKeyIds::none(),
        OpenStorage {
            memory: &BLOCK,
            held: HeldPlaces::NONE,
            plan: PlanFrom::Region(region),
        },
    )
    .expect("the session opens in its region");
    assert_eq!(
        BLOCK.counts(),
        (1, 0),
        "one block for the region and its arena"
    );
    let head = Arena::span(core::mem::size_of::<StateRegion>()).expect("a region in the space");
    assert_eq!(
        BLOCK.last.load(Ordering::SeqCst),
        head + engine.arena_bytes().max(ARENA_ALIGN),
        "the block is the region's span and the plan's arena"
    );
}

/// What the state owns and its tasks reach by handles that count nothing (its round, the planes of
/// its gets, its queryables and its faces' watchers, the places it lends its Router and its registry
/// in for a step) lies
/// in its region (`crate::engine::StatePlaces`), so the arena an open lays out holds no place of
/// them. Turned red by a plan that still reserves one, which the open would leave unused, or by a
/// region too small to hold the round.
#[test]
fn the_states_own_values_lie_in_its_region_and_not_in_its_arena() {
    let plan = crate::arena::ArenaPlan::of(
        &client_config(),
        &wz_session_core::limits::SessionLimits::defaults(),
    )
    .expect("the client's limits lay an arena out");
    for part in [
        "delivery round",
        "registry lend",
        "router lend",
        "query plane",
        "get plane",
        "face plane",
    ] {
        assert!(plan.rows().all(|row| row.part() != part), "{part}");
    }
    assert!(core::mem::size_of::<StateRegion>() >= core::mem::size_of::<crate::round::Round>());
}
