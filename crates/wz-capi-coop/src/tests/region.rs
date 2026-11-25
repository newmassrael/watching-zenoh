// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The state of a session whose shape the build fixes, opened as one zeroed reservation: a config
//! the region admits takes one reservation of the struct's own size, given back once when the
//! state is let go, and a config it refuses, or a memory with none to give, takes nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use wz_session_core::limit_binding::{Quota, UnlentRows};

use super::client_config;
use crate::arena::{
    AllocatorMemory, ArenaLimit, ArenaMemory, ArenaRefused, ArenaRegion, PlanShape,
};
use crate::region::StateRegion;
use crate::CoopConfig;

/// The allocator, counting its plain reservations, its zeroed ones and what it is given back.
struct Counted {
    reserves: AtomicUsize,
    zeroed: AtomicUsize,
    zeroed_bytes: AtomicUsize,
    releases: AtomicUsize,
}

impl Counted {
    const fn new() -> Self {
        Self {
            reserves: AtomicUsize::new(0),
            zeroed: AtomicUsize::new(0),
            zeroed_bytes: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
        }
    }

    /// The plain reservations, the zeroed ones and the releases so far.
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.reserves.load(Ordering::SeqCst),
            self.zeroed.load(Ordering::SeqCst),
            self.releases.load(Ordering::SeqCst),
        )
    }
}

impl ArenaMemory for Counted {
    fn reserve(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        AllocatorMemory.reserve(layout)
    }

    fn reserve_zeroed(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
        self.zeroed.fetch_add(1, Ordering::SeqCst);
        self.zeroed_bytes.fetch_add(layout.size(), Ordering::SeqCst);
        AllocatorMemory.reserve_zeroed(layout)
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

/// The open of a config its region admits reserves the state once, zeroed, at the struct's own
/// size and by no plain reservation, and its drop gives it back once. Turned red by an open that
/// reserves the state twice, or by a plan's arena, or by a drop that keeps it or gives it back
/// twice.
#[test]
fn a_state_opens_by_one_zeroed_reservation_given_back_once() {
    static OPENED: Counted = Counted::new();
    let config = client_config();
    let region = region_of(&config);
    let state = StateRegion::open(&region, &config, &OPENED).expect("the region admits its own");
    assert_eq!(OPENED.counts(), (0, 1, 0));
    assert_eq!(
        OPENED.zeroed_bytes.load(Ordering::SeqCst),
        core::mem::size_of::<StateRegion>()
    );
    drop(state);
    assert_eq!(OPENED.counts(), (0, 1, 1));
}

/// A config that dials more endpoints than the region holds rows for, or holds limits it was not
/// laid out for, is refused under the limit that differs before anything is reserved; a memory
/// with none to give refuses the open with the bytes it was asked for. Turned red by an open that
/// reserves before it admits the config, or admits one its region was not laid out for.
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
        StateRegion::open(&region, &more, &REFUSED).err(),
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
        StateRegion::open(&region, &other, &REFUSED).err(),
        Some(ArenaRefused::Limit {
            limit: ArenaLimit::LimitsDifferFromBuild,
            why: UnlentRows::NoCeiling,
        })
    );
    assert_eq!(REFUSED.counts(), (0, 0, 0));
    assert_eq!(
        StateRegion::open(&region, &config, &NoMemory).err(),
        Some(ArenaRefused::NoMemory {
            bytes: core::mem::size_of::<StateRegion>(),
        })
    );
}
