// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A build that keeps no table of engines (`engine-rows` off) claims no row at an open: more
//! engines than the build's `ENGINE_ROWS` are made and held at once, on either storage policy, and
//! each one's drop gives its arena back. On the fixed policy (`session-fixed-storage`) a build that
//! keeps the table refuses the engine past its rows (`engine_rows.rs`). The engines are the open's
//! first frame (`CoopEngine::assemble`), so nothing is dialled.
#![cfg(not(feature = "engine-rows"))]

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

use wz_capi_coop::arena::{
    admitted_faces, admitted_handshakes, ArenaMemory, ArenaRegion, HeldPlaces, OpenRegion,
    OpenStorage, PlanFrom, PlanShape,
};
use wz_capi_coop::open_source::OpenSource;
use wz_capi_coop::{CoopConfig, CoopEngine, EngineHold, OpenKeyIds};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps;
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::session_init_params::{KeepAliveConf, LinkRxConf, SessionZid, TxQueueConf};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::WhatAmI;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// The host's links, counted as the engine's sessions count the parts of a link and waited for by
/// their owner, as the engine opens over them.
type PosixLinks = <wz_runtime_posix::links::PosixLinks<wz_capi_coop::LinkCount> as wz_capi_coop::ComposedLinks>::WaitedByOwner;
type Engine = CoopEngine<PosixLinks, PosixClock>;

/// The arenas the allocator gave and was not given back.
static OUT: AtomicUsize = AtomicUsize::new(0);

/// The allocator, counting the arenas it gives.
struct Counting;

impl ArenaMemory for Counting {
    fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
        // SAFETY: the layout is not of zero bytes, which the trait's contract rules out.
        let base = NonNull::new(unsafe { std::alloc::alloc(layout) })?;
        OUT.fetch_add(1, Ordering::SeqCst);
        Some(base)
    }

    unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
        OUT.fetch_sub(1, Ordering::SeqCst);
        // SAFETY: the caller's: the allocator gave `base` for `layout`, given back once.
        unsafe { std::alloc::dealloc(base.as_ptr(), layout) }
    }
}

/// A client's config that would dial a loopback port nothing answers a session on.
fn config() -> CoopConfig {
    let limits = SessionLimits::defaults();
    CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:9".to_owned()],
        whatami: WhatAmI::Client,
        zid: Some(SessionZid::from([0xe2; 4])),
        owned_address: None,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        sn_resolution: wz_session_core::policy::SnResolution::default(),
        link_rx: LinkRxConf::default(),
        tx_queue: TxQueueConf::pico_of_snapshot(&SessionPolicy::defaults(), &limits),
        timeouts: SessionTimeouts::spec_defaults(),
        open_timeout_ms: 100,
        redial_ms: None,
        idle_wait_ms: 10,
        listen: Vec::new(),
        accept_pending: admitted_handshakes(&limits).expect("the build admits its own value"),
        max_faces: admitted_faces(&limits).expect("the build admits its own value"),
        groups: Vec::new(),
        clock_moves: None,
        limits,
        initial_interest: false,
    }
}

/// The engine of [`config`] made by `region`, its arena from [`Counting`], held and not dialled.
fn assembled(region: &'static OpenRegion) -> EngineHold<Engine> {
    config
        .open_with(|input| {
            Engine::assemble(
                wz_runtime_posix::links::PosixLinks::new(LOOPBACK, PosixTcpDial)
                    .counted_by::<wz_capi_coop::LinkCount>()
                    .waited_by_owner(),
                PosixClock,
                PosixEntropy,
                input,
                SessionPolicy::defaults(),
                OpenKeyIds::none(),
                OpenStorage {
                    memory: &Counting,
                    plan: PlanFrom::Region(region),
                },
            )
        })
        .expect("an open that claims no row is refused for none")
}

/// One more engine than the build's `ENGINE_ROWS` made and held at once, each holding its arena,
/// and every arena given back once they are dropped. Turned red, on the fixed storage policy, by
/// an open that claims a row of a table this build does not keep, and on either policy by an
/// engine that keeps its arena past its drop.
#[test]
fn engines_past_the_builds_rows_are_held_at_once_where_no_table_keeps_them() {
    let rows = ArenaRegion::of(PlanShape::of(&config()), SessionLimits::defaults())
        .expect("the build lays the config out");
    let region: &'static OpenRegion = Box::leak(Box::new(
        Engine::open_region(rows, HeldPlaces::NONE).expect("the engine's places lay out"),
    ));
    let held: Vec<EngineHold<Engine>> =
        (0..=caps::ENGINE_ROWS).map(|_| assembled(region)).collect();
    assert_eq!(
        OUT.load(Ordering::SeqCst),
        caps::ENGINE_ROWS + 1,
        "each engine holds its own arena"
    );
    drop(held);
    assert_eq!(
        OUT.load(Ordering::SeqCst),
        0,
        "each engine's drop gave its arena back"
    );
}
