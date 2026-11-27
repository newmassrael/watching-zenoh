// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process's table of engines with the build's `ENGINE_ROWS` rows held, under the build's
//! storage policy: on the fixed policy one more open is refused before it reserves anything, and
//! with a row let go of an open goes on past the rows; on the heap policy the count bounds nothing,
//! and opens go on past it, each on a row of the heap. The table is the process's, so it is filled
//! in a binary of its own, by this one test.

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

use wz_capi_coop::arena::{
    admitted_faces, admitted_handshakes, ArenaMemory, ArenaRegion, HeldPlaces, OpenRegion,
    OpenStorage, PlanFrom, PlanShape,
};
use wz_capi_coop::{CoopConfig, CoopEngine, EngineHold, OpenError, OpenKeyIds, RowClaim};
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

/// A client's config that dials a loopback port nothing answers a session on, given a tenth of a
/// second to.
fn config() -> CoopConfig {
    let limits = SessionLimits::defaults();
    CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:9".to_owned()],
        whatami: WhatAmI::Client,
        zid: Some(SessionZid::from([0xe1; 4])),
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

/// An open of [`config`] by the region its config lays out, its arena from [`Counting`].
fn open() -> Result<EngineHold<Engine>, OpenError> {
    let config = config();
    let rows = ArenaRegion::of(PlanShape::of(&config), SessionLimits::defaults())
        .expect("the build lays the config out");
    let region: &'static OpenRegion = Box::leak(Box::new(
        Engine::open_region(rows, HeldPlaces::NONE).expect("the engine's places lay out"),
    ));
    Engine::open_made_in(
        wz_runtime_posix::links::PosixLinks::new(LOOPBACK, PosixTcpDial)
            .counted_by::<wz_capi_coop::LinkCount>()
            .waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || config,
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        OpenStorage {
            memory: &Counting,
            plan: PlanFrom::Region(region),
        },
    )
}

/// The opens past the build's `ENGINE_ROWS` rows, held all at once. On the fixed policy the
/// table holds that many and no more: an open is refused with `NoEngineRow` and reserves no
/// arena, and with one row let go of the same open goes on past the rows. On the heap policy a row
/// past the count is one more of the heap, and eleven opens past it go on, as zenoh-pico opens a
/// session wherever its heap has room. Either way an open that goes on reaches the refusal of the
/// endpoint it dials, which nothing answers, gives its arena back and lets its row go again, for
/// the next claim. Turned red by an open that takes no row, takes one past a fixed table, is
/// refused past the count on the heap policy, reserves its arena before it is refused, or keeps
/// the row of an open that failed.
#[test]
fn an_open_past_the_builds_rows_is_refused_only_where_the_storage_policy_is_fixed() {
    let mut held: Vec<RowClaim> = std::iter::from_fn(RowClaim::take)
        .take(caps::ENGINE_ROWS + 1)
        .collect();
    let opens = if wz_session_core::bounded::ENFORCES_CAPACITY {
        assert_eq!(held.len(), caps::ENGINE_ROWS, "every row is held once");
        assert_eq!(open().err(), Some(OpenError::NoEngineRow));
        assert_eq!(
            OUT.load(Ordering::SeqCst),
            0,
            "the refused open reserved no arena"
        );
        drop(held.pop().expect("a row at least"));
        1
    } else {
        assert_eq!(
            held.len(),
            caps::ENGINE_ROWS + 1,
            "the heap gives a row past the build's count"
        );
        11
    };
    for _ in 0..opens {
        let past = open().err();
        assert!(
            past.is_some() && past != Some(OpenError::NoEngineRow),
            "the open goes past the rows: {past:?}"
        );
        assert_eq!(
            OUT.load(Ordering::SeqCst),
            0,
            "the failed open gave its arena back"
        );
    }
    let again = RowClaim::take().expect("the failed open let its row go");
    drop(again);
    drop(held);
}
