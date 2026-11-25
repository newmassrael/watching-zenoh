// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The state of a session whose shape the build fixes, as one struct: the session's tables, its one
//! face's peer tables, the rows each lays out beside it and the key arena their keys lie in. Its
//! size is its `size_of` and its layout its fields' offsets; the allocator hands it zeroed, every
//! table of it empty (`ZeroEmpty`), and [`StateRegion::bind`] joins each table to its rows and its
//! keys by one walk of the description the type states, so nothing is planned or lent at the open.
//!
//! A region is reached through a pointer to it, never by a reference to the whole: the tables'
//! rows and the key arena lie in it beside the tables, reached through the tables, and a unique
//! reference to the whole would cover them too. Each field is projected from the pointer alone.

use core::ptr::{addr_of_mut, NonNull};

use wz_session_core::bounded::{Region, RegionLines, ZeroEmpty};
use wz_session_core::caps;
use wz_session_core::key_arena::{place_region, KeyArena};
use wz_session_core::peer_tables::{PeerTableRows, PeerTables, PEER_TABLE_LINES};
use wz_session_core::session_tables::{SessionTables, SESSION_TABLE_LINES};

use crate::arena::ArenaRegion;
use crate::engine::CoopRows;

/// The lines of a [`StateRegion`]'s description, at most: its session tables', its peer tables',
/// and the final stage's of a build that answers queries.
pub const STATE_REGION_LINES: usize = SESSION_TABLE_LINES + PEER_TABLE_LINES + 1;

/// The state of a session of the build's shape: see the module documentation. The key arena is the
/// last field, so a region dropped in place drops every table, and every key they hold, before it.
pub struct StateRegion {
    tables: SessionTables<CoopRows, Region>,
    peer: PeerTables<Region>,
    table_rows: wz_session_core::session_tables::SessionRows<CoopRows>,
    peer_rows: PeerTableRows,
    /// The Finals owed to the peer's queries; the replies to them are staged outside the session's
    /// lock (the engine's `answer`), so the peer's reply stage is laid out no rows.
    #[cfg(feature = "queryable")]
    finals: wz_session_core::reply_stage::FinalStageRows,
    keys: KeyArena<{ caps::KEY_ARENA_BYTES }>,
}

// SAFETY: every field is `ZeroEmpty`: the tables and the peer tables of the region policy, their
// rows (`MaybeUninit`) and the key arena.
unsafe impl ZeroEmpty for StateRegion {}

impl StateRegion {
    /// The region's description: the lines that place each table's rows and hand each table the
    /// key arena, read by [`Self::bind`].
    pub const DESCRIPTION: RegionLines<STATE_REGION_LINES> = {
        let lines = RegionLines::EMPTY
            .with(
                &SessionTables::<CoopRows, Region>::places(
                    core::mem::offset_of!(Self, tables),
                    core::mem::offset_of!(Self, table_rows),
                ),
                0,
            )
            .with(
                &PeerTables::<Region>::places(
                    core::mem::offset_of!(Self, peer),
                    core::mem::offset_of!(Self, peer_rows),
                ),
                0,
            );
        #[cfg(feature = "queryable")]
        let lines = lines.seq(PeerTables::<Region>::finals_place(
            core::mem::offset_of!(Self, peer),
            core::mem::offset_of!(Self, finals),
        ));
        lines
    };

    /// Make the zeroed region at `region` a session's of `build`: each table placed its rows and
    /// handed the key arena, then held to the build's rows and limits. Until then every bound of
    /// the region is one of nothing, so a region not bound refuses all it is asked.
    ///
    /// # Safety
    /// `region` points at a `StateRegion` of all zero bytes, aligned, that nothing else reaches,
    /// and which neither moves nor is given back while a table of it lives.
    pub unsafe fn bind(region: NonNull<Self>, build: &ArenaRegion) {
        // SAFETY: the caller's contract.
        unsafe { Self::place(region, build) };
        let at = region.as_ptr();
        // SAFETY: the tables field alone, projected from the pointer: the rows and the key arena
        // are reached through the tables, not through this reference.
        let tables = unsafe { &mut *addr_of_mut!((*at).tables) };
        tables.limit_to(&build.tables());
        // SAFETY: the peer tables field alone, as the tables above.
        let peer = unsafe { &mut *addr_of_mut!((*at).peer) };
        peer.limit_to(build.limits());
    }

    /// Place each table of the zeroed region at `region` its rows and hand it the key arena,
    /// leaving every bound one of nothing.
    ///
    /// # Safety
    /// As [`Self::bind`].
    unsafe fn place(region: NonNull<Self>, build: &ArenaRegion) {
        let at = region.as_ptr();
        // SAFETY: the key arena field alone, reached by this one reference before any key exists
        // and not after `space`; it stays in the region for as long as the tables do.
        let keys =
            unsafe { (*addr_of_mut!((*at).keys)).space(build.limits().max_keyexpr_bytes_held()) };
        // SAFETY: the description is this type's own: its lines name the tables' sequences and key
        // handles in the region, each holding no value, and the rows beside them, which only those
        // tables reach; the caller's contract keeps the region in place.
        unsafe { place_region(region.cast::<u8>(), keys, &Self::DESCRIPTION) };
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::arena::{ArenaPlan, PlanShape, TAKES_FACES};
    use wz_session_core::limits::SessionLimits;
    use wz_session_core::reply_stage::FinalStaging;
    use wz_session_core::session_tables::{FILTER_ROWS, INTEREST_ROWS};

    /// A client of the build's limits, the shape a build of fixed limits lays its arena out by.
    const CLIENT: PlanShape = PlanShape {
        max_faces: if TAKES_FACES { caps::MAX_FACES } else { 0 },
        accept_pending: caps::MAX_ACCEPT_PENDING,
        ..PlanShape::dial_only(0, 1024)
    };

    /// The region of that client, as the build lays it out when it is compiled.
    static BUILD_REGION: ArenaRegion = match ArenaRegion::of(CLIENT, SessionLimits::BUILD) {
        Ok(region) => region,
        Err(_) => panic!("the build lays its own client out"),
    };

    /// A zeroed block of one `StateRegion`, given back when dropped.
    struct Block(NonNull<StateRegion>);

    impl Block {
        fn zeroed() -> Self {
            let layout = std::alloc::Layout::new::<StateRegion>();
            // SAFETY: the layout is of a type of some bytes.
            let block = unsafe { std::alloc::alloc_zeroed(layout) };
            Self(NonNull::new(block.cast::<StateRegion>()).expect("the test allocator answers"))
        }
    }

    impl Drop for Block {
        fn drop(&mut self) {
            // SAFETY: the region is dropped once, in place, its key arena last (its last field);
            // then the block goes back with the layout it was given with.
            unsafe {
                core::ptr::drop_in_place(self.0.as_ptr());
                std::alloc::dealloc(
                    self.0.as_ptr().cast::<u8>(),
                    std::alloc::Layout::new::<StateRegion>(),
                );
            }
        }
    }

    /// Each table the region lays out holds the rows the plan of the build's client counts for
    /// it, no more and no fewer, and the key arena the plan's bytes. Turned red by a row array of
    /// the region, or a line of its description, that differs from what the plan lends.
    #[test]
    fn a_state_regions_tables_hold_the_rows_the_builds_plan_counts() {
        let plan = ArenaPlan::planned(CLIENT, &SessionLimits::BUILD).expect("the build's client");
        let rows = plan.tables();
        let block = Block::zeroed();
        // SAFETY: the block is a zeroed `StateRegion` this test alone reaches, freed after.
        unsafe { StateRegion::place(block.0, &BUILD_REGION) };
        // SAFETY: the tables field alone; the rows are reached only through it.
        let tables = unsafe { &*core::ptr::addr_of!((*block.0.as_ptr()).tables) };
        assert_eq!(tables.keyexprs().capacity(), rows.keyexprs);
        assert_eq!(tables.subscribers().capacity(), rows.subscribers);
        assert_eq!(FILTER_ROWS, rows.write_filters());
        assert_eq!(INTEREST_ROWS, rows.interests());
        assert_eq!(plan.key_bytes(), caps::KEY_ARENA_BYTES);
        let peers = plan.peers().rows;
        assert_eq!(peers.pending_declares, caps::MAX_PENDING_DECLARES);
        assert_eq!((peers.replies, peers.reply_bytes), (0, 0));
        let finals = if cfg!(feature = "queryable") {
            caps::MAX_PENDING_FINALS
        } else {
            0
        };
        assert_eq!(peers.finals, finals);
    }

    /// A region of all zero bytes holds nothing and, its bounds ones of nothing, admits nothing;
    /// bound to the build, it admits what the build's limits do. Turned red by a zero field of the
    /// region that is not an empty one, or by a bind that leaves a bound unstated.
    #[test]
    fn a_state_region_of_zero_bytes_admits_nothing_until_bound_to_the_build() {
        let block = Block::zeroed();
        {
            // SAFETY: the fields alone, of a zeroed region every field of which is `ZeroEmpty`.
            let (tables, peer) = unsafe {
                (
                    &*core::ptr::addr_of!((*block.0.as_ptr()).tables),
                    &*core::ptr::addr_of!((*block.0.as_ptr()).peer),
                )
            };
            assert!(tables.subscribers().is_empty());
            assert!(tables.keyexprs().is_empty());
            assert_eq!(peer.finals.owed(), 0);
            assert!(
                !peer.finals.has_room(),
                "a stage placed no rows has no room"
            );
        }
        // SAFETY: the block is a zeroed `StateRegion` this test alone reaches, freed after.
        unsafe { StateRegion::bind(block.0, &BUILD_REGION) };
        // SAFETY: the peer tables field alone.
        let peer = unsafe { &*core::ptr::addr_of!((*block.0.as_ptr()).peer) };
        assert_eq!(peer.finals.has_room(), cfg!(feature = "queryable"));
        assert_eq!(peer.queries.requester(), None);
    }
}
