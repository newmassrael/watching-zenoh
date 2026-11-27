// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The registry of a session whose shape the build fixes, laid out as fields of the session's
//! region (`crate::region::StateRegion`) instead of lent from an arena: the registry, the rows of
//! the application's tables, of the one face's set and of the session's own gets, each table placed
//! over its rows by the region's one walk (`place_region`). A build of this form takes no face
//! beside its dial role's (`listen` and `group` lay their arena out at the open), so the registry
//! holds one set, the dial face's, always held by it.
//!
//! The registry lies in a `MaybeUninit` field: the region's drop does not drop it. Its handle
//! ([`RegionField`]) does, so the session state that holds the handle lets the registry go before
//! the round it delivers to, as a registry it held by value did.

use core::mem::{offset_of, size_of, MaybeUninit};
use core::ptr::{self, addr_of_mut, NonNull};

use wz_session_core::bounded::{LendRefused, Region, RegionLines, SeqPlace, ZeroEmpty};
#[cfg(feature = "query")]
use wz_session_core::get_legs::{GetLegs, GetLegsRows, GET_LEGS_LINES};
use wz_session_core::limits::SessionLimits;
use wz_session_core::peer_tables::{PeerTableRows, PeerTables, PEER_TABLE_LINES};
#[cfg(feature = "query")]
use wz_session_core::session_tables::PendingGetHandle;
use wz_session_core::session_tables::{SessionRows, SessionTables, TableRows, SESSION_TABLE_LINES};
use wz_session_core::slot_observer::{ObserverRegionRows, SLOT_OBSERVER_LINES};

use super::held::OneHolder;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::DeclWatches;
#[cfg(feature = "local-queryable")]
use super::Gets;
use super::{App, CoopSinks, FaceTables, Registry, RegistryOf, FACE_SETS};
use crate::engine::{CoopRows, RoundDelivery};
use crate::region::RegionField;

/// The rows of the legs one face holds of the session's gets, or the session's own queryables
/// hold: its queries' and, with `liveliness-get`, its snapshots'.
#[cfg(feature = "query")]
struct GetRows {
    legs: GetLegsRows<PendingGetHandle>,
    #[cfg(feature = "liveliness-get")]
    snapshots: GetLegsRows<PendingGetHandle, { super::SNAPSHOT_LEGS }>,
}

// SAFETY: each field is rows of `MaybeUninit` (`ZeroEmpty`), holding no value until placed.
#[cfg(feature = "query")]
unsafe impl ZeroEmpty for GetRows {}

/// The lines a face's legs take in a region's description: a table of legs each for its queries
/// and its snapshots, none in a build that asks nothing.
#[cfg(all(feature = "query", not(feature = "liveliness-get")))]
const GET_LINES: usize = GET_LEGS_LINES;
#[cfg(all(feature = "query", feature = "liveliness-get"))]
const GET_LINES: usize = 2 * GET_LEGS_LINES;
#[cfg(not(feature = "query"))]
const GET_LINES: usize = 0;

#[cfg(feature = "query")]
impl super::Gets {
    /// The description of a face's legs at `at` in a region and their [`GetRows`] at `rows`:
    /// each table of legs placed over its rows. A leg keeps no key and the tables state no quota
    /// (the session's table of gets bounds them), so nothing holds them to the limits after.
    const fn places(at: usize, rows: usize) -> RegionLines<GET_LINES> {
        let lines = RegionLines::EMPTY.with(
            &GetLegs::<PendingGetHandle, Region>::places(
                at.wrapping_add(offset_of!(super::Gets, legs)),
                rows.wrapping_add(offset_of!(GetRows, legs)),
            ),
            0,
        );
        #[cfg(feature = "liveliness-get")]
        let lines = lines.with(
            &GetLegs::<PendingGetHandle, Region, { super::SNAPSHOT_LEGS }>::places(
                at.wrapping_add(offset_of!(super::Gets, snapshots)),
                rows.wrapping_add(offset_of!(GetRows, snapshots)),
            ),
            0,
        );
        lines
    }
}

/// The rows of one set of face tables: its peer's stagings, the Finals owed to its peer's queries,
/// and its pending gets.
struct FaceTableRows {
    peer: PeerTableRows,
    /// The Finals owed to the peer's queries; the replies to them are staged outside the session's
    /// lock (the engine's `answer`), so the peer's reply stage is laid out no rows.
    #[cfg(feature = "queryable")]
    finals: wz_session_core::reply_stage::FinalStageRows,
    #[cfg(feature = "query")]
    gets: GetRows,
}

// SAFETY: each field is rows of `MaybeUninit` (`ZeroEmpty`), holding no value until placed.
unsafe impl ZeroEmpty for FaceTableRows {}

/// The lines one set of face tables takes in a region's description, at most.
const FACE_TABLE_LINES: usize = PEER_TABLE_LINES + 1 + GET_LINES;

impl FaceTables {
    /// The description of a set at `at` in a region and its [`FaceTableRows`] at `rows`: its
    /// peer's tables', its Finals' and its gets' lines.
    const fn places(at: usize, rows: usize) -> RegionLines<FACE_TABLE_LINES> {
        let peer = at.wrapping_add(offset_of!(FaceTables, peer));
        let lines = RegionLines::EMPTY.with(
            &PeerTables::<Region>::places(peer, rows.wrapping_add(offset_of!(FaceTableRows, peer))),
            0,
        );
        #[cfg(feature = "queryable")]
        let lines = lines.seq(PeerTables::<Region>::finals_place(
            peer,
            rows.wrapping_add(offset_of!(FaceTableRows, finals)),
        ));
        #[cfg(feature = "query")]
        let lines = lines.with(
            &super::Gets::places(
                at.wrapping_add(offset_of!(FaceTables, gets)),
                rows.wrapping_add(offset_of!(FaceTableRows, gets)),
            ),
            0,
        );
        lines
    }
}

/// The rows of the registry: the application's watchers' and tables', the one set's and its
/// tables', and the session's own gets'.
struct RegistryRows {
    app: ObserverRegionRows<CoopSinks>,
    tables: SessionRows<CoopRows>,
    /// The sets, written field by field where they lie before the region is placed, then counted
    /// by the registry's table of them.
    sets: [MaybeUninit<FaceTables>; FACE_SETS],
    set_rows: [FaceTableRows; FACE_SETS],
    #[cfg(feature = "local-queryable")]
    local: GetRows,
}

// SAFETY: each field is rows of `MaybeUninit` or of `ZeroEmpty` rows, holding no value until placed.
unsafe impl ZeroEmpty for RegistryRows {}

/// The registry of a session of the build's shape and its rows, a field of the session's region.
pub(crate) struct RegistryRegion {
    registry: MaybeUninit<Registry>,
    rows: RegistryRows,
}

// SAFETY: a `MaybeUninit`, valid as any bytes and dropped by nothing, and the rows (`ZeroEmpty`).
unsafe impl ZeroEmpty for RegistryRegion {}

/// The lines of a [`RegistryRegion`]'s description, at most: the application's, its tables', the
/// sets' table, each set's, and the session's own gets'.
pub(crate) const REGISTRY_REGION_LINES: usize =
    SLOT_OBSERVER_LINES + SESSION_TABLE_LINES + 1 + FACE_SETS * FACE_TABLE_LINES + GET_LINES;

impl RegistryRegion {
    /// The description of a registry region at `at` in a region: the lines that place each of the
    /// registry's tables over its rows and hand each its handle to the region's key arena.
    pub(crate) const fn places(at: usize) -> RegionLines<REGISTRY_REGION_LINES> {
        let registry = at.wrapping_add(offset_of!(Self, registry));
        let rows = at.wrapping_add(offset_of!(Self, rows));
        let app = registry.wrapping_add(offset_of!(RegistryOf<OneHolder>, app));
        let sets = rows.wrapping_add(offset_of!(RegistryRows, sets));
        let set_rows = rows.wrapping_add(offset_of!(RegistryRows, set_rows));
        let mut lines = RegionLines::EMPTY
            .with(
                &App::places(app, rows.wrapping_add(offset_of!(RegistryRows, app))),
                0,
            )
            .with(
                &SessionTables::<CoopRows, Region>::places(
                    app.wrapping_add(offset_of!(App, tables)),
                    rows.wrapping_add(offset_of!(RegistryRows, tables)),
                ),
                0,
            )
            .seq(SeqPlace::of::<FaceTables>(
                registry.wrapping_add(offset_of!(RegistryOf<OneHolder>, sets)),
                sets,
                FACE_SETS,
            ));
        let mut set = 0;
        while set < FACE_SETS {
            lines = lines.with(
                &FaceTables::places(
                    sets.wrapping_add(set.wrapping_mul(size_of::<FaceTables>())),
                    set_rows.wrapping_add(set.wrapping_mul(size_of::<FaceTableRows>())),
                ),
                0,
            );
            set = set.wrapping_add(1);
        }
        #[cfg(feature = "local-queryable")]
        let lines = lines.with(
            &Gets::places(
                registry.wrapping_add(offset_of!(RegistryOf<OneHolder>, local)),
                rows.wrapping_add(offset_of!(RegistryRows, local)),
            ),
            0,
        );
        lines
    }

    /// Write, where they lie, the parts of the zeroed registry region at `at` whose empty value is
    /// not all zero bytes: each set (its peer's tables held to `limits`, its gets with no
    /// deadline) and the session's own gets. Asked before the region is placed, which then hands
    /// each of them its rows and its key arena over what is written here.
    ///
    /// # Safety
    /// `at` points at a `RegistryRegion` of all zero bytes, aligned, that nothing else reaches.
    pub(crate) unsafe fn write_parts(at: NonNull<Self>, limits: &SessionLimits) {
        let at = at.as_ptr();
        let mut set = 0;
        while set < FACE_SETS {
            // SAFETY: the caller's contract; the row is one of the sets' rows in the region, a
            // `MaybeUninit` of all zero bytes reached by this one reference alone, which
            // `rowless_over_zero` makes a whole set, its peer's tables left as those bytes.
            unsafe {
                let place = &mut *addr_of_mut!((*at).rows.sets)
                    .cast::<MaybeUninit<FaceTables>>()
                    .add(set);
                FaceTables::rowless_over_zero(place, limits);
            }
            set = set.wrapping_add(1);
        }
        #[cfg(feature = "local-queryable")]
        // SAFETY: the caller's contract; the field is written once, whole, before anything reads it.
        unsafe {
            let registry = addr_of_mut!((*at).registry).cast::<Registry>();
            ptr::write(addr_of_mut!((*registry).local), Gets::default());
        }
    }

    /// Make the placed registry region at `at` the session's registry and hand back its handle:
    /// what the application's subscribers match goes to `delivery`, the application's tables are
    /// held to `tables` and every table to `limits`, and the set written by
    /// [`Self::write_parts`] is counted as the dial face's. Refused, the registry left unmade and
    /// `delivery` dropped, when `limits` admit more declaration watches than the build.
    ///
    /// # Safety
    /// `at` points at a `RegistryRegion` that [`Self::write_parts`] wrote and the region's walk
    /// then placed, that nothing else reaches, and that neither moves nor is given back before the
    /// handle is dropped.
    pub(in crate::engine) unsafe fn bind(
        at: NonNull<Self>,
        limits: &SessionLimits,
        tables: &TableRows,
        delivery: RoundDelivery,
    ) -> Result<RegionField<Registry>, LendRefused> {
        // The watches' events wait in the session's round where the build keeps one; a read that
        // hands each record out as it reads it hands them out itself.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            wz_round
        ))]
        let decl_watches = DeclWatches::under(limits, &delivery.round)?;
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(wz_round)
        ))]
        let decl_watches = DeclWatches::under(limits)?;
        // SAFETY: the caller's contract. Every field of the registry is written here or holds its
        // empty value already: the application's tables, the sets' table and the count of the
        // faces' writes at zero bytes, each set and the session's own gets by `write_parts`, and
        // the delivery and the watches here, each once, whole, before the registry is read.
        unsafe {
            let registry = addr_of_mut!((*at.as_ptr()).registry).cast::<Registry>();
            ptr::write(addr_of_mut!((*registry).delivery), delivery);
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            ptr::write(addr_of_mut!((*registry).decl_watches), decl_watches);
            (*addr_of_mut!((*registry).sets)).assume_held(FACE_SETS);
            let mut held = RegionField::new(NonNull::new_unchecked(registry));
            held.app.limit_to(limits);
            held.app.tables.limit_to(tables);
            Ok(held)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::arena::{ArenaPlan, PlanShape};
    use crate::region::StateRegion;
    use core::ptr::addr_of;
    use wz_session_core::reply_stage::FinalStaging;

    /// A zeroed `StateRegion`, given back when dropped.
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
            // SAFETY: the region is dropped once, in place (its registry, never bound, is a
            // `MaybeUninit` the drop leaves alone and holds nothing to give back); then the block
            // goes back with the layout it was given with.
            unsafe {
                core::ptr::drop_in_place(self.0.as_ptr());
                std::alloc::dealloc(
                    self.0.as_ptr().cast::<u8>(),
                    std::alloc::Layout::new::<StateRegion>(),
                );
            }
        }
    }

    /// A set written over zero bytes leaves its peer's tables as those bytes, empty, and holds them
    /// to the session's limits, before the region's walk hands them their rows. Turned red by a
    /// set whose peer is not held to `limits` (a quota left at zero bytes admits nothing), or by
    /// peer tables that are not empty at zero bytes.
    #[test]
    fn a_set_over_zero_bytes_holds_its_empty_peer_to_the_sessions_limits() {
        use wz_session_core::limit_binding::Quota;
        let mut limits = SessionLimits::BUILD;
        if limits
            .select_max_peer_keyexpr_aliases(Quota::at_most(2))
            .is_err()
        {
            // A build whose limits keep the build's value alone states no other quota.
            return;
        }
        let layout = std::alloc::Layout::new::<FaceTables>();
        // SAFETY: the layout is of a type of some bytes.
        let block = unsafe { std::alloc::alloc_zeroed(layout) };
        let place = NonNull::new(block.cast::<MaybeUninit<FaceTables>>())
            .expect("the test allocator answers");
        // SAFETY: the block holds all zero bytes, aligned for a set, and is reached by this one
        // reference alone until it is given back.
        let set = unsafe { FaceTables::rowless_over_zero(&mut *place.as_ptr(), &limits) };
        assert_eq!(
            set.peer.subscribers.alias_quota().get(),
            Quota::at_most(2),
            "the peer's tables are held to the session's limits"
        );
        assert_eq!(set.peer.subscribers.alias_count(), 0);
        assert_eq!(set.peer.remote_subscribers.declared_count(), 0);
        assert_eq!(set.peer.finals.owed(), 0);
        // SAFETY: the set was made whole and is dropped once, in place; then the block goes back
        // with the layout it was given with.
        unsafe {
            core::ptr::drop_in_place(place.as_ptr().cast::<FaceTables>());
            std::alloc::dealloc(block, layout);
        }
    }

    /// Placed, the region's registry holds the application's tables at the rows the plan of the
    /// build's client counts, its one set placed and not yet counted, and the set's tables held
    /// to the build's limits. Turned red by a line of the registry's description at the wrong
    /// offset, by rows of a count the plan does not lend, or by a set counted before it is bound.
    #[test]
    fn a_placed_registry_holds_the_rows_the_builds_plan_counts() {
        let shape =
            PlanShape::dial_only(0, 1024, &wz_session_core::policy::SessionPolicy::defaults());
        let plan = ArenaPlan::planned(shape, &SessionLimits::BUILD).expect("the build's client");
        let rows = plan.tables();
        let block = Block::zeroed();
        // SAFETY: the block is a zeroed `StateRegion` this test alone reaches, freed after.
        unsafe { StateRegion::place(block.0, &SessionLimits::BUILD) };
        // SAFETY: the registry's field of the region, read through its pointer alone.
        let registry = unsafe {
            addr_of!((*StateRegion::registry_at(block.0).as_ptr()).registry).cast::<Registry>()
        };
        // SAFETY: the application's part and the sets' table, fields of the placed registry, each
        // a value at its empty or placed state, referenced alone and not written.
        let (app, sets) = unsafe { (&*addr_of!((*registry).app), &*addr_of!((*registry).sets)) };
        let tables = &app.tables;
        assert_eq!(tables.keyexprs().capacity(), rows.keyexprs);
        assert_eq!(tables.subscribers().capacity(), rows.subscribers);
        assert!(tables.subscribers().is_empty());
        assert_eq!(
            sets.len(),
            0,
            "the set is counted when the registry is bound"
        );
        // SAFETY: the set's row, written by `write_parts` and placed, read and not written.
        let set = unsafe {
            &*addr_of!((*StateRegion::registry_at(block.0).as_ptr()).rows.sets).cast::<FaceTables>()
        };
        assert_eq!(set.peer.finals.owed(), 0);
        assert_eq!(
            set.peer.finals.has_room(),
            cfg!(feature = "queryable"),
            "the Finals are laid out rows only where the build answers queries"
        );
    }
}
