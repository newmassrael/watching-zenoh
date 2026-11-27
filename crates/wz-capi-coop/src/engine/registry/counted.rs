// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The registry of a session whose tables take their memory at their first row
//! (`tables-on-use`): made by value at the open, each table counted from the limits the open
//! resolved and holding no row, every key counted against the session's key budget. A build of this
//! form, as one of the region's, takes no face beside its dial role's, so the registry holds one
//! set, the dial face's, always held by it. The set is the first row of the registry's table of
//! sets, written where that table keeps it: the one memory the open takes for the registry, and no
//! frame holds the set as a value of its own.

use core::mem::ManuallyDrop;

use wz_session_core::bounded::BoundedVec;
use wz_session_core::limits::SessionLimits;
use wz_session_core::on_use::BudgetKeys;
use wz_session_core::peer_tables::PeerRows;
#[cfg(feature = "local-queryable")]
use wz_session_core::pending_get::DueRow;
use wz_session_core::session_tables::TableRows;
use wz_session_core::slot_observer::RequesterRows;

use super::held::OneHolder;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::DeclWatches;
use super::{App, FaceTables, Gets, RegistryOf, FACE_SETS};
use crate::arena::{ArenaRefused, MAX_FACE_SETS};
use crate::engine::RoundDelivery;
use crate::RowPolicy;

impl FaceTables {
    /// Count a set of no rows where it lies: its gets of `gets` rows and its peer's tables of
    /// `peer`, each taking its memory at its first row, every key counted against `keys`, the
    /// session's key budget, and held to `limits`.
    fn count_rows(
        &mut self,
        keys: BudgetKeys,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) {
        self.gets = Gets::counted(keys, gets, limits);
        self.peer.count_rows(keys, peer, limits);
    }
}

impl RegistryOf<OneHolder> {
    /// A session that holds nothing and has been told nothing, with its dial face, made by value:
    /// the application's tables of the rows `tables` counts, the dial face's set of `gets` rows of
    /// gets and `peer` of its peer's tables, and the session's own gets where it answers its own,
    /// every table holding no row until its first and held to `limits`, every key counted against
    /// `keys`, the session's key budget. What the application's subscribers match goes to
    /// `delivery`. Refused when `limits` admit more declaration watchers or watches than the
    /// build, or when the allocator has no room for the dial face's set, the one row the registry
    /// takes here.
    pub(in crate::engine) fn counted(
        limits: &SessionLimits,
        keys: BudgetKeys,
        tables: TableRows,
        gets: RequesterRows,
        peer: PeerRows,
        delivery: RoundDelivery,
    ) -> Result<Self, ArenaRefused> {
        let app = App::counted(keys, tables, limits).map_err(ArenaRefused::Lend)?;
        let mut sets = BoundedVec::<FaceTables, MAX_FACE_SETS, RowPolicy>::counted(FACE_SETS);
        // SAFETY: `rowless_in` writes a whole set into the row it is handed and cannot unwind.
        let set = unsafe {
            sets.push_in_place(|place| {
                FaceTables::rowless_in(place, limits);
            })
        }
        .ok_or(ArenaRefused::NoMemory {
            bytes: core::mem::size_of::<FaceTables>().saturating_mul(FACE_SETS),
        })?;
        set.count_rows(keys, gets, peer, limits);
        #[cfg(feature = "local-queryable")]
        let local = Gets::counted(keys, gets, limits);
        // The watches' events wait in the session's round where the build keeps one; a read that
        // hands each record out as it reads it hands them out itself.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            wz_round
        ))]
        let decl_watches =
            DeclWatches::under(limits, &delivery.round).map_err(ArenaRefused::Lend)?;
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(wz_round)
        ))]
        let decl_watches = DeclWatches::under(limits).map_err(ArenaRefused::Lend)?;
        let mut registry = Self {
            app: ManuallyDrop::new(app),
            delivery,
            sets: ManuallyDrop::new(sets),
            holders: OneHolder,
            #[cfg(feature = "local-queryable")]
            local,
            #[cfg(feature = "local-queryable")]
            local_due: DueRow::NEVER,
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            decl_watches,
            faces_written: 0,
            #[cfg(all(test, feature = "std"))]
            face_lookups: 0,
            #[cfg(test)]
            peer_looks: core::cell::Cell::new(0),
            #[cfg(test)]
            set_reads: core::cell::Cell::new(0),
            #[cfg(all(test, feature = "std"))]
            pushes: (0, 0, 0),
            #[cfg(all(test, feature = "std", feature = "query"))]
            replies_alone: 0,
            #[cfg(all(test, feature = "std", feature = "queryable"))]
            drains_within_frames: 0,
        };
        registry.index_dues();
        Ok(registry)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::arena::{ArenaPlan, PlanShape};
    use wz_session_core::on_use::KeyBudget;
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::reply_stage::FinalStaging;

    /// Where a registry no session holds hands what its tables match.
    fn delivery() -> RoundDelivery {
        RoundDelivery {
            #[cfg(wz_round)]
            round: crate::round::leaked(4),
            #[cfg(feature = "queryable")]
            plane: wz_session_core::placed::PlacedRef::of_static(alloc::boxed::Box::leak(
                crate::engine::query::leaked_plane(1),
            )),
        }
    }

    /// A registry of the on-use form, counted at the open, holds the application's tables at the rows the plan of the
    /// build's client counts and its dial face's one set, counted from the plan's rows of a face;
    /// no table of the application's has taken a row, and no key is counted against the budget.
    /// Turned red by an application's table made of the build's bound rather than counted
    /// (`SlotMap::new` in place of `SlotMap::counted`), by a table that takes its rows when it is
    /// made, by a registry with no set, or, in a build without `queryable`, by a set whose peer's
    /// tables are not counted (`count_rows` not called: its Finals keep the build's bound and have
    /// room).
    #[test]
    fn an_on_use_registry_holds_the_plans_rows_and_has_taken_none() {
        let limits = SessionLimits::BUILD;
        let shape = PlanShape::dial_only(0, 1024, &SessionPolicy::defaults());
        let plan = ArenaPlan::planned(shape, &limits).expect("the build's client");
        let budget = KeyBudget::new(limits.key_arena_bytes(), limits.max_keyexpr_bytes_held());
        // SAFETY: the budget outlives the registry, which is dropped first, and every key of it.
        let keys = unsafe { budget.keys() };
        let rows = plan.tables();
        let registry = super::super::Registry::counted(
            &limits,
            keys,
            rows,
            plan.gets().rows,
            plan.peers().rows,
            delivery(),
        )
        .expect("the build's limits admit the build's watches");
        let tables = &registry.app.tables;
        assert_eq!(tables.keyexprs().capacity(), rows.keyexprs);
        assert_eq!(tables.subscribers().capacity(), rows.subscribers);
        assert!(
            !tables.keyexprs().holds_rows() && !tables.subscribers().holds_rows(),
            "no table of the application's took a row"
        );
        assert_eq!(registry.sets.len(), FACE_SETS, "the dial face's set");
        let set = registry.sets.first().expect("the dial face's set");
        assert_eq!(set.peer.finals.owed(), 0);
        assert_eq!(
            set.peer.finals.has_room(),
            cfg!(feature = "queryable"),
            "the Finals are counted rows only where the build answers queries"
        );
        assert_eq!(budget.counts().used, 0, "no key is counted yet");
        drop(registry);
    }
}
