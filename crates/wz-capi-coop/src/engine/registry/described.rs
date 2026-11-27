// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The descriptions of the registry and of one set of face tables, in the two forms that lay them
//! out at the open: one list of lines for each (`RegionLines`), which a region of the build's shape
//! places over the rows it lays out beside them (`placed`) and a plan walks, each line lent the
//! arena's next span (`RegistryOf::new`, `FaceTables::lend`). The tables' own descriptions are the
//! session core's (`SessionTables::places`, `SlotObserverOf::places`, `PeerTables::places`,
//! `Requesters::places`); these join them at the offsets the registry and a set keep them at, so
//! where a table lies and how many rows it is lent is one fact, read by both forms.
//!
//! A plan walks the registry's own lines and the dial face's set at the open, and the set of each
//! other place when a face first takes it (`adding::SpareSets`), so the pages of the places no face
//! takes stay unwritten.
//!
//! A set describes no reply stage: this engine's queryable answers outside the session's lock into
//! a stage of its own (`crate::arena`'s `peer_rows`), so a face's stage holds no row in either
//! form and refuses and counts a reply staged there.

use core::mem::offset_of;

#[cfg(feature = "runtime-plan")]
use core::ptr::NonNull;

#[cfg(feature = "runtime-plan")]
use wz_session_core::bounded::{seq_bytes, Arena, LendRefused, RowCounts, TableLender};
use wz_session_core::bounded::{RegionLines, RowCount, SeqPlace};
#[cfg(feature = "runtime-plan")]
use wz_session_core::key_arena::{lend_region, KeySpace};
#[cfg(feature = "runtime-plan")]
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "runtime-plan")]
use wz_session_core::peer_tables::PeerRows;
use wz_session_core::peer_tables::{PeerTableRows, PEER_TABLE_LINES};
#[cfg(feature = "runtime-plan")]
use wz_session_core::pubsub::SubscriberPeer;
#[cfg(feature = "query")]
use wz_session_core::reply_sink::ConsolidatingSink;
use wz_session_core::session_tables::SESSION_TABLE_LINES;
#[cfg(feature = "runtime-plan")]
use wz_session_core::slot_observer::RequesterRows;
use wz_session_core::slot_observer::SLOT_OBSERVER_LINES;
#[cfg(feature = "query")]
use wz_session_core::slot_observer::{RequesterRegionRows, REQUESTER_LINES};

use super::held::Holders;
#[cfg(feature = "query")]
use super::Gets;
use super::{App, FaceTables, Peer, RegistryOf};
use crate::engine::CoopTables;
#[cfg(feature = "query")]
use crate::engine::{LegHold, LegSink};
#[cfg(feature = "runtime-plan")]
use crate::RowPolicy;

/// The rows a region keeps for one set's requesters, or for the session's own gets.
#[cfg(feature = "query")]
pub(super) type GetRows = RequesterRegionRows<ConsolidatingSink<LegSink, LegHold>, LegSink>;

/// The lines one set's requesters take in a description: none in a build that asks nothing.
#[cfg(feature = "query")]
const GET_LINES: usize = REQUESTER_LINES;
#[cfg(not(feature = "query"))]
const GET_LINES: usize = 0;

/// The rows a region keeps for one set of face tables: its peer's stagings, the Finals owed to its
/// peer's queries, and its pending gets. A plan keeps none, and reads no line's offset into them.
pub(super) struct FaceTableRows {
    peer: PeerTableRows,
    #[cfg(feature = "queryable")]
    finals: wz_session_core::reply_stage::FinalStageRows,
    #[cfg(feature = "query")]
    gets: GetRows,
}

/// The lines one set of face tables takes in a description, at most: its peer's, its Finals' and
/// its gets'.
pub(super) const FACE_TABLE_LINES: usize = PEER_TABLE_LINES + 1 + GET_LINES;

impl FaceTables {
    /// The description of a set at `at` and, in a region, its `FaceTableRows` at `rows`: its
    /// peer's tables' lines, its Finals' where the build answers queries, and its gets' where it
    /// asks them, each lent by a plan the count of the face's rows that holds it.
    pub(super) const fn places(at: usize, rows: usize) -> RegionLines<FACE_TABLE_LINES> {
        let peer = at.wrapping_add(offset_of!(FaceTables, peer));
        let lines = RegionLines::EMPTY.with(
            &Peer::places(peer, rows.wrapping_add(offset_of!(FaceTableRows, peer))),
            0,
        );
        #[cfg(feature = "queryable")]
        let lines = lines.seq(Peer::finals_place(
            peer,
            rows.wrapping_add(offset_of!(FaceTableRows, finals)),
        ));
        #[cfg(feature = "query")]
        let lines = lines.with(
            &Gets::places(
                at.wrapping_add(offset_of!(FaceTables, gets)),
                rows.wrapping_add(offset_of!(FaceTableRows, gets)),
            ),
            0,
        );
        lines
    }
}

#[cfg(feature = "runtime-plan")]
impl FaceTables {
    /// The description of a set from its start: the lines `Self::lend` lends and
    /// `Self::arena_bytes` counts.
    pub(super) const LINES: RegionLines<FACE_TABLE_LINES> = Self::places(0, 0);

    /// The counts a set's lines are lent: `gets` of its gets and `peer` of its peer's stagings
    /// and Finals.
    pub(super) const fn counts(gets: RequesterRows, peer: PeerRows) -> RowCounts {
        peer.counts().and(&gets.counts())
    }

    /// The bytes of an arena a set of `gets` and `peer` rows takes where it is lent
    /// (`Self::lend`): its description's lines summed, and the row its peer's side composes keys
    /// in. `None` past the address space.
    pub(super) const fn arena_bytes(gets: RequesterRows, peer: PeerRows) -> Option<usize> {
        match (
            seq_bytes(Self::LINES.seq_lines(), &Self::counts(gets, peer)),
            SubscriberPeer::<RowPolicy>::compose_bytes(),
        ) {
            (Some(lines), Some(compose)) => lines.checked_add(compose),
            _ => None,
        }
    }

    /// Lend a set of no rows its rows where it lies, from `arena`, by one walk of its description:
    /// `gets` rows of its gets and `peer` of its peer's stagings and Finals, each line the
    /// arena's next span, each table's keys kept in `keys`, the session's key arena; then the row
    /// its peer's side composes keys in, which a region keeps inline; and its gets held to
    /// `limits`, as its peer's tables were when the set was made. Refused when the arena has not
    /// the rows; the set stays whole, with what was lent before the refusal.
    pub(super) fn lend(
        &mut self,
        arena: &mut Arena,
        keys: KeySpace,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) -> Result<(), LendRefused> {
        let mut lend = TableLender::new(arena);
        // SAFETY: the description is this type's (`Self::places`): each line names a table of the
        // set, which holds no value (a set of no rows, `FaceTables::rowless_in`), and states the
        // bytes of its rows, and each key line a table's handle to the key arena, which holds no
        // key; the set is reached by nothing else during the call, and `keys` is the session's,
        // which outlives it.
        unsafe {
            lend_region(
                NonNull::from(&mut *self).cast::<u8>(),
                keys,
                &Self::LINES,
                &Self::counts(gets, peer),
                &mut lend,
            );
        }
        lend.finish()?;
        self.peer.subscribers.lend_compose_row(arena)?;
        #[cfg(feature = "query")]
        self.gets.limit_to(limits);
        #[cfg(not(feature = "query"))]
        let _ = limits;
        Ok(())
    }
}

/// The sets the registry's table of them has room for: the build's bound, under which a plan lends
/// a set for each face its config admits, or the one set a region of the build's shape lays out.
#[cfg(feature = "runtime-plan")]
const SET_ROOM: usize = crate::arena::MAX_FACE_SETS;
#[cfg(not(feature = "runtime-plan"))]
const SET_ROOM: usize = super::FACE_SETS;

/// The lines of the index of which face holds each set (`Holders::LINES`): one where the form may
/// keep an index, none in a region's, whose one set its dial role's face holds.
#[cfg(feature = "runtime-plan")]
pub(super) const HELD_LINES: usize = 1;
#[cfg(not(feature = "runtime-plan"))]
pub(super) const HELD_LINES: usize = 0;

/// The line of the tokens the faces that went still owe, in a build whose faces go.
#[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
const OWED_LINES: usize = 1;
#[cfg(not(all(feature = "liveliness", any(feature = "listen", feature = "group"))))]
const OWED_LINES: usize = 0;

/// The lines of the session's own gets, in a build that answers its own.
#[cfg(feature = "local-queryable")]
const LOCAL_LINES: usize = GET_LINES;
#[cfg(not(feature = "local-queryable"))]
const LOCAL_LINES: usize = 0;

/// The lines of the registry's own description (`RegistryOf::places`), at most: the application's
/// lists' and tables', the sets' table's, the index's, the owed tokens' and the session's own
/// gets'.
pub(super) const REGISTRY_LINES: usize =
    SLOT_OBSERVER_LINES + SESSION_TABLE_LINES + 1 + HELD_LINES + OWED_LINES + LOCAL_LINES;

/// Where a region keeps the rows of each part of the registry's own description, from the start of
/// what the description describes. A plan keeps none: it lends each line the arena's next span and
/// reads no line's offset into them (`Self::LENT`).
pub(super) struct RegistryRowsAt {
    /// The application's lists' rows (an `ObserverRegionRows`).
    pub(super) app: usize,
    /// The application's tables' rows (a `SessionRows`).
    pub(super) tables: usize,
    /// The sets' rows.
    pub(super) sets: usize,
    /// The session's own gets' rows.
    #[cfg(feature = "local-queryable")]
    pub(super) local: usize,
}

#[cfg(feature = "runtime-plan")]
impl RegistryRowsAt {
    /// A plan's: no rows kept beside the registry.
    const LENT: Self = Self {
        app: 0,
        tables: 0,
        sets: 0,
        #[cfg(feature = "local-queryable")]
        local: 0,
    };
}

impl<H: Holders> RegistryOf<H> {
    /// The description of a registry at `at` and, in a region, its rows where `rows` says: the
    /// application's lists' lines (the session's own tokens are rows of its one table set, so its
    /// observer's own registry of them has no room) and its tables', the sets' table's, a set for
    /// each face a plan counts (`RowCount::FaceSets`), the index of which face holds each where
    /// the form keeps one, the tokens owed by the faces that went where faces go, and the session's
    /// own gets' where it answers its own; and the handle each keeps to the key arena. A set's own
    /// lines are the set's description (`FaceTables::places`), walked where the set lies.
    pub(super) const fn places(at: usize, rows: RegistryRowsAt) -> RegionLines<REGISTRY_LINES> {
        let app = at.wrapping_add(offset_of!(Self, app));
        let lines = RegionLines::EMPTY
            .with(&App::places::<0>(app, rows.app), 0)
            .with(
                &CoopTables::places(app.wrapping_add(offset_of!(App, tables)), rows.tables),
                0,
            )
            .seq(
                SeqPlace::of::<FaceTables>(
                    at.wrapping_add(offset_of!(Self, sets)),
                    rows.sets,
                    SET_ROOM,
                )
                .counted(RowCount::FaceSets),
            )
            .with(&H::LINES, at.wrapping_add(offset_of!(Self, holders)));
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        let lines = lines.seq(
            SeqPlace::of::<super::OwedTokens>(
                at.wrapping_add(offset_of!(Self, owed)),
                0,
                wz_session_core::caps::SESSION_MAX_REMOTE_DECLS,
            )
            .counted(RowCount::OwedTokens),
        );
        #[cfg(feature = "local-queryable")]
        let lines = lines.with(
            &Gets::places(at.wrapping_add(offset_of!(Self, local)), rows.local),
            0,
        );
        lines
    }
}

#[cfg(feature = "runtime-plan")]
impl<H: Holders> RegistryOf<H> {
    /// The registry's own description from its start: the lines `RegistryOf::new` lends.
    pub(super) const LINES: RegionLines<REGISTRY_LINES> = Self::places(0, RegistryRowsAt::LENT);
}
