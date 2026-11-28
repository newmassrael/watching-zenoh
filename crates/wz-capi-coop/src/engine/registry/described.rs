// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The descriptions of the registry and of one set of face tables, in the two forms that lay them
//! out at the open: one list of lines for each (`RegionLines`), which a region of the build's shape
//! places over the rows it lays out beside them (`placed`) and a plan walks, each line lent the
//! arena's next span (`Registry::new`, `FaceTables::lend`). The tables' own descriptions are the
//! session core's (`SessionTables::places`, `SlotObserverOf::places`, `PeerTables::places`,
//! `GetLegs::places`); these join them at the offsets the registry and a set keep them at, so
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

#[cfg(wz_lent)]
use core::ptr::NonNull;

#[cfg(feature = "query")]
use wz_session_core::bounded::ZeroEmpty;
#[cfg(wz_lent)]
use wz_session_core::bounded::{seq_bytes, Arena, LendRefused, RowCounts, TableLender};
use wz_session_core::bounded::{RegionLines, RowCount, SeqPlace};
#[cfg(feature = "query")]
use wz_session_core::get_legs::{GetLegs, GetLegsRows, GET_LEGS_LINES};
#[cfg(wz_lent)]
use wz_session_core::key_arena::{lend_region, KeySpace};
#[cfg(wz_lent)]
use wz_session_core::peer_tables::PeerRows;
use wz_session_core::peer_tables::{PeerTableRows, PEER_TABLE_LINES};
#[cfg(wz_lent)]
use wz_session_core::pubsub::SubscriberPeer;
#[cfg(feature = "query")]
use wz_session_core::session_tables::PendingGetHandle;
use wz_session_core::session_tables::SESSION_TABLE_LINES;
#[cfg(wz_lent)]
use wz_session_core::slot_observer::RequesterRows;
use wz_session_core::slot_observer::SLOT_OBSERVER_LINES;

use super::held::HeldPlaces;
#[cfg(feature = "query")]
use super::Gets;
use super::{App, FaceTables, Peer, Registry};
use crate::engine::CoopTables;
#[cfg(any(feature = "query", wz_lent))]
use crate::RowPolicy;

/// The rows a region keeps for the legs one set holds of the session's gets, or the session's own
/// queryables hold: its queries' and, with `liveliness-get`, its snapshots'.
#[cfg(feature = "query")]
pub(super) struct GetRows {
    legs: GetLegsRows<PendingGetHandle>,
    #[cfg(feature = "liveliness-get")]
    snapshots: GetLegsRows<PendingGetHandle, { super::SNAPSHOT_LEGS }>,
}

// SAFETY: each field is rows of `MaybeUninit` (`ZeroEmpty`), holding no value until placed.
#[cfg(feature = "query")]
unsafe impl ZeroEmpty for GetRows {}

/// The lines one set's legs take in a description: a table of legs each for its queries and its
/// snapshots, none in a build that asks nothing.
#[cfg(all(feature = "query", not(feature = "liveliness-get")))]
const GET_LINES: usize = GET_LEGS_LINES;
#[cfg(all(feature = "query", feature = "liveliness-get"))]
const GET_LINES: usize = 2 * GET_LEGS_LINES;
#[cfg(not(feature = "query"))]
const GET_LINES: usize = 0;

#[cfg(feature = "query")]
impl Gets {
    /// The description of a set's legs at `at` and, in a region, their [`GetRows`] at `rows`:
    /// each table of legs, lent by a plan the count of its kind of get on one face (a face's
    /// `RowCount::Queries` and `RowCount::LivelinessGets`). A leg keeps no key and the tables
    /// state no quota (the session's table of gets bounds them), so nothing holds them to the
    /// limits after.
    const fn places(at: usize, rows: usize) -> RegionLines<GET_LINES> {
        let lines = RegionLines::EMPTY.with(
            &GetLegs::<PendingGetHandle, RowPolicy>::places(
                at.wrapping_add(offset_of!(Gets, legs)),
                rows.wrapping_add(offset_of!(GetRows, legs)),
                RowCount::Queries,
            ),
            0,
        );
        #[cfg(feature = "liveliness-get")]
        let lines = lines.with(
            &GetLegs::<PendingGetHandle, RowPolicy, { super::SNAPSHOT_LEGS }>::places(
                at.wrapping_add(offset_of!(Gets, snapshots)),
                rows.wrapping_add(offset_of!(GetRows, snapshots)),
                RowCount::LivelinessGets,
            ),
            0,
        );
        lines
    }
}

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

#[cfg(wz_lent)]
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
    /// in. `None` past the address space. Read where sets are built after the open
    /// (`adding::SpareSets`).
    #[cfg(any(feature = "listen", feature = "group", test))]
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
    /// its peer's side composes keys in, which a region keeps inline. Its legs state no quota of
    /// their own (the session's table of gets bounds them), and its peer's tables were held to the
    /// session's limits when the set was made. Refused when the arena has not the rows; the set
    /// stays whole, with what was lent before the refusal.
    pub(super) fn lend(
        &mut self,
        arena: &mut Arena,
        keys: KeySpace,
        gets: RequesterRows,
        peer: PeerRows,
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
        Ok(())
    }
}

/// The bytes of an arena a set's gets take, `gets` rows of them: the set's description's lines of
/// the gets' counts, each other line lent none under them. What a plan reports as a table of gets
/// (`crate::arena::ArenaPart::PendingGets`), the session's own gets' table being of the same
/// description (`Gets::places`). `None` past the address space.
#[cfg(all(feature = "query", wz_lent))]
pub(crate) const fn set_get_bytes(gets: RequesterRows) -> Option<usize> {
    seq_bytes(FaceTables::LINES.seq_lines(), &gets.counts())
}

/// The bytes of an arena a set's peer's tables take, `peer` rows of them: the set's description's
/// lines of the peer's counts, each other line lent none under them, and the row the peer's side
/// composes keys in, which no line names. What a plan reports as a face's peer tables
/// (`crate::arena::ArenaPart::PeerTables`). `None` past the address space.
#[cfg(wz_lent)]
pub(crate) const fn set_peer_bytes(peer: PeerRows) -> Option<usize> {
    match (
        seq_bytes(FaceTables::LINES.seq_lines(), &peer.counts()),
        SubscriberPeer::<RowPolicy>::compose_bytes(),
    ) {
        (Some(lines), Some(compose)) => lines.checked_add(compose),
        _ => None,
    }
}

/// The sets the registry's table of them has room for: the build's bound, under which a plan lends
/// a set for each face its config admits, or the one set a region of the build's shape lays out.
#[cfg(wz_lent)]
const SET_ROOM: usize = crate::arena::MAX_FACE_SETS;
#[cfg(not(wz_lent))]
const SET_ROOM: usize = super::FACE_SETS;

/// The lines of the table of the places' marks (`HeldPlaces::LINES`): one where the form may
/// keep marks past the dial role's place, none in a region's, whose one set its dial role's face
/// holds.
#[cfg(wz_lent)]
pub(super) const HELD_LINES: usize = 1;
#[cfg(not(wz_lent))]
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

/// The lines of the registry's own description (`Registry::places`), at most: the application's
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

#[cfg(wz_lent)]
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

impl Registry {
    /// The description of a registry at `at` and, in a region, its rows where `rows` says: the
    /// application's lists' lines and its tables' (the session's own tokens among their rows), the
    /// sets' table's, a set for each face a plan counts (`RowCount::FaceSets`), the marks of which
    /// face holds each place past the dial role's where the form keeps them (`RowCount::HeldSets`),
    /// the tokens owed by the faces that went where faces go, and the session's own gets' where it
    /// answers its own; and
    /// the handle each keeps to the key arena. A set's own lines are the set's description
    /// (`FaceTables::places`), walked where the set lies.
    pub(super) const fn places(at: usize, rows: RegistryRowsAt) -> RegionLines<REGISTRY_LINES> {
        let app = at.wrapping_add(offset_of!(Self, app));
        let lines = RegionLines::EMPTY
            .with(&App::places(app, rows.app), 0)
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
            .with(
                &HeldPlaces::LINES,
                at.wrapping_add(offset_of!(Self, holders)),
            );
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        let lines = lines.seq(super::owed::Owed::place(
            at.wrapping_add(offset_of!(Self, owed)),
        ));
        #[cfg(feature = "local-queryable")]
        let lines = lines.with(
            &Gets::places(at.wrapping_add(offset_of!(Self, local)), rows.local),
            0,
        );
        lines
    }
}

#[cfg(wz_lent)]
impl Registry {
    /// The registry's own description from its start: the lines `Registry::new` lends.
    pub(super) const LINES: RegionLines<REGISTRY_LINES> = Self::places(0, RegistryRowsAt::LENT);
}

/// The bytes of an arena the lines of the registry's own description take under `counts`, each
/// line of a count `counts` leaves at none lent no row: a part of what a plan reports of the
/// registry (`crate::arena::ArenaPart`), the lines of the counts the part names, so the parts add
/// up to what the open's walk lends (`Registry::new`). `None` past the address space.
#[cfg(wz_lent)]
pub(crate) const fn registry_bytes(counts: &RowCounts) -> Option<usize> {
    seq_bytes(Registry::LINES.seq_lines(), counts)
}

/// The bytes of one row of the table of the registry's own description that `count` lends (the
/// sets', the index of their holders', the tokens owed): what a plan reports as that table's row.
/// None where the build describes no table of that count.
#[cfg(wz_lent)]
pub(crate) const fn registry_row_bytes(count: RowCount) -> Option<usize> {
    stride_of(Registry::LINES.seq_lines(), count)
}

/// The bytes of one row of the first of `lines` lent by `count`, none where no line is.
#[cfg(wz_lent)]
const fn stride_of(lines: &[SeqPlace], count: RowCount) -> Option<usize> {
    let mut rest = lines;
    while let [line, tail @ ..] = rest {
        if line.count as u8 == count as u8 {
            return Some(line.stride as usize);
        }
        rest = tail;
    }
    None
}
