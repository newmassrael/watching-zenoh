// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What each connectivity listener was told while its history is replayed.
//!
//! A listener declared with its history is handed the faces that stand, on the declaring thread,
//! and what the faces do meanwhile waits for it in a queue of
//! [`MAX_CONNECTIVITY_REPLAY_EVENTS`](wz_session_core::caps::MAX_CONNECTIVITY_REPLAY_EVENTS)
//! rows. A listener whose queue ran out of rows is brought to the faces as they stand when its
//! replay ends, by what it was told: a row that stands and it was not told is told it came, a row
//! it was told that went is told it left. So while a listener replays, the engine notes on each of
//! its face rows which listeners were told the row, and a row that went stays, as a tombstone,
//! until each of them was told it left. A listener that replays no more is told every event as it
//! comes, and nothing is noted for it.
//!
//! What this costs, stated as the contract: a transport that came and went inside a replay is not
//! told, and past the queue one reconnect may be lost, a row that went and came back under the same
//! key being told neither.

use alloc::vec::Vec;

use wz_session_core::caps;
use wz_session_core::face::FaceLinkRow;

use crate::SessionEngine;

/// The listener tables of a session's connectivity plane, each with its own rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToldPlane {
    /// The transport events listeners (`MAX_TRANSPORT_EVENTS_LISTENERS`).
    Transports,
    /// The link events listeners (`MAX_LINK_EVENTS_LISTENERS`).
    Links,
}

/// Which face row an event is of: the peer, whether it is a member of a joined group, and which
/// link of the face; a transport is its face's first link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToldKey {
    /// The peer's zid.
    pub zid: [u8; 16],
    /// Whether the face is a member of a group the session joined.
    pub is_multicast: bool,
    /// Which link of the face, `0` for the first.
    pub link: usize,
}

impl ToldKey {
    /// The key of `row`.
    pub fn of_row(row: &FaceLinkRow) -> Self {
        Self {
            zid: row.zid,
            is_multicast: row.is_multicast,
            link: row.link,
        }
    }
}

// Each listener of a plane is a bit of a `u64`: a build that admits more listeners than that
// would note none of the ones past it.
const _: () = assert!(caps::MAX_TRANSPORT_EVENTS_LISTENERS <= 64);
const _: () = assert!(caps::MAX_LINK_EVENTS_LISTENERS <= 64);

/// The listeners of each plane told one row, a bit for each listener's row in its plane's table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToldBits {
    transports: u64,
    links: u64,
}

impl ToldBits {
    /// The bit of `listener`, none for a listener past the 64 a plane's bits hold (no build
    /// admits one: see the assertions above).
    fn bit(listener: usize) -> u64 {
        u32::try_from(listener)
            .ok()
            .and_then(|shift| 1u64.checked_shl(shift))
            .unwrap_or(0)
    }

    fn plane(&mut self, plane: ToldPlane) -> &mut u64 {
        match plane {
            ToldPlane::Transports => &mut self.transports,
            ToldPlane::Links => &mut self.links,
        }
    }

    /// Whether `listener` of `plane` was told the row.
    pub fn has(self, plane: ToldPlane, listener: usize) -> bool {
        let bits = match plane {
            ToldPlane::Transports => self.transports,
            ToldPlane::Links => self.links,
        };
        bits & Self::bit(listener) != 0
    }

    /// Note that `listener` of `plane` was told the row: `false` when it was already.
    pub fn set(&mut self, plane: ToldPlane, listener: usize) -> bool {
        let bit = Self::bit(listener);
        let bits = self.plane(plane);
        let was = *bits & bit != 0;
        *bits |= bit;
        bit != 0 && !was
    }

    /// Note that `listener` of `plane` was told the row left: `false` when it was never told
    /// the row came.
    pub fn clear(&mut self, plane: ToldPlane, listener: usize) -> bool {
        let bit = Self::bit(listener);
        let bits = self.plane(plane);
        let was = *bits & bit != 0;
        *bits &= !bit;
        was
    }

    /// Whether no listener of either plane was told the row.
    pub fn is_empty(self) -> bool {
        self.transports == 0 && self.links == 0
    }

    /// The listeners told either `self` or `other`: two departures of one key owed to listeners
    /// apart, kept as one.
    pub fn union(self, other: Self) -> Self {
        Self {
            transports: self.transports | other.transports,
            links: self.links | other.links,
        }
    }
}

/// The row of `key` as `engine` holds it now, read a row at a time; `None` when no row that
/// stands has the key.
pub fn standing_row<E: SessionEngine + ?Sized>(engine: &E, key: &ToldKey) -> Option<FaceLinkRow> {
    let mut at: usize = 0;
    while let Some(row) = engine.face_link_at(at) {
        if ToldKey::of_row(&row) == *key {
            return Some(row);
        }
        at = at.checked_add(1)?;
    }
    None
}

/// The told bits of the faces of an engine that reads its faces from snapshots, which the heap
/// holds: a row for each face row a replaying listener was told, kept past its face as its
/// tombstone. An engine that reserves its memory keeps the bits on its own face rows instead.
#[derive(Debug, Default)]
pub struct ToldLedger {
    rows: Vec<(FaceLinkRow, ToldBits)>,
}

impl ToldLedger {
    /// A ledger that notes nothing yet.
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Note `listener` of `plane` told of the row of `key`, which `stands` reads as the engine
    /// holds it now (`None` when it does not stand): whether the listener is to be told. A row
    /// that came and went before the listener was told it is not told; a row that was told already
    /// is not told again.
    pub fn tell_came(
        &mut self,
        plane: ToldPlane,
        listener: usize,
        key: &ToldKey,
        stands: Option<FaceLinkRow>,
    ) -> bool {
        if let Some((_, bits)) = self
            .rows
            .iter_mut()
            .find(|(row, _)| ToldKey::of_row(row) == *key)
        {
            return bits.set(plane, listener);
        }
        let Some(row) = stands else {
            return false;
        };
        let mut bits = ToldBits::default();
        let told = bits.set(plane, listener);
        if told {
            self.rows.push((row, bits));
        }
        told
    }

    /// Note `listener` of `plane` told that the row of `key` left: whether the listener is to
    /// be told, which it is only when it was told the row came. A tombstone no listener is left
    /// to tell is let go of.
    pub fn tell_went(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        let Some(at) = self
            .rows
            .iter()
            .position(|(row, bits)| ToldKey::of_row(row) == *key && bits.has(plane, listener))
        else {
            return false;
        };
        let Some((_, bits)) = self.rows.get_mut(at) else {
            return false;
        };
        let told = bits.clear(plane, listener);
        if bits.is_empty() {
            self.rows.swap_remove(at);
        }
        told
    }

    /// The first row `listener` of `plane` was told that no longer stands, as `stands` says
    /// of each key.
    pub fn first_gone(
        &self,
        plane: ToldPlane,
        listener: usize,
        stands: impl Fn(&ToldKey) -> bool,
    ) -> Option<FaceLinkRow> {
        self.rows
            .iter()
            .find(|(row, bits)| bits.has(plane, listener) && !stands(&ToldKey::of_row(row)))
            .map(|(row, _)| row.clone())
    }

    /// Note nothing more for `listener` of `plane`, which replays no more: the rows only it was
    /// told are let go of.
    pub fn forget(&mut self, plane: ToldPlane, listener: usize) {
        self.rows.retain_mut(|(_, bits)| {
            bits.clear(plane, listener);
            !bits.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::face::RowEnds;

    fn row(first: u8, link: usize) -> FaceLinkRow {
        FaceLinkRow {
            zid: [first; 16],
            whatami: 1,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            link,
            links: link.saturating_add(1),
            ends: RowEnds::None,
            kind: None,
            mtu: 0,
            group_endpoint: None,
            lost_after: 0,
        }
    }

    fn key(first: u8) -> ToldKey {
        ToldKey::of_row(&row(first, 0))
    }

    /// A row is told once to each listener, and only while it stands.
    ///
    /// # Control
    ///
    /// Answering `true` from `tell_came` for a row told already reds the second assertion.
    #[test]
    fn a_row_is_told_once_and_only_while_it_stands() {
        let mut ledger = ToldLedger::new();
        assert!(ledger.tell_came(ToldPlane::Transports, 0, &key(1), Some(row(1, 0))));
        assert!(!ledger.tell_came(ToldPlane::Transports, 0, &key(1), Some(row(1, 0))));
        assert!(ledger.tell_came(ToldPlane::Transports, 1, &key(1), Some(row(1, 0))));
        assert!(ledger.tell_came(ToldPlane::Links, 0, &key(1), Some(row(1, 0))));
        assert!(
            !ledger.tell_came(ToldPlane::Transports, 0, &key(2), None),
            "a row that came and went before it was told is not told"
        );
        assert!(
            !ledger.tell_went(ToldPlane::Transports, 0, &key(2)),
            "nor is it told it left"
        );
    }

    /// The union holds each listener of either side, in its own plane only.
    ///
    /// # Control
    ///
    /// A union that keeps one side's bits alone reds the first or the second assertion.
    #[test]
    fn a_union_holds_the_listeners_of_both_sides() {
        let mut one = ToldBits::default();
        one.set(ToldPlane::Transports, 0);
        let mut other = ToldBits::default();
        other.set(ToldPlane::Links, 3);
        let both = one.union(other);
        assert!(both.has(ToldPlane::Transports, 0));
        assert!(both.has(ToldPlane::Links, 3));
        assert!(!both.has(ToldPlane::Links, 0), "a bit stays in its plane");
        assert!(ToldBits::default().union(ToldBits::default()).is_empty());
    }

    /// A row that went is kept, as a tombstone, until every listener told it came was told it
    /// left, and a listener that replays no more lets go of its part.
    ///
    /// # Control
    ///
    /// Letting go of the row at the first `tell_went` reds the second listener's `first_gone`.
    #[test]
    fn a_tombstone_stays_until_every_listener_told_it_came_was_told_it_left() {
        let mut ledger = ToldLedger::new();
        ledger.tell_came(ToldPlane::Transports, 0, &key(3), Some(row(3, 0)));
        ledger.tell_came(ToldPlane::Links, 2, &key(3), Some(row(3, 0)));
        let gone = |_: &ToldKey| false;
        assert_eq!(
            ledger
                .first_gone(ToldPlane::Transports, 0, gone)
                .map(|row| row.zid),
            Some([3; 16])
        );
        assert!(ledger.tell_went(ToldPlane::Transports, 0, &key(3)));
        assert!(!ledger.tell_went(ToldPlane::Transports, 0, &key(3)));
        assert_eq!(
            ledger
                .first_gone(ToldPlane::Links, 2, gone)
                .map(|row| row.zid),
            Some([3; 16]),
            "the link listener still owes the row's departure"
        );
        ledger.forget(ToldPlane::Links, 2);
        assert!(ledger.first_gone(ToldPlane::Links, 2, gone).is_none());
        assert!(ledger.rows.is_empty(), "the tombstone is let go of");
        assert!(
            ledger
                .first_gone(ToldPlane::Transports, 0, |_| true)
                .is_none(),
            "a row that stands is no tombstone"
        );
    }
}
