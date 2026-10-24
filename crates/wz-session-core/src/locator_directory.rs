// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where a node may be reached: a zid's candidate locators, each held as soft
//! state (decision D3 of `docs/session-lifecycle-intent.md`).
//!
//! Identity and location are separate. A zid names a node; a locator is a hint
//! for reaching one, never the identity itself (LISP, RFC 9300 and RFC 9301;
//! ILNP, RFC 6740). A dial made from a hint is made FOR the zid it was found
//! under, and the session closes at the InitAck if another node answers
//! (decision D4), so a stale hint costs one failed dial and never a session to
//! the wrong node.
//!
//! Three sources confirm a hint, and they differ in how a hint stops being
//! true:
//!
//! - [`crate::locator_directory::LocatorSource::Declared`]: the build or the
//!   operator stated it. It does
//!   not expire and is never evicted; it leaves only when it is withdrawn.
//! - [`crate::locator_directory::LocatorSource::Hello`]: a scouting Hello from the node listed it. Nothing
//!   ever says a Hello's locators stopped being true, so the confirmation
//!   expires unless a later Hello confirms it again (soft state: Clark, 1988;
//!   Raman and McCanne, 1999), and it must carry a lifetime.
//! - [`crate::locator_directory::LocatorSource::Linkstate`]: the link-state
//!   flood carried it (AP). The
//!   flood is event-driven, and the graph drops a node it no longer reaches,
//!   so its source may confirm until it withdraws, or give a lifetime as a
//!   bound on a withdrawal it might miss.
//!
//! The directory is the mechanism only: how long a confirmation lasts is the
//! source's to say, since only the source knows how often it refreshes or
//! whether it withdraws, so every confirmation carries its own
//! [`crate::locator_directory::Lifetime`].
//!
//! Lookups never return an expired hint, whether or not
//! [`crate::locator_directory::LocatorDirectory::expire`] has run since. Candidates come in the order an opener should try them: the
//! declared ones first, as the operator's intent, then the most recently
//! confirmed first, as the likeliest to be current.
//!
//! The table is a fixed number of rows, so the fixed-memory profile holds the
//! same type with no allocator. When it is full, a confirmation of a new hint
//! displaces the soft-state row that would expire first; a table of declared
//! hints only refuses it, and counts the refusal.

use crate::caps::MAX_LOCATOR_LEN;
use crate::credential_identity::CREDENTIAL_ZID_BYTES;

/// A zid in its sixteen-byte form ([`crate::credential_identity::zid_from_wire`]).
pub type DirectoryZid = [u8; CREDENTIAL_ZID_BYTES];

/// A locator's text, as a node advertises it.
pub type LocatorText = heapless::String<MAX_LOCATOR_LEN>;

/// Who confirmed a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocatorSource {
    /// The build or the operator stated it.
    Declared,
    /// A scouting Hello from the node listed it.
    Hello,
    /// The link-state flood carried it.
    Linkstate,
}

impl LocatorSource {
    const COUNT: usize = 3;

    fn index(self) -> usize {
        match self {
            Self::Declared => 0,
            Self::Hello => 1,
            Self::Linkstate => 2,
        }
    }
}

/// How long one confirmation lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// Until the source withdraws it.
    Permanent,
    /// This many milliseconds after the confirmation.
    Millis(u64),
}

/// Why a confirmation was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryRefusal {
    /// The locator is longer than [`MAX_LOCATOR_LEN`] bytes.
    LocatorTooLong,
    /// Every row holds a declared hint, so none can make room.
    Full,
    /// A declared hint must be [`Lifetime::Permanent`], and a Hello's must not
    /// be, since no message ever withdraws it.
    LifetimeOfAnotherSource,
}

/// One hint: a zid, a locator, and when each source's confirmation of it ends.
#[derive(Debug, Clone)]
pub struct DirectoryRow {
    zid: DirectoryZid,
    locator: LocatorText,
    /// The instant each source's confirmation expires, `u64::MAX` for a
    /// permanent one, `None` for a source that has not confirmed it.
    expires_ms: [Option<u64>; LocatorSource::COUNT],
    /// The latest confirmation by any source.
    confirmed_ms: u64,
}

impl DirectoryRow {
    /// The zid the hint is for.
    pub fn zid(&self) -> &DirectoryZid {
        &self.zid
    }

    /// The locator.
    pub fn locator(&self) -> &str {
        self.locator.as_str()
    }

    /// The latest confirmation by any source, in the clock the directory is given.
    pub fn confirmed_ms(&self) -> u64 {
        self.confirmed_ms
    }

    /// Whether `source` confirms the hint at `now_ms`.
    pub fn confirmed_by(&self, source: LocatorSource, now_ms: u64) -> bool {
        self.expires_ms[source.index()].is_some_and(|end| now_ms < end)
    }

    fn is_live(&self, now_ms: u64) -> bool {
        self.expires_ms.iter().flatten().any(|end| now_ms < *end)
    }

    fn is_declared(&self) -> bool {
        self.expires_ms[LocatorSource::Declared.index()].is_some()
    }

    /// The instant the last of its confirmations ends.
    fn last_end_ms(&self) -> u64 {
        self.expires_ms.iter().flatten().copied().max().unwrap_or(0)
    }
}

/// A zid's candidate locators, `N` rows at most.
pub struct LocatorDirectory<const N: usize> {
    /// Oldest confirmation first, so the newest is at the end.
    rows: heapless::Vec<DirectoryRow, N>,
    refused: usize,
}

impl<const N: usize> Default for LocatorDirectory<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LocatorDirectory<N> {
    /// An empty directory.
    pub const fn new() -> Self {
        Self {
            rows: heapless::Vec::new(),
            refused: 0,
        }
    }

    /// `source` confirms that `zid` may be reached at `locator`, at `now_ms`, for
    /// `lifetime`. A hint already held is refreshed and becomes the newest; a new
    /// one takes a free row, or the row of the soft-state hint that would expire
    /// first.
    pub fn confirm(
        &mut self,
        zid: DirectoryZid,
        locator: &str,
        source: LocatorSource,
        now_ms: u64,
        lifetime: Lifetime,
    ) -> Result<(), DirectoryRefusal> {
        let end = match (source, lifetime) {
            (LocatorSource::Declared, Lifetime::Millis(_))
            | (LocatorSource::Hello, Lifetime::Permanent) => {
                self.refused += 1;
                return Err(DirectoryRefusal::LifetimeOfAnotherSource);
            }
            (_, Lifetime::Permanent) => u64::MAX,
            (_, Lifetime::Millis(ms)) => now_ms.saturating_add(ms),
        };
        let mut row = match self.position(&zid, locator) {
            Some(at) => self.rows.remove(at),
            None => {
                let Ok(text) = LocatorText::try_from(locator) else {
                    self.refused += 1;
                    return Err(DirectoryRefusal::LocatorTooLong);
                };
                if self.rows.is_full() && !self.make_room(now_ms) {
                    self.refused += 1;
                    return Err(DirectoryRefusal::Full);
                }
                DirectoryRow {
                    zid,
                    locator: text,
                    expires_ms: [None; LocatorSource::COUNT],
                    confirmed_ms: now_ms,
                }
            }
        };
        row.expires_ms[source.index()] = Some(end);
        row.confirmed_ms = row.confirmed_ms.max(now_ms);
        // The row came out of the table or there is room for it, so this push
        // cannot fail.
        let _ = self.rows.push(row);
        Ok(())
    }

    /// `source` no longer confirms any hint for `zid`: a node the link-state
    /// graph dropped, or a Hello that replaces the node's whole list. A hint
    /// another source still confirms stays.
    pub fn withdraw(&mut self, zid: &DirectoryZid, source: LocatorSource) {
        for row in self.rows.iter_mut().filter(|row| row.zid == *zid) {
            row.expires_ms[source.index()] = None;
        }
        self.rows
            .retain(|row| row.expires_ms.iter().any(Option::is_some));
    }

    /// Drop every hint no source confirms at `now_ms`, and say how many went.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.rows.len();
        for row in self.rows.iter_mut() {
            for end in row.expires_ms.iter_mut() {
                if end.is_some_and(|end| now_ms >= end) {
                    *end = None;
                }
            }
        }
        self.rows
            .retain(|row| row.expires_ms.iter().any(Option::is_some));
        before - self.rows.len()
    }

    /// The live candidates for `zid` at `now_ms`, in the order to try them: the
    /// declared ones, then the rest, the most recently confirmed first.
    pub fn candidates<'a>(
        &'a self,
        zid: &'a DirectoryZid,
        now_ms: u64,
    ) -> impl Iterator<Item = &'a DirectoryRow> + 'a {
        let live = move |row: &&DirectoryRow| row.zid == *zid && row.is_live(now_ms);
        let declared = self
            .rows
            .iter()
            .rev()
            .filter(live)
            .filter(move |row| row.confirmed_by(LocatorSource::Declared, now_ms));
        let rest = self
            .rows
            .iter()
            .rev()
            .filter(live)
            .filter(move |row| !row.confirmed_by(LocatorSource::Declared, now_ms));
        declared.chain(rest)
    }

    /// How many rows the directory holds, live or not yet expired by [`Self::expire`].
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the directory holds no row.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// How many confirmations were refused since the directory was made.
    pub fn refused(&self) -> usize {
        self.refused
    }

    fn position(&self, zid: &DirectoryZid, locator: &str) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.zid == *zid && row.locator.as_str() == locator)
    }

    /// Free one row: an expired one if there is one, or else the soft-state row
    /// whose last confirmation ends first. `false` when every row is declared.
    fn make_room(&mut self, now_ms: u64) -> bool {
        if self.expire(now_ms) > 0 {
            return true;
        }
        let victim = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| !row.is_declared())
            .min_by_key(|(_, row)| row.last_end_ms())
            .map(|(at, _)| at);
        match victim {
            Some(at) => {
                self.rows.remove(at);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: DirectoryZid = [0xa1; 16];
    const B: DirectoryZid = [0xb2; 16];

    fn locators<'a, const N: usize>(
        dir: &'a LocatorDirectory<N>,
        zid: &'a DirectoryZid,
        now_ms: u64,
    ) -> heapless::Vec<&'a str, N> {
        dir.candidates(zid, now_ms)
            .map(DirectoryRow::locator)
            .collect()
    }

    #[test]
    fn a_soft_hint_lasts_its_lifetime_and_a_declared_one_until_withdrawn() {
        let mut dir = LocatorDirectory::<4>::new();
        dir.confirm(
            A,
            "tcp/10.0.0.1:7447",
            LocatorSource::Declared,
            0,
            Lifetime::Permanent,
        )
        .unwrap();
        dir.confirm(
            A,
            "udp/10.0.0.2:7447",
            LocatorSource::Hello,
            0,
            Lifetime::Millis(100),
        )
        .unwrap();
        assert_eq!(locators(&dir, &A, 99).len(), 2);
        // Expired at its end, before any purge has run.
        assert_eq!(locators(&dir, &A, 100).as_slice(), ["tcp/10.0.0.1:7447"]);
        assert_eq!(dir.expire(100), 1, "the purge drops the soft hint only");
        assert_eq!(
            locators(&dir, &A, u64::MAX - 1).as_slice(),
            ["tcp/10.0.0.1:7447"]
        );
        dir.withdraw(&A, LocatorSource::Declared);
        assert!(
            dir.is_empty(),
            "a declared hint leaves when it is withdrawn"
        );
    }

    #[test]
    fn a_confirmation_refreshes_the_hint_and_makes_it_the_newest() {
        let mut dir = LocatorDirectory::<4>::new();
        dir.confirm(A, "udp/a:1", LocatorSource::Hello, 0, Lifetime::Millis(100))
            .unwrap();
        dir.confirm(
            A,
            "udp/a:2",
            LocatorSource::Hello,
            10,
            Lifetime::Millis(100),
        )
        .unwrap();
        assert_eq!(locators(&dir, &A, 20).as_slice(), ["udp/a:2", "udp/a:1"]);
        dir.confirm(
            A,
            "udp/a:1",
            LocatorSource::Hello,
            90,
            Lifetime::Millis(100),
        )
        .unwrap();
        assert_eq!(
            locators(&dir, &A, 95).as_slice(),
            ["udp/a:1", "udp/a:2"],
            "the most recently confirmed is tried first"
        );
        assert_eq!(
            locators(&dir, &A, 150).as_slice(),
            ["udp/a:1"],
            "the refresh moved its end; the other ended at 110"
        );
        assert_eq!(dir.len(), 2, "a refresh is one row, not two");
    }

    #[test]
    fn declared_hints_come_first_and_other_zids_are_not_candidates() {
        let mut dir = LocatorDirectory::<4>::new();
        dir.confirm(
            A,
            "udp/hello:1",
            LocatorSource::Hello,
            5,
            Lifetime::Millis(100),
        )
        .unwrap();
        dir.confirm(
            A,
            "tcp/declared:1",
            LocatorSource::Declared,
            0,
            Lifetime::Permanent,
        )
        .unwrap();
        dir.confirm(
            B,
            "tcp/b:1",
            LocatorSource::Linkstate,
            9,
            Lifetime::Millis(100),
        )
        .unwrap();
        assert_eq!(
            locators(&dir, &A, 10).as_slice(),
            ["tcp/declared:1", "udp/hello:1"]
        );
        assert_eq!(locators(&dir, &B, 10).as_slice(), ["tcp/b:1"]);
    }

    /// The flood withdraws what the graph no longer reaches, so its hint may last
    /// until then; a full table still takes a timed hint before it.
    #[test]
    fn a_link_state_hint_may_last_until_its_withdrawal_and_is_displaced_after_timed_ones() {
        let mut dir = LocatorDirectory::<2>::new();
        dir.confirm(
            A,
            "tcp/ls:1",
            LocatorSource::Linkstate,
            0,
            Lifetime::Permanent,
        )
        .unwrap();
        dir.confirm(
            A,
            "udp/hello:1",
            LocatorSource::Hello,
            0,
            Lifetime::Millis(500),
        )
        .unwrap();
        assert_eq!(locators(&dir, &A, 1_000_000).as_slice(), ["tcp/ls:1"]);
        dir.confirm(B, "udp/b:1", LocatorSource::Hello, 1, Lifetime::Millis(500))
            .unwrap();
        assert_eq!(
            locators(&dir, &A, 2).as_slice(),
            ["tcp/ls:1"],
            "the timed hint went first, though the link-state one is older"
        );
        dir.withdraw(&A, LocatorSource::Linkstate);
        assert_eq!(locators(&dir, &A, 2).len(), 0, "withdrawn, it is gone");
    }

    #[test]
    fn a_withdrawal_takes_one_source_away_and_leaves_the_others() {
        let mut dir = LocatorDirectory::<4>::new();
        dir.confirm(
            A,
            "tcp/a:1",
            LocatorSource::Linkstate,
            0,
            Lifetime::Millis(1000),
        )
        .unwrap();
        dir.confirm(
            A,
            "tcp/a:1",
            LocatorSource::Hello,
            0,
            Lifetime::Millis(1000),
        )
        .unwrap();
        dir.confirm(
            A,
            "tcp/a:2",
            LocatorSource::Linkstate,
            0,
            Lifetime::Millis(1000),
        )
        .unwrap();
        dir.withdraw(&A, LocatorSource::Linkstate);
        assert_eq!(
            locators(&dir, &A, 1).as_slice(),
            ["tcp/a:1"],
            "the hint Hello still confirms stays; the link-state-only one goes"
        );
        assert!(dir
            .candidates(&A, 1)
            .all(|row| !row.confirmed_by(LocatorSource::Linkstate, 1)));
    }

    #[test]
    fn a_full_table_displaces_the_soft_hint_that_ends_first_and_never_a_declared_one() {
        let mut dir = LocatorDirectory::<2>::new();
        dir.confirm(
            A,
            "tcp/declared:1",
            LocatorSource::Declared,
            0,
            Lifetime::Permanent,
        )
        .unwrap();
        dir.confirm(
            A,
            "udp/soon:1",
            LocatorSource::Hello,
            0,
            Lifetime::Millis(50),
        )
        .unwrap();
        dir.confirm(
            B,
            "udp/new:1",
            LocatorSource::Hello,
            1,
            Lifetime::Millis(500),
        )
        .unwrap();
        assert_eq!(locators(&dir, &A, 2).as_slice(), ["tcp/declared:1"]);
        assert_eq!(locators(&dir, &B, 2).as_slice(), ["udp/new:1"]);
        assert_eq!(dir.refused(), 0);

        let mut declared = LocatorDirectory::<1>::new();
        declared
            .confirm(
                A,
                "tcp/declared:1",
                LocatorSource::Declared,
                0,
                Lifetime::Permanent,
            )
            .unwrap();
        assert_eq!(
            declared.confirm(B, "udp/b:1", LocatorSource::Hello, 1, Lifetime::Millis(9)),
            Err(DirectoryRefusal::Full)
        );
        assert_eq!(declared.refused(), 1, "the refusal is counted");
        assert_eq!(locators(&declared, &A, 2).as_slice(), ["tcp/declared:1"]);
    }

    #[test]
    fn an_expired_row_is_the_first_room_a_full_table_takes() {
        let mut dir = LocatorDirectory::<1>::new();
        dir.confirm(
            A,
            "udp/old:1",
            LocatorSource::Hello,
            0,
            Lifetime::Millis(10),
        )
        .unwrap();
        dir.confirm(
            B,
            "udp/new:1",
            LocatorSource::Hello,
            20,
            Lifetime::Millis(10),
        )
        .unwrap();
        assert_eq!(locators(&dir, &B, 21).as_slice(), ["udp/new:1"]);
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn a_lifetime_that_does_not_fit_its_source_and_an_overlong_locator_are_refused() {
        let mut dir = LocatorDirectory::<2>::new();
        assert_eq!(
            dir.confirm(
                A,
                "tcp/a:1",
                LocatorSource::Declared,
                0,
                Lifetime::Millis(5)
            ),
            Err(DirectoryRefusal::LifetimeOfAnotherSource)
        );
        assert_eq!(
            dir.confirm(A, "tcp/a:1", LocatorSource::Hello, 0, Lifetime::Permanent),
            Err(DirectoryRefusal::LifetimeOfAnotherSource)
        );
        let mut long = heapless::String::<{ MAX_LOCATOR_LEN + 1 }>::new();
        for _ in 0..=MAX_LOCATOR_LEN {
            long.push('x').unwrap();
        }
        assert_eq!(
            dir.confirm(
                A,
                long.as_str(),
                LocatorSource::Hello,
                0,
                Lifetime::Millis(5)
            ),
            Err(DirectoryRefusal::LocatorTooLong)
        );
        assert_eq!(dir.refused(), 3);
        assert!(dir.is_empty());
    }
}
