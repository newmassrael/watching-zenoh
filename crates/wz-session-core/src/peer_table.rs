// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The peers a node is told to hold, each with its connection machine
//! (decision D5 of `docs/session-lifecycle-intent.md`).
//!
//! One [`peer_connection`](crate::peer_connection) machine per peer, keyed by
//! the peer's zid, in a table of `N` entries with no allocator, so the
//! fixed-memory profile holds the same table as AP. The lifecycle verbs are the
//! machine's administrative events (BGP's ManualStart and ManualStop, RFC 4271,
//! section 8): [`PeerTable::open`] and [`PeerTable::close`]. What the host
//! learns while it works for a peer (a resolution, the end of a dial, a lost
//! session, a timer) it reports with [`PeerTable::report`].
//!
//! Every call returns the [`PeerDuties`] the machine asked of the host: resolve
//! the candidates, dial them, arm or cancel the retry timer, give an attempt or
//! a session back. The host performs them and reports what came of them. The
//! table holds no timer, socket or session itself, so its behaviour is a pure
//! function of the calls it is given.
//!
//! A peer's machine stays in the table after `close`, in `Idle`, so its state
//! can still be read; a full table reuses an `Idle` entry for a new peer, and
//! refuses (and counts) only when every entry holds a peer the node is told to
//! hold.

use sce_rust_runtime::Engine;

use crate::constant_session_id::built_under_constant_id;
use crate::duty_outbox::{Duties, DutyOutbox};
use crate::locator_directory::DirectoryZid;
use crate::peer_connection::{
    PeerConnectionActions, PeerConnectionEvent, PeerConnectionPolicy, PeerConnectionState,
};

/// The id every peer machine is built under (SCE ADR 0045: the host gives a
/// machine its id). A constant, so the generated constructor never refuses it.
const PEER_CONNECTION_SESSION_ID: &str = "wz-peer-connection";

/// What the host is asked to do for a peer after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerDuties(Duties);

impl PeerDuties {
    /// Read the peer's candidates and report `ResolveFound` or `ResolveEmpty`.
    pub fn resolve(self) -> bool {
        self.0.has(PeerBinding::RESOLVE)
    }

    /// Take a session slot and dial the candidates for the peer's zid, then
    /// report how the dial ended.
    pub fn dial(self) -> bool {
        self.0.has(PeerBinding::DIAL)
    }

    /// Arm the retry timer at the schedule's next wait, and report `RetryDue`
    /// when it fires.
    pub fn arm_retry(self) -> bool {
        self.0.has(PeerBinding::ARM_RETRY)
    }

    /// Disarm the retry timer.
    pub fn cancel_retry(self) -> bool {
        self.0.has(PeerBinding::CANCEL_RETRY)
    }

    /// Drop the attempt under way and give back what it took.
    pub fn abandon_dial(self) -> bool {
        self.0.has(PeerBinding::ABANDON_DIAL)
    }

    /// Close the peer's session and give back its slot.
    pub fn close_session(self) -> bool {
        self.0.has(PeerBinding::CLOSE_SESSION)
    }

    /// A session came up: start the retry schedule over (the host keeps it
    /// damped while the peer oscillates).
    pub fn reset_retry(self) -> bool {
        self.0.has(PeerBinding::RESET_RETRY)
    }

    /// Whether nothing is asked.
    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

/// Why a peer could not be taken into the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerTableRefusal {
    /// Every entry holds a peer the node is told to hold.
    Full,
}

/// The host binding of one machine: each action body records its duty.
#[derive(Default)]
struct PeerBinding {
    duties: DutyOutbox,
}

impl PeerBinding {
    const RESOLVE: u8 = 1 << 0;
    const DIAL: u8 = 1 << 1;
    const ARM_RETRY: u8 = 1 << 2;
    const CANCEL_RETRY: u8 = 1 << 3;
    const ABANDON_DIAL: u8 = 1 << 4;
    const CLOSE_SESSION: u8 = 1 << 5;
    const RESET_RETRY: u8 = 1 << 6;
}

impl PeerConnectionActions for PeerBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn abandon_dial(&mut self) {
        self.duties.record(Self::ABANDON_DIAL);
    }

    fn arm_retry(&mut self) {
        self.duties.record(Self::ARM_RETRY);
    }

    fn cancel_retry(&mut self) {
        self.duties.record(Self::CANCEL_RETRY);
    }

    fn close_session(&mut self) {
        self.duties.record(Self::CLOSE_SESSION);
    }

    fn dial(&mut self) {
        self.duties.record(Self::DIAL);
    }

    fn reset_retry(&mut self) {
        self.duties.record(Self::RESET_RETRY);
    }

    fn resolve(&mut self) {
        self.duties.record(Self::RESOLVE);
    }
}

/// One peer and its machine.
struct PeerEntry {
    zid: DirectoryZid,
    engine: Engine<PeerConnectionPolicy<PeerBinding>>,
}

impl PeerEntry {
    fn new(zid: DirectoryZid) -> Self {
        let mut engine = Engine::new(built_under_constant_id(
            PeerConnectionPolicy::new_with_session_id(
                PEER_CONNECTION_SESSION_ID,
                PeerBinding::default(),
            ),
            "the peer connection session id",
        ));
        // W3C SCXML 3.3: enter the initial `Idle` leaf.
        engine.initialize();
        Self { zid, engine }
    }

    fn drive(&mut self, event: PeerConnectionEvent) -> PeerDuties {
        self.engine.process_event(event);
        PeerDuties(self.engine.policy().actions().duties.take())
    }

    fn state(&self) -> PeerConnectionState {
        self.engine.get_current_state()
    }
}

/// The peers a node is told to hold, `N` at most.
pub struct PeerTable<const N: usize> {
    entries: heapless::Vec<PeerEntry, N>,
    refused: usize,
}

impl<const N: usize> Default for PeerTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerTable<N> {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            refused: 0,
        }
    }

    /// `open` for `zid`: the authority `admitted` it or refused it. A peer the
    /// node already holds, or is working to hold, is unchanged (decision D6: a
    /// second `open` changes nothing).
    pub fn open(
        &mut self,
        zid: DirectoryZid,
        admitted: bool,
    ) -> Result<PeerDuties, PeerTableRefusal> {
        let event = if admitted {
            PeerConnectionEvent::ManualStart
        } else {
            PeerConnectionEvent::ManualRefused
        };
        let at = match self.position(&zid) {
            Some(at) => at,
            None => self.take_entry(zid)?,
        };
        Ok(self.entries[at].drive(event))
    }

    /// `close` for `zid`: the node no longer holds the peer. A peer it does not
    /// hold, or holds no intent for, is unchanged.
    pub fn close(&mut self, zid: &DirectoryZid) -> PeerDuties {
        self.report(zid, PeerConnectionEvent::ManualStop)
    }

    /// What came of a duty the host performed for `zid`. An event the peer's
    /// state has no transition for changes nothing, and a peer the table does
    /// not hold is not taken in by a report.
    pub fn report(&mut self, zid: &DirectoryZid, event: PeerConnectionEvent) -> PeerDuties {
        match self.position(zid) {
            Some(at) => self.entries[at].drive(event),
            None => PeerDuties(Duties::default()),
        }
    }

    /// The state of `zid`'s machine, or `None` for a peer the table does not
    /// hold. A refusal is read as its cause (`NoLocator`, `NoSlot`,
    /// `IdentityMismatch`, `AuthorityRefused`).
    pub fn state(&self, zid: &DirectoryZid) -> Option<PeerConnectionState> {
        self.position(zid).map(|at| self.entries[at].state())
    }

    /// Every peer in the table and its state.
    pub fn peers(&self) -> impl Iterator<Item = (&DirectoryZid, PeerConnectionState)> + '_ {
        self.entries.iter().map(|entry| (&entry.zid, entry.state()))
    }

    /// How many `open`s were refused for want of an entry.
    pub fn refused(&self) -> usize {
        self.refused
    }

    fn position(&self, zid: &DirectoryZid) -> Option<usize> {
        self.entries.iter().position(|entry| entry.zid == *zid)
    }

    /// An entry for a new peer: a free one, or one whose peer is in `Idle`.
    fn take_entry(&mut self, zid: DirectoryZid) -> Result<usize, PeerTableRefusal> {
        if !self.entries.is_full() {
            // Not full, so the push cannot fail.
            let _ = self.entries.push(PeerEntry::new(zid));
            return Ok(self.entries.len() - 1);
        }
        match self
            .entries
            .iter()
            .position(|entry| entry.state() == PeerConnectionState::Idle)
        {
            Some(at) => {
                self.entries[at] = PeerEntry::new(zid);
                Ok(at)
            }
            None => {
                self.refused += 1;
                Err(PeerTableRefusal::Full)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PeerConnectionEvent as E;
    use PeerConnectionState as S;

    const A: DirectoryZid = [0xa1; 16];
    const B: DirectoryZid = [0xb2; 16];

    #[test]
    fn an_open_peer_is_resolved_dialled_and_held_and_a_close_gives_its_session_back() {
        let mut table = PeerTable::<2>::new();
        let duties = table.open(A, true).unwrap();
        assert!(duties.resolve(), "open asks the host to resolve");
        assert_eq!(table.state(&A), Some(S::Resolving));
        assert!(table.report(&A, E::ResolveFound).dial());
        assert_eq!(table.state(&A), Some(S::Connecting));
        assert!(table.report(&A, E::DialEstablished).reset_retry());
        assert_eq!(table.state(&A), Some(S::Established));
        assert!(table.close(&A).close_session());
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_second_open_and_a_second_close_change_nothing() {
        let mut table = PeerTable::<2>::new();
        table.open(A, true).unwrap();
        table.report(&A, E::ResolveFound);
        table.report(&A, E::DialEstablished);
        let again = table.open(A, true).unwrap();
        assert!(again.is_empty(), "a second open asks for nothing");
        assert_eq!(table.state(&A), Some(S::Established));
        table.close(&A);
        assert!(
            table.close(&A).is_empty(),
            "a second close asks for nothing"
        );
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_failure_backs_off_and_retries_and_a_lost_session_does_too() {
        let mut table = PeerTable::<1>::new();
        table.open(A, true).unwrap();
        table.report(&A, E::ResolveFound);
        assert!(table.report(&A, E::DialFailed).arm_retry());
        assert_eq!(table.state(&A), Some(S::Backoff));
        assert!(table.report(&A, E::RetryDue).resolve());
        table.report(&A, E::ResolveFound);
        table.report(&A, E::DialEstablished);
        assert!(table.report(&A, E::SessionLost).arm_retry());
        assert_eq!(table.state(&A), Some(S::Backoff));
        assert!(table.close(&A).cancel_retry(), "a close disarms the timer");
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_refusal_names_its_cause_and_holds_until_the_next_open() {
        let cases = [
            (E::ResolveEmpty, S::NoLocator),
            (E::DialNoSlot, S::NoSlot),
            (E::DialMismatch, S::IdentityMismatch),
        ];
        for (event, cause) in cases {
            let mut table = PeerTable::<1>::new();
            table.open(A, true).unwrap();
            if event != E::ResolveEmpty {
                table.report(&A, E::ResolveFound);
            }
            table.report(&A, event);
            assert_eq!(table.state(&A), Some(cause));
            assert!(
                table.report(&A, E::RetryDue).is_empty(),
                "a refusal arms no retry"
            );
            assert!(
                table.open(A, true).unwrap().resolve(),
                "the next open tries again"
            );
        }
        let mut table = PeerTable::<1>::new();
        table.open(A, false).unwrap();
        assert_eq!(table.state(&A), Some(S::AuthorityRefused));
        assert!(table.close(&A).is_empty());
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_close_while_working_drops_the_attempt() {
        let mut table = PeerTable::<1>::new();
        table.open(A, true).unwrap();
        assert!(table.close(&A).abandon_dial(), "closed while resolving");
        table.open(A, true).unwrap();
        table.report(&A, E::ResolveFound);
        assert!(table.close(&A).abandon_dial(), "closed while dialling");
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_full_table_reuses_an_idle_entry_and_refuses_when_none_is() {
        let mut table = PeerTable::<1>::new();
        table.open(A, true).unwrap();
        assert_eq!(table.open(B, true), Err(PeerTableRefusal::Full));
        assert_eq!(table.refused(), 1, "the refusal is counted");
        table.close(&A);
        assert!(
            table.open(B, true).unwrap().resolve(),
            "A's idle entry is B's now"
        );
        assert_eq!(table.state(&A), None);
        assert_eq!(table.state(&B), Some(S::Resolving));
    }

    #[test]
    fn a_report_for_a_peer_the_table_does_not_hold_takes_nothing_in() {
        let mut table = PeerTable::<1>::new();
        assert!(table.report(&A, E::DialEstablished).is_empty());
        assert_eq!(table.state(&A), None);
        assert_eq!(table.peers().count(), 0);
    }
}
