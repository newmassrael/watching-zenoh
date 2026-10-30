// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The peers a node is told to hold, each with its connection machine
//! (decision D5 of `docs/session-lifecycle-intent.md`).
//!
//! One [`peer_connection`](crate::peer_connection) machine per peer, keyed by
//! what names the peer to its host (a node's zid, or a configured endpoint),
//! in a table of `N` entries with no allocator, so the
//! fixed-memory profile holds the same table as AP. The lifecycle verbs are the
//! machine's administrative events (BGP's ManualStart and ManualStop, RFC 4271,
//! section 8): [`crate::peer_table::PeerTable::open`] and
//! [`crate::peer_table::PeerTable::close`]. What the host
//! learns while it works for a peer (a resolution, the end of a dial, a lost
//! session, a timer) it reports with [`crate::peer_table::PeerTable::report`].
//!
//! Every call returns the [`crate::peer_table::PeerDuties`] the machine asked of
//! the host: resolve
//! the candidates, dial them, arm or cancel the retry timer, give an attempt or
//! a session back. The host performs them and reports what came of them. The
//! table holds no timer, socket or session itself, so its behaviour is a pure
//! function of the calls it is given.
//!
//! A peer's machine stays in the table after `close`, in `Idle`, so its state
//! can still be read; a full table reuses an `Idle` entry for a new peer, and
//! refuses (and counts) only when every entry holds a peer the node is told to
//! hold.

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use sce_rust_runtime::Engine;

use crate::duty_outbox::{Duties, DutyOutbox};
use crate::peer_connection::{
    PeerConnectionActions, PeerConnectionEvent, PeerConnectionPolicy, PeerConnectionState,
};
use sce_rust_runtime::helpers::session_id::SessionId;

/// The id every peer machine is built under (SCE ADR 0045: the host gives a
/// machine its id). A constant, so the generated constructor never refuses it.
const PEER_CONNECTION_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-peer-connection");

/// What the host is asked to do for a peer after an event. The default asks
/// for nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

/// A machine's state as a reader is shown it (decision D6: each peer's machine
/// state is readable): the state's word and, for a refusal, the cause its child
/// state names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateWords {
    /// `idle`, `resolving`, `connecting`, `established`, `backoff` or `refused`.
    pub state: &'static str,
    /// For `refused`, why: `no_locator`, `no_slot`, `identity_mismatch` or
    /// `authority_refused`.
    pub cause: Option<&'static str>,
}

impl PeerConnectionState {
    /// The words a reader is shown for this state. The one place the machine's
    /// states are spelled for a reader, matched without a wildcard, so a state the
    /// machine gains is a build error here rather than a reply that lacks it.
    pub const fn words(self) -> StateWords {
        let (state, cause) = match self {
            Self::Idle => ("idle", None),
            Self::Resolving => ("resolving", None),
            Self::Connecting => ("connecting", None),
            Self::Established => ("established", None),
            Self::Backoff => ("backoff", None),
            Self::Refused => ("refused", None),
            Self::NoLocator => ("refused", Some("no_locator")),
            Self::NoSlot => ("refused", Some("no_slot")),
            Self::IdentityMismatch => ("refused", Some("identity_mismatch")),
            Self::AuthorityRefused => ("refused", Some("authority_refused")),
        };
        StateWords { state, cause }
    }

    /// Whether a machine in this state holds a peer the node is told to hold (its
    /// intent, decision D6): every state but `Idle`, which is where `close` leaves
    /// a machine and the one a full table reuses. A refusal is held until the next
    /// `open`, so it is in the intent too.
    pub const fn in_intent(self) -> bool {
        !matches!(self, Self::Idle)
    }
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
struct PeerEntry<K> {
    key: K,
    engine: Engine<PeerConnectionPolicy<PeerBinding>>,
}

impl<K> PeerEntry<K> {
    /// Build the entry of `key` in `slot`, where the table keeps it, and enter its machine's
    /// initial state.
    ///
    /// The machine is a kilobyte. Built as a value and moved (into the entry, and the entry into
    /// the table's vector) it was a slot of the frame of every function it passed through, the
    /// planner's among them, on the path of the first dial, and the deepest the node reaches when
    /// it starts. The machine's own `new_in_place` writes it where it will live.
    fn init_in(slot: &mut MaybeUninit<Self>, key: K) -> &mut Self {
        let at = slot.as_mut_ptr();
        // SAFETY: `at` points at storage for one entry that holds no value. The key is written to
        // its field, and the machine is built in its field by `new_in_place`, which writes every
        // field of the engine; with both written the entry is whole, and it is lent as such.
        let entry = unsafe {
            addr_of_mut!((*at).key).write(key);
            let engine = &mut *addr_of_mut!((*at).engine)
                .cast::<MaybeUninit<Engine<PeerConnectionPolicy<PeerBinding>>>>();
            Engine::new_in_place(
                engine,
                PeerConnectionPolicy::new_with_checked_session_id(
                    PEER_CONNECTION_SESSION_ID,
                    PeerBinding::default(),
                ),
            );
            &mut *at
        };
        // W3C SCXML 3.3: enter the initial `Idle` leaf.
        entry.engine.initialize();
        entry
    }

    fn drive(&mut self, event: PeerConnectionEvent) -> PeerDuties {
        self.engine.process_event(event);
        PeerDuties(self.engine.policy().actions().duties.take())
    }

    fn state(&self) -> PeerConnectionState {
        self.engine.get_current_state()
    }
}

/// The peers a node is told to hold, `N` at most, each named by a `K`.
///
/// `K` is what names a peer to its host: a node's zid where the host dials a
/// node, or a configured endpoint where it dials a locator for no node
/// (decision D7: a target is a zid or a locator). The table compares keys and
/// nothing else.
pub struct PeerTable<K, const N: usize> {
    entries: heapless::Vec<PeerEntry<K>, N>,
    refused: usize,
}

impl<K, const N: usize> PeerTable<K, N> {
    /// Names every field of the table. [`PeerPlanner::new_boxed`](crate::peer_planner::PeerPlanner::new_boxed)
    /// takes the all-zero bytes of a table for an empty one, which holds while every field is a
    /// length-bounded vector or a count; a field added here stops this from compiling, so that
    /// whoever adds it reads that claim against it.
    #[allow(dead_code)]
    pub(crate) fn fields_are_read_by_the_boxed_planner(self) {
        let Self {
            entries: _,
            refused: _,
        } = self;
    }
}

impl<K: PartialEq, const N: usize> Default for PeerTable<K, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: PartialEq, const N: usize> PeerTable<K, N> {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            refused: 0,
        }
    }

    /// `open` for `key`: the authority `admitted` it or refused it. A peer the
    /// node already holds, or is working to hold, is unchanged (decision D6: a
    /// second `open` changes nothing).
    pub fn open(&mut self, key: K, admitted: bool) -> Result<PeerDuties, PeerTableRefusal> {
        let event = if admitted {
            PeerConnectionEvent::ManualStart
        } else {
            PeerConnectionEvent::ManualRefused
        };
        let at = match self.position(&key) {
            Some(at) => at,
            None => self.take_entry(key)?,
        };
        Ok(self.entries[at].drive(event))
    }

    /// `close` for `key`: the node no longer holds the peer, and its session is
    /// closed. A peer it does not hold, or holds no intent for, is unchanged.
    pub fn close(&mut self, key: &K) -> PeerDuties {
        self.report(key, PeerConnectionEvent::ManualStop)
    }

    /// Take `key` out of the table without asking for anything: the node stops
    /// working to hold the peer and leaves a session it has standing. Upstream's
    /// shape for an endpoint a `connect/endpoints` write no longer lists: it is
    /// not dialled again when it drops, and a live session to it is not closed
    /// (`zenoh/src/net/runtime/orchestrator.rs`
    /// @ `if peers.contains(&endpoint) && zwrite!(session.endpoints).remove(&endpoint) {`).
    /// The state the peer was in, or `None` for a peer the table did not hold.
    pub fn forget(&mut self, key: &K) -> Option<PeerConnectionState> {
        let at = self.position(key)?;
        Some(self.entries.swap_remove(at).state())
    }

    /// What came of a duty the host performed for `key`. An event the peer's
    /// state has no transition for changes nothing, and a peer the table does
    /// not hold is not taken in by a report.
    pub fn report(&mut self, key: &K, event: PeerConnectionEvent) -> PeerDuties {
        match self.position(key) {
            Some(at) => self.entries[at].drive(event),
            None => PeerDuties(Duties::default()),
        }
    }

    /// The state of `key`'s machine, or `None` for a peer the table does not
    /// hold. A refusal is read as its cause (`NoLocator`, `NoSlot`,
    /// `IdentityMismatch`, `AuthorityRefused`).
    pub fn state(&self, key: &K) -> Option<PeerConnectionState> {
        self.position(key).map(|at| self.entries[at].state())
    }

    /// Every peer in the table and its state.
    pub fn peers(&self) -> impl Iterator<Item = (&K, PeerConnectionState)> + '_ {
        self.entries.iter().map(|entry| (&entry.key, entry.state()))
    }

    /// How many `open`s were refused for want of an entry.
    pub fn refused(&self) -> usize {
        self.refused
    }

    fn position(&self, key: &K) -> Option<usize> {
        self.entries.iter().position(|entry| entry.key == *key)
    }

    /// An entry for a new peer: a free one, or one whose peer is in `Idle`.
    fn take_entry(&mut self, key: K) -> Result<usize, PeerTableRefusal> {
        if self.entries.is_full() {
            let Some(at) = self
                .entries
                .iter()
                .position(|entry| !entry.state().in_intent())
            else {
                self.refused += 1;
                return Err(PeerTableRefusal::Full);
            };
            // The row of a peer the node is not working to hold is given up, and the new peer
            // takes the free row at the end (the order of the rows is not a contract: `forget`
            // takes a row out the same way).
            drop(self.entries.swap_remove(at));
        }
        Ok(self.push_new(key))
    }

    /// Build the entry of `key` in the row after the last one, where it stays, and return its
    /// index. The table is not full.
    fn push_new(&mut self, key: K) -> usize {
        assert!(
            !self.entries.is_full(),
            "the caller made room for the entry"
        );
        let at = self.entries.len();
        // SAFETY: the table is not full, so row `at` is inside the vector's capacity and holds no
        // value; `init_in` writes the whole entry there, and the length moves over the row only
        // after that (an entry that failed to build is never counted, and so never dropped).
        unsafe {
            let slot = &mut *self
                .entries
                .as_mut_ptr()
                .add(at)
                .cast::<MaybeUninit<PeerEntry<K>>>();
            PeerEntry::init_in(slot, key);
            self.entries.set_len(at + 1);
        }
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locator_directory::DirectoryZid;
    use PeerConnectionEvent as E;
    use PeerConnectionState as S;

    const A: DirectoryZid = [0xa1; 16];
    const B: DirectoryZid = [0xb2; 16];

    #[test]
    fn an_open_peer_is_resolved_dialled_and_held_and_a_close_gives_its_session_back() {
        let mut table = PeerTable::<DirectoryZid, 2>::new();
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
        let mut table = PeerTable::<DirectoryZid, 2>::new();
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
        let mut table = PeerTable::<DirectoryZid, 1>::new();
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
            let mut table = PeerTable::<DirectoryZid, 1>::new();
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
        let mut table = PeerTable::<DirectoryZid, 1>::new();
        table.open(A, false).unwrap();
        assert_eq!(table.state(&A), Some(S::AuthorityRefused));
        assert!(table.close(&A).is_empty());
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_close_while_working_drops_the_attempt() {
        let mut table = PeerTable::<DirectoryZid, 1>::new();
        table.open(A, true).unwrap();
        assert!(table.close(&A).abandon_dial(), "closed while resolving");
        table.open(A, true).unwrap();
        table.report(&A, E::ResolveFound);
        assert!(table.close(&A).abandon_dial(), "closed while dialling");
        assert_eq!(table.state(&A), Some(S::Idle));
    }

    #[test]
    fn a_full_table_reuses_an_idle_entry_and_refuses_when_none_is() {
        let mut table = PeerTable::<DirectoryZid, 1>::new();
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
        let mut table = PeerTable::<DirectoryZid, 1>::new();
        assert!(table.report(&A, E::DialEstablished).is_empty());
        assert_eq!(table.state(&A), None);
        assert_eq!(table.peers().count(), 0);
    }

    /// A forgotten peer leaves the table with no duty asked, whatever its state:
    /// its session is the host's to leave standing, as upstream leaves one to an
    /// endpoint a config write stops listing. The key is any type that names a
    /// peer to its host.
    #[test]
    fn a_forgotten_peer_leaves_without_a_duty_and_its_session_stands() {
        let mut table = PeerTable::<&str, 2>::new();
        table.open("tcp/10.0.0.1:7447", true).unwrap();
        table.report(&"tcp/10.0.0.1:7447", E::ResolveFound);
        table.report(&"tcp/10.0.0.1:7447", E::DialEstablished);
        assert_eq!(table.forget(&"tcp/10.0.0.1:7447"), Some(S::Established));
        assert_eq!(table.state(&"tcp/10.0.0.1:7447"), None);
        assert!(
            table
                .report(&"tcp/10.0.0.1:7447", E::SessionLost)
                .is_empty(),
            "a forgotten peer is not dialled again when it drops"
        );
        assert_eq!(table.forget(&"tcp/10.0.0.1:7447"), None);
    }

    /// Decision D6 — what a reader is shown, read off a machine driven there: a
    /// refusal names its cause, a held peer is in the intent, and only the state
    /// `close` leaves is out of it.
    #[test]
    fn a_state_is_shown_by_its_word_and_a_refusal_by_its_cause() {
        let mut table = PeerTable::<DirectoryZid, 2>::new();
        table.open(A, true).unwrap();
        table.report(&A, E::ResolveEmpty);
        let refused = table.state(&A).unwrap();
        assert_eq!(
            refused.words(),
            StateWords {
                state: "refused",
                cause: Some("no_locator")
            }
        );
        assert!(refused.in_intent(), "a refusal holds until the next open");

        table.open(B, true).unwrap();
        table.report(&B, E::ResolveFound);
        table.report(&B, E::DialEstablished);
        let held = table.state(&B).unwrap();
        assert_eq!(held.words().state, "established");
        assert_eq!(held.words().cause, None);
        assert!(held.in_intent());

        table.close(&B);
        let closed = table.state(&B).unwrap();
        assert_eq!(closed.words().state, "idle");
        assert!(!closed.in_intent(), "a closed peer is out of the intent");
    }
}
