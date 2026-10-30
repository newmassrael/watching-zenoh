// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host of the peer connection machines, written once for every profile
//! (decision D5 of `docs/session-lifecycle-intent.md`).
//!
//! [`crate::peer_table::PeerTable`] holds one machine per peer and asks things of
//! its host as duties: resolve the candidates, dial them, arm or cancel a retry,
//! give an attempt or a session back. This module is that host's bookkeeping, and
//! it is the same on every profile: which face a dial opened, which peer each
//! held face is held for, which retry timer is still its peer's, which zid a
//! peer's last session named. What differs between profiles is only what a peer
//! IS to the host (a node's zid, or a configured endpoint), where its candidates
//! come from, and how long to wait, and the host answers those through
//! [`PeerPorts`](crate::peer_planner::PeerPorts).
//!
//! It is a PLANNER, not a driver: every call hands the actions the host is to take
//! to a sink the caller gives (dial this target as this face, wake me for this
//! peer after this long, drop this face), and the host takes them. Nothing here
//! awaits, dials or holds a socket, so the whole of the peer lifecycle is reachable
//! by a unit test, and the same code runs on a host with an allocator and on one
//! without.
//!
//! # Memory
//!
//! Every table is a fixed-capacity vector, so the planner costs the heap nothing.
//! `N` bounds the peers, and with them the held faces, the armed timers and the
//! remembered zids, each of which is at most one per peer. `D` bounds the dials in
//! flight together with the ones a peer stopped wanting while they ran, which stay
//! until they end; a dial the planner has no room to track is not made, and the
//! peer's machine is told the host has no slot for it, as it is when the host
//! itself has none.

use heapless::Vec;

use crate::locator_directory::DirectoryZid;
use crate::peer_connection::{PeerConnectionEvent as E, PeerConnectionState};
use crate::peer_table::{PeerDuties, PeerTable, PeerTableRefusal};

/// What the host is to do for the peers it holds.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerAction<K, I, T> {
    /// Dial `target` (made for `key`) as face `id`.
    Dial {
        /// The face the dial opens.
        id: I,
        /// The peer the dial is made for.
        key: K,
        /// What to dial.
        target: T,
    },
    /// Report [`PeerPlanner::retry_due`] for `key` and `generation` after
    /// `after_ms`.
    Retry {
        /// The peer.
        key: K,
        /// Which arming this is. A timer of an earlier arming that fires after its
        /// peer was forgotten, or left the wait another way, is not the peer's
        /// retry, and [`PeerPlanner::retry_due`] drops it.
        generation: u64,
        /// The wait, from the host's retry schedule.
        after_ms: u64,
        /// Whether the wait follows the loss of a session the peer held, the one
        /// wait an operator is told of at a higher level than the others.
        after_loss: bool,
    },
    /// Drop face `id`: a session its peer no longer wants. Raised only when a
    /// peer's machine is stopped from Established (`manual.stop`: a lifecycle
    /// `close`, or a host that stops holding a peer and hangs its session up), so a
    /// host that never stops a peer is never asked for it.
    Close {
        /// The face.
        id: I,
    },
}

/// How a dial the planner asked for ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialEnd<I> {
    /// A session to the peer is up, held as the dialled face.
    Established {
        /// The zid the session's remote named, which a `close` names it by.
        remote: Option<DirectoryZid>,
    },
    /// A session to the peer is up, but the host holds it as `held`, another face
    /// (the peer was already reached another way, or the dialled link joined the
    /// session `held` represents); the dialled face is not held on its own.
    AlreadyHeld {
        /// The face the host holds to the peer.
        held: I,
        /// The zid the session's remote named, which a `close` names it by.
        remote: Option<DirectoryZid>,
    },
    /// The host has no room for another session.
    NoSlot,
    /// Another node answered at the locator (decision D4).
    Mismatch,
    /// The dial failed otherwise: unreachable, refused, timed out.
    Failed,
}

/// What the host answers for the planner: what a peer is dialled at, and how long
/// to wait before dialling it again.
pub trait PeerPorts<K> {
    /// What the host dials.
    type Target;

    /// What to dial for `key` now, or `None` when the host knows no candidate for
    /// it that it can dial.
    fn dialable(&self, key: &K) -> Option<Self::Target>;

    /// The next wait before `key` is dialled again, on the host's retry schedule.
    /// Asking advances the schedule's growth.
    fn retry_wait_ms(&mut self, key: &K) -> u64;

    /// Start `key`'s retry schedule over: a session came up, or the peer left the
    /// wait, so its outage is over.
    fn retry_restart(&mut self, key: &K);
}

/// What a dial the planner asked for is, while it runs.
#[derive(Debug, Clone)]
enum DialState<K> {
    /// Running for `K`.
    Running(K),
    /// Its peer stopped wanting it while it ran: a session it opens is dropped when
    /// it ends.
    Abandoned,
    /// Its peer was forgotten while it ran: a session it opens is left standing,
    /// owned by no machine.
    Released,
}

/// The peers a host holds, each driven by its connection machine, and what the host
/// is doing for each. `K` names a peer, `I` a face, `N` bounds the peers and `D` the
/// dials.
pub struct PeerPlanner<K, I, const N: usize, const D: usize> {
    table: PeerTable<K, N>,
    /// Dials under way, by the face they open.
    dials: Vec<(I, DialState<K>), D>,
    /// The face each peer's session is held as. One per peer: a peer is one
    /// session, however many links it joined, and the face is its primary's.
    held: Vec<(K, I), N>,
    /// The arming of each peer's retry timer that is still its own.
    armed: Vec<(K, u64), N>,
    /// The zid each peer's last session named, kept after the session is lost: a
    /// `close` names a node by its zid, and an endpoint, which has none of its own,
    /// is the node it reached (decision D6).
    remotes: Vec<(K, DirectoryZid), N>,
    /// The next arming's generation.
    next_generation: u64,
}

/// Find `key` in a vector of `(key, value)` rows.
fn row<'a, K: PartialEq, V, const M: usize>(rows: &'a Vec<(K, V), M>, key: &K) -> Option<&'a V> {
    rows.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Set `key`'s row to `value`, replacing the one it had. `false` when the vector has
/// no room for a new row.
fn set_row<K: PartialEq, V, const M: usize>(rows: &mut Vec<(K, V), M>, key: K, value: V) -> bool {
    if let Some(at) = rows.iter().position(|(k, _)| *k == key) {
        rows[at].1 = value;
        return true;
    }
    rows.push((key, value)).is_ok()
}

/// Remove `key`'s row, if it has one.
fn drop_row<K: PartialEq, V, const M: usize>(rows: &mut Vec<(K, V), M>, key: &K) {
    if let Some(at) = rows.iter().position(|(k, _)| k == key) {
        rows.swap_remove(at);
    }
}

impl<K, I, const N: usize, const D: usize> Default for PeerPlanner<K, I, N, D>
where
    K: Clone + Ord,
    I: Copy + Ord + From<u64>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, I, const N: usize, const D: usize> PeerPlanner<K, I, N, D>
where
    K: Clone + Ord,
    I: Copy + Ord + From<u64>,
{
    /// No peer held.
    pub const fn new() -> Self {
        Self {
            table: PeerTable::new(),
            dials: Vec::new(),
            held: Vec::new(),
            armed: Vec::new(),
            remotes: Vec::new(),
            next_generation: 0,
        }
    }

    /// No peer held, built on the heap and never as a value on the stack.
    ///
    /// A planner holds its rows inline, so a large one is hundreds of kilobytes, and `Box::new(Self::new())`
    /// builds it on the stack first: an unoptimised build passes it through several frames, and a thread of
    /// the ordinary two-megabyte stack overflows. The empty planner is the all-zero bytes: every field is a
    /// vector bounded in length, which is empty at length zero whatever its buffer holds, or a count that
    /// starts at zero. A field of another kind has to be read against this, which the pattern below makes
    /// the compiler ask of whoever adds one.
    #[cfg(feature = "alloc")]
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        // Exhaustive on purpose: see above.
        let _fields_are_read = |planner: Self| {
            let Self {
                table,
                dials: _,
                held: _,
                armed: _,
                remotes: _,
                next_generation: _,
            } = planner;
            table.fields_are_read_by_the_boxed_planner();
        };
        let layout = core::alloc::Layout::new::<Self>();
        // A planner holds a length and a generation at the least, so its size is never zero, which
        // `alloc_zeroed` needs.
        debug_assert!(layout.size() != 0);
        // SAFETY: the layout is that of `Self`, of a size that is not zero. Each field of `Self` is valid
        // as all-zero bytes and is then the field of `new()`: a `heapless::Vec` of length zero (its buffer
        // is never read below its length), a `usize` count of zero, a `u64` generation of zero, and
        // `table` is a vector and a count. The pointer is the allocator's own for that layout, which
        // `Box` frees with the same one.
        unsafe {
            let at = alloc::alloc::alloc_zeroed(layout).cast::<Self>();
            if at.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            alloc::boxed::Box::from_raw(at)
        }
    }

    /// `open` for `key`, which the authority admitted. A peer already held or being
    /// reached is unchanged, and one its machine refused tries again (decision D6).
    /// `Err` when the table has no room to hold another peer.
    pub fn open<P: PeerPorts<K>>(
        &mut self,
        key: K,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) -> Result<(), PeerTableRefusal> {
        let duties = self.table.open(key.clone(), true)?;
        self.perform(key, duties, false, ports, next_id, emit);
        Ok(())
    }

    /// The retry timer `generation` of `key` fired. A timer whose arming is no
    /// longer the peer's changes nothing.
    pub fn retry_due<P: PeerPorts<K>>(
        &mut self,
        key: K,
        generation: u64,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) {
        if row(&self.armed, &key) != Some(&generation) {
            return;
        }
        drop_row(&mut self.armed, &key);
        let duties = self.table.report(&key, E::RetryDue);
        self.perform(key, duties, false, ports, next_id, emit);
    }

    /// Whether face `id` is a dial this planner asked for, running or not wanted
    /// any more.
    pub fn is_dialing(&self, id: I) -> bool {
        self.dials.iter().any(|(face, _)| *face == id)
    }

    /// The peer a dial of this planner's is running for, or `None` for a face that
    /// is no dial of its own, or one its peer stopped wanting.
    pub fn dial_key(&self, id: I) -> Option<&K> {
        self.dials.iter().find_map(|(face, state)| match state {
            DialState::Running(key) if *face == id => Some(key),
            _ => None,
        })
    }

    /// The dial of face `id` ended as `end`. `None` when the face is not one of this
    /// planner's dials. The `bool` says whether the host is to hold the face.
    pub fn dial_ended<P: PeerPorts<K>>(
        &mut self,
        id: I,
        end: DialEnd<I>,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) -> Option<bool> {
        let at = self.dials.iter().position(|(face, _)| *face == id)?;
        let (_, state) = self.dials.swap_remove(at);
        let key = match state {
            // Its peer stopped wanting it while it ran: a session that came up is
            // dropped, and nothing is reported to a machine that is past it.
            DialState::Abandoned => return Some(false),
            // Its peer was forgotten while it ran: a session that came up stands,
            // owned by no machine, as a forgotten peer's held session does.
            DialState::Released => return Some(matches!(end, DialEnd::Established { .. })),
            DialState::Running(key) => key,
        };
        let (event, keep) = match end {
            DialEnd::Established { remote } => {
                self.hold(&key, id);
                self.learn_remote(&key, remote);
                (E::DialEstablished, true)
            }
            DialEnd::AlreadyHeld { held, remote } => {
                self.hold(&key, held);
                self.learn_remote(&key, remote);
                (E::DialEstablished, false)
            }
            DialEnd::NoSlot => (E::DialNoSlot, false),
            DialEnd::Mismatch => (E::DialMismatch, false),
            DialEnd::Failed => (E::DialFailed, false),
        };
        let duties = self.table.report(&key, event);
        self.perform(key, duties, false, ports, next_id, emit);
        Some(keep)
    }

    /// Face `id` died. `false` when it is not a face a peer is held by.
    pub fn face_down<P: PeerPorts<K>>(
        &mut self,
        id: I,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) -> bool {
        let mut lost: Vec<K, N> = Vec::new();
        for (key, face) in &self.held {
            if *face == id {
                // At most one peer per row of `held`, and `held` has `N` rows.
                let _ = lost.push(key.clone());
            }
        }
        if lost.is_empty() {
            return false;
        }
        lost.sort_unstable();
        self.held.retain(|(_, face)| *face != id);
        for key in lost {
            let duties = self.table.report(&key, E::SessionLost);
            self.perform(key, duties, true, ports, next_id, emit);
        }
        true
    }

    /// `close` for the node `zid` (decision D6): every machine that holds it, its own
    /// (`node`) and that of each peer whose last session reached it, is stopped. A
    /// session it holds is closed, a dial it runs is dropped and a wait it is in is
    /// cancelled, and the peer is not dialled again until an `open` starts it. The
    /// machine stays in the table, `Idle`.
    pub fn withdraw<P: PeerPorts<K>>(
        &mut self,
        zid: &DirectoryZid,
        node: K,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) {
        let mut keys: Vec<K, N> = Vec::new();
        for (key, remote) in &self.remotes {
            if remote == zid && *key != node {
                // At most one row per peer, and `remotes` has `N` rows.
                let _ = keys.push(key.clone());
            }
        }
        keys.sort_unstable();
        // The node's own machine last, with a table that has room for it or not.
        let _ = keys.push(node);
        for key in keys {
            self.stop(&key, ports, next_id, emit);
        }
    }

    /// Stop the machine of `key` (`manual.stop`): the session it holds is closed
    /// (a [`PeerAction::Close`]), a dial it runs is dropped and a wait it is in is
    /// cancelled, and the peer is not dialled again until an `open` starts it. The
    /// machine stays in the table, `Idle`; [`Self::forget`] takes it out. A host
    /// that stops holding a peer it dialled (a configured endpoint the list no
    /// longer names) stops it, so the session is hung up, and then forgets it.
    pub fn stop<P: PeerPorts<K>>(
        &mut self,
        key: &K,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) {
        let duties = self.table.close(key);
        self.perform(key.clone(), duties, false, ports, next_id, emit);
    }

    /// Stop working to hold `key`, and leave a session it has standing: its machine
    /// leaves the table asking for nothing, its timer is disowned and a dial it runs
    /// ends unowned. The host forgets its own schedule for the peer.
    pub fn forget(&mut self, key: &K) {
        self.table.forget(key);
        drop_row(&mut self.armed, key);
        drop_row(&mut self.remotes, key);
        for (_, state) in self.dials.iter_mut() {
            if matches!(state, DialState::Running(running) if running == key) {
                *state = DialState::Released;
            }
        }
        drop_row(&mut self.held, key);
    }

    /// The state of `key`'s machine.
    pub fn state(&self, key: &K) -> Option<PeerConnectionState> {
        self.table.state(key)
    }

    /// Every machine, with the zid its last session named, for the status read
    /// (decision D6).
    pub fn machines(
        &self,
    ) -> impl Iterator<Item = (&K, PeerConnectionState, Option<&DirectoryZid>)> + '_ {
        self.table
            .peers()
            .map(|(key, state)| (key, state, row(&self.remotes, key)))
    }

    /// The face a peer's session is held as.
    fn hold(&mut self, key: &K, face: I) {
        // One row per peer, and the table that bounds the peers bounds `held`.
        let _ = set_row(&mut self.held, key.clone(), face);
    }

    /// Keep the zid `key`'s session named, for a later `close` to name it by.
    fn learn_remote(&mut self, key: &K, remote: Option<DirectoryZid>) {
        if let Some(remote) = remote {
            let _ = set_row(&mut self.remotes, key.clone(), remote);
        }
    }

    /// Perform `duties` for `key`, and the duties each answer raises in turn.
    /// `lost` says whether they answer a held session's loss.
    fn perform<P: PeerPorts<K>>(
        &mut self,
        key: K,
        mut duties: PeerDuties,
        lost: bool,
        ports: &mut P,
        next_id: &mut u64,
        emit: &mut dyn FnMut(PeerAction<K, I, P::Target>),
    ) {
        while !duties.is_empty() {
            let mut next = PeerDuties::default();
            if duties.reset_retry() || duties.cancel_retry() {
                ports.retry_restart(&key);
            }
            if duties.cancel_retry() {
                drop_row(&mut self.armed, &key);
            }
            if duties.abandon_dial() {
                for (_, state) in self.dials.iter_mut() {
                    if matches!(state, DialState::Running(running) if *running == key) {
                        *state = DialState::Abandoned;
                    }
                }
            }
            if duties.close_session() {
                if let Some(id) = row(&self.held, &key).copied() {
                    drop_row(&mut self.held, &key);
                    emit(PeerAction::Close { id });
                }
            }
            if duties.arm_retry() {
                let after_ms = ports.retry_wait_ms(&key);
                let generation = self.next_generation;
                self.next_generation += 1;
                // One row per peer, bounded by the table.
                let _ = set_row(&mut self.armed, key.clone(), generation);
                emit(PeerAction::Retry {
                    key: key.clone(),
                    generation,
                    after_ms,
                    after_loss: lost,
                });
            }
            if duties.resolve() {
                let found = ports.dialable(&key).is_some();
                next = self.table.report(
                    &key,
                    if found {
                        E::ResolveFound
                    } else {
                        E::ResolveEmpty
                    },
                );
            } else if duties.dial() {
                match ports.dialable(&key) {
                    Some(target) => {
                        let id = I::from(*next_id);
                        if self
                            .dials
                            .push((id, DialState::Running(key.clone())))
                            .is_ok()
                        {
                            *next_id += 1;
                            emit(PeerAction::Dial {
                                id,
                                key: key.clone(),
                                target,
                            });
                        } else {
                            // No room to track another dial: it is not made, and the
                            // machine is told the host has no slot for it.
                            next = self.table.report(&key, E::DialNoSlot);
                        }
                    }
                    // The candidates went between the resolution and the dial.
                    None => next = self.table.report(&key, E::DialFailed),
                }
            }
            duties = next;
        }
    }
}

// The planner itself needs no allocator (it builds for a bare-metal target with
// none); its tests collect the actions into a growable vector.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::vec::Vec as Vector;
    use PeerConnectionState as S;

    /// A face: the planner mints it from the counter it is given.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Face(u64);

    impl From<u64> for Face {
        fn from(id: u64) -> Self {
            Self(id)
        }
    }

    const A: DirectoryZid = [0xa1; 16];
    const B: DirectoryZid = [0xb2; 16];

    /// A host that dials a peer if it has a candidate for it, waits 100 ms and
    /// counts the times a schedule was started over.
    #[derive(Default)]
    struct Host {
        candidates: Vector<u8>,
        restarts: usize,
        waits: usize,
    }

    impl PeerPorts<u8> for Host {
        type Target = &'static str;

        fn dialable(&self, key: &u8) -> Option<&'static str> {
            self.candidates.contains(key).then_some("target")
        }

        fn retry_wait_ms(&mut self, _key: &u8) -> u64 {
            self.waits += 1;
            100
        }

        fn retry_restart(&mut self, _key: &u8) {
            self.restarts += 1;
        }
    }

    type Plan = PeerPlanner<u8, Face, 4, 6>;
    type Action = PeerAction<u8, Face, &'static str>;

    #[test]
    fn a_planner_built_on_the_heap_holds_and_dials_as_one_built_by_value() {
        let mut by_value = Plan::new();
        let mut on_heap = Plan::new_boxed();
        assert_eq!(on_heap.state(&1), None);
        let (mut host, mut next_id) = (
            Host {
                candidates: Vector::from([1]),
                ..Host::default()
            },
            0,
        );
        let (mut host_heap, mut next_heap) = (
            Host {
                candidates: Vector::from([1]),
                ..Host::default()
            },
            0,
        );
        let value = actions(|e| by_value.open(1, &mut host, &mut next_id, e).unwrap());
        let heap = actions(|e| on_heap.open(1, &mut host_heap, &mut next_heap, e).unwrap());
        let (id_value, id_heap) = (dial_of(&value), dial_of(&heap));
        assert_eq!(id_value, id_heap);
        assert_eq!(by_value.state(&1), on_heap.state(&1));
        assert_eq!(on_heap.state(&1), Some(S::Connecting));
        assert!(on_heap.is_dialing(id_heap));
        assert_eq!(on_heap.dial_key(id_heap), Some(&1));
    }

    /// Run one planner call and return what it asked of the host.
    fn actions(call: impl FnOnce(&mut dyn FnMut(Action))) -> Vector<Action> {
        let mut out = Vector::new();
        call(&mut |action| out.push(action));
        out
    }

    fn dial_of(actions: &[Action]) -> Face {
        match actions {
            [PeerAction::Dial { id, .. }] => *id,
            other => panic!("expected one dial, got {other:?}"),
        }
    }

    fn retry_of(actions: &[Action]) -> (u8, u64, u64, bool) {
        match actions {
            [PeerAction::Retry {
                key,
                generation,
                after_ms,
                after_loss,
            }] => (*key, *generation, *after_ms, *after_loss),
            other => panic!("expected one retry, got {other:?}"),
        }
    }

    /// An open resolves, dials and holds the face the dial opens; the loss of that
    /// face waits on the schedule and says it follows a loss; the timer dials again.
    #[test]
    fn an_open_dials_holds_and_a_lost_face_is_retried() {
        let mut host = Host {
            candidates: Vector::from([1]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;

        let dial = actions(|e| plan.open(1, &mut host, &mut next_id, e).unwrap());
        let id = dial_of(&dial);
        assert_eq!(plan.state(&1), Some(S::Connecting));
        assert!(plan.is_dialing(id));
        assert_eq!(plan.dial_key(id), Some(&1));

        let up = actions(|e| {
            assert_eq!(
                plan.dial_ended(
                    id,
                    DialEnd::Established { remote: Some(A) },
                    &mut host,
                    &mut next_id,
                    e
                ),
                Some(true)
            );
        });
        assert!(up.is_empty());
        assert_eq!(plan.state(&1), Some(S::Established));
        assert!(!plan.is_dialing(id), "the dial is over");
        assert_eq!(host.restarts, 1, "a session up starts the schedule over");

        let lost = actions(|e| assert!(plan.face_down(id, &mut host, &mut next_id, e)));
        let (key, generation, after_ms, after_loss) = retry_of(&lost);
        assert_eq!((key, after_ms, after_loss), (1, 100, true));
        assert_eq!(plan.state(&1), Some(S::Backoff));

        let again = actions(|e| plan.retry_due(1, generation, &mut host, &mut next_id, e));
        assert_eq!(dial_of(&again), Face(1));
        assert!(
            !plan.face_down(Face(9), &mut host, &mut next_id, &mut |_| {}),
            "a face no peer is held by"
        );
    }

    /// A peer with no candidate is refused by its machine as `NoLocator`; an
    /// outcome the host reports for another peer's dial is no outcome of this one.
    #[test]
    fn a_peer_with_no_candidate_is_refused_and_a_foreign_dial_is_nobodys() {
        let mut host = Host::default();
        let mut plan = Plan::new();
        let mut next_id = 0;
        let out = actions(|e| plan.open(1, &mut host, &mut next_id, e).unwrap());
        assert!(out.is_empty(), "nothing to dial, and no retry of a refusal");
        assert_eq!(plan.state(&1), Some(S::NoLocator));

        let none = actions(|e| {
            assert_eq!(
                plan.dial_ended(Face(7), DialEnd::Failed, &mut host, &mut next_id, e),
                None
            );
        });
        assert!(none.is_empty());
    }

    /// A timer of an arming that is no longer the peer's dials nothing.
    #[test]
    fn a_stale_timer_dials_nothing() {
        let mut host = Host {
            candidates: Vector::from([1]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        let id = dial_of(&actions(|e| {
            plan.open(1, &mut host, &mut next_id, e).unwrap()
        }));
        let failed = actions(|e| {
            plan.dial_ended(id, DialEnd::Failed, &mut host, &mut next_id, e);
        });
        let (_, generation, _, _) = retry_of(&failed);

        plan.forget(&1);
        assert_eq!(plan.state(&1), None);
        let stale = actions(|e| plan.retry_due(1, generation, &mut host, &mut next_id, e));
        assert!(
            stale.is_empty(),
            "the peer was forgotten, so its timer is nobody's"
        );
    }

    /// A dial whose peer is forgotten while it runs ends unowned and its session
    /// stands; one whose peer stops wanting it ends dropped.
    #[test]
    fn a_released_dial_is_held_unowned_and_an_abandoned_one_is_dropped() {
        let mut host = Host {
            candidates: Vector::from([1, 2]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        let one = dial_of(&actions(|e| {
            plan.open(1, &mut host, &mut next_id, e).unwrap()
        }));
        plan.forget(&1);
        assert!(plan.is_dialing(one));
        assert_eq!(plan.dial_key(one), None, "no peer owns it any more");
        let kept = actions(|e| {
            assert_eq!(
                plan.dial_ended(
                    one,
                    DialEnd::Established { remote: None },
                    &mut host,
                    &mut next_id,
                    e
                ),
                Some(true)
            );
        });
        assert!(kept.is_empty());
        assert!(
            !plan.face_down(one, &mut host, &mut next_id, &mut |_| {}),
            "no peer holds it"
        );

        // A refusal after the open abandons nothing here; a withdrawal does.
        let two = dial_of(&actions(|e| {
            plan.open(2, &mut host, &mut next_id, e).unwrap()
        }));
        let none = actions(|e| plan.withdraw(&B, 2, &mut host, &mut next_id, e));
        assert!(none.is_empty());
        assert_eq!(plan.state(&2), Some(S::Idle));
        let ended = actions(|e| {
            assert_eq!(
                plan.dial_ended(
                    two,
                    DialEnd::Established { remote: None },
                    &mut host,
                    &mut next_id,
                    e
                ),
                Some(false),
                "the dial of a stopped peer is dropped when it ends"
            );
        });
        assert!(ended.is_empty());
    }

    /// A face can hold several peers (a node and an endpoint that reach one remote),
    /// and its loss is reported to each, the lowest key first.
    #[test]
    fn a_face_holding_two_peers_reports_the_loss_of_both() {
        let mut host = Host {
            candidates: Vector::from([1, 2]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        let first = dial_of(&actions(|e| {
            plan.open(2, &mut host, &mut next_id, e).unwrap()
        }));
        plan.dial_ended(
            first,
            DialEnd::Established { remote: Some(A) },
            &mut host,
            &mut next_id,
            &mut |_| {},
        );
        let second = dial_of(&actions(|e| {
            plan.open(1, &mut host, &mut next_id, e).unwrap()
        }));
        plan.dial_ended(
            second,
            DialEnd::AlreadyHeld {
                held: first,
                remote: Some(A),
            },
            &mut host,
            &mut next_id,
            &mut |_| {},
        );
        assert_eq!(
            plan.state(&1),
            Some(S::Established),
            "held by the face that holds the remote"
        );

        let lost = actions(|e| assert!(plan.face_down(first, &mut host, &mut next_id, e)));
        let keys: Vector<u8> = lost
            .iter()
            .map(|action| match action {
                PeerAction::Retry { key, .. } => *key,
                other => panic!("expected a retry, got {other:?}"),
            })
            .collect();
        assert_eq!(keys, [1, 2]);
    }

    /// The close of a node stops the machine of the node and that of each peer whose
    /// session reached it, and no other.
    #[test]
    fn a_withdrawal_stops_every_machine_that_reached_the_node() {
        let mut host = Host {
            candidates: Vector::from([1, 2, 3]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        for (key, remote) in [(1u8, A), (2, A), (3, B)] {
            let id = dial_of(&actions(|e| {
                plan.open(key, &mut host, &mut next_id, e).unwrap()
            }));
            plan.dial_ended(
                id,
                DialEnd::Established {
                    remote: Some(remote),
                },
                &mut host,
                &mut next_id,
                &mut |_| {},
            );
        }
        let closed = actions(|e| plan.withdraw(&A, 1, &mut host, &mut next_id, e));
        let mut faces: Vector<Face> = closed
            .iter()
            .map(|action| match action {
                PeerAction::Close { id } => *id,
                other => panic!("expected a close, got {other:?}"),
            })
            .collect();
        faces.sort();
        assert_eq!(
            faces,
            [Face(0), Face(1)],
            "the sessions of the two machines that held A"
        );
        assert_eq!(plan.state(&1), Some(S::Idle));
        assert_eq!(plan.state(&2), Some(S::Idle));
        assert_eq!(
            plan.state(&3),
            Some(S::Established),
            "another node's machine is untouched"
        );
    }

    /// A host that stops holding one peer stops its machine: the session it holds
    /// is closed, and forgetting it then leaves nothing of it; a peer the planner
    /// does not hold is stopped without effect.
    #[test]
    fn a_stopped_peer_closes_its_session_and_a_forgotten_one_leaves_nothing() {
        let mut host = Host {
            candidates: Vector::from([1]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        let id = dial_of(&actions(|e| {
            plan.open(1, &mut host, &mut next_id, e).unwrap()
        }));
        plan.dial_ended(
            id,
            DialEnd::Established { remote: None },
            &mut host,
            &mut next_id,
            &mut |_| {},
        );

        let closed = actions(|e| plan.stop(&1, &mut host, &mut next_id, e));
        assert_eq!(closed, [PeerAction::Close { id }]);
        assert_eq!(plan.state(&1), Some(S::Idle));
        plan.forget(&1);
        assert_eq!(plan.state(&1), None);
        assert!(
            actions(|e| plan.stop(&1, &mut host, &mut next_id, e)).is_empty(),
            "a peer the planner does not hold has nothing to stop"
        );
    }

    /// The status read: every machine with the zid its last session named, kept
    /// after the session is lost.
    #[test]
    fn the_machines_are_read_with_the_zid_they_reached() {
        let mut host = Host {
            candidates: Vector::from([1]),
            ..Host::default()
        };
        let mut plan = Plan::new();
        let mut next_id = 0;
        let id = dial_of(&actions(|e| {
            plan.open(1, &mut host, &mut next_id, e).unwrap()
        }));
        plan.dial_ended(
            id,
            DialEnd::Established { remote: Some(A) },
            &mut host,
            &mut next_id,
            &mut |_| {},
        );
        plan.face_down(id, &mut host, &mut next_id, &mut |_| {});
        let read: Vector<_> = plan.machines().collect();
        assert_eq!(read, [(&1, S::Backoff, Some(&A))]);
    }

    /// A planner with no room for another dial does not make one: the peer's machine
    /// is told the host has no slot, and refuses with `NoSlot`.
    #[test]
    fn a_dial_the_planner_cannot_track_is_not_made() {
        let mut host = Host {
            candidates: Vector::from([1, 2, 3]),
            ..Host::default()
        };
        let mut plan: PeerPlanner<u8, Face, 4, 2> = PeerPlanner::new();
        let mut next_id = 0;
        for key in [1, 2] {
            let mut out = Vector::new();
            plan.open(key, &mut host, &mut next_id, &mut |a: Action| out.push(a))
                .unwrap();
            assert_eq!(out.len(), 1);
        }
        let mut out: Vector<Action> = Vector::new();
        plan.open(3, &mut host, &mut next_id, &mut |a| out.push(a))
            .unwrap();
        assert!(out.is_empty(), "no dial was made: {out:?}");
        assert_eq!(plan.state(&3), Some(S::NoSlot));
        assert_eq!(next_id, 2, "and no face was minted for it");
    }
}
