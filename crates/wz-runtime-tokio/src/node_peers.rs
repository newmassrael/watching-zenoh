// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The nodes a face loop is told to hold by zid, each driven by its connection
//! machine (decision D5 of `docs/session-lifecycle-intent.md`).
//!
//! A lifecycle `open` names a node. Its [`PeerTable`] entry is the machine, and
//! this module is the host the machine asks things of: it performs each duty
//! against the loop's directory (decision D3) and its retry schedule, and turns
//! what the loop sees (a dial that ended, a face that died, a timer that fired)
//! into the machine's events.
//!
//! It is a PLANNER, not a driver: every call returns the [`NodeAction`]s the
//! loop is to take (dial this target as this face, wake me for this node after
//! this long, drop this face), and the loop takes them. Nothing here awaits,
//! dials or holds a socket, so the whole of the node lifecycle is reachable by
//! a unit test without a loop, a listener or a peer.

use std::collections::{BTreeMap, BTreeSet};

use wz_session_core::locator_directory::DirectoryZid;
use wz_session_core::peer_connection::{PeerConnectionEvent as E, PeerConnectionState};
use wz_session_core::peer_table::{PeerDuties, PeerTable};

use crate::accept_loop::{
    candidate_locators, first_dialable_locator, FaceId, LoopDirectory, RedialSchedule,
};
use crate::retry_period::RetryPolicy;
use crate::session_open::MeshDialTarget;

/// How many nodes a face loop can be told to hold by zid.
pub const LOOP_PEER_ROWS: usize = 256;

/// What the loop is to do for the nodes it holds.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeAction {
    /// Dial `target` (made for its node) as face `id`.
    Dial {
        /// The face the dial opens.
        id: FaceId,
        /// What to dial, for which node.
        target: MeshDialTarget,
    },
    /// Report [`NodePeers::retry_due`] for `zid` after `after_ms`.
    Retry {
        /// The node.
        zid: DirectoryZid,
        /// The wait, from the retry schedule.
        after_ms: u64,
    },
    /// Drop face `id`: a session its node no longer wants.
    Close {
        /// The face.
        id: FaceId,
    },
}

/// How a dial the planner asked for ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialEnd {
    /// A session to the node is up, held as the dialled face.
    Established,
    /// A session to the node is up, but the loop holds it as `held`, another face
    /// (the node was already reached another way); the dialled face is dropped.
    AlreadyHeld {
        /// The face the loop holds to the node.
        held: FaceId,
    },
    /// The loop has no room for another session.
    NoSlot,
    /// Another node answered at the locator (decision D4).
    Mismatch,
    /// The dial failed otherwise: unreachable, refused, timed out.
    Failed,
}

/// The loop's state the planner reads: the directory and the clock.
pub struct NodeContext<'a> {
    /// The loop's locator directory (decision D3).
    pub directory: &'a LoopDirectory,
    /// The loop's monotonic clock, in milliseconds.
    pub now_ms: u64,
}

/// The nodes a face loop holds by zid, and what it is doing for each.
pub struct NodePeers {
    table: Box<PeerTable<DirectoryZid, LOOP_PEER_ROWS>>,
    /// Dials under way, by the face they open.
    dialing: BTreeMap<FaceId, DirectoryZid>,
    /// Dials whose node stopped wanting them while they ran: dropped when they end.
    abandoned: BTreeSet<FaceId>,
    /// The face each held node is held by.
    held: BTreeMap<FaceId, DirectoryZid>,
    /// Each node's retry schedule while it is down.
    retry: RedialSchedule<DirectoryZid>,
}

impl NodePeers {
    /// No node held, retries on `policy` (upstream's `connect/retry`).
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            table: Box::new(PeerTable::new()),
            dialing: BTreeMap::new(),
            abandoned: BTreeSet::new(),
            held: BTreeMap::new(),
            retry: RedialSchedule::new(policy),
        }
    }

    /// `open` for `zid`, which the authority admitted. A node already held or
    /// being reached is unchanged (decision D6).
    pub fn open(
        &mut self,
        zid: DirectoryZid,
        cx: &NodeContext<'_>,
        next_id: &mut u64,
    ) -> Vec<NodeAction> {
        match self.table.open(zid, true) {
            Ok(duties) => self.perform(zid, duties, cx, next_id),
            Err(why) => {
                log::warn!("node peers: no room to hold another node ({why:?}); refusing the open");
                Vec::new()
            }
        }
    }

    /// The retry timer of `zid` fired.
    pub fn retry_due(
        &mut self,
        zid: DirectoryZid,
        cx: &NodeContext<'_>,
        next_id: &mut u64,
    ) -> Vec<NodeAction> {
        let duties = self.table.report(&zid, E::RetryDue);
        self.perform(zid, duties, cx, next_id)
    }

    /// Whether face `id` is a dial this planner asked for.
    pub fn is_dialing(&self, id: FaceId) -> bool {
        self.dialing.contains_key(&id) || self.abandoned.contains(&id)
    }

    /// The dial of face `id` ended as `end`. `None` when the face is not one of
    /// this planner's dials. The `bool` says whether the loop is to hold the face.
    pub fn dial_ended(
        &mut self,
        id: FaceId,
        end: DialEnd,
        cx: &NodeContext<'_>,
        next_id: &mut u64,
    ) -> Option<(bool, Vec<NodeAction>)> {
        if self.abandoned.remove(&id) {
            // Its node stopped wanting it while it ran: a session that came up is
            // dropped, and nothing is reported to a machine that is past it.
            return Some((false, Vec::new()));
        }
        let zid = self.dialing.remove(&id)?;
        let (event, keep) = match end {
            DialEnd::Established => {
                self.held.insert(id, zid);
                (E::DialEstablished, true)
            }
            DialEnd::AlreadyHeld { held } => {
                self.held.insert(held, zid);
                (E::DialEstablished, false)
            }
            DialEnd::NoSlot => (E::DialNoSlot, false),
            DialEnd::Mismatch => (E::DialMismatch, false),
            DialEnd::Failed => (E::DialFailed, false),
        };
        let duties = self.table.report(&zid, event);
        Some((keep, self.perform(zid, duties, cx, next_id)))
    }

    /// Face `id` died. `None` when it is not a face a node is held by.
    pub fn face_down(
        &mut self,
        id: FaceId,
        cx: &NodeContext<'_>,
        next_id: &mut u64,
    ) -> Option<Vec<NodeAction>> {
        let zid = self.held.remove(&id)?;
        let duties = self.table.report(&zid, E::SessionLost);
        Some(self.perform(zid, duties, cx, next_id))
    }

    /// The state of `zid`'s machine.
    pub fn state(&self, zid: &DirectoryZid) -> Option<PeerConnectionState> {
        self.table.state(zid)
    }

    /// Perform `duties` for `zid`, and the duties each answer raises in turn.
    fn perform(
        &mut self,
        zid: DirectoryZid,
        mut duties: PeerDuties,
        cx: &NodeContext<'_>,
        next_id: &mut u64,
    ) -> Vec<NodeAction> {
        let mut actions = Vec::new();
        while !duties.is_empty() {
            let mut next = PeerDuties::default();
            if duties.reset_retry() || duties.cancel_retry() {
                self.retry.forget(&zid);
            }
            if duties.abandon_dial() {
                let gone: Vec<FaceId> = self
                    .dialing
                    .iter()
                    .filter(|(_, held_for)| **held_for == zid)
                    .map(|(id, _)| *id)
                    .collect();
                for id in gone {
                    self.dialing.remove(&id);
                    self.abandoned.insert(id);
                }
            }
            if duties.close_session() {
                let held: Vec<FaceId> = self
                    .held
                    .iter()
                    .filter(|(_, held_for)| **held_for == zid)
                    .map(|(id, _)| *id)
                    .collect();
                for id in held {
                    self.held.remove(&id);
                    actions.push(NodeAction::Close { id });
                }
            }
            if duties.arm_retry() {
                actions.push(NodeAction::Retry {
                    zid,
                    after_ms: self.retry.next_ms(&zid, None),
                });
            }
            if duties.resolve() {
                let found = self.dialable(&zid, cx).is_some();
                next = self.table.report(
                    &zid,
                    if found {
                        E::ResolveFound
                    } else {
                        E::ResolveEmpty
                    },
                );
            } else if duties.dial() {
                match self.dialable(&zid, cx) {
                    Some(target) => {
                        let id = FaceId(*next_id);
                        *next_id += 1;
                        self.dialing.insert(id, zid);
                        actions.push(NodeAction::Dial {
                            id,
                            target: target.for_node(zid),
                        });
                    }
                    // The candidates went between the resolution and the dial.
                    None => next = self.table.report(&zid, E::DialFailed),
                }
            }
            duties = next;
        }
        actions
    }

    /// The first of `zid`'s candidates that can be dialled from this loop.
    fn dialable(&self, zid: &DirectoryZid, cx: &NodeContext<'_>) -> Option<MeshDialTarget> {
        first_dialable_locator(&candidate_locators(cx.directory, zid, cx.now_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept_loop::learn_locators;
    use wz_session_core::locator_directory::LocatorSource;
    use PeerConnectionState as S;

    const A: DirectoryZid = [0xa1; 16];

    fn directory_with(locators: &[&str]) -> Box<LoopDirectory> {
        let mut directory = Box::new(LoopDirectory::new());
        let texts: Vec<String> = locators.iter().map(|l| (*l).to_owned()).collect();
        learn_locators(&mut directory, &A, &texts, LocatorSource::Linkstate, 0);
        directory
    }

    fn the_dial(actions: &[NodeAction]) -> (FaceId, MeshDialTarget) {
        match actions {
            [NodeAction::Dial { id, target }] => (*id, target.clone()),
            other => panic!("expected one dial, got {other:?}"),
        }
    }

    #[test]
    fn an_open_dials_the_node_for_its_zid_and_holds_the_face_it_opens() {
        let directory = directory_with(&["tcp/127.0.0.1:7201"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(1000));
        let mut next_id = 10;
        let (id, target) = the_dial(&peers.open(A, &cx, &mut next_id));
        assert_eq!(id, FaceId(10));
        assert_eq!(target.expected_zid, Some(A), "dialled for the node (D4)");
        assert_eq!(peers.state(&A), Some(S::Connecting));
        assert!(
            peers.open(A, &cx, &mut next_id).is_empty(),
            "a second open is a no-op"
        );
        let (keep, actions) = peers
            .dial_ended(id, DialEnd::Established, &cx, &mut next_id)
            .expect("its dial");
        assert!(keep && actions.is_empty());
        assert_eq!(peers.state(&A), Some(S::Established));
    }

    #[test]
    fn a_failed_dial_backs_off_on_the_schedule_and_the_retry_dials_again() {
        let directory = directory_with(&["tcp/127.0.0.1:7202"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(1500));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open(A, &cx, &mut next_id));
        let (keep, actions) = peers
            .dial_ended(id, DialEnd::Failed, &cx, &mut next_id)
            .unwrap();
        assert!(!keep);
        assert_eq!(
            actions,
            [NodeAction::Retry {
                zid: A,
                after_ms: 1500
            }]
        );
        assert_eq!(peers.state(&A), Some(S::Backoff));
        the_dial(&peers.retry_due(A, &cx, &mut next_id));
        assert_eq!(peers.state(&A), Some(S::Connecting));
    }

    #[test]
    fn a_held_node_whose_face_dies_is_retried() {
        let directory = directory_with(&["tcp/127.0.0.1:7203"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(700));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open(A, &cx, &mut next_id));
        peers.dial_ended(id, DialEnd::Established, &cx, &mut next_id);
        let actions = peers.face_down(id, &cx, &mut next_id).expect("a held face");
        assert_eq!(
            actions,
            [NodeAction::Retry {
                zid: A,
                after_ms: 700
            }]
        );
        assert!(peers.face_down(id, &cx, &mut next_id).is_none(), "once");
    }

    #[test]
    fn each_refusal_is_the_machine_state_that_names_it() {
        let empty = directory_with(&[]);
        let cx = NodeContext {
            directory: &empty,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        assert!(peers.open(A, &cx, &mut next_id).is_empty());
        assert_eq!(peers.state(&A), Some(S::NoLocator), "no candidate");

        let directory = directory_with(&["tcp/127.0.0.1:7204"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        for (end, cause) in [
            (DialEnd::Mismatch, S::IdentityMismatch),
            (DialEnd::NoSlot, S::NoSlot),
        ] {
            let mut peers = NodePeers::new(RetryPolicy::constant(1000));
            let (id, _) = the_dial(&peers.open(A, &cx, &mut next_id));
            let (keep, actions) = peers.dial_ended(id, end, &cx, &mut next_id).unwrap();
            assert!(!keep && actions.is_empty(), "a refusal arms no retry");
            assert_eq!(peers.state(&A), Some(cause));
        }
    }

    #[test]
    fn a_node_reached_another_way_is_held_by_that_face() {
        let directory = directory_with(&["tcp/127.0.0.1:7205"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open(A, &cx, &mut next_id));
        let (keep, _) = peers
            .dial_ended(
                id,
                DialEnd::AlreadyHeld { held: FaceId(99) },
                &cx,
                &mut next_id,
            )
            .unwrap();
        assert!(!keep, "the dialled face is the redundant one");
        assert_eq!(peers.state(&A), Some(S::Established));
        assert!(
            peers.face_down(FaceId(99), &cx, &mut next_id).is_some(),
            "the face that holds the node is the one whose loss is reported"
        );
    }

    #[test]
    fn a_dial_that_is_not_the_planners_is_not_reported() {
        let directory = directory_with(&["tcp/127.0.0.1:7206"]);
        let cx = NodeContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = NodePeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        assert!(!peers.is_dialing(FaceId(5)));
        assert!(peers
            .dial_ended(FaceId(5), DialEnd::Established, &cx, &mut next_id)
            .is_none());
        assert!(peers.face_down(FaceId(5), &cx, &mut next_id).is_none());
    }
}
