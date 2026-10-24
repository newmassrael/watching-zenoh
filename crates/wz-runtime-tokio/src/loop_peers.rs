// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The peers a face loop is told to hold, each driven by its connection
//! machine (decision D5 of `docs/session-lifecycle-intent.md`).
//!
//! A peer is named one of two ways (decision D7: a target is a zid or a
//! locator). A lifecycle `open` names a NODE by its zid, and the machine dials
//! the candidates the loop's directory holds for it (decision D3), each for its
//! zid (decision D4). A configured `connect/endpoints` member names an ENDPOINT,
//! and the machine dials that locator for no node. Its
//! [`PeerTable`](wz_session_core::peer_table::PeerTable) entry is
//! the machine either way, and this module is the host the machine asks things
//! of: it performs each duty against the directory, the configured endpoints
//! and the retry schedule, and turns what the loop sees (a dial that ended, a
//! face that died, a timer that fired) into the machine's events.
//!
//! It is a PLANNER, not a driver: every call returns the
//! [`PeerAction`](crate::loop_peers::PeerAction)s the
//! loop is to take (dial this target as this face, wake me for this peer after
//! this long, drop this face), and the loop takes them. Nothing here awaits,
//! dials or holds a socket, so the whole of the peer lifecycle is reachable by
//! a unit test without a loop, a listener or a peer.

use std::collections::{BTreeMap, BTreeSet};

use wz_session_core::locator_directory::DirectoryZid;
use wz_session_core::peer_connection::{PeerConnectionEvent as E, PeerConnectionState};
use wz_session_core::peer_table::{PeerDuties, PeerTable};

use crate::accept_loop::{
    candidate_locators, first_dialable_locator, FaceId, LoopDirectory, RedialSchedule,
};
use crate::retry_period::RetryPolicy;
use crate::session_open::{MeshDialKey, MeshDialTarget};

/// How many peers a face loop can be told to hold, nodes and endpoints together.
pub const LOOP_PEER_ROWS: usize = 256;

/// What names a peer the loop holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerKey {
    /// A node a lifecycle `open` named, by its zid in its sixteen-byte form.
    Node(DirectoryZid),
    /// A configured connect endpoint, by its pre-handshake identity.
    Endpoint(MeshDialKey),
}

impl std::fmt::Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(zid) => {
                f.write_str("node ")?;
                zid.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
            Self::Endpoint(key) => write!(f, "endpoint {key}"),
        }
    }
}

/// What the loop is to do for the peers it holds.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerAction {
    /// Dial `target` (made for `key`) as face `id`.
    Dial {
        /// The face the dial opens.
        id: FaceId,
        /// The peer the dial is made for.
        key: PeerKey,
        /// What to dial.
        target: MeshDialTarget,
    },
    /// Report [`LoopPeers::retry_due`] for `key` and `generation` after
    /// `after_ms`.
    Retry {
        /// The peer.
        key: PeerKey,
        /// Which arming this is. A timer of an earlier arming that fires after
        /// its peer was forgotten, or left the wait another way, is not the
        /// peer's retry, and [`LoopPeers::retry_due`] drops it.
        generation: u64,
        /// The wait, from the retry schedule.
        after_ms: u64,
    },
    /// Drop face `id`: a session its peer no longer wants. Raised only by a
    /// lifecycle `close` (`manual.stop` from Established), so only a build
    /// with the close seam can be asked for it.
    #[cfg(feature = "session-close-ingress")]
    Close {
        /// The face.
        id: FaceId,
    },
}

/// How a dial the planner asked for ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialEnd {
    /// A session to the peer is up, held as the dialled face.
    Established {
        /// The zid the session's remote named, which a `close` names it by.
        remote: Option<DirectoryZid>,
    },
    /// A session to the peer is up, but the loop holds it as `held`, another face
    /// (the peer was already reached another way, or the dialled link joined
    /// the session `held` represents); the dialled face is not held on its own.
    AlreadyHeld {
        /// The face the loop holds to the peer.
        held: FaceId,
        /// The zid the session's remote named, which a `close` names it by.
        remote: Option<DirectoryZid>,
    },
    /// The loop has no room for another session.
    NoSlot,
    /// Another node answered at the locator (decision D4).
    Mismatch,
    /// The dial failed otherwise: unreachable, refused, timed out.
    Failed,
}

/// The loop's state the planner reads: the directory and the clock.
pub struct PeerContext<'a> {
    /// The loop's locator directory (decision D3).
    pub directory: &'a LoopDirectory,
    /// The loop's monotonic clock, in milliseconds.
    pub now_ms: u64,
}

/// The peers a face loop holds, and what it is doing for each.
pub struct LoopPeers {
    table: Box<PeerTable<PeerKey, LOOP_PEER_ROWS>>,
    /// How to dial each configured endpoint the table holds: the scheme and
    /// the `#` retry overrides the operator wrote, by the endpoint's key.
    endpoints: BTreeMap<MeshDialKey, MeshDialTarget>,
    /// Dials under way, by the face they open.
    dialing: BTreeMap<FaceId, PeerKey>,
    /// Dials whose peer stopped wanting them while they ran: a session one opens
    /// is dropped when it ends.
    abandoned: BTreeSet<FaceId>,
    /// Dials whose peer was forgotten while they ran: a session one opens is
    /// left standing, unowned, as a forgotten peer's held session is.
    released: BTreeSet<FaceId>,
    /// The peers each face holds. One face can hold several: a node and an
    /// endpoint that reach the same remote, or two endpoints of one multilink
    /// session.
    held: BTreeMap<FaceId, BTreeSet<PeerKey>>,
    /// Each peer's retry schedule while it is down.
    retry: RedialSchedule<PeerKey>,
    /// The arming of each peer's retry timer that is still its own.
    armed: BTreeMap<PeerKey, u64>,
    /// The zid each peer's last session named, kept after the session is lost:
    /// a `close` names a node by its zid, and an endpoint, which has none of its
    /// own, is the node it reached (decision D6).
    remotes: BTreeMap<PeerKey, DirectoryZid>,
    /// The next arming's generation.
    next_generation: u64,
}

impl LoopPeers {
    /// No peer held, retries on `policy` (upstream's `connect/retry`).
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            table: Box::new(PeerTable::new()),
            endpoints: BTreeMap::new(),
            dialing: BTreeMap::new(),
            abandoned: BTreeSet::new(),
            released: BTreeSet::new(),
            held: BTreeMap::new(),
            retry: RedialSchedule::new(policy),
            armed: BTreeMap::new(),
            remotes: BTreeMap::new(),
            next_generation: 0,
        }
    }

    /// `open` for the node `zid`, which the authority admitted. A node already
    /// held or being reached is unchanged (decision D6).
    pub fn open_node(
        &mut self,
        zid: DirectoryZid,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Vec<PeerAction> {
        self.open(PeerKey::Node(zid), cx, next_id)
    }

    /// The configured connect endpoints change: `targets` join them, and with
    /// `replace` they are the whole of them. An endpoint a replace leaves out is
    /// forgotten: it is not dialled again when it drops, and a live session to
    /// it is left standing (upstream's shape, [`PeerTable::forget`]). An
    /// endpoint already held or being reached is unchanged, and one its machine
    /// refused tries again (decision D6). A member's dial plan is taken from
    /// `targets`, so a member listed again with another scheme or another `#`
    /// retry span is dialled that way from its next dial.
    pub fn set_endpoints(
        &mut self,
        targets: Vec<MeshDialTarget>,
        replace: bool,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Vec<PeerAction> {
        if replace {
            let listed: BTreeSet<&MeshDialKey> = targets.iter().map(|t| &t.key).collect();
            let gone: Vec<MeshDialKey> = self
                .endpoints
                .keys()
                .filter(|key| !listed.contains(key))
                .cloned()
                .collect();
            for key in gone {
                self.forget(&PeerKey::Endpoint(key));
            }
        }
        let mut actions = Vec::new();
        for target in targets {
            let key = target.key.clone();
            self.endpoints.insert(key.clone(), target);
            actions.extend(self.open(PeerKey::Endpoint(key), cx, next_id));
        }
        actions
    }

    /// The configured endpoints the loop holds.
    pub fn endpoints(&self) -> impl Iterator<Item = &MeshDialTarget> + '_ {
        self.endpoints.values()
    }

    /// The retry timer `generation` of `key` fired. A timer whose arming is no
    /// longer the peer's changes nothing.
    pub fn retry_due(
        &mut self,
        key: PeerKey,
        generation: u64,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Vec<PeerAction> {
        if self.armed.get(&key) != Some(&generation) {
            return Vec::new();
        }
        self.armed.remove(&key);
        let duties = self.table.report(&key, E::RetryDue);
        self.perform(key, duties, false, cx, next_id)
    }

    /// Whether face `id` is a dial this planner asked for.
    pub fn is_dialing(&self, id: FaceId) -> bool {
        self.dialing.contains_key(&id)
            || self.abandoned.contains(&id)
            || self.released.contains(&id)
    }

    /// Whether face `id` is a dial this planner made for a node, which the loop
    /// holds by one face.
    pub fn dials_a_node(&self, id: FaceId) -> bool {
        matches!(self.dialing.get(&id), Some(PeerKey::Node(_)))
    }

    /// The dial of face `id` ended as `end`. `None` when the face is not one of
    /// this planner's dials. The `bool` says whether the loop is to hold the face.
    pub fn dial_ended(
        &mut self,
        id: FaceId,
        end: DialEnd,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Option<(bool, Vec<PeerAction>)> {
        if self.abandoned.remove(&id) {
            // Its peer stopped wanting it while it ran: a session that came up is
            // dropped, and nothing is reported to a machine that is past it.
            return Some((false, Vec::new()));
        }
        if self.released.remove(&id) {
            // Its peer was forgotten while it ran: a session that came up stands,
            // owned by no machine, as a forgotten peer's held session does.
            return Some((matches!(end, DialEnd::Established { .. }), Vec::new()));
        }
        let key = self.dialing.remove(&id)?;
        let (event, keep) = match end {
            DialEnd::Established { remote } => {
                self.held.entry(id).or_default().insert(key.clone());
                self.learn_remote(&key, remote);
                (E::DialEstablished, true)
            }
            DialEnd::AlreadyHeld { held, remote } => {
                self.held.entry(held).or_default().insert(key.clone());
                self.learn_remote(&key, remote);
                (E::DialEstablished, false)
            }
            DialEnd::NoSlot => (E::DialNoSlot, false),
            DialEnd::Mismatch => (E::DialMismatch, false),
            DialEnd::Failed => (E::DialFailed, false),
        };
        let duties = self.table.report(&key, event);
        Some((keep, self.perform(key, duties, false, cx, next_id)))
    }

    /// Face `id` died. `None` when it is not a face a peer is held by.
    pub fn face_down(
        &mut self,
        id: FaceId,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Option<Vec<PeerAction>> {
        let keys = self.held.remove(&id)?;
        let mut actions = Vec::new();
        for key in keys {
            let duties = self.table.report(&key, E::SessionLost);
            actions.extend(self.perform(key, duties, true, cx, next_id));
        }
        Some(actions)
    }

    /// `close` for the node `zid` (decision D6): every machine that holds it,
    /// its own and that of each endpoint whose last session reached it, is
    /// stopped. A session it holds is closed, a dial it runs is dropped and a
    /// wait it is in is cancelled, and the peer is not dialled again until an
    /// `open`, or a connect-list edit naming the endpoint, starts it. The
    /// machine stays in the table, `Idle`.
    #[cfg(feature = "session-close-ingress")]
    pub fn withdraw(
        &mut self,
        zid: &DirectoryZid,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Vec<PeerAction> {
        let node = PeerKey::Node(*zid);
        let mut keys: Vec<PeerKey> = self
            .remotes
            .iter()
            .filter(|(key, remote)| *remote == zid && **key != node)
            .map(|(key, _)| key.clone())
            .collect();
        keys.push(node);
        let mut actions = Vec::new();
        for key in keys {
            let duties = self.table.close(&key);
            actions.extend(self.perform(key, duties, false, cx, next_id));
        }
        actions
    }

    /// The state of `key`'s machine.
    pub fn state(&self, key: &PeerKey) -> Option<PeerConnectionState> {
        self.table.state(key)
    }

    /// Keep the zid `key`'s session named, for a later `close` to name it by.
    fn learn_remote(&mut self, key: &PeerKey, remote: Option<DirectoryZid>) {
        if let Some(remote) = remote {
            self.remotes.insert(key.clone(), remote);
        }
    }

    /// `open` for `key`: the authority admitted it.
    fn open(&mut self, key: PeerKey, cx: &PeerContext<'_>, next_id: &mut u64) -> Vec<PeerAction> {
        match self.table.open(key.clone(), true) {
            Ok(duties) => self.perform(key, duties, false, cx, next_id),
            Err(why) => {
                log::warn!("loop peers: no room to hold {key} ({why:?}); refusing the open");
                if let PeerKey::Endpoint(endpoint) = &key {
                    self.endpoints.remove(endpoint);
                }
                Vec::new()
            }
        }
    }

    /// Stop working to hold `key`, and leave a session it has standing.
    fn forget(&mut self, key: &PeerKey) {
        self.table.forget(key);
        if let PeerKey::Endpoint(endpoint) = key {
            self.endpoints.remove(endpoint);
        }
        // Its growth goes with it, so a peer listed again later starts from the
        // initial wait rather than the ceiling of the outage before its removal.
        self.retry.forget(key);
        self.armed.remove(key);
        self.remotes.remove(key);
        let running: Vec<FaceId> = self
            .dialing
            .iter()
            .filter(|(_, dialled_for)| *dialled_for == key)
            .map(|(id, _)| *id)
            .collect();
        for id in running {
            self.dialing.remove(&id);
            self.released.insert(id);
        }
        self.held.retain(|_, keys| {
            keys.remove(key);
            !keys.is_empty()
        });
    }

    /// Perform `duties` for `key`, and the duties each answer raises in turn.
    /// `lost` says whether they answer a held session's loss, the one wait an
    /// operator is told of at `info`.
    fn perform(
        &mut self,
        key: PeerKey,
        mut duties: PeerDuties,
        lost: bool,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Vec<PeerAction> {
        let mut actions = Vec::new();
        while !duties.is_empty() {
            let mut next = PeerDuties::default();
            if duties.reset_retry() || duties.cancel_retry() {
                self.retry.forget(&key);
            }
            if duties.cancel_retry() {
                self.armed.remove(&key);
            }
            if duties.abandon_dial() {
                let gone: Vec<FaceId> = self
                    .dialing
                    .iter()
                    .filter(|(_, dialled_for)| **dialled_for == key)
                    .map(|(id, _)| *id)
                    .collect();
                for id in gone {
                    self.dialing.remove(&id);
                    self.abandoned.insert(id);
                }
            }
            #[cfg(feature = "session-close-ingress")]
            if duties.close_session() {
                let mut emptied = Vec::new();
                for (id, keys) in self.held.iter_mut() {
                    if keys.remove(&key) {
                        actions.push(PeerAction::Close { id: *id });
                        if keys.is_empty() {
                            emptied.push(*id);
                        }
                    }
                }
                for id in emptied {
                    self.held.remove(&id);
                }
            }
            if duties.arm_retry() {
                let overrides = match &key {
                    PeerKey::Endpoint(endpoint) => {
                        self.endpoints.get(endpoint).and_then(MeshDialTarget::retry)
                    }
                    PeerKey::Node(_) => None,
                };
                let after_ms = self.retry.next_ms(&key, overrides);
                let generation = self.next_generation;
                self.next_generation += 1;
                self.armed.insert(key.clone(), generation);
                if lost {
                    log::info!(
                        "loop peers: {key} lost its session; dialling it again in {after_ms}ms"
                    );
                } else {
                    log::debug!("loop peers: {key} not reached; dialling it again in {after_ms}ms");
                }
                actions.push(PeerAction::Retry {
                    key: key.clone(),
                    generation,
                    after_ms,
                });
            }
            if duties.resolve() {
                let found = self.dialable(&key, cx).is_some();
                next = self.table.report(
                    &key,
                    if found {
                        E::ResolveFound
                    } else {
                        E::ResolveEmpty
                    },
                );
            } else if duties.dial() {
                match self.dialable(&key, cx) {
                    Some(target) => {
                        let id = FaceId(*next_id);
                        *next_id += 1;
                        self.dialing.insert(id, key.clone());
                        actions.push(PeerAction::Dial {
                            id,
                            key: key.clone(),
                            target,
                        });
                    }
                    // The candidates went between the resolution and the dial.
                    None => next = self.table.report(&key, E::DialFailed),
                }
            }
            duties = next;
        }
        actions
    }

    /// What to dial for `key`: a node's first candidate that can be dialled from
    /// this loop, made for its zid, or an endpoint's own plan.
    fn dialable(&self, key: &PeerKey, cx: &PeerContext<'_>) -> Option<MeshDialTarget> {
        match key {
            PeerKey::Node(zid) => {
                first_dialable_locator(&candidate_locators(cx.directory, zid, cx.now_ms))
                    .map(|target| target.for_node(*zid))
            }
            PeerKey::Endpoint(endpoint) => self.endpoints.get(endpoint).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept_loop::learn_locators;
    use wz_session_core::locator_directory::LocatorSource;
    use PeerConnectionState as S;

    const A: DirectoryZid = [0xa1; 16];
    const NODE: PeerKey = PeerKey::Node(A);
    /// A dial that came up, its remote unnamed.
    const UP: DialEnd = DialEnd::Established { remote: None };

    fn directory_with(locators: &[&str]) -> Box<LoopDirectory> {
        let mut directory = Box::new(LoopDirectory::new());
        let texts: Vec<String> = locators.iter().map(|l| (*l).to_owned()).collect();
        learn_locators(&mut directory, &A, &texts, LocatorSource::Linkstate, 0);
        directory
    }

    fn endpoint(text: &str) -> MeshDialTarget {
        let locator =
            wz_session_core::locator::parse_any_locator(text).expect("a fixture locator parses");
        crate::session_open::mesh_dial_plan(locator).expect("a fixture locator is dialable")
    }

    fn the_dial(actions: &[PeerAction]) -> (FaceId, MeshDialTarget) {
        match actions {
            [PeerAction::Dial { id, target, .. }] => (*id, target.clone()),
            other => panic!("expected one dial, got {other:?}"),
        }
    }

    fn the_retry(actions: &[PeerAction]) -> (PeerKey, u64, u64) {
        match actions {
            [PeerAction::Retry {
                key,
                generation,
                after_ms,
            }] => (key.clone(), *generation, *after_ms),
            other => panic!("expected one retry, got {other:?}"),
        }
    }

    #[test]
    fn an_open_dials_the_node_for_its_zid_and_holds_the_face_it_opens() {
        let directory = directory_with(&["tcp/127.0.0.1:7201"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 10;
        let (id, target) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        assert_eq!(id, FaceId(10));
        assert_eq!(target.expected_zid, Some(A), "dialled for the node (D4)");
        assert!(peers.dials_a_node(id));
        assert_eq!(peers.state(&NODE), Some(S::Connecting));
        assert!(
            peers.open_node(A, &cx, &mut next_id).is_empty(),
            "a second open is a no-op"
        );
        let (keep, actions) = peers
            .dial_ended(id, UP, &cx, &mut next_id)
            .expect("its dial");
        assert!(keep && actions.is_empty());
        assert_eq!(peers.state(&NODE), Some(S::Established));
    }

    #[test]
    fn a_failed_dial_backs_off_on_the_schedule_and_the_retry_dials_again() {
        let directory = directory_with(&["tcp/127.0.0.1:7202"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1500));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        let (keep, actions) = peers
            .dial_ended(id, DialEnd::Failed, &cx, &mut next_id)
            .unwrap();
        assert!(!keep);
        let (key, generation, after_ms) = the_retry(&actions);
        assert_eq!((key, after_ms), (NODE, 1500));
        assert_eq!(peers.state(&NODE), Some(S::Backoff));
        the_dial(&peers.retry_due(NODE, generation, &cx, &mut next_id));
        assert_eq!(peers.state(&NODE), Some(S::Connecting));
    }

    #[test]
    fn a_held_node_whose_face_dies_is_retried() {
        let directory = directory_with(&["tcp/127.0.0.1:7203"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(700));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        peers.dial_ended(id, UP, &cx, &mut next_id);
        let actions = peers.face_down(id, &cx, &mut next_id).expect("a held face");
        assert_eq!(the_retry(&actions).2, 700);
        assert!(peers.face_down(id, &cx, &mut next_id).is_none(), "once");
    }

    #[test]
    fn each_refusal_is_the_machine_state_that_names_it() {
        let empty = directory_with(&[]);
        let cx = PeerContext {
            directory: &empty,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        assert!(peers.open_node(A, &cx, &mut next_id).is_empty());
        assert_eq!(peers.state(&NODE), Some(S::NoLocator), "no candidate");

        let directory = directory_with(&["tcp/127.0.0.1:7204"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        for (end, cause) in [
            (DialEnd::Mismatch, S::IdentityMismatch),
            (DialEnd::NoSlot, S::NoSlot),
        ] {
            let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
            let (id, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
            let (keep, actions) = peers.dial_ended(id, end, &cx, &mut next_id).unwrap();
            assert!(!keep && actions.is_empty(), "a refusal arms no retry");
            assert_eq!(peers.state(&NODE), Some(cause));
        }
    }

    #[test]
    fn a_node_reached_another_way_is_held_by_that_face() {
        let directory = directory_with(&["tcp/127.0.0.1:7205"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        let (keep, _) = peers
            .dial_ended(
                id,
                DialEnd::AlreadyHeld {
                    held: FaceId(99),
                    remote: None,
                },
                &cx,
                &mut next_id,
            )
            .unwrap();
        assert!(!keep, "the dialled face is the redundant one");
        assert_eq!(peers.state(&NODE), Some(S::Established));
        assert!(
            peers.face_down(FaceId(99), &cx, &mut next_id).is_some(),
            "the face that holds the node is the one whose loss is reported"
        );
    }

    #[test]
    fn a_dial_that_is_not_the_planners_is_not_reported() {
        let directory = directory_with(&["tcp/127.0.0.1:7206"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        assert!(!peers.is_dialing(FaceId(5)));
        assert!(peers.dial_ended(FaceId(5), UP, &cx, &mut next_id).is_none());
        assert!(peers.face_down(FaceId(5), &cx, &mut next_id).is_none());
    }

    /// An endpoint is dialled as written, for no node, and its machine holds it
    /// as a node's does: a dropped session is retried on the endpoint's own `#`
    /// retry span, which is laid over the loop's policy.
    #[test]
    fn an_endpoint_is_dialled_for_no_node_and_retried_on_its_own_span() {
        let directory = directory_with(&[]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        let plan = endpoint("tcp/127.0.0.1:7207#retry_period_init_ms=250;retry_period_max_ms=250");
        let key = PeerKey::Endpoint(plan.key.clone());
        let actions = peers.set_endpoints(vec![plan.clone()], false, &cx, &mut next_id);
        let (id, target) = the_dial(&actions);
        assert_eq!(
            target, plan,
            "an endpoint is dialled as written, for no node"
        );
        assert!(!peers.dials_a_node(id), "an endpoint's dial may aggregate");
        peers.dial_ended(id, UP, &cx, &mut next_id);
        assert_eq!(peers.state(&key), Some(S::Established));
        let lost = peers.face_down(id, &cx, &mut next_id).expect("held");
        assert_eq!(
            the_retry(&lost).2,
            250,
            "the endpoint's span, not the policy's"
        );
    }

    /// A replace forgets an endpoint it leaves out: a dial of it that is running
    /// ends unowned (a session it opens stands), its pending retry is not its
    /// own any more, and an endpoint listed again starts from the initial wait.
    #[test]
    fn a_replace_forgets_what_it_leaves_out_and_a_stale_timer_dials_nothing() {
        let directory = directory_with(&[]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let policy = RetryPolicy {
            period_init_ms: 50,
            period_max_ms: 800,
            period_increase_factor: 4.0,
        };
        let mut peers = LoopPeers::new(policy);
        let mut next_id = 0;
        let kept = endpoint("tcp/127.0.0.1:7208");
        let gone = endpoint("tcp/127.0.0.1:7209");
        let gone_key = PeerKey::Endpoint(gone.key.clone());
        let mut dials =
            peers.set_endpoints(vec![kept.clone(), gone.clone()], true, &cx, &mut next_id);
        assert_eq!(dials.len(), 2);
        let gone_dial = match dials.remove(1) {
            PeerAction::Dial { id, key, .. } => {
                assert_eq!(key, gone_key);
                id
            }
            other => panic!("expected a dial, got {other:?}"),
        };
        // Two failures grow its wait past the initial one.
        let (_, _, first) = the_retry(
            &peers
                .dial_ended(gone_dial, DialEnd::Failed, &cx, &mut next_id)
                .unwrap()
                .1,
        );
        assert_eq!(first, 50);

        // The replace drops it while it waits.
        let (_, generation, _) = {
            let actions = peers.retry_due(gone_key.clone(), 0, &cx, &mut next_id);
            let (id, _) = the_dial(&actions);
            the_retry(
                &peers
                    .dial_ended(id, DialEnd::Failed, &cx, &mut next_id)
                    .unwrap()
                    .1,
            )
        };
        assert!(
            peers
                .set_endpoints(vec![kept.clone()], true, &cx, &mut next_id)
                .is_empty(),
            "the endpoint kept is already being reached"
        );
        assert_eq!(peers.state(&gone_key), None, "forgotten");
        assert!(
            peers
                .retry_due(gone_key.clone(), generation, &cx, &mut next_id)
                .is_empty(),
            "the timer of a forgotten endpoint dials nothing"
        );

        // Listed again, it dials at once and its first wait is the initial one.
        let (id, _) = the_dial(&peers.set_endpoints(vec![gone.clone()], false, &cx, &mut next_id));
        let (_, fresh, wait) = the_retry(
            &peers
                .dial_ended(id, DialEnd::Failed, &cx, &mut next_id)
                .unwrap()
                .1,
        );
        assert_eq!(wait, 50, "the growth went with the removal");
        assert!(
            peers
                .retry_due(gone_key.clone(), generation, &cx, &mut next_id)
                .is_empty(),
            "the old arming is not the new outage's"
        );
        the_dial(&peers.retry_due(gone_key, fresh, &cx, &mut next_id));
    }

    /// A dial whose endpoint a replace dropped while it ran opens a session the
    /// loop holds, owned by no machine: its loss is not reported.
    #[test]
    fn a_dial_released_by_a_replace_is_held_unowned() {
        let directory = directory_with(&[]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(1000));
        let mut next_id = 0;
        let plan = endpoint("tcp/127.0.0.1:7210");
        let (id, _) = the_dial(&peers.set_endpoints(vec![plan], false, &cx, &mut next_id));
        assert!(peers
            .set_endpoints(Vec::new(), true, &cx, &mut next_id)
            .is_empty());
        assert!(
            peers.is_dialing(id),
            "its end is still the planner's to answer"
        );
        let (keep, actions) = peers.dial_ended(id, UP, &cx, &mut next_id).unwrap();
        assert!(keep && actions.is_empty(), "held, and nothing asked of it");
        assert!(
            peers.face_down(id, &cx, &mut next_id).is_none(),
            "owned by no machine"
        );
    }

    /// One face can hold several peers: two endpoints that reach one session
    /// are both lost with it.
    #[test]
    fn a_face_holding_two_peers_reports_the_loss_of_both() {
        let directory = directory_with(&[]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(300));
        let mut next_id = 0;
        let actions = peers.set_endpoints(
            vec![
                endpoint("tcp/127.0.0.1:7211"),
                endpoint("tcp/127.0.0.1:7212"),
            ],
            false,
            &cx,
            &mut next_id,
        );
        let ids: Vec<FaceId> = actions
            .iter()
            .map(|action| match action {
                PeerAction::Dial { id, .. } => *id,
                other => panic!("expected dials, got {other:?}"),
            })
            .collect();
        peers.dial_ended(ids[0], UP, &cx, &mut next_id);
        peers.dial_ended(
            ids[1],
            DialEnd::AlreadyHeld {
                held: ids[0],
                remote: None,
            },
            &cx,
            &mut next_id,
        );
        let lost = peers.face_down(ids[0], &cx, &mut next_id).expect("held");
        assert_eq!(lost.len(), 2, "both endpoints back off: {lost:?}");
    }

    /// Decision D6 — a `close` of a held node stops its machine: its session is
    /// dropped, and the face's loss that follows is nobody's to retry.
    #[cfg(feature = "session-close-ingress")]
    #[test]
    fn a_withdrawn_node_drops_its_session_and_is_not_dialled_again() {
        let directory = directory_with(&["tcp/127.0.0.1:7213"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(500));
        let mut next_id = 0;
        let (id, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        peers.dial_ended(id, UP, &cx, &mut next_id);
        assert_eq!(
            peers.withdraw(&A, &cx, &mut next_id),
            [PeerAction::Close { id }]
        );
        assert_eq!(peers.state(&NODE), Some(S::Idle));
        assert!(
            peers.face_down(id, &cx, &mut next_id).is_none(),
            "the face it closed holds nobody"
        );
        the_dial(&peers.open_node(A, &cx, &mut next_id));
        assert_eq!(
            peers.state(&NODE),
            Some(S::Connecting),
            "an open starts it again"
        );
    }

    /// Decision D6 — an endpoint has no zid of its own, and a `close` names it by
    /// the node its last session reached: its machine is stopped where it waits,
    /// and the timer it armed dials nothing. Listing it again starts it.
    #[cfg(feature = "session-close-ingress")]
    #[test]
    fn a_withdrawn_endpoint_is_named_by_the_node_it_reached() {
        let directory = directory_with(&[]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(500));
        let mut next_id = 0;
        let plan = endpoint("tcp/127.0.0.1:7214");
        let key = PeerKey::Endpoint(plan.key.clone());
        let (id, _) = the_dial(&peers.set_endpoints(vec![plan.clone()], false, &cx, &mut next_id));
        peers.dial_ended(
            id,
            DialEnd::Established { remote: Some(A) },
            &cx,
            &mut next_id,
        );
        let (_, generation, _) = the_retry(&peers.face_down(id, &cx, &mut next_id).expect("held"));
        assert_eq!(peers.state(&key), Some(S::Backoff));

        assert!(peers.withdraw(&A, &cx, &mut next_id).is_empty());
        assert_eq!(peers.state(&key), Some(S::Idle));
        assert!(
            peers
                .retry_due(key.clone(), generation, &cx, &mut next_id)
                .is_empty(),
            "the wait it was in is cancelled"
        );
        assert!(
            peers.withdraw(&[0xb2; 16], &cx, &mut next_id).is_empty(),
            "another node's close touches it not"
        );
        the_dial(&peers.set_endpoints(vec![plan], false, &cx, &mut next_id));
        assert_eq!(peers.state(&key), Some(S::Connecting));
    }
}
