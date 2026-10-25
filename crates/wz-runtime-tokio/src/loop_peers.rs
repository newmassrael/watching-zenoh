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
//! the machine either way.
//!
//! The bookkeeping of the machines (which face a dial opened, which peer each held
//! face is held for, which retry timer is still its peer's) is written once for
//! every profile, in [`wz_session_core::peer_planner`]. This module is what an
//! AP face loop adds to it: what names a peer ([`PeerKey`](crate::loop_peers::PeerKey)), the configured
//! endpoints and how each is dialled, the loop's directory the candidates of a
//! node come from, and the retry schedule (upstream's `connect/retry`, with an
//! endpoint's own `#` overrides laid over it). Those are the planner's ports.
//!
//! It is a PLANNER, not a driver: every call returns the
//! [`PeerAction`](crate::loop_peers::PeerAction)s the
//! loop is to take (dial this target as this face, wake me for this peer after
//! this long, drop this face), and the loop takes them. Nothing here awaits,
//! dials or holds a socket, so the whole of the peer lifecycle is reachable by
//! a unit test without a loop, a listener or a peer.

use std::collections::{BTreeMap, BTreeSet};

use wz_session_core::locator_directory::DirectoryZid;
use wz_session_core::peer_connection::PeerConnectionState;
use wz_session_core::peer_planner::{PeerPlanner, PeerPorts};

use crate::accept_loop::{
    candidate_locators, first_dialable_locator, FaceId, LoopDirectory, RedialSchedule,
};
use crate::retry_period::RetryPolicy;
use crate::session_open::{MeshDialKey, MeshDialTarget};

/// How many peers a face loop can be told to hold, nodes and endpoints together.
pub const LOOP_PEER_ROWS: usize = 256;

/// How many dials a face loop can have in flight for its peers, with the ones a
/// peer stopped wanting while they ran, which stay until they end.
pub const LOOP_PEER_DIALS: usize = 2 * LOOP_PEER_ROWS;

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

/// What the loop is to do for the peers it holds: dial a target as a face, report
/// a retry timer after a wait, or (with the close seam) drop a face.
pub type PeerAction = wz_session_core::peer_planner::PeerAction<PeerKey, FaceId, MeshDialTarget>;

/// How a dial the planner asked for ended.
pub type DialEnd = wz_session_core::peer_planner::DialEnd<FaceId>;

/// The loop's state the planner reads: the directory and the clock.
pub struct PeerContext<'a> {
    /// The loop's locator directory (decision D3).
    pub directory: &'a LoopDirectory,
    /// The loop's monotonic clock, in milliseconds.
    pub now_ms: u64,
}

/// What an AP face loop answers for the planner.
struct LoopPorts<'a> {
    cx: &'a PeerContext<'a>,
    /// How to dial each configured endpoint the loop holds.
    endpoints: &'a BTreeMap<MeshDialKey, MeshDialTarget>,
    /// Each peer's retry schedule while it is down.
    retry: &'a mut RedialSchedule<PeerKey>,
}

impl PeerPorts<PeerKey> for LoopPorts<'_> {
    type Target = MeshDialTarget;

    /// What to dial for `key`: a node's first candidate that can be dialled from
    /// this loop, made for its zid, or an endpoint's own plan.
    fn dialable(&self, key: &PeerKey) -> Option<MeshDialTarget> {
        match key {
            PeerKey::Node(zid) => {
                first_dialable_locator(&candidate_locators(self.cx.directory, zid, self.cx.now_ms))
                    .map(|target| target.for_node(*zid))
            }
            PeerKey::Endpoint(endpoint) => self.endpoints.get(endpoint).cloned(),
        }
    }

    fn retry_wait_ms(&mut self, key: &PeerKey) -> u64 {
        let overrides = match key {
            PeerKey::Endpoint(endpoint) => {
                self.endpoints.get(endpoint).and_then(MeshDialTarget::retry)
            }
            PeerKey::Node(_) => None,
        };
        self.retry.next_ms(key, overrides)
    }

    fn retry_restart(&mut self, key: &PeerKey) {
        self.retry.forget(key);
    }
}

/// The planner of an AP face loop, over the loop's own peer keys and faces.
type LoopPlanner = PeerPlanner<PeerKey, FaceId, LOOP_PEER_ROWS, LOOP_PEER_DIALS>;

/// The peers a face loop holds, and what it is doing for each.
pub struct LoopPeers {
    planner: Box<LoopPlanner>,
    /// How to dial each configured endpoint the planner holds: the scheme and
    /// the `#` retry overrides the operator wrote, by the endpoint's key.
    endpoints: BTreeMap<MeshDialKey, MeshDialTarget>,
    /// Each peer's retry schedule while it is down.
    retry: RedialSchedule<PeerKey>,
}

impl LoopPeers {
    /// No peer held, retries on `policy` (upstream's `connect/retry`).
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            planner: Box::new(LoopPlanner::new()),
            endpoints: BTreeMap::new(),
            retry: RedialSchedule::new(policy),
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
    /// it is left standing (upstream's shape, `PeerTable::forget` of
    /// `wz_session_core::peer_table`). An
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
        self.plan(cx, |planner, ports, emit| {
            planner.retry_due(key, generation, ports, next_id, emit)
        })
        .1
    }

    /// Whether face `id` is a dial this planner asked for.
    pub fn is_dialing(&self, id: FaceId) -> bool {
        self.planner.is_dialing(id)
    }

    /// Whether face `id` is a dial this planner made for a node, which the loop
    /// holds by one face.
    pub fn dials_a_node(&self, id: FaceId) -> bool {
        matches!(self.planner.dial_key(id), Some(PeerKey::Node(_)))
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
        let (keep, actions) = self.plan(cx, |planner, ports, emit| {
            planner.dial_ended(id, end, ports, next_id, emit)
        });
        keep.map(|keep| (keep, actions))
    }

    /// Face `id` died. `None` when it is not a face a peer is held by.
    pub fn face_down(
        &mut self,
        id: FaceId,
        cx: &PeerContext<'_>,
        next_id: &mut u64,
    ) -> Option<Vec<PeerAction>> {
        let (held, actions) = self.plan(cx, |planner, ports, emit| {
            planner.face_down(id, ports, next_id, emit)
        });
        held.then_some(actions)
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
        self.plan(cx, |planner, ports, emit| {
            planner.withdraw(zid, PeerKey::Node(*zid), ports, next_id, emit)
        })
        .1
    }

    /// The state of `key`'s machine.
    pub fn state(&self, key: &PeerKey) -> Option<PeerConnectionState> {
        self.planner.state(key)
    }

    /// Every machine, as the loop publishes it for the status query (decision
    /// D6): by the zid it is read by, a node's own and an endpoint's last
    /// session's, the node's machine first and then its endpoints in order. An
    /// endpoint that has not reached a node has no zid to be read by and is left
    /// out.
    #[cfg(feature = "session-close-ingress")]
    pub fn board_rows(&self) -> crate::peer_board::BoardRows {
        let mut rows = crate::peer_board::BoardRows::new();
        for (key, state, remote) in self.planner.machines() {
            let (zid, endpoint) = match key {
                PeerKey::Node(zid) => (*zid, None),
                PeerKey::Endpoint(endpoint) => match remote {
                    Some(zid) => (*zid, Some(endpoint.to_string())),
                    None => continue,
                },
            };
            let words = state.words();
            rows.entry(zid)
                .or_default()
                .push(crate::peer_board::BoardRow {
                    endpoint,
                    state: words.state,
                    cause: words.cause,
                    in_intent: state.in_intent(),
                });
        }
        for machines in rows.values_mut() {
            machines.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
        }
        rows
    }

    /// Run one call of the planner against the loop's ports, and return what it
    /// answered with the actions it asked for. An operator is told of the wait
    /// that follows a lost session at `info` and of the others at `debug`.
    fn plan<R>(
        &mut self,
        cx: &PeerContext<'_>,
        call: impl FnOnce(&mut LoopPlanner, &mut LoopPorts<'_>, &mut dyn FnMut(PeerAction)) -> R,
    ) -> (R, Vec<PeerAction>) {
        let mut ports = LoopPorts {
            cx,
            endpoints: &self.endpoints,
            retry: &mut self.retry,
        };
        let mut actions = Vec::new();
        let answer = call(&mut self.planner, &mut ports, &mut |action| {
            actions.push(action)
        });
        for action in &actions {
            if let PeerAction::Retry {
                key,
                after_ms,
                after_loss,
                ..
            } = action
            {
                if *after_loss {
                    log::info!(
                        "loop peers: {key} lost its session; dialling it again in {after_ms}ms"
                    );
                } else {
                    log::debug!("loop peers: {key} not reached; dialling it again in {after_ms}ms");
                }
            }
        }
        (answer, actions)
    }

    /// `open` for `key`: the authority admitted it.
    fn open(&mut self, key: PeerKey, cx: &PeerContext<'_>, next_id: &mut u64) -> Vec<PeerAction> {
        let (opened, actions) = self.plan(cx, |planner, ports, emit| {
            planner.open(key.clone(), ports, next_id, emit)
        });
        if let Err(why) = opened {
            log::warn!("loop peers: no room to hold {key} ({why:?}); refusing the open");
            if let PeerKey::Endpoint(endpoint) = &key {
                self.endpoints.remove(endpoint);
            }
        }
        actions
    }

    /// Stop working to hold `key`, and leave a session it has standing.
    fn forget(&mut self, key: &PeerKey) {
        self.planner.forget(key);
        if let PeerKey::Endpoint(endpoint) = key {
            self.endpoints.remove(endpoint);
        }
        // Its growth goes with it, so a peer listed again later starts from the
        // initial wait rather than the ceiling of the outage before its removal.
        self.retry.forget(key);
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
                ..
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

    /// Decision D6 — what the status query reads: every machine that holds a
    /// node, by the node's zid, the node's own first; an endpoint not yet at a
    /// node is read by nobody; a withdrawal leaves the machines `idle` and the
    /// node out of the intent.
    #[cfg(feature = "session-close-ingress")]
    #[test]
    fn the_board_reads_each_machine_by_the_node_it_holds() {
        let directory = directory_with(&["tcp/127.0.0.1:7216"]);
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut peers = LoopPeers::new(RetryPolicy::constant(500));
        let mut next_id = 0;
        let reached = endpoint("tcp/127.0.0.1:7217");
        let unreached = endpoint("tcp/127.0.0.1:7218");
        let (node_dial, _) = the_dial(&peers.open_node(A, &cx, &mut next_id));
        peers.dial_ended(
            node_dial,
            DialEnd::Established { remote: Some(A) },
            &cx,
            &mut next_id,
        );
        let actions =
            peers.set_endpoints(vec![reached.clone(), unreached], false, &cx, &mut next_id);
        let PeerAction::Dial {
            id: reached_dial, ..
        } = &actions[0]
        else {
            panic!("expected the reached endpoint's dial, got {actions:?}");
        };
        peers.dial_ended(
            *reached_dial,
            DialEnd::AlreadyHeld {
                held: node_dial,
                remote: Some(A),
            },
            &cx,
            &mut next_id,
        );

        let board = peers.board_rows();
        assert_eq!(
            board.len(),
            1,
            "the unreached endpoint names no node: {board:?}"
        );
        let established = |endpoint: Option<String>| crate::peer_board::BoardRow {
            endpoint,
            state: "established",
            cause: None,
            in_intent: true,
        };
        assert_eq!(
            board[&A],
            vec![
                established(None),
                established(Some(reached.key.to_string()))
            ]
        );

        peers.withdraw(&A, &cx, &mut next_id);
        let board = peers.board_rows();
        assert!(
            board[&A]
                .iter()
                .all(|row| row.state == "idle" && !row.in_intent),
            "{board:?}"
        );
    }
}
