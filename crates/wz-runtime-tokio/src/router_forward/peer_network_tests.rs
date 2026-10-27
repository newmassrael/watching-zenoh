// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A NETWORK of peer nodes on the region-hat forwarder held equal to the same
//! network of `LinkstateForwarder` nodes (`docs/peer-region-hats.md`, steps 3 and
//! 4, past the one node).
//!
//! The one-node gate ([`super::peer_differential_tests`]) scripts what arrives
//! on each face, so it cannot see what only a network does: a message crossing
//! more than one hop, a flood that returns to the node it came from, two paths
//! to one subscriber, a link-state graph that has to be exchanged rather than
//! handed over. Here the nodes are wired to each other by a deterministic
//! frame pump: what a node sent on a face is delivered, in order, to the face
//! at the far end, until nothing is in flight; then every node ticks, and the
//! pump runs again, until a tick sends nothing. The same topology and the same
//! script are built once from `LinkstateForwarder` nodes and once from
//! region-hat peers, and what the END POINTS (clients attached to a node)
//! received after each step is compared.
//!
//! What a network adds to the one-node gate's rules: a message delivered twice
//! is a difference, and a pump that does not settle is a failure of its own (a
//! loop), so loop freedom is graded by the same run that grades delivery.

use super::peer_differential_tests::{decode, make, zid, Mode, Plane, Seen, Wire};
use super::*;
use crate::runtime_impl::TokioRuntime;
use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::collections::BTreeMap;
use wz_runtime_core::runtime::Runtime;
use wz_session_core::declare_build::build_declare_subscriber;
use wz_session_core::interest_build::InterestKinds;

/// Frames a settle may move before it is called a loop. Every scene here moves
/// a few hundred.
const FRAME_LIMIT: usize = 20_000;

/// Where the far end of a face is.
#[derive(Clone, Copy, Debug)]
enum Far {
    /// Another node's face.
    Node { node: u8, face: u64 },
    /// An end point, a client that only records.
    Endpoint(u8),
}

/// A node's side of a link: what it sent on it, and how much of that was read.
struct Face {
    sink: Arc<RecordingLinkDriver>,
    read: usize,
    far: Far,
}

struct NetNode {
    fwd: Box<dyn FaceForwarder>,
    faces: BTreeMap<u64, Face>,
    next_face: u64,
}

/// A client attached to a node: what it received, and the request it must answer.
struct Endpoint {
    node: u8,
    face: u64,
    inbox: Vec<Seen>,
    open_request: Option<u64>,
}

/// One thing that happens to the network. Nodes exist from the start; links and
/// end points are made by steps, so a late join is a step.
#[derive(Clone, Debug)]
enum NetStep {
    /// Two nodes are linked as peers.
    Link(u8, u8),
    /// An end point (named by a zid byte) is attached to a node.
    Attach(u8, u8),
    /// An end point subscribes.
    Subscribe(u8, &'static str),
    /// An end point puts.
    Put(u8, &'static str, &'static [u8]),
    /// An end point declares a queryable.
    Queryable(u8, &'static str, bool),
    /// An end point withdraws its subscription.
    Unsubscribe(u8, &'static str),
    /// An end point sends an `Interest`: its id, the kinds, current, future and
    /// the key it is restricted to.
    Interest(u8, u64, InterestKinds, bool, bool, &'static str),
    /// An end point ends an interest of its own.
    InterestFinal(u8, u64),
    /// An end point declares a liveliness token.
    #[cfg(feature = "routing-token-tables")]
    Token(u8, &'static str),
    /// An end point withdraws a liveliness token.
    #[cfg(feature = "routing-token-tables")]
    Untoken(u8, &'static str),
    /// The link between two nodes goes down, both ends told.
    Cut(u8, u8),
    /// An end point queries, with its own request id.
    Query(u8, u64, &'static str),
    /// An end point answers the request it was last sent.
    Reply(u8, &'static str, &'static [u8]),
    /// An end point ends the request it was last sent.
    Final(u8),
}

struct Network {
    nodes: BTreeMap<u8, NetNode>,
    endpoints: BTreeMap<u8, Endpoint>,
    /// Frames carried between nodes since the last read, the data plane only:
    /// what a flood or a loop would multiply.
    carried: usize,
    moved: usize,
    /// The declaration ids handed out so far; one per declaration, so that no end
    /// point replaces what an earlier declaration of its own named.
    declarations: u64,
    /// The id each end point declared a key with, by kind, so a retraction names it.
    declared: BTreeMap<(u8, &'static str, &'static str), u64>,
}

/// What one step made the end points receive, and how many data messages the
/// nodes carried between them to do it.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    received: BTreeMap<u8, Vec<Seen>>,
    carried: usize,
}

impl Network {
    fn new(plane: Plane, mode: Mode, nodes: &[u8]) -> Self {
        let began = Instant::now();
        Self {
            nodes: nodes
                .iter()
                .map(|&n| {
                    let (fwd, _clock) = make(plane, n, mode, began);
                    (
                        n,
                        NetNode {
                            fwd,
                            faces: BTreeMap::new(),
                            next_face: 0,
                        },
                    )
                })
                .collect(),
            endpoints: BTreeMap::new(),
            carried: 0,
            moved: 0,
            declarations: 0,
            declared: BTreeMap::new(),
        }
    }

    /// A face on `node` for a remote `remote` of role `wire`, registered with
    /// the node's forwarder.
    fn open_face(&mut self, node: u8, remote: u8, wire: Wire, far: Far) -> u64 {
        let (actions, sink) = recording_actions();
        TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
            *s = Some(zid(remote).as_slice().to_vec())
        });
        TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(wire as u8));
        let n = self.nodes.get_mut(&node).expect("a node of the network");
        let id = n.next_face;
        n.next_face += 1;
        n.fwd.register(FaceId(id), &actions);
        n.faces.insert(id, Face { sink, read: 0, far });
        id
    }

    /// The frames every face sent since it was last read, with the far end each
    /// goes to, in node and face order.
    fn collect(&mut self) -> Vec<(Far, Vec<u8>)> {
        let mut out = Vec::new();
        for node in self.nodes.values_mut() {
            for face in node.faces.values_mut() {
                let total = face.sink.frame_count();
                for i in face.read..total {
                    out.push((face.far, face.sink.frame_bytes(i)));
                }
                face.read = total;
            }
        }
        out
    }

    /// Hand one frame to the far end it was sent to.
    fn deliver(&mut self, far: Far, frame: &[u8]) {
        match far {
            Far::Node { node, face } => {
                let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(frame) else {
                    return;
                };
                let messages = parse_frame_payload(&payload).expect("a frame payload");
                if !messages.iter().all(|m| matches!(m, NetworkMessage::Oam(_))) {
                    self.carried += 1;
                }
                let outcome = DriverLoopOutcome::FramePayload {
                    priority: Priority::DEFAULT,
                    reliable: true,
                    sn: 0,
                    messages,
                    has_ext: false,
                    extensions: Vec::new(),
                };
                self.nodes[&node]
                    .fwd
                    .forward(FaceId(face), IterationEvent::Poll(&outcome));
            }
            Far::Endpoint(name) => {
                let endpoint = self
                    .endpoints
                    .get_mut(&name)
                    .expect("an attached end point");
                for (seen, rid) in decode(frame) {
                    if let Some(rid) = rid {
                        endpoint.open_request = Some(rid);
                    }
                    endpoint.inbox.push(seen);
                }
            }
        }
    }

    /// Move frames until nothing is in flight.
    fn pump(&mut self) -> usize {
        let mut moved = 0;
        loop {
            let batch = self.collect();
            if batch.is_empty() {
                return moved;
            }
            for (far, frame) in batch {
                self.deliver(far, &frame);
                moved += 1;
                self.moved += 1;
                assert!(
                    self.moved < FRAME_LIMIT,
                    "the network moved {FRAME_LIMIT} frames without settling: a loop"
                );
            }
        }
    }

    /// Pump, tick every node, and pump again, until a tick sends nothing.
    fn settle(&mut self) {
        loop {
            self.pump();
            for node in self.nodes.values() {
                node.fwd.tick();
            }
            if self.pump() == 0 {
                return;
            }
        }
    }

    /// The id `endpoint` declared `keyexpr` with as `kind`.
    fn declared_id(&self, endpoint: u8, keyexpr: &'static str, kind: &'static str) -> u64 {
        *self
            .declared
            .get(&(endpoint, keyexpr, kind))
            .unwrap_or_else(|| panic!("end point {endpoint} never declared {kind} {keyexpr}"))
    }

    fn inject(&mut self, endpoint: u8, message: NetworkMessage) {
        let Endpoint { node, face, .. } = self.endpoints[&endpoint];
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![message],
            has_ext: false,
            extensions: Vec::new(),
        };
        self.nodes[&node]
            .fwd
            .forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Apply `step`, settle the network, and return what the end points received.
    fn apply(&mut self, step: &NetStep) -> Outcome {
        for e in self.endpoints.values_mut() {
            e.inbox.clear();
        }
        self.carried = 0;
        match step {
            NetStep::Link(a, b) => {
                // Both ends exist before either is served a frame.
                let fa = self.open_face(*a, *b, Wire::Peer, Far::Node { node: *b, face: 0 });
                let fb = self.open_face(*b, *a, Wire::Peer, Far::Node { node: *a, face: fa });
                self.nodes
                    .get_mut(a)
                    .and_then(|n| n.faces.get_mut(&fa))
                    .expect("the face just opened")
                    .far = Far::Node { node: *b, face: fb };
            }
            NetStep::Attach(name, node) => {
                let face = self.open_face(*node, *name, Wire::Client, Far::Endpoint(*name));
                self.endpoints.insert(
                    *name,
                    Endpoint {
                        node: *node,
                        face,
                        inbox: Vec::new(),
                        open_request: None,
                    },
                );
            }
            NetStep::Subscribe(name, keyexpr) => {
                self.declarations += 1;
                self.declared
                    .insert((*name, keyexpr, "subscriber"), self.declarations);
                let declare =
                    build_declare_subscriber(self.declarations, 0, Some(keyexpr)).expect("declare");
                self.inject(*name, NetworkMessage::Declare(Box::new(declare)));
            }
            NetStep::Unsubscribe(name, keyexpr) => {
                // The retraction carries the id AND the key, as zenoh-pico sends it.
                let declared = self.declared_id(*name, keyexpr, "subscriber");
                let undeclare = wz_session_core::declare_build::build_undeclare_subscriber_on_wire(
                    declared, 0, keyexpr,
                )
                .expect("undeclare");
                self.inject(*name, NetworkMessage::Declare(Box::new(undeclare)));
            }
            NetStep::Interest(name, id, kinds, current, future, keyexpr) => {
                let interest = wz_session_core::interest_build::build_interest_kinds(
                    *id,
                    *kinds,
                    *current,
                    *future,
                    0,
                    Some(keyexpr),
                )
                .expect("interest");
                self.inject(*name, NetworkMessage::Interest(interest));
            }
            NetStep::InterestFinal(name, id) => {
                let end = wz_session_core::interest_build::build_interest_final(*id);
                self.inject(*name, NetworkMessage::Interest(end));
            }
            #[cfg(feature = "routing-token-tables")]
            NetStep::Token(name, keyexpr) => {
                self.declarations += 1;
                self.declared
                    .insert((*name, keyexpr, "token"), self.declarations);
                let declare = wz_session_core::declare_build::build_declare_token(
                    self.declarations,
                    0,
                    Some(keyexpr),
                )
                .expect("declare token");
                self.inject(*name, NetworkMessage::Declare(Box::new(declare)));
            }
            #[cfg(feature = "routing-token-tables")]
            NetStep::Untoken(name, keyexpr) => {
                let declared = self.declared_id(*name, keyexpr, "token");
                let undeclare = wz_session_core::declare_build::build_undeclare_token_on_wire(
                    declared, 0, keyexpr,
                )
                .expect("undeclare token");
                self.inject(*name, NetworkMessage::Declare(Box::new(undeclare)));
            }
            NetStep::Cut(a, b) => {
                // What was sent before the cut is delivered first, as a link
                // that fails does not take back what it carried.
                self.pump();
                for (node, other) in [(*a, *b), (*b, *a)] {
                    let n = self.nodes.get_mut(&node).expect("a node of the network");
                    let face = n
                        .faces
                        .iter()
                        .find(|(_, f)| matches!(f.far, Far::Node { node, .. } if node == other))
                        .map(|(id, _)| *id)
                        .expect("a link between the two nodes");
                    n.fwd.deregister(FaceId(face));
                    n.faces.remove(&face);
                }
            }
            NetStep::Put(name, keyexpr, payload) => {
                let push = wz_session_core::push_build::build_push_literal(keyexpr, payload)
                    .expect("push");
                self.inject(*name, NetworkMessage::Push(Box::new(push)));
            }
            NetStep::Queryable(name, keyexpr, complete) => {
                let declare = build_declare_queryable_with_info(
                    keyexpr,
                    QueryableInfo {
                        complete: *complete,
                        distance: 0,
                    },
                )
                .expect("declare queryable");
                self.inject(*name, NetworkMessage::Declare(Box::new(declare)));
            }
            NetStep::Query(name, rid, keyexpr) => {
                let request =
                    wz_session_core::request_build::build_request_query(*rid, 0, Some(keyexpr))
                        .expect("request");
                self.inject(*name, NetworkMessage::Request(Box::new(request)));
            }
            NetStep::Reply(name, keyexpr, payload) => {
                if let Some(rid) = self.endpoints[name].open_request {
                    let response = wz_session_core::response_build::build_response_reply_literal(
                        rid, keyexpr, payload,
                    )
                    .expect("response");
                    self.inject(*name, NetworkMessage::Response(Box::new(response)));
                }
            }
            NetStep::Final(name) => {
                if let Some(rid) = self
                    .endpoints
                    .get_mut(name)
                    .and_then(|e| e.open_request.take())
                {
                    let end = wz_session_core::response_final_build::build_response_final(
                        rid,
                        wz_session_core::sample::QosLevel::DEFAULT,
                    );
                    self.inject(*name, NetworkMessage::ResponseFinal(end));
                }
            }
        }
        self.settle();
        Outcome {
            received: self
                .endpoints
                .iter()
                .filter(|(_, e)| !e.inbox.is_empty())
                .map(|(name, e)| {
                    let mut seen = e.inbox.clone();
                    seen.sort();
                    (*name, seen)
                })
                .collect(),
            carried: self.carried,
        }
    }
}

/// What every step of `script` made the end points receive on `plane`.
fn run(plane: Plane, mode: Mode, nodes: &[u8], script: &[NetStep]) -> Vec<Outcome> {
    let mut network = Network::new(plane, mode, nodes);
    script.iter().map(|step| network.apply(step)).collect()
}

/// A network scene: its nodes and what happens to it.
struct Scene {
    name: &'static str,
    nodes: Vec<u8>,
    script: Vec<NetStep>,
}

/// The end point at the named node: one byte, away from the node zids.
const fn ep(n: u8) -> u8 {
    0xE0 + n
}

/// Subscribe at one end of a chain of four and put at the other: a message
/// that must cross three links, then a query across the same three and its
/// answer and final back.
fn a_chain_of_four() -> Scene {
    Scene {
        name: "a chain of four",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(4), 4),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Put(ep(4), "demo/x", b"across three links"),
            NetStep::Queryable(ep(4), "demo/q", true),
            NetStep::Query(ep(1), 5, "demo/q"),
            NetStep::Reply(ep(4), "demo/q", b"answered across three links"),
            NetStep::Final(ep(4)),
            NetStep::Put(ep(4), "demo/y", b"again"),
        ],
    }
}

/// A hub with three spokes, a subscriber on two of them and a publisher on the
/// third: each subscriber gets the Put once.
fn a_star() -> Scene {
    Scene {
        name: "a star",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(1, 3),
            NetStep::Link(1, 4),
            NetStep::Attach(ep(2), 2),
            NetStep::Attach(ep(3), 3),
            NetStep::Attach(ep(4), 4),
            NetStep::Subscribe(ep(2), "demo/**"),
            NetStep::Subscribe(ep(3), "demo/**"),
            NetStep::Put(ep(4), "demo/x", b"to both"),
        ],
    }
}

/// A ring of four: two paths between a subscriber and a publisher, and a flood
/// that can go round. The Put must arrive once and the pump must settle.
fn a_ring_of_four() -> Scene {
    Scene {
        name: "a ring of four",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Link(4, 1),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(3), 3),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Put(ep(3), "demo/x", b"by one path"),
        ],
    }
}

/// A diamond: two equal paths between the ends.
fn a_diamond() -> Scene {
    Scene {
        name: "a diamond",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(1, 3),
            NetStep::Link(2, 4),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(4), 4),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Subscribe(ep(4), "demo/**"),
            NetStep::Put(ep(4), "demo/x", b"from one end"),
            NetStep::Put(ep(1), "demo/y", b"from the other"),
        ],
    }
}

/// A chain that grows: the subscription is made on a chain of three, then a
/// fourth node and its publisher join, so the new publisher's Put has to find a
/// subscription declared before it existed.
fn a_chain_that_grows() -> Scene {
    Scene {
        name: "a chain that grows",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Attach(ep(1), 1),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(4), 4),
            NetStep::Put(ep(4), "demo/x", b"from the new end"),
        ],
    }
}

/// A line of five with a subscriber at each end and the publisher in the
/// middle: the Put goes out both ways and each end gets it once.
fn a_line_published_from_the_middle() -> Scene {
    Scene {
        name: "a line published from the middle",
        nodes: vec![1, 2, 3, 4, 5],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Link(4, 5),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(3), 3),
            NetStep::Attach(ep(5), 5),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Subscribe(ep(5), "demo/**"),
            NetStep::Put(ep(3), "demo/x", b"both ways"),
        ],
    }
}

/// A subscription is withdrawn across three links: the Put before it arrives
/// and the Put after it does not.
fn a_subscription_withdrawn_across_three_links() -> Scene {
    Scene {
        name: "a subscription withdrawn across three links",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(4), 4),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Put(ep(4), "demo/x", b"while subscribed"),
            NetStep::Unsubscribe(ep(1), "demo/**"),
            NetStep::Put(ep(4), "demo/x", b"after the withdrawal"),
        ],
    }
}

/// A ring loses a link: the tree is recomputed and the next Put finds the other
/// way round, which is what a link-state graph is for.
fn a_ring_that_loses_a_link() -> Scene {
    Scene {
        name: "a ring that loses a link",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Link(4, 1),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(3), 3),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Put(ep(3), "demo/x", b"before the cut"),
            NetStep::Cut(1, 2),
            NetStep::Put(ep(3), "demo/x", b"after the cut"),
            NetStep::Cut(1, 4),
            NetStep::Put(ep(3), "demo/x", b"cut off"),
        ],
    }
}

/// Queryables at both ends of a line and a querier in the middle: the query is
/// answered and ended whichever way it went.
fn queries_along_a_line() -> Scene {
    Scene {
        name: "queries along a line",
        nodes: vec![1, 2, 3, 4, 5],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Link(4, 5),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(3), 3),
            NetStep::Attach(ep(5), 5),
            NetStep::Queryable(ep(1), "demo/q", true),
            NetStep::Queryable(ep(5), "demo/q", true),
            NetStep::Query(ep(3), 9, "demo/q"),
            NetStep::Reply(ep(1), "demo/q", b"from the west"),
            NetStep::Reply(ep(5), "demo/q", b"from the east"),
            NetStep::Final(ep(1)),
            NetStep::Final(ep(5)),
        ],
    }
}

/// Two nodes: a subscriber on one and a publisher on the other, one link
/// between them. The one case gossip delivers across, because a peer hat sends
/// its own north faces what its clients subscribed to.
fn two_nodes() -> Scene {
    Scene {
        name: "two nodes",
        nodes: vec![1, 2],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(2), 2),
            NetStep::Subscribe(ep(1), "demo/**"),
            NetStep::Put(ep(2), "demo/x", b"across one link"),
        ],
    }
}

/// An interest across three links: the asker is answered with the subscription
/// that exists at the far end, then with the ones that come, and not after it
/// ends its interest.
fn an_interest_across_a_chain() -> Scene {
    Scene {
        name: "an interest across a chain",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(4), 4),
            NetStep::Subscribe(ep(4), "demo/a"),
            NetStep::Interest(ep(1), 7, InterestKinds::SUBSCRIBERS, true, true, "demo/**"),
            NetStep::Subscribe(ep(4), "demo/b"),
            NetStep::InterestFinal(ep(1), 7),
            NetStep::Subscribe(ep(4), "demo/c"),
        ],
    }
}

/// Liveliness across three links: a token at one end, a client at the other
/// that asked for tokens with a current-and-future interest, the token and its
/// withdrawal, a token that comes later and one after the interest ended.
#[cfg(feature = "routing-token-tables")]
fn liveliness_across_a_chain() -> Scene {
    Scene {
        name: "liveliness across a chain",
        nodes: vec![1, 2, 3, 4],
        script: vec![
            NetStep::Link(1, 2),
            NetStep::Link(2, 3),
            NetStep::Link(3, 4),
            NetStep::Attach(ep(1), 1),
            NetStep::Attach(ep(4), 4),
            NetStep::Token(ep(4), "live/a"),
            NetStep::Interest(ep(1), 9, InterestKinds::TOKENS, true, true, "live/**"),
            NetStep::Token(ep(4), "live/b"),
            NetStep::Untoken(ep(4), "live/a"),
            NetStep::InterestFinal(ep(1), 9),
            NetStep::Token(ep(4), "live/c"),
        ],
    }
}

fn scenes() -> Vec<Scene> {
    #[allow(unused_mut)]
    let mut scenes = vec![
        two_nodes(),
        a_chain_of_four(),
        a_star(),
        a_ring_of_four(),
        a_diamond(),
        a_chain_that_grows(),
        a_line_published_from_the_middle(),
        a_subscription_withdrawn_across_three_links(),
        a_ring_that_loses_a_link(),
        queries_along_a_line(),
        an_interest_across_a_chain(),
    ];
    #[cfg(feature = "routing-token-tables")]
    scenes.push(liveliness_across_a_chain());
    scenes
}

/// Every step of every scene in `mode` on which the two planes' end points
/// received something different, or the nodes carried a different number of
/// data messages to do it.
///
/// Returned with how many of the differences are each of the two the pin explains,
/// a token pushed to an end point that asked for tokens (see
/// [`is_a_token_pushed_to_an_interested_client`]) and a token interest brokered
/// to the peers (see [`is_an_interest_brokered_to_the_peers`]); every other
/// difference is a failure.
fn differences(mode: Mode) -> (Vec<String>, usize, usize) {
    let mut out = Vec::new();
    let mut explained = 0;
    let mut brokered = 0;
    for scene in scenes() {
        let old = run(Plane::LinkstateForwarder, mode, &scene.nodes, &scene.script);
        let new = run(Plane::RegionHat, mode, &scene.nodes, &scene.script);
        for (n, (a, b)) in old.iter().zip(&new).enumerate() {
            if a == b {
                continue;
            }
            if is_a_token_pushed_to_an_interested_client(&scene.script[n], a, b) {
                explained += 1;
                continue;
            }
            if is_an_interest_brokered_to_the_peers(&scene.script[n], a, b) {
                brokered += 1;
                continue;
            }
            out.push(format!(
                "{mode:?} / {} / step {n} {:?}\n  linkstate:  {a:?}\n  region-hat: {b:?}",
                scene.name, scene.script[n]
            ));
        }
    }
    (out, explained, brokered)
}

/// The one difference the network gate allows, and the same one the one-node gate
/// does (`TOKEN_TO_INTERESTED_CLIENT`): a token declared or withdrawn at a node
/// reaches an end point that asked for tokens with a future interest, which the
/// pin's broker hat does (it propagates a token to a south face that holds a
/// matching remote interest) and `LinkstateForwarder`'s partial token plane does
/// not. The two networks must carry as many messages to do it, and what
/// `LinkstateForwarder` delivered must be a part of what the region-hat peer did.
#[cfg(feature = "routing-token-tables")]
fn is_a_token_pushed_to_an_interested_client(step: &NetStep, a: &Outcome, b: &Outcome) -> bool {
    let is_token = |s: &Seen| matches!(s, Seen::DeclareToken { .. } | Seen::UndeclareToken);
    matches!(step, NetStep::Token(..) | NetStep::Untoken(..))
        && a.carried == b.carried
        && b.received
            .iter()
            .any(|(ep, seen)| seen.iter().any(is_token) && !a.received.contains_key(ep))
        && a.received.iter().all(|(ep, seen)| {
            b.received
                .get(ep)
                .is_some_and(|r| seen.iter().all(|s| r.contains(s)))
        })
}

#[cfg(not(feature = "routing-token-tables"))]
fn is_a_token_pushed_to_an_interested_client(_: &NetStep, _: &Outcome, _: &Outcome) -> bool {
    false
}

/// The second difference the network gate allows, and the one the one-node gate does
/// (`TOKEN_INTEREST_BROKERED`): with `routing-interest-pending-gc`, `LinkstateForwarder` carries
/// a client's token interest on to its peers, and its withdrawal after it, because its token table
/// does not hold the mesh tier. The pin's peer hat does, and sends a current-and-future interest
/// on only to the faces whose remote bound is south
/// (`zenoh/src/net/routing/hat/peer/interests.rs` @ `.filter(|f| f.remote_bound.is_south())`).
/// What the end points received is the same; the nodes carried more messages to do it.
#[cfg(all(
    feature = "routing-token-tables",
    feature = "routing-interest-pending-gc"
))]
fn is_an_interest_brokered_to_the_peers(step: &NetStep, a: &Outcome, b: &Outcome) -> bool {
    matches!(step, NetStep::Interest(..) | NetStep::InterestFinal(..))
        && a.received == b.received
        && a.carried > b.carried
}

#[cfg(not(all(
    feature = "routing-token-tables",
    feature = "routing-interest-pending-gc"
)))]
fn is_an_interest_brokered_to_the_peers(_: &NetStep, _: &Outcome, _: &Outcome) -> bool {
    false
}

/// How many messages of the kind `wanted` the end points of `scene` received on
/// the region-hat plane over the whole script.
fn received(mode: Mode, scene: &Scene, wanted: impl Fn(&Seen) -> bool) -> usize {
    run(Plane::RegionHat, mode, &scene.nodes, &scene.script)
        .iter()
        .flat_map(|o| o.received.values().flatten())
        .filter(|s| wanted(s))
        .count()
}

#[test]
fn in_gossip_mode_a_network_of_either_plane_delivers_the_same() {
    let (differing, explained, brokered) = differences(Mode::Gossip);
    assert!(differing.is_empty(), "{}", differing.join("\n"));
    assert_eq!(
        explained, 0,
        "gossip carries no token across a link to explain"
    );
    assert_eq!(
        brokered > 0,
        cfg!(all(
            feature = "routing-token-tables",
            feature = "routing-interest-pending-gc"
        )),
        "the brokered interest occurs exactly when the forwarder brokers one, \
         and a stale allowance is a hole"
    );
    // Equal is not the whole claim: the pin's peer hat sends a message across
    // one link and relays none between two peers, so gossip delivers across a
    // link and not across a second one, in both planes.
    let is_put = |s: &Seen| matches!(s, Seen::Push { .. });
    let named = |name: &str| {
        scenes()
            .into_iter()
            .find(|s| s.name == name)
            .expect("a scene of that name")
    };
    assert_eq!(
        received(Mode::Gossip, &named("two nodes"), is_put),
        1,
        "across one link"
    );
    for relayed in [
        "a chain of four",
        "a star",
        "a line published from the middle",
        "a ring that loses a link",
    ] {
        assert_eq!(
            received(Mode::Gossip, &named(relayed), is_put),
            0,
            "{relayed}: no peer relays to another in the pin's peer hat"
        );
    }
}

#[test]
fn in_link_state_mode_a_network_of_either_plane_delivers_the_same() {
    let (differing, explained, brokered) = differences(Mode::LinkState);
    assert!(differing.is_empty(), "{}", differing.join("\n"));
    assert_eq!(
        explained > 0,
        cfg!(feature = "routing-token-tables"),
        "the allowed token difference occurs exactly when the token plane is built, \
         and a stale allowance is a hole"
    );
    assert_eq!(
        brokered > 0,
        cfg!(all(
            feature = "routing-token-tables",
            feature = "routing-interest-pending-gc"
        )),
        "the brokered interest occurs exactly when the forwarder brokers one, \
         and a stale allowance is a hole"
    );
    let is_put = |s: &Seen| matches!(s, Seen::Push { .. });
    // Each subscriber of each scene got each Put exactly once: across three
    // links, through a hub, round a ring, along two equal paths, and from a
    // node that joined after the subscription.
    let expected = [
        ("two nodes", 1),
        ("a chain of four", 2),
        ("a star", 2),
        ("a ring of four", 1),
        ("a diamond", 2),
        ("a chain that grows", 1),
        ("a line published from the middle", 2),
        ("a subscription withdrawn across three links", 1),
        ("a ring that loses a link", 2),
        ("queries along a line", 0),
        ("an interest across a chain", 0),
        ("liveliness across a chain", 0),
    ];
    for scene in scenes() {
        let want = expected
            .iter()
            .find(|(name, _)| *name == scene.name)
            .map(|(_, n)| *n)
            .expect("every scene has an expected count");
        assert_eq!(
            received(Mode::LinkState, &scene, is_put),
            want,
            "{}: every Put reaches each subscriber once",
            scene.name
        );
    }
    // A query along a line is answered and ended: the querier gets at least
    // one answer and exactly one final.
    let line = scenes()
        .into_iter()
        .find(|s| s.name == "queries along a line")
        .expect("the query scene");
    assert!(
        received(Mode::LinkState, &line, |s| matches!(
            s,
            Seen::Response { .. }
        )) >= 1,
        "the querier is answered across the line"
    );
    assert_eq!(
        received(Mode::LinkState, &line, |s| matches!(
            s,
            Seen::ResponseFinal { .. }
        )),
        1,
        "and is sent exactly one final"
    );
    // An interest across three links is answered with what exists at the far end
    // and then with what comes, and with nothing after it is ended.
    let interest = scenes()
        .into_iter()
        .find(|s| s.name == "an interest across a chain")
        .expect("the interest scene");
    let declared_to_asker = |key: &'static str, answering: bool| {
        received(Mode::LinkState, &interest, move |s| {
            matches!(
                s,
                Seen::DeclareSubscriber { keyexpr, answer_to }
                    if keyexpr == key && answer_to.is_some() == answering
            )
        })
    };
    assert_eq!(
        declared_to_asker("demo/a", true),
        1,
        "the subscription that existed answers the interest"
    );
    assert_eq!(
        declared_to_asker("demo/b", false),
        1,
        "the one that came while it asked is told as a declaration of its own"
    );
    assert_eq!(
        declared_to_asker("demo/c", false) + declared_to_asker("demo/c", true),
        0,
        "and not the one after it ended"
    );
    assert_eq!(
        received(Mode::LinkState, &interest, |s| matches!(
            s,
            Seen::DeclareFinal { answer_to: Some(7) }
        )),
        1,
        "the current half is closed by exactly one final"
    );
    // The same for liveliness: the token that existed is told to the asker.
    #[cfg(feature = "routing-token-tables")]
    {
        let live = scenes()
            .into_iter()
            .find(|s| s.name == "liveliness across a chain")
            .expect("the liveliness scene");
        assert!(
            received(Mode::LinkState, &live, |s| matches!(
                s,
                Seen::DeclareToken { keyexpr, answer_to: Some(9) } if keyexpr == "live/a"
            )) >= 1,
            "the token that existed at the far end is told to the asker"
        );
    }
}
