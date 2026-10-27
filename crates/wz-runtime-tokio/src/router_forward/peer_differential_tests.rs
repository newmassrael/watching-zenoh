// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A peer node on the region-hat forwarder held equal to `LinkstateForwarder`
//! (`docs/peer-region-hats.md`, step 3).
//!
//! The same scene, a list of faces coming up and messages arriving on them, is
//! played into both forwarders through the one seam they share
//! ([`FaceForwarder`]), and what each sent to each face after each step is
//! compared. The comparison is over decoded messages, not bytes: a sequence
//! number, a declaration id or the order of two messages a single step sent
//! to different faces says nothing about routing, and the same message sent
//! twice is a difference. What a scene is compared on is stated by [`Seen`].
//!
//! A difference this gate finds is one of three things, and each is written
//! down where it is found: a defect of the region-hat forwarder at node mode
//! Peer (fixed), a defect of `LinkstateForwarder` (reported and fixed there),
//! or a difference the pin itself makes (recorded as such, with the citation,
//! and the scene is graded against the pin's rule instead).

use super::*;
use crate::linkstate_forward::LinkstateForwarder;
use crate::runtime_impl::TokioRuntime;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use sce_forge_runtime::codec::SceBytes;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use wz_codecs::linkstate::LinkstateOwned;
use wz_codecs::linkstate_link::LinkstateLink;
use wz_runtime_core::runtime::Runtime;
use wz_session_core::declare_build::build_declare_subscriber;
use wz_session_core::query_mode::ConsolidationMode;
use wz_session_core::request_build::RequestQueryBuilder;
use wz_session_core::wireexpr_resolve::id_and_suffix;

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// The 2-bit INIT wire form of a remote's role.
#[derive(Clone, Copy, Debug)]
enum Wire {
    Router = 0b00,
    Peer = 0b01,
    Client = 0b10,
}

/// What a node sent, reduced to what routing decides. Everything the two
/// forwarders legitimately number or order differently is left out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Seen {
    /// A `Push` and the payload of its `Put`, `None` for a `Del`.
    Push {
        keyexpr: String,
        payload: Option<Vec<u8>>,
    },
    /// A `DeclareSubscriber` and the keyexpr it names.
    DeclareSubscriber { keyexpr: String },
    /// A `DeclareFinal`.
    DeclareFinal,
    /// An `UndeclareSubscriber`.
    UndeclareSubscriber,
    /// A `DeclareQueryable` and the completeness it carries.
    DeclareQueryable { keyexpr: String, complete: bool },
    /// A `Request` forwarded to a queryable, with the target, the timeout and
    /// the query body (consolidation and parameters) it carries. Its request id
    /// is left out: each forwarder numbers the queries it relays by its own
    /// table, and the reply is matched to it through [`Node::last_request`].
    Request {
        keyexpr: String,
        target: Option<String>,
        timeout_ms: Option<u64>,
        body: String,
    },
    /// A `Response` as the querier sees it, so the request id is the
    /// querier's own, which both forwarders must restore.
    Response {
        request_id: u64,
        keyexpr: String,
        payload: Option<Vec<u8>>,
    },
    /// An `Err` `Response` as the querier sees it, the relay's own
    /// `Err("Timeout")` included.
    ResponseErr {
        request_id: u64,
        keyexpr: String,
        payload: Vec<u8>,
    },
    /// A `ResponseFinal` as the querier sees it.
    ResponseFinal { request_id: u64 },
    /// A link-state list, as the (zid, sorted link zids) of each entry that
    /// names its node, so the psid numbering is not compared.
    LinkState {
        entries: usize,
        nodes: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    },
    /// Anything else, by the name of its kind, so that a kind one node sends
    /// and the other does not is a difference and its contents are not.
    Other(&'static str),
}

/// One thing that happens to the node under test.
#[derive(Clone, Debug)]
enum Step {
    /// A face comes up: id, the remote's zid byte, its role.
    Up(u64, u8, Wire),
    /// The neighbour on a face advertises a link back to the node, which forms
    /// the edge in the graph.
    LinkBack(u64, u8, u64),
    /// A `DeclareSubscriber` arrives on a face.
    Subscribe(u64, &'static str),
    /// The `UndeclareSubscriber` of the same keyexpr arrives on a face.
    Unsubscribe(u64, &'static str),
    /// A `Put` arrives on a face.
    Put(u64, &'static str, &'static [u8]),
    /// A `DeclareQueryable` arrives on a face: keyexpr, completeness.
    Queryable(u64, &'static str, bool),
    /// A `Request` arrives on a face: the querier's request id, keyexpr.
    Query(u64, u64, &'static str),
    /// A `Request` that also carries what the querier asked for.
    QueryWith(u64, u64, &'static str, Asked),
    /// The queryable on a face answers the last `Request` that was forwarded
    /// to it, with a `Reply` under the keyexpr.
    Reply(u64, &'static str, &'static [u8]),
    /// The same, with an `Err` reply.
    ReplyErr(u64, &'static str, &'static [u8]),
    /// Time passes: the node's clock moves on by this many milliseconds.
    Advance(u64),
    /// The queryable on a face ends the last `Request` forwarded to it.
    Final(u64),
    /// The queryable on a face answers the request it has just ended, which is
    /// a reply that loses the race to its own final.
    ReplyAfterFinal(u64, &'static str, &'static [u8]),
    /// A face goes down.
    Down(u64),
    /// The periodic tick.
    Tick,
}

/// What a querier asks beyond the keyexpr. Every field left `None` is absent
/// from the Request, which is the wire default.
#[derive(Clone, Copy, Debug, Default)]
struct Asked {
    target: Option<QueryTarget>,
    consolidation: Option<ConsolidationMode>,
    timeout_ms: Option<u64>,
    parameters: Option<&'static str>,
}

/// A node under test: the forwarder and what has been recorded on each face.
struct Node {
    fwd: Box<dyn FaceForwarder>,
    /// How far the node's injected clock has been moved from where it began,
    /// in milliseconds.
    clock_ms: Arc<AtomicU64>,
    sinks: BTreeMap<u64, Arc<RecordingLinkDriver>>,
    /// How many frames of each face were already read.
    read: BTreeMap<u64, usize>,
    /// The request id the node used on the last `Request` it forwarded to each
    /// face and that is not yet ended, which is what that face's answer must
    /// carry. A queryable that was sent no `Request` has nothing to answer: its
    /// `Reply` and `Final` steps do nothing, and that shows as a difference on
    /// the `Query` step when only one of two nodes forwarded the request.
    last_request: BTreeMap<u64, u64>,
    /// The request id each face last ended with a `Final`, for a reply that
    /// arrives after it.
    ended_request: BTreeMap<u64, u64>,
    self_zid: u8,
}

impl Node {
    fn new(fwd: Box<dyn FaceForwarder>, clock_ms: Arc<AtomicU64>, self_zid: u8) -> Self {
        Self {
            fwd,
            clock_ms,
            sinks: BTreeMap::new(),
            read: BTreeMap::new(),
            last_request: BTreeMap::new(),
            ended_request: BTreeMap::new(),
            self_zid,
        }
    }

    /// Apply `step` and return what each face was sent by it.
    fn apply(&mut self, step: &Step) -> BTreeMap<u64, Vec<Seen>> {
        match step {
            Step::Up(id, zid_byte, wire) => {
                let (actions, sink) = recording_actions();
                TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
                    *s = Some(zid(*zid_byte).as_slice().to_vec())
                });
                TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(*wire as u8));
                self.fwd.register(FaceId(*id), &actions);
                self.sinks.insert(*id, sink);
                self.read.insert(*id, 0);
            }
            Step::LinkBack(id, neighbour, sn) => {
                let oam = build_linkstate_oam_owned(&list(vec![
                    entry(0, 1, self.self_zid, &[]),
                    entry(1, *sn, *neighbour, &[0]),
                ]))
                .expect("build oam");
                self.deliver(*id, NetworkMessage::Oam(oam));
            }
            Step::Subscribe(id, keyexpr) => {
                let declare = build_declare_subscriber(0, 0, Some(keyexpr)).expect("declare");
                self.deliver(*id, NetworkMessage::Declare(Box::new(declare)));
            }
            Step::Unsubscribe(id, keyexpr) => {
                let undeclare =
                    wz_session_core::declare_build::build_undeclare_subscriber_with_keyexpr(
                        keyexpr,
                    )
                    .expect("undeclare");
                self.deliver(*id, NetworkMessage::Declare(Box::new(undeclare)));
            }
            Step::Put(id, keyexpr, payload) => {
                let push = wz_session_core::push_build::build_push_literal(keyexpr, payload)
                    .expect("push");
                self.deliver(*id, NetworkMessage::Push(Box::new(push)));
            }
            Step::Queryable(id, keyexpr, complete) => {
                let declare = build_declare_queryable_with_info(
                    keyexpr,
                    QueryableInfo {
                        complete: *complete,
                        distance: 0,
                    },
                )
                .expect("declare queryable");
                self.deliver(*id, NetworkMessage::Declare(Box::new(declare)));
            }
            Step::Query(id, rid, keyexpr) => {
                let request =
                    wz_session_core::request_build::build_request_query(*rid, 0, Some(keyexpr))
                        .expect("request");
                self.deliver(*id, NetworkMessage::Request(Box::new(request)));
            }
            Step::QueryWith(id, rid, keyexpr, asked) => {
                let mut builder = RequestQueryBuilder::new(*rid, 0, Some(keyexpr));
                if let Some(target) = asked.target {
                    builder = builder.request_target(target);
                }
                if let Some(mode) = asked.consolidation {
                    builder = builder.consolidation(mode);
                }
                if let Some(ms) = asked.timeout_ms {
                    builder = builder.request_timeout_ms(ms);
                }
                if let Some(parameters) = asked.parameters {
                    builder = builder.parameters(parameters.as_bytes());
                }
                let request = builder.build().expect("request");
                self.deliver(*id, NetworkMessage::Request(Box::new(request)));
            }
            Step::Advance(ms) => {
                self.clock_ms.fetch_add(*ms, Ordering::SeqCst);
            }
            Step::ReplyErr(id, keyexpr, payload) => {
                if let Some(rid) = self.last_request.get(id).copied() {
                    let response = wz_session_core::response_build::build_response_err_literal(
                        rid, keyexpr, payload,
                    )
                    .expect("response");
                    self.deliver(*id, NetworkMessage::Response(Box::new(response)));
                }
            }
            Step::Reply(id, keyexpr, payload) => {
                if let Some(rid) = self.last_request.get(id).copied() {
                    let response = wz_session_core::response_build::build_response_reply_literal(
                        rid, keyexpr, payload,
                    )
                    .expect("response");
                    self.deliver(*id, NetworkMessage::Response(Box::new(response)));
                }
            }
            Step::Final(id) => {
                if let Some(rid) = self.last_request.remove(id) {
                    self.ended_request.insert(*id, rid);
                    let end = wz_session_core::response_final_build::build_response_final(
                        rid,
                        wz_session_core::sample::QosLevel::DEFAULT,
                    );
                    self.deliver(*id, NetworkMessage::ResponseFinal(end));
                }
            }
            Step::ReplyAfterFinal(id, keyexpr, payload) => {
                if let Some(rid) = self.ended_request.get(id).copied() {
                    let response = wz_session_core::response_build::build_response_reply_literal(
                        rid, keyexpr, payload,
                    )
                    .expect("response");
                    self.deliver(*id, NetworkMessage::Response(Box::new(response)));
                }
            }
            Step::Down(id) => self.fwd.deregister(FaceId(*id)),
            Step::Tick => self.fwd.tick(),
        }
        self.drain()
    }

    fn deliver(&self, id: u64, message: NetworkMessage) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![message],
            has_ext: false,
            extensions: Vec::new(),
        };
        self.fwd.forward(FaceId(id), IterationEvent::Poll(&outcome));
    }

    /// What every face was sent since the last call, sorted so that the order
    /// of two messages in one step is not compared.
    fn drain(&mut self) -> BTreeMap<u64, Vec<Seen>> {
        let mut out = BTreeMap::new();
        for (id, sink) in &self.sinks {
            let from = self.read[id];
            let total = sink.frame_count();
            let mut seen: Vec<Seen> = Vec::new();
            for i in from..total {
                for (s, rid) in decode(&sink.frame_bytes(i)) {
                    if let Some(rid) = rid {
                        self.last_request.insert(*id, rid);
                    }
                    seen.push(s);
                }
            }
            seen.sort();
            if !seen.is_empty() {
                out.insert(*id, seen);
            }
            self.read.insert(*id, total);
        }
        out
    }
}

/// What a frame carried and, for a `Request`, the request id it was sent with.
fn decode(frame: &[u8]) -> Vec<(Seen, Option<u64>)> {
    use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
    let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(frame) else {
        return vec![(Seen::Other("non-frame"), None)];
    };
    parse_frame_payload(&payload)
        .expect("a frame payload")
        .iter()
        .map(|message| {
            let rid = match message {
                NetworkMessage::Request(request) => Some(request.rid),
                _ => None,
            };
            (seen_of(message), rid)
        })
        .collect()
}

/// The literal keyexpr of a wire expression the scenes built.
fn literal<S: sce_forge_runtime::codec::CodecStorage>(
    body: &wz_codecs::wireexpr::WireexprOwnedVariant<S>,
) -> String {
    let (id, suffix) = id_and_suffix(body);
    assert_eq!(id, 0, "the scenes use literal key expressions");
    suffix.unwrap_or_default().to_owned()
}

fn seen_of(message: &NetworkMessage) -> Seen {
    match message {
        NetworkMessage::Push(push) => {
            let (id, suffix) = id_and_suffix(&push.keyexpr.body);
            assert_eq!(id, 0, "the scenes use literal key expressions");
            let payload = match &push.body {
                PushOwnedVariant::CodecZenohMsgPut(put) => {
                    wz_session_core::put_payload::inline_bytes(put).map(<[u8]>::to_vec)
                }
                _ => None,
            };
            Seen::Push {
                keyexpr: suffix.unwrap_or_default().to_owned(),
                payload,
            }
        }
        NetworkMessage::Declare(declare) => match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => {
                let (id, suffix) = id_and_suffix(&sub.keyexpr.body);
                assert_eq!(id, 0, "the scenes use literal key expressions");
                Seen::DeclareSubscriber {
                    keyexpr: suffix.unwrap_or_default().to_owned(),
                }
            }
            DeclareOwnedVariant::CodecZenohDeclFinal(_) => Seen::DeclareFinal,
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => Seen::UndeclareSubscriber,
            DeclareOwnedVariant::CodecZenohDeclQueryable(q) => Seen::DeclareQueryable {
                keyexpr: literal(&q.keyexpr.body),
                complete: read_queryable_info(q.extensions.as_ref()).complete,
            },
            _ => Seen::Other("declare"),
        },
        NetworkMessage::Request(request) => Seen::Request {
            keyexpr: literal(&request.keyexpr.body),
            target: wz_session_core::request_routing_context::read_request_target(request)
                .map(|target| format!("{target:?}")),
            timeout_ms: wz_session_core::request_routing_context::read_request_timeout_ms(request),
            body: match &request.body {
                wz_session_core::wire::RequestOwnedVariant::CodecZenohQuery(query) => {
                    format!("{:?} {:?}", query.consolidation, query.parameters)
                }
                #[allow(unreachable_patterns)]
                _ => String::new(),
            },
        },
        NetworkMessage::Response(response) => match &response.body {
            wz_session_core::wire::ResponseOwnedVariant::CodecZenohErr(err) => Seen::ResponseErr {
                request_id: response.request_id,
                keyexpr: literal(&response.keyexpr.body),
                payload: err.payload.as_slice().to_vec(),
            },
            body => {
                let payload = match body {
                    wz_session_core::wire::ResponseOwnedVariant::CodecZenohReply(reply) => {
                        match &reply.body {
                            wz_session_core::wire::parts::ReplyOwnedVariant::CodecZenohMsgPut(
                                put,
                            ) => {
                                wz_session_core::put_payload::inline_bytes(put).map(<[u8]>::to_vec)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                Seen::Response {
                    request_id: response.request_id,
                    keyexpr: literal(&response.keyexpr.body),
                    payload,
                }
            }
        },
        NetworkMessage::ResponseFinal(end) => Seen::ResponseFinal {
            request_id: end.request_id,
        },
        NetworkMessage::Oam(oam) => match try_parse_linkstate_oam(oam) {
            LinkstateOam::Decoded(list) => Seen::LinkState {
                entries: list.link_states.len(),
                nodes: link_state_by_zid(&list.link_states),
            },
            _ => Seen::Other("oam"),
        },
        _ => Seen::Other("network-message"),
    }
}

/// A list's entries keyed by the zid they name, each with the zids it links
/// to, resolved through the psids the same list names.
fn link_state_by_zid(entries: &[LinkstateOwned]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let zid_of: BTreeMap<u64, Vec<u8>> = entries
        .iter()
        .filter_map(|e| Some((e.psid, e.zid.as_ref()?.as_slice().to_vec())))
        .collect();
    let mut out: Vec<(Vec<u8>, Vec<Vec<u8>>)> = entries
        .iter()
        .filter_map(|e| {
            let me = e.zid.as_ref()?.as_slice().to_vec();
            let mut links: Vec<Vec<u8>> = e
                .links
                .iter()
                .filter_map(|l| zid_of.get(&l.psid).cloned())
                .collect();
            links.sort();
            Some((me, links))
        })
        .collect();
    out.sort();
    out
}

fn entry(psid: u64, sn: u64, node: u8, links: &[u64]) -> LinkstateOwned {
    const OPT_P: u8 = 0x01;
    const OPT_W: u8 = 0x02;
    LinkstateOwned {
        options: OPT_P | OPT_W,
        psid,
        sn,
        zid_len: Some(4),
        zid: Some(SceBytes::from_slice(zid(node).as_slice()).unwrap()),
        whatami: Some(2),
        num_locators: None,
        locators: None,
        links_len: links.len() as u64,
        links: links.iter().map(|&psid| LinkstateLink { psid }).collect(),
        weights: None,
    }
}

fn list(entries: Vec<LinkstateOwned>) -> LinkstateListOwned {
    LinkstateListOwned {
        num_link_states: entries.len() as u64,
        link_states: entries,
    }
}

/// The peer routing mode both nodes are held to: zenoh's `routing.peer.mode`,
/// `peer_to_peer` (gossip, the default) or `linkstate`.
#[derive(Clone, Copy, Debug)]
enum Mode {
    Gossip,
    LinkState,
}

/// The two nodes a scene is played into, both at node zid byte `self_zid` and
/// both in `mode`.
fn both(self_zid: u8, mode: Mode) -> (Node, Node) {
    let full = matches!(mode, Mode::LinkState);
    // Each node reads its own clock, which a scene moves by the same amount in
    // both with `Step::Advance`.
    let began = Instant::now();
    let clock = || {
        let moved = Arc::new(AtomicU64::new(0));
        let read = Arc::clone(&moved);
        let now: Box<dyn Fn() -> Instant + Send + Sync> =
            Box::new(move || began + Duration::from_millis(read.load(Ordering::SeqCst)));
        (moved, now)
    };
    let (moved_old, now_old) = clock();
    let linkstate = LinkstateForwarder::with_clock(zid(self_zid), WhatAmI::Peer, now_old);
    linkstate.set_full_linkstate(full);
    let (moved_new, now_new) = clock();
    let hat = RouterForwarder::peer_with_clock(zid(self_zid), now_new);
    hat.on_tables_mut().set_peer_region_full_linkstate(full);
    (
        Node::new(Box::new(linkstate), moved_old, self_zid),
        Node::new(Box::new(hat), moved_new, self_zid),
    )
}

/// What a step sent, split into the data plane and the link-state list, which
/// are graded by different rules.
type Sent = BTreeMap<u64, Vec<Seen>>;

fn split(sent: Sent) -> (Sent, Sent) {
    let mut data = Sent::new();
    let mut topology = Sent::new();
    for (face, seen) in sent {
        for s in seen {
            let into = if matches!(s, Seen::LinkState { .. }) {
                &mut topology
            } else {
                &mut data
            };
            into.entry(face).or_default().push(s);
        }
    }
    (data, topology)
}

/// One step on which the two nodes sent different things.
#[derive(Debug)]
struct Divergence {
    step: Step,
    plane: &'static str,
    linkstate: Sent,
    region_hat: Sent,
}

/// Play `scene` into both nodes in `mode` and return every step on which they
/// sent something different, per plane. Empty means equal.
fn diverge(scene: &[Step], self_zid: u8, mode: Mode) -> Vec<Divergence> {
    let (mut old, mut new) = both(self_zid, mode);
    let mut out = Vec::new();
    for step in scene {
        let (old_data, old_topology) = split(old.apply(step));
        let (new_data, new_topology) = split(new.apply(step));
        for (plane, a, b) in [
            ("data", old_data, new_data),
            ("topology", old_topology, new_topology),
        ] {
            if a != b {
                out.push(Divergence {
                    step: step.clone(),
                    plane,
                    linkstate: a,
                    region_hat: b,
                });
            }
        }
    }
    out
}

/// Two peers 0xAA and 0xBB meet this node 0x01; 0xBB subscribes to `demo/**`;
/// 0xAA puts on `demo/data`.
fn two_peers_one_subscribes() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xBB, Wire::Peer),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(1, 0xBB, 5),
        Step::Tick,
        Step::Subscribe(1, "demo/**"),
        Step::Put(0, "demo/data", b"payload"),
    ]
}

/// A peer, a router and a client meet this node; the router and the client
/// subscribe; the peer puts.
fn a_peer_a_router_and_a_client() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xDD, Wire::Router),
        Step::Up(2, 0xCC, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(1, 0xDD, 5),
        Step::Tick,
        Step::Subscribe(1, "demo/**"),
        Step::Subscribe(2, "demo/data"),
        Step::Put(0, "demo/data", b"payload"),
    ]
}

/// A client subscribes first, a peer comes up afterwards and a router after it:
/// what a late face is told, and what reaches the client when the router puts.
fn faces_that_come_up_after_a_subscription() -> Vec<Step> {
    vec![
        Step::Up(0, 0xCC, Wire::Client),
        Step::Subscribe(0, "demo/**"),
        Step::Up(1, 0xAA, Wire::Peer),
        Step::LinkBack(1, 0xAA, 5),
        Step::Up(2, 0xDD, Wire::Router),
        Step::LinkBack(2, 0xDD, 5),
        Step::Tick,
        Step::Put(2, "demo/late", b"from the router"),
        Step::Put(1, "demo/late", b"from the peer"),
    ]
}

/// A subscription is withdrawn and a face goes away: nothing more is sent to
/// either.
fn a_subscription_withdrawn_and_a_face_gone() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xCC, Wire::Client),
        Step::Up(2, 0xCD, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Subscribe(1, "demo/data"),
        Step::Subscribe(2, "demo/data"),
        Step::Put(0, "demo/data", b"both"),
        Step::Unsubscribe(1, "demo/data"),
        Step::Put(0, "demo/data", b"one"),
        Step::Down(2),
        Step::Put(0, "demo/data", b"none"),
    ]
}

/// A client puts, with a peer, a router and another client subscribed: where a
/// Put from a node's own client goes.
fn a_client_puts() -> Vec<Step> {
    vec![
        Step::Up(0, 0xCC, Wire::Client),
        Step::Up(1, 0xAA, Wire::Peer),
        Step::Up(2, 0xDD, Wire::Router),
        Step::Up(3, 0xCD, Wire::Client),
        Step::LinkBack(1, 0xAA, 5),
        Step::LinkBack(2, 0xDD, 5),
        Step::Tick,
        Step::Subscribe(1, "demo/**"),
        Step::Subscribe(2, "demo/**"),
        Step::Subscribe(3, "demo/**"),
        Step::Put(0, "demo/data", b"from a client"),
    ]
}

/// Queries between a peer, a client and a router, each querying a queryable of
/// another kind: the Request is forwarded, the Reply returns to the querier under
/// its own request id and the final ends it.
fn queries_between_peers_clients_and_a_router() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xCC, Wire::Peer),
        Step::Up(2, 0xDD, Wire::Client),
        Step::Up(3, 0xEE, Wire::Router),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(1, 0xCC, 5),
        Step::LinkBack(3, 0xEE, 5),
        Step::Tick,
        Step::Queryable(1, "demo/q", true),
        Step::Queryable(2, "demo/c", false),
        Step::Tick,
        Step::Query(0, 99, "demo/q"),
        Step::Reply(1, "demo/q", b"from a peer"),
        Step::Final(1),
        Step::Query(0, 100, "demo/c"),
        Step::Reply(2, "demo/c", b"from a client"),
        Step::Final(2),
        Step::Query(2, 7, "demo/q"),
        Step::Reply(1, "demo/q", b"for a client"),
        Step::Final(1),
        Step::Query(3, 8, "demo/c"),
        Step::Reply(2, "demo/c", b"for a router"),
        Step::Final(2),
    ]
}

/// A client declares a queryable first; a peer and a router come up after it and
/// each queries it.
fn a_queryable_declared_before_the_faces_come_up() -> Vec<Step> {
    vec![
        Step::Up(0, 0xDD, Wire::Client),
        Step::Queryable(0, "demo/q", true),
        Step::Up(1, 0xAA, Wire::Peer),
        Step::LinkBack(1, 0xAA, 5),
        Step::Up(2, 0xEE, Wire::Router),
        Step::LinkBack(2, 0xEE, 5),
        Step::Tick,
        Step::Query(1, 5, "demo/q"),
        Step::Reply(0, "demo/q", b"to the peer"),
        Step::Final(0),
        Step::Query(2, 6, "demo/q"),
        Step::Reply(0, "demo/q", b"to the router"),
        Step::Final(0),
    ]
}

/// The queryable's face goes down while its query is open: the querier is owed
/// the end of the query.
fn a_queryable_face_goes_down_mid_query() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xDD, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/q", true),
        Step::Query(0, 5, "demo/q"),
        Step::Down(1),
    ]
}

/// Two client queryables of one keyexpr, one complete and one not, queried with
/// each target, each consolidation mode, a timeout and parameters: what a
/// querier asked for reaches the queryables, and the answers return.
fn what_a_querier_asks_for() -> Vec<Step> {
    let ask = |target, consolidation, timeout_ms, parameters| Asked {
        target,
        consolidation,
        timeout_ms,
        parameters,
    };
    let mut scene = vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::Up(2, 0xC2, Wire::Client),
        Step::Up(3, 0xEE, Wire::Router),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(3, 0xEE, 5),
        Step::Tick,
        Step::Queryable(1, "demo/a", true),
        Step::Queryable(2, "demo/a", false),
        Step::Tick,
    ];
    let asks = [
        ask(None, None, None, None),
        ask(Some(QueryTarget::All), None, None, None),
        ask(Some(QueryTarget::AllComplete), None, None, None),
        ask(None, Some(ConsolidationMode::None), None, None),
        ask(None, Some(ConsolidationMode::Monotonic), None, None),
        ask(None, Some(ConsolidationMode::Latest), None, None),
        ask(None, None, Some(4_000), None),
        ask(None, None, None, Some("x=1;y=2")),
    ];
    for (n, asked) in asks.into_iter().enumerate() {
        let querier = if n % 2 == 0 { 0 } else { 3 };
        scene.extend([
            Step::QueryWith(querier, 40 + n as u64, "demo/a", asked),
            Step::Reply(1, "demo/a", b"one"),
            Step::Final(1),
            Step::Reply(2, "demo/a", b"two"),
            Step::Final(2),
        ]);
    }
    scene
}

/// A queryable answers with an `Err`, and another leaves its query unanswered
/// until it times out, after which a late reply arrives and is dropped.
fn an_error_reply_and_a_timeout() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::Up(2, 0xC2, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/e", true),
        Step::Queryable(2, "demo/t", true),
        Step::Tick,
        Step::Query(0, 21, "demo/e"),
        Step::ReplyErr(1, "demo/e", b"refused"),
        Step::Final(1),
        Step::Query(0, 22, "demo/t"),
        Step::Advance(5_000),
        Step::Tick,
        Step::Advance(6_000),
        Step::Tick,
        Step::Reply(2, "demo/t", b"too late"),
        Step::Final(2),
    ]
}

/// A query is open while the topology changes: a new router comes up and the
/// tick recomputes the tree, and the reply still reaches the querier.
fn a_query_open_across_a_recompute() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/r", true),
        Step::Query(0, 31, "demo/r"),
        Step::Up(2, 0xEE, Wire::Router),
        Step::LinkBack(2, 0xEE, 5),
        Step::Tick,
        Step::Reply(1, "demo/r", b"across"),
        Step::Final(1),
        Step::Query(2, 32, "demo/r"),
        Step::Reply(1, "demo/r", b"to the new router"),
        Step::Final(1),
    ]
}

/// A querier asks for a timeout shorter than the default: the clock moves past
/// it and not past the default, so only a relay that honours the carried
/// deadline ends the query (`ext_timeout.unwrap_or(queries_default_timeout)`).
fn a_timeout_shorter_than_the_default() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/s", true),
        Step::Tick,
        Step::QueryWith(
            0,
            51,
            "demo/s",
            Asked {
                timeout_ms: Some(2_000),
                ..Asked::default()
            },
        ),
        Step::Advance(1_000),
        Step::Tick,
        Step::Advance(2_000),
        Step::Tick,
        Step::Reply(1, "demo/s", b"late"),
        Step::Final(1),
    ]
}

/// A queryable answers one keyexpr twice, under each consolidation mode: what
/// the querier receives says whether a relay consolidates on its own.
fn two_replies_under_each_consolidation_mode() -> Vec<Step> {
    let mut scene = vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/k", true),
        Step::Tick,
    ];
    for (n, mode) in [
        ConsolidationMode::None,
        ConsolidationMode::Monotonic,
        ConsolidationMode::Latest,
    ]
    .into_iter()
    .enumerate()
    {
        scene.extend([
            Step::QueryWith(
                0,
                60 + n as u64,
                "demo/k",
                Asked {
                    consolidation: Some(mode),
                    ..Asked::default()
                },
            ),
            Step::Reply(1, "demo/k", b"v1"),
            Step::Reply(1, "demo/k", b"v2"),
            Step::Final(1),
        ]);
    }
    scene
}

/// Two queryables of one keyexpr whose finals and replies arrive in each order,
/// and replies that arrive after their own final: the querier's final waits for
/// every branch, and a reply that lost its race is dropped.
fn finals_and_replies_in_every_order() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::Up(2, 0xC2, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Queryable(1, "demo/o", true),
        Step::Queryable(2, "demo/o", true),
        Step::Tick,
        Step::Query(0, 71, "demo/o"),
        Step::Final(1),
        Step::Reply(2, "demo/o", b"only"),
        Step::Final(2),
        Step::ReplyAfterFinal(2, "demo/o", b"too late"),
        Step::ReplyAfterFinal(1, "demo/o", b"too late too"),
        Step::Query(0, 72, "demo/o"),
        Step::Reply(1, "demo/o", b"a"),
        Step::Reply(2, "demo/o", b"b"),
        Step::Final(2),
        Step::Final(1),
        Step::ReplyAfterFinal(1, "demo/o", b"after both"),
    ]
}

fn scenes() -> Vec<(&'static str, Vec<Step>)> {
    vec![
        (
            "a timeout shorter than the default",
            a_timeout_shorter_than_the_default(),
        ),
        (
            "two replies under each consolidation mode",
            two_replies_under_each_consolidation_mode(),
        ),
        (
            "finals and replies in every order",
            finals_and_replies_in_every_order(),
        ),
        ("what a querier asks for", what_a_querier_asks_for()),
        (
            "an error reply and a timeout",
            an_error_reply_and_a_timeout(),
        ),
        (
            "a query across a recompute",
            a_query_open_across_a_recompute(),
        ),
        (
            "queries between peers, clients and a router",
            queries_between_peers_clients_and_a_router(),
        ),
        (
            "a queryable before the faces",
            a_queryable_declared_before_the_faces_come_up(),
        ),
        (
            "a queryable face goes down mid-query",
            a_queryable_face_goes_down_mid_query(),
        ),
        ("two peers", two_peers_one_subscribes()),
        (
            "a peer, a router and a client",
            a_peer_a_router_and_a_client(),
        ),
        (
            "faces after a subscription",
            faces_that_come_up_after_a_subscription(),
        ),
        (
            "withdrawn and gone",
            a_subscription_withdrawn_and_a_face_gone(),
        ),
        ("a client puts", a_client_puts()),
    ]
}

/// How many data messages (anything but a link-state list) the region-hat
/// peer sent over all scenes in `mode`: a gate whose scenes send nothing
/// compares nothing.
fn data_messages_sent(mode: Mode) -> usize {
    messages_sent(mode, |_| true)
}

/// How many of the data messages the region-hat peer sent over all scenes in
/// `mode` satisfy `wanted`.
fn messages_sent(mode: Mode, wanted: impl Fn(&Seen) -> bool) -> usize {
    scenes()
        .iter()
        .map(|(_, scene)| {
            let (_, mut node) = both(0x01, mode);
            scene
                .iter()
                .map(|step| {
                    split(node.apply(step))
                        .0
                        .values()
                        .flatten()
                        .filter(|s| wanted(s))
                        .count()
                })
                .sum::<usize>()
        })
        .sum()
}

/// A query reached a queryable and its answer reached the querier: the half of
/// the query plane a scene set that only sent Requests would not exercise.
fn answers_delivered(mode: Mode) -> usize {
    messages_sent(mode, |s| matches!(s, Seen::Response { .. }))
}

/// Each thing the query scenes claim to exercise, counted in what the region-hat
/// peer sent in `mode`. A scene that stopped producing one would still be
/// "equal", and equal over nothing proves nothing.
fn assert_the_query_scenes_exercise_what_they_claim(mode: Mode) {
    let requests_with = |wanted: fn(&Seen) -> bool| messages_sent(mode, wanted);
    let counted = [
        (
            "a Request carrying target All",
            requests_with(|s| matches!(s, Seen::Request { target: Some(t), .. } if t == "All")),
        ),
        (
            "a Request carrying target AllComplete",
            requests_with(
                |s| matches!(s, Seen::Request { target: Some(t), .. } if t == "AllComplete"),
            ),
        ),
        (
            "a Request carrying a timeout",
            requests_with(|s| {
                matches!(
                    s,
                    Seen::Request {
                        timeout_ms: Some(4_000),
                        ..
                    }
                )
            }),
        ),
        (
            "a Request carrying a consolidation mode",
            requests_with(|s| matches!(s, Seen::Request { body, .. } if body.starts_with("Some("))),
        ),
        (
            "a Request carrying parameters",
            requests_with(|s| matches!(s, Seen::Request { body, .. } if body.contains(" Some("))),
        ),
        (
            "an Err reply returned to a querier",
            requests_with(
                |s| matches!(s, Seen::ResponseErr { payload, .. } if payload == b"refused"),
            ),
        ),
        (
            "the relay's own Err(Timeout) returned to a querier",
            requests_with(
                |s| matches!(s, Seen::ResponseErr { payload, .. } if payload == b"Timeout"),
            ),
        ),
        (
            "a reply that crossed a recompute",
            requests_with(
                |s| matches!(s, Seen::Response { payload: Some(p), .. } if p == b"across"),
            ),
        ),
        (
            "the relay ending a query at the timeout the querier carried",
            requests_with(
                |s| matches!(s, Seen::ResponseErr { request_id: 51, payload, .. } if payload == b"Timeout"),
            ),
        ),
        (
            "both replies of a consolidated query reaching its querier",
            requests_with(
                |s| matches!(s, Seen::Response { request_id: 60..=62, payload: Some(p), .. } if p == b"v1" || p == b"v2"),
            ),
        ),
        (
            "an answer after one branch ended and the querier's final after both",
            requests_with(|s| {
                matches!(s, Seen::Response { request_id: 71, payload: Some(p), .. } if p == b"only")
                    || matches!(s, Seen::ResponseFinal { request_id: 71 })
            }),
        ),
    ];
    for (what, n) in counted {
        assert!(n >= 1, "{mode:?}: no scene produced {what}");
    }
}

/// The two reasons the gate lets the planes differ in gossip mode, each a place
/// where `LinkstateForwarder` leaves the pin and the region-hat peer follows it.
const FACE_UP_LIST: &str = "face-up link-state list";
const TREE_READVERTISE: &str = "re-advertise to a tree child";

/// Why `d` is not a failure, or `None` when it is one. Link-state mode has no
/// allowed difference: the extension is wz's, so there is no pin to be right.
fn explained(mode: Mode, d: &Divergence) -> Option<&'static str> {
    if !matches!(mode, Mode::Gossip) {
        return None;
    }
    match (d.plane, &d.step) {
        // The pin's gossip `add_link` sends a new link the entries of the nodes
        // the graph holds AND that are linked neighbours, zid only
        // (`zenoh/src/net/protocol/network.rs` @ `// Send all nodes linkstate on new link`),
        // which never includes self; `LinkstateForwarder` sends its own entry
        // and every node it knows. The list the region-hat peer sends is graded
        // against the pin by
        // `a_gossip_peer_tells_a_new_link_the_neighbours_it_knows_and_not_itself`.
        ("topology", Step::Up(..)) => Some(FACE_UP_LIST),
        // The pin's peer hat has no tree, so a recompute tells no child
        // anything (`zenoh/src/net/routing/hat/peer/pubsub.rs` @ `if ctx.subs.is_some() && self.region() != *src_region {`
        // for the rule that a peer hat offers its faces nothing from its own
        // region). `LinkstateForwarder` re-advertises a declaration it already
        // told the face at face-up when the tick recomputes its tree.
        ("data", Step::Tick)
            if d.region_hat.is_empty()
                && d.linkstate.values().flatten().all(|s| {
                    matches!(
                        s,
                        Seen::DeclareSubscriber { .. } | Seen::DeclareQueryable { .. }
                    )
                }) =>
        {
            Some(TREE_READVERTISE)
        }
        _ => None,
    }
}

/// Every step of every scene in `mode` whose difference `explained` does not
/// explain, and the set of reasons that did explain one.
fn unexplained(mode: Mode) -> (Vec<String>, std::collections::BTreeSet<&'static str>) {
    let mut failures = Vec::new();
    let mut reasons = std::collections::BTreeSet::new();
    for (name, scene) in scenes() {
        for d in diverge(&scene, 0x01, mode) {
            match explained(mode, &d) {
                Some(reason) => {
                    reasons.insert(reason);
                }
                None => failures.push(format!(
                    "{mode:?} / {name} / {:?} / {}\n  linkstate:  {:?}\n  region-hat: {:?}",
                    d.step, d.plane, d.linkstate, d.region_hat
                )),
            }
        }
    }
    (failures, reasons)
}

/// In the pin's mode (gossip) the two peer planes send the same data and the
/// same topology but for two differences, both explained by the pin, and both
/// of which must still occur: a reason no scene reaches any more is stale.
#[test]
fn in_gossip_mode_the_two_peer_planes_differ_only_where_the_pin_says() {
    let (failures, reasons) = unexplained(Mode::Gossip);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        reasons,
        [FACE_UP_LIST, TREE_READVERTISE].into_iter().collect(),
        "each allowed difference must be one a scene produces"
    );
    assert!(
        data_messages_sent(Mode::Gossip) >= 8,
        "the scenes must send something for the comparison to mean anything"
    );
    assert!(
        answers_delivered(Mode::Gossip) >= 2,
        "the query scenes must deliver an answer to a querier for the comparison to mean anything"
    );
    assert_the_query_scenes_exercise_what_they_claim(Mode::Gossip);
}

/// What the pin's gossip peer tells a new link (`zenoh/src/net/protocol/network.rs`
/// @ `// Send all nodes linkstate on new link`): the entries of the nodes its
/// graph holds that are linked neighbours, by zid, and never its own. The
/// first link finds the graph empty of neighbours, so it is told nothing; a
/// neighbour whose own entry has arrived is named to the next link.
#[test]
fn a_gossip_peer_tells_a_new_link_the_neighbours_it_knows_and_not_itself() {
    let scene = [
        Step::Up(0, 0xAA, Wire::Peer),
        Step::LinkBack(0, 0xAA, 5),
        Step::Up(1, 0xBB, Wire::Peer),
    ];
    let (_, mut node) = both(0x01, Mode::Gossip);
    let told: Vec<Sent> = scene.iter().map(|s| split(node.apply(s)).1).collect();
    let nodes_told = |sent: &Sent, face: u64| -> Vec<Vec<u8>> {
        match sent.get(&face).map(Vec::as_slice) {
            Some([Seen::LinkState { nodes, .. }]) => nodes.iter().map(|(z, _)| z.clone()).collect(),
            other => panic!("one link-state list for face {face}, got {other:?}"),
        }
    };
    assert_eq!(
        nodes_told(&told[0], 0),
        Vec::<Vec<u8>>::new(),
        "the first link: no neighbour is in the graph yet, and self is never named"
    );
    assert_eq!(
        nodes_told(&told[2], 1),
        vec![zid(0xAA).as_slice().to_vec()],
        "the second link is told the neighbour whose entry arrived, and only it"
    );
}

/// In wz's link-state extension the two planes send the same data AND the same
/// topology: the region-hat peer relays inside its region along the tree, as
/// `LinkstateForwarder` does.
#[test]
fn in_link_state_mode_the_two_peer_planes_send_the_same_data_and_topology() {
    let (failures, reasons) = unexplained(Mode::LinkState);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        reasons.is_empty(),
        "link-state mode has no allowed difference"
    );
    assert!(
        data_messages_sent(Mode::LinkState) > data_messages_sent(Mode::Gossip),
        "the extension relays between peers, which gossip does not: \
         a scene set that sends as much in both would not exercise the tree"
    );
    assert!(
        answers_delivered(Mode::LinkState) > answers_delivered(Mode::Gossip),
        "the extension answers a query across peers, which gossip does not"
    );
    assert_the_query_scenes_exercise_what_they_claim(Mode::LinkState);
}
