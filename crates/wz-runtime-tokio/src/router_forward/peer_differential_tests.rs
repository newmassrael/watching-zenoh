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
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::query_mode::ConsolidationMode;
use wz_session_core::request_build::RequestQueryBuilder;
use wz_session_core::wireexpr_resolve::id_and_suffix;

pub(super) fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// The 2-bit INIT wire form of a remote's role.
#[derive(Clone, Copy, Debug)]
pub(super) enum Wire {
    Router = 0b00,
    Peer = 0b01,
    Client = 0b10,
}

/// What a node sent, reduced to what routing decides. Everything the two
/// forwarders legitimately number or order differently is left out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Seen {
    /// A `Push` and the payload of its `Put`, `None` for a `Del`.
    Push {
        keyexpr: String,
        payload: Option<Vec<u8>>,
    },
    /// A `DeclareSubscriber` and the keyexpr it names.
    DeclareSubscriber {
        keyexpr: String,
        answer_to: Option<u64>,
    },
    /// A `DeclareFinal`, and the interest it ends.
    DeclareFinal { answer_to: Option<u64> },
    /// A `DeclareToken`, and the interest it answers when it answers one.
    #[cfg(feature = "routing-token-tables")]
    DeclareToken {
        keyexpr: String,
        answer_to: Option<u64>,
    },
    /// An `UndeclareToken`.
    #[cfg(feature = "routing-token-tables")]
    UndeclareToken,
    /// An `Interest` the node propagated: what it asks for (current, future),
    /// the kinds and options its body carries, and the key. Its id is left out,
    /// as a request id is: a forwarder numbers the interests it relays itself.
    Interest {
        mode: u8,
        options: u8,
        keyexpr: Option<String>,
    },
    /// An `Interest` that ends a propagated one.
    InterestFinal,
    /// An `UndeclareSubscriber`.
    UndeclareSubscriber,
    /// A `DeclareQueryable` and the completeness it carries.
    DeclareQueryable {
        keyexpr: String,
        complete: bool,
        answer_to: Option<u64>,
    },
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
    /// The size of the graph the node holds: not a message but a witness read
    /// after each step, so that a plane that sends the same frames while
    /// learning a different topology is a difference.
    Graph { nodes: usize, edges: usize },
    /// What a handler the node hosts was given: a sample, or a query.
    Hosted(String),
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
    /// An `Interest` arrives on a face: its id, the kinds it asks for, whether
    /// it asks for what exists (`current`) and for what comes (`future`), and
    /// the key it is restricted to.
    Interest(u64, u64, InterestKinds, bool, bool, &'static str),
    /// The `Interest` of that id is ended by its sender.
    InterestFinal(u64, u64),
    /// A `DeclareToken` arrives on a face.
    #[cfg(feature = "routing-token-tables")]
    Token(u64, &'static str),
    /// The `UndeclareToken` of the same keyexpr arrives on a face.
    #[cfg(feature = "routing-token-tables")]
    Untoken(u64, &'static str),
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
    /// The node's own session puts: keyexpr, payload, priority, express.
    NodePut(&'static str, &'static [u8], Priority, bool),
    /// The node's own session deletes.
    #[cfg(feature = "pubsub-delete")]
    NodeDelete(&'static str),
    /// The node hosts a subscriber on a keyexpr.
    NodeHost(&'static str),
    /// The node takes the subscribers it hosts on a keyexpr back.
    NodeUnhost(&'static str),
    /// The node hosts a queryable: keyexpr, completeness, the name it answers with.
    NodeHostQueryable(&'static str, bool, &'static str),
    /// The node takes the queryables it hosts on a keyexpr back.
    NodeUnhostQueryable(&'static str),
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
    fwd: Box<dyn NodeSession>,
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
    /// The next declaration id. A face that reuses one replaces what it named,
    /// which is a protocol violation and not a scene, so every declaration a
    /// scene makes carries an id of its own.
    next_declaration: std::cell::Cell<u64>,
    /// The id each declaration of a face was made with, by the key and the kind,
    /// so that its retraction names it.
    declared: BTreeMap<(u64, &'static str, &'static str), u64>,
    /// What the handlers the node hosts were given since the last step.
    hosted: HostedLog,
    self_zid: u8,
}

impl Node {
    fn new(fwd: Box<dyn NodeSession>, clock_ms: Arc<AtomicU64>, self_zid: u8) -> Self {
        Self {
            fwd,
            clock_ms,
            sinks: BTreeMap::new(),
            read: BTreeMap::new(),
            last_request: BTreeMap::new(),
            ended_request: BTreeMap::new(),
            next_declaration: std::cell::Cell::new(1),
            declared: BTreeMap::new(),
            hosted: HostedLog::default(),
            self_zid,
        }
    }

    /// What the hosted handlers were given since the last call.
    fn heard_by_hosts(&self) -> Sent {
        let mut log = self.hosted.lock().unwrap();
        let heard: Vec<Seen> = log.drain(..).map(Seen::Hosted).collect();
        if heard.is_empty() {
            Sent::new()
        } else {
            Sent::from([(0, heard)])
        }
    }

    /// The id `face` declared `keyexpr` with as `kind`; a retraction of a
    /// declaration that was never made is a scene's mistake.
    fn declared_id(&self, face: u64, keyexpr: &'static str, kind: &'static str) -> u64 {
        *self
            .declared
            .get(&(face, keyexpr, kind))
            .unwrap_or_else(|| panic!("face {face} never declared {kind} {keyexpr}"))
    }

    fn declaration_id(&self) -> u64 {
        let id = self.next_declaration.get();
        self.next_declaration.set(id + 1);
        id
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
                let declared = self.declaration_id();
                self.declared.insert((*id, keyexpr, "subscriber"), declared);
                let declare =
                    build_declare_subscriber(declared, 0, Some(keyexpr)).expect("declare");
                self.deliver(*id, NetworkMessage::Declare(Box::new(declare)));
            }
            Step::Unsubscribe(id, keyexpr) => {
                // The retraction carries the id AND the key, as zenoh-pico sends it.
                let declared = self.declared_id(*id, keyexpr, "subscriber");
                let undeclare = wz_session_core::declare_build::build_undeclare_subscriber_on_wire(
                    declared, 0, keyexpr,
                )
                .expect("undeclare");
                self.deliver(*id, NetworkMessage::Declare(Box::new(undeclare)));
            }
            Step::Put(id, keyexpr, payload) => {
                let push = wz_session_core::push_build::build_push_literal(keyexpr, payload)
                    .expect("push");
                self.deliver(*id, NetworkMessage::Push(Box::new(push)));
            }
            Step::Interest(id, interest_id, kinds, current, future, keyexpr) => {
                let interest = wz_session_core::interest_build::build_interest_kinds(
                    *interest_id,
                    *kinds,
                    *current,
                    *future,
                    0,
                    Some(keyexpr),
                )
                .expect("interest");
                self.deliver(*id, NetworkMessage::Interest(interest));
            }
            Step::InterestFinal(id, interest_id) => {
                let end = wz_session_core::interest_build::build_interest_final(*interest_id);
                self.deliver(*id, NetworkMessage::Interest(end));
            }
            #[cfg(feature = "routing-token-tables")]
            Step::Token(id, keyexpr) => {
                let declared = self.declaration_id();
                self.declared.insert((*id, keyexpr, "token"), declared);
                let declare =
                    wz_session_core::declare_build::build_declare_token(declared, 0, Some(keyexpr))
                        .expect("declare token");
                self.deliver(*id, NetworkMessage::Declare(Box::new(declare)));
            }
            #[cfg(feature = "routing-token-tables")]
            Step::Untoken(id, keyexpr) => {
                let declared = self.declared_id(*id, keyexpr, "token");
                let undeclare = wz_session_core::declare_build::build_undeclare_token_on_wire(
                    declared, 0, keyexpr,
                )
                .expect("undeclare token");
                self.deliver(*id, NetworkMessage::Declare(Box::new(undeclare)));
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
            Step::NodePut(keyexpr, payload, priority, express) => {
                self.fwd.publish(keyexpr, payload, *priority, *express)
            }
            #[cfg(feature = "pubsub-delete")]
            Step::NodeDelete(keyexpr) => self.fwd.publish_delete(keyexpr),
            Step::NodeHost(keyexpr) => self.fwd.host_subscriber(keyexpr, Arc::clone(&self.hosted)),
            Step::NodeUnhost(keyexpr) => self.fwd.unhost_subscriber(keyexpr),
            Step::NodeHostQueryable(keyexpr, complete, name) => {
                self.fwd
                    .host_queryable(keyexpr, *complete, name, Arc::clone(&self.hosted))
            }
            Step::NodeUnhostQueryable(keyexpr) => self.fwd.unhost_queryable(keyexpr),
        }
        self.drain()
    }

    /// The size of the graph the node learned: nodes, then mutual links.
    fn graph(&self) -> (usize, usize) {
        (self.fwd.node_count(), self.fwd.edge_count())
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
pub(super) fn decode(frame: &[u8]) -> Vec<(Seen, Option<u64>)> {
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
                    answer_to: declare.interest_id,
                }
            }
            DeclareOwnedVariant::CodecZenohDeclFinal(_) => Seen::DeclareFinal {
                answer_to: declare.interest_id,
            },
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => Seen::UndeclareSubscriber,
            DeclareOwnedVariant::CodecZenohDeclQueryable(q) => Seen::DeclareQueryable {
                keyexpr: literal(&q.keyexpr.body),
                complete: read_queryable_info(q.extensions.as_ref()).complete,
                answer_to: declare.interest_id,
            },
            #[cfg(feature = "routing-token-tables")]
            DeclareOwnedVariant::CodecZenohDeclToken(t) => Seen::DeclareToken {
                keyexpr: literal(&t.keyexpr.body),
                answer_to: declare.interest_id,
            },
            #[cfg(feature = "routing-token-tables")]
            DeclareOwnedVariant::CodecZenohUndeclToken(_) => Seen::UndeclareToken,
            _ => Seen::Other("declare"),
        },
        NetworkMessage::Interest(interest) => match &interest.body {
            Some(body) => Seen::Interest {
                mode: interest.header & 0x60,
                options: body.header,
                keyexpr: body.keyexpr.as_ref().map(|k| literal(&k.body)),
            },
            None => Seen::InterestFinal,
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
pub(super) enum Mode {
    Gossip,
    LinkState,
}

/// The two nodes a scene is played into, both at node zid byte `self_zid` and
/// both in `mode`.
fn both(self_zid: u8, mode: Mode) -> (Node, Node) {
    let began = Instant::now();
    let (old, moved_old) = make(Plane::LinkstateForwarder, self_zid, mode, began);
    let (new, moved_new) = make(Plane::RegionHat, self_zid, mode, began);
    (
        Node::new(old, moved_old, self_zid),
        Node::new(new, moved_new, self_zid),
    )
}

/// The two peer planes the gate holds equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plane {
    /// The single-net peer forwarder, which retires at step 7.
    LinkstateForwarder,
    /// The region-hat forwarder at node mode Peer.
    RegionHat,
}

/// What the handlers a node hosts were given, in order.
pub(super) type HostedLog = Arc<std::sync::Mutex<Vec<String>>>;

/// A sample as a hosted subscriber was given it.
fn heard(sample: &dyn wz_session_core::sink::SampleView) -> String {
    format!(
        "{:?} {} {:?}",
        sample.kind(),
        sample.keyexpr(),
        sample.payload()
    )
}

/// What a node does as the owner of its own session, which the two planes spell
/// the same way: publish, and read the size of the graph it learned. Step 6 of
/// the note adds an entry here for each surface a plane has and a scene can
/// observe.
pub(super) trait NodeSession: FaceForwarder {
    /// Put `payload` on `keyexpr` at `priority`.
    fn publish(&self, keyexpr: &str, payload: &[u8], priority: Priority, express: bool);
    /// Delete `keyexpr`.
    #[cfg(feature = "pubsub-delete")]
    fn publish_delete(&self, keyexpr: &str);
    /// Advertise the node's dial locators on the floods it originates.
    fn set_self_locators(&self, locators: Vec<String>);
    /// Host a subscriber on `keyexpr`; what it is given is written to `log`.
    fn host_subscriber(&self, keyexpr: &str, log: HostedLog);
    /// Take the subscribers hosted on `keyexpr` back.
    fn unhost_subscriber(&self, keyexpr: &str);
    /// Host a queryable on `keyexpr` that answers every query with its own name;
    /// the queries it is given are written to `log`.
    fn host_queryable(&self, keyexpr: &str, complete: bool, name: &'static str, log: HostedLog);
    /// Take the queryables hosted on `keyexpr` back.
    fn unhost_queryable(&self, keyexpr: &str);
    /// Nodes in the graph of the peers, self included.
    fn node_count(&self) -> usize;
    /// Mutual links in that graph.
    fn edge_count(&self) -> usize;
}

impl NodeSession for LinkstateForwarder {
    fn publish(&self, keyexpr: &str, payload: &[u8], priority: Priority, express: bool) {
        let _ = LinkstateForwarder::publish_qos(self, keyexpr, payload, priority, express);
    }
    #[cfg(feature = "pubsub-delete")]
    fn publish_delete(&self, keyexpr: &str) {
        let _ = LinkstateForwarder::publish_delete(self, keyexpr);
    }
    fn set_self_locators(&self, locators: Vec<String>) {
        LinkstateForwarder::set_self_locators(self, locators)
    }
    fn host_subscriber(&self, keyexpr: &str, log: HostedLog) {
        let _ = self.register_local_subscriber(
            keyexpr,
            Box::new(move |sample| log.lock().unwrap().push(heard(sample))),
        );
    }
    fn unhost_subscriber(&self, keyexpr: &str) {
        let _ = self.undeclare_subscription(keyexpr);
    }
    fn host_queryable(&self, keyexpr: &str, complete: bool, name: &'static str, log: HostedLog) {
        let _ = self.register_local_queryable(
            keyexpr,
            complete,
            Box::new(move |query, replies| {
                log.lock()
                    .unwrap()
                    .push(format!("asked {}", query.keyexpr()));
                replies.reply(name.as_bytes());
            }),
        );
    }
    fn unhost_queryable(&self, keyexpr: &str) {
        let _ = self.undeclare_queryable(keyexpr);
    }
    fn node_count(&self) -> usize {
        LinkstateForwarder::node_count(self)
    }
    fn edge_count(&self) -> usize {
        LinkstateForwarder::edge_count(self)
    }
}

impl NodeSession for RouterForwarder {
    fn publish(&self, keyexpr: &str, payload: &[u8], priority: Priority, express: bool) {
        let tables = self.on_tables();
        let _ = if priority == Priority::DEFAULT && !express {
            tables.publish(keyexpr, payload)
        } else {
            tables.publish_qos(keyexpr, payload, priority, express)
        };
    }
    fn set_self_locators(&self, locators: Vec<String>) {
        self.on_tables_mut().set_self_locators(locators)
    }
    fn host_subscriber(&self, keyexpr: &str, log: HostedLog) {
        self.on_tables_mut().register_local_subscriber(
            keyexpr,
            Box::new(move |sample| log.lock().unwrap().push(heard(sample))),
        );
    }
    fn unhost_subscriber(&self, keyexpr: &str) {
        self.on_tables_mut().unregister_local_subscriber(keyexpr);
    }
    fn host_queryable(&self, keyexpr: &str, complete: bool, name: &'static str, log: HostedLog) {
        self.on_tables_mut().register_local_queryable(
            keyexpr,
            complete,
            Box::new(move |query, replies| {
                log.lock()
                    .unwrap()
                    .push(format!("asked {}", query.keyexpr()));
                replies.reply(name.as_bytes());
            }),
        );
    }
    fn unhost_queryable(&self, keyexpr: &str) {
        self.on_tables_mut().unregister_local_queryable(keyexpr);
    }
    #[cfg(feature = "pubsub-delete")]
    fn publish_delete(&self, keyexpr: &str) {
        let _ = self.on_tables().publish_delete(keyexpr);
    }
    fn node_count(&self) -> usize {
        self.on_tables().north_net_node_count()
    }
    fn edge_count(&self) -> usize {
        self.on_tables().north_net_edge_count()
    }
}

/// One forwarder of `plane` at node zid byte `self_zid` in `mode`, and the handle
/// that moves its clock. A node reads its own clock, which a scene moves by the
/// same amount in both planes; `began` is the instant every clock starts from.
pub(super) fn make(
    plane: Plane,
    self_zid: u8,
    mode: Mode,
    began: Instant,
) -> (Box<dyn NodeSession>, Arc<AtomicU64>) {
    let full = matches!(mode, Mode::LinkState);
    let moved = Arc::new(AtomicU64::new(0));
    let read = Arc::clone(&moved);
    let now: Box<dyn Fn() -> Instant + Send + Sync> =
        Box::new(move || began + Duration::from_millis(read.load(Ordering::SeqCst)));
    let forwarder: Box<dyn NodeSession> = match plane {
        Plane::LinkstateForwarder => {
            let linkstate = LinkstateForwarder::with_clock(zid(self_zid), WhatAmI::Peer, now);
            linkstate.set_full_linkstate(full);
            Box::new(linkstate)
        }
        Plane::RegionHat => {
            let hat = RouterForwarder::peer_with_clock(zid(self_zid), now);
            hat.on_tables_mut().set_peer_region_full_linkstate(full);
            Box::new(hat)
        }
    };
    (forwarder, moved)
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
        let graph = |node: &Node| {
            let (nodes, edges) = node.graph();
            Sent::from([(0, vec![Seen::Graph { nodes, edges }])])
        };
        for (plane, a, b) in [
            ("data", old_data, new_data),
            ("topology", old_topology, new_topology),
            ("graph", graph(&old), graph(&new)),
            ("hosted", old.heard_by_hosts(), new.heard_by_hosts()),
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

/// A client asks, with interests, what a peer declared: the current set and
/// what follows it for subscribers, the current set alone for queryables, an
/// interest ended and a declaration after it that is not answered.
fn a_client_asks_what_peers_declared() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xCC, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Subscribe(0, "demo/a"),
        Step::Queryable(0, "demo/q", true),
        Step::Interest(1, 7, InterestKinds::SUBSCRIBERS, true, true, "demo/**"),
        Step::Interest(1, 8, InterestKinds::QUERYABLES, true, false, "demo/**"),
        Step::Subscribe(0, "demo/b"),
        Step::Queryable(0, "demo/r", false),
        Step::Unsubscribe(0, "demo/a"),
        Step::InterestFinal(1, 7),
        Step::Subscribe(0, "demo/c"),
    ]
}

/// A peer and a router ask what a client declared, each with a current
/// interest: the answers and the final return to the face that asked.
fn a_peer_and_a_router_ask_what_a_client_declared() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xCC, Wire::Client),
        Step::Up(2, 0xEE, Wire::Router),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(2, 0xEE, 5),
        Step::Tick,
        Step::Subscribe(1, "demo/s"),
        Step::Queryable(1, "demo/q", true),
        Step::Interest(0, 3, InterestKinds::SUBSCRIBERS, true, false, "demo/**"),
        Step::Interest(2, 4, InterestKinds::QUERYABLES, true, false, "demo/**"),
        Step::Interest(0, 5, InterestKinds::SUBSCRIBERS, true, true, "other/**"),
        Step::Subscribe(1, "other/x"),
    ]
}

/// Liveliness tokens: a client's token reaches the peers, a client that asked
/// with a current-and-future interest is told the tokens that exist and then
/// the ones that come, a withdrawal reaches it, and an interest ended is
/// answered no more.
#[cfg(feature = "routing-token-tables")]
fn liveliness_tokens() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::Up(2, 0xC2, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::Token(1, "live/a"),
        Step::Interest(2, 5, InterestKinds::TOKENS, true, true, "live/**"),
        Step::Token(0, "live/b"),
        Step::Untoken(1, "live/a"),
        Step::Untoken(0, "live/b"),
        Step::InterestFinal(2, 5),
        Step::Token(1, "live/c"),
    ]
}

/// The node's own session as a publisher (step 6): its Put goes to the peers and
/// the clients that subscribed, to no one when no one did, banded and express
/// when it asks, and stops reaching a subscriber that withdrew or left. Two
/// peers and two clients, one client subscribing a narrower key than the peer.
fn a_node_publishes() -> Vec<Step> {
    #[allow(unused_mut)]
    let mut scene = vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xBB, Wire::Peer),
        Step::Up(2, 0xC1, Wire::Client),
        Step::Up(3, 0xC2, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::LinkBack(1, 0xBB, 5),
        Step::Tick,
        Step::NodePut("demo/none", b"n0", Priority::DEFAULT, false),
        Step::Subscribe(0, "demo/**"),
        Step::Subscribe(2, "demo/c/**"),
        Step::NodePut("demo/a", b"n1", Priority::DEFAULT, false),
        Step::NodePut("demo/c/x", b"n2", Priority::DEFAULT, false),
        Step::NodePut("demo/a", b"n3", Priority::RealTime, true),
        Step::Subscribe(1, "demo/a"),
        Step::NodePut("demo/a", b"n4", Priority::DEFAULT, false),
        Step::Unsubscribe(0, "demo/**"),
        Step::NodePut("demo/a", b"n5", Priority::DEFAULT, false),
        Step::Down(1),
        Step::NodePut("demo/a", b"n6", Priority::DEFAULT, false),
    ];
    #[cfg(feature = "pubsub-delete")]
    scene.push(Step::NodeDelete("demo/c/x"));
    scene
}

/// The node as a subscriber and a queryable (step 6): what it hosts is told to the
/// peers, delivered to the handler for a peer's Put and for its own, and taken
/// back; a client holding the same key keeps the interest alive past the hosted
/// subscriber's departure. A hosted queryable answers a peer's and a client's
/// query; a second one on the same key, incomplete, joins it, a client declares
/// the key incomplete too, and taking the key back removes both hosted ones and
/// leaves the client's, which the advertisement is lowered to.
fn a_node_hosts() -> Vec<Step> {
    vec![
        Step::Up(0, 0xAA, Wire::Peer),
        Step::Up(1, 0xC1, Wire::Client),
        Step::LinkBack(0, 0xAA, 5),
        Step::Tick,
        Step::NodeHost("demo/h/**"),
        Step::Put(0, "demo/h/a", b"from the peer"),
        Step::Subscribe(1, "demo/h/**"),
        Step::Put(0, "demo/h/b", b"to both"),
        Step::NodePut("demo/h/c", b"own", Priority::DEFAULT, false),
        Step::NodeUnhost("demo/h/**"),
        Step::Put(0, "demo/h/d", b"to the client only"),
        Step::Unsubscribe(1, "demo/h/**"),
        Step::NodeHostQueryable("demo/q/**", true, "first"),
        Step::Query(0, 7, "demo/q/x"),
        Step::Query(1, 8, "demo/q/y"),
        Step::NodeHostQueryable("demo/q/**", false, "second"),
        Step::Queryable(1, "demo/q/**", false),
        Step::NodeUnhostQueryable("demo/q/**"),
        Step::Query(0, 9, "demo/q/z"),
    ]
}

fn scenes() -> Vec<(&'static str, Vec<Step>)> {
    #[allow(unused_mut)]
    let mut scenes = vec![
        ("a node hosts", a_node_hosts()),
        ("a node publishes", a_node_publishes()),
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
        (
            "a client asks what peers declared",
            a_client_asks_what_peers_declared(),
        ),
        (
            "a peer and a router ask what a client declared",
            a_peer_and_a_router_ask_what_a_client_declared(),
        ),
    ];
    #[cfg(feature = "routing-token-tables")]
    scenes.push(("liveliness tokens", liveliness_tokens()));
    scenes
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

/// What the node-publish scene claims to exercise, counted in what the
/// region-hat peer sent in `mode`: a Put of the node reaching a peer and a
/// client, a banded one, a delete, and nothing after a subscriber left.
fn assert_the_node_publish_scene_exercises_what_it_claims(mode: Mode) {
    let (_, mut node) = both(0x01, mode);
    let mut got: Vec<(u64, Seen)> = Vec::new();
    for step in a_node_publishes() {
        for (face, seen) in node.apply(&step) {
            got.extend(seen.into_iter().map(|s| (face, s)));
        }
    }
    let put = |face: u64, payload: &[u8]| {
        got.iter().any(|(f, s)| {
            *f == face && matches!(s, Seen::Push { payload: Some(p), .. } if p == payload)
        })
    };
    assert!(
        !put(0, b"n0") && !put(2, b"n0"),
        "{mode:?}: n0 has no subscriber"
    );
    assert!(
        put(0, b"n1") && !put(2, b"n1"),
        "{mode:?}: n1 reaches the peer only"
    );
    assert!(
        put(0, b"n2") && put(2, b"n2"),
        "{mode:?}: n2 reaches the peer and the client"
    );
    assert!(put(0, b"n3"), "{mode:?}: the banded Put reaches the peer");
    assert!(
        put(0, b"n4") && put(1, b"n4"),
        "{mode:?}: n4 reaches both peers"
    );
    assert!(
        !put(0, b"n5") && put(1, b"n5"),
        "{mode:?}: n5 follows the withdrawal"
    );
    assert!(!put(1, b"n6"), "{mode:?}: n6 follows the face going down");
    #[cfg(feature = "pubsub-delete")]
    assert!(
        got.iter()
            .any(|(f, s)| *f == 2 && matches!(s, Seen::Push { payload: None, .. })),
        "{mode:?}: the delete reaches the client"
    );
}

/// A node's dial locators ride the link-state it originates, in both planes:
/// the pin asks its runtime for them whenever it builds a net's message.
#[test]
fn a_node_advertises_its_locators_in_the_flood_it_originates() {
    let locator = "tcp/10.0.0.1:7447";
    for plane in [Plane::LinkstateForwarder, Plane::RegionHat] {
        let (fwd, clock) = make(plane, 0x01, Mode::LinkState, Instant::now());
        let mut node = Node::new(fwd, clock, 0x01);
        node.fwd.set_self_locators(vec![locator.to_string()]);
        node.apply(&Step::Up(0, 0xAA, Wire::Peer));
        let sink = &node.sinks[&0];
        let carried = (0..sink.frame_count()).any(|i| {
            sink.frame_bytes(i)
                .windows(locator.len())
                .any(|w| w == locator.as_bytes())
        });
        assert!(carried, "{plane:?}: the first flood carries the locator");
    }
}

/// What the hosting scene claims to exercise, counted in what the region-hat peer's hosts
/// were given and what it sent in `mode`: the hosted subscriber hears a peer's Put and its
/// own, hears nothing once taken back, and a hosted queryable answers a peer and a client
/// until it is taken back.
fn assert_the_hosting_scene_exercises_what_it_claims(mode: Mode) {
    let (_, mut node) = both(0x01, mode);
    let mut heard_by_hosts: Vec<Seen> = Vec::new();
    let mut sent: Vec<(u64, Seen)> = Vec::new();
    for step in a_node_hosts() {
        let out = node.apply(&step);
        heard_by_hosts.extend(node.heard_by_hosts().into_values().flatten());
        for (face, seen) in out {
            sent.extend(seen.into_iter().map(|s| (face, s)));
        }
    }
    let heard_payload = |what: &str| {
        heard_by_hosts
            .iter()
            .any(|s| matches!(s, Seen::Hosted(h) if h.contains(what)))
    };
    assert!(
        heard_payload("demo/h/a"),
        "{mode:?}: the hosted subscriber hears the peer"
    );
    assert!(heard_payload("demo/h/b"), "{mode:?}: and the next Put");
    assert!(heard_payload("demo/h/c"), "{mode:?}: and the node's own");
    assert!(
        !heard_payload("demo/h/d"),
        "{mode:?}: and nothing once taken back"
    );
    let answered = |face: u64, name: &[u8]| {
        sent.iter().any(|(f, s)| {
            *f == face && matches!(s, Seen::Response { payload: Some(p), .. } if p == name)
        })
    };
    assert!(
        answered(0, b"first"),
        "{mode:?}: the hosted queryable answers the peer"
    );
    assert!(answered(1, b"first"), "{mode:?}: and the client");
    assert!(
        !sent.iter().any(|(_, s)| matches!(
            s,
            Seen::Response {
                request_id: 9,
                payload: Some(_),
                ..
            }
        )),
        "{mode:?}: and answers nothing once taken back"
    );
}

/// A region-hat peer whose hosted subscriber on `demo/**` writes what it is given to a
/// log and, while `echoes` allows, publishes into its own pattern from inside itself.
/// The handler holds the forwarder weakly, as the peer plane's tests do, so that the
/// forwarder and its handler do not keep each other alive.
fn a_peer_with_a_subscriber_that_echoes(
    echoes: impl Fn() -> bool + Send + 'static,
) -> (Arc<RouterForwarder>, HostedLog) {
    let fwd = Arc::new(RouterForwarder::peer(zid(0x05)));
    let log = HostedLog::default();
    let heard_by = Arc::clone(&log);
    let weak = Arc::downgrade(&fwd);
    fwd.on_tables_mut().register_local_subscriber(
        "demo/**",
        Box::new(move |sample| {
            heard_by.lock().unwrap().push(heard(sample));
            if echoes() {
                if let Some(fwd) = weak.upgrade() {
                    fwd.on_tables()
                        .publish("demo/data", b"echo")
                        .expect("publish");
                }
            }
        }),
    );
    (fwd, log)
}

/// A hosted subscriber that publishes into its own pattern is given what it published once
/// the delivery it is in is done: not dropped, as it was until step 6, and not delivered
/// inside itself, which an `FnMut` cannot take. The peer plane's
/// `dispatch_self_reentrant_subscriber_redelivers_a_single_self_echo`, on the region-hat peer.
#[test]
fn a_hosted_subscriber_hears_what_it_published_into_itself_after_the_delivery() {
    let once = std::sync::atomic::AtomicBool::new(false);
    let (fwd, log) = a_peer_with_a_subscriber_that_echoes(move || {
        !once.swap(true, std::sync::atomic::Ordering::SeqCst)
    });
    fwd.on_tables()
        .publish("demo/data", b"first")
        .expect("publish");
    let heard: Vec<String> = log.lock().unwrap().clone();
    assert_eq!(
        heard.len(),
        2,
        "the Put and its one echo, each given once: {heard:?}"
    );
    assert!(heard[0].contains("demo/data") && heard[1].contains("demo/data"));
}

/// A subscriber that publishes into itself every time is given a bounded number of
/// deliveries, the queue's size, and the delivery ends: zenoh bounds a channel's memory
/// and not the loop, and this is the bound a single thread's drain keeps.
#[test]
fn a_hosted_subscriber_that_always_echoes_is_given_a_bounded_number_of_deliveries() {
    let (fwd, log) = a_peer_with_a_subscriber_that_echoes(|| true);
    fwd.on_tables()
        .publish("demo/data", b"first")
        .expect("publish");
    assert_eq!(
        log.lock().unwrap().len(),
        1 + SELF_ECHO_QUEUE_CAP,
        "the first Put, then one delivery for each of the queue's places"
    );
}

/// What is left in the queue when a delivery ends is not given to a subscriber the host took
/// back, which would be a retracted subscriber still receiving.
#[test]
fn a_retracted_subscriber_is_not_given_what_was_queued_for_it() {
    let (fwd, log) = a_peer_with_a_subscriber_that_echoes(|| true);
    fwd.on_tables()
        .publish("demo/data", b"first")
        .expect("publish");
    let before = log.lock().unwrap().len();
    // One echo is still queued: the budget ran out first.
    assert!(fwd.on_tables_mut().unregister_local_subscriber("demo/**"));
    // A second subscriber elsewhere makes the next delivery drain the queue.
    let other = HostedLog::default();
    let other_log = Arc::clone(&other);
    fwd.on_tables_mut().register_local_subscriber(
        "other/**",
        Box::new(move |sample| other_log.lock().unwrap().push(heard(sample))),
    );
    fwd.on_tables()
        .publish("other/x", b"next")
        .expect("publish");
    assert_eq!(
        other.lock().unwrap().len(),
        1,
        "the other one hears its own"
    );
    assert_eq!(
        log.lock().unwrap().len(),
        before,
        "the retracted one is given nothing more"
    );
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

/// The reasons the gate lets the planes differ, each a place where
/// `LinkstateForwarder` leaves the pin and the region-hat peer follows it. The
/// first two are about how a gossip peer behaves and so occur in gossip mode
/// only; the rest are about the interest and token planes, which the link-state
/// extension does not touch, and occur in both.
const FACE_UP_LIST: &str = "face-up link-state list";
const TREE_READVERTISE: &str = "re-advertise to a tree child";
const INTEREST_ANSWER_DECLARATIONS: &str = "a current interest answered with the declarations";
const ROUTER_INTEREST_REFUSED: &str = "an interest from a router refused";
#[cfg(feature = "routing-token-tables")]
const TOKEN_TO_INTERESTED_CLIENT: &str = "a token pushed to a client that asked for tokens";
#[cfg(all(
    feature = "routing-token-tables",
    feature = "routing-interest-pending-gc"
))]
const TOKEN_INTEREST_BROKERED: &str = "a client's token interest brokered to the peers";

/// Whether `step` is the node's own session putting or deleting.
fn is_a_node_put(step: &Step) -> bool {
    match step {
        Step::NodePut(..) => true,
        #[cfg(feature = "pubsub-delete")]
        Step::NodeDelete(..) => true,
        _ => false,
    }
}

const NODE_PUT_TO_CLIENT: &str = "the node's own Put reaches a client that subscribed";
const NODE_PUT_TO_OWN_SUBSCRIBER: &str = "the node's own Put reaches a subscriber it hosts";
const QABL_DECLARED_AGAIN: &str = "a queryable declared again with what it already was";
const GOSSIP_GRAPH: &str = "the graph a gossip peer keeps";
const LINK_DOWN_LIST: &str = "a link-state list sent when a link goes down";

/// The reasons each mode must still produce: one no scene reaches any more is
/// stale, and a stale allowance is a hole.
fn expected_reasons(mode: Mode) -> std::collections::BTreeSet<&'static str> {
    let mut reasons: std::collections::BTreeSet<&'static str> = [
        INTEREST_ANSWER_DECLARATIONS,
        ROUTER_INTEREST_REFUSED,
        NODE_PUT_TO_CLIENT,
        NODE_PUT_TO_OWN_SUBSCRIBER,
        QABL_DECLARED_AGAIN,
    ]
    .into_iter()
    .collect();
    #[cfg(feature = "routing-token-tables")]
    reasons.insert(TOKEN_TO_INTERESTED_CLIENT);
    #[cfg(all(
        feature = "routing-token-tables",
        feature = "routing-interest-pending-gc"
    ))]
    reasons.insert(TOKEN_INTEREST_BROKERED);
    if matches!(mode, Mode::Gossip) {
        reasons.insert(FACE_UP_LIST);
        reasons.insert(TREE_READVERTISE);
        reasons.insert(GOSSIP_GRAPH);
        reasons.insert(LINK_DOWN_LIST);
    }
    reasons
}

/// Why `d` is not a failure, or `None` when it is one.
fn explained(mode: Mode, d: &Divergence) -> Option<&'static str> {
    if let Some(reason) = explained_interest_or_token(d) {
        return Some(reason);
    }
    // The pin's broker hat routes a Put to every owned face that holds a
    // matching subscription, whatever region the Put came from
    // (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `if ctx.subs.is_some() {`),
    // and the node's own session is such a source. The region-hat peer therefore
    // reaches the clients that subscribed; `LinkstateForwarder::publish` reaches
    // its tree children and its gateways and none of its client faces. Every
    // face it does reach is reached with the same message.
    // A Put of the node's own session reaches the subscribers the same session
    // hosts unless it was sent to remote destinations only
    // (`zenoh/src/api/session.rs` @ `state.subscriber_callbacks(true, SubscriberKind::Subscriber, &wire_expr, false);`);
    // `LinkstateForwarder::publish` delivers to none of its own.
    if is_a_node_put(&d.step)
        && d.plane == "hosted"
        && d.linkstate.is_empty()
        && !d.region_hat.is_empty()
    {
        return Some(NODE_PUT_TO_OWN_SUBSCRIBER);
    }
    // A queryable declaration is propagated when what the other regions fold
    // out of it changed, and a second, incomplete queryable on a key whose
    // first is complete changes nothing
    // (`zenoh/src/net/routing/dispatcher/queries.rs` @ `tables.hats[dst].propagate_queryable(ctx.reborrow(), res.clone(), other_info);`).
    // `LinkstateForwarder` declares the key again, complete as before.
    if matches!(d.step, Step::NodeHostQueryable(..))
        && d.plane == "data"
        && d.region_hat.is_empty()
        && d.linkstate
            .values()
            .flatten()
            .all(|s| matches!(s, Seen::DeclareQueryable { .. }))
    {
        return Some(QABL_DECLARED_AGAIN);
    }
    if is_a_node_put(&d.step)
        && d.plane == "data"
        && d.region_hat.len() > d.linkstate.len()
        && d.linkstate
            .iter()
            .all(|(face, seen)| d.region_hat.get(face) == Some(seen))
    {
        return Some(NODE_PUT_TO_CLIENT);
    }
    if !matches!(mode, Mode::Gossip) {
        return None;
    }
    match (d.plane, &d.step) {
        // The pin's gossip net adds a node to its graph for what a neighbour
        // told it and not for a link coming up
        // (`zenoh/src/net/protocol/network.rs` @ `if self.full_linkstate || self.gossip_multihop {`
        // in `add_link`), and a gossip flood forms no edge. `LinkstateForwarder`
        // adds the node at once and, after a recompute, an edge. Nothing routes
        // by a gossip graph, so this is a count of what each plane keeps and not
        // a routing difference; the link-state extension keeps the same graph
        // in both planes, which the other mode's test holds.
        ("graph", _) => Some(GOSSIP_GRAPH),
        // The pin's gossip `remove_link` forgets the link and sends nothing:
        // the flood to the remaining links is inside the `full_linkstate ||
        // gossip_multihop` branch that follows
        // (`zenoh/src/net/protocol/network.rs` @ `self.graph[self.idx].links.retain(|dest, _| dest != zid);`).
        // `LinkstateForwarder` tells the faces that remain its own entry.
        ("topology", Step::Down(..))
            if d.region_hat.is_empty()
                && d.linkstate
                    .values()
                    .flatten()
                    .all(|s| matches!(s, Seen::LinkState { .. })) =>
        {
            Some(LINK_DOWN_LIST)
        }
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

/// A client's current-and-future token interest that `LinkstateForwarder` brokers to the peers
/// while the region-hat peer does not.
///
/// This peer's token table does not carry the mesh tier (see `dump_interest_tokens`), so with
/// `routing-interest-pending-gc` it asks its peers as well as its gateways, answers the client
/// with the tokens it holds and owes the client's final until the peers have answered. The
/// pin's peer hat holds the mesh tier and answers from its own table: it sends a current-and-future
/// interest on only to the faces whose remote bound is south
/// (`zenoh/src/net/routing/hat/peer/interests.rs` @ `.filter(|f| f.remote_bound.is_south())`),
/// which the peers of this node are not, and closes the interest with the final at once. So the
/// difference is exactly: a copy of the interest on another face, and the asker's answer the same
/// but for the final.
#[cfg(all(
    feature = "routing-token-tables",
    feature = "routing-interest-pending-gc"
))]
fn token_interest_brokered(
    d: &Divergence,
    face: u64,
    kinds: &InterestKinds,
) -> Option<&'static str> {
    let is_final = |s: &Seen| matches!(s, Seen::DeclareFinal { .. });
    let copied_to_another_face = d.linkstate.iter().any(|(other, seen)| {
        *other != face
            && !seen.is_empty()
            && seen.iter().all(|s| matches!(s, Seen::Interest { .. }))
    });
    let told_the_asker: Vec<&Seen> = d
        .linkstate
        .get(&face)
        .map(|seen| seen.iter().collect())
        .unwrap_or_default();
    let region_hat_told: Vec<&Seen> = d
        .region_hat
        .get(&face)
        .map(|seen| seen.iter().filter(|s| !is_final(s)).collect())
        .unwrap_or_default();
    let region_hat_closed = d
        .region_hat
        .get(&face)
        .is_some_and(|seen| seen.iter().any(is_final));
    (*kinds == InterestKinds::TOKENS
        && copied_to_another_face
        && region_hat_closed
        && d.region_hat.keys().all(|f| *f == face)
        && told_the_asker == region_hat_told)
        .then_some(TOKEN_INTEREST_BROKERED)
}

#[cfg(not(all(
    feature = "routing-token-tables",
    feature = "routing-interest-pending-gc"
)))]
fn token_interest_brokered(_: &Divergence, _: u64, _: &InterestKinds) -> Option<&'static str> {
    None
}

/// The differences in the interest and token planes, in either mode.
fn explained_interest_or_token(d: &Divergence) -> Option<&'static str> {
    if d.plane != "data" {
        return None;
    }
    match &d.step {
        Step::Interest(face, _, kinds, ..) => {
            let asked = d.linkstate.get(face).map(Vec::as_slice);
            let region_hat = d.region_hat.get(face).map(Vec::as_slice);
            let only_a_final =
                |seen: Option<&[Seen]>| matches!(seen, Some([Seen::DeclareFinal { .. }]));
            // The pin's dispatcher refuses an Interest from a router
            // (`zenoh/src/net/routing/dispatcher/interests.rs` @ `if self.state.whatami.is_router() {`),
            // so the region-hat peer says nothing to it; `LinkstateForwarder`
            // answers with a final.
            if only_a_final(asked) && region_hat.is_none() && d.region_hat.is_empty() {
                return Some(ROUTER_INTEREST_REFUSED);
            }
            // The pin's dispatcher answers a current Interest with the
            // declarations the OTHER hats hold, then a final
            // (`zenoh/src/net/routing/dispatcher/interests.rs` @ `hats[region].send_current_subscribers(`
            // and `@ hats[region].send_declare_final(ctx.reborrow(), msg.id, &src);`).
            // A current subscriber Interest from a peer in the north region is
            // itself outside the pin's protocol (its peer hat asserts that a
            // current Interest from the north asks for tokens only), so this is
            // the dispatcher's release behaviour, which the region-hat peer
            // follows; `LinkstateForwarder` sends the final alone.
            if only_a_final(asked)
                && matches!(
                    region_hat,
                    Some([.., Seen::DeclareFinal { .. }]) if region_hat.is_some_and(|r| r.len() > 1)
                )
            {
                return Some(INTEREST_ANSWER_DECLARATIONS);
            }
            token_interest_brokered(d, *face, kinds)
        }
        // The copy of a brokered interest is withdrawn from the peers when its asker ends it.
        #[cfg(all(
            feature = "routing-token-tables",
            feature = "routing-interest-pending-gc"
        ))]
        Step::InterestFinal(..) => (d.region_hat.is_empty()
            && !d.linkstate.is_empty()
            && d.linkstate
                .values()
                .flatten()
                .all(|s| matches!(s, Seen::InterestFinal)))
        .then_some(TOKEN_INTEREST_BROKERED),
        #[cfg(feature = "routing-token-tables")]
        Step::Token(..) | Step::Untoken(..) => {
            // A token declared or withdrawn at a peer reaches a client that asked
            // for tokens with a future interest: the pin's broker hat propagates
            // a token to a south face that holds a matching remote interest.
            // `LinkstateForwarder`'s token plane is partial and does not.
            let is_token = |s: &Seen| matches!(s, Seen::DeclareToken { .. } | Seen::UndeclareToken);
            let extra_to_a_face_linkstate_left_out = d
                .region_hat
                .iter()
                .any(|(face, seen)| seen.iter().any(is_token) && !d.linkstate.contains_key(face));
            let linkstate_subset = d.linkstate.iter().all(|(face, seen)| {
                d.region_hat
                    .get(face)
                    .is_some_and(|r| seen.iter().all(|s| r.contains(s)))
            });
            (extra_to_a_face_linkstate_left_out && linkstate_subset)
                .then_some(TOKEN_TO_INTERESTED_CLIENT)
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
        expected_reasons(Mode::Gossip),
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
    assert_the_node_publish_scene_exercises_what_it_claims(Mode::Gossip);
    assert_the_hosting_scene_exercises_what_it_claims(Mode::Gossip);
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

/// What the region-hat peer does with an Interest and a token, graded against
/// the pin and not against `LinkstateForwarder`, which the pin-explained
/// differences above leave out: an Interest from a router is refused (nothing is
/// sent to it, not even a final), a current Interest from a peer is answered with
/// the declarations the other hats hold and then its final, and a client that
/// asked for tokens with a future interest is sent a token a peer declares and
/// the withdrawal of it.
#[test]
fn the_region_hat_peer_answers_interests_and_tokens_as_the_pins_dispatcher_does() {
    for mode in [Mode::Gossip, Mode::LinkState] {
        let (_, mut node) = both(0x01, mode);
        let steps = [
            Step::Up(0, 0xAA, Wire::Peer),
            Step::Up(1, 0xCC, Wire::Client),
            Step::Up(2, 0xEE, Wire::Router),
            Step::LinkBack(0, 0xAA, 5),
            Step::LinkBack(2, 0xEE, 5),
            Step::Tick,
            Step::Subscribe(1, "demo/s"),
        ];
        for step in &steps {
            node.apply(step);
        }
        let router_asks = node.apply(&Step::Interest(
            2,
            4,
            InterestKinds::QUERYABLES,
            true,
            false,
            "demo/**",
        ));
        assert!(
            !router_asks.contains_key(&2),
            "{mode:?}: an Interest from a router is refused, not answered: {router_asks:?}"
        );
        let peer_asks = node.apply(&Step::Interest(
            0,
            3,
            InterestKinds::SUBSCRIBERS,
            true,
            false,
            "demo/**",
        ));
        assert_eq!(
            peer_asks.get(&0).map(Vec::as_slice),
            // What a step sent is sorted, which puts a declaration before a final.
            Some(
                [
                    Seen::DeclareSubscriber {
                        keyexpr: "demo/s".to_owned(),
                        answer_to: Some(3)
                    },
                    Seen::DeclareFinal { answer_to: Some(3) },
                ]
                .as_slice()
            ),
            "{mode:?}: a current Interest from a peer is answered with the declarations \
             of the other hats and then its final"
        );
        #[cfg(feature = "routing-token-tables")]
        {
            node.apply(&Step::Up(3, 0xC2, Wire::Client));
            node.apply(&Step::Interest(
                3,
                5,
                InterestKinds::TOKENS,
                true,
                true,
                "live/**",
            ));
            let declared = node.apply(&Step::Token(0, "live/b"));
            assert_eq!(
                declared.get(&3).map(Vec::as_slice),
                Some(
                    [Seen::DeclareToken {
                        keyexpr: "live/b".to_owned(),
                        answer_to: None
                    }]
                    .as_slice()
                ),
                "{mode:?}: a token a peer declares reaches a client that asked for tokens"
            );
            let withdrawn = node.apply(&Step::Untoken(0, "live/b"));
            assert_eq!(
                withdrawn.get(&3).map(Vec::as_slice),
                Some([Seen::UndeclareToken].as_slice()),
                "{mode:?}: and so does its withdrawal"
            );
        }
    }
}

/// In wz's link-state extension the two planes send the same data AND the same
/// topology: the region-hat peer relays inside its region along the tree, as
/// `LinkstateForwarder` does. The only differences are the interest and token
/// planes' ones, which the extension does not touch.
#[test]
fn in_link_state_mode_the_two_peer_planes_send_the_same_data_and_topology() {
    let (failures, reasons) = unexplained(Mode::LinkState);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        reasons,
        expected_reasons(Mode::LinkState),
        "each allowed difference must be one a scene produces"
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
    assert_the_node_publish_scene_exercises_what_it_claims(Mode::LinkState);
    assert_the_hosting_scene_exercises_what_it_claims(Mode::LinkState);
}
