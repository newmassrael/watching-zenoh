// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.21 `routing-interest-pending-gc` on the region-hat forwarder: the interest a peer node
//! BROKERS for its client, to its gateways.
//!
//! zenoh's peer hat does not answer a client's interest from its own tables and close it: it
//! PROPAGATES the interest to the faces whose remote bound is south, the gateways, and holds
//! the client's `DeclareFinal` until the last of them has answered
//! (`zenoh/src/net/routing/hat/peer/interests.rs` @ `fn route_interest`). A gateway keeps its
//! other remotes' declarations to itself and tells a peer only what it is asked, so a peer that
//! answered a pico publisher's write-filter interest from its own tables alone would finalize an
//! empty filter, and the publisher would never send to a subscriber behind the gateway.
//!
//! The pieces, each the pin's:
//!
//! - WHERE: a `CurrentFuture` interest goes to every gateway, a `Current` one to at most one,
//!   so that a stateless answer is not duplicated
//!   (`zenoh/src/net/routing/hat/peer/interests.rs` @ `let dsts = if msg.mode == InterestMode::Current {`).
//!   The pin's third destination, a peer whose initial interest is not finalized, has no wz
//!   counterpart: wz peers flood declarations rather than exchange an initial interest.
//! - THE TABLE: one pending entry for each propagated copy, kept in
//!   [`PendingCurrentInterests`](crate::interest_broker::PendingCurrentInterests), whose
//!   reference count is the pin's `Arc<CurrentInterest>` made explicit. The client's final is
//!   sent when the last copy has been answered, has died with its face, or has timed out.
//! - THE TIMEOUT: `routing.interests.timeout`, 10 s by default. zenoh-pico's CURRENT interest
//!   carries no timeout of its own (`vendor/zenoh-pico/src/net/liveliness.c:348`), so without the
//!   sweep a foreign client waits for ever on a gateway that has gone silent.
//! - THE END: a client's `Interest(Final)`, or its departure, is passed on to every gateway
//!   still holding a `CurrentFuture` copy, under the id that gateway was given.
//!
//! NOT PORTED: the single-net peer forwarder also withheld data for a key from a gateway that
//! had FINALIZED its interest on exactly that key and declared nothing matching (R2904; the pin's
//! `subscriber_interest_finalized`, `zenoh/src/net/routing/hat/peer/pubsub.rs`). That rule
//! belongs to the data route toward a gateway, and this forwarder's is the hats' own; it is an
//! open residual of the atom, not a decision.
//!
//! It acts for a node of mode Peer and for a client face only: the pin's other hats propagate by
//! their own rules, which wz's router hats carry separately.

use super::*;
use crate::interest_broker::{CurrentInterest, PendingCurrentInterests};
use wz_codecs::interest_body::InterestBodyOwned;
use wz_session_core::interest_build::{
    build_interest_final_propagated, build_interest_propagated, InterestKinds,
};

/// The default interest deadline, zenoh's `routing.interests.timeout`.
const DEFAULT_INTEREST_TIMEOUT: Duration = Duration::from_millis(10_000);

/// R2903 — one brokered CurrentFuture copy a gateway holds as live: where it went and under
/// which id, which is what the client's Final is passed on under.
#[derive(Clone, Debug)]
pub(super) struct BrokeredCopy {
    upstream: FaceId,
    up_id: u64,
}

/// What the broker keeps: the pending table, its deadline and the live CurrentFuture copies.
/// State of the node and not of any one region, so it is the forwarder's and not the tables'.
pub(super) struct InterestBroker {
    pending: PlainMutex<PendingCurrentInterests>,
    timeout: PlainCell<Duration>,
    future: PlainMutex<HashMap<(FaceId, u64), Vec<BrokeredCopy>>>,
}

impl InterestBroker {
    pub(super) fn new() -> Self {
        Self {
            pending: PlainMutex::new(PendingCurrentInterests::new()),
            timeout: PlainCell::new(DEFAULT_INTEREST_TIMEOUT),
            future: PlainMutex::new(HashMap::new()),
        }
    }
}

/// The declaration kinds an inbound `Interest` asks for, as the [`InterestKinds`] union the
/// broker re-emits upstream, or `None` when it names none of them (a KEYEXPRS-only interest has
/// nothing a gateway could answer, and [`InterestKinds`] cannot represent the empty set on
/// purpose).
fn interest_kinds_of(body: &InterestBodyOwned) -> Option<InterestKinds> {
    [
        (body.su(), InterestKinds::SUBSCRIBERS),
        (body.qu(), InterestKinds::QUERYABLES),
        (body.to(), InterestKinds::TOKENS),
    ]
    .into_iter()
    .filter(|(asked, _)| *asked)
    .map(|(_, kind)| kind)
    .reduce(|acc, kind| acc | kind)
}

/// R2903 — a gateway's relayed TOKEN answer, re-expressed for the CLIENT's link.
///
/// A keyexpr on the wire is only meaningful on the link it was sent on: an answer to an interest
/// that asked for KEYEXPRS names its resource by an id the gateway declared on THAT link
/// (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub fn decl_key(`, which declares one
/// whenever the face's interests asked for keyexprs), and the same id means nothing, or
/// something else, on the link to the client. So the token is resolved against the gateway
/// face's alias table and rebuilt as a literal reply under the client's own interest id.
///
/// Subscriber and queryable answers never reach this: they are ingested rather than relayed.
///
/// `None` is a token whose keyexpr cannot be resolved; it is dropped rather than forwarded with
/// a scope the client would resolve wrongly. A body with no keyexpr of its own is relayed as it
/// came, under the client's id.
fn relay_answer_for_client(
    declare: &DeclareOwned,
    upstream_aliases: &hashbrown::HashMap<u64, String>,
    client_interest_id: u64,
) -> Option<DeclareOwned> {
    let rebuilt = match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclToken(t) => {
            wz_session_core::declare_build::build_declare_token_reply_with_id(
                client_interest_id,
                t.id,
                &resolve_wireexpr(&t.keyexpr.body, upstream_aliases)?,
            )
        }
        _ => {
            let mut relayed = declare.clone();
            relayed.interest_id = Some(client_interest_id);
            return Some(relayed);
        }
    };
    rebuilt.ok()
}

impl RouterForwarder {
    /// zenoh's `routing.interests.timeout`: how long an interest this node brokered waits for its
    /// gateway's `DeclareFinal` before the sweep abandons it and finalizes the client anyway.
    /// Takes effect for interests brokered after the call.
    pub fn set_interest_timeout(&self, timeout: Duration) {
        self.broker.timeout.set(timeout);
    }

    /// How many brokered copies are outstanding: the pending-table witness.
    pub fn pending_interests_len(&self) -> usize {
        self.broker.pending.guard().len()
    }

    /// How many brokered copies the timeout sweep has abandoned: the GC witness.
    pub fn pending_interests_timed_out(&self) -> usize {
        self.broker.pending.guard().timed_out()
    }
}

impl<T: std::ops::Deref<Target = Tables>> OnTables<'_, T> {
    /// The faces that are this node's gateways: the faces whose remote end is a gateway to it,
    /// which a stock router is to a peer (`zenoh/src/net/routing/hat/peer/pubsub.rs` @
    /// `.filter(|f| f.remote_bound.is_south())`). A face with no graph link, a client leaf or a
    /// face whose handshake carried no zid, is never one.
    fn gateway_faces(&self) -> Vec<FaceId> {
        let net = self.north_net();
        let mut faces: Vec<FaceId> = self
            .tables
            .faces
            .iter()
            .filter(|(_, state)| {
                state
                    .link
                    .and_then(|link| net.get_link(link))
                    .is_some_and(|link| link.remote_is_gateway)
            })
            .map(|(id, _)| *id)
            .collect();
        faces.sort_unstable();
        faces
    }

    /// R2903 — WHERE a client's interest is brokered: every gateway for a `CurrentFuture`
    /// interest, one for a `Current` one (`let dsts = if msg.mode == InterestMode::Current {`),
    /// never the face it came from.
    fn interest_upstreams(&self, inbound: FaceId, future: bool) -> Vec<FaceId> {
        let mut gateways = self.gateway_faces();
        gateways.retain(|g| *g != inbound);
        if !future {
            gateways.truncate(1);
        }
        gateways
    }

    /// PROPAGATE a client's interest to `upstreams`, recording one pending entry per copy.
    /// Returns how many copies were sent; `0` means there was no gateway and the caller still
    /// owes the client its `DeclareFinal` inline (the pin's `Arc::into_inner` succeeding at
    /// once when the loop placed no copy).
    ///
    /// The propagated copy is a fresh `Interest` with an id THIS node minted, not the client's:
    /// two clients may legally choose the same id, and the gateway answers against the id it
    /// was given. The id rewrite back to the client's own is [`Self::relay_brokered_declare`]'s
    /// job. The client's options are forwarded as the pin forwards `options: msg.options`: its
    /// kind set, and its AGGREGATE bit, by which the client matches the answer it gets back.
    /// An unrestricted interest (`target == None`) is propagated unrestricted, because upstream's
    /// matcher admits the whole table for an absent resource
    /// (`zenoh/src/net/routing/hat/peer/token.rs` @ `res.is_none_or`).
    pub(super) fn propagate_current_interest(
        &self,
        inbound: FaceId,
        src_interest_id: u64,
        options: &InterestBodyOwned,
        current_future: bool,
        target: Option<&str>,
        upstreams: Vec<FaceId>,
    ) -> usize {
        let Some(kinds) = interest_kinds_of(options) else {
            return 0;
        };
        if upstreams.is_empty() {
            return 0;
        }
        let deadline = self.now() + self.broker.timeout.get();
        let mut sent = 0usize;
        for up in upstreams {
            let up_id = self.broker.pending.guard().allocate_id();
            // CurrentFuture is propagated as CurrentFuture, Current as Current: the pin's
            // propagated mode only ever WIDENS Future to CurrentFuture, and every hat
            // propagation site stamps `ext_qos` in both modes, so the router-plane builder is
            // the one that does (`scripts/lib/router_interest_qos_gate.py`).
            let Ok(msg) = build_interest_propagated(
                up_id,
                kinds,
                options.ag(),
                current_future,
                target.map(|t| (0, Some(t))),
            ) else {
                continue; // a keyexpr this node cannot re-encode is not brokered
            };
            // SEND FIRST, and record the pending entry only for a copy that actually left: a
            // copy that never reached the wire must not create a pending entry, or the client's
            // final would be withheld for a whole window on account of a gateway never asked.
            let mut carrier = Some(NetworkMessage::Interest(msg));
            if !self.send_to_face(up, true, || carrier.take().expect("built once")) {
                continue;
            }
            self.broker.pending.guard().insert(
                up,
                up_id,
                CurrentInterest {
                    src_face: inbound,
                    src_interest_id,
                    current_future,
                },
                deadline,
            );
            // A CurrentFuture copy stays live upstream after its current answer: remember it so
            // the client's Final can be passed on.
            if current_future {
                self.broker
                    .future
                    .guard()
                    .entry((inbound, src_interest_id))
                    .or_default()
                    .push(BrokeredCopy {
                        upstream: up,
                        up_id,
                    });
            }
            sent += 1;
        }
        sent
    }

    /// Brokering as `respond_to_interest` reaches it: the upstreams for a CURRENT interest from a
    /// client of a peer node, and the copies sent. `0` when this is not that case.
    pub(super) fn broker_current_interest(
        &self,
        inbound: FaceId,
        src_interest_id: u64,
        options: &InterestBodyOwned,
        future: bool,
        target: Option<&str>,
    ) -> usize {
        if self.tables.node_mode != WhatAmI::Peer || !self.is_client_face(inbound) {
            return 0;
        }
        let upstreams = self.interest_upstreams(inbound, future);
        self.propagate_current_interest(
            inbound,
            src_interest_id,
            options,
            future,
            target,
            upstreams,
        )
    }

    /// R2903 — pass a client's end-of-interest on to every gateway still holding a brokered copy
    /// of it: the client sent `Interest(Final)` for `client_id`, or (`client_id == None`) the
    /// client left and every interest of its goes. The pin's `route_interest_final` sends the
    /// Final under the id the gateway was given (`zenoh/src/net/routing/hat/peer/interests.rs` @
    /// `mode: InterestMode::Final,`), which is the minted one, not the client's.
    pub(super) fn finalize_brokered_future(&self, client: FaceId, client_id: Option<u64>) {
        let copies: Vec<BrokeredCopy> = {
            let mut table = self.broker.future.guard();
            let keys: Vec<(FaceId, u64)> = table
                .keys()
                .filter(|(face, id)| *face == client && client_id.map_or(true, |c| c == *id))
                .copied()
                .collect();
            keys.into_iter()
                .filter_map(|k| table.remove(&k))
                .flatten()
                .collect()
        };
        for copy in copies {
            self.send_one_to_face(
                copy.upstream,
                NetworkMessage::Interest(build_interest_final_propagated(copy.up_id)),
            );
        }
    }

    /// An inbound `Declare` on a gateway face carrying an interest id THIS node minted: relay it
    /// DOWN to the client that is waiting, rewriting the id to the client's own
    /// (`zenoh/src/net/routing/hat/peer/token.rs` @ `interest_id`). `true` when the declare was
    /// consumed, so the caller does not ALSO run it through the ordinary ingest: a solicited reply
    /// is addressed to one client, not a topology change to re-flood.
    fn relay_brokered_declare(&self, upstream: FaceId, declare: &DeclareOwned) -> bool {
        let Some(up_id) = declare.interest_id else {
            return false;
        };
        let Some(interest) = self.broker.pending.guard().lookup(upstream, up_id).cloned() else {
            return false;
        };
        // Rebuilt for the client's link, not cloned (see `relay_answer_for_client`). Consumed
        // either way, since an answer addressed to a client is never a topology change.
        let relayed = self.tables.faces.get(&upstream).and_then(|state| {
            relay_answer_for_client(declare, &state.keyexpr_table, interest.src_interest_id)
        });
        if let Some(relayed) = relayed {
            self.send_one_to_face(
                interest.src_face,
                NetworkMessage::Declare(Box::new(relayed)),
            );
        }
        true
    }

    /// The UNWIND: a gateway answered (or died, or timed out), so its pending entry is dropped
    /// and, when it was the last one for that client, the client is sent the single
    /// `DeclareFinal` it has been waiting for (`dispatcher/interests.rs`
    /// `finalize_pending_interest`).
    fn finish_brokered_interest(&self, interest: &CurrentInterest) {
        self.send_one_to_face(
            interest.src_face,
            NetworkMessage::Declare(Box::new(build_declare_final_reply(
                interest.src_interest_id,
            ))),
        );
    }

    /// THE GC, driven from the tick: abandon every brokered interest past its deadline and
    /// finalize the clients that are now fully unwound. A cheap empty sweep when nothing is
    /// pending.
    pub(super) fn reap_timed_out_interests(&self) {
        let reaped = self.broker.pending.guard().expired(self.now());
        for interest in &reaped {
            self.finish_brokered_interest(interest);
        }
    }

    /// The single INGRESS gate for a solicited answer on a gateway face. `true` means the broker
    /// consumed the `Declare` and the ordinary ingest must not also see it.
    ///
    /// Two shapes, in the order zenoh takes them:
    /// - a `DeclFinal` stamped with a propagated id: the gateway is DONE. The entry is retired,
    ///   and when it was this client's last gateway the client is sent its own final.
    /// - a `DeclToken` stamped with a propagated id: relayed down with the client's id.
    ///
    /// R2903 — a `DeclSubscriber` / `DeclQueryable` answer is NOT consumed. It falls through to
    /// the ordinary ingest, which registers it as the gateway's declaration and pushes it to
    /// every client whose stored future interest matches, in that client's own reply shape. That
    /// is the pin's shape: the answer lands in the node's tables, the client-facing side answers
    /// the client from them, and only the final is brokered.
    ///
    /// An id this node never minted falls through to `false`: an unsolicited declaration on a
    /// mesh face is an ordinary topology change, and a stale final for an entry the GC already
    /// abandoned must not disturb anything.
    pub(super) fn absorb_brokered_declare(&self, upstream: FaceId, declare: &DeclareOwned) -> bool {
        if self.is_client_face(upstream) {
            return false;
        }
        let Some(up_id) = declare.interest_id else {
            return false;
        };
        if matches!(declare.body, DeclareOwnedVariant::CodecZenohDeclFinal(_)) {
            if self
                .broker
                .pending
                .guard()
                .lookup(upstream, up_id)
                .is_none()
            {
                return false;
            }
            let finished = self.broker.pending.guard().resolve(upstream, up_id);
            if let Some(interest) = finished {
                self.finish_brokered_interest(&interest);
            }
            return true;
        }
        if matches!(
            declare.body,
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
                | DeclareOwnedVariant::CodecZenohDeclQueryable(_)
        ) {
            return false;
        }
        self.relay_brokered_declare(upstream, declare)
    }

    /// The interest twin of the pending-query drain at a face's departure (zenoh's
    /// `finalize_pending_interests` on face close): a gateway that dies before answering
    /// finalizes every client whose LAST outstanding copy it held, so the client terminates now
    /// instead of waiting out the whole window for a node that is already gone; entries where the
    /// DEPARTED face is the client are dropped silently, there being nobody to send a final to.
    /// The FUTURE half: a departing client's live copies are finalized at their gateways (the pin
    /// undeclares a closed face's interests the same way), and a departing gateway simply stops
    /// holding any.
    pub(super) fn drain_brokered_interests(&self, departed: FaceId) {
        let orphaned = self.broker.pending.guard().drain_face(departed);
        for interest in &orphaned {
            self.finish_brokered_interest(interest);
        }
        self.finalize_brokered_future(departed, None);
        self.broker.future.guard().retain(|_, copies| {
            copies.retain(|c| c.upstream != departed);
            !copies.is_empty()
        });
    }
}
