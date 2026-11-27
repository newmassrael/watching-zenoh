// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311md — the shared multicast observer-drain reply sink SSOT.
//!
//! The decision "given a [`ResponseSink`](crate::response_sink::ResponseSink) /
//! [`DeclareReplySink`](crate::response_sink::DeclareReplySink) call, which
//! [`MulticastTxItem`] does it become" lives here ONCE, generic over the enqueue
//! backing `Q` — the TX-staging twin of the
//! [`multicast_rx`](crate::multicast_rx) (RX dispatch) and
//! [`multicast_tx`](crate::multicast_tx) (TX emit) SSOTs. Both multicast drive
//! loops drain their observer's staged replies through the same
//! [`MulticastReplySink<Q>`]; the only per-profile difference is `Q` — the AP
//! loop backs it with a `tokio::sync::mpsc` sender, the MCU loop with an
//! `Rc<RefCell<VecDeque>>` (single-task).
//!
//! Before R311md this construction was duplicated byte-for-byte (except the
//! enqueue line) in the AP `MulticastReplySink` and the MCU
//! `MulticastReplyQueue`, and the duplication forced wz-session-lwip to dep
//! wz-codecs just to name `ResponseOwned` in its copy of `send_response`.
//! Folding the impls here removes both: the two profiles now contribute only a
//! [`MulticastReplyEnqueue`] backing.

#[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
use crate::multicast_tx::DeclarationReply;
use crate::multicast_tx::MulticastTxItem;
#[cfg(any(
    feature = "codec-response",
    feature = "liveliness-token",
    feature = "declare-subscriber"
))]
use crate::multicast_tx::MulticastTxReply;

/// The backing one staged multicast reply is enqueued onto for the drive loop to
/// frame + multicast — the only per-profile difference between the AP loop (a
/// `tokio::sync::mpsc` sender) and the MCU loop (an `Rc<RefCell<VecDeque>>`).
/// Implementors enqueue fire-and-forget: the AP drops the item if the receiver
/// is gone (the loop ended, exactly as a dead link would), the MCU `push_back`
/// never fails. `enqueue` takes the already-constructed [`MulticastTxItem`], so
/// a backing names no codec type — that is the whole point (it keeps the MCU
/// backing crate free of a wz-codecs dependency).
pub trait MulticastReplyEnqueue {
    /// Enqueue one outbound reply item for the loop to frame + multicast.
    fn enqueue(&self, item: MulticastTxItem);

    /// Enqueue one reply lent for the call. A backing that queues owned items takes a copy (the
    /// default); one that encodes its replies where they wait writes this one from where it lies,
    /// and nothing of it is kept on the heap.
    #[cfg(any(
        feature = "codec-response",
        feature = "liveliness-token",
        feature = "declare-subscriber"
    ))]
    fn enqueue_reply(&self, reply: MulticastTxReply<'_>) {
        self.enqueue(reply.to_item());
    }

    /// Enqueue one staged reply, described by the parts its stage lends. A backing that queues
    /// owned items builds the owned record from them (the default), and skips a reply the wire
    /// cannot carry; one that encodes its replies where they wait writes it with the stage's lent
    /// writer ([`crate::lent_response::ResponseWriter`]), and builds no owned record of it.
    #[cfg(feature = "codec-response")]
    fn enqueue_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>) {
        if let Ok(response) = crate::query::QueryReply::from_parts(&parts).into_response() {
            self.enqueue_reply(MulticastTxReply::Response(&response));
        }
    }

    /// Enqueue the answer to a member's interest in liveliness tokens for the held token
    /// `token_id` on `keyexpr`. A backing that queues owned items builds the owned `Declare` of it
    /// (the default); one that encodes its replies where they wait writes the borrowed reply from
    /// where it lies (`multicast_tx::multicast_tx_token_reply`), and builds no owned record of it.
    /// A keyexpr past the protocol's bound is not answered either way: the chain's `DeclFinal`
    /// still terminates the interest.
    #[cfg(feature = "liveliness-token")]
    fn enqueue_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        if let Ok(declare) =
            crate::declare::local_token::build_token_reply(token_id, keyexpr, interest_id).and_then(
                |reply| reply.try_into_owned_in::<crate::transport_profile::TransportStorage>(),
            )
        {
            self.enqueue_reply(MulticastTxReply::DeclareReply(&declare));
        }
    }

    /// Enqueue `reply`, a declaration that answers a member's interest, handed as the arguments
    /// of its writer. A backing that queues owned items builds the owned `Declare` of it (the
    /// default), and skips one the wire cannot carry; one that encodes its replies where they wait
    /// writes it with the writer of its kind (`multicast_tx::multicast_tx_declaration_reply`), and
    /// builds no owned record of it.
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn enqueue_declaration_reply(&self, reply: DeclarationReply<'_>) {
        if let Some(declare) = reply.owned() {
            self.enqueue_reply(MulticastTxReply::DeclareReply(&declare));
        }
    }

    /// Enqueue the final of the replies to `request_id`, with its query's `qos`. A backing that
    /// queues owned items queues the owned item (the default); one that encodes its replies where
    /// they wait writes it from its two numbers (`multicast_tx::multicast_tx_response_final`).
    #[cfg(feature = "codec-response-final")]
    fn enqueue_response_final(
        &self,
        request_id: crate::wire_id::RequestId,
        qos: crate::sample::QosLevel,
    ) {
        self.enqueue(MulticastTxItem::ResponseFinal { request_id, qos });
    }
}

/// The shared observer-drain reply sink: the SSOT for the staged-reply ->
/// [`MulticastTxItem`] construction, generic over the enqueue backing `Q`. An
/// application's observer drains its staged replies through this —
/// `flush_query_replies` (the queryable `Response` + `ResponseFinal` chain, via
/// [`ResponseSink`](crate::response_sink::ResponseSink)) and
/// `flush_declare_replies` (the liveliness `Declare` reply, via
/// [`DeclareReplySink`](crate::response_sink::DeclareReplySink)) — and `Q`
/// decides only HOW each constructed item is queued for the loop.
///
/// Per the R311lq interface segregation it implements exactly those two
/// observer-drain concerns, NOT `LivelinessGetPrune` (the connectionless
/// multicast transport — JOIN + lease, never a re-dial — has no reconnect
/// declaration cache to prune). `Clone` when `Q: Clone`, so the `on_event`
/// closure can hold a sink clone while the loop owns the backing's other end.
pub struct MulticastReplySink<Q> {
    queue: Q,
}

impl<Q: Clone> Clone for MulticastReplySink<Q> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
        }
    }
}

impl<Q> MulticastReplySink<Q> {
    /// Wrap an enqueue backing as a reply sink.
    pub fn new(queue: Q) -> Self {
        Self { queue }
    }
}

// The queryable-reply drain (R311lq): the observer hands the sink each staged reply as
// its parts and the terminal rid; the sink hands the reply to the backing
// (`MulticastReplyEnqueue::enqueue_reply_parts`) and wraps the rid in its
// `MulticastTxItem`. Every method is gated by its own codec, so a build with neither
// reply codec has a sink with nothing to send: a host that drains a group's whole
// observer through one sink (`SlotObserver::flush_pending`) names it in every build.
impl<Q: MulticastReplyEnqueue> crate::response_sink::ResponseSink for MulticastReplySink<Q> {
    // A staged reply goes to the backing as its parts, so that a backing that writes its replies
    // where they wait builds no owned record of it.
    #[cfg(feature = "codec-response")]
    fn send_reply_parts(&self, parts: crate::reply_stage::ReplyParts<'_>) {
        self.queue.enqueue_reply_parts(parts);
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(
        &self,
        request_id: crate::wire_id::RequestId,
        qos: crate::sample::QosLevel,
    ) {
        self.queue.enqueue_response_final(request_id, qos);
    }
}

// A reply a handler built as the owned record on the tokio engine's own path is sent as it is,
// the one place a `wz_codecs` owned type is named for a group: here in wz-session-core, not in
// the backing crates.
#[cfg(feature = "codec-response")]
impl<Q: MulticastReplyEnqueue> crate::response_sink::OwnedResponseSink for MulticastReplySink<Q> {
    fn send_response(&self, response: crate::wire::ResponseOwned) {
        self.queue
            .enqueue_reply(MulticastTxReply::Response(&response));
    }
}

// The declarer-side liveliness interest-response drain (R311lr): the observer
// hands the sink the borrowed (token_id, keyexpr, interest_id); the sink owns
// the encode by building the owned `Declare` via the shared `build_*_reply`
// SSOT (the same wire shape the unicast `SessionLinkActions: DeclareReplySink`
// derives) and enqueues it. A separate impl block from `ResponseSink` per the
// R311lq segregation — a declare reply is a distinct message family from a query
// `Response`.
// R311y530 — the impl block's gate widened with the trait's: `DeclareReplySink`
// now also carries the session-local SUBSCRIBER interest-response, so a build
// with `declare-subscriber` and no `liveliness-token` must still find this impl
// (the multicast reply loop is a `DeclareReplySink` consumer either way).
#[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
impl<Q: MulticastReplyEnqueue> crate::response_sink::DeclareReplySink for MulticastReplySink<Q> {
    // The backing writes the reply as it keeps its replies, owned or encoded where they wait.
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        self.queue
            .enqueue_token_reply(token_id, keyexpr, interest_id);
    }
    // Each answer goes to the backing as the arguments of its writer, so that a backing that writes
    // its replies where they wait builds no owned record of it.
    fn send_declare_final_reply(&self, interest_id: u64) {
        self.queue
            .enqueue_declaration_reply(DeclarationReply::Final { interest_id });
    }
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        self.queue
            .enqueue_declaration_reply(DeclarationReply::Subscriber {
                interest_id,
                subscriber_id,
                keyexpr,
            });
    }
    /// Open-debt item 913 — a member's interest in queryables is answered on the group with each
    /// matching queryable, as zenoh-pico answers one on a multicast transport
    /// (`vendor/zenoh-pico/src/session/interest.c` @
    /// `ret = _z_interest_send_decl_queryable(zn, id, NULL, restr_key_opt);`): a member's
    /// querier's write filter opens on it. Upstream's `z_test_peer_multicast.c` at
    /// `Z_FEATURE_MULTICAST_DECLARATIONS=1` found it missing: the session that opened last never
    /// queried, the others having declared their queryables before it was there to hear them.
    #[cfg(feature = "declare-queryable")]
    fn send_declare_queryable_reply(
        &self,
        queryable_id: u64,
        keyexpr: &str,
        complete: bool,
        interest_id: u64,
    ) {
        self.queue
            .enqueue_declaration_reply(DeclarationReply::Queryable {
                interest_id,
                queryable_id,
                keyexpr,
                complete,
            });
    }
    // The id-only retraction the unicast sink sends, through this transport's own enqueue.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        self.queue
            .enqueue_declaration_reply(DeclarationReply::UndeclareSubscriber { subscriber_id });
    }
}

// A group keeps no cache of the interests a session asks again after it reconnects: a group has
// no reconnect (a member that joins again is a new member), so a liveliness get that ended has
// nothing to prune here, which is the trait's own body where no cache exists. With it a host that
// drains its observer through one sink, the shape `SlotObserver::flush_pending` takes, drains a
// group's through this one.
impl<Q> crate::response_sink::LivelinessGetPrune for MulticastReplySink<Q> {
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, interest_id: u64) {
        let _ = interest_id;
    }
}

/// Whether `event` carries a member's interest that asks for declarations held now: an
/// `Interest` with the CURRENT bit, whose answer is the declarations held at this moment and a
/// final. zenoh-pico answers one on a multicast transport whatever its declarations switch, a
/// JOIN first (`vendor/zenoh-pico/src/session/interest.c` @
/// `// Push a join in case it's a new node`), which is what lets a member that has not admitted
/// this session yet admit it before the answer arrives: every engine that joins groups asks its
/// group for that JOIN on this.
#[cfg(feature = "storage-profile")]
pub fn asks_for_declarations(event: &crate::driver_loop::IterationEvent<'_, '_>) -> bool {
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::network_message::NetworkMessage;
    match event {
        IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
            crate::driver_loop::owned_records(messages).is_some_and(|messages| {
                messages.iter().any(
                    |message| matches!(message, NetworkMessage::Interest(interest) if interest.c()),
                )
            })
        }
        // An interest lent where its frame lies, by a build that lends its group's records.
        IterationEvent::InPlace(record) => record.interest().is_some_and(|interest| interest.c()),
        _ => false,
    }
}

/// Open-debt item 913 — the keyexprs a group session declared to its group, and the members'
/// interests in them it still owes an answer: what every engine that joins groups answers a
/// member with. zenoh-pico answers a CURRENT interest that asks for keyexprs with a declaration
/// of each key it holds that meets the interest's, ahead of its other declarations and the final
/// (`vendor/zenoh-pico/src/session/interest.c` @
/// `ret = _z_interest_send_decl_resource(zn, id, NULL, restr_key_opt);`). An engine notes the
/// interests of each event its group delivers ([`Self::asked`]) and sends the answers after the
/// JOIN the interest asked for ([`Self::take_answers`]); the lock around it is the engine's.
#[cfg(all(
    feature = "codec-declare",
    feature = "declare-final",
    feature = "storage-profile",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
#[derive(Debug, Default)]
pub struct GroupKeyexprAnswers {
    /// One entry an id, ordered by it, so the answers go out in the order of the ids. A list and
    /// not a tree: a session declares a handful of keyexprs to its group, and a tree would carry
    /// insertion and rebalancing code of its own for this one map.
    declared: alloc::vec::Vec<(crate::wire_id::ExprId, alloc::string::String)>,
    owed: alloc::vec::Vec<OwedKeyexprs>,
}

/// One interest's claim on a group session's keyexprs.
#[cfg(all(
    feature = "codec-declare",
    feature = "declare-final",
    feature = "storage-profile",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
#[derive(Debug)]
struct OwedKeyexprs {
    interest_id: u64,
    /// The key the interest names, `None` for every key. A key the member named by a declaration
    /// of its own arrives here as the literal it declared, the group's dispatch having resolved
    /// it per member (`MulticastDispatcher::apply_declared_aliases`).
    restriction: Option<alloc::string::String>,
    /// Whether this answer ends the interest: it asks for no other kind, so nothing else stages
    /// its final.
    ends: bool,
}

#[cfg(all(
    feature = "codec-declare",
    feature = "declare-final",
    feature = "storage-profile",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
impl GroupKeyexprAnswers {
    /// The session declared `keyexpr` to the group as `mapping_id`.
    /// An id declared again names the keyexpr it is declared with now.
    pub fn declared(&mut self, mapping_id: crate::wire_id::ExprId, keyexpr: &str) {
        match self.place_of(mapping_id) {
            Ok(at) => {
                if let Some((_, held)) = self.declared.get_mut(at) {
                    *held = keyexpr.into();
                }
            }
            Err(at) => self.declared.insert(at, (mapping_id, keyexpr.into())),
        }
    }

    /// The session retracted declaration `mapping_id`.
    pub fn retracted(&mut self, mapping_id: crate::wire_id::ExprId) {
        if let Ok(at) = self.place_of(mapping_id) {
            self.declared.remove(at);
        }
    }

    /// Where `mapping_id` is held, or where it goes to keep the ids in order.
    fn place_of(&self, mapping_id: crate::wire_id::ExprId) -> Result<usize, usize> {
        self.declared
            .binary_search_by_key(&mapping_id, |(id, _)| *id)
    }

    /// Note each interest in `event` that asks for keyexprs now, owned in a batch or lent where its
    /// frame lies; whether any answer is owed after it.
    pub fn asked(&mut self, event: &crate::driver_loop::IterationEvent<'_, '_>) -> bool {
        use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
        use crate::network_message::NetworkMessage;
        match event {
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                for message in crate::driver_loop::owned_records(messages).unwrap_or_default() {
                    if let NetworkMessage::Interest(interest) = message {
                        self.asked_owned(interest);
                    }
                }
            }
            IterationEvent::InPlace(record) => {
                if let Some(interest) = record.interest() {
                    self.asked_lent(interest);
                }
            }
            _ => {}
        }
        !self.owed.is_empty()
    }

    /// [`Self::asked`] for one owned interest.
    fn asked_owned(&mut self, interest: &crate::transport_profile::owned::InterestOwned) {
        use wz_codecs::wireexpr::WireexprOwnedVariant;
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            return;
        };
        if !interest.c() || !body.ke() {
            return;
        }
        // A key the dispatch could not make literal names a declaration the member never
        // made: zenoh-pico answers such an interest with nothing, not even its final
        // (`vendor/zenoh-pico/src/session/interest.c` @
        // `_Z_RETURN_IF_ERR(_z_get_keyexpr_from_wireexpr(zn, &restr_key, wireexpr, peer, true));`),
        // and the session's other answers to it drop it alike.
        let restriction = match body.keyexpr.as_ref().map(|wire| &wire.body) {
            None => None,
            Some(WireexprOwnedVariant::WireexprLocal(local)) if local.id == 0 => {
                match local.suffix.as_ref() {
                    Some(suffix) => {
                        Some(alloc::string::String::from(suffix.as_text().into_inner()))
                    }
                    None => return,
                }
            }
            Some(_) => return,
        };
        self.owed.push(OwedKeyexprs {
            interest_id: interest.interest_id,
            restriction,
            ends: !(body.su() || body.qu() || body.to()),
        });
    }

    /// [`Self::asked`] for one interest lent where its frame lies, by the rule of the owned one.
    fn asked_lent(&mut self, interest: &wz_codecs::lent::Interest<'_>) {
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            return;
        };
        if !interest.c() || !body.ke() {
            return;
        }
        let restriction = match body.keyexpr.as_ref().map(|wire| &wire.body) {
            None => None,
            Some(wz_codecs::lent::WireexprVariant::WireexprLocal(local)) if local.id == 0 => {
                match local.suffix {
                    Some(suffix) => Some(alloc::string::String::from(suffix.into_inner())),
                    None => return,
                }
            }
            Some(_) => return,
        };
        self.owed.push(OwedKeyexprs {
            interest_id: interest.interest_id,
            restriction,
            ends: !(body.su() || body.qu() || body.to()),
        });
    }

    /// Every owed answer handed to `each` as the arguments of its writer, in the order it is sent,
    /// and none owed after: each declared keyexpr that meets the interest's key, then the final
    /// when nothing else ends the interest. An engine whose reply backing does not wait puts each
    /// on the group at once (`MulticastReplyEnqueue::enqueue_declaration_reply`).
    pub fn take_declarations(&mut self, mut each: impl FnMut(DeclarationReply<'_>)) {
        for ask in core::mem::take(&mut self.owed) {
            for (mapping_id, keyexpr) in &self.declared {
                if ask.restriction.as_deref().is_some_and(|restriction| {
                    !crate::keyexpr_match::keyexpr_intersects_text(restriction, keyexpr)
                }) {
                    continue;
                }
                // A keyexpr is declared under an id that is not the literal's zero, which would
                // name no declaration.
                let Some(mapping_id) = core::num::NonZero::new(*mapping_id) else {
                    continue;
                };
                each(DeclarationReply::Keyexpr {
                    interest_id: ask.interest_id,
                    mapping_id,
                    keyexpr: keyexpr.as_str(),
                });
            }
            if ask.ends {
                each(DeclarationReply::Final {
                    interest_id: ask.interest_id,
                });
            }
        }
    }

    /// [`Self::take_declarations`], each answer handed as its owned `Declare`, lent for the call
    /// ([`DeclarationReply::owned`]); one the wire cannot carry is skipped. An engine whose push may
    /// wait for room keeps a copy ([`MulticastTxReply::to_item`]) and queues it with its own lock
    /// let go.
    pub fn take_answers(&mut self, mut each: impl FnMut(MulticastTxReply<'_>)) {
        self.take_declarations(|reply| {
            if let Some(declare) = reply.owned() {
                each(MulticastTxReply::DeclareReply(&declare));
            }
        });
    }
}

// The sink is a `DeclareReplySink` where a declare reply exists, which is what the test reads.
#[cfg(all(
    test,
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
mod tests {
    use super::*;
    use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// What a sink enqueued, in order.
    struct Recorded(RefCell<Vec<MulticastTxItem>>);

    impl MulticastReplyEnqueue for &Recorded {
        fn enqueue(&self, item: MulticastTxItem) {
            self.0.borrow_mut().push(item);
        }
    }

    /// Compiles only for a sink a whole observer drain takes.
    fn drains_a_whole_observer<S: ResponseSink + DeclareReplySink + LivelinessGetPrune>(_: &S) {}

    /// A group's sink is one a whole observer drain takes, in a build with no reply codec as in
    /// one with them, and a liveliness get that ended prunes nothing from it.
    #[test]
    fn a_group_sink_takes_a_whole_drain_and_prunes_nothing() {
        let recorded = Recorded(RefCell::new(Vec::new()));
        let sink = MulticastReplySink::new(&recorded);
        drains_a_whole_observer(&sink);
        #[cfg(feature = "liveliness-get")]
        sink.prune_liveliness_get_interest(7);
        assert!(recorded.0.borrow().is_empty());
    }

    /// What a backing that writes its replies where they wait was handed: each answer to an
    /// interest as the arguments of its writer, and each final of a query's replies by its two
    /// numbers. Nothing reaches it as an owned item.
    #[derive(Default)]
    struct Parts {
        declarations: RefCell<Vec<alloc::string::String>>,
        #[cfg(feature = "codec-response-final")]
        finals: RefCell<Vec<(crate::wire_id::RequestId, crate::sample::QosLevel)>>,
    }

    impl MulticastReplyEnqueue for &Parts {
        fn enqueue(&self, _item: MulticastTxItem) {
            panic!("an answer reached the backing as an owned item");
        }

        fn enqueue_declaration_reply(&self, reply: DeclarationReply<'_>) {
            self.declarations
                .borrow_mut()
                .push(alloc::format!("{reply:?}"));
        }

        #[cfg(feature = "codec-response-final")]
        fn enqueue_response_final(
            &self,
            request_id: crate::wire_id::RequestId,
            qos: crate::sample::QosLevel,
        ) {
            self.finals.borrow_mut().push((request_id, qos));
        }
    }

    /// The group's sink hands each answer to an interest to its backing as the arguments of its
    /// writer, and the final of a query's replies by its two numbers, and builds no owned record of
    /// either. Turned red by a sink that builds the owned reply itself (`send_declare_*_reply`,
    /// `send_response_final`) rather than handing its backing the parts.
    #[test]
    fn the_group_sink_hands_each_answer_to_its_backing_as_its_parts() {
        let parts = Parts::default();
        let sink = MulticastReplySink::new(&parts);
        sink.send_declare_final_reply(42);
        #[cfg(feature = "declare-subscriber")]
        sink.send_declare_subscriber_reply(9, "demo/s", 42);
        #[cfg(feature = "declare-queryable")]
        sink.send_declare_queryable_reply(8, "demo/q", true, 42);
        #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
        sink.send_undeclare_subscriber_reply(9);
        let expected = Vec::from([
            alloc::format!("{:?}", DeclarationReply::Final { interest_id: 42 }),
            #[cfg(feature = "declare-subscriber")]
            alloc::format!(
                "{:?}",
                DeclarationReply::Subscriber {
                    interest_id: 42,
                    subscriber_id: 9,
                    keyexpr: "demo/s",
                }
            ),
            #[cfg(feature = "declare-queryable")]
            alloc::format!(
                "{:?}",
                DeclarationReply::Queryable {
                    interest_id: 42,
                    queryable_id: 8,
                    keyexpr: "demo/q",
                    complete: true,
                }
            ),
            #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
            alloc::format!(
                "{:?}",
                DeclarationReply::UndeclareSubscriber { subscriber_id: 9 }
            ),
        ]);
        assert_eq!(*parts.declarations.borrow(), expected);
        #[cfg(feature = "codec-response-final")]
        {
            let qos = crate::sample::QosLevel::DEFAULT;
            sink.send_response_final(7, qos);
            assert_eq!(*parts.finals.borrow(), [(7, qos)]);
        }
    }

    /// What a backing that queues owned items was handed: each declaration reply as the owned
    /// `Declare`, and every other item as it came.
    #[derive(Default)]
    struct OwnedReplies {
        declarations: RefCell<Vec<crate::transport_profile::owned::DeclareOwned>>,
        items: RefCell<Vec<MulticastTxItem>>,
    }

    impl MulticastReplyEnqueue for &OwnedReplies {
        fn enqueue(&self, item: MulticastTxItem) {
            self.items.borrow_mut().push(item);
        }

        fn enqueue_reply(&self, reply: MulticastTxReply<'_>) {
            match reply {
                MulticastTxReply::DeclareReply(declare) => {
                    self.declarations.borrow_mut().push(declare.clone());
                }
                #[cfg(feature = "codec-response")]
                _ => panic!("an answer is a declaration reply"),
            }
        }
    }

    /// A backing that queues owned items is handed, for each answer to an interest, the owned reply
    /// the builder of its kind builds, and nothing for a keyexpr past the protocol's bound; the
    /// final of a query's replies reaches it as the owned item. Turned red by a default
    /// `enqueue_declaration_reply` that builds another reply than the builder of its kind, or one
    /// that queues a refused reply, or a default `enqueue_response_final` that queues another item.
    #[test]
    fn an_answer_reaches_an_owned_backing_as_its_builders_reply() {
        let owned = OwnedReplies::default();
        let sink = MulticastReplySink::new(&owned);
        sink.send_declare_final_reply(42);
        #[cfg(feature = "declare-subscriber")]
        {
            sink.send_declare_subscriber_reply(9, "demo/s", 42);
            let past = "k".repeat(usize::from(u16::MAX) + 1);
            sink.send_declare_subscriber_reply(10, &past, 42);
        }
        #[cfg(feature = "declare-queryable")]
        sink.send_declare_queryable_reply(8, "demo/q", false, 42);
        #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
        sink.send_undeclare_subscriber_reply(9);
        let expected = Vec::from([
            crate::declare_build::build_declare_final_reply(42),
            #[cfg(feature = "declare-subscriber")]
            crate::declare_build::build_declare_subscriber_reply_with_id(42, 9, "demo/s")
                .expect("a reply"),
            #[cfg(feature = "declare-queryable")]
            crate::declare_build::build_declare_queryable_reply_with_id(
                42,
                8,
                "demo/q",
                crate::queryable_info::QueryableInfo::local(false),
            )
            .expect("a reply"),
            #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
            crate::declare_build::build_undeclare_subscriber(9),
        ]);
        assert_eq!(*owned.declarations.borrow(), expected);
        assert!(owned.items.borrow().is_empty(), "no answer is an item");
        #[cfg(feature = "codec-response-final")]
        {
            let qos = crate::sample::QosLevel::DEFAULT;
            sink.send_response_final(7, qos);
            match owned.items.borrow().first() {
                Some(MulticastTxItem::ResponseFinal {
                    request_id,
                    qos: of,
                }) => {
                    assert_eq!((*request_id, *of), (7, qos));
                }
                _ => panic!("the final is the owned item"),
            };
        }
    }

    /// A held token's answer to a member's interest reaches a backing that queues owned items as
    /// the owned reply `build_token_reply` builds, and a keyexpr past the protocol's bound reaches
    /// it as nothing. Turned red by a default `enqueue_token_reply` that queues another reply, or
    /// one that queues a refused reply.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn a_token_reply_reaches_an_owned_backing_as_the_owned_reply() {
        let recorded = Recorded(RefCell::new(Vec::new()));
        let sink = MulticastReplySink::new(&recorded);
        sink.send_declare_token_reply(9, "demo/token", 42);
        let past = "k".repeat(usize::from(u16::MAX) + 1);
        sink.send_declare_token_reply(10, &past, 42);
        let expected = crate::declare::local_token::build_token_reply(9, "demo/token", 42)
            .and_then(|reply| {
                reply.try_into_owned_in::<crate::transport_profile::TransportStorage>()
            })
            .expect("an owned reply");
        let items = recorded.0.borrow();
        assert_eq!(items.len(), 1, "the refused reply queues nothing");
        match items.first() {
            Some(MulticastTxItem::DeclareReply { declare }) => assert_eq!(**declare, expected),
            _ => panic!("the answer is a declaration reply"),
        }
    }

    /// A member's current interest in keyexprs is answered with each declared keyexpr its key
    /// meets, then its final when it asks for nothing else; an interest in what is declared
    /// later only, and one naming its key by a declaration the dispatch could not resolve, are
    /// owed nothing, and an answer once taken is not owed again.
    #[cfg(all(
        feature = "codec-declare",
        feature = "declare-final",
        feature = "storage-profile"
    ))]
    #[test]
    fn a_members_keyexpr_interest_is_answered_with_the_keys_it_meets_and_its_final() {
        use crate::declare_build::{build_declare_final_reply, build_declare_kexpr_reply};
        use crate::driver_loop::DriverLoopOutcome;
        use crate::interest_build::{build_interest_exact, InterestKinds};
        use crate::network_message::NetworkMessage;
        let ask = |id: u64, current: bool, key: Option<(crate::wire_id::ExprId, Option<&str>)>| {
            NetworkMessage::Interest(
                build_interest_exact(id, InterestKinds::KEYEXPRS, current, !current, key)
                    .expect("an interest"),
            )
        };
        let frame = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: alloc::vec![
                ask(42, true, Some((0, Some("demo/**")))),
                ask(43, false, None),
                ask(44, true, Some((9, Some("x")))),
            ],
            has_ext: false,
            extensions: Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        };
        let mut answers = GroupKeyexprAnswers::default();
        answers.declared(5, "demo/a/x");
        answers.declared(6, "other/y");
        answers.declared(7, "demo/b");
        answers.retracted(7);
        // Noted record by record where the build lends them, so what is owed is the answer after
        // the last event the frame raised.
        let mut owed = false;
        crate::driver_loop::deliver_frame(&frame, |event| owed = answers.asked(&event));
        assert!(owed);
        let mut replies = Vec::new();
        answers.take_answers(|reply| match reply {
            MulticastTxReply::DeclareReply(declare) => replies.push(declare.clone()),
            #[cfg(feature = "codec-response")]
            _ => panic!("an answer is a declaration reply"),
        });
        assert_eq!(
            replies,
            [
                build_declare_kexpr_reply(42, 5, "demo/a/x").expect("a reply"),
                build_declare_final_reply(42),
            ]
        );
        let mut again = 0usize;
        answers.take_answers(|_| again += 1);
        assert_eq!(again, 0, "an answer is taken once");
    }

    /// The keys are answered in the order of their ids, whatever order they were declared in; an
    /// id declared again is answered once, with the key it names now; a retraction of an id never
    /// declared changes nothing.
    #[cfg(all(
        feature = "codec-declare",
        feature = "declare-final",
        feature = "storage-profile"
    ))]
    #[test]
    fn keys_are_answered_in_id_order_and_a_redeclared_id_by_its_new_key() {
        use crate::declare_build::{build_declare_final_reply, build_declare_kexpr_reply};
        use crate::driver_loop::DriverLoopOutcome;
        use crate::interest_build::{build_interest_exact, InterestKinds};
        use crate::network_message::NetworkMessage;
        let frame = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: alloc::vec![NetworkMessage::Interest(
                build_interest_exact(42, InterestKinds::KEYEXPRS, true, false, None)
                    .expect("an interest"),
            )],
            has_ext: false,
            extensions: Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        };
        let mut answers = GroupKeyexprAnswers::default();
        answers.declared(9, "k/nine");
        answers.declared(3, "k/three");
        answers.declared(6, "k/six");
        answers.declared(3, "k/three/again");
        answers.retracted(6);
        answers.retracted(77);
        let mut owed = false;
        crate::driver_loop::deliver_frame(&frame, |event| owed = answers.asked(&event));
        assert!(owed);
        let mut replies = Vec::new();
        answers.take_answers(|reply| match reply {
            MulticastTxReply::DeclareReply(declare) => replies.push(declare.clone()),
            #[cfg(feature = "codec-response")]
            _ => panic!("an answer is a declaration reply"),
        });
        assert_eq!(
            replies,
            [
                build_declare_kexpr_reply(42, 3, "k/three/again").expect("a reply"),
                build_declare_kexpr_reply(42, 9, "k/nine").expect("a reply"),
                build_declare_final_reply(42),
            ]
        );
    }

    /// The answers to a member's keyexpr interest are handed as the arguments of their writers, in
    /// the order the owned replies go, each the parts of the owned reply `take_answers` hands; an
    /// answer once handed is not owed again. Turned red by a walk that hands another id, key or
    /// interest than the owned answer (`take_declarations`), or the final before the keys.
    #[cfg(all(
        feature = "codec-declare",
        feature = "declare-final",
        feature = "storage-profile"
    ))]
    #[test]
    fn a_keyexpr_interest_is_answered_with_the_parts_of_its_owned_replies() {
        use crate::declare_build::{build_declare_final_reply, build_declare_kexpr_reply};
        use crate::driver_loop::DriverLoopOutcome;
        use crate::interest_build::{build_interest_exact, InterestKinds};
        use crate::network_message::NetworkMessage;
        let frame = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: alloc::vec![NetworkMessage::Interest(
                build_interest_exact(42, InterestKinds::KEYEXPRS, true, false, None)
                    .expect("an interest"),
            )],
            has_ext: false,
            extensions: Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        };
        let mut answers = GroupKeyexprAnswers::default();
        answers.declared(9, "k/nine");
        answers.declared(3, "k/three");
        let mut owed = false;
        crate::driver_loop::deliver_frame(&frame, |event| owed = answers.asked(&event));
        assert!(owed);
        let mut handed = Vec::new();
        answers
            .take_declarations(|reply| handed.push((alloc::format!("{reply:?}"), reply.owned())));
        let key = |id: crate::wire_id::ExprId| core::num::NonZero::new(id).expect("a declared id");
        assert_eq!(
            handed,
            [
                (
                    alloc::format!(
                        "{:?}",
                        DeclarationReply::Keyexpr {
                            interest_id: 42,
                            mapping_id: key(3),
                            keyexpr: "k/three",
                        }
                    ),
                    Some(build_declare_kexpr_reply(42, 3, "k/three").expect("a reply")),
                ),
                (
                    alloc::format!(
                        "{:?}",
                        DeclarationReply::Keyexpr {
                            interest_id: 42,
                            mapping_id: key(9),
                            keyexpr: "k/nine",
                        }
                    ),
                    Some(build_declare_kexpr_reply(42, 9, "k/nine").expect("a reply")),
                ),
                (
                    alloc::format!("{:?}", DeclarationReply::Final { interest_id: 42 }),
                    Some(build_declare_final_reply(42)),
                ),
            ]
        );
        let mut again = 0usize;
        answers.take_declarations(|_| again += 1);
        assert_eq!(again, 0, "an answer is handed once");
    }
}
