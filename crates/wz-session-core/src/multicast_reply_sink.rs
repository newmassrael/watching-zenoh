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

use crate::multicast_tx::MulticastTxItem;
// Only the boxed reply variants (Response / DeclareReply) name Box; the unboxed
// ResponseFinal does not, so a codec-response-final-only build imports nothing.
// R311y530 — `declare-subscriber` joins the list: the session-local subscriber
// interest-response also enqueues boxed `DeclareReply` items, which exist under either feature
// (`MulticastTxItem::DeclareReply`; open-debt item 913 found the variant still gated on
// `liveliness-token` alone, which left a `declare-subscriber` build without it uncompilable).
#[cfg(any(
    feature = "codec-response",
    feature = "liveliness-token",
    feature = "declare-subscriber"
))]
use alloc::boxed::Box;

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

// The queryable-reply drain (R311lq): the observer hands the sink the owned
// `Response` (drained from `pending_replies` via `QueryReply::into_response`) and
// the terminal rid; the sink wraps each in the matching `MulticastTxItem` and
// enqueues it. `send_response` is the one place a `wz_codecs` owned type is
// named — here in wz-session-core (which already deps wz-codecs), not in the
// backing crates. Every method is gated by its own codec, so a build with neither
// reply codec has a sink with nothing to send: a host that drains a group's whole
// observer through one sink (`SlotObserver::flush_pending`) names it in every build.
impl<Q: MulticastReplyEnqueue> crate::response_sink::ResponseSink for MulticastReplySink<Q> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: crate::wire::ResponseOwned) {
        self.queue.enqueue(MulticastTxItem::Response {
            response: Box::new(response),
        });
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(
        &self,
        request_id: crate::wire_id::RequestId,
        qos: crate::sample::QosLevel,
    ) {
        self.queue
            .enqueue(MulticastTxItem::ResponseFinal { request_id, qos });
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
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        // A keyexpr past the protocol's bound is not answered, as the subscriber reply
        // below skips one: the chain's `DeclFinal` still terminates the interest.
        if let Ok(declare) =
            crate::declare::local_token::build_token_reply(token_id, keyexpr, interest_id).and_then(
                |reply| reply.try_into_owned_in::<crate::transport_profile::TransportStorage>(),
            )
        {
            self.queue.enqueue(MulticastTxItem::DeclareReply {
                declare: Box::new(declare),
            });
        }
    }
    fn send_declare_final_reply(&self, interest_id: u64) {
        // Same UNGATED builder as the unicast sink, for the same reason: the
        // `local_token` module does not exist in a `declare-subscriber`-only
        // build, and `DeclFinal` was never a liveliness-specific message.
        self.queue.enqueue(MulticastTxItem::DeclareReply {
            declare: Box::new(crate::declare_build::build_declare_final_reply(interest_id)),
        });
    }
    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        if let Ok(declare) = crate::declare_build::build_declare_subscriber_reply_with_id(
            interest_id,
            subscriber_id,
            keyexpr,
        ) {
            self.queue.enqueue(MulticastTxItem::DeclareReply {
                declare: Box::new(declare),
            });
        }
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
        if let Ok(declare) = crate::declare_build::build_declare_queryable_reply_with_id(
            interest_id,
            queryable_id,
            keyexpr,
            crate::queryable_info::QueryableInfo::local(complete),
        ) {
            self.queue.enqueue(MulticastTxItem::DeclareReply {
                declare: Box::new(declare),
            });
        }
    }
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        // Same id-only retraction the unicast sink emits, through this
        // transport's own enqueue. Infallible where the declare twin is not:
        // an `UndeclSubscriber` carries no keyexpr, so there is no bounded
        // field to overflow.
        self.queue.enqueue(MulticastTxItem::DeclareReply {
            declare: Box::new(crate::declare_build::build_undeclare_subscriber(
                subscriber_id,
            )),
        });
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
        IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Interest(interest) if interest.c())),
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
    declared: alloc::collections::BTreeMap<crate::wire_id::ExprId, alloc::string::String>,
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
    pub fn declared(&mut self, mapping_id: crate::wire_id::ExprId, keyexpr: &str) {
        self.declared.insert(mapping_id, keyexpr.into());
    }

    /// The session retracted declaration `mapping_id`.
    pub fn retracted(&mut self, mapping_id: crate::wire_id::ExprId) {
        self.declared.remove(&mapping_id);
    }

    /// Note each interest in `event` that asks for keyexprs now, owned in a batch or lent where its
    /// frame lies; whether any answer is owed after it.
    pub fn asked(&mut self, event: &crate::driver_loop::IterationEvent<'_, '_>) -> bool {
        use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
        use crate::network_message::NetworkMessage;
        match event {
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                for message in messages.iter() {
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

    /// Every owed answer, in the order it is sent, and none owed after: each declared keyexpr
    /// that meets the interest's key, then the final when nothing else ends the interest. The
    /// engine queues them on the group, with its own lock let go when a push may wait for room.
    pub fn take_answers(&mut self) -> alloc::vec::Vec<MulticastTxItem> {
        let mut answers = alloc::vec::Vec::new();
        for ask in core::mem::take(&mut self.owed) {
            for (mapping_id, keyexpr) in &self.declared {
                if ask.restriction.as_deref().is_some_and(|restriction| {
                    !crate::keyexpr_match::keyexpr_intersects_text(restriction, keyexpr)
                }) {
                    continue;
                }
                if let Ok(declare) = crate::declare_build::build_declare_kexpr_reply(
                    ask.interest_id,
                    *mapping_id,
                    keyexpr,
                ) {
                    answers.push(MulticastTxItem::DeclareReply {
                        declare: Box::new(declare),
                    });
                }
            }
            if ask.ends {
                answers.push(MulticastTxItem::DeclareReply {
                    declare: Box::new(crate::declare_build::build_declare_final_reply(
                        ask.interest_id,
                    )),
                });
            }
        }
        answers
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
        use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
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
        assert!(answers.asked(&IterationEvent::Poll(&frame)));
        let replies: Vec<_> = answers
            .take_answers()
            .into_iter()
            .map(|item| match item {
                MulticastTxItem::DeclareReply { declare } => *declare,
                _ => panic!("an answer is a declaration reply"),
            })
            .collect();
        assert_eq!(
            replies,
            [
                build_declare_kexpr_reply(42, 5, "demo/a/x").expect("a reply"),
                build_declare_final_reply(42),
            ]
        );
        assert!(answers.take_answers().is_empty(), "an answer is taken once");
    }
}
