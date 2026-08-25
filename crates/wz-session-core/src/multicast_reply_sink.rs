// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
// interest-response also enqueues boxed `DeclareReply` items.
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
// backing crates.
#[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
impl<Q: MulticastReplyEnqueue> crate::response_sink::ResponseSink for MulticastReplySink<Q> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: wz_codecs::response::ResponseOwned) {
        self.queue.enqueue(MulticastTxItem::Response {
            response: Box::new(response),
        });
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        self.queue
            .enqueue(MulticastTxItem::ResponseFinal { request_id });
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
        let declare =
            crate::declare::local_token::build_token_reply(token_id, keyexpr, interest_id)
                .try_into_owned()
                .expect("local-token reply keyexpr is within MAX_KEYEXPR_BYTES");
        self.queue.enqueue(MulticastTxItem::DeclareReply {
            declare: Box::new(declare),
        });
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
}
