// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The spans of upstream's routing code, opened where wz does the same step.
//!
//! Upstream's `zenoh` opens `demux{zid, src}` round the handling of each message a face sends
//! (`zenoh/src/net/primitives/demux.rs` @ `tracing::debug_span!(`, `zid` being the node's own),
//! and `register_subscriber{self, res}` / `register_queryable{self, res}` round the registration
//! of a declaration in the hat of the face's region, each with the one event that
//! `#[tracing::instrument(.., ret)]` makes when the function returns
//! (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `fn register_subscriber(`). Its own test of its
//! regions counts those events by the node's zid and the hat's region name
//! (`zenoh/tests/regions/main.rs` @ `pub mod predicates_ext`): how many times a node's north hat
//! registered a subscriber or a queryable for a key. That is a count of upstream's steps and not an
//! observable of the API, and it is met only by a routing that takes the same steps and says so
//! the same way.
//!
//! Without the `tracing-spans` feature every function here is empty, and a build pays nothing.
//! With it, a span is opened only where `tracing` has a subscriber that wants the level, as upstream
//! opens `demux` (`tracing::enabled!(tracing::Level::DEBUG).then(..)`).

use wz_session_core::extbound::Region;
use wz_session_core::wire_id::RequestId;

use crate::accept_loop::FaceId;
use crate::linkstate_forward::Zid;

/// A span that is open until this drops: nothing without the feature, or where `tracing` wants
/// no span of that level.
pub(super) struct Held {
    #[cfg(feature = "tracing-spans")]
    span: Option<tracing::span::EnteredSpan>,
}

impl Held {
    /// The registration returned `registered`: the one event upstream's `ret` makes inside the
    /// span. A second event inside it would be counted as a second registration.
    #[cfg(feature = "tracing-spans")]
    pub(super) fn returned(&self, registered: bool) {
        if self.span.is_some() {
            tracing::debug!(r#return = registered);
        }
    }

    #[cfg(not(feature = "tracing-spans"))]
    #[inline(always)]
    pub(super) fn returned(&self, _registered: bool) {}
}

/// The handling of one message of face `src` by the node `zid`.
#[cfg(feature = "tracing-spans")]
pub(super) fn demux(zid: Zid, src: FaceId) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG)
            .then(|| tracing::debug_span!("demux", zid = %zid, src = src.0).entered()),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn demux(_zid: Zid, _src: FaceId) -> Held {
    Held {}
}

/// The registration of a subscriber of `keyexpr` in the hat of `region`.
#[cfg(feature = "tracing-spans")]
pub(super) fn register_subscriber(region: &Region, keyexpr: &str) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!("register_subscriber", self = %region, res = %keyexpr).entered()
        }),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn register_subscriber(_region: &Region, _keyexpr: &str) -> Held {
    Held {}
}

/// The registration of a queryable of `keyexpr` in the hat of `region`.
#[cfg(feature = "tracing-spans")]
pub(super) fn register_queryable(region: &Region, keyexpr: &str) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!("register_queryable", self = %region, res = %keyexpr).entered()
        }),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn register_queryable(_region: &Region, _keyexpr: &str) -> Held {
    Held {}
}

/// The node `zid` took query `rid` of face `src` to route: upstream's event at the same step
/// (`zenoh/src/net/routing/dispatcher/queries.rs` @ `"{}:{} Route query for res {}{}",`), with the
/// face and the query id as fields, so that a reader can time a query through the node.
#[cfg(feature = "tracing-spans")]
pub(super) fn query_routed(zid: Zid, src: FaceId, rid: RequestId) {
    tracing::debug!(zid = %zid, src = src.0, rid, "route query");
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn query_routed(_zid: Zid, _src: FaceId, _rid: RequestId) {}

/// The node `zid` sent face `dst` the final of its query `rid`: upstream's events at the same
/// step, for a query routed nowhere (`zenoh/src/net/routing/dispatcher/queries.rs` @
/// `"{}:{} Send final reply (no matching queryables or not master)",`) and for one whose last
/// branch ended (@ `"{}:{} Propagate final reply"`).
#[cfg(feature = "tracing-spans")]
pub(super) fn query_final(zid: Zid, dst: FaceId, rid: RequestId) {
    tracing::debug!(zid = %zid, dst = dst.0, rid, "send final reply");
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn query_final(_zid: Zid, _dst: FaceId, _rid: RequestId) {}

#[cfg(all(test, feature = "tracing-spans"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// One event as a reader records it: its message and its numeric fields, in order.
    type Told = (String, Vec<(String, u64)>);

    /// A subscriber that records every event and opens no span.
    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<Told>>>);

    #[derive(Default)]
    struct Fields {
        message: String,
        numbers: Vec<(String, u64)>,
    }

    impl Visit for Fields {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.numbers.push((field.name().to_owned(), value));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            }
        }
    }

    impl Subscriber for Recorded {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.is_event()
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0
                .lock()
                .expect("the record")
                .push((fields.message, fields.numbers));
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    /// A query the node routes and the final it sends are told with the face and the query id,
    /// which is what a reader matches the two by.
    #[test]
    fn a_query_routed_and_its_final_are_told_with_their_face_and_id() {
        let recorded = Recorded::default();
        let zid = Zid::from_slice(&[1, 2, 3, 4]);
        tracing::subscriber::with_default(recorded.clone(), || {
            query_routed(zid, FaceId(7), 41);
            query_final(zid, FaceId(7), 41);
        });
        let told = recorded.0.lock().expect("the record").clone();
        assert_eq!(
            told,
            [
                (
                    "route query".to_owned(),
                    vec![("src".to_owned(), 7), ("rid".to_owned(), 41)]
                ),
                (
                    "send final reply".to_owned(),
                    vec![("dst".to_owned(), 7), ("rid".to_owned(), 41)]
                ),
            ]
        );
    }
}
