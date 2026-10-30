// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.2 -- a Request dispatched where its frame lies.
//!
//! The fixed-memory MCU profile's receive path (`drive::dispatch_datagram`,
//! `wz-runtime-coop`'s `rx-in-place`) decodes a Request record over the
//! datagram the link lends and hands it over as
//! [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace)
//! instead of projecting it into a boxed owned message. This module is the
//! queryable side of that: the keyexpr is resolved without a `String`
//! ([`resolve_wireexpr_view`]), the selector parameters, the attachment, the
//! source info and the value are read where they lie, and the matching
//! queryables are fired through the SAME fan-out the owned path takes
//! ([`QueryableRegistry::fire_projection`]), over a projection of the lent query
//! instead of the owned one. A queryable's contract was already a view borrowed
//! for the call (`QuerySink::handle`), so no queryable changes; its replies are
//! staged as they always are.
//!
//! What it dispatches is what [`QueryableRegistry::dispatch_request`] dispatches
//! for the owned projection of the same record, field for field: only a Query
//! body reaches the table; the keyexpr by the same resolution rule; the target
//! and the QoS off the same extension chain by the same readers
//! (`read_target_in`, `read_qos_in`); the parameters, attachment, source info
//! and value under the same features. And it owes the requester its Final on
//! the same rule: iff the query reached the table, whatever it matched.
//!
//! Two Requests are not represented lent and take the owned projection
//! instead: a Query whose value is a list of slices (read through the
//! shared-memory un-swap BEFORE routing, on the owned path, which must still
//! happen when routing then refuses it), and a Request whose resolved keyexpr is
//! longer than [`KeyexprBuf`], which only the fixed bounded backing refuses. Each
//! is still dispatched, as the copying path dispatches it.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use wz_codecs::query::QueryView;
use wz_codecs::query_ext_entry::{QueryExtEntryView, QueryExtEntryViewVariant};
use wz_codecs::request::{RequestView, RequestViewVariant};

use super::{DispatchOutcome, QueryEnvelope, QueryProjection, QueryableRegistry};
use crate::ext_view::{walked, ExtEntryView};
use crate::query_sink::QuerySink;
use crate::reply_stage::{FinalStage, FinalStaging, ReplyStage};
use crate::wireexpr_resolve::{
    resolve_wireexpr_viewed, KeyexprBuf, KeyexprPastBound, MappingSpaces,
};

/// Why a Request read in place is dispatched through its owned projection
/// instead.
enum Fallback {
    /// Its Query's value is a list of slices.
    SlicedValue,
    /// Its keyexpr does not fit the bounded buffer.
    KeyexprPastBound,
    /// It carries a timestamp stack, which the delivering node adds to: the stack is an owned
    /// value the lent form has none of.
    #[cfg(feature = "pubsub-ts-stack")]
    Instrumented,
}

/// The target and the QoS a Request's extension chain carries, each by the rule the owned path
/// reads it by (`read_target_of`, `read_qos_of`), in one walk of the chain: a chain read where
/// its frame lies decodes every entry again at every walk, and the Request used to be walked
/// once for the target, once for the QoS of the replies and once more for the QoS of the Final.
fn read_envelope_extensions(
    request: &RequestView<'_>,
) -> (
    Option<crate::query_mode::QueryTarget>,
    crate::sample::QosLevel,
) {
    let (target, qos) = crate::ext_nodeid::read_two_z64_of(
        walked(request.extensions.as_ref()),
        crate::query_mode::TARGET_EXT_HEADER,
        crate::declare_ext_qos::QOS_EXT_HEADER,
    );
    (
        crate::request_routing_context::target_of_raw(target),
        crate::declare_ext_qos::qos_of_raw(qos),
    )
}

/// Whether a Query's chain carries its value as a list of slices: the shape the
/// owned path un-swaps before routing (`QueryableRegistry::unswap_query_value`
/// reads the first value entry that has slices).
fn has_sliced_value<'a>(exts: impl Iterator<Item = QueryExtEntryView<'a>>) -> bool {
    exts.into_iter().any(|ext| {
        ext.eid() == crate::ext_header::body_eid::QUERY_VALUE
            && matches!(
                &ext.body,
                QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(z) if z.slices.is_some()
            )
    })
}

/// What a queryable is shown of `query` read in place, each field under the
/// gate the owned projection reads it under. The shareable forms are `None`:
/// the bytes are the link's, lent for the call, and a queryable that keeps them
/// copies them.
///
/// The Query's chain is walked where it lies, once for each field that reads it: the attachment,
/// the source info and the value each scan it for their own extension, as they scanned the held
/// chain, and the bytes they hand out stay in the frame.
fn lent_projection<'q>(query: &QueryView<'q>) -> QueryProjection<'q> {
    #[cfg(not(any(
        feature = "query-attachment",
        feature = "query-source-info",
        feature = "query-value"
    )))]
    let _ = query.extensions;
    QueryProjection {
        #[cfg(feature = "query-selector-parameters")]
        parameters: query.parameters,
        #[cfg(not(feature = "query-selector-parameters"))]
        parameters: None,
        #[cfg(feature = "query-attachment")]
        attachment: crate::attachment::decode_attachment_ext_in(
            walked(query.extensions.as_ref()),
            crate::attachment::ATTACHMENT_EXT_ID_QUERY,
        ),
        #[cfg(not(feature = "query-attachment"))]
        attachment: None,
        #[cfg(feature = "query-source-info")]
        source_info: crate::sample::extract_source_info_in(walked(query.extensions.as_ref())),
        #[cfg(not(feature = "query-source-info"))]
        source_info: None,
        // A build with no heap does not project a query's value (its encoding is an
        // owned hint), nor a value or attachment held as shareable bytes.
        #[cfg(all(feature = "alloc", feature = "query-value"))]
        plain_value: crate::query_value_ext::decode_query_value_ext_in(walked(
            query.extensions.as_ref(),
        )),
        #[cfg(all(feature = "alloc", not(feature = "query-value")))]
        plain_value: None,
        #[cfg(feature = "alloc")]
        shared_value: None,
        #[cfg(feature = "alloc")]
        attachment_shared: None,
        #[cfg(feature = "pubsub-ts-stack")]
        ts_stack: None,
    }
}

impl<C: QuerySink, P: crate::bounded::Storage> QueryableRegistry<C, P> {
    /// Dispatch a Request the in-place receive path lent: the queryable side of
    /// [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace),
    /// staging replies into `pending_replies` and the Final it owes into
    /// `pending_final_rids`, as [`Self::dispatch_messages`] does for an owned
    /// one. See the module docs for what it hands to the owned projection.
    pub(super) fn dispatch_request_in_place(
        &mut self,
        request: &RequestView<'_>,
        spaces: MappingSpaces<'_>,
        pending_replies: &mut ReplyStage,
        pending_final_rids: &mut FinalStage,
    ) {
        // As the owned path: a Query that would owe a Final the table cannot
        // hold is refused before any queryable runs, and counted.
        if matches!(request.body, RequestViewVariant::CodecZenohQuery(_))
            && !pending_final_rids.has_room()
        {
            pending_final_rids.refuse_request();
            return;
        }
        // The target and the QoS come off the Request's chain in one walk, and the QoS the
        // terminator carries is the one the replies inherit.
        let (target, qos) = read_envelope_extensions(request);
        let envelope = QueryEnvelope {
            rid: request.rid,
            target,
            qos,
        };
        match self.dispatch_lent(request, spaces, envelope, pending_replies) {
            Ok(outcome) => {
                if outcome.dispatched {
                    // The terminator carries the query's QoS, read by the rule
                    // the owned path reads it by.
                    pending_final_rids.owe(request.rid, qos);
                }
            }
            #[cfg(feature = "alloc")]
            Err(Fallback::SlicedValue | Fallback::KeyexprPastBound) => {
                self.dispatch_owned_projection(request, spaces, pending_replies, pending_final_rids)
            }
            #[cfg(feature = "pubsub-ts-stack")]
            Err(Fallback::Instrumented) => {
                self.dispatch_owned_projection(request, spaces, pending_replies, pending_final_rids)
            }
            // With no allocator there is no owned projection to fall back on, so a
            // Request the lent form cannot represent reaches no queryable, and is
            // owed its Final as a query that matched nobody is: the requester's
            // query ends with no reply, where a refused one would be left to time out.
            #[cfg(not(feature = "alloc"))]
            Err(Fallback::SlicedValue | Fallback::KeyexprPastBound) => {
                pending_final_rids.owe(request.rid, qos);
            }
        }
    }

    /// The lent dispatch itself: [`Self::dispatch_request`]'s steps over the
    /// Request where it lies.
    fn dispatch_lent(
        &mut self,
        request: &RequestView<'_>,
        spaces: MappingSpaces<'_>,
        envelope: QueryEnvelope,
        replies: &mut ReplyStage,
    ) -> Result<DispatchOutcome, Fallback> {
        // Only the Query body arm reaches the table.
        let RequestViewVariant::CodecZenohQuery(query) = &request.body else {
            return Ok(DispatchOutcome::NOT_DISPATCHED);
        };
        if has_sliced_value(walked(query.extensions.as_ref())) {
            return Err(Fallback::SlicedValue);
        }
        // A Request the nodes record on is delivered with a stack of its own to add to.
        #[cfg(feature = "pubsub-ts-stack")]
        if crate::ext_view::find_by_eid_in(
            walked(request.extensions.as_ref()),
            crate::ext_header::ext_eid(crate::ts_stack::TS_STACK_EXT_HEADER),
        )
        .is_some()
        {
            return Err(Fallback::Instrumented);
        }
        let mut composed = KeyexprBuf::new();
        let keyexpr = match resolve_wireexpr_viewed(&request.keyexpr.body, spaces, &mut composed) {
            Ok(Some(keyexpr)) => keyexpr,
            // The empty keyexpr, or an id the space does not hold: the query
            // never reaches the table and owes nothing, as on the owned path.
            Ok(None) => return Ok(DispatchOutcome::NOT_DISPATCHED),
            Err(KeyexprPastBound) => return Err(Fallback::KeyexprPastBound),
        };
        let matched =
            self.fire_projection(envelope, keyexpr, lent_projection(query), replies, true);
        Ok(DispatchOutcome {
            dispatched: true,
            matched,
        })
    }

    /// The fallback: the owned projection of `request`, dispatched by the path
    /// the copying receive takes ([`Self::dispatch_messages`]), so a Request the
    /// lent form cannot represent is dispatched, and owes its Final, exactly as
    /// it always did. Heap profile only.
    #[cfg(feature = "alloc")]
    fn dispatch_owned_projection(
        &mut self,
        request: &RequestView<'_>,
        spaces: MappingSpaces<'_>,
        pending_replies: &mut ReplyStage,
        pending_final_rids: &mut FinalStage,
    ) {
        // The wire profile is unbounded (`Heap`, or the AP's shared frame
        // ranges), so this projection cannot refuse a decoded Request. The
        // view is first filled into the codec's own record (the heap profile has the stack
        // for its 1.8 KB, and this is the path of a Request the lent form cannot hold), and
        // that record consumes itself into the owned one.
        let mut record = wz_codecs::request::Request::default();
        if request.into_builder(&mut record).is_err() {
            return;
        }
        if let Ok(owned) = record.try_into_owned_in::<crate::wire::WireStorage>() {
            self.dispatch_messages(
                &[crate::network_message::NetworkMessage::Request(Box::new(
                    owned,
                ))],
                spaces,
                pending_replies,
                pending_final_rids,
            );
        }
    }
}

// The lent dispatch against the owned one on the same wire record: every field
// a queryable can read through `QueryView` must be the same, the replies it
// stages and the Final the query is owed must be the same, for a query that
// matches, one that matches nobody (still owed its Final), one whose keyexpr
// routing cannot place (owed nothing), a keyexpr through the peer's space, and
// one past the bounded buffer (the fallback). The allocation count of the path
// is the lwIP harness's (`wz-session-lwip/tests/rx_frame_allocations.rs`).
#[cfg(all(test, feature = "query-queryable"))]
mod tests {
    use super::*;
    use crate::driver_loop::{InPlaceRecord, IterationEvent};
    use crate::network_message::{parse_frame_payload, NetworkMessage};
    use crate::query::QueryReply;
    use crate::query_mode::QueryTarget;
    use crate::reply_stage::ReplyStaging as _;
    use crate::request_build::RequestQueryBuilder;
    use crate::sample::{EncodingHint, QosLevel, SourceInfo};
    use alloc::string::String;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    use sce_forge_runtime::codec::SceCursor;
    use std::sync::{Arc, Mutex};

    /// Everything a queryable can read through the view, as owned values.
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        keyexpr: String,
        parameters: Option<Vec<u8>>,
        attachment: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
        encoding: Option<EncodingHint>,
        source_info: Option<SourceInfo>,
        rid: u64,
        is_local: bool,
        qos: QosLevel,
        #[cfg(feature = "pubsub-ts-stack")]
        ts_stack: Option<crate::ts_stack::TsStack>,
    }

    /// What one dispatch left behind: what the queryables saw, the replies they
    /// staged, and the Finals owed.
    type Left = (Vec<Seen>, Vec<QueryReply>, Vec<(u64, QosLevel)>);

    type Registry = super::QueryableRegistry<crate::query_sink::BoxedQuerySink>;

    fn recording() -> (Registry, Arc<Mutex<Vec<Seen>>>) {
        let mut registry = Registry::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        registry.register("demo/**", move |view, out| {
            into.lock().expect("not poisoned").push(Seen {
                keyexpr: String::from(view.keyexpr()),
                parameters: view.parameters().map(<[u8]>::to_vec),
                attachment: view.attachment().map(<[u8]>::to_vec),
                payload: view.payload().map(<[u8]>::to_vec),
                encoding: view.encoding().cloned(),
                source_info: view.source_info().cloned(),
                rid: view.rid(),
                is_local: view.is_local(),
                qos: view.qos(),
                #[cfg(feature = "pubsub-ts-stack")]
                ts_stack: view.ts_stack().cloned(),
            });
            out.reply(b"answer");
        });
        (registry, log)
    }

    /// The peer's id space: one alias, and one whose expansion together with a
    /// suffix is past the bounded keyexpr buffer.
    fn peer() -> HashMap<u64, String> {
        let mut peer = HashMap::new();
        peer.insert(5, String::from("demo/mapped"));
        peer.insert(
            6,
            alloc::format!("demo/{}", "x".repeat(crate::caps::MAX_KEYEXPR_BYTES)),
        );
        peer
    }

    /// What the owned path and the lent path leave behind for the same wire
    /// record.
    fn both(request: &crate::wire::RequestOwned) -> (Left, Left) {
        let wire = request
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
            .expect("a fixture request is encodable");
        let peer = peer();
        let (mut owned, owned_log) = recording();
        let messages = parse_frame_payload(&wire).expect("the record decodes");
        assert!(matches!(messages.as_slice(), [NetworkMessage::Request(_)]));
        let (mut owned_replies, mut owned_finals) = (ReplyStage::new(), FinalStage::new());
        owned.dispatch_messages(&messages, &peer, &mut owned_replies, &mut owned_finals);
        let (mut lent, lent_log) = recording();
        let decoded = RequestView::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
        let (mut lent_replies, mut lent_finals) = (ReplyStage::new(), FinalStage::new());
        lent.dispatch_iteration_event(
            IterationEvent::InPlace(InPlaceRecord::request_of_frame(
                &decoded,
                true,
                0,
                crate::qos::Priority::DEFAULT,
            )),
            &peer,
            &mut lent_replies,
            &mut lent_finals,
        );
        let owned_seen = owned_log.lock().expect("not poisoned").clone();
        let lent_seen = lent_log.lock().expect("not poisoned").clone();
        (
            (
                owned_seen,
                owned_replies.drain_staged().collect(),
                owned_finals.drain_owed().collect(),
            ),
            (
                lent_seen,
                lent_replies.drain_staged().collect(),
                lent_finals.drain_owed().collect(),
            ),
        )
    }

    #[test]
    fn a_query_is_dispatched_lent_as_the_owned_path_dispatches_it() {
        let full = {
            let builder = RequestQueryBuilder::new(12, 0, Some("demo/full"))
                .parameters(b"a=1;b=2")
                .request_qos(0x0D);
            #[cfg(feature = "query-attachment")]
            let builder = builder.query_attachment(b"att");
            #[cfg(feature = "query-value")]
            let builder = builder.query_value(
                b"value",
                EncodingHint {
                    packed_id: 0x0B,
                    schema: Some(String::from("text")),
                },
            );
            #[cfg(feature = "query-source-info")]
            let builder = builder.query_source_info(SourceInfo::new(&[1, 2, 3, 4], 7, 11));
            builder.build().expect("build")
        };
        let cases = [
            RequestQueryBuilder::new(11, 0, Some("demo/a"))
                .build()
                .expect("build"),
            full,
            // Matches nobody: still dispatched, still owed its Final.
            RequestQueryBuilder::new(13, 0, Some("other/a"))
                .build()
                .expect("build"),
            // A target only complete queryables answer: matches nobody here.
            RequestQueryBuilder::new(14, 0, Some("demo/a"))
                .request_target(QueryTarget::AllComplete)
                .build()
                .expect("build"),
            // Through the peer's alias, with and without a suffix.
            RequestQueryBuilder::new(15, 5, None)
                .build()
                .expect("build"),
            RequestQueryBuilder::new(16, 5, Some("/more"))
                .build()
                .expect("build"),
            // An id the peer never declared: never routed, owed nothing.
            RequestQueryBuilder::new(17, 77, None)
                .build()
                .expect("build"),
            // Past the bounded buffer: the fixed backing falls back to the
            // owned projection, which dispatches it.
            RequestQueryBuilder::new(18, 6, Some("/tail"))
                .build()
                .expect("build"),
        ];
        let mut finals = 0;
        for (i, request) in cases.iter().enumerate() {
            let (owned, lent) = both(request);
            assert_eq!(lent, owned, "case {i}");
            finals += owned.2.len();
        }
        assert_eq!(finals, cases.len() - 1, "every case but the unroutable one");
    }

    /// A Request that carries a timestamp stack is dispatched with it: the lent form has no stack
    /// of its own for the nodes to add to, so it takes the owned path, and a queryable is shown
    /// the same stack either way. A Request that carries none is shown none.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn an_instrumented_query_is_dispatched_with_its_stack_on_both_paths() {
        use crate::ts_stack::{point, TsStack};

        let mut stack = TsStack::new(point::SEND | point::RECEIVE);
        stack.record(point::SEND, alloc::vec![9, 8, 7], false);
        let instrumented = RequestQueryBuilder::new(21, 0, Some("demo/a"))
            .request_qos(0x0D)
            .request_ts_stack(&stack)
            .build()
            .expect("build");
        let (owned, lent) = both(&instrumented);
        assert_eq!(lent, owned, "the lent path is the owned one");
        assert_eq!(owned.0.len(), 1);
        assert_eq!(owned.0[0].ts_stack.as_ref(), Some(&stack));
        assert!(!owned.0[0].is_local, "it came in over a link");
        assert_eq!(owned.2.len(), 1, "the query is owed its Final");

        let plain = RequestQueryBuilder::new(22, 0, Some("demo/a"))
            .build()
            .expect("build");
        let (owned, lent) = both(&plain);
        assert_eq!(lent, owned);
        assert_eq!(owned.0[0].ts_stack, None);
    }

    /// The fixed backing's refusal holds on the lent path too: a Query that would
    /// owe a Final the table has no room for is refused before a queryable runs,
    /// and counted.
    #[cfg(feature = "bounded-heapless")]
    #[test]
    fn a_lent_query_past_pending_finals_is_refused_before_a_queryable_runs() {
        let request = RequestQueryBuilder::new(21, 0, Some("demo/a"))
            .build()
            .expect("build");
        let wire = request
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
            .expect("a fixture request is encodable");
        let decoded = RequestView::decode(&mut SceCursor::new(&wire)).expect("the record decodes");
        let (mut reg, log) = recording();
        let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
        for rid in 0..crate::caps::MAX_PENDING_FINALS as u64 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        reg.dispatch_iteration_event(
            IterationEvent::InPlace(InPlaceRecord::request_of_frame(
                &decoded,
                true,
                0,
                crate::qos::Priority::DEFAULT,
            )),
            &peer(),
            &mut replies,
            &mut finals,
        );
        let ran = log.lock().expect("not poisoned").len();
        assert_eq!(
            (ran, replies.staged(), finals.owed(), finals.refusals()),
            (0, 0, crate::caps::MAX_PENDING_FINALS, 1),
            "(handler runs, replies staged, finals owed, requests refused)"
        );
    }
}
