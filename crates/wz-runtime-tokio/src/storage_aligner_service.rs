// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311 A8c-2a — the storage-aligner DRIVER, ANSWER half
//! (§5.11 storage domain, aligner): the AP-side tokio binding that answers a
//! peer replica's alignment query, replying with the entries the peer needs
//! to converge.
//!
//! The no_std kernel ([`wz_session_core::storage_aligner`] +
//! [`StorageState::answer_alignment_query`](wz_session_core::storage_state::StorageState::answer_alignment_query))
//! decodes nothing and emits nothing — it takes a typed
//! [`AlignmentQuery`](wz_session_core::storage_aligner::AlignmentQuery) and
//! returns the full `Vec<AlignmentResponse>` to send back. This module is its
//! tokio binding: an [`AlignerService`] declares a [`Queryable`] on this
//! replica's aligner keyexpr (`@zid/<zid-hex>/<config-fp>/aligner`), and each
//! inbound query is decoded from its attachment
//! ([`decode_alignment_query`](wz_session_core::storage_aligner::wire::decode_alignment_query)),
//! answered by the kernel, and every response emitted on the reply seam
//! ([`ReplyOut::reply_keyed_attached`](wz_session_core::query_sink::ReplyOut::reply_keyed_attached)):
//! the serialized
//! [`AlignmentReply`](wz_session_core::storage_aligner::AlignmentReply) rides
//! the reply attachment, the retrieved value (if any) rides the payload. It
//! shares the live [`crate::storage_service::StorageService`] state (via
//! [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state)),
//! so the answer reflects the actual stored data. Dropping the service
//! undeclares the queryable (RAII teardown).
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `Replication::spawn_aligner_queryable` +
//! `Replication::aligner`
//! (`plugins/zenoh-plugin-storage-manager/src/replication/core.rs:415-467`
//! and `core/aligner_query.rs:73-172`): the queryable is declared on the
//! `aligner_key_expr_formatter` `@zid/${zid:*}/${hash_configuration:*}/aligner`
//! (core.rs:47) with `allowed_origin(Locality::Remote)` (core.rs:444); a query
//! with an empty attachment is skipped (core.rs:460-462, aligner_query.rs:74-80);
//! otherwise the attachment is deserialized into an `AlignmentQuery` and the
//! matching reply(s) are emitted via `reply_to_query`
//! (aligner_query.rs:340-362): `q.reply(q.key_expr(), value).encoding(enc)
//! .attachment(bincode(reply))` for a retrieval, or an empty-payload
//! `q.reply(q.key_expr(), ZBytes::new()).attachment(bincode(reply))` for a
//! metadata-only reply.
//!
//! ## Deliberate divergences (each documented)
//!
//! - **Callback-driven, not a `recv_async` loop with a task per query.** zenoh
//!   loops `while queryable.recv_async()` and spawns a fresh task per received
//!   query (core.rs:459-467) because its answer awaits an async `RwLock` over
//!   the replication log / storage. wz's [`StorageState::answer_alignment_query`]
//!   is synchronous and pure over the locked snapshot — it returns the full
//!   `Vec<AlignmentResponse>` in one shot with no awaits mid-answer — so the
//!   session's queryable registry fires the answer closure directly. There is
//!   no per-query task to spawn and nothing to block the drive loop.
//! - **No replication log.** zenoh reads `EventMetadata` and `Fingerprint`s out
//!   of its `LogLatest` (aligner_query.rs:106-264). wz has no log; the kernel
//!   recomputes interval / sub-interval buckets + `EventMetadata` from the
//!   `StorageState.latest` snapshot (the [`wz_session_core::storage_aligner`]
//!   divergence note). This module is unaffected — it consumes the kernel's
//!   `Vec`, however the kernel produced it.
//!
//! ## NON-goals (this atom, A8c-2a)
//!
//! The ASK side — `spawn_query_replica_aligner` (the pull loop) +
//! [`process_alignment_reply`](wz_session_core::storage_state::StorageState::process_alignment_reply)
//! follow (A8c-2b) — and the
//! [`DigestSubscriber`](crate::storage_replication_service::DigestSubscriber)
//! `on_diff` → ask-loop wiring + facade forward (A8c-2c). This atom is the
//! answer queryable only.

use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::locality::Locality;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::storage_aligner::wire::{decode_alignment_query, encode_alignment_reply};
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_replication::{zid_to_zenoh_hex, ReplicationConfig};
use wz_session_core::storage_state::StorageState;

use crate::session::{Queryable, QueryableError, QueryableOptions, Session, Unicast};
use crate::session_glue::SessionLinkActions;
use crate::storage_service::wall_clock_ntp64;

/// The keyexpr this replica's aligner queryable answers on:
/// `@zid/<zid-hex>/<config-fp>/aligner`. zenoh `aligner_key_expr_formatter`
/// `@zid/${zid:*}/${hash_configuration:*}/aligner` (core.rs:47), filled with
/// this replica's zid and configuration fingerprint — the SAME two values the
/// digest keyexpr carries.
///
/// Both components render through zenoh's `keformat` `set<S: Display>`: the zid
/// via zenoh's `ZenohId` Display (the
/// [`zid_to_zenoh_hex`](wz_session_core::storage_replication::zid_to_zenoh_hex)
/// SSOT — LE id read as a `u128`, big-endian hex, one leading zero stripped,
/// NOT a naive per-byte hex) and the fingerprint via the `u64`'s decimal
/// `Display` (`Fingerprint` `Deref`s to `u64`). Using the shared SSOT keeps
/// this byte-identical to a real zenoh's keyexpr and consistent with the
/// digest keyexpr + the aligner's `AlignmentReply::Discovery` zid encoding, so
/// an asker querying `@zid/<our-zid>/<fp>/aligner` reaches this queryable.
pub fn aligner_keyexpr(config: &ReplicationConfig, local_zid: &[u8]) -> String {
    format!(
        "@zid/{}/{}/aligner",
        zid_to_zenoh_hex(local_zid),
        config.fingerprint().value()
    )
}

/// Answer one inbound alignment query: decode the `AlignmentQuery` from the
/// query attachment, run the kernel answer engine over the locked shared
/// state, and emit every [`AlignmentResponse`](wz_session_core::storage_aligner::AlignmentResponse)
/// on the reply seam. `now` is the wall-clock NTP64 the kernel uses for the
/// Hot-era upper bound in a `Diff` answer (injected so the answer is
/// deterministically testable). Pure over the shared state: no Session, no
/// clock — the testable core of the queryable callback.
///
/// A query with no attachment, or an attachment that fails to decode, produces
/// no replies (zenoh skips it: core.rs:460-462 + aligner_query.rs:74-91) —
/// never fatal. Each response's reply keyexpr is the query's own keyexpr (the
/// aligner keyexpr the query arrived on), matching zenoh's
/// `q.reply(q.key_expr(), ..)` (aligner_query.rs:351/356); a metadata-only
/// response (every reply but a Put `Retrieval`) carries an empty payload, the
/// retrieved value (a Put `Retrieval`) carries its payload + encoding. The
/// serialized `AlignmentReply` always rides the attachment.
fn answer_alignment_into<B: StorageBackend>(
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    local_zid: &[u8],
    view: &dyn QueryView,
    out: &mut dyn ReplyOut,
    now: u64,
) {
    let query_bytes = match view.attachment() {
        Some(bytes) => bytes,
        // zenoh skips a query with an empty attachment (core.rs:460-462,
        // aligner_query.rs:74-80) — there is nothing to align against.
        None => return,
    };
    let query = match decode_alignment_query(query_bytes) {
        Ok(query) => query,
        // A malformed attachment is logged + dropped by zenoh
        // (aligner_query.rs:82-91); here it is ignored, never fatal.
        Err(_) => return,
    };

    let responses = {
        let guard = state.lock().expect("storage state mutex poisoned");
        guard.answer_alignment_query(config, &query, local_zid, now)
    };

    for response in responses {
        let attachment = encode_alignment_reply(&response.reply);
        match &response.value {
            // A Put Retrieval: the stored value rides the payload (+ encoding),
            // the AlignmentReply rides the attachment.
            Some(value) => out.reply_keyed_attached(
                view.keyexpr(),
                &value.payload,
                value.encoding.as_ref(),
                &attachment,
            ),
            // A metadata-only reply (Discovery / Intervals / SubIntervals /
            // EventsMetadata / a Delete Retrieval): an empty-payload Put
            // carrying only the AlignmentReply attachment.
            None => out.reply_keyed_attached(view.keyexpr(), &[], None, &attachment),
        }
    }
}

/// A live aligner answer service bound to a [`Session`]: a [`Queryable`] on
/// this replica's aligner keyexpr (`@zid/<zid-hex>/<config-fp>/aligner`) that
/// answers a peer's [`AlignmentQuery`](wz_session_core::storage_aligner::AlignmentQuery)
/// with the entries it needs to converge. Dropping it undeclares the queryable
/// (RAII teardown), so the service's lifetime is the handle's lifetime.
///
/// The queryable uses [`Locality::Remote`] so a replica does not answer its
/// OWN alignment queries (zenoh `allowed_origin(Locality::Remote)`,
/// core.rs:444), and is left INCOMPLETE (zenoh declares the aligner queryable
/// without `.complete(..)`, core.rs:441-444): an asker targets a specific
/// replica's fully-qualified aligner keyexpr, so the BestMatching completeness
/// signal is irrelevant here.
pub struct AlignerService<R: SessionRuntime, T: TimeSource> {
    _queryable: Queryable<R, T>,
}

impl<R, T> AlignerService<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare the aligner answer queryable. `state` is shared with the
    /// [`StorageService`](crate::storage_service::StorageService) (pass its
    /// `shared_state()`), so each answer reflects the live stored data.
    /// `config` + `local_zid` fix the queryable keyexpr (this replica's
    /// [`aligner_keyexpr`]) and the `AlignmentReply::Discovery` identity; both
    /// must match what this replica publishes on its digest keyexpr so an asker
    /// reaches the right queryable.
    pub fn declare<B>(
        session: &Session<R, T, Unicast>,
        state: Arc<Mutex<StorageState<B>>>,
        config: ReplicationConfig,
        local_zid: Vec<u8>,
    ) -> Result<Self, QueryableError>
    where
        B: StorageBackend + Send + 'static,
    {
        let keyexpr = aligner_keyexpr(&config, &local_zid);
        let queryable = session.declare_queryable(
            keyexpr,
            QueryableOptions::default().with_allowed_origin(Locality::Remote),
            move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                // `now` is read at answer time for the Hot-era upper bound a
                // `Diff` answer needs; the pure core is tested with a fixed one.
                answer_alignment_into(&state, &config, &local_zid, view, out, wall_clock_ntp64());
            },
        )?;
        Ok(Self {
            _queryable: queryable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::query_sink::BorrowedQuery;
    use wz_session_core::sample::{EncodingHint, TimestampHint};
    use wz_session_core::storage_aligner::wire::encode_alignment_query;
    use wz_session_core::storage_aligner::{AlignmentQuery, AlignmentReply};
    use wz_session_core::storage_backend::MemoryStorage;

    fn cfg() -> ReplicationConfig {
        ReplicationConfig::new("demo/**", None, 20, 5, 6, 30, 250)
    }

    /// One recorded `reply_keyed_attached` emit:
    /// `(keyexpr, payload, encoding packed_id, attachment bytes)`. Factored to
    /// a `type` per `clippy::type_complexity`.
    type RecordedReply = (String, Vec<u8>, Option<u32>, Vec<u8>);

    /// A reply recorder capturing each `reply_keyed_attached` emit.
    #[derive(Default)]
    struct RecordingReplies {
        keyed_attached: Vec<RecordedReply>,
        plain: u32,
    }

    impl ReplyOut for RecordingReplies {
        fn reply(&mut self, _payload: &[u8]) {
            self.plain += 1;
        }
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _encoding_id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {
        }
        fn reply_keyed_attached(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&EncodingHint>,
            attachment: &[u8],
        ) {
            self.keyed_attached.push((
                keyexpr.to_string(),
                payload.to_vec(),
                encoding.map(|e| e.packed_id),
                attachment.to_vec(),
            ));
        }
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn query_view<'a>(keyexpr: &'a str, attachment: Option<&'a [u8]>) -> BorrowedQuery<'a> {
        BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment,
            source_info: None,
            rid: 1,
            is_local: false,
        }
    }

    fn state_with_put(
        key: &str,
        payload: Vec<u8>,
        now: u64,
    ) -> Arc<Mutex<StorageState<MemoryStorage>>> {
        let mut st = StorageState::new(MemoryStorage::new());
        st.process_put(
            key,
            payload,
            None,
            TimestampHint {
                time: now,
                zid: vec![0x01],
            },
        );
        Arc::new(Mutex::new(st))
    }

    #[test]
    fn aligner_keyexpr_is_zenoh_formatted() {
        let config = cfg();
        // The zid renders via zenoh's ZenohId Display (LE -> u128 -> big-endian
        // hex): [0x01, 0xab] -> u128 0xab01 -> "ab01", NOT a per-byte "01ab".
        let ke = aligner_keyexpr(&config, &[0x01, 0xab]);
        assert_eq!(
            ke,
            format!("@zid/ab01/{}/aligner", config.fingerprint().value())
        );
    }

    #[test]
    fn discovery_emits_one_empty_payload_reply_carrying_the_zid() {
        let config = cfg();
        let zid = vec![0x07];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1, 2, 3], now);
        let ke = aligner_keyexpr(&config, &zid);

        let query = encode_alignment_query(&AlignmentQuery::Discovery);
        let view = query_view(&ke, Some(&query));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);

        // Exactly one Discovery reply: empty payload, no encoding, attachment =
        // the serialized AlignmentReply::Discovery(zid), on the aligner keyexpr.
        assert_eq!(out.keyed_attached.len(), 1);
        let (got_ke, got_payload, got_enc, got_attach) = &out.keyed_attached[0];
        assert_eq!(got_ke, &ke);
        assert!(
            got_payload.is_empty(),
            "a metadata-only reply has no payload"
        );
        assert_eq!(*got_enc, None);
        assert_eq!(
            got_attach,
            &encode_alignment_reply(&AlignmentReply::Discovery(zid.clone()))
        );
        assert_eq!(
            out.plain, 0,
            "the aligner only emits via reply_keyed_attached"
        );
    }

    #[test]
    fn all_retrieval_carries_value_and_matches_the_kernel_one_for_one() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![9, 8, 7], now);
        let ke = aligner_keyexpr(&config, &zid);

        // The kernel's own answer for the SAME All query is the ground truth.
        let expected =
            state
                .lock()
                .unwrap()
                .answer_alignment_query(&config, &AlignmentQuery::All, &zid, now);
        assert!(
            !expected.is_empty(),
            "an All query over a stored Put yields at least one Retrieval"
        );

        let query = encode_alignment_query(&AlignmentQuery::All);
        let view = query_view(&ke, Some(&query));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);

        assert_eq!(
            out.keyed_attached.len(),
            expected.len(),
            "one reply_keyed_attached per kernel response"
        );
        for (got, response) in out.keyed_attached.iter().zip(expected.iter()) {
            assert_eq!(&got.0, &ke, "reply keyexpr is the query keyexpr");
            let (exp_payload, exp_enc) = match &response.value {
                Some(v) => (v.payload.clone(), v.encoding.as_ref().map(|e| e.packed_id)),
                None => (Vec::new(), None),
            };
            assert_eq!(got.1, exp_payload);
            assert_eq!(got.2, exp_enc);
            assert_eq!(got.3, encode_alignment_reply(&response.reply));
        }
        // The stored value (a Put) is carried back on at least one reply.
        assert!(
            out.keyed_attached
                .iter()
                .any(|(_, p, _, _)| p == &[9, 8, 7]),
            "the stored Put's value rides a Retrieval reply payload"
        );
    }

    #[test]
    fn empty_attachment_query_is_skipped() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1], now);
        let ke = aligner_keyexpr(&config, &zid);

        let view = query_view(&ke, None);
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);
        assert!(
            out.keyed_attached.is_empty() && out.plain == 0,
            "a query with no attachment is skipped (nothing to align)"
        );
    }

    #[test]
    fn corrupt_attachment_query_is_ignored() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1], now);
        let ke = aligner_keyexpr(&config, &zid);

        let view = query_view(&ke, Some(&[0xff, 0x00, 0x01]));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);
        assert!(
            out.keyed_attached.is_empty() && out.plain == 0,
            "an undecodable attachment is ignored, not fatal"
        );
    }

    // A REAL live-session test: the aligner service declares its queryable on
    // the aligner keyexpr against a session. The cross-session answer (a remote
    // peer's AlignmentQuery -> reply) needs a TWO-INSTANCE e2e (the queryable is
    // Remote-only, so a single-session loopback cannot exercise it by
    // construction); that rides the storage-aligner track's live convergence
    // e2e. Here the decode / answer / emit core is covered by the unit tests
    // above; this asserts the declare wiring.
    #[test]
    fn aligner_service_declares_on_the_aligner_keyexpr() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let config = cfg();
        let state = Arc::new(Mutex::new(StorageState::new(MemoryStorage::new())));
        let aligner = AlignerService::declare(&session, state, config, vec![0x01]);
        assert!(
            aligner.is_ok(),
            "the aligner answer queryable declares on @zid/<zid>/<fp>/aligner"
        );
    }
}
