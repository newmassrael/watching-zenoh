// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an advanced subscriber reads and writes around the gets it asks: the `@adv` publisher
//! token a liveliness sample names, the selector of a history get, a reply turned back into a
//! sample, the timeout of a get, and the bookkeeping of the gets in flight.
//!
//! Each is a plain function or value over strings, numbers and a sample, so the host that issues
//! the get (a runtime session's `query` or an engine's `get_on_wire`) does not decide any of it
//! again.

#[cfg(feature = "advanced-recovery")]
use std::collections::HashSet;
#[cfg(feature = "advanced-recovery")]
use std::sync::Mutex;
#[cfg(feature = "advanced-recovery")]
use std::time::Duration;

#[cfg(feature = "advanced-recovery")]
use wz_session_core::reply_sink::{ReplyKind, ReplyView};
#[cfg(feature = "advanced-recovery")]
use wz_session_core::sample::{EncodingHint, Sample};
#[cfg(feature = "advanced-recovery")]
use wz_session_core::zid_hex::zenoh_hex_to_zid;

/// R311y89 (review C3) — convert a `RecoveryConfig::query_timeout` `Duration`
/// into the `QueryOptions::with_timeout_ms` `u32` ms value, clamped to
/// `[1, u32::MAX]`. The upper clamp keeps the cast lossless (the
/// `with_timeout_ms` field is `u32`).
///
/// R311y326 — the lower clamp's original correctness bite is superseded but the
/// clamp is kept. It said a `0` (a zero / sub-ms `Duration` truncates to `0`)
/// was the `timeout_ms == 0` "never-expire" sentinel that would wedge a
/// no-answerer recovery GET forever. `ext-pubsub-advanced-recovery` composes
/// `query-timeout` (Cargo.toml), so `QueryOptions::effective_timeout_ms` now
/// resolves a `0` to `DEFAULT_QUERY_TIMEOUT_MS` — a `0` would inherit the 10s
/// platform default, not never-expire, so it can no longer wedge. The clamp
/// stays because a recovery GET should carry ITS configured timeout, not fall
/// back to the platform default; `>= 1` pins that intent (a zero-Duration config
/// still yields a live 1 ms deadline rather than silently becoming 10s).
#[cfg(feature = "advanced-recovery")]
pub fn recovery_query_timeout_ms(query_timeout: Duration) -> u32 {
    query_timeout.as_millis().clamp(1, u32::MAX as u128) as u32
}

/// Rebuild a recovery / history reply as a [`Sample`], field for field. `None`
/// for an Err reply. Shared by the recovery and history GETs.
///
/// R2554 — it decides NOTHING about ordering, and that is the point. It used to
/// return `Option<((Vec<u8>, u32), u32, Sample)>` and so had to open with
/// `reply.source_info()?`, dropping every reply without one — which is exactly
/// a timestamped publisher's whole cache. R2553 replaced the tuple with an enum
/// that named both shapes; R2554 removes the fork from here altogether, because
/// a reply is just a sample and `State::route_sample` is where a sample's
/// shape is read. Upstream's GET callbacks do the same thing by construction:
/// they hand the sample straight to `handle_sample`.
///
/// R311y561 — the DEL arm. A Del reply is now rebuilt as a Del sample rather
/// than discarded: the `@adv` cache retains deletes since
/// `CachedSample` carries the sample kind, so a
/// recovering subscriber sees the retraction it missed instead of silently
/// keeping a resurrected value. This is also why the `ReplyKind` test is now an
/// Err-exclusion rather than a Put-only admission.
///
/// R311y561 also RESTORES the timestamp. The R311y95 note below said a recovered
/// sample "arrives timestamp-less" because "the `ReplyView` exposes no
/// reply-timestamp accessor" — that ceased to be true at R311y321, which added
/// [`ReplyView::timestamp`], and the prose outlived the fact by rounds. The
/// cached timestamp is re-applied here.
///
/// R311y562 CLOSES the last of it, and the fix was never on this side.
/// `CachedSample` now retains the `encoding` and the
/// `attachment` too, and the recovery reply carries both
/// (`wz_session_core::query_sink::ReplyMeta`), so the two re-applications
/// below finally receive something. They were written at R311y95 and had been
/// dead code ever since — the reply could not carry what the ring never kept,
/// which is why the gap survived a reader who checked only this function. A
/// recovered sample is now field-for-field the live one, minus nothing.
///
/// The Del arm carries neither, and that is the WIRE's rule rather than a
/// residual: `_z_push_body_encode` gates `has_attachment` on `_is_put` and
/// reads the encoding only inside the `_is_put` branch
/// (`vendor/zenoh-pico/src/protocol/codec/message.c:263,269-276`).
#[cfg(feature = "advanced-recovery")]
pub fn recovered_sample_from_reply(reply: &dyn ReplyView) -> Option<Sample> {
    let kind = reply.kind();
    if kind == ReplyKind::Err {
        return None;
    }
    // A recovered reply's bytes are held, not copied, when the reply holds them
    // shareable (a reply off the wire is a range of the frame it arrived in), so
    // the recovered sample is a second reference to that storage as a live one is.
    let mut sample = match kind {
        ReplyKind::Del => Sample::new_del(reply.keyexpr()),
        _ => Sample::new_put_shared(
            reply.keyexpr(),
            reply
                .payload_shared()
                .cloned()
                .unwrap_or_else(|| wz_session_core::link::RxBytes::from(reply.payload().to_vec())),
        ),
    };
    sample.source_info = reply.source_info().cloned();
    sample.timestamp = reply.timestamp().cloned();
    sample.attachment = reply.attachment_shared().cloned().or_else(|| {
        reply
            .attachment()
            .map(|bytes| wz_session_core::link::RxBytes::from(bytes.to_vec()))
    });
    if let Some((packed_id, schema)) = reply.put_encoding() {
        sample.encoding = Some(EncodingHint {
            packed_id,
            schema: schema.map(String::from),
        });
    }
    Some(sample)
}

/// Build the startup history GET selector from the `_max` cap (`sample_depth`)
/// and the `_time` age bound (`max_age`). The `_time` form `[now(-{age}s)..]`
/// is byte-identical to zenoh's `TimeRange<TimeExpr>` Display of
/// `[Inclusive(Now{offset_secs:-age})..]` (zenoh-util time_range.rs:128-141/
/// 327-339), so a wz cache and a zenoh cache both filter it exactly.
///
/// R311y442 — two changes, and both are what makes the GET legible to a real
/// zenoh cache. The parts are `;`-joined, not `&`-joined (upstream's separator;
/// see [`wz_session_core::selector_params`]), and the list ALWAYS carries the bare
/// `_anyke` flag. The return is therefore no longer `Option`: even with neither
/// knob set the GET must announce that it accepts replies keyed outside the
/// `@adv` namespace it is addressed to, because that is how every cached sample
/// comes back. Without it zenoh's responder refuses each reply and the
/// subscriber recovers nothing at all — measured as 5 refusals against 5 cached
/// samples on a `z_advanced_pub` oracle.
#[cfg(feature = "advanced-history")]
pub fn history_selector(sample_depth: Option<usize>, max_age: Option<f64>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(max) = sample_depth {
        parts.push(format!("_max={max}"));
    }
    if let Some(age) = max_age {
        // R311y442 review (REVIEWER 1, finding 6) — upstream's `TimeExpr` Display
        // special-cases a zero offset to `now()` rather than `now(-0s)`
        // (zenoh-util/src/time_range.rs:333-339), and IEEE `-0.0 == 0.0` so a
        // `max_age(0.0)` lands there. The two forms parse to the same instant, so
        // this is byte-parity rather than a behaviour change — but the emitted
        // selector is the thing a foreign peer logs and a future diff compares.
        if age == 0.0 {
            parts.push("_time=[now()..]".to_string());
        } else {
            parts.push(format!("_time=[now(-{age}s)..]"));
        }
    }
    wz_session_core::selector_params::anyke_params(&parts)
}

/// R311y592 — the subscriber's in-flight recovery / history GETs, and the seam
/// a teardown cancels them through.
///
/// This is pico's `_ze_advanced_subscriber_state_t::_cancellation_token`: ONE
/// per subscriber state, carried by every recovery / history GET the subscriber
/// issues (`vendor/zenoh-pico/src/api/advanced_subscriber.c:924-928`) and
/// cancelled in the subscriber's drop handler (`advanced_subscriber.c:1230-1231`)
/// so that every resource is released by the time undeclare returns.
///
/// wz reaches the same guarantee through the registration rather than through a
/// token object, because a session's `cancel_pending_query` already IS this
/// tree's cancellation primitive and pico's own token bottoms out in the same
/// place (`_z_cancel_pending_query` is `_z_unregister_pending_query`,
/// `vendor/zenoh-pico/src/session/query.c:290-298`). Adding a second mechanism
/// would leave two spellings of one idea.
///
/// Why this matters beyond tidiness: `State` owns `on_sample`, and at the C
/// ABI that is a C function pointer plus a context the application may free the
/// moment `ze_undeclare_advanced_subscriber` returns. An in-flight GET keeps its
/// own `Arc<Mutex<State>>`, so without this a reply landing one instant after
/// the undeclare called into freed memory.
#[cfg(feature = "advanced-recovery")]
pub struct PendingGets {
    /// `Some` while the subscriber is live, `None` once cancelled. ONE optional
    /// rather than a set plus a `cancelled` flag, so the two can never disagree
    /// under a concurrent cancel — the discipline `wz-capi-pico`'s `CancelFan`
    /// applies to the C `z_get` fan, for the same reason.
    inner: Mutex<Option<InFlight>>,
}

/// The live half of [`PendingGets`].
///
/// Two sets rather than one because a GET can COMPLETE BEFORE IT IS RECORDED: a
/// `Locality::SessionLocal` / `Any` query is answered by the loopback inside
/// the session's `query`, so `on_final` can run before the call returns the rid
/// there is to record. `finished_early` absorbs exactly that ordering; every
/// entry in it is removed by the matching `record`, so it cannot accumulate.
#[cfg(feature = "advanced-recovery")]
#[derive(Default)]
struct InFlight {
    /// Issued, not yet terminal — the set a teardown must cancel.
    live: HashSet<u64>,
    /// Terminal before `record` saw them (the synchronous-loopback ordering).
    finished_early: HashSet<u64>,
}

#[cfg(feature = "advanced-recovery")]
impl Default for PendingGets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "advanced-recovery")]
impl PendingGets {
    /// A table that holds no GET and accepts them.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Some(InFlight::default())),
        }
    }

    /// Lock, recovering from poisoning rather than propagating it.
    ///
    /// A panic in a reply callback poisons this mutex, and the guard below runs
    /// in `Drop` — where a second panic would abort the process. The data behind
    /// it is two sets of `u64` with no cross-field invariant a panic can leave
    /// half-applied, so the poisoned guard is exactly as usable as a healthy one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<InFlight>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record a GET that has just been issued. `false` means the subscriber was
    /// torn down while this GET was going out, and the caller must undo the
    /// registration it just made rather than leave a live pending query behind.
    pub fn record(&self, rid: u64) -> bool {
        match self.lock().as_mut() {
            Some(in_flight) => {
                // Already terminal (the loopback answered inside `query`): there
                // is nothing left to cancel, so consume the marker instead of
                // adding a rid that would never be removed.
                if !in_flight.finished_early.remove(&rid) {
                    in_flight.live.insert(rid);
                }
                true
            }
            None => false,
        }
    }

    /// A GET reached its terminal Final: forget it.
    pub fn finish(&self, rid: u64) {
        if let Some(in_flight) = self.lock().as_mut() {
            if !in_flight.live.remove(&rid) {
                in_flight.finished_early.insert(rid);
            }
        }
    }

    /// Take every still-outstanding rid and refuse all future ones. Idempotent:
    /// a second call answers with an empty list.
    pub fn cancel(&self) -> Vec<u64> {
        match self.lock().take() {
            Some(in_flight) => in_flight.live.into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// `(live, finished_early)` sizes. Test-only: the two sets are the whole
    /// state of this type, and a test that asserts only on `live` cannot see
    /// `finished_early` growing without bound.
    ///
    /// Public, because the tests of the host that issues the gets are in another
    /// crate and a test that asserts only on `live` cannot see `finished_early`
    /// growing without bound; it reads two lengths and changes nothing.
    pub fn sizes(&self) -> (usize, usize) {
        match self.lock().as_ref() {
            Some(in_flight) => (in_flight.live.len(), in_flight.finished_early.len()),
            None => (0, 0),
        }
    }
}

/// R2552 — WHICH SHAPE of `@adv` publisher a token key expression names.
///
/// The `<eid|uhlc>` chunk is a discriminator, not a number: wz's own publisher
/// writes `eid.to_string()` for `Sequencing::SequenceNumber` and the literal
/// `uhlc` for `Sequencing::Timestamp | Sequencing::None`
/// (`crates/wz-ext-pubsub/src/advanced_publisher.rs` @ `let discriminator = match options.sequencing {`),
/// and upstream splits on exactly that — `zenoh-ext/src/advanced_subscriber.rs` @ `if parsed.eid() == KE_UHLC {`.
///
/// THIS TYPE EXISTS BECAUSE ITS ABSENCE MADE THE TIMESTAMPED SHAPE
/// UNEXPRESSIBLE. [`parse_heartbeat_source`] returned `Option<(Vec<u8>, u32)>`,
/// so the only way to report a `uhlc` token was `None` — indistinguishable from
/// a malformed key expression. Two of wz's own three sequencing modes emit that
/// token, so a wz timestamped or unsequenced advanced publisher announced
/// itself and wz's own advanced subscriber discarded the announcement. The
/// handling of that shape is a later part; being able to NAME it is this one,
/// and each caller now says which shapes it serves rather than being handed a
/// pair it cannot question.
///
/// R2555 — AND IT WAS STILL ONE ARM SHORT, which the paragraph above predicts
/// without noticing: upstream branches THREE ways here and this type offered
/// TWO, so "an `@adv/pub` token whose zid I cannot read" had no spelling but
/// `None` — the very sentence above, one case later. Upstream's third arm,
/// `zenoh-ext/src/advanced_subscriber.rs` @ `} else if s.kind() == SampleKind::Put {`,
/// still queries such a publisher's cache; it simply accounts for it globally,
/// because with no identity there is no per-source slot to open.
///
/// THE RULE THIS LEAVES BEHIND, since the defect has now recurred three times
/// in as many rounds (a parser tuple that hid `uhlc`, a reply tuple that hid
/// the timestamped shape, and this): when wz mirrors an upstream dispatch, the
/// wz type needs ONE VARIANT PER UPSTREAM ARM, and the check is to count the
/// arms at the upstream branch rather than to enumerate the cases wz happened
/// to notice.
#[cfg(feature = "advanced-recovery")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvPublisherSource {
    /// `<eid>` — sequence-number sequencing, the only shape carrying the
    /// per-source sequence numbers the recovery and heartbeat paths key on.
    Sequenced {
        /// The publisher's zid, decoded from the hex chunk.
        zid: Vec<u8>,
        /// The publisher's entity id.
        eid: u32,
    },
    /// `uhlc` — timestamp / none sequencing, ordered by the timestamp's own id
    /// rather than by a sequence number.
    Timestamped {
        /// The publisher's zid, decoded from the hex chunk.
        zid: Vec<u8>,
    },
    /// R2555 — an `@adv/pub` token whose ZID CHUNK does not decode, so no
    /// per-source state can be keyed for it. Upstream's third arm, and it is
    /// NOT a rejection: the publisher's cache is still queried, accounted
    /// globally instead of per source.
    ///
    /// Distinct from `None` on purpose, and that distinction is the whole
    /// point of the variant. `None` means "this key expression is not an
    /// `@adv/pub` token at all", which is unreachable in practice (the
    /// liveliness subscriber is declared on `<base>/@adv/pub/**`, so nothing
    /// else can arrive) and would have nothing to query if it were. Folding
    /// the two together is what hid this case: one of them is a non-event and
    /// the other is a publisher wz can still recover history from.
    Unidentified,
}

/// R311y84 — parse an `@adv` publisher token keyexpr
/// `<base>/@adv/pub/<zid_hex>/<eid|uhlc>/_` back into its source shape, the wz
/// analogue of zenoh's `ke_liveliness::parse`. Returns `None` only on a
/// MALFORMED key expression (bad `@adv/pub` layout, un-decodable zid hex, or a
/// discriminator that is neither `uhlc` nor a `u32`). The trailing `_` meta
/// chunk and any further chunks are ignored.
///
/// R2552 — the `uhlc` discriminator is now a VALUE rather than a parse failure.
/// It was folded into `None` before, which conflated "this publisher orders by
/// timestamp" with "this key expression is broken"; the two want opposite
/// responses from a caller.
#[cfg(feature = "advanced-recovery")]
pub fn parse_heartbeat_source(keyexpr: &str) -> Option<AdvPublisherSource> {
    let chunks: Vec<&str> = keyexpr.split('/').collect();
    let adv = chunks
        .iter()
        .position(|c| *c == crate::advanced_ke::KE_ADV_PREFIX)?;
    if chunks.get(adv + 1) != Some(&crate::advanced_ke::KE_ADV_PUB) {
        return None;
    }
    // R2555 — a zid chunk that does not decode is the UNIDENTIFIED shape, not a
    // refusal. Upstream reaches its third arm by exactly this test failing
    // (`ZenohId::from_str`), and still queries the publisher's cache.
    let Some(zid) = zenoh_hex_to_zid(chunks.get(adv + 2)?) else {
        return Some(AdvPublisherSource::Unidentified);
    };
    let discriminator = *chunks.get(adv + 3)?;
    if discriminator == crate::advanced_ke::KE_ADV_UHLC {
        return Some(AdvPublisherSource::Timestamped { zid });
    }
    let eid = discriminator.parse::<u32>().ok()?;
    Some(AdvPublisherSource::Sequenced { zid, eid })
}

#[cfg(test)]
mod tests;
