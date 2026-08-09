// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y615 (§1.1f) — the second AGGREGATION plane: Query/Reply EXCHANGES, and
//! the latency of each.
//!
//! [`crate::agg`] answers "what is this capture carrying". This one answers
//! "how long did the other side take", which is the question a passive reader
//! opens a capture to ask when something is slow, and the crate could not
//! answer it at all: a decoded frame carried no time, so no two frames could be
//! subtracted. R311y615 put the capture clock on
//! [`PassiveFrame::observed_at_ms`] first; this module is its first consumer.
//!
//! ## What a `rid` correlates, and in whose space
//!
//! A `Request` carries a `rid` minted by the SENDER, and every `Response` and
//! the closing `ResponseFinal` echo it back in `request_id`. So the key is not
//! the id alone — it is the id PLUS the direction that minted it, exactly as
//! [`crate::agg::KeyexprSpaces`] treats a keyexpr id. Two directions may both
//! be querying, both from 1, and a table keyed on the bare id would merge a
//! request with someone else's reply and produce a latency out of two unrelated
//! events.
//!
//! ```text
//!   A ──Request{rid=7, keyexpr=demo/**}──▶ B     opens (A,7)
//!   A ◀─Response{request_id=7, Reply}──── B      first-reply latency
//!   A ◀─Response{request_id=7, Reply}──── B
//!   A ◀─ResponseFinal{request_id=7}────── B      completion latency, closes it
//! ```
//!
//! ## What the latency IS
//!
//! The interval between two instants AT THE TAP. A tap beside the querier
//! measures that querier's round trip to within its own delay; a tap beside the
//! responder measures almost none of it. Nothing in a capture says which
//! position the tap held, so this plane reports the interval it can defend and
//! names it for the vantage point rather than calling it "the" RTT.
//!
//! ## What is never invented
//!
//! - A frame with no clock ([`PassiveFrame::observed_at_ms`] `None`) yields NO
//!   sample. It is counted in [`ExchangeGaps::unstamped`], because a capture
//!   format that carries no timestamps must not read as a capture whose every
//!   exchange took zero milliseconds.
//! - A completion that precedes its request — an out-of-order capture, a clock
//!   stepped backwards — yields no sample either
//!   ([`ExchangeGaps::non_monotonic`]). A `saturating_sub` would have turned
//!   both into a confident `0`.
//! - A `Response` whose `Request` was never seen is an ORPHAN
//!   ([`ExchangeGaps::orphan_responses`]), the ordinary signature of a capture
//!   started mid-query, and it is reported rather than dropped.
//! - An exchange still open when the flow's frames run out is UNCLOSED
//!   ([`ExchangeTable::unclosed`]), not a completion with a missing half.
//!
//! ## Memory, without a new constant
//!
//! Open exchanges live only for the duration of one [`Self::observe_flow`] call
//! and are keyed within that flow, so the map is bounded by the number of
//! `Request` records in the frames the caller handed in — which the caller
//! already bounds through [`crate::Limits::frames_per_flow`]. A consumer that
//! streams frames without retaining them must therefore call this per flow and
//! per bounded window; that is a real limit and it is stated rather than
//! papered over with a cap number nobody measured.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::network_message::{BatchParse, NetworkMessage};
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

use crate::agg::{KeyexprSpaces, ThroughputGaps};
use crate::filter::{Filter, RecordView, Selection, Truth};

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// A latency distribution, accumulated without keeping every sample.
///
/// `min` / `max` are `Option` rather than sentinel-initialised: a `0` floor on
/// an empty set is a number a reader can print, and printing it would claim a
/// measurement that was never taken.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LatencySamples {
    count: usize,
    min_ms: Option<u64>,
    max_ms: Option<u64>,
    total_ms: u64,
}

impl LatencySamples {
    fn add(&mut self, ms: u64) {
        self.count += 1;
        self.min_ms = Some(match self.min_ms {
            Some(m) => m.min(ms),
            None => ms,
        });
        self.max_ms = Some(match self.max_ms {
            Some(m) => m.max(ms),
            None => ms,
        });
        self.total_ms += ms;
    }

    fn merge(&mut self, other: &Self) {
        if other.count == 0 {
            return;
        }
        self.count += other.count;
        self.total_ms += other.total_ms;
        self.min_ms = match (self.min_ms, other.min_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.max_ms = match (self.max_ms, other.max_ms) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    /// How many intervals went in.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The shortest, or `None` when nothing was sampled.
    pub fn min_ms(&self) -> Option<u64> {
        self.min_ms
    }

    /// The longest, or `None` when nothing was sampled.
    pub fn max_ms(&self) -> Option<u64> {
        self.max_ms
    }

    /// The arithmetic mean, truncated to whole milliseconds, or `None` when
    /// nothing was sampled.
    pub fn mean_ms(&self) -> Option<u64> {
        (self.count > 0).then(|| self.total_ms / self.count as u64)
    }

    /// Every interval summed — the figure a caller needs to re-derive a mean at
    /// a different granularity, and the one a merge is built on.
    pub fn total_ms(&self) -> u64 {
        self.total_ms
    }

    /// `true` when no interval was ever measurable.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// One queried keyexpr's exchange row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRow {
    /// The keyexpr the `Request` named, after alias resolution.
    pub keyexpr: String,
    /// `Request` records opened here.
    pub requests: usize,
    /// Of those, the ones a `ResponseFinal` closed.
    pub completed: usize,
    /// `Response` records carrying a `Reply`.
    pub replies: usize,
    /// `Response` records carrying an `Err`.
    pub errs: usize,
    /// Request → FIRST `Response`. What a querier feels as "time to first
    /// result", and the only latency a streaming query has before it ends.
    pub first_reply: LatencySamples,
    /// Request → `ResponseFinal`. The whole exchange, which for a query that
    /// returns many samples is dominated by the SOURCE's pace rather than by
    /// the network, so it is kept apart from the first-reply figure above.
    pub completion: LatencySamples,
}

impl ExchangeRow {
    fn new(keyexpr: String) -> Self {
        Self {
            keyexpr,
            requests: 0,
            completed: 0,
            replies: 0,
            errs: 0,
            first_reply: LatencySamples::default(),
            completion: LatencySamples::default(),
        }
    }

    /// Requests that this capture never saw closed.
    pub fn unclosed(&self) -> usize {
        self.requests - self.completed
    }
}

/// R311y615 — everything this plane saw and could not turn into a sample, on
/// the rule [`ThroughputGaps`] is written to: a total that is quietly short is
/// indistinguishable from one that is right.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeGaps {
    /// `Response` / `ResponseFinal` whose `Request` this capture never carried.
    pub orphan_responses: usize,
    /// Exchanges that correlated but where one of the two frames had no capture
    /// clock, so no interval exists to measure.
    pub unstamped: usize,
    /// Correlated, stamped, and the later event's clock reads EARLIER than the
    /// first's. No sample, because the only alternatives are a negative
    /// duration or a fabricated zero.
    pub non_monotonic: usize,
    /// `Request` records whose keyexpr did not resolve against either id space,
    /// so the exchange belongs to no row. Tracked for correlation regardless —
    /// its latency is still counted in [`ExchangeTable::totals`].
    pub unattributed_requests: usize,
}

impl ExchangeGaps {
    /// `true` when every record this plane was shown became a row or a sample.
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

/// One exchange awaiting its close, within one flow.
#[derive(Debug, Clone)]
struct OpenExchange {
    /// `None` when the request's keyexpr did not resolve — the exchange is
    /// still correlated and still timed, it just has no row to land in.
    keyexpr: Option<String>,
    requested_at: Option<u64>,
    first_reply_at: Option<u64>,
    replies: usize,
    errs: usize,
}

/// Query/Reply exchanges and their latencies, over one or more flows.
#[derive(Debug, Default, Clone)]
pub struct ExchangeTable {
    rows: BTreeMap<String, ExchangeRow>,
    requests: usize,
    completed: usize,
    replies: usize,
    errs: usize,
    unclosed: usize,
    first_reply: LatencySamples,
    completion: LatencySamples,
    gaps: ExchangeGaps,
    unread: ThroughputGaps,
    selection: Selection,
}

impl ExchangeTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one flow's frames in, in capture order.
    ///
    /// The unit is a FLOW and not a frame for the reason
    /// [`crate::agg::ThroughputTable::observe_flow`] gives: request ids and
    /// keyexpr ids are both per-session spaces, and one map across two sessions
    /// would correlate a request with a stranger's reply.
    pub fn observe_flow(&mut self, frames: &[PassiveFrame]) {
        self.observe_flow_where(frames, &Filter::any())
    }

    /// R311y618 (§1.1q) — the same correlation, over the exchanges a selector
    /// picks.
    ///
    /// ## The unit judged is the EXCHANGE, and the REQUEST is what carries it
    ///
    /// A selector is asked ONCE PER EXCHANGE, at its `Request`, and the
    /// responses follow whatever the request's verdict was. This is the rule
    /// R311y616 left undecided, and the alternative — judging each `Response`
    /// on its own — is not merely different, it is unsound here: a `Response`
    /// identifies itself by `request_id` and its keyexpr field is the
    /// responder's, so a `key ==` term could admit a request and reject its own
    /// reply, leaving a completion latency measured against an exchange the
    /// table says never happened.
    ///
    /// ## What a rejected exchange does NOT do
    ///
    /// It does not become an orphan. The responses to a suppressed request are
    /// dropped WITHOUT touching [`ExchangeGaps::orphan_responses`], because
    /// that counter means "this capture began mid-query" and a selector that
    /// manufactured it out of its own choice would make the number unreadable
    /// — the reader could no longer tell a truncated capture from a narrow
    /// question. For the same reason a suppressed exchange is never
    /// [`Self::unclosed`].
    ///
    /// ## Where the filter still does not reach
    ///
    /// Batch-level loss is unfiltered, exactly as in [`crate::agg`]: a halted
    /// batch is traffic no predicate can be evaluated against, so it stays in
    /// [`Self::unread`]. [`ExchangeGaps::unattributed_requests`] DOES follow
    /// the selection, and the difference is principled — that record was read,
    /// and a filter can judge it (to [`Truth::Unknown`] at worst, which
    /// [`Self::selection`] counts).
    pub fn observe_flow_where(&mut self, frames: &[PassiveFrame], filter: &Filter) {
        let mut spaces = KeyexprSpaces::new();
        let mut open: BTreeMap<(usize, u64), OpenExchange> = BTreeMap::new();
        let mut suppressed: BTreeSet<(usize, u64)> = BTreeSet::new();
        for frame in frames {
            match &frame.carried {
                Carried::Batch(batch) => self.observe_batch(
                    &mut spaces,
                    &mut open,
                    &mut suppressed,
                    frame,
                    batch,
                    filter,
                ),
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => self.observe_batch(
                    &mut spaces,
                    &mut open,
                    &mut suppressed,
                    frame,
                    batch,
                    filter,
                ),
                // Matched by name for the reason R311y614 matched them by name
                // in the throughput plane: a new `Carried` variant must fail to
                // compile here rather than join the silent set.
                Carried::Undecompressible => self.unread.undecompressible_batches += 1,
                #[cfg(feature = "reassembly")]
                Carried::FragmentWithoutResolution => self.unread.unresolvable_fragments += 1,
                Carried::Nothing => {}
                #[cfg(feature = "reassembly")]
                Carried::Fragment(_) => {}
            }
        }
        // Whatever is still open when the flow's frames run out was never
        // closed on the wire this observer saw. Counted, never completed: a
        // query whose reply the capture missed is not a query that answered
        // instantly.
        self.unclosed += open.len();
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_batch(
        &mut self,
        spaces: &mut KeyexprSpaces,
        open: &mut BTreeMap<(usize, u64), OpenExchange>,
        suppressed: &mut BTreeSet<(usize, u64)>,
        frame: &PassiveFrame,
        batch: &BatchParse,
        filter: &Filter,
    ) {
        if batch.halt.is_some() {
            self.unread.halted_batches += 1;
            self.unread.unparsed_bytes += batch.unparsed_bytes;
        }
        for message in &batch.messages {
            self.observe_message(spaces, open, suppressed, frame, message, filter);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_message(
        &mut self,
        spaces: &mut KeyexprSpaces,
        open: &mut BTreeMap<(usize, u64), OpenExchange>,
        suppressed: &mut BTreeSet<(usize, u64)>,
        frame: &PassiveFrame,
        message: &NetworkMessage,
        filter: &Filter,
    ) {
        let direction = frame.direction;
        let at = frame.observed_at_ms;
        match message {
            NetworkMessage::Declare(d) => spaces.absorb(direction, d),
            NetworkMessage::Request(r) => {
                let key = (dir_index(direction), r.rid);
                let resolved = spaces.resolve(direction, &r.keyexpr.body);
                // The filter is asked AFTER resolution, because a `key` term
                // needs the resolved name, and BEFORE any counter moves,
                // because a rejected exchange must leave no trace in the
                // totals. The record's kind and payload size come from the
                // THROUGHPUT plane's classifier so `kind == query` means the
                // same thing whichever plane a reader points it at.
                let (kind, payload_bytes) = match crate::agg::classify(message) {
                    Some((_, counts, kind)) => (kind, counts.payload_bytes),
                    None => (crate::filter::RecordKind::Query, 0),
                };
                let view = RecordView {
                    direction,
                    keyexpr: resolved.as_ref().ok().map(|k| k.as_str()),
                    kind,
                    payload_bytes,
                    observed_at_ms: at,
                };
                let truth = filter.matches(&view);
                self.selection.record(truth);
                if truth != Truth::Yes {
                    // Remember the rid so this exchange's own responses are
                    // dropped in silence rather than counted as orphans, and
                    // drop any earlier exchange this rid reopened — an
                    // un-admitted request cannot leave a predecessor behind to
                    // be reported unclosed.
                    suppressed.insert(key);
                    open.remove(&key);
                    return;
                }
                suppressed.remove(&key);
                let keyexpr = match resolved {
                    Ok(k) => Some(k),
                    Err(_) => {
                        self.gaps.unattributed_requests += 1;
                        None
                    }
                };
                self.requests += 1;
                if let Some(ref k) = keyexpr {
                    self.rows
                        .entry(k.clone())
                        .or_insert_with(|| ExchangeRow::new(k.clone()))
                        .requests += 1;
                }
                // A repeated rid inside one flow means the first exchange was
                // never closed — the same loss `unclosed` counts at the end of
                // the flow, reached one query earlier.
                if open
                    .insert(
                        key,
                        OpenExchange {
                            keyexpr,
                            requested_at: at,
                            first_reply_at: None,
                            replies: 0,
                            errs: 0,
                        },
                    )
                    .is_some()
                {
                    self.unclosed += 1;
                }
            }
            NetworkMessage::Response(r) => {
                // The reply travels back, so the rid lives in the PEER's space.
                let key = (dir_index(direction.peer()), r.request_id);
                // R311y618 — a response to an exchange the selector did not
                // admit is not an orphan. It is a response this reader chose
                // not to look at, and saying otherwise would report the
                // signature of a truncated capture.
                if suppressed.contains(&key) {
                    return;
                }
                let Some(entry) = open.get_mut(&key) else {
                    self.gaps.orphan_responses += 1;
                    return;
                };
                use wz_codecs::response::ResponseOwnedVariant;
                match &r.body {
                    ResponseOwnedVariant::CodecZenohErr(_) => entry.errs += 1,
                    _ => entry.replies += 1,
                }
                if entry.first_reply_at.is_none() {
                    entry.first_reply_at = at;
                }
            }
            NetworkMessage::ResponseFinal(f) => {
                let key = (dir_index(direction.peer()), f.request_id);
                // The close is where the suppression is FORGOTTEN as well as
                // honoured: the rid is free again afterwards, so a later
                // exchange reusing it is judged on its own request.
                if suppressed.remove(&key) {
                    return;
                }
                let Some(entry) = open.remove(&key) else {
                    self.gaps.orphan_responses += 1;
                    return;
                };
                self.close(entry, at);
            }
            _ => {}
        }
    }

    /// Fold one closed exchange into the totals and, when it has a keyexpr,
    /// into its row.
    ///
    /// The two gap counters are raised AT MOST ONCE PER EXCHANGE, not once per
    /// interval. An unstamped capture would otherwise report twice as many
    /// unstamped exchanges as it holds, and a reader comparing that figure
    /// against [`Self::completed`] would conclude the file was internally
    /// inconsistent.
    fn close(&mut self, entry: OpenExchange, closed_at: Option<u64>) {
        self.completed += 1;
        self.replies += entry.replies;
        self.errs += entry.errs;

        let mut unstamped = false;
        let mut backwards = false;
        let mut measure = |from: Option<u64>, to: Option<u64>| match (from, to) {
            (Some(f), Some(t)) if t >= f => Some(t - f),
            (Some(_), Some(_)) => {
                backwards = true;
                None
            }
            _ => {
                unstamped = true;
                None
            }
        };
        // A first reply that never arrived is not a missing CLOCK — the
        // exchange has no first-reply interval at all, and `replies == 0` on
        // the row is what says so. Asking for it anyway would have made every
        // empty query answer look like a timestamp problem.
        let saw_reply = entry.replies + entry.errs > 0;
        let first = if saw_reply {
            measure(entry.requested_at, entry.first_reply_at)
        } else {
            None
        };
        let total = measure(entry.requested_at, closed_at);
        if unstamped {
            self.gaps.unstamped += 1;
        }
        if backwards {
            self.gaps.non_monotonic += 1;
        }
        if let Some(ms) = first {
            self.first_reply.add(ms);
        }
        if let Some(ms) = total {
            self.completion.add(ms);
        }

        let Some(keyexpr) = entry.keyexpr else {
            return;
        };
        let row = self
            .rows
            .entry(keyexpr.clone())
            .or_insert_with(|| ExchangeRow::new(keyexpr));
        row.completed += 1;
        row.replies += entry.replies;
        row.errs += entry.errs;
        if let Some(ms) = first {
            row.first_reply.add(ms);
        }
        if let Some(ms) = total {
            row.completion.add(ms);
        }
    }

    /// Every queried keyexpr, slowest first.
    ///
    /// Ordered by mean completion, then by request count, then by the keyexpr
    /// itself — the last tiebreak is what makes the order TOTAL, so two runs
    /// over one capture cannot disagree. A row with no measurable completion
    /// sorts LAST rather than first: an unmeasured exchange is not a fast one.
    pub fn rows(&self) -> Vec<&ExchangeRow> {
        let mut rows: Vec<&ExchangeRow> = self.rows.values().collect();
        rows.sort_by(|a, b| {
            let (ka, kb) = (
                a.completion.mean_ms().unwrap_or(0),
                b.completion.mean_ms().unwrap_or(0),
            );
            kb.cmp(&ka)
                .then_with(|| b.requests.cmp(&a.requests))
                .then_with(|| a.keyexpr.cmp(&b.keyexpr))
        });
        rows
    }

    /// One queried keyexpr's row, if it has one.
    pub fn row(&self, keyexpr: &str) -> Option<&ExchangeRow> {
        self.rows.get(keyexpr)
    }

    /// `Request` records seen, attributed or not.
    pub fn requests(&self) -> usize {
        self.requests
    }

    /// Exchanges a `ResponseFinal` closed.
    pub fn completed(&self) -> usize {
        self.completed
    }

    /// Requests this capture never saw closed — the flow's frames ended first,
    /// or the rid was reused before a close arrived.
    pub fn unclosed(&self) -> usize {
        self.unclosed
    }

    /// `Response` records carrying a `Reply`, and carrying an `Err`.
    pub fn responses(&self) -> (usize, usize) {
        (self.replies, self.errs)
    }

    /// Latency across every keyexpr — `(first reply, completion)`.
    ///
    /// Includes exchanges whose keyexpr did not resolve, which is why it is not
    /// the sum of [`Self::rows`]: a correlated exchange is a measurement even
    /// when nobody can name what it asked for.
    pub fn totals(&self) -> (LatencySamples, LatencySamples) {
        (self.first_reply, self.completion)
    }

    /// What this plane could not turn into a sample.
    pub fn gaps(&self) -> ExchangeGaps {
        self.gaps
    }

    /// What this plane could not READ — the same measurement
    /// [`crate::agg::ThroughputTable::gaps`] makes, over the same frames.
    ///
    /// Reported by both planes rather than shared, because the two are fed
    /// independently: a consumer that runs only this one still has to be told
    /// its rows are short.
    pub fn unread(&self) -> ThroughputGaps {
        self.unread
    }

    /// R311y618 (§1.1q) — what the selector did to the EXCHANGES it was shown.
    ///
    /// One verdict per `Request`, never one per message, so
    /// [`crate::filter::Selection::seen`] here is a count of exchanges and is
    /// directly comparable with [`Self::requests`] — which the throughput
    /// plane's identically-named figure is NOT, since that one counts records.
    /// The two planes answer different questions about the same capture and
    /// this accessor says which.
    pub fn selection(&self) -> Selection {
        self.selection
    }

    /// Merge another table's rows and totals into this one.
    ///
    /// For a consumer aggregating across captures. Latency merges exactly —
    /// [`LatencySamples`] keeps a sum and a count rather than a running mean —
    /// so a merge of two files gives the number one file of both would.
    pub fn merge(&mut self, other: &Self) {
        for (key, row) in &other.rows {
            let dst = self
                .rows
                .entry(key.clone())
                .or_insert_with(|| ExchangeRow::new(key.clone()));
            dst.requests += row.requests;
            dst.completed += row.completed;
            dst.replies += row.replies;
            dst.errs += row.errs;
            dst.first_reply.merge(&row.first_reply);
            dst.completion.merge(&row.completion);
        }
        self.requests += other.requests;
        self.completed += other.completed;
        self.replies += other.replies;
        self.errs += other.errs;
        self.unclosed += other.unclosed;
        self.first_reply.merge(&other.first_reply);
        self.completion.merge(&other.completion);
        self.gaps.orphan_responses += other.gaps.orphan_responses;
        self.gaps.unstamped += other.gaps.unstamped;
        self.gaps.non_monotonic += other.gaps.non_monotonic;
        self.gaps.unattributed_requests += other.gaps.unattributed_requests;
        self.unread.halted_batches += other.unread.halted_batches;
        self.unread.unparsed_bytes += other.unread.unparsed_bytes;
        self.unread.undecompressible_batches += other.unread.undecompressible_batches;
        self.unread.unresolvable_fragments += other.unread.unresolvable_fragments;
        self.selection.matched += other.selection.matched;
        self.selection.rejected += other.selection.rejected;
        self.selection.undecided += other.selection.undecided;
    }
}

/// Correlate an entire [`crate::Dissection`] — every stream flow and every
/// datagram flow, each correlated within its own request-id space.
pub fn exchanges(dissection: &crate::Dissection) -> ExchangeTable {
    exchanges_where(dissection, &Filter::any())
}

/// R311y618 (§1.1q) — the same correlation, over the exchanges a selector picks.
///
/// The second of the three planes to take a [`Filter`], and it takes the SAME
/// one: a reader compiles one selector and points it at throughput, exchanges
/// and payloads, rather than learning a second vocabulary per plane.
pub fn exchanges_where(dissection: &crate::Dissection, filter: &Filter) -> ExchangeTable {
    let mut table = ExchangeTable::new();
    for flow in dissection.flows() {
        table.observe_flow_where(&flow.frames, filter);
    }
    for flow in dissection.datagram_flows() {
        table.observe_flow_where(&flow.frames, filter);
    }
    table
}

// R311y615 — `pub(crate)`, on the precedent R311y613 set for `ws::tests` and
// with the same trade named: the export plane's end-to-end test needs a capture
// that CARRIES an exchange, and the record builders for one live here. The
// alternative is a second Request/Response encoder in `report::tests`, which is
// the copy that drifts. The cost is that `cfg(test)` visibility widens to the
// crate -> [[feedback_cfg_test_is_a_widener_not_a_gate]].
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datagram_tests::udp_packet;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use wz_codecs::wire_const::FLAG_N_N;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// `M=1` — the id lives in the SENDER's space.
    pub(crate) fn sender_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
        Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            }),
        }
    }

    /// `M=0` — the id lives in the RECEIVER's space.
    fn receiver_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
        Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            }),
        }
    }

    fn has_suffix(keyexpr: &Wireexpr<'static>) -> bool {
        match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        }
    }

    /// A `Request` carrying a `Query` for `keyexpr`, under `rid`.
    ///
    /// The MID comes from the codec's generated `Default` and the `N` bit from
    /// [`FLAG_N_N`] — R311y615 named it precisely so this line, and the census
    /// fixtures beside it, stop spelling `0x20`.
    pub(crate) fn request_query(rid: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | n,
            rid,
            keyexpr,
            body: wz_codecs::request::RequestVariant::CodecZenohQuery(
                wz_codecs::query::Query::default(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A `Request` carrying a `MsgPut` of `payload` — a put that expects an
    /// answer, and the only request shape on this plane that carries BYTES.
    ///
    /// A `Query` request has a payload too, but zenoh carries it as an ext-chain
    /// entry rather than a decoded field (`out/wz-codecs/query.rs:33-38`), so
    /// [`crate::agg::classify`] cannot size it and reports `0`. That limit is a
    /// property of the codec's reach, not of this fixture; a `bytes` term over
    /// this plane is therefore driven with the shape whose size the decoder
    /// actually knows.
    pub(crate) fn request_put(rid: u64, keyexpr: Wireexpr<'static>, payload: &[u8]) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | n,
            rid,
            keyexpr,
            body: wz_codecs::request::RequestVariant::CodecZenohMsgPut(
                wz_codecs::msg_put::MsgPut {
                    payload_len: payload.len() as u64,
                    payload,
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A `Response` carrying a `Reply` with `payload`, echoing `request_id`.
    pub(crate) fn response_reply(
        request_id: u64,
        keyexpr: Wireexpr<'static>,
        payload: &[u8],
    ) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header | n,
            request_id,
            keyexpr,
            body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
                body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(
                    wz_codecs::msg_put::MsgPut {
                        payload_len: payload.len() as u64,
                        payload,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A `Response` carrying an `Err`, echoing `request_id`.
    fn response_err(request_id: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header | n,
            request_id,
            keyexpr,
            body: wz_codecs::response::ResponseVariant::CodecZenohErr(wz_codecs::err::Err {
                payload_len: 3,
                payload: b"nak",
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// The closing `ResponseFinal`.
    pub(crate) fn response_final(request_id: u64) -> Vec<u8> {
        wz_codecs::response_final::ResponseFinal {
            request_id,
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// `DeclKexpr`: bind `id` to `suffix` in the SENDER's space.
    fn declare_kexpr(id: u64, suffix: &'static str) -> Vec<u8> {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    header: wz_session_core::wire_const::D_MID_KEXPR
                        | wz_session_core::wire_const::FLAG_D_N,
                    id,
                    keyexpr: sender_space(0, Some(suffix)),
                },
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// One record per UDP datagram, with the capture instant the tuple names.
    ///
    /// Deliberately the WHOLE pipeline — packet bytes in, table out — and
    /// deliberately through [`Dissection::push_packet_at`], because the clock
    /// this plane measures is one the packet source supplies and a test that
    /// built `PassiveFrame`s itself would stamp them by hand and prove nothing
    /// about the wiring.
    pub(crate) fn dissect(records: &[(bool, Option<u64>, Vec<u8>)]) -> Dissection {
        let mut d = Dissection::new();
        for (i, (from_low, ts, record)) in records.iter().enumerate() {
            let wire = crate::datagram_tests::frame_carrying(record);
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, &wire)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, &wire)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, *ts, &pkt);
        }
        d
    }

    pub(crate) fn correlate(records: &[(bool, Option<u64>, Vec<u8>)]) -> ExchangeTable {
        exchanges(&dissect(records))
    }

    /// One query exchange, stamped: A asks at 1000, B first replies at 1030,
    /// B closes at 1050.
    fn one_query() -> Vec<(bool, Option<u64>, Vec<u8>)> {
        alloc::vec![
            (
                true,
                Some(1_000),
                request_query(7, sender_space(0, Some("demo/**")))
            ),
            (
                false,
                Some(1_030),
                response_reply(7, sender_space(0, Some("demo/a")), b"first")
            ),
            (
                false,
                Some(1_040),
                response_reply(7, sender_space(0, Some("demo/b")), b"second")
            ),
            (false, Some(1_050), response_final(7)),
        ]
    }

    /// ANTI-VACUITY. Everything below asserts about `Request` / `Response` /
    /// `ResponseFinal` records; this asserts the fixture actually produces
    /// them. Without it a build that decoded all three as `Unknown` would give
    /// an empty table and every "no orphan / no gap" assertion would pass on
    /// absence — the exact shape R311y613 found in the network census.
    #[test]
    fn the_fixture_puts_real_request_and_response_records_on_the_wire() {
        let d = dissect(&one_query());
        let frames = &d.datagram_flows()[0].frames;
        assert_eq!(frames.len(), 4, "one frame per datagram");
        let mut kinds = Vec::new();
        for f in frames {
            let Carried::Batch(b) = &f.carried else {
                panic!("frame carried no batch: {:?}", f.carried);
            };
            assert!(b.halt.is_none(), "batch walk halted: {:?}", b.halt);
            assert_eq!(b.messages.len(), 1, "one record per batch");
            kinds.push(match &b.messages[0] {
                NetworkMessage::Request(_) => "request",
                NetworkMessage::Response(_) => "response",
                NetworkMessage::ResponseFinal(_) => "final",
                other => panic!("unexpected record: {other:?}"),
            });
        }
        assert_eq!(kinds, ["request", "response", "response", "final"]);
    }

    /// The wiring R311y615 added, asserted at the seam it crosses: the capture
    /// instant handed to `push_packet_at` comes back out on the FRAME.
    #[test]
    fn the_capture_clock_reaches_every_frame() {
        let d = dissect(&one_query());
        let stamps: Vec<Option<u64>> = d.datagram_flows()[0]
            .frames
            .iter()
            .map(|f| f.observed_at_ms)
            .collect();
        assert_eq!(stamps, [Some(1_000), Some(1_030), Some(1_040), Some(1_050)]);
    }

    /// §1.1f, the plane itself.
    #[test]
    fn a_query_exchange_reports_its_latency_at_the_tap() {
        let t = correlate(&one_query());
        assert_eq!(t.requests(), 1);
        assert_eq!(t.completed(), 1);
        assert_eq!(t.unclosed(), 0);
        assert_eq!(t.responses(), (2, 0));
        assert!(t.gaps().is_clean(), "unexpected gaps: {:?}", t.gaps());

        let row = t.row("demo/**").expect("the queried keyexpr has a row");
        assert_eq!(row.first_reply.count(), 1);
        assert_eq!(row.first_reply.mean_ms(), Some(30), "1030 - 1000");
        assert_eq!(row.completion.mean_ms(), Some(50), "1050 - 1000");
        assert_eq!(row.completion.min_ms(), Some(50));
        assert_eq!(row.completion.max_ms(), Some(50));
    }

    /// THE ANTI-FABRICATION LEG, and the reason `observed_at_ms` is an
    /// `Option`. The identical exchange with NO capture timestamps must report
    /// no latency — not a confident zero, which is what a `u64` clock
    /// defaulting to 0 would have produced for every exchange in the file.
    #[test]
    fn a_capture_without_timestamps_reports_no_latency_rather_than_zero() {
        let unstamped: Vec<(bool, Option<u64>, Vec<u8>)> = one_query()
            .into_iter()
            .map(|(from_low, _, rec)| (from_low, None, rec))
            .collect();
        let t = correlate(&unstamped);

        assert_eq!(t.completed(), 1, "correlation does not need a clock");
        let row = t.row("demo/**").expect("the row still exists");
        assert!(row.completion.is_empty(), "no completion sample");
        assert!(row.first_reply.is_empty(), "no first-reply sample");
        assert_eq!(row.completion.mean_ms(), None);
        assert_eq!(row.completion.min_ms(), None, "not a zero floor");
        assert_eq!(
            t.gaps().unstamped,
            1,
            "counted ONCE per exchange, not once per interval"
        );
        assert_eq!(
            t.gaps().non_monotonic,
            0,
            "a missing clock is not a reordered one"
        );
    }

    /// A clock that steps backwards is a reordering fact about two packets, and
    /// it must not become a duration. `saturating_sub` would have made it 0.
    #[test]
    fn a_backwards_clock_yields_no_sample_and_says_so() {
        let t = correlate(&[
            (
                true,
                Some(5_000),
                request_query(1, sender_space(0, Some("k"))),
            ),
            (false, Some(4_000), response_final(1)),
        ]);
        assert_eq!(t.completed(), 1);
        assert_eq!(t.gaps().non_monotonic, 1);
        assert_eq!(t.gaps().unstamped, 0);
        assert!(t.totals().1.is_empty(), "no completion sample");
    }

    /// THE DISCRIMINATOR for the two-space key. Both directions query with
    /// `rid = 1` at the same time; a table keyed on the bare id would close A's
    /// request with B's `ResponseFinal` and mint two latencies out of four
    /// unrelated instants.
    ///
    /// Wire order: A asks (t=100), B asks (t=110), A answers B (t=115),
    /// B answers A (t=180). The correct answer is A→B 80 ms and B→A 5 ms; the
    /// bare-id answer is 15 ms and 70 ms.
    #[test]
    fn each_direction_owns_its_request_id_space() {
        let t = correlate(&[
            (
                true,
                Some(100),
                request_query(1, sender_space(0, Some("from/a"))),
            ),
            (
                false,
                Some(110),
                request_query(1, sender_space(0, Some("from/b"))),
            ),
            (true, Some(115), response_final(1)),
            (false, Some(180), response_final(1)),
        ]);
        assert_eq!(t.completed(), 2);
        assert_eq!(t.unclosed(), 0);
        assert_eq!(t.gaps().orphan_responses, 0);
        assert_eq!(
            t.row("from/a").expect("A's row").completion.mean_ms(),
            Some(80),
            "A asked at 100 and B closed it at 180"
        );
        assert_eq!(
            t.row("from/b").expect("B's row").completion.mean_ms(),
            Some(5),
            "B asked at 110 and A closed it at 115"
        );
    }

    /// R311y621 (§1.4i) — the correlation plane says what it could not READ,
    /// and a body this build cannot decompress is exactly that.
    ///
    /// The distinction this page turns on: a capture with no exchanges and a
    /// capture whose exchanges were unreadable produce the SAME rows. `unread`
    /// is the only thing that tells them apart, so a reader who sees
    /// `0 requests` has to be able to find out which one they are looking at.
    /// `gaps()` is pinned clean beside it because the two are different
    /// questions — an ORPHAN is a record this plane read and could not
    /// correlate, and nothing here was read at all.
    #[test]
    fn a_batch_this_build_cannot_decompress_is_unread_rather_than_absent() {
        let t = exchanges(&crate::datagram_tests::compressed_session_dissection());

        let unread = t.unread();
        assert_eq!(unread.undecompressible_batches, 1);
        assert_eq!(unread.halted_batches, 0);
        assert_eq!(unread.unparsed_bytes, 0);
        assert_eq!(unread.unresolvable_fragments, 0);
        assert!(!unread.is_clean(), "the shortfall must be visible at all");
        assert_eq!(t.requests(), 0);
        assert_eq!(
            t.gaps().orphan_responses,
            0,
            "an orphan is a record this plane READ; nothing here was read"
        );
    }

    /// R311y621 (§1.4i) — the same plane, for a capture that began mid-session:
    /// fragments whose chain could never be resolved are counted.
    ///
    /// `unclosed` is pinned at zero and that is the load-bearing half. An
    /// unresolvable fragment is traffic this plane never saw the inside of, so
    /// it must not manufacture a query that never closed out of it — the same
    /// rule R311y618 wrote for a rejected exchange, reached from the other side.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_with_no_resolution_is_unread_rather_than_an_unclosed_query() {
        let t = exchanges(&crate::datagram_tests::midsession_fragment_dissection());

        let unread = t.unread();
        assert_eq!(unread.unresolvable_fragments, 1);
        assert_eq!(unread.undecompressible_batches, 0);
        assert_eq!(unread.halted_batches, 0);
        assert_eq!(unread.unparsed_bytes, 0);
        assert!(!unread.is_clean(), "the shortfall must be visible at all");
        assert_eq!(t.requests(), 0);
        assert_eq!(
            t.unclosed(),
            0,
            "traffic never read cannot be an exchange that failed to close"
        );
    }

    /// A capture that starts mid-query carries replies whose request went past
    /// before the tap was listening. Reported, never invented.
    #[test]
    fn a_reply_whose_request_was_never_captured_is_an_orphan() {
        let t = correlate(&[
            (
                false,
                Some(10),
                response_reply(9, sender_space(0, Some("mid/session")), b"x"),
            ),
            (false, Some(20), response_final(9)),
        ]);
        assert_eq!(t.requests(), 0);
        assert_eq!(t.completed(), 0);
        assert_eq!(t.gaps().orphan_responses, 2, "the reply AND the close");
        assert!(t.rows().is_empty(), "nothing to attribute");
    }

    /// A query whose close the capture never carried is UNCLOSED. It must not
    /// read as an exchange that completed, and it must not contribute a
    /// completion sample of any value.
    #[test]
    fn an_exchange_the_capture_never_saw_closed_is_unclosed() {
        let t = correlate(&[
            (
                true,
                Some(1),
                request_query(3, sender_space(0, Some("never/closed"))),
            ),
            (
                false,
                Some(2),
                response_reply(3, sender_space(0, Some("never/closed")), b"partial"),
            ),
        ]);
        assert_eq!(t.requests(), 1);
        assert_eq!(t.completed(), 0);
        assert_eq!(t.unclosed(), 1);
        assert!(t.totals().1.is_empty());
        let row = t.row("never/closed").expect("the request opened a row");
        assert_eq!(row.unclosed(), 1);
    }

    /// An `Err` is an answer, and a different one from a `Reply`. A plane that
    /// folded them together could not tell a queryable that is slow from one
    /// that is failing.
    #[test]
    fn an_err_answer_is_counted_apart_from_a_reply() {
        let t = correlate(&[
            (
                true,
                Some(0),
                request_query(2, sender_space(0, Some("q/err"))),
            ),
            (
                false,
                Some(7),
                response_err(2, sender_space(0, Some("q/err"))),
            ),
            (false, Some(9), response_final(2)),
        ]);
        assert_eq!(t.responses(), (0, 1));
        let row = t.row("q/err").expect("row");
        assert_eq!((row.replies, row.errs), (0, 1));
        assert_eq!(
            row.first_reply.mean_ms(),
            Some(7),
            "an Err is what the querier waited for"
        );
    }

    /// The row is named by the DECLARED keyexpr, resolved through the same
    /// two-space rule R311y613 built for throughput — including the `M=0`
    /// reference, which a single-space participant must refuse.
    #[test]
    fn a_declared_alias_names_the_exchange_row() {
        let t = correlate(&[
            // B declares id 4 = "sensors/**" in B's own space.
            (false, Some(0), declare_kexpr(4, "sensors/**")),
            // A queries it. Travelling A→B with M=0, the id names the
            // RECEIVER's space, which is B's — the shape zenoh emits.
            (true, Some(100), request_query(5, receiver_space(4, None))),
            (false, Some(160), response_final(5)),
        ]);
        assert_eq!(t.gaps().unattributed_requests, 0);
        let row = t
            .row("sensors/**")
            .expect("the alias resolved against B's space");
        assert_eq!(row.requests, 1);
        assert_eq!(row.completion.mean_ms(), Some(60));
    }

    /// An id no space has bound is NOT attributed to a keyexpr — and the
    /// exchange is still correlated and still timed, because a latency is a
    /// fact about two packets whether or not anyone can name the topic.
    #[test]
    fn an_unresolvable_request_keyexpr_is_timed_but_unattributed() {
        let t = correlate(&[
            (true, Some(10), request_query(6, sender_space(99, None))),
            (false, Some(35), response_final(6)),
        ]);
        assert_eq!(t.gaps().unattributed_requests, 1);
        assert!(t.rows().is_empty(), "no row to put it in");
        assert_eq!(t.completed(), 1);
        assert_eq!(
            t.totals().1.mean_ms(),
            Some(25),
            "the total still holds the measurement"
        );
    }

    /// Slowest first, and an UNMEASURED row sorts last rather than first: an
    /// exchange nobody could time is not a fast one.
    #[test]
    fn the_rows_are_ordered_slowest_first() {
        let t = correlate(&[
            (
                true,
                Some(0),
                request_query(1, sender_space(0, Some("fast"))),
            ),
            (false, Some(5), response_final(1)),
            (
                true,
                Some(0),
                request_query(2, sender_space(0, Some("slow"))),
            ),
            (false, Some(500), response_final(2)),
            (
                true,
                None,
                request_query(3, sender_space(0, Some("untimed"))),
            ),
            (false, None, response_final(3)),
        ]);
        let order: Vec<&str> = t.rows().iter().map(|r| r.keyexpr.as_str()).collect();
        assert_eq!(order, ["slow", "fast", "untimed"]);
    }

    /// A merge of two tables gives what one table over both captures gives.
    /// True only because [`LatencySamples`] keeps a SUM and a COUNT: a running
    /// mean cannot be merged without weights, and averaging two means is the
    /// classic way to get a number that is nobody's measurement.
    #[test]
    fn merging_two_tables_equals_one_table_over_both() {
        let left = one_query();
        let right = alloc::vec![
            (
                true,
                Some(9_000),
                request_query(11, sender_space(0, Some("demo/**")))
            ),
            (false, Some(9_400), response_final(11)),
        ];

        let mut merged = correlate(&left);
        merged.merge(&correlate(&right));

        let mut both = left;
        both.extend(right);
        let single = correlate(&both);

        let (m, s) = (
            merged.row("demo/**").expect("merged row"),
            single.row("demo/**").expect("single row"),
        );
        assert_eq!(m.requests, s.requests);
        assert_eq!(m.completed, s.completed);
        assert_eq!(m.completion.count(), s.completion.count());
        assert_eq!(m.completion.total_ms(), s.completion.total_ms());
        assert_eq!(m.completion.mean_ms(), s.completion.mean_ms());
        assert_eq!(m.completion.mean_ms(), Some(225), "(50 + 400) / 2");
        assert_eq!(merged.completed(), single.completed());
    }

    /// The read-loss half, on the rule the throughput plane follows: a batch
    /// this plane could not walk makes its rows INCOMPLETE, and the reader has
    /// to be able to see that.
    #[test]
    fn a_batch_this_plane_could_not_walk_is_reported_not_swallowed() {
        // MID 0x0F is in no network dispatch arm, so the walk absorbs the rest
        // of the batch and halts — with the ResponseFinal behind it.
        let mut record = alloc::vec![0x0Fu8, 0x00, 0x00];
        record.extend_from_slice(&response_final(4));
        let t = correlate(&[
            (
                true,
                Some(0),
                request_query(4, sender_space(0, Some("halted"))),
            ),
            (false, Some(50), record),
        ]);
        assert_eq!(t.unread().halted_batches, 1);
        assert!(t.unread().unparsed_bytes > 0);
        assert_eq!(
            t.completed(),
            0,
            "the close was behind the halt and is not invented"
        );
        assert_eq!(t.unclosed(), 1);
    }

    // R311y618 (§1.1q) — the selector reaches this plane. The rule under test
    // is that the REQUEST is judged and the exchange follows it.

    fn correlate_where(
        records: &[(bool, Option<u64>, Vec<u8>)],
        selector: &str,
    ) -> (ExchangeTable, ExchangeTable) {
        let d = dissect(records);
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        (exchanges_where(&d, &filter), exchanges(&d))
    }

    /// Two exchanges on two topics, one of them stamped slower.
    fn two_topics() -> Vec<(bool, Option<u64>, Vec<u8>)> {
        alloc::vec![
            (
                true,
                Some(1_000),
                request_query(1, sender_space(0, Some("demo/a")))
            ),
            (false, Some(1_010), response_final(1)),
            (
                true,
                Some(2_000),
                request_query(2, sender_space(0, Some("demo/b")))
            ),
            (false, Some(2_500), response_final(2)),
        ]
    }

    /// ANTI-VACUITY, and the invariant the whole design rests on: the identity
    /// filter is the unfiltered path. Every assertion below would be
    /// uninteresting if the filtered walk were a different walk.
    #[test]
    fn the_identity_filter_is_the_unfiltered_exchange_plane() {
        let (filtered, plain) = correlate_where(&two_topics(), "");
        assert_eq!(filtered.requests(), plain.requests());
        assert_eq!(filtered.completed(), plain.completed());
        assert_eq!(filtered.totals().1.mean_ms(), plain.totals().1.mean_ms());
        assert_eq!(filtered.rows().len(), plain.rows().len());
        assert_eq!(
            filtered.selection(),
            crate::filter::Selection {
                matched: 2,
                rejected: 0,
                undecided: 0
            }
        );
    }

    /// The narrowing itself: one topic's exchange survives, and the LATENCY
    /// follows it — the mean is the surviving exchange's, not the average of
    /// both, which is what proves the reply was admitted with its request.
    #[test]
    fn a_selector_narrows_the_plane_and_the_latency_follows_the_request() {
        let (t, plain) = correlate_where(&two_topics(), "key == demo/b");
        assert_eq!(plain.totals().1.mean_ms(), Some(255), "the control");
        assert_eq!(t.requests(), 1);
        assert_eq!(t.completed(), 1);
        assert_eq!(
            t.totals().1.mean_ms(),
            Some(500),
            "the slow exchange's own interval, not a blend"
        );
        assert_eq!(t.rows().len(), 1);
        assert_eq!(t.rows()[0].keyexpr, "demo/b");
        assert_eq!(
            t.selection(),
            crate::filter::Selection {
                matched: 1,
                rejected: 1,
                undecided: 0
            }
        );
    }

    /// THE RULE, stated as a test: the responses to a request the selector did
    /// not admit are dropped in SILENCE. They are not orphans — that counter
    /// means the capture began mid-query — and the exchange is not unclosed.
    ///
    /// The control leg matters as much as the assertion: the same table still
    /// reports a real orphan, so `orphan_responses == 0` here is a decision and
    /// not a counter that stopped working.
    #[test]
    fn the_responses_to_a_rejected_request_are_not_orphans() {
        // BOTH answering arms must be driven, and the first draft of this test
        // drove only one: `two_topics` closes with a bare `ResponseFinal`, so
        // deleting the suppression check from the `Response` arm changed
        // nothing and the test still passed. The rejected exchange below
        // carries a REPLY as well as its close.
        let mut records = two_topics();
        records.insert(
            3,
            (
                false,
                Some(2_100),
                response_reply(2, sender_space(0, Some("demo/b")), b"answer"),
            ),
        );
        // A genuine orphan: a close for a request this capture never saw.
        records.push((false, Some(3_000), response_final(9)));
        let (t, plain) = correlate_where(&records, "key == demo/a");
        assert_eq!(
            plain.gaps().orphan_responses,
            1,
            "the control: one real orphan is in this capture"
        );
        assert_eq!(t.requests(), 1);
        assert_eq!(
            t.gaps().orphan_responses,
            1,
            "the REAL orphan survives the selector, and the rejected exchange's \
             own close did not join it"
        );
        assert_eq!(
            t.unclosed(),
            0,
            "a rejected exchange is not an unclosed one"
        );
    }

    /// A rejected request that never closes leaves nothing behind either — the
    /// end-of-flow sweep counts only exchanges the selector admitted.
    #[test]
    fn a_rejected_request_that_never_closes_is_not_unclosed() {
        let (t, plain) = correlate_where(
            &alloc::vec![(
                true,
                Some(10),
                request_query(3, sender_space(0, Some("noise/x")))
            )],
            "key == demo/a",
        );
        assert_eq!(
            plain.unclosed(),
            1,
            "the control: unfiltered it is unclosed"
        );
        assert_eq!(t.unclosed(), 0);
        assert_eq!(t.selection().rejected, 1);
    }

    /// An id no space bound makes a `key` term UNDECIDABLE, not false. The
    /// exchange leaves the rows, and it leaves `unattributed_requests` too:
    /// that gap qualifies the rows a reader is looking at, and a record the
    /// reader is not being shown must not add to it.
    #[test]
    fn an_unresolvable_request_keyexpr_is_undecided_rather_than_rejected() {
        let (t, plain) = correlate_where(
            &alloc::vec![
                (true, Some(10), request_query(6, sender_space(99, None))),
                (false, Some(35), response_final(6)),
            ],
            "key == demo/a",
        );
        assert_eq!(
            plain.gaps().unattributed_requests,
            1,
            "the control: unfiltered the request is counted and unattributed"
        );
        assert_eq!(
            t.selection(),
            crate::filter::Selection {
                matched: 0,
                rejected: 0,
                undecided: 1
            },
            "undecided, which is not the same answer as rejected"
        );
        assert_eq!(t.requests(), 0);
        assert_eq!(t.gaps().unattributed_requests, 0);
    }

    /// A term over something a `Request` carries that is NOT its keyexpr, to
    /// show the view is the shared one: `kind == query` admits a query and the
    /// direction term admits only the asker's side.
    #[test]
    fn the_exchange_view_answers_kind_and_direction_terms() {
        let (kinds, _) = correlate_where(&two_topics(), "kind == query");
        assert_eq!(kinds.requests(), 2, "both requests are queries");
        let (dels, _) = correlate_where(&two_topics(), "kind == del");
        assert_eq!(dels.requests(), 0);
        assert_eq!(dels.selection().rejected, 2);
        let (asker, _) = correlate_where(&two_topics(), "dir == a");
        assert_eq!(asker.requests(), 2, "every request travelled A to B");
        let (other, _) = correlate_where(&two_topics(), "dir == b");
        assert_eq!(other.requests(), 0);
    }

    // R311y620 (§1.4k) — the two fields the R311y618 selector work left
    // undriven on this plane, each on its own page for the reason the
    // throughput plane's four are separate: a page carrying several terms is
    // satisfied by any one of them and gates none.

    /// A `bytes` term, against requests whose payloads differ.
    ///
    /// Both requests are on ONE keyexpr and are the same kind, so nothing but
    /// the size can be doing the narrowing.
    #[test]
    fn the_exchange_view_answers_a_bytes_term_off_the_wire() {
        let records = alloc::vec![
            (
                true,
                Some(1_000),
                request_put(1, sender_space(0, Some("sized/topic")), &[0u8; 10])
            ),
            (false, Some(1_010), response_final(1)),
            (
                true,
                Some(2_000),
                request_put(2, sender_space(0, Some("sized/topic")), &[0u8; 100])
            ),
            (false, Some(2_010), response_final(2)),
        ];

        let (heavy, plain) = correlate_where(&records, "bytes > 50");
        assert_eq!(plain.requests(), 2, "the control: unfiltered both are seen");
        assert_eq!(heavy.requests(), 1, "only the 100-byte put");
        assert_eq!(heavy.selection().rejected, 1);
        assert_eq!(heavy.unclosed(), 0, "and the admitted one still closed");

        // The complementary term, so a view reporting a constant size cannot
        // satisfy the assertions above.
        let (light, _) = correlate_where(&records, "bytes < 50");
        assert_eq!(light.requests(), 1);
        assert_eq!(light.selection().rejected, 1);
    }

    /// A `time` term, judged on the REQUEST — which is this plane's rule from
    /// R311y618, and the reason the term needs its own page here rather than
    /// inheriting the throughput plane's.
    ///
    /// The responses are stamped LATER than the window deliberately: an
    /// exchange follows the request that opened it, so a plane that judged the
    /// response instead would admit the pair the term excludes.
    #[test]
    fn the_exchange_view_answers_a_time_term_off_the_wire() {
        let (early, plain) = correlate_where(&two_topics(), "time < 1500");
        assert_eq!(plain.requests(), 2, "the control: two exchanges in all");
        assert_eq!(early.requests(), 1, "the one asked at 1000");
        assert_eq!(early.selection().rejected, 1);
        assert_eq!(early.selection().undecided, 0, "both stamps were carried");

        let (late, _) = correlate_where(&two_topics(), "time >= 1500");
        assert_eq!(late.requests(), 1, "and the one asked at 2000");
        assert_eq!(late.selection().rejected, 1);
    }

    /// A request the capture could not time leaves a `time` term undecided.
    ///
    /// Without this the test above is free: a plane that read `0` for a missing
    /// instant would answer every `time <` term with a confident yes, and a
    /// reader would take "the whole capture happened before 1500" off a source
    /// that never said when anything happened.
    #[test]
    fn an_unclocked_request_leaves_a_time_term_undecided() {
        let records = alloc::vec![
            (
                true,
                None,
                request_query(1, sender_space(0, Some("dark/topic")))
            ),
            (false, None, response_final(1)),
        ];

        let (asked, plain) = correlate_where(&records, "time < 1500");
        assert_eq!(plain.requests(), 1, "the control: the exchange is there");
        assert_eq!(
            asked.selection(),
            crate::filter::Selection {
                matched: 0,
                rejected: 0,
                undecided: 1
            },
            "a question the capture cannot answer is not a Yes either"
        );
        assert_eq!(asked.requests(), 0);
        assert_eq!(asked.unclosed(), 0, "an unjudged exchange is not unclosed");
    }

    /// Merging carries the selection, so a consumer folding two captures under
    /// one selector still sees how much of the pair went unjudged.
    #[test]
    fn merging_carries_the_selection() {
        let (a, _) = correlate_where(&two_topics(), "key == demo/a");
        let (b, _) = correlate_where(&two_topics(), "key == demo/a");
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.selection().matched, 2);
        assert_eq!(merged.selection().rejected, 2);
    }
}
