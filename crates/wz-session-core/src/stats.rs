// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y9 — per-session transport byte/message counters (the `transport-stats`
//! atom).
//!
//! The wz analogue of zenoh's `zenoh-transport` `stats` feature
//! (`common/stats.rs` `TransportStats`): additive instrumentation that counts
//! the wire bytes + messages crossing a session in each direction, gated behind
//! the off-default `transport-stats` feature so a build that does not want the
//! ~4 atomic adds per message pays nothing.
//!
//! ## Where it counts (the two single-site seams)
//!
//! (R311y810 — the four seam references below are CODE SPANS, not links. This
//! module became unconditional so its report type can be named in every feature
//! combination, and `session_actions` / `drive` are gated on
//! `alloc + session-unicast` while `send_wire` is private, so a link to any of
//! them is unresolved in the default-feature rustdoc Layer C1bz measures. The
//! links were correct while the whole module shared their gate; widening it is
//! what broke them.)
//!
//! - **TX** — `session_actions::SessionLinkActions::send_wire`, the one
//!   wire-emit seam every production TX path routes through (handshake / close /
//!   Frame / Fragment / batch flush / keepalive). The bytes counted are the
//!   ACTUAL wire bytes handed to `send_blocking` (post-compression when the
//!   `transport-compression` wrap fires), so `tx_bytes` is the on-the-wire total.
//! - **RX** — `drive::dispatch_link_event`'s `LinkEvent::Rx` arm, the
//!   single inbound chokepoint every link kind funnels through (stream TCP/TLS/
//!   serial and datagram UDP/WS/quic-datagram alike). The bytes counted are the
//!   raw link bytes (`rx.bytes.len()`, BEFORE the optional decompression), so
//!   `rx_bytes` is the on-the-wire total — the zenoh `rx_bytes` parity point.
//!
//! ## Standalone (the adminspace consumer is P4)
//!
//! A public snapshot accessor (`session_actions::SessionLinkActions`'s
//! `stats_report`, surfaced on the AP `OpenedSession` as `.stats()`) makes the
//! counters readable WITHOUT the adminspace `@/<zid>/.../stats` queryable, which
//! stays P4-deferred (zenoh exposes the same `get_stats()` independent of
//! adminspace). Counting `tx/rx` bytes + messages is the faithful minimal set;
//! per-priority and dropped-message splits are a deliberate later extension
//! (a wz link driver drops oversize datagrams internally without a return
//! signal, so a faithful `dropped` counter needs a driver-level hook first).
//!
//! AP-only: `transport-stats` is never enabled on an MCU lane, so the
//! [`core::sync::atomic`] counters here never reach a target without 64-bit /
//! pointer atomics.
//!
//! R311y810 — the MODULE is unconditional; only the COUNTING half
//! (`TransportStats`, its atomics and the `inc_*` seams) carries the gate.
//! `TransportStatsReport` is four plain integers, and a consumer that holds one
//! in a struct field must be able to name the type in every feature
//! combination; gating the type is how a cfg-gated pub struct field appears,
//! which is the composability hazard Layer C1bf audits for.

#[cfg(feature = "transport-stats")]
use core::sync::atomic::{AtomicUsize, Ordering};

/// Per-session wire byte/message counters. Interior-mutable (atomic), so a
/// shared `&SessionLinkActions` (the `Arc`/`Rc`-wrapped action bundle) increments
/// them from the TX seam and the RX dispatch without a mutex. `Relaxed` ordering
/// is sufficient — these are monotonic observability counters, not a
/// synchronization signal (the zenoh `TransportStats` `AtomicUsize`/`Relaxed`
/// choice).
#[cfg(feature = "transport-stats")]
#[derive(Debug, Default)]
pub struct TransportStats {
    tx_bytes: AtomicUsize,
    tx_msgs: AtomicUsize,
    rx_bytes: AtomicUsize,
    rx_msgs: AtomicUsize,
}

#[cfg(feature = "transport-stats")]
impl TransportStats {
    /// Count one outbound wire message of `bytes` bytes (the TX seam).
    #[inline]
    pub fn inc_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.tx_msgs.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one inbound wire message of `bytes` bytes (the RX dispatch).
    #[inline]
    pub fn inc_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.rx_msgs.fetch_add(1, Ordering::Relaxed);
    }

    /// A plain-integer snapshot of the live counters — the value the public
    /// accessor hands out (a consumer reads a consistent-enough point sample;
    /// `Relaxed` loads are fine for monotonic counters).
    pub fn report(&self) -> TransportStatsReport {
        TransportStatsReport {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_msgs: self.tx_msgs.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_msgs: self.rx_msgs.load(Ordering::Relaxed),
        }
    }
}

/// An immutable snapshot of a `TransportStats` — the serializable value the
/// public accessor returns (the zenoh `TransportStats::report()` analogue).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStatsReport {
    /// Total bytes handed to the link write seam across this session's lifetime.
    pub tx_bytes: usize,
    /// Total outbound wire messages (one per `send_wire`).
    pub tx_msgs: usize,
    /// Total raw link bytes received (pre-decompression).
    pub rx_bytes: usize,
    /// Total inbound wire messages (one per `LinkEvent::Rx`).
    pub rx_msgs: usize,
}

#[cfg(feature = "alloc")]
impl TransportStatsReport {
    /// Render this snapshot as OpenMetrics text — the block zenoh's adminspace
    /// appends to the `zenoh_build` gauge under its `stats` feature
    /// (`manager().get_stats().report().openmetrics_text()`,
    /// `zenoh/src/net/runtime/adminspace.rs:722-730`).
    ///
    /// The LINE FORMAT is upstream's exactly — `# HELP <name> <text>`,
    /// `# TYPE <name> <type>`, then `<name> <value>`, each newline-terminated,
    /// which is what the `stats_struct!` macro emits for a plain (non-
    /// discriminated) field (`io/zenoh-transport/src/common/stats.rs:48-53`
    /// and `:207-230`).
    ///
    /// # The NAMES are not uniform, and that is the honest part
    ///
    /// Only two of wz's four counters mean the same thing as the upstream
    /// counter of that name, so only those two carry upstream's name:
    ///
    /// - `tx_bytes` / `rx_bytes` — EXACT. zenoh increments `tx_bytes` by
    ///   `batch.len()` where the batch is handed to the link write
    ///   (`unicast/universal/link.rs:202`) and `rx_bytes` by the raw bytes read;
    ///   wz counts the same two quantities at `send_wire` and at the
    ///   `LinkEvent::Rx` chokepoint.
    /// - `wz_tx_batches` / `wz_rx_batches` — DELIBERATELY NOT `tx_t_msgs` /
    ///   `rx_t_msgs`. Upstream's message counters count TRANSPORT MESSAGES,
    ///   including several inside one batch (`inc_tx_t_msgs(batch.stats.t_msgs)`,
    ///   `link.rs:201`; `inc_rx_t_msgs(1)` per decoded message,
    ///   `unicast/universal/rx.rs:235`), while wz counts ONE PER BATCH. Serving
    ///   a batch count under upstream's message name would leave a dashboard
    ///   written for zenoh silently reading the wrong quantity, so the
    ///   divergence is carried in the metric NAME rather than only in a comment.
    ///   wz has no transport-message counter to export; that is a residual, not
    ///   a rename.
    pub fn openmetrics_text(&self) -> alloc::string::String {
        let mut out = alloc::string::String::new();
        push_counter(
            &mut out,
            "tx_bytes",
            "Counter of sent bytes.",
            self.tx_bytes,
        );
        push_counter(
            &mut out,
            "rx_bytes",
            "Counter of received bytes.",
            self.rx_bytes,
        );
        push_counter(
            &mut out,
            "wz_tx_batches",
            "Counter of sent wire batches (NOT zenoh tx_t_msgs, which counts \
             transport messages within a batch).",
            self.tx_msgs,
        );
        push_counter(
            &mut out,
            "wz_rx_batches",
            "Counter of received wire batches (NOT zenoh rx_t_msgs, which counts \
             transport messages within a batch).",
            self.rx_msgs,
        );
        out
    }
}

/// One `# HELP` / `# TYPE` / value triple in upstream's plain-field shape.
///
/// Every counter this module exports is a monotonic `counter`, so the type is
/// not a parameter: a gauge would need a different upstream arm anyway.
#[cfg(feature = "alloc")]
fn push_counter(out: &mut alloc::string::String, name: &str, help: &str, value: usize) {
    use core::fmt::Write as _;
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push_str("\n# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    out.push_str(name);
    out.push(' ');
    // `write!` into a String cannot fail; the result is consumed to keep the
    // no-panic posture this crate holds elsewhere.
    let _ = write!(out, "{value}");
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `inc_tx` / `inc_rx` accumulate bytes and bump the message count by one
    /// each; `report` snapshots them faithfully.
    ///
    /// Gated with the COUNTING half (R311y810): `TransportStats` is the atomics,
    /// which only exist under the feature, while the report type and its
    /// renderer above are unconditional.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn counters_accumulate_and_report() {
        let s = TransportStats::default();
        assert_eq!(s.report(), TransportStatsReport::default());

        s.inc_tx(100);
        s.inc_tx(40);
        s.inc_rx(12);

        let r = s.report();
        assert_eq!(r.tx_bytes, 140);
        assert_eq!(r.tx_msgs, 2);
        assert_eq!(r.rx_bytes, 12);
        assert_eq!(r.rx_msgs, 1);
    }

    /// R311y810 — the LINE FORMAT is upstream's plain-field shape, pinned as a
    /// whole string rather than by substring: `# HELP`, `# TYPE ... counter`,
    /// then `<name> <value>`, newline-terminated, in field order. A renderer
    /// that emitted the right names in the wrong shape would pass a `contains`
    /// assertion and fail a scraper.
    #[cfg(feature = "alloc")]
    #[test]
    fn openmetrics_text_is_upstreams_plain_field_shape() {
        let r = TransportStatsReport {
            tx_bytes: 140,
            tx_msgs: 2,
            rx_bytes: 12,
            rx_msgs: 1,
        };
        assert_eq!(
            r.openmetrics_text(),
            "# HELP tx_bytes Counter of sent bytes.\n\
             # TYPE tx_bytes counter\n\
             tx_bytes 140\n\
             # HELP rx_bytes Counter of received bytes.\n\
             # TYPE rx_bytes counter\n\
             rx_bytes 12\n\
             # HELP wz_tx_batches Counter of sent wire batches (NOT zenoh tx_t_msgs, \
             which counts transport messages within a batch).\n\
             # TYPE wz_tx_batches counter\n\
             wz_tx_batches 2\n\
             # HELP wz_rx_batches Counter of received wire batches (NOT zenoh rx_t_msgs, \
             which counts transport messages within a batch).\n\
             # TYPE wz_rx_batches counter\n\
             wz_rx_batches 1\n"
        );
    }

    /// The two counters that carry UPSTREAM's names must carry upstream's
    /// meaning, and the two that do not must not borrow those names. This pins
    /// the naming decision itself: a later edit that "tidied" the batch counters
    /// into `tx_t_msgs` / `rx_t_msgs` would make a zenoh dashboard read a batch
    /// count as a message count, and this is what refuses it.
    ///
    /// The check is on the METRIC-NAME positions — a `# TYPE <name>` line and a
    /// `<name> <value>` sample — not on the text anywhere, because the HELP
    /// prose names `tx_t_msgs` ON PURPOSE to say what the counter is not. A bare
    /// `contains` here failed for exactly that reason on its first run, which is
    /// the distinction worth keeping rather than deleting from the HELP text.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_batch_counters_do_not_borrow_upstreams_message_names() {
        let text = TransportStatsReport::default().openmetrics_text();
        assert!(text.contains("\ntx_bytes 0\n"), "{text}");
        assert!(text.contains("\nrx_bytes 0\n"), "{text}");
        for borrowed in ["tx_t_msgs", "rx_t_msgs"] {
            for line in text.lines() {
                assert!(
                    !line.starts_with(&alloc::format!("# TYPE {borrowed} "))
                        && !line.starts_with(&alloc::format!("{borrowed} ")),
                    "wz has no transport-message counter; it must not serve one \
                     under upstream's name\n{text}"
                );
            }
        }
    }

    /// The default snapshot is all-zero (a fresh session has counted nothing).
    #[cfg(feature = "transport-stats")]
    #[test]
    fn default_is_zero() {
        assert_eq!(
            TransportStats::default().report(),
            TransportStatsReport {
                tx_bytes: 0,
                tx_msgs: 0,
                rx_bytes: 0,
                rx_msgs: 0,
            }
        );
    }
}
