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
//! - **TX** — [`crate::session_actions::SessionLinkActions::send_wire`], the one
//!   wire-emit seam every production TX path routes through (handshake / close /
//!   Frame / Fragment / batch flush / keepalive). The bytes counted are the
//!   ACTUAL wire bytes handed to `send_blocking` (post-compression when the
//!   `transport-compression` wrap fires), so `tx_bytes` is the on-the-wire total.
//! - **RX** — [`crate::drive::dispatch_link_event`]'s `LinkEvent::Rx` arm, the
//!   single inbound chokepoint every link kind funnels through (stream TCP/TLS/
//!   serial and datagram UDP/WS/quic-datagram alike). The bytes counted are the
//!   raw link bytes (`rx.bytes.len()`, BEFORE the optional decompression), so
//!   `rx_bytes` is the on-the-wire total — the zenoh `rx_bytes` parity point.
//!
//! ## Standalone (the adminspace consumer is P4)
//!
//! A public snapshot accessor ([`crate::session_actions::SessionLinkActions`]'s
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

use core::sync::atomic::{AtomicUsize, Ordering};

/// Per-session wire byte/message counters. Interior-mutable (atomic), so a
/// shared `&SessionLinkActions` (the `Arc`/`Rc`-wrapped action bundle) increments
/// them from the TX seam and the RX dispatch without a mutex. `Relaxed` ordering
/// is sufficient — these are monotonic observability counters, not a
/// synchronization signal (the zenoh `TransportStats` `AtomicUsize`/`Relaxed`
/// choice).
#[derive(Debug, Default)]
pub struct TransportStats {
    tx_bytes: AtomicUsize,
    tx_msgs: AtomicUsize,
    rx_bytes: AtomicUsize,
    rx_msgs: AtomicUsize,
}

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

/// An immutable snapshot of a [`TransportStats`] — the serializable value the
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `inc_tx` / `inc_rx` accumulate bytes and bump the message count by one
    /// each; `report` snapshots them faithfully.
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

    /// The default snapshot is all-zero (a fresh session has counted nothing).
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
