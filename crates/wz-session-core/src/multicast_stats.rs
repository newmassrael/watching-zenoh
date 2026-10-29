// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2848 — where a multicast transport's counts are RECORDED: the seam both
//! multicast drive loops and the shared RX dispatch report into.
//!
//! R2847 built the counters of one multicast transport
//! (`stats_registry::MulticastMetrics`) and proved its attribution against the
//! pin's own registry, but nothing recorded into it: the multicast plane named
//! no counter at all. This is the recording side, and it is placed where the
//! upstream counts are taken rather than where it would be convenient to take
//! them:
//!
//! - a received datagram's BYTES are counted by the loop that read it
//!   (`io/zenoh-transport/src/multicast/link.rs` @ `transport.link_stats.inc_bytes(zenoh_stats::Rx, batch.len() as u64);`);
//! - each TRANSPORT message decoded out of it is counted by the batch walk
//!   (`io/zenoh-transport/src/multicast/rx.rs` @ `stats.inc_transport_message(zenoh_stats::Rx, 1);`),
//!   which in this tree is the shared RX dispatch in `multicast_rx`;
//! - each NETWORK message is counted in the partition of the peer that sent
//!   it, where it is handed up
//!   (`io/zenoh-transport/src/multicast/rx.rs` @ `peer.stats.inc_network_message(`),
//!   which is the same dispatch's fan to the observer;
//! - a sent datagram's bytes and transport messages are counted per write
//!   (`io/zenoh-transport/src/multicast/link.rs` @ `stats.inc_transport_message(zenoh_stats::Tx,  1);`
//!   for the JOIN, and the batch's own count for data), and a sent network
//!   message where it enters the transport
//!   (`io/zenoh-transport/src/multicast/tx.rs` @ `self.link_stats.inc_network_message(zenoh_stats::Tx, msg);`).
//!
//! # Why a trait taking `&self`
//!
//! The RX dispatch receives the observer callback AND this recorder, and the
//! loop's own wrapper around that callback records the peer arrivals and
//! departures the dispatch announces. Two holders at once is only possible
//! with a shared borrow, so the recorder keeps its state behind whatever
//! interior mutability its owner chooses — the runtime's is a mutex, because
//! the node's stats registry reads the same counts from another task.
//!
//! `()` records nothing: it is what a loop without a registry passes, and what
//! the MCU loop always passes, since `transport-stats` is never on an MCU lane.
//!
//! (`multicast_rx`, `multicast_tx` and `stats_registry::MulticastMetrics` are
//! code spans rather than links: the first two are `session-multicast`-gated
//! and absent from the default-feature rustdoc run Layer C1bz measures.)

use crate::multicast_peer_arrived::MulticastPeerArrived;
use crate::multicast_peer_lost::MulticastPeerLost;
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;

/// The counts one multicast transport takes, reported by the code that
/// observes each one. Every method defaults to recording nothing.
pub trait MulticastStatsRecorder {
    /// A datagram of `bytes` went out to the group, carrying
    /// `transport_messages`.
    fn datagram_sent(&self, _bytes: usize, _transport_messages: u64) {}

    /// A datagram of `bytes` arrived from the group.
    fn datagram_received(&self, _bytes: usize) {}

    /// One transport message was decoded out of a received datagram, whoever
    /// sent it: the count is the link's, not a peer's.
    fn transport_message_received(&self) {}

    /// A network message was pushed onto the transport's queue.
    ///
    /// R2929 — reported by its tally, taken before the push, and only once the
    /// push has succeeded: a message that found no room is
    /// [`Self::network_message_dropped`] instead, as upstream's multicast
    /// schedule counts one or the other.
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_sent(&self, _tally: &crate::multicast_tx::MulticastTxTally) {}

    /// R2929 — a network message found no room on the transport's queue within
    /// its deadline: a congestion drop.
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_dropped(&self, _tally: &crate::multicast_tx::MulticastTxTally) {}

    /// The admitted peer `zid` sent `msg`. The owned message is the heap profile's:
    /// a build with no allocator reads each record where its datagram lies and
    /// counts none (`transport-stats` implies `alloc`, so it has no counts to take).
    #[cfg(feature = "alloc")]
    fn network_message_received(&self, _zid: &[u8], _msg: &NetworkMessage) {}

    /// A peer was admitted to the group.
    fn peer_arrived(&self, _arrived: &MulticastPeerArrived) {}

    /// A peer left the group, announced or inferred.
    fn peer_lost(&self, _lost: &MulticastPeerLost) {}
}

/// Records nothing.
impl MulticastStatsRecorder for () {}

/// R2852 — records into the inner recorder when there is one, and nothing
/// otherwise: what a host passes when whether a transport is counted is decided
/// at run time (a node registry it may or may not hold) rather than by type.
impl<R: MulticastStatsRecorder> MulticastStatsRecorder for Option<R> {
    fn datagram_sent(&self, bytes: usize, transport_messages: u64) {
        if let Some(inner) = self {
            inner.datagram_sent(bytes, transport_messages);
        }
    }

    fn datagram_received(&self, bytes: usize) {
        if let Some(inner) = self {
            inner.datagram_received(bytes);
        }
    }

    fn transport_message_received(&self) {
        if let Some(inner) = self {
            inner.transport_message_received();
        }
    }

    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_sent(&self, tally: &crate::multicast_tx::MulticastTxTally) {
        if let Some(inner) = self {
            inner.network_message_sent(tally);
        }
    }

    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_dropped(&self, tally: &crate::multicast_tx::MulticastTxTally) {
        if let Some(inner) = self {
            inner.network_message_dropped(tally);
        }
    }

    #[cfg(feature = "alloc")]
    fn network_message_received(&self, zid: &[u8], msg: &NetworkMessage) {
        if let Some(inner) = self {
            inner.network_message_received(zid, msg);
        }
    }

    fn peer_arrived(&self, arrived: &MulticastPeerArrived) {
        if let Some(inner) = self {
            inner.peer_arrived(arrived);
        }
    }

    fn peer_lost(&self, lost: &MulticastPeerLost) {
        if let Some(inner) = self {
            inner.peer_lost(lost);
        }
    }
}

/// `resource-snapshot` — a recorder that spaces the transport messages a group receives
/// (`docs/observation-plane.md` M4) and passes every report on to the recorder it wraps.
///
/// The counting of a transport message is one seam, [`MulticastStatsRecorder::transport_message_received`],
/// which the stats registry already hangs its count on; the interval meter hangs on the same one,
/// so the two count the same messages as a unicast session's two do
/// (`drive::note_rx_transport_message`). The tap holds no state of its own: the meter belongs to
/// the host that holds the group, which reads it and keeps it across a re-join of the group and
/// retires it into the node's [`ReceiveLedger`](crate::resource_snapshot::ReceiveLedger) when the
/// group is left. `meter` is `None` for a host that does not count, and the tap is then the
/// recorder it wraps.
///
/// `now_us` reads the host's clock in microseconds, the low 32 bits of it: the meter reads spans
/// modulo 2^32, and the clock is the one the loop runs on, so every group of a node reads one.
#[cfg(feature = "resource-snapshot")]
pub struct IntervalTap<'a, R: ?Sized, C> {
    inner: &'a R,
    meter: Option<&'a crate::interval_meter::BuildIntervalMeter>,
    now_us: C,
}

#[cfg(feature = "resource-snapshot")]
impl<'a, R: ?Sized, C> IntervalTap<'a, R, C> {
    /// A tap over `inner` that feeds `meter`, reading the time from `now_us`.
    pub fn new(
        inner: &'a R,
        meter: Option<&'a crate::interval_meter::BuildIntervalMeter>,
        now_us: C,
    ) -> Self {
        Self {
            inner,
            meter,
            now_us,
        }
    }
}

#[cfg(feature = "resource-snapshot")]
impl<R: MulticastStatsRecorder + ?Sized, C: Fn() -> u32> MulticastStatsRecorder
    for IntervalTap<'_, R, C>
{
    fn datagram_sent(&self, bytes: usize, transport_messages: u64) {
        self.inner.datagram_sent(bytes, transport_messages);
    }

    fn datagram_received(&self, bytes: usize) {
        self.inner.datagram_received(bytes);
    }

    fn transport_message_received(&self) {
        self.inner.transport_message_received();
        if let Some(meter) = self.meter {
            meter.observe((self.now_us)());
        }
    }

    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_sent(&self, tally: &crate::multicast_tx::MulticastTxTally) {
        self.inner.network_message_sent(tally);
    }

    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )
    ))]
    fn network_message_dropped(&self, tally: &crate::multicast_tx::MulticastTxTally) {
        self.inner.network_message_dropped(tally);
    }

    #[cfg(feature = "alloc")]
    fn network_message_received(&self, zid: &[u8], msg: &NetworkMessage) {
        self.inner.network_message_received(zid, msg);
    }

    fn peer_arrived(&self, arrived: &MulticastPeerArrived) {
        self.inner.peer_arrived(arrived);
    }

    fn peer_lost(&self, lost: &MulticastPeerLost) {
        self.inner.peer_lost(lost);
    }
}

#[cfg(all(test, feature = "resource-snapshot"))]
mod tap_tests {
    extern crate std;

    use super::*;
    use crate::interval_meter::BuildIntervalMeter;
    use core::cell::Cell;

    /// Counts what is reported to it, and nothing else.
    #[derive(Default)]
    struct Counting {
        messages: Cell<u64>,
        datagrams: Cell<u64>,
    }

    impl MulticastStatsRecorder for Counting {
        fn datagram_received(&self, _bytes: usize) {
            self.datagrams.set(self.datagrams.get() + 1);
        }

        fn transport_message_received(&self) {
            self.messages.set(self.messages.get() + 1);
        }
    }

    #[test]
    fn the_tap_spaces_each_transport_message_and_passes_every_report_on() {
        let inner = Counting::default();
        let meter = BuildIntervalMeter::new();
        let clock = Cell::new(1_000u32);
        let tap = IntervalTap::new(&inner, Some(&meter), || {
            clock.set(clock.get() + 100);
            clock.get()
        });
        for _ in 0..4 {
            tap.transport_message_received();
        }
        tap.datagram_received(64);
        let reading = meter.reading();
        assert_eq!(reading.messages, 4, "each transport message is counted");
        assert_eq!(reading.interval_sum_us, 300, "three intervals of 100");
        assert_eq!(
            (inner.messages.get(), inner.datagrams.get()),
            (4, 1),
            "the wrapped recorder was told of everything, so the two count the same messages"
        );
    }

    #[test]
    fn a_tap_with_no_meter_is_the_recorder_it_wraps() {
        let inner = Counting::default();
        let tap = IntervalTap::new(&inner, None, || panic!("no meter, so no clock read"));
        tap.transport_message_received();
        tap.transport_message_received();
        assert_eq!(inner.messages.get(), 2);
    }
}
