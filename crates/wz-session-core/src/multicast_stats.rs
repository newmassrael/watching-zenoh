// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

    /// A network message is about to enter the transport.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    fn network_message_sent(&self, _item: &crate::multicast_tx::MulticastTxItem) {}

    /// The admitted peer `zid` sent `msg`.
    fn network_message_received(&self, _zid: &[u8], _msg: &NetworkMessage) {}

    /// A peer was admitted to the group.
    fn peer_arrived(&self, _arrived: &MulticastPeerArrived) {}

    /// A peer left the group, announced or inferred.
    fn peer_lost(&self, _lost: &MulticastPeerLost) {}
}

/// Records nothing.
impl MulticastStatsRecorder for () {}
