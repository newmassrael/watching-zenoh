// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The identity of a unicast datagram link: the one remote end it carries a session with.
//!
//! ## Why this module exists
//!
//! A UDP socket takes a datagram from anyone who sends one. The MCU links used to answer that by
//! sending their replies to the source of the most recent datagram they took, which is how an
//! acceptor learns its peer from the `InitSyn` and was never turned off after it had. One datagram
//! from another address then pointed the replies and the keep-alives of an established session at
//! that address until the real peer next spoke: on the T2G kit a single stray stalled a session
//! for about twenty seconds. The link's ends, as the admin space reports them, were already
//! written once and never renamed; what the link sent to was not, so the link named one peer and
//! talked to another.
//!
//! ## The rule
//!
//! A link IS its pair of ends, and the remote end does not change once it is known. Upstream holds
//! the same: a dialled UDP link connects its socket to the remote address
//! (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `Connect the socket to the remote address`),
//! so the kernel drops what anyone else sends, and a listener keeps one link per source address
//! (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `A new peers has sent data to this socket`),
//! so a datagram is only ever read by the link of the peer that sent it.
//!
//! - A dialled link knows its peer from the dial: it is bound from the start.
//! - An accepting link is bound by the first `InitSyn` it takes, to that datagram's source. What
//!   arrives before it from anyone is not part of a session
//!   ([`DatagramVerdict::Stray`](crate::datagram_peer::DatagramVerdict::Stray)).
//! - A bound link takes its peer's datagrams only. Another source's `InitSyn` is
//!   [`DatagramVerdict::Refused`](crate::datagram_peer::DatagramVerdict::Refused): the link
//!   carries one session, and a node that accepts several keeps a listener that gives each peer a
//!   link of its own. Anything else is a stray.
//!
//! The decision is made here once, for every stack's driver: the link on BSD-style sockets
//! (`wz-runtime-coop`) and the lwIP one (`wz-session-lwip`) each call
//! [`PeerBinding::admit`](crate::datagram_peer::PeerBinding::admit) on every datagram they take
//! and discard what it does not admit. A driver that reads a socket another session shares (a
//! listener's) does not discard: what is not its peer's is the other session's, so it asks
//! [`PeerBinding::is_peer`](crate::datagram_peer::PeerBinding::is_peer) and leaves the datagram
//! where it is.
//!
//! Unconditional, as [`crate::ext_admit`] is: it reads one header byte and an address, so it needs
//! neither a codec feature nor the `alloc` storage profile.

use core::cell::Cell;

use wz_codecs::wire_const;

/// Whether `datagram` opens a unicast handshake: its first byte is an INIT transport header with
/// the A flag clear, that is an `InitSyn`.
///
/// A header read and nothing more: it decodes no body and allocates nothing, so a link or a
/// listener can ask it of a datagram from a source it has no session with, before it spends
/// anything on that source. The datagram is not otherwise judged (it may still fail to decode,
/// which the session built for it will say); an `InitAck`, which opens nothing, and every other
/// message and an empty datagram are `false`.
pub fn is_init_syn(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|&header| {
        header & 0x1F == wire_const::T_MID_INIT && header & wire_const::FLAG_T_INIT_A == 0
    })
}

/// What a link does with one datagram it has taken, by [`PeerBinding::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramVerdict {
    /// From the link's peer: the session reads it.
    Peer,
    /// The `InitSyn` that bound an accepting link to its source, which is the peer from now on:
    /// the session reads it.
    Bound,
    /// From a source that is not the peer, or before an accepting link has one, and not an
    /// `InitSyn`: part of no session. Discarded and counted.
    Stray,
    /// An `InitSyn` from another source than the bound peer: a session this link cannot carry.
    /// Discarded and counted; its sender retries on its own timer.
    Refused,
}

impl DatagramVerdict {
    /// Whether the session reads the datagram.
    pub fn is_taken(self) -> bool {
        matches!(self, Self::Peer | Self::Bound)
    }
}

/// The datagrams a link has discarded since it was made, by why.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForeignCounts {
    /// [`DatagramVerdict::Stray`]s.
    pub strays: u32,
    /// [`DatagramVerdict::Refused`]s.
    pub refused: u32,
}

/// The remote end of one unicast datagram link, `A` being how its stack names an address and a
/// port: unknown until an accepting link takes its first `InitSyn`, and fixed from then on (see
/// the module's rule).
///
/// Interior-mutable, because a driver's receive and send seams both take `&self`: the drive loop
/// and the session's actions reach the one driver from the one thread that runs them.
#[derive(Debug)]
pub struct PeerBinding<A: Copy + Eq> {
    peer: Cell<Option<A>>,
    foreign: Cell<ForeignCounts>,
}

impl<A: Copy + Eq> PeerBinding<A> {
    /// The binding of a link that dialled `peer`.
    pub const fn dialled(peer: A) -> Self {
        Self {
            peer: Cell::new(Some(peer)),
            foreign: Cell::new(ForeignCounts {
                strays: 0,
                refused: 0,
            }),
        }
    }

    /// The binding of a link that waits for a peer to open a session with it.
    pub const fn accepting() -> Self {
        Self {
            peer: Cell::new(None),
            foreign: Cell::new(ForeignCounts {
                strays: 0,
                refused: 0,
            }),
        }
    }

    /// The peer, once there is one: what every send goes to.
    pub fn peer(&self) -> Option<A> {
        self.peer.get()
    }

    /// Whether `source` is the bound peer. Not a decision about the datagram: what a link asks of
    /// a datagram on a socket it shares, which is another session's when this is `false`.
    pub fn is_peer(&self, source: A) -> bool {
        self.peer.get() == Some(source)
    }

    /// Decide `datagram`, taken from `source`: bind an accepting link to the source of its first
    /// `InitSyn`, and count what is not admitted. The caller discards a datagram whose verdict is
    /// not [taken](DatagramVerdict::is_taken).
    pub fn admit(&self, source: A, datagram: &[u8]) -> DatagramVerdict {
        let verdict = match self.peer.get() {
            Some(peer) if peer == source => DatagramVerdict::Peer,
            Some(_) if is_init_syn(datagram) => DatagramVerdict::Refused,
            Some(_) => DatagramVerdict::Stray,
            None if is_init_syn(datagram) => {
                self.peer.set(Some(source));
                DatagramVerdict::Bound
            }
            None => DatagramVerdict::Stray,
        };
        let mut foreign = self.foreign.get();
        match verdict {
            DatagramVerdict::Stray => foreign.strays = foreign.strays.saturating_add(1),
            DatagramVerdict::Refused => foreign.refused = foreign.refused.saturating_add(1),
            DatagramVerdict::Peer | DatagramVerdict::Bound => return verdict,
        }
        self.foreign.set(foreign);
        verdict
    }

    /// What the link has discarded so far.
    pub fn foreign(&self) -> ForeignCounts {
        self.foreign.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: ([u8; 4], u16) = ([10, 0, 0, 1], 7447);
    const OTHER: ([u8; 4], u16) = ([10, 0, 0, 9], 7447);
    /// The same address as the peer on another port: a different end.
    const OTHER_PORT: ([u8; 4], u16) = ([10, 0, 0, 1], 7448);

    /// An `InitSyn` header with no body: all `admit` reads.
    const SYN: [u8; 1] = [wire_const::T_MID_INIT];
    /// An `InitAck` header.
    const ACK: [u8; 1] = [wire_const::T_MID_INIT | wire_const::FLAG_T_INIT_A];
    /// A keep-alive header: any message that opens nothing.
    const KEEP_ALIVE: [u8; 1] = [wire_const::T_MID_KEEP_ALIVE];

    #[test]
    fn the_init_syn_header_is_told_from_every_other() {
        assert!(is_init_syn(&SYN));
        assert!(
            is_init_syn(&[wire_const::T_MID_INIT | 0x80]),
            "the Z flag is not the A flag"
        );
        assert!(!is_init_syn(&ACK), "an InitAck opens nothing");
        assert!(!is_init_syn(&[]), "an empty datagram opens nothing");
        for mid in (0u8..0x20).filter(|&mid| mid != wire_const::T_MID_INIT) {
            assert!(!is_init_syn(&[mid, 0, 0]), "MID {mid:#04x} is not an INIT");
        }
    }

    #[test]
    fn a_dialled_link_takes_its_peer_and_nothing_else() {
        let binding = PeerBinding::dialled(PEER);
        assert_eq!(binding.admit(PEER, &ACK), DatagramVerdict::Peer);
        assert_eq!(binding.admit(OTHER, &KEEP_ALIVE), DatagramVerdict::Stray);
        assert_eq!(
            binding.admit(OTHER_PORT, &KEEP_ALIVE),
            DatagramVerdict::Stray
        );
        assert_eq!(binding.admit(OTHER, &SYN), DatagramVerdict::Refused);
        assert_eq!(binding.peer(), Some(PEER), "nothing moves the peer");
        assert_eq!(binding.admit(PEER, &KEEP_ALIVE), DatagramVerdict::Peer);
        assert_eq!(
            binding.foreign(),
            ForeignCounts {
                strays: 2,
                refused: 1
            }
        );
    }

    #[test]
    fn an_accepting_link_is_bound_by_its_first_init_syn_and_only_by_it() {
        let binding = PeerBinding::accepting();
        assert_eq!(binding.peer(), None);
        // Before a session opens, nothing that does not open one binds the link.
        assert_eq!(binding.admit(OTHER, &KEEP_ALIVE), DatagramVerdict::Stray);
        assert_eq!(binding.admit(PEER, &ACK), DatagramVerdict::Stray);
        assert_eq!(binding.peer(), None);
        assert_eq!(binding.admit(PEER, &SYN), DatagramVerdict::Bound);
        assert_eq!(binding.peer(), Some(PEER));
        // Bound: the peer's retransmitted InitSyn is the session's, another's is refused, and a
        // stranger's datagram while the handshake runs moves nothing.
        assert_eq!(binding.admit(PEER, &SYN), DatagramVerdict::Peer);
        assert_eq!(binding.admit(OTHER, &SYN), DatagramVerdict::Refused);
        assert_eq!(binding.admit(OTHER, &KEEP_ALIVE), DatagramVerdict::Stray);
        assert_eq!(binding.peer(), Some(PEER));
        assert_eq!(
            binding.foreign(),
            ForeignCounts {
                strays: 3,
                refused: 1
            }
        );
    }

    #[test]
    fn asking_whether_a_source_is_the_peer_decides_and_counts_nothing() {
        let binding = PeerBinding::dialled(PEER);
        assert!(binding.is_peer(PEER));
        assert!(!binding.is_peer(OTHER));
        assert_eq!(binding.foreign(), ForeignCounts::default());
        assert!(!PeerBinding::<([u8; 4], u16)>::accepting().is_peer(PEER));
    }

    #[test]
    fn only_the_peers_and_the_binding_datagram_are_taken() {
        assert!(DatagramVerdict::Peer.is_taken());
        assert!(DatagramVerdict::Bound.is_taken());
        assert!(!DatagramVerdict::Stray.is_taken());
        assert!(!DatagramVerdict::Refused.is_taken());
    }
}
