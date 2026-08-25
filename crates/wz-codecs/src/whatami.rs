// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh `WhatAmI` node role (Router / Peer / Client) as a typed enum —
//! the single source of truth for "what role" across the wz stack.
//!
//! Before this type the role rode as a bare `u8` in two incompatible forms
//! (the handshake INIT/JOIN cbyte packs it 2-bit; the link-state OAM carries
//! the raw API byte) with the valid set hand-enumerated in four places. This
//! enum makes an illegal role unrepresentable and owns BOTH wire mappings, so
//! every codec adapter converts `WhatAmI <-> its own wire shape` at exactly one
//! place. Ported from zenoh `commons/zenoh-protocol/src/core/whatami.rs`
//! (discriminants Router=0b001, Peer=0b010, Client=0b100); `wz-codecs` is the
//! home because it is the lowest crate every role consumer (the session layer,
//! the routing graph, the runtime driver) already depends on, and it is the
//! wire layer that owns the role's encoding.
//!
//! `no_std`: the whole type is `core`-only (no `alloc`) so the MCU lanes carry
//! it for free.

/// A zenoh node's role. The discriminants are the API-form role bytes zenoh
/// uses (`WhatAmI as u8`): Router = 1, Peer = 2, Client = 4 — a one-hot set so
/// a [`WhatAmIMatcher`]-style bitmask (a later gossip-policy consumer) can test
/// membership with a bitwise AND.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WhatAmI {
    Router = 0b001,
    #[default]
    Peer = 0b010,
    Client = 0b100,
}

impl WhatAmI {
    const U8_R: u8 = Self::Router as u8;
    const U8_P: u8 = Self::Peer as u8;
    const U8_C: u8 = Self::Client as u8;

    /// The API-form role byte (1 / 2 / 4) — what the link-state OAM carries on
    /// the wire and what a one-hot matcher AND-tests. The inverse is
    /// [`TryFrom<u8>`](Self::try_from).
    pub const fn to_api(self) -> u8 {
        self as u8
    }

    /// The 2-bit INIT / JOIN handshake wire form (Router -> 0b00, Peer -> 0b01,
    /// Client -> 0b10), the value packed into the INIT `cbyte` / JOIN cbyte.
    /// The SSOT for the handshake whatami packing: the encoder (the session
    /// `init_cbyte` / JOIN builder) and the decoder (the routing driver) both
    /// route through this pair, so the two halves of the bijection can never
    /// drift. Equals zenoh `commons/zenoh-codec/src/transport/init.rs:84-90`
    /// and pico `_z_whatami_to_uint8` (`(w >> 1) & 0x03`).
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Router => 0b00,
            Self::Peer => 0b01,
            Self::Client => 0b10,
        }
    }

    /// Decode the 2-bit INIT / JOIN wire form back to the role. `None` for the
    /// reserved `0b11` pattern a conforming encoder never emits — zenoh rejects
    /// it at decode (`init.rs:171` `_ => Err(DidntRead)`); pico's arithmetic
    /// `1 << (b & 0x03)` would instead yield the out-of-set value 8. Returning
    /// `None` keeps a malformed role unrepresentable rather than admitting it.
    pub const fn from_wire(wire: u8) -> Option<Self> {
        match wire & 0b11 {
            0b00 => Some(Self::Router),
            0b01 => Some(Self::Peer),
            0b10 => Some(Self::Client),
            _ => None,
        }
    }

    /// The lowercase role name, matching zenoh `WhatAmI::to_str`.
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Peer => "peer",
            Self::Client => "client",
        }
    }
}

impl TryFrom<u8> for WhatAmI {
    type Error = ();

    /// Map an API-form role byte (1 / 2 / 4) to the role, rejecting anything
    /// out of the set. Replaces the routing graph's hand-rolled
    /// `is_valid_whatami` — the single validator for a wire-carried role byte.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            Self::U8_R => Ok(Self::Router),
            Self::U8_P => Ok(Self::Peer),
            Self::U8_C => Ok(Self::Client),
            _ => Err(()),
        }
    }
}

impl From<WhatAmI> for u8 {
    fn from(w: WhatAmI) -> Self {
        w as u8
    }
}

impl core::fmt::Display for WhatAmI {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.to_str())
    }
}

/// A set of [`WhatAmI`] roles as a one-hot bitmask — the gossip-policy gate that
/// asks "does this target's role belong to the set I gossip to?". Membership is
/// a bitwise AND with the role's one-hot API byte (`Router = 0b001`,
/// `Peer = 0b010`, `Client = 0b100`), so a router-or-peer matcher is `0b011`.
/// The load-bearing consumer is the link-state driver's `gossip_target`
/// (zenoh's per-target send gate, `gossip_target.matches(face_whatami)`).
///
/// Ported from zenoh `commons/zenoh-protocol/src/core/whatami.rs`, with one
/// deliberate simplification: zenoh wraps the set in a `NonZeroU8` (a bit-7
/// marker keeps it non-zero) purely so `Option<WhatAmIMatcher>` occupies one
/// byte in its config tables. wz stores the matcher directly (no `Option`
/// niche to exploit), so a plain `u8` bitset — `empty()` = `0` — carries the
/// identical `matches` semantics without the marker bit or its `unsafe`
/// constructor. `core`-only, like [`WhatAmI`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WhatAmIMatcher(u8);

impl WhatAmIMatcher {
    /// The empty set — matches no role (the gate sends to nobody).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Add [`WhatAmI::Router`] to the set.
    pub const fn router(self) -> Self {
        Self(self.0 | WhatAmI::Router as u8)
    }

    /// Add [`WhatAmI::Peer`] to the set.
    pub const fn peer(self) -> Self {
        Self(self.0 | WhatAmI::Peer as u8)
    }

    /// Add [`WhatAmI::Client`] to the set.
    pub const fn client(self) -> Self {
        Self(self.0 | WhatAmI::Client as u8)
    }

    /// Whether the set is empty — a gate that admits no target.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether `w` is in the set — the gossip-target membership test (zenoh
    /// `WhatAmIMatcher::matches`). AND against the role's one-hot API byte.
    pub const fn matches(self, w: WhatAmI) -> bool {
        (self.0 & w.to_api()) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{WhatAmI, WhatAmIMatcher};

    #[test]
    fn api_byte_round_trips_and_rejects_out_of_set() {
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(WhatAmI::try_from(w.to_api()), Ok(w));
            assert_eq!(u8::from(w), w.to_api());
        }
        assert_eq!(WhatAmI::to_api(WhatAmI::Router), 1);
        assert_eq!(WhatAmI::to_api(WhatAmI::Peer), 2);
        assert_eq!(WhatAmI::to_api(WhatAmI::Client), 4);
        // out-of-set api bytes (incl. the reserved one-hot 8) are rejected.
        for bad in [0u8, 3, 5, 8, 255] {
            assert_eq!(WhatAmI::try_from(bad), Err(()));
        }
    }

    #[test]
    fn wire_round_trips_and_rejects_reserved() {
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(WhatAmI::from_wire(w.to_wire()), Some(w));
        }
        assert_eq!(WhatAmI::to_wire(WhatAmI::Router), 0);
        assert_eq!(WhatAmI::to_wire(WhatAmI::Peer), 1);
        assert_eq!(WhatAmI::to_wire(WhatAmI::Client), 2);
        // 0b11 reserved -> None (a conforming encoder never emits it).
        assert_eq!(WhatAmI::from_wire(0b11), None);
    }

    #[test]
    fn wire_mapping_is_byte_equal_to_the_prior_arithmetic_form() {
        // The migration replaces init_cbyte's `(api >> 1) & 3` and the driver's
        // `1 << (wire & 3)` (pico's _z_whatami_to/from_uint8) with this enum.
        // Pin byte-equality so the SSOT consolidation is behaviour-preserving.
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(
                w.to_wire(),
                (w.to_api() >> 1) & 0x03,
                "to_wire vs (api>>1)&3"
            );
            assert_eq!(1u8 << w.to_wire(), w.to_api(), "1<<wire vs api");
        }
    }

    #[test]
    fn matcher_membership_is_a_one_hot_bitset() {
        // The zenoh peer/router default gossip target: router|peer, not client.
        let rp = WhatAmIMatcher::empty().router().peer();
        assert!(rp.matches(WhatAmI::Router));
        assert!(rp.matches(WhatAmI::Peer));
        assert!(
            !rp.matches(WhatAmI::Client),
            "client is never a gossip target"
        );
        assert!(!rp.is_empty());

        // The empty set admits no role.
        let e = WhatAmIMatcher::empty();
        assert!(e.is_empty());
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert!(!e.matches(w));
        }

        // A single-role matcher admits only that role.
        let c = WhatAmIMatcher::empty().client();
        assert!(c.matches(WhatAmI::Client));
        assert!(!c.matches(WhatAmI::Router));
        assert!(!c.matches(WhatAmI::Peer));
    }
}
