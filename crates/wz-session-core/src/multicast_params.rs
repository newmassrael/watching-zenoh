// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round C — per-deploy multicast-transport JOIN parameters.
//!
//! The inputs the multicast drive loop packs into each outbound JOIN frame
//! (`sources/codecs/join.scxml` body = version + cbyte + zid + lease +
//! next-sn), plus the periodic-emit cadence. Pure owned value type;
//! alloc-gated (the `zid` is a `Vec<u8>`). The multicast sibling of
//! [`crate::scout_params::ScoutParams`] (active scouting) and
//! [`crate::session_init_params::SessionInitParams`] (unicast handshake) —
//! kept separate so the handshake-free multicast transport does not couple
//! to either the scouting bundle or the unicast handshake bundle.
//!
//! JOIN is the multicast transport's peer-announcement beacon (session-fsm
//! §3.1/§3.2): unlike unicast (INIT/OPEN handshake) a peer simply
//! multicasts a periodic JOIN carrying its identity + lease, and group
//! members admit it (`MulticastDispatcher::ingest_join`). So these params
//! describe THIS peer's self-advertisement, not a negotiation.

use alloc::vec::Vec;

/// Inputs for each outbound multicast JOIN frame plus the periodic-emit
/// cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastParams {
    /// Zenoh protocol version byte (`Z_PROTO_VERSION`), emitted as JOIN
    /// body byte 0.
    pub version: u8,
    /// This peer's WhatAmI, in the JOIN cbyte wire form (low 2 bits;
    /// `join` codec `set_whatami`). A multicast peer advertises itself, so
    /// this is what it IS (typically PEER), not what it is looking for
    /// (contrast [`crate::scout_params::ScoutParams::what`], a search mask).
    pub whatami: u8,
    /// This peer's own zenoh id (1..=16 bytes). The drive loop packs
    /// `zid_len - 1` into the JOIN cbyte high nibble and appends the bytes;
    /// it is the key group members admit the peer under (the §3.2
    /// per-peer-table key).
    pub zid: Vec<u8>,
    /// The lease window this peer advertises in its JOIN (milliseconds).
    /// Group members hold the peer alive for at least this long after each
    /// JOIN; the local sweep lease ([`crate::multicast_dispatch::MulticastConfig::lease_ms`])
    /// is the symmetric inbound side (how long THIS node holds OTHER peers).
    pub lease_ms: u64,
    /// Period between this peer's outbound JOINs (milliseconds; zenoh
    /// default 2500). The drive loop owns this cadence — the periodic JOIN
    /// is the multicast liveness beacon (there is no separate keepalive on
    /// the handshake-free transport; a peer stays alive while its JOINs keep
    /// arriving).
    pub join_interval_ms: u64,
    /// A1b — this node's 2-bit `seq_num_res` wire code (the SN ring width,
    /// [`crate::sn::mask_from_res`]; wz default `0x02` = 28-bit, matching
    /// the unicast `SessionInitParams::seq_num_res` fixture default and
    /// zenoh-pico's `Z_SN_RESOLUTION`). Multicast peers must agree on the
    /// resolution (there is no negotiation — §3.2 rejection rules drop a
    /// JOIN advertising a different one, zenoh-pico
    /// `_z_multicast_handle_join_inner` incompatible-config refuse); a JOIN
    /// that omits the optional advertises the default and is treated as
    /// this value.
    pub seq_num_res: u8,
}
