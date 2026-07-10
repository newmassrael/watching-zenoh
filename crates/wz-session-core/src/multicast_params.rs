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

use wz_codecs::whatami::WhatAmI;

/// R311kq — the PROTOCOL default an omitted JOIN `sn_res` / `batch_size`
/// optional means (zenoh-pico `_Z_DEFAULT_RESOLUTION_SIZE`, protocol/
/// definitions/core.h:22; decode fills it when the S flag is absent,
/// codec/transport.c:155-157). Distinct from any per-deploy CONFIG
/// default: pico's `make_join` advertises (S=1) exactly when its config
/// departs from these protocol constants, so "omitted" is a wire
/// statement of "I run the protocol defaults", not "match me locally".
pub const PROTOCOL_DEFAULT_RESOLUTION: u8 = 0x02;

/// R311kq — the protocol-default multicast batch size an omitted JOIN
/// `batch_size` optional means (zenoh-pico
/// `_Z_DEFAULT_MULTICAST_BATCH_SIZE`, protocol/definitions/core.h:21).
/// NOTE: pico's shipped CONFIG default (`Z_BATCH_MULTICAST_SIZE`,
/// CMakeLists 2048) differs from this protocol constant — a default-built
/// pico therefore always advertises S=1 in its JOIN.
pub const PROTOCOL_DEFAULT_BATCH_SIZE: u16 = 8192;

/// Pack the JOIN resolution cbyte: `seq_num_res` in bits 0-1,
/// `req_id_res` in bits 2-3 (zenoh-pico `_z_join_encode`,
/// codec/transport.c:54-56). The `join` codec carries the byte opaque
/// ("host decomposes", join.scxml); these two helpers are that host
/// decomposition's single home.
pub fn pack_res_cbyte(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

/// Unpack a JOIN resolution cbyte into `(seq_num_res, req_id_res)` —
/// the decode twin of [`pack_res_cbyte`] (zenoh-pico `_z_join_decode`,
/// codec/transport.c:150-152).
pub fn unpack_res_cbyte(cbyte: u8) -> (u8, u8) {
    (cbyte & 0x03, (cbyte >> 2) & 0x03)
}

/// Inputs for each outbound multicast JOIN frame plus the periodic-emit
/// cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastParams {
    /// Zenoh protocol version byte (`Z_PROTO_VERSION`), emitted as JOIN
    /// body byte 0.
    pub version: u8,
    /// This peer's role (Router / Peer / Client). The JOIN encoder
    /// projects it to the cbyte's 2-bit wire form via [`WhatAmI::to_wire`]
    /// (`join` codec `set_whatami`) at the codec edge — the typed role is
    /// stored, not a pre-encoded wire byte (the unicast
    /// [`crate::session_init_params::SessionInitParams::whatami`] is now
    /// the same type, so the two no longer disagree on form). A multicast
    /// peer advertises what it IS (typically Peer), not what it is looking
    /// for (contrast [`crate::scout_params::ScoutParams::what`], a search
    /// mask).
    pub whatami: WhatAmI,
    /// This peer's own zenoh id (1..=16 bytes). The drive loop packs
    /// `zid_len - 1` into the JOIN cbyte high nibble and appends the bytes;
    /// it is the key group members admit the peer under (the §3.2
    /// per-peer-table key).
    pub zid: Vec<u8>,
    /// The lease window this peer advertises in its JOIN (milliseconds).
    /// Group members hold the peer alive for at least this long after each
    /// JOIN; the local sweep lease ([`crate::multicast_dispatch::MulticastConfig::lease_ms`])
    /// is the symmetric inbound side (how long THIS node holds OTHER peers).
    /// R311kr — a whole-second value rides the wire in SECONDS under the
    /// JOIN `T` header flag (zenoh-pico `make_join` parity); the glue owns
    /// that projection, so this field stays milliseconds on both sides.
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
    /// that omits the optional advertises [`PROTOCOL_DEFAULT_RESOLUTION`]
    /// (R311kq — the PROTOCOL default, not this local value; pico decode
    /// semantics).
    pub seq_num_res: u8,
    /// R311kq — this node's 2-bit `req_id_res` wire code (request-id
    /// resolution; JOIN resolution-cbyte bits 2-3, [`pack_res_cbyte`]).
    /// The multicast mirror of
    /// [`crate::session_init_params::SessionInitParams::req_id_res`];
    /// group-agreed like `seq_num_res` (zenoh-pico
    /// `_z_multicast_handle_join_inner` refuses a JOIN advertising a
    /// different one — same incompatible-config guard).
    pub req_id_res: u8,
    /// R311ko — the group-wide outbound frame budget in bytes (zenoh-pico
    /// `Z_BATCH_MULTICAST_SIZE`, CMake default 2048): a data emission whose
    /// encoded `T_MID_FRAME` exceeds this re-frames as a `T_MID_FRAGMENT`
    /// chain ([`crate::frame_encode::multicast_frame_or_fragments`]).
    /// Group-agreed like `seq_num_res` — multicast has no negotiation, so
    /// a JOIN advertising a DIFFERENT batch size is dropped (zenoh-pico
    /// `_z_multicast_handle_join_inner` incompatible-config refuse), and a
    /// JOIN that omits the optional advertises
    /// [`PROTOCOL_DEFAULT_BATCH_SIZE`] (R311kq). The unicast
    /// counterpart is the negotiated-min
    /// `SessionLinkActions::negotiated_batch_mtu`; here the budget is a
    /// per-deploy constant. (pico additionally floors at the link MTU —
    /// `min(link MTU, batch)`, multicast/transport.c:73; the wz UDP driver
    /// exposes no MTU, so the budget alone governs and stays well under
    /// the 65507-byte UDP datagram ceiling at the default.)
    pub batch_size: u16,
    /// R311y227 (transport-qos) — whether THIS node offers the per-priority QoS
    /// conduit on the group: its JOIN carries the `ext_qos` advertisement
    /// (`Box<[PrioritySn; NUM]>`, zenoh `Join.ext_qos`) and its data frames ride
    /// the per-priority conduits with an on-frame `ext_qos`. `false` = the
    /// pico-faithful 2-channel default (zenoh-pico multicast is ALWAYS non-qos —
    /// its JOIN sends `_is_qos = false`, `src/transport/multicast/transport.c:125`),
    /// byte-identical to the pre-QoS wire. Group-agreed (zenoh's multicast QoS is
    /// a deployment-wide choice): a qos node emits qos frames a non-qos / pico
    /// receiver would reject, so the JOIN validator refuses a qos/non-qos
    /// MISMATCH (C2). The field is unconditional (a plain bool) but only ever
    /// `true` under `transport-qos` — a build without the feature has no
    /// per-priority conduit to offer, so the emit / JOIN paths keep it inert.
    /// R311y232 (ACTIVATION) — sourced at the transport spawn seam from the deploy's
    /// multicast-QoS choice (the AP `spawn_router_mcast_egress` / `_ingress` `qos`
    /// param, driven by the demo `--multicast-qos` flag; the MCU multicast_drive
    /// stays `false`, no `transport-qos`). This is the wz analogue of zenoh
    /// `transport.multicast.qos.enabled` — a knob DISTINCT from unicast:
    /// `QoSMulticastConf` defaults `false` (commons/zenoh-config defaults.rs:234)
    /// where `QoSUnicastConf` defaults `true`, and zenoh's multicast manager reads
    /// `config.multicast.is_qos` on its own (multicast/establishment.rs:54,
    /// manager.rs:40), NOT the unicast `is_qos`. So the multicast offer does NOT
    /// reuse the unicast `WzConfig.qos` (an earlier ACTIVATION sketch's premise,
    /// corrected by direct-read). Absent `transport-qos` the whole per-priority
    /// conduit is elided, so the seam forces `false` and the wire stays the
    /// pico-faithful 2-channel default.
    pub is_qos: bool,
}

impl MulticastParams {
    /// R311kq — whether this node's JOIN must carry the S-flag optionals
    /// (`sn_res` cbyte + `batch_size`): exactly when any of them departs
    /// from the protocol defaults, so an omitted optional stays an honest
    /// "I run the protocol defaults" statement (zenoh-pico
    /// `_z_t_msg_make_join`, protocol/definitions/transport.c:117-120).
    pub fn join_advertises_caps(&self) -> bool {
        self.seq_num_res != PROTOCOL_DEFAULT_RESOLUTION
            || self.req_id_res != PROTOCOL_DEFAULT_RESOLUTION
            || self.batch_size != PROTOCOL_DEFAULT_BATCH_SIZE
    }
}

/// R311ls/R311lt — the static parameterization of one multicast drive-loop
/// run, separated from the loop's live collaborators (dispatcher / link /
/// clock handles, the observer callback, the I/O seam) via the
/// Introduce-Parameter-Object refactor. Shared by BOTH transport profiles'
/// drive loops — the AP `wz_runtime_tokio::multicast_glue::drive_multicast_session`
/// and the MCU `wz_session_lwip::multicast_drive::run_multicast_session` — so
/// the "what configures the loop" inputs have one SSOT and each entry point
/// stays within clippy's argument-count bound (the multicast loops are large
/// enough to trip it). The `params` borrow lives for the call's duration; the
/// two scalars are owned.
pub struct MulticastDriveConfig<'a> {
    /// The multicast protocol config (zid, lease, batch_size, JOIN interval,
    /// SN / req-id resolutions) the loop advertises in its JOIN beacon and
    /// enforces on inbound peers.
    pub params: &'a MulticastParams,
    /// Scheduler cadence: the loop falls to a PeerSweep tick every `tick_ms`
    /// (>= the §3.1 lease/3 cadence; sweeping more often only sharpens
    /// eviction, and sweep is idempotent).
    pub tick_ms: u64,
    /// Bounded select-loop / poll-loop budget for tests (`Some(n)`);
    /// production passes `None` to run until the link is lost.
    pub max_iters: Option<usize>,
}

/// R311lt — outcome of one multicast drive-loop run, shared by the AP
/// (`drive_multicast_session`) and MCU (`run_multicast_session`) loops so the
/// two profiles report the same terminal vocabulary. The MCU poll loop never
/// produces [`Self::LinkLost`] (its `try_recv` has no link-loss event — a
/// silent group is just an empty poll), so that variant is AP-only in
/// practice; the enum stays shared for the common cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MulticastOutcome {
    /// The session left Running (e.g. a pre-stopped dispatcher).
    Stopped,
    /// The multicast link was lost (AP only — the `select!` `LinkEvent::Lost`
    /// arm; the MCU poll loop has no equivalent event).
    LinkLost(crate::link::LostCause),
    /// The bounded iteration budget was exhausted (test guard).
    IterationLimit,
}
