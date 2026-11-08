// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A1a — modular sequence-number arithmetic (zenoh-pico
//! `src/transport/utils.c` mirror).
//!
//! Zenoh transport SNs live on a modular ring whose size is negotiated by
//! the 2-bit `seq_num_res` wire code (INIT/JOIN). Ordering on the ring is
//! the HALF-WINDOW precedence rule — `right` follows `left` iff the modular
//! distance is non-zero and at most half the ring (`_z_sn_precedes`,
//! utils.c:80). This is NOT a plain `<` compare: a peer that batches or
//! skips SNs stays inside the window, while a stale / duplicated datagram
//! falls outside and is dropped (the R311jq review established the same
//! rule on the TX side — frame-scoped minting keeps gaps far below
//! half-window).
//!
//! First consumer: the multicast data plane (session-fsm §2.3 RxDispatch
//! rules applied per-peer, §3.1 `Frame -> per-peer RxDispatch`). UDP
//! multicast reorders and duplicates datagrams, so every inbound Frame is
//! admitted against the announcing peer's last-seen SN before its payload
//! reaches the application registries. Pure no_std + no_alloc;
//! unconditional (like [`crate::reliability`]).

/// Map the 2-bit `seq_num_res` wire code to the SN ring MASK (ring size -
/// 1). Mirrors zenoh-pico `_z_sn_max` / `_z_sn_modulo_mask` (utils.c):
/// `0x00` -> 7-bit, `0x01` -> 14-bit, `0x02` -> 28-bit, `0x03` -> 63-bit
/// (the usable VLE widths of 1/2/4/8-byte encodings). An out-of-range code
/// yields the widest mask — the defensive arm zenoh-pico leaves at 0, but
/// a zero mask would collapse the ring to one value and drop every frame;
/// wz prefers the permissive window (the codec cannot produce a code > 3
/// from the 2-bit field, so the arm is unreachable from the wire).
pub const fn mask_from_res(seq_num_res: u8) -> u64 {
    match seq_num_res {
        0x00 => (u8::MAX >> 1) as u64,
        0x01 => (u16::MAX >> 2) as u64,
        0x02 => (u32::MAX >> 4) as u64,
        _ => u64::MAX >> 1,
    }
}

/// The narrowest SN ring a session can negotiate that holds `sn`: the first of
/// the four masks [`mask_from_res`] answers for, in order, that is at least
/// `sn`. An `sn` past the widest ring is answered with the widest, which no
/// sender of a conforming session can pass.
pub const fn narrowest_mask_covering(sn: u64) -> u64 {
    let mut res = 0u8;
    while res < 3 && mask_from_res(res) < sn {
        res += 1;
    }
    mask_from_res(res)
}

/// Half the ring (`_z_sn_half`): the largest forward distance still
/// considered "ahead" by [`precedes`].
pub const fn half(mask: u64) -> u64 {
    mask >> 1
}

/// Half-window precedence (`_z_sn_precedes`): does `right` strictly follow
/// `left` on the ring of `mask`? True iff the modular distance
/// `(right - left) & mask` is non-zero and at most [`half`] the ring.
/// Equality is NOT precedence (a duplicate SN is stale).
pub const fn precedes(mask: u64, left: u64, right: u64) -> bool {
    let distance = right.wrapping_sub(left) & mask;
    distance != 0 && distance <= half(mask)
}

/// Ring-consecutive check (`_z_sn_consecutive`): is `right` exactly one
/// step after `left` on the ring of `mask`? The modular distance form
/// accepts a non-canonical `right` from the wire (any representative of
/// the same residue), exactly as zenoh-pico's masked subtraction does.
/// First consumer: the reassembly dispatcher's strict in-order
/// continuation check (§2.5) — a plain `==` on `wrapping_add(1)` diverges
/// from this at the ring seam (R311ka F-5).
pub const fn consecutive(mask: u64, left: u64, right: u64) -> bool {
    right.wrapping_sub(left) & mask == 1
}

/// Modular decrement (`_z_sn_decrement`). Used to seed a peer's last-seen
/// SN from its JOIN-advertised `next_sn` (the next SN it WILL send): the
/// baseline is one before, so the first data frame at exactly `next_sn`
/// passes [`precedes`].
pub const fn decrement(mask: u64, sn: u64) -> u64 {
    sn.wrapping_sub(1) & mask
}

/// Modular increment (`_z_sn_increment`): the TX-side step on the same
/// ring. The multicast TX path mints with this directly ([`TxSn`]); the
/// unicast chokepoint keeps a raw monotonic counter and projects each
/// minted value onto the ring (`fetch_add & mask` — the equivalent walk,
/// see `SessionLinkActions::next_outbound_frame_sn`), and the fragment
/// walk (`frame_encode::fragment_body`) steps with this (R311kb).
pub const fn increment(mask: u64, sn: u64) -> u64 {
    sn.wrapping_add(1) & mask
}

/// A1c — per-channel TX sequence-number mint state (zenoh-pico
/// `_z_transport_common_t._sn_tx_reliable` / `_sn_tx_best_effort` pair on
/// one ring). The multicast drive loop owns one instance: each outbound
/// data frame [`mint`](TxSn::mint)s its channel's next SN, and the
/// periodic JOIN beacon advertises the LIVE `next_*` values so receivers
/// seed their RX baselines one before the next real frame (§3.2
/// `init_rx_seq`). Fields are public — the JOIN encoder reads them
/// directly, and tests construct arbitrary ring positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxSn {
    /// The ring mask ([`mask_from_res`]); both channels share it.
    pub mask: u64,
    /// Next SN the reliable channel will send.
    pub next_reliable: u64,
    /// Next SN the best-effort channel will send.
    pub next_best_effort: u64,
}

impl TxSn {
    /// A fresh announcer: both channels start at 0 on the ring of
    /// `mask` (zenoh-pico seeds from `Z_SN_RESOLUTION`-bounded random;
    /// wz starts at 0 — the JOIN advertisement makes any start valid).
    pub const fn new(mask: u64) -> Self {
        Self {
            mask,
            next_reliable: 0,
            next_best_effort: 0,
        }
    }

    /// Mint the next SN for a channel: returns the current `next_*` and
    /// advances it one step on the ring.
    pub fn mint(&mut self, reliable: bool) -> u64 {
        let slot = if reliable {
            &mut self.next_reliable
        } else {
            &mut self.next_best_effort
        };
        let sn = *slot;
        *slot = increment(self.mask, sn);
        sn
    }

    /// R2929 — the transport message carrying `sn` on a channel has been
    /// written: the next one this channel will WRITE is the one after it.
    pub fn written(&mut self, reliable: bool, sn: u64) {
        let slot = if reliable {
            &mut self.next_reliable
        } else {
            &mut self.next_best_effort
        };
        *slot = increment(self.mask, sn);
    }
}

/// R311ke — per-channel unicast RX SN gate state, the zenoh-pico
/// `_z_transport_peer_unicast_t._sn_rx_reliable` / `_sn_rx_best_effort`
/// pair (transport/peer.c:212-214 seeds both, unicast/rx.c:100-185 gates
/// every inbound FRAME / FRAGMENT against them per channel). The unicast
/// counterpart of the multicast `PeerSlot.rx_sn_*` fields — one peer per
/// unicast session, so the session actions hold a single instance.
///
/// `None` = unseeded: the handshake's OpenSyn/OpenAck `initial_sn` seeds
/// both channels via [`RxSn::seed`] before any legal data frame, so an
/// unseeded channel only sees a frame on a non-conforming peer — wz
/// admits-and-tracks it (permissive first-frame baseline) rather than
/// dropping, mirroring the multicast slot's JOIN-seeded tolerance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RxSn {
    pub reliable: Option<u64>,
    pub best_effort: Option<u64>,
}

impl RxSn {
    /// Seed both channels one before the peer's announced `initial_sn`
    /// (zenoh-pico peer.c:212-214 `_z_sn_decrement(sn_res, initial_sn_rx)`
    /// into BOTH `_sn_rx_*`), so the first frame at exactly `initial_sn`
    /// passes [`Self::admit`].
    pub fn seed(&mut self, mask: u64, initial_sn: u64) {
        let baseline = decrement(mask, initial_sn);
        self.reliable = Some(baseline);
        self.best_effort = Some(baseline);
    }

    /// Admit one inbound frame SN on its channel: the half-window
    /// [`precedes`] gate against the last accepted SN; a pass stores
    /// `sn` as the new baseline (rx.c stores the accepted `msg->_sn`).
    /// `false` = stale / duplicate / reordered — the caller drops the
    /// frame without advancing the FSM (pico's silent drop).
    pub fn admit(&mut self, mask: u64, reliable: bool, sn: u64) -> bool {
        !matches!(self.admit_judged(mask, reliable, sn), RxAdmit::Stale)
    }

    /// [`Self::admit`] that also says whether the admitted frame jumped
    /// forward: the baseline moves exactly as `admit` moves it, and the
    /// verdict names what `admit` folds into `true` or `false`. A forward
    /// jump of `k > 1` is [`RxAdmit::Gap`] with `k - 1` frames missing; the
    /// first frame of an unseeded channel has no baseline to jump from and is
    /// [`RxAdmit::Accept`], and so is a step across the ring seam.
    pub fn admit_judged(&mut self, mask: u64, reliable: bool, sn: u64) -> RxAdmit {
        let slot = if reliable {
            &mut self.reliable
        } else {
            &mut self.best_effort
        };
        match *slot {
            Some(last) if !precedes(mask, last, sn) => RxAdmit::Stale,
            Some(last) => {
                // `precedes` bounds the distance to 1..=half the ring.
                let distance = sn.wrapping_sub(last) & mask;
                *slot = Some(sn);
                if distance > 1 {
                    RxAdmit::Gap {
                        missing: u32::try_from(distance - 1).unwrap_or(u32::MAX),
                    }
                } else {
                    RxAdmit::Accept
                }
            }
            None => {
                *slot = Some(sn);
                RxAdmit::Accept
            }
        }
    }
}

/// What the RX SN gate made of one inbound frame ([`RxSn::admit_judged`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAdmit {
    /// The frame is the next one on its channel, or the first one seen.
    Accept,
    /// The frame is admitted but `missing` frames between the last admitted
    /// one and this one never arrived (a forward jump on the ring, saturated
    /// at `u32::MAX`).
    Gap { missing: u32 },
    /// A duplicate, a backward step or a jump past half the ring: the frame
    /// is dropped and the baseline stays.
    Stale,
}

/// Whether a forward gap on the reliable channel ends the link under `mode`
/// (the `reliable-gap-reconnect` policy). `peer_declarations_final` is whether
/// the peer's initial declarations have all arrived. A pure decision: the
/// caller has already established that the frame is a reliable-channel gap.
pub const fn reacts_to_gap(
    mode: crate::policy::ReliableGapReconnect,
    peer_declarations_final: bool,
) -> bool {
    use crate::policy::ReliableGapReconnect as Mode;
    match mode {
        Mode::Off => false,
        Mode::UntilDeclarationsSynced => !peer_declarations_final,
        Mode::Always => true,
    }
}

/// R311y215 (transport-qos) — the inbound Frame/Fragment SN gates: ONE
/// [`RxSn`] per `Priority` conduit when `transport-qos` compiles (zenoh's
/// per-(priority,reliability) `TransportPriorityRx`,
/// `io/zenoh-transport/src/unicast/universal/rx.rs`), else the single R311ke
/// conduit. The RX mirror of [`crate::session_actions::FrameTxConduits`]: the
/// array SHAPE is compile-time behind the feature (no runtime `is_qos` heap
/// sizing on an MCU no-alloc build), and a non-QoS session admits only
/// `conduit[Priority::DEFAULT]` (the send seam forces `priority = Data` when
/// `!is_qos()`, so no peer ever fills the others). Every conduit is seeded from
/// the one OpenSyn/OpenAck `initial_sn` — zenoh seeds each priority Rx from the
/// single announced origin (SN-safety S2/S3).
///
/// The per-(priority,reliability) split is what makes a QoS session's RX gate
/// INDEPENDENT across priorities: a `high` frame at SN=5 and a `low` frame at
/// SN=3 both admit (they gate on SEPARATE conduits), where the pre-QoS single
/// gate would drop the second as out-of-window. That independence is the
/// property the priority-select multilink (R311y216) relies on.
#[derive(Debug, Clone, PartialEq, Eq)]
// Without `transport-qos` the struct is a single `RxSn` field whose `Default`
// is trivially derivable (clippy::derivable_impls); under the feature the
// `[RxSn; NUM]` array has no generic `Default` derive, so the seed-all-conduits
// default is written by hand below.
#[cfg_attr(not(feature = "transport-qos"), derive(Default))]
pub struct RxConduits {
    #[cfg(feature = "transport-qos")]
    conduits: [RxSn; crate::qos::Priority::NUM],
    #[cfg(not(feature = "transport-qos"))]
    conduit: RxSn,
}

#[cfg(feature = "transport-qos")]
impl Default for RxConduits {
    fn default() -> Self {
        Self {
            conduits: core::array::from_fn(|_| RxSn::default()),
        }
    }
}

impl RxConduits {
    /// The `(priority)` conduit — `conduits[priority]` under `transport-qos`,
    /// the single conduit otherwise (priority ignored, no cfg-skew — mirrors
    /// [`crate::session_actions::FrameTxConduits::select`]).
    #[inline]
    fn select_mut(&mut self, _priority: crate::qos::Priority) -> &mut RxSn {
        #[cfg(feature = "transport-qos")]
        {
            &mut self.conduits[_priority as usize]
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            &mut self.conduit
        }
    }

    /// Seed EVERY conduit one before `initial_sn` (the OpenSyn/OpenAck origin),
    /// so the first frame at exactly `initial_sn` passes [`RxSn::admit`] on any
    /// priority (SN-safety S2/S3 — all conduits share the one announced origin).
    pub fn seed(&mut self, mask: u64, initial_sn: u64) {
        #[cfg(feature = "transport-qos")]
        for c in &mut self.conduits {
            c.seed(mask, initial_sn);
        }
        #[cfg(not(feature = "transport-qos"))]
        self.conduit.seed(mask, initial_sn);
    }

    /// Admit one inbound frame SN on its `(priority, reliable)` conduit — the
    /// half-window [`RxSn::admit`] against THAT conduit's last accepted SN.
    /// Under a non-QoS session `priority` is `DEFAULT` and there is one conduit,
    /// so behavior is identical to the pre-QoS single gate.
    pub fn admit(
        &mut self,
        priority: crate::qos::Priority,
        mask: u64,
        reliable: bool,
        sn: u64,
    ) -> bool {
        self.select_mut(priority).admit(mask, reliable, sn)
    }

    /// [`Self::admit`] with the verdict of [`RxSn::admit_judged`]: the same
    /// conduit, the same baseline move, and a forward jump named.
    pub fn admit_judged(
        &mut self,
        priority: crate::qos::Priority,
        mask: u64,
        reliable: bool,
        sn: u64,
    ) -> RxAdmit {
        self.select_mut(priority).admit_judged(mask, reliable, sn)
    }
}

/// R311y227 (transport-qos) — the multicast TX per-priority SN conduits: ONE
/// [`TxSn`] per `Priority` conduit when `transport-qos` compiles (the multicast
/// mirror of the unicast [`crate::session_actions::FrameTxConduits`] and the RX
/// [`RxConduits`]), else the single 2-channel [`TxSn`] — the pico-faithful
/// multicast default (zenoh-pico multicast is ALWAYS non-qos, its JOIN sends
/// `_is_qos = false`, `src/transport/multicast/transport.c:125`). The array SHAPE
/// is compile-time behind the feature (no runtime `is_qos` heap sizing on an MCU
/// no-alloc build, which never compiles `transport-qos`); a multicast session
/// that has not negotiated is_qos mints only `conduit[Priority::DEFAULT]` — the
/// emit seam ([`crate::multicast_tx::multicast_tx_emit`]) forces `priority =
/// Data` unless the group is_qos, so no non-DEFAULT frame ever rides (else a
/// non-qos / pico receiver would `bail!("Unknown priority")`,
/// zenoh `io/zenoh-transport/src/multicast/rx.rs`).
///
/// The multicast drive loop owns one instance; each outbound data frame mints
/// its `(priority, reliable)` conduit's next SN, and the periodic JOIN beacon
/// advertises the LIVE `next_*` values. A non-qos JOIN advertises the one
/// DEFAULT conduit ([`Self::advertise_default`]); a qos JOIN additionally
/// advertises all `Priority::NUM` conduits in its `ext_qos` (zenoh's
/// `Join.ext_qos`, `commons/zenoh-protocol/src/transport/join.rs`
/// @ `pub ext_qos: Option<ext::QoSType>`).
///
/// DIVERGENCE from the unicast [`crate::session_actions::FrameTxConduits`]: that
/// mirror uses `AtomicTxSn` because the unicast writer is reached concurrently
/// (the writer task vs the caller); the multicast drive loop is a SINGLE task
/// that owns `&mut` its conduits, so a plain non-atomic [`TxSn`] is sufficient
/// and cheaper (no atomics on the MCU no-alloc profile's hot path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastTxConduits {
    #[cfg(feature = "transport-qos")]
    conduits: [TxSn; crate::qos::Priority::NUM],
    #[cfg(not(feature = "transport-qos"))]
    conduit: TxSn,
}

impl MulticastTxConduits {
    /// A fresh announcer on the ring of `mask`: every conduit starts at 0, like
    /// [`TxSn::new`] (the JOIN advertisement makes any start valid).
    pub fn new(mask: u64) -> Self {
        #[cfg(feature = "transport-qos")]
        {
            Self {
                conduits: core::array::from_fn(|_| TxSn::new(mask)),
            }
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            Self {
                conduit: TxSn::new(mask),
            }
        }
    }

    /// The shared ring mask (every conduit is built on the same `mask`, so the
    /// DEFAULT conduit's is authoritative) — the fragment walk's masking point.
    pub fn mask(&self) -> u64 {
        self.advertise_default().mask
    }

    /// Test-only mutable handle on the DEFAULT (Data) conduit — the fragment
    /// re-frame tests pin a specific `next_reliable` ring position (to fix the
    /// VLE-width body offset) without minting to it. Not a production path (the
    /// emit only ever [`Self::mint`]s). Gated on `transport-fragmentation` — its
    /// sole consumer is the oversize-fragment re-frame test, which itself needs
    /// the fragmentation codec.
    #[cfg(all(test, feature = "transport-fragmentation"))]
    pub(crate) fn default_conduit_mut(&mut self) -> &mut TxSn {
        self.select_mut(crate::qos::Priority::DEFAULT)
    }

    /// The `(priority)` conduit — `conduits[priority]` under `transport-qos`, the
    /// single conduit otherwise (priority ignored, no cfg-skew — mirrors
    /// [`RxConduits::select_mut`]).
    #[inline]
    fn select_mut(&mut self, _priority: crate::qos::Priority) -> &mut TxSn {
        #[cfg(feature = "transport-qos")]
        {
            &mut self.conduits[_priority as usize]
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            &mut self.conduit
        }
    }

    /// Mint the next SN for a `(priority, reliable)` conduit: the current `next_*`
    /// on THAT conduit, advanced one step. Under a non-qos multicast session the
    /// emit seam passes `Priority::DEFAULT` and there is one conduit, so behavior
    /// is byte-identical to the pre-QoS single [`TxSn::mint`].
    pub fn mint(&mut self, priority: crate::qos::Priority, reliable: bool) -> u64 {
        self.select_mut(priority).mint(reliable)
    }

    /// R2929 — the transport message carrying `sn` on the `(priority, reliable)`
    /// conduit has been WRITTEN ([`TxSn::written`]). A loop whose sends pass
    /// through a queue keeps a second set of conduits advanced only by this,
    /// and advertises THAT in its JOIN: a receiver re-seeds its expected SN
    /// from every JOIN (`MulticastDispatcher::ingest_join_qos`, as zenoh-pico's
    /// `_z_multicast_handle_join_inner` does), so a JOIN that advertised an SN
    /// minted but still queued would make the receiver drop that message as
    /// stale when it arrives.
    pub fn written(&mut self, priority: crate::qos::Priority, reliable: bool, sn: u64) {
        self.select_mut(priority).written(reliable, sn);
    }

    /// The DEFAULT-priority conduit as a plain [`TxSn`] snapshot — the source of
    /// the single-conduit JOIN advertisement (`Join.next_sn`, and the whole beacon
    /// on a non-qos session). Zenoh's qos JOIN sets `next_sn = PrioritySn::DEFAULT`
    /// (a dummy — the real per-priority SNs ride `ext_qos`,
    /// `io/zenoh-transport/src/multicast/link.rs:487`); wz advertises the live
    /// DEFAULT conduit here, identical on a non-qos session.
    pub fn advertise_default(&self) -> TxSn {
        #[cfg(feature = "transport-qos")]
        {
            self.conduits[crate::qos::Priority::DEFAULT as usize]
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            self.conduit
        }
    }

    /// The live `next_*` of every priority conduit, for the qos JOIN's `ext_qos`
    /// advertisement (zenoh `Box<[PrioritySn; NUM]>`). Only present under
    /// `transport-qos` (a non-qos build advertises the single conduit via
    /// [`Self::advertise_default`]).
    #[cfg(feature = "transport-qos")]
    pub fn advertise_per_priority(&self) -> [TxSn; crate::qos::Priority::NUM] {
        self.conduits
    }
}

/// R311y227 — one multicast per-peer RX SN gate pair (last-seen reliable +
/// best_effort), the raw-`u64` twin of the unicast [`RxSn`] (no unseeded `Option`
/// state — a multicast slot is ALWAYS JOIN-seeded before any frame). One per
/// `Priority` conduit inside [`MulticastRxConduits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MulticastRxPair {
    pub reliable: u64,
    pub best_effort: u64,
}

/// R311y227 — the multicast per-peer RX SN conduits: one [`MulticastRxPair`] per
/// `Priority` when `transport-qos` compiles (the per-peer RX twin of the TX
/// [`MulticastTxConduits`], mirroring zenoh's per-peer `priority_rx`,
/// `io/zenoh-transport/src/multicast/transport.rs`), else the single 2-channel
/// pair — the pico-faithful multicast default. The array SHAPE is compile-time
/// (an MCU no-alloc build never compiles `transport-qos`, so a peer table stays
/// 2-channel). A non-qos peer fills only the DEFAULT conduit (its frames carry no
/// `ext_qos` → decoded priority DEFAULT), so its gate is identical to the pre-QoS
/// single pair. The RX mirror of the seed/gate the raw `PeerSlot.rx_sn_*` fields
/// carried before R311y227.
#[derive(Debug, Clone, PartialEq, Eq)]
// Without `transport-qos` the single `conduit` field's `Default` is trivially
// derivable (clippy::derivable_impls); under the feature the `[_; NUM]` array has
// no generic `Default`, so the seed-all-conduits default is written by hand below
// — the same split `RxConduits` uses.
#[cfg_attr(not(feature = "transport-qos"), derive(Default))]
pub struct MulticastRxConduits {
    #[cfg(feature = "transport-qos")]
    conduits: [MulticastRxPair; crate::qos::Priority::NUM],
    #[cfg(not(feature = "transport-qos"))]
    conduit: MulticastRxPair,
}

#[cfg(feature = "transport-qos")]
impl Default for MulticastRxConduits {
    fn default() -> Self {
        Self {
            conduits: [MulticastRxPair::default(); crate::qos::Priority::NUM],
        }
    }
}

impl MulticastRxConduits {
    /// The `(priority)` conduit — `conduits[priority]` under `transport-qos`, the
    /// single conduit otherwise (priority ignored, no cfg-skew — mirrors
    /// [`RxConduits::select_mut`] / [`MulticastTxConduits::select_mut`]).
    #[inline]
    fn select_mut(&mut self, _priority: crate::qos::Priority) -> &mut MulticastRxPair {
        #[cfg(feature = "transport-qos")]
        {
            &mut self.conduits[_priority as usize]
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            &mut self.conduit
        }
    }

    /// Seed the DEFAULT conduit's two channels one before the JOIN-advertised
    /// `next_sn_*` — the NON-qos path (a non-qos peer advertises a single 2-channel
    /// pair; zenoh-pico `_z_conduit_sn_list_decrement`). Every other conduit stays
    /// at 0: a non-qos peer never sends a non-DEFAULT frame. Identical to the
    /// pre-R311y227 `PeerSlot::seed_from_join` 2-SN seed.
    pub fn seed_plain(&mut self, mask: u64, next_reliable: u64, next_best_effort: u64) {
        // JOIN-authoritative reset: a non-qos peer advertises ONLY the DEFAULT
        // 2-channel pair, so every OTHER conduit returns to its unseeded baseline.
        // This clears any stale non-DEFAULT baseline a recycled slot — or a peer
        // that was qos on a PRIOR JOIN and re-JOINs non-qos (or whose qos ext
        // fails to parse) — left behind, closing the re-JOIN-consistency gap the
        // R311y227 review flagged. pico re-copies the whole `_sn_rx_sns` from every
        // JOIN (multicast/rx.c:453-456), so a full reset is the faithful model.
        *self = Self::default();
        let d = self.select_mut(crate::qos::Priority::DEFAULT);
        d.reliable = decrement(mask, next_reliable);
        d.best_effort = decrement(mask, next_best_effort);
    }

    /// Seed EVERY priority conduit one before its OWN JOIN-advertised `next_sn`
    /// pair — the qos path. The JOIN `ext_qos` carries `Priority::NUM` DISTINCT
    /// pairs, so each conduit gates on its own origin; this is NOT the single-origin
    /// unicast [`RxConduits::seed`] (mirror-latent-gap: a shared origin would
    /// stale-drop the high-priority stream whose SN sits far from the low's).
    /// zenoh `priority_rx[i].sync(next_sns[i])`, multicast/transport.rs.
    #[cfg(feature = "transport-qos")]
    pub fn seed_per_priority(
        &mut self,
        mask: u64,
        pairs: &[MulticastRxPair; crate::qos::Priority::NUM],
    ) {
        for (c, p) in self.conduits.iter_mut().zip(pairs.iter()) {
            c.reliable = decrement(mask, p.reliable);
            c.best_effort = decrement(mask, p.best_effort);
        }
    }

    /// Admit one inbound frame SN on its `(priority, reliable)` conduit — the
    /// half-window [`precedes`] gate against THAT conduit's last-seen SN; a pass
    /// advances the baseline. `false` = stale / duplicate / reordered (the caller
    /// drops the frame). Under a non-qos peer `priority` is DEFAULT and only the
    /// DEFAULT conduit is ever exercised, so this is byte-identical to the
    /// pre-R311y227 single-pair `precedes`-then-store gate.
    pub fn admit(
        &mut self,
        priority: crate::qos::Priority,
        mask: u64,
        reliable: bool,
        sn: u64,
    ) -> bool {
        let pair = self.select_mut(priority);
        let last = if reliable {
            pair.reliable
        } else {
            pair.best_effort
        };
        if !precedes(mask, last, sn) {
            return false;
        }
        if reliable {
            pair.reliable = sn;
        } else {
            pair.best_effort = sn;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 2-bit wire codes map to the zenoh-pico `_z_sn_max` masks
    /// (utils.c: U8_MAX>>1 / U16_MAX>>2 / U32_MAX>>4 / U64_MAX>>1).
    #[test]
    fn mask_mapping_mirrors_pico() {
        assert_eq!(mask_from_res(0x00), 0x7F);
        assert_eq!(mask_from_res(0x01), 0x3FFF);
        assert_eq!(mask_from_res(0x02), 0x0FFF_FFFF);
        assert_eq!(mask_from_res(0x03), u64::MAX >> 1);
    }

    /// The four masks are spelled out, and both sides of each edge are
    /// checked: an SN equal to a mask fits it, one past it needs the next.
    #[test]
    fn the_narrowest_mask_covering_an_sn_is_the_first_that_holds_it() {
        for (sn, mask) in [
            (0u64, 0x7Fu64),
            (127, 0x7F),
            (128, 0x3FFF),
            (0x3FFF, 0x3FFF),
            (0x4000, 0x0FFF_FFFF),
            (1 << 20, 0x0FFF_FFFF),
            (0x0FFF_FFFF, 0x0FFF_FFFF),
            (0x1000_0000, 0x7FFF_FFFF_FFFF_FFFF),
            (u64::MAX, 0x7FFF_FFFF_FFFF_FFFF),
        ] {
            assert_eq!(narrowest_mask_covering(sn), mask, "sn {sn}");
        }
    }

    /// Forward steps within half the ring precede; equality and stale
    /// (backward) SNs do not.
    #[test]
    fn precedes_basic_ordering() {
        let mask = mask_from_res(0x00); // 7-bit ring, half = 63
        assert!(precedes(mask, 0, 1));
        assert!(precedes(mask, 0, 63), "exactly half is still ahead");
        assert!(
            !precedes(mask, 0, 64),
            "past half-window is stale/ambiguous"
        );
        assert!(!precedes(mask, 5, 5), "duplicate SN is not ahead");
        assert!(!precedes(mask, 5, 4), "backward step is stale");
    }

    /// Precedence is modular: wrap-around across the ring boundary stays
    /// within the half-window (the property a plain `<` compare breaks).
    #[test]
    fn precedes_wraps_around_ring() {
        let mask = mask_from_res(0x00); // ring size 128
        assert!(precedes(mask, 127, 0), "127 -> 0 wraps forward");
        assert!(precedes(mask, 120, 10), "distance 18 across the seam");
        assert!(
            !precedes(mask, 0, 127),
            "0 -> 127 is distance 127 = backward"
        );
    }

    /// Seeding a baseline with [`decrement`] admits the very first frame
    /// at the JOIN-advertised `next_sn` (the §3.2 `init_rx_seq` contract).
    #[test]
    fn decrement_seeds_baseline_for_next_sn() {
        let mask = mask_from_res(0x02);
        let next_sn = 42;
        let baseline = decrement(mask, next_sn);
        assert!(precedes(mask, baseline, next_sn));
        // next_sn = 0 wraps the baseline to the ring top and still admits.
        let baseline = decrement(mask, 0);
        assert_eq!(baseline, mask);
        assert!(precedes(mask, baseline, 0));
    }

    /// Consecutive is the distance-1 ring check: it holds across the seam
    /// (`mask -> 0`) and rejects duplicates, gaps, and backward steps —
    /// the `_z_sn_consecutive` contract the reassembly continuation gate
    /// mirrors.
    #[test]
    fn consecutive_holds_across_ring_seam() {
        let mask = mask_from_res(0x02);
        assert!(consecutive(mask, 5, 6));
        assert!(consecutive(mask, mask, 0), "seam step mask -> 0");
        assert!(!consecutive(mask, 5, 5), "duplicate is not consecutive");
        assert!(!consecutive(mask, 5, 7), "gap is not consecutive");
        assert!(!consecutive(mask, 6, 5), "backward step is not consecutive");
        // A non-canonical wire value of the same residue still passes
        // (the masked-subtraction form, not a canonical-form compare).
        assert!(consecutive(mask, mask, 2 * (mask + 1)));
    }

    /// Increment walks the ring and wraps at the mask (TX mint step).
    #[test]
    fn increment_wraps_at_mask() {
        let mask = mask_from_res(0x01);
        assert_eq!(increment(mask, 0), 1);
        assert_eq!(increment(mask, mask), 0);
    }

    /// R311ke — [`RxSn`] seeds both channels from `initial_sn` and gates
    /// per channel: the first frame at `initial_sn` passes, a duplicate or
    /// backward SN is rejected, and the channels track independently.
    #[test]
    fn rx_sn_seeds_and_gates_per_channel() {
        let mask = mask_from_res(0x00);
        let mut rx = RxSn::default();
        rx.seed(mask, 42);
        assert!(rx.admit(mask, true, 42), "first frame at initial_sn passes");
        assert!(!rx.admit(mask, true, 42), "duplicate SN is stale");
        assert!(!rx.admit(mask, true, 41), "backward SN is stale");
        assert!(rx.admit(mask, true, 43), "next forward SN passes");
        // The best-effort channel still sits at the seed baseline.
        assert!(
            rx.admit(mask, false, 42),
            "channels gate independently (best-effort untouched by reliable)"
        );
    }

    /// An unseeded [`RxSn`] channel admits the first frame and tracks from
    /// it (permissive baseline for a non-conforming peer that skipped the
    /// handshake seeding) — subsequent stale SNs still drop.
    #[test]
    fn rx_sn_unseeded_admits_first_then_gates() {
        let mask = mask_from_res(0x00);
        let mut rx = RxSn::default();
        assert!(
            rx.admit(mask, true, 7),
            "unseeded channel admits-and-tracks"
        );
        assert!(!rx.admit(mask, true, 7), "then gates duplicates");
        assert!(!rx.admit(mask, true, 7 + 65), "past half-window is stale");
    }

    /// A forward jump of `k` is a gap of `k - 1` missing frames and moves the
    /// baseline; equal, backward and past-half-window frames are stale and
    /// leave it where it was.
    #[test]
    fn rx_sn_judged_names_a_forward_gap() {
        let mask = mask_from_res(0x00); // half = 63
        let mut rx = RxSn::default();
        rx.seed(mask, 10);
        assert_eq!(rx.admit_judged(mask, true, 10), RxAdmit::Accept);
        assert_eq!(rx.admit_judged(mask, true, 11), RxAdmit::Accept);
        assert_eq!(
            rx.admit_judged(mask, true, 14),
            RxAdmit::Gap { missing: 2 },
            "11 -> 14 lost 12 and 13"
        );
        assert_eq!(
            rx.admit_judged(mask, true, 14),
            RxAdmit::Stale,
            "the baseline moved to the gapped frame"
        );
        assert_eq!(rx.admit_judged(mask, true, 13), RxAdmit::Stale);
        assert_eq!(rx.admit_judged(mask, true, 15), RxAdmit::Accept);
        assert_eq!(
            rx.admit_judged(mask, true, 15 + 64),
            RxAdmit::Stale,
            "past half the ring is not a jump forward"
        );
        assert_eq!(
            rx.admit_judged(mask, true, 15 + 63),
            RxAdmit::Gap { missing: 62 },
            "exactly half the ring is still ahead"
        );
    }

    /// A step across the ring seam is a consecutive frame, and a jump across
    /// it is a gap of the modular distance.
    #[test]
    fn rx_sn_judged_reads_the_ring_seam_as_distance() {
        let mask = mask_from_res(0x00); // ring of 128
        let mut rx = RxSn::default();
        rx.seed(mask, 0); // baseline = 127
        assert_eq!(rx.admit_judged(mask, true, 0), RxAdmit::Accept);

        let mut rx = RxSn::default();
        rx.seed(mask, 126);
        assert_eq!(rx.admit_judged(mask, true, 126), RxAdmit::Accept);
        assert_eq!(rx.admit_judged(mask, true, 127), RxAdmit::Accept);
        assert_eq!(rx.admit_judged(mask, true, 0), RxAdmit::Accept, "wrap");
        assert_eq!(rx.admit_judged(mask, true, 1), RxAdmit::Accept);

        let mut rx = RxSn::default();
        rx.seed(mask, 126);
        assert_eq!(rx.admit_judged(mask, true, 126), RxAdmit::Accept);
        assert_eq!(
            rx.admit_judged(mask, true, 1),
            RxAdmit::Gap { missing: 2 },
            "126 -> 1 skips 127 and 0"
        );
    }

    /// The first frame of an unseeded channel has nothing to jump from.
    #[test]
    fn rx_sn_judged_first_frame_of_an_unseeded_channel_is_no_gap() {
        let mask = mask_from_res(0x00);
        let mut rx = RxSn::default();
        assert_eq!(rx.admit_judged(mask, true, 100), RxAdmit::Accept);
        assert_eq!(rx.admit_judged(mask, true, 101), RxAdmit::Accept);
        assert_eq!(
            rx.admit_judged(mask, true, 105),
            RxAdmit::Gap { missing: 3 }
        );
    }

    /// The channels judge apart: a gap on one leaves the other's baseline
    /// alone, and the verdict itself does not depend on the channel (the
    /// caller decides which channel may react).
    #[test]
    fn rx_sn_judged_channels_are_independent() {
        let mask = mask_from_res(0x00);
        let mut rx = RxSn::default();
        rx.seed(mask, 0);
        assert_eq!(rx.admit_judged(mask, true, 0), RxAdmit::Accept);
        assert_eq!(rx.admit_judged(mask, true, 5), RxAdmit::Gap { missing: 4 });
        assert_eq!(
            rx.admit_judged(mask, false, 0),
            RxAdmit::Accept,
            "best-effort still sits at the seed"
        );
        assert_eq!(rx.admit_judged(mask, false, 3), RxAdmit::Gap { missing: 2 });
    }

    /// `admit` is `admit_judged` with the verdict folded to a bool: the same
    /// answers and the same baselines over a walk that hits every verdict.
    #[test]
    fn rx_sn_admit_is_the_judged_verdict_folded() {
        let mask = mask_from_res(0x00);
        let mut plain = RxSn::default();
        let mut judged = RxSn::default();
        plain.seed(mask, 5);
        judged.seed(mask, 5);
        for sn in [5u64, 6, 9, 9, 8, 10, 74, 40, 11, 127, 0, 2] {
            let folded = !matches!(judged.admit_judged(mask, true, sn), RxAdmit::Stale);
            assert_eq!(plain.admit(mask, true, sn), folded, "sn {sn}");
            assert_eq!(plain, judged, "baselines after sn {sn}");
        }
    }

    /// The conduit wrapper judges on the conduit's own channel.
    #[test]
    fn rx_conduits_judged_reads_the_conduit_baseline() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut rx = RxConduits::default();
        rx.seed(mask, 1);
        assert_eq!(
            rx.admit_judged(Priority::DEFAULT, mask, true, 1),
            RxAdmit::Accept
        );
        assert_eq!(
            rx.admit_judged(Priority::DEFAULT, mask, true, 4),
            RxAdmit::Gap { missing: 2 }
        );
        assert_eq!(
            rx.admit_judged(Priority::DEFAULT, mask, true, 4),
            RxAdmit::Stale
        );
        assert_eq!(
            rx.admit_judged(Priority::DEFAULT, mask, false, 1),
            RxAdmit::Accept,
            "the best-effort channel was not moved by the reliable gap"
        );
    }

    /// Under QoS each priority judges against its own baseline: a gap on one
    /// is no gap on another.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn rx_conduits_judged_per_priority() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut rx = RxConduits::default();
        rx.seed(mask, 1);
        assert_eq!(
            rx.admit_judged(Priority::RealTime, mask, true, 5),
            RxAdmit::Gap { missing: 4 }
        );
        assert_eq!(
            rx.admit_judged(Priority::Background, mask, true, 1),
            RxAdmit::Accept,
            "the low conduit is still at its seed"
        );
    }

    /// Every cell of the decision: `off` never reacts, `always` always does,
    /// and `until-declarations-synced` reacts only while the peer's initial
    /// declarations have not all arrived.
    #[test]
    fn a_reliable_gap_reacts_by_mode_and_peer_final() {
        use crate::policy::ReliableGapReconnect as Mode;
        assert!(!reacts_to_gap(Mode::Off, false));
        assert!(!reacts_to_gap(Mode::Off, true));
        assert!(reacts_to_gap(Mode::UntilDeclarationsSynced, false));
        assert!(!reacts_to_gap(Mode::UntilDeclarationsSynced, true));
        assert!(reacts_to_gap(Mode::Always, false));
        assert!(reacts_to_gap(Mode::Always, true));
    }

    /// `TxSn::mint` returns the advertised `next_*` and advances per
    /// channel independently; a receiver seeding from the pre-mint
    /// advertisement admits the minted SN.
    #[test]
    fn tx_sn_mints_per_channel() {
        let mask = mask_from_res(0x02);
        let mut tx = TxSn::new(mask);
        let advertised = tx.next_reliable;
        assert_eq!(tx.mint(true), 0);
        assert_eq!(tx.mint(true), 1);
        assert_eq!(tx.mint(false), 0, "channels mint independently");
        assert_eq!(tx.next_reliable, 2);
        assert_eq!(tx.next_best_effort, 1);
        // RX seeding contract: baseline = decrement(advertised next) admits
        // the first minted SN.
        assert!(precedes(mask, decrement(mask, advertised), 0));
    }

    /// R311y215 — the per-priority RX conduits gate INDEPENDENTLY: a
    /// high-priority frame at SN=5 and a low-priority frame at a LOWER SN=3 both
    /// admit, because they gate on SEPARATE conduits. The pre-QoS single gate
    /// would drop the SN=3 frame as out-of-window after admitting SN=5 — this
    /// independence is the non-hollow core of the QoS transport (and the
    /// invariant the R311y216 priority-select multilink relies on).
    #[cfg(feature = "transport-qos")]
    #[test]
    fn rx_conduits_gate_independently_per_priority() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut rx = RxConduits::default();
        // Seed all conduits from one origin: baseline = decrement(1) = 0.
        rx.seed(mask, 1);
        // High conduit admits a forward SN=5, advancing ONLY its own baseline.
        assert!(rx.admit(Priority::RealTime, mask, true, 5));
        // Low conduit still admits the LOWER SN=3 off its own baseline (0) — a
        // shared gate would have advanced to 5 and dropped 3 as stale.
        assert!(
            rx.admit(Priority::Background, mask, true, 3),
            "the low conduit gates on its own baseline, independent of high"
        );
        // Within each conduit the half-window gate still holds.
        assert!(
            !rx.admit(Priority::RealTime, mask, true, 5),
            "high duplicate is stale"
        );
        assert!(
            !rx.admit(Priority::Background, mask, true, 3),
            "low duplicate is stale"
        );
        assert!(
            rx.admit(Priority::Background, mask, true, 4),
            "low advances on its own ring"
        );
        // reliable vs best-effort stay independent WITHIN a priority too.
        assert!(
            rx.admit(Priority::RealTime, mask, false, 2),
            "the high best-effort channel is seeded + gates apart from high reliable"
        );
    }

    /// R311y227 — the multicast TX per-priority conduits mint INDEPENDENTLY: each
    /// `(priority, reliable)` conduit is its own SN ring, the TX twin of
    /// `rx_conduits_gate_independently_per_priority`. This is the property the qos
    /// JOIN's per-priority `ext_qos` advertisement (8 distinct next-SNs) exists to
    /// carry: a `high` frame and a `low` frame drawn in the same instant get
    /// SN=0 EACH on their own conduit, not 0 and 1 off one shared ring.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn mcast_tx_conduits_mint_independently_per_priority() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut tx = MulticastTxConduits::new(mask);
        // Each priority's reliable ring starts at 0 and advances on ITS OWN ring.
        assert_eq!(tx.mint(Priority::RealTime, true), 0);
        assert_eq!(
            tx.mint(Priority::Background, true),
            0,
            "low conduit is its own ring, not the +1 of a shared ring"
        );
        assert_eq!(
            tx.mint(Priority::RealTime, true),
            1,
            "high advances only itself"
        );
        assert_eq!(tx.mint(Priority::Background, true), 1);
        // reliable vs best-effort stay independent WITHIN a priority (TxSn's pair).
        assert_eq!(
            tx.mint(Priority::RealTime, false),
            0,
            "high best-effort is a separate channel"
        );
        // advertise_default reflects the DEFAULT (Data) conduit — untouched above,
        // so still at 0 on both channels (the non-qos JOIN's single advertisement).
        let d = tx.advertise_default();
        assert_eq!((d.next_reliable, d.next_best_effort), (0, 0));
        // Minting the DEFAULT conduit advances what advertise_default reports.
        assert_eq!(tx.mint(Priority::DEFAULT, true), 0);
        assert_eq!(tx.advertise_default().next_reliable, 1);
        // The per-priority advertisement exposes every conduit's live next SN.
        let per = tx.advertise_per_priority();
        assert_eq!(per[Priority::RealTime as usize].next_reliable, 2);
        assert_eq!(per[Priority::Background as usize].next_reliable, 2);
        assert_eq!(per[Priority::DEFAULT as usize].next_reliable, 1);
    }

    /// R311y227 — without `transport-qos` the multicast TX collapses to ONE
    /// conduit (the pico-faithful 2-channel default): every priority mints off the
    /// same ring, byte-identical to the pre-QoS single `TxSn`. Guards the cfg arm
    /// so a non-qos / MCU build never grows a per-priority ring.
    #[cfg(not(feature = "transport-qos"))]
    #[test]
    fn mcast_tx_conduits_collapse_to_one_ring_without_qos() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut tx = MulticastTxConduits::new(mask);
        // Priority is ignored: RealTime then Background share one reliable ring.
        assert_eq!(tx.mint(Priority::RealTime, true), 0);
        assert_eq!(
            tx.mint(Priority::Background, true),
            1,
            "one shared ring: the second mint is +1"
        );
        assert_eq!(tx.advertise_default().next_reliable, 2);
    }

    /// R311y227 — the multicast per-peer RX conduits gate INDEPENDENTLY (the RX
    /// twin of `rx_conduits_gate_independently_per_priority`, seeded from a qos
    /// peer's DISTINCT per-priority JOIN SNs): a high-priority frame at SN=205 and
    /// a low-priority frame at a much lower SN=6 BOTH admit, because each gates on
    /// its own conduit seeded from its own advertised origin. The pre-R311y227
    /// single gate would drop the low frame as out-of-window after the high.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn mcast_rx_conduits_gate_independently_per_priority() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut rx = MulticastRxConduits::default();
        // Seed each conduit from its OWN advertised next-SN (RealTime near 200,
        // Background near 5) — the per-priority seed, NOT a shared origin.
        let mut pairs = [MulticastRxPair::default(); Priority::NUM];
        pairs[Priority::RealTime as usize] = MulticastRxPair {
            reliable: 200,
            best_effort: 0,
        };
        pairs[Priority::Background as usize] = MulticastRxPair {
            reliable: 5,
            best_effort: 0,
        };
        rx.seed_per_priority(mask, &pairs);
        // High conduit admits its forward SN=205 (baseline was 199).
        assert!(rx.admit(Priority::RealTime, mask, true, 205));
        // Low conduit still admits the FAR-LOWER SN=6 off its own baseline (4) — a
        // shared gate would have advanced to 205 and dropped 6 as stale.
        assert!(
            rx.admit(Priority::Background, mask, true, 6),
            "the low conduit gates on its own origin, independent of high"
        );
        // Within each conduit the half-window duplicate gate still holds.
        assert!(
            !rx.admit(Priority::RealTime, mask, true, 205),
            "high dup is stale"
        );
        assert!(
            !rx.admit(Priority::Background, mask, true, 6),
            "low dup is stale"
        );
    }

    /// R311y227 — the non-qos `seed_plain` seeds ONLY the DEFAULT conduit from the
    /// base 2-channel `next_sn` (the pico-faithful path a non-qos peer advertises),
    /// leaving the gate byte-identical to the pre-R311y227 single pair.
    #[test]
    fn mcast_rx_conduits_seed_plain_gates_default_conduit() {
        use crate::qos::Priority;
        let mask = mask_from_res(0x02);
        let mut rx = MulticastRxConduits::default();
        rx.seed_plain(mask, 10, 20); // next_reliable=10, next_best_effort=20
        assert!(
            rx.admit(Priority::DEFAULT, mask, true, 10),
            "first reliable at 10 admits"
        );
        assert!(
            !rx.admit(Priority::DEFAULT, mask, true, 10),
            "duplicate stale"
        );
        assert!(
            rx.admit(Priority::DEFAULT, mask, false, 20),
            "first best-effort at 20 admits"
        );
    }
}
