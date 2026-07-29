// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y450 — §5.18 time: the NODE-scoped Hybrid Logical Clock ([`NodeHlc`]) and
//! the per-role enablement map that decides whether a node has one at all
//! ([`TimestampingEnabled`]).
//!
//! ## Why this module exists (the R311xw carry, closed)
//!
//! [`crate::timestamp_source`] built a FRESH [`uhlc::HLC`] inside
//! `FallbackStamp::new`, and its own module note recorded the resulting hazard as
//! hypothetical — "two storages on the SAME node could stamp two simultaneous
//! un-timestamped samples with the same `(time, zid)`" — with the prescribed fix
//! deferred until "the second consumer lands". The second consumer LANDED in
//! R311y69 (`ext-pubsub-advanced-publisher` stamps every cached put through the
//! same seam), so from then on a build with `time-hlc,ext-pubsub-advanced-publisher`
//! held TWO independent HLCs deriving the SAME `uhlc::ID` from the same node zid
//! and keeping SEPARATE `last_time` — which breaks the very premise uhlc's
//! uniqueness guarantee rests on. This module is that deferred promotion: ONE
//! clock per node, borrowed by every consumer.
//!
//! ## The zenoh shape this mirrors
//!
//! zenoh builds the node clock once, in the Runtime, and hands `Arc` clones out:
//!
//! ```text
//! // zenoh/src/net/runtime/mod.rs:147-148
//! let hlc = (*unwrap_or_default!(config.timestamping().enabled().get(whatami)))
//!     .then(|| Arc::new(HLCBuilder::new().with_id(uhlc::ID::from(&zid)).build()));
//! let router = Arc::new(Router::new(zid, whatami, hlc.clone(), &config)?);
//! ```
//!
//! Two things follow from that `.then(..)`, and both are load-bearing here:
//!
//! 1. The clock is `Option`, gated on THIS node's role. With zenoh's shipped
//!    default (`enabled: { router: true, peer: false, client: false }` —
//!    `DEFAULT_CONFIG.json5:206`) a peer / client node has NO clock. Always
//!    constructing one would make wz stamp where zenoh does not, which is a
//!    foreign-observable divergence in the opposite direction from the one an
//!    unimplemented atom produces — so [`TimestampingEnabled::default`] carries
//!    zenoh's map verbatim and `None` is the default path off a router.
//! 2. The `None` case is NOT "no timestamp". zenoh's own auto-stamp consumer
//!    resolves it to a plain wall clock:
//!
//!    ```text
//!    // zenoh/src/api/session.rs:833-843 — Session::new_timestamp()
//!    match self.0.runtime.hlc() {
//!        Some(hlc) => hlc.new_timestamp(),
//!        None => Timestamp::new(SystemTime::now().., self.0.zid().into()),
//!    }
//!    ```
//!
//!    and that is what the storage plugin stamps an un-timestamped sample with
//!    (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs:182`,
//!    `sample.timestamp().cloned().unwrap_or(self.session.new_timestamp())`).
//!    So wz's pre-existing `time-hlc`-off behaviour — [`crate::timestamp_source::wall_clock_ntp64`]
//!    paired with the node's own zid — already WAS zenoh's `None` branch; the
//!    role gate simply reaches it on a peer, exactly as upstream does. A
//!    peer-hosted storage getting wall-clock rather than HLC stamps is parity,
//!    not a regression.
//!
//! ## Cost when the feature is off
//!
//! [`NodeHlc`] is a ZERO-SIZED struct without `time-hlc` (the single field is
//! cfg'd away), so every holder — [`crate::timestamp_source::FallbackStamp`], the
//! two forwarders — carries it UNCONDITIONALLY and no constructor signature
//! changes across the toggle. That is deliberate: a cfg'd-away parameter would
//! push the feature split into six call sites, and this project has been bitten
//! before by a cfg that silently compiles a proof out.

use wz_codecs::whatami::WhatAmI;

/// zenoh's `timestamping.enabled` per-role map: whether a node of a given role
/// timestamps data messages that do not already carry one.
///
/// The wire-visible policy knob for §5.18. zenoh accepts either a single boolean
/// or a per-role table for this field ("Accepts a single boolean value or
/// different values for router, peer and client" —
/// `DEFAULT_CONFIG.json5:204-206`); [`Self::all`] is the single-boolean form and
/// the struct literal is the table form, so both zenoh spellings are expressible
/// rather than only the one wz happens to default to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampingEnabled {
    /// Router-role nodes timestamp. zenoh default: `true`.
    pub router: bool,
    /// Peer-role nodes timestamp. zenoh default: `false`.
    pub peer: bool,
    /// Client-role nodes timestamp. zenoh default: `false`.
    pub client: bool,
}

impl Default for TimestampingEnabled {
    /// zenoh's shipped default, verbatim: `{ router: true, peer: false,
    /// client: false }` (`DEFAULT_CONFIG.json5:206`). Only a router stamps.
    fn default() -> Self {
        Self {
            router: true,
            peer: false,
            client: false,
        }
    }
}

impl TimestampingEnabled {
    /// The single-boolean zenoh spelling — `enabled: true` / `enabled: false`
    /// applies to every role.
    pub const fn all(enabled: bool) -> Self {
        Self {
            router: enabled,
            peer: enabled,
            client: enabled,
        }
    }

    /// Resolve the map against THIS node's role — zenoh's
    /// `config.timestamping().enabled().get(whatami)`.
    pub const fn get(self, whatami: WhatAmI) -> bool {
        match whatami {
            WhatAmI::Router => self.router,
            WhatAmI::Peer => self.peer,
            WhatAmI::Client => self.client,
        }
    }
}

/// The node-scoped Hybrid Logical Clock: ONE clock per node, `Arc`-shared by
/// every auto-stamp consumer on it (the storage capture leg, the advanced
/// publisher, and the two forward seams), or absent when this node's role does
/// not timestamp.
///
/// wz's counterpart of zenoh's `Option<Arc<HLC>>` on the Runtime
/// (`zenoh/src/net/runtime/mod.rs:147`, reachable as `Runtime::hlc()` at `:336`).
/// Cheap to [`Clone`] — an `Arc` bump — because the sharing IS the point: two
/// clocks with the same `uhlc::ID` are worse than no clock, since uhlc's
/// "unique across the system" guarantee silently stops holding while every
/// individual stamp still looks well-formed.
///
/// Zero-sized without `time-hlc`; see the module note on why holders take it
/// unconditionally.
#[derive(Clone, Default)]
pub struct NodeHlc {
    /// `None` = this node does not timestamp (role gate), which consumers
    /// resolve to the plain wall clock — zenoh's `Session::new_timestamp()`
    /// `None` arm.
    #[cfg(feature = "time-hlc")]
    clock: Option<std::sync::Arc<NodeClock>>,
}

/// The clock plus the identity its stamps carry. Held behind one `Arc` so a
/// clone cannot separate the two — the `uhlc::ID` inside `hlc` is DERIVED from
/// `zid`, and a stamp pairing one node's time word with another's zid would be
/// the same uniqueness break this module exists to remove.
#[cfg(feature = "time-hlc")]
struct NodeClock {
    hlc: uhlc::HLC,
    /// This node's zid, as `TimestampHint::zid` carries it on every stamp.
    zid: Vec<u8>,
}

impl NodeHlc {
    /// Build this node's clock: `Some` when [`TimestampingEnabled`] says a node
    /// of role `whatami` timestamps, `None` otherwise. The `uhlc::ID` derives
    /// from `zid` ([`hlc_id_from_zid`]) and the physical clock is wz's
    /// [`wall_clock_ntp64`](crate::timestamp_source::wall_clock_ntp64) SSOT.
    ///
    /// Mirrors zenoh's `(*..enabled().get(whatami)).then(|| Arc::new(..))` — the
    /// gate is evaluated ONCE at node construction, not per stamp, so a build
    /// that does not stamp pays nothing per message.
    ///
    /// Call this ONCE per node and clone the result to each consumer. Building
    /// it twice re-introduces the duplicate-`ID` defect the module note
    /// describes; that is why the parameter list is the node's identity and
    /// role rather than anything a per-consumer call site would have handy.
    #[cfg_attr(not(feature = "time-hlc"), allow(unused_variables))]
    pub fn for_node(zid: &[u8], whatami: WhatAmI, enabled: TimestampingEnabled) -> Self {
        #[cfg(feature = "time-hlc")]
        {
            let clock = enabled
                .get(whatami)
                .then(|| build_clock(zid, wz_physical_clock));
            Self { clock }
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            Self {}
        }
    }

    /// A node that does not timestamp. Distinct from [`Self::for_node`] with a
    /// disabling map only in that it names the intent at the call site (a test
    /// fixture, or a construction path with no role to consult yet).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether this node holds a clock — zenoh's `runtime.hlc().is_some()`.
    /// The `active <=> cfg-toggle` observable: `false` on every build without
    /// `time-hlc`, and on a `time-hlc` build whose role disables stamping.
    pub fn is_stamping(&self) -> bool {
        #[cfg(feature = "time-hlc")]
        {
            self.clock.is_some()
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            false
        }
    }

    /// Mint the next timestamp off this node's clock, or `None` when the node
    /// does not stamp. The stamp pairs the HLC's NTP64 time word with the NODE's
    /// zid, which is what zenoh's `hlc.new_timestamp()` carries (the HLC's
    /// `uhlc::ID` IS the node zid).
    ///
    /// Successive calls strictly increase even within one physical instant —
    /// that is the logical counter in the low `uhlc::CSIZE` bits of the NTP64
    /// fraction, and it is the whole reason a node prefers this over the bare
    /// wall clock.
    pub fn stamp(&self) -> Option<wz_session_core::sample::TimestampHint> {
        #[cfg(feature = "time-hlc")]
        {
            let clock = self.clock.as_deref()?;
            Some(wz_session_core::sample::TimestampHint {
                time: clock.hlc.new_timestamp().get_time().as_u64(),
                zid: clock.zid.clone(),
            })
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            None
        }
    }

    /// R311y450 — the forward-path stamp: zenoh's `treat_timestamp!` macro
    /// (`zenoh/src/net/routing/dispatcher/pubsub.rs:176-210`), applied to a Push
    /// this node is about to forward.
    ///
    /// Three branches, and the split matters:
    ///
    /// - No clock (role gate off, or `time-hlc` absent) → the Push passes
    ///   through UNTOUCHED, byte-identical to a build without this seam. This is
    ///   the default on a peer / client.
    /// - Put with NO timestamp → mint one ("Timestamp not present; add one",
    ///   `pubsub.rs:203-205`). This is the branch a foreign subscriber can
    ///   witness: a Put that entered the node bare leaves it stamped.
    /// - Put WITH a timestamp → ABSORB it into the clock
    ///   (`hlc.update_with_timestamp`, `pubsub.rs:184`), so this node's future
    ///   stamps sort after a timestamp it has relayed. On the error return
    ///   (the peer's timestamp is further ahead than uhlc's drift bound) zenoh
    ///   branches on `drop_future_timestamp`; wz implements the `false` arm —
    ///   REPLACE the timestamp — which is zenoh's shipped default
    ///   (`DEFAULT_CONFIG.json5:207-209`, "If set to false (default), messages
    ///   with timestamps in the future are retimestamped"). The `true` arm (drop
    ///   the message) is NOT implemented and NOT exposed as a knob: nothing in
    ///   the oracle inventory can drive a future timestamp past the drift bound,
    ///   so a config field for it would be inert by construction.
    ///
    /// A `Del` body is left alone, faithfully — zenoh guards the whole macro on
    /// `if let PushBody::Put(data)` (`pubsub.rs:181`).
    ///
    /// Call ONCE per Push, at the head of the forward, BEFORE fan-out: every
    /// egress leg must carry the SAME timestamp. zenoh stamps at `pubsub.rs:328`
    /// and fans the one stamped `msg` out to all of `route`.
    #[cfg(feature = "codec-push")]
    pub fn treat_timestamp(&self, push: &mut wz_codecs::push::PushOwned) {
        #[cfg(feature = "time-hlc")]
        {
            let Some(clock) = self.clock.as_deref() else {
                return;
            };
            if !wz_session_core::push_build::push_is_put(push) {
                return;
            }
            if let Some(inbound) = wz_session_core::push_build::read_push_timestamp(push) {
                if clock
                    .hlc
                    .update_with_timestamp(&to_uhlc_timestamp(&inbound))
                    .is_ok()
                {
                    return;
                }
                // Absorb rejected the inbound timestamp (beyond the drift
                // bound). zenoh's default `drop_future_timestamp: false` arm
                // replaces it rather than dropping the message.
            }
            if let Some(stamp) = self.stamp() {
                let _ = wz_session_core::push_build::set_push_timestamp(push, &stamp);
            }
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            let _ = push;
        }
    }
}

impl core::fmt::Debug for NodeHlc {
    /// Prints the OBSERVABLE state (does this node stamp) rather than the
    /// clock's interior. `uhlc::HLC`'s `last_time` is behind a spin lock and
    /// reading it to format a debug line would contend with live stamping.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeHlc")
            .field("stamping", &self.is_stamping())
            .finish()
    }
}

/// Lift a wz [`TimestampHint`](wz_session_core::sample::TimestampHint) into the
/// `uhlc::Timestamp` the absorb path needs. The hint's `zid` becomes the
/// `uhlc::ID` through the same [`hlc_id_from_zid`] clamp the node's own id uses,
/// so a malformed inbound zid degrades to the guard value instead of failing the
/// absorb for a reason unrelated to the time word.
#[cfg(feature = "time-hlc")]
fn to_uhlc_timestamp(hint: &wz_session_core::sample::TimestampHint) -> uhlc::Timestamp {
    uhlc::Timestamp::new(uhlc::NTP64(hint.time), hlc_id_from_zid(&hint.zid))
}

/// Assemble one node clock over an injectable physical `clock`.
///
/// The physical clock is a parameter for one reason, and it is a testing reason
/// worth stating: with the REAL wall clock, two independently built HLCs still
/// produce a strictly increasing interleaved sequence, because the physical
/// clock advances between reads and masks the fork. Only a FROZEN clock isolates
/// the shared logical counter, so only a frozen clock can tell "one shared
/// clock" apart from "two clocks with the same id" — the precise defect R311y450
/// removes. A test that cannot make that distinction would pass on the broken
/// code, which is worse than no test.
#[cfg(feature = "time-hlc")]
fn build_clock(zid: &[u8], clock: fn() -> uhlc::NTP64) -> std::sync::Arc<NodeClock> {
    std::sync::Arc::new(NodeClock {
        hlc: uhlc::HLCBuilder::new()
            .with_clock(clock)
            .with_id(hlc_id_from_zid(zid))
            .build(),
        zid: zid.to_vec(),
    })
}

/// The HLC's physical clock: wz's wall-clock NTP64 SSOT lifted into a
/// `uhlc::NTP64` (byte-identical to uhlc's own `system_time_clock`, but routed
/// through wz's single recipe so the HLC, the digest publisher's Hot-era bound
/// and the aligner's answer `now` cannot drift apart). A plain `fn` so it
/// satisfies `HLCBuilder::with_clock(fn() -> NTP64)`.
#[cfg(feature = "time-hlc")]
fn wz_physical_clock() -> uhlc::NTP64 {
    uhlc::NTP64(crate::timestamp_source::wall_clock_ntp64())
}

/// Derive a non-zero `uhlc::ID` from a node `zid`. `uhlc::ID` is 1..=16
/// little-endian bytes and must be non-zero; a real zid satisfies both, but
/// clamp to `MAX_SIZE` and guard the all-zero / empty edge so clock construction
/// (and the absorb path, which derives an id from an INBOUND zid) can never
/// panic on a value that arrived off the wire.
#[cfg(feature = "time-hlc")]
fn hlc_id_from_zid(zid: &[u8]) -> uhlc::ID {
    let len = zid.len().min(uhlc::ID::MAX_SIZE);
    uhlc::ID::try_from(&zid[..len])
        .unwrap_or_else(|_| uhlc::ID::try_from(&[1u8][..]).expect("constant non-zero id is valid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zenoh_default_map_stamps_only_on_a_router() {
        // DEFAULT_CONFIG.json5:206 verbatim. A peer or client node must NOT
        // stamp: doing so would make wz add timestamps where zenoh does not,
        // which a foreign subscriber can see.
        let enabled = TimestampingEnabled::default();
        assert!(enabled.get(WhatAmI::Router));
        assert!(!enabled.get(WhatAmI::Peer));
        assert!(!enabled.get(WhatAmI::Client));
    }

    #[test]
    fn the_single_boolean_spelling_applies_to_every_role() {
        // zenoh accepts `enabled: true` as well as the per-role table.
        for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert!(TimestampingEnabled::all(true).get(role));
            assert!(!TimestampingEnabled::all(false).get(role));
        }
    }

    #[test]
    fn a_role_gated_off_node_holds_no_clock() {
        // True in BOTH feature configs (a build without `time-hlc` never
        // stamps), so this test is not gated.
        let off = NodeHlc::for_node(&[0x01], WhatAmI::Peer, TimestampingEnabled::default());
        assert!(!off.is_stamping());
        assert!(off.stamp().is_none());
        assert!(!NodeHlc::disabled().is_stamping());
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_stamping_node_mints_strictly_increasing_stamps_carrying_its_zid() {
        let zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let node = NodeHlc::for_node(&zid, WhatAmI::Router, TimestampingEnabled::default());
        assert!(node.is_stamping());
        let mut prev = 0u64;
        for _ in 0..1000 {
            let stamp = node.stamp().expect("a router-role node stamps");
            assert_eq!(stamp.zid, zid, "the stamp carries the NODE identity");
            assert!(
                stamp.time > prev,
                "HLC stamps must strictly increase: {} !> {prev}",
                stamp.time
            );
            prev = stamp.time;
        }
    }

    /// A physical clock that never moves, so the only remaining source of
    /// increase is the HLC's logical counter. See [`build_clock`] for why the
    /// discriminating tests below cannot use the real one.
    #[cfg(feature = "time-hlc")]
    fn frozen_clock() -> uhlc::NTP64 {
        uhlc::NTP64(0x0000_1234_0000_0000)
    }

    /// A stamping node whose physical clock is frozen.
    #[cfg(feature = "time-hlc")]
    fn frozen_node(zid: &[u8]) -> NodeHlc {
        NodeHlc {
            clock: Some(build_clock(zid, frozen_clock)),
        }
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn clones_share_one_clock_rather_than_forking_it() {
        // THE DEFECT THIS MODULE EXISTS TO REMOVE, as a RED-reproducing test.
        // Before R311y450 each consumer built its own HLC from the same node
        // zid, so two clocks derived the SAME `uhlc::ID` while keeping separate
        // `last_time`; two stamps minted "simultaneously" through different
        // consumers could then collide on `(time, zid)`.
        //
        // The physical clock MUST be frozen for this to discriminate. Measured:
        // with the real wall clock this same assertion PASSES against two
        // independently built clocks — the physical advance between reads hides
        // the fork — so a wall-clock version of this test would have gone green
        // on the broken code. Frozen, a forked pair repeats time words (each
        // counts up from the same frozen instant on its own `last_time`) and the
        // strict-increase assertion fails; one shared clock cannot repeat.
        let node = frozen_node(&[0x07]);
        let other = node.clone();
        let mut prev = 0u64;
        for _ in 0..500 {
            for stamp in [
                node.stamp().expect("stamping"),
                other.stamp().expect("stamping"),
            ] {
                assert!(
                    stamp.time > prev,
                    "interleaved stamps from two handles must share one counter: {} !> {prev}",
                    stamp.time
                );
                prev = stamp.time;
            }
        }
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn the_logical_counter_advances_under_a_frozen_physical_clock() {
        // Isolate the counter: with the physical clock frozen the only way
        // successive timestamps can increase is the low-CSIZE-bit counter (the
        // `else { last_time += 1 }` branch inside uhlc). The real-clock
        // monotonicity test above cannot prove this — its clock may always
        // advance on its own.
        let node = frozen_node(&[0x01]);
        let mut prev = node.stamp().expect("stamping").time;
        for _ in 0..16 {
            let next = node.stamp().expect("stamping").time;
            assert!(
                next > prev,
                "frozen clock: counter must advance: {next} !> {prev}"
            );
            prev = next;
        }
    }

    // ── The forward-path stamp (`treat_timestamp`), the zenoh macro mirror.
    //
    // These need `codec-push` (the Push codec) and `pubsub-timestamp` (the
    // send-side gate `set_push_timestamp` routes through — with it off a forward
    // stamp is a deliberate no-op, so asserting a timestamp appeared would be
    // asserting against the gate).
    #[cfg(all(feature = "codec-push", feature = "pubsub-timestamp"))]
    mod forward_stamp {
        use super::*;
        use wz_session_core::push_build::build_push_literal;
        // The stamping-path fixtures and their builders exist only where a clock
        // can exist — without `time-hlc` the only reachable branch is the
        // non-stamping one below, and an unconditional import would be dead
        // (this crate denies warnings).
        #[cfg(feature = "time-hlc")]
        use wz_session_core::push_build::{
            build_push_del_literal, build_push_literal_with_meta, read_push_timestamp,
        };

        /// A Put whose inline timestamp slot is empty — what a client that does
        /// not set one puts on the wire.
        fn bare_put() -> wz_codecs::push::PushOwned {
            build_push_literal("demo/hlc", b"v").expect("build put")
        }

        /// A Put carrying `time` paired with `zid`.
        #[cfg(feature = "time-hlc")]
        fn stamped_put(time: u64, zid: &[u8]) -> wz_codecs::push::PushOwned {
            let meta = wz_session_core::metadata::PushMetadata {
                timestamp: Some(wz_session_core::sample::TimestampHint {
                    time,
                    zid: zid.to_vec(),
                }),
                ..Default::default()
            };
            build_push_literal_with_meta("demo/hlc", b"v", &meta).expect("build stamped put")
        }

        #[test]
        fn a_non_stamping_node_leaves_the_push_byte_identical() {
            // The default path off a router, and the ONLY path on a build without
            // `time-hlc`: the forward wire is unchanged by this seam existing.
            let node = NodeHlc::for_node(&[0x01], WhatAmI::Peer, TimestampingEnabled::default());
            let before = bare_put();
            let mut after = before.clone();
            node.treat_timestamp(&mut after);
            assert_eq!(before, after, "a non-stamping node must not touch the Push");
        }

        #[cfg(feature = "time-hlc")]
        #[test]
        fn an_untimestamped_put_gets_one_and_the_header_bit_agrees() {
            // zenoh `pubsub.rs:203-205` — "Timestamp not present; add one". THE
            // foreign-observable branch: a pico subscriber prints
            // `with timestamp:` only when the field is present.
            let node_zid = [0xA1, 0xB2];
            let node =
                NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default());
            let mut push = bare_put();
            assert!(
                read_push_timestamp(&push).is_none(),
                "the fixture must start bare or this proves nothing"
            );
            node.treat_timestamp(&mut push);
            let ts = read_push_timestamp(&push).expect("a router stamps an un-timestamped Put");
            assert_eq!(ts.zid, node_zid, "the stamp carries the ROUTER's zid");
            assert!(
                ts.time >= (1u64 << 32),
                "a real post-epoch NTP64, not a bare counter: {}",
                ts.time
            );
            // The field and its header flag must move together — a set field with
            // `_Z_FLAG_Z_P_T` clear shifts the peer's decode of the rest of the
            // body. Checked on the wire header, not via the accessor that reads
            // the field, so this cannot pass on a field-only edit.
            let wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
                panic!("fixture is a Put");
            };
            assert_eq!(put.header & 0x20, 0x20, "_Z_FLAG_Z_P_T must be set");
        }

        #[cfg(feature = "time-hlc")]
        #[test]
        fn a_del_is_neither_stamped_nor_allowed_to_advance_the_clock() {
            // zenoh guards the whole macro on `if let PushBody::Put(data)`
            // (`pubsub.rs:181`). TWO properties here, and the second is the one
            // that makes the `push_is_put` guard load-bearing:
            //
            // 1. the Del passes through unchanged — which `set_push_timestamp`'s
            //    own variant match would deliver even with the guard deleted, so
            //    this assertion ALONE does not test the guard; and
            // 2. treating a Del must not MINT a timestamp, because a mint advances
            //    the node's logical counter for a message that can never carry the
            //    result.
            //
            // Only a frozen physical clock can see (2): under it each mint adds
            // exactly 1, so the delta across the treat is the witness. Measured
            // both ways — with the guard the delta is 1, with the guard deleted it
            // is 2 and this reds.
            let node = frozen_node(&[0x01]);
            assert!(node.is_stamping(), "the fixture only bites on a live clock");
            let before = build_push_del_literal("demo/hlc").expect("build del");
            let mut after = before.clone();
            let t0 = node.stamp().expect("stamping").time;
            node.treat_timestamp(&mut after);
            let t1 = node.stamp().expect("stamping").time;
            assert_eq!(before, after, "a Del must not be stamped");
            assert_eq!(
                t1 - t0,
                1,
                "treating a Del must not mint a timestamp (frozen clock: 1 per mint)"
            );
        }

        #[cfg(feature = "time-hlc")]
        #[test]
        fn an_inbound_timestamp_within_the_drift_bound_is_absorbed_not_replaced() {
            // zenoh `pubsub.rs:184-185` — `update_with_timestamp` Ok arm does
            // NOTHING to the message. The relayed Put must keep the PUBLISHER's
            // timestamp; rewriting it would destroy the ordering the publisher
            // established. Absorption is still observable locally: the node's
            // next own stamp must sort after the timestamp it just absorbed.
            let node = NodeHlc::for_node(&[0x01], WhatAmI::Router, TimestampingEnabled::default());
            let publisher_zid = [0x0B, 0x0C];
            let inbound_time = crate::timestamp_source::wall_clock_ntp64();
            let mut push = stamped_put(inbound_time, &publisher_zid);
            node.treat_timestamp(&mut push);
            let ts = read_push_timestamp(&push).expect("still stamped");
            assert_eq!(
                (ts.time, ts.zid.as_slice()),
                (inbound_time, publisher_zid.as_slice()),
                "an absorbed timestamp must survive the relay untouched"
            );
            assert!(
                node.stamp().expect("stamping").time > inbound_time,
                "the absorbed timestamp must have advanced this node's clock"
            );
        }

        #[cfg(feature = "time-hlc")]
        #[test]
        fn an_inbound_timestamp_beyond_the_drift_bound_is_replaced() {
            // The error arm: uhlc rejects a timestamp further ahead than its
            // 500ms drift bound, and zenoh's shipped `drop_future_timestamp:
            // false` (`DEFAULT_CONFIG.json5:207-209`) RETIMESTAMPS rather than
            // dropping. 10s ahead is two orders of magnitude past the bound, so
            // this does not sit near a threshold.
            let node_zid = [0x01];
            let node =
                NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default());
            let ten_seconds = 10u64 << 32;
            let future_time = crate::timestamp_source::wall_clock_ntp64() + ten_seconds;
            let mut push = stamped_put(future_time, &[0x0B, 0x0C]);
            node.treat_timestamp(&mut push);
            let ts = read_push_timestamp(&push).expect("still stamped");
            assert_ne!(
                ts.time, future_time,
                "a future timestamp past the drift bound must be replaced"
            );
            assert_eq!(ts.zid, node_zid, "the replacement carries THIS node's zid");
            assert!(
                ts.time < future_time,
                "the replacement is this node's own now, behind the rejected future"
            );
        }
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_oversized_or_empty_zid_still_yields_a_usable_clock() {
        // `uhlc::ID` is 1..=16 non-zero bytes. A 32-byte zid clamps and an
        // empty one falls back to the guard id, so neither panics during
        // construction — the absorb path derives an id from an INBOUND zid, so
        // this guard is reachable from the wire, not only from a test.
        let long = NodeHlc::for_node(&[0xAB; 32], WhatAmI::Router, TimestampingEnabled::all(true));
        assert!(long.stamp().is_some());
        let empty = NodeHlc::for_node(&[], WhatAmI::Router, TimestampingEnabled::all(true));
        assert!(empty.stamp().is_some());
    }
}
