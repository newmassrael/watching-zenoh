// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y450 — §5.18 time: the NODE-scoped Hybrid Logical Clock ([`NodeHlc`]) and
//! the per-role enablement map that decides whether a node has one at all
//! ([`TimestampingEnabled`]).
//!
//! ## Why this module exists (the R311xw carry, closed)
//!
//! [`crate::timestamp_source`] built a FRESH `uhlc::HLC` inside
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
//! ## The arithmetic is wz's, the rules are `uhlc`'s
//!
//! The clock is [`wz_session_core::hlc::Hlc`] over an `EpochSource`, not a `uhlc::HLC`. It is
//! `uhlc`'s stamp and absorb rules, held to `uhlc` by a differential test over random clock
//! traces, in one atomic word. Measured on the build machine (release, one stamp per call): a
//! single thread stamps in the same time as `uhlc` (15 ns, nearly all of it the clock read), four
//! threads stamp in 29 ns each where `uhlc`'s lock costs 52 ns, and a refused remote stamp costs
//! 13 ns where `uhlc` costs 78 ns because it formats a message that nobody here reads. Two
//! behaviours differ and are stated where they happen: a source that cannot say what time it is
//! stamps nothing (`uhlc`'s clock had no way to say so), and the bound reads `UHLC_MAX_DELTA_MS`
//! itself since the crate that read it is no longer in the path.
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

    /// The map with ONE role's entry replaced — what a config document that
    /// states `timestamping/enabled` for this node's run-mode means.
    ///
    /// R2112 (open-debt items 102 + 210) — a stock zenoh document resolves this
    /// key against the reading node's own `whatami`
    /// (`config.timestamping().enabled().get(whatami)`), so what a host learns
    /// from its file is ONE role's boolean, not a whole map. Overriding just
    /// that entry keeps the other two at zenoh's shipped values instead of
    /// flattening all three to the one the file happened to answer for — which
    /// [`Self::all`] would do, and which would be a claim the document never
    /// made.
    ///
    /// The resolved role is the one the node PLAYS, so a router-hat host writes
    /// [`WhatAmI::Router`] and the entry it overrides is the entry
    /// [`Self::get`] will read back.
    pub const fn with_role(self, whatami: WhatAmI, enabled: bool) -> Self {
        match whatami {
            WhatAmI::Router => Self {
                router: enabled,
                ..self
            },
            WhatAmI::Peer => Self {
                peer: enabled,
                ..self
            },
            WhatAmI::Client => Self {
                client: enabled,
                ..self
            },
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
    /// R2626 — zenoh's `timestamping.drop_future_timestamp`: DROP a Put whose
    /// inbound timestamp uhlc rejects, instead of re-stamping it.
    ///
    /// ⚠ A PLAIN BOOL AND NOT PART OF [`TimestampingEnabled`], which is the one
    /// thing to get wrong here. Upstream's two keys in the same config section
    /// have different shapes: `enabled: Option<ModeDependentValue<bool>>` is
    /// resolved against the node's `whatami` (which is why wz mirrors it as a
    /// three-role map), while `drop_future_timestamp: Option<bool>` is a single
    /// node-scoped value read once
    /// (`zenoh/src/net/routing/dispatcher/tables.rs` @ `            unwrap_or_default!(config.timestamping().drop_future_timestamp());`).
    /// Folding it into the map would invent a per-role axis upstream does not
    /// have.
    ///
    /// `false` is upstream's shipped default
    /// (`commons/zenoh-config/src/defaults.rs` @ `    pub const drop_future_timestamp: bool = false;`),
    /// and it is what `Default` yields here.
    #[cfg(feature = "time-hlc")]
    drop_future_timestamp: bool,
    /// The `clock-quality-stamping` policy: `true` is `trusted-only`, which stamps nothing while
    /// the clock's standing ([`Self::report_sync_acquired`] and its siblings) is not a trusted
    /// one. A plain bool beside `drop_future_timestamp` for the same reason: it is node-scoped
    /// and is read once, when the node is built.
    #[cfg(feature = "time-hlc")]
    trusted_only: bool,
}

/// R2626 — what [`NodeHlc::treat_timestamp`] tells its caller to do with the
/// message it was just handed.
///
/// wz needs this and zenoh does not, and the reason is structural rather than a
/// difference of opinion: upstream's `treat_timestamp!` is a MACRO expanded
/// INSIDE `route_data`, so its drop arm is a bare `return;` that leaves the
/// forwarding function directly. wz's is a function called by two forwarders, so
/// the same decision has to cross a call boundary — and a `()` return cannot
/// carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampVerdict {
    /// Forward the message. It may have been stamped or re-stamped in place.
    Relay,
    /// Do not forward it AT ALL — zenoh's `drop_future_timestamp: true` arm,
    /// whose upstream spelling is a `return` out of `route_data` before any
    /// destination is reached. Not a per-destination skip.
    Drop,
}

/// The clock plus the identity its stamps carry. Held behind one `Arc` so a
/// clone cannot separate the two: a stamp pairing one node's time word with
/// another's zid would be the same uniqueness break this module exists to remove.
#[cfg(feature = "time-hlc")]
struct NodeClock {
    hlc: wz_session_core::hlc::Hlc<NodeEpoch>,
    /// This node's zid, as `TimestampHint::zid` carries it on every stamp.
    zid: Vec<u8>,
    /// How far the clock is to be trusted, as the host last reported it. Moved only by the host's
    /// reports, under the lock; read by `trusted`, which is what the stamping path looks at.
    standing: std::sync::Mutex<wz_session_core::clock_standing::ClockStanding>,
    /// `standing.is_trusted()` as of the last report, so a stamp reads one atomic and not a lock.
    trusted: core::sync::atomic::AtomicBool,
    /// Data this node passed on unstamped because of the `trusted-only` policy.
    unstamped: core::sync::atomic::AtomicU32,
}

/// The time source a node's clock reads, behind a pointer so the node can be handed a source other
/// than the system clock (the application's own clock, or a frozen one in a test) without the
/// type of the clock changing.
#[cfg(feature = "time-hlc")]
struct NodeEpoch(Box<dyn wz_session_core::epoch::EpochSource + Send + Sync>);

#[cfg(feature = "time-hlc")]
impl wz_session_core::epoch::EpochSource for NodeEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        self.0.try_since_epoch()
    }
}

/// How far ahead of the clock a remote timestamp may be before the clock refuses it, in
/// milliseconds, when the host states nothing: the `CLOCK_MAX_FORWARD_STEP_MS` limit, whose default
/// is `uhlc`'s `DEFAULT_DELTA_MS`, which zenoh's node clock runs with.
#[cfg(feature = "time-hlc")]
const DEFAULT_MAX_DELTA_MS: u64 = wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS as u64;

/// The bound, from the value of `UHLC_MAX_DELTA_MS` (or its absence). `uhlc` reads that variable
/// on its `std` profile and a zenoh node therefore honours it; the same variable moves this
/// node's bound, so an operator's setting means the same on both. A value that is not a whole
/// number of milliseconds is ignored in favour of the default: refusing to start a node over a
/// clock tolerance would be worse than running with zenoh's own.
#[cfg(feature = "time-hlc")]
fn max_delta_from(raw: Option<&str>) -> wz_session_core::ntp64::Ntp64 {
    let ms = raw
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_DELTA_MS);
    wz_session_core::ntp64::Ntp64::from_duration(core::time::Duration::from_millis(ms))
}

impl NodeHlc {
    /// Build this node's clock: `Some` when [`TimestampingEnabled`] says a node
    /// of role `whatami` timestamps, `None` otherwise. Its stamps carry `zid`
    /// and its time is the system clock through
    /// [`SystemEpoch`](crate::timestamp_source::SystemEpoch), the same source
    /// as the [`wall_clock_ntp64`](crate::timestamp_source::wall_clock_ntp64) SSOT.
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
                .then(|| build_clock(zid, crate::timestamp_source::SystemEpoch));
            // Upstream's shipped default; `with_drop_future_timestamp` is how a
            // host that read the key states otherwise.
            Self {
                clock,
                drop_future_timestamp: false,
                trusted_only: matches!(
                    wz_session_core::policy::SessionPolicy::default().clock_quality_stamping,
                    wz_session_core::policy::ClockQualityStamping::TrustedOnly
                ),
            }
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            Self {}
        }
    }

    /// Set the `clock-quality-stamping` policy (builder): `true` is `trusted-only`. `for_node`
    /// reads the build's value; this is for a host that states it another way, and for a test
    /// that names the value it is about.
    #[cfg_attr(not(feature = "time-hlc"), allow(unused_mut, unused_variables))]
    pub fn with_trusted_only_stamping(mut self, trusted_only: bool) -> Self {
        #[cfg(feature = "time-hlc")]
        {
            self.trusted_only = trusted_only;
        }
        self
    }

    /// The host reports that the clock follows a reference, for the first time or again after a
    /// loss. Whether it changed the clock's standing; `false` also on a node with no clock.
    pub fn report_sync_acquired(&self) -> bool {
        #[cfg(feature = "time-hlc")]
        {
            self.report(|standing| standing.sync_acquired())
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            false
        }
    }

    /// The host reports that the reference is gone. With `clock-source` the clock is held over;
    /// without it, it is unsynchronised again.
    pub fn report_sync_lost(&self) -> bool {
        #[cfg(feature = "time-hlc")]
        {
            self.report(|standing| standing.sync_lost())
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            false
        }
    }

    /// The host reports that its bound on running without a reference has passed.
    #[cfg(feature = "clock-source")]
    pub fn report_holdover_expired(&self) -> bool {
        self.report(|standing| standing.holdover_expired())
    }

    /// Give the standing machine one event, then refresh the atomic the stamping path reads.
    #[cfg(feature = "time-hlc")]
    fn report(
        &self,
        event: impl FnOnce(&mut wz_session_core::clock_standing::ClockStanding) -> bool,
    ) -> bool {
        let Some(clock) = self.clock.as_deref() else {
            return false;
        };
        let mut standing = clock
            .standing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = event(&mut standing);
        clock
            .trusted
            .store(standing.is_trusted(), core::sync::atomic::Ordering::Release);
        changed
    }

    /// How far the clock is to be trusted now, or `None` on a node with no clock.
    #[cfg(feature = "time-hlc")]
    pub fn clock_standing(&self) -> Option<wz_session_core::clock_quality::ClockQualityState> {
        let clock = self.clock.as_deref()?;
        let standing = clock
            .standing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(standing.state())
    }

    /// How many data messages this node passed on unstamped because the `trusted-only` policy
    /// found its clock untrusted. Zero on a node with no clock.
    pub fn unstamped(&self) -> u32 {
        #[cfg(feature = "time-hlc")]
        {
            self.clock.as_deref().map_or(0, |clock| {
                clock.unstamped.load(core::sync::atomic::Ordering::Relaxed)
            })
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            0
        }
    }

    /// Whether the `trusted-only` policy forbids stamping now.
    #[cfg(feature = "time-hlc")]
    fn quality_forbids_stamping(&self, clock: &NodeClock) -> bool {
        self.trusted_only && !clock.trusted.load(core::sync::atomic::Ordering::Acquire)
    }

    /// A node that does not timestamp. Distinct from [`Self::for_node`] with a
    /// disabling map only in that it names the intent at the call site (a test
    /// fixture, or a construction path with no role to consult yet).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// R2626 — set zenoh's `timestamping.drop_future_timestamp` (builder).
    ///
    /// A BUILDER rather than a fourth argument to [`Self::for_node`], because
    /// this knob is orthogonal to the role gate and every one of that
    /// constructor's callers means the upstream default. Making it positional
    /// would have edited a dozen sites to write `false`.
    ///
    /// ⚠ It has no effect on a node that does not stamp: with no clock there is
    /// no `update_with_timestamp` to reject anything, so nothing can reach the
    /// drop arm. That mirrors upstream, where the whole macro body sits inside
    /// `if let Some(hlc)`.
    #[cfg_attr(not(feature = "time-hlc"), allow(unused_mut, unused_variables))]
    pub fn with_drop_future_timestamp(mut self, drop_future: bool) -> Self {
        #[cfg(feature = "time-hlc")]
        {
            self.drop_future_timestamp = drop_future;
        }
        self
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
            if self.quality_forbids_stamping(clock) {
                return None;
            }
            // A source that cannot say what time it is stamps nothing: a node that does not know
            // the date does not invent one, and its caller falls back as it does for a node with
            // no clock.
            let time = clock.hlc.new_timestamp().ok()?.as_word();
            Some(wz_session_core::sample::TimestampHint {
                time,
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
    ///   branches on `drop_future_timestamp`. wz implements BOTH arms: `false`
    ///   REPLACES the timestamp, which is zenoh's shipped default
    ///   (`DEFAULT_CONFIG.json5:207-209`, "If set to false (default), messages
    ///   with timestamps in the future are retimestamped"), and `true` DROPS the
    ///   message — reported to the caller as [`TimestampVerdict::Drop`].
    ///
    ///   ⛔ R2626 CORRECTED THE REASON THIS ARM WAS MISSING, and the correction
    ///   is worth keeping because the argument was load-bearing for rounds. This
    ///   comment used to say the `true` arm was "NOT implemented and NOT exposed
    ///   as a knob: nothing in the oracle inventory can drive a future timestamp
    ///   past the drift bound, so a config field for it would be inert by
    ///   construction". That is a hand-written list of oracle BINARIES standing
    ///   in for a population — the population is what upstream's API can be made
    ///   to do, and its publisher builder takes an arbitrary `uhlc::Timestamp`.
    ///   R2624 built the counterexample (`oracles/future-stamp`), so the knob is
    ///   witnessable rather than inert, and R2626 built it.
    ///
    /// A `Del` body is left alone, faithfully — zenoh guards the whole macro on
    /// `if let PushBody::Put(data)` (`pubsub.rs:181`).
    ///
    /// Call ONCE per Push, at the head of the forward, BEFORE fan-out: every
    /// egress leg must carry the SAME timestamp. zenoh stamps at `pubsub.rs:328`
    /// and fans the one stamped `msg` out to all of `route`.
    #[cfg(feature = "codec-push")]
    pub fn treat_timestamp(&self, push: &mut wz_session_core::wire::PushOwned) -> TimestampVerdict {
        #[cfg(feature = "time-hlc")]
        {
            let Some(clock) = self.clock.as_deref() else {
                return TimestampVerdict::Relay;
            };
            if !wz_session_core::push_build::push_is_put(push) {
                return TimestampVerdict::Relay;
            }
            // `trusted-only`: a clock that is not to be trusted neither stamps nor judges. The Put
            // goes on exactly as it came, with whatever timestamp it carries, and is counted.
            if self.quality_forbids_stamping(clock) {
                clock
                    .unstamped
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return TimestampVerdict::Relay;
            }
            if let Some(inbound) = wz_session_core::push_build::read_push_timestamp(push) {
                match clock
                    .hlc
                    .update_with_timestamp(wz_session_core::ntp64::Ntp64::from_word(inbound.time))
                {
                    Ok(Ok(())) => return TimestampVerdict::Relay,
                    // A clock that cannot say what time it is cannot judge the timestamp either:
                    // the message goes on as it came, neither dropped for a reading this node
                    // could not take nor re-stamped from a date it does not know.
                    Err(_) => return TimestampVerdict::Relay,
                    Ok(Err(_)) => {}
                }
                // Absorb rejected the inbound timestamp (beyond the drift
                // bound). This is the ONLY arm either branch of
                // `drop_future_timestamp` can reach: a bare Put is always
                // stamped below, and an accepted timestamp already returned.
                if self.drop_future_timestamp {
                    return TimestampVerdict::Drop;
                }
                // zenoh's default `false` arm replaces rather than dropping.
            }
            if let Some(stamp) = self.stamp() {
                let _ = wz_session_core::push_build::set_push_timestamp(push, &stamp);
            }
            TimestampVerdict::Relay
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            let _ = push;
            TimestampVerdict::Relay
        }
    }

    /// R2892 — [`treat_timestamp`](Self::treat_timestamp) over a BORROWED Push,
    /// for the one call each forwarder makes at the head of its forward: the Put
    /// every destination is then served, borrowed unchanged when this node does
    /// not stamp, or `None` for the drop verdict. Both forwarders call this, so
    /// the single stamp point is one function rather than two copies of it; the
    /// peer forwarder's copy had drifted to cover its mesh leg only.
    #[cfg(feature = "codec-push")]
    pub fn stamp_for_every_destination<'a>(
        &self,
        push: &'a wz_session_core::wire::PushOwned,
    ) -> Option<std::borrow::Cow<'a, wz_session_core::wire::PushOwned>> {
        if !self.is_stamping() {
            return Some(std::borrow::Cow::Borrowed(push));
        }
        let mut carrier = push.clone();
        match self.treat_timestamp(&mut carrier) {
            TimestampVerdict::Drop => None,
            TimestampVerdict::Relay => Some(std::borrow::Cow::Owned(carrier)),
        }
    }
}

impl core::fmt::Debug for NodeHlc {
    /// Prints the OBSERVABLE state (does this node stamp) rather than the
    /// clock's interior, which is a word that live stamping is advancing.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeHlc")
            .field("stamping", &self.is_stamping())
            .finish()
    }
}

/// Assemble one node clock over an injectable time `source`.
///
/// The source is a parameter for one reason, and it is a testing reason
/// worth stating: with the REAL wall clock, two independently built HLCs still
/// produce a strictly increasing interleaved sequence, because the physical
/// clock advances between reads and masks the fork. Only a FROZEN clock isolates
/// the shared logical counter, so only a frozen clock can tell "one shared
/// clock" apart from "two clocks with one identity" — the precise defect R311y450
/// removes. A test that cannot make that distinction would pass on the broken
/// code, which is worse than no test.
///
/// The arithmetic is [`wz_session_core::hlc::HlcCore`], `uhlc`'s rules in one atomic word, held to
/// `uhlc` by the differential test in `tests/hlc_core_agrees_with_uhlc.rs`. Its stamp carries no
/// identity: the node's zid rides beside the time word, as it did with `uhlc`, whose own id was
/// never read here.
#[cfg(feature = "time-hlc")]
fn build_clock(
    zid: &[u8],
    source: impl wz_session_core::epoch::EpochSource + Send + Sync + 'static,
) -> std::sync::Arc<NodeClock> {
    let max_delta = max_delta_from(std::env::var("UHLC_MAX_DELTA_MS").ok().as_deref());
    std::sync::Arc::new(NodeClock {
        hlc: wz_session_core::hlc::Hlc::new(NodeEpoch(Box::new(source)), max_delta),
        zid: zid.to_vec(),
        standing: std::sync::Mutex::new(wz_session_core::clock_standing::ClockStanding::new()),
        trusted: core::sync::atomic::AtomicBool::new(false),
        unstamped: core::sync::atomic::AtomicU32::new(0),
    })
}

#[cfg(test)]
mod tests;
