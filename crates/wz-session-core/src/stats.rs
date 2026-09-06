// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y9 / R2371 — the per-session transport counters (the `transport-stats`
//! atom): the wz analogue of zenoh's `zenoh-stats` crate.
//!
//! Additive instrumentation that counts what crosses a session in each
//! direction, gated behind the off-default `transport-stats` feature so a build
//! that does not want the atomic adds per message pays nothing.
//!
//! # The FIELD SET is upstream's, and it is DERIVED rather than listed
//!
//! R2332 measured the shape at the pin and found this module carrying four flat
//! counters against upstream's multi-axis registry; R2371 built the difference.
//! Upstream's population lives in ONE place —
//! `commons/zenoh-stats/src/stats.rs` @ `fn init_stats`, whose `stats_default!`
//! invocations declare:
//!
//! - link stats `bytes` / `t_msgs` / `n_msgs` / `n_dropped`, where `n_msgs`
//!   itself splits by MEDIUM (`net` / `shm`);
//! - payload stats for FOUR message kinds — `z_put`, `z_del`, `z_query` and
//!   `z_reply` — each as `_msgs` + `_pl_bytes`, and each split by SPACE
//!   (`admin` / `user`);
//! - three interceptor-drop counters: `downsampler_dropped_msgs`,
//!   `low_pass_dropped_bytes` and `low_pass_dropped_msgs`;
//!
//! each of those in BOTH directions (`tx_` / `rx_`). wz carries the same set,
//! and carries it as a PRODUCT of axis enums
//! ([`StatMedium`](crate::stats::StatMedium),
//! [`StatSpace`](crate::stats::StatSpace),
//! [`StatMessage`](crate::stats::StatMessage)) rather than as four dozen
//! hand-written fields, so the renderer WALKS the axes instead of naming them.
//! Adding a variant to an axis changes the rendered surface with no edit to the
//! renderer at all, which is what keeps the population derived rather than
//! transcribed:
//! [`openmetrics_text`](crate::stats::TransportStatsReport::openmetrics_text)
//! cannot silently omit a combination, because it was never told the
//! combinations.
//!
//! (Every intra-doc link in THIS module header is fully qualified on purpose:
//! the outer `///` on `pub mod stats;` in `lib.rs` merges with it and the pair
//! resolves in the CRATE ROOT scope, where these names are not imported. The
//! `///` docs on the items below are in module scope and need no prefix.
//! R311y739 paid five broken links to learn this in a sibling module; R2371
//! paid twelve here, at the pre-push doc-link budget.)
//!
//! The upstream anchor for the counting SEMANTICS — which direction prefix,
//! which `medium` selector, which reason maps to which drop counter — is
//! `commons/zenoh-stats/src/stats.rs` @ `fn incr_stats`, the `StatsPath` impls.
//!
//! # Where it counts (the seams)
//!
//! - **Wire (`bytes`, `t_msgs`, `n_dropped`)** — the `session_actions` module's
//!   `emit_on_link`, the one seam every production wire write routes through
//!   (handshake / close / Frame / Fragment / batch flush / keepalive), and its
//!   RX twin, the `LinkEvent::Rx` arm of the `drive` module's
//!   `dispatch_link_event`. The bytes are the ACTUAL wire bytes — TX
//!   post-compression, RX pre-decompression — so both are on-the-wire totals,
//!   which is the zenoh `tx_bytes` / `rx_bytes` parity point.
//! - **Network (`n_msgs`, the payload counters)** — the `session_actions`
//!   module's `dispatch_network_message`, the single TX chokepoint all seven
//!   typed `dispatch_*` wrappers land on, and the RX twin
//!   [`inc_rx_network`](crate::stats::TransportStats::inc_rx_network) driven
//!   from the `drive` module's frame-payload walk. Each TX wrapper hands down a
//!   [`NetworkStatsClass`](crate::stats::NetworkStatsClass)
//!   derived from its OWN typed message, so the classification is a parameter
//!   the compiler demands of every sender rather than a `match` a new sender can
//!   fall through.
//! - **Interceptor drops** — the forwarder's chain, which since R2371 attributes
//!   a drop to the interceptor that made it and charges it to the face's own
//!   session (`wz-runtime-tokio`'s `InterceptorVerdict`).
//!
//! # `t_msgs` is a MEASUREMENT, not a rename (R2371)
//!
//! This module used to export its two message counters as `wz_tx_batches` /
//! `wz_rx_batches`, deliberately refusing upstream's `t_msgs` name on the
//! reasoning that upstream counts TRANSPORT messages, several of which ride one
//! batch, while wz counted one per batch.
//!
//! Re-measured against wz's own emit structure, that premise is false. wz's
//! batching accumulates NETWORK messages into ONE Frame (the `session_actions`
//! module's `dispatch_network_message`, whose `batch.active` arm appends into a
//! single staged buffer), and a fragment chain emits each chunk through its own
//! `send_wire` (that module's `emit_frame_or_fragments`). Every wire write is
//! therefore exactly ONE transport message — a Frame, a Fragment, or a
//! handshake message — and each spends its own sequence number, which is the
//! tree's own statement of the same fact: an SN is what "zenoh's receive-side
//! `SeqNum::roll` requires of every accepted transport message".
//!
//! So the per-write count IS the transport-message count, and it now carries
//! upstream's name. The quantity that has no wz twin is the one the old name
//! implied: wz never puts two transport messages in one write, so this counter
//! can never exceed the write count. That is a property of the emit path, not a
//! missing counter — and it is a MEASUREMENT of this tree, so the test that used
//! to refuse upstream's name now pins the granularity instead.
//!
//! # `n_dropped` holds upstream's quantity for a DIFFERENT reason (R2371)
//!
//! Upstream charges `tx_n_dropped` on `ReasonLabel::Congestion`
//! (`commons/zenoh-stats/src/stats.rs` @ `ReasonLabel::Congestion`) — a message
//! its priority queue refused because the queue was full and the message's
//! congestion control was `Drop`. wz has no bounded TX queue to congest: the
//! link writers are unbounded channels, so no wz message is ever dropped for
//! congestion.
//!
//! What wz DOES drop — and used to drop silently — is a write the LINK DRIVER
//! refuses: an oversize datagram past the link MTU, or a write onto a closed
//! writer channel. Before R2371 the driver's send returned `()`, so those drops
//! were invisible to the transport, which is precisely the blocker this atom's
//! residual named. [`LinkSendOutcome`](crate::link::LinkSendOutcome) is that
//! driver-level hook, and `n_dropped` is charged from it.
//!
//! The counter therefore holds upstream's QUANTITY (transport messages the
//! transport did not put on the wire) under upstream's NAME, for a REASON
//! upstream does not have. That divergence is recorded here and on
//! [`StatDrop::Transport`](crate::stats::StatDrop::Transport) rather than
//! hidden behind a matching name — the same
//! discipline the `wz_*_batches` decision applied, reaching the opposite answer
//! because this time the quantity does match.
//!
//! # The adminspace consumer is BUILT (R2371)
//!
//! This module's prose used to say the adminspace `stats` queryable "stays
//! P4-deferred". Re-measured, it is not deferred: the `adminspace` module's
//! metrics body appends this report's
//! [`openmetrics_text`](crate::stats::TransportStatsReport::openmetrics_text)
//! to the
//! `@/<zid>/.../metrics` reply, `AdminAnswerCtx` carries the report, and the leg
//! is covered end to end by `declare_adminspace_metrics_get_returns_openmetrics_text`
//! and cross-impl against a real zenoh-pico `z_get` by
//! `wz_peer_adminspace_metrics_to_pico_zget.rs`. The clause described the state
//! at R311y9 and outlived it.
//!
//! AP-only: `transport-stats` is never enabled on an MCU lane, so the
//! [`core::sync::atomic`] counters here never reach a target without 64-bit /
//! pointer atomics.
//!
//! R311y810 — the MODULE is unconditional; only the COUNTING half
//! ([`TransportStats`](crate::stats::TransportStats), its atomics and the
//! `inc_*` seams) carries the gate.
//! [`TransportStatsReport`](crate::stats::TransportStatsReport) is plain
//! integers, and a consumer that holds one in
//! a struct field must be able to name the type in every feature combination;
//! gating the type is how a cfg-gated `pub` struct field appears, which is the
//! composability hazard Layer C1bf audits for. The AXIS enums and
//! [`NetworkStatsClass`](crate::stats::NetworkStatsClass) are ungated for the
//! same reason: the TX chokepoint
//! names the class in its signature, and that signature exists under the codec
//! union rather than under `transport-stats`.

#[cfg(feature = "transport-stats")]
use core::sync::atomic::{AtomicUsize, Ordering};

/// The MEDIUM axis of upstream's `n_msgs` split — `net` / `shm`, declared at
/// `commons/zenoh-stats/src/stats.rs` @ `n_msgs medium` and selected at
/// `commons/zenoh-stats/src/stats.rs` @ `let medium = if labels.shm`.
///
/// (Both anchors are kept on ONE line each. An anchor folded after its `@` is
/// not read as an anchor at all — `upstream_citation_anchor_gate.py` demotes it
/// to a BARE mention, which is a budget it must not silently enter.)
///
/// wz's `shm` arm has a real subject: a Push whose payload carries the SHM
/// DESCRIPTOR rather than the bytes ([`crate::extshm`] and the
/// `push_build` module's SHM literal builder), which is exactly what upstream's
/// `labels.shm` marks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatMedium {
    /// The bytes rode the link (upstream's `net`).
    Net,
    /// The message carried an SHM descriptor; the bytes rode shared memory
    /// (upstream's `shm`).
    Shm,
}

impl StatMedium {
    /// Every variant, in render order. THE population — the renderer and the
    /// counter arrays are both sized from this, so a new medium reaches the
    /// exported surface without a renderer edit.
    pub const ALL: [StatMedium; 2] = [StatMedium::Net, StatMedium::Shm];
    /// How many media there are — [`Self::ALL`]'s length, never a literal.
    pub const COUNT: usize = Self::ALL.len();

    /// This variant's index into a `[_; StatMedium::COUNT]` counter array.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Upstream's label for this medium — the JSON key it splits `n_msgs` on,
    /// and the OpenMetrics label value wz renders it as.
    pub const fn label(self) -> &'static str {
        match self {
            StatMedium::Net => "net",
            StatMedium::Shm => "shm",
        }
    }
}

/// The SPACE axis of upstream's payload split — `admin` / `user`
/// (`commons/zenoh-stats/src/stats.rs` @ `SpaceLabel::Admin`). A message whose
/// key expression addresses the admin space (`@`-prefixed, the
/// `@/<zid>/...` subtree this tree's `adminspace` module serves) counts as
/// `admin`; everything else is `user`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatSpace {
    /// The admin space — an `@`-prefixed key expression.
    Admin,
    /// Ordinary application traffic.
    User,
}

impl StatSpace {
    /// Every variant, in render order. See [`StatMedium::ALL`].
    pub const ALL: [StatSpace; 2] = [StatSpace::Admin, StatSpace::User];
    /// How many spaces there are — [`Self::ALL`]'s length.
    pub const COUNT: usize = Self::ALL.len();

    /// This variant's index into a `[_; StatSpace::COUNT]` counter array.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Upstream's label for this space.
    pub const fn label(self) -> &'static str {
        match self {
            StatSpace::Admin => "admin",
            StatSpace::User => "user",
        }
    }

    /// Classify a key expression the way upstream's `SpaceLabel` does: the admin
    /// space is the `@`-prefixed subtree.
    ///
    /// zenoh reserves `@` as the admin-space prefix at the KEYEXPR level, so the
    /// discriminator is the first byte of the literal expression and not a table
    /// lookup. An ALIASED expression that this face has not resolved has no
    /// literal to read; the caller passes what it resolved, and an unresolvable
    /// alias counts as [`StatSpace::User`] — the same side upstream lands on
    /// when the resource has no admin prefix.
    pub fn of_keyexpr(keyexpr: &str) -> StatSpace {
        if keyexpr.starts_with('@') {
            StatSpace::Admin
        } else {
            StatSpace::User
        }
    }
}

/// The MESSAGE-KIND axis of upstream's payload split — the four kinds
/// `z_put` / `z_del` / `z_query` / `z_reply`
/// (`commons/zenoh-stats/src/stats.rs` @ `MessageLabel::Put`, whose `Reply` and
/// `ReplyErr` arms BOTH fold onto `reply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatMessage {
    /// A Put — data published, whether inside a `Push` or a `Request`.
    Put,
    /// A Del — a tombstone, same two carriers as [`StatMessage::Put`].
    Del,
    /// A Query — a `Request` carrying a `Query` body.
    Query,
    /// A Reply — a `Response` carrying either a `Reply` or an `Err` body;
    /// upstream folds its `ReplyErr` label onto this same counter.
    Reply,
}

impl StatMessage {
    /// Every variant, in render order. See [`StatMedium::ALL`].
    pub const ALL: [StatMessage; 4] = [
        StatMessage::Put,
        StatMessage::Del,
        StatMessage::Query,
        StatMessage::Reply,
    ];
    /// How many payload kinds there are — [`Self::ALL`]'s length.
    pub const COUNT: usize = Self::ALL.len();

    /// This variant's index into a `[_; StatMessage::COUNT]` counter array.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Upstream's infix for this kind — the `<msg>` in `{tx,rx}_z_<msg>_msgs`.
    pub const fn label(self) -> &'static str {
        match self {
            StatMessage::Put => "put",
            StatMessage::Del => "del",
            StatMessage::Query => "query",
            StatMessage::Reply => "reply",
        }
    }
}

/// Why a message was dropped — the wz counterpart of upstream's `ReasonLabel`,
/// carrying only the reasons that reach a counter
/// (`commons/zenoh-stats/src/stats.rs` @ `ReasonLabel::Downsampling`).
///
/// The mapping onto counters is upstream's, arm for arm; see
/// [`TransportStats::inc_tx_drop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatDrop {
    /// The TRANSPORT refused the write — this tree's `n_dropped` subject.
    ///
    /// ⚠ Upstream's `n_dropped` is charged on `ReasonLabel::Congestion`, a
    /// message its bounded priority queue refused. wz has no bounded TX queue,
    /// so nothing here is ever dropped for congestion; what IS dropped is a
    /// write the link driver refuses — an oversize datagram past the link MTU,
    /// or a write onto a closed writer channel, both reported through
    /// [`LinkSendOutcome`](crate::link::LinkSendOutcome). Same quantity
    /// (transport messages that never reached the wire), same name, a reason
    /// upstream does not have. The module docs carry the full note.
    Transport,
    /// The downsampling interceptor rate-limited the message
    /// (upstream `ReasonLabel::Downsampling`).
    Downsampling,
    /// The low-pass interceptor refused the message for exceeding its size cap
    /// (upstream `ReasonLabel::LowPass`). This is the one reason that charges
    /// BYTES as well as messages, exactly as upstream does.
    LowPass,
}

impl StatDrop {
    /// Every variant. Not a render axis — each reason maps to its OWN counter
    /// name rather than to a label on a shared one, mirroring upstream's match —
    /// but still the population, so a new reason cannot be added without the
    /// exhaustive `match` in [`TransportStats::inc_tx_drop`] refusing to compile.
    pub const ALL: [StatDrop; 3] = [
        StatDrop::Transport,
        StatDrop::Downsampling,
        StatDrop::LowPass,
    ];
}

/// The payload classification of ONE network message — the (kind, space, bytes)
/// triple upstream derives from its `NetworkMessagePayloadLabels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadClass {
    /// Which of the four payload kinds this message is.
    pub message: StatMessage,
    /// Which space its key expression addresses.
    pub space: StatSpace,
    /// The PAYLOAD bytes — upstream's `pl_bytes`, the message's own payload and
    /// not the encoded envelope (which `bytes` already counts at the wire seam).
    pub pl_bytes: usize,
}

/// How one network message counts — the parameter every TX sender hands the
/// `dispatch_network_message` chokepoint, and the RX walk hands
/// [`TransportStats::inc_rx_network`].
///
/// A CONTROL-plane message (Declare / Interest / OAM / ResponseFinal) has no
/// payload class: upstream's payload counters cover only the four data kinds,
/// so those messages count toward `n_msgs` and nothing else. That is
/// [`NetworkStatsClass::control`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStatsClass {
    /// Which medium carried the bytes.
    pub medium: StatMedium,
    /// The payload classification, or `None` for a control-plane message.
    pub payload: Option<PayloadClass>,
}

impl NetworkStatsClass {
    /// A control-plane network message: counts toward `n_msgs` on the `net`
    /// medium and toward no payload counter.
    pub const fn control() -> NetworkStatsClass {
        NetworkStatsClass {
            medium: StatMedium::Net,
            payload: None,
        }
    }

    /// A data-plane network message whose payload rode the LINK.
    pub const fn net(message: StatMessage, space: StatSpace, pl_bytes: usize) -> NetworkStatsClass {
        NetworkStatsClass {
            medium: StatMedium::Net,
            payload: Some(PayloadClass {
                message,
                space,
                pl_bytes,
            }),
        }
    }

    /// A data-plane network message whose payload rode SHARED MEMORY — the
    /// message carried a descriptor, so `n_msgs` counts on the `shm` medium.
    pub const fn shm(message: StatMessage, space: StatSpace, pl_bytes: usize) -> NetworkStatsClass {
        NetworkStatsClass {
            medium: StatMedium::Shm,
            payload: Some(PayloadClass {
                message,
                space,
                pl_bytes,
            }),
        }
    }

    /// The same class with its medium forced to [`StatMedium::Shm`] — the TX
    /// senders build a class from the typed message and only then learn whether
    /// the SHM swap fired.
    #[must_use]
    pub const fn on_shm(mut self) -> NetworkStatsClass {
        self.medium = StatMedium::Shm;
        self
    }
}

/// One `(msgs, pl_bytes)` pair — upstream's payload counters always move
/// together, so they are one value rather than two parallel arrays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PayloadCounters {
    /// Upstream's `z_<kind>_msgs` for this (kind, space).
    pub msgs: usize,
    /// Upstream's `z_<kind>_pl_bytes` for this (kind, space).
    pub pl_bytes: usize,
}

/// One direction's whole counter set — upstream's `tx_`/`rx_` half.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionReport {
    /// Wire bytes (upstream `bytes`): TX post-compression, RX pre-decompression.
    pub bytes: usize,
    /// Transport messages (upstream `t_msgs`) — one per wire write. See the
    /// module docs for why that equality holds in this tree.
    pub t_msgs: usize,
    /// Network messages (upstream `n_msgs`), indexed by [`StatMedium::index`].
    pub n_msgs: [usize; StatMedium::COUNT],
    /// Transport messages the transport did not put on the wire (upstream
    /// `n_dropped`). See [`StatDrop::Transport`] for the reason divergence.
    pub n_dropped: usize,
    /// The payload counters, indexed by [`StatMessage::index`] then
    /// [`StatSpace::index`].
    pub payload: [[PayloadCounters; StatSpace::COUNT]; StatMessage::COUNT],
    /// Upstream `downsampler_dropped_msgs`.
    pub downsampler_dropped_msgs: usize,
    /// Upstream `low_pass_dropped_msgs`.
    pub low_pass_dropped_msgs: usize,
    /// Upstream `low_pass_dropped_bytes`.
    pub low_pass_dropped_bytes: usize,
}

impl DirectionReport {
    /// The network-message count on one medium.
    pub fn n_msgs_on(&self, medium: StatMedium) -> usize {
        self.n_msgs[medium.index()]
    }

    /// The payload counters for one (kind, space).
    pub fn payload_of(&self, message: StatMessage, space: StatSpace) -> PayloadCounters {
        self.payload[message.index()][space.index()]
    }

    /// Network messages across every medium — the quantity a caller that does
    /// not care about the split wants, derived rather than counted separately.
    pub fn n_msgs_total(&self) -> usize {
        let mut total = 0;
        let mut i = 0;
        while i < StatMedium::COUNT {
            total += self.n_msgs[i];
            i += 1;
        }
        total
    }
}

/// An immutable snapshot of a [`TransportStats`] — the serializable value the
/// public accessor returns (the zenoh `TransportStats::report()` analogue).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStatsReport {
    /// The outbound half.
    pub tx: DirectionReport,
    /// The inbound half.
    pub rx: DirectionReport,
}

/// Per-session counters. Interior-mutable (atomic), so a shared
/// `&SessionLinkActions` (the `Arc`/`Rc`-wrapped action bundle) increments them
/// from the TX seam, the RX dispatch and the forwarder's interceptor chain
/// without a mutex. `Relaxed` ordering is sufficient — these are monotonic
/// observability counters, not a synchronization signal (the same ordering
/// choice zenoh makes).
#[cfg(feature = "transport-stats")]
#[derive(Debug, Default)]
pub struct TransportStats {
    tx: DirectionCounters,
    rx: DirectionCounters,
}

/// One direction's atomics — the live twin of [`DirectionReport`].
///
/// `payload_msgs` / `payload_pl_bytes` are two arrays rather than one array of
/// pairs because [`PayloadCounters`] is the PLAIN snapshot type and an atomic
/// pair would need a second struct that exists only to be summed.
#[cfg(feature = "transport-stats")]
#[derive(Debug, Default)]
struct DirectionCounters {
    bytes: AtomicUsize,
    t_msgs: AtomicUsize,
    n_msgs: [AtomicUsize; StatMedium::COUNT],
    n_dropped: AtomicUsize,
    payload_msgs: [[AtomicUsize; StatSpace::COUNT]; StatMessage::COUNT],
    payload_pl_bytes: [[AtomicUsize; StatSpace::COUNT]; StatMessage::COUNT],
    downsampler_dropped_msgs: AtomicUsize,
    low_pass_dropped_msgs: AtomicUsize,
    low_pass_dropped_bytes: AtomicUsize,
}

#[cfg(feature = "transport-stats")]
impl DirectionCounters {
    /// One wire write of `bytes` bytes — one transport message.
    #[inline]
    fn inc_wire(&self, bytes: usize) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.t_msgs.fetch_add(1, Ordering::Relaxed);
    }

    /// One network message, classified.
    #[inline]
    fn inc_network(&self, class: &NetworkStatsClass) {
        self.n_msgs[class.medium.index()].fetch_add(1, Ordering::Relaxed);
        if let Some(p) = class.payload {
            let (m, s) = (p.message.index(), p.space.index());
            self.payload_msgs[m][s].fetch_add(1, Ordering::Relaxed);
            self.payload_pl_bytes[m][s].fetch_add(p.pl_bytes, Ordering::Relaxed);
        }
    }

    /// `msgs` messages dropped for `reason`, carrying `bytes` payload bytes.
    ///
    /// The arm-for-arm mirror of upstream's reason match: only LowPass charges a
    /// byte counter, because only LowPass has one.
    #[inline]
    fn inc_drop(&self, reason: StatDrop, msgs: usize, bytes: usize) {
        match reason {
            StatDrop::Transport => {
                self.n_dropped.fetch_add(msgs, Ordering::Relaxed);
            }
            StatDrop::Downsampling => {
                self.downsampler_dropped_msgs
                    .fetch_add(msgs, Ordering::Relaxed);
            }
            StatDrop::LowPass => {
                self.low_pass_dropped_msgs
                    .fetch_add(msgs, Ordering::Relaxed);
                self.low_pass_dropped_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    fn report(&self) -> DirectionReport {
        let load = |a: &AtomicUsize| a.load(Ordering::Relaxed);
        let mut n_msgs = [0usize; StatMedium::COUNT];
        for medium in StatMedium::ALL {
            n_msgs[medium.index()] = load(&self.n_msgs[medium.index()]);
        }
        let mut payload = [[PayloadCounters::default(); StatSpace::COUNT]; StatMessage::COUNT];
        for message in StatMessage::ALL {
            for space in StatSpace::ALL {
                let (m, s) = (message.index(), space.index());
                payload[m][s] = PayloadCounters {
                    msgs: load(&self.payload_msgs[m][s]),
                    pl_bytes: load(&self.payload_pl_bytes[m][s]),
                };
            }
        }
        DirectionReport {
            bytes: load(&self.bytes),
            t_msgs: load(&self.t_msgs),
            n_msgs,
            n_dropped: load(&self.n_dropped),
            payload,
            downsampler_dropped_msgs: load(&self.downsampler_dropped_msgs),
            low_pass_dropped_msgs: load(&self.low_pass_dropped_msgs),
            low_pass_dropped_bytes: load(&self.low_pass_dropped_bytes),
        }
    }
}

#[cfg(feature = "transport-stats")]
impl TransportStats {
    /// Count one outbound WIRE write of `bytes` bytes — the TX seam. One write
    /// is one transport message (see the module docs).
    #[inline]
    pub fn inc_tx(&self, bytes: usize) {
        self.tx.inc_wire(bytes);
    }

    /// Count one inbound WIRE read of `bytes` bytes — the RX dispatch.
    #[inline]
    pub fn inc_rx(&self, bytes: usize) {
        self.rx.inc_wire(bytes);
    }

    /// Count one outbound NETWORK message — the `dispatch_network_message`
    /// chokepoint, which takes the class from its typed caller.
    #[inline]
    pub fn inc_tx_network(&self, class: &NetworkStatsClass) {
        self.tx.inc_network(class);
    }

    /// Count one inbound NETWORK message — the RX frame-payload walk.
    #[inline]
    pub fn inc_rx_network(&self, class: &NetworkStatsClass) {
        self.rx.inc_network(class);
    }

    /// Charge `msgs` outbound drops of `reason` carrying `bytes` payload bytes.
    #[inline]
    pub fn inc_tx_drop(&self, reason: StatDrop, msgs: usize, bytes: usize) {
        self.tx.inc_drop(reason, msgs, bytes);
    }

    /// Charge `msgs` inbound drops of `reason` carrying `bytes` payload bytes.
    ///
    /// There is no inbound [`StatDrop::Transport`] arm in practice — a wz link
    /// driver drops on WRITE, never on read — but the method is symmetric with
    /// its TX twin because upstream's inbound interceptor drops are real and
    /// land here.
    #[inline]
    pub fn inc_rx_drop(&self, reason: StatDrop, msgs: usize, bytes: usize) {
        self.rx.inc_drop(reason, msgs, bytes);
    }

    /// A plain-integer snapshot of the live counters — the value the public
    /// accessor hands out (a consumer reads a consistent-enough point sample;
    /// `Relaxed` loads are fine for monotonic counters).
    pub fn report(&self) -> TransportStatsReport {
        TransportStatsReport {
            tx: self.tx.report(),
            rx: self.rx.report(),
        }
    }
}

#[cfg(feature = "alloc")]
impl TransportStatsReport {
    /// Render this snapshot as OpenMetrics text — the block zenoh's adminspace
    /// appends to the `zenoh_build` gauge under its `stats` feature.
    ///
    /// The LINE FORMAT is upstream's exactly — `# HELP <name> <text>`,
    /// `# TYPE <name> <type>`, then `<name> <value>`, each newline-terminated,
    /// which is the shape upstream's admin space writes at
    /// `zenoh/src/net/runtime/adminspace.rs` @ `# HELP zenoh_build`.
    ///
    /// ⚠ R2241: this citation used to name a transport-side stats module and its
    /// `stats_struct!` macro. NEITHER exists at 1.10.0 —
    /// `io/zenoh-transport/src/common/stats.rs` @ REMOVED — and the only place
    /// upstream still emits this format is the admin space's build info. The
    /// line-format claim is therefore anchored on what upstream still writes.
    ///
    /// # The SPLIT counters carry LABELS, which is what upstream's registry is
    ///
    /// A counter on a split axis renders one sample per axis value —
    /// `tx_n_msgs{medium="net"}`, `tx_z_put_msgs{space="user"}` — rather than a
    /// flattened name per combination. That is the closer mirror of upstream,
    /// whose 1.10.0 rewrite made these a LABEL-INDEXED registry
    /// (`commons/zenoh-stats/src/labels.rs` @ `pub enum MessageLabel`)
    /// rather than a flat struct, and it is what lets the renderer walk the axis
    /// enums instead of naming every product.
    ///
    /// # Every counter here means what upstream's counter of that name means
    ///
    /// R2371 removed the two `wz_*_batches` names this method used to export.
    /// They existed because the counters behind them were believed to hold a
    /// batch count where upstream holds a transport-message count; re-measured
    /// against this tree's emit path, they hold the same quantity, so they carry
    /// upstream's `t_msgs` name. The module docs record that measurement, and
    /// `t_msgs_counts_one_per_wire_write` is the test that pins it.
    ///
    /// The one surviving divergence is `n_dropped`'s REASON, which is documented
    /// on [`StatDrop::Transport`] and does not change the quantity.
    pub fn openmetrics_text(&self) -> alloc::string::String {
        let mut out = alloc::string::String::new();
        for (dir, verb, rep) in [("tx", "sent", &self.tx), ("rx", "received", &self.rx)] {
            let name = |suffix: &str| alloc::format!("{dir}_{suffix}");

            push_counter(
                &mut out,
                &name("bytes"),
                &alloc::format!("Counter of {verb} bytes."),
                rep.bytes,
            );
            push_counter(
                &mut out,
                &name("t_msgs"),
                &alloc::format!("Counter of {verb} transport messages."),
                rep.t_msgs,
            );
            push_labeled_counter(
                &mut out,
                &name("n_msgs"),
                &alloc::format!("Counter of {verb} network messages."),
                "medium",
                StatMedium::ALL
                    .into_iter()
                    .map(|m| (m.label(), rep.n_msgs_on(m))),
            );
            push_counter(
                &mut out,
                &name("n_dropped"),
                &alloc::format!("Counter of {verb} transport messages dropped."),
                rep.n_dropped,
            );
            for message in StatMessage::ALL {
                let kind = message.label();
                push_labeled_counter(
                    &mut out,
                    &name(&alloc::format!("z_{kind}_msgs")),
                    &alloc::format!("Counter of {verb} {kind} messages."),
                    "space",
                    StatSpace::ALL
                        .into_iter()
                        .map(|s| (s.label(), rep.payload_of(message, s).msgs)),
                );
                push_labeled_counter(
                    &mut out,
                    &name(&alloc::format!("z_{kind}_pl_bytes")),
                    &alloc::format!("Counter of {verb} {kind} payload bytes."),
                    "space",
                    StatSpace::ALL
                        .into_iter()
                        .map(|s| (s.label(), rep.payload_of(message, s).pl_bytes)),
                );
            }
            push_counter(
                &mut out,
                &name("downsampler_dropped_msgs"),
                &alloc::format!("Counter of {verb} messages dropped by downsampling."),
                rep.downsampler_dropped_msgs,
            );
            push_counter(
                &mut out,
                &name("low_pass_dropped_msgs"),
                &alloc::format!("Counter of {verb} messages dropped by the low-pass filter."),
                rep.low_pass_dropped_msgs,
            );
            push_counter(
                &mut out,
                &name("low_pass_dropped_bytes"),
                &alloc::format!("Counter of {verb} bytes dropped by the low-pass filter."),
                rep.low_pass_dropped_bytes,
            );
        }
        out
    }

    /// Every counter NAME this report renders, in render order — the exported
    /// surface as a list, without the values.
    ///
    /// This exists so a gate can compare wz's surface against upstream's
    /// declared field set without parsing OpenMetrics text, and so the
    /// in-tree test that checks the render covers every axis product has a
    /// population DERIVED from the same walk the renderer performs rather than
    /// from a second hand-written list (which is the shape that cannot fail).
    pub fn counter_names() -> alloc::vec::Vec<alloc::string::String> {
        let mut names = alloc::vec::Vec::new();
        for dir in ["tx", "rx"] {
            names.push(alloc::format!("{dir}_bytes"));
            names.push(alloc::format!("{dir}_t_msgs"));
            names.push(alloc::format!("{dir}_n_msgs"));
            names.push(alloc::format!("{dir}_n_dropped"));
            for message in StatMessage::ALL {
                let kind = message.label();
                names.push(alloc::format!("{dir}_z_{kind}_msgs"));
                names.push(alloc::format!("{dir}_z_{kind}_pl_bytes"));
            }
            names.push(alloc::format!("{dir}_downsampler_dropped_msgs"));
            names.push(alloc::format!("{dir}_low_pass_dropped_msgs"));
            names.push(alloc::format!("{dir}_low_pass_dropped_bytes"));
        }
        names
    }
}

/// One `# HELP` / `# TYPE` / value triple in upstream's plain-field shape.
///
/// Every counter this module exports is a monotonic `counter`, so the type is
/// not a parameter: a gauge would need a different upstream arm anyway.
#[cfg(feature = "alloc")]
fn push_counter(out: &mut alloc::string::String, name: &str, help: &str, value: usize) {
    use core::fmt::Write as _;
    push_header(out, name, help);
    out.push_str(name);
    out.push(' ');
    // `write!` into a String cannot fail; the result is consumed to keep the
    // no-panic posture this crate holds elsewhere.
    let _ = write!(out, "{value}");
    out.push('\n');
}

/// One `# HELP` / `# TYPE` header followed by ONE SAMPLE PER AXIS VALUE, each
/// carrying the axis as an OpenMetrics label.
///
/// `samples` is an iterator rather than a slice so the caller can hand it the
/// axis enum's own `ALL` walk without materialising a vector — which is what
/// keeps the rendered population derived from the enum.
#[cfg(feature = "alloc")]
fn push_labeled_counter(
    out: &mut alloc::string::String,
    name: &str,
    help: &str,
    label: &str,
    samples: impl Iterator<Item = (&'static str, usize)>,
) {
    use core::fmt::Write as _;
    push_header(out, name, help);
    for (value_label, value) in samples {
        out.push_str(name);
        let _ = write!(out, "{{{label}=\"{value_label}\"}} {value}");
        out.push('\n');
    }
}

/// The two metadata lines every counter above shares.
#[cfg(feature = "alloc")]
fn push_header(out: &mut alloc::string::String, name: &str, help: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push_str("\n# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y811 — the report type is NAMEABLE AND CONSTRUCTIBLE WITH NO FEATURES
    /// AT ALL, which is the whole reason R311y810 un-gated this module: a
    /// consumer holds one in an UNGATED struct field (`AdminAnswerCtx`'s
    /// `stats`), so a build with neither `alloc` nor `transport-stats` must still
    /// be able to name the type, copy it, and compare it.
    ///
    /// This test is UNCONDITIONAL on purpose. Every other test in this module is
    /// gated on one of the two features, so in the bare configuration the module
    /// compiled to nothing at all — and a test module that compiles to nothing
    /// does not merely fail to check anything, it makes `use super::*` an unused
    /// import and turns the whole crate's `-D warnings` test build red. That is
    /// exactly how R311y810 reached origin: the bare arm is compiled only by
    /// Layer C1o (whose filter selects `keyexpr_match`), so the break surfaced
    /// there rather than in a stats lane. The claim and the compile are now
    /// pinned in the same place.
    #[test]
    fn the_report_type_is_nameable_and_usable_with_no_features() {
        let mut r = TransportStatsReport::default();
        r.tx.bytes = 140;
        r.tx.t_msgs = 2;
        r.rx.bytes = 12;
        r.rx.t_msgs = 1;
        r.tx.n_msgs[StatMedium::Net.index()] = 3;
        r.tx.payload[StatMessage::Put.index()][StatSpace::User.index()] = PayloadCounters {
            msgs: 1,
            pl_bytes: 9,
        };

        // Field access without `alloc`: the members are plain integers.
        assert_eq!(
            (r.tx.bytes, r.tx.t_msgs, r.rx.bytes, r.rx.t_msgs),
            (140, 2, 12, 1)
        );
        assert_eq!(r.tx.n_msgs_on(StatMedium::Net), 3);
        assert_eq!(r.tx.n_msgs_on(StatMedium::Shm), 0);
        assert_eq!(r.tx.n_msgs_total(), 3);
        assert_eq!(
            r.tx.payload_of(StatMessage::Put, StatSpace::User),
            PayloadCounters {
                msgs: 1,
                pl_bytes: 9
            }
        );

        // `Copy` + `PartialEq` + `Default` are the bounds a holder of an ungated
        // field actually leans on (`AdminAnswerCtx` takes one by value).
        let copied = r;
        assert_eq!(copied, r);
        assert_ne!(r, TransportStatsReport::default());
    }

    /// The axis enums ARE the population: every `index()` is a distinct slot
    /// inside `COUNT`, and `COUNT` is `ALL`'s length rather than a literal. A
    /// variant added without extending `ALL` — the way an axis silently stops
    /// being rendered — makes this fail on the index bound.
    #[test]
    fn every_axis_variant_has_a_distinct_slot_inside_its_count() {
        assert_eq!(StatMedium::COUNT, StatMedium::ALL.len());
        assert_eq!(StatSpace::COUNT, StatSpace::ALL.len());
        assert_eq!(StatMessage::COUNT, StatMessage::ALL.len());

        // Each axis' indices must TILE `0..COUNT` — no collision, no gap. The
        // occupancy array is FIXED-SIZE on purpose: this module compiles in the
        // bare, no-`alloc` configuration (see the unconditional test above), so
        // the check cannot reach for a growable vector. An index at or past
        // `COUNT` panics on the subscript, which is the same failure.
        let mut medium = [0u8; StatMedium::COUNT];
        for m in StatMedium::ALL {
            medium[m.index()] += 1;
        }
        assert!(
            medium.iter().all(|&n| n == 1),
            "medium indices must tile 0..COUNT: {medium:?}"
        );

        let mut space = [0u8; StatSpace::COUNT];
        for s in StatSpace::ALL {
            space[s.index()] += 1;
        }
        assert!(
            space.iter().all(|&n| n == 1),
            "space indices must tile 0..COUNT: {space:?}"
        );

        let mut message = [0u8; StatMessage::COUNT];
        for m in StatMessage::ALL {
            message[m.index()] += 1;
        }
        assert!(
            message.iter().all(|&n| n == 1),
            "message indices must tile 0..COUNT: {message:?}"
        );
    }

    /// Admin space is the `@`-prefixed subtree, everything else is user — the
    /// discriminator upstream's `SpaceLabel` uses.
    #[test]
    fn the_admin_space_is_the_at_prefixed_subtree() {
        assert_eq!(StatSpace::of_keyexpr("@/abc/session"), StatSpace::Admin);
        assert_eq!(StatSpace::of_keyexpr("demo/example"), StatSpace::User);
        // Not a PREFIX MATCH on the whole word: `@` anywhere else is user data.
        assert_eq!(StatSpace::of_keyexpr("demo/@weird"), StatSpace::User);
        assert_eq!(StatSpace::of_keyexpr(""), StatSpace::User);
    }

    /// `inc_tx` / `inc_rx` accumulate bytes and bump the TRANSPORT-message count
    /// by one each; `report` snapshots them faithfully.
    ///
    /// R2371 — this is the granularity claim the module docs make: ONE wire
    /// write is ONE transport message, which is why this counter carries
    /// upstream's `t_msgs` name rather than the `wz_*_batches` name it used to.
    /// A change that made a write carry several transport messages would have to
    /// change this test, which is where the reader would find the note.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn t_msgs_counts_one_per_wire_write() {
        let s = TransportStats::default();
        assert_eq!(s.report(), TransportStatsReport::default());

        s.inc_tx(100);
        s.inc_tx(40);
        s.inc_rx(12);

        let r = s.report();
        assert_eq!(r.tx.bytes, 140);
        assert_eq!(r.tx.t_msgs, 2);
        assert_eq!(r.rx.bytes, 12);
        assert_eq!(r.rx.t_msgs, 1);
        // The network plane is untouched by a wire write: a Frame carrying N
        // network messages counts ONE here and N there.
        assert_eq!(r.tx.n_msgs_total(), 0);
    }

    /// The network seam splits by medium and charges the payload counters on the
    /// (kind, space) cell — and a CONTROL message charges `n_msgs` and nothing
    /// else, which is upstream's shape (its payload labels cover four kinds).
    #[cfg(feature = "transport-stats")]
    #[test]
    fn the_network_seam_splits_by_medium_kind_and_space() {
        let s = TransportStats::default();
        s.inc_tx_network(&NetworkStatsClass::net(
            StatMessage::Put,
            StatSpace::User,
            30,
        ));
        s.inc_tx_network(&NetworkStatsClass::shm(
            StatMessage::Put,
            StatSpace::User,
            12,
        ));
        s.inc_tx_network(&NetworkStatsClass::control());
        s.inc_rx_network(&NetworkStatsClass::net(
            StatMessage::Reply,
            StatSpace::Admin,
            7,
        ));

        let r = s.report();
        assert_eq!(r.tx.n_msgs_on(StatMedium::Net), 2, "put + control");
        assert_eq!(r.tx.n_msgs_on(StatMedium::Shm), 1);
        assert_eq!(
            r.tx.payload_of(StatMessage::Put, StatSpace::User),
            PayloadCounters {
                msgs: 2,
                pl_bytes: 42
            }
        );
        // Control charged no payload cell at all.
        assert_eq!(
            r.tx.payload_of(StatMessage::Put, StatSpace::Admin),
            PayloadCounters::default()
        );
        assert_eq!(
            r.rx.payload_of(StatMessage::Reply, StatSpace::Admin),
            PayloadCounters {
                msgs: 1,
                pl_bytes: 7
            }
        );
    }

    /// The reason -> counter mapping is upstream's, arm for arm: only LowPass
    /// charges a byte counter, and the three reasons never bleed into each
    /// other's counters.
    #[cfg(feature = "transport-stats")]
    #[test]
    fn each_drop_reason_charges_only_its_own_counters() {
        for reason in StatDrop::ALL {
            let s = TransportStats::default();
            s.inc_tx_drop(reason, 2, 500);
            let d = s.report().tx;
            // Order: n_dropped, downsampler_dropped_msgs, low_pass_dropped_msgs.
            let charged = [
                d.n_dropped,
                d.downsampler_dropped_msgs,
                d.low_pass_dropped_msgs,
            ];
            assert_eq!(
                charged.iter().filter(|v| **v != 0).count(),
                1,
                "{reason:?} charged {charged:?}"
            );
            assert_eq!(
                d.low_pass_dropped_bytes,
                if reason == StatDrop::LowPass { 500 } else { 0 },
                "only LowPass carries bytes ({reason:?})"
            );
        }
    }

    /// R2371 — the RENDER covers the WHOLE derived surface: every name
    /// [`TransportStatsReport::counter_names`] lists appears as a `# TYPE` line,
    /// and every split counter emits one sample per axis value.
    ///
    /// The population is derived on BOTH sides — the names from the axis enums,
    /// the rendered text from the same enums — so this cannot pass by both sides
    /// being wrong in the same way; what it pins is that the two walks agree and
    /// that the count is not zero. A render that dropped an axis silently would
    /// emit fewer samples than the axis has variants, which the per-name sample
    /// count catches.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_render_covers_every_derived_counter_and_axis_value() {
        let text = TransportStatsReport::default().openmetrics_text();
        let names = TransportStatsReport::counter_names();

        // A population of zero would make every assertion below vacuous.
        assert_eq!(
            names.len(),
            2 * (4 + 2 * StatMessage::COUNT + 3),
            "the derived name list must be the axis product, not a hand list"
        );

        for name in &names {
            assert!(
                text.contains(&alloc::format!("\n# TYPE {name} counter\n"))
                    || text.starts_with(&alloc::format!("# TYPE {name} counter\n"))
                    || text.contains(&alloc::format!("# TYPE {name} counter\n")),
                "{name} is not rendered\n{text}"
            );
        }

        // The split counters render one LABELLED sample per axis value.
        for (name, axis_len) in [
            ("tx_n_msgs", StatMedium::COUNT),
            ("rx_n_msgs", StatMedium::COUNT),
            ("tx_z_put_msgs", StatSpace::COUNT),
            ("rx_z_reply_pl_bytes", StatSpace::COUNT),
        ] {
            let samples = text
                .lines()
                .filter(|l| l.starts_with(&alloc::format!("{name}{{")))
                .count();
            assert_eq!(samples, axis_len, "{name} rendered {samples} sample(s)");
        }

        // Every rendered sample line belongs to a name the walk produced: a
        // stray counter no `counter_names` entry covers would escape the gate.
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let head = line.split(['{', ' ']).next().unwrap_or_default();
            assert!(
                names.iter().any(|n| n == head),
                "{head} is rendered but not in the derived name list\n{text}"
            );
        }
    }

    /// The LINE FORMAT is upstream's plain-field shape, pinned as a whole string
    /// rather than by substring for the counters that are NOT split: `# HELP`,
    /// `# TYPE ... counter`, then `<name> <value>`, newline-terminated. A
    /// renderer that emitted the right names in the wrong shape would pass a
    /// `contains` assertion and fail a scraper.
    #[cfg(feature = "alloc")]
    #[test]
    fn openmetrics_text_is_upstreams_plain_field_shape() {
        let mut r = TransportStatsReport::default();
        r.tx.bytes = 140;
        r.tx.t_msgs = 2;
        let text = r.openmetrics_text();
        assert!(
            text.starts_with(
                "# HELP tx_bytes Counter of sent bytes.\n\
                 # TYPE tx_bytes counter\n\
                 tx_bytes 140\n\
                 # HELP tx_t_msgs Counter of sent transport messages.\n\
                 # TYPE tx_t_msgs counter\n\
                 tx_t_msgs 2\n\
                 # HELP tx_n_msgs Counter of sent network messages.\n\
                 # TYPE tx_n_msgs counter\n\
                 tx_n_msgs{medium=\"net\"} 0\n\
                 tx_n_msgs{medium=\"shm\"} 0\n"
            ),
            "{text}"
        );
    }

    /// R2371 — the `wz_*_batches` names are GONE, and must not come back.
    ///
    /// They were introduced to refuse upstream's `t_msgs` name on a premise the
    /// module docs now record as refuted by measurement. This is the twin of the
    /// test that used to sit here: that one refused upstream's name, this one
    /// refuses the wz-local name, and both exist so the decision is pinned
    /// somewhere a later edit has to read.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_wz_local_batch_names_are_not_exported() {
        let text = TransportStatsReport::default().openmetrics_text();
        for retired in ["wz_tx_batches", "wz_rx_batches"] {
            assert!(
                !text.contains(retired),
                "{retired} was retired at R2371; the counter carries upstream's \
                 t_msgs name because it holds upstream's quantity\n{text}"
            );
        }
        for adopted in ["tx_t_msgs", "rx_t_msgs"] {
            assert!(text.contains(&alloc::format!("\n{adopted} ")), "{text}");
        }
    }

    /// The default snapshot is all-zero (a fresh session has counted nothing).
    #[cfg(feature = "transport-stats")]
    #[test]
    fn default_is_zero() {
        assert_eq!(
            TransportStats::default().report(),
            TransportStatsReport::default()
        );
    }
}
