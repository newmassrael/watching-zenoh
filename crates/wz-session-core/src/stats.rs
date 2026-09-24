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
//! hand-written fields, so the counter arrays are SIZED by the axes instead of
//! naming every product. Adding a variant to an axis changes the report with no
//! edit to its fields, which is what keeps the population derived rather than
//! transcribed.
//!
//! R2843 — this report no longer has an OpenMetrics rendering. It had one, the
//! flat `tx_bytes` / `tx_n_msgs{medium=…}` block the metrics leg appended after
//! its build info, which was the 1.5.0 shape; the pin writes its metrics only
//! from its registry, and so does wz now (the `stats_registry` module). The
//! report stays as the per-session snapshot `OpenedSession::stats()` hands out.
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
//! # The adminspace consumer is the REGISTRY, not this report (R2843)
//!
//! R2371 recorded that the metrics leg appended this report's OpenMetrics
//! rendering. R2843 replaced that consumer: `AdminAnswerCtx` now carries a
//! `stats_registry::StatsRegistry`, a one-session host builds it with
//! `SessionLinkActions::session_stats_registry`, and the leg's body is that
//! registry's document. Covered end to end by
//! `declare_adminspace_metrics_get_returns_openmetrics_text`.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// The network message kind a registry sample counts
/// (`commons/zenoh-stats/src/labels.rs` @ `pub enum MessageLabel`).
///
/// Not [`StatMessage`]: that axis is the JSON `_stats` schema's four payload
/// kinds, which folds an `Err` reply onto `Reply` and has no kind at all for a
/// control-plane message, while this one names every network body — nine of
/// them, `reply-err` apart from `reply`
/// (`commons/zenoh-stats/src/labels.rs` @ `ResponseBody::Err(_) => MessageLabel::ReplyErr,`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageLabel {
    /// A `Push` carrying a `Put`.
    Put,
    /// A `Push` carrying a `Del`.
    Del,
    /// A `Request`.
    Query,
    /// A `Response` carrying a `Reply`.
    Reply,
    /// A `Response` carrying an `Err`.
    ReplyErr,
    /// A `ResponseFinal`.
    ResponseFinal,
    /// An `Interest`.
    Interest,
    /// A `Declare`.
    Declare,
    /// An `OAM`.
    Oam,
}

impl MessageLabel {
    /// Upstream's label value.
    pub const fn label(self) -> &'static str {
        match self {
            MessageLabel::Put => "put",
            MessageLabel::Del => "delete",
            MessageLabel::Query => "query",
            MessageLabel::Reply => "reply",
            MessageLabel::ReplyErr => "reply-err",
            MessageLabel::ResponseFinal => "response-final",
            MessageLabel::Interest => "interest",
            MessageLabel::Declare => "declare",
            MessageLabel::Oam => "oam",
        }
    }
}

/// How one network message counts — the parameter every TX sender hands the
/// `dispatch_network_message` chokepoint, and the RX walk hands
/// [`TransportStats::inc_rx_network`].
///
/// A CONTROL-plane message (Declare / Interest / OAM / ResponseFinal) has no
/// payload class: upstream's payload counters cover only the four data kinds,
/// so those messages count toward `n_msgs` and nothing else. That is
/// [`NetworkStatsClass::control`].
///
/// R2822 — every class also names its [`MessageLabel`], the registry's nine-way
/// kind. It is a constructor PARAMETER rather than something derived later, so
/// a sender cannot build a class without saying what it sends: the compiler
/// asks each of the typed senders, which is the population, and a new sender
/// cannot fall through. Only [`Self::undecoded`] can leave it unnamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStatsClass {
    /// The registry's message kind; `None` only for a received body this build
    /// could not decode and whose MID does not settle the kind.
    pub kind: Option<MessageLabel>,
    /// Which medium carried the bytes.
    pub medium: StatMedium,
    /// The payload classification, or `None` for a control-plane message.
    pub payload: Option<PayloadClass>,
}

impl NetworkStatsClass {
    /// A control-plane network message of `kind`: counts toward `n_msgs` on
    /// the `net` medium and toward no payload counter.
    pub const fn control(kind: MessageLabel) -> NetworkStatsClass {
        NetworkStatsClass {
            kind: Some(kind),
            medium: StatMedium::Net,
            payload: None,
        }
    }

    /// A received network message whose body this build has no codec for.
    ///
    /// It still counts toward `n_msgs`, and it carries NO registry kind: the
    /// registry leaves it out rather than file it under a kind it may not be.
    /// Such a message exists only in a build that compiles out the matching
    /// codec — upstream always decodes — and in exactly that build the wire
    /// constant that would name its MID is compiled out too
    /// (`wz_codecs::wire_const` gates each network MID on its codec), so a
    /// kind read off the MID would need a second, ungated copy of the wire
    /// table for a case no full build reaches.
    pub const fn undecoded() -> NetworkStatsClass {
        NetworkStatsClass {
            kind: None,
            medium: StatMedium::Net,
            payload: None,
        }
    }

    /// The class a sender hands the chokepoint in a build WITHOUT
    /// `transport-stats`, where nothing reads it. Named so that building one
    /// does not mean inventing a kind or resolving a key expression for a
    /// counter that is not compiled.
    pub const fn unread() -> NetworkStatsClass {
        NetworkStatsClass {
            kind: None,
            medium: StatMedium::Net,
            payload: None,
        }
    }

    /// A data-plane network message of `kind` whose payload rode the LINK.
    pub const fn net(
        kind: MessageLabel,
        message: StatMessage,
        space: StatSpace,
        pl_bytes: usize,
    ) -> NetworkStatsClass {
        NetworkStatsClass {
            kind: Some(kind),
            medium: StatMedium::Net,
            payload: Some(PayloadClass {
                message,
                space,
                pl_bytes,
            }),
        }
    }

    /// A data-plane network message of `kind` whose payload rode SHARED MEMORY
    /// — the message carried a descriptor, so `n_msgs` counts on the `shm`
    /// medium.
    pub const fn shm(
        kind: MessageLabel,
        message: StatMessage,
        space: StatSpace,
        pl_bytes: usize,
    ) -> NetworkStatsClass {
        NetworkStatsClass {
            kind: Some(kind),
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

    /// Count one inbound WIRE read of `bytes` bytes — the RX dispatch. Bytes
    /// only: see [`Self::inc_rx_transport_message`].
    #[inline]
    pub fn inc_rx(&self, bytes: usize) {
        self.rx.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count one inbound TRANSPORT message — one per message decoded out of a
    /// received unit, not one per read.
    ///
    /// R2825. The TX side can count a write as one transport message because
    /// wz never puts two in one write (the module docs measure it). The RX side
    /// cannot: a peer batches, and zenoh batches by default, so one read
    /// carries several. Upstream counts inside its batch walk, one per decoded
    /// message (`io/zenoh-transport/src/unicast/universal/rx.rs` @ `stats.inc_transport_message(zenoh_stats::Rx, 1);`),
    /// and before R2825 this counter counted reads, which undercounts every
    /// batched peer.
    #[inline]
    pub fn inc_rx_transport_message(&self) {
        self.rx.t_msgs.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y811 — the report type is NAMEABLE AND CONSTRUCTIBLE WITH NO FEATURES
    /// AT ALL, which is the whole reason R311y810 un-gated this module: a
    /// consumer holds one in an UNGATED struct field (`AdminAnswerCtx`'s
    /// `stats` did until R2843 moved it to the registry), so a build with neither
    /// `alloc` nor `transport-stats` must still be able to name the type, copy
    /// it, and compare it.
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
        // field actually leans on.
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
        // R2825 — a READ is not a transport message: one unit of 12 bytes
        // that carried two messages counts its bytes once and its messages
        // twice, as upstream's batch walk counts them.
        s.inc_rx(12);
        s.inc_rx_transport_message();
        s.inc_rx_transport_message();

        let r = s.report();
        assert_eq!(r.tx.bytes, 140);
        assert_eq!(r.tx.t_msgs, 2);
        assert_eq!(r.rx.bytes, 12);
        assert_eq!(r.rx.t_msgs, 2);
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
            MessageLabel::Put,
            StatMessage::Put,
            StatSpace::User,
            30,
        ));
        s.inc_tx_network(&NetworkStatsClass::shm(
            MessageLabel::Put,
            StatMessage::Put,
            StatSpace::User,
            12,
        ));
        s.inc_tx_network(&NetworkStatsClass::control(MessageLabel::Declare));
        s.inc_rx_network(&NetworkStatsClass::net(
            MessageLabel::Reply,
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
