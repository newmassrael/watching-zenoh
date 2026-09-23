// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Link-layer types shared between LinkDriver impls and dispatch code.
//!
//! Carries the small wire-shape value types (TxFrame / RxFrame / LinkEvent
//! / LostCause) so MCU runtime profiles can express the same LinkDriver
//! contract without dragging in std / tokio. The LinkDriver trait itself
//! and its concrete TcpDriver / UdpDriver impls stay in wz-runtime-tokio
//! because those are tokio-specific (TcpStream / UdpSocket).
//!
//! Layer: §5.C link-tier value-type surface.

use alloc::string::String;
use alloc::vec::Vec;
use wz_runtime_core::Runtime;

use crate::reliability::Reliability;

// The `ActionsHandle` GAT below references `SessionLinkActions`, which lives
// behind the same `all(alloc, session-unicast)` gate as the action bundle
// itself (lib.rs); these imports + the GAT are therefore gated identically so
// the `SessionRuntime` trait still compiles on a minus-session-unicast subset.
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
use crate::session_actions::SessionLinkActions;
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
use core::ops::Deref;
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
use wz_runtime_core::TimeSource;

/// R311y453 — which LINK PROTOCOL a transport speaks, as a RULE sees it: the wz
/// mirror of zenoh's `InterceptorLink` (`zenoh-config/src/lib.rs:317-327`), and
/// the vocabulary of the §5.16 `link_protocols` subject axis.
///
/// Deliberately NOT [`crate::locator::Proto`], which was the first thing tried
/// and does not fit: `Proto` is the IP-locator scheme set, because serial,
/// unixsock, unixpipe and vsock locators are not `SocketAddr`-based and carry
/// their own parsed types.
///
/// R2794 (open-debt item 814) — EXACTLY UPSTREAM'S NINE, and no longer a
/// superset. This enum used to carry a tenth value, `QuicDatagram`, on the stated
/// ground that "zenoh has no such transport". It has one
/// (`io/zenoh-links/zenoh-link-quic_datagram`, locator prefix `"quic"`), and it
/// files it under `Quic` on this axis, because upstream reads the axis off the
/// link's auth id and the datagram link carries the same `LinkAuthId::Quic` the
/// stream link does. So one rule narrowed to `quic` governs both there, while
/// here the same rule silently missed the datagram link -- for a deny rule, a
/// bypass -- and wz accepted a `quic-datagram` rule zenohd refuses as unknown.
///
/// The extra value existed because ONE enum was answering two questions: which
/// protocol a rule matches, and what KIND of link this is (streamed, reliable,
/// how it advertises itself). Those have different answers for the same link,
/// so they are now two types. The kind is [`LinkKind`]; a link STORES its kind
/// and derives this protocol from it, so the two cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorLink {
    /// `tcp/...` — the TCP stream link.
    Tcp,
    /// `udp/...` — the UDP datagram link.
    Udp,
    /// `tls/...` — TLS over TCP.
    Tls,
    /// `quic/...` — QUIC, over a stream OR over datagrams: upstream files both of
    /// its QUIC links under this one protocol, and so does wz.
    Quic,
    /// `serial/...` — the COBS-framed tty link.
    Serial,
    /// `unixpipe/...` — the named-FIFO link.
    Unixpipe,
    /// `unixsock-stream/...` — the Unix-domain stream socket link. Named as zenoh
    /// names it (`UnixsockStream`), not as wz's shorter locator scheme spells it.
    UnixsockStream,
    /// `vsock/...` — the AF_VSOCK host/guest link.
    Vsock,
    /// `ws/...` — WebSocket over TCP, one batch per BINARY message.
    Ws,
}

impl InterceptorLink {
    /// The config spelling of this link protocol — zenoh serialises
    /// `InterceptorLink` with `#[serde(rename_all = "kebab-case")]`
    /// (`zenoh-config/src/lib.rs:314-327`), so `UnixsockStream` is
    /// `unixsock-stream`, not the shorter scheme wz's own locator grammar uses.
    /// A deploy config is written against UPSTREAM's vocabulary.
    pub fn as_str(&self) -> &'static str {
        match self {
            InterceptorLink::Tcp => "tcp",
            InterceptorLink::Udp => "udp",
            InterceptorLink::Tls => "tls",
            InterceptorLink::Quic => "quic",
            InterceptorLink::Serial => "serial",
            InterceptorLink::Unixpipe => "unixpipe",
            InterceptorLink::UnixsockStream => "unixsock-stream",
            InterceptorLink::Vsock => "vsock",
            InterceptorLink::Ws => "ws",
        }
    }

    /// R2650 — every variant, so the INVERSE of [`Self::as_str`] can be derived
    /// rather than written a second time.
    ///
    /// A config reader has to turn upstream's spelling back into a variant, and
    /// a hand-written reverse `match` would be a second copy of this vocabulary,
    /// free to disagree with the one above. [`Self::from_upstream_str`] searches
    /// THIS list through `as_str`, so there is one table and the inverse cannot
    /// drift from it.
    ///
    /// Its completeness is held by `every_link_variant_is_listed_in_all`, which
    /// carries an exhaustive `match`: adding a variant stops that test
    /// compiling, which is the only way a list like this stays honest.
    pub const ALL: &'static [InterceptorLink] = &[
        InterceptorLink::Tcp,
        InterceptorLink::Udp,
        InterceptorLink::Tls,
        InterceptorLink::Quic,
        InterceptorLink::Serial,
        InterceptorLink::Unixpipe,
        InterceptorLink::UnixsockStream,
        InterceptorLink::Vsock,
        InterceptorLink::Ws,
    ];

    /// The variant upstream spells `text`, or `None`.
    ///
    /// Upstream deserializes this axis into an enum, so an unknown protocol is a
    /// parse error there; a reader that shrugged one off would accept a document
    /// a real zenohd refuses.
    pub fn from_upstream_str(text: &str) -> Option<InterceptorLink> {
        InterceptorLink::ALL
            .iter()
            .copied()
            .find(|link| link.as_str() == text)
    }

    /// Parse a config spelling back, or `None` for an unknown name. Every config
    /// surface (the demo knobs today, a `deploy.yaml` loader later) parses
    /// through this one function rather than growing its own table.
    ///
    /// R2794 — this used to carry its OWN hand-written list of the values,
    /// beside the `ALL` that [`Self::from_upstream_str`] searches: a second copy
    /// of one vocabulary, free to disagree with the first. It now IS that search.
    /// The config spelling and upstream's are the same words on this axis (see
    /// [`Self::as_str`]), so there was never a second vocabulary to keep.
    pub fn from_config_str(s: &str) -> Option<Self> {
        Self::from_upstream_str(s)
    }
}

/// R2794 (open-debt item 814) — the KIND of link a transport is: what the
/// link itself answers, as opposed to which protocol a rule sees it as
/// ([`InterceptorLink`]).
///
/// The two differ for real links, which is why they are two types. Upstream's
/// QUIC datagram link is protocol `quic` to every rule, yet it is not streamed
/// and not reliable, and it advertises itself as `quic/…?rel=0`; its reliable
/// UDP link is protocol `udp` to every rule, yet it IS streamed and reliable.
/// One enum answering both questions had to either give a rule a protocol
/// upstream does not have, or give a link the wrong answers for itself -- and
/// wz had done the first.
///
/// A link STORES its kind (see [`LinkSubject`]) and DERIVES its protocol
/// through [`Self::interceptor_protocol`], so there is one fact and the two
/// answers cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `tcp/...` — the TCP stream link.
    Tcp,
    /// `udp/...` — the UDP datagram link.
    Udp,
    /// `udp/...?rel=1` — upstream's RELIABLE UDP link (R2810): QUIC under a
    /// plaintext session, one bidirectional stream. A distinct KIND, and the
    /// SAME protocol as [`Self::Udp`] to a rule, because upstream gives every
    /// variant of its udp link one auth id
    /// (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `&LinkAuthId::Udp`).
    UdpReliable,
    /// `tls/...` — TLS over TCP.
    Tls,
    /// `quic/...` — QUIC, batch over one bidirectional stream.
    Quic,
    /// `quic/...?rel=0` — QUIC unreliable datagrams (RFC9221). A distinct KIND,
    /// and the SAME protocol as [`Self::Quic`] to a rule.
    QuicDatagram,
    /// `serial/...` — the COBS-framed tty link.
    Serial,
    /// `unixpipe/...` — the named-FIFO link.
    Unixpipe,
    /// `unixsock-stream/...` — the Unix-domain stream socket link.
    UnixsockStream,
    /// `vsock/...` — the AF_VSOCK host/guest link.
    Vsock,
    /// `ws/...` — WebSocket over TCP, one batch per BINARY message.
    Ws,
}

impl LinkKind {
    /// Every kind. Its completeness is held by
    /// `every_link_kind_is_listed_in_all`, whose exhaustive `match` stops
    /// compiling when a kind is added -- the same device `InterceptorLink::ALL`
    /// uses, for the same reason.
    pub const ALL: &'static [LinkKind] = &[
        LinkKind::Tcp,
        LinkKind::Udp,
        LinkKind::UdpReliable,
        LinkKind::Tls,
        LinkKind::Quic,
        LinkKind::QuicDatagram,
        LinkKind::Serial,
        LinkKind::Unixpipe,
        LinkKind::UnixsockStream,
        LinkKind::Vsock,
        LinkKind::Ws,
    ];

    /// The protocol a RULE sees this link as -- upstream's reading of the axis,
    /// which it takes from the link's auth id
    /// (`zenoh/src/net/routing/interceptor/mod.rs` @ `LinkAuthId::Quic(_) => Self(InterceptorLink::Quic),`).
    ///
    /// Wildcard-free: a new kind must state which protocol it is to a rule, which
    /// is exactly the decision the old single enum let a new link skip.
    pub fn interceptor_protocol(self) -> InterceptorLink {
        match self {
            LinkKind::Tcp => InterceptorLink::Tcp,
            // Both UDP kinds are `udp` to a rule, as upstream files them.
            LinkKind::Udp | LinkKind::UdpReliable => InterceptorLink::Udp,
            LinkKind::Tls => InterceptorLink::Tls,
            // Both QUIC kinds are `quic` to a rule, as upstream files them.
            LinkKind::Quic | LinkKind::QuicDatagram => InterceptorLink::Quic,
            LinkKind::Serial => InterceptorLink::Serial,
            LinkKind::Unixpipe => InterceptorLink::Unixpipe,
            LinkKind::UnixsockStream => InterceptorLink::UnixsockStream,
            LinkKind::Vsock => InterceptorLink::Vsock,
            LinkKind::Ws => InterceptorLink::Ws,
        }
    }

    /// R2259 (open-debt item 593) — whether this protocol carries a BYTE STREAM
    /// rather than framed datagrams, which is what zenoh-c's `z_link_is_streamed`
    /// reports.
    ///
    /// ⛔ R2260 CORRECTED THIS AGAINST UPSTREAM AND IT WAS WRONG IN TWO ARMS.
    /// R2259 derived it from what wz's own framing does — "the two datagram
    /// schemes are the unstreamed ones" — and asserted in prose that `Ws` was
    /// streamed "as upstream classifies it". Read at the pin, upstream says the
    /// opposite for `Ws`, and for `Serial` too. This is `z_link_is_streamed`, a
    /// zenoh-c accessor, so upstream's answer IS the specification and a
    /// derivation from wz's framing is not a second opinion — it is a bug.
    ///
    /// The table below is TRANSCRIBED from each link's own `LinkUnicastTrait`
    /// impl at the pin and is held to it by `scripts/lib/upstream_link_axis_gate.py`,
    /// which reads these two `matches!` bodies and this table and grades both
    /// against the pinned upstream links, so it cannot drift back into prose.
    /// (R2794: this line used to name a test,
    /// `crates/wz-integration-tests/tests/upstream_link_axis_oracle.rs`, that does
    /// not exist in the tree -- the gate is the only thing holding the table.)
    ///
    /// | link             | streamed | reliable |
    /// |------------------|----------|----------|
    /// | tcp              | true     | true     |
    /// | udp              | false    | false    |
    /// | udp-reliable     | true     | true     |
    /// | tls              | true     | true     |
    /// | quic             | true     | true     |
    /// | quic-datagram    | false    | false    |
    /// | serial           | false    | false    |
    /// | unixpipe         | true     | true     |
    /// | unixsock-stream  | true     | true     |
    /// | vsock            | true     | true     |
    /// | ws               | false    | TRUE     |
    ///
    /// ⚠ `udp` is upstream's one CONDITIONAL: its impl matches on a variant and
    /// answers `true` only for the reliable-UDP one, `false` for the connected
    /// and unconnected forms. R2810 gave wz that variant as its own kind,
    /// [`LinkKind::UdpReliable`] (row `udp-reliable`), so the conditional is two
    /// rows here and the gate grades each against the upstream ARM it stands
    /// for rather than skipping the link.
    pub fn is_streamed(&self) -> bool {
        !matches!(
            self,
            LinkKind::Udp | LinkKind::QuicDatagram | LinkKind::Serial | LinkKind::Ws
        )
    }

    /// R2259 (open-debt item 593) — whether this protocol delivers RELIABLY,
    /// the input to zenoh-c's `z_link_reliability`.
    ///
    /// ⛔⛔ R2259 wrote this as its own match "so the coincidence does not look
    /// like a definition", and then gave it the SAME arms as
    /// [`is_streamed`](Self::is_streamed) anyway. R2260 read upstream and the
    /// coincidence is not one: **`ws` is the link where the two axes disagree**
    /// — unstreamed and reliable, because a WebSocket delivers discrete BINARY
    /// messages over a TCP connection that retransmits. Writing two matches was
    /// right; filling them identically was the mistake, and only reading
    /// upstream could have caught it.
    ///
    /// Upstream keeps this as a per-crate `IS_RELIABLE` constant rather than a
    /// method body (except `udp`, which matches on its variant like its
    /// streamed twin) — `io/zenoh-links/zenoh-link-ws/src/lib.rs`
    /// @ `IS_RELIABLE`. The table on `is_streamed` carries both columns.
    pub fn is_reliable(&self) -> bool {
        !matches!(
            self,
            LinkKind::Udp | LinkKind::QuicDatagram | LinkKind::Serial
        )
    }

    /// R311y473 — the DIALABLE LOCATOR for this protocol at `address`: the string
    /// a foreign peer has to be able to parse and connect to.
    ///
    /// Deliberately NOT [`InterceptorLink::as_str`]. That is a CONFIG spelling,
    /// and the two roles differ -- zenoh gives both its QUIC links the `quic`
    /// scheme and selects with the `rel` metadata key
    /// (`io/zenoh-link/src/lib.rs:165-171`), so the datagram kind advertises
    /// `?rel=0`; and `unixsock-stream` coincides only because the config spelling
    /// was already written as the scheme. R311y470 shipped a round fixing exactly this
    /// confusion at the listener-advertise sites, where a log word had been reused
    /// as a scheme and produced two locators no zenoh peer could dial.
    ///
    /// This is the ONE table. `BoundListener::advertised_locator` (the R311y470
    /// site) delegates here rather than carrying a second copy, so a new
    /// transport's scheme is stated once and every emitter inherits it. The match
    /// is wildcard-free for the same reason it is there: a new variant must state
    /// its scheme rather than inherit a plausible-looking neighbour's.
    pub fn locator_for(&self, address: &str) -> String {
        use alloc::format;
        match self {
            LinkKind::Tcp => format!("tcp/{address}"),
            LinkKind::Udp => format!("udp/{address}"),
            // The `rel=1` is what makes it DIALABLE as this kind: a peer reading
            // `udp/{address}` alone dials the datagram link, which cannot talk to
            // a reliable listener. Upstream's listener keeps its endpoint's
            // metadata on the locator it returns for the same reason
            // (`io/zenoh-link-commons/src/quic/unicast.rs` @ `endpoint.metadata(),`).
            LinkKind::UdpReliable => format!("udp/{address}?rel=1"),
            LinkKind::Tls => format!("tls/{address}"),
            LinkKind::Quic => format!("quic/{address}"),
            LinkKind::QuicDatagram => format!("quic/{address}?rel=0"),
            LinkKind::Serial => format!("serial/{address}"),
            LinkKind::Unixpipe => format!("unixpipe/{address}"),
            LinkKind::UnixsockStream => format!("unixsock-stream/{address}"),
            LinkKind::Vsock => format!("vsock/{address}"),
            LinkKind::Ws => format!("ws/{address}"),
        }
    }
}

/// The link MTU a [`BoxedLinkDriver`] reports when it has no fixed
/// frame-size bound of its own — zenoh-pico's `_z_get_link_mtu_tcp`
/// (`src/link/unicast/tcp.c:86`) returns the identical `65535`, the
/// u16 ceiling a stream link never exceeds. A driver whose link DOES
/// cap the frame (serial = `_Z_SERIAL_MTU_SIZE` 1500) overrides
/// [`BoxedLinkDriver::link_mtu`]; everything else inherits this and the
/// `min` against it is therefore a no-op (own / peer `batch_size` are
/// `u16`, so they never exceed it).
pub const DEFAULT_LINK_MTU: usize = 65_535;

/// What a [`BoxedLinkDriver::send_blocking`] did with the bytes it was handed —
/// the DRIVER-LEVEL DROP HOOK (R2371).
///
/// Until R2371 that method returned `()`, so a driver that refused a write
/// dropped it silently: the UDP and QUIC-datagram writers discard a datagram
/// past their link MTU, and every channel-backed writer discards a write onto a
/// closed channel, and in both cases the transport above was told nothing. The
/// `transport-stats` atom carried that as its named blocker — a faithful
/// `n_dropped` counter "needs a driver-level hook first" — and this is that
/// hook.
///
/// It is deliberately a RETURN VALUE rather than a counter the driver owns.
/// A driver counting its own drops would put the number somewhere the session
/// cannot reach and the adminspace cannot render, and would leave every OTHER
/// consumer of a refused write (a caller that wants to retry, a lane that wants
/// to assert a drop happened) with nothing. The transport is where the outcome
/// is already known to belong to a session.
///
/// `#[must_use]` is the point: a caller that ignores the outcome is back to the
/// silent drop this type exists to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused write is the drop `transport-stats` counts; ignoring it \
              restores the silent-drop behaviour this type replaced"]
pub enum LinkSendOutcome {
    /// The driver accepted the bytes — they are on the wire, or queued on a
    /// writer that owns them now.
    Sent,
    /// The driver refused the bytes and they will never reach the wire.
    Dropped(LinkDropCause),
}

impl LinkSendOutcome {
    /// Whether this outcome is a drop — the predicate the stats seam charges on.
    pub fn is_dropped(self) -> bool {
        matches!(self, LinkSendOutcome::Dropped(_))
    }
}

/// Why a driver refused a write.
///
/// These are wz's real drop reasons, and they are NOT upstream's: zenoh drops on
/// CONGESTION, at a bounded priority queue wz does not have (see
/// [`StatDrop::Transport`](crate::stats::StatDrop::Transport)). Naming them
/// keeps a later reader from reading `n_dropped` as a congestion signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDropCause {
    /// The payload exceeded what this link can put in one write — a datagram
    /// past the link MTU on UDP / QUIC-datagram, or a frame past the stream
    /// envelope's length field. A well-formed session fragments to the
    /// negotiated budget before reaching the driver, so this is the backstop
    /// firing rather than the normal path.
    Oversize,
    /// The writer this driver feeds is gone — the task exited, or the channel's
    /// receiver dropped. Every subsequent write on this link drops the same way
    /// until the session notices the link is down.
    WriterGone,
}

/// Synchronous outbound link-write seam the session FSM action layer
/// drives. The FSM's link sink (`R::LinkSink`, resolved through
/// [`SessionRuntime::link_driver`]) decouples the runtime-agnostic
/// `SessionLinkActions` from the concrete transport: the tokio AP
/// profile wraps an async `LinkDriver` behind a blocking-enqueue
/// adapter (`TokioLinkDriverAdapter` / `UdpWriteDriver` /
/// `TcpWriteDriver`); the lwIP MCU profile wraps a synchronous
/// `LwipUdpSocket::send_to`.
///
/// The trait is deliberately *pure* — it carries no `Send + Sync`
/// supertrait. Auto-trait requirements are a per-profile *storage*
/// decision, not a contract of the write seam itself: the tokio
/// profile shares the driver across worker threads so it binds
/// [`SessionRuntime::LinkSink`] to `Arc<dyn BoxedLinkDriver + Send +
/// Sync>`, while the single-task lwIP MCU profile shares the same
/// `udp_pcb` between its sync drive loop and its driver, so it binds
/// `LinkSink` to a `Rc<dyn BoxedLinkDriver>` that is intentionally
/// `!Send` (the MCU socket holds raw `*mut udp_pcb` pointers that
/// cannot satisfy `Send` without an `unsafe impl`). Baking `Send +
/// Sync` onto the trait would force that `unsafe` hack onto the MCU
/// impl; keeping the trait pure lets each profile's `LinkSink` carry
/// the auto-traits its concurrency model actually needs.
///
/// R2794 — this text sat at the top of the file, left behind when the
/// "hoist frame encoders + BoxedLinkDriver" refactor moved this trait down, and
/// so it documented [`InterceptorLink`] instead of the seam it describes. It is
/// back on the trait it is about.
pub trait BoxedLinkDriver {
    /// Hand `bytes` to the link, reporting whether they were accepted.
    ///
    /// R2371 — the return value is the drop hook; see [`LinkSendOutcome`]. A
    /// driver that cannot refuse a write returns
    /// [`LinkSendOutcome::Sent`] unconditionally, which is most of them.
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome;
    fn open_blocking(&self);
    fn close_blocking(&self);

    /// The largest single frame this link can carry, in bytes — the wz
    /// analogue of zenoh-pico's per-link `zl->_mtu` (set by the link's
    /// `_z_get_link_mtu_*` at open, `tcp.c:111` / `serial.c:71`). The
    /// transport TX path bounds its outbound budget by it:
    /// `min(link mtu, negotiated batch)` is the wbuf size pico computes
    /// at `transport/unicast/transport.c:47`, so a message past the
    /// budget fragments to chunks the link can actually emit rather than
    /// being handed a frame the driver can only drop.
    ///
    /// Defaults to [`DEFAULT_LINK_MTU`] (a stream link with no fixed
    /// frame cap — TCP / UDP / the lwIP MCU socket). A frame-bounded
    /// link (serial) overrides this with its real cap; the default's
    /// `min` term is then inert for every unbounded link.
    fn link_mtu(&self) -> usize {
        DEFAULT_LINK_MTU
    }

    /// R311y453 — the LINK-DERIVED SUBJECT of this driver's transport: what the
    /// §5.16 interceptors scope their rules by, or `None` for a driver that
    /// carries no subject at all (the test doubles).
    ///
    /// Resolved ONCE, at link open, and stored — so this is a field read on the
    /// per-message admission path, never a syscall. Returning a reference rather
    /// than an owned [`LinkSubject`] is what makes that true: an owned return
    /// would clone the interface-name vector per message.
    ///
    /// Read here, on the link driver, because it is the only object that knows
    /// its own scheme and its own local address — deriving it from a dial
    /// locator instead would be wrong for an ACCEPTED link, which never had one.
    fn link_subject(&self) -> Option<&LinkSubject> {
        None
    }

    /// R311y473 — the LOCATOR PAIR of this driver's transport: the `{src,dst}`
    /// zenoh's adminspace renders per link (`link_to_json`,
    /// `net/runtime/adminspace.rs:608-613`), or `None` for a driver that cannot
    /// name its endpoints (the test doubles, and the MCU drivers whose stack has
    /// no address to read).
    ///
    /// Resolved ONCE, at link open, and stored, for the same reason
    /// [`Self::link_subject`] is: the constructing pipeline is the only object
    /// that knows both its own scheme AND its own socket, and an admin GET must
    /// not turn into a syscall per reply.
    ///
    /// The strings are DIALABLE LOCATORS, not log words. R311y470 found two of
    /// nine advertise sites emitting a scheme no zenoh peer — and in one case not
    /// even wz's own parser — could dial, because they reused a transport's log
    /// name as its scheme. This accessor feeds an admin surface a foreign client
    /// reads, so it inherits that contract: build the string through
    /// [`crate::link::LinkEndpoints::new`]'s callers in the runtime's
    /// `link_interfaces` helpers, which state the scheme explicitly.
    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        None
    }
}

/// R311y473 — one link's locator pair, the wz counterpart of the `{src,dst}`
/// object zenoh's `link_to_json` emits per link of a transport
/// (`net/runtime/adminspace.rs:608-613`). Populated into
/// [`crate::adminspace::AdminLink`] by the admin host, so a foreign admin client
/// sees the same shape against wz as against zenohd.
///
/// Both fields are LOCATORS (`<scheme>/<address>`), not bare addresses — see the
/// dialability contract on [`BoxedLinkDriver::link_endpoints`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkEndpoints {
    /// This end of the link — zenoh's `Link::src`.
    pub src: String,
    /// The peer end of the link — zenoh's `Link::dst`.
    pub dst: String,
}

impl LinkEndpoints {
    /// Build a pair from two already-rendered locator strings.
    pub fn new(src: impl Into<String>, dst: impl Into<String>) -> Self {
        Self {
            src: src.into(),
            dst: dst.into(),
        }
    }
}

/// R311y453 — the subject a §5.16 rule can narrow itself to, as derived from the
/// LINK a message arrived on: the wz counterpart of the `interfaces` +
/// `link_protocols` pair zenoh checks in every interceptor factory
/// (`net/routing/interceptor/downsampling.rs:90-116`, and the identical block in
/// `access_control.rs` / `low_pass.rs`).
///
/// One value type rather than one accessor per axis, because the axis set GROWS:
/// zenoh's ACL subject also has cert-CN and username
/// (`interceptor/authorization.rs:39-46`). The cert-CN is a LINK fact and lands
/// as a field here, not as a fourth trait method and a fourth constructor
/// parameter on six pipelines.
///
/// R2631 — the username did NOT land here, and that corrects this note rather
/// than contradicting it: a username is a SESSION fact. A link driver cannot know
/// who authenticated over it; the accept handshake does, so the name lives on the
/// session and reaches the ACL through the interceptor context's `username`,
/// beside the zid it resembles.
///
/// Every field is an [`Option`], and the distinction is load-bearing — see
/// [`interfaces`](Self::interfaces).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkSubject {
    /// What KIND of link the transport is, or `None` when the driver cannot say
    /// (a test double). A rule narrowed by `link_protocols` treats `None` as
    /// MATCHING — see the fail-closed note below.
    ///
    /// R2794 (open-debt item 814) — this used to be `protocol:
    /// Option<InterceptorLink>`, one value read by two consumers who needed
    /// different things from it: a rule wanted the protocol, zenoh-c's
    /// `z_link_is_streamed` / `z_link_reliability` wanted the link's own
    /// answers. The kind is the fact; [`Self::protocol`] derives what a rule
    /// sees, so the datagram link is `quic` to a rule while still reporting
    /// itself as unstreamed and best-effort.
    pub kind: Option<LinkKind>,
    /// The names of the NICs this link's local address sits on:
    ///
    /// - `Some(names)` — resolved. An EMPTY set is a DEFINITE answer, "this link
    ///   is on no NIC", which is the honest report for a unix-socket, pipe,
    ///   serial or vsock link. A rule narrowed by `interfaces` does NOT match it.
    /// - `None` — could not be determined (the resolver failed, or the platform
    ///   has no implementation). A rule narrowed by `interfaces` DOES match it.
    ///
    /// zenoh cannot express that difference: it maps a failed lookup to the same
    /// `vec![]` it uses for "no NICs"
    /// (`io/zenoh-link-commons/src/unicast.rs:112-118`), so upstream silently
    /// reads a broken syscall as a definite negative.
    pub interfaces: Option<Vec<String>>,
    /// R2698 — the COMMON NAME on the peer's leaf certificate, for a link that
    /// presents one:
    ///
    /// - `Some(name)` — the peer authenticated and its leaf certificate's
    ///   subject carries that common name;
    /// - `None` — there is no such name to report. That covers a link with no
    ///   certificate at all (tcp, unixsock, serial), a TLS link whose peer sent
    ///   no chain, and a certificate whose subject has no common name.
    ///
    /// ⚠ THE THREE CASES ARE ONE ANSWER HERE, deliberately, where `interfaces`
    /// above splits "resolved to nothing" from "could not resolve". Upstream
    /// makes the same collapse and it is not an oversight on either side: its
    /// extraction answers `auth_value: None` both when `peer_certificates()` is
    /// absent and when the subject has no common name
    /// (`io/zenoh-links/zenoh-link-tls/src/unicast.rs` @
    /// `fn get_client_cert_common_name`), so a rule narrowed by this axis has
    /// only ever been able to ask "is this peer named X". Splitting it here
    /// would invent a distinction no rule can express and no upstream document
    /// can request.
    pub cert_common_name: Option<String>,
}

impl LinkSubject {
    /// A subject nothing is known about — every axis indeterminate. What a
    /// driver with no transport identity reports, and the value a
    /// [`BoxedLinkDriver::link_subject`] of `None` is equivalent to.
    pub const UNKNOWN: Self = Self {
        kind: None,
        interfaces: None,
        cert_common_name: None,
    };

    /// R2794 — the protocol a RULE sees this link as, derived from its
    /// [`kind`](Self::kind) and never stored beside it.
    pub fn protocol(&self) -> Option<InterceptorLink> {
        self.kind.map(LinkKind::interceptor_protocol)
    }

    /// R2698 — this subject with its peer's leaf-certificate common name filled
    /// in, consuming and returning so a link's `wire_*` can add it to the
    /// subject a shared constructor already built.
    ///
    /// Separate from construction because of WHEN the value exists: the peer
    /// chain is readable for one window inside the link's own wiring — before
    /// the stream is split, after which the rustls connection is gone — while
    /// the subject itself is built by a helper shared with every transport that
    /// never sees a certificate. Threading an `Option<String>` through that
    /// helper would put a TLS-only parameter on the tcp, vsock, serial and
    /// unixsock paths, where the only honest argument is `None`.
    #[must_use]
    pub fn with_cert_common_name(mut self, cert_common_name: Option<String>) -> Self {
        self.cert_common_name = cert_common_name;
        self
    }

    /// Whether this subject is governed by a rule narrowed to `protocols`.
    ///
    /// FAIL-CLOSED: an indeterminate protocol MATCHES, so a rule still applies to
    /// a link that cannot identify itself. All three §5.16 interceptors are
    /// RESTRICTIVE when they apply — a deny, a rate limit, a size cap — so
    /// "apply when unsure" is the conservative direction for every one of them.
    ///
    /// This is a DELIBERATE divergence, and it fixes an upstream inconsistency
    /// rather than inventing a policy: zenoh's two subject axes disagree with
    /// each other on the error path. Its `interfaces` arm SKIPS the whole check
    /// when `transport.get_links()` fails, leaving the interceptor installed
    /// (restrictive); its `link_protocols` arm returns `(None, None)` when
    /// `transport.get_auth_ids()` fails, installing NOTHING (permissive)
    /// — `downsampling.rs:90-116`. wz applies one policy to both.
    pub fn matches_protocols(&self, protocols: &[InterceptorLink]) -> bool {
        match self.protocol() {
            Some(p) => protocols.contains(&p),
            None => true,
        }
    }

    /// Whether this subject is governed by a rule narrowed to `interfaces`.
    ///
    /// Fail-closed on an indeterminate set, exactly as
    /// [`matches_protocols`](Self::matches_protocols); a RESOLVED-but-empty set
    /// is a definite negative and does not match.
    ///
    /// The quantifier is ANY — the link matches if any of its NIC names is
    /// listed. zenoh uses ANY on its `link_protocols` axis but ALL-links on its
    /// `interfaces` axis (`downsampling.rs:92-96` returns early unless EVERY link
    /// of the transport has a listed interface), a second inconsistency between
    /// the two axes that wz does not reproduce.
    pub fn matches_interfaces(&self, interfaces: &[String]) -> bool {
        match &self.interfaces {
            Some(names) => names.iter().any(|n| interfaces.contains(n)),
            None => true,
        }
    }

    /// [`matches_protocols`](Self::matches_protocols) over an OPTIONAL subject: an
    /// ABSENT subject is indeterminate, exactly as an absent protocol is, and so
    /// matches. The two "unknown" spellings — `None` subject and `UNKNOWN`
    /// subject — must not diverge, which is why the fold lives here rather than
    /// at each of the three call sites.
    ///
    /// An EMPTY `protocols` list means the rule does not narrow by protocol at
    /// all, so it matches everything; the same holds for
    /// [`opt_matches_interfaces`](Self::opt_matches_interfaces). That is what
    /// makes both axes OPT-IN, as zenoh's `Option<NEVec<_>>` config fields are.
    pub fn opt_matches_protocols(subject: Option<&Self>, protocols: &[InterceptorLink]) -> bool {
        protocols.is_empty() || subject.map_or(true, |s| s.matches_protocols(protocols))
    }

    /// [`matches_interfaces`](Self::matches_interfaces) over an OPTIONAL subject.
    /// See [`opt_matches_protocols`](Self::opt_matches_protocols).
    pub fn opt_matches_interfaces(subject: Option<&Self>, interfaces: &[String]) -> bool {
        interfaces.is_empty() || subject.map_or(true, |s| s.matches_interfaces(interfaces))
    }
}

/// Runtime-tier extension that owns the per-profile *storage* of a
/// [`BoxedLinkDriver`]. A session-tier trait (rather than a method on
/// `wz_runtime_core::Runtime`) because `BoxedLinkDriver` lives in
/// `wz-session-core` — putting `LinkSink` on the lower `Runtime` trait
/// would invert the dependency direction (runtime-core would have to
/// know the session link seam). The split mirrors `Runtime::Mutex`:
/// the runtime owns the concrete type of a concurrency-model-dependent
/// piece of storage, exposing only the operations generic-`R` code
/// needs.
///
/// `SessionLinkActions<R: SessionRuntime, T>` stores its driver as one
/// `R::LinkSink` field and reaches the write seam through
/// [`Self::link_driver`]; no third generic `D: BoxedLinkDriver` is
/// introduced, so the `<R, T>` arity the rest of the session API uses
/// stays stable. The `LinkSink: Clone` bound lets both profiles share
/// the driver by refcount clone (tokio `Arc`, MCU `Rc`).
// `Sized` supertrait: the `ActionsHandle` GAT names `SessionLinkActions<Self,
// T>`, whose `R` parameter is `Sized` by the struct's implicit bound, so
// `Self` must be `Sized` here. Every runtime is a concrete `Send + Sync +
// 'static` value (no `dyn SessionRuntime` exists), so this is a no-op on the
// impls while letting generic-`R` session code embed `Self` in the bundle type.
pub trait SessionRuntime: Runtime + Sized {
    /// Per-profile owning handle to the link write seam. Tokio binds
    /// `Arc<dyn BoxedLinkDriver + Send + Sync>` (shared across worker
    /// threads); the lwIP MCU profile binds `Rc<dyn BoxedLinkDriver>`
    /// (`!Send`, single-task drive loop). `Clone` is the shared-by-
    /// refcount contract both profiles satisfy.
    type LinkSink: Clone;

    /// R311y205 (transport-multilink IMPL-2b-i) — a per-profile shareable
    /// pointer to an arbitrary owned value `U`: `Arc<U>` on the tokio AP
    /// profile (atomic refcount, `Send + Sync` when `U` is), `Rc<U>` on the
    /// single-task lwIP MCU profile (plain loads / stores, ARMv6-M-safe). The
    /// multilink aggregation core holds its shared session kernel behind this
    /// (`SessionLinkActions::core: R::Shared<SessionCore>`) so N physical links
    /// can share ONE [`SessionCore`] (the SN / rx-SN / identity kernel) while
    /// each keeps its own [`LinkState`] — the wz mirror of zenoh's
    /// `TransportUnicastUniversal` (one shared `priority_tx`/`rx` Arc + a
    /// per-link `links` collection). The same per-profile pointer split as
    /// [`ActionsHandle`](Self::ActionsHandle) and [`LinkSink`](Self::LinkSink):
    /// each profile carries exactly the auto-traits + refcount discipline its
    /// concurrency model needs — no atomics the MCU never uses. At N=1 (every
    /// build today) it is a refcount-1 pointer, behavior-identical to embedding
    /// `U` by value.
    ///
    /// The `Deref` bound lets generic-`R` code reach `&U` through the opaque
    /// pointer without naming `Arc` / `Rc`; `Clone` is the share-by-refcount
    /// contract the aggregation join ([`add_link`]) uses to place one link's
    /// [`LinkState`] both in its own binding and in the shared core's link set.
    ///
    /// [`SessionCore`]: crate::session_actions::SessionCore
    /// [`LinkState`]: crate::session_actions::LinkState
    /// [`add_link`]: crate::session_actions::SessionCore
    type Shared<U>: Clone + core::ops::Deref<Target = U>;

    /// R2708 (open-debt item 785) — WORK THIS SESSION OWES ITS DRIVE LOOP EVERY
    /// ITERATION, as a per-profile opaque value this kernel never looks inside.
    ///
    /// # The defect this closes, and why it lands HERE
    ///
    /// A buffered subscription applies backpressure by making the loop WAIT,
    /// because waiting is what stops the loop reading the link, which is what
    /// closes the peer's window. Until this existed, the only way to reach that
    /// await was `LoopStages::after_dispatch`, supplied by the HOST — and
    /// `drive_session_until_terminal`, the entry 289 of 308 call sites use,
    /// defaults it to a no-op. So delivery under backpressure depended on
    /// whether an embedder had wired something, and a hosted lane went red over
    /// exactly that (R2705).
    ///
    /// The repair had to put the knowledge where the DECISION is. The loop
    /// decides whether to read; the only thing it holds that means "this
    /// session" is [`SessionLinkActions`], whose `core` is this kernel. So the
    /// session's per-iteration work hangs here, and the loop reaches it without
    /// the host's help.
    ///
    /// [`SessionLinkActions`]: crate::session_actions::SessionLinkActions
    ///
    /// # Why an ASSOCIATED TYPE and not a field this crate can name
    ///
    /// Because this crate must not learn what a future is. The work the tokio
    /// profile owes its loop is an `async` drain; `wz-session-core` is `no_std`
    /// and carries ZERO boxed futures today, and the lwIP MCU profile — which
    /// has no executor at all — links it. An associated type keeps the shape
    /// exactly where it belongs: each profile names its own, this crate names
    /// none, and the MCU binds `()` and pays nothing (a zero-sized field).
    ///
    /// That is not a new idea here; it is the idiom [`LinkSink`](Self::LinkSink)
    /// and [`Shared`](Self::Shared) already are. `Default` is the only bound
    /// because the kernel's one interaction with the value is CREATING an empty
    /// one; everything else is the owning profile's business.
    type IterationWork: Default;

    /// Wrap an owned value in the per-profile [`Shared`](Self::Shared) pointer
    /// (tokio `Arc::new`, lwIP `Rc::new`). Generic-`R` code (the
    /// [`SessionLinkActions`] constructor + the multilink join) shares a
    /// `SessionCore` / `LinkState` through this without naming the concrete
    /// pointer type.
    ///
    /// [`SessionLinkActions`]: crate::session_actions::SessionLinkActions
    fn share<U>(value: U) -> Self::Shared<U>;

    /// Per-profile shared handle to the [`SessionLinkActions`] bundle one
    /// logical FSM instance drives. The tokio AP profile binds
    /// `Arc<SessionLinkActions<Self, T>>` because the handle is cloned into
    /// spawned query / reply tasks the multi-thread runtime may move across
    /// worker threads (`Send + Sync` required); the single-task lwIP MCU
    /// profile binds `Rc<SessionLinkActions<Self, T>>` — its sync drive loop
    /// shares the bundle only with the FSM action binding within that one
    /// task, so an atomic refcount is pure waste *and* a hard portability
    /// wall: `alloc::sync::Arc` needs `target_has_atomic = "ptr"`, absent on
    /// ARMv6-M (Cortex-M0/M0+), whereas `Rc` lowers to plain loads / stores
    /// and composes on every MCU target. Mirrors the [`LinkSink`] per-
    /// profile-pointer split: each profile carries exactly the auto-traits +
    /// refcount discipline its concurrency model needs — no `unsafe`, no
    /// atomics the model never uses.
    ///
    /// A generic associated type over `T: TimeSource` because the bundle is
    /// parameterised by the monotonic clock the handle cannot itself fix.
    /// The `Deref` bound lets generic-`R` code (the
    /// [`SessionActionsBinding`](crate::session_actions::SessionActionsBinding)
    /// action methods, [`new_session_engine`](crate::drive::new_session_engine))
    /// reach the bundle through the opaque handle without naming `Arc` / `Rc`.
    ///
    /// [`LinkSink`]: SessionRuntime::LinkSink
    #[cfg(all(feature = "alloc", feature = "session-unicast"))]
    type ActionsHandle<T: TimeSource>: Clone + Deref<Target = SessionLinkActions<Self, T>>;

    /// Wrap an owned [`SessionLinkActions`] bundle in the per-profile shared
    /// handle (tokio `Arc::new`, lwIP `Rc::new`). The sole construction seam
    /// [`SessionLinkActions::new_generic`](crate::session_actions::SessionLinkActions::new_generic)
    /// routes through this so generic-`R` code never names the concrete
    /// pointer type.
    #[cfg(all(feature = "alloc", feature = "session-unicast"))]
    fn wrap_actions<T: TimeSource>(actions: SessionLinkActions<Self, T>) -> Self::ActionsHandle<T>;

    /// Erase the per-profile refcount wrapper to the pure
    /// `&dyn BoxedLinkDriver` the action methods send through. The
    /// tokio impl is `&**sink` (dropping the `+ Send + Sync` auto
    /// traits is an allowed reference coercion); the MCU impl is the
    /// analogous `&**sink` over `Rc`.
    fn link_driver(sink: &Self::LinkSink) -> &dyn BoxedLinkDriver;
}

/// Outbound payload to send over a link. The R51 baseline carries
/// raw bytes; future rounds extend to typed frames (carrying codec
/// metadata for re-encoding on the link side without copy).
pub struct TxFrame<'a> {
    pub bytes: &'a [u8],
}

/// Inbound frame received from a link. R51 baseline: owned `Vec<u8>`.
/// Future rounds (per docs/runtime-crate-tokio.md §2.3) will switch
/// this to a pool-slot borrow `RxFrame<'pool>` for zero-copy decode.
#[derive(Debug)]
pub struct RxFrame {
    pub bytes: Vec<u8>,
    /// The datagram SOURCE address, when the link is a shared medium that
    /// needs per-message attribution. `None` on point-to-point links
    /// (unicast TCP/UDP — one peer per socket, so the source is implicit);
    /// `Some` on a MULTICAST link, where the group carries traffic from
    /// many peers and inbound Frame / KeepAlive / Close (which do NOT carry
    /// the sender zid on the wire) are attributed to a peer by their source
    /// address — the zenoh-pico multicast model (`_z_find_peer_entry(addr)`,
    /// the peer found by `_remote_addr`). Round C/H.
    pub src: Option<core::net::SocketAddr>,
}

impl RxFrame {
    /// A point-to-point inbound frame (no source attribution needed — the
    /// link has one implicit peer). The common case for unicast links.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, src: None }
    }

    /// A shared-medium (multicast) inbound frame carrying its datagram
    /// source address for per-peer attribution.
    pub fn with_src(bytes: Vec<u8>, src: core::net::SocketAddr) -> Self {
        Self {
            bytes,
            src: Some(src),
        }
    }
}

/// Single event source surfaced by a link driver. R51 baseline
/// emits only Ready / Rx / Lost; backpressure + framing_error +
/// tx_drained land when their consumers (codec-level decoder +
/// session FSM) are wired.
#[derive(Debug)]
pub enum LinkEvent {
    Ready,
    Rx(RxFrame),
    Lost { cause: LostCause },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostCause {
    PeerClosed,
    Timeout,
    OsError,
    /// R2608 — `close_link_on_expiration` tore this link down because the
    /// PEER'S CERTIFICATE CHAIN reached its earliest `not_after`, not because
    /// anything went wrong on the wire.
    ///
    /// A variant rather than a reuse of [`Self::Timeout`]: that one already
    /// means "the peer went quiet for too long", and a certificate deadline is
    /// a different fact about a healthy link. Folding the two together is the
    /// one-word-two-meanings shape this workspace keeps paying for, and it
    /// would make a log unreadable exactly where an operator is asking WHY a
    /// working session dropped.
    ///
    /// DERIVED as cheap before it was added: nothing in this workspace BRANCHES
    /// on a `LostCause`. The session FSM's only cause-match is over
    /// `LinkDropCause`, a different enum, so this variant is diagnostic and
    /// costs no arm anywhere.
    ///
    /// ⚠ The quic link does NOT report this yet: it closes the `quinn::Connection`
    /// and quinn maps that to `NotConnected`, which surfaces as
    /// [`Self::OsError`] — the divergence R2600 named and this round does not
    /// retire.
    CertificateExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2650 — [`InterceptorLink::ALL`] is COMPLETE, and the compiler is what
    /// says so rather than this test's own reading.
    ///
    /// The match below is exhaustive by construction, so adding a variant stops
    /// this test COMPILING. That is the whole mechanism: a hand-written list is
    /// trustworthy only when something forces a look at it, and a test that
    /// merely counted would go stale silently the moment the count was updated
    /// without the list.
    #[test]
    fn every_link_variant_is_listed_in_all() {
        fn _adding_a_variant_must_not_compile_until_all_is_updated(link: InterceptorLink) {
            match link {
                InterceptorLink::Tcp
                | InterceptorLink::Udp
                | InterceptorLink::Tls
                | InterceptorLink::Quic
                | InterceptorLink::Serial
                | InterceptorLink::Unixpipe
                | InterceptorLink::UnixsockStream
                | InterceptorLink::Vsock
                | InterceptorLink::Ws => {}
            }
        }
        // R2794 — 10 -> 9: exactly upstream's set, which has no `QuicDatagram`.
        assert_eq!(
            InterceptorLink::ALL.len(),
            9,
            "a variant was added: list it in ALL and move this count"
        );

        // The inverse is an inverse over the WHOLE list, not over a sample.
        for link in InterceptorLink::ALL {
            assert_eq!(
                InterceptorLink::from_upstream_str(link.as_str()),
                Some(*link),
                "`{}` must round-trip through the one table",
                link.as_str()
            );
        }
        // And it REFUSES what upstream refuses: this axis deserializes into an
        // enum there, so an unknown protocol is a parse error, not a shrug.
        assert_eq!(InterceptorLink::from_upstream_str("carrier-pigeon"), None);
        // The kebab-case spellings are upstream's, not wz's locator grammar.
        assert_eq!(
            InterceptorLink::from_upstream_str("unixsock-stream"),
            Some(InterceptorLink::UnixsockStream)
        );
        // R2794 — and `quic-datagram` is one of the things upstream refuses: its
        // enum has no such value, so a rule naming it does not parse there. wz
        // accepted it while it carried the value, which let a config through
        // that zenohd rejects. `from_config_str` is the same search, so it must
        // refuse it too.
        assert_eq!(InterceptorLink::from_upstream_str("quic-datagram"), None);
        assert_eq!(InterceptorLink::from_config_str("quic-datagram"), None);
    }

    /// R2794 (open-debt item 814) — [`LinkKind::ALL`] is complete, every kind
    /// names a protocol a rule can write, and the one kind that differs from its
    /// protocol keeps its OWN answers.
    ///
    /// The last property is the one the split exists for. The datagram kind is
    /// `quic` to a rule, so a `quic` rule governs it, and yet it must still
    /// report itself unstreamed and best-effort to zenoh-c. A single value
    /// could not hold both, which is why a one-line fix that set the datagram
    /// link's protocol to `Quic` would have closed the ACL bypass and opened a
    /// C-ABI regression in the same stroke.
    #[test]
    fn every_link_kind_is_listed_in_all_and_maps_to_a_rule_protocol() {
        fn _adding_a_kind_must_not_compile_until_all_is_updated(kind: LinkKind) {
            match kind {
                LinkKind::Tcp
                | LinkKind::Udp
                | LinkKind::UdpReliable
                | LinkKind::Tls
                | LinkKind::Quic
                | LinkKind::QuicDatagram
                | LinkKind::Serial
                | LinkKind::Unixpipe
                | LinkKind::UnixsockStream
                | LinkKind::Vsock
                | LinkKind::Ws => {}
            }
        }
        assert_eq!(
            LinkKind::ALL.len(),
            11,
            "a kind was added: list it in ALL and move this count"
        );

        // Every kind's protocol is a value a rule can actually name.
        for kind in LinkKind::ALL {
            assert!(
                InterceptorLink::ALL.contains(&kind.interceptor_protocol()),
                "{kind:?} maps to a protocol outside the rule vocabulary"
            );
        }
        // And every protocol a rule can name reaches at least one kind -- a
        // protocol no link could ever present would be a rule that can only
        // ever match a subject that names nothing.
        for protocol in InterceptorLink::ALL {
            assert!(
                LinkKind::ALL
                    .iter()
                    .any(|k| k.interceptor_protocol() == *protocol),
                "no link kind presents `{}` to a rule",
                protocol.as_str()
            );
        }

        // THE PAIR: `quic` to a rule, datagram to itself.
        assert_eq!(
            LinkKind::QuicDatagram.interceptor_protocol(),
            InterceptorLink::Quic,
            "upstream files its QUIC datagram link under `quic`"
        );
        assert!(!LinkKind::QuicDatagram.is_streamed());
        assert!(!LinkKind::QuicDatagram.is_reliable());
        assert_eq!(
            LinkKind::QuicDatagram.locator_for("127.0.0.1:7447"),
            "quic/127.0.0.1:7447?rel=0",
            "the datagram kind advertises the `rel=0` marker a foreign peer dials"
        );
        // Its sibling shares the protocol and NOT the kind answers, which is
        // exactly what one enum could not say.
        assert_eq!(LinkKind::Quic.interceptor_protocol(), InterceptorLink::Quic);
        assert!(LinkKind::Quic.is_streamed());
        assert!(LinkKind::Quic.is_reliable());

        // R2810 — THE SECOND PAIR, the mirror image of the first: `udp` to a
        // rule, and streamed AND reliable to itself -- the one upstream link
        // whose streamed answer depends on its variant. A `udp` deny rule must
        // govern it, and zenoh-c must still be told it is a reliable stream.
        assert_eq!(
            LinkKind::UdpReliable.interceptor_protocol(),
            InterceptorLink::Udp,
            "upstream files every variant of its udp link under `udp`"
        );
        assert!(LinkKind::UdpReliable.is_streamed());
        assert!(LinkKind::UdpReliable.is_reliable());
        assert_eq!(
            LinkKind::UdpReliable.locator_for("127.0.0.1:7447"),
            "udp/127.0.0.1:7447?rel=1",
            "without `rel=1` a foreign peer dials the datagram link"
        );
        assert!(!LinkKind::Udp.is_streamed());
        assert!(!LinkKind::Udp.is_reliable());
        let reliable_udp = LinkSubject {
            kind: Some(LinkKind::UdpReliable),
            ..LinkSubject::UNKNOWN
        };
        assert!(reliable_udp.matches_protocols(&[InterceptorLink::Udp]));
        assert!(!reliable_udp.matches_protocols(&[InterceptorLink::Quic]));

        // And a subject derives its protocol from its kind, never alongside it.
        let subject = LinkSubject {
            kind: Some(LinkKind::QuicDatagram),
            ..LinkSubject::UNKNOWN
        };
        assert_eq!(subject.protocol(), Some(InterceptorLink::Quic));
        assert!(subject.matches_protocols(&[InterceptorLink::Quic]));
        assert!(!subject.matches_protocols(&[InterceptorLink::Udp]));
    }
}
