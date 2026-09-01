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
/// R311y453 — which LINK PROTOCOL a transport speaks: the wz mirror of zenoh's
/// `InterceptorLink` (`zenoh-config/src/lib.rs:317-327`), and the vocabulary of
/// the §5.16 `link_protocols` subject axis.
///
/// Deliberately NOT [`crate::locator::Proto`], which was the first thing tried
/// and does not fit: `Proto` is the IP-locator scheme set (Tcp / Udp / Tls / Ws /
/// Quic / QuicDatagram), because serial, unixsock, unixpipe and vsock locators
/// are not `SocketAddr`-based and carry their own parsed types. The subject axis
/// has to name every link a face can arrive on, so it needs the wider set.
///
/// SUPERSET of upstream, in one place and on purpose: zenoh has no
/// [`QuicDatagram`](Self::QuicDatagram) because it has no such transport; wz does
/// (`transport-link-quic-datagram`), and a subject axis that could not name a
/// link wz can actually accept would be a hole, not fidelity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorLink {
    /// `tcp/...` — the TCP stream link.
    Tcp,
    /// `udp/...` — the UDP datagram link.
    Udp,
    /// `tls/...` — TLS over TCP.
    Tls,
    /// `quic/...` — QUIC, batch over one bidirectional stream.
    Quic,
    /// `quic-datagram/...` — QUIC unreliable datagrams (RFC9221). wz-only; zenoh's
    /// `InterceptorLink` has no counterpart.
    QuicDatagram,
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
            InterceptorLink::QuicDatagram => "quic-datagram",
            InterceptorLink::Serial => "serial",
            InterceptorLink::Unixpipe => "unixpipe",
            InterceptorLink::UnixsockStream => "unixsock-stream",
            InterceptorLink::Vsock => "vsock",
            InterceptorLink::Ws => "ws",
        }
    }

    /// R2259 (open-debt item 593) — whether this protocol carries a BYTE STREAM
    /// rather than framed datagrams, which is what zenoh-c's `z_link_is_streamed`
    /// reports and what wz's own framing already branches on.
    ///
    /// Derived from the protocol rather than recorded per link, because it IS a
    /// property of the protocol: every wz link of a given scheme frames the same
    /// way. The two datagram schemes are the ones whose drivers deliver a whole
    /// batch per receive — `udp` and the RFC9221 `quic-datagram` — and every
    /// other one hands the session an unframed stream that COBS, a length prefix
    /// or a WebSocket message boundary re-frames.
    ///
    /// ⚠ `Ws` is STREAMED here even though a WebSocket delivers discrete BINARY
    /// messages, and that is upstream's classification rather than a slip: zenoh
    /// builds its ws link on `LinkUnicastTrait` with `is_streamed() == true`
    /// (`io/zenoh-link-ws/src/unicast.rs`), because the transport layer above it
    /// must still prefix each batch with its length.
    pub fn is_streamed(&self) -> bool {
        !matches!(self, InterceptorLink::Udp | InterceptorLink::QuicDatagram)
    }

    /// R2259 (open-debt item 593) — whether this protocol delivers RELIABLY,
    /// the input to zenoh-c's `z_link_reliability`.
    ///
    /// The same two datagram schemes are the unreliable ones, and for the same
    /// reason they are unstreamed: neither retransmits. They are nevertheless
    /// two questions rather than one — a protocol could frame and still not
    /// retransmit — so this is written as its own match instead of delegating to
    /// [`is_streamed`](Self::is_streamed), which would make the coincidence look
    /// like a definition.
    pub fn is_reliable(&self) -> bool {
        !matches!(self, InterceptorLink::Udp | InterceptorLink::QuicDatagram)
    }

    /// R311y473 — the DIALABLE LOCATOR for this protocol at `address`: the string
    /// a foreign peer has to be able to parse and connect to.
    ///
    /// Deliberately NOT [`as_str`](Self::as_str). That is a CONFIG spelling, and
    /// two of these ten differ between the two roles — `quic-datagram` is a
    /// wz-only word (zenoh gives both its QUIC links the `quic` scheme and selects
    /// with the `rel` metadata key, `io/zenoh-link/src/lib.rs:165-171`), and
    /// `unixsock-stream` happens to coincide only because the config spelling was
    /// already written as the scheme. R311y470 shipped a round fixing exactly this
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
            InterceptorLink::Tcp => format!("tcp/{address}"),
            InterceptorLink::Udp => format!("udp/{address}"),
            InterceptorLink::Tls => format!("tls/{address}"),
            InterceptorLink::Quic => format!("quic/{address}"),
            InterceptorLink::QuicDatagram => format!("quic/{address}?rel=0"),
            InterceptorLink::Serial => format!("serial/{address}"),
            InterceptorLink::Unixpipe => format!("unixpipe/{address}"),
            InterceptorLink::UnixsockStream => format!("unixsock-stream/{address}"),
            InterceptorLink::Vsock => format!("vsock/{address}"),
            InterceptorLink::Ws => format!("ws/{address}"),
        }
    }

    /// Parse a config spelling back, or `None` for an unknown name. The inverse of
    /// [`as_str`](Self::as_str), kept beside it so the two cannot drift; every
    /// config surface (the demo knobs today, a `deploy.yaml` loader later) parses
    /// through this one function rather than growing its own table.
    pub fn from_config_str(s: &str) -> Option<Self> {
        [
            InterceptorLink::Tcp,
            InterceptorLink::Udp,
            InterceptorLink::Tls,
            InterceptorLink::Quic,
            InterceptorLink::QuicDatagram,
            InterceptorLink::Serial,
            InterceptorLink::Unixpipe,
            InterceptorLink::UnixsockStream,
            InterceptorLink::Vsock,
            InterceptorLink::Ws,
        ]
        .into_iter()
        .find(|link| link.as_str() == s)
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

pub trait BoxedLinkDriver {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability);
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
/// (`interceptor/authorization.rs:39-46`), which wz does not resolve yet. Those
/// land as fields here, not as a fourth trait method and a fourth constructor
/// parameter on six pipelines.
///
/// Every field is an [`Option`], and the distinction is load-bearing — see
/// [`interfaces`](Self::interfaces).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkSubject {
    /// Which link protocol the transport speaks, or `None` when the driver
    /// cannot say (a test double). A rule narrowed by `link_protocols` treats
    /// `None` as MATCHING — see the fail-closed note below.
    pub protocol: Option<InterceptorLink>,
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
}

impl LinkSubject {
    /// A subject nothing is known about — every axis indeterminate. What a
    /// driver with no transport identity reports, and the value a
    /// [`BoxedLinkDriver::link_subject`] of `None` is equivalent to.
    pub const UNKNOWN: Self = Self {
        protocol: None,
        interfaces: None,
    };

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
        match self.protocol {
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
}
