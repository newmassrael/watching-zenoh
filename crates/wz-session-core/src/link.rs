// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
