// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qa / qg — multi-peer face loop: the `routing-router` and `routing-peer`
//! foundations.
//!
//! [`accept_loop`] is the accept-only entry (the `routing-router` foundation);
//! [`peer_loop`] (R311qg, `routing-peer`) generalises it to a node that also
//! DIALS a configured peer set, holding the dialed and accepted faces in one
//! set. Both delegate to the shared [`face_drive_loop`] core, differing only in
//! their [`FaceSources`] (accept-only vs accept + dial).
//!
//! The single-peer session-open path ([`crate::session_open::accept_endpoint`]
//! -> [`accept_locator`](crate::session_open::accept_locator) ->
//! [`accept_tcp`](crate::link_pipeline::accept_tcp)) binds, accepts ONE peer,
//! and hands back one [`OpenedSession`]. A router/peer node instead binds ONCE
//! and *holds N concurrent peer sessions* — it loops `accept`, brings each
//! accepted link up to Established, and keeps every face driven until the peer
//! closes or the node shuts down. This module is that loop: the smallest
//! increment of `routing-router` (the catalog keystone, §5.15 / inventory
//! `routing-router`), with **no forwarding** between faces yet (that is the
//! sibling `routing-routes` atom).
//!
//! ## zenoh anchor
//!
//! - The accept loop mirrors zenoh's per-listener `accept_task`
//!   (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` `accept_task`): a task that
//!   `select!`s a cancellation token against `accept()` and registers each new
//!   link with the transport manager. The accept is **role-agnostic** — zenoh
//!   accepts every inbound link regardless of `WhatAmI`
//!   (`commons/zenoh-protocol/src/core/whatami.rs` Router/Peer/Client); role
//!   behaviour lives entirely in the routing layer, not the accept seam. So this
//!   loop carries no role flag: a held face is a held face.
//! - The live faces table mirrors zenoh's hold maps — the transport manager's
//!   `transports: HashMap<ZenohIdProto, Arc<dyn TransportUnicastTrait>>`
//!   (`io/zenoh-transport/src/unicast/manager.rs`) and the routing dispatcher's
//!   `tables.faces: HashMap<usize, Arc<FaceState>>`
//!   (`zenoh/src/net/routing/dispatcher/tables.rs`). Here it is a
//!   [`FaceId`]-keyed map of peer addresses; zid-keyed dedup and per-face
//!   routing state arrive when forwarding (`routing-routes`) needs them.
//!
//! ## Why a single-task `FuturesUnordered`, not spawned tasks
//!
//! The session drive future is **not `Send`** — the SCE `Engine` it drives owns
//! bare `Box<dyn FnMut()>` callback fields (`completion_callback` / `on_http_send`,
//! sce-rust-runtime `engine.rs:360,368`, with no `+ Send` bound), so the engine
//! and any future borrowing it are `!Send`. (The outbound sink itself IS `Send`
//! — an `mpsc::UnboundedSender<Vec<u8>>` in `StreamWriteDriver`; the `RefCell`-
//! backed sink in `session_glue` is the lwIP/MCU `LocalSwappableLink` twin, NOT
//! this tokio path.) A `tokio::spawn` / `JoinSet` per face is therefore
//! impossible. Instead every face's open future and drive future live in two
//! [`FuturesUnordered`] sets polled on this one task, so N peers are held
//! concurrently with no `Send` bound and no inter-task races — the same
//! single-task concurrency the loopback open tests get from `tokio::join!`,
//! generalised to a dynamic, unbounded set. (The internal `writer_task`s *are*
//! `Send` and still run on the worker pool.)
//!
//! ## NON-goals (this atom)
//!
//! Forwarding between faces (`routing-routes`), routing tables / resource tree /
//! HAT, gossip discovery (`scouting-gossip`), failover / static routes, zid-keyed
//! face dedup, and per-face graceful Close-frame teardown on shutdown (the demo
//! R292 drain chain composes per face later). Shutdown here stops accepting and
//! drops in-flight faces (their sockets close; the detached writer tasks drain).

use std::collections::BTreeMap;
use std::future::Future;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
// `PushOwned` is the multicast INGRESS fold payload (the deferred `mcast_faces`
// plane); gated on `codec-push` (which provides it) so the accept-only foundation
// (`routing-accept` without `codec-push`, run-ci Layer C1w) stays minimal.
#[cfg(feature = "codec-push")]
use wz_codecs::push::PushOwned;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::net::TcpStream;
use wz_runtime_core::TimeSource;

use crate::runtime_impl::TokioTime;
use crate::session_glue::{
    drive_session_until_terminal_with_extra_deadline, DriverOutcome, ExtraDeadline, IterationEvent,
    SessionInitParams, SessionLinkActions, SessionTimeouts,
};
// R311y296 — the plain (no-extra-deadline) drive is now reached only by the
// aggregated-secondary-link path and this module's own tests. `drive_face` —
// the registered-face path, and the only one a `FaceForwarder` hook can key on
// — threads `next_extra_deadline_ms` instead. A JOINED link is deliberately
// left on the plain drive: it shares the primary's session (and so its pending
// table), is never `register`ed as its own face, and the forwarder maps its
// events back to the primary via `register_joined` — so it has no per-face
// deadline of its own to arm, and the primary's drive already arms that
// session's.
#[cfg(any(test, feature = "transport-multilink"))]
use crate::session_glue::drive_session_until_terminal;
use crate::session_open::{
    accept_and_open_session, initiate_and_open_session, AcceptedLink, AcceptedPeer, BoundListener,
    DialedLink, OpenError, OpenedSession,
};
use wz_session_core::locator::{parse_locator, Proto};

// R311y205 (transport-multilink) — the aggregation seam wired into the live
// accept/dial path: when `WzConfig.max_links > 1` a face is opened via the
// `_with_multilink` establishment variants (so the 0x4 ext negotiates + the peer
// ephemeral pubkey is captured), and a SECOND+ physical link to an already-held
// peer zid is aggregated onto the first's shared `SessionCore` via
// [`join_link`] instead of registering a redundant face. Every symbol here is
// feature-gated, so a non-multilink build compiles the accept loop UNCHANGED.
#[cfg(feature = "transport-multilink")]
use crate::config::LinkReliabilityPref;
#[cfg(feature = "transport-multilink")]
use crate::multilink::{join_link, JoinOutcome};
// R311y219 (transport-multilink + transport-qos) — the per-face QoS-priority band
// the loop tags each aggregated link with. `Priority` is unconditional (no feature
// gate), so the band tuple `(Priority, Priority)` threads through the multilink
// open path with NO per-call-site cfg branch (the y218 `qos: bool` discipline); it
// is only APPLIED under `transport-qos`, where the `_with_multilink` entrypoints
// map it to the `all(multilink,qos)`-gated `set_link_priority_range`.
#[cfg(feature = "transport-multilink")]
use crate::session_open::{
    accept_and_open_session_with_multilink, initiate_and_open_session_with_multilink,
};
#[cfg(feature = "transport-multilink")]
use std::collections::BTreeSet;
// R311y227 — also the multicast INGRESS band (McastIngressItem.priority +
// route_mcast_ingress), which is `codec-push`-gated, not multilink.
#[cfg(any(feature = "transport-multilink", feature = "codec-push"))]
use wz_session_core::qos::Priority;

/// Backoff applied after an `accept()` error before re-arming the accept —
/// zenoh's `TCP_ACCEPT_THROTTLE_TIME` (100ms, `io/zenoh-links/zenoh-link-tcp/src/
/// lib.rs`). The dominant accept-error cause is fd exhaustion (EMFILE/ENFILE):
/// the pending connection stays in the kernel queue, so an un-throttled re-arm
/// returns the same error immediately and hot-spins the task at full CPU until a
/// fd frees (which it cannot while the loop monopolises the task). The sleep both
/// yields (letting a fd free / shutdown win the next `select!`) and matches the
/// upstream constant.
const ACCEPT_ERROR_THROTTLE_MS: u64 = 100;

/// Monotonic identifier the accept loop assigns to each accepted peer, in
/// accept order — zenoh's `face_counter` (`tables.faces` key). Stable for the
/// lifetime of the face; not reused after the face leaves the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaceId(pub u64);

/// A held peer link: its [`FaceId`], the accepted-peer transport tag, and the
/// remote peer's zid (R311qi — the routing identity a peer-mesh graph keys faces
/// on, read from the [`OpenedSession`] at `FaceUp`; `None` if the handshake did
/// not surface it). Not `Copy` because the zid is an owned `Vec<u8>`.
///
/// `peer` is an [`AcceptedPeer`] (Slice B), NOT a bare `SocketAddr`: a mesh face
/// can now be a non-IP peer (unixsock / vsock — [`AcceptedPeer::NonIp`]) whose
/// identity is the handshake zid, not a transport address. The loop NEVER reads
/// `peer` for routing / dedup / locator logic — it is a log/event tag only
/// (`Display`); the routing identity is `peer_zid`. A DIALED face tags
/// [`AcceptedPeer::Ip`] (a dial target is always IP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Face {
    pub id: FaceId,
    pub peer: AcceptedPeer,
    pub peer_zid: Option<Vec<u8>>,
}

/// A request from the topology forwarder to the accept loop: dial a peer that
/// gossip DISCOVERED and the autoconnect policy admitted. The sync ingest path
/// cannot open an outbound link itself — it is not the async task that owns the
/// in-flight-open [`FuturesUnordered`] — so it hands the loop this intent over an
/// unbounded channel and the loop turns it into a `dial_face` (A5c). The wz
/// analogue of the `(zid, locators)` pair zenoh's gossip passes to
/// `runtime.connect_peer` (`hat/p2p_peer/gossip.rs:455`), minus the per-dial task
/// spawn — wz routes the dial back to its single drive task instead.
///
/// `zid` is the trimmed wire bytes (the SAME representation as [`Face::peer_zid`],
/// not the routing-graph `Zid`) deliberately: it keeps this type — and the
/// channel arm the shared drive loop polls — free of the `routing-peer`-only
/// graph crate, and it is exactly the form the loop's "already hold a face to
/// this peer?" dedup (A5c) compares against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialIntent {
    /// The discovered peer's zid (trimmed wire bytes) — so the loop can skip a
    /// peer it already holds a face to rather than open a redundant second link.
    pub zid: Vec<u8>,
    /// The dial addresses the peer advertised in its link-state (its locators);
    /// the loop (A5c) parses one into a socket address to connect to.
    pub locators: Vec<String>,
}

/// The forwarder's sending end of the dial-intent channel — held inside the
/// [`FaceForwarder`] and written (non-blocking) from the sync ingest path. The
/// channel is UNBOUNDED because the producer is synchronous (mid graph-borrow)
/// and must never await or block on a full queue; discovery is bounded by the
/// mesh size in practice.
pub type DialIntentSender = tokio::sync::mpsc::UnboundedSender<DialIntent>;
/// The accept loop's receiving end, drained in the loop's `select!` (A5c).
pub type DialIntentReceiver = tokio::sync::mpsc::UnboundedReceiver<DialIntent>;

/// A runtime connect-list reconcile request (`router-connect-reconcile`): the NEW
/// full desired outbound connect-set, delivered to [`face_drive_loop`] when the
/// operator changes the connect endpoints at runtime. The wz analogue of zenoh's
/// `update_peers` (`net/runtime/orchestrator.rs:413`), which re-reads
/// `connect().endpoints().get(whatami)` on the config `"connect/endpoints"` change
/// event and, for a Peer/Router, `spawn_peer_connector`s each newly-listed peer it
/// does not already hold a link to. wz carries the resolved TCP `SocketAddr`s (the
/// same numeric-TCP scope as the static [`FaceSources::dial_targets`]); the loop
/// dials each address it is not already dialing (address dedup — a config endpoint
/// has no zid pre-handshake, so the gossip zid dedup [`holds_zid`] cannot apply).
/// ADD-ONLY, faithful to the router branch (`orchestrator.rs:449-467`): a removed
/// endpoint is NOT torn down (the Client close-removed branch `427-448` is
/// deliberately router-inapplicable — closing a live federation face on a
/// static-list edit would blackhole the mesh).
///
/// The sending end lives in the run-mode host (`run_router_hat`), written when the
/// operator affordance fires; the channel is UNBOUNDED (the producer is a sync
/// timer callback that must not await) and reconcile events are rare (operator
/// cadence), so unbounded growth is a non-issue.
pub type ReconcileSender = tokio::sync::mpsc::UnboundedSender<Vec<SocketAddr>>;
/// The accept loop's receiving end of the reconcile channel, drained in the loop's
/// `select!`. `None` when `router-connect-reconcile` is not wired (every non-router
/// loop, and a router built without the feature) — then the arm parks forever and
/// the loop is byte-for-byte the prior behaviour.
pub type ReconcileReceiver = tokio::sync::mpsc::UnboundedReceiver<Vec<SocketAddr>>;

/// Observable lifecycle events the accept loop emits to its caller (the demo
/// logs them; tests count them). The faces table is internal; these events are
/// the observation seam — `FaceUp`/`FaceDown` bracket exactly the interval a
/// face is held.
#[derive(Debug)]
pub enum AcceptEvent {
    /// An accepted peer completed the 4-way handshake; the face is now held in
    /// the live faces table.
    FaceUp(Face),
    /// A held face's session reached a terminal state (peer Close, link loss, or
    /// open-deadline); it has left the faces table.
    FaceDown(Face, DriverOutcome),
    /// An accepted peer never reached Established (handshake failed or timed
    /// out); it never entered the faces table. `peer` is an [`AcceptedPeer`]
    /// (Slice B): a mesh-capable non-IP face whose handshake fails now surfaces
    /// here with [`AcceptedPeer::NonIp`] (rendered `<anonymous unixsock peer>`),
    /// where before Slice B a non-IP peer was rejected pre-open and never reached
    /// this event.
    FaceFailed {
        id: FaceId,
        peer: AcceptedPeer,
        cause: OpenError,
    },
    /// `accept()` itself returned a (typically transient) error; the loop logs
    /// it (via this event), throttles ([`ACCEPT_ERROR_THROTTLE_MS`]), then keeps
    /// accepting — zenoh's `accept_task` parity (log + `TCP_ACCEPT_THROTTLE_TIME`
    /// sleep). Surfaced so the caller can log it rather than the loop swallowing
    /// it.
    AcceptError(io::Error),
    /// R311y213 (transport-multilink) — a second+ physical link was AGGREGATED onto
    /// an EXISTING logical session (the `join_link` success at the multilink
    /// accept/dial site). Distinct from [`FaceUp`](Self::FaceUp), which is a NEW
    /// session's first link: a joined link does NOT enter the faces table nor bump
    /// `established`/`peak_concurrent` (it rides `ml_faces` + the shared core), so
    /// without this event the aggregation is invisible to the loop's `on_event`
    /// consumer — the join success would `continue` before any event fired, leaving
    /// a 2-link session byte-indistinguishable from single-link at the caller's log
    /// level. `live_links` is the session's link count after the join. Present only
    /// under `transport-multilink` (the aggregation path itself is feature-gated).
    #[cfg(feature = "transport-multilink")]
    LinkAggregated {
        peer_zid: Vec<u8>,
        live_links: usize,
    },
}

/// The forwarding seam the [`accept_loop`] threads its held faces through —
/// the data-plane injection point that keeps the loop itself
/// forwarding-AGNOSTIC (its job is accept-and-hold; whether held faces route
/// traffic to each other is this hook's concern). The loop reports three
/// things per face: it entered the live set ([`register`](Self::register),
/// with the face's transport send seam so a forwarder can later send TO it),
/// each inbound iteration event ([`forward`](Self::forward), the per-face
/// `drive_session_until_terminal` observer), and it left the set
/// ([`deregister`](Self::deregister)).
///
/// The hold-only path (the `routing-router` foundation with no `routing-routes`
/// forwarding) passes [`NoOpForwarder`]; the `routing-routes` atom passes a
/// forwarder backed by the [`RouteTable`](wz_session_core::routing::RouteTable)
/// (see [`crate::routing_forward`]). Taken as `&dyn` so the loop carries one
/// concrete future type in its [`FuturesUnordered`] regardless of which
/// forwarder is wired, and `!Send` is fine — the whole loop is single-task.
/// A future routing-peer reuses this same seam.
pub trait FaceForwarder {
    /// A face reached Established and entered the live set. `actions` is its
    /// transport send seam; a forwarder that routes clones it (an `Arc`) so it
    /// can forward TO this face later.
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>);
    /// A held face left the live set (peer Close / link loss). It can no
    /// longer be a forward destination.
    fn deregister(&self, id: FaceId);
    /// One inbound iteration event from the face `id` — the per-face observer
    /// the loop installs on each held session's drive loop. A routing
    /// forwarder inspects it for declarations / Puts to route.
    fn forward(&self, id: FaceId, event: IterationEvent<'_>);

    /// A Push RECEIVED on the multicast INGRESS group (the deferred `mcast_faces`
    /// plane, I1) — folded from the separate multicast drive-loop task into this
    /// forwarder. A routing forwarder routes it as a mcast-sourced Push (delivered
    /// to unicast subscribers, echo-guarded off the groups). Default no-op: only a
    /// forwarder with a multicast ingress plane (the router) implements it.
    #[cfg(feature = "codec-push")]
    fn route_mcast_ingress(&self, _priority: Priority, _reliable: bool, _push: &PushOwned) {}

    /// The on-group ROUTER member set changed (a JOIN admit / lease evict on the
    /// router's multicast group) — the I3b Designated-Router election candidate
    /// set, relayed from the multicast INGRESS loop. Default no-op: only the
    /// router (which runs the ingress loop and holds the group egress) elects a
    /// per-keyexpr DR to keep two group-sharing routers loop-free. `_members`
    /// carries RAW zid bytes (the router override converts them to `Zid`) so this
    /// trait — and the accept loop that relays them — stay free of
    /// `wz-routing-graph`; a `routing-accept` build that never links the routing
    /// graph still compiles.
    fn set_mcast_group_members(&self, _members: &[Vec<u8>]) {}

    /// The on-group SUBSCRIBER keyexpr aggregate changed (a DeclareSubscriber /
    /// UndeclareSubscriber over the router's multicast group, or a lease evict) —
    /// the §5.21 sub plane, relayed from the multicast INGRESS loop as a DEDUPED
    /// literal set. Default no-op: only the router (which runs the ingress loop)
    /// advertises the group's interest into the unicast mesh, so a mesh-side
    /// publisher routes matching Puts toward it and they reach the on-group
    /// subscriber (cross-router reachability). Carries owned `String`s (no codec /
    /// routing-graph type) so this trait and the accept loop stay dependency-free.
    fn set_mcast_group_subs(&self, _subs: &[String]) {}

    /// How often the loop should call [`tick`](Self::tick), or `None` (the
    /// default) to never tick. The extension point for a forwarder with a
    /// time-driven obligation: it returns `Some(period)` and the loop arms a timer.
    /// The linkstate peer returns `Some` — it COALESCES its spanning-tree
    /// recomputes on this cadence (D2c, `linkstate_forward.rs`), debouncing a burst
    /// of topology changes into one compute. The accept-only / hold-only forwarders
    /// have no time-driven work, so they keep the `None` default and the loop arms
    /// no timer. Read ONCE when the loop starts (a fixed cadence, not a per-tick
    /// query).
    fn tick_period(&self) -> Option<Duration> {
        None
    }

    /// R311y296 — when the face `id` next needs its drive loop to wake, as an
    /// ABSOLUTE monotonic-ms deadline on that face's clock epoch, or `None`
    /// (the default) to impose no wake. Polled once per drive iteration and
    /// folded into that face's Established wake `min` (see
    /// [`crate::session_glue::drive_session_until_terminal_with_extra_deadline`]).
    ///
    /// The extension point for a forwarder with a PER-FACE, DATA-DEPENDENT
    /// deadline — the sibling of [`tick_period`](Self::tick_period), and
    /// deliberately not the same seam: `tick_period` is one fixed cadence read
    /// once at loop start, which is a poll. This is a deadline the forwarder
    /// recomputes from its own state, so the loop wakes when there is actually
    /// something due and not before.
    ///
    /// `wz-capi-pico` is the consumer: it returns its face's earliest pending
    /// `z_get` deadline ([`crate::session::Session::next_reply_deadline_ms`]),
    /// because its C reply closures may only be fired from the drive thread and
    /// so its timeout sweep cannot live in a task of its own. Without the hook
    /// the sweep would run on the keepalive cadence (~3333 ms for a 10 s lease),
    /// making a `timeout_ms = 100` get 33x late.
    ///
    /// Runs on the loop's single task with the same borrow discipline as the
    /// other hooks (no `RefCell` held across an `.await`).
    fn next_extra_deadline_ms(&self, _id: FaceId) -> Option<u64> {
        None
    }

    /// R311y296 — the signal that face `id`'s
    /// [`next_extra_deadline_ms`](Self::next_extra_deadline_ms) may have
    /// CHANGED, so its drive loop should re-arm. `None` (the default) means the
    /// forwarder's deadline never changes asynchronously and the loop need
    /// never be woken to re-read it.
    ///
    /// This is the half that is easy to omit and impossible to work around: the
    /// deadline is only READ when the loop arms its wake, and the loop is
    /// normally parked in `select!` on the PREVIOUS wake — up to a keepalive
    /// period (~3333 ms) away. A `z_get` issued from the C application thread
    /// while the loop is parked would therefore not be seen until that old wake
    /// fired, which is exactly the lateness the deadline exists to remove. The
    /// forwarder notifies; the loop re-iterates and re-arms.
    ///
    /// An `Arc` rather than a borrow because a forwarder builds it per face
    /// (the C session's registry owns one per face) rather than holding it as a
    /// field. Signal with `notify_one`, not `notify_waiters` — see
    /// [`crate::session_glue::ExtraDeadline`].
    fn deadline_revised(&self, _id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        None
    }

    /// The periodic timer fired (cadence from [`tick_period`](Self::tick_period)).
    /// The forwarder's hook for time-driven work that is the FORWARDER's own
    /// obligation, not a caller policy. Putting it on the seam (rather than in a
    /// caller's hand-rolled `select!`) is what makes EVERY `peer_loop` caller share
    /// the behaviour, not only the demo. Default no-op; only a forwarder that
    /// returned `Some` from [`tick_period`](Self::tick_period) is ever ticked — the
    /// linkstate peer does, to flush a coalesced recompute (D2c). Runs on the
    /// loop's single task with the same borrow discipline as the other hooks (no
    /// `RefCell` held across an `.await`).
    fn tick(&self) {}

    /// Whether this forwarder requires AT MOST ONE held face per peer zid, so the
    /// loop drops a second face that establishes to an already-held zid (the wz
    /// analog of zenoh's transport manager `init_transport_unicast` keeping one
    /// transport per zid). A forwarder that keys ROUTING STATE on the peer zid
    /// returns `true`: the linkstate peer's topology graph keys the self-edge on
    /// zid, so two faces to one zid would let one face's teardown `remove_link`
    /// (also keyed on zid) prune the still-live peer. A FaceId-keyed forwarder
    /// (the star router) or a hold-only one returns the default `false` — it holds
    /// N faces regardless of zid, so the loop must not drop a legitimate second
    /// face (e.g. two clients that happen to share a fixture zid). Read per
    /// face-up; cheap.
    fn dedups_faces_by_zid(&self) -> bool {
        false
    }

    /// R311y219b (transport-multilink) — a SECOND+ physical link aggregated onto a
    /// peer's logical session (`join_link`) is NOT `register`ed as its own face (it
    /// shares the primary's), so its inbound events reach [`forward`](Self::forward)
    /// tagged with the JOINED link's own [`FaceId`] — which is not in the routing
    /// forwarder's face table. Without a mapping back to the PRIMARY registered face,
    /// the routing forwarder drops the joined link's data/control at its
    /// `faces.get(inbound)` delivery gate (the joined-face delivery gap: latent since
    /// y205 because DEFAULT priority always routed to the first-alive = primary link,
    /// first hit by y219 priority routing which deliberately routes onto the secondary
    /// link). `joined_id` is the aggregated link's FaceId; `primary_id` is the
    /// session's registered face. Default no-op: only a forwarder with a face table
    /// (the routing peer/router) needs the mapping; the hold-only [`NoOpForwarder`]
    /// and observation-only test forwarders ignore it (and keep observing per
    /// physical link, so per-link witnesses are unaffected).
    fn register_joined(&self, _joined_id: FaceId, _primary_id: FaceId) {}

    /// The joined link left the aggregate (its own death): drop the joined->primary
    /// mapping so a later [`FaceId`] reuse cannot mis-resolve. Default no-op.
    fn deregister_joined(&self, _joined_id: FaceId) {}
}

/// The hold-only [`FaceForwarder`]: the `routing-router` foundation holds
/// faces but routes nothing between them, so every hook is a no-op. The
/// unit-struct default for an [`accept_loop`] that is not a forwarding router.
pub struct NoOpForwarder;

impl FaceForwarder for NoOpForwarder {
    fn register(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) {}
    fn deregister(&self, _id: FaceId) {}
    fn forward(&self, _id: FaceId, _event: IterationEvent<'_>) {}
}

/// What an [`accept_loop`] run accomplished, returned when the shutdown future
/// completes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptLoopSummary {
    /// Peers accepted at the TCP layer (a face open was started for each).
    pub accepted: usize,
    /// Outbound peers dialed (peer-mesh mode, [`peer_loop`]): a face open was
    /// started for each configured dial target. Always 0 for a pure acceptor
    /// ([`accept_loop`]). The dial-source counterpart to [`accepted`](Self::accepted).
    pub dialed: usize,
    /// Faces that reached Established (entered the faces table at least once) —
    /// counts dialed and accepted faces uniformly (a held face is a held face).
    pub established: usize,
    /// High-water mark of the live faces table — the "held N peers at once"
    /// witness that distinguishes this from the one-shot accept path.
    pub peak_concurrent: usize,
}

/// The tagged result of one face-open attempt — the `opening`
/// [`FuturesUnordered`]'s item. `(id, peer, opened)` so a completion routes to
/// the right face record without threading state through the set. `peer` is an
/// [`AcceptedPeer`] (Slice B): the accept path passes the accepted peer tag
/// through unchanged (IP or mesh-capable non-IP), and the dial path wraps its
/// `SocketAddr` target as [`AcceptedPeer::Ip`].
type OpenResult = (FaceId, AcceptedPeer, Result<OpenedSession, OpenError>);

/// A boxed face-open future — the `opening` set's element type. Boxed `dyn
/// Future` because the two open SOURCES, [`open_face`] (accept) and [`dial_face`]
/// (dial), are distinct future types that must share one [`FuturesUnordered`];
/// one heap alloc per open is negligible beside the handshake it wraps. No
/// `Send` bound — the whole loop is single-task `!Send` (see the module doc).
type OpenFuture = Pin<Box<dyn Future<Output = OpenResult>>>;

/// R311y205 (transport-multilink) — the `driving` set's boxed element type in an
/// aggregating build. [`drive_face`], [`drive_joined_face`] and
/// [`drain_rejected_face`] are distinct `async fn` opaque types, so a
/// `max_links > 1` loop needs one boxed `dyn Future` to hold them all in the same
/// [`FuturesUnordered`] (the same reason [`OpenFuture`] boxes). A non-multilink
/// build has only `drive_face`, so its `driving` set stays the unboxed
/// `impl Future` — byte-identical to today (this alias is feature-gated).
#[cfg(feature = "transport-multilink")]
type DriveFuture<'f> = Pin<Box<dyn Future<Output = (Face, DriverOutcome)> + 'f>>;

/// Run the accepted link's deferred transport handshake, then bring it up to
/// Established. Tagged with `(id, peer)` so the loop can route the result without
/// threading state through [`FuturesUnordered`]. The transport (ws/tls) SERVER
/// handshake ([`AcceptedLink::handshake`]) runs HERE, in the spawned per-face
/// future — NOT in the loop's `select!` arm — so a slow/stalled handshake never
/// blocks accepting the next peer (a failed handshake surfaces as
/// [`OpenError::AcceptHandshake`], an isolated `FaceFailed`). Production
/// semantics: `max_iters = None` (the accept-side open-deadline —
/// `accepting.inactivity_timeout`, 1s — bounds a silent peer; see
/// [`accept_and_open_session`]).
async fn open_face(
    id: FaceId,
    peer: AcceptedPeer,
    accepted: AcceptedLink,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let result = match accepted.handshake().await {
        Ok(link) => accept_and_open_session(link, params, clock, None, tick_interval_ms).await,
        Err(e) => Err(OpenError::AcceptHandshake(e)),
    };
    (id, peer, result)
}

/// Dial one configured peer and bring the OUTBOUND link up to Established — the
/// dial-out twin of [`open_face`]. Where `open_face` opens an *accepted* link via
/// [`accept_and_open_session`], this connects to `peer` then opens the
/// *initiated* link via [`initiate_and_open_session`] (the same SSOT the
/// single-session initiator drives), tagged `(id, peer)` so its completion
/// routes through the same `opening` arm. A failed TCP connect surfaces as
/// [`OpenError::Dial`] (a `FaceFailed`, not a panic), so one unreachable peer
/// never sinks the mesh. TCP only (the mesh DIAL side): after R311y376 (Stage 3)
/// the ACCEPT side accepts the whole stream family (tcp/ws/tls) via
/// [`BoundListener::accept_raw`], but the outbound mesh dial here still targets a
/// raw [`SocketAddr`] ([`FaceSources::dial_targets`]) — generalizing it (locator /
/// DNS / TLS dial, reusing
/// [`connect_and_open_session`](crate::session_open::connect_and_open_session)) is
/// a later `routing-peer` atom, the dial-side twin of this stage.
async fn dial_face(
    id: FaceId,
    peer: SocketAddr,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let result = match TcpStream::connect(peer).await {
        Ok(stream) => {
            initiate_and_open_session(
                DialedLink::Tcp(stream),
                params,
                clock,
                None,
                tick_interval_ms,
            )
            .await
        }
        Err(e) => Err(OpenError::Dial(e)),
    };
    // Wrap the dial target as an IP accepted-peer tag: a dial endpoint is always
    // a `SocketAddr` (the mesh dial side is TCP-only), so the `OpenResult` peer
    // tag is `AcceptedPeer::Ip` (Slice B — only the accept side may be non-IP).
    (id, AcceptedPeer::Ip(peer), result)
}

/// R311y205 (transport-multilink) — the per-link traffic-class preference the
/// loop tags each aggregated physical link with, spreading the classes across
/// the links so [`SessionCore::select_link`](wz_session_core::session_actions)
/// can segregate the reliable channel onto one link and the best-effort channel
/// onto another (the slice-1 reliability-segregation the deploy proves). A simple
/// deterministic spread by open order — even [`FaceId`] -> `Reliable`, odd ->
/// `BestEffort` — so a 2-link aggregation (the slice-1 shape) lands one link of
/// each class; full per-priority ranges are the deferred slice-3 refinement. The
/// pref is fixed at open (the `_with_multilink` variant stages it before the
/// handshake), and only the SENDER's prefs decide which link carries each Put.
#[cfg(feature = "transport-multilink")]
fn multilink_pref(id: FaceId) -> LinkReliabilityPref {
    if id.0 % 2 == 0 {
        LinkReliabilityPref::Reliable
    } else {
        LinkReliabilityPref::BestEffort
    }
}

/// R311y219 (transport-multilink) — the traffic-class preference for an aggregated
/// link, choosing between the y205 reliability-SPREAD and the y219 priority-SPREAD.
/// A 2-link aggregate can segregate on ONE axis only ([`SessionCore::select_link`]
/// disqualifies a reliability-mismatched link BEFORE the priority band, faithful to
/// zenoh `select`, `unicast/universal/tx.rs`): with QoS OFF the links split by
/// reliability class ([`multilink_pref`], even -> Reliable / odd -> BestEffort);
/// with QoS ON every link is UNIFORM `Reliable` so the per-face priority band (not
/// the reliability class) is the live `select_link` discriminant for the reliable
/// data channel. The `#[cfg(not(transport-qos))]` build never applies a band, so it
/// keeps the y205 even/odd spread regardless of the runtime `qos` bool (byte-
/// identical). Placed at the deploy caller (not inside the `_with_multilink`
/// entrypoint) so a direct-entrypoint caller keeps the exact pref it passes.
#[cfg(feature = "transport-multilink")]
fn multilink_pref_for(id: FaceId, qos: bool) -> LinkReliabilityPref {
    #[cfg(feature = "transport-qos")]
    if qos {
        return LinkReliabilityPref::Reliable;
    }
    #[cfg(not(feature = "transport-qos"))]
    let _ = qos;
    multilink_pref(id)
}

/// R311y219 (transport-multilink) — the priority analogue of [`multilink_pref`]: the
/// deterministic per-face QoS-priority band that pins each priority conduit to one
/// link when QoS segregates by priority. Even [`FaceId`] -> HIGH band
/// `[Control..=InteractiveLow]`, odd -> LOW `[DataHigh..=Background]` — non-
/// overlapping AND jointly covering the whole `Control..=Background` (0..=7) scale,
/// so every priority is a `full` match on EXACTLY one link (deterministic route, no
/// reliance on the width tie-break). The band is APPLIED only under `transport-qos`
/// (via [`SessionLinkActions::set_link_priority_range`] inside the `_with_multilink`
/// entrypoints); the returned tuple is feature-independent (`Priority` is
/// unconditional) so it threads with no cfg branch. A wz DEPLOYMENT convention (a
/// by-id-parity auto-assignment); zenoh takes per-link priority ranges from explicit
/// endpoint config (`tx.rs:88`), while the `select_link` MECHANISM the band feeds is
/// the faithful mirror. Full per-priority ranges for 3+ links are the deferred
/// slice-5.
#[cfg(feature = "transport-multilink")]
fn multilink_priority_range(id: FaceId) -> (Priority, Priority) {
    if id.0 % 2 == 0 {
        (Priority::Control, Priority::InteractiveLow)
    } else {
        (Priority::DataHigh, Priority::Background)
    }
}

/// R311y205 (transport-multilink) — [`open_face`] negotiating the 0x4
/// Z_EXT_MULTILINK aggregation ext: the accept-side open used when `max_links > 1`
/// so the acceptor reflects the ext + captures the initiator's ephemeral pubkey
/// (the key a second link is bound to the logical session by) and this link is
/// tagged with `pref`. Byte-identical to [`open_face`] otherwise; the loop
/// branches on `max_links` at the accept site.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn open_face_multilink(
    id: FaceId,
    peer: AcceptedPeer,
    accepted: AcceptedLink,
    pref: LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    // The deferred transport handshake runs here in the spawned future (never the
    // loop's `select!` arm), same as the single-link [`open_face`] — a failed
    // ws/tls handshake is an isolated `FaceFailed`, not a loop stall.
    let result = match accepted.handshake().await {
        Ok(link) => {
            accept_and_open_session_with_multilink(
                link,
                params,
                pref,
                qos,
                band,
                clock,
                None,
                tick_interval_ms,
            )
            .await
        }
        Err(e) => Err(OpenError::AcceptHandshake(e)),
    };
    // `peer` is already an `AcceptedPeer` (the accepted-peer tag threaded from the
    // `Step::Accepted` arm — IP or mesh-capable non-IP); pass it through unchanged.
    (id, peer, result)
}

/// R311y205 (transport-multilink) — [`dial_face`] negotiating the 0x4
/// Z_EXT_MULTILINK aggregation ext: the dial-side open used when `max_links > 1`
/// so the initiator offers the ext + captures the responder's ephemeral pubkey
/// and this link is tagged with `pref`. Byte-identical to [`dial_face`] otherwise;
/// the loop branches on `max_links` at each dial site.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn dial_face_multilink(
    id: FaceId,
    peer: SocketAddr,
    pref: LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let result = match TcpStream::connect(peer).await {
        Ok(stream) => {
            initiate_and_open_session_with_multilink(
                DialedLink::Tcp(stream),
                params,
                pref,
                qos,
                band,
                clock,
                None,
                tick_interval_ms,
            )
            .await
        }
        Err(e) => Err(OpenError::Dial(e)),
    };
    // Dial target -> IP tag (Slice B), same as `dial_face`.
    (id, AcceptedPeer::Ip(peer), result)
}

/// R311y212 (transport-multilink per-link auto-re-add) — the backoff + 0x4 re-dial
/// twin: [`dial_face_after`]'s delay composed with [`dial_face_multilink`]'s
/// 0x4-negotiating establishment. Because the re-dial reaches the SAME peer (the
/// retained `SocketAddr`), it captures the SAME REMOTE ephemeral multilink pubkey
/// the survivor is bound to, so `join_link`'s `authorize_link` config-equality
/// (the candidate's captured-peer key vs the session's bound-peer key) passes —
/// the identity is the PEER's key, not this node's. It re-tags its traffic class
/// via `pref` AND its QoS-priority `band` (both the DEAD link's retained values,
/// not `multilink_pref(new_id)` / `multilink_priority_range(new_id)` — the fresh
/// id's parity may differ, which would flip the band and collapse the segregation).
/// Completes into the same `opening` -> [`Step::Opened`] -> JOIN path as an
/// immediate multilink dial, so a successful re-dial aggregates onto the surviving
/// shared core (`join_link`) and a failed one surfaces `Err` -> the Err arm
/// re-schedules it (retry-until-success).
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn dial_face_multilink_after(
    id: FaceId,
    peer: SocketAddr,
    backoff_ms: u64,
    pref: LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    dial_face_multilink(id, peer, pref, qos, band, params, clock, tick_interval_ms).await
}

/// The fixed backoff between a dropped/failed dial and its re-dial. Shared by
/// two substrates: `router-connect-reconcile` peer auto-reconnect (a dropped
/// DESIRED peer) and `transport-multilink` per-link auto-re-add (R311y212 — a
/// dropped aggregated link re-JOINed onto the surviving session). zenoh uses a
/// configurable `ConnectionRetryConf` exponential period (`orchestrator.rs:788`);
/// wz takes the simple fixed 1 s of the client `ReconnectPolicy` default — the
/// per-endpoint retry-config surface is a deferred concern, not this atom.
#[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
const RECONNECT_BACKOFF_MS: u64 = 1000;

/// Dial a peer after a fixed backoff — the delayed twin of [`dial_face`] used by the
/// `router-connect-reconcile` peer auto-reconnect (the wz analogue of zenoh's
/// `peer_connector_retry` sleep-then-connect loop, `orchestrator.rs:820`). A dropped
/// or failed outbound dial to a still-desired peer is re-scheduled through this so
/// the retry does not hot-loop on an unreachable peer; it completes into the SAME
/// `opening` -> [`Step::Opened`] path as an immediate dial, so a successful re-dial
/// is held + registered identically, and a failed one surfaces as `FaceFailed` and
/// is re-scheduled again (retry-until-success-or-removed-from-`desired`).
#[cfg(feature = "router-connect-reconcile")]
async fn dial_face_after(
    id: FaceId,
    peer: SocketAddr,
    backoff_ms: u64,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    dial_face(id, peer, params, clock, tick_interval_ms).await
}

/// Schedule a re-dial of a dropped/failed outbound peer IF it is still desired
/// (`router-connect-reconcile` peer auto-reconnect — the wz analogue of zenoh's
/// `closed_session` Peer/Router arm, `orchestrator.rs:1210`, gated on
/// `peers.contains(endpoint)` `:1225`). Re-keys the dial-address index to the fresh
/// [`FaceId`] BEFORE the backoff so the address stays CLAIMED across the drop->redial
/// gap (a concurrent reconcile then dedups against it instead of opening a second
/// link). A peer no longer in `desired` (removed from the connect list) is dropped,
/// not re-dialed — the removal is honoured for RECONNECTION even though the router
/// never actively closes a live face (the close-removed asymmetry, faithful to
/// zenoh's Client-only teardown branch).
///
/// A re-dial is NOT counted in `summary.dialed` — that counter is the number of
/// distinct configured/reconciled peers dialed, not TCP connect attempts, so a
/// permanently-unreachable peer does not inflate it without bound. `announce`
/// controls the log level: the FIRST re-dial after a drop (an operator-visible peer
/// flap) logs at `info`; subsequent retries against a still-unreachable peer log at
/// `debug`, so a down configured peer does not emit a 1 Hz `info` storm (the retry
/// cadence is bounded by [`RECONNECT_BACKOFF_MS`]).
#[cfg(feature = "router-connect-reconcile")]
#[allow(clippy::too_many_arguments)]
fn schedule_redial(
    addr: SocketAddr,
    desired: &std::collections::HashSet<SocketAddr>,
    dialed_targets: &mut BTreeMap<FaceId, SocketAddr>,
    opening: &mut FuturesUnordered<OpenFuture>,
    next_id: &mut u64,
    announce: bool,
    params: &SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) {
    if !desired.contains(&addr) {
        return;
    }
    let id = FaceId(*next_id);
    *next_id += 1;
    // Reserve the address under the new id before the backoff so a reconcile that
    // arrives during the wait does not also dial it (the drop->redial dedup gap).
    dialed_targets.insert(id, addr);
    if announce {
        log::info!(
            "reconcile: re-dialing desired peer {addr} in {RECONNECT_BACKOFF_MS}ms (face {})",
            id.0
        );
    } else {
        log::debug!(
            "reconcile: retrying re-dial of desired peer {addr} in {RECONNECT_BACKOFF_MS}ms (face {})",
            id.0
        );
    }
    opening.push(Box::pin(dial_face_after(
        id,
        addr,
        RECONNECT_BACKOFF_MS,
        params.clone(),
        clock,
        tick_interval_ms,
    )));
}

/// R311y212 (transport-multilink) — schedule a re-dial + re-JOIN of a dropped
/// aggregated link this node DIALED (the multilink twin of [`schedule_redial`],
/// its own substrate, NOT gated on `router-connect-reconcile`). Unlike the peer
/// auto-reconnect there is no `desired` connect-list gate — every retained
/// multilink dial endpoint is permanently wanted (a per-link retry policy is a
/// deferred slice). Re-keys the retained endpoint to a fresh [`FaceId`] BEFORE
/// the backoff (so the re-add is tracked across the drop->redial gap and the Err
/// arm can retry it), carrying the DEAD link's `pref` AND its QoS-priority `band`
/// so the re-added link restores BOTH its traffic class and its priority band (a
/// fresh-id band would flip on parity and collapse the segregation). `announce`
/// controls the log level: the first re-add after a drop logs at `info` (an
/// operator-visible link flap), retries at `debug`. The re-dial completes into the
/// SAME `opening` -> [`Step::Opened`] JOIN path, so it aggregates onto the
/// surviving shared core with SN continuity.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
fn schedule_multilink_redial(
    addr: SocketAddr,
    pref: LinkReliabilityPref,
    qos: bool,
    band: (Priority, Priority),
    ml_dial_endpoints: &mut BTreeMap<
        FaceId,
        (SocketAddr, LinkReliabilityPref, (Priority, Priority)),
    >,
    opening: &mut FuturesUnordered<OpenFuture>,
    next_id: &mut u64,
    announce: bool,
    params: &SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) {
    let id = FaceId(*next_id);
    *next_id += 1;
    // Re-key the retained endpoint to the fresh id BEFORE the backoff, so the
    // re-add is tracked (a failed re-dial's Err arm finds it and retries).
    ml_dial_endpoints.insert(id, (addr, pref, band));
    if announce {
        log::info!(
            "multilink: re-adding dropped link to {addr} in {RECONNECT_BACKOFF_MS}ms (face {})",
            id.0
        );
    } else {
        log::debug!(
            "multilink: retrying re-add to {addr} in {RECONNECT_BACKOFF_MS}ms (face {})",
            id.0
        );
    }
    opening.push(Box::pin(dial_face_multilink_after(
        id,
        addr,
        RECONNECT_BACKOFF_MS,
        pref,
        qos,
        band,
        params.clone(),
        clock,
        tick_interval_ms,
    )) as OpenFuture);
}

/// Drive one Established face to terminal, then drain it. The per-iteration
/// observer threads each inbound event to `forwarder.forward(face.id, …)` — the
/// data-plane seam: the hold-only [`NoOpForwarder`] discards it (this atom just
/// holds the transport session), a routing forwarder routes it. The
/// borrow-then-consume shape — borrow `opened`'s fields for the drive, then
/// [`OpenedSession::drain_to_close`] consumes `opened` — keeps the drop-order +
/// bounded writer-drain a single typed primitive (the R292 drain contract), not
/// a hand-ordered sequence re-copied here.
async fn drive_face(
    face: Face,
    mut opened: OpenedSession,
    forwarder: &dyn FaceForwarder,
) -> (Face, DriverOutcome) {
    let timeouts = SessionTimeouts::spec_defaults();
    // R311y296 — the forwarder's per-face deadline joins this face's wake
    // `min`. Every stock forwarder keeps both `None` defaults, so their arming
    // is unchanged; `wz-capi-pico`'s returns its pending-`z_get` deadline and
    // notifies when a get is issued. The face is `register`ed before this runs
    // (`Step::Opened`), so `deadline_revised` resolves to the real signal
    // rather than the inert fallback.
    let revised = forwarder.deadline_revised(face.id);
    let outcome = drive_session_until_terminal_with_extra_deadline(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| forwarder.forward(face.id, event),
        ExtraDeadline {
            next_ms: || forwarder.next_extra_deadline_ms(face.id),
            revised: revised.as_deref(),
        },
    )
    .await;
    opened.drain_to_close().await;
    (face, outcome)
}

/// R311y205 (transport-multilink) — drive an AGGREGATED secondary link to
/// terminal. Like [`drive_face`], but the RX admits against the `joined` handle's
/// SHARED `SessionCore` (its per-channel rx-SN gate is the primary's, so the
/// aggregated data plane is one continuous sequence), while `opened.engine` runs
/// this physical link's own FSM / lease. The secondary shares the primary's
/// forwarder face (no second `register`), so its inbound events are still tagged
/// with THIS link's [`FaceId`] for the observer. On teardown the loop
/// (`Step::Driven`) removes it from the shared set via the tracked `joined`
/// handle — the secondary's own FSM `release_link` del_links only its throwaway
/// core, so the loop does the effective removal.
#[cfg(feature = "transport-multilink")]
async fn drive_joined_face(
    face: Face,
    mut opened: OpenedSession,
    joined: Arc<SessionLinkActions>,
    forwarder: &dyn FaceForwarder,
) -> (Face, DriverOutcome) {
    let timeouts = SessionTimeouts::spec_defaults();
    let outcome = drive_session_until_terminal(
        &mut opened.inbound,
        &joined,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| forwarder.forward(face.id, event),
    )
    .await;
    opened.drain_to_close().await;
    (face, outcome)
}

/// R311y205 (transport-multilink) — flush + drop a REJECTED aggregation link. Its
/// MAX_LINKS / INVALID link-only close was already staged on `opened.actions` by
/// [`join_link`]; this drains so the close reaches the peer before the socket
/// closes. The link never entered the faces table nor the forwarder, so
/// `Step::Driven` drops its `FaceId` silently. Returns `Terminated` so it shares
/// the `driving` set's item type with [`drive_face`].
#[cfg(feature = "transport-multilink")]
async fn drain_rejected_face(face: Face, opened: OpenedSession) -> (Face, DriverOutcome) {
    opened.drain_to_close().await;
    (face, DriverOutcome::Terminated)
}

/// One [`select!`](tokio::select) outcome, decoded so the borrow of each
/// [`FuturesUnordered`] (its `next()` future) is released *before* the handler
/// mutates a set (`opening.push` / `driving.push`). Decoupling the poll from the
/// mutation lets a handler mutate `opening`/`driving` after the `select!` has
/// resolved and dropped its `.next()` borrow, rather than overlapping it from a
/// sibling arm.
enum Step {
    Shutdown,
    // Boxed: an `OpenedSession` is large (it owns the FSM engine), so carrying it
    // inline would make every `Step` value that big on the stack (clippy
    // `large_enum_variant`). One box per open event is negligible.
    Opened(Box<OpenResult>),
    Driven((Face, DriverOutcome)),
    Accepted(io::Result<(AcceptedLink, AcceptedPeer)>),
    /// The forwarder's periodic timer fired (its [`FaceForwarder::tick_period`]
    /// cadence) — call [`FaceForwarder::tick`]. Only ever produced when a timer
    /// is armed (a forwarder that returned `Some` from `tick_period`).
    Tick,
    /// A gossip-autoconnect [`DialIntent`] arrived on the dial-intent channel —
    /// dial the discovered peer unless a face to it is already held. Only ever
    /// produced when [`FaceSources::dial_intents`] is `Some`.
    Dial(DialIntent),
    /// A Push arrived on the multicast INGRESS channel (the deferred `mcast_faces`
    /// plane, I1) — route it via [`FaceForwarder::route_mcast_ingress`]. Only ever
    /// produced when [`FaceSources::mcast_ingress`] is `Some`.
    McastIngress(McastIngressItem),
    /// The on-group ROUTER member set changed (I3b) — relay it to
    /// [`FaceForwarder::set_mcast_group_members`] for the Designated-Router
    /// election. Only ever produced when [`FaceSources::mcast_members`] is `Some`.
    McastMembers(Vec<Vec<u8>>),
    /// The on-group SUBSCRIBER keyexpr aggregate changed (sub plane, S2) — relay
    /// it to [`FaceForwarder::set_mcast_group_subs`] so the router advertises the
    /// group's interest into the unicast mesh. Only ever produced when
    /// [`FaceSources::mcast_group_subs`] is `Some`.
    McastGroupSubs(Vec<String>),
    /// A runtime connect-list reconcile arrived (`router-connect-reconcile`) — the
    /// NEW full desired outbound connect-set; dial each newly-listed address not
    /// already being dialed (ADD-ONLY, the wz analogue of zenoh's `update_peers`
    /// Peer/Router branch). Only ever produced when [`FaceSources::reconcile`] is
    /// `Some`; the variant is always present so the `select!` arm carries no
    /// attribute (tokio's `select!` rejects branch attributes), and its handler body
    /// is `#[cfg]`-gated — inert without the feature.
    Reconcile(Vec<SocketAddr>),
}

/// Await the forwarder's periodic tick, or park forever when no timer is armed
/// (the forwarder declared no periodic obligation via
/// [`FaceForwarder::tick_period`]). A fixed `select!` arm-set needs every arm to
/// be a real future at compile time; this makes the tick arm a no-op
/// `pending()` when there is nothing to tick, so the accept-only / hold-only
/// paths poll no extra timer and keep their exact prior behaviour.
async fn forwarder_tick(timer: &mut Option<tokio::time::Interval>) {
    match timer {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Await the next gossip-autoconnect [`DialIntent`], or park forever when there
/// is no dial-intent channel (autoconnect not enabled) — the dial-intent twin of
/// [`forwarder_tick`], so the `select!` arm-set is fixed at compile time. When
/// the channel CLOSES (every sender dropped — the forwarder is gone), the
/// receiver is taken so subsequent polls park rather than hot-looping on the
/// closed channel (a closed `recv()` resolves to `None` immediately). Cancel-safe
/// (tokio `mpsc::UnboundedReceiver::recv`), so losing the race to a sibling arm
/// never drops a buffered intent.
async fn recv_dial_intent(rx: &mut Option<DialIntentReceiver>) -> DialIntent {
    let closed = if let Some(r) = rx.as_mut() {
        match r.recv().await {
            Some(intent) => return intent,
            None => true,
        }
    } else {
        false
    };
    if closed {
        *rx = None;
    }
    std::future::pending::<DialIntent>().await
}

/// Await the next multicast INGRESS [`McastIngressItem`], or park forever when
/// there is no ingress channel (the `mcast_faces` plane is off) — the multicast
/// twin of [`recv_dial_intent`], so the `select!` arm-set is fixed at compile
/// time. On channel CLOSE (the multicast drive-loop task ended — every sender
/// dropped) the receiver is taken so subsequent polls park rather than hot-loop
/// on the closed channel. Cancel-safe (tokio `mpsc::UnboundedReceiver::recv`), so
/// losing the race to a sibling arm never drops a buffered ingress Push.
async fn recv_mcast_ingress(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<McastIngressItem>>,
) -> McastIngressItem {
    let closed = if let Some(r) = rx.as_mut() {
        match r.recv().await {
            Some(item) => return item,
            None => true,
        }
    } else {
        false
    };
    if closed {
        *rx = None;
    }
    std::future::pending::<McastIngressItem>().await
}

/// Await the next on-group ROUTER member update (I3b), or park forever when there
/// is no membership channel (the ingress plane is off) — the membership twin of
/// [`recv_mcast_ingress`], so the `select!` arm-set is fixed at compile time. On
/// channel CLOSE the receiver is taken so later polls park rather than hot-loop.
/// Cancel-safe (tokio `mpsc::UnboundedReceiver::recv`).
async fn recv_mcast_members(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<Vec<Vec<u8>>>>,
) -> Vec<Vec<u8>> {
    let closed = if let Some(r) = rx.as_mut() {
        match r.recv().await {
            Some(item) => return item,
            None => true,
        }
    } else {
        false
    };
    if closed {
        *rx = None;
    }
    std::future::pending::<Vec<Vec<u8>>>().await
}

/// Await the next on-group SUBSCRIBER aggregate update (sub plane, S2), or park
/// forever when there is no sub channel (the ingress plane is off) — the
/// subscriber twin of [`recv_mcast_members`], so the `select!` arm-set is fixed at
/// compile time. On channel CLOSE the receiver is taken so later polls park rather
/// than hot-loop. Cancel-safe (tokio `mpsc::UnboundedReceiver::recv`).
async fn recv_mcast_group_subs(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<Vec<String>>>,
) -> Vec<String> {
    let closed = if let Some(r) = rx.as_mut() {
        match r.recv().await {
            Some(item) => return item,
            None => true,
        }
    } else {
        false
    };
    if closed {
        *rx = None;
    }
    std::future::pending::<Vec<String>>().await
}

/// Await the next runtime connect-list reconcile ([`ReconcileReceiver`]), or park
/// forever when there is no reconcile channel (`router-connect-reconcile` not wired)
/// — the reconcile twin of [`recv_dial_intent`], so the `select!` arm-set is fixed
/// at compile time. On channel CLOSE (the host dropped the sender) the receiver is
/// taken so later polls park rather than hot-loop. Cancel-safe (tokio
/// `mpsc::UnboundedReceiver::recv`), so losing the race to a sibling arm never drops
/// a buffered reconcile request.
async fn recv_reconcile(rx: &mut Option<ReconcileReceiver>) -> Vec<SocketAddr> {
    let closed = if let Some(r) = rx.as_mut() {
        match r.recv().await {
            Some(set) => return set,
            None => true,
        }
    } else {
        false
    };
    if closed {
        *rx = None;
    }
    std::future::pending::<Vec<SocketAddr>>().await
}

/// The first locator a [`DialIntent`] carries that the TCP dial path
/// ([`dial_face`]) can actually reach: a numeric `tcp/<addr:port>` endpoint
/// (parsed through the locator SSOT [`parse_locator`]). A non-tcp scheme
/// (`tls` / `udp` / `ws`) or a non-numeric / DNS address is skipped — the same
/// TCP-only numeric scope as the static `dial_targets` (the richer
/// scheme-dispatched / DNS dial is the same tracked `routing-peer` follow-up
/// [`dial_face`] notes). `None` when no carried locator qualifies.
fn first_dialable_addr(locators: &[String]) -> Option<SocketAddr> {
    locators.iter().find_map(|loc| match parse_locator(loc) {
        Ok(p) if p.proto == Proto::Tcp => Some(p.addr),
        _ => None,
    })
}

/// The outcome of weighing a [`DialIntent`] against the held faces — the pure
/// dial decision the [`Step::Dial`] arm acts on (extracted so it is unit-testable
/// without standing up a TCP loop).
enum DialDecision {
    /// Dial the discovered peer at this TCP address.
    Dial(SocketAddr),
    /// Skip — a face to this peer's zid is already held (the zenoh
    /// `get_transport_unicast(&zid).is_some()` dedup).
    AlreadyHeld,
    /// Skip — none of the carried locators is TCP-dialable.
    NoLocator,
}

/// Whether any currently-held face is to peer `zid`. Two uses: (1) the dial-intent
/// dedup ([`dial_decision`]) — a gossip-autoconnect intent for a peer this node
/// already holds a face to is not re-dialed (zenoh's `get_transport_unicast` check
/// before `connect_peer`); and (2) the face-establishment dedup in `Step::Opened`,
/// but ONLY for a forwarder that keys routing state on the zid
/// ([`FaceForwarder::dedups_faces_by_zid`] — the pure acceptor / star router holds
/// N faces regardless of zid and never consults this). O(held faces) — a mesh node
/// holds tens, and this runs only on a dial-intent or a face-up, never per message.
fn holds_zid(faces: &BTreeMap<FaceId, Option<Vec<u8>>>, zid: &[u8]) -> bool {
    faces.values().any(|z| z.as_deref() == Some(zid))
}

/// Weigh a [`DialIntent`] against the held faces: dedup first (a peer already held
/// is never re-dialed), then pick a TCP-dialable locator. The forwarder already
/// applied the autoconnect role + zid policy at emit (A5b), so this is only the
/// loop-side "do I already have it / can I reach it" decision.
fn dial_decision(faces: &BTreeMap<FaceId, Option<Vec<u8>>>, intent: &DialIntent) -> DialDecision {
    if holds_zid(faces, &intent.zid) {
        return DialDecision::AlreadyHeld;
    }
    match first_dialable_addr(&intent.locators) {
        Some(addr) => DialDecision::Dial(addr),
        None => DialDecision::NoLocator,
    }
}

/// Where a face-drive node's faces come from: the inbound `listener` it accepts
/// on, the outbound `dial_targets` it dials at startup, and the runtime
/// `dial_intents` a gossip-autoconnect peer dials on discovery. A pure acceptor
/// ([`accept_loop`]) has no dial targets and no dial intents; a peer-mesh node
/// ([`peer_loop`]) has both static dial targets and (when a deploy enables
/// autoconnect) the dynamic dial-intent stream. Bundling the sources keeps the
/// loop signature within the argument-count budget as the family grows, and
/// names the real distinction between the two entry points.
/// One Push RECEIVED on a multicast INGRESS group, folded from the (separate,
/// `Send`) multicast drive-loop task to the `!Send` forwarder on the peer-loop
/// task (the deferred `mcast_faces` plane, I1 — see
/// [`spawn_router_mcast_ingress`](crate::multicast_glue::spawn_router_mcast_ingress)).
/// The owned `PushOwned` crosses the task boundary; the forwarder routes it via
/// [`FaceForwarder::route_mcast_ingress`]. The struct is always defined so the
/// accept-loop's `select!` arm needs no `#[cfg]` (tokio's `select!` rejects
/// attributes on branches); the `PushOwned` payload is gated on `codec-push`
/// (which provides it), and the struct is inert without `codec-push` — nothing
/// constructs it (`spawn_router_mcast_ingress` is `codec-push`-gated).
pub struct McastIngressItem {
    /// The received Push (owned so it can cross the task boundary).
    #[cfg(feature = "codec-push")]
    pub push: PushOwned,
    /// The frame's reliability, preserved for the routed egress legs.
    pub reliable: bool,
    /// R311y227 — the frame's decoded QoS band, so the router re-injects the
    /// group-ingress Push into the mesh / local subscribers at the priority it
    /// arrived (DEFAULT on a non-qos group). Paired with `push` (`codec-push`).
    #[cfg(feature = "codec-push")]
    pub priority: Priority,
}

pub struct FaceSources {
    /// The bound listener for inbound peers (accept source), scheme-keyed
    /// ([`BoundListener`]) so a router/peer accepts the whole stream family
    /// (tcp/ws/tls) — [`face_drive_loop`]'s `select!` arm accepts one raw
    /// connection per iteration via [`BoundListener::accept_raw`], and the ws/tls
    /// SERVER handshake is deferred to the spawned open future so a slow handshake
    /// never blocks the loop. R311y376 (Stage 3) generalized this from a bare
    /// [`tokio::net::TcpListener`].
    pub listener: BoundListener,
    /// The peer addresses to dial at startup (static outbound source); empty for
    /// a pure acceptor.
    pub dial_targets: Vec<SocketAddr>,
    /// The runtime dial-intent stream (the dynamic outbound source): the
    /// [`LinkstateForwarder`](crate::linkstate_forward::LinkstateForwarder)'s
    /// gossip-autoconnect emits a [`DialIntent`] per discovered, policy-admitted
    /// peer; the loop dials each one it does not already hold a face to. `None`
    /// when autoconnect is not enabled (an accept-only loop, or a peer-mesh node
    /// that did not opt in) — then the loop never dials on discovery.
    pub dial_intents: Option<DialIntentReceiver>,
    /// The multicast INGRESS receiver (the deferred `mcast_faces` plane, I1): a
    /// router-hat built with `router-multicast-faces` joins the group and folds
    /// each received Push here, from the (separate, `Send`) multicast drive-loop
    /// task to the `!Send` forwarder. `None` when the ingress plane is off — then
    /// the loop's ingress arm parks forever and non-router / non-multicast builds
    /// are byte-identical. Gated on `codec-push` (the fold payload
    /// are byte-identical. The channel is always `None` without `codec-push` (its
    /// producer `spawn_router_mcast_ingress` is `codec-push`-gated), so the arm is
    /// inert but present (no `#[cfg]` on the `select!` branch).
    pub mcast_ingress: Option<tokio::sync::mpsc::UnboundedReceiver<McastIngressItem>>,
    /// The multicast INGRESS on-group ROUTER member relay (I3b): the router-hat's
    /// `spawn_router_mcast_ingress` loop sends its live Designated-Router election
    /// candidate set here on each group membership change, and the drive loop
    /// forwards it to [`FaceForwarder::set_mcast_group_members`]. `None` when the
    /// ingress plane is off (the arm parks forever). The sibling of
    /// `mcast_ingress` from the same helper.
    pub mcast_members: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<Vec<u8>>>>,
    /// The multicast INGRESS on-group SUBSCRIBER relay (sub plane, S2): the
    /// router-hat's `spawn_router_mcast_ingress` loop sends the deduped group-
    /// subscriber keyexpr aggregate here on each change, and the drive loop forwards
    /// it to [`FaceForwarder::set_mcast_group_subs`]. `None` when the ingress plane
    /// is off (the arm parks forever). The sibling of `mcast_members` from the same
    /// helper.
    pub mcast_group_subs: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<String>>>,
    /// The runtime connect-list reconcile stream (`router-connect-reconcile`): the
    /// run-mode host (`run_router_hat`) sends the NEW full desired outbound
    /// connect-set here when the operator changes the connect endpoints at runtime,
    /// and the loop dials each newly-listed address it is not already dialing (the
    /// wz analogue of zenoh's `update_peers`, `orchestrator.rs:413`). `None` when
    /// `router-connect-reconcile` is not wired (every non-router loop, and a router
    /// built without the feature) — then the arm parks forever and the loop is
    /// byte-for-byte the prior behaviour. Always-present (no `#[cfg]` on the field)
    /// so the `select!` arm needs no attribute, exactly like the mcast fields above.
    pub reconcile: Option<ReconcileReceiver>,
    /// R311y205 (transport-multilink) — the max number of physical links this loop
    /// aggregates into ONE logical unicast session per peer zid (from
    /// [`WzConfig.max_links`](crate::config::WzConfig)). `1` (or the field absent
    /// in a non-multilink build) = the single-link path, byte-identical to today:
    /// a second link to a held zid is dropped by the `dedups_faces_by_zid` rule as
    /// before. `> 1` turns on aggregation — the accept/dial sites open with the
    /// `_with_multilink` variants and `Step::Opened` joins a second link onto the
    /// first's shared core rather than registering a redundant face. Feature-gated
    /// so the struct — and every non-multilink caller — is unchanged without it.
    #[cfg(feature = "transport-multilink")]
    pub max_links: usize,
    /// R311y218 (transport-multilink) — whether this loop OFFERS the QoS transport
    /// on every aggregated link it opens (sourced from `WzConfig.qos`). Uniform per
    /// loop (unlike the per-face `multilink_pref`); staged via `set_qos_offer` in
    /// the `_with_multilink` entrypoints. `false` = single-conduit, byte-identical.
    /// Gated `transport-multilink` (a plain bool like `max_links`, not
    /// `all(..,transport-qos)`) so the threading carries no per-call-site cfg branch;
    /// the value is only honored under `transport-qos` (else `set_qos_offer` elides).
    #[cfg(feature = "transport-multilink")]
    pub qos: bool,
}

/// Bind-once, hold-N: the shared multi-face drive core behind both
/// [`accept_loop`] (accept-only) and [`peer_loop`] (dial + accept). A node's
/// faces come from the two [`FaceSources`] — dialing each `dial_targets` address
/// (outbound, seeded once at startup) and accepting inbound links on `listener`
/// — but once a link reaches Established it is a *face*, held and driven
/// identically regardless of which side opened it (a held face is a held face,
/// per the module doc). `params` is the local node's session-init template,
/// cloned per face. The loop runs until `shutdown` resolves, then returns its
/// [`AcceptLoopSummary`].
///
/// Shutdown drops the in-flight open/drive futures: each face's socket closes
/// and its (detached, `Send`) writer task drains. Per-face graceful Close is a
/// NON-goal of this atom (see the module doc).
async fn face_drive_loop<S, F>(
    sources: FaceSources,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    mut on_event: F,
    forwarder: &dyn FaceForwarder,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    let FaceSources {
        mut listener,
        dial_targets,
        mut dial_intents,
        mut mcast_ingress,
        mut mcast_members,
        mut mcast_group_subs,
        mut reconcile,
        #[cfg(feature = "transport-multilink")]
        max_links,
        #[cfg(feature = "transport-multilink")]
        qos,
    } = sources;
    tokio::pin!(shutdown);

    // The live faces, each mapped to its peer zid (`None` if the handshake never
    // surfaced one). The value is READ — `holds_zid` scans it for the
    // gossip-autoconnect dial-intent dedup and, for a zid-keying forwarder, the
    // face-establishment dedup — so this single map is the source for "who do I
    // hold", replacing the prior value-less id set plus a parallel zid set (the
    // duplication the old comment warned against; the value is no longer write-only
    // now that the dedups read it). `peak_concurrent` and the held-count read its
    // cardinality.
    let mut faces: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
    // The address index of the OUTBOUND dials (`router-connect-reconcile`): every
    // dialed face's `FaceId -> SocketAddr`, populated at each dial-push (startup
    // seed, gossip `Step::Dial`, reconcile-add) and pruned when the face leaves.
    // A runtime reconcile dedups additions against this (dial `addr` iff `addr` is
    // not already an in-flight/held dial) — the address dedup the zid-keyed `faces`
    // map structurally cannot do (a config endpoint carries no zid until the
    // handshake completes, and a star router keeps N faces regardless of zid).
    // Accepted faces are never indexed here (their `SocketAddr` is the remote's
    // ephemeral source port, never a connect-list target), so a reconcile never
    // touches an inbound peer. Maintained only when the feature is compiled.
    #[cfg(feature = "router-connect-reconcile")]
    let mut dialed_targets: BTreeMap<FaceId, SocketAddr> = BTreeMap::new();
    // The DESIRED outbound connect-set (`router-connect-reconcile` peer auto-
    // reconnect): the addresses the node WANTS to hold a dial to — seeded from the
    // static `dial_targets` and updated by each runtime reconcile (grows on add,
    // shrinks on remove). A dropped/failed dial is re-dialed iff its address is still
    // in this set (the zenoh `closed_session` `peers.contains(endpoint)` gate,
    // `orchestrator.rs:1225`); a removed address simply leaves the set and is not
    // reconnected (the router never actively closes a live face — the close-removed
    // asymmetry). Maintained only when the feature is compiled.
    #[cfg(feature = "router-connect-reconcile")]
    let mut desired: std::collections::HashSet<SocketAddr> = dial_targets.iter().copied().collect();
    let mut next_id: u64 = 0;
    // R311y205 (transport-multilink) — the per-peer aggregation registry (active
    // only when `max_links > 1`). `ml_sessions` maps a peer zid to its logical
    // session: the (primary FaceId, primary Face) reported on FaceUp/FaceDown and
    // registered with the forwarder, plus a STABLE shared-core handle used as
    // [`join_link`]'s primary arg. That handle survives individual link deaths
    // (its `SessionCore` is the shared one, alive while any link remains), so a
    // link joining AFTER the primary's own link died still resolves the session —
    // it is NOT re-derived from a per-link entry that teardown removes. `ml_faces`
    // tracks EVERY aggregated physical link (primary and secondary) by its FaceId
    // to its (peer zid, core-bound actions handle): the handle whose shared
    // `SessionCore` a `del_link` on the link's teardown targets (the primary's own
    // actions; a secondary's `joined` transplant handle). `ml_rejected` holds the
    // FaceIds of over-limit / mismatch links draining their reject close, dropped
    // silently when their drive ends. All feature-gated, so a non-multilink loop
    // allocates none of them.
    #[cfg(feature = "transport-multilink")]
    let mut ml_sessions: BTreeMap<Vec<u8>, (FaceId, Face, Arc<SessionLinkActions>)> =
        BTreeMap::new();
    #[cfg(feature = "transport-multilink")]
    let mut ml_faces: BTreeMap<FaceId, (Vec<u8>, Arc<SessionLinkActions>)> = BTreeMap::new();
    #[cfg(feature = "transport-multilink")]
    let mut ml_rejected: BTreeSet<FaceId> = BTreeSet::new();
    // R311y212 (transport-multilink per-link auto-re-add) — the retained dial
    // endpoint (+ traffic-class pref) for every aggregated link THIS node dialed,
    // keyed by FaceId. Its own substrate (not `router-connect-reconcile`'s
    // `dialed_targets`, which is removed at the JOIN and dial-vs-accept-gated on a
    // different feature): a dialed link keeps its entry across the JOIN so that on
    // a PARTIAL loss it can be re-dialed + re-JOINed onto the surviving session. An
    // ACCEPTED link has no entry (no re-dial owner — the peer re-dials it).
    #[cfg(feature = "transport-multilink")]
    let mut ml_dial_endpoints: BTreeMap<
        FaceId,
        (SocketAddr, LinkReliabilityPref, (Priority, Priority)),
    > = BTreeMap::new();
    let mut summary = AcceptLoopSummary::default();
    let mut opening: FuturesUnordered<OpenFuture> = FuturesUnordered::new();
    // R311y205 (transport-multilink) — an aggregating loop drives three distinct
    // future shapes (face / joined / rejected), so `driving` holds boxed futures;
    // a non-multilink loop keeps the unboxed single-shape set, byte-identical.
    #[cfg(not(feature = "transport-multilink"))]
    let mut driving = FuturesUnordered::new();
    #[cfg(feature = "transport-multilink")]
    let mut driving: FuturesUnordered<DriveFuture<'_>> = FuturesUnordered::new();

    // Arm the forwarder's periodic tick (e.g. the linkstate peer's self-flood
    // cadence — its protocol obligation, now driven by the loop so EVERY caller
    // converges, not only a demo with a hand-rolled flood `select!`). A
    // forwarder with no periodic obligation returns `None`, so no timer is
    // created and the tick arm parks forever — the accept-only and hold-only
    // loops keep their exact prior behaviour (no extra wakeups).
    let mut tick_timer = forwarder.tick_period().map(tokio::time::interval);

    // Seed the outbound dial faces (peer-mesh mode). Each configured target is
    // dialed concurrently and, once Established, held in the SAME face set as
    // accepted peers — the dial-out face source, symmetric to the accept arm
    // below. Boxed into the shared `opening` set because `dial_face` and
    // `open_face` are distinct future types (see [`OpenFuture`]). Empty for a
    // pure acceptor, so [`accept_loop`] seeds nothing here.
    for peer in dial_targets {
        let id = FaceId(next_id);
        next_id += 1;
        summary.dialed += 1;
        // Index the static dial so a later reconcile does not re-dial an address
        // already seeded here (dedup includes still-in-flight opens).
        #[cfg(feature = "router-connect-reconcile")]
        dialed_targets.insert(id, peer);
        // R311y205 (transport-multilink) — a `max_links > 1` node dials with the
        // 0x4-negotiating variant so its outbound links aggregate (the pref tags
        // this link's traffic class); the `#[cfg(not)]` arm is the byte-identical
        // single-link seed.
        #[cfg(not(feature = "transport-multilink"))]
        opening.push(Box::pin(dial_face(
            id,
            peer,
            params.clone(),
            clock,
            tick_interval_ms,
        )));
        #[cfg(feature = "transport-multilink")]
        opening.push(if max_links > 1 {
            Box::pin(dial_face_multilink(
                id,
                peer,
                multilink_pref_for(id, qos),
                qos,
                multilink_priority_range(id),
                params.clone(),
                clock,
                tick_interval_ms,
            )) as OpenFuture
        } else {
            Box::pin(dial_face(id, peer, params.clone(), clock, tick_interval_ms)) as OpenFuture
        });
        // R311y212 — retain the dial endpoint so a partial-loss re-add can re-dial
        // this link (aggregating dials only; a single-link seed is not re-added
        // through this substrate). R311y219 — retain the pref AND the priority band
        // so a re-add restores both (a fresh-id band would flip on parity).
        #[cfg(feature = "transport-multilink")]
        if max_links > 1 {
            ml_dial_endpoints.insert(
                id,
                (
                    peer,
                    multilink_pref_for(id, qos),
                    multilink_priority_range(id),
                ),
            );
        }
    }

    loop {
        let step = tokio::select! {
            _ = &mut shutdown => Step::Shutdown,
            Some(opened) = opening.next() => Step::Opened(Box::new(opened)),
            Some(driven) = driving.next() => Step::Driven(driven),
            // The fast, non-blocking accept: one raw connection per iteration
            // (ws/tls SERVER handshake deferred to the spawned open future, so a
            // slow handshake never stalls this arm). R311y376 (Stage 3) — was
            // `accept_tcp_on(&listener)`; now scheme-keyed via `accept_raw`.
            accepted = listener.accept_raw() => Step::Accepted(accepted),
            _ = forwarder_tick(&mut tick_timer) => Step::Tick,
            intent = recv_dial_intent(&mut dial_intents) => Step::Dial(intent),
            item = recv_mcast_ingress(&mut mcast_ingress) => Step::McastIngress(item),
            members = recv_mcast_members(&mut mcast_members) => Step::McastMembers(members),
            subs = recv_mcast_group_subs(&mut mcast_group_subs) => Step::McastGroupSubs(subs),
            set = recv_reconcile(&mut reconcile) => Step::Reconcile(set),
        };

        match step {
            Step::Shutdown => break,

            Step::Opened(opened) => {
                let (id, peer, result) = *opened;
                match result {
                    Ok(opened) => {
                        // R311qi — capture the remote peer's zid (the routing
                        // identity) from the established session before `opened`
                        // is moved into the drive future.
                        let face = Face {
                            id,
                            peer,
                            peer_zid: opened.peer_zid(),
                        };
                        // R311y205 (transport-multilink) — aggregation JOIN. When
                        // `max_links > 1` and this established link's peer zid
                        // already has a logical session, aggregate this physical
                        // link onto that session's shared `SessionCore` (the wz
                        // analogue of zenoh's `init_existing_transport_unicast`
                        // add-link path) instead of registering a second face — the
                        // replacement for the `dedups_faces_by_zid` drop in the
                        // aggregating case. The FIRST link to a peer records the
                        // session and falls through to the normal register+drive
                        // (it IS the session's primary face). A zid-less link cannot
                        // aggregate, so it falls through and is held single-link.
                        #[cfg(feature = "transport-multilink")]
                        if max_links > 1 {
                            if let Some(peer_zid) = face.peer_zid.clone() {
                                // The session's STABLE shared-core handle (held in
                                // `ml_sessions`, alive across link deaths), used as
                                // join_link's primary arg — NOT a per-link entry that
                                // teardown removes, so a join after the original
                                // primary link died still resolves the session.
                                let existing = ml_sessions.get(&peer_zid).map(
                                    |(primary_id, _, core_handle)| {
                                        (*primary_id, core_handle.clone())
                                    },
                                );
                                if let Some((primary_id, core_handle)) = existing {
                                    // A second+ link to a held peer: try to aggregate.
                                    match join_link(&core_handle, &opened.actions, max_links) {
                                        JoinOutcome::Joined(joined) => {
                                            let live_links = core_handle.live_link_count();
                                            log::debug!(
                                                "multilink: aggregated link {} onto peer {:02x?} \
                                                 (live links now {})",
                                                id.0,
                                                peer_zid,
                                                live_links
                                            );
                                            // Surface the aggregation to the loop's
                                            // event consumer — a joined link never
                                            // reaches the FaceUp emit below (the arm
                                            // `continue`s), so this is the ONLY
                                            // on_event a caller sees for the join.
                                            on_event(&AcceptEvent::LinkAggregated {
                                                peer_zid: peer_zid.clone(),
                                                live_links,
                                            });
                                            ml_faces.insert(id, (peer_zid, joined.clone()));
                                            // R311y219b — tell the forwarder this
                                            // joined link's inbound (which arrives
                                            // tagged with its OWN id, never
                                            // `register`ed) maps to the PRIMARY
                                            // registered face, so a routing forwarder
                                            // delivers its data/control instead of
                                            // dropping it at the faces.get gate. A
                                            // no-op for observation-only forwarders.
                                            forwarder.register_joined(id, primary_id);
                                            // Drop its dial-address index — a joined
                                            // link is not a standalone reconnectable
                                            // dial (no-op for an accepted link).
                                            #[cfg(feature = "router-connect-reconcile")]
                                            dialed_targets.remove(&id);
                                            driving.push(Box::pin(drive_joined_face(
                                                face, opened, joined, forwarder,
                                            ))
                                                as DriveFuture<'_>);
                                        }
                                        JoinOutcome::OverLimit => {
                                            log::debug!(
                                                "multilink: link {} over max_links ({}) for peer \
                                                 {:02x?}; rejected MAX_LINKS",
                                                id.0,
                                                max_links,
                                                peer_zid
                                            );
                                            #[cfg(feature = "router-connect-reconcile")]
                                            dialed_targets.remove(&id);
                                            // R311y212 — a REJECTED dialed link is not
                                            // re-added; drop its retained endpoint so it
                                            // does not leak past the ml_rejected drain
                                            // (which `continue`s in Step::Driven before
                                            // the death-handler leak-guard is reached).
                                            ml_dial_endpoints.remove(&id);
                                            ml_rejected.insert(id);
                                            driving
                                                .push(Box::pin(drain_rejected_face(face, opened))
                                                    as DriveFuture<'_>);
                                        }
                                        JoinOutcome::InvalidPubkey => {
                                            log::debug!(
                                                "multilink: link {} pubkey mismatch for peer \
                                                 {:02x?}; rejected INVALID",
                                                id.0,
                                                peer_zid
                                            );
                                            #[cfg(feature = "router-connect-reconcile")]
                                            dialed_targets.remove(&id);
                                            // R311y212 — see the MAX_LINKS arm: drop the
                                            // rejected link's retained endpoint so it does
                                            // not leak past the ml_rejected drain.
                                            ml_dial_endpoints.remove(&id);
                                            ml_rejected.insert(id);
                                            driving
                                                .push(Box::pin(drain_rejected_face(face, opened))
                                                    as DriveFuture<'_>);
                                        }
                                    }
                                    continue;
                                }
                                // The FIRST link to this peer becomes the session's
                                // primary; record it (with a stable shared-core
                                // handle for future joins), then fall through to
                                // register it as the representative face.
                                ml_sessions.insert(
                                    peer_zid.clone(),
                                    (id, face.clone(), opened.actions.clone()),
                                );
                                ml_faces.insert(id, (peer_zid, opened.actions.clone()));
                            }
                        }
                        // Face-establishment zid-dedup, but ONLY when the forwarder
                        // keys routing state on the zid ([`FaceForwarder::dedups_faces_by_zid`]
                        // — the linkstate peer, whose graph self-edge is zid-keyed).
                        // For such a forwarder a second face to an already-held zid
                        // is a redundant link (a mutual `--connect`, a dial+accept
                        // to the same peer, or an autoconnect dial that raced one);
                        // dropping it keeps one face per peer, so the graph never
                        // gets two links for one zid and one face's teardown can't
                        // `remove_link`-prune the still-live peer. The pure acceptor
                        // / star router (FaceId-keyed) returns `false` and holds N
                        // faces regardless of zid (so two clients sharing a fixture
                        // zid are both held — Layer E3/E5). A zid-less face cannot be
                        // deduped, so it is held. zenoh's transport manager
                        // (`init_transport_unicast`) keeps one transport per zid for
                        // EVERY node; wz scopes it to the forwarders that need it.
                        if forwarder.dedups_faces_by_zid() {
                            if let Some(z) = &face.peer_zid {
                                if holds_zid(&faces, z) {
                                    log::debug!(
                                        "dropping redundant face {} to an already-held peer",
                                        id.0
                                    );
                                    // The dropped face never enters `faces`; drop its
                                    // dial-address index too so a later reconcile does
                                    // not treat the abandoned id as a live dial (no-op
                                    // for an accepted face, which is not indexed).
                                    #[cfg(feature = "router-connect-reconcile")]
                                    dialed_targets.remove(&id);
                                    continue;
                                }
                            }
                        }
                        faces.insert(id, face.peer_zid.clone());
                        summary.established += 1;
                        summary.peak_concurrent = summary.peak_concurrent.max(faces.len());
                        // Register the face's send seam BEFORE moving `opened`
                        // into the drive future, so a forwarder can route TO
                        // this face from the moment it is held.
                        forwarder.register(id, &opened.actions);
                        // `Face` is no longer `Copy` (it owns the zid), so clone
                        // it for the borrowed FaceUp event; the original moves
                        // into the drive future.
                        on_event(&AcceptEvent::FaceUp(face.clone()));
                        // R311y205 (transport-multilink) — box the drive future in
                        // an aggregating build so it shares `driving` with the
                        // joined / rejected drives; unboxed + byte-identical
                        // otherwise.
                        #[cfg(not(feature = "transport-multilink"))]
                        driving.push(drive_face(face, opened, forwarder));
                        #[cfg(feature = "transport-multilink")]
                        driving
                            .push(Box::pin(drive_face(face, opened, forwarder)) as DriveFuture<'_>);
                    }
                    Err(cause) => {
                        // R311y212 — a failed retained MULTILINK dial (a re-add or an
                        // initial aggregating dial that never connected) is
                        // re-scheduled: retry-until-success. Handled FIRST and
                        // mutually exclusive with the router-connect-reconcile redial
                        // below (a multilink dial handled here is removed from
                        // `ml_dial_endpoints`, and `ml_handled` gates the other arm),
                        // so a both-features build never double-dials one id.
                        #[cfg(feature = "transport-multilink")]
                        let ml_handled = if max_links > 1 {
                            if let Some((addr, pref, band)) = ml_dial_endpoints.remove(&id) {
                                schedule_multilink_redial(
                                    addr,
                                    pref,
                                    qos,
                                    band,
                                    &mut ml_dial_endpoints,
                                    &mut opening,
                                    &mut next_id,
                                    false,
                                    &params,
                                    clock,
                                    tick_interval_ms,
                                );
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        #[cfg(not(feature = "transport-multilink"))]
                        let ml_handled = false;
                        // Drop its dial-address index; if it was a still-DESIRED
                        // outbound dial, re-schedule with backoff (peer auto-reconnect,
                        // zenoh's `peer_connector_retry`). A failed ACCEPT is not
                        // indexed, so the `desired` gate is a no-op for it.
                        #[cfg(feature = "router-connect-reconcile")]
                        if !ml_handled {
                            if let Some(addr) = dialed_targets.remove(&id) {
                                schedule_redial(
                                    addr,
                                    &desired,
                                    &mut dialed_targets,
                                    &mut opening,
                                    &mut next_id,
                                    false,
                                    &params,
                                    clock,
                                    tick_interval_ms,
                                );
                            }
                        }
                        let _ = ml_handled;
                        on_event(&AcceptEvent::FaceFailed { id, peer, cause });
                    }
                }
            }

            Step::Driven((face, outcome)) => {
                // R311y205 (transport-multilink) — aggregation teardown. A rejected
                // (MAX_LINKS/INVALID) link finished draining its close: drop it
                // silently (it never entered `faces` nor the forwarder). Otherwise,
                // if this is a tracked aggregated link, remove it from the shared
                // set; the whole session tears down (deregister + FaceDown on its
                // primary face) only when the LAST link departs — while ≥1 link
                // remains the session survives and the forwarder keeps routing over
                // it (failover). A link not tracked here (a zid-less single-link
                // face) falls through to the normal single-link teardown below.
                #[cfg(feature = "transport-multilink")]
                if max_links > 1 {
                    if ml_rejected.remove(&face.id) {
                        continue;
                    }
                    if let Some((peer_zid, handle)) = ml_faces.remove(&face.id) {
                        // R311y219b — this link died: drop its joined->primary mapping
                        // so a later FaceId reuse cannot mis-resolve its successor's
                        // inbound onto a stale primary. A no-op for observation-only
                        // forwarders. This fires for BOTH a joined secondary (removes
                        // its real entry) AND the primary (which reaches here too, but
                        // is never a `joined_faces` KEY — it is `register`ed, not
                        // joined — so its removal is a harmless no-op).
                        forwarder.deregister_joined(face.id);
                        // R311y212 — drop this link's retained dial endpoint (Some
                        // iff THIS node dialed it); a partial-loss re-add re-inserts
                        // a fresh id, a total-collapse leaves it removed (no re-add).
                        let dead = ml_dial_endpoints.remove(&face.id);
                        // Remove THIS link from the shared aggregation set. For the
                        // primary its FSM `release_link` already did so (idempotent
                        // here); for a transplanted secondary that `release_link`
                        // touched only its throwaway core, so this is the effective
                        // removal from the shared core.
                        let remaining = handle.del_link(&handle.link);
                        if remaining == 0 {
                            if let Some((primary_id, primary_face, _core)) =
                                ml_sessions.remove(&peer_zid)
                            {
                                faces.remove(&primary_id);
                                #[cfg(feature = "router-connect-reconcile")]
                                dialed_targets.remove(&primary_id);
                                forwarder.deregister(primary_id);
                                on_event(&AcceptEvent::FaceDown(primary_face, outcome));
                            }
                        } else if let Some((addr, pref, band)) = dead {
                            // R311y212 — PARTIAL loss of a link THIS node DIALED:
                            // re-dial + re-JOIN it onto the surviving shared core so
                            // the aggregate returns to strength. The survivor is
                            // uninterrupted and the shared SN stays continuous (no
                            // core reset; `del_link` above freed a max_links slot, and
                            // the re-dial re-presents the OnceLock pubkey so join_link
                            // config-equality passes). The 1s backoff means the
                            // del_link always lands first.
                            log::debug!(
                                "multilink: dialed link {} left; peer {:02x?} survives on {} \
                                 link(s), re-adding",
                                face.id.0,
                                peer_zid,
                                remaining
                            );
                            schedule_multilink_redial(
                                addr,
                                pref,
                                qos,
                                band,
                                &mut ml_dial_endpoints,
                                &mut opening,
                                &mut next_id,
                                true,
                                &params,
                                clock,
                                tick_interval_ms,
                            );
                        } else {
                            // A dropped link this node ACCEPTED (no retained
                            // endpoint) — the peer owns its re-dial; just note the
                            // survival (failover holds on the survivor meanwhile).
                            log::debug!(
                                "multilink: accepted link {} left; peer {:02x?} session survives \
                                 on {} link(s)",
                                face.id.0,
                                peer_zid,
                                remaining
                            );
                        }
                        continue;
                    }
                }
                // R311y212 — leak-guard: a dialed multilink link that fell through
                // the JOIN branch (zid-less, or died before Establishing) is torn
                // down single-link here and never hit the `dead` removal above; drop
                // its retained endpoint so the map does not leak. A link that DID go
                // through the multilink branch `continue`d already (its entry removed
                // via `dead`), so this is a no-op for it.
                #[cfg(feature = "transport-multilink")]
                ml_dial_endpoints.remove(&face.id);
                faces.remove(&face.id);
                // A held face left. Drop its dial-address index; if it was a
                // still-DESIRED outbound dial, re-schedule it with backoff — the peer
                // auto-reconnect (zenoh's `closed_session` Peer/Router re-dial of a
                // dropped configured peer, `orchestrator.rs:1210`). A dropped ACCEPTED
                // face is not indexed, so `schedule_redial`'s gate is a no-op for it
                // (a router does not dial a peer that connected inbound).
                #[cfg(feature = "router-connect-reconcile")]
                if let Some(addr) = dialed_targets.remove(&face.id) {
                    // An established face dropped — announce the first re-dial at info
                    // (an operator-visible peer flap); its retries fall to debug.
                    schedule_redial(
                        addr,
                        &desired,
                        &mut dialed_targets,
                        &mut opening,
                        &mut next_id,
                        true,
                        &params,
                        clock,
                        tick_interval_ms,
                    );
                }
                forwarder.deregister(face.id);
                on_event(&AcceptEvent::FaceDown(face, outcome));
            }

            Step::Dial(intent) => {
                // A gossip-discovered, policy-admitted peer (the forwarder applied
                // the autoconnect role + zid gate at emit, A5b). Dial it as an
                // outbound face unless a face to it is already held (dedup) or no
                // locator is TCP-dialable. A dialed face flows through the SAME
                // `opening` -> `Step::Opened` path as a static dial, so it is
                // registered + held + zid-tracked identically.
                match dial_decision(&faces, &intent) {
                    DialDecision::Dial(addr) => {
                        let id = FaceId(next_id);
                        next_id += 1;
                        summary.dialed += 1;
                        // Index the gossip dial so a reconcile does not re-dial the
                        // same address (and vice-versa).
                        #[cfg(feature = "router-connect-reconcile")]
                        dialed_targets.insert(id, addr);
                        // R311y205 (transport-multilink) — a `max_links > 1` node
                        // dials the discovered peer with the 0x4-negotiating variant
                        // (aggregation), else the byte-identical single-link dial.
                        #[cfg(not(feature = "transport-multilink"))]
                        opening.push(Box::pin(dial_face(
                            id,
                            addr,
                            params.clone(),
                            clock,
                            tick_interval_ms,
                        )));
                        #[cfg(feature = "transport-multilink")]
                        opening.push(if max_links > 1 {
                            Box::pin(dial_face_multilink(
                                id,
                                addr,
                                multilink_pref_for(id, qos),
                                qos,
                                multilink_priority_range(id),
                                params.clone(),
                                clock,
                                tick_interval_ms,
                            )) as OpenFuture
                        } else {
                            Box::pin(dial_face(id, addr, params.clone(), clock, tick_interval_ms))
                                as OpenFuture
                        });
                        // R311y212 — retain the discovered-peer dial endpoint for
                        // partial-loss re-add (aggregating dials only). R311y219 —
                        // retain the pref AND the priority band.
                        #[cfg(feature = "transport-multilink")]
                        if max_links > 1 {
                            ml_dial_endpoints.insert(
                                id,
                                (
                                    addr,
                                    multilink_pref_for(id, qos),
                                    multilink_priority_range(id),
                                ),
                            );
                        }
                    }
                    DialDecision::AlreadyHeld => {
                        // R311y205 (transport-multilink) — the aggregation relax of
                        // the "already held -> skip" dedup: when `max_links > 1` and
                        // the held peer's session still has room, a second dialed
                        // link to it is opened to AGGREGATE rather than suppressed.
                        #[cfg(feature = "transport-multilink")]
                        if max_links > 1 {
                            let room = ml_sessions
                                .get(&intent.zid)
                                .map(|(_, _, core_handle)| core_handle.link_count() < max_links)
                                .unwrap_or(false);
                            if room {
                                if let Some(addr) = first_dialable_addr(&intent.locators) {
                                    let id = FaceId(next_id);
                                    next_id += 1;
                                    summary.dialed += 1;
                                    #[cfg(feature = "router-connect-reconcile")]
                                    dialed_targets.insert(id, addr);
                                    opening.push(Box::pin(dial_face_multilink(
                                        id,
                                        addr,
                                        multilink_pref_for(id, qos),
                                        qos,
                                        multilink_priority_range(id),
                                        params.clone(),
                                        clock,
                                        tick_interval_ms,
                                    ))
                                        as OpenFuture);
                                    // R311y212 — retain the aggregation-relax dial
                                    // endpoint for partial-loss re-add. R311y219 —
                                    // retain the pref AND the priority band.
                                    ml_dial_endpoints.insert(
                                        id,
                                        (
                                            addr,
                                            multilink_pref_for(id, qos),
                                            multilink_priority_range(id),
                                        ),
                                    );
                                    continue;
                                }
                            }
                        }
                        log::debug!(
                            "autoconnect: already hold a face to peer {:02x?}; \
                             skipping redundant dial",
                            intent.zid
                        );
                    }
                    DialDecision::NoLocator => log::debug!(
                        "autoconnect: discovered peer advertised no TCP-dialable \
                         locator ({:?}); skipping dial",
                        intent.locators
                    ),
                }
            }

            // A Push arrived on the multicast INGRESS group (the deferred
            // `mcast_faces` plane, I1) — route it into the forwarder as a
            // mcast-sourced Push (delivered to unicast subscribers, echo-guarded
            // off the groups). Folded here, on the loop's single task, so the
            // `!Send` forwarder is touched only from its own task. A no-ingress
            // loop never reaches here (the arm parks on a `None` channel). The
            // route call is `codec-push`-gated (the trait method takes `PushOwned`);
            // without `codec-push` the channel is always `None` so this is dead.
            Step::McastIngress(_item) => {
                #[cfg(feature = "codec-push")]
                forwarder.route_mcast_ingress(_item.priority, _item.reliable, &_item.push);
            }

            // The on-group ROUTER set changed — refresh the forwarder's DR
            // election candidates (I3b). No-op default for non-router forwarders;
            // the arm parks when there is no membership channel.
            Step::McastMembers(members) => {
                forwarder.set_mcast_group_members(&members);
            }

            // The on-group SUBSCRIBER aggregate changed — advertise/withdraw the
            // group's interest into the unicast mesh (sub plane, S2). No-op default
            // for non-router forwarders; the arm parks when there is no sub channel.
            Step::McastGroupSubs(subs) => {
                forwarder.set_mcast_group_subs(&subs);
            }

            // A runtime connect-list reconcile arrived (`router-connect-reconcile`):
            // dial each newly-listed connect endpoint not already being dialed. This
            // is the wz analogue of zenoh's `update_peers` Peer/Router branch
            // (`orchestrator.rs:449-467`) — ADD-ONLY. A removed endpoint is
            // deliberately NOT torn down (the Client close-removed branch `427-448`
            // is router-inapplicable: closing a live federation face on a static-list
            // edit would blackhole the mesh). Dedup is by ADDRESS against
            // `dialed_targets` (a config endpoint carries no zid until the handshake,
            // so the gossip `holds_zid` zid dedup cannot apply, and the address set
            // covers still-in-flight opens the zid set never would). The arm parks
            // when `reconcile` is `None`, so a non-router / feature-off loop never
            // reaches here; the body is `#[cfg]`-gated so a feature-off build compiles
            // none of the reconcile dial logic.
            Step::Reconcile(_desired_set) => {
                #[cfg(feature = "router-connect-reconcile")]
                {
                    // Adopt the new full desired connect-set: the peer auto-reconnect
                    // re-dial gate (`schedule_redial`) reads it, so an added endpoint
                    // is both dialed now AND reconnected if it later drops, and a
                    // removed endpoint stops being reconnected (its live face is NOT
                    // closed — the add-only / close-removed asymmetry).
                    desired = _desired_set.iter().copied().collect();
                    // The addresses already being dialed (in-flight or held) — dial
                    // only the desired endpoints NOT among them (the address dedup;
                    // `desired` is already a set, so there are no intra-request dups).
                    let already: std::collections::HashSet<SocketAddr> =
                        dialed_targets.values().copied().collect();
                    for addr in desired.iter().copied() {
                        if already.contains(&addr) {
                            continue;
                        }
                        let id = FaceId(next_id);
                        next_id += 1;
                        summary.dialed += 1;
                        dialed_targets.insert(id, addr);
                        log::debug!(
                            "reconcile: dialing newly-listed connect endpoint {addr} (face {})",
                            id.0
                        );
                        opening.push(Box::pin(dial_face(
                            id,
                            addr,
                            params.clone(),
                            clock,
                            tick_interval_ms,
                        )));
                    }
                }
            }

            Step::Accepted(Ok((accepted, peer))) => {
                // Slice B — the mesh accept loop holds a face per accepted peer
                // keyed by its handshake zid, so an IP peer AND a mesh-capable
                // non-IP peer (unixsock / vsock / unixpipe — each a genuine per-peer
                // stream accept) are all held as faces; `peer` (an `AcceptedPeer`)
                // is threaded straight into the open future as a log/event tag. A
                // NON-mesh-capable acceptor is rejected here. R311y401's quic is the
                // first `false` from `AcceptedLink::supports_mesh_multi_peer`, but
                // under the SHIPPED callers this arm still fires for no transport: a
                // `--router`/`--peer quic/` is rejected EARLIER at bind cert-absence
                // (the mesh callers — runner.rs router / pico session.rs — thread no
                // quic cert), so a quic `AcceptedLink` reaches here only via a
                // direct-API caller that bound a quic listener WITH a cert. This arm
                // stays the runtime backstop; its `BoundListener` twin is the
                // bind-time first line.
                if !accepted.supports_mesh_multi_peer() {
                    on_event(&AcceptEvent::AcceptError(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "the mesh accept loop cannot hold a {peer} face: its acceptor is \
                             single-connection, not multi-peer — dropping (the one-shot \
                             `accept_bound` path serves it)"
                        ),
                    )));
                    drop(accepted);
                    // Throttle before re-arming, the same guard the
                    // `Step::Accepted(Err)` arm applies: a hypothetical future
                    // non-mesh acceptor that returned immediately (as the retired
                    // R311y380 non-blocking unixpipe accept did) would otherwise
                    // reject-and-re-arm at CPU speed without this sleep. Bounds the
                    // mis-config to one reject per throttle interval, matching
                    // zenoh's accept_task parity. (Reached today only by a direct-API
                    // quic caller; the shipped `--router quic/` path is rejected at
                    // bind cert-absence first — kept as the runtime backstop.)
                    clock.sleep(ACCEPT_ERROR_THROTTLE_MS).await;
                    continue;
                }
                let id = FaceId(next_id);
                next_id += 1;
                summary.accepted += 1;
                // R311y205 (transport-multilink) — a `max_links > 1` acceptor opens
                // with the 0x4-negotiating variant so an inbound peer's second link
                // can aggregate (the ext captures its ephemeral pubkey); the
                // `#[cfg(not)]` arm is the byte-identical single-link accept.
                #[cfg(not(feature = "transport-multilink"))]
                opening.push(Box::pin(open_face(
                    id,
                    peer,
                    accepted,
                    params.clone(),
                    clock,
                    tick_interval_ms,
                )));
                #[cfg(feature = "transport-multilink")]
                opening.push(if max_links > 1 {
                    Box::pin(open_face_multilink(
                        id,
                        peer,
                        accepted,
                        multilink_pref_for(id, qos),
                        qos,
                        multilink_priority_range(id),
                        params.clone(),
                        clock,
                        tick_interval_ms,
                    )) as OpenFuture
                } else {
                    Box::pin(open_face(
                        id,
                        peer,
                        accepted,
                        params.clone(),
                        clock,
                        tick_interval_ms,
                    )) as OpenFuture
                });
            }

            Step::Accepted(Err(e)) => {
                on_event(&AcceptEvent::AcceptError(e));
                // Throttle before re-arming: a persistent accept error (EMFILE)
                // would otherwise hot-spin the loop. zenoh's accept_task parity.
                clock.sleep(ACCEPT_ERROR_THROTTLE_MS).await;
            }

            // The forwarder's periodic cadence elapsed — let it do its
            // time-driven control-plane work (the linkstate peer floods its own
            // link-state). A no-timer forwarder never reaches here.
            Step::Tick => forwarder.tick(),
        }
    }

    // Stop accepting; drop in-flight opens + drives (sockets close, writer tasks
    // drain). Faces table cleared — the summary already captured the high-water
    // mark.
    drop(opening);
    drop(driving);
    faces.clear();
    summary
}

/// Bind-once, accept-and-hold-N: the multi-peer accept loop (the
/// `routing-router` foundation).
///
/// Loops accepting inbound links on the already-bound [`BoundListener`] (the
/// whole stream family — tcp/ws/tls — since R311y376 Stage 3, was tcp-only); each
/// accepted link is opened to Established (concurrently, so one peer's handshake
/// never blocks accepting the next — the ws/tls transport handshake is part of
/// that per-face open, off the accept path) and then driven as a held *face*
/// until the peer closes. A thin entry over [`face_drive_loop`] with NO outbound
/// dials — every face comes from accepting. `on_event` observes each
/// [`AcceptEvent`]; the loop runs until `shutdown` resolves, then returns its
/// [`AcceptLoopSummary`].
pub async fn accept_loop<S, F>(
    listener: BoundListener,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    on_event: F,
    forwarder: &dyn FaceForwarder,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    face_drive_loop(
        FaceSources {
            listener,
            dial_targets: Vec::new(),
            // accept-only: no static dials and no autoconnect dial-intent stream.
            dial_intents: None,
            // accept-only: no multicast ingress plane.
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            // accept-only: no runtime connect-list reconcile.
            reconcile: None,
            // accept-only: single-link (a multilink node aggregates via `peer_loop`,
            // the full mesh entry that carries `max_links`); byte-identical to today.
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-multilink")]
            qos: false,
        },
        params,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        forwarder,
    )
    .await
}

/// Bind-once, dial-configured-peers, accept-inbound, hold-all: the peer-mesh
/// node (the `routing-peer` foundation, R311qg).
///
/// The dial + accept generalisation of [`accept_loop`]: a peer both DIALS each
/// [`FaceSources::dial_targets`] address (its outbound mesh links) AND accepts
/// inbound peers on [`FaceSources::listener`], holding every resulting face in
/// one set. The only difference from `accept_loop` is the seeded outbound dials;
/// both delegate to the shared [`face_drive_loop`] core, so accept-side
/// robustness (one peer's handshake never blocks another, a failed open is
/// isolated as `FaceFailed`) covers a dialed face too — an unreachable dial
/// target surfaces as `FaceFailed` and the mesh keeps forming.
///
/// Hold-only (this atom): a held mesh face routes nothing yet. Mesh forwarding
/// needs zid-keyed loop suppression (a Put must not cycle a ring, which the
/// star router's `src_id != dst` face skip does not prevent), the next
/// `routing-peer` atom. So `peer_loop` takes the same `forwarder` seam as
/// `accept_loop`; a hold-only node passes [`NoOpForwarder`].
#[cfg(feature = "routing-peer")]
pub async fn peer_loop<S, F>(
    sources: FaceSources,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    on_event: F,
    forwarder: &dyn FaceForwarder,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    face_drive_loop(
        sources,
        params,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        forwarder,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::future::join_all;
    use tokio::net::TcpStream;
    use tokio::sync::watch;

    use crate::link_pipeline::bind_tcp;
    use crate::session_open::{initiate_and_open_session, DEFAULT_OPEN_TICK_MS};
    use wz_runtime_tokio_test_support::fixture_session_init_params;

    // ── R311y219 per-face priority-band + reliability-axis policy ──────────

    /// `multilink_priority_range` splits the 8 priorities into two NON-overlapping
    /// bands that JOINTLY cover the whole `Control..=Background` scale, so every
    /// priority is a `full` match on exactly one link (deterministic route). Even
    /// [`FaceId`] -> HIGH `[Control..=InteractiveLow]`, odd -> LOW
    /// `[DataHigh..=Background]`.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn multilink_priority_range_splits_high_low_by_parity_and_covers_all() {
        use wz_session_core::qos::Priority;
        assert_eq!(
            multilink_priority_range(FaceId(0)),
            (Priority::Control, Priority::InteractiveLow),
            "even FaceId -> HIGH band"
        );
        assert_eq!(
            multilink_priority_range(FaceId(1)),
            (Priority::DataHigh, Priority::Background),
            "odd FaceId -> LOW band"
        );
        // Non-overlapping AND jointly covering 0..=7: the HIGH band ends exactly one
        // below where the LOW band begins, so every priority lands in exactly one.
        let (hi_lo, hi_hi) = multilink_priority_range(FaceId(0));
        let (lo_lo, lo_hi) = multilink_priority_range(FaceId(1));
        assert_eq!(
            hi_lo,
            Priority::Control,
            "HIGH band starts at the top priority"
        );
        assert_eq!(
            lo_hi,
            Priority::Background,
            "LOW band ends at the bottom priority"
        );
        assert_eq!(
            hi_hi.wire_byte() + 1,
            lo_lo.wire_byte(),
            "the two bands are contiguous + non-overlapping (jointly cover 0..=7)"
        );
    }

    /// `multilink_pref_for` chooses the segregation AXIS: with QoS ON every link is
    /// UNIFORM Reliable (so the priority band is the `select_link` discriminant),
    /// with QoS OFF it keeps the y205 even/odd reliability spread. A build WITHOUT
    /// `transport-qos` never applies a band, so the qos bool is inert there.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn multilink_pref_for_uniform_reliable_iff_qos() {
        // QoS OFF: the y205 even/odd reliability spread (matches multilink_pref).
        assert_eq!(
            multilink_pref_for(FaceId(0), false),
            LinkReliabilityPref::Reliable
        );
        assert_eq!(
            multilink_pref_for(FaceId(1), false),
            LinkReliabilityPref::BestEffort
        );
        assert_eq!(
            multilink_pref_for(FaceId(0), false),
            multilink_pref(FaceId(0))
        );
        assert_eq!(
            multilink_pref_for(FaceId(1), false),
            multilink_pref(FaceId(1))
        );
        // QoS ON: uniform Reliable (priority is the discriminant) — but ONLY when
        // transport-qos compiles (else the band is never applied, so qos is inert).
        #[cfg(feature = "transport-qos")]
        {
            assert_eq!(
                multilink_pref_for(FaceId(0), true),
                LinkReliabilityPref::Reliable
            );
            assert_eq!(
                multilink_pref_for(FaceId(1), true),
                LinkReliabilityPref::Reliable,
                "with qos ON the odd link is Reliable too (uniform), not BestEffort"
            );
        }
        #[cfg(not(feature = "transport-qos"))]
        assert_eq!(
            multilink_pref_for(FaceId(1), true),
            LinkReliabilityPref::BestEffort,
            "without transport-qos the qos bool is inert: even/odd spread holds"
        );
    }

    // ── shared fixtures ────────────────────────────────────────────────

    async fn bind_loopback() -> (BoundListener, SocketAddr) {
        let listener = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"), None)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        (BoundListener::Tcp(listener), addr)
    }

    /// One acceptor node identity (a distinct zid from the initiators).
    fn acceptor_params() -> SessionInitParams {
        let mut p = fixture_session_init_params();
        p.zid = vec![0xAA; 4];
        p
    }

    /// The shutdown future: resolves when `go` flips true (level-triggered
    /// `watch`, not edge-triggered `Notify` — a receiver cannot miss the wakeup).
    async fn shutdown_on(mut go: watch::Receiver<bool>) {
        let _ = go.wait_for(|&v| v).await;
    }

    #[test]
    fn dial_decision_dedups_held_peers_and_requires_a_tcp_locator() {
        let acc = || DialIntent {
            zid: vec![0xAA; 4],
            locators: vec!["tcp/127.0.0.1:7447".into()],
        };
        // No held face + a tcp locator -> dial that address.
        let empty: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
        assert!(matches!(
            dial_decision(&empty, &acc()),
            DialDecision::Dial(a) if a == "127.0.0.1:7447".parse().unwrap()
        ));
        // A held face to the peer's zid -> skip (the dedup), even with a valid
        // locator. A zid-less held face (None) matches no peer.
        let mut held: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
        held.insert(FaceId(0), Some(vec![0xAA; 4]));
        held.insert(FaceId(1), None);
        assert!(holds_zid(&held, &[0xAA; 4]));
        assert!(!holds_zid(&held, &[0xBB; 4]), "a different zid is not held");
        assert!(matches!(
            dial_decision(&held, &acc()),
            DialDecision::AlreadyHeld
        ));
        // No tcp locator (tls / non-numeric) -> skip.
        let no_tcp = DialIntent {
            zid: vec![0xBB; 4],
            locators: vec!["tls/127.0.0.1:7447".into(), "nonsense".into()],
        };
        assert!(matches!(
            dial_decision(&empty, &no_tcp),
            DialDecision::NoLocator
        ));
        // first_dialable_addr picks the first TCP locator past non-tcp ones.
        assert_eq!(
            first_dialable_addr(&["udp/1.2.3.4:7447".into(), "tcp/9.9.9.9:7447".into()]),
            Some("9.9.9.9:7447".parse().unwrap())
        );
        assert_eq!(first_dialable_addr(&[]), None);
    }

    /// An initiator that dials, opens to Established, then HOLDS (keeps driving so
    /// keepalive flows and the acceptor's face does not lease out) until `go`
    /// flips, then drains via the same [`OpenedSession::drain_to_close`] SSOT the
    /// production `drive_face` uses. A peer-side close also releases it (the drive
    /// arm of the `select!`).
    async fn idle_initiator(addr: SocketAddr, zid: u8, mut go: watch::Receiver<bool>) {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = initiate_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established");

        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&v| v) => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound, &opened.actions, &mut opened.engine,
                None, &opened.clock, &timeouts, |_e| {},
            ) => {}
        }
        opened.drain_to_close().await;
    }

    /// The UDP twin of [`idle_initiator`] (R311y382): dials `udp/<listen>` through
    /// the scheme-keyed [`connect_and_open_session`] SSOT (which `dial_udp`s an
    /// ephemeral socket and drives the handshake), holds until `go`, then drains.
    /// Each initiator binds a distinct ephemeral source port, so the acceptor's
    /// demux keys a distinct face per initiator — the multi-peer property the F2
    /// discriminator asserts.
    #[cfg(feature = "transport-link-udp")]
    async fn udp_idle_initiator(listen: SocketAddr, zid: u8, mut go: watch::Receiver<bool>) {
        use crate::session_open::{connect_and_open_session, DialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator = parse_any_locator(&format!("udp/{listen}")).expect("parse udp locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("udp initiator reaches Established");

        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&v| v) => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound, &opened.actions, &mut opened.engine,
                None, &opened.clock, &timeouts, |_e| {},
            ) => {}
        }
        opened.drain_to_close().await;
    }

    /// The unixsock twin of [`udp_idle_initiator`] (Slice B): dials
    /// `unixsock-stream/<path>` through the scheme-keyed
    /// [`connect_and_open_session`] SSOT, holds until `go`, then drains. Each
    /// initiator is a distinct client on the SAME listener path, so the acceptor
    /// `accept()`s a distinct per-peer `UnixStream` per initiator — the genuine
    /// multi-peer property the non-IP ENABLEMENT discriminator asserts (unlike
    /// UDP's src-keyed demux, unixsock has a real per-connection stream accept).
    #[cfg(feature = "transport-link-unixsock")]
    async fn unixsock_idle_initiator(path: String, zid: u8, mut go: watch::Receiver<bool>) {
        use crate::session_open::{connect_and_open_session, DialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator =
            parse_any_locator(&format!("unixsock-stream/{path}")).expect("parse unixsock locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("unixsock initiator reaches Established");

        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&v| v) => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound, &opened.actions, &mut opened.engine,
                None, &opened.clock, &timeouts, |_e| {},
            ) => {}
        }
        opened.drain_to_close().await;
    }

    /// The unixpipe twin of [`unixsock_idle_initiator`] (R311y392): dials a
    /// `unixpipe/<base>` listener through the multi-client invitation handshake,
    /// reaches Established, and idles until `go`. The multi-client acceptor gives
    /// each initiator a DISTINCT dedicated FIFO pair, so N of these are held as N
    /// ZID-keyed mesh faces at once — the property the mesh-join discriminator
    /// asserts.
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    async fn unixpipe_idle_initiator(base: String, zid: u8, mut go: watch::Receiver<bool>) {
        use crate::session_open::{connect_and_open_session, DialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator =
            parse_any_locator(&format!("unixpipe/{base}")).expect("parse unixpipe locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("unixpipe initiator reaches Established");

        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&v| v) => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound, &opened.actions, &mut opened.engine,
                None, &opened.clock, &timeouts, |_e| {},
            ) => {}
        }
        opened.drain_to_close().await;
    }

    // ── tests ──────────────────────────────────────────────────────────

    /// The accept loop accepts N peers and holds all N faces concurrently
    /// (peak == N) — the core property that separates the multi-peer loop from
    /// the one-shot accept. N is larger than two to exercise the dynamic
    /// `FuturesUnordered` hold meaningfully. All N+1 futures are `!Send`, so they
    /// run on the one task via `join!` + `join_all`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_loop_holds_n_concurrent_peers() {
        const N: usize = 6;
        let (listener, addr) = bind_loopback().await;

        // `go` flips when the Nth face is up: it ends the acceptor AND releases
        // every initiator, so all N are held simultaneously first.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::FaceUp(_) = event {
                    if up.fetch_add(1, SeqCst) + 1 == N {
                        let _ = go_tx.send(true);
                    }
                }
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators = (0..N).map(|i| idle_initiator(addr, (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer accept completes within 20s");

        assert_eq!(summary.accepted, N, "accepted all N peers");
        assert_eq!(summary.established, N, "all N reached Established");
        assert_eq!(
            summary.peak_concurrent, N,
            "held all N faces simultaneously (high-water mark)"
        );
    }

    /// R311y382 — the F2 DISCRIMINATOR: the demux holds N concurrent UDP faces off
    /// ONE listen socket, retiring the single-shot model's perpetual throttle. Two
    /// initiators (distinct ephemeral source ports) dial one `udp/..` listener
    /// through the mesh accept loop; the demux keys a distinct face per source, so
    /// both reach Established and are held at once (peak_concurrent == 2) with ZERO
    /// `AcceptError`. Under the superseded single-shot model the first accept
    /// `take`s the socket, the second `accept_raw` `Err`s every interval (the
    /// throttle storm) AND the second initiator's datagrams cross-talk into the
    /// first face, so only ONE face ever forms — `go` never flips and the test
    /// times out (RED). NON-FLAKY: loopback UDP is lossless, so two clean
    /// handshakes are deterministic (the same assumption udp_seam_e2e /
    /// accept_loop_holds_n_concurrent_peers rely on). [[feedback-no-flaky-ever]]
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_udp_peers() {
        use crate::session_open::bind_endpoint;
        const N: usize = 2;
        let listener = bind_endpoint("udp/127.0.0.1:0")
            .await
            .expect("bind a udp demux listener");
        let addr = listener.local_addr().expect("udp listener addr");

        // `go` flips when the Nth face is up: it ends the acceptor AND releases
        // both initiators, so both are held simultaneously first.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let rejects = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let go_tx = go_tx.clone();
            let rejects = rejects.clone();
            move |event: &AcceptEvent| match event {
                AcceptEvent::FaceUp(_) => {
                    if up.fetch_add(1, SeqCst) + 1 == N {
                        let _ = go_tx.send(true);
                    }
                }
                AcceptEvent::AcceptError(_) => {
                    rejects.fetch_add(1, SeqCst);
                }
                _ => {}
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators = (0..N).map(|i| udp_idle_initiator(addr, (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer udp accept completes within 20s (single-shot would hold only 1 face)");

        assert_eq!(
            summary.accepted, N,
            "accepted both udp peers (demux, not the single-shot 1)"
        );
        assert_eq!(summary.established, N, "both udp peers reached Established");
        assert_eq!(
            summary.peak_concurrent, N,
            "held both udp faces off ONE listen socket simultaneously (F2 retired)"
        );
        assert_eq!(
            rejects.load(SeqCst),
            0,
            "no AcceptError throttle storm: accept_raw pends between srcs, never Errs (F2 retired)"
        );
    }

    /// Slice B — the non-IP mesh ENABLEMENT discriminator: two unixsock clients
    /// connect to ONE `unixsock-stream/<path>` listener through the mesh accept
    /// loop and BOTH are held as ZID-keyed faces at once (peak_concurrent == 2),
    /// with ZERO AcceptError. unixsock is a genuine per-peer stream accept (one
    /// `UnixListener`, one `accept()` per client), so this is the direct unixsock
    /// twin of [`accept_loop_holds_n_concurrent_peers`] (TCP). Under the PRE-Slice-B
    /// loop every `AcceptedPeer::NonIp` is rejected in the `Step::Accepted` arm,
    /// which `drop`s the accepted link — so each unixsock initiator's handshake is
    /// torn down (`LinkLost`) and its "reaches Established" expect panics at once (a
    /// fast RED); either way pre-Slice-B holds ZERO faces, never two. NON-FLAKY: a
    /// loopback unix socket is lossless + in-order, so two
    /// clean handshakes are deterministic (the assumption the udp/tcp N-peer
    /// siblings share). [[feedback-no-flaky-ever]]
    #[cfg(feature = "transport-link-unixsock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_unixsock_peers() {
        use crate::session_open::bind_endpoint;
        const N: usize = 2;
        let path = std::env::temp_dir()
            .join(format!("wz-unixsock-mesh-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Bind fresh: a stale socket file from a crashed prior run would EADDRINUSE.
        let _ = std::fs::remove_file(&path);
        let listener = bind_endpoint(&format!("unixsock-stream/{path}"))
            .await
            .expect("bind a unixsock listener");

        // `go` flips when the Nth face is up: it ends the acceptor AND releases
        // both initiators, so both are held simultaneously first.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let rejects = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let go_tx = go_tx.clone();
            let rejects = rejects.clone();
            move |event: &AcceptEvent| match event {
                AcceptEvent::FaceUp(_) => {
                    if up.fetch_add(1, SeqCst) + 1 == N {
                        let _ = go_tx.send(true);
                    }
                }
                AcceptEvent::AcceptError(_) => {
                    rejects.fetch_add(1, SeqCst);
                }
                _ => {}
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators =
            (0..N).map(|i| unixsock_idle_initiator(path.clone(), (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer unixsock accept completes within 20s (pre-Slice-B rejects all NonIp)");

        assert_eq!(
            summary.accepted, N,
            "accepted both unixsock peers (a genuine per-peer accept, not a NonIp reject)"
        );
        assert_eq!(
            summary.established, N,
            "both unixsock peers reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, N,
            "held both unixsock faces simultaneously (non-IP ZID-keyed mesh face)"
        );
        assert_eq!(
            rejects.load(SeqCst),
            0,
            "no NonIp reject: unixsock is a mesh-capable non-IP acceptor"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// R311y392 — the MESH-JOIN discriminator (replaces the retired R311y380
    /// `mesh_accept_loop_throttles_a_nonblocking_unixpipe_reject`, whose whole
    /// premise — a NON-mesh unixpipe reject-throttle — the multi-client acceptor
    /// dissolved). Two initiators dial ONE `unixpipe/<base>` listener through the
    /// invitation handshake and BOTH are held as ZID-keyed faces at once
    /// (peak_concurrent == 2), with ZERO AcceptError — the direct unixpipe twin of
    /// [`mesh_accept_loop_holds_two_unixsock_peers`]. RED on the OLD
    /// single-connection acceptor: it returned one link immediately with no dialer
    /// (a NonIp reject) and could not serve a second client, so peak was 0/1 and
    /// `accepted != 2`. NON-FLAKY: a loopback FIFO pair is lossless + in-order, so
    /// two clean handshakes are deterministic (the unixsock/udp N-peer siblings'
    /// assumption). [[feedback-no-flaky-ever]]
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_unixpipe_peers() {
        use crate::session_open::bind_endpoint;
        const N: usize = 2;
        let base = std::env::temp_dir()
            .join(format!("wz-unixpipe-mesh-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let listener = bind_endpoint(&format!("unixpipe/{base}"))
            .await
            .expect("bind a unixpipe listener");

        // `go` flips when the Nth face is up: it ends the acceptor AND releases
        // both initiators, so both are held simultaneously first.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let rejects = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let go_tx = go_tx.clone();
            let rejects = rejects.clone();
            move |event: &AcceptEvent| match event {
                AcceptEvent::FaceUp(_) => {
                    if up.fetch_add(1, SeqCst) + 1 == N {
                        let _ = go_tx.send(true);
                    }
                }
                AcceptEvent::AcceptError(_) => {
                    rejects.fetch_add(1, SeqCst);
                }
                _ => {}
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators =
            (0..N).map(|i| unixpipe_idle_initiator(base.clone(), (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer unixpipe accept completes within 20s");

        assert_eq!(
            summary.accepted, N,
            "accepted both unixpipe peers (a genuine per-peer dedicated-pipe accept)"
        );
        assert_eq!(
            summary.established, N,
            "both unixpipe peers reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, N,
            "held both unixpipe faces simultaneously (non-IP ZID-keyed mesh face)"
        );
        assert_eq!(
            rejects.load(SeqCst),
            0,
            "no NonIp reject: unixpipe is a mesh-capable non-IP acceptor (R311y392)"
        );

        let _ = std::fs::remove_file(format!("{base}_uplink"));
    }

    /// Slice B — pins the loop's mesh-capability BACKSTOP predicate
    /// ([`AcceptedLink::supports_mesh_multi_peer`], consulted in the
    /// `Step::Accepted` arm) at the TRUE polarity: tcp is mesh-capable. The match
    /// is wildcard-free, so a NEW `AcceptedLink` variant forces a decision at
    /// compile time; this pins the value for tcp (a representative `true`). Since
    /// R311y392 the stream + same-host families are mesh-capable (R311y401's quic is
    /// the first `false`; its BIND twin is pinned by `boundlistener_quic_is_not_mesh_capable`,
    /// and this AcceptedLink polarity is compiler-forced by the wildcard-free match) — `acceptedlink_unixpipe_is_mesh_capable`
    /// pins the once-`false` unixpipe arm at its new `true` polarity.
    #[tokio::test]
    async fn acceptedlink_tcp_is_mesh_capable() {
        use crate::session_open::AcceptedLink;
        let listener = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"), None)
            .await
            .expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");
        // A loopback accept yields a real TcpStream for the AcceptedLink::Tcp arm.
        let (accepted_stream, _client) = tokio::join!(
            async { listener.accept().await.expect("accept").0 },
            async { TcpStream::connect(addr).await.expect("connect") },
        );
        let accepted = AcceptedLink::Tcp(accepted_stream);
        assert!(
            accepted.supports_mesh_multi_peer(),
            "tcp accept is mesh-capable"
        );
    }

    /// R311y392 — the once-`false` unixpipe arm now pins at `true`: an accepted
    /// unixpipe link (produced by the multi-client acceptor task after a client's
    /// invitation handshake) IS mesh-capable, so the `Step::Accepted` backstop no
    /// longer rejects it. Replaces the retired `acceptedlink_unixpipe_is_not_mesh_capable`.
    /// Drives one real client through `dial_unixpipe` so the acceptor yields a
    /// genuine `AcceptedLink::Unixpipe` (there is no standalone open any more — the
    /// link only exists after a handshake).
    #[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn acceptedlink_unixpipe_is_mesh_capable() {
        use crate::session_open::AcceptedLink;
        use crate::unixpipe_pipeline::{bind_unixpipe, dial_unixpipe};
        let base = std::env::temp_dir()
            .join(format!("wz-unixpipe-cap-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let mut acc = bind_unixpipe(&base)
            .await
            .expect("bind the unixpipe acceptor");
        // Drive one client through the invitation handshake; the acceptor task
        // yields the accepted listener-side link.
        let dialer = tokio::spawn({
            let base = base.clone();
            async move { dial_unixpipe(&base).await }
        });
        let link = acc.recv_new_link().await.expect("accept one client");
        let _client = dialer.await.unwrap().expect("dial completes");
        let accepted = AcceptedLink::Unixpipe(link);
        assert!(
            accepted.supports_mesh_multi_peer(),
            "unixpipe accept is mesh-capable (multi-client acceptor, R311y392)"
        );
        drop(acc);
    }

    /// A peer that connects then closes WITHOUT handshaking surfaces as
    /// `FaceFailed` and is isolated: the loop keeps accepting and still brings the
    /// well-behaved peers to a full peak. This is the load-bearing robustness
    /// property — a router that died when one client half-opened a connection
    /// would be a DoS vector.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_loop_isolates_a_failed_handshake_and_keeps_accepting() {
        const GOOD: usize = 3;
        let (listener, addr) = bind_loopback().await;

        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let failed = failed.clone();
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| {
                match event {
                    AcceptEvent::FaceUp(_) => {
                        up.fetch_add(1, SeqCst);
                    }
                    AcceptEvent::FaceFailed { .. } => {
                        failed.fetch_add(1, SeqCst);
                    }
                    _ => {}
                }
                // Release only once the good peers are all up AND the bad peer
                // has surfaced as FaceFailed — so the failure is observed, not
                // dropped by an early shutdown.
                if up.load(SeqCst) >= GOOD && failed.load(SeqCst) >= 1 {
                    let _ = go_tx.send(true);
                }
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );

        // Bad peer: connect, then drop the socket before sending InitSyn — the
        // acceptor reads EOF mid-handshake and the open returns Err (fast, no
        // wait on the 1s accept deadline).
        let bad = async move {
            let s = TcpStream::connect(addr).await.expect("bad peer connect");
            drop(s);
        };
        let good = (0..GOOD).map(|i| idle_initiator(addr, (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _, _) = tokio::join!(acceptor, bad, join_all(good));
            summary
        })
        .await
        .expect("failed-handshake isolation completes within 20s");

        assert_eq!(
            summary.accepted,
            GOOD + 1,
            "accepted the good peers + the bad one"
        );
        assert_eq!(
            summary.established, GOOD,
            "only the good peers reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, GOOD,
            "held all good faces; the bad peer never entered the table"
        );
        assert!(
            failed.load(SeqCst) >= 1,
            "the bad peer surfaced as FaceFailed"
        );
    }

    /// A held face whose peer closes WHILE its siblings stay up surfaces as
    /// `FaceDown` and is evicted from the faces table, and the loop keeps running.
    /// This is the inverse of the hold property — a held-set that only ever grows
    /// would not prove the table EVICTS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_loop_evicts_a_face_that_leaves_while_siblings_hold() {
        const N: usize = 3;
        let (listener, addr) = bind_loopback().await;

        // Two stages: `release_early` frees ONE initiator once all N are up;
        // `shutdown` then fires after that face's FaceDown is observed.
        let (early_tx, early_rx) = watch::channel(false);
        let (shut_tx, shut_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let down = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let down = down.clone();
            let early_tx = early_tx.clone();
            let shut_tx = shut_tx.clone();
            // The `fetch_add` runs in the guard (every event counts); the body
            // fires only at the threshold — a non-matching guard falls to `_`.
            move |event: &AcceptEvent| match event {
                // all up → free the early initiator
                AcceptEvent::FaceUp(_) if up.fetch_add(1, SeqCst) + 1 == N => {
                    let _ = early_tx.send(true);
                }
                // first eviction → end the loop
                AcceptEvent::FaceDown(..) if down.fetch_add(1, SeqCst) + 1 == 1 => {
                    let _ = shut_tx.send(true);
                }
                _ => {}
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(shut_rx.clone()),
            on_event,
            &NoOpForwarder,
        );

        // The early peer releases (closes) once all N are up; the two holders
        // stay up until shutdown, so the eviction happens under live concurrency.
        let early = idle_initiator(addr, 0x01, early_rx.clone());
        let hold1 = idle_initiator(addr, 0x02, shut_rx.clone());
        let hold2 = idle_initiator(addr, 0x03, shut_rx.clone());

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _, _, _) = tokio::join!(acceptor, early, hold1, hold2);
            summary
        })
        .await
        .expect("mid-life eviction completes within 20s");

        assert_eq!(summary.established, N, "all N reached Established");
        assert_eq!(
            summary.peak_concurrent, N,
            "all N were held at once before the early one left"
        );
        assert!(
            down.load(SeqCst) >= 1,
            "the early face left via FaceDown while siblings held"
        );
    }

    /// Shutdown while a handshake is still in flight (the `opening` set is
    /// non-empty) returns promptly and leaks nothing: `drop(opening)` cancels the
    /// in-flight open, the socket closes. A silent peer (connects, never sends
    /// InitSyn) sits in `opening`; a fixed-delay shutdown fires well inside the
    /// 1s accept deadline, so the open is mid-flight when the loop tears down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_loop_shuts_down_cleanly_with_a_handshake_in_flight() {
        let (listener, addr) = bind_loopback().await;

        // Silent peer: connects and holds the socket open without sending InitSyn,
        // so its open_face stays pending in `opening`.
        let silent = async move {
            let s = TcpStream::connect(addr).await.expect("silent peer connect");
            tokio::time::sleep(Duration::from_millis(400)).await;
            drop(s);
        };
        // Shutdown after the acceptor has surely accepted the silent peer (200ms
        // >> loopback accept latency) but well before its 1s accept deadline.
        let shutdown = tokio::time::sleep(Duration::from_millis(200));
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown,
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        );

        let summary = tokio::time::timeout(Duration::from_secs(10), async {
            let (summary, _) = tokio::join!(acceptor, silent);
            summary
        })
        .await
        .expect("shutdown with an in-flight handshake completes promptly");

        assert_eq!(summary.accepted, 1, "accepted the silent peer");
        assert_eq!(
            summary.established, 0,
            "it never established (shutdown fired mid-handshake)"
        );
        assert_eq!(summary.peak_concurrent, 0, "no face was ever held");
    }

    /// R311qi — a held face carries the remote peer's zid, captured from the
    /// handshake (the acceptor learns the initiator's announced zid from its
    /// InitSyn) and surfaced on the `FaceUp` event — the routing identity a
    /// peer-mesh graph will key the face on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_held_face_carries_the_peer_zid_from_the_handshake() {
        let (listener, addr) = bind_loopback().await;
        let (go_tx, go_rx) = watch::channel(false);

        // Capture the FaceUp event's peer_zid, then end the loop.
        let captured: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let on_event = {
            let captured = captured.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::FaceUp(face) = event {
                    *captured.lock().unwrap() = face.peer_zid.clone();
                    let _ = go_tx.send(true);
                }
            }
        };
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        // One initiator with a distinct, known zid (0x07) the acceptor captures.
        let initiator = idle_initiator(addr, 0x07, go_rx.clone());

        tokio::time::timeout(Duration::from_secs(20), async {
            let _ = tokio::join!(acceptor, initiator);
        })
        .await
        .expect("handshake completes within 20s");

        assert_eq!(
            *captured.lock().unwrap(),
            Some(vec![0x07; 4]),
            "the held face carries the initiator's announced zid (from the InitSyn)"
        );
    }

    // ── routing-peer atom (R311qg): dial + accept mesh node ─────────────

    /// One peer-node identity (a distinct zid from the acceptor and initiators).
    #[cfg(feature = "routing-peer")]
    fn peer_params() -> SessionInitParams {
        let mut p = fixture_session_init_params();
        p.zid = vec![0xBB; 4];
        p
    }

    /// A peer DIALS a configured target and holds the resulting OUTBOUND face —
    /// the dial-out face source in isolation, the mirror of accept-and-hold. The
    /// peer also listens (it is a full mesh node) but no inbound peer connects
    /// here, so its only face is the one it dialed: `dialed == 1`, `accepted == 0`.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peer_loop_dials_a_configured_peer_and_holds_it() {
        let (acc_listener, acc_addr) = bind_loopback().await;
        let (peer_listener, _peer_addr) = bind_loopback().await;

        // `go` flips when the peer's dialed face is up; it ends BOTH loops.
        let (go_tx, go_rx) = watch::channel(false);

        // The dial target: a plain acceptor that holds the peer's outbound link.
        let acceptor = accept_loop(
            acc_listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        );

        // The peer dials the acceptor; its FaceUp flips `go`.
        let on_event = move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(_) = event {
                let _ = go_tx.send(true);
            }
        };
        let peer = peer_loop(
            FaceSources {
                listener: peer_listener,
                dial_targets: vec![acc_addr],
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                #[cfg(feature = "transport-multilink")]
                qos: false,
            },
            peer_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (_acc, peer) = tokio::join!(acceptor, peer);
            peer
        })
        .await
        .expect("peer dial completes within 20s");

        assert_eq!(summary.dialed, 1, "dialed the one configured target");
        assert_eq!(summary.accepted, 0, "no inbound peer connected");
        assert_eq!(
            summary.established, 1,
            "the dialed face reached Established"
        );
        assert_eq!(summary.peak_concurrent, 1, "held the outbound face");
    }

    /// A5c: a gossip-autoconnect [`DialIntent`] makes the loop dial the
    /// discovered peer over real TCP — the dynamic dial source, twin of the
    /// static `dial_targets`. Inject one intent (as the forwarder's emit would,
    /// A5b) carrying the acceptor's `tcp/<addr>` locator; the loop parses it,
    /// dials, and holds the resulting face exactly like a static dial.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_autoconnect_dial_intent_dials_the_discovered_peer() {
        let (acc_listener, acc_addr) = bind_loopback().await;
        let (peer_listener, _peer_addr) = bind_loopback().await;

        // `go` flips when the autoconnected face is up; it ends BOTH loops.
        let (go_tx, go_rx) = watch::channel(false);

        let acceptor = accept_loop(
            acc_listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        );

        // A dial-intent for the acceptor (zid 0xAA) carrying its tcp locator —
        // what the forwarder emits for a discovered, policy-admitted peer. Buffer
        // it before the loop starts; `intent_tx` stays alive so the channel does
        // not close (the loop parks on the arm after consuming the one intent).
        let (intent_tx, intent_rx) = tokio::sync::mpsc::unbounded_channel();
        intent_tx
            .send(DialIntent {
                zid: vec![0xAA; 4],
                locators: vec![format!("tcp/{acc_addr}")],
            })
            .expect("buffer the dial-intent");

        let on_event = move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(_) = event {
                let _ = go_tx.send(true);
            }
        };
        let peer = peer_loop(
            FaceSources {
                listener: peer_listener,
                dial_targets: vec![],
                dial_intents: Some(intent_rx),
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                #[cfg(feature = "transport-multilink")]
                qos: false,
            },
            peer_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (_acc, peer) = tokio::join!(acceptor, peer);
            peer
        })
        .await
        .expect("autoconnect dial completes within 20s");

        assert_eq!(
            summary.dialed, 1,
            "the dial-intent triggered one outbound dial"
        );
        assert_eq!(summary.accepted, 0, "no inbound peer connected");
        assert_eq!(
            summary.established, 1,
            "the autoconnected face reached Established"
        );
        drop(intent_tx);
    }

    /// The mesh keystone: a peer holds a DIALED face and an ACCEPTED face at
    /// once. It dials an acceptor (outbound) AND accepts an initiator (inbound),
    /// so its peak is 2 faces from two different sources — `dialed == 1` and
    /// `accepted == 1` — the property that makes it a mesh node, not a one-sided
    /// acceptor or one-sided dialer.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peer_loop_holds_a_dialed_and_an_accepted_face_at_once() {
        let (acc_listener, acc_addr) = bind_loopback().await;
        let (peer_listener, peer_addr) = bind_loopback().await;

        // `go` flips once the peer holds BOTH faces (peak 2); it releases the
        // initiator and the acceptor and ends the peer loop.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::FaceUp(_) = event {
                    if up.fetch_add(1, SeqCst) + 1 == 2 {
                        let _ = go_tx.send(true);
                    }
                }
            }
        };

        // The dial target (outbound leg) and the inbound initiator.
        let acceptor = accept_loop(
            acc_listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        );
        let initiator = idle_initiator(peer_addr, 0x11, go_rx.clone());

        let peer = peer_loop(
            FaceSources {
                listener: peer_listener,
                dial_targets: vec![acc_addr],
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                #[cfg(feature = "transport-multilink")]
                qos: false,
            },
            peer_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (_acc, _ini, peer) = tokio::join!(acceptor, initiator, peer);
            peer
        })
        .await
        .expect("dial+accept mesh forms within 20s");

        assert_eq!(summary.dialed, 1, "dialed the outbound target");
        assert_eq!(summary.accepted, 1, "accepted the inbound initiator");
        assert_eq!(
            summary.established, 2,
            "both the dialed and the accepted face reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, 2,
            "held the dialed AND the accepted face at once (a mesh node)"
        );
    }
}
