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

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use wz_runtime_core::TimeSource;

use crate::link_pipeline::accept_tcp_on;
use crate::runtime_impl::TokioTime;
use crate::session_glue::{
    drive_session_until_terminal, DriverOutcome, IterationEvent, SessionInitParams,
    SessionLinkActions, SessionTimeouts,
};
use crate::session_open::{
    accept_and_open_session, initiate_and_open_session, DialedLink, OpenError, OpenedSession,
};

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

/// A held peer link: its [`FaceId`], the remote socket address, and the remote
/// peer's zid (R311qi — the routing identity a peer-mesh graph keys faces on,
/// read from the [`OpenedSession`] at `FaceUp`; `None` if the handshake did not
/// surface it). Not `Copy` because the zid is an owned `Vec<u8>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Face {
    pub id: FaceId,
    pub peer: SocketAddr,
    pub peer_zid: Option<Vec<u8>>,
}

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
    /// out); it never entered the faces table.
    FaceFailed {
        id: FaceId,
        peer: SocketAddr,
        cause: OpenError,
    },
    /// `accept()` itself returned a (typically transient) error; the loop logs
    /// it (via this event), throttles ([`ACCEPT_ERROR_THROTTLE_MS`]), then keeps
    /// accepting — zenoh's `accept_task` parity (log + `TCP_ACCEPT_THROTTLE_TIME`
    /// sleep). Surfaced so the caller can log it rather than the loop swallowing
    /// it.
    AcceptError(io::Error),
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

    /// How often the loop should call [`tick`](Self::tick), or `None` (the
    /// default) to never tick. The extension point for a forwarder whose protocol
    /// has a PERIODIC control-plane obligation: it returns `Some(period)` and the
    /// loop arms a timer. Every current forwarder is EVENT-DRIVEN (the linkstate
    /// peer floods its link-state on each link change; the accept-only / hold-only
    /// / data-plane forwarders have no time-driven work), so they keep the `None`
    /// default and the loop arms no timer. Read ONCE when the loop starts (a fixed
    /// cadence, not a per-tick query).
    fn tick_period(&self) -> Option<Duration> {
        None
    }

    /// The periodic timer fired (cadence from [`tick_period`](Self::tick_period)).
    /// The forwarder's hook for time-driven work that is the FORWARDER's protocol
    /// obligation, not a caller policy. Putting it on the seam (rather than in a
    /// caller's hand-rolled `select!`) is what would make EVERY `peer_loop` caller
    /// share the behaviour, not only the demo. Default no-op; only a forwarder
    /// that returned `Some` from [`tick_period`](Self::tick_period) is ever ticked
    /// — no current forwarder does (all are event-driven), so this is a dormant
    /// extension point. Runs on the loop's single task with the same borrow
    /// discipline as the other hooks (no `RefCell` held across an `.await`).
    fn tick(&self) {}
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
/// the right face record without threading state through the set.
type OpenResult = (FaceId, SocketAddr, Result<OpenedSession, OpenError>);

/// A boxed face-open future — the `opening` set's element type. Boxed `dyn
/// Future` because the two open SOURCES, [`open_face`] (accept) and [`dial_face`]
/// (dial), are distinct future types that must share one [`FuturesUnordered`];
/// one heap alloc per open is negligible beside the handshake it wraps. No
/// `Send` bound — the whole loop is single-task `!Send` (see the module doc).
type OpenFuture = Pin<Box<dyn Future<Output = OpenResult>>>;

/// Bring one accepted link up to Established. Tagged with `(id, peer)` so the
/// loop can route the result without threading state through
/// [`FuturesUnordered`]. Production semantics: `max_iters = None` (the
/// accept-side open-deadline — `accepting.inactivity_timeout`, 1s — bounds a
/// silent peer; see [`accept_and_open_session`]).
async fn open_face(
    id: FaceId,
    peer: SocketAddr,
    accepted: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let result = accept_and_open_session(accepted, params, clock, None, tick_interval_ms).await;
    (id, peer, result)
}

/// Dial one configured peer and bring the OUTBOUND link up to Established — the
/// dial-out twin of [`open_face`]. Where `open_face` opens an *accepted* link via
/// [`accept_and_open_session`], this connects to `peer` then opens the
/// *initiated* link via [`initiate_and_open_session`] (the same SSOT the
/// single-session initiator drives), tagged `(id, peer)` so its completion
/// routes through the same `opening` arm. A failed TCP connect surfaces as
/// [`OpenError::Dial`] (a `FaceFailed`, not a panic), so one unreachable peer
/// never sinks the mesh. TCP only — symmetric to the TCP-only accept side
/// ([`accept_tcp_on`]); locator / DNS / TLS dial (reusing
/// [`connect_and_open_session`](crate::session_open::connect_and_open_session))
/// is a later `routing-peer` atom.
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
    (id, peer, result)
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
    let outcome = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
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
    Accepted(io::Result<(DialedLink, SocketAddr)>),
    /// The forwarder's periodic timer fired (its [`FaceForwarder::tick_period`]
    /// cadence) — call [`FaceForwarder::tick`]. Only ever produced when a timer
    /// is armed (a forwarder that returned `Some` from `tick_period`).
    Tick,
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

/// Where a face-drive node's faces come from: the inbound `listener` it accepts
/// on, and the outbound `dial_targets` it dials. A pure acceptor
/// ([`accept_loop`]) has no dial targets; a peer-mesh node ([`peer_loop`]) has
/// both. Bundling the two sources keeps the loop signature within the
/// argument-count budget as the family grows, and names the real distinction
/// between the two entry points.
pub struct FaceSources {
    /// The bound TCP listener for inbound peers (accept source).
    pub listener: TcpListener,
    /// The peer addresses to dial at startup (outbound source); empty for a
    /// pure acceptor.
    pub dial_targets: Vec<SocketAddr>,
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
        listener,
        dial_targets,
    } = sources;
    tokio::pin!(shutdown);

    // The live face-id set — only its membership and cardinality are read
    // (`peak_concurrent` high-water + the held-count); the peer address and zid
    // live authoritatively on the `Face` carried by each event, so the set
    // stores no value (a `BTreeMap<_, SocketAddr>` value here would be
    // write-only state duplication).
    let mut faces: BTreeSet<FaceId> = BTreeSet::new();
    let mut next_id: u64 = 0;
    let mut summary = AcceptLoopSummary::default();
    let mut opening: FuturesUnordered<OpenFuture> = FuturesUnordered::new();
    let mut driving = FuturesUnordered::new();

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
        opening.push(Box::pin(dial_face(
            id,
            peer,
            params.clone(),
            clock,
            tick_interval_ms,
        )));
    }

    loop {
        let step = tokio::select! {
            _ = &mut shutdown => Step::Shutdown,
            Some(opened) = opening.next() => Step::Opened(Box::new(opened)),
            Some(driven) = driving.next() => Step::Driven(driven),
            accepted = accept_tcp_on(&listener) => {
                Step::Accepted(accepted.map(|(stream, peer)| (DialedLink::Tcp(stream), peer)))
            }
            _ = forwarder_tick(&mut tick_timer) => Step::Tick,
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
                        faces.insert(id);
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
                        driving.push(drive_face(face, opened, forwarder));
                    }
                    Err(cause) => {
                        on_event(&AcceptEvent::FaceFailed { id, peer, cause });
                    }
                }
            }

            Step::Driven((face, outcome)) => {
                faces.remove(&face.id);
                forwarder.deregister(face.id);
                on_event(&AcceptEvent::FaceDown(face, outcome));
            }

            Step::Accepted(Ok((accepted, peer))) => {
                let id = FaceId(next_id);
                next_id += 1;
                summary.accepted += 1;
                opening.push(Box::pin(open_face(
                    id,
                    peer,
                    accepted,
                    params.clone(),
                    clock,
                    tick_interval_ms,
                )));
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
/// Loops accepting inbound TCP links on the already-bound `listener`; each
/// accepted link is opened to Established (concurrently, so one peer's handshake
/// never blocks accepting the next) and then driven as a held *face* until the
/// peer closes. A thin entry over [`face_drive_loop`] with NO outbound dials —
/// every face comes from accepting. `on_event` observes each [`AcceptEvent`];
/// the loop runs until `shutdown` resolves, then returns its
/// [`AcceptLoopSummary`].
pub async fn accept_loop<S, F>(
    listener: TcpListener,
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

    // ── shared fixtures ────────────────────────────────────────────────

    async fn bind_loopback() -> (TcpListener, SocketAddr) {
        let listener = bind_tcp("127.0.0.1:0".parse().expect("loopback addr"))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        (listener, addr)
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
