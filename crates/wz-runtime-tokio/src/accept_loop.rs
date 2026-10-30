// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qa / qg — multi-peer face loop: the `routing-router` and `routing-peer`
//! foundations.
//!
//! [`accept_loop`] is the accept-only entry (the `routing-router` foundation);
//! [`peer_loop`] (R311qg, `routing-peer`) generalises it to a node that also
//! DIALS a configured peer set, holding the dialed and accepted faces in one
//! set. Both delegate to the shared `face_drive_loop` core, differing only in
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
//! ## Why a single-task `FuturesUnordered` by default
//!
//! Every face's open future and drive future live in two [`FuturesUnordered`]
//! sets polled on this one task, so N peers are held concurrently with no
//! `Send` bound on the forwarder and no inter-task races — the same single-task
//! concurrency the loopback open tests get from `tokio::join!`, generalised to a
//! dynamic, unbounded set. (The internal `writer_task`s *are* `Send` and run on
//! the worker pool.)
//!
//! The reason this used to give for NOT spawning a face, that the SCE `Engine`
//! the drive future owns carries callbacks with no `+ Send` bound, no longer
//! holds: `sce-rust-runtime`'s `completion_callback` and `on_http_send` are both
//! `+ Send` at the pinned revision, and the drive future of a face is `Send`
//! when its forwarder is `Sync`. What keeps this the default is the forwarder:
//! the routing forwarders (`LinkstateForwarder`, `RouterForwarder`) keep their
//! tables in `Rc`/`RefCell`, so they can only be called from one task. A node
//! whose forwarder is `Send + Sync` (the C ABI's) is being moved to a task per
//! face's drive instead; the plan and its stages are in
//! `docs/parallel-faces-design.md`.
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
// R2233 (open-debt item 585) — the dial axis's currency is the LOCATOR now.
// R2900 — and its pre-handshake identity is a `MeshDialKey`, so production code
// names the bare address type nowhere; only this module's fixtures do.
#[cfg(test)]
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
// `PushOwned` is the multicast INGRESS fold payload (the deferred `mcast_faces`
// plane); gated on `codec-push` (which provides it) so the accept-only foundation
// (`routing-accept` without `codec-push`, run-ci Layer C1w) stays minimal.
#[cfg(feature = "codec-push")]
use wz_session_core::wire::PushOwned;
// R2734 — the second arm of `McastIngressBody`, gated with the plane it rides
// (see that enum's own note on why a Query and not all seven kinds).
#[cfg(feature = "codec-push")]
use wz_session_core::wire::RequestOwned;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use wz_runtime_core::TimeSource;

use crate::link_collision::{LinkCollisions, Resolution};
#[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
use crate::retry_period::RetryPeriod;
use crate::retry_period::RetryPolicy;
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
    dial_locator, mesh_dial_plan, AcceptedLink, AcceptedPeer, BoundListener, DialConfig,
    MeshDialTarget, OpenError, OpenedSession,
};
// R2900 — the identity is read only where a dial is deduped or re-dialed: the
// reconcile and multilink substrates, and this module's tests.
#[cfg(any(
    test,
    feature = "router-connect-reconcile",
    feature = "transport-multilink"
))]
use crate::session_open::MeshDialKey;
use wz_session_core::locator::AnyLocator;
use wz_session_core::locator_directory::{DirectoryZid, Lifetime, LocatorDirectory, LocatorSource};

// R311y205 (transport-multilink) — the aggregation seam wired into the live
// accept/dial path: when `WzConfig.max_links > 1` a face is opened via the
// `_with_multilink` establishment variants (so the 0x4 ext negotiates + the peer
// ephemeral pubkey is captured), and a SECOND+ physical link to an already-held
// peer zid is aggregated onto the first's shared `SessionCore` via
// [`join_link`] instead of registering a redundant face. Every symbol here is
// feature-gated, so a non-multilink build compiles the accept loop UNCHANGED.
#[cfg(feature = "transport-multilink")]
use crate::multilink::{join_link, JoinOutcome};
// R311y219 (transport-multilink + transport-qos) — the per-face QoS-priority band
// the loop tags each aggregated link with. `Priority` is unconditional (no feature
// gate), so the band tuple `(Priority, Priority)` threads through the multilink
// open path with NO per-call-site cfg branch (the y218 `qos: bool` discipline); it
// is only APPLIED under `transport-qos`, where the `_with_multilink` entrypoints
// map it to the `all(multilink,qos)`-gated `set_link_priority_range`.
//
// Item 751 — reached through their staging twins, so the node's south partition
// is installed on every aggregated link as on every single one.
#[cfg(feature = "transport-multilink")]
use crate::session_open::{accept_multilink_with_staging, initiate_multilink_with_staging};
// R311y506 (session-extqos) / R2095 (open-debt item 513) — the offer-carrying
// open entrypoints, and they are UNCONDITIONAL as of R2095.
//
// Gated on `session-extqos` they could carry only a declared QoS band, so every
// OTHER capability an operator configured on a mesh node — qos, lowlatency,
// compression, shm — reached no InitSyn this loop ever wrote: `SessionOffer` was
// assembled on the demo's single-session `Role::Initiator` arm and nowhere else,
// which is what open-debt item 513 measured. zenoh takes all of them off ONE
// manager config that BOTH directions read (`StateOpen` at
// `io/zenoh-transport/src/unicast/establishment/open.rs:605-636` and
// `StateAccept` at `io/zenoh-transport/src/unicast/establishment/accept.rs:725-755`
// are built from the same `manager.config.unicast.*` fields), which is the shape
// [`FaceSources::offer`] restores here.
//
// Item 751 — the staging twins of the two offer-carrying entrypoints: the offer
// and the node's south partition ride every face ([`FaceTemplate`]).
use crate::session_open::{
    accept_and_open_session_with_staging, initiate_and_open_session_with_staging, DialedLink,
};
#[cfg(feature = "transport-multilink")]
use std::collections::BTreeSet;
use wz_session_core::region_partition::SouthPartition;
use wz_session_core::transport_mode::SessionOffer;
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

/// The face a counter's value names, which is how the peer planner
/// (`wz_session_core::peer_planner`, a module of the builds with `session-unicast`)
/// mints the face of a dial it asks for.
impl From<u64> for FaceId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

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
    /// R311y463 — the peer's handshake ROLE, the second half of the routing
    /// classification `peer_zid` is the first half of. The router places the
    /// face in a region from it (R2866: `router_forward::face_region`), and the
    /// region decides whether this face is eligible for the CLIENT-only
    /// token/subscriber current-dump and future-push paths, so a face-lifecycle
    /// observer that omits it cannot explain a face that routes nothing.
    /// `None` = the INIT never surfaced a role (kept distinct from `Some(Peer)`,
    /// which is what the routing boundary DEFAULTS such a face to).
    pub peer_whatami: Option<wz_codecs::whatami::WhatAmI>,
    /// R2951 — whether THIS node dialed the face (a configured or discovered
    /// connect target) rather than accepted it. Upstream's start conditions
    /// count only the node's own dials (`start_conditions`, fed by
    /// `spawn_peer_connector`), and a face event that could not say which side
    /// opened it made every observer that needs that answer approximate it.
    pub dialed: bool,
    /// session-extqos (R311y506) — the QoS link metadata NEGOTIATED on this face,
    /// after the directional containment merged the peer's `init::ext::QoSLink`
    /// into ours.
    ///
    /// This is the OUTCOME, not the offer: a node that declared nothing still
    /// reports the peer's band here, because the merge adopts an undeclared
    /// side's counterpart (`(None, p) => p`, zenoh's own arm). That is what makes
    /// it an observation of the PEER's wire rather than an echo of local config —
    /// the distinction a cross-impl witness needs.
    #[cfg(feature = "session-extqos")]
    pub qos_link: wz_session_core::extqos::QosLinkState,
}

/// WHICH DISCOVERY PLANE produced a [`DialIntent`].
///
/// R2141 (open-debt item 223) — the multicast-scouting plane learned to
/// autoconnect this round, and it emits its intents into the SAME channel the
/// gossip plane does, because the loop that dials is the same loop. Upstream
/// keeps the two planes' policies separate for exactly this reason
/// (`AutoConnect::multicast` and `AutoConnect::gossip`, `net/common.rs`, read
/// from two different config subtrees) while both end at `connect_peer`.
///
/// The tag is NOT decoration. [`AcceptLoopSummary::gossip_dialed`] was built by
/// R311y423 as a DISCRIMINATOR: it is bumped in the one `Step::Dial` arm, which
/// at the time was reachable only through a gossip-discovered peer, and
/// `wz_gossip_autoconnect_zenohd_interop` asserts on it. Feeding a second
/// producer into that channel untagged would have quietly turned it into "any
/// intent dial" and left that test crediting the gossip atom for a multicast
/// discovery. So the counter splits by origin instead, and each plane keeps a
/// witness only its own discovery can move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialIntentOrigin {
    /// A peer learned off a link-state / gossip flood — zenoh
    /// `zenoh/src/net/protocol/gossip.rs` @ `fn add_node`, wz
    /// `linkstate_forward`'s discovery emit.
    Gossip,
    /// A node that answered this one's multicast Scout with a Hello — zenoh
    /// `Runtime::autoconnect_all`, wz `scouting_autoconnect`.
    MulticastScout,
}

impl DialIntentOrigin {
    /// The source whose hints a discovery from this plane is (decision D3).
    pub fn locator_source(self) -> LocatorSource {
        match self {
            Self::Gossip => LocatorSource::Linkstate,
            Self::MulticastScout => LocatorSource::Hello,
        }
    }
}

/// Decision D3 of `docs/session-lifecycle-intent.md` — how many hints the
/// directory a face loop holds can keep: a mesh of hundreds of nodes, each with a
/// few locators, and the soft-state rows that a full table displaces first.
pub const LOOP_DIRECTORY_ROWS: usize = 512;

/// Decision D3 — how long a Hello's confirmation of a locator lasts. Upstream
/// scouts again at most every 8 s
/// (`zenoh/src/net/runtime/orchestrator.rs`
/// @ `const SCOUT_MAX_PERIOD: Duration = Duration::from_millis(8_000);`), so a live
/// node's Hello arrives at least that often while the scouting runs. The lifetime
/// is RSVP's soft-state rule over that refresh period R, L >= (K + 0.5) * 1.5 * R
/// with K = 3 (RFC 2205, section 3.7): a hint survives K lost refreshes and a
/// refresh period jittered by half again, so 5.25 * 8 s.
pub const HELLO_LIFETIME_MS: u64 = 42_000;

/// The directory a face loop holds (decision D3).
pub type LoopDirectory = LocatorDirectory<LOOP_DIRECTORY_ROWS>;

/// Take the locators a discovery plane read for `zid` into `directory`, as
/// `source`'s hints at `now_ms`.
///
/// A link-state read is the graph's whole current set for the node, so that
/// source's earlier hints for it are withdrawn first and a locator the graph no
/// longer carries is not kept: the flood is event-driven and the graph drops what
/// it no longer reaches, so its hints last until the next read replaces them. A
/// Hello's hints last [`HELLO_LIFETIME_MS`], since nothing ever withdraws them.
/// Every read of the directory for a zid is preceded by this for that zid, so a
/// node the graph lost is never dialled from a link-state hint it no longer has.
pub fn learn_locators(
    directory: &mut LoopDirectory,
    zid: &DirectoryZid,
    locators: &[String],
    source: LocatorSource,
    now_ms: u64,
) {
    let lifetime = match source {
        LocatorSource::Hello => Lifetime::Millis(HELLO_LIFETIME_MS),
        LocatorSource::Linkstate | LocatorSource::Declared => Lifetime::Permanent,
    };
    if source == LocatorSource::Linkstate {
        directory.withdraw(zid, LocatorSource::Linkstate);
    }
    for locator in locators {
        if let Err(why) = directory.confirm(*zid, locator, source, now_ms, lifetime) {
            log::debug!("directory: `{locator}` not taken for a node ({why:?})");
        }
    }
}

/// The candidate locators of `zid`, in the order to try them (decision D3).
pub(crate) fn candidate_locators(
    directory: &LoopDirectory,
    zid: &DirectoryZid,
    now_ms: u64,
) -> Vec<String> {
    directory
        .candidates(zid, now_ms)
        .map(|row| row.locator().to_owned())
        .collect()
}

/// A request from a discovery plane to the accept loop: dial a peer it
/// DISCOVERED and whose role + zid the autoconnect policy admitted. A discovery
/// path cannot open an outbound link itself — the gossip one is a sync ingest,
/// the scouting one is a task that owns a UDP socket, and neither is the async
/// task that owns the in-flight-open [`FuturesUnordered`] — so it hands the loop
/// this intent over an unbounded channel and the loop turns it into a `dial_face`
/// (A5c). The wz analogue of the `(zid, locators)` pair zenoh passes to
/// `runtime.connect_peer` (`zenoh/src/net/protocol/gossip.rs` @ `connect_peer`
/// for gossip,
/// `orchestrator.rs`'s `autoconnect_all` for multicast), minus the per-dial task
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
    /// The dial addresses the peer advertised (its link-state locators, or the
    /// locators its Hello carried); the loop (A5c) parses one into a socket
    /// address to connect to.
    pub locators: Vec<String>,
    /// R2141 — which plane discovered it, so the loop's counters stay
    /// discriminating with two producers on one channel.
    pub origin: DialIntentOrigin,
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
/// full desired outbound connect-set, delivered to `face_drive_loop` when the
/// operator changes the connect endpoints at runtime.
///
/// ⚠ R2665 — THIS PARAGRAPH NAMED AN UPSTREAM MECHANISM THAT DOES NOT EXIST AT
/// THE PIN, and the correction is kept rather than silently swapped because the
/// wrong version described the wrong SHAPE, not merely the wrong line. It said
/// this mirrored zenoh's `update_peers`, "which re-reads
/// `connect().endpoints()` on the config `connect/endpoints` CHANGE EVENT".
/// Measured against the pinned checkout: `update_peers` occurs ZERO times, and
/// the line it cited is the middle of an ordinary peer-connect loop. There is no
/// config change event for endpoints upstream either — the only config
/// subscriber is `plugins`-gated.
///
/// What upstream ACTUALLY does, and therefore what this request is the analogue
/// of: `zenoh/src/net/runtime/orchestrator.rs` @ `pub(super) fn closed_session`
/// and @ `pub(super) fn closed_link` lock the LIVE config AT CLOSE TIME, re-read
/// `connect().endpoints().get(whatami)`, and re-dial the addresses still listed.
/// So the trigger is a CLOSE consulting current config, not an event fired by a
/// write — which is why wz's equivalent is a set the loop holds and a request
/// that replaces it, rather than a subscription.
///
/// wz carries the resolved LOCATORS (R2233 — the
/// same currency as the static [`FaceSources::dial_targets`], which was a list of
/// bare `SocketAddr`s until the mesh dial side learned to dispatch on scheme; a
/// runtime add of a `quic/...` endpoint was unrepresentable while this channel
/// carried addresses); the loop dials each address it is not already dialing
/// (address dedup — a config endpoint has no zid pre-handshake, so the gossip zid
/// dedup `holds_zid` cannot apply).
/// ADD-ONLY, faithful to the router branch (`orchestrator.rs:449-467`): a removed
/// endpoint is NOT torn down (the Client close-removed branch `427-448` is
/// deliberately router-inapplicable — closing a live federation face on a
/// static-list edit would blackhole the mesh).
///
/// The sending end lives in the run-mode host (`run_router_hat`), written when the
/// operator affordance fires; the channel is UNBOUNDED (the producer is a sync
/// timer callback that must not await) and reconcile events are rare (operator
/// cadence), so unbounded growth is a non-issue.
pub type ReconcileSender = tokio::sync::mpsc::UnboundedSender<ConnectReconcile>;
/// The accept loop's receiving end of the reconcile channel, drained in the loop's
/// `select!`. `None` when `router-connect-reconcile` is not wired (every non-router
/// loop, and a router built without the feature) — then the arm parks forever and
/// the loop is byte-for-byte the prior behaviour.
pub type ReconcileReceiver = tokio::sync::mpsc::UnboundedReceiver<ConnectReconcile>;

/// R2671 (open-debt item 770) — WHICH RECONCILE THIS IS, carried on the channel
/// rather than assumed by the loop.
///
/// ⭐ THE DEFECT THIS CLOSES IS A MISMATCH OF ARITY, not of value. The channel
/// used to carry a bare `Vec<AnyLocator>` and the loop always ADOPTED it whole,
/// so every producer had to hand over the FULL desired set. Two of the three
/// could: `--connect-after` composes `dials + addrs`, and a `connect/endpoints`
/// config write carries the whole document list by definition. The third could
/// not — `AdminConfigWrite::ConnectAdd` is one operator's ADD, and the host that
/// receives it has no way to read the current set back (the desired map is a
/// loop-local, and `WzConfig::connect_endpoints` is private, empty at startup,
/// and holds TEXT where the loop holds RESOLVED locators). So it sent its
/// fragment down a replace-shaped channel and every startup endpoint silently
/// left the re-dial set, with no symptom until one of them dropped.
///
/// ⚠ THE FIX IS NOT A MERGE IN THE PRODUCER, and that is the whole point of
/// putting the verb here: the only place that can merge correctly is the place
/// that HOLDS the set, because a producer that re-derives it from text loses the
/// DNS resolution `resolve_dial_targets` did at startup ([`AnyLocator`] has no
/// `Display`, so a resolved endpoint cannot even be spelled back).
///
/// ⚠ `ConnectAdd`'s own doc still reads "deliberately an ADD" and stays true —
/// the INTENT is unchanged. What changed is that the channel can now say so,
/// instead of the intent being widened to a replace on the way down.
#[cfg(feature = "router-connect-reconcile")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectReconcile {
    /// Adopt this as the whole desired connect-set. An endpoint absent from it
    /// stops being RE-DIALLED; its live face is not closed (the add-only /
    /// close-removed asymmetry the module doc states). Decision D5 — the loop
    /// forgets its connection machine ([`crate::loop_peers`]).
    Replace(Vec<AnyLocator>),
    /// Add these to the desired connect-set, leaving every existing member —
    /// including the DNS-resolved startup seed — in place.
    Add(Vec<AnyLocator>),
    /// Add a NODE: the locators the link-state graph holds for it, each dialled
    /// for its zid, as an [`Self::Add`] does otherwise (decision D4 of
    /// `docs/session-lifecycle-intent.md`). A session one of them opens closes at
    /// an InitAck from another zid, so a node now answering at a locator the
    /// graph gave for this one is not mistaken for it. Re-dials of these members
    /// carry the zid too. The locators are the graph's text, taken into the
    /// loop's directory as link-state hints, and the members are the node's
    /// candidates there (decision D3), a Hello's among them.
    ///
    /// Decision D5 — a node is not a member of the desired connect-set: the
    /// loop holds it by its connection machine ([`crate::loop_peers`]), which
    /// resolves, dials, backs off and names a refusal. The lifecycle opener is
    /// the one producer, so the variant is that feature's.
    #[cfg(feature = "session-close-ingress")]
    AddNode {
        /// The node's zid in its sixteen-byte form.
        zid: DirectoryZid,
        /// The locators the graph holds for the node, as the node advertised them.
        locators: Vec<String>,
    },
    /// Decision D6 — take a NODE out of the intent: a lifecycle `close`. Every
    /// machine that holds it is stopped — its own, and each configured
    /// endpoint's whose last session reached it — so no session to it is
    /// dialled again until an `open` or a connect-list edit names it. Its live
    /// sessions are closed by the close itself, not by this request.
    #[cfg(feature = "session-close-ingress")]
    Withdraw {
        /// The node's zid in its sixteen-byte form.
        zid: DirectoryZid,
    },
}

/// Decision D6 — the intent a lifecycle `close` withdraws a peer from: the
/// loop's peers ([`crate::loop_peers`]), reached over the loop's reconcile
/// channel. A host that holds the sender wraps it in this and hands it to the
/// lifecycle queries as their intent.
#[cfg(all(
    feature = "router-connect-reconcile",
    feature = "session-close-ingress"
))]
#[derive(Debug, Clone)]
pub struct LoopIntent(pub ReconcileSender);

#[cfg(all(
    feature = "router-connect-reconcile",
    feature = "session-close-ingress"
))]
impl wz_session_core::lifecycle_query::PeerIntent for LoopIntent {
    fn withdraw(&self, peer_zid: &[u8]) {
        let Some(zid) = wz_session_core::credential_identity::zid_from_wire(peer_zid) else {
            log::warn!("lifecycle close: {peer_zid:02x?} is not a zid; no intent is withdrawn");
            return;
        };
        if self.0.send(ConnectReconcile::Withdraw { zid }).is_err() {
            log::warn!("lifecycle close: the face loop is gone; no intent is withdrawn");
        }
    }
}

/// The payload alias a feature-off build still needs for the channel types to
/// name something. The reconcile arm parks in that build, so nothing is ever
/// sent or received; this exists so the aliases above compile unchanged.
#[cfg(not(feature = "router-connect-reconcile"))]
pub type ConnectReconcile = Vec<AnyLocator>;

/// R2667 (§5.23 `config-mutate-runtime`) — the sink a `WzConfig`'s configured
/// `connect/endpoints` list is installed onto, decoupled from the concrete
/// channel exactly as `RouterLinkWeightSink` is for the router weights slice.
///
/// ⭐ THIS EXISTS BECAUSE THE CONSUMER IS A LOOP-LOCAL, which is the one shape
/// the other two sinks did not have to face. The desired connect-set is the
/// endpoints of the loop's peers ([`crate::loop_peers::LoopPeers`]), living
/// inside `face_drive_loop`, not a field on a long-lived object, so nothing can
/// implement a sink "on" it. What CAN be implemented on
/// is the SENDER the loop already drains, and that is what this abstracts: the
/// config seam names a sink, the host holds the channel.
///
/// ⚠ A FULL-LIST REPLACE, and deliberately not the add-only shape of the
/// `connect-add` intent beside it. The intent is add-only because it drives a
/// seam that excludes close-removed teardown on purpose; a CONFIG write carries
/// the whole list the way the document does, and upstream reads that whole list
/// at close time (`zenoh/src/net/runtime/orchestrator.rs`
/// @ `pub(super) fn closed_session`) to decide what to re-dial. Dropping an
/// endpoint therefore stops it being RE-DIALLED and never closes a live face —
/// upstream's semantics, not a narrowing.
#[cfg(feature = "router-connect-reconcile")]
pub trait ConnectEndpointsSink {
    /// Replace the desired outbound connect-set, returning whether the loop is
    /// still there to receive it. `false` means the channel is closed — the
    /// face loop is gone — which is a fact the caller should report rather than
    /// a failure of the write.
    fn set_connect_endpoints(&self, endpoints: Vec<AnyLocator>) -> bool;
}

/// What one [`ConnectReconcile`] asks of the loop's peers, its members folded
/// into dial plans: the input of [`crate::loop_peers::LoopPeers::set_endpoints`]
/// or of its `open_node`.
#[cfg(feature = "router-connect-reconcile")]
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectPlan {
    /// Configured endpoints: `targets` join the set, and with `replace` they
    /// are the whole of it.
    Endpoints {
        /// The members, each keyed by its pre-handshake identity.
        targets: Vec<MeshDialTarget>,
        /// Whether they are the whole set.
        replace: bool,
    },
    /// A node, and the locators the graph holds for it (decision D5).
    #[cfg(feature = "session-close-ingress")]
    Node {
        /// The node's zid in its sixteen-byte form.
        zid: DirectoryZid,
        /// The locators the graph holds for the node, as the node advertised them.
        locators: Vec<String>,
    },
    /// A node out of the intent (decision D6).
    #[cfg(feature = "session-close-ingress")]
    Withdraw {
        /// The node's zid in its sixteen-byte form.
        zid: DirectoryZid,
    },
}

/// R2671 (open-debt item 770) — FOLD one [`ConnectReconcile`] into the plan the
/// loop's peers take, and the ONE place that reads its verb.
///
/// ⭐ EXTRACTED RATHER THAN INLINED, and that is the repair rather than a
/// tidy-up. The merge used to live inside `face_drive_loop`'s `select!` arm,
/// where the only way to reach it is to stand up a loop, a listener and a host —
/// so the arity defect above was structurally untestable, and the integration
/// test that does exist never built a node whose desired set was non-empty,
/// which is exactly the case where subset-versus-whole differs. The fold and
/// the set it lands in ([`crate::loop_peers::LoopPeers`], decision D5) are
/// both reachable by a unit test in microseconds.
///
/// Refusals are reported through `on_refused` rather than logged here, so the
/// caller keeps the loop's wording and a test can count them without a logger.
#[cfg(feature = "router-connect-reconcile")]
pub fn fold_connect_reconcile(
    request: ConnectReconcile,
    mut on_refused: impl FnMut(AnyLocator),
) -> ConnectPlan {
    let (rows, replace) = match request {
        ConnectReconcile::Replace(rows) => (rows, true),
        ConnectReconcile::Add(rows) => (rows, false),
        #[cfg(feature = "session-close-ingress")]
        ConnectReconcile::AddNode { zid, locators } => {
            return ConnectPlan::Node { zid, locators };
        }
        #[cfg(feature = "session-close-ingress")]
        ConnectReconcile::Withdraw { zid } => return ConnectPlan::Withdraw { zid },
    };
    // R2233 — fold each through the ONE classification and refuse a member with
    // no pre-handshake identity, exactly as the startup seed does. Keyed by the
    // identity (R2900: a `MeshDialKey`, the resolved address for the IP family),
    // so a re-listed endpoint spelled differently still dedups to one dial.
    let targets = rows
        .into_iter()
        .filter_map(
            |locator| match crate::session_open::mesh_dial_plan(locator) {
                Ok(target) => Some(target),
                Err(rejected) => {
                    on_refused(rejected);
                    None
                }
            },
        )
        .collect();
    ConnectPlan::Endpoints { targets, replace }
}

/// The production [`ConnectEndpointsSink`]: the channel end itself. Sending on a
/// closed channel answers `false` rather than panicking, which is the same
/// reading the host's `connect-add` arm already takes.
#[cfg(feature = "router-connect-reconcile")]
impl ConnectEndpointsSink for ReconcileSender {
    fn set_connect_endpoints(&self, endpoints: Vec<AnyLocator>) -> bool {
        self.send(ConnectReconcile::Replace(endpoints)).is_ok()
    }
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
    /// R2758 — a face that REACHED Established and was refused anyway, because
    /// [`FaceSources::max_sessions`] was already met.
    ///
    /// ⚠ ITS OWN VARIANT, and the two it is not are the argument.
    /// [`Self::FaceUp`] is false — the face never entered the table.
    /// [`Self::FaceFailed`] is false too, and more interestingly: that variant
    /// means "never reached Established", while this face completed the whole
    /// 4-way handshake and was turned away after it. Folding this into either
    /// would make a caller's count of successful opens or of handshake
    /// failures wrong, and an outcome a caller cannot name is one nobody can
    /// act on — which for "this node is turning peers away" is the reading
    /// that matters most.
    ///
    /// `held` is the table size at the moment of refusal, so a log line can
    /// say what the limit was without the caller holding the config.
    FaceRefused {
        id: FaceId,
        peer_zid: Option<Vec<u8>>,
        held: usize,
    },
    /// `accept()` itself returned a (typically transient) error; the loop logs
    /// it (via this event), throttles (`ACCEPT_ERROR_THROTTLE_MS`), then keeps
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
/// The hold-only path passes [`NoOpForwarder`]; a routing node passes one of
/// the mesh forwarders (the peer's `LinkstateForwarder`, the router hat's
/// `RouterForwarder`). R2912 retired the third, the single-hop star engine
/// over session-core's `RouteTable`, which no run-mode had built since R2886.
/// Taken as `&dyn` so the loop carries one concrete future type in its
/// [`FuturesUnordered`] regardless of which forwarder is wired, and `!Send` is
/// fine — the whole loop is single-task.
pub trait FaceForwarder {
    /// A face reached Established and entered the live set. `actions` is its
    /// transport send seam; a forwarder that routes clones it (an `Arc`) so it
    /// can forward TO this face later.
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>);
    /// [`register`](Self::register) for a forwarder that can refuse the face at the moment it is
    /// held: `true` when the face is held, `false` when the forwarder holds a face that stays to
    /// the same node and the link is to be closed unheld.
    ///
    /// [`holds_peer`](Self::holds_peer) is asked earlier and is only an answer for the moment it
    /// is given: a node that listens and dials has more than one loop, each registering into the
    /// one table the forwarder keeps, and the other's face can come up between that question and
    /// this call. This call is the decision, made under the table's own lock, and the loop tells
    /// nothing of the face (not its dial machine, not its set of faces) before it is made.
    /// Default: the face is registered and held.
    fn admit(&self, id: FaceId, actions: &Arc<SessionLinkActions>) -> bool {
        self.register(id, actions);
        true
    }
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
    ///
    /// `from` is the group member that sent it (item 751): the pin's per-member
    /// face carries the member's zid, and its routing asks that zid of every
    /// message. `None` when the member is not known.
    #[cfg(feature = "codec-push")]
    fn route_mcast_ingress(
        &self,
        _priority: Priority,
        _reliable: bool,
        _push: &PushOwned,
        _from: Option<&wz_session_core::driver_loop::MulticastPeerId>,
    ) {
    }

    /// R2734 — a QUERY received on the multicast INGRESS group, the admitting
    /// twin of [`route_mcast_ingress`](Self::route_mcast_ingress).
    ///
    /// A routing forwarder routes it exactly as it routes a unicast Query, from
    /// the same source-only ingress face; any reply is then discarded, because
    /// that face has no send seam. THAT IS THE PIN'S BEHAVIOUR AND NOT A
    /// SHORTCUT: upstream routes a multicast peer's Request through a face built
    /// with `DummyPrimitives` and drops the Response there, so the querier is
    /// unreachable in both implementations and what this buys is the local
    /// queryable actually running.
    ///
    /// No `priority` parameter, deliberately: the frame band is the Push path's
    /// re-injection argument (`route_push` carries it to the mesh and to local
    /// subscribers), while a Query is routed by
    /// `RouterForwarder::route_request`'s own query-route computation, which
    /// takes no band. Passing one would be a parameter no arm reads.
    /// Default no-op: only a forwarder with a multicast ingress plane implements it.
    ///
    /// `from` as for [`route_mcast_ingress`](Self::route_mcast_ingress).
    #[cfg(feature = "codec-push")]
    fn route_mcast_ingress_request(
        &self,
        _reliable: bool,
        _request: &RequestOwned,
        _from: Option<&wz_session_core::driver_loop::MulticastPeerId>,
    ) {
    }

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

    /// Item 751 -- whether the forwarder REFUSES the session `actions` opened, and
    /// why. The loop drops a refused face before it is held, as it drops one over
    /// `max_sessions`, and reports it as a [`AcceptEvent::FaceRefused`].
    ///
    /// The pin refuses a remote its region rules cannot place: `compute_region_of`
    /// answers an error ("North-north ... configuration (invalid)", "Remote's auto
    /// preset conflicts with custom configuration") and the transport is never
    /// built (`zenoh/src/net/runtime/mod.rs` @ `compute_region_of(`). Default
    /// `None`: a forwarder that places no remote refuses none.
    fn refuses_face(&self, _actions: &Arc<SessionLinkActions>) -> Option<String> {
        None
    }

    /// Item 751 -- how the node's south is partitioned into subregions, which
    /// the loop installs on every session it opens, dialled and accepted alike,
    /// before the first wire byte. A session announces on its Open the bound the
    /// partition gives its peer, as the pin's transport manager asks the node's
    /// one config for it while it builds each Open
    /// (`zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_transient_bound_of(`).
    ///
    /// Asked of the forwarder rather than handed to the loop beside it because
    /// the forwarder places its faces by the same partition: one value, one
    /// owner, so a session cannot announce a bound its node does not route by.
    /// Read once, when the loop starts. Default `Auto`: a node on the preset
    /// announces nothing, which is every session the loop opened before.
    fn south_partition(&self) -> wz_session_core::region_partition::SouthPartition {
        wz_session_core::region_partition::SouthPartition::Auto
    }

    /// The authentication this node asks of the peers it accepts and answers to the peers it
    /// dials, which the loop installs on every session it opens before the first wire byte
    /// ([`SessionAuth`]). `None`, the default, is a node that authenticates nobody and offers
    /// nothing, which is every session the loop opened before this existed.
    ///
    /// Asked of the forwarder for the reason [`Self::south_partition`] is: the forwarder is the
    /// node's one owner of the policy its sessions are opened by, and a loop that took the
    /// authentication as a parameter beside it could be handed one that its node's forwarder
    /// does not hold. Read once, when the loop starts; the factory it returns is called for each
    /// session, so a handshake's state is never shared between two links.
    #[cfg(feature = "session-extauth")]
    fn session_auth(&self) -> Option<SessionAuth> {
        None
    }

    /// The prefix this node's keys carry on the wire (`namespace`), which the loop installs on
    /// every session it opens before the first wire byte, as it does the authentication. `None`,
    /// the default, is a node whose keys are the wire's. Each participant's namespace is its own:
    /// the two ends of a link need not hold the same one.
    #[cfg(feature = "routing-namespace")]
    fn session_namespace(&self) -> Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr> {
        None
    }

    /// The §5.16 INGRESS admission of the owned frame the face `id` just decoded, run before it
    /// is reported: `outcome` may be edited in place (a denied message is dropped from the
    /// batch). Called for a whole frame and again for a fragment chain that completes, so a
    /// policy cannot be stepped around by sending something too big for one frame.
    ///
    /// The default does nothing, and that is a scope statement about the routing forwarders:
    /// they admit inbound at the top of [`Self::forward`] (`admit_inbound`) on the message they
    /// route, and running a chain here as well would run it twice. A forwarder that has no
    /// admission of its own, like the C API's, which hands a message to a subscriber and
    /// routes nothing, implements this instead.
    fn ingress(&self, _id: FaceId, _outcome: &mut wz_session_core::driver_loop::DriverLoopOutcome) {
    }

    /// Whether face `id` must stop taking inbound frames until a destination it feeds has room
    /// again: the forwarder's half of credit-based flow control.
    ///
    /// `Some(wake)` says the face is gated now. The face's drive, which asks after every event it
    /// has dispatched ([`crate::session_glue::LoopStages::after_dispatch`], the one point of the
    /// loop where waiting costs only this face's progress), waits for `wake` for a bounded time
    /// and asks again, and goes on reading when the answer is `None`. A face that waits keeps
    /// its keepalives and its lease check, as a face that waits on a slow consumer does
    /// (`park_on_drain`); only its reading stops, so its peer's own sends queue behind the
    /// socket, which is what upstream's parked receive task of a link does.
    ///
    /// The default is `None`: a forwarder that never holds a message back never gates a face.
    /// The answer is read on the loop's own thread with the same borrow discipline as the other
    /// hooks, and the `Arc` is what makes the wait `Send`, as [`Self::deadline_revised`]'s is.
    fn read_gate(&self, _id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        None
    }

    /// The signal that raises [`woken`](Self::woken) on the loop: for a forwarder that holds
    /// messages for a full link and must send them when the link has room, however quiet the
    /// loop is otherwise. Signal with `notify_one`, which stores a permit, so a notice raised
    /// while the loop is not parked on it is honoured at its next arm and not lost.
    ///
    /// `None` (the default) is a forwarder with nothing to be woken for, which costs the loop a
    /// pending arm and no timer, as [`tick_period`](Self::tick_period) does.
    fn wake_signal(&self) -> Option<Arc<tokio::sync::Notify>> {
        None
    }

    /// The loop was woken by [`wake_signal`](Self::wake_signal). Runs on the loop's own thread
    /// with the same borrow discipline as the other hooks. The default does nothing.
    fn woken(&self) {}

    /// R3067 -- whether the forwarder ALREADY holds a face to the peer `zid`
    /// that this loop does not hold: a link the node's DIAL role made.
    ///
    /// The loop's own dedup ([`dedups_faces_by_zid`](Self::dedups_faces_by_zid))
    /// sees only the faces it holds, and a node that both listens and dials
    /// meets the same peer through two roles whenever the two dial each other.
    /// Asked at the same point and under the same rule, so the second link to a
    /// node is refused wherever it came from. Default `false`: a node whose
    /// forwarder is the only holder of faces has nothing the loop cannot see.
    fn holds_peer(&self, _zid: &[u8]) -> bool {
        false
    }

    /// Which of two links to one node this forwarder keeps, when the loop holds a face to the
    /// node already and a second link to it has completed its handshake. `held_dialled` and
    /// `new_dialled` say whether this node dialled each link. The loop asks it only of a
    /// forwarder that [`dedups_faces_by_zid`](Self::dedups_faces_by_zid).
    ///
    /// `Some(SecondLink::Refuse)` keeps the held face and closes the new link, which is what
    /// the first up has always done; `Some(SecondLink::Replace)` keeps the NEW link: the held
    /// face is closed ([`close_face`](Self::close_face)), and the new link is admitted once the
    /// loop has processed that face's departure, because the routing state is keyed on the zid
    /// and a face that is still leaving would remove the link of the face that replaced it.
    ///
    /// Two nodes that dialled each other make two links between them, and "the first up" is
    /// decided differently at the two ends (each keeps the link that completed first on its side
    /// and closes the one the other kept), which leaves none. A forwarder that answers with
    /// [`wz_session_core::link_admission::judge_second_link`] keeps, at both ends, the link the
    /// node with the lower zid dialled. Default `None`: the loop keeps the first up.
    fn judge_second_link(
        &self,
        _held_dialled: bool,
        _new_dialled: bool,
        _remote_zid: &[u8],
    ) -> Option<wz_session_core::link_admission::SecondLink> {
        None
    }

    /// Ask the face `id` to close, because a link that replaces it has come up
    /// ([`judge_second_link`](Self::judge_second_link)). `true` when the face was asked and its
    /// departure will reach the loop as the end of its drive; `false` when the forwarder has no
    /// such face to ask, and the loop then keeps the first up. Default `false`.
    fn close_face(&self, _id: FaceId) -> bool {
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
    ///
    /// R3123 -- `_actions` is the joined link's own session handle: what a forwarder
    /// acknowledges the shared-memory slices that arrive on that link through, since the
    /// counters they are owed are the ones the joined link's peer named.
    fn register_joined(
        &self,
        _joined_id: FaceId,
        _primary_id: FaceId,
        _actions: &Arc<SessionLinkActions>,
    ) {
    }

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
    /// R2758 — faces refused because
    /// [`FaceSources::max_sessions`] was already reached.
    ///
    /// A SEPARATE counter rather than a reading of
    /// [`accepted`](Self::accepted) minus [`established`](Self::established),
    /// for the reason the gossip counter below states: that difference is
    /// bumped by the dedup-by-zid rule and by open failures too, so asserting
    /// on it would pass on a node the bound never refused.
    pub refused_over_max_sessions: usize,
    /// Faces refused because the held set had reached the host's moving
    /// [`FaceSources::ceiling`] while [`FaceSources::max_sessions`] had room: the node's
    /// measured capacity, not the configured limit. A SEPARATE counter from
    /// [`refused_over_max_sessions`](Self::refused_over_max_sessions), so a refusal says whose
    /// limit it was.
    pub refused_over_capacity: usize,
    /// Links closed unanswered because [`AcceptBounds::pending`] accepts were already
    /// mid-handshake when they arrived. Before the session exists, so none of the counters
    /// above applies to them and none of [`accepted`](Self::accepted) counts them.
    pub refused_over_pending: usize,
    /// R311y423 — of [`dialed`](Self::dialed), the subset dialed because the
    /// GOSSIP-autoconnect policy admitted a discovered peer (the `Step::Dial`
    /// arm), as opposed to a configured `--connect` target or a reconcile add.
    ///
    /// A SEPARATE counter rather than a reading of `dialed`, because `dialed`
    /// cannot discriminate: it is bumped by the static seed, the gossip arm and
    /// reconcile alike, so asserting on it would pass on a node that autoconnect
    /// never moved. That is the hollow-witness shape R311y140 recorded (a
    /// convergence tick is handshake-satisfiable), and `scouting-autoconnect` is
    /// exactly the atom a hollow witness would falsely credit — its whole content
    /// is "a peer learned off the link-state flood got dialed".
    ///
    /// R2141 — and it counts only [`DialIntentOrigin::Gossip`] intents now. The
    /// arm it is bumped in gained a second producer this round, so the origin tag
    /// is what keeps the sentence above true; see [`DialIntentOrigin`].
    pub gossip_dialed: usize,
    /// R2141 (open-debt item 223) — of [`dialed`](Self::dialed), the subset
    /// dialed because a node ANSWERED this one's multicast Scout and the
    /// `scouting/multicast/autoconnect` policy admitted its role + zid
    /// ([`DialIntentOrigin::MulticastScout`]).
    ///
    /// The multicast twin of [`gossip_dialed`](Self::gossip_dialed) and a
    /// separate counter for the same reason: `dialed` is bumped by the static
    /// `--connect` seed, by reconcile, and by BOTH discovery planes, so it cannot
    /// say which one moved. This one is reachable through exactly one path — a
    /// Hello decoded off the scouting group, past
    /// `AutoConnect::should_autoconnect` — so a run that raises it has done the
    /// thing item 223 says wz never did.
    pub scout_dialed: usize,
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

/// A link that completed its handshake to a node the loop holds a face to, is the link to keep
/// ([`FaceForwarder::judge_second_link`]), and waits for that face to leave
/// ([`crate::link_collision`]): the open as it arrived, and whether this loop accepted it, which
/// the loop forgets when it makes the face and must be told again when the open is admitted.
struct ParkedOpen {
    id: FaceId,
    peer: AcceptedPeer,
    opened: OpenedSession,
    accepted: bool,
}

/// Admit a parked link now that the face it replaces has left, through the door a new link comes
/// in by: it is the same open, completed, and meets the checks of any other (the bounds, the
/// region rules, the peer's machine) at the moment it is admitted and not at the moment it was
/// parked.
fn admit_parked(
    parked: ParkedOpen,
    opening: &mut FuturesUnordered<OpenFuture>,
    accepted_ids: &mut std::collections::BTreeSet<FaceId>,
) {
    if parked.accepted {
        accepted_ids.insert(parked.id);
    }
    opening.push(Box::pin(std::future::ready((
        parked.id,
        parked.peer,
        Ok(parked.opened),
    ))));
}

/// R311y205 (transport-multilink) — the `driving` set's boxed element type in an
/// aggregating build. [`drive_face`], [`drive_joined_face`] and
/// [`drain_rejected_face`] are distinct `async fn` opaque types, so a
/// `max_links > 1` loop needs one boxed `dyn Future` to hold them all in the same
/// [`FuturesUnordered`] (the same reason [`OpenFuture`] boxes). A non-multilink
/// build has only `drive_face`, so its `driving` set stays the unboxed
/// `impl Future` — byte-identical to today (this alias is feature-gated).
#[cfg(feature = "transport-multilink")]
type DriveFuture<'f> = Pin<Box<dyn Future<Output = (Face, DriverOutcome)> + 'f>>;

/// Item 751 — what every face this loop opens is opened from, dialled,
/// accepted and re-dialled alike: the node's session-init template, and the
/// south partition its forwarder places faces by
/// ([`FaceForwarder::south_partition`]), which each session announces from on
/// its Open.
///
/// One value carried to every open site rather than a second parameter beside
/// `params`, so no open path can be written that takes the template and drops
/// the partition: the template is the only thing an open site is handed.
#[derive(Clone)]
struct FaceTemplate {
    params: SessionInitParams,
    partition: Arc<SouthPartition>,
    /// The node's authentication ([`FaceForwarder::session_auth`]), installed on each session
    /// beside the partition.
    #[cfg(feature = "session-extauth")]
    auth: Option<SessionAuth>,
    /// The node's namespace ([`FaceForwarder::session_namespace`]), installed on each session
    /// beside the partition.
    #[cfg(feature = "routing-namespace")]
    namespace: Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr>,
}

/// Which side of a handshake a session is opened on: the authentication a node holds is
/// different for the peers it accepts (it verifies their credentials) and for the peers it
/// dials (it presents its own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRole {
    /// The session was accepted: this node is the responder.
    Accept,
    /// The session was dialled: this node is the initiator.
    Dial,
}

/// How a node builds the authentication of one session: called for each session, on the side
/// ([`AuthRole`]) it is opened from, so every handshake starts from its own state. `None` is
/// "this node asks nothing of, and offers nothing to, a session opened on that side".
#[cfg(feature = "session-extauth")]
pub type SessionAuth =
    Arc<dyn Fn(AuthRole) -> Option<wz_session_core::auth_dispatch::AuthDispatch> + Send + Sync>;

impl FaceTemplate {
    /// The template and the staging that installs the partition and the node's authentication
    /// on a session before its first wire byte, split for one open call. `role` is the side the
    /// session is opened from. `expected_zid` is the node a dial is made for
    /// ([`MeshDialTarget::expected_zid`]); an accepted session names none.
    fn into_parts(
        self,
        role: AuthRole,
        expected_zid: Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]>,
    ) -> (
        SessionInitParams,
        impl FnOnce(&Arc<SessionLinkActions>) -> Result<(), OpenError>,
    ) {
        let partition = self.partition;
        #[cfg(feature = "session-extauth")]
        let auth = self.auth;
        #[cfg(feature = "routing-namespace")]
        let namespace = self.namespace;
        #[cfg(not(feature = "session-extauth"))]
        let _ = role;
        (self.params, move |actions: &Arc<SessionLinkActions>| {
            if let Some(zid) = expected_zid {
                actions.expect_peer_zid(zid);
            }
            actions.set_south_partition((*partition).clone());
            #[cfg(feature = "routing-namespace")]
            if let Some(namespace) = &namespace {
                actions.set_namespace(namespace.clone());
            }
            #[cfg(feature = "session-extauth")]
            if let Some(dispatch) = auth.as_ref().and_then(|build| build(role)) {
                actions.install_auth_dispatch(dispatch);
            }
            Ok(())
        })
    }
}

/// Run the accepted link's deferred transport handshake, then bring it up to
/// Established. Tagged with `(id, peer)` so the loop can route the result without
/// threading state through [`FuturesUnordered`]. The transport (ws/tls) SERVER
/// handshake ([`AcceptedLink::handshake`]) runs HERE, in the spawned per-face
/// future — NOT in the loop's `select!` arm — so a slow/stalled handshake never
/// blocks accepting the next peer (a failed handshake surfaces as
/// [`OpenError::AcceptHandshake`], an isolated `FaceFailed`). Production
/// semantics: `max_iters = None` (the accept-side open-deadline —
/// `accepting.inactivity_timeout`, which is what is left of
/// [`AcceptBounds::timeout_ms`] once the link's own handshake is done — bounds a silent peer;
/// see
/// [`accept_and_open_session_with_offer`](crate::session_open::accept_and_open_session_with_offer)).
#[allow(clippy::too_many_arguments)]
async fn open_face(
    id: FaceId,
    peer: AcceptedPeer,
    accepted: AcceptedLink,
    template: FaceTemplate,
    offer: SessionOffer,
    clock: TokioTime,
    tick_interval_ms: u64,
    bounds: AcceptBounds,
) -> OpenResult {
    let (params, stage) = template.into_parts(AuthRole::Accept, None);
    let started = clock.now_monotonic_ms();
    let result = match handshake_within(accepted, &bounds).await {
        // R2095 — the loop's WHOLE capability offer rides the accept open, the
        // same value its dials carry. A declared QoS band still arms the
        // acceptor's subset containment against the initiator's `QoSLink`; what
        // is new is that the other capabilities travel with it, which is what
        // zenoh's acceptor does off the manager config the opener also reads.
        Ok(link) => {
            let spent = clock.now_monotonic_ms().saturating_sub(started);
            accept_and_open_session_with_staging(
                link,
                params,
                offer,
                stage,
                clock,
                None,
                tick_interval_ms,
                bounds.timeouts_after(spent),
            )
            .await
        }
        Err(e) => Err(OpenError::AcceptHandshake(e)),
    };
    (id, peer, result)
}

/// The accepted link's own handshake (the ws or tls server side), given at most the accept
/// bound: upstream wraps its whole accept in the timeout, so a peer that stalls here is
/// dropped by the same clock that bounds the session handshake after it. A bound that elapses
/// is a failed link handshake, the error of a peer that never completed it.
async fn handshake_within(accepted: AcceptedLink, bounds: &AcceptBounds) -> io::Result<DialedLink> {
    match tokio::time::timeout(
        std::time::Duration::from_millis(bounds.timeout_ms),
        accepted.handshake(),
    )
    .await
    {
        Ok(link) => link,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the accepted link did not complete its handshake within the accept timeout",
        )),
    }
}

/// Dial one configured peer and bring the OUTBOUND link up to Established — the
/// dial-out twin of [`open_face`]. Where `open_face` opens an *accepted* link via
/// [`accept_and_open_session_with_offer`](crate::session_open::accept_and_open_session_with_offer),
/// this connects to `peer` then opens the *initiated* link via
/// [`initiate_and_open_session_with_offer`](crate::session_open::initiate_and_open_session_with_offer)
/// (the same SSOT the single-session initiator drives; reached through its
/// staging twin so the template's partition rides it), tagged `(id, peer)` so its completion
/// routes through the same `opening` arm. A failed TCP connect surfaces as
/// [`OpenError::Dial`] (a `FaceFailed`, not a panic), so one unreachable peer
/// never sinks the mesh.
///
/// R2233 (open-debt item 585) — EVERY IP-family scheme, not TCP. This function
/// used to call `TcpStream::connect(peer)` directly, bypassing the scheme
/// dispatcher [`dial_locator`] that has carried tls / ws / quic /
/// quic-datagram / udp for rounds; that bypass — not a missing transport — was
/// the whole of "wz cannot mesh-dial anything but TCP", while the ACCEPT side
/// of the same loop took the entire stream family via
/// [`BoundListener::accept_raw`]. Dialing through the dispatcher makes the two
/// sides symmetric and costs one call.
///
/// `dial_config` is the out-of-band material a locator string cannot carry (the
/// TLS / QUIC client certs). It is per-LOOP rather than per-target, which is
/// upstream's shape — zenoh builds one `TransportManager` config and every
/// `peer_connector` dials from it — and it is an [`Arc`] because each dial is a
/// separate future in the loop's `opening` set.
///
/// `target` is the numeric endpoint the loop holds; its address is ALSO this
/// dial's pre-handshake identity ([`AcceptedPeer::Ip`], the dedup key, the
/// re-dial schedule's key), so it is read off the same value rather than
/// derived a second way.
async fn dial_face(
    id: FaceId,
    target: MeshDialTarget,
    dial_config: Arc<DialConfig>,
    template: FaceTemplate,
    offer: SessionOffer,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let peer = target.peer_tag();
    let (params, stage) = template.into_parts(AuthRole::Dial, target.expected_zid);
    // R2944 — the link's QoS metadata is its endpoint's, read before the dial.
    let offer = match crate::session_open::offer_for_endpoint(offer, &target.locator) {
        Ok(offer) => offer,
        Err(e) => return (id, peer, Err(e)),
    };
    let result = match dial_locator(target.locator, &dial_config).await {
        // R2095 (open-debt item 513) — THE seam the item names. Every capability
        // the node was configured with rides THIS InitSyn; before it a mesh dial
        // went out through the bare open, so a `--peer` / `--router-hat` node
        // offered nothing at all no matter what its config file said. A declared
        // band still arms the initiator's superset containment against the
        // acceptor's InitAck — it is one field of the offer now rather than the
        // only thing in it.
        Ok(link) => {
            initiate_and_open_session_with_staging(
                link,
                params,
                offer,
                stage,
                clock,
                None,
                tick_interval_ms,
            )
            .await
        }
        Err(e) => Err(OpenError::Dial(e)),
    };
    // R2900 — the tag is the target's own: an address for the IP family, the
    // transport name for the four shapes that have none (the accept side's
    // split, now that the dial side carries those shapes too).
    (id, peer, result)
}

/// R311y219 (transport-multilink) — the deterministic per-face QoS-priority band that pins each priority conduit to one
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
/// (the key a second link is bound to the logical session by). Byte-identical to
/// [`open_face`] otherwise; the loop branches on `max_links` at the accept site.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn open_face_multilink(
    id: FaceId,
    peer: AcceptedPeer,
    accepted: AcceptedLink,
    offer: SessionOffer,
    band: (Priority, Priority),
    template: FaceTemplate,
    clock: TokioTime,
    tick_interval_ms: u64,
    bounds: AcceptBounds,
) -> OpenResult {
    let (params, stage) = template.into_parts(AuthRole::Accept, None);
    let started = clock.now_monotonic_ms();
    // The deferred transport handshake runs here in the spawned future (never the
    // loop's `select!` arm), same as the single-link [`open_face`] — a failed
    // ws/tls handshake is an isolated `FaceFailed`, not a loop stall.
    let result = match handshake_within(accepted, &bounds).await {
        Ok(link) => {
            let spent = clock.now_monotonic_ms().saturating_sub(started);
            accept_multilink_with_staging(
                link,
                params,
                offer,
                band,
                stage,
                clock,
                None,
                tick_interval_ms,
                bounds.timeouts_after(spent),
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
/// so the initiator offers the ext + captures the responder's ephemeral pubkey.
/// Byte-identical to [`dial_face`] otherwise; the loop branches on `max_links` at
/// each dial site.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn dial_face_multilink(
    id: FaceId,
    target: MeshDialTarget,
    dial_config: Arc<DialConfig>,
    offer: SessionOffer,
    band: (Priority, Priority),
    template: FaceTemplate,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    let peer = target.peer_tag();
    let (params, stage) = template.into_parts(AuthRole::Dial, target.expected_zid);
    // R2944 — the link's QoS metadata is its endpoint's, read before the dial;
    // `band` stands in only where the endpoint declares none.
    let offer = match crate::session_open::offer_for_endpoint(offer, &target.locator) {
        Ok(offer) => offer,
        Err(e) => return (id, peer, Err(e)),
    };
    let result = match dial_locator(target.locator, &dial_config).await {
        // R2096 (open-debt item 516) — THE seam the item names. R2095 wired the
        // SINGLE-link dial (`dial_face`) to the whole offer and this one kept a
        // bare `qos: bool`, so on an aggregating node three of the four
        // capabilities reached no InitSyn at all and the wire form depended on
        // `--max-links`.
        Ok(link) => {
            initiate_multilink_with_staging(
                link,
                params,
                offer,
                band,
                stage,
                clock,
                None,
                tick_interval_ms,
            )
            .await
        }
        Err(e) => Err(OpenError::Dial(e)),
    };
    // Dial target -> its own tag, same as `dial_face`.
    (id, peer, result)
}

/// R311y212 (transport-multilink per-link auto-re-add) — the backoff + 0x4 re-dial
/// twin: a backoff sleep composed with [`dial_face_multilink`]'s
/// 0x4-negotiating establishment. Because the re-dial reaches the SAME peer (the
/// retained `SocketAddr`), it captures the SAME REMOTE ephemeral multilink pubkey
/// the survivor is bound to, so `join_link`'s `authorize_link` config-equality
/// (the candidate's captured-peer key vs the session's bound-peer key) passes —
/// the identity is the PEER's key, not this node's. It re-stages its QoS-priority
/// `band` (the DEAD link's retained value, not `multilink_priority_range(new_id)`
/// — the fresh id's parity may differ, which would flip the band and collapse
/// the segregation).
/// Completes into the same `opening` -> [`Step::Opened`] -> JOIN path as an
/// immediate multilink dial, so a successful re-dial aggregates onto the surviving
/// shared core (`join_link`) and a failed one surfaces `Err` -> the Err arm
/// re-schedules it (retry-until-success).
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
async fn dial_face_multilink_after(
    id: FaceId,
    target: MeshDialTarget,
    dial_config: Arc<DialConfig>,
    backoff_ms: u64,
    offer: SessionOffer,
    band: (Priority, Priority),
    params: FaceTemplate,
    clock: TokioTime,
    tick_interval_ms: u64,
) -> OpenResult {
    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    dial_face_multilink(
        id,
        target,
        dial_config,
        offer,
        band,
        params,
        clock,
        tick_interval_ms,
    )
    .await
}

/// R311y786 — the per-PEER-ADDRESS re-dial schedule: how long each dropped or
/// failed outbound dial waits before its next attempt, and how that wait grows.
///
/// Until R311y786 this was a `const RECONNECT_BACKOFF_MS: u64 = 1000`, so a
/// configured peer that was simply switched off was re-dialed at 1 Hz forever —
/// where zenoh's `peer_connector_retry` holds a `ConnectionRetryPeriod` across
/// the retries of one outage and grows it toward `period_max_ms`
/// (`net/runtime/orchestrator.rs:787-820`). The growth arithmetic itself is
/// [`RetryPeriod`], shared with the client reconnect supervisor.
///
/// Keyed by ADDRESS, not [`FaceId`], because the id is fresh on every re-dial —
/// keying on it would rebuild the state each attempt and reproduce the fixed
/// delay exactly. The address is what persists across an outage, and it is
/// already the key both substrates track their dials by.
///
/// Decision D5 — generic over what names a peer (`K`). The `transport-multilink`
/// per-link re-add keys it by address. The loop's peers
/// ([`crate::loop_peers`], `router-connect-reconcile`) key their own instance
/// by [`crate::loop_peers::PeerKey`]: a configured endpoint's outage is its
/// address's, a node's is the node's and not one of its addresses'. The two
/// instances are two schedules, one per substrate, and a dial belongs to one
/// substrate (the planner's are its own; the others are the re-add's).
#[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
pub(crate) struct RedialSchedule<K = MeshDialKey> {
    policy: RetryPolicy,
    /// Only addresses with an outage IN PROGRESS. [`Self::forget`] removes an
    /// address the moment a dial to it succeeds, so this map does not grow with
    /// the mesh — it holds the peers currently down, not the peers ever seen.
    /// R2900 — keyed by the target's [`MeshDialKey`], the address for the IP
    /// family and the naming value for the four shapes that have none.
    periods: BTreeMap<K, RetryPeriod>,
}

#[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
impl<K: Ord + Clone> RedialSchedule<K> {
    pub(crate) fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            periods: BTreeMap::new(),
        }
    }

    /// The wait for the next re-dial of `addr`, growing its state for the one
    /// after. A first-ever (or post-success) call returns `period_init_ms`, so
    /// the FIRST re-dial of an outage is unchanged from the fixed-delay era —
    /// which is why adopting the growth does not move any timing a test that
    /// observes only the first re-dial depends on.
    /// R2496 — `overrides` is the endpoint's own `#`-tail retry span, layered
    /// over the global policy at the moment the outage's period is CREATED.
    /// Laid on here rather than at construction because the schedule is one
    /// instance for the whole loop while the overrides belong to one address.
    pub(crate) fn next_ms(
        &mut self,
        addr: &K,
        overrides: Option<&wz_session_core::locator::LocatorRetry>,
    ) -> u64 {
        let policy = self.policy.layered(overrides);
        self.periods
            .entry(addr.clone())
            .or_insert_with(|| policy.period())
            .next_ms()
    }

    /// Forget `addr`'s growth: the next outage starts at `period_init_ms` again.
    ///
    /// Called when a dial SUCCEEDS (zenoh's `period` is a local of
    /// `peer_connector_retry` and dies with the successful connect) and when an
    /// address stops being desired (a reconcile removal — otherwise a peer
    /// re-added to the connect list an hour later would inherit the ceiling from
    /// the outage that preceded its removal).
    pub(crate) fn forget(&mut self, addr: &K) {
        self.periods.remove(addr);
    }
}

/// R311y212 (transport-multilink) — schedule a re-dial + re-JOIN of a dropped
/// aggregated link this node DIALED (its own substrate, NOT gated on
/// `router-connect-reconcile`). Unlike a configured endpoint, which the loop's
/// peers hold by its connection machine ([`crate::loop_peers`]), every retained
/// multilink link is permanently wanted while its session lives. R311y786 — its
/// waits come from a [`RedialSchedule`] keyed by address: a PER-LINK policy is
/// still the deferred slice, so N links to one address share that address's
/// schedule. Re-keys the retained endpoint to a fresh [`FaceId`] BEFORE
/// the backoff (so the re-add is tracked across the drop->redial gap and the Err
/// arm can retry it), carrying the DEAD link's QoS-priority `band` so the
/// re-added link restores its priority band (a fresh-id band would flip on
/// parity and collapse the segregation). `announce`
/// controls the log level: the first re-add after a drop logs at `info` (an
/// operator-visible link flap), retries at `debug`. The re-dial completes into the
/// SAME `opening` -> [`Step::Opened`] JOIN path, so it aggregates onto the
/// surviving shared core with SN continuity.
#[cfg(feature = "transport-multilink")]
#[allow(clippy::too_many_arguments)]
fn schedule_multilink_redial(
    target: MeshDialTarget,
    dial_config: &Arc<DialConfig>,
    offer: SessionOffer,
    band: (Priority, Priority),
    // R2233 — the retained endpoint is the LOCATOR now, not a bare address: this
    // substrate has no `desired` map to look the dial plan up in (every retained
    // multilink endpoint is permanently wanted), so the plan has to travel with
    // the retention. Its key is the schedule's key.
    ml_dial_endpoints: &mut BTreeMap<FaceId, (MeshDialTarget, (Priority, Priority))>,
    redial: &mut RedialSchedule,
    opening: &mut FuturesUnordered<OpenFuture>,
    next_id: &mut u64,
    announce: bool,
    params: &FaceTemplate,
    clock: TokioTime,
    tick_interval_ms: u64,
) {
    let id = FaceId(*next_id);
    *next_id += 1;
    // Re-key the retained endpoint to the fresh id BEFORE the backoff, so the
    // re-add is tracked (a failed re-dial's Err arm finds it and retries).
    let addr = target.key.clone();
    ml_dial_endpoints.insert(id, (target.clone(), band));
    let backoff_ms = redial.next_ms(&addr, target.retry());
    if announce {
        log::info!(
            "multilink: re-adding dropped link to {addr} in {backoff_ms}ms (face {})",
            id.0
        );
    } else {
        log::debug!(
            "multilink: retrying re-add to {addr} in {backoff_ms}ms (face {})",
            id.0
        );
    }
    opening.push(Box::pin(dial_face_multilink_after(
        id,
        target,
        Arc::clone(dial_config),
        backoff_ms,
        offer,
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
///
/// Generic over the forwarder (`?Sized`, so `&dyn FaceForwarder` still fits) because
/// the drive of a SPAWNED face holds the forwarder as `dyn FaceForwarder + Send +
/// Sync`, and the future is `Send` only if the reference it holds is to a `Sync`
/// type, which a bare `dyn FaceForwarder` is not.
async fn drive_face<F: FaceForwarder + ?Sized>(
    face: Face,
    mut opened: OpenedSession,
    forwarder: &F,
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
        // R2702/R2703 — no session-owned stages here, and that is a scope
        // statement rather than an omission: this loop drives a FACE of a
        // routing node, whose §5.16 ingress admission already happens at the
        // forwarder (`admit_inbound`, consulted at the top of `forward`), and
        // whose samples go to the routing tables rather than to a buffered
        // subscription. Adding the decorator here would run the chain twice, which is why the
        // forwarder is ASKED ([`FaceForwarder::ingress`]) and the routing ones answer nothing.
        crate::session_glue::LoopStages {
            ingress: |outcome: &mut wz_session_core::driver_loop::DriverLoopOutcome| {
                forwarder.ingress(face.id, outcome)
            },
            // The forwarder's credit gate: a face that fed a destination with no room left
            // stops reading until the destination drains, and nothing else stops.
            after_dispatch: || {
                let (forwarder, id) = (forwarder, face.id);
                async move {
                    while let Some(wake) = forwarder.read_gate(id) {
                        // Registered as a waiter BEFORE the gate is asked again, so a notice
                        // raised between the two is not lost: either the second answer sees
                        // the room, or the notice finds this waiter.
                        let notified = wake.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        if forwarder.read_gate(id).is_none() {
                            break;
                        }
                        // Bounded, so that a link that does not notify (a driver that was
                        // not asked, or one whose waker was cleared) costs a recheck and not
                        // a stalled face.
                        let _ = tokio::time::timeout(READ_GATE_BACKSTOP, notified).await;
                    }
                }
            },
        },
    )
    .await;
    opened.drain_to_close().await;
    (face, outcome)
}

/// The longest a gated face waits for a notice that a destination has room before it asks the
/// forwarder again. The notice is what ends the wait (`BoxedLinkDriver::watch_room`); this is
/// for the link that never gives one, and is not the cadence of a healthy gate.
const READ_GATE_BACKSTOP: Duration = Duration::from_millis(25);

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

/// What turns a face's drive into a task of its own: the hook a node uses to put its own
/// condition around every spawned drive (the C ABI wraps it in its read gate, so a stopped
/// read task stops a face as it stops the node).
///
/// A face's drive normally runs inside the accept loop's single task (see the module
/// comment). For a node whose forwarder is `Send + Sync` the loop can instead spawn it on
/// the runtime ([`SpawnedFaces`]), so N links are driven by N tasks and the node's capacity
/// is not one core.
pub trait FaceExecutor: Send + Sync {
    /// The drive of one face, wrapped as this executor wants it polled. The default runs
    /// it as it is.
    fn wrap(&self, drive: SpawnedDrive) -> SpawnedDrive {
        drive
    }
}

/// The boxed drive of a spawned face: `Send` (it runs on a worker thread) and `'static`
/// (it owns its forwarder handle and its session).
pub type SpawnedDrive = Pin<Box<dyn Future<Output = (Face, DriverOutcome)> + Send + 'static>>;

/// The [`FaceExecutor`] that wraps nothing.
pub struct PlainFaceExecutor;

impl FaceExecutor for PlainFaceExecutor {}

/// Where a spawned face's drive runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnOn {
    /// On the runtime's workers: N faces are driven by up to N threads at once.
    Workers,
    /// As a local task of the thread the loop itself runs on (inside a `LocalSet`): the faces
    /// are still driven one thread at a time, which is the contract of a node whose callbacks
    /// are serial, but each face is woken by its own socket instead of through the loop's
    /// task. That saves, for every frame, the loop polling each of its other arms (the
    /// listeners, the dial and multicast channels, the opens in flight) to find the one drive
    /// that was ready.
    LocalSet,
}

/// The things a loop needs to spawn faces instead of holding their drives itself.
pub struct SpawnedFaces {
    /// The forwarder, shared with every spawned drive. `Sync` because, on [`SpawnOn::Workers`],
    /// the drives call it from different threads at once.
    pub forwarder: Arc<dyn FaceForwarder + Send + Sync>,
    /// How each drive is wrapped before it is spawned.
    pub executor: Arc<dyn FaceExecutor>,
    /// Where each drive runs.
    pub on: SpawnOn,
}

/// [`drive_face`] owning its forwarder handle, as a spawned drive must.
async fn drive_face_shared(
    face: Face,
    opened: OpenedSession,
    forwarder: Arc<dyn FaceForwarder + Send + Sync>,
) -> (Face, DriverOutcome) {
    drive_face(face, opened, &*forwarder).await
}

/// The next spawned drive to finish, with the face it drove. A drive that PANICKED or was
/// cancelled has no result to hand back, so its face comes from `faces` (kept by task id
/// when it was spawned) and its outcome is `Terminated`: the face is gone either way, and
/// the loop's teardown of a gone face is the same. `None` when nothing is spawned.
async fn next_spawned(
    drives: &mut tokio::task::JoinSet<(Face, DriverOutcome)>,
    faces: &mut BTreeMap<tokio::task::Id, Face>,
) -> Option<(Face, DriverOutcome)> {
    match drives.join_next_with_id().await? {
        Ok((task, driven)) => {
            faces.remove(&task);
            Some(driven)
        }
        Err(failed) => {
            let face = faces.remove(&failed.id())?;
            log::error!(
                "the drive of face {} ended without a result: {failed}",
                face.id.0
            );
            Some((face, DriverOutcome::Terminated))
        }
    }
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
    /// The forwarder's wake signal ([`FaceForwarder::wake_signal`]) was raised — call
    /// [`FaceForwarder::woken`]. Only ever produced by a forwarder that returned a signal.
    Woken,
    /// A gossip-autoconnect [`DialIntent`] arrived on the dial-intent channel —
    /// dial the discovered peer unless a face to it is already held. Only ever
    /// produced when [`FaceSources::dial_intents`] is `Some`.
    Dial(DialIntent),
    /// A Push arrived on the multicast INGRESS channel (the deferred `mcast_faces`
    /// plane, I1) — route it via [`FaceForwarder::route_mcast_ingress`]. Only ever
    /// produced when [`FaceSources::mcast_ingress`] is `Some`.
    ///
    /// Boxed: the item carries a whole owned `Push` or `Request`, which is far
    /// larger than every other `Step` (clippy `large_enum_variant`), and one box
    /// per group-ingress message is negligible beside the message it carries.
    McastIngress(Box<McastIngressItem>),
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
    /// A desired-outbound-connect-set reconcile, carrying its own verb
    /// ([`ConnectReconcile`]): dial each newly-listed address not already being
    /// dialed (ADD-ONLY teardown-wise, the wz analogue of zenoh's `update_peers`
    /// Peer/Router branch). Only ever produced when [`FaceSources::reconcile`] is
    /// `Some`; the variant is always present so the `select!` arm carries no
    /// attribute (tokio's `select!` rejects branch attributes), and its handler body
    /// is `#[cfg]`-gated — inert without the feature.
    Reconcile(ConnectReconcile),
    /// Decision D5 — the retry timer of a peer the loop holds fired. Always
    /// present, like [`Self::Reconcile`], because `select!` takes no branch
    /// attribute; the queue that produces it is empty in a build without the
    /// loop's peers.
    PeerRetry(PeerRetryDue),
}

/// Decision D5 — what a peer's retry timer yields: the peer, and which arming
/// of its timer fired ([`crate::loop_peers::PeerAction::Retry`]).
#[cfg(feature = "router-connect-reconcile")]
type PeerRetryDue = (crate::loop_peers::PeerKey, u64);
/// Nothing is ever armed in a build without the loop's peers; this exists so
/// the queue's type names something.
#[cfg(not(feature = "router-connect-reconcile"))]
type PeerRetryDue = std::convert::Infallible;

/// Decision D5 — the retry timers of the peers the loop holds: each yields its
/// peer when it fires. Empty in a build without the loop's peers.
type PeerRetries = FuturesUnordered<Pin<Box<dyn Future<Output = PeerRetryDue>>>>;

/// Decision D5 — the parts of the face loop the actions of its peers
/// ([`crate::loop_peers`]) are taken on, borrowed for one batch of them.
#[cfg(feature = "router-connect-reconcile")]
struct PeerHost<'a> {
    opening: &'a mut FuturesUnordered<OpenFuture>,
    retries: &'a mut PeerRetries,
    /// The sessions of the faces a peer is held by, which a `close` may drop.
    #[cfg(feature = "session-close-ingress")]
    sessions: &'a BTreeMap<FaceId, Arc<SessionLinkActions>>,
    #[cfg(feature = "transport-multilink")]
    max_links: usize,
    #[cfg(feature = "transport-multilink")]
    ml_dial_endpoints: &'a mut BTreeMap<FaceId, (MeshDialTarget, (Priority, Priority))>,
    dial_config: &'a Arc<DialConfig>,
    params: &'a FaceTemplate,
    offer: SessionOffer,
    clock: TokioTime,
    tick_interval_ms: u64,
}

#[cfg(feature = "router-connect-reconcile")]
impl PeerHost<'_> {
    /// Take what the loop's peers asked for: dial a peer's target as a fresh
    /// face, arm a peer's retry timer, or close a session its peer no longer
    /// wants. Returns how many dials it opened.
    ///
    /// A configured endpoint's dial aggregates (`transport-multilink`,
    /// `max_links > 1`) as every dial of an aggregating node does, and its link
    /// is retained for the per-link re-add; a node's dial is held by one face.
    fn take(self, actions: Vec<crate::loop_peers::PeerAction>) -> usize {
        use crate::loop_peers::PeerAction;
        #[cfg(feature = "transport-multilink")]
        use crate::loop_peers::PeerKey;
        let mut dials = 0;
        for action in actions {
            match action {
                PeerAction::Dial { id, key, target } => {
                    dials += 1;
                    #[cfg(feature = "transport-multilink")]
                    if self.max_links > 1 && matches!(key, PeerKey::Endpoint(_)) {
                        self.ml_dial_endpoints
                            .insert(id, (target.clone(), multilink_priority_range(id)));
                        self.opening.push(Box::pin(dial_face_multilink(
                            id,
                            target,
                            Arc::clone(self.dial_config),
                            self.offer,
                            multilink_priority_range(id),
                            self.params.clone(),
                            self.clock,
                            self.tick_interval_ms,
                        )) as OpenFuture);
                        continue;
                    }
                    // Only an aggregating build reads which peer a dial is for.
                    #[cfg(not(feature = "transport-multilink"))]
                    let _ = key;
                    self.opening.push(Box::pin(dial_face(
                        id,
                        target,
                        Arc::clone(self.dial_config),
                        self.params.clone(),
                        self.offer,
                        self.clock,
                        self.tick_interval_ms,
                    )));
                }
                PeerAction::Retry {
                    key,
                    generation,
                    after_ms,
                    ..
                } => self.retries.push(Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(after_ms)).await;
                    (key, generation)
                })),
                // Only a peer's machine being stopped asks for it, and an AP loop stops
                // a peer only for a lifecycle `close`, which is that seam's.
                PeerAction::Close { id } => {
                    #[cfg(feature = "session-close-ingress")]
                    if let Some(actions) = self.sessions.get(&id) {
                        actions.request_close();
                    }
                    #[cfg(not(feature = "session-close-ingress"))]
                    let _ = id;
                }
            }
        }
        dials
    }
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

/// Await the forwarder's wake signal ([`FaceForwarder::wake_signal`]), or park forever when it
/// has none: the arm of `face_drive_loop`'s `select!` that lets a forwarder holding messages
/// for a full link send them as soon as the link has room.
async fn forwarder_woken(signal: &Option<Arc<tokio::sync::Notify>>) {
    match signal {
        Some(signal) => signal.notified().await,
        None => std::future::pending::<()>().await,
    }
}

/// Await the next inbound connection on ANY of the node's bound listeners — the
/// accept arm of `face_drive_loop`'s `select!`, and the seam that makes
/// `listen/endpoints` a LIST rather than a first-element (R2099, open-debt item
/// 512).
///
/// Upstream shape: zenoh's `bind_listeners_impl`
/// (`zenoh/src/net/runtime/orchestrator.rs:520-541`) adds every configured
/// endpoint to the one transport manager, which then accepts on all of them into
/// a single session table. wz has no manager-owned accept task, so the fan-in is
/// here: every listener is polled each iteration and the first to yield wins.
///
/// Three arms, and the first two exist to keep the pre-existing shapes exactly as
/// they were:
/// * EMPTY — park forever. A `FaceSources` with no listener accepts nothing (a
///   dial-only node), and a parking arm is how every other optional source in
///   this loop spells that (see [`recv_dial_intent`]).
/// * ONE — await it directly. No `select_all`, no boxing: the single-listener
///   path is the one every node before this round took, and it stays identical.
/// * MANY — `select_all` over one [`BoundListener::accept_raw`] future per
///   listener. Cancel-safe in both directions: `select_all` drops the losers, and
///   every `accept_raw` arm is individually cancel-safe (its per-variant doc says
///   so — the channel-backed ones are bare `recv`s, the socket-backed ones are
///   `accept` syscalls that buffer in the kernel), which is the same property the
///   surrounding `select!` already relies on.
///
/// FAIRNESS: `select_all` polls in order, so a listener that is always ready can
/// starve a later one within a single call. It cannot starve it across calls —
/// each call builds a fresh future set — and the same in-order bias already
/// exists between the `select!` arms themselves, so this adds no new class.
async fn accept_any(listeners: &mut [BoundListener]) -> io::Result<(AcceptedLink, AcceptedPeer)> {
    match listeners {
        [] => std::future::pending().await,
        [only] => only.accept_raw().await,
        many => {
            let futures: Vec<_> = many.iter_mut().map(|l| Box::pin(l.accept_raw())).collect();
            futures_util::future::select_all(futures).await.0
        }
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
async fn recv_reconcile(rx: &mut Option<ReconcileReceiver>) -> ConnectReconcile {
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
    std::future::pending::<ConnectReconcile>().await
}

/// The first locator a [`DialIntent`] carries that the dial path ([`dial_face`])
/// can actually reach: a NUMERIC IP endpoint, parsed through the locator SSOT
/// [`parse_locator`].
///
/// R2233 (open-debt item 585) — the scheme is no longer part of the question.
/// This used to demand `Proto::Tcp` because `dial_face` called
/// `TcpStream::connect`; now that the dial goes through [`dial_locator`], a
/// discovered peer that advertises only `quic/...` or `tls/...` is dialable and
/// skipping it was the same TCP-only bypass one plane over. What is still
/// demanded is that the locator names its target without a resolver: the
/// gossip arm runs on the loop's own task and must not block on one.
///
/// R2900 — and that is ALL that is demanded. The dedup key is a
/// [`MeshDialKey`](crate::session_open::MeshDialKey) now, so a peer that advertises only `unixsock-stream/...`,
/// `unixpipe/...`, `serial/...` or `vsock/...` is dialable too, as the pin's
/// autoconnect dials whatever locator a discovered peer carries. A DNS name is
/// still skipped, for the resolver reason above. `None` when no carried locator
/// qualifies.
pub(crate) fn first_dialable_locator(locators: &[String]) -> Option<MeshDialTarget> {
    locators.iter().find_map(|loc| {
        crate::session_open::plan_endpoint(loc)
            .ok()
            .and_then(|locator| mesh_dial_plan(locator).ok())
    })
}

/// The outcome of weighing a [`DialIntent`] against the held faces — the pure
/// dial decision the `Step::Dial` arm acts on (extracted so it is unit-testable
/// without standing up a TCP loop).
enum DialDecision {
    /// Dial the discovered peer at this target.
    Dial(MeshDialTarget),
    /// Skip — a face to this peer's zid is already held (the zenoh
    /// `get_transport_unicast(&zid).is_some()` dedup).
    AlreadyHeld,
    /// Skip — none of the carried locators is dialable.
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
    // The id and not its spelling: an intent holds the id from the routing graph (trimmed)
    // and a face the bytes its peer sent.
    faces.values().any(|z| {
        z.as_deref()
            .is_some_and(|held| crate::zid_hex::same_zid(held, zid))
    })
}

/// Weigh a [`DialIntent`] against the held faces: dedup first (a peer already held
/// is never re-dialed), then pick a dialable locator. The forwarder already
/// applied the autoconnect role + zid policy at emit (A5b), so this is only the
/// loop-side "do I already have it / can I reach it" decision.
///
/// The dial is made for the node the intent names (decision D4 of
/// `docs/session-lifecycle-intent.md`): a discovery plane found a zid and the
/// locators it advertised, so a session another node answers at the locator closes
/// at its InitAck, as upstream's `connect_peer` dials each locator for the zid
/// (`zenoh/src/net/runtime/orchestrator.rs`
/// @ `match manager.open_transport_unicast_with_zid(endpoint, zid).await {`).
///
/// The locators are the node's candidates in `directory` (decision D3), which
/// [`learn_locators`] took the intent into first, so a node a Hello and the
/// flood both found is tried at every locator either gave, in the directory's
/// order.
fn dial_decision(
    faces: &BTreeMap<FaceId, Option<Vec<u8>>>,
    intent: &DialIntent,
    directory: &LoopDirectory,
    now_ms: u64,
) -> DialDecision {
    if holds_zid(faces, &intent.zid) {
        return DialDecision::AlreadyHeld;
    }
    let Some(zid) = wz_session_core::credential_identity::zid_from_wire(&intent.zid) else {
        return DialDecision::NoLocator;
    };
    match first_dialable_locator(&candidate_locators(directory, &zid, now_ms)) {
        Some(target) => DialDecision::Dial(target.for_node(zid)),
        None => DialDecision::NoLocator,
    }
}

/// Take a discovery into `directory` and weigh it: [`learn_locators`] then
/// [`dial_decision`], the two steps the `Step::Dial` arm takes.
fn learn_and_decide(
    faces: &BTreeMap<FaceId, Option<Vec<u8>>>,
    intent: &DialIntent,
    directory: &mut LoopDirectory,
    now_ms: u64,
) -> DialDecision {
    if let Some(zid) = wz_session_core::credential_identity::zid_from_wire(&intent.zid) {
        learn_locators(
            directory,
            &zid,
            &intent.locators,
            intent.origin.locator_source(),
            now_ms,
        );
    }
    dial_decision(faces, intent, directory, now_ms)
}

/// Where a face-drive node's faces come from: the inbound `listeners` it accepts
/// on, the outbound `dial_targets` it dials at startup (with the `dial_config`
/// trust material those dials need), and the runtime
/// `dial_intents` a gossip-autoconnect peer dials on discovery. A pure acceptor
/// ([`accept_loop`]) has no dial targets and no dial intents; a peer-mesh node
/// ([`peer_loop`]) has both static dial targets and (when a deploy enables
/// autoconnect) the dynamic dial-intent stream. Bundling the sources keeps the
/// loop signature within the argument-count budget as the family grows, and
/// names the real distinction between the two entry points.
/// One Push RECEIVED on a multicast INGRESS group, folded from the (separate,
/// `Send`) multicast drive-loop task to the `!Send` forwarder on the peer-loop
/// task (the deferred `mcast_faces` plane, I1 — see
/// [`spawn_router_mcast_group`](crate::multicast_glue::spawn_router_mcast_group)).
/// The owned `PushOwned` crosses the task boundary; the forwarder routes it via
/// [`FaceForwarder::route_mcast_ingress`]. The struct is always defined so the
/// accept-loop's `select!` arm needs no `#[cfg]` (tokio's `select!` rejects
/// attributes on branches); the `PushOwned` payload is gated on `codec-push`
/// (which provides it), and the struct is inert without `codec-push` — nothing
/// constructs it (`spawn_router_mcast_group` is `codec-push`-gated).
pub struct McastIngressItem {
    /// What arrived, in the kinds the router ADMITS from a group.
    #[cfg(feature = "codec-push")]
    pub body: McastIngressBody,
    /// The frame's reliability, preserved for the routed egress legs.
    pub reliable: bool,
    /// R311y227 — the frame's decoded QoS band, so the router re-injects the
    /// group-ingress Push into the mesh / local subscribers at the priority it
    /// arrived (DEFAULT on a non-qos group). Paired with `push` (`codec-push`).
    #[cfg(feature = "codec-push")]
    pub priority: Priority,
    /// Item 751 — the group member that sent it, as the multicast RX dispatch
    /// named it just before the frame (`IterationEvent::MulticastSource`).
    /// `None` only if no member is held at the datagram's source, which cannot
    /// be a datagram the dispatch admitted.
    pub from: Option<wz_session_core::driver_loop::MulticastPeerId>,
}

/// R2734 — what arrived on a multicast INGRESS group, in the kinds the router
/// admits into its routing core.
///
/// A BARE `PushOwned` FIELD UNTIL THIS ROUND, and the widening is the point:
/// upstream's multicast transport filters NO message kind on the way to the
/// per-peer face (`io/zenoh-transport/src/multicast/rx.rs` @
/// `peer.handler.handle_message(msg)`), where wz's fold admitted Push alone.
///
/// ⚠ IT IS DELIBERATELY NOT "ALL SEVEN KINDS". R2734 measured what each kind
/// would reach and found that every other entry point declines a source-only
/// face for a stated reason -- a group peer's subscriptions already travel by
/// the MulticastDispatcher, its Interests are answered into a face with no send
/// seam, and its Responses can match no pending query because no Request was
/// ever sent to it. Forwarding those would be wiring that dies one call later.
/// A Query is the one kind with an effect wz was actually missing: it runs a
/// local queryable. Oam is out of scope here -- it feeds upstream's linkstate
/// machinery, which is a topology question this plane does not own.
///
/// Gated with the plane it rides: `spawn_router_mcast_group` is
/// `codec-push`-gated, so without that feature nothing constructs either arm.
#[cfg(feature = "codec-push")]
pub enum McastIngressBody {
    /// A data Push, routed by [`FaceForwarder::route_mcast_ingress`].
    Push(PushOwned),
    /// A Query from a group peer, routed by
    /// [`FaceForwarder::route_mcast_ingress_request`]. Its reply is discarded,
    /// which is the pin's behaviour and not a wz shortcut: upstream hands the
    /// Response to the requesting face's `DummyPrimitives`, and wz's
    /// `send_to_face` already returns false for a face it cannot find.
    Request(RequestOwned),
}

/// A limit on the faces a loop holds that is worked out each time the loop would admit one, so
/// that it can follow something the loop does not own (what the node has measured of itself).
/// A face already held is not closed by a lower ceiling: the ceiling decides who is admitted, not
/// who stays.
///
/// It also carries the loop's refusals, live: [`AcceptLoopSummary`] reports its counts only when
/// the loop ends, and a monitor asks while it runs. Clones share the counters, so the host that
/// hands the ceiling to the loop reads what the loop counted.
#[derive(Clone)]
pub struct SessionCeiling {
    limit: Arc<dyn Fn() -> usize + Send + Sync>,
    refused_over_max_sessions: Arc<std::sync::atomic::AtomicU64>,
    refused_over_capacity: Arc<std::sync::atomic::AtomicU64>,
    shed_over_capacity: Arc<std::sync::atomic::AtomicU64>,
    /// A ceiling put on the limit from outside by a loop that read what the node can serve
    /// ([`Self::set_cap`]); `usize::MAX` is none.
    cap: Arc<std::sync::atomic::AtomicUsize>,
}

impl SessionCeiling {
    /// A ceiling that is `limit()` faces at the moment of each admission.
    pub fn new(limit: impl Fn() -> usize + Send + Sync + 'static) -> Self {
        Self {
            limit: Arc::new(limit),
            refused_over_max_sessions: Arc::default(),
            refused_over_capacity: Arc::default(),
            shed_over_capacity: Arc::default(),
            cap: Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        }
    }

    /// The faces the loop may hold now: the limit, or the ceiling put on it from outside when
    /// that is lower.
    pub fn get(&self) -> usize {
        (self.limit)().min(self.cap.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Put a ceiling on the limit, or lift it with `None`. For the loop that closes on what the
    /// node serves (`capacity_control`, behind `routing-router-hat`): the limit is a model's, and a node that cut its
    /// sessions because the model was wrong must not admit them again at the model's number.
    pub fn set_cap(&self, cap: Option<usize>) {
        self.cap.store(
            cap.unwrap_or(usize::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Faces the loop refused because `max_sessions` was reached, since it started.
    pub fn refused_over_max_sessions(&self) -> u64 {
        self.refused_over_max_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Faces the loop refused because this ceiling was reached, since it started.
    pub fn refused_over_capacity(&self) -> u64 {
        self.refused_over_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Count `closed` faces the host ordered closed because the node held more than it measured
    /// it can keep the leases of. The loop does not close them; the host that does reports them
    /// here, beside the refusals, so that one handle says everything the ceiling cost.
    pub fn note_shed(&self, closed: usize) {
        self.shed_over_capacity.fetch_add(
            u64::try_from(closed).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Faces the host ordered closed for capacity, since it started.
    pub fn shed_over_capacity(&self) -> u64 {
        self.shed_over_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SessionCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionCeiling").field(&self.get()).finish()
    }
}

// How much an accepting node gives an inbound link before its handshake is complete lives in
// `accept_bounds`, which every build has (the C interfaces carry it for every role); the loop
// that reads it re-exports it, so a path through this module still names it.
pub use crate::accept_bounds::AcceptBounds;
pub use crate::config::{ACCEPT_PENDING, ACCEPT_TIMEOUT_MS};

pub struct FaceSources {
    /// The bound listeners for inbound peers (accept source), each scheme-keyed
    /// ([`BoundListener`]) so a router/peer accepts the whole stream family
    /// (tcp/ws/tls) — `face_drive_loop`'s `select!` arm accepts one raw
    /// connection per iteration via `accept_any`, and the ws/tls SERVER
    /// handshake is deferred to the spawned open future so a slow handshake never
    /// blocks the loop. R311y376 (Stage 3) generalized this from a bare
    /// [`tokio::net::TcpListener`].
    ///
    /// R2099 (open-debt item 512) — a LIST, because `listen/endpoints` is a list
    /// and upstream binds every member of it: zenoh's `bind_listeners_impl`
    /// (`zenoh/src/net/runtime/orchestrator.rs:520-541`) loops the whole
    /// configured slice calling `add_listener` on each, and `print_locators`
    /// then names every bound locator. Until this round wz bound
    /// `listen.first()` and dropped the rest silently, which is the half-truth
    /// item 512 measured: the key reached the flag carrying ONE of its members,
    /// and was still reported APPLIED.
    ///
    /// ONE field rather than "the listener plus the extra ones", for the reason
    /// R2096 gave when it retired `qos: bool` beside [`Self::offer`]: two fields
    /// for one fact is what lets the two disagree. A single-element `Vec` is the
    /// byte-identical prior behaviour — `accept_any` awaits that one listener
    /// directly, with no `select_all` in the path.
    ///
    /// (`face_drive_loop` / `accept_any` are named in code spans rather than
    /// intra-doc links: they are PRIVATE, and a public item's doc linking to one
    /// is a rustdoc error this crate's C1bz budget counts.)
    ///
    /// EMPTY is representable and means "accept nothing": the arm parks forever,
    /// so a dial-only node is expressible without inventing a listener. That is
    /// upstream's shape too — `bind_listeners` returns `Ok` on an empty slice
    /// after warning "Starting with no listener endpoints!".
    pub listeners: Vec<BoundListener>,
    /// The peer endpoints to dial at startup (static outbound source); empty for
    /// a pure acceptor.
    ///
    /// R2233 (open-debt item 585) — LOCATORS, not bare `SocketAddr`s. The mesh
    /// dial side used to hold addresses because it dialed with
    /// `TcpStream::connect`; every scheme the operator could configure was
    /// flattened away at
    /// [`resolve_mesh_dial_target`](crate::session_open::resolve_mesh_dial_target),
    /// which is why two wz nodes could accept quic from each other and never
    /// dial it. The loop dispatches on the scheme now ([`dial_locator`]), so the
    /// scheme has to survive to it.
    ///
    /// A member with no PRE-HANDSHAKE IDENTITY — no `SocketAddr`, i.e. an
    /// unresolved DNS name or a `serial` / `unixsock-stream` / `unixpipe` /
    /// `vsock` endpoint — is REFUSED by the loop and reported, not dialed and
    /// not silently dropped: the loop's dial dedup, its `desired` connect-set
    /// and its per-address re-dial schedule are all keyed by address, so a
    /// target with none cannot take part in them. That classification is
    /// [`mesh_dial_plan`], the one this
    /// field's own resolver applies at configuration time — where the refusal
    /// is a startup error rather than a log line. The type is deliberately the
    /// WIDER one so the refusal is reported at all: it is upstream's shape too
    /// (zenoh's `connect/endpoints` is a `Vec<EndPoint>` and the orchestrator
    /// refuses what it cannot dial).
    pub dial_targets: Vec<AnyLocator>,
    /// R2233 (open-debt item 585) — the out-of-band client material every dial
    /// this loop makes needs and a locator string cannot carry: the TLS root-CA
    /// and the QUIC root-CA.
    ///
    /// THE fourth piece of item 585, and the one that is not a type change.
    /// `FaceSources` had ten fields and not one of them was trust material, so
    /// the asymmetry ran deeper than the dial call: the ACCEPT side receives its
    /// cert once, OUTSIDE the loop, at bind time ([`BoundListener`]), while the
    /// dial side needs it INSIDE the loop, on every target, at every re-dial.
    /// Without this field a `quic/...` dial reaches [`dial_locator`] with
    /// `DialConfig::default()` and lands on its typed `Unsupported` — the
    /// capability present and unreachable.
    ///
    /// PER-LOOP, not per-target, which is upstream's shape: zenoh builds one
    /// `TransportManager` from the node's config and every `peer_connector`
    /// dials from it. Per-target trust would be a separate design step.
    ///
    /// [`Arc`] rather than an owned value because each dial is its own future in
    /// the loop's `opening` set and re-dials outlive the seeding; `DialConfig`
    /// is deliberately not `Clone` (it holds built rustls configs), so a shared
    /// handle is the honest shape rather than a workaround.
    ///
    /// NOT an `Option`: `DialConfig::default()` ALREADY means "no tls / quic
    /// material", and a `tls/...` dial under it surfaces the runtime's typed
    /// `Unsupported`. A second spelling of "absent" would be one fact under two
    /// names — the reason R2096 retired `qos: bool` from beside
    /// [`Self::offer`].
    pub dial_config: Arc<DialConfig>,
    /// The runtime dial-intent stream (the dynamic outbound source): the
    /// `RouterForwarder`'s (`crate::router_forward`, with `routing-router-hat`)
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
    /// producer `spawn_router_mcast_group` is `codec-push`-gated), so the arm is
    /// inert but present (no `#[cfg]` on the `select!` branch).
    pub mcast_ingress: Option<tokio::sync::mpsc::UnboundedReceiver<McastIngressItem>>,
    /// The multicast INGRESS on-group ROUTER member relay (I3b): the router-hat's
    /// `spawn_router_mcast_group` loop sends its live Designated-Router election
    /// candidate set here on each group membership change, and the drive loop
    /// forwards it to [`FaceForwarder::set_mcast_group_members`]. `None` when the
    /// ingress plane is off (the arm parks forever). The sibling of
    /// `mcast_ingress` from the same helper.
    pub mcast_members: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<Vec<u8>>>>,
    /// The multicast INGRESS on-group SUBSCRIBER relay (sub plane, S2): the
    /// router-hat's `spawn_router_mcast_group` loop sends the deduped group-
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
    /// R2758 — how many faces this loop will hold at once
    /// (zenoh `unicast.max_sessions`).
    ///
    /// Upstream denies at the manager, under the session-table guard and right
    /// after its connection-to-self check
    /// (`io/zenoh-transport/src/unicast/manager.rs` @ `max_sessions`):
    /// `if guard.len() >= self.config.unicast.max_sessions` returns
    /// `close::reason::INVALID`. This loop holds that table as `faces`, so the
    /// bound is the same comparison at the same moment — after the
    /// dedup-by-zid rule, before the face is inserted.
    ///
    /// ⚠ UNGATED and carried even by a loop that never fills it, because a
    /// bound whose absence is invisible is the one that is discovered by a
    /// peer rather than by a reader.
    pub max_sessions: usize,
    /// How long an inbound link gets to complete its handshake and how many get it at once
    /// (zenoh `unicast.accept_timeout` and `accept_pending`): see [`AcceptBounds`]. Upstream's
    /// own when the host states none.
    pub accept: AcceptBounds,
    /// A ceiling worked out at each admission, or `None` for a node whose only bound is
    /// [`Self::max_sessions`]. A face is refused when the held set has reached the SMALLER of
    /// the two, and the refusal is counted under
    /// [`AcceptLoopSummary::refused_over_capacity`] when this one was the smaller, so an operator
    /// can tell the node's measured limit from the configured one.
    ///
    /// The capacity model's number is not known at construction: it is calibrated by the
    /// emissions the node has timed ([`crate::config::WzConfig::effective_max_sessions`]), which
    /// the first sessions of the process produce, so the bound a burst meets is the calibrated
    /// one once the first few of it are up.
    pub ceiling: Option<SessionCeiling>,
    /// Decision D6 of `docs/session-lifecycle-intent.md` — the board this loop
    /// publishes its peer machines to after each change, for the lifecycle status
    /// query to read ([`crate::peer_board`]), or `None` for a host that hosts no
    /// such query. Only a loop that holds its peers by machines (the connect
    /// reconcile with the lifecycle verbs) has anything to publish; any other
    /// leaves the board as it was given, empty. Ungated, as [`Self::ceiling`] is,
    /// so no construction site carries a cfg.
    pub peer_board: Option<crate::peer_board::PeerBoard>,
    /// R2095 (open-debt item 513) — the capability SET every face this loop
    /// opens OFFERS at its handshake, dialed and accepted alike.
    ///
    /// This is the field that closes item 513. It replaces a `FaceQosLink` that
    /// could carry a declared QoS band and nothing else, so a mesh node's
    /// `--qos` / `--lowlatency` / `--compression` / `--shm` — and every stock
    /// config key that expands into one of them — reached no wire at all: the
    /// only `SessionOffer` in the demo was built on the single-session
    /// `Role::Initiator` arm. Measured by
    /// `wz_reads_a_stock_zenohd_config`'s wire leg, which reads the InitSyn a
    /// config-driven node actually wrote.
    ///
    /// UNIFORM PER LOOP AND PER DIRECTION, and that is upstream's shape rather
    /// than a simplification: zenoh builds `StateOpen`
    /// (`io/zenoh-transport/src/unicast/establishment/open.rs:605-636`) and
    /// `StateAccept`
    /// (`io/zenoh-transport/src/unicast/establishment/accept.rs:725-755`) from
    /// the SAME `manager.config.unicast.{is_qos,is_lowlatency,is_compression}`,
    /// so a node configured for a capability offers it whichever end dialled.
    /// A per-face offer would be the per-link QoS band refinement, which is a
    /// separate design step (zenoh's `PriorityRange` IS per link).
    ///
    /// R2096 (open-debt item 516) — it is now the loop's ONLY answer to "what
    /// does this node offer". The `qos: bool` that used to sit beside it, and
    /// travel separately into the `_with_multilink` entrypoints, is gone: two
    /// fields for one fact is what let `--max-links 2` disagree with
    /// `--max-links 1` about the same flag. Read the QoS half as
    /// `offer.mode == TransportMode::Qos`.
    ///
    /// [`SessionOffer::universal`] — also its `Default` — is the zero offer, so
    /// an accept-only or capability-free loop is byte-identical to the era
    /// before this field: `apply_offer` of the universal offer stages nothing.
    pub offer: SessionOffer,
    /// R311y786 — the connection-retry period every re-dial this loop schedules is
    /// paced by: zenoh's `connect.retry` (`period_init_ms` / `period_max_ms` /
    /// `period_increase_factor`), sourced from
    /// [`WzConfig.connect_retry`](crate::config::WzConfig). Applies to BOTH re-dial
    /// substrates — `router-connect-reconcile` peer auto-reconnect and the
    /// `transport-multilink` per-link re-add — which shared the fixed constant it
    /// replaced.
    ///
    /// UNCONDITIONAL, like [`Self::offer`] and for the same reason: the
    /// alternative is a `#[cfg(any(..))]` on the field, which every construction
    /// site would then repeat and every new site would be a place to forget. A
    /// build with neither re-dial substrate simply never reads it.
    pub retry: RetryPolicy,
    /// R2844 — the node's stats registry, or `None` for a node that keeps none.
    ///
    /// This loop is the mesh node's transport manager: every face enters the
    /// held set at one site and leaves it at one of two, which is where
    /// upstream's transport manager registers a transport's stats and drops
    /// them (`io/zenoh-transport/src/unicast/manager.rs` @ `let stats = self.stats.unicast_transport_stats(`).
    /// Recording here means no host re-learns the face lifecycle to report it.
    ///
    /// UNCONDITIONAL, like [`Self::offer`]: the handle type exists in every
    /// build, and a node built without `transport-stats` passes `None`.
    pub stats: Option<crate::node_stats::NodeStats>,
}

/// How `face_drive_loop` holds the drive of its faces: through which forwarder, and whether each
/// drive is spawned on the runtime or held inside the loop's own task.
struct FaceDriving<'a> {
    forwarder: &'a dyn FaceForwarder,
    spawned: Option<SpawnedFaces>,
}

/// Bind-once, hold-N: the shared multi-face drive core behind both
/// [`accept_loop`] (accept-only) and [`peer_loop`] (dial + accept). A node's
/// faces come from the two [`FaceSources`] — dialing each `dial_targets` locator
/// (outbound, seeded once at startup) and accepting inbound links on `listeners`
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
    driving: FaceDriving<'_>,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    let FaceDriving { forwarder, spawned } = driving;
    let FaceSources {
        mut listeners,
        dial_targets,
        dial_config,
        mut dial_intents,
        mut mcast_ingress,
        mut mcast_members,
        mut mcast_group_subs,
        mut reconcile,
        #[cfg(feature = "transport-multilink")]
        max_links,
        max_sessions,
        accept,
        ceiling,
        peer_board,
        offer,
        retry,
        stats,
    } = sources;
    // Only the loop that holds its peers by machines publishes them (decision D6).
    #[cfg(not(all(
        feature = "router-connect-reconcile",
        feature = "session-close-ingress"
    )))]
    let _ = peer_board;
    tokio::pin!(shutdown);
    // Item 751 — every face below is opened from this one template, so each
    // session announces from the partition the forwarder places it by.
    let params = FaceTemplate {
        params,
        partition: Arc::new(forwarder.south_partition()),
        #[cfg(feature = "session-extauth")]
        auth: forwarder.session_auth(),
        #[cfg(feature = "routing-namespace")]
        namespace: forwarder.session_namespace(),
    };

    // R2233 (open-debt item 585) — fold the configured dial targets into their
    // dial PLANS at the seam, and REFUSE (loudly) any member with no
    // pre-handshake identity. `mesh_dial_plan` is the same classification
    // `resolve_mesh_dial_target` applies at configuration time, so a host that
    // built its list through that resolver loses nothing here; this arm exists
    // because `FaceSources` is public and its field is the wider `AnyLocator`,
    // so a caller CAN hand the loop a target the dial axis has no identity for.
    // Refusing and naming it is the honest answer — dropping it silently would
    // reproduce, one layer up, exactly the half-truth item 585 is about.
    // R2900 — the one shape left to refuse is an UNRESOLVED name: the loop must
    // not block on a resolver, and `resolve_mesh_dial_target` resolves names at
    // configuration time. Every other shape has a `MeshDialKey`.
    let dial_targets: Vec<MeshDialTarget> = dial_targets
        .into_iter()
        .filter_map(|locator| match mesh_dial_plan(locator) {
            Ok(target) => Some(target),
            Err(rejected) => {
                log::warn!(
                    "mesh dial: refusing configured target {rejected:?} — an unresolved \
                     name; resolve it at configuration time \
                     (session_open::resolve_mesh_dial_target)"
                );
                None
            }
        })
        .collect();

    // The live faces, each mapped to its peer zid (`None` if the handshake never
    // surfaced one). The value is READ — `holds_zid` scans it for the
    // gossip-autoconnect dial-intent dedup and, for a zid-keying forwarder, the
    // face-establishment dedup — so this single map is the source for "who do I
    // hold", replacing the prior value-less id set plus a parallel zid set (the
    // duplication the old comment warned against; the value is no longer write-only
    // now that the dedups read it). `peak_concurrent` and the held-count read its
    // cardinality.
    let mut faces: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
    // The directions of the faces held, and the links waiting behind a face that is closing
    // because a link that replaces it came up ([`crate::link_collision`]). Both are read at the
    // face-establishment dedup and written where a face is held and where one leaves.
    let mut collisions: LinkCollisions<ParkedOpen> = LinkCollisions::default();
    // R2951 — the ids of opens the loop ACCEPTED, from the accept push until the
    // open resolves either way. What is not in it is a dial, which is how
    // `Face::dialed` is answered in every build, the loop's peers or not.
    let mut accepted_ids: std::collections::BTreeSet<FaceId> = std::collections::BTreeSet::new();
    // Decision D3 — where the nodes this loop dials by zid may be reached: the
    // hints the discovery planes and the lifecycle opener give, read just after
    // each gives them. Boxed, because a table of its rows is too large for the
    // loop's future to carry inline.
    let mut directory: Box<LoopDirectory> = Box::new(LoopDirectory::new());
    // R311y786 — the per-address re-dial waits of the multilink per-link re-add,
    // replacing the fixed `RECONNECT_BACKOFF_MS`. Loop-local (not per-face)
    // because the growth must survive the FaceId churn of the retries it is
    // pacing. The loop's peers keep their own (decision D5).
    #[cfg(feature = "transport-multilink")]
    let mut redial = RedialSchedule::new(retry);
    // The FIELD is unconditional (so no construction site carries a cfg) but a build
    // with NEITHER re-dial substrate schedules nothing to pace, so the local is
    // discarded here — the same shape `run_router_hat` uses for the admin permit it
    // only reads under a feature. Keeps that combo warning-clean without putting an
    // `#[allow]` on the destructure, which would also hide a real future unused.
    #[cfg(not(any(feature = "router-connect-reconcile", feature = "transport-multilink")))]
    let _ = retry;
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
    // keyed by FaceId. Its own substrate (not the connection machine of a
    // configured endpoint, which holds the endpoint by its session and is
    // `router-connect-reconcile`'s): a dialed link keeps its entry across the JOIN
    // so that on a PARTIAL loss it can be re-dialed + re-JOINed onto the surviving
    // session. An
    // ACCEPTED link has no entry (no re-dial owner — the peer re-dials it).
    #[cfg(feature = "transport-multilink")]
    let mut ml_dial_endpoints: BTreeMap<FaceId, (MeshDialTarget, (Priority, Priority))> =
        BTreeMap::new();
    let mut summary = AcceptLoopSummary::default();
    let mut opening: FuturesUnordered<OpenFuture> = FuturesUnordered::new();
    // Decision D5 — the peers the loop is told to hold, each by its connection
    // machine: the configured endpoints (`connect/endpoints`, and each reconcile
    // of them) and the nodes a lifecycle `open` names. The planner, the sessions
    // a `close` may drop, and the retry timers it arms.
    #[cfg(feature = "router-connect-reconcile")]
    let mut peers = crate::loop_peers::LoopPeers::new(retry);
    #[cfg(all(
        feature = "router-connect-reconcile",
        feature = "session-close-ingress"
    ))]
    let mut peer_sessions: BTreeMap<FaceId, Arc<SessionLinkActions>> = BTreeMap::new();
    let mut peer_retries: PeerRetries = FuturesUnordered::new();
    // The planner's view of the loop at this moment.
    #[cfg(feature = "router-connect-reconcile")]
    macro_rules! peer_cx {
        () => {
            crate::loop_peers::PeerContext {
                directory: &directory,
                now_ms: clock.now_monotonic_ms(),
            }
        };
    }
    // Take what the loop's peers asked for; the value is how many dials it opened.
    // Every call into the planner ends here, so this is where its machines, as
    // they now are, are published for the status query (decision D6).
    #[cfg(feature = "router-connect-reconcile")]
    macro_rules! take_peer_actions {
        ($actions:expr) => {{
            let dials = PeerHost {
                opening: &mut opening,
                retries: &mut peer_retries,
                #[cfg(feature = "session-close-ingress")]
                sessions: &peer_sessions,
                #[cfg(feature = "transport-multilink")]
                max_links,
                #[cfg(feature = "transport-multilink")]
                ml_dial_endpoints: &mut ml_dial_endpoints,
                dial_config: &dial_config,
                params: &params,
                offer,
                clock,
                tick_interval_ms,
            }
            .take($actions);
            #[cfg(feature = "session-close-ingress")]
            if let Some(board) = &peer_board {
                board.publish(peers.board_rows());
            }
            dials
        }};
    }
    // Report how a peer's dial ended and take what its machine asks next; the
    // value is whether the loop is to hold the face (`true` for a face that is
    // not a peer's dial). Every arm that ends a dial reports through this one
    // spelling.
    #[cfg(feature = "router-connect-reconcile")]
    macro_rules! peer_dial_ended {
        ($id:expr, $end:expr) => {{
            let cx = peer_cx!();
            match peers.dial_ended($id, $end, &cx, &mut next_id) {
                Some((keep, actions)) => {
                    take_peer_actions!(actions);
                    keep
                }
                None => true,
            }
        }};
    }
    // Report a face's death to the peers it held, and take what their machines
    // ask next.
    #[cfg(feature = "router-connect-reconcile")]
    macro_rules! peer_face_down {
        ($id:expr) => {{
            #[cfg(feature = "session-close-ingress")]
            peer_sessions.remove(&$id);
            let cx = peer_cx!();
            if let Some(actions) = peers.face_down($id, &cx, &mut next_id) {
                take_peer_actions!(actions);
            }
        }};
    }
    // R311y205 (transport-multilink) — an aggregating loop drives three distinct
    // future shapes (face / joined / rejected), so `driving` holds boxed futures;
    // a non-multilink loop keeps the unboxed single-shape set, byte-identical.
    #[cfg(not(feature = "transport-multilink"))]
    let mut driving = FuturesUnordered::new();
    #[cfg(feature = "transport-multilink")]
    let mut driving: FuturesUnordered<DriveFuture<'_>> = FuturesUnordered::new();
    // The drives of faces SPAWNED on the runtime (`spawned` is `Some`), and the face each
    // task drives, by task id, for the one whose task ends without a result. Empty in a
    // loop that holds its drives itself.
    let mut spawned_drives: tokio::task::JoinSet<(Face, DriverOutcome)> =
        tokio::task::JoinSet::new();
    let mut spawned_faces: BTreeMap<tokio::task::Id, Face> = BTreeMap::new();

    // Arm the forwarder's periodic tick (e.g. the linkstate peer's self-flood
    // cadence — its protocol obligation, now driven by the loop so EVERY caller
    // converges, not only a demo with a hand-rolled flood `select!`). A
    // forwarder with no periodic obligation returns `None`, so no timer is
    // created and the tick arm parks forever — the accept-only and hold-only
    // loops keep their exact prior behaviour (no extra wakeups).
    let mut tick_timer = forwarder.tick_period().map(tokio::time::interval);
    // The forwarder's wake signal: a forwarder that holds messages for a full link is told when
    // the link has room, and sends them then and not at the next tick.
    let wake_signal = forwarder.wake_signal();

    // Seed the outbound dial faces (peer-mesh mode). Each configured target is
    // dialed concurrently and, once Established, held in the SAME face set as
    // accepted peers — the dial-out face source, symmetric to the accept arm
    // below. Boxed into the shared `opening` set because `dial_face` and
    // `open_face` are distinct future types (see [`OpenFuture`]). Empty for a
    // pure acceptor, so [`accept_loop`] seeds nothing here.
    //
    // Decision D5 — with `router-connect-reconcile` the configured targets are
    // the loop's endpoints, each held by its connection machine, which dials it
    // now and again whenever its session is lost, until a reconcile forgets it.
    #[cfg(feature = "router-connect-reconcile")]
    {
        let cx = peer_cx!();
        let actions = peers.set_endpoints(dial_targets, false, &cx, &mut next_id);
        summary.dialed += take_peer_actions!(actions);
    }
    #[cfg(not(feature = "router-connect-reconcile"))]
    for target in dial_targets {
        let id = FaceId(next_id);
        next_id += 1;
        summary.dialed += 1;
        // R311y205 (transport-multilink) — a `max_links > 1` node dials with the
        // 0x4-negotiating variant so its outbound links aggregate (the pref tags
        // this link's traffic class); the `#[cfg(not)]` arm is the byte-identical
        // single-link seed.
        #[cfg(not(feature = "transport-multilink"))]
        opening.push(Box::pin(dial_face(
            id,
            target,
            Arc::clone(&dial_config),
            params.clone(),
            offer,
            clock,
            tick_interval_ms,
        )));
        #[cfg(feature = "transport-multilink")]
        opening.push(if max_links > 1 {
            // R311y212 — retain the dial endpoint so a partial-loss re-add can
            // re-dial this link (aggregating dials only; a single-link seed is not
            // re-added through this substrate). R311y219 — retain the priority
            // band so a re-add restores it (a fresh-id band would flip on
            // parity). R2233 — retained BEFORE the dial consumes the plan, and
            // it is the plan (scheme included) that is retained now.
            ml_dial_endpoints.insert(id, (target.clone(), multilink_priority_range(id)));
            Box::pin(dial_face_multilink(
                id,
                target,
                Arc::clone(&dial_config),
                offer,
                multilink_priority_range(id),
                params.clone(),
                clock,
                tick_interval_ms,
            )) as OpenFuture
        } else {
            Box::pin(dial_face(
                id,
                target,
                Arc::clone(&dial_config),
                params.clone(),
                offer,
                clock,
                tick_interval_ms,
            )) as OpenFuture
        });
    }

    loop {
        let step = tokio::select! {
            _ = &mut shutdown => Step::Shutdown,
            Some(opened) = opening.next() => Step::Opened(Box::new(opened)),
            Some(due) = peer_retries.next() => Step::PeerRetry(due),
            Some(driven) = driving.next() => Step::Driven(driven),
            Some(driven) = next_spawned(&mut spawned_drives, &mut spawned_faces) => {
                Step::Driven(driven)
            }
            // The fast, non-blocking accept: one raw connection per iteration
            // (ws/tls SERVER handshake deferred to the spawned open future, so a
            // slow handshake never stalls this arm). R311y376 (Stage 3) — was
            // `accept_tcp_on(&listener)`; now scheme-keyed via `accept_raw`.
            // R2099 (item 512) — over EVERY bound listener, not the first one.
            accepted = accept_any(&mut listeners) => Step::Accepted(accepted),
            _ = forwarder_tick(&mut tick_timer) => Step::Tick,
            _ = forwarder_woken(&wake_signal) => Step::Woken,
            intent = recv_dial_intent(&mut dial_intents) => Step::Dial(intent),
            item = recv_mcast_ingress(&mut mcast_ingress) => Step::McastIngress(Box::new(item)),
            members = recv_mcast_members(&mut mcast_members) => Step::McastMembers(members),
            subs = recv_mcast_group_subs(&mut mcast_group_subs) => Step::McastGroupSubs(subs),
            set = recv_reconcile(&mut reconcile) => Step::Reconcile(set),
        };

        match step {
            Step::Shutdown => break,

            Step::Opened(opened) => {
                let (id, peer, result) = *opened;
                // Decision D5 — whether this is a dial the loop's peers asked for:
                // its end is reported to its peer's machine at whichever arm below
                // ends it. A node's dial is held as a single-link face.
                #[cfg(feature = "router-connect-reconcile")]
                let peer_dial = peers.is_dialing(id);
                #[cfg(all(feature = "router-connect-reconcile", feature = "transport-multilink"))]
                let node_dial = peers.dials_a_node(id);
                // Without the planner no dial is a node's; only the multilink JOIN
                // branch reads the answer then.
                #[cfg(all(
                    feature = "transport-multilink",
                    not(feature = "router-connect-reconcile")
                ))]
                let node_dial = false;
                match result {
                    Ok(opened) => {
                        // R311y786 — this dial SUCCEEDED, so the outage it was
                        // retrying is over: forget the address's grown wait, and the
                        // NEXT outage starts at `period_init_ms` again. zenoh's
                        // `period` is a local of `peer_connector_retry` and dies with
                        // the successful connect (`orchestrator.rs:787-806`); this is
                        // that lifetime, spelled out because wz's re-dial is a future
                        // in a shared loop rather than a per-peer task with a stack.
                        // Placed BEFORE the multilink JOIN branch below, which
                        // `continue`s: a joined link is a successful dial too, and a
                        // reset written after that branch would never run for one.
                        // A peer's dial resets its own schedule when its machine
                        // reaches Established (`reset_retry`, decision D5).
                        #[cfg(feature = "transport-multilink")]
                        if let Some((target, _)) = ml_dial_endpoints.get(&id) {
                            redial.forget(&target.key);
                        }
                        // R311qi — capture the remote peer's zid (the routing
                        // identity) from the established session before `opened`
                        // is moved into the drive future.
                        let face = Face {
                            id,
                            peer,
                            peer_zid: opened.peer_zid(),
                            peer_whatami: opened.peer_whatami(),
                            // R2951 — not an accept, so one of this node's dials.
                            dialed: !accepted_ids.remove(&id),
                            // session-extqos — read the MERGED metadata off the
                            // session actions, before `opened` moves into the
                            // drive future. Post-handshake, so it is the outcome
                            // of the containment, not the staged offer.
                            #[cfg(feature = "session-extqos")]
                            qos_link: opened.actions.qos_link_metadata(),
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
                        // aggregate, so it falls through and is held single-link. A
                        // node dial (decision D5) is held single-link too: its
                        // machine holds the node by one face.
                        #[cfg(feature = "transport-multilink")]
                        if max_links > 1 && !node_dial {
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
                                            // Decision D5 — an endpoint whose dial
                                            // joined a session is held by that
                                            // session's face, and is lost with it;
                                            // the link itself is the re-add's.
                                            #[cfg(feature = "router-connect-reconcile")]
                                            if peer_dial {
                                                peer_dial_ended!(
                                                    id,
                                                    crate::loop_peers::DialEnd::AlreadyHeld {
                                                        held: primary_id,
                                                        remote: wz_session_core::credential_identity::zid_from_wire(&peer_zid),
                                                    }
                                                );
                                            }
                                            ml_faces.insert(id, (peer_zid, joined.clone()));
                                            // R311y219b — tell the forwarder this
                                            // joined link's inbound (which arrives
                                            // tagged with its OWN id, never
                                            // `register`ed) maps to the PRIMARY
                                            // registered face, so a routing forwarder
                                            // delivers its data/control instead of
                                            // dropping it at the faces.get gate. A
                                            // no-op for observation-only forwarders.
                                            forwarder.register_joined(id, primary_id, &joined);
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
                                            // Decision D5 — the session is full, but
                                            // it is the endpoint's: held by its face.
                                            #[cfg(feature = "router-connect-reconcile")]
                                            if peer_dial {
                                                peer_dial_ended!(
                                                    id,
                                                    crate::loop_peers::DialEnd::AlreadyHeld {
                                                        held: primary_id,
                                                        remote: wz_session_core::credential_identity::zid_from_wire(&peer_zid),
                                                    }
                                                );
                                            }
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
                                            // Decision D5 — a link the session refuses
                                            // is a dial that failed: the endpoint
                                            // backs off and tries again.
                                            #[cfg(feature = "router-connect-reconcile")]
                                            if peer_dial {
                                                peer_dial_ended!(
                                                    id,
                                                    crate::loop_peers::DialEnd::Failed
                                                );
                                            }
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
                        //
                        // A second link to a held node is a COLLISION and is resolved, not
                        // merely refused ([`crate::link_collision`]): of two links that went
                        // opposite ways the forwarder's rule keeps the one the lower zid
                        // dialled, which both ends read alike, so a forwarder that has the rule
                        // may keep the NEW link. The held face is then asked to close and the new
                        // link waits, parked, for the face to leave, because the graph is keyed
                        // on the zid (see above) and a face still leaving would remove the link
                        // of the one that replaced it.
                        if forwarder.dedups_faces_by_zid() {
                            if let Some(z) = &face.peer_zid {
                                // A face the forwarder holds and this loop cannot see keeps the
                                // first up, as it always has.
                                let resolution = if forwarder.holds_peer(z) {
                                    Resolution::Refuse
                                } else if holds_zid(&faces, z) {
                                    // One link of an aggregated session is not a face of its
                                    // own and cannot be closed alone.
                                    #[cfg(feature = "transport-multilink")]
                                    let can_replace = |held: FaceId| !ml_faces.contains_key(&held);
                                    #[cfg(not(feature = "transport-multilink"))]
                                    let can_replace = |_: FaceId| true;
                                    collisions.resolve(
                                        &faces,
                                        z,
                                        face.dialed,
                                        |held_dialled, new_dialled| {
                                            forwarder.judge_second_link(
                                                held_dialled,
                                                new_dialled,
                                                z,
                                            )
                                        },
                                        can_replace,
                                    )
                                } else {
                                    Resolution::Admit
                                };
                                let refused = match resolution {
                                    Resolution::Admit => false,
                                    Resolution::Refuse => true,
                                    Resolution::Replace { held } => {
                                        if forwarder.close_face(held) {
                                            log::debug!(
                                                "face {} to the node of held face {} is the link \
                                                 to keep: face {} is closing and face {} waits",
                                                id.0,
                                                held.0,
                                                held.0,
                                                id.0
                                            );
                                            collisions.park(
                                                held,
                                                ParkedOpen {
                                                    id,
                                                    peer: face.peer.clone(),
                                                    opened,
                                                    accepted: !face.dialed,
                                                },
                                            );
                                            continue;
                                        }
                                        // The forwarder holds no such face to ask: the held one
                                        // stays, as it did before there was a rule.
                                        true
                                    }
                                };
                                if refused {
                                    log::debug!(
                                        "dropping redundant face {} to an already-held peer",
                                        id.0
                                    );
                                    // Decision D5 — a peer's dial that met the remote
                                    // already held: the peer is held by that face (a
                                    // configured endpoint a gossip dial reached first
                                    // is lost, and dialled again, with that face).
                                    #[cfg(feature = "router-connect-reconcile")]
                                    if peer_dial {
                                        let end = match faces.iter().find(|(_, held)| {
                                            held.as_deref().is_some_and(|held| {
                                                crate::zid_hex::same_zid(held, z)
                                            })
                                        }) {
                                            Some((held, _)) => {
                                                crate::loop_peers::DialEnd::AlreadyHeld {
                                                    held: *held,
                                                    remote: wz_session_core::credential_identity::zid_from_wire(z),
                                                }
                                            }
                                            // Held by the forwarder alone, by no face
                                            // this loop can watch: not a hold the
                                            // machine can keep, so the dial failed.
                                            None => crate::loop_peers::DialEnd::Failed,
                                        };
                                        peer_dial_ended!(id, end);
                                    }
                                    continue;
                                }
                            }
                        }
                        // R2758 — THE SESSION BOUND, at upstream's moment.
                        //
                        // `io/zenoh-transport/src/unicast/manager.rs` @
                        // `max_sessions` denies under the session-table guard,
                        // immediately after the connection-to-self check:
                        // `if guard.len() >= self.config.unicast.max_sessions`
                        // returns `close::reason::INVALID`. The dedup-by-zid
                        // rule above is this loop's analogue of that self/dup
                        // check, so the bound belongs directly under it — and
                        // BEFORE `faces.insert`, because a bound applied after
                        // admission is not a bound.
                        //
                        // A rejected face is dropped exactly the way a
                        // redundant one is: it never enters `faces`.
                        if faces.len() >= max_sessions {
                            log::debug!(
                                "refusing face {} — max_sessions {} reached",
                                id.0,
                                max_sessions
                            );
                            // Decision D5 — no room for the session: the peer's
                            // machine names the refusal `NoSlot`.
                            #[cfg(feature = "router-connect-reconcile")]
                            if peer_dial {
                                peer_dial_ended!(id, crate::loop_peers::DialEnd::NoSlot);
                            }
                            summary.refused_over_max_sessions += 1;
                            if let Some(ceiling) = ceiling.as_ref() {
                                ceiling
                                    .refused_over_max_sessions
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            on_event(&AcceptEvent::FaceRefused {
                                id,
                                peer_zid: face.peer_zid.clone(),
                                held: faces.len(),
                            });
                            continue;
                        }
                        // The host's moving ceiling, read at the same moment and for the same
                        // reason: the capacity the node has measured is a bound on admission,
                        // and a bound applied after the face is held is not one.
                        if let Some((host_ceiling, limit)) = ceiling.as_ref().map(|c| (c, c.get()))
                        {
                            if faces.len() >= limit {
                                log::debug!(
                                    "refusing face {} — measured capacity {} reached",
                                    id.0,
                                    limit
                                );
                                #[cfg(feature = "router-connect-reconcile")]
                                if peer_dial {
                                    peer_dial_ended!(id, crate::loop_peers::DialEnd::NoSlot);
                                }
                                summary.refused_over_capacity += 1;
                                host_ceiling
                                    .refused_over_capacity
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                on_event(&AcceptEvent::FaceRefused {
                                    id,
                                    peer_zid: face.peer_zid.clone(),
                                    held: faces.len(),
                                });
                                continue;
                            }
                        }
                        // Item 751 -- a remote the forwarder's region rules cannot
                        // place is refused here, before it is held, as the pin
                        // refuses it when the transport opens.
                        if let Some(why) = forwarder.refuses_face(&opened.actions) {
                            log::warn!("refusing face {} -- {why}", id.0);
                            #[cfg(feature = "router-connect-reconcile")]
                            if peer_dial {
                                peer_dial_ended!(id, crate::loop_peers::DialEnd::Failed);
                            }
                            on_event(&AcceptEvent::FaceRefused {
                                id,
                                peer_zid: face.peer_zid.clone(),
                                held: faces.len(),
                            });
                            continue;
                        }
                        // Register the face's send seam BEFORE moving `opened`
                        // into the drive future, so a forwarder can route TO
                        // this face from the moment it is held. The registration is the
                        // forwarder's admission ([`FaceForwarder::admit`]) and it comes before
                        // anything is told of the face: a link it refuses is dropped as a
                        // redundant one is, and the dial machine below is told the dial failed,
                        // not that the peer is held by a face that does not exist.
                        if !forwarder.admit(id, &opened.actions) {
                            log::debug!(
                                "dropping face {} to a peer the forwarder holds by another face",
                                id.0
                            );
                            #[cfg(feature = "router-connect-reconcile")]
                            if peer_dial {
                                peer_dial_ended!(id, crate::loop_peers::DialEnd::Failed);
                            }
                            on_event(&AcceptEvent::FaceRefused {
                                id,
                                peer_zid: face.peer_zid.clone(),
                                held: faces.len(),
                            });
                            continue;
                        }
                        // Decision D5 — a peer's dial that came up: its machine
                        // holds the peer by this face, unless the peer stopped
                        // wanting it while it ran, when the session is dropped here
                        // unheld.
                        #[cfg(feature = "router-connect-reconcile")]
                        if peer_dial {
                            let end = crate::loop_peers::DialEnd::Established {
                                remote: face
                                    .peer_zid
                                    .as_deref()
                                    .and_then(wz_session_core::credential_identity::zid_from_wire),
                            };
                            if !peer_dial_ended!(id, end) {
                                forwarder.deregister(id);
                                continue;
                            }
                            #[cfg(feature = "session-close-ingress")]
                            peer_sessions.insert(id, opened.actions.clone());
                        }
                        faces.insert(id, face.peer_zid.clone());
                        collisions.admitted(id, face.dialed);
                        summary.established += 1;
                        summary.peak_concurrent = summary.peak_concurrent.max(faces.len());
                        if let Some(stats) = &stats {
                            stats.transport_opened(id.0, &opened.actions);
                        }
                        // `Face` is no longer `Copy` (it owns the zid), so clone
                        // it for the borrowed FaceUp event; the original moves
                        // into the drive future.
                        on_event(&AcceptEvent::FaceUp(face.clone()));
                        // R311y205 (transport-multilink) — box the drive future in
                        // an aggregating build so it shares `driving` with the
                        // joined / rejected drives; unboxed + byte-identical
                        // otherwise.
                        //
                        // A node whose forwarder is `Send + Sync` has the drive spawned
                        // on the runtime instead, wrapped as its executor wants it
                        // polled: this face is then driven by a task of its own.
                        if let Some(spawn) = &spawned {
                            let drive = spawn.executor.wrap(Box::pin(drive_face_shared(
                                face.clone(),
                                opened,
                                Arc::clone(&spawn.forwarder),
                            )));
                            let task = match spawn.on {
                                SpawnOn::Workers => spawned_drives.spawn(drive),
                                SpawnOn::LocalSet => spawned_drives.spawn_local(drive),
                            };
                            spawned_faces.insert(task.id(), face);
                        } else {
                            #[cfg(not(feature = "transport-multilink"))]
                            driving.push(drive_face(face, opened, forwarder));
                            #[cfg(feature = "transport-multilink")]
                            driving
                                .push(Box::pin(drive_face(face, opened, forwarder))
                                    as DriveFuture<'_>);
                        }
                    }
                    Err(cause) => {
                        // R2951 — an accept that never opened leaves no mark behind.
                        accepted_ids.remove(&id);
                        // Decision D5 — a peer's dial that did not open: another
                        // node answered (D4), or the peer was not reached. Its
                        // machine backs off and dials again, so the link the dial
                        // retained for the multilink re-add is not the re-add's.
                        #[cfg(feature = "router-connect-reconcile")]
                        if peer_dial {
                            let end = if matches!(cause, OpenError::InitAckPeerMismatch) {
                                crate::loop_peers::DialEnd::Mismatch
                            } else {
                                crate::loop_peers::DialEnd::Failed
                            };
                            #[cfg(feature = "transport-multilink")]
                            ml_dial_endpoints.remove(&id);
                            peer_dial_ended!(id, end);
                        }
                        // R311y212 — a failed retained MULTILINK dial (a re-add, or a
                        // discovered peer's aggregating dial that never connected) is
                        // re-scheduled: retry-until-success. A peer's dial left
                        // `ml_dial_endpoints` above, so no id is dialled again twice.
                        #[cfg(feature = "transport-multilink")]
                        if max_links > 1 {
                            if let Some((target, band)) = ml_dial_endpoints.remove(&id) {
                                schedule_multilink_redial(
                                    target,
                                    &dial_config,
                                    offer,
                                    band,
                                    &mut ml_dial_endpoints,
                                    &mut redial,
                                    &mut opening,
                                    &mut next_id,
                                    false,
                                    &params,
                                    clock,
                                    tick_interval_ms,
                                );
                            }
                        }
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
                                // An aggregated session is never replaced (`can_replace`), so
                                // nothing waits behind it; a link that did would be admitted as
                                // any other is, and its direction is forgotten all the same.
                                if let Some(parked) = collisions.departed(primary_id) {
                                    admit_parked(parked, &mut opening, &mut accepted_ids);
                                }
                                // Decision D5 — the session is gone: the peers its
                                // primary face held back off and dial again.
                                #[cfg(feature = "router-connect-reconcile")]
                                peer_face_down!(primary_id);
                                forwarder.deregister(primary_id);
                                if let Some(stats) = &stats {
                                    stats.transport_closed(primary_id.0);
                                }
                                on_event(&AcceptEvent::FaceDown(primary_face, outcome));
                            }
                        } else if let Some((target, band)) = dead {
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
                                target,
                                &dial_config,
                                offer,
                                band,
                                &mut ml_dial_endpoints,
                                &mut redial,
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
                let departed = face.id;
                // Decision D5 — the face a peer was held by died: each peer's
                // machine backs off and asks for the retry. This is the peer
                // auto-reconnect, upstream's re-dial of a configured endpoint
                // its closed session still lists
                // (`zenoh/src/net/runtime/orchestrator.rs`
                // @ `if peers.contains(&endpoint) && zwrite!(session.endpoints).remove(&endpoint) {`):
                // an endpoint a reconcile no longer lists was forgotten, and a
                // face no peer holds (an accepted one, a discovered peer's)
                // reports nothing.
                #[cfg(feature = "router-connect-reconcile")]
                peer_face_down!(face.id);
                forwarder.deregister(face.id);
                if let Some(stats) = &stats {
                    stats.transport_closed(face.id.0);
                }
                on_event(&AcceptEvent::FaceDown(face, outcome));
                // The face has left the loop, the forwarder and the observers, which is what a
                // link parked behind it waited for: the node is held by no face now, and the
                // link that replaces it is admitted as any other.
                if let Some(parked) = collisions.departed(departed) {
                    admit_parked(parked, &mut opening, &mut accepted_ids);
                }
            }

            Step::Dial(intent) => {
                // A DISCOVERED, policy-admitted peer — the producing plane applied
                // the autoconnect role + zid gate at emit (the forwarder for
                // gossip, A5b; the scouting task for a Hello, R2141). Dial it as
                // an outbound face unless a face to it is already held (dedup) or
                // no locator is TCP-dialable. A dialed face flows through the SAME
                // `opening` -> `Step::Opened` path as a static dial, so it is
                // registered + held + zid-tracked identically.
                match learn_and_decide(&faces, &intent, &mut directory, clock.now_monotonic_ms()) {
                    DialDecision::Dial(target) => {
                        let id = FaceId(next_id);
                        next_id += 1;
                        summary.dialed += 1;
                        // R311y423 — the discovery-only counters. This arm is
                        // reached ONLY via a DialIntent, which a plane emits only
                        // after its autoconnect policy admits a node it
                        // discovered, so incrementing here (and nowhere else)
                        // makes the pair true discriminators.
                        //
                        // R2141 — split by ORIGIN. There are two producers on this
                        // channel now, and a single counter would credit whichever
                        // atom the reader happened to be asking about; see
                        // `DialIntentOrigin`.
                        match intent.origin {
                            DialIntentOrigin::Gossip => summary.gossip_dialed += 1,
                            DialIntentOrigin::MulticastScout => summary.scout_dialed += 1,
                        }
                        // R311y205 (transport-multilink) — a `max_links > 1` node
                        // dials the discovered peer with the 0x4-negotiating variant
                        // (aggregation), else the byte-identical single-link dial.
                        #[cfg(not(feature = "transport-multilink"))]
                        opening.push(Box::pin(dial_face(
                            id,
                            target,
                            Arc::clone(&dial_config),
                            params.clone(),
                            offer,
                            clock,
                            tick_interval_ms,
                        )));
                        #[cfg(feature = "transport-multilink")]
                        opening.push(if max_links > 1 {
                            // R311y212 — retain the discovered-peer dial endpoint for
                            // partial-loss re-add (aggregating dials only). R311y219 —
                            // retain the priority band.
                            ml_dial_endpoints
                                .insert(id, (target.clone(), multilink_priority_range(id)));
                            Box::pin(dial_face_multilink(
                                id,
                                target,
                                Arc::clone(&dial_config),
                                offer,
                                multilink_priority_range(id),
                                params.clone(),
                                clock,
                                tick_interval_ms,
                            )) as OpenFuture
                        } else {
                            Box::pin(dial_face(
                                id,
                                target,
                                Arc::clone(&dial_config),
                                params.clone(),
                                offer,
                                clock,
                                tick_interval_ms,
                            )) as OpenFuture
                        });
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
                                if let Some(target) = first_dialable_locator(&intent.locators) {
                                    let id = FaceId(next_id);
                                    next_id += 1;
                                    summary.dialed += 1;
                                    // R311y212 — retain the aggregation-relax dial
                                    // endpoint for partial-loss re-add. R311y219 —
                                    // retain the priority band.
                                    ml_dial_endpoints
                                        .insert(id, (target.clone(), multilink_priority_range(id)));
                                    opening.push(Box::pin(dial_face_multilink(
                                        id,
                                        target,
                                        Arc::clone(&dial_config),
                                        offer,
                                        multilink_priority_range(id),
                                        params.clone(),
                                        clock,
                                        tick_interval_ms,
                                    ))
                                        as OpenFuture);
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
                        "autoconnect: discovered peer advertised no numeric IP \
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
                // R2734 — the fold now carries a Query as well as a Push, so the
                // kind is decided HERE rather than by the fold dropping everything
                // that is not a Push. Each arm is a different routing entry point
                // on the forwarder; both enter through the same source-only
                // ingress face.
                #[cfg(feature = "codec-push")]
                match &_item.body {
                    McastIngressBody::Push(push) => {
                        forwarder.route_mcast_ingress(
                            _item.priority,
                            _item.reliable,
                            push,
                            _item.from.as_ref(),
                        );
                    }
                    McastIngressBody::Request(request) => {
                        forwarder.route_mcast_ingress_request(
                            _item.reliable,
                            request,
                            _item.from.as_ref(),
                        );
                    }
                }
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
            // the loop's endpoints change, and each newly-listed one is dialled by
            // its connection machine (decision D5). This is the wz analogue of
            // zenoh's `update_peers` Peer/Router branch (`orchestrator.rs:449-467`)
            // — ADD-ONLY. A removed endpoint is forgotten, NOT torn down (the
            // Client close-removed branch `427-448` is router-inapplicable: closing
            // a live federation face on a static-list edit would blackhole the
            // mesh). An endpoint is named by its ADDRESS (a config endpoint carries
            // no zid until the handshake, so the gossip `holds_zid` zid dedup
            // cannot apply), and one already held or being reached is unchanged.
            // The arm parks when `reconcile` is `None`, so a non-router /
            // feature-off loop never reaches here; the body is `#[cfg]`-gated so a
            // feature-off build compiles none of the reconcile dial logic.
            Step::Reconcile(_desired_set) => {
                #[cfg(feature = "router-connect-reconcile")]
                {
                    // R2671 — the fold, the refusal and the verb are read in
                    // `fold_connect_reconcile`, and the set it lands in is the
                    // planner's, so a unit test reaches both; this arm keeps only
                    // the loop's own wording.
                    let plan = fold_connect_reconcile(_desired_set, |rejected| {
                        log::warn!(
                            "reconcile: refusing connect endpoint {rejected:?} — a {} \
                             endpoint has no address to identify it by before the \
                             handshake",
                            crate::session_open::locator_scheme(&rejected)
                        );
                    });
                    match plan {
                        // `Replace` adopts the whole set and `Add` leaves the
                        // existing members standing. An added endpoint is dialled
                        // now AND again whenever its session is lost; one a
                        // replace drops is not dialled again, and its live face
                        // is NOT closed (the add-only / close-removed asymmetry).
                        ConnectPlan::Endpoints { targets, replace } => {
                            let cx = peer_cx!();
                            let actions = peers.set_endpoints(targets, replace, &cx, &mut next_id);
                            let dials = take_peer_actions!(actions);
                            if dials > 0 {
                                log::debug!(
                                    "reconcile: dialing {dials} newly-listed connect endpoint(s)"
                                );
                            }
                            summary.dialed += dials;
                        }
                        // Decision D5 — a node's add goes to its connection
                        // machine: the graph's locators become its link-state
                        // hints (D3), and the machine resolves and dials them for
                        // its zid (D4).
                        #[cfg(feature = "session-close-ingress")]
                        ConnectPlan::Node { zid, locators } => {
                            learn_locators(
                                &mut directory,
                                &zid,
                                &locators,
                                LocatorSource::Linkstate,
                                clock.now_monotonic_ms(),
                            );
                            let cx = peer_cx!();
                            let actions = peers.open_node(zid, &cx, &mut next_id);
                            take_peer_actions!(actions);
                        }
                        // Decision D6 — a lifecycle `close`: every machine that
                        // holds the node is stopped, so it is not dialled again.
                        #[cfg(feature = "session-close-ingress")]
                        ConnectPlan::Withdraw { zid } => {
                            let cx = peer_cx!();
                            let actions = peers.withdraw(&zid, &cx, &mut next_id);
                            take_peer_actions!(actions);
                        }
                    }
                }
            }

            Step::PeerRetry(_due) => {
                #[cfg(feature = "router-connect-reconcile")]
                {
                    let (key, generation) = _due;
                    let cx = peer_cx!();
                    let actions = peers.retry_due(key, generation, &cx, &mut next_id);
                    take_peer_actions!(actions);
                }
                #[cfg(not(feature = "router-connect-reconcile"))]
                match _due {}
            }

            Step::Accepted(Ok((accepted, peer))) => {
                // Slice B — the mesh accept loop holds a face per accepted peer
                // keyed by its handshake zid, so an IP peer AND a mesh-capable
                // non-IP peer (unixsock / vsock / unixpipe — each a genuine per-peer
                // stream accept) are all held as faces; `peer` (an `AcceptedPeer`)
                // is threaded straight into the open future as a log/event tag.
                //
                // ⛔ R2723 — THE NON-MESH REJECT ARM IS GONE, and it is the CADENCE
                // of an acceptor that made it obsolete rather than a decision to be
                // more permissive. It dropped any link whose acceptor could not
                // yield N CONCURRENT peers, and the only such acceptor is serial: a
                // tty is point-to-point. But "N at once" and "N over time" are
                // different questions, and the loop only ever needed the second.
                // R2722 gave the serial listener link-liveness feedback, so its
                // `accept_raw` parks while a link is live and yields the next peer
                // once that one has dropped — and `accept_any` rebuilds its future
                // set every iteration, so a listener that serves peers ONE AT A TIME
                // feeds this loop exactly as a multi-peer one does. The budget is
                // enforced by the listener, not by an admission test here.
                //
                // Widening the predicate instead would have been the wrong repair
                // twice over: it is a TRUE statement about concurrency that must
                // keep answering `false` for a tty, and a widened version would
                // admit every variant, leaving this arm a check that can never fire.
                // The surviving consumer is the BIND-time one, which now reports the
                // cadence to an operator rather than refusing the listen.
                // Upstream's DoS guard, at the same place (`handle_new_link_unicast`): a link
                // that arrives while `accept_pending` accepts are still mid-handshake is closed
                // straight away and nothing is said to the peer, because either the bound is too
                // small for the deployment or someone is filling it, and a reply costs the
                // acceptor what the peer is spending. `accepted_ids` is exactly those accepts:
                // inserted below, removed when the open resolves.
                if accepted_ids.len() >= accept.pending {
                    summary.refused_over_pending += 1;
                    log::debug!(
                        "closing {peer:?} unanswered: {} accepts are already mid-handshake",
                        accepted_ids.len()
                    );
                    drop(accepted);
                    continue;
                }
                let id = FaceId(next_id);
                next_id += 1;
                summary.accepted += 1;
                // R2951 — every open that is not an ACCEPT is one of this node's
                // dials; this is the one accept push, so marking it here is what
                // lets `Face::dialed` be answered in every build.
                accepted_ids.insert(id);
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
                    offer,
                    clock,
                    tick_interval_ms,
                    accept,
                )));
                #[cfg(feature = "transport-multilink")]
                opening.push(if max_links > 1 {
                    Box::pin(open_face_multilink(
                        id,
                        peer,
                        accepted,
                        offer,
                        multilink_priority_range(id),
                        params.clone(),
                        clock,
                        tick_interval_ms,
                        accept,
                    )) as OpenFuture
                } else {
                    Box::pin(open_face(
                        id,
                        peer,
                        accepted,
                        params.clone(),
                        offer,
                        clock,
                        tick_interval_ms,
                        accept,
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

            // The forwarder was told a link it holds messages for has room.
            Step::Woken => forwarder.woken(),
        }
    }

    // Stop accepting; drop in-flight opens + drives (sockets close, writer tasks
    // drain). Faces table cleared — the summary already captured the high-water
    // mark.
    drop(opening);
    drop(driving);
    // Spawned drives are cancelled AND awaited: a task mid-poll finishes that poll on its
    // worker, so without the wait a callback could still be running after this returns.
    spawned_drives.shutdown().await;
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
/// until the peer closes. A thin entry over `face_drive_loop` with NO outbound
/// dials — every face comes from accepting. `on_event` observes each
/// [`AcceptEvent`]; the loop runs until `shutdown` resolves, then returns its
/// [`AcceptLoopSummary`].
///
/// Every face opens with the ZERO offer: this is the entry for a node that
/// carries no capability configuration of its own. One that does, and still
/// only accepts, reaches [`accept_loop_offering`].
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
    accept_loop_offering(
        listener,
        params,
        SessionOffer::universal(),
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        forwarder,
    )
    .await
}

/// [`accept_loop`] for an accept-only node that DOES carry a capability
/// configuration: every face it accepts opens with `offer`.
///
/// Its caller is the zenoh-c ABI's listening session. zenoh builds the accept
/// side of every transport from the same manager config the open side reads —
/// `accept_link` stages QoS from it
/// (`io/zenoh-transport/src/unicast/establishment/accept.rs` @ `ext_qos: ext::qos::StateAccept::new(manager.config.unicast.is_qos, &endpoint)?,`),
/// and lowlatency, compression and the SHM authenticator beside it — so a
/// zenoh-c session that listens offers what its config enables exactly as one
/// that dials does. Without this entry the listening half of that session could
/// only offer nothing, which is what it did.
///
/// The offer is the node's; a listener endpoint's own QoS band is not staged
/// here, as it is not by [`accept_loop`] either.
#[allow(clippy::too_many_arguments)]
pub async fn accept_loop_offering<S, F>(
    listener: BoundListener,
    params: SessionInitParams,
    offer: SessionOffer,
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
        accept_only_sources(listener, offer, AcceptBounds::default()),
        params,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        FaceDriving {
            forwarder,
            spawned: None,
        },
    )
    .await
}

/// [`accept_loop_offering`] with each accepted face's drive SPAWNED on the runtime, one task
/// per face, instead of held inside the loop's single task: the entry of a node whose
/// forwarder is `Send + Sync`.
///
/// The accept, the handshakes, the `max_sessions` bound, the zid dedup and every forwarder
/// hook that is not the per-event one still run on THIS task, which is the control plane;
/// what moves to the workers is the drive of each face, which is the data plane. So N peers
/// are read, decoded and delivered by up to N threads, and a callback that does real work on
/// one link no longer holds up the others. `executor` wraps each spawned drive (the C ABI
/// puts its read gate around it).
///
/// The forwarder is called from several threads at once: an implementation keeps its state
/// behind locks, as the C ABI's does (a registry of `Arc`s and mutexes). The routing
/// forwarders keep theirs in `Rc`/`RefCell` and so reach only [`accept_loop_offering`].
#[allow(clippy::too_many_arguments)]
pub async fn accept_loop_offering_spawned<S, F>(
    listener: BoundListener,
    params: SessionInitParams,
    offer: SessionOffer,
    accept: AcceptBounds,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    on_event: F,
    forwarder: Arc<dyn FaceForwarder + Send + Sync>,
    executor: Arc<dyn FaceExecutor>,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    accept_loop_spawned_on(
        SpawnOn::Workers,
        listener,
        params,
        offer,
        accept,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        forwarder,
        executor,
    )
    .await
}

/// [`accept_loop_offering_spawned`] with each face's drive a LOCAL task of the thread the loop
/// runs on ([`SpawnOn::LocalSet`]): one thread drives every face, as in [`accept_loop_offering`],
/// and each face is woken on its own. Must run inside a `LocalSet`.
#[allow(clippy::too_many_arguments)]
pub async fn accept_loop_offering_spawned_local<S, F>(
    listener: BoundListener,
    params: SessionInitParams,
    offer: SessionOffer,
    accept: AcceptBounds,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    on_event: F,
    forwarder: Arc<dyn FaceForwarder + Send + Sync>,
    executor: Arc<dyn FaceExecutor>,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    accept_loop_spawned_on(
        SpawnOn::LocalSet,
        listener,
        params,
        offer,
        accept,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        forwarder,
        executor,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop_spawned_on<S, F>(
    on: SpawnOn,
    listener: BoundListener,
    params: SessionInitParams,
    offer: SessionOffer,
    accept: AcceptBounds,
    clock: TokioTime,
    tick_interval_ms: u64,
    shutdown: S,
    on_event: F,
    forwarder: Arc<dyn FaceForwarder + Send + Sync>,
    executor: Arc<dyn FaceExecutor>,
) -> AcceptLoopSummary
where
    S: Future<Output = ()>,
    F: FnMut(&AcceptEvent),
{
    let control: &dyn FaceForwarder = &*forwarder;
    face_drive_loop(
        accept_only_sources(listener, offer, accept),
        params,
        clock,
        tick_interval_ms,
        shutdown,
        on_event,
        FaceDriving {
            forwarder: control,
            spawned: Some(SpawnedFaces {
                forwarder: Arc::clone(&forwarder),
                executor,
                on,
            }),
        },
    )
    .await
}

/// What an accept-only node's loop is built from: the one listener it was handed, and the
/// defaults of everything an accept-only node does not do.
fn accept_only_sources(
    listener: BoundListener,
    offer: SessionOffer,
    accept: AcceptBounds,
) -> FaceSources {
    FaceSources {
        // accept-only: ONE listener, the one this entry point binds. A node
        // that binds a whole `listen/endpoints` list reaches `peer_loop`,
        // which is where R2099 threads the multi-bind.
        listeners: vec![listener],
        dial_targets: Vec::new(),
        // accept-only: this loop opens no outbound link at all, so there is no
        // dial to carry client trust material for. The default is the honest
        // value, not a placeholder: it means "no tls / quic client config",
        // which is exactly true here.
        dial_config: Arc::new(DialConfig::default()),
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
        // R2758 — UPSTREAM'S DEFAULT, not "unbounded".
        //
        // This entry carries no configuration of its own (see the offer
        // below), and the honest reading of that is upstream's shipped
        // value rather than the absence of a bound: zenoh has no unbounded
        // mode — `unicast.max_sessions` defaults to 1000 and the manager
        // always compares against it. A caller that needs a different bound
        // reaches `peer_loop`, which takes the configured `FaceSources`.
        max_sessions: crate::config::DEFAULT_MAX_SESSIONS,
        // The caller's: upstream's own for the entries that state none, the C interface's
        // for the ones that stand for a node with a configuration of its own.
        accept,
        ceiling: None,
        peer_board: None,
        // The caller's: [`accept_loop`] passes the zero offer, an accept-only
        // node with a configuration of its own passes that configuration's.
        // A mesh node reaches `peer_loop`, which is where R2095 threads the
        // configured offer for dials as well.
        offer,
        // accept-only: the loop schedules no outbound dial at all, so no
        // re-dial either. Carried because the field is unconditional; never
        // read on this path.
        retry: RetryPolicy::ZENOH_DEFAULT,
        // accept-only: this entry carries no configuration of its own, and a
        // node that keeps a stats registry reaches `peer_loop`.
        stats: None,
    }
}

/// Bind-once, dial-configured-peers, accept-inbound, hold-all: the peer-mesh
/// node (the `routing-peer` foundation, R311qg).
///
/// The dial + accept generalisation of [`accept_loop`]: a peer both DIALS each
/// [`FaceSources::dial_targets`] locator (its outbound mesh links — every
/// IP-family scheme since R2233, dispatched by [`dial_locator`] and carrying the
/// loop's [`FaceSources::dial_config`] trust material) AND accepts inbound peers
/// on [`FaceSources::listeners`], holding every resulting face in one set. The
/// only difference from `accept_loop` is the seeded outbound dials;
/// both delegate to the shared `face_drive_loop` core, so accept-side
/// robustness (one peer's handshake never blocks another, a failed open is
/// isolated as `FaceFailed`) covers a dialed face too — an unreachable dial
/// target surfaces as `FaceFailed` and the mesh keeps forming.
///
/// R2438 — THE TWO SENTENCES THAT WERE HERE WERE FALSE, and they had been
/// asserting a missing capability for long enough that the atom's own registry
/// entry flagged them (`routing-peer`: "the registry is right and the CODE is
/// the thing that went stale, and nothing measures that direction either").
/// They read: "a held mesh face routes nothing yet", and that mesh forwarding
/// "needs zid-keyed loop suppression ... the next `routing-peer` atom".
///
/// Both are refuted by this crate: `linkstate_forward` is a shipped module
/// (`crate::linkstate_forward`), it forwards Push, propagates Declare interest
/// and routes Query / Response / ResponseFinal, and its tier tables are keyed by
/// graph zid with a per-face psid-to-zid mapping — which IS the zid-keyed
/// suppression the deleted sentence said was still owed. A held face routes
/// whatever forwarder it was given.
///
/// The seam itself is unchanged and is why the comment could rot unnoticed:
/// `peer_loop` takes the same `forwarder` parameter as `accept_loop`, so a node
/// that genuinely wants no forwarding still passes [`NoOpForwarder`]. "Can be
/// hold-only" is a caller's choice here; it was never this function's ceiling.
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
        FaceDriving {
            forwarder,
            spawned: None,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    // R2233 — the production dial no longer names either of these: it goes
    // through `dial_locator`, which owns every scheme's connect and returns the
    // `DialedLink` union. The loop's own fixtures still stand up raw loopback
    // streams, so the imports live here rather than at module scope.
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;
    use std::time::Duration;
    use wz_session_core::locator::Proto;

    /// R2233 — the dial-target currency is a LOCATOR; build the `tcp/<addr>` one
    /// through the locator SSOT so a fixture reads the grammar a configured
    /// `--connect` does, and a new locator field cannot default in silently here.
    ///
    /// `routing-peer`-gated because every caller is: an accept-only build has no
    /// dial targets to construct, and an ungated helper is dead code there.
    #[cfg(feature = "routing-peer")]
    fn tcp_dial(addr: SocketAddr) -> AnyLocator {
        wz_session_core::locator::parse_any_locator(&format!("tcp/{addr}"))
            .expect("tcp/<addr> locator")
    }

    /// R2671 (open-debt item 770) — THE CASE NO TEST BUILT: a node whose desired
    /// connect-set is ALREADY NON-EMPTY.
    ///
    /// The `connect-add` defect was invisible for exactly one reason -- every
    /// fixture that exercised the reconcile path started from an empty desired
    /// set, and on an empty set a subset IS the whole set, so the arity mismatch
    /// had no observable consequence anywhere it was tested. This seeds the set
    /// the way `face_drive_loop` seeds it from `dial_targets` and then asks the
    /// question the operator asks. Decision D5 — the set is the loop's peers'
    /// configured endpoints ([`crate::loop_peers::LoopPeers`]).
    ///
    /// ⚠ BOTH VERBS ARE ASSERTED AGAINST THE SAME SEED, deliberately. A fixture
    /// that only checked `Add` would pass just as well if `Add` and `Replace`
    /// were transposed; asserting that the same input produces DIFFERENT sets is
    /// what makes the distinction load-bearing rather than incidental.
    #[cfg(all(feature = "router-connect-reconcile", feature = "routing-peer"))]
    #[test]
    fn an_add_keeps_the_startup_seed_and_a_replace_does_not() {
        use crate::loop_peers::{LoopPeers, PeerContext};

        let ep: Vec<SocketAddr> = ["127.0.0.1:7001", "127.0.0.1:7002", "127.0.0.1:7003"]
            .iter()
            .map(|s| s.parse().expect("fixture addr"))
            .collect();
        let directory = LoopDirectory::new();
        let cx = PeerContext {
            directory: &directory,
            now_ms: 0,
        };
        let mut next_id = 0;

        // Seeded the way the loop seeds it: the resolved startup dial targets.
        let seeded = |next_id: &mut u64| {
            let mut peers = LoopPeers::new(RetryPolicy::ZENOH_DEFAULT);
            let seed = ep[..2]
                .iter()
                .map(|a| crate::session_open::mesh_dial_plan(tcp_dial(*a)).expect("ip locator"))
                .collect();
            peers.set_endpoints(seed, false, &cx, next_id);
            peers
        };
        let keys = |peers: &LoopPeers| {
            let mut keys: Vec<MeshDialKey> = peers.endpoints().map(|t| t.key.clone()).collect();
            keys.sort();
            keys
        };
        let reconcile = |peers: &mut LoopPeers,
                         request: ConnectReconcile,
                         refused: &mut usize,
                         next_id: &mut u64| {
            match fold_connect_reconcile(request, |_| *refused += 1) {
                ConnectPlan::Endpoints { targets, replace } => {
                    peers.set_endpoints(targets, replace, &cx, next_id)
                }
                #[cfg(feature = "session-close-ingress")]
                ConnectPlan::Node { .. } | ConnectPlan::Withdraw { .. } => {
                    panic!("an endpoint request plans no node")
                }
            }
        };

        let mut peers = seeded(&mut next_id);
        assert_eq!(
            keys(&peers).len(),
            2,
            "the seed itself must be the two startup targets"
        );

        // ADD: the third arrives, the two startup targets SURVIVE. Before R2671
        // this evicted them, because the host sent its fragment on a channel the
        // loop always read as a whole-set replace.
        let mut refused = 0usize;
        let dials = reconcile(
            &mut peers,
            ConnectReconcile::Add(vec![tcp_dial(ep[2])]),
            &mut refused,
            &mut next_id,
        );
        assert_eq!(refused, 0, "every fixture endpoint is mesh-dialable");
        assert_eq!(dials.len(), 1, "only the new member is dialled: {dials:?}");
        let mut want: Vec<MeshDialKey> = ep.iter().map(|a| MeshDialKey::Ip(*a)).collect();
        want.sort();
        assert_eq!(
            keys(&peers),
            want,
            "an ADD must leave the startup seed in the desired set"
        );

        // REPLACE: the same input, the opposite outcome -- the anti-vacuity arm.
        let mut peers = seeded(&mut next_id);
        reconcile(
            &mut peers,
            ConnectReconcile::Replace(vec![tcp_dial(ep[2])]),
            &mut refused,
            &mut next_id,
        );
        assert_eq!(
            keys(&peers),
            vec![MeshDialKey::Ip(ep[2])],
            "a REPLACE must adopt only what it carries -- otherwise the two verbs \
             are the same verb and this distinction buys nothing"
        );

        // The refusal arm still reports, and an unusable member does not take the
        // rest of the request with it.
        let mut peers = seeded(&mut next_id);
        refused = 0;
        let named = wz_session_core::locator::parse_any_locator("tcp/example.org:7447")
            .expect("a NAMED locator parses; it is the dial plan that refuses it");
        reconcile(
            &mut peers,
            ConnectReconcile::Add(vec![named, tcp_dial(ep[2])]),
            &mut refused,
            &mut next_id,
        );
        assert_eq!(
            refused, 1,
            "a pre-handshake-identityless endpoint is refused by name"
        );
        assert_eq!(
            keys(&peers).len(),
            3,
            "and the rest of the ADD still applies"
        );
    }

    /// Decision D5 — an add of a NODE is not a member of the desired set: it is
    /// planned as the node, untouched, for the loop's peers, which hold the node
    /// by its connection machine. An add of locators plans them for no node.
    #[cfg(all(
        feature = "router-connect-reconcile",
        feature = "routing-peer",
        feature = "session-close-ingress"
    ))]
    #[test]
    fn an_added_node_is_handed_to_the_planner_and_added_locators_name_no_node() {
        let addr: SocketAddr = "127.0.0.1:7004".parse().expect("fixture addr");
        let mut zid = [0u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES];
        zid[..2].copy_from_slice(&[0xab, 0x01]);

        let plan = fold_connect_reconcile(ConnectReconcile::Add(vec![tcp_dial(addr)]), |_| {
            panic!("a tcp locator is mesh-dialable")
        });
        match plan {
            ConnectPlan::Endpoints { targets, replace } => {
                assert!(!replace);
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].key, MeshDialKey::Ip(addr));
                assert_eq!(targets[0].expected_zid, None, "a locator names no node");
            }
            ConnectPlan::Node { .. } | ConnectPlan::Withdraw { .. } => {
                panic!("an add of locators plans no node")
            }
        }

        let handed = fold_connect_reconcile(
            ConnectReconcile::AddNode {
                zid,
                locators: vec![format!("tcp/{addr}")],
            },
            |_| panic!("nothing is folded here"),
        );
        assert_eq!(
            handed,
            ConnectPlan::Node {
                zid,
                locators: vec![format!("tcp/{addr}")],
            }
        );
    }

    use futures_util::future::join_all;
    use tokio::net::TcpStream;
    use tokio::sync::watch;

    use crate::link_pipeline::bind_tcp;
    use crate::session_open::{initiate_and_open_session, DEFAULT_OPEN_TICK_MS};
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    use wz_session_core::locator::parse_locator;

    // ── R311y786 per-address re-dial schedule ──────────────────────────────

    /// R2900 — the schedule's key is a [`MeshDialKey`]; these cases grade the
    /// growth arithmetic, which is the same for every key shape, over IP keys.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    fn addr(port: u16) -> MeshDialKey {
        use std::net::{IpAddr, Ipv4Addr};
        MeshDialKey::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    }

    /// R2496 — an endpoint whose `#`-tail names no retry override, which is
    /// what every case below is about: these pin the GLOBAL policy's shape, and
    /// the per-endpoint layering has its own case.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    fn no_overrides() -> Option<&'static wz_session_core::locator::LocatorRetry> {
        None
    }

    /// The wait GROWS across the retries of one outage, per address. This is the
    /// defect R311y786 paid off: the fixed `RECONNECT_BACKOFF_MS` returned 1000
    /// forever, so a configured peer that was switched off was re-dialed at 1 Hz
    /// for as long as it stayed down.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn the_redial_wait_grows_per_address() {
        let mut s = RedialSchedule::new(RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 400,
            period_increase_factor: 2.0,
        });
        let a = &addr(7001);
        assert_eq!(
            (0..5)
                .map(|_| s.next_ms(a, no_overrides()))
                .collect::<Vec<_>>(),
            vec![100, 200, 400, 400, 400],
            "one address's retries must climb to the ceiling and stay there"
        );
    }

    /// R2496 (`router-connect-reconcile`) — an endpoint's OWN `#`-tail decides
    /// its cadence, which is what zenoh does per endpoint after resolving the
    /// global block
    /// (`commons/zenoh-config/src/connection_retry.rs` @ `pub fn get_retry_config(`).
    ///
    /// The second half is the ANTI-VACUITY arm and is not decoration: with the
    /// layering removed both addresses would still climb 100/200/400, so a test
    /// that only watched the tuned peer could not tell "the override applied"
    /// from "the global happened to be those numbers".
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn an_endpoints_own_tail_overrides_the_global_cadence() {
        let mut s = RedialSchedule::new(RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 400,
            period_increase_factor: 2.0,
        });
        let tuned =
            parse_locator("tcp/127.0.0.1:7001#retry_period_init_ms=25;retry_period_max_ms=50")
                .expect("valid tuned locator")
                .retry;
        let a = &addr(7001);
        assert_eq!(
            (0..4)
                .map(|_| s.next_ms(a, tuned.as_deref()))
                .collect::<Vec<_>>(),
            vec![25, 50, 50, 50],
            "the endpoint's own init and ceiling must be the ones that apply"
        );
        let b = &addr(7002);
        assert_eq!(
            (0..3)
                .map(|_| s.next_ms(b, no_overrides()))
                .collect::<Vec<_>>(),
            vec![100, 200, 400],
            "a peer whose tail says nothing keeps the GLOBAL cadence"
        );
    }

    /// Two peers down at once keep INDEPENDENT schedules. Sharing one counter
    /// would make a second peer's first re-dial inherit the first peer's grown
    /// wait — a peer that just dropped would wait the ceiling immediately.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn two_addresses_do_not_share_a_wait() {
        let mut s = RedialSchedule::new(RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 0,
            period_increase_factor: 2.0,
        });
        let (a, b) = (&addr(7001), &addr(7002));
        assert_eq!(s.next_ms(a, no_overrides()), 100);
        assert_eq!(s.next_ms(a, no_overrides()), 200);
        assert_eq!(
            s.next_ms(b, no_overrides()),
            100,
            "a different peer's FIRST re-dial must be period_init_ms"
        );
        assert_eq!(
            s.next_ms(a, no_overrides()),
            400,
            "and the first peer's own growth continues"
        );
    }

    /// [`RedialSchedule::forget`] resets the growth, which is what the loop calls
    /// on a SUCCESSFUL dial (and on an address that stops being desired). Without
    /// it a peer that flapped hours ago would start its next outage at the
    /// ceiling — the state would be per-process rather than per-outage, which is
    /// not the lifetime zenoh's `peer_connector_retry` local has.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn forget_returns_an_address_to_the_initial_wait() {
        let mut s = RedialSchedule::new(RetryPolicy {
            period_init_ms: 100,
            period_max_ms: 0,
            period_increase_factor: 2.0,
        });
        let a = &addr(7001);
        assert_eq!(s.next_ms(a, no_overrides()), 100);
        assert_eq!(s.next_ms(a, no_overrides()), 200);
        s.forget(a);
        assert_eq!(
            s.next_ms(a, no_overrides()),
            100,
            "a recovered peer's NEXT outage starts from period_init_ms"
        );
        // And forgetting an address with no state is a no-op, not a panic — the
        // loop calls it for every successful dial, including first-time ones.
        s.forget(&addr(7099));
    }

    /// The schedule holds only peers with an outage IN PROGRESS: `forget` removes
    /// the entry rather than resetting it in place, so a long-lived mesh does not
    /// accumulate one entry per address ever dialed.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn a_recovered_address_leaves_no_entry_behind() {
        let mut s = RedialSchedule::new(RetryPolicy::ZENOH_DEFAULT);
        let a = &addr(7001);
        s.next_ms(a, no_overrides());
        assert_eq!(s.periods.len(), 1);
        s.forget(a);
        assert!(
            s.periods.is_empty(),
            "a recovered peer must not stay in the map"
        );
    }

    /// A `constant` policy keeps the pre-y786 cadence exactly — the escape hatch
    /// the existing multilink suites and any flat-cadence deploy rely on.
    #[cfg(any(feature = "router-connect-reconcile", feature = "transport-multilink"))]
    #[test]
    fn a_constant_policy_reproduces_the_fixed_backoff() {
        let mut s = RedialSchedule::new(RetryPolicy::constant(1000));
        let a = &addr(7001);
        assert_eq!(
            (0..4)
                .map(|_| s.next_ms(a, no_overrides()))
                .collect::<Vec<_>>(),
            vec![1000, 1000, 1000, 1000]
        );
    }

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

    // ── shared fixtures ────────────────────────────────────────────────

    async fn bind_loopback() -> (BoundListener, SocketAddr) {
        let listener = bind_tcp(
            "127.0.0.1:0".parse().expect("loopback addr"),
            &crate::link_socket::LinkSocket::NONE,
        )
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

    /// R2233 (open-debt item 585) — this test's own name used to say
    /// `requires_a_tcp_locator`, and its `no_tcp` case asserted that a peer
    /// advertising `tls/127.0.0.1:7447` was NOT dialable. That was a true
    /// statement about a bypass, not about a capability: `dial_face` called
    /// `TcpStream::connect` and skipped the scheme dispatcher, so the gossip
    /// plane had to skip every non-tcp peer to avoid dialing TCP at a TLS port.
    /// The dispatcher is in the path now, so the assertion INVERTS — a `tls/` or
    /// `quic/` peer is dialed — and what survives is the NUMERIC requirement:
    /// this arm runs on the loop's own task and must not block on a resolver.
    ///
    /// R2900 — and the requirement narrows once more: what survives is only that
    /// the locator names its target WITHOUT a resolver. A peer that advertises
    /// only an address-less shape is dialed by its own key, as the pin's
    /// autoconnect dials whatever a discovered peer carries.
    /// Decision D3 — the loop's directory joins what the two planes found for one
    /// node: the newest hint is tried first, a link-state read replaces the
    /// graph's earlier set for the node, and a Hello's hint expires after
    /// `HELLO_LIFETIME_MS` while the flood's stays until the graph replaces it.
    #[test]
    fn the_loop_dials_a_node_at_the_hints_its_planes_gave_newest_first() {
        fn addr_of(decision: DialDecision) -> SocketAddr {
            match decision {
                DialDecision::Dial(t) => t.ip_addr().expect("an IP target"),
                _ => panic!("expected a dial"),
            }
        }
        let empty: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
        let mut directory = Box::new(LoopDirectory::new());
        let found = |locator: &str, origin| DialIntent {
            zid: vec![0xAA; 4],
            locators: vec![locator.into()],
            origin,
        };
        let flood = found("tcp/127.0.0.1:7101", DialIntentOrigin::Gossip);
        let hello = found("tcp/127.0.0.1:7102", DialIntentOrigin::MulticastScout);
        assert_eq!(
            addr_of(learn_and_decide(&empty, &flood, &mut directory, 0)),
            "127.0.0.1:7101".parse().unwrap()
        );
        assert_eq!(
            addr_of(learn_and_decide(&empty, &hello, &mut directory, 10)),
            "127.0.0.1:7102".parse().unwrap(),
            "the Hello's hint is the newest"
        );
        // The flood's set for the node moves: 7101 is no longer the graph's.
        let moved = found("tcp/127.0.0.1:7103", DialIntentOrigin::Gossip);
        learn_and_decide(&empty, &moved, &mut directory, 20);
        let mut zid = [0u8; 16];
        zid[..4].copy_from_slice(&[0xAA; 4]);
        assert_eq!(
            candidate_locators(&directory, &zid, 20),
            ["tcp/127.0.0.1:7103", "tcp/127.0.0.1:7102"],
            "the graph's earlier locator is withdrawn, the Hello's stays"
        );
        assert_eq!(
            candidate_locators(&directory, &zid, 10 + HELLO_LIFETIME_MS),
            ["tcp/127.0.0.1:7103"],
            "the Hello's hint ends; the flood's lasts until the graph replaces it"
        );
    }

    /// A discovery weighed by a loop whose directory has heard nothing else.
    fn decide(faces: &BTreeMap<FaceId, Option<Vec<u8>>>, intent: &DialIntent) -> DialDecision {
        let mut directory = Box::new(LoopDirectory::new());
        learn_and_decide(faces, intent, &mut directory, 0)
    }

    #[test]
    fn dial_decision_dedups_held_peers_and_requires_a_resolver_free_locator() {
        fn ip(t: &MeshDialTarget) -> &wz_session_core::locator::ParsedLocator {
            match &t.locator {
                AnyLocator::Ip(parsed) => parsed,
                other => panic!("expected an IP-family target, got {other:?}"),
            }
        }
        let acc = || DialIntent {
            zid: vec![0xAA; 4],
            locators: vec!["tcp/127.0.0.1:7447".into()],
            origin: DialIntentOrigin::Gossip,
        };
        // No held face + a numeric locator -> dial that endpoint.
        let empty: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
        assert!(matches!(
            decide(&empty,&acc()),
            DialDecision::Dial(t)
                if ip(&t).addr == "127.0.0.1:7447".parse().unwrap() && ip(&t).proto == Proto::Tcp
        ));
        // Decision D4: the dial is made for the node the intent names.
        let mut aa = [0u8; 16];
        aa[..4].copy_from_slice(&[0xAA; 4]);
        assert!(matches!(
            decide(&empty,&acc()),
            DialDecision::Dial(t) if t.expected_zid == Some(aa)
        ));
        // A held face to the peer's zid -> skip (the dedup), even with a valid
        // locator. A zid-less held face (None) matches no peer.
        let mut held: BTreeMap<FaceId, Option<Vec<u8>>> = BTreeMap::new();
        held.insert(FaceId(0), Some(vec![0xAA; 4]));
        held.insert(FaceId(1), None);
        assert!(holds_zid(&held, &[0xAA; 4]));
        assert!(!holds_zid(&held, &[0xBB; 4]), "a different zid is not held");
        assert!(matches!(decide(&held, &acc()), DialDecision::AlreadyHeld));
        // A NON-tcp numeric peer is dialed, and the SCHEME survives the decision —
        // this is the capability item 585 names, one plane over from the static
        // dial list.
        let tls_peer = DialIntent {
            zid: vec![0xBB; 4],
            locators: vec!["tls/127.0.0.1:7447".into()],
            origin: DialIntentOrigin::Gossip,
        };
        assert!(matches!(
            decide(&empty,&tls_peer),
            DialDecision::Dial(t) if ip(&t).proto == Proto::Tls
        ));
        let quic_peer = DialIntent {
            zid: vec![0xCC; 4],
            locators: vec!["quic/127.0.0.1:7447".into()],
            origin: DialIntentOrigin::Gossip,
        };
        assert!(matches!(
            decide(&empty,&quic_peer),
            DialDecision::Dial(t) if ip(&t).proto == Proto::Quic
        ));
        // R2900 — a peer that advertises only a unix socket is dialed by the
        // socket path, where it used to be skipped for having no address.
        let unix_peer = DialIntent {
            zid: vec![0xEE; 4],
            locators: vec!["unixsock-stream//tmp/wz-peer.sock".into()],
            origin: DialIntentOrigin::Gossip,
        };
        assert!(matches!(
            decide(&empty,&unix_peer),
            DialDecision::Dial(t)
                if t.key == MeshDialKey::Unixsock(String::from("/tmp/wz-peer.sock"))
        ));
        // What is still refused: a locator that needs a resolver this arm must
        // not run, and one that does not parse.
        let undialable = DialIntent {
            zid: vec![0xDD; 4],
            locators: vec!["tcp/example.org:7447".into(), "nonsense".into()],
            origin: DialIntentOrigin::Gossip,
        };
        assert!(matches!(
            decide(&empty, &undialable),
            DialDecision::NoLocator
        ));
        // `first_dialable_locator` takes the FIRST numeric IP locator, whatever
        // its scheme — where it used to walk past every non-tcp one.
        let first = first_dialable_locator(&["udp/1.2.3.4:7447".into(), "tcp/9.9.9.9:7447".into()])
            .expect("a numeric locator");
        assert_eq!(ip(&first).addr, "1.2.3.4:7447".parse().unwrap());
        assert_eq!(ip(&first).proto, Proto::Udp);
        assert!(first_dialable_locator(&[]).is_none());
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
    #[cfg(all(feature = "transport-link-unixsock", unix))]
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

    /// R2355 — the ws twin of [`unixsock_idle_initiator`]: dials a
    /// `ws/127.0.0.1:<port>` listener through the same
    /// [`connect_and_open_session`] SSOT, reaches Established over the RFC6455
    /// link, and idles until `go`. ws LISTENS on tcp but is a distinct scheme
    /// through the whole accept path (the server upgrade runs per accepted
    /// connection), which is what makes N of these a real test of the loop's
    /// scheme-keyed listener rather than of tcp wearing a different locator.
    #[cfg(feature = "transport-link-ws")]
    async fn ws_idle_initiator(addr: SocketAddr, zid: u8, mut go: watch::Receiver<bool>) {
        use crate::session_open::{connect_and_open_session, DialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator = parse_any_locator(&format!("ws/{addr}")).expect("parse ws locator");
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
        .expect("ws initiator reaches Established");

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
    #[cfg(all(feature = "transport-link-unixpipe", unix))]
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

    /// The quic twin of [`unixsock_idle_initiator`] (R311y404): dials a
    /// `quic/<addr>` listener through the cert-threaded [`connect_and_open_session`]
    /// SSOT (`DialConfig.quic`, exactly the `quic_e2e` dial path), reaches
    /// Established, and idles until `go`. Each initiator is a distinct client on the
    /// SAME quic endpoint, so the DEFERRED-handshake acceptor holds each as a
    /// DISTINCT ZID-keyed mesh face — the property the mesh-join discriminator
    /// asserts. Builds its own client config trusting the acceptor's self-signed
    /// `localhost` cert (SNI `localhost`, the self-trust-anchor pattern).
    ///
    /// SHUTDOWN IS GATED ON INITIATOR COMPLETION, not the acceptor's FaceUp (unlike
    /// the lossless-IPC siblings, which flip `go` from the acceptor's Nth FaceUp).
    /// The LAST initiator to reach Established flips `go`, which both ends the
    /// acceptor and releases every initiator. This is load-bearing for QUIC: all
    /// connections share the ONE server-endpoint UDP socket, so tearing the acceptor
    /// down on its own FaceUp — while a peer initiator is still awaiting its final
    /// handshake datagram (OpenAck) — would close that shared socket under the
    /// in-flight initiator (retransmit to a closed port -> `LinkLost(OsError)`, a
    /// teardown race the independent-fd siblings never hit). Since the acceptor's
    /// per-face Established (it SENT OpenAck) precedes the initiator's (it RECEIVED
    /// it), "all N initiators Established" already implies the acceptor recorded N
    /// FaceUps -> `peak_concurrent == N` holds before shutdown.
    #[cfg(feature = "transport-link-quic")]
    #[allow(clippy::too_many_arguments)]
    async fn quic_idle_initiator(
        addr: SocketAddr,
        cert_pem: String,
        zid: u8,
        up: Arc<AtomicUsize>,
        n: usize,
        go_tx: watch::Sender<bool>,
        mut go: watch::Receiver<bool>,
    ) {
        use crate::quic_config::quic_client_config_from_pem;
        use crate::session_open::{connect_and_open_session, DialConfig, QuicDialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator = parse_any_locator(&format!("quic/{addr}")).expect("parse quic locator");
        let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
            .expect("build quic client config");
        let cfg = DialConfig::default().with_quic(QuicDialConfig {
            client_config,
            server_name: "localhost".to_string(),
        });
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("quic initiator reaches Established");

        // This initiator is now Established. Only once ALL N are (the acceptor holds
        // N faces by then) do we flip `go` to shut the acceptor down — never before,
        // or the shared-endpoint teardown would kill an in-flight peer (see the fn
        // doc). Flipping `go` also releases this + every other initiator's idle wait.
        if up.fetch_add(1, SeqCst) + 1 == n {
            let _ = go_tx.send(true);
        }

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

    /// R311y408 — the quic-DATAGRAM twin of [`quic_idle_initiator`]: dials a
    /// `quic-datagram/<addr>` listener through the SAME cert-threaded
    /// [`connect_and_open_session`] SSOT (`DialConfig.quic` — the datagram dial
    /// reuses the reliable-quic client cert, exactly the `quic_datagram_e2e` dial
    /// path), reaches Established over the RFC9221 unreliable-DATAGRAM link (NO
    /// stream), and idles until `go`. Each initiator is a distinct client on the
    /// SAME server-endpoint UDP socket, so the DEFERRED-handshake datagram acceptor
    /// holds each as a DISTINCT ZID-keyed mesh face — the property
    /// [`mesh_accept_loop_holds_two_quic_datagram_peers`] asserts. The shutdown
    /// discipline is IDENTICAL to the reliable-quic initiator (gated on ALL
    /// initiators reaching Established, never the acceptor's FaceUp), for the same
    /// shared-UDP-socket teardown-race reason spelled out on [`quic_idle_initiator`].
    #[cfg(feature = "transport-link-quic-datagram")]
    #[allow(clippy::too_many_arguments)]
    async fn quic_datagram_idle_initiator(
        addr: SocketAddr,
        cert_pem: String,
        zid: u8,
        up: Arc<AtomicUsize>,
        n: usize,
        go_tx: watch::Sender<bool>,
        mut go: watch::Receiver<bool>,
    ) {
        use crate::quic_config::quic_client_config_from_pem;
        use crate::session_open::{connect_and_open_session, DialConfig, QuicDialConfig};
        use wz_session_core::locator::parse_any_locator;
        let locator = parse_any_locator(&format!("quic-datagram/{addr}"))
            .expect("parse quic-datagram locator");
        let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
            .expect("build quic client config");
        let cfg = DialConfig::default().with_quic(QuicDialConfig {
            client_config,
            server_name: "localhost".to_string(),
        });
        let mut params = fixture_session_init_params();
        params.zid = vec![zid; 4];
        let mut opened = connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(10_000),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("quic-datagram initiator reaches Established");

        // See `quic_idle_initiator`: flip `go` only once ALL N are Established (the
        // acceptor holds N faces by then), never on a per-initiator FaceUp, so the
        // shared server-endpoint UDP socket is never torn down under an in-flight peer.
        if up.fetch_add(1, SeqCst) + 1 == n {
            let _ = go_tx.send(true);
        }

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

    /// A forwarder that measures how many of its per-event calls are inside it at once and
    /// which threads they run on. `Send + Sync` (atomics and a mutex), so the spawned entry
    /// takes it; each call holds for a few milliseconds, so two calls overlap if and only
    /// if two faces' drives run at the same time.
    #[cfg(feature = "codec-push")]
    #[derive(Default)]
    struct OverlapProbe {
        inside: AtomicUsize,
        deepest: AtomicUsize,
        calls: AtomicUsize,
        threads: std::sync::Mutex<std::collections::HashSet<std::thread::ThreadId>>,
    }

    #[cfg(feature = "codec-push")]
    impl FaceForwarder for OverlapProbe {
        fn register(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) {}
        fn deregister(&self, _id: FaceId) {}
        fn forward(&self, _id: FaceId, event: IterationEvent<'_>) {
            if !matches!(event, IterationEvent::Poll(_)) {
                return;
            }
            self.calls.fetch_add(1, SeqCst);
            let now = self.inside.fetch_add(1, SeqCst) + 1;
            self.deepest.fetch_max(now, SeqCst);
            self.threads
                .lock()
                .expect("probe threads")
                .insert(std::thread::current().id());
            std::thread::sleep(Duration::from_millis(3));
            self.inside.fetch_sub(1, SeqCst);
        }
    }

    /// An initiator that dials, opens to Established, then PUTS `messages` small messages
    /// a millisecond apart, so the acceptor's face for it has frames to drive.
    #[cfg(feature = "codec-push")]
    async fn chatty_initiator(
        addr: SocketAddr,
        zid: u8,
        messages: usize,
        mut go: watch::Receiver<bool>,
    ) {
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
        let actions = opened.actions.clone();
        let sender = async move {
            for _ in 0..messages {
                actions
                    .send_push_literal("demo/overlap", b"x", true)
                    .expect("a put routes");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            std::future::pending::<()>().await;
        };
        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&v| v) => {}
            _ = sender => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound, &opened.actions, &mut opened.engine,
                None, &opened.clock, &timeouts, |_e| {},
            ) => {}
        }
        opened.drain_to_close().await;
    }

    /// How the accept-only node of [`overlap_run`] drives its faces.
    #[cfg(feature = "codec-push")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Drive {
        /// Held inside the loop's own task.
        Held,
        /// Spawned on the runtime's workers.
        Workers,
        /// Spawned as local tasks of the loop's own thread (inside a `LocalSet`).
        Local,
    }

    /// Four chatty peers against an accept-only node whose forwarder is the
    /// [`OverlapProbe`], with each face's drive driven as `drive` says. Returns the loop's
    /// summary and the probe.
    #[cfg(feature = "codec-push")]
    async fn overlap_run(drive: Drive) -> (AcceptLoopSummary, Arc<OverlapProbe>) {
        const N: usize = 4;
        let (listener, addr) = bind_loopback().await;
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::FaceUp(_) = event {
                    up.fetch_add(1, SeqCst);
                }
            }
        };
        let probe = Arc::new(OverlapProbe::default());
        let acceptor = async {
            match drive {
                Drive::Workers => {
                    accept_loop_offering_spawned(
                        listener,
                        acceptor_params(),
                        SessionOffer::universal(),
                        AcceptBounds::default(),
                        TokioTime::new(),
                        DEFAULT_OPEN_TICK_MS,
                        shutdown_on(go_rx.clone()),
                        on_event,
                        probe.clone(),
                        Arc::new(PlainFaceExecutor),
                    )
                    .await
                }
                Drive::Local => {
                    accept_loop_offering_spawned_local(
                        listener,
                        acceptor_params(),
                        SessionOffer::universal(),
                        AcceptBounds::default(),
                        TokioTime::new(),
                        DEFAULT_OPEN_TICK_MS,
                        shutdown_on(go_rx.clone()),
                        on_event,
                        probe.clone(),
                        Arc::new(PlainFaceExecutor),
                    )
                    .await
                }
                Drive::Held => {
                    accept_loop_offering(
                        listener,
                        acceptor_params(),
                        SessionOffer::universal(),
                        TokioTime::new(),
                        DEFAULT_OPEN_TICK_MS,
                        shutdown_on(go_rx.clone()),
                        on_event,
                        &*probe,
                    )
                    .await
                }
            }
        };
        let initiators = (0..N).map(|i| chatty_initiator(addr, (i as u8) + 1, 60, go_rx.clone()));
        // Let the traffic run once every face is up, then end the loop and the peers.
        let flipper = {
            let up = up.clone();
            async move {
                while up.load(SeqCst) < N {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                tokio::time::sleep(Duration::from_millis(600)).await;
                let _ = go_tx.send(true);
            }
        };
        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _, _) = tokio::join!(acceptor, join_all(initiators), flipper);
            summary
        })
        .await
        .expect("the run completes within 20s");
        (summary, probe)
    }

    /// With each face's drive spawned, the drives of four peers run AT THE SAME TIME, on
    /// more than one thread: the forwarder's per-event calls overlap. This is what a node
    /// of one core cannot do.
    #[cfg(feature = "codec-push")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spawned_faces_are_driven_in_parallel() {
        let (summary, probe) = overlap_run(Drive::Workers).await;
        assert_eq!(summary.established, 4, "all four peers are held");
        let calls = probe.calls.load(SeqCst);
        assert!(calls > 20, "the probe saw the traffic ({calls} calls)");
        let deepest = probe.deepest.load(SeqCst);
        assert!(
            deepest >= 2,
            "two faces' drives were inside the forwarder at once, deepest was {deepest}"
        );
        let threads = probe.threads.lock().expect("probe threads").len();
        assert!(threads >= 2, "the drives ran on {threads} thread(s)");
    }

    /// The control of the test above: the same four peers with the drives held in the loop's
    /// own task are driven ONE AT A TIME, so the calls never overlap. It is what makes the
    /// parallel result a property of the spawn and not of the probe or the traffic.
    #[cfg(feature = "codec-push")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn held_faces_are_driven_one_at_a_time() {
        let (summary, probe) = overlap_run(Drive::Held).await;
        assert_eq!(summary.established, 4, "all four peers are held");
        let calls = probe.calls.load(SeqCst);
        assert!(calls > 20, "the probe saw the traffic ({calls} calls)");
        assert_eq!(
            probe.deepest.load(SeqCst),
            1,
            "a loop that holds the drives itself never has two inside the forwarder"
        );
    }

    /// With each face's drive a LOCAL task, all four peers are held and driven, and the
    /// forwarder is still entered by one call at a time on ONE thread: the drives are separate
    /// tasks, but they share the thread, which is the contract of a node with serial
    /// callbacks. It is the control of [`spawned_faces_are_driven_in_parallel`] on the other
    /// side: what the local spawn keeps is what the worker spawn gives up.
    #[cfg(feature = "codec-push")]
    #[tokio::test(flavor = "current_thread")]
    async fn local_faces_are_driven_one_at_a_time_on_one_thread() {
        let local = tokio::task::LocalSet::new();
        let (summary, probe) = local.run_until(overlap_run(Drive::Local)).await;
        assert_eq!(summary.established, 4, "all four peers are held");
        let calls = probe.calls.load(SeqCst);
        assert!(calls > 20, "the probe saw the traffic ({calls} calls)");
        assert_eq!(
            probe.deepest.load(SeqCst),
            1,
            "local tasks of one thread never have two inside the forwarder"
        );
        assert_eq!(
            probe.threads.lock().expect("probe threads").len(),
            1,
            "every face's drive ran on the one thread"
        );
    }

    /// R2758 — THE SESSION BOUND REFUSES THE PEER PAST IT.
    ///
    /// zenoh denies at the manager under the session-table guard
    /// (`io/zenoh-transport/src/unicast/manager.rs` @ `max_sessions`:
    /// `if guard.len() >= self.config.unicast.max_sessions` ->
    /// `close::reason::INVALID`). This is that comparison against the table
    /// this loop keeps: two peers dial a node whose bound is ONE, and exactly
    /// one is held.
    ///
    /// ⚠ NON-FLAKY BY OBSERVATION, NOT BY TIMER. Shutdown flips when BOTH a
    /// `FaceUp` and a `FaceRefused` have been seen, so the loop cannot end
    /// before the refusal it is asserting on. A version that slept instead
    /// would pass on a node that simply had not accepted the second peer yet —
    /// the hollow-witness shape this module's own R311y140 note records.
    /// [[feedback-no-flaky-ever]]
    ///
    /// ⚠ WHICH peer is refused is deliberately NOT asserted: both dial the
    /// same loopback listener and the accept order is the kernel's. The claim
    /// is about the COUNT the table admits, which is what the bound governs.
    ///
    /// CONTROL, and the FORM of its red was measured rather than predicted —
    /// the first version of this sentence guessed wrong. Disabling the
    /// `faces.len() >= max_sessions` guard reds this test by the 20s TIMEOUT,
    /// not by the `established` assertion: with no refusal there is no
    /// `FaceRefused`, so the shutdown predicate below can never be satisfied
    /// and the loop runs until the timeout kills it. That is a consequence of
    /// the witness being observation-driven, and it is a STRONGER coupling than
    /// an assertion — the test cannot even finish without the behaviour it is
    /// asserting on — but it is a different red from the one a reader would
    /// assume, so it is written down.
    ///
    /// ⚠ GATED ON `routing-peer` because it drives [`peer_loop`], which is the
    /// entry that takes a configurable [`FaceSources::max_sessions`].
    /// [`accept_loop`] carries the bound too but fixes it at
    /// [`crate::config::DEFAULT_MAX_SESSIONS`], and a witness that had to open
    /// a thousand faces to reach it would be a benchmark, not a test.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn max_sessions_refuses_the_peer_past_the_bound() {
        let (listener, addr) = bind_loopback().await;

        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let refused = refused.clone();
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| {
                match event {
                    AcceptEvent::FaceUp(_) => {
                        up.fetch_add(1, SeqCst);
                    }
                    AcceptEvent::FaceRefused { .. } => {
                        refused.fetch_add(1, SeqCst);
                    }
                    _ => {}
                }
                // Both outcomes observed — the bound has done its work.
                if up.load(SeqCst) >= 1 && refused.load(SeqCst) >= 1 {
                    let _ = go_tx.send(true);
                }
            }
        };

        let node = peer_loop(
            FaceSources {
                listeners: vec![listener],
                dial_targets: vec![],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                // THE SUBJECT.
                max_sessions: 1,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
                offer: SessionOffer::universal(),
                retry: RetryPolicy::ZENOH_DEFAULT,
                stats: None,
            },
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators = (0..2u8).map(|i| idle_initiator(addr, i + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(node, join_all(initiators));
            summary
        })
        .await
        .expect("the bounded node completes within 20s");

        assert_eq!(
            summary.established, 1,
            "a bound of one admits exactly one peer"
        );
        assert_eq!(
            summary.peak_concurrent, 1,
            "the table never held more than the bound"
        );
        assert_eq!(
            summary.refused_over_max_sessions, 1,
            "the second peer was refused BY THE BOUND, not by a handshake failure"
        );
    }

    /// A forwarder that holds no face to any node when the loop asks (`holds_peer` says no) and
    /// refuses the link when it registers it, as a registry does whose other role's face to the
    /// node came up in between: the loop then holds no face, tells nobody it is up, and the
    /// forwarder is asked once.
    #[cfg(feature = "routing-peer")]
    #[tokio::test]
    async fn a_face_the_forwarder_refuses_at_its_admission_is_not_held() {
        struct RefusesAtAdmission(AtomicUsize);
        impl FaceForwarder for RefusesAtAdmission {
            fn register(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) {}
            fn admit(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) -> bool {
                self.0.fetch_add(1, SeqCst);
                false
            }
            fn deregister(&self, _id: FaceId) {}
            fn forward(&self, _id: FaceId, _event: IterationEvent<'_>) {}
        }

        let (listener, addr) = bind_loopback().await;
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let refused = refused.clone();
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| match event {
                AcceptEvent::FaceUp(_) => {
                    up.fetch_add(1, SeqCst);
                }
                AcceptEvent::FaceRefused { .. } => {
                    refused.fetch_add(1, SeqCst);
                    let _ = go_tx.send(true);
                }
                _ => {}
            }
        };
        let forwarder = RefusesAtAdmission(AtomicUsize::new(0));

        let node = peer_loop(
            FaceSources {
                listeners: vec![listener],
                dial_targets: vec![],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                max_sessions: crate::config::DEFAULT_MAX_SESSIONS,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
                offer: SessionOffer::universal(),
                retry: RetryPolicy::ZENOH_DEFAULT,
                stats: None,
            },
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &forwarder,
        );
        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(node, idle_initiator(addr, 1, go_rx.clone()));
            summary
        })
        .await
        .expect("the node completes within 20s");

        assert_eq!(forwarder.0.load(SeqCst), 1, "the forwarder is asked once");
        assert_eq!(up.load(SeqCst), 0, "a refused face is never reported up");
        assert_eq!(refused.load(SeqCst), 1, "it is reported refused");
        assert_eq!(summary.established, 0, "and the loop holds none");
    }

    /// Runs an accept-only loop with `bounds` over `peers` silent TCP connections, which send
    /// nothing, and reports for each whether the loop had closed it `after` the last connected,
    /// with the loop's summary. A silent peer is the whole subject of both bounds: it is a link
    /// that has arrived and has not begun a handshake.
    async fn silent_peers_against(
        bounds: AcceptBounds,
        peers: usize,
        after: Duration,
    ) -> (Vec<bool>, AcceptLoopSummary) {
        use tokio::io::AsyncReadExt as _;
        let (listener, addr) = bind_loopback().await;
        let (go_tx, go_rx) = watch::channel(false);
        let node = face_drive_loop(
            accept_only_sources(listener, SessionOffer::universal(), bounds),
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            |_event: &AcceptEvent| {},
            FaceDriving {
                forwarder: &NoOpForwarder,
                spawned: None,
            },
        );
        let observe = async move {
            let mut streams = Vec::new();
            for _ in 0..peers {
                streams.push(TcpStream::connect(addr).await.expect("connect"));
                // One at a time, so the order the loop sees them in is the order they are
                // counted in, and the refused one is the last.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(after).await;
            let mut closed = Vec::new();
            for stream in &mut streams {
                let mut byte = [0u8; 1];
                // A closed link reads end-of-stream at once; an open and silent one has nothing
                // to read, so the read is still pending when the short bound elapses.
                let read =
                    tokio::time::timeout(Duration::from_millis(200), stream.read(&mut byte)).await;
                closed.push(matches!(read, Ok(Ok(0)) | Ok(Err(_))));
            }
            let _ = go_tx.send(true);
            closed
        };
        let (summary, closed) = tokio::join!(node, observe);
        (closed, summary)
    }

    /// Upstream's `accept_pending`: a link that arrives while that many accepts are still
    /// mid-handshake is closed at once, unanswered. Two silent peers fill a bound of two, the
    /// third is closed and counted apart; with the default bound, a hundred, the same three
    /// are all held, so the closing above is the bound's and not the loop's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_link_past_the_pending_bound_is_closed_unanswered_and_counted() {
        let bounded = AcceptBounds {
            pending: 2,
            ..AcceptBounds::default()
        };
        let (closed, summary) = silent_peers_against(bounded, 3, Duration::from_millis(300)).await;
        assert_eq!(
            closed,
            [false, false, true],
            "the third link, past the bound of two, is the one closed"
        );
        assert_eq!(summary.refused_over_pending, 1);
        assert_eq!(summary.accepted, 2, "a refused link is not an accepted one");

        let (closed, summary) =
            silent_peers_against(AcceptBounds::default(), 3, Duration::from_millis(300)).await;
        assert_eq!(closed, [false, false, false], "control: nothing is closed");
        assert_eq!(summary.refused_over_pending, 0);
        assert_eq!(summary.accepted, 3);
    }

    /// Upstream's `accept_timeout` is the whole accept's bound, and it is the node's to state:
    /// a silent peer is dropped when the stated time has passed, and not before. The session
    /// machine's own window is one second (§2.5, pico's), which this loop used to apply to every
    /// peer; a bound of four hundred milliseconds drops a peer the old one would have kept for
    /// another six hundred, and the default, ten seconds, keeps one the old one had dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_silent_link_is_dropped_when_the_accept_timeout_has_passed_and_not_before() {
        let short = AcceptBounds::default().with_timeout_ms(400);
        let (closed, _) = silent_peers_against(short, 1, Duration::from_millis(700)).await;
        assert_eq!(closed, [true], "dropped after 400 ms, well within 700");

        let (closed, _) =
            silent_peers_against(AcceptBounds::default(), 1, Duration::from_millis(1500)).await;
        assert_eq!(
            closed,
            [false],
            "control: the default ten seconds still holds a peer silent for one and a half"
        );
    }

    /// The host's moving ceiling bounds admission like `max_sessions` does and is counted apart
    /// from it: a node whose configured bound has room refuses the second peer because its
    /// measured capacity is one, and the summary says so. The configured counter stays at zero,
    /// which is what lets an operator tell whose limit it was.
    ///
    /// Observation-driven like the test above: shutdown waits for both a `FaceUp` and a
    /// `FaceRefused`, so the loop cannot end before the refusal this asserts on.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_moving_ceiling_refuses_the_peer_past_it_and_counts_it_apart() {
        let (listener, addr) = bind_loopback().await;
        // The host's handle: what the loop counts while it runs is what this reads.
        let live = SessionCeiling::new(|| 1);

        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let up = up.clone();
            let refused = refused.clone();
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| {
                match event {
                    AcceptEvent::FaceUp(_) => {
                        up.fetch_add(1, SeqCst);
                    }
                    AcceptEvent::FaceRefused { .. } => {
                        refused.fetch_add(1, SeqCst);
                    }
                    _ => {}
                }
                if up.load(SeqCst) >= 1 && refused.load(SeqCst) >= 1 {
                    let _ = go_tx.send(true);
                }
            }
        };

        let node = peer_loop(
            FaceSources {
                listeners: vec![listener],
                dial_targets: vec![],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                max_sessions: usize::MAX,
                accept: AcceptBounds::default(),
                // THE SUBJECT.
                ceiling: Some(live.clone()),
                peer_board: None,
                offer: SessionOffer::universal(),
                retry: RetryPolicy::ZENOH_DEFAULT,
                stats: None,
            },
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            on_event,
            &NoOpForwarder,
        );
        let initiators = (0..2u8).map(|i| idle_initiator(addr, i + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(node, join_all(initiators));
            summary
        })
        .await
        .expect("the node with a ceiling completes within 20s");

        assert_eq!(summary.established, 1, "a ceiling of one admits one peer");
        assert_eq!(
            summary.refused_over_capacity, 1,
            "the second peer was refused BY THE MEASURED CAPACITY"
        );
        assert_eq!(
            summary.refused_over_max_sessions, 0,
            "the configured bound had room and refused nobody"
        );
        // The same counts, read from the host's handle and not from the end-of-run summary.
        assert_eq!(live.refused_over_capacity(), 1);
        assert_eq!(live.refused_over_max_sessions(), 0);
    }

    /// R2844 — the face loop is the node's transport manager, so the node's
    /// stats registry is filled HERE: a face that comes up is counted, labelled
    /// with the peer the handshake named, and a face that goes down is counted
    /// out and still listed as disconnected. Each snapshot is taken inside the
    /// loop's own FaceUp / FaceDown event, so it reads the registry exactly as
    /// the loop left it at that step.
    ///
    /// R2852 — gated on `routing-peer` too: the node under test is a
    /// `peer_loop`, which a `routing-accept` + `transport-stats` build without
    /// it does not have, and that build's test target did not compile.
    #[cfg(all(feature = "transport-stats", feature = "routing-peer"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_face_loop_records_each_face_into_the_node_registry() {
        use crate::node_stats::NodeStats;
        use wz_session_core::stats_registry::MetricsQuery;
        use wz_session_core::WhatAmI;

        fn document(stats: &NodeStats, query: MetricsQuery) -> String {
            let mut doc = String::new();
            stats.snapshot().encode_metrics(&mut doc, query);
            doc
        }
        const OPENED: &str = r#"zenoh_transports_opened{local_id="a1b2",local_whatami="router"} "#;
        // zenoh's rendering of the initiator's `[1; 4]` zid.
        const PEER: &str = r#"remote_zid="1010101",remote_whatami="peer""#;
        let with_disconnected = MetricsQuery {
            disconnected: true,
            ..MetricsQuery::default()
        };

        let (listener, addr) = bind_loopback().await;
        let stats = NodeStats::new("a1b2", WhatAmI::Router, "v1");
        let (leave_tx, leave_rx) = watch::channel(false);
        let (stop_tx, stop_rx) = watch::channel(false);
        let seen: Arc<std::sync::Mutex<Vec<(&'static str, String)>>> = Arc::default();
        let on_event = {
            let stats = stats.clone();
            let seen = seen.clone();
            move |event: &AcceptEvent| {
                let step = match event {
                    AcceptEvent::FaceUp(_) => "up",
                    AcceptEvent::FaceDown(..) => "down",
                    _ => return,
                };
                let doc = document(&stats, with_disconnected);
                seen.lock().expect("seen poisoned").push((step, doc));
                let _ = if step == "up" {
                    leave_tx.send(true)
                } else {
                    stop_tx.send(true)
                };
            }
        };

        let node = peer_loop(
            FaceSources {
                listeners: vec![listener],
                dial_targets: vec![],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                max_sessions: crate::config::DEFAULT_MAX_SESSIONS,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
                offer: SessionOffer::universal(),
                retry: RetryPolicy::ZENOH_DEFAULT,
                // THE SUBJECT.
                stats: Some(stats.clone()),
            },
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(stop_rx),
            on_event,
            &NoOpForwarder,
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(node, idle_initiator(addr, 1, leave_rx));
        })
        .await
        .expect("the face comes up and goes down within 20s");

        let seen = seen.lock().expect("seen poisoned");
        let steps: Vec<&str> = seen.iter().map(|(step, _)| *step).collect();
        assert_eq!(steps, ["up", "down"], "one face, up then down");
        let (_, up) = &seen[0];
        let (_, down) = &seen[1];
        assert!(
            up.contains(&format!("\n{OPENED}1\n")),
            "counted while held:\n{up}"
        );
        assert!(
            up.lines()
                .any(|l| l.contains(PEER) && l.contains(r#"disconnected="false""#)),
            "its series carry the peer the handshake named:\n{up}"
        );
        assert!(
            down.contains(&format!("\n{OPENED}0\n")),
            "counted out:\n{down}"
        );
        assert!(
            down.lines()
                .any(|l| l.contains(PEER) && l.contains(r#"disconnected="true""#)),
            "still listed, as disconnected, until the collection delay:\n{down}"
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
    #[cfg(all(feature = "transport-link-unixsock", unix))]
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

    /// R2355 — the MULTI-PEER ws discriminator, in the tree rather than behind a
    /// binary. Two ws clients dial ONE `ws/127.0.0.1:0` listener through the
    /// mesh accept loop and BOTH are held at once (`peak_concurrent == 2`), with
    /// zero `AcceptError`.
    ///
    /// WHY IT IS HERE. The `transport-link-ws` registry entry carried "the
    /// multi-peer `--router ws/` path stays tcp-only (`bind_endpoint` via
    /// `BoundListener::into_tcp`, a clean typed `Unsupported`) pending the
    /// accept_loop generalization" as an open residual. R311y376 did the
    /// generalization -- `FaceSources.listener` became a scheme-keyed
    /// `BoundListener` -- but its only proof was
    /// `wz_router_ws_acceptor_zenohd_interop`, which needs a real `zenohd` and
    /// so runs on the `--ignored` Layer Z lane. A clause whose evidence only
    /// exists when a foreign binary is installed is a clause most runs cannot
    /// see, so this is the wz<->wz twin that runs on C1v every time.
    ///
    /// RED on the pre-y376 loop: `bind_endpoint` projected to a raw
    /// `TcpListener`, so a `ws/` listen surfaced `Unsupported` at BIND and the
    /// loop never started -- the failure lands on the `expect` below, before any
    /// initiator dials. On a loop generalized but NOT running the per-accept
    /// server upgrade, the initiators' RFC6455 client handshake never completes
    /// and `established` stays 0.
    ///
    /// TWO peers, not one: the point of the clause is the MULTI-peer path, and a
    /// single-accept assertion is satisfied by the one-shot `accept_bound` seam
    /// that was never tcp-only in the first place. NON-FLAKY: loopback TCP under
    /// ws is lossless + in-order, so two clean handshakes are deterministic --
    /// the assumption the unixsock/udp/tcp N-peer siblings above share.
    #[cfg(feature = "transport-link-ws")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_ws_peers() {
        use crate::session_open::bind_endpoint;
        const N: usize = 2;
        let listener = bind_endpoint("ws/127.0.0.1:0")
            .await
            .expect("bind a ws listener through the shipped multi-peer seam");
        let addr = listener.local_addr().expect("ws listener local_addr");

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
        let initiators = (0..N).map(|i| ws_idle_initiator(addr, (i as u8) + 1, go_rx.clone()));

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer ws accept completes within 20s");

        assert_eq!(
            summary.accepted, N,
            "accepted both ws peers through the scheme-keyed BoundListener"
        );
        assert_eq!(
            summary.established, N,
            "both ws peers reached Established, so the per-accept RFC6455 server \
             upgrade ran inside the loop"
        );
        assert_eq!(
            summary.peak_concurrent, N,
            "held both ws faces simultaneously — the MULTI-peer property, not the \
             one-shot accept seam"
        );
        assert_eq!(rejects.load(SeqCst), 0, "no AcceptError over a ws listener");
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
    #[cfg(all(feature = "transport-link-unixpipe", unix))]
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

    /// R311y404 — the MESH-JOIN discriminator for QUIC. Two initiators dial ONE
    /// `quic/<addr>` endpoint through the cert-threaded handshake and BOTH are held
    /// as ZID-keyed faces at once (peak_concurrent == 2), with ZERO AcceptError — the
    /// quic twin of [`mesh_accept_loop_holds_two_unixpipe_peers`]. RED on the
    /// pre-R311y404 acceptor: `supports_mesh_multi_peer` was `false`, so the
    /// `Step::Accepted` arm reject-throttle-dropped EVERY quic accept (0 faces held,
    /// `accepted == 0`, `peak == 0`); the deferred-handshake split flips it `true` and
    /// runs the crypto OFF the accept path, so both peers land as faces. GATING: the
    /// accept_loop mod is `routing-accept`-gated, so this test compiles only when the
    /// harness names `routing-accept` alongside `transport-link-quic` (a bare
    /// `transport-link-quic` build compiles the whole loop — and this test — OUT).
    /// NON-FLAKY: shutdown is gated on ALL initiators reaching Established
    /// ([`quic_idle_initiator`] flips `go`), NOT the acceptor's FaceUp — QUIC's
    /// connections share one endpoint UDP socket, so an acceptor-FaceUp shutdown
    /// could close it under a peer still awaiting its OpenAck (`LinkLost`); gating on
    /// initiator completion closes that teardown race. [[feedback-no-flaky-ever]]
    /// [[feedback-flaky-rootcause-never-revert]]
    #[cfg(feature = "transport-link-quic")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_quic_peers() {
        use crate::quic_config::quic_server_config_from_pem;
        use crate::session_open::{bind_locator, AcceptConfig, QuicAcceptConfig};
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        use wz_session_core::locator::parse_any_locator;
        const N: usize = 2;

        // Self-signed `localhost` cert (SAN `localhost`), the self-trust-anchor
        // quic_e2e pattern: the acceptor presents it, the clients trust the same PEM.
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");

        // Bind the mesh-capable quic acceptor through the real bind seam
        // (`Proto::Quic` -> `BoundListener::Quic` given `AcceptConfig.quic`).
        let accept_cfg = AcceptConfig::default().with_quic(QuicAcceptConfig { server_config });
        let locator = parse_any_locator("quic/127.0.0.1:0").expect("parse quic locator");
        let listener = bind_locator(locator, &accept_cfg)
            .await
            .expect("bind a quic listener");
        let addr = listener.local_addr().expect("quic listener local addr");

        // `go` flips when all N INITIATORS reach Established (each initiator counts
        // itself up; the last one sends), NOT on the acceptor's Nth FaceUp: the
        // acceptor must outlive every initiator's handshake because they share one
        // endpoint UDP socket (see `quic_idle_initiator`). By then the acceptor holds
        // all N faces (its per-face Established precedes the initiator's), so
        // `peak_concurrent == N` is already recorded when shutdown fires.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let rejects = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let rejects = rejects.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::AcceptError(_) = event {
                    rejects.fetch_add(1, SeqCst);
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
        let initiators = (0..N).map(|i| {
            quic_idle_initiator(
                addr,
                cert_pem.clone(),
                (i as u8) + 1,
                up.clone(),
                N,
                go_tx.clone(),
                go_rx.clone(),
            )
        });

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer quic accept completes within 20s");

        assert_eq!(
            summary.accepted, N,
            "accepted both quic peers (a genuine per-peer connection accept)"
        );
        assert_eq!(
            summary.established, N,
            "both quic peers reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, N,
            "held both quic faces simultaneously (deferred-handshake ZID-keyed mesh face)"
        );
        assert_eq!(
            rejects.load(SeqCst),
            0,
            "no reject: quic is a mesh-capable acceptor (R311y404 deferred split)"
        );
    }

    /// R311y408 — the quic-DATAGRAM twin of [`mesh_accept_loop_holds_two_quic_peers`]:
    /// the RFC9221 unreliable-datagram acceptor holds TWO ZID-keyed mesh faces off
    /// ONE bound server endpoint. Binds a `quic-datagram/...` listener through the
    /// real seam (`Proto::QuicDatagram` -> `BoundListener::QuicDatagram` given
    /// `AcceptConfig.quic`), then two initiators dial the same endpoint and both
    /// reach Established, held simultaneously (peak_concurrent == 2) with ZERO
    /// `AcceptError`. THE DISCRIMINATOR for `supports_mesh_multi_peer == true` on the
    /// QuicDatagram acceptor: if the `AcceptedLink::QuicDatagram` arm (consulted by
    /// the `Step::Accepted` backstop) returned `false`, the loop would reject-
    /// throttle-drop the SECOND accept — `rejects > 0`, `peak == 1`, `go` never
    /// flips, timeout (RED). The deferred `complete_quic_datagram_accept` split
    /// (R311y408, mirroring R311y404's reliable-quic split) is what runs the crypto
    /// OFF the accept path so both peers land as faces. GATING: the accept_loop mod
    /// is `routing-accept`-gated, so this test compiles only when the harness names
    /// `routing-accept` alongside `transport-link-quic-datagram` (a bare
    /// `transport-link-quic-datagram` build compiles the whole loop — and this test —
    /// OUT). NON-FLAKY: shutdown is gated on ALL initiators reaching Established
    /// ([`quic_datagram_idle_initiator`] flips `go`), NOT the acceptor's FaceUp —
    /// datagram connections share one endpoint UDP socket, and loopback UDP is
    /// lossless, so two clean handshakes are deterministic (the same assumption
    /// `mesh_accept_loop_holds_two_udp_peers` / `quic_datagram_e2e` rely on).
    /// [[feedback-no-flaky-ever]] [[feedback-flaky-rootcause-never-revert]]
    #[cfg(feature = "transport-link-quic-datagram")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mesh_accept_loop_holds_two_quic_datagram_peers() {
        use crate::quic_config::quic_server_config_from_pem;
        use crate::session_open::{bind_locator, AcceptConfig, QuicAcceptConfig};
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        use wz_session_core::locator::parse_any_locator;
        const N: usize = 2;

        // Self-signed `localhost` cert: the acceptor presents it, the clients trust
        // the same PEM (the self-trust-anchor quic_datagram_e2e pattern). Datagrams
        // reuse the SAME server cert as the reliable-quic backend.
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");

        // Bind the mesh-capable quic-datagram acceptor through the real bind seam
        // (`Proto::QuicDatagram` -> `BoundListener::QuicDatagram` given `AcceptConfig.quic`).
        let accept_cfg = AcceptConfig::default().with_quic(QuicAcceptConfig { server_config });
        let locator =
            parse_any_locator("quic-datagram/127.0.0.1:0").expect("parse quic-datagram locator");
        let listener = bind_locator(locator, &accept_cfg)
            .await
            .expect("bind a quic-datagram listener");
        let addr = listener
            .local_addr()
            .expect("quic-datagram listener local addr");

        // `go` flips when all N INITIATORS reach Established (each counts itself up;
        // the last one sends), NOT on the acceptor's Nth FaceUp — the shared-endpoint
        // teardown-race guard (see `quic_datagram_idle_initiator`). By then the
        // acceptor holds all N faces (its per-face Established precedes the
        // initiator's), so `peak_concurrent == N` is already recorded at shutdown.
        let (go_tx, go_rx) = watch::channel(false);
        let up = Arc::new(AtomicUsize::new(0));
        let rejects = Arc::new(AtomicUsize::new(0));
        let on_event = {
            let rejects = rejects.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::AcceptError(_) = event {
                    rejects.fetch_add(1, SeqCst);
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
        let initiators = (0..N).map(|i| {
            quic_datagram_idle_initiator(
                addr,
                cert_pem.clone(),
                (i as u8) + 1,
                up.clone(),
                N,
                go_tx.clone(),
                go_rx.clone(),
            )
        });

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, _) = tokio::join!(acceptor, join_all(initiators));
            summary
        })
        .await
        .expect("multi-peer quic-datagram accept completes within 20s");

        assert_eq!(
            summary.accepted, N,
            "accepted both quic-datagram peers (a genuine per-peer connection accept)"
        );
        assert_eq!(
            summary.established, N,
            "both quic-datagram peers reached Established"
        );
        assert_eq!(
            summary.peak_concurrent, N,
            "held both quic-datagram faces simultaneously (deferred-handshake ZID-keyed mesh face)"
        );
        assert_eq!(
            rejects.load(SeqCst),
            0,
            "no reject: quic-datagram is a mesh-capable acceptor (R311y408 deferred split)"
        );
    }

    // ⛔ R2723 — `acceptedlink_tcp_is_mesh_capable` and
    // `acceptedlink_unixpipe_is_mesh_capable` are GONE with the predicate they
    // pinned. They were the ONLY callers `AcceptedLink::supports_mesh_multi_peer`
    // had left once the loop stopped consulting it, and a test whose subject has
    // been deleted is not coverage. The BIND-time twin keeps its own pins
    // (`boundlistener_*_is_mesh_capable` in `session_open`), which is where the
    // cadence is now declared and reported.
    /// ⛔ R2723 — THE MESH LOOP HOLDS A FACE OFF A TTY, which it could not do
    /// before this round however the listener behaved.
    ///
    /// The `Step::Accepted` arm used to drop any link whose acceptor could not
    /// yield N CONCURRENT peers, and serial is the only such acceptor, so a
    /// `serial/...` listener reached the loop and had its link thrown away with an
    /// `AcceptError`. That was the right call while a wz serial listener yielded
    /// ONE link EVER; R2722 gave it link-liveness feedback, so it serves peers one
    /// AT A TIME and `accept_any` — which rebuilds its future set every iteration
    /// — feeds the loop from it like any other listener.
    ///
    /// THE DISCRIMINATOR IS `summary.accepted`. Restoring the reject arm makes
    /// this arm report 0 accepted and 0 established while everything else about
    /// the test still runs, so it fails on the admission decision specifically
    /// rather than on the transport working at all.
    #[cfg(feature = "transport-link-serial")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_loop_holds_a_face_off_a_serial_listener() {
        use crate::serial_pipeline::{drive_serial_handshake, SerialPort};
        use crate::session_open::{bind_locator, AcceptConfig};
        use tokio_serial::SerialStream;
        use wz_session_core::locator::{parse_any_locator, AnyLocator};
        use wz_session_core::serial_link::SerialRole;

        let (mut master, slave) = SerialStream::pair().expect("openpty serial pair");
        let path = tokio_serial::SerialPort::name(&slave).expect("pty slave has a device path");
        // The slave handle stays open for the test's life: the listener opens the
        // same device by PATH, and letting this one close first would tear the pty
        // down under it.
        let _slave_keepalive = slave;

        let locator = format!("serial/{path}#baudrate=115200");
        let endpoint = match parse_any_locator(&locator).expect("locator parses") {
            AnyLocator::Serial(ep) => ep,
            other => panic!("expected AnyLocator::Serial, got {other:?}"),
        };
        let listener = bind_locator(
            AnyLocator::Serial(endpoint.clone()),
            &AcceptConfig::default(),
        )
        .await
        .expect("a serial listen binds");

        let (go_tx, go_rx) = watch::channel(false);
        let on_event = {
            let go_tx = go_tx.clone();
            move |event: &AcceptEvent| {
                if let AcceptEvent::FaceUp(_) = event {
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
        let initiator = async {
            drive_serial_handshake(&mut master, SerialRole::Initiator)
                .await
                .expect("the peer's serial-link handshake reaches Connected");
            let mut params = fixture_session_init_params();
            params.zid = vec![0x01; 4];
            let mut opened = initiate_and_open_session(
                DialedLink::Serial {
                    stream: SerialPort::dialled(master),
                    endpoint,
                },
                params,
                TokioTime::new(),
                Some(10_000),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("the tty peer reaches Established against the loop");

            let timeouts = SessionTimeouts::spec_defaults();
            let mut go = go_rx.clone();
            tokio::select! {
                _ = go.wait_for(|&v| v) => {}
                _ = drive_session_until_terminal(
                    &mut opened.inbound, &opened.actions, &mut opened.engine,
                    None, &opened.clock, &timeouts, |_e| {},
                ) => {}
            }
            opened.drain_to_close().await;
        };

        let summary = tokio::time::timeout(Duration::from_secs(20), async {
            let (summary, ()) = tokio::join!(acceptor, initiator);
            summary
        })
        .await
        .expect("the serial face comes up within 20s");

        assert_eq!(
            summary.accepted, 1,
            "the loop ACCEPTED the tty link instead of dropping it as non-mesh"
        );
        assert_eq!(
            summary.established, 1,
            "and carried it to Established, so the admission was not merely a count"
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
                listeners: vec![peer_listener],
                dial_targets: vec![tcp_dial(acc_addr)],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                offer: SessionOffer::universal(),
                // R311y786 — the PRE-y786 cadence (fixed 1 s), so these suites keep
                // measuring what they were written for; the growth has its own.
                retry: RetryPolicy::constant(1000),
                stats: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                // R2758 — unbounded, so these fixtures keep the subject they had.
                max_sessions: usize::MAX,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
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
        // R311y423 — the NEG half of the gossip_dialed discriminator: a CONFIGURED
        // dial bumps `dialed` and must leave `gossip_dialed` at 0. Without this, a
        // counter that merely mirrored `dialed` would satisfy the positive
        // assertion in the autoconnect test and credit scouting-autoconnect to a
        // node autoconnect never moved.
        // R2141 — BOTH discovery counters, because there are two now and a static
        // dial is neither.
        assert_eq!(
            (summary.gossip_dialed, summary.scout_dialed),
            (0, 0),
            "a configured --connect dial is not a discovery dial on either plane"
        );
        assert_eq!(summary.accepted, 0, "no inbound peer connected");
        assert_eq!(
            summary.established, 1,
            "the dialed face reached Established"
        );
        assert_eq!(summary.peak_concurrent, 1, "held the outbound face");
    }

    /// R2233 (open-debt item 585) — THE witness the item exists for: two wz mesh
    /// nodes meet over a **QUIC** face, one dialing and one accepting.
    ///
    /// Before this round the accept half of this test already passed
    /// ([`mesh_accept_loop_holds_two_quic_peers`], R311y404) and the dial half
    /// was UNREPRESENTABLE — not "failing", unrepresentable: `dial_targets` held
    /// `SocketAddr`s, `resolve_mesh_dial_target` rejected `quic/...` by name, and
    /// `dial_face` called `TcpStream::connect`. So wz accepted QUIC from zenohd
    /// and from a foreign pico, and two wz nodes could not form a QUIC mesh face
    /// between themselves — a parity gap the four cross-impl legs HID, because in
    /// each of them the external implementation did the dialing wz could not.
    ///
    /// What it binds, and why each half matters:
    /// * `dial_targets` carries the SCHEME (a `quic/` locator, not an address),
    ///   so `dial_locator` can dispatch on it — ② of the item.
    /// * `dial_config` carries the ROOT CA, so the dispatcher's quic arm has the
    ///   trust material a locator string cannot hold — ④, the piece that is not
    ///   a type change. Drop it and the same dial reaches
    ///   `dial_locator`'s `cfg.quic == None` arm and fails `Unsupported`, which
    ///   is why this test is not satisfied by the type change alone.
    ///
    /// SHUTDOWN ORDER, from `quic_idle_initiator`'s doc: the acceptor must
    /// outlive the dialer's handshake (both sides share one endpoint UDP socket),
    /// and the acceptor's per-face Established precedes the dialer's, so flipping
    /// `go` on the DIALER's FaceUp already implies the acceptor held its face.
    #[cfg(all(feature = "routing-peer", feature = "transport-link-quic"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peer_loop_dials_a_configured_quic_peer_and_holds_it() {
        use crate::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
        use crate::session_open::{bind_locator, AcceptConfig, QuicAcceptConfig, QuicDialConfig};
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        use wz_session_core::locator::parse_any_locator;

        // One self-signed `localhost` cert: the acceptor presents it, the dialer
        // trusts the same PEM (the `quic_e2e` self-trust-anchor pattern).
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");
        let accept_cfg = AcceptConfig::default().with_quic(QuicAcceptConfig { server_config });
        let listener = bind_locator(
            parse_any_locator("quic/127.0.0.1:0").expect("parse quic listen locator"),
            &accept_cfg,
        )
        .await
        .expect("bind a quic listener");
        let acc_addr = listener.local_addr().expect("quic listener local addr");

        let (go_tx, go_rx) = watch::channel(false);
        let acceptor = accept_loop(
            listener,
            acceptor_params(),
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            shutdown_on(go_rx.clone()),
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        );

        // The mesh DIAL target, through the same resolver a `--connect` uses — so
        // this fixture proves the configuration path, not a hand-built locator.
        let target = crate::session_open::resolve_mesh_dial_target(&format!("quic/{acc_addr}"))
            .await
            .expect("a quic mesh dial target resolves");
        let dial_config = Arc::new(
            DialConfig::default().with_quic(QuicDialConfig {
                client_config: quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
                    .expect("build quic client config"),
                server_name: "localhost".to_string(),
            }),
        );

        let on_event = move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(_) = event {
                let _ = go_tx.send(true);
            }
        };
        let peer = peer_loop(
            FaceSources {
                // Dial-only: an empty listener list is representable and means
                // "accept nothing", so the only face this node can hold is the
                // one it DIALED. That is what makes the count below attributable.
                listeners: vec![],
                dial_targets: vec![target],
                dial_config,
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                offer: SessionOffer::universal(),
                retry: RetryPolicy::constant(1000),
                stats: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                // R2758 — unbounded, so these fixtures keep the subject they had.
                max_sessions: usize::MAX,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
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
        .expect("the quic mesh dial completes within 20s");

        assert_eq!(summary.dialed, 1, "dialed the one configured quic target");
        assert_eq!(summary.accepted, 0, "dial-only: nothing connected inbound");
        assert_eq!(
            summary.established, 1,
            "the dialed QUIC face reached Established — wz mesh-dialed quic"
        );
        assert_eq!(summary.peak_concurrent, 1, "held the outbound quic face");
    }

    /// A5c: a gossip-autoconnect [`DialIntent`] makes the loop dial the
    /// discovered peer over real TCP — the dynamic dial source, twin of the
    /// static `dial_targets`. Inject one intent (as the forwarder's emit would,
    /// A5b) carrying the acceptor's `tcp/<addr>` locator; the loop parses it,
    /// dials, and holds the resulting face exactly like a static dial.
    ///
    /// R2141 — swept over BOTH [`DialIntentOrigin`]s, and the assertion is that
    /// the origin's OWN counter rose and the other stayed at zero. With two
    /// producers on one channel that pair is the whole discriminator: a loop that
    /// ignored the tag and bumped one counter for every intent passes the `dialed`
    /// half and fails here, which is the direction that would have silently
    /// credited the gossip atom for a multicast discovery.
    #[cfg(feature = "routing-peer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_autoconnect_dial_intent_dials_the_discovered_peer() {
        for origin in [DialIntentOrigin::Gossip, DialIntentOrigin::MulticastScout] {
            one_autoconnect_dial_intent_is_attributed_to_its_own_plane(origin).await;
        }
    }

    /// One leg of the sweep above — factored out so the `for` reads as the
    /// population and not as a copy.
    #[cfg(feature = "routing-peer")]
    async fn one_autoconnect_dial_intent_is_attributed_to_its_own_plane(origin: DialIntentOrigin) {
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
                origin,
            })
            .expect("buffer the dial-intent");

        let on_event = move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(_) = event {
                let _ = go_tx.send(true);
            }
        };
        let peer = peer_loop(
            FaceSources {
                listeners: vec![peer_listener],
                dial_targets: vec![],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: Some(intent_rx),
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                offer: SessionOffer::universal(),
                // R311y786 — the PRE-y786 cadence (fixed 1 s), so these suites keep
                // measuring what they were written for; the growth has its own.
                retry: RetryPolicy::constant(1000),
                stats: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                // R2758 — unbounded, so these fixtures keep the subject they had.
                max_sessions: usize::MAX,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
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
            "the dial-intent triggered one outbound dial ({origin:?})"
        );
        // R311y423 — and it must be counted as a DISCOVERY dial. Paired with the
        // static-dial test (which asserts these stay 0), this is what makes the
        // counters discriminators rather than second names for `dialed`: only the
        // DialIntent path moves them.
        //
        // R2141 — and it must land on the ORIGIN'S OWN counter, with the other
        // plane's untouched. `expected` is derived from `origin` rather than
        // written per leg, so a third plane cannot be added without this failing.
        let (want_gossip, want_scout) = match origin {
            DialIntentOrigin::Gossip => (1, 0),
            DialIntentOrigin::MulticastScout => (0, 1),
        };
        assert_eq!(
            (summary.gossip_dialed, summary.scout_dialed),
            (want_gossip, want_scout),
            "a {origin:?} dial must be attributed to its own plane and to no other"
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
                listeners: vec![peer_listener],
                dial_targets: vec![tcp_dial(acc_addr)],
                dial_config: Arc::new(DialConfig::default()),
                dial_intents: None,
                mcast_ingress: None,
                mcast_members: None,
                mcast_group_subs: None,
                reconcile: None,
                offer: SessionOffer::universal(),
                // R311y786 — the PRE-y786 cadence (fixed 1 s), so these suites keep
                // measuring what they were written for; the growth has its own.
                retry: RetryPolicy::constant(1000),
                stats: None,
                #[cfg(feature = "transport-multilink")]
                max_links: 1,
                // R2758 — unbounded, so these fixtures keep the subject they had.
                max_sessions: usize::MAX,
                accept: AcceptBounds::default(),
                ceiling: None,
                peer_board: None,
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
