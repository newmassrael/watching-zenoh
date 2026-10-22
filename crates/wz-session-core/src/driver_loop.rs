// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R76 / R83 / R311di-12 — Driver-loop outcome envelope + iteration
//! event observer surface.
//!
//! `DriverLoopOutcome` summarises a single iteration of
//! `poll_and_dispatch_one` (wz-runtime-tokio): typed FSM advance,
//! KeepAlive side-effect, R74 `FramePayload` with the decoded
//! `NetworkMessage` batch, parse error, or link-lost event.
//!
//! `IterationEvent<'a>` wraps either a borrowed `&DriverLoopOutcome`
//! (the poll arm fired) or a `LeaseCheckOutcome` (the lease-deadline
//! arm fired), and is the observer callback's parameter inside
//! `drive_session_until_terminal`.
//!
//! Both types are runtime-agnostic — they only reference primitive
//! types, `Vec`, and earlier-migrated wz-session-core types
//! (`NetworkMessage`, `InboundParseError`, `LostCause`,
//! `LeaseCheckOutcome`) plus the wz-codecs `ExtEntry` projection from
//! `FramePayload.extensions`. Alloc-gated due to the Vec fields.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use wz_codecs::ext_entry::ExtEntryOwned;

use crate::lease::{KeepAliveCheckOutcome, LeaseCheckOutcome};
use crate::link::LostCause;
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
use crate::parse_error::InboundParseError;

/// R76 — outcome of a single iteration of the production driver
/// loop. Five observable outcomes the caller dispatches on: a typed
/// FSM event reached the engine; a KeepAlive parsed and updated the
/// lease stamp but did not advance the FSM (R72b); a Frame envelope
/// parsed and its payload decoded into a `NetworkMessage` batch the
/// application layer should dispatch (R74); the wire bytes failed to
/// parse (the helper raises `FramingError` to the FSM and returns
/// `ParseError` for logging); or the link itself terminated.
///
/// `#[derive(Debug)]` derives transitively over wz-codecs codec
/// structs (e.g. `ExtEntry`) — those carry the category-uniform
/// `Debug + Clone + PartialEq` derive set per
/// `sce-build::forge::rust_derive_policy::RustDeriveCategory::CodecStruct`
/// SSOT (SCE 14ff5e36d).
#[derive(Debug)]
pub enum DriverLoopOutcome {
    /// A typed `SessionFsmUnicastEvent` reached `Engine::process_event`;
    /// any state transition triggered by the event has completed.
    AdvancedFsm,
    /// The inbound frame parsed to a `KeepAlive` record. The lease
    /// stamp was updated inside `handle_inbound` (R72b); the engine
    /// state is unchanged.
    SideEffectOnly,
    /// R74 — the inbound frame parsed to a `Frame` transport envelope
    /// whose tail payload decoded into a batch of `NetworkMessage`
    /// records. The session FSM is unchanged (Frame receipt is not a
    /// session-state trigger); the application layer dispatches
    /// `messages` against its per-MID handler set.
    ///
    /// The heap profile's outcome: it owns the decoded batch. The per-session slot
    /// profile delivers each record where its frame lies (`InPlaceRecord`), and a
    /// frame with none to deliver is `Self::EmptyFrame` where no allocator exists.
    #[cfg(feature = "alloc")]
    FramePayload {
        reliable: bool,
        sn: u64,
        messages: Vec<NetworkMessage>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
        /// R311y221 — the DELIVERED-frame priority band (the decoded ext_qos),
        /// surfaced on the delivery outcome so a consumer of this `FramePayload`
        /// can read the band the frame arrived on. `Priority::DEFAULT` under a
        /// non-QoS session, the lowlatency lean-rx path, and the multicast plane
        /// (whose per-priority conduits stay deferred, R311y215 step 8). The
        /// FUNCTIONAL RX priority — the per-priority SN-conduit gate
        /// (`admit_rx_frame_sn`) and the reassembly chain key — was complete in
        /// y215; y221 threads the SAME decoded band onto the delivered outcome so a
        /// transit re-forward (`forward_push`) can preserve it end-to-end instead
        /// of re-banding to DEFAULT. R311y223/y226 SCOPE (honesty): this is the FRAME
        /// CONDUIT band (SN-conduit gate + `select_link`) and is deliberately
        /// TRANSPORT-ONLY — it is NOT stamped onto the app `Sample`. The
        /// app-observable priority is the SEPARATE per-message Push qos ext, which
        /// zenoh/pico both source independently of the frame conduit (y226 surfaces it
        /// via `Sample::priority()`); the local-subscriber / client-attachment seams
        /// carry this frame band on the WIRE (transit + client egress) but do not
        /// project it onto the delivered `Sample`. Unconditional
        /// (not `#[cfg]`-gated): the variant is ungated and `qos::Priority` is
        /// always compiled, so a gated field would feature-skew every consumer
        /// match (signature-stability).
        priority: crate::qos::Priority,
    },
    /// A `Frame` every record of which is a plain `Put` (see [`crate::plain_push`]),
    /// reported as the records' places in the frame rather than as the owned messages
    /// [`Self::FramePayload`] carries: what a data stream is made of, delivered to the
    /// subscribers without building a message per record.
    ///
    /// Produced only for a session whose host turned the lane on
    /// ([`crate::session_actions::SessionLinkActions::set_plain_put_lane`]), and for a
    /// frame where EVERY record is plain; one record that is anything else (a declare,
    /// a request, a put with a timestamp) makes the whole frame a [`Self::FramePayload`],
    /// so the order of a frame's records is never split between the two forms. Its
    /// `reliable`, `sn` and `priority` are the frame's, as the owned outcome's are, and
    /// the frame passed the same sequence-number gate.
    #[cfg(feature = "alloc")]
    FramePlainPuts {
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
        /// The frame's batch of records; `puts` are ranges of it.
        payload: crate::link::RxBytes,
        puts: Vec<crate::plain_push::PlainPut>,
    },
    /// A `Frame` the session read that carried no record to deliver: the heap
    /// profile reports it as a [`Self::FramePayload`] with an empty batch, and a
    /// build with no allocator, which has no batch to be empty, reports this
    /// instead. Its `reliable`, `sn` and `priority` are the frame's, as the
    /// owned outcome's are.
    #[cfg(not(feature = "alloc"))]
    EmptyFrame {
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    },
    /// `parse_inbound` rejected the wire bytes, OR the Frame envelope
    /// parsed but `parse_frame_payload` could not decode an authored
    /// network-MID envelope inside the payload batch (e.g. a truncated
    /// `Request` body). The helper has already injected `FramingError`
    /// into the engine so the session-fsm `framing.error` transition
    /// fires; the variant is returned so the caller can log the
    /// underlying error.
    ParseError(InboundParseError),
    /// The link reported `LostCause`. The helper has injected
    /// `LinkLost` into the engine so the `link.lost` transition
    /// fires; the cause is returned for logging.
    LinkLost(LostCause),
    /// R311ke — an inbound Frame/Fragment SN fell outside its channel's
    /// half-window ([`crate::sn::RxSn`] gate — zenoh-pico
    /// `_z_sn_precedes`, unicast/rx.c:100-185): a stale, duplicated, or
    /// reordered datagram. Dropped without FSM advance (pico's silent
    /// drop — an INFO-level event, not a session error); the payload
    /// never reaches the application layer. On a rejection the drive
    /// helper also clears the channel's in-progress reassembly chain
    /// (pico's dbuf-clear, rx.c:112-113) so a chain whose continuation
    /// was superseded never completes from mixed generations. TCP's
    /// in-order delivery cannot produce this; UDP unicast can.
    #[cfg(feature = "codec-frame")]
    RxSnRejected {
        /// R311y215 — the QoS priority conduit the rejected frame gated on, so
        /// the drive helper clears the in-progress reassembly chain on the RIGHT
        /// (peer, reliable, priority) key (SN-safety F4). DEFAULT under non-QoS.
        priority: crate::qos::Priority,
        reliable: bool,
        sn: u64,
    },
    /// R311kc — the InitAck's size parameters exceeded our InitSyn
    /// advertisement (the zenoh-pico
    /// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` rejection,
    /// unicast/transport.c:123-140: "Any of the size parameters in the
    /// InitAck must be less or equal than the one in the InitSyn").
    /// The dispatcher has already injected `FramingError` so the FSM's
    /// `framing.error` arm tears the session down with
    /// `CloseReason::Invalid` (wire Close(INVALID) — pico aborts
    /// without a Close frame; wz spends the one frame on a clean
    /// teardown since the initiator-side reply is not an amplification
    /// vector). Surfaced as its own variant so the open loop maps it to
    /// a typed open error instead of folding it into `Terminal`.
    #[cfg(feature = "codec-init-body")]
    InitAckCapsRejected,
    /// R311y817 — the InitAck's `0x7` PATCH extension announced a level
    /// ABOVE our InitSyn's, the same "must be less or equal than the one
    /// in the InitSyn" rule as [`Self::InitAckCapsRejected`] applied to
    /// the one establishment parameter that rides the ext chain instead
    /// of the body. zenoh `bail!`s out of `PatchFsm::recv_init_ack`
    /// (`unicast/establishment/ext/patch.rs:78-84`) and zenoh-pico
    /// returns `_Z_ERR_GENERIC` before building its OpenSyn
    /// (`unicast/transport.c:142-148`), so the dispatcher injects
    /// `EstablishmentExtRejected` and the FSM tears the session down with
    /// `CloseReason::Generic` (wire Close(GENERIC)).
    ///
    /// R311y823 — GENERIC rather than the INVALID its body-side sibling
    /// closes with, and that is upstream's split rather than a wz taste:
    /// zenoh tags each establishment failure with the reason to close on,
    /// and every EXTENSION handler's error carries `close::reason::GENERIC`
    /// (`unicast/establishment/open.rs:321-364`) where the body's size
    /// parameters carry `INVALID` (`open.rs:288,304`). The patch rides the
    /// ext chain, so it takes the ext family's reason even though pico
    /// checks it inside the same rule block as the three sizes.
    ///
    /// Its own variant rather than a fold into `InitAckCapsRejected`
    /// because the two answer different questions about the peer — "it
    /// enlarged a size we have to allocate for" against "it speaks a
    /// protocol revision we do not" — and pico itself separates them,
    /// down to a different error code (`_Z_ERR_GENERIC`, carrying an
    /// upstream `TODO: Use a better error code?`).
    ///
    /// INITIATOR-ONLY, and that asymmetry is upstream's: an InitSyn
    /// announcing a future level is negotiated DOWN by the acceptor's
    /// `min()`, never refused.
    #[cfg(feature = "codec-init-body")]
    InitAckPatchRejected,
    /// R2539 — the peer's `init::ext::RegionName` (`0x8`) was PRESENT and its
    /// value is not a region name: not UTF-8, empty, or over
    /// [`crate::extregion::MAX_REGION_NAME_LEN`] bytes.
    ///
    /// An extension-handler failure, so it closes GENERIC through
    /// `establishment.ext_rejected` like the patch above, not `INVALID`.
    ///
    /// ⚠ SYMMETRIC, unlike `InitAckPatchRejected`, and that is upstream's
    /// shape too: both `RegionNameFsm` receive arms are
    /// `ext.map(ext_to_name).transpose()?`
    /// (`io/zenoh-transport/src/unicast/establishment/ext/region_name.rs`
    /// @ `fn recv_init_syn`,
    /// @ `fn recv_init_ack`), so an acceptor refuses a malformed InitSyn
    /// exactly as an initiator refuses a malformed InitAck. There is no
    /// negotiation to lower it into — a region name is an identity, not a
    /// level.
    #[cfg(feature = "codec-init-body")]
    InitRegionRejected,
    /// An InitSyn announced a protocol version other than
    /// [`wz_codecs::wire_const::PROTOCOL_VERSION`], carried here.
    ///
    /// zenoh refuses it first thing, before reading any other field, and closes
    /// INVALID (`io/zenoh-transport/src/unicast/establishment/accept.rs` @
    /// `if init_syn.version != input.mine_version {`), so the dispatcher
    /// injects `FramingError` and the FSM closes with `CloseReason::Invalid`.
    /// A body laid out by another protocol revision is not one this node can
    /// claim to have read, and answering it with an InitAck would be
    /// negotiating fields it does not know the meaning of.
    ///
    /// ACCEPTOR-ONLY, as upstream's is: neither reference checks the version an
    /// InitAck carries. zenoh-pico checks no InitSyn's either; wz follows zenoh,
    /// the stricter of the two, because the byte decides how every byte after
    /// it is laid out.
    #[cfg(feature = "codec-init-body")]
    InitSynVersionRejected {
        /// The version the InitSyn announced.
        version: u8,
    },
    /// R2858 — the peer's `open::ext::RemoteBound` (`0x7` on the OPEN
    /// carrier) was PRESENT and, after upstream's `as u8` truncation, is
    /// neither bound. Both roles refuse it with GENERIC through
    /// `establishment.ext_rejected`, as upstream's two receive arms do
    /// ([`crate::extbound`]).
    #[cfg(feature = "codec-open-body")]
    OpenRemoteBoundRejected,
    /// Item 751 — THIS node's south partition cannot place the peer, so there is
    /// no bound to announce on the Open and the handshake fails before it is
    /// sent, with GENERIC through `establishment.ext_rejected`: upstream's bound
    /// callback `?`s the same error out of building its Open
    /// (`io/zenoh-transport/src/unicast/establishment/open.rs`
    /// @ `.map_err(|e| (e, Some(close::reason::GENERIC)))?`). The one error the
    /// partition raises here is a router remote matching a subregion of a node
    /// that is not a router.
    #[cfg(feature = "codec-open-body")]
    OpenLocalBoundUnplaceable(crate::region_partition::RegionError),
    /// session-extqos (R311y506) — the peer's `init::ext::QoSLink` body could
    /// not be reconciled with ours: its priority band is not on the required
    /// side of the containment, its reliability contradicts ours, it carried
    /// both QoS forms at once, or its z64 body is not a valid state encoding.
    /// Every one of those is a `zerror!` bail-out inside zenoh's
    /// `QoSFsm::recv_init_syn` / `recv_init_ack`, which `?`s out of the
    /// establishment FSM and aborts the handshake — so the dispatcher injects
    /// `EstablishmentExtRejected` and the FSM tears the session down with
    /// `CloseReason::Generic` (R311y823; zenoh's ext-handler `map_err` carries
    /// `close::reason::GENERIC`, `establishment/open.rs:321`). Its own variant
    /// (the `InitAckCapsRejected` pattern) so the open loop can map it to a
    /// typed open error rather than folding it into `Terminal`.
    #[cfg(all(feature = "session-extqos", feature = "codec-init-body"))]
    QosLinkRejected(crate::extqos::QosLinkError),
    /// session-extshm (R311y507) — an initiator's `init::ext::Shm` challenge
    /// body did not decode. zenoh `recv_init_syn` `bail!`s on exactly this
    /// (`ext/shm.rs`), aborting establishment, so the dispatcher injects
    /// `EstablishmentExtRejected` and the FSM tears the session down with
    /// `CloseReason::Generic` (R311y823; the accept side's ext `map_err` at
    /// `establishment/accept.rs:242`). Its own variant (the
    /// `InitAckCapsRejected` pattern) so the open loop can map it to a typed
    /// error.
    ///
    /// ONLY the acceptor reaches this: the initiator's mirror of the same
    /// failure degrades to "no shared memory" instead, which is upstream's
    /// asymmetry and not a wz simplification.
    #[cfg(all(feature = "session-extshm", feature = "codec-init-body"))]
    ShmChallengeRejected,
    /// R3b — a Z_EXT_AUTH method rejected the peer on a handshake recv stage
    /// (a bad usrpwd credential / unknown user / missing required sub-ext, or a
    /// malformed auth ext). The dispatcher injects `EstablishmentExtRejected`
    /// so the FSM tears the session down with `CloseReason::Generic` (wire
    /// Close(GENERIC), R311y823) — the wz mirror of zenoh's establishment FSM
    /// `?`-propagating the usrpwd verify error into a transport close
    /// (`auth/usrpwd.rs:418/424`), which its caller closes GENERIC on
    /// (`establishment/open.rs:329`). Surfaced as its own variant so the open loop
    /// maps it to a typed open-loop auth-reject error (the
    /// `InitAckCapsRejected` pattern). The carried `AuthError` identifies the
    /// method failure for logging.
    #[cfg(feature = "session-extauth")]
    AuthRejected(crate::auth_dispatch::AuthError),
    /// R311im — the inbound frame parsed to a transport `Fragment`
    /// (`T_MID_FRAGMENT`, MID `0x06`). Reassembly is stateful — the slot
    /// pool ([`crate::reassembly_dispatch::ReassemblyDispatcher`]) lives in
    /// the drive loop, not in the pure `poll_and_dispatch_one` dispatch
    /// helper — so the helper surfaces the decoded fragment here and the
    /// drive loop feeds it to the dispatcher. On chain completion the drive
    /// loop synthesizes a `FramePayload` from the reassembled bytes (the
    /// reassembled message re-enters the same per-MID dispatch path a
    /// `T_MID_FRAME` payload would). The session FSM is unchanged (fragment
    /// receipt is not a session-state trigger, like `Frame`).
    #[cfg(all(feature = "alloc", feature = "reassembly"))]
    Fragment {
        reliable: bool,
        sn: u64,
        more: bool,
        payload: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
        /// R311y215 — the QoS priority projected from this fragment's `ext_qos`,
        /// carried up so the drive loop keys the reassembly chain by (peer,
        /// reliable, priority). DEFAULT for a pre-QoS chain.
        priority: crate::qos::Priority,
        /// R311y578 — the `0x2 First` / `0x3 Drop` chain-boundary markers,
        /// carried up so the drive loop can hand them to the Router, which
        /// owns the chain state the rules act on (clear-and-restart on
        /// First, refuse a marker-less chain start, abort on Drop).
        markers: crate::extfragment::FragmentMarkers,
    },
}

/// R83 — per-iteration event surfaced to the
/// `drive_session_until_terminal` observer callback. Each
/// iteration of the driver loop runs exactly one branch of the
/// inner `tokio::select!` (or the no-baseline `await`) and fires
/// the callback with the matching variant before looping.
///
/// Variant choice mirrors the loop body's two work paths:
///
/// - [`IterationEvent::Poll`] fires when the
///   `poll_and_dispatch_one` arm completes — i.e. the link
///   produced a `LinkEvent`. The borrowed [`DriverLoopOutcome`]
///   reflects whatever the dispatch helper returned: typed FSM
///   advance, `KeepAlive` side-effect, R74 `FramePayload` with
///   the decoded `NetworkMessage` batch, `ParseError`, or
///   `LinkLost`. Application-layer dispatch reads
///   `FramePayload.messages` here.
/// - [`IterationEvent::Lease`] fires when the lease-deadline
///   sleep arm wins the `tokio::select!` race — i.e. the peer
///   has gone silent. The carried [`LeaseCheckOutcome`] is the
///   helper's verdict (`NotMonitored` / `NoBaseline` / `WithinLease` /
///   `Expired`);
///   on `Expired` the FSM has already been advanced to `Closing`
///   inside the helper, so the next loop top will return
///   `Terminated`.
///
/// The borrow `'a` is the loop iteration's stack frame. Observers
/// that need to retain outcome data across iterations must clone
/// the relevant fields (e.g. `FramePayload.messages.clone()`) into
/// owned storage; the reference does not outlive the callback.
///
/// Synchronous contract. The callback runs inside the
/// `tokio::select!` arm, so heavy work blocks the loop. Callers
/// with expensive consumers should buffer (`Vec`, `mpsc::Sender`)
/// inside the closure and drain on a separate task.
///
/// `Copy` because both variants are payload-cheap: `Poll` carries
/// only a `&DriverLoopOutcome` reference (references are `Copy`),
/// and `Lease(LeaseCheckOutcome)` is itself a unit-only enum that
/// derives `Copy`. Making `IterationEvent` `Copy` lets a single
/// observer callback fan the same event out to multiple
/// `dispatch_iteration_event` consumers (subscriber + queryable
/// registries) without having to manually re-construct the variant
/// or split the dispatch into separate iterations.
#[derive(Clone, Copy, Debug)]
pub enum IterationEvent<'a> {
    /// `poll_and_dispatch_one` returned. The borrowed outcome
    /// covers all five `DriverLoopOutcome` variants.
    Poll(&'a DriverLoopOutcome),
    /// `tokio::time::sleep` won the select race against the poll
    /// future; `check_lease_deadline` has already run and its
    /// verdict is carried here. `Copy` because the enum has only
    /// unit variants.
    Lease(LeaseCheckOutcome),
    /// R311kx — the keepalive TX deadline check ran (the AP loop runs it
    /// on every deadline-arm wake alongside the lease check; the MCU loop
    /// when the busy-poll compare crosses the TX deadline) and its
    /// verdict is carried here. On `Emitted` a KeepAlive wire frame went
    /// out through `send_keep_alive` — the TX liveness counterpart of
    /// `Lease` (which watches the PEER's silence). Carries the ungated
    /// [`KeepAliveCheckOutcome`] so this variant — and every consumer's
    /// match — stays feature-independent; only the producer
    /// (`check_keepalive_deadline`) is `transport-keepalive`-gated.
    /// `Copy` (a unit-only enum).
    KeepAlive(KeepAliveCheckOutcome),
    /// The per-iteration reassembly deadline sweep evicted one or more
    /// chains whose continuation never arrived (the carried `usize` is the
    /// count). Emitted by [`crate::drive::sweep_reporting`] from both the AP
    /// and MCU drive loops so the application layer can observe a peer that
    /// began a fragmented message and abandoned it — the silent-eviction
    /// counterpart of the `Poll(FramePayload)` chain-completion event.
    /// `Copy` (a bare `usize`). Consumers that only care about `Poll` ignore
    /// it via their `if let Poll(..)` partial match.
    ReassemblyTimeout(usize),
    /// A reassembly chain was dropped at ingest — an out-of-order /
    /// capacity-overflow abort, or a per-peer-quota / pool-exhaustion
    /// refusal. Emitted by [`crate::drive::report_outcome_reassembling`] when
    /// a fragment ingest returns a terminal non-completion outcome, so the
    /// application can observe a malformed / abusive fragment stream — the
    /// drop counterpart of `Poll(FramePayload)` (completion) and
    /// `ReassemblyTimeout` (deadline). Carries an ungated
    /// [`ReassemblyDropReason`] (a stable observer-API mirror of the
    /// reassembly-internal abort/refuse reasons) so this variant — and every
    /// consumer's match — stays feature-independent.
    ReassemblyDropped(ReassemblyDropReason),
    /// R311y784 — a multicast group peer left, by its own Close or by lease
    /// expiry. Fired ONCE per departing peer, BEFORE its pool slot recycles,
    /// which is the only window in which its zid still exists to report.
    ///
    /// This is the §3.2 `emit_peer_lost` effect point, which the SCXML has
    /// marked since R311jh and which had no realisation until this round: the
    /// dispatcher drove the peer FSM to Expired and freed the slot, and the
    /// application was never told. Both upstreams do tell — zenoh calls
    /// `peer.handler.closed()` from `del_peer`
    /// (`io/zenoh-transport/src/multicast/transport.rs:427-446`), pico calls
    /// `_z_interest_peer_disconnected` / `_z_connectivity_peer_disconnected`
    /// (`src/transport/multicast/lease.c:110-133`, `multicast/rx.c:513-536`).
    ///
    /// Carries an ungated [`MulticastPeerLost`] so this variant — and every
    /// consumer's match — stays feature-independent; only the producers (the
    /// two drive loops) are `session-multicast`-gated. `Copy`.
    MulticastPeerLost(MulticastPeerLost),
    /// R2728 — a multicast group peer was ADMITTED, by the JOIN that allocated
    /// it a slot. Fired ONCE per admission, never on the refresh a live peer's
    /// periodic beacon takes — the `JoinOutcome::Admitted` / `Refreshed` split
    /// the dispatcher already computes and, until this round, discarded.
    ///
    /// The admitting twin of [`MulticastPeerLost`], and it closes the asymmetry
    /// that variant's own doc left standing: wz told an application a peer had
    /// gone and never told it one had come, so the first observable fact about
    /// any group peer was its removal. Both references announce the admission
    /// from the new-entry branch — zenoh builds the peer's FACE there
    /// (`zenoh/src/net/routing/gateway.rs` @ `pub fn new_peer_multicast`), pico
    /// fires its connectivity callback there
    /// (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
    /// `_z_connectivity_peer_connected(`).
    ///
    /// Carries an ungated [`MulticastPeerArrived`] so this variant — and every
    /// consumer's match — stays feature-independent; only the producer (the
    /// shared RX dispatch SSOT) is `session-multicast`-gated. `Copy`.
    MulticastPeerArrived(MulticastPeerArrived),
    /// Item 751 — the group member whose data the NEXT [`IterationEvent::Poll`]
    /// carries. Fired by the multicast RX dispatch immediately before each
    /// `Poll` it fans, for a whole Frame and for a reassembled chain alike.
    ///
    /// A multicast Frame carries no zid (the dispatcher keys members by datagram
    /// source), so the `Poll` alone is anonymous data. Upstream's routing never
    /// sees anonymous data: each member has a face stamped with its zid
    /// (`zenoh/src/net/routing/gateway.rs` @ `pub fn new_peer_multicast`), and
    /// the inter-region filter is handed it as the forwarder
    /// (`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `fwd_zid: Some(&src_face.zid),`).
    /// The pairing is by order, not by a field of `Poll`, because `Poll` is the
    /// one event the unicast loops and every application observer already
    /// consume and a field there would change all of them. An observer that does
    /// not care ignores this event, as it ignores the other multicast ones.
    /// Carries the same ungated [`MulticastPeerId`] the departure does. `Copy`.
    MulticastSource(MulticastPeerId),
    /// The application layer's own deadline has come due: the moment it stated through
    /// [`SessionCore::set_app_wake_deadline_ms`](crate::session_actions::SessionCore::set_app_wake_deadline_ms)
    /// is now or past.
    ///
    /// A session's steady state is event-free: the loop raises an event for a datagram, for the
    /// lease or keep-alive coming due, and for little else, so a layer whose work is not one of
    /// those (a pending query's deadline, a query left for it by the application) would run only
    /// when one of them happened to fall near. This is the event that says "your time". It
    /// carries nothing and the layer has no obligation: the deadline is spent when the event is
    /// raised, so the layer that wants another states it again, and one that does not is not
    /// woken again for it. An observer that has no deadlines ignores it. Ungated, as the others.
    AppWake,
    /// ARCHITECTURE section 9.2 ("Codec::decode parses in place from slot",
    /// "Event emitted with `&slot` borrow") — ONE record of an inbound `Frame`,
    /// decoded where the frame lies and handed over borrowed: the receive path
    /// of the fixed-memory MCU profile (`drive::dispatch_datagram`, reached
    /// under `wz-runtime-coop`'s `rx-in-place`) emits it for every Push, Request
    /// and Response record, in place of a `Poll(FramePayload)` carrying the
    /// owned message, so a subscriber, a queryable or a pending get is handed
    /// the frame's own bytes and nothing is built on the heap for the record.
    ///
    /// The record is valid for the call only; its bytes go when the link takes
    /// its buffer back. A consumer that keeps something copies it, which is what
    /// [`Sample::from_view`](crate::sample::Sample::from_view) does for a
    /// subscriber. Every other record of the same frame still arrives as a
    /// `Poll(FramePayload)` of one owned message, in wire order with these.
    ///
    /// A consumer that reads Push, Request or Response data out of
    /// `Poll(FramePayload)` must read this variant too, or it misses every such
    /// record on that path: the subscriber registry, the queryable registry, the
    /// reply registry and the switchboard do, through the observer fan. Ungated
    /// like the other variants, so every consumer's match stays
    /// feature-independent; only the producer is gated. `Copy`.
    InPlace(InPlaceRecord<'a>),
    /// ARCHITECTURE section 9.3 — one inbound `Fragment` read where its unit
    /// lies, its payload staged into its reassembly slot straight from there:
    /// what the reassembling in-place receive path
    /// (`drive::dispatch_datagram_reassembling`, reached under
    /// `wz-runtime-coop`'s `rx-in-place` with `reassembly`) reports in place of
    /// `Poll(DriverLoopOutcome::Fragment)`, whose payload is an owned copy.
    ///
    /// Carries a borrowed descriptor, not the payload's bytes: the unit and
    /// where in it the payload starts, valid for the call only. A consumer that
    /// counts or inspects fragments reads this variant as it reads
    /// `Poll(Fragment)` on the copying path. A chain the fragment completes
    /// arrives after it, as `InPlace` and `Poll(FramePayload)` events read in
    /// the slot. Ungated, like the other variants; only the producer is gated.
    /// `Copy`.
    InPlaceFragment(InPlaceFragment<'a>),
}

/// One inbound `Fragment` read where its unit lies: what
/// [`IterationEvent::InPlaceFragment`] carries. The fields of
/// `DriverLoopOutcome::Fragment` but the extension chain (its two facts a
/// participant acts on, the priority and the chain-boundary markers, are
/// here), with the payload as a range of the unit instead of a copy of it.
#[derive(Clone, Copy, Debug)]
pub struct InPlaceFragment<'a> {
    unit: &'a [u8],
    payload_at: usize,
    reliable: bool,
    sn: u64,
    more: bool,
    has_ext: bool,
    priority: crate::qos::Priority,
    /// Only a build that reassembles reads a fragment at all.
    #[cfg(feature = "reassembly")]
    markers: crate::extfragment::FragmentMarkers,
}

impl<'a> InPlaceFragment<'a> {
    /// The fragment at the front of `unit`, whose payload starts at
    /// `payload_at`. Built by the reassembling in-place receive path alone.
    #[cfg(all(feature = "reassembly", feature = "session-unicast"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        unit: &'a [u8],
        payload_at: usize,
        reliable: bool,
        sn: u64,
        more: bool,
        has_ext: bool,
        priority: crate::qos::Priority,
        markers: crate::extfragment::FragmentMarkers,
    ) -> Self {
        debug_assert!(
            payload_at <= unit.len(),
            "the payload starts inside the unit"
        );
        Self {
            unit,
            payload_at,
            reliable,
            sn,
            more,
            has_ext,
            priority,
            markers,
        }
    }

    /// The whole unit the fragment was read from.
    pub fn unit(&self) -> &'a [u8] {
        self.unit
    }

    /// Where in [`Self::unit`] the payload lies: from the end of the head to
    /// the end of the unit (a `Fragment` consumes the rest of its unit).
    pub fn payload_range(&self) -> core::ops::Range<usize> {
        self.payload_at..self.unit.len()
    }

    /// The payload: the bytes staged into the chain's slot.
    pub fn payload(&self) -> &'a [u8] {
        &self.unit[self.payload_at..]
    }

    /// Whether the fragment rode the reliable channel (the R bit).
    pub fn reliable(&self) -> bool {
        self.reliable
    }

    /// The fragment's sequence number.
    pub fn sn(&self) -> u64 {
        self.sn
    }

    /// Whether more fragments follow (the M bit).
    pub fn more(&self) -> bool {
        self.more
    }

    /// Whether the fragment carried an extension chain of its own.
    pub fn has_ext(&self) -> bool {
        self.has_ext
    }

    /// The priority its QoS extension carries, `Priority::DEFAULT` without one.
    pub fn priority(&self) -> crate::qos::Priority {
        self.priority
    }

    /// The chain-boundary markers it carries.
    #[cfg(feature = "reassembly")]
    pub fn markers(&self) -> crate::extfragment::FragmentMarkers {
        self.markers
    }
}

/// One record of an inbound `Frame` decoded where the frame lies, with the
/// frame's own reliability, SN and priority: what [`IterationEvent::InPlace`]
/// carries.
///
/// Three kinds travel this way on every build: a Push ([`Self::push`]), a
/// Request ([`Self::request`]) and a Response ([`Self::response`]), each read by
/// the registry that consumes it (the subscribers, the queryables, the pending
/// gets); a record of any other kind is decoded into its owned message and
/// reported as `Poll(FramePayload)`.
///
/// On the per-session slot profile (`session-slot`) the control kinds travel this
/// way too: a Declare (`declare`), an Interest (`interest`) and a ResponseFinal
/// (`response_final`). Their owned messages are what that profile cannot build:
/// the boxed `DeclareOwned` and the lists it carries are heap, and the same
/// mirror at the inline profile would put the spread of the codecs' widest bodies
/// into the one record buffer of every pump and refuse a keyexpr past the codec's
/// own text bound, which the decode where the frame lies reads whole. Exactly one
/// accessor answers `Some`.
#[derive(Clone, Copy, Debug)]
pub struct InPlaceRecord<'a> {
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        all(feature = "session-slot", feature = "codec-frame")
    ))]
    record: LentRecord<'a>,
    _frame: core::marker::PhantomData<&'a [u8]>,
}

/// The record an [`InPlaceRecord`] lends, by kind.
///
/// Only the unicast receive path builds one (and the tests that stand in for
/// it, each under its own registry's features); a build without it still has
/// the type, so that the record's accessors are the same API in every build,
/// and may construct no variant.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    all(feature = "session-slot", feature = "codec-frame")
))]
#[cfg_attr(
    not(any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )),
    allow(dead_code)
)]
#[derive(Clone, Copy, Debug)]
enum LentRecord<'a> {
    #[cfg(feature = "codec-push")]
    Push(&'a wz_codecs::push::Push<'a>),
    #[cfg(feature = "codec-request")]
    Request(&'a wz_codecs::request::RequestView<'a>),
    #[cfg(feature = "codec-response")]
    Response(&'a wz_codecs::response::Response<'a>),
    #[cfg(all(feature = "session-slot", feature = "codec-declare"))]
    Declare(&'a wz_codecs::declare::Declare<'a>),
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-frame",
        feature = "codec-response-final"
    ))]
    ResponseFinal(&'a wz_codecs::response_final::ResponseFinal<'a>),
    #[cfg(all(feature = "session-slot", feature = "codec-frame"))]
    Interest(&'a wz_codecs::interest::Interest<'a>),
}

impl<'a> InPlaceRecord<'a> {
    /// The record of a frame at `sn` on the `reliable` channel and `priority`
    /// band. Built by the unicast receive path alone (and the tests that stand
    /// in for it).
    #[cfg(all(
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        ),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            all(feature = "session-slot", feature = "codec-frame")
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    fn of_frame(
        record: LentRecord<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self {
            reliable,
            sn,
            priority,
            record,
            _frame: core::marker::PhantomData,
        }
    }

    /// A Push record of a frame (see [`Self::reliable`] and its siblings).
    #[cfg(all(
        feature = "codec-push",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn push_of_frame(
        push: &'a wz_codecs::push::Push<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(LentRecord::Push(push), reliable, sn, priority)
    }

    /// A Request record of a frame.
    #[cfg(all(
        feature = "codec-request",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn request_of_frame(
        request: &'a wz_codecs::request::RequestView<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(LentRecord::Request(request), reliable, sn, priority)
    }

    /// A Response record of a frame.
    #[cfg(all(
        feature = "codec-response",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn response_of_frame(
        response: &'a wz_codecs::response::Response<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(LentRecord::Response(response), reliable, sn, priority)
    }

    /// A Declare record of a frame, on the slot profile.
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-declare",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn declare_of_frame(
        declare: &'a wz_codecs::declare::Declare<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(LentRecord::Declare(declare), reliable, sn, priority)
    }

    /// A ResponseFinal record of a frame, on the slot profile.
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-frame",
        feature = "codec-response-final",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn response_final_of_frame(
        response_final: &'a wz_codecs::response_final::ResponseFinal<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(
            LentRecord::ResponseFinal(response_final),
            reliable,
            sn,
            priority,
        )
    }

    /// An Interest record of a frame, on the slot profile.
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-frame",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ))]
    #[cfg_attr(
        not(any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )),
        allow(dead_code)
    )]
    pub(crate) fn interest_of_frame(
        interest: &'a wz_codecs::interest::Interest<'a>,
        reliable: bool,
        sn: u64,
        priority: crate::qos::Priority,
    ) -> Self {
        Self::of_frame(LentRecord::Interest(interest), reliable, sn, priority)
    }

    /// Whether the carrying frame rode the reliable channel.
    pub fn reliable(&self) -> bool {
        self.reliable
    }

    /// The carrying frame's sequence number.
    pub fn sn(&self) -> u64 {
        self.sn
    }

    /// The carrying frame's priority band.
    pub fn priority(&self) -> crate::qos::Priority {
        self.priority
    }

    /// The Push, as it is decoded: its keyexpr, extensions and payload are
    /// ranges of the frame. `None` when the record is of another kind.
    #[cfg(feature = "codec-push")]
    pub fn push(&self) -> Option<&'a wz_codecs::push::Push<'a>> {
        match self.record {
            LentRecord::Push(push) => Some(push),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The Request, as its view: its keyexpr and body ranges of the frame, and its extension chains as
    /// the bytes they occupy, walked where they lie (a chain is not held, so a Request is a few words
    /// however many extensions it may carry). `None` when the record is of another kind.
    #[cfg(feature = "codec-request")]
    pub fn request(&self) -> Option<&'a wz_codecs::request::RequestView<'a>> {
        match self.record {
            LentRecord::Request(request) => Some(request),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The Response, as it is decoded, its keyexpr, extensions and body ranges
    /// of the frame. `None` when the record is of another kind.
    #[cfg(feature = "codec-response")]
    pub fn response(&self) -> Option<&'a wz_codecs::response::Response<'a>> {
        match self.record {
            LentRecord::Response(response) => Some(response),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The Declare, as it is decoded, its keyexpr, extensions and inner body
    /// ranges of the frame (slot profile). `None` when the record is of another
    /// kind.
    #[cfg(all(feature = "session-slot", feature = "codec-declare"))]
    pub fn declare(&self) -> Option<&'a wz_codecs::declare::Declare<'a>> {
        match self.record {
            LentRecord::Declare(declare) => Some(declare),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The ResponseFinal, as it is decoded (slot profile). `None` when the
    /// record is of another kind.
    #[cfg(all(
        feature = "session-slot",
        feature = "codec-frame",
        feature = "codec-response-final"
    ))]
    pub fn response_final(&self) -> Option<&'a wz_codecs::response_final::ResponseFinal<'a>> {
        match self.record {
            LentRecord::ResponseFinal(response_final) => Some(response_final),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The Interest, as it is decoded, its keyexpr and extensions ranges of the
    /// frame (slot profile). `None` when the record is of another kind.
    #[cfg(all(feature = "session-slot", feature = "codec-frame"))]
    pub fn interest(&self) -> Option<&'a wz_codecs::interest::Interest<'a>> {
        match self.record {
            LentRecord::Interest(interest) => Some(interest),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

impl IterationEvent<'_> {
    /// Whether the event hands the application a `Push`: a record lent where its
    /// frame lies ([`IterationEvent::InPlace`]), or, on the heap profile, an owned
    /// batch with a Push in it ([`IterationEvent::Poll`] of a `FramePayload`).
    ///
    /// The one question a consumer that only wants to know a Push arrived asks, whichever
    /// profile delivered it: the two forms are different events, and a reader that
    /// matched only one of them would miss every Push the other delivers.
    #[cfg(feature = "codec-push")]
    pub fn delivers_push(&self) -> bool {
        match self {
            IterationEvent::InPlace(record) => record.push().is_some(),
            #[cfg(feature = "alloc")]
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => messages
                .iter()
                .any(|m| matches!(m, crate::network_message::NetworkMessage::Push(_))),
            _ => false,
        }
    }
}

/// Hand one record a walk LENT ([`crate::network_message::try_for_each_record`]) to
/// `on_event` as the in-place event that carries it
/// ([`IterationEvent::InPlace`]), with the carrying frame's own reliability, SN and
/// priority. The one place a lent record becomes an event, shared by the unicast
/// receive path and the multicast one, so a Push is delivered the same whichever
/// transport it arrived on.
///
/// A record the walk read and judged and no consumer reads further
/// ([`WalkedRecord::Skipped`](crate::network_message::WalkedRecord::Skipped)) raises
/// no event. An OWNED record is the caller's (it builds the outcome that reports it),
/// so it is not handled here.
///
/// Its callers are the unicast walk (`drive`, which is `session-unicast`) and the
/// multicast walk of a build with no allocator; a test build that has neither carries
/// no caller, so `test` is not a reason to compile it.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    ),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "session-slot"
    )
))]
pub(crate) fn report_lent_record(
    one: crate::network_message::WalkedRecord<'_>,
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    on_event: &mut dyn FnMut(IterationEvent<'_>),
) {
    use crate::network_message::WalkedRecord;
    match one {
        // Owned: the caller's, see above.
        #[cfg(feature = "alloc")]
        WalkedRecord::Owned(_) => {}
        #[cfg(feature = "codec-push")]
        WalkedRecord::Push(push) => on_event(IterationEvent::InPlace(
            InPlaceRecord::push_of_frame(push, reliable, sn, priority),
        )),
        #[cfg(feature = "codec-request")]
        WalkedRecord::Request(request) => on_event(IterationEvent::InPlace(
            InPlaceRecord::request_of_frame(request, reliable, sn, priority),
        )),
        #[cfg(feature = "codec-response")]
        WalkedRecord::Response(response) => on_event(IterationEvent::InPlace(
            InPlaceRecord::response_of_frame(response, reliable, sn, priority),
        )),
        // The slot profile's control records, lent as the data records are.
        #[cfg(all(feature = "session-slot", feature = "codec-declare"))]
        WalkedRecord::Declare(declare) => on_event(IterationEvent::InPlace(
            InPlaceRecord::declare_of_frame(declare, reliable, sn, priority),
        )),
        #[cfg(all(feature = "session-slot", feature = "codec-response-final"))]
        WalkedRecord::ResponseFinal(response_final) => on_event(IterationEvent::InPlace(
            InPlaceRecord::response_final_of_frame(response_final, reliable, sn, priority),
        )),
        #[cfg(feature = "session-slot")]
        WalkedRecord::Interest(interest) => on_event(IterationEvent::InPlace(
            InPlaceRecord::interest_of_frame(interest, reliable, sn, priority),
        )),
        // Read and judged, and nothing reads it further: no event, and the walk
        // counts it as a record dispatched.
        #[cfg(feature = "session-slot")]
        WalkedRecord::Skipped => {}
    }
}

/// Walk a data payload's records where they lie, handing each to `on_event` as
/// [`report_lent_record`] does, before the next is decoded: what a `Frame`'s payload
/// and a reassembled chain are read through on a profile that lends every record
/// ([`RecordForm::LentControl`](crate::network_message::RecordForm::LentControl)). A
/// payload with no record is reported as one empty frame
/// ([`DriverLoopOutcome::EmptyFrame`]), as the unicast walk reports it.
///
/// An error from a record ends the walk after the records before it were handed over.
/// The walk takes no session and holds one record at a time, so it allocates nothing
/// whatever the peer put in the payload.
///
/// The multicast receive path of a build with no allocator; the heap profile decodes a
/// batch owned (`multicast_rx`).
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    feature = "session-multicast",
    not(feature = "alloc")
))]
pub(crate) fn walk_lent_payload(
    payload: &[u8],
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    on_event: &mut dyn FnMut(IterationEvent<'_>),
) -> Result<(), crate::parse_error::InboundParseError> {
    use crate::network_message::{new_record_buf, try_for_each_record, RecordForm};
    let mut record = new_record_buf();
    let mut dispatched = false;
    try_for_each_record(payload, &mut record, RecordForm::LentControl, |one| {
        report_lent_record(one, reliable, sn, priority, &mut *on_event);
        dispatched = true;
        Ok(())
    })?;
    if !dispatched {
        #[cfg(feature = "alloc")]
        on_event(IterationEvent::Poll(&DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages: alloc::vec::Vec::new(),
            has_ext: false,
            extensions: alloc::vec::Vec::new(),
            priority,
        }));
        #[cfg(not(feature = "alloc"))]
        on_event(IterationEvent::Poll(&DriverLoopOutcome::EmptyFrame {
            reliable,
            sn,
            priority,
        }));
    }
    Ok(())
}

/// Build the [`DriverLoopOutcome`] a completed reassembly chain re-enters
/// the loop with: the reassembled bytes go back through
/// [`parse_frame_payload_lending`](crate::network_message::parse_frame_payload_lending),
/// so the application's per-MID dispatch sees the reassembled message exactly
/// as it sees a `T_MID_FRAME` payload, and what it is handed holds a copy of
/// its own and not a slice of the reassembler's slot. The reassembled bytes are the inner
/// NetworkMessage batch; transport ext chains were per-fragment, so the
/// reassembled outcome carries none. Shared by the unicast
/// [`crate::drive::report_outcome_reassembling`] and the multicast
/// [`crate::multicast_dispatch::ingest_multicast_fragment`] completion
/// closures (one re-entry SSOT). `reassembly` implies `codec-frame`, so
/// the payload parser is in scope.
///
/// R311y221 — `priority` is the reassembled chain's band (keyed on
/// `(peer, reliable, priority)` at ingest): the unicast caller passes the
/// chain's real decoded priority, the multicast caller passes DEFAULT (its
/// per-priority conduits stay deferred, R311y215 step 8), so the synthesized
/// whole-frame outcome carries the same band the un-fragmented path would.
#[cfg(all(feature = "alloc", feature = "reassembly"))]
pub fn reassembled_frame_outcome(
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    msg: &[u8],
) -> DriverLoopOutcome {
    reassembled_chain_outcome(
        reliable,
        sn,
        priority,
        crate::reassembly_dispatch::ChainBytes::Borrowed(msg),
    )
}

/// [`reassembled_frame_outcome`] over the chain as the Router delivers it
/// ([`ChainBytes`](crate::reassembly_dispatch::ChainBytes)), which is what the
/// receive loops call.
///
/// ARCHITECTURE section 9.3 -- a LENT chain is decoded where it lies: every
/// message is a range of the reassembly staging itself (the pooled arena's
/// slot, or the heap arena's buffer moved, not copied), so the payload the
/// application is handed IS the bytes the fragments were staged into, and the
/// staging goes home when the last of those ranges drops. A BORROWED chain is
/// the arena that cannot lend: its bytes are valid for this call only, and they
/// are copied once into a buffer the messages share
/// ([`parse_frame_payload_lending`](crate::network_message::parse_frame_payload_lending)),
/// as before.
#[cfg(all(feature = "alloc", feature = "reassembly"))]
pub fn reassembled_chain_outcome(
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    chain: crate::reassembly_dispatch::ChainBytes<'_>,
) -> DriverLoopOutcome {
    use crate::reassembly_dispatch::ChainBytes;
    // The participant refuses a batch whose chains hold an extension the message
    // does not define, with the M bit set, as the unfragmented path does. The
    // refusal is reported and the batch dropped, as upstream drops a reassembled
    // message it cannot read without closing the link
    // (`io/zenoh-transport/src/common/defragmentation.rs` @
    // `let res: Option<NetworkMessage> = rcodec.read(&mut reader).ok();`).
    let decoded = match &chain {
        ChainBytes::Borrowed(msg) => crate::network_message::parse_frame_payload_lending(msg),
        #[cfg(feature = "rx-shared-bytes")]
        ChainBytes::Lent(bytes) => crate::network_message::parse_frame_payload_in(bytes),
    };
    let parsed = decoded
        .map_err(InboundParseError::Codec)
        .and_then(crate::network_message::refuse_unknown_mandatory_ext);
    match parsed {
        Ok(messages) => DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            has_ext: false,
            extensions: Vec::new(),
            priority,
        },
        Err(parse_err) => DriverLoopOutcome::ParseError(parse_err),
    }
}

/// Why a reassembly chain was dropped at ingest, surfaced on
/// [`IterationEvent::ReassemblyDropped`]. A stable, feature-independent
/// mirror of the reassembly-internal `AbortReason` / `RefuseReason` (which
/// live behind the `reassembly` feature); kept separate so the public
/// observer API does not leak the gated dispatcher types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyDropReason {
    /// A continuation arrived whose SN was not the chain's expected next SN —
    /// strict in-order policy aborted the chain (§2.5, `fragment.ooo`).
    OutOfOrder,
    /// Staging the fragment would exceed the slot's capacity — the §7.1
    /// reassembly-capacity hard error.
    CapacityOverflow,
    /// The peer already held `per_peer_quota` open chains (§5.M quota-first).
    PeerQuota,
    /// Every slot was occupied by another peer's in-progress chain.
    PoolExhausted,
    /// R311y578 — the SENDER announced the chain was abandoned (the
    /// `0x3 Drop` marker). Kept apart from [`Self::OutOfOrder`]: this is a
    /// healthy sender saying so on the wire, not a receiver-side inference
    /// from SNs, and an observer that conflated the two would read a
    /// congested-but-correct link as a lossy one.
    SenderDropped,
    /// R311y578 — a `0x2 First` marker restarted a chain that was already
    /// open on the same key; the staged prefix was discarded.
    Superseded,
    /// R311y578 — the fragment would have started a chain but carried no
    /// `0x2 First` marker on a session that negotiated them. The
    /// observer-vs-participant case: a reader attached to a live flow sees
    /// this for every chain already in progress when it attached.
    MissingStartMarker,
    /// A continuation's SN was not the chain's last plus one and the router did
    /// not know the SN ring, so it could not say whether the step was a wrap or
    /// a loss. Kept apart from [`Self::OutOfOrder`], the judgement on a known
    /// ring. A session that negotiated its ring never reports this one: it is
    /// the mirror of the router's own word, which only a reader that missed the
    /// handshake reaches.
    Unresolvable,
}

/// R311y784 / R311y787 — the multicast departure observer surface,
/// re-exported from [`crate::multicast_peer_lost`] where it is DEFINED.
///
/// It moved out of this module in R311y787 and the re-export is not
/// cosmetic: these types are allocation-free and their producer (the
/// multicast Router) compiles on the no-alloc MCU profile, where this
/// `alloc`-gated module does not exist at all — naming them through
/// `crate::driver_loop` was an E0432 on run-ci Layer G.12. The path stays
/// because [`IterationEvent::MulticastPeerLost`] carries the value and the
/// alloc-side consumers (wz-runtime-tokio, wz-session-lwip) name it here.
pub use crate::multicast_peer_lost::{
    MulticastPeerId, MulticastPeerLost, MulticastPeerLostReason, OBSERVER_ZID_MAX,
};

/// R2728 — the multicast ARRIVAL observer surface, re-exported from
/// [`crate::multicast_peer_arrived`] where it is DEFINED, on the same terms and
/// for the same reason as the departure re-export above: the type is
/// allocation-free and its producer compiles on the no-alloc MCU profile, while
/// this module is `alloc`-gated. The path stays because
/// [`IterationEvent::MulticastPeerArrived`] carries the value and the alloc-side
/// consumers name it here.
pub use crate::multicast_peer_arrived::MulticastPeerArrived;

#[cfg(feature = "reassembly")]
impl ReassemblyDropReason {
    /// Map a terminal non-completion ingest to this feature-independent
    /// observer mirror; `None` for the progressing outcomes (Begun /
    /// Continued / Reassembled), which the caller reports through their
    /// own events. Shared by the unicast and multicast ingest reporters
    /// (one mapping SSOT). Lives here, not on `IngestOutcome`: the
    /// reassembly dispatcher also compiles on the no-alloc MCU profile,
    /// where this alloc-gated observer module does not exist.
    pub fn from_ingest(
        outcome: crate::reassembly_dispatch::IngestOutcome,
    ) -> Option<ReassemblyDropReason> {
        use crate::reassembly_dispatch::{AbortReason, IngestOutcome, RefuseReason};
        match outcome {
            IngestOutcome::Aborted(AbortReason::OutOfOrder) => {
                Some(ReassemblyDropReason::OutOfOrder)
            }
            IngestOutcome::Aborted(AbortReason::CapacityOverflow) => {
                Some(ReassemblyDropReason::CapacityOverflow)
            }
            IngestOutcome::Refused(RefuseReason::PeerQuota) => {
                Some(ReassemblyDropReason::PeerQuota)
            }
            IngestOutcome::Refused(RefuseReason::PoolExhausted) => {
                Some(ReassemblyDropReason::PoolExhausted)
            }
            IngestOutcome::Aborted(AbortReason::SenderDropped) => {
                Some(ReassemblyDropReason::SenderDropped)
            }
            IngestOutcome::Aborted(AbortReason::Superseded) => {
                Some(ReassemblyDropReason::Superseded)
            }
            IngestOutcome::Refused(RefuseReason::MissingStartMarker) => {
                Some(ReassemblyDropReason::MissingStartMarker)
            }
            IngestOutcome::Aborted(AbortReason::Unresolvable) => {
                Some(ReassemblyDropReason::Unresolvable)
            }
            IngestOutcome::Begun | IngestOutcome::Continued | IngestOutcome::Reassembled => None,
        }
    }
}

/// R76b — terminal result of a production session drive loop. Runtime-
/// agnostic: the AP `drive_session_until_terminal` (tokio `select!` loop)
/// and the lwIP MCU `run_session` (sync polling loop) both return this.
/// Stage 4b hoisted it here from `wz-runtime-tokio::session_glue` so the
/// two loops share one outcome SSOT; wz-runtime-tokio re-exports it.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutcome {
    /// The engine reached a terminal state
    /// (`Engine::is_in_final_state() == true`) via FSM transition.
    /// Production callers exit the session lifecycle here; the
    /// outbound driver close has already been dispatched by the
    /// `Closed.onentry` action chain.
    Terminated,
    /// The caller-supplied `max_iters` cap was reached without the
    /// engine reaching a terminal state. Test callers use this to
    /// bound runaway loops; production callers pass `None` for
    /// unlimited iteration.
    IterationLimit,
}

// A batch put back together from fragments is judged like one that arrived whole:
// a message in it that holds an extension it does not define, with the M bit set,
// refuses the batch (`commons/zenoh-codec/src/common/extension.rs` @
// `if u.is_mandatory() {`).
#[cfg(all(test, feature = "reassembly", feature = "codec-push"))]
mod reassembled_batch_tests {
    use super::*;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs_test_support::TestWire as _;

    fn push_with_put_ext(header: u8) -> Vec<u8> {
        let mut push = crate::push_build::build_push_literal("k", b"v").unwrap();
        match &mut push.body {
            crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
                put.extensions = Some(alloc::vec![ExtEntryOwned {
                    header,
                    body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
                }]);
                put.header |= 0x80;
            }
            other => panic!("a literal push carries a Put, got {other:?}"),
        }
        push.wire()
    }

    #[test]
    fn a_reassembled_batch_with_a_mandatory_look_alike_is_refused() {
        let priority = crate::qos::Priority::DEFAULT;
        assert!(matches!(
            reassembled_frame_outcome(true, 1, priority, &push_with_put_ext(0x03)),
            DriverLoopOutcome::FramePayload { .. }
        ));
        assert!(matches!(
            reassembled_frame_outcome(true, 1, priority, &push_with_put_ext(0x13)),
            DriverLoopOutcome::ParseError(InboundParseError::UnknownMandatoryExt { eid: 0x13 })
        ));
    }
}
