// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Stage 3 — runtime-agnostic drive-loop dispatch core.
//!
//! `dispatch_link_event` is the synchronous body of
//! `wz-runtime-tokio::poll_and_dispatch_one` lifted out of the AP shell: it
//! takes an already-polled `LinkEvent` (the one `.await` — `driver.poll_event()`
//! — stays in the tokio async wrapper) and drives the engine-free session FSM,
//! returning the typed `DriverLoopOutcome`. Generic over `R: SessionRuntime` /
//! `T: TimeSource` so the lwIP MCU sync loop (Stage 4) dispatches through the
//! same SSOT the tokio loop does.
//!
//! `report_outcome_reassembling` drives the const-generic reassembly pool on a
//! `Fragment` outcome and re-enters `parse_frame_payload` on chain completion;
//! generic over the pool dims + runtime so the AP (32/65536) and MCU (4/4096)
//! profiles share one ingest path. The peer ZID (the §2.3 chain key) is read
//! from `actions.inbound_peer_zid` through `R::with_mutex_mut` (the AP
//! `std::sync::Mutex` and the MCU `critical_section` mutex behind one seam).

use crate::constant_session_id::built_under_constant_id;
use sce_rust_runtime::Engine;

use wz_runtime_core::TimeSource;

use crate::driver_loop::DriverLoopOutcome;
use crate::inbound::inbound_to_fsm_event;
use crate::lease::LeaseCheckOutcome;
#[cfg(feature = "alloc")]
use crate::link::LinkEvent;
use crate::link::SessionRuntime;
// `InboundParseError` is named only as `::Codec(..)` in the codec-frame `Frame`
// arm (and the reassembly re-parse, which implies codec-frame); the `Err(err)`
// arm passes the value without naming the type.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
use crate::parse_error::InboundParseError;
use crate::session_actions::{SessionActionsBinding, SessionLinkActions, SESSION_HOST_REALIZATION};
use crate::session_fsm_unicast::{SessionFsmUnicastActions, SessionFsmUnicastPolicy};
// `InboundFrame` is named by the ungated `Unknown` match arm; the codec-gated
// arms (`Frame` / `KeepAlive` / `Fragment` / `Init` / `Open` / `Close`) reuse it.
use crate::inbound::InboundFrame;
// parse_frame_payload_in backs the codec-frame `Frame` arm only (the heap profile's:
// the slot profile reads a frame where it lies).
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
use crate::network_message::parse_frame_payload_in;

/// R2965 (open-debt item 847) — [`parse_frame_payload_in`], never inlined, for
/// [`dispatch_unit`]'s callers of it and no one else's. It takes the batch as a
/// [`RxBytes`](crate::link::RxBytes) so the messages it decodes are ranges of
/// it, not copies out of it.
///
/// Decoding a batch builds each message into a local of that message's own size
/// (an `Interest` is 336 bytes, an `Oam` 312, an extension chain 264), and a
/// target whose codegen does not overlay the locals of disjoint arms (ARMv6-M)
/// gives the enclosing function the SUM of them. Inlined into `dispatch_unit`
/// that sum was 1440 bytes of the frame that stays live under the FSM's whole
/// action chain — the deepest call the MCU acceptor makes — although a batch is
/// decoded only on the Frame path, never while an InitAck is being built.
/// Behind this call it is paid only while a batch is decoded.
///
/// A wrapper here rather than `#[inline(never)]` on the decoder itself, because
/// the decoder has other callers and that change was measured on the multicast
/// image: +592 and +668 bytes of text, past the footprint ledger's band, for a
/// stack saving that image does not need. This keeps the out-of-line copy where
/// the deep frame is.
///
/// It is also the participant seam of the mandatory-extension rule for the NETWORK
/// messages and the zenoh bodies they carry. A batch with a message whose chain
/// holds an extension the message does not define, with the M bit set, is refused
/// whole, as a batch that does not decode is; upstream's reader refuses that
/// message (`commons/zenoh-codec/src/common/extension.rs` @
/// `if u.is_mandatory() {`). The decode reads it, so a capture still sees it, and
/// the refusal is made here, in the one function both unicast paths of a whole
/// batch go through; a batch put back together from fragments and a multicast
/// batch are judged by the same
/// [`refuse_unknown_mandatory_ext`](crate::network_message::refuse_unknown_mandatory_ext)
/// at their own seams.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
#[inline(never)]
fn parse_frame_payload_out_of_line(
    batch: &crate::link::RxBytes,
) -> Result<alloc::vec::Vec<crate::network_message::NetworkMessage>, InboundParseError> {
    let messages = parse_frame_payload_in(batch).map_err(InboundParseError::Codec)?;
    crate::network_message::refuse_unknown_mandatory_ext(messages)
}
// transport-lowlatency — the lean rx branch reads the leading message id
// (wire_const) and synthesizes an empty ext list (Vec); transport-compression's
// rx un-wrap holds the decompressed batch in a Vec too.
#[cfg(all(
    feature = "alloc",
    any(feature = "transport-lowlatency", feature = "transport-compression")
))]
use alloc::vec::Vec;
#[cfg(feature = "transport-lowlatency")]
use wz_codecs::wire_const;

/// R2371 (`transport-stats`) — charge one frame's worth of NETWORK messages,
/// then hand the batch on untouched.
///
/// Placed on the parse RESULT rather than in the per-MID dispatch below because
/// that is where the whole batch exists at once: a Frame carrying N network
/// messages counts N here and 1 at the wire seam, which is the `n_msgs` /
/// `t_msgs` distinction upstream draws. Both `parse_frame_payload` call sites —
/// the lean lowlatency path and the framed path — route through here, so a frame
/// cannot be counted on one and missed on the other.
///
/// # The alias resolver is EMPTY on this side, on purpose
///
/// Classification needs the literal key expression, and an inbound alias names
/// the PEER's id space — which lives on the face (the forwarder's per-face
/// table), not on this session. So an inbound aliased expression falls to
/// [`crate::stats::StatSpace::User`], the decided default
/// [`crate::network_message::stats_class`] documents. Passing a resolver that
/// answers `None` states that rather than reaching for the wrong table: the
/// session's OWN outbound space would resolve the peer's ids against our
/// declarations, which is not a partial answer but a wrong one.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn count_rx_network_messages<R: SessionRuntime, T: TimeSource>(
    _actions: &SessionLinkActions<R, T>,
    messages: alloc::vec::Vec<crate::network_message::NetworkMessage>,
) -> alloc::vec::Vec<crate::network_message::NetworkMessage> {
    #[cfg(feature = "transport-stats")]
    for msg in &messages {
        let class = crate::network_message::stats_class(msg, |_id| None);
        _actions.stats.inc_rx_network(&class);
        // R2825 — the registry: the payload observed, and the message counted
        // on the link that received it, under the message's own band.
        let priority = crate::network_message::network_message_priority(msg);
        let rx = crate::stats_registry::StatsDirection::Rx;
        _actions.observe_payload(rx, priority, &class);
        _actions.count_network_message(rx, &_actions.link, priority, &class);
    }
    messages
}

/// R2825 — count one received TRANSPORT message, on the JSON counters and on
/// the receiving link's registry cell: one per message decoded out of a unit,
/// as upstream's batch walk counts
/// (`io/zenoh-transport/src/unicast/universal/rx.rs` @ `stats.inc_transport_message(zenoh_stats::Rx, 1);`).
#[cfg(feature = "transport-stats")]
fn count_rx_transport_message<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) {
    actions.stats.inc_rx_transport_message();
    actions.record_on_link(&actions.link, |metrics, slot| {
        metrics.inc_transport_message(crate::stats_registry::StatsDirection::Rx, slot, 1)
    });
}

/// The link under a session is gone (`cause` says how): the FSM is told, and
/// the outcome names the cause. What [`dispatch_link_event`] does with a
/// `LinkEvent::Lost`, and what a loop with no allocator does with a link that
/// reports itself lost: such a build has no `LinkEvent` (its `Rx` arm holds an
/// owned frame), and a stream link can still be closed under it.
pub fn dispatch_link_lost<R: SessionRuntime, T: TimeSource>(
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    cause: crate::link::LostCause,
) -> DriverLoopOutcome {
    engine.process_event(crate::session_fsm_unicast::SessionFsmUnicastEvent::LinkLost);
    DriverLoopOutcome::LinkLost(cause)
}

/// Drive one already-polled `LinkEvent` through the inbound chain so the
/// engine-free session FSM advances. The synchronous core of
/// `wz-runtime-tokio::poll_and_dispatch_one` (whose sole `.await` —
/// `driver.poll_event()` — stays in the tokio async wrapper). Generic over the
/// runtime so the lwIP MCU loop dispatches through the same SSOT.
#[cfg(feature = "alloc")]
pub fn dispatch_link_event<R: SessionRuntime, T: TimeSource>(
    event: LinkEvent,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match event {
        LinkEvent::Ready => {
            engine.process_event(E::LinkOpened);
            DriverLoopOutcome::AdvancedFsm
        }
        LinkEvent::Lost { cause } => dispatch_link_lost(engine, cause),
        LinkEvent::Rx(rx) => {
            // transport-stats — count the RAW link bytes received (the on-the-
            // wire total, BEFORE the optional decompression below), the zenoh
            // rx_bytes parity point. The single inbound chokepoint every link
            // kind funnels through.
            #[cfg(feature = "transport-stats")]
            {
                actions.stats.inc_rx(rx.bytes.len());
                // R2825 — the same bytes on this link's registry cell. The
                // transport-message count is NOT here: a unit carries as many
                // as the peer batched, and `dispatch_unit` counts each.
                let bytes = rx.bytes.len() as u64;
                actions.record_on_link(&actions.link, |metrics, slot| {
                    metrics.inc_bytes(crate::stats_registry::StatsDirection::Rx, slot, bytes)
                });
            }
            // transport-compression — un-wrap the OUTERMOST wire layer FIRST
            // (zenoh decompresses the batch before any transport-message
            // dispatch). While compression is ACTIVE the datagram is
            // [BatchHeader][payload]; decompress it into `bytes` (which the
            // universal dispatch below then reads). A malformed blob — or one that
            // would expand past the negotiated mtu bound (the decompression-bomb
            // guard) — is a framing error. `compresses_batches` is the SAME
            // predicate the TX wrap uses, so this side un-wraps exactly what the
            // other side wraps: pre-establishment handshake frames pass through
            // verbatim, and so does every frame on a lean lowlatency link, where
            // zenoh's rx does not decompress either (R311y434).
            #[cfg(feature = "transport-compression")]
            let decompressed: Option<Vec<u8>> = if actions.compresses_batches() {
                match crate::compression::decompress_batch(
                    &rx.bytes,
                    actions.negotiated_batch_mtu(),
                ) {
                    Some(b) => Some(b),
                    None => {
                        engine.process_event(E::FramingError);
                        return DriverLoopOutcome::ParseError(
                            crate::parse_error::InboundParseError::CompressionFailed,
                        );
                    }
                }
            } else {
                None
            };
            // The unit, made shareable ONCE, before anything is decoded out of
            // it: a link that lent its buffer hands it up lent and a heap read
            // is moved behind the one `Arc`, so the frame's payload, the
            // messages decoded from it and a remainder parked for the next turn
            // are all ranges of this storage and not copies of it. A
            // decompressed batch is a buffer this function built, which is
            // what `RxBytes::lend` is for.
            #[cfg(feature = "transport-compression")]
            let unit = match decompressed {
                Some(inflated) => crate::link::RxBytes::lend(inflated),
                None => rx.bytes.into_lent(),
            };
            #[cfg(not(feature = "transport-compression"))]
            let unit = rx.bytes.into_lent();
            dispatch_unit(&unit, actions, engine)
        }
    }
}

/// transport-lowlatency — whether a unit of an established lean session is a
/// bare network message batch, by its leading message id (zenoh lean rx,
/// codec/transport/mod.rs:60-73): KeepAlive and Close are not (their wire form
/// is identical in both modes, top-level transport messages, never
/// Frame-wrapped, and they take the universal decode), nor is an empty unit;
/// any OTHER leading id is a bare NetworkMessage (mids 0x19..=0x1F) with no
/// Frame(sn) wrapper.
///
/// The one rule both lean receive paths classify by: the copying
/// [`dispatch_unit`] and the in-place [`dispatch_datagram`]. Using the
/// message-id constants (not the network-mid range) keeps it feature-robust:
/// `T_MID_KEEP_ALIVE` is ungated, and the `T_MID_CLOSE` arm rides `codec-close`
/// exactly like the `handle_inbound` decode arm it defers to.
#[cfg(feature = "transport-lowlatency")]
fn is_lean_network_unit(bytes: &[u8]) -> bool {
    match bytes.first().map(|h| h & 0x1F) {
        None => false,
        Some(wire_const::T_MID_KEEP_ALIVE) => false,
        #[cfg(feature = "codec-close")]
        Some(wire_const::T_MID_CLOSE) => false,
        Some(_) => true,
    }
}

/// R311y632 (§17) — dispatch ONE framing unit that [`dispatch_link_event`]
/// has already un-wrapped.
///
/// Split out so the REMAINDER of a batch can re-enter WITHOUT being handed to
/// the decompressor a second time: compression wraps the whole unit, so bytes
/// that have already come out of it must not go back in.
/// [`dispatch_pending`] is the other caller.
#[cfg(feature = "alloc")]
fn dispatch_unit<R: SessionRuntime, T: TimeSource>(
    unit: &crate::link::RxBytes,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    dispatch_unit_in(unit.as_slice(), Some(unit), actions, engine)
}

/// [`dispatch_unit`] over a unit that is only BORROWED: the bytes of a datagram
/// where the link holds them, read without making a shareable value of them
/// first. It is the one dispatch of a unit that is not a `Frame` for a profile
/// whose receive does not copy ([`dispatch_datagram`]'s `session-slot` form),
/// and runs the same code as the copying path, so a handshake is judged the same
/// way whichever way it arrived. The only things that need an owner are a
/// residue left for the next turn and the lean arm, and each copies then.
///
/// On a build with no allocator nothing is copied and no residue is parked: the
/// bytes of the unit the message did not consume are reported through `consumed`
/// (the length of the unit on entry, shortened to where the message ended), and the
/// caller reads the rest of the datagram where it lies, as upstream's batch walk
/// does.
#[cfg(all(feature = "codec-frame", feature = "session-slot"))]
fn dispatch_unit_borrowed<R: SessionRuntime, T: TimeSource>(
    bytes: &[u8],
    #[cfg(not(feature = "alloc"))] consumed: &mut usize,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    #[cfg(feature = "alloc")]
    {
        dispatch_unit_in(bytes, None, actions, engine)
    }
    #[cfg(not(feature = "alloc"))]
    {
        dispatch_unit_in(bytes, consumed, actions, engine)
    }
}

/// The body of [`dispatch_unit`] and `dispatch_unit_borrowed`: `bytes` is the
/// unit, and `shared` is the same unit as a shareable value when the caller has
/// one.
fn dispatch_unit_in<R: SessionRuntime, T: TimeSource>(
    bytes: &[u8],
    #[cfg(feature = "alloc")] shared: Option<&crate::link::RxBytes>,
    #[cfg(not(feature = "alloc"))] consumed_out: &mut usize,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    // The unit is read two ways below: as bytes, for the leading id and the
    // lengths, and (when there is one) as a shareable value, for every decode and
    // for the remainder it parks. The decodes run over `shared` itself and never
    // over a copy of it, because a range is recognisable as part of `shared` only
    // if it is.

    // transport-lowlatency — lean rx: once this session negotiated
    // lowlatency AND is established, a datagram whose leading message id
    // is neither Close nor KeepAlive is a BARE NetworkMessage with NO
    // Frame(sn) wrapper. zenoh's lowlatency rx dispatches the leading id
    // and routes the default (non-Close/-KeepAlive) arm straight to a
    // NetworkMessage decode (codec/transport/mod.rs:60-73). Decode the
    // payload directly and surface it as a FramePayload, synthesizing
    // reliable=true / sn=0 — the lean wire carries no SN and the
    // per-channel half-window gate (`admit_rx_frame_sn`) does not exist on
    // this path (zenoh's lowlatency transport tracks no SN). Close /
    // KeepAlive (and an empty datagram) fall through to `handle_inbound`:
    // their wire form is identical in both modes (top-level transport
    // messages, never Frame-wrapped). The `is_established` guard keeps the
    // handshake Init / Open frames (which still ride the universal path —
    // lowlatency only selects the transport post-establishment, zenoh
    // manager.rs:611) off this branch.
    #[cfg(all(feature = "alloc", feature = "transport-lowlatency"))]
    if actions.is_lowlatency() && actions.is_established() {
        // Dispatch the leading message id ([`is_lean_network_unit`]).
        if is_lean_network_unit(bytes) {
            // A unit that is only borrowed is made a value of its own here, the
            // one case that needs it (a profile that reads lean units in place
            // never gets here).
            let owned;
            let unit = match shared {
                Some(unit) => unit,
                None => {
                    owned = crate::link::RxBytes::from(bytes.to_vec());
                    &owned
                }
            };
            return match parse_frame_payload_out_of_line(unit) {
                Ok(messages) => {
                    // R2825 — a lean datagram is ONE transport message whatever
                    // it carries, which is how upstream's lowlatency rx counts it.
                    #[cfg(feature = "transport-stats")]
                    count_rx_transport_message(actions);
                    DriverLoopOutcome::FramePayload {
                        reliable: true,
                        sn: 0,
                        messages: count_rx_network_messages(actions, messages),
                        has_ext: false,
                        extensions: Vec::new(),
                        // R311y221 — the lowlatency lean wire carries no Frame
                        // envelope and no ext_qos (zenoh lowlatency tracks no
                        // SN / no per-priority conduit), so the delivered band
                        // is DEFAULT.
                        priority: crate::qos::Priority::DEFAULT,
                    }
                }
                Err(parse_err) => {
                    engine.process_event(E::FramingError);
                    DriverLoopOutcome::ParseError(parse_err)
                }
            };
        }
    }
    // R311y632 (§17) — THE UNIT IS A BATCH. Take the message at the front and
    // park whatever follows it, so the next drive-loop turn dispatches that
    // instead of the peer's next datagram. `consumed == 0` means the extent is
    // unknown (an unrecognised MID), and the walk must not guess where the next
    // message begins: nothing is parked, and the `Unknown` frame below already
    // projects to `FramingError`, which is what both reference implementations
    // do with a batch they cannot finish reading.
    #[cfg(feature = "alloc")]
    let parsed = match shared {
        Some(unit) => actions.handle_inbound_consuming_in(unit),
        None => actions.handle_inbound_consuming(bytes),
    };
    #[cfg(not(feature = "alloc"))]
    let parsed = actions.handle_inbound_consuming(bytes);
    if let Ok((_, consumed)) = &parsed {
        // R2825 — one transport message decoded off the front of the unit.
        #[cfg(feature = "transport-stats")]
        count_rx_transport_message(actions);
        if *consumed > 0 && *consumed < bytes.len() {
            #[cfg(feature = "alloc")]
            {
                let rest = match shared {
                    Some(unit) => unit.subslice(*consumed..bytes.len()),
                    // A borrowed unit's residue is copied to be kept: the one copy
                    // a batch costs on this path, and a unit holding only the one
                    // message a handshake sends costs none.
                    None => Some(crate::link::RxBytes::from(bytes[*consumed..].to_vec())),
                };
                if let Some(rest) = rest {
                    actions.park_pending_unit(rest);
                }
            }
            // A build with no allocator has nowhere to park a residue: it says where
            // the message ended, and the reader of the datagram goes on from there
            // over the bytes where they lie.
            #[cfg(not(feature = "alloc"))]
            {
                *consumed_out = *consumed;
            }
        }
    }
    // Destructured where it lies: `Result::map` would take the 720-byte result by value
    // and hand the frame on through a closure, a slot of the frame each time.
    match parsed {
        Ok((frame, _)) => match inbound_to_fsm_event(&frame) {
            Some(event) => {
                // R311kc — initiator InitAck params validation (zenoh-pico
                // unicast/transport.c:123-140): an InitAck whose size
                // parameters exceed our InitSyn advertisement REJECTS the
                // session — `framing.error` drives Closing with
                // `CloseReason::Invalid` (wire Close(INVALID)) and the
                // typed outcome surfaces the reason to the open loop.
                // Unlike the silent-drop admissions below, the reject must
                // advance the FSM: hanging until the handshake timeout
                // would mislabel a non-conforming peer as a silent one.
                // `handle_inbound` already captured the (rejected) caps
                // into `inbound_peer_init_caps`; inert — the session is
                // torn down before any mint reads them.
                //
                // R311kj review fix — scoped to `SentInitSyn`, the ONE
                // Initiator state that awaits the InitAck (pico validates
                // exactly there in its open sequence). The R311kc
                // `!is_established()` scope was role-blind: a bogus
                // enlarging InitAck aimed at an ACCEPTOR mid-handshake
                // tore the session down where pico (and pre-R311kc wz)
                // lets the FSM ignore the no-transition event. Outside
                // SentInitSyn the frame now falls through to the FSM,
                // which ignores it (pico drops it).
                //
                // R311y817 — the PATCH extension is the FOURTH member of
                // that same pico rule block and was the one wz did not
                // enforce, because it rides the ext chain and
                // `init_ack_caps_acceptable` reads only the body. pico
                // checks it immediately after the three sizes
                // (`transport.c:141-149`, under Z_FEATURE_FRAGMENTATION)
                // and lets the same `ret` abort before the OpenSyn;
                // zenoh `bail!`s the equivalent out of
                // `PatchFsm::recv_init_ack`. Ordered after the size
                // check for the same reason pico orders it there, and
                // BEFORE the `negotiate_patch_against_peer` min() below,
                // which must never see a level the session is refusing
                // (zenoh's `state.patch = other_ext` likewise sits after
                // its bail).
                #[cfg(feature = "codec-init-body")]
                if let InboundFrame::Init {
                    is_ack: true,
                    body,
                    extensions,
                    ..
                } = &frame
                {
                    use crate::session_fsm_unicast::SessionFsmUnicastState as S;
                    if engine.get_current_state() == S::SentInitSyn {
                        if !actions.init_ack_caps_acceptable(body.sn_res, body.batch_size) {
                            engine.process_event(E::FramingError);
                            return DriverLoopOutcome::InitAckCapsRejected;
                        }
                        // R311y823 — the PATCH reject leaves through
                        // `establishment.ext_rejected`, not `framing.error`,
                        // because the reason byte differs on the wire. zenoh
                        // reserves INVALID for the three BODY size parameters
                        // checked immediately above (`open.rs:288,304`) and
                        // closes GENERIC for every EXTENSION handler failure
                        // (`open.rs:321-364`) -- and `link.close` puts that
                        // byte in a Close the peer reads
                        // (`unicast/link.rs:103-114`). The patch is an
                        // extension, so it takes the extension's reason even
                        // though it is the fourth member of pico's rule block.
                        if !actions
                            .init_ack_patch_acceptable(crate::extpatch::peer_patch(extensions))
                        {
                            engine.process_event(E::EstablishmentExtRejected);
                            return DriverLoopOutcome::InitAckPatchRejected;
                        }
                    }
                }
                // R311il — §2.7 dispatcher admission pre-classify. The
                // accept-side caps (half-open + token bucket on
                // init_syn; cookie HMAC on open_syn) depend on HOST
                // state, not on the triggering frame's wire payload, so
                // the engine-free FSM carries no `cond=` for them — the
                // dispatcher evaluates admission and injects the event
                // only when it passes. Denial drops silently: no Close
                // frame, no FSM advance (anti-amplification per the §2.7
                // trust-class matrix). Engine-free successor of the
                // retired Lua `cond="cookie_valid()"` transition guard.
                let admit = match event {
                    E::InitSynReceived => {
                        actions.half_open_cap_available() && actions.accept_rate_token()
                    }
                    #[cfg(feature = "session-unicast-accept")]
                    E::OpenSynReceived => actions.cookie_valid(),
                    // A build with no accept side has no cookie to verify and no handshake to
                    // admit: an OpenSyn is denied silently, like every inadmissible frame here.
                    // Naming `cookie_valid` only under the accept feature is also what leaves
                    // the cookie decoder and its HMAC out of an initiator-only image.
                    #[cfg(not(feature = "session-unicast-accept"))]
                    E::OpenSynReceived => false,
                    // R2782 — the initiator's twin: an OpenAck is admitted
                    // only while one is awaited. A replay after
                    // `Established` was measured to reset the RX baseline.
                    E::OpenAckReceived => actions.open_ack_awaited(),
                    _ => true,
                };
                if !admit {
                    return DriverLoopOutcome::SideEffectOnly;
                }
                // An InitSyn of another protocol version is refused before any
                // of its fields is negotiated, as upstream refuses it before
                // reading the resolution (`DriverLoopOutcome::InitSynVersionRejected`).
                // After the admission gate, so an InitSyn over the half-open
                // cap or the rate limit is still dropped silently rather than
                // answered with a Close: the anti-amplification rule outranks
                // the courtesy of saying why. Scoped to the state that awaits
                // an InitSyn, as the InitAck checks above are scoped to the one
                // that awaits an InitAck.
                #[cfg(feature = "codec-init-body")]
                if let InboundFrame::Init {
                    is_ack: false,
                    body,
                    ..
                } = &frame
                {
                    use crate::session_fsm_unicast::SessionFsmUnicastState as S;
                    if engine.get_current_state() == S::AwaitingInitSyn
                        && body.version != wz_codecs::wire_const::PROTOCOL_VERSION
                    {
                        engine.process_event(E::FramingError);
                        return DriverLoopOutcome::InitSynVersionRejected {
                            version: body.version,
                        };
                    }
                }
                // R2772 — REBUILD the acceptor's negotiated state from the
                // cookie the peer just echoed. This is the half that makes the
                // cookie a CARRIER: R2769 gave it the state and taught the
                // guard to decode it, and the guard then threw the decoded
                // copy away because a predicate must not have side effects.
                //
                // ⛔ IT BELONGS HERE AND NOT IN `cookie_valid`, which is the
                // admission predicate the match above calls BEFORE the event
                // is injected. Upstream splits it the same way, both halves in
                // the HANDLER rather than in a check:
                // `io/zenoh-transport/src/unicast/establishment/accept.rs` @
                // `// Rebuild the state from the cookie`, and the nonce
                // compare a few lines above it in the same function.
                // Installing state from a guard would put
                // a write inside a question.
                //
                // Placed with the other post-admission merges below, and
                // BEFORE them deliberately: those merge a peer's OFFER off an
                // Init frame, while this restores an OUTCOME already
                // negotiated in this handshake. A restore that ran after a
                // merge would be overwriting the newer answer with the older.
                //
                // R2782 — and everything else an admitted OpenSyn does, in
                // one call and upstream's order: the restore, spending the
                // nonce that admitted it, then the RX SN seed and the peer
                // lease on the rebuilt state. The seed and the lease used to
                // run at PARSE time, on any OpenSyn -- before the caps they
                // read were back (they ride the cookie's head now), and on
                // frames never admitted; and an unspent nonce let a replay of
                // this very OpenSyn be admitted again after `Established`.
                // R2858 — the peer's `0x7` REMOTE-BOUND, off either Open, and a
                // present-but-invalid one REFUSED. Upstream reads it while
                // building each Open's receive output, `?`-ing a bad value out
                // with GENERIC (`io/zenoh-transport/src/unicast/establishment/accept.rs`
                // @ `other_bound: match open_syn.ext_remote_bound {`), so it is
                // an extension failure and leaves through `ext_rejected` like
                // the region name below. Placed BEFORE the admissions so a
                // refused Open seeds no SN and adopts no lease.
                #[cfg(feature = "codec-open-body")]
                if let InboundFrame::Open { extensions, .. } = &frame {
                    if !actions.admit_peer_remote_bound(extensions) {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::OpenRemoteBoundRejected;
                    }
                }
                #[cfg(feature = "codec-open-body")]
                if let InboundFrame::Open {
                    is_ack: false,
                    body,
                    ..
                } = &frame
                {
                    actions.admit_open_syn(body.lease, body.initial_sn);
                }
                #[cfg(feature = "codec-open-body")]
                if let InboundFrame::Open {
                    is_ack: true, body, ..
                } = &frame
                {
                    actions.admit_open_ack(body.lease, body.initial_sn);
                }
                // R311y578 — take the `min(local, peer)` protocol PATCH
                // level off every admitted Init frame (zenoh-pico
                // `transport.c:237-241` runs the same cap on both sides).
                // wz has emitted its own patch ext since R121f1 and never
                // read the peer's; the negotiated level is the sole gate
                // on the Fragment chain-boundary markers, so a session
                // that never took it can only ever leave them off.
                // R2539 — admit the peer's `0x8` REGION-NAME identity off
                // every admitted Init, and REFUSE a present-but-malformed
                // one. Upstream validates on receipt in both roles
                // (`io/zenoh-transport/src/unicast/establishment/ext/region_name.rs`
                // @ `fn recv_init_syn`,
                // @ `fn recv_init_ack`, each `ext.map(ext_to_name)
                // .transpose()?`), so an empty, over-long or non-UTF-8 value
                // propagates an error out of the FSM rather than reading as
                // "no region". It is an EXTENSION failure, so it leaves
                // through `establishment.ext_rejected` (GENERIC) like the
                // patch above rather than `framing.error` (INVALID).
                //
                // Placed before the patch `min()` for the same reason that
                // one sits after its own reject: a refused Init must not have
                // its other extensions merged into the session first.
                #[cfg(feature = "codec-init-body")]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    if !actions.admit_peer_region(extensions) {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::InitRegionRejected;
                    }
                }
                #[cfg(feature = "codec-init-body")]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    actions.negotiate_patch_against_peer(crate::extpatch::peer_patch(extensions));
                }
                // transport-lowlatency — AND the peer's lowlatency offer into
                // the session capability on every admitted Init frame (zenoh
                // `is_lowlatency &= other_ext.is_some()`, both the acceptor's
                // recv_init_syn and the initiator's recv_init_ack). Runs
                // BEFORE `engine.process_event` below, so the acceptor's merge
                // lands before the InitSyn transition fires its InitAck send
                // (which reflects the ext only if the merged flag still
                // holds). Acceptor sees InitSyn (is_ack=false), initiator sees
                // InitAck (is_ack=true) — both are negotiation points, so the
                // arm matches any Init frame.
                #[cfg(all(feature = "transport-lowlatency", feature = "codec-init-body"))]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    actions.negotiate_lowlatency_against_peer(
                        crate::extlowlatency::peer_offered_lowlatency(extensions),
                    );
                }
                // transport-qos — the same `&=` merge for the Z_EXT_QOS
                // offer on every admitted Init frame (zenoh "both sides
                // QoS or NoQoS", both recv_init_syn and recv_init_ack),
                // BEFORE the InitAck reflect. `peer_offered_qos` accepts
                // the unit OR the z64 QoSLink form at id 0x1, and reads a
                // QoSLink by its body: a body of 0 is NoQoS, as upstream
                // reads it.
                #[cfg(all(feature = "transport-qos", feature = "codec-init-body"))]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    actions.negotiate_qos_against_peer(crate::extqos::peer_offered_qos(extensions));
                }
                // session-extqos — the z64 `QoSLink` half: merge the
                // peer's priority band / reliability into ours under
                // the DIRECTIONAL containment (acceptor on InitSyn
                // demands a subset, initiator on InitAck demands a
                // superset). Runs right after the `&=` above, so the
                // acceptor's InitAck reflects the MERGED band. A refusal
                // is a handshake abort upstream (zenoh `?`s the
                // `zerror!` out of the establishment FSM), so wz injects
                // `FramingError` — the `InitAckCapsRejected` pattern —
                // instead of degrading to a band neither side agreed to.
                #[cfg(all(feature = "session-extqos", feature = "codec-init-body"))]
                if let InboundFrame::Init {
                    is_ack, extensions, ..
                } = &frame
                {
                    if let Err(err) = actions.negotiate_qos_link_against_peer(*is_ack, extensions) {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::QosLinkRejected(err);
                    }
                }
                // session-extcompression — the same `&=` merge for the
                // Z_EXT_COMPRESSION offer on every admitted Init frame
                // (zenoh `is_compression &= other_ext.is_some()`, both
                // recv_init_syn and recv_init_ack), BEFORE the InitAck
                // send reflects it.
                #[cfg(all(feature = "session-extcompression", feature = "codec-init-body"))]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    actions.negotiate_compression_against_peer(
                        crate::extcompression::peer_offered_compression(extensions),
                    );
                }
                // session-extshm — the same `&=` merge for the SHM
                // capability (the scoped unit-ext negotiation) on every
                // admitted Init frame, BEFORE the InitAck reflect.
                #[cfg(all(feature = "session-extshm", feature = "codec-init-body"))]
                if let InboundFrame::Init { extensions, .. } = &frame {
                    actions.negotiate_shm_against_peer(actions.shm_peer_offered(extensions));
                }
                // session-extshm (R311y507) — the CHALLENGE-RESPONSE,
                // which supersedes the capability `&=` above whenever an
                // authenticator is installed. Init phase: the ACCEPTOR
                // maps the initiator's segment on InitSyn (before its
                // InitAck echoes the challenge back); the INITIATOR
                // validates that echo against its own challenge on
                // InitAck and maps the acceptor's segment.
                //
                // Only the acceptor's arm can ABORT: zenoh `bail!`s on a
                // malformed InitSyn body while the initiator's mirror
                // degrades to "no SHM", and that asymmetry is upstream's
                // — a malformed challenge aimed at an acceptor is an
                // attack surface, a malformed answer is just a peer that
                // will not get shared memory.
                #[cfg(all(feature = "session-extshm", feature = "codec-init-body"))]
                if let InboundFrame::Init {
                    is_ack, extensions, ..
                } = &frame
                {
                    if *is_ack {
                        actions.shm_recv_init_ack(extensions);
                    } else if actions.shm_recv_init_syn(extensions).is_err() {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::ShmChallengeRejected;
                    }
                }
                // session-extshm (R311y507) — the Open phase, where BOTH
                // roles finally decide `is_shm`: the acceptor on the
                // initiator's echo (OpenSyn), the initiator on the
                // acceptor's literal `1` (OpenAck). A peer that offered
                // SHM but never proved it can map our memory lands on
                // `is_shm = false` here rather than at the capability
                // merge — which is the whole difference between a
                // capability flag and a proof.
                #[cfg(all(feature = "session-extshm", feature = "codec-open-body"))]
                if let InboundFrame::Open {
                    is_ack, extensions, ..
                } = &frame
                {
                    if *is_ack {
                        actions.shm_recv_open_ack(extensions);
                    } else {
                        actions.shm_recv_open_syn(extensions);
                    }
                }
                // R3b — feed the admitted handshake frame's ext chain into
                // the matching Z_EXT_AUTH demux stage BEFORE advancing the
                // FSM, so a usrpwd reject tears the session down instead of
                // emitting the next handshake message. zenoh runs auth recv
                // inside the establishment FSM transition; this is the
                // engine-free analogue, placed right where the per-event
                // admission already gates (an unadmitted frame returned
                // above and is never auth-checked). An empty dispatch admits
                // every stage (zenoh `Auth::default()`). The InitSyn/OpenSyn
                // (accept) and InitAck/OpenAck (initiator) demux stages each
                // pair an event with its frame variant.
                #[cfg(feature = "session-extauth")]
                {
                    let auth: Option<Result<(), crate::auth_dispatch::AuthError>> = match &frame {
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init {
                            is_ack: false,
                            extensions,
                            ..
                        } => Some(actions.with_auth(|d| d.accept_recv_init_syn(extensions))),
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init {
                            is_ack: true,
                            extensions,
                            ..
                        } => Some(actions.with_auth(|d| d.open_recv_init_ack(extensions))),
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open {
                            is_ack: false,
                            extensions,
                            ..
                        } => Some(
                            // R2566 — the accept stage's OUTPUT is an identity,
                            // and this is the seam that lands it. Assigned
                            // unconditionally (including `None`) so a
                            // re-handshake that authenticates nobody clears the
                            // previous principal instead of leaving it readable.
                            actions
                                .with_auth(|d| d.accept_recv_open_syn(extensions))
                                .map(|id| actions.set_peer_auth_id(id)),
                        ),
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open {
                            is_ack: true,
                            extensions,
                            ..
                        } => Some(actions.with_auth(|d| d.open_recv_open_ack(extensions))),
                        _ => None,
                    };
                    if let Some(Err(e)) = auth {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::AuthRejected(e);
                    }
                }
                // R311y205 (transport-multilink IMPL-2b-ii) — feed the
                // admitted handshake frame's ext chain into the matching
                // 0x4 Z_EXT_MULTILINK demux stage, BESIDE the auth demux
                // above (the 0x4 ext is UN-wrapped, not muxed through
                // auth). `with_multilink` is `None` when no dispatch is
                // installed (max_links=1) — the peer's 0x4 ext, if any, is
                // then ignored. A challenge failure rejects the session
                // exactly like an auth reject; a success latches the peer's
                // captured ephemeral pubkey (the join gate's identity key).
                #[cfg(feature = "transport-multilink")]
                {
                    let ml: Option<Result<(), crate::auth_dispatch::AuthError>> = match &frame {
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init {
                            is_ack: false,
                            extensions,
                            ..
                        } => actions.with_multilink(|d| d.accept_recv_init_syn(extensions)),
                        #[cfg(feature = "codec-init-body")]
                        InboundFrame::Init {
                            is_ack: true,
                            extensions,
                            ..
                        } => actions.with_multilink(|d| d.open_recv_init_ack(extensions)),
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open {
                            is_ack: false,
                            extensions,
                            ..
                        } => actions.with_multilink(|d| d.accept_recv_open_syn(extensions)),
                        #[cfg(feature = "codec-open-body")]
                        InboundFrame::Open {
                            is_ack: true,
                            extensions,
                            ..
                        } => actions.with_multilink(|d| d.open_recv_open_ack(extensions)),
                        _ => None,
                    };
                    if let Some(Err(e)) = ml {
                        engine.process_event(E::EstablishmentExtRejected);
                        return DriverLoopOutcome::AuthRejected(e);
                    }
                    // Latch the peer's captured ephemeral pubkey (no-op
                    // when no dispatch / no key captured yet).
                    actions.capture_multilink_pubkey();
                }
                // Decision D4 — a dial made for a node closes on an InitAck
                // from another one. Upstream's order: after the InitAck and
                // every extension handler are taken, before the OpenSyn is
                // built, with the INVALID reason, which `framing.error`
                // closes on:
                // `io/zenoh-transport/src/unicast/establishment/open.rs` @
                // `// Check if the expected_zid matches the peer's ZID`
                #[cfg(feature = "codec-init-body")]
                if let InboundFrame::Init {
                    is_ack: true, body, ..
                } = &frame
                {
                    use crate::session_fsm_unicast::SessionFsmUnicastState as S;
                    if engine.get_current_state() == S::SentInitSyn
                        && !actions.init_ack_zid_acceptable(body.zid.as_slice())
                    {
                        engine.process_event(E::FramingError);
                        return DriverLoopOutcome::InitAckPeerMismatch;
                    }
                }
                // Item 751 — decide the bound this node announces for the peer
                // on the Open the event below sends: the initiator's OpenSyn on
                // the InitAck it is waiting for, the acceptor's OpenAck on the
                // OpenSyn it just rebuilt from the cookie. Last, so every fact the
                // decision reads (the peer's zid, role and region name) is the
                // admitted one, and before the event, because upstream fails the
                // handshake on an error here instead of sending its Open.
                #[cfg(all(feature = "codec-init-body", feature = "codec-open-body"))]
                {
                    use crate::session_fsm_unicast::SessionFsmUnicastState as S;
                    let sends_an_open = match &frame {
                        InboundFrame::Init { is_ack: true, .. } => {
                            engine.get_current_state() == S::SentInitSyn
                        }
                        InboundFrame::Open { is_ack: false, .. } => true,
                        _ => false,
                    };
                    if sends_an_open {
                        if let Err(why) = actions.decide_local_remote_bound() {
                            engine.process_event(E::EstablishmentExtRejected);
                            return DriverLoopOutcome::OpenLocalBoundUnplaceable(why);
                        }
                    }
                }
                engine.process_event(event);
                DriverLoopOutcome::AdvancedFsm
            }
            None => match frame {
                #[cfg(all(feature = "alloc", feature = "codec-frame"))]
                InboundFrame::Frame {
                    reliable,
                    sn,
                    payload,
                    has_ext,
                    extensions,
                    priority,
                } => {
                    // R311y215 (SN-safety F5) — a non-DEFAULT ext_qos on
                    // a session that did NOT negotiate QoS is a wire-spec
                    // violation (a peer must not prioritize without a
                    // negotiated `is_qos`). A QoS session accepts every
                    // priority on its own conduit.
                    //
                    // R2927 — and it is LINK-FATAL, as upstream's is, where
                    // wz used to drop the frame and keep the link: see
                    // [`crate::link::LostCause::UnknownPriority`]. Every
                    // build checks, since the priority is decoded in every
                    // build; a build without `transport-qos` negotiates none.
                    //
                    // R311ke — per-channel RX SN gate (pico
                    // `_z_sn_precedes`, unicast/rx.c:108-131): a stale
                    // / duplicate / reordered frame drops before its
                    // payload reaches the application layer. R311y215 —
                    // the gate is per-(priority, reliable) conduit. The
                    // typed outcome lets `report_outcome_reassembling`
                    // clear the channel's in-progress chain (dbuf-clear
                    // parity) and observers count the drop.
                    //
                    // Both gates are [`refuse_frame`], which the in-place
                    // receive path ([`dispatch_datagram`]) runs too.
                    if let Some(refused) = refuse_frame(actions, engine, priority, reliable, sn) {
                        return refused;
                    }
                    // The lane of a data stream: a frame every record of which is a plain
                    // Put is reported as where its records lie, and the generic decode
                    // below never runs for it. One record that is anything else sends the
                    // whole frame down the generic path, so this reads what the codec
                    // reads or declines. Not under `transport-stats`, which counts the
                    // owned messages, and not on the fixed backing, whose bounded keyexpr
                    // buffer cannot hold every key a Put names.
                    #[cfg(all(
                        feature = "pubsub-put",
                        not(feature = "transport-stats"),
                        not(feature = "bounded-heapless")
                    ))]
                    if actions.plain_put_lane_open() {
                        if let Some(puts) = crate::plain_push::read_plain_puts(&payload) {
                            return DriverLoopOutcome::FramePlainPuts {
                                reliable,
                                sn,
                                priority,
                                payload,
                                puts,
                            };
                        }
                    }
                    match parse_frame_payload_out_of_line(&payload) {
                        // `payload` is a range of the unit when the unit was
                        // lent, so the messages below are ranges of it too.
                        Ok(messages) => DriverLoopOutcome::FramePayload {
                            reliable,
                            sn,
                            messages: count_rx_network_messages(actions, messages),
                            has_ext,
                            extensions,
                            // R311y221 — the true decoded band (already
                            // in scope from the InboundFrame::Frame
                            // destructure above; gates the RX conduit at
                            // `admit_rx_frame_sn`). DEFAULT under non-QoS.
                            priority,
                        },
                        Err(parse_err) => {
                            engine.process_event(E::FramingError);
                            DriverLoopOutcome::ParseError(parse_err)
                        }
                    }
                }
                #[cfg(feature = "codec-keep-alive")]
                InboundFrame::KeepAlive { .. } => DriverLoopOutcome::SideEffectOnly,
                // R311im — surface the decoded fragment to the drive
                // loop, which owns the stateful ReassemblyDispatcher +
                // clock. This pure helper cannot reassemble (no slot
                // pool, no `now_ms`), so it hands the fragment up.
                #[cfg(all(feature = "alloc", feature = "reassembly"))]
                InboundFrame::Fragment {
                    reliable,
                    sn,
                    more,
                    payload,
                    has_ext,
                    extensions,
                    priority,
                    markers,
                } => {
                    // R311y215 (SN-safety F5) / R2927 — as with Frame, a
                    // prioritized fragment on a non-QoS session is link-fatal
                    // (upstream's fragment arm bails the same way).
                    if !actions.negotiated_qos() && priority != crate::qos::Priority::DEFAULT {
                        engine.process_event(E::LinkLost);
                        return DriverLoopOutcome::LinkLost(
                            crate::link::LostCause::UnknownPriority,
                        );
                    }
                    // R311ke — fragments ride the same per-(priority,
                    // reliable) conduit SN counter as frames (pico gates
                    // them through the same `_z_sn_precedes`,
                    // rx.c:160-176), so the gate must see them too or a
                    // frame following a fragment chain would compare
                    // against a stale baseline. The chain-level
                    // ring-consecutive check stays in the
                    // ReassemblyDispatcher (a forward GAP passes here
                    // and aborts there, exactly pico's two-stage check).
                    if !actions.admit_rx_frame_sn(priority, reliable, sn) {
                        return DriverLoopOutcome::RxSnRejected {
                            priority,
                            reliable,
                            sn,
                        };
                    }
                    DriverLoopOutcome::Fragment {
                        reliable,
                        sn,
                        more,
                        payload,
                        has_ext,
                        extensions,
                        priority,
                        markers,
                    }
                }
                #[cfg(feature = "codec-init-body")]
                InboundFrame::Init { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                #[cfg(feature = "codec-open-body")]
                InboundFrame::Open { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                #[cfg(feature = "codec-close")]
                InboundFrame::Close { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                // R311y605 — a JOIN reaches `inbound_to_fsm_event` as
                // `Some(FramingError)`, exactly as it did before it was
                // decodable at all (it fell through to `Unknown` then).
                // Same unreachability, same reason.
                #[cfg(all(feature = "alloc", feature = "codec-join"))]
                InboundFrame::Join { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                // Transport OAM projects to `Some(FramingError)` for the same
                // reason a JOIN does — wz's unicast FSM has no operations
                // transition — so the outer Some arm took it.
                #[cfg(feature = "alloc")]
                InboundFrame::Oam { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                #[cfg(all(feature = "alloc", feature = "codec-frame"))]
                InboundFrame::Network { .. } => {
                    unreachable!("observer network envelope projects to FramingError")
                }
                InboundFrame::Unknown { .. } => {
                    // inbound_to_fsm_event projects these to Some(event),
                    // so the outer Some arm handled them — this branch
                    // is unreachable.
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
            },
        },
        Err(err) => {
            engine.process_event(E::FramingError);
            DriverLoopOutcome::ParseError(err)
        }
    }
}
/// R311y632 (§17) — dispatch the next message of the framing unit already in
/// hand, if the last one did not exhaust it.
///
/// # Why the caller polls this BEFORE the link
///
/// A drive loop's shape is "poll the link, dispatch what came back". A unit
/// holding two messages therefore delivers the second one only when the PEER
/// sends again — which is a loss whenever it never does, and a latency bug
/// whenever it does. So the loops ask here first, and only reach for the link
/// when nothing is parked.
///
/// `None` is the ordinary answer: most units hold one message.
#[cfg(feature = "alloc")]
pub fn dispatch_pending<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> Option<DriverLoopOutcome> {
    let residue = actions.take_pending_batch()?;
    Some(dispatch_unit(&residue, actions, engine))
}

/// The two gates a decoded `Frame` passes before its payload is read, in the
/// order the copying path has always run them: `Some` is the outcome of a frame
/// that did not pass.
///
/// - R311y215 / R2927 — a non-DEFAULT priority on a session that negotiated no
///   QoS is link-fatal (see [`crate::link::LostCause::UnknownPriority`]).
/// - R311ke / R311y215 — the per-(priority, reliable) conduit SN gate (pico
///   `_z_sn_precedes`): a stale, duplicate or reordered frame is dropped.
#[cfg(feature = "codec-frame")]
fn refuse_frame<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    priority: crate::qos::Priority,
    reliable: bool,
    sn: u64,
) -> Option<DriverLoopOutcome> {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    if !actions.negotiated_qos() && priority != crate::qos::Priority::DEFAULT {
        engine.process_event(E::LinkLost);
        return Some(DriverLoopOutcome::LinkLost(
            crate::link::LostCause::UnknownPriority,
        ));
    }
    if !actions.admit_rx_frame_sn(priority, reliable, sn) {
        return Some(DriverLoopOutcome::RxSnRejected {
            priority,
            reliable,
            sn,
        });
    }
    None
}

/// Which path [`dispatch_datagram`] took one unit down: the count a profile
/// keeps of how much of its traffic is read in place and why the rest is not.
#[cfg(feature = "codec-frame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramPath {
    /// The unit began with an admissible `Frame` and was read where it lies.
    InPlace,
    /// The unit was an admissible `Fragment` and its payload was staged into
    /// its reassembly slot from where the unit lies
    /// ([`dispatch_datagram_reassembling`]); a chain it completed was read in
    /// that slot.
    FragmentInPlace,
    /// The unit was a lean lowlatency unit (`transport-lowlatency`): a bare
    /// network message batch with no `Frame` envelope, read where it lies as a
    /// `Frame`'s payload is.
    LowLatencyInPlace,
    /// The unit was copied onto the heap and dispatched by
    /// [`dispatch_link_event`], for the reason given.
    Copied(CopyReason),
}

/// Why [`dispatch_datagram`] copied a unit instead of reading it where it lies.
/// Each is a unit the in-place path does not take by design, documented on
/// [`dispatch_datagram`]; counting them is what keeps a profile honest about
/// what its receive path costs.
#[cfg(feature = "codec-frame")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyReason {
    /// The session compresses its batches: the inflated batch is a buffer of
    /// its own, written by the decompressor.
    Compressed,
    /// A `Fragment` on a path that holds no reassembly Router
    /// ([`dispatch_datagram`]); [`dispatch_datagram_reassembling`] stages one
    /// in place.
    Fragment,
    /// A `Fragment` whose own extension chain a participant must refuse: the
    /// FSM's `framing.error` arm is the copying path's.
    FragmentExtRefused,
    /// A `Fragment` whose head does not decode: the copying path decodes it
    /// again and reports the error the way it always has.
    FragmentHeadUndecodable,
    /// A handshake, KeepAlive or Close, or any other unit that does not begin
    /// with a `Frame` (nor, on a lean lowlatency session, with a network
    /// message): its state changes and residue parking are the copying path's.
    NotAFrame,
    /// A `Frame` whose own extension chain a participant must refuse: the FSM's
    /// `framing.error` arm is the copying path's.
    FrameExtRefused,
    /// A `Frame` whose head does not decode: the copying path decodes it again
    /// and reports the error the way it always has.
    FrameHeadUndecodable,
}

/// How [`dispatch_datagram`] hands over a Push, a Request or a Response record:
/// lent where the frame lies when this build can deliver it so, owned otherwise.
///
/// `transport-stats` keeps the owned form: its counters classify a received
/// message by reading the owned message (`network_message::stats_class`), and
/// that profile is the AP's, which never takes this path. A counter that
/// silently skipped the records of an in-place frame would be a wrong number,
/// so the build that has the counters does not lend.
///
/// On the per-session slot profile (`session-slot`) EVERY record is lent, the
/// control kinds (a Declare, an Interest, a ResponseFinal) too
/// ([`RecordForm::LentControl`](crate::network_message::RecordForm::LentControl)):
/// the owned message a control record would otherwise become is a boxed
/// `DeclareOwned` with heap lists, which is what that profile does not have.
#[cfg(all(feature = "codec-frame", feature = "session-slot", feature = "alloc"))]
const RECORD_FORM: crate::network_message::RecordForm = if cfg!(feature = "transport-stats") {
    crate::network_message::RecordForm::Owned
} else {
    crate::network_message::RecordForm::LentControl
};
// A build with no allocator has the one form: `transport-stats` implies `alloc`, and
// the owned messages are the heap profile's.
#[cfg(all(
    feature = "codec-frame",
    feature = "session-slot",
    not(feature = "alloc")
))]
const RECORD_FORM: crate::network_message::RecordForm =
    crate::network_message::RecordForm::LentControl;
#[cfg(all(
    feature = "codec-frame",
    not(feature = "session-slot"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    )
))]
const RECORD_FORM: crate::network_message::RecordForm = if cfg!(feature = "transport-stats") {
    crate::network_message::RecordForm::Owned
} else {
    crate::network_message::RecordForm::Lent
};
/// Without a lendable codec there is no record to lend.
#[cfg(all(
    feature = "codec-frame",
    not(feature = "session-slot"),
    not(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response"
    ))
))]
const RECORD_FORM: crate::network_message::RecordForm = crate::network_message::RecordForm::Owned;

/// How [`dispatch_datagram_reassembling`] hands over a lendable record of a
/// message it reassembled: as a `Frame`'s, except under `routing-namespace`,
/// whose copying path strips the namespace off the reassembled message's owned
/// outcome before the fan-out. A lent record has no owned outcome to strip, so
/// that build keeps the owned form here and the strip is not skipped.
#[cfg(all(feature = "reassembly", feature = "alloc"))]
const REASSEMBLED_RECORD_FORM: crate::network_message::RecordForm =
    if cfg!(feature = "routing-namespace") {
        crate::network_message::RecordForm::Owned
    } else {
        RECORD_FORM
    };
#[cfg(all(feature = "reassembly", not(feature = "alloc")))]
const REASSEMBLED_RECORD_FORM: crate::network_message::RecordForm = RECORD_FORM;

/// Dispatch one inbound datagram that the link LENDS, where it lies, and hand
/// every event to `on_event` as it happens.
///
/// The receive path of the fixed-memory MCU profile. [`dispatch_link_event`]
/// takes the datagram as an owned [`RxFrame`](crate::link::RxFrame), so a link
/// that holds it in its own buffer copies it onto the heap first; the `Frame`
/// arm then copies the payload out of that copy (an owned unit's sub-range is
/// a copy) and decodes every record of it into a list whose length the peer
/// chose, before the application sees the first one. Here the unit is borrowed
/// for the length of the call, the payload is read where it lies, and the
/// records are decoded and dispatched one at a time
/// (`network_message::for_each_record`), in wire order:
///
/// - a Push, a Request or a Response is decoded where the payload lies and
///   lent as the [`InPlace` event](crate::driver_loop::IterationEvent::InPlace):
///   its keyexpr, extensions and body are ranges of the datagram, and nothing
///   is built on the heap for it (ARCHITECTURE section 9.2). The subscriber
///   registry delivers a Push as a borrowed sample, the queryable registry a
///   Request as a borrowed query, the reply registry a Response as a borrowed
///   reply;
/// - any other record is decoded into its owned message in `record`, a
///   one-record buffer the caller keeps across datagrams, and reported as a
///   [`DriverLoopOutcome::FramePayload`] of that one message.
///
/// Every event carries the frame's own SN, reliability and priority; a frame
/// that carries no record is reported as one `FramePayload` with none, as the
/// copying path reports it.
///
/// Only a unit that BEGINS with an admissible `Frame` takes that path, and only
/// on a session that reads its units as they arrive; on an established lean
/// lowlatency session, a unit that is a bare network message batch is read the
/// same way, the whole unit being the batch ([`DatagramPath::LowLatencyInPlace`]).
/// Everything else is the copying path, unchanged and owned, and is answered as
/// [`DatagramPath::Copied`] with its [`CopyReason`]: a handshake, KeepAlive,
/// Close or Fragment at the front (whose state changes, residue parking and
/// reassembly hand-off are [`dispatch_link_event`]'s;
/// [`dispatch_datagram_reassembling`] reads a Fragment in place), a `Frame`
/// whose own extension chain must be refused (the FSM's `framing.error` arm is
/// there), and a compressed batch. A `Frame` consumes the rest of its unit, so
/// the path leaves nothing to park.
///
/// One difference from the copying path is deliberate: when a record does not
/// decode, or carries an extension a participant must refuse, the records
/// before it have already been dispatched, and then the FSM takes
/// `framing.error` and the error is reported, where the copying path refuses
/// the whole frame first. That is zenoh-pico's receive loop
/// (`src/transport/unicast/rx.c` @ `// Handle all the zenoh message, one by one`);
/// the copying path is upstream zenoh's, which decodes a frame's messages into
/// one list before it handles any.
///
/// Whatever the path, `on_event` runs inside the link's lend, so what it does
/// is on the stack above the receive; a profile measures that before it
/// selects this path.
#[cfg(feature = "codec-frame")]
pub fn dispatch_datagram<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> DatagramPath {
    let (path, used) = dispatch_datagram_unit(unit, actions, engine, record, on_event);
    // A datagram that holds more than one message: the heap profile parks what
    // follows the first (`dispatch_pending` reads it next turn), and a build with no
    // allocator reads the rest where the datagram lies, a message at a time, as
    // upstream's batch walk does.
    #[cfg(not(feature = "alloc"))]
    {
        let mut at = used;
        while at > 0 && at < unit.len() {
            let (_, used) = dispatch_datagram_unit(&unit[at..], actions, engine, record, on_event);
            at = if used == 0 { unit.len() } else { at + used };
        }
    }
    #[cfg(feature = "alloc")]
    let _ = used;
    path
}

/// [`dispatch_datagram`] for the unit at the front of `unit`: which path it took, and
/// how many bytes of `unit` that unit was. A `Frame`, a `Fragment` and a lean batch
/// consume what is left of the datagram by construction; a handshake message,
/// a KeepAlive or a Close consume their own length, which a build with no allocator
/// reads and goes on from.
#[cfg(feature = "codec-frame")]
fn dispatch_datagram_unit<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> (DatagramPath, usize) {
    match in_place_unit(unit, actions, false) {
        Ok(InPlaceUnit::Frame(head, payload_at)) => (
            frame_in_place(unit, head, payload_at, actions, engine, record, on_event),
            unit.len(),
        ),
        // Not produced when fragments are not asked for; were it, a path with
        // no Router to stage it into copies it, which is the answer below.
        #[cfg(feature = "reassembly")]
        Ok(InPlaceUnit::Fragment(..)) => {
            dispatch_copied(unit, CopyReason::Fragment, actions, engine, on_event)
        }
        #[cfg(feature = "transport-lowlatency")]
        Ok(InPlaceUnit::Lean) => (
            lean_in_place(unit, actions, engine, record, on_event),
            unit.len(),
        ),
        Err(reason) => dispatch_copied(unit, reason, actions, engine, on_event),
    }
}

/// [`dispatch_datagram`] for a session that reassembles: the same path for
/// every unit, and a `Fragment` is read where it lies too, its payload staged
/// into its chain's slot in `reasm` straight from the unit. ARCHITECTURE
/// section 9.3 allows that one copy and this path makes no other:
///
/// - the head (SN, extension chain, R and M bits) is decoded where the unit
///   lies, and its chain is kept as header bytes, so reading it allocates
///   nothing;
/// - the fragment passes the gates the copying path's `Fragment` arm runs, in
///   its order: a prioritized fragment on a session that negotiated no QoS is
///   link-fatal, and a stale, duplicate or reordered SN is dropped and clears
///   its channel's chain (the dbuf-clear [`report_outcome_reassembling`] makes);
/// - it is reported to `on_event` as [`IterationEvent::InPlaceFragment`], a
///   borrowed descriptor of the unit and where its payload starts, in place of
///   the copying path's `Poll(Fragment)`, whose payload is an owned copy;
/// - its payload goes to the Router, which copies it into the chain's slot;
/// - a chain it completes is read IN ITS SLOT, borrowed for the delivery call,
///   record by record as a `Frame`'s payload is: a Push is lent where the slot
///   holds it, any other record decoded into `record`. The copying path decodes
///   the whole message into a list first, out of a copy of the slot.
///
/// Every other unit takes the path [`dispatch_datagram`] takes, and every
/// `Poll` it reports goes through [`report_outcome_reassembling`], as the
/// copying loop's outcomes do, so an SN rejection on a `Frame` clears its
/// channel's chain too.
///
/// One difference from the copying path is deliberate, and it is the frame
/// path's: a completed message's records are dispatched as they are decoded, so
/// a record that does not decode is reported after the records before it. The
/// copying path refuses the whole reassembled message first. Neither takes
/// `framing.error` for a reassembled message that does not decode; both report
/// the error and drop it, as upstream drops a reassembled message it cannot
/// read.
#[cfg(feature = "reassembly")]
pub fn dispatch_datagram_reassembling<R, T, const SLOTS: usize, const CAP: usize, S>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    now_ms: u64,
    on_event: &mut dyn FnMut(IterationEvent<'_>),
) -> DatagramPath
where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
{
    let (path, used) =
        dispatch_datagram_reassembling_unit(unit, actions, engine, record, reasm, now_ms, on_event);
    // The rest of a datagram that holds more than one message, as
    // [`dispatch_datagram`] reads it.
    #[cfg(not(feature = "alloc"))]
    {
        let mut at = used;
        while at > 0 && at < unit.len() {
            let (_, used) = dispatch_datagram_reassembling_unit(
                &unit[at..],
                actions,
                engine,
                record,
                reasm,
                now_ms,
                on_event,
            );
            at = if used == 0 { unit.len() } else { at + used };
        }
    }
    #[cfg(feature = "alloc")]
    let _ = used;
    path
}

/// [`dispatch_datagram_reassembling`] for the unit at the front of `unit`, with the
/// number of bytes of `unit` it was.
#[cfg(feature = "reassembly")]
fn dispatch_datagram_reassembling_unit<R, T, const SLOTS: usize, const CAP: usize, S>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    now_ms: u64,
    on_event: &mut dyn FnMut(IterationEvent<'_>),
) -> (DatagramPath, usize)
where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
{
    match in_place_unit(unit, actions, true) {
        Ok(InPlaceUnit::Fragment(head, payload_at)) => (
            fragment_in_place(
                unit, head, payload_at, actions, engine, record, reasm, now_ms, on_event,
            ),
            unit.len(),
        ),
        Ok(InPlaceUnit::Frame(head, payload_at)) => (
            frame_in_place(
                unit,
                head,
                payload_at,
                actions,
                engine,
                record,
                &mut through_hand_off(reasm, actions, now_ms, on_event),
            ),
            unit.len(),
        ),
        #[cfg(feature = "transport-lowlatency")]
        Ok(InPlaceUnit::Lean) => (
            lean_in_place(
                unit,
                actions,
                engine,
                record,
                &mut through_hand_off(reasm, actions, now_ms, on_event),
            ),
            unit.len(),
        ),
        Err(reason) => dispatch_copied(
            unit,
            reason,
            actions,
            engine,
            &mut through_hand_off(reasm, actions, now_ms, on_event),
        ),
    }
}

/// `on_event` with every `Poll` passed through [`report_outcome_reassembling`]
/// on its way, as the copying loop reports its outcomes.
#[cfg(feature = "reassembly")]
fn through_hand_off<'a, R, T, const SLOTS: usize, const CAP: usize, S>(
    reasm: &'a mut ReassemblyDispatcher<SLOTS, CAP, S>,
    actions: &'a SessionLinkActions<R, T>,
    now_ms: u64,
    on_event: &'a mut dyn FnMut(IterationEvent<'_>),
) -> impl FnMut(IterationEvent<'_>) + 'a
where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
{
    move |event: IterationEvent<'_>| match event {
        IterationEvent::Poll(outcome) => {
            report_outcome_reassembling(outcome, reasm, actions, now_ms, &mut *on_event)
        }
        other => on_event(other),
    }
}

/// The copying path for a unit [`dispatch_datagram`] does not read in place:
/// the unit copied onto the heap and dispatched by [`dispatch_link_event`].
#[cfg(feature = "codec-frame")]
// Out of line: it is the path of a handshake, a KeepAlive and a Close and of the units that are not
// read as a Frame, which is not the path of the traffic. Inlined into the dispatch of a unit, the
// decode of a handshake body and its extension chain (a few KB of arrays) is part of the frame of
// every Frame the session receives.
#[inline(never)]
fn dispatch_copied<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    reason: CopyReason,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> (DatagramPath, usize) {
    // Fixed-memory step S5 — under `session-slot` a handshake, a KeepAlive or a
    // Close is dispatched where the link holds it, by the copying path's own
    // code over bytes that are only borrowed (`dispatch_unit_borrowed`), and the
    // decode of it holds its body and its extension chain in arrays: a session
    // is established and closed without a heap. The path is still the copying
    // path's, and the unit is still counted as one that was not read as a Frame
    // (`CopyReason::NotAFrame`), because what it does with the message is the
    // same; what it no longer does is copy the unit onto the heap first.
    #[cfg(all(feature = "session-slot", feature = "alloc"))]
    if matches!(reason, CopyReason::NotAFrame) {
        account_bytes_in_place(unit, actions);
        let outcome = dispatch_unit_borrowed(unit, actions, engine);
        on_event(crate::driver_loop::IterationEvent::Poll(&outcome));
        return (DatagramPath::Copied(reason), unit.len());
    }
    // A build with no allocator has no copying path: whatever the reason the unit
    // was not read as a `Frame` (a handshake, a KeepAlive, a Close, and also a unit
    // whose frame head did not decode, an extension chain it refused, a compressed
    // batch or a fragment with no Router), it is read where the link holds it by the
    // one dispatch of a unit, which has no arm for a `Frame` or a `Fragment` and so
    // answers those with the framing error the copying path's parse failure
    // gave, and tells the datagram's reader where the message ended.
    #[cfg(not(feature = "alloc"))]
    {
        account_bytes_in_place(unit, actions);
        let mut consumed = unit.len();
        let outcome = dispatch_unit_borrowed(unit, &mut consumed, actions, engine);
        on_event(crate::driver_loop::IterationEvent::Poll(&outcome));
        (DatagramPath::Copied(reason), consumed)
    }
    #[cfg(feature = "alloc")]
    {
        let frame = crate::link::RxFrame::new(alloc::vec::Vec::from(unit));
        on_event(crate::driver_loop::IterationEvent::Poll(
            &dispatch_link_event(LinkEvent::Rx(frame), actions, engine),
        ));
        (DatagramPath::Copied(reason), unit.len())
    }
}

/// The accounting `dispatch_link_event` and `dispatch_unit` do for a unit and
/// the one transport message decoded off its front, for a unit read in place.
#[cfg(feature = "codec-frame")]
fn account_unit_in_place<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
) {
    account_bytes_in_place(unit, actions);
    #[cfg(feature = "transport-stats")]
    count_rx_transport_message(actions);
}

/// The accounting `dispatch_link_event` does for a unit's bytes, the on-the-wire
/// total, before anything is decoded out of it.
#[cfg(feature = "codec-frame")]
fn account_bytes_in_place<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
) {
    #[cfg(feature = "transport-stats")]
    {
        actions.stats.inc_rx(unit.len());
        let bytes = unit.len() as u64;
        actions.record_on_link(&actions.link, |metrics, slot| {
            metrics.inc_bytes(crate::stats_registry::StatsDirection::Rx, slot, bytes)
        });
    }
    #[cfg(not(feature = "transport-stats"))]
    let _ = (unit, actions);
}

/// transport-lowlatency — a lean unit read where it lies: the whole unit is a
/// bare network message batch, walked record by record as a `Frame`'s payload
/// is ([`walk_records_in_place`]), every event carrying what the copying lean
/// path's `FramePayload` carries (reliable, SN 0, the DEFAULT band, no chain:
/// the lean wire has no envelope, no SN and no per-priority conduit).
///
/// What the copying lean path does, kept: no SN gate (lowlatency tracks no
/// SN), the unit's bytes counted first and the one transport message counted
/// once the batch has been read, and a batch that does not decode raised as
/// `framing.error`. What differs is the frame path's difference: records before
/// a bad one have been dispatched when it is reported.
#[cfg(feature = "transport-lowlatency")]
fn lean_in_place<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> DatagramPath {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    account_bytes_in_place(unit, actions);
    let carrier = RecordCarrier {
        reliable: true,
        sn: 0,
        priority: crate::qos::Priority::DEFAULT,
        #[cfg(feature = "alloc")]
        has_ext: false,
    };
    let walked = walk_records_in_place(
        unit,
        carrier,
        #[cfg(feature = "alloc")]
        &mut || Ok(alloc::vec::Vec::new()),
        RECORD_FORM,
        RecordSource::Frame,
        actions,
        record,
        on_event,
    );
    match walked {
        // R2825 — a lean datagram is ONE transport message whatever it
        // carries, which is how upstream's lowlatency rx counts it.
        #[cfg(feature = "transport-stats")]
        Ok(()) => count_rx_transport_message(actions),
        #[cfg(not(feature = "transport-stats"))]
        Ok(()) => {}
        Err(parse_err) => {
            engine.process_event(E::FramingError);
            on_event(crate::driver_loop::IterationEvent::Poll(
                &DriverLoopOutcome::ParseError(parse_err),
            ));
        }
    }
    DatagramPath::LowLatencyInPlace
}

/// The admissible `Frame` at the front of a unit, read where it lies.
#[cfg(feature = "codec-frame")]
fn frame_in_place<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    head: crate::inbound::FrameHead<crate::inbound::InPlaceExtChain>,
    payload_at: usize,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> DatagramPath {
    use crate::driver_loop::IterationEvent;
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    account_unit_in_place(unit, actions);
    actions.stamp_rx_activity();
    let priority = head.priority();
    let crate::inbound::FrameHead {
        reliable,
        sn,
        #[cfg(feature = "alloc")]
        has_ext,
        chain,
        ..
    } = head;
    // The frame's own chain is owned only for an owned record (the heap profile's).
    #[cfg(not(feature = "alloc"))]
    let _ = chain;
    if let Some(refused) = refuse_frame(actions, engine, priority, reliable, sn) {
        on_event(IterationEvent::Poll(&refused));
        return DatagramPath::InPlace;
    }
    let carrier = RecordCarrier {
        reliable,
        sn,
        priority,
        #[cfg(feature = "alloc")]
        has_ext,
    };
    // The frame's own chain is handed over owned only with an owned record:
    // a frame whose every record is lent never owns it.
    let walked = walk_records_in_place(
        &unit[payload_at..],
        carrier,
        #[cfg(feature = "alloc")]
        &mut || chain.owned(unit, payload_at),
        RECORD_FORM,
        RecordSource::Frame,
        actions,
        record,
        on_event,
    );
    if let Err(parse_err) = walked {
        engine.process_event(E::FramingError);
        on_event(IterationEvent::Poll(&DriverLoopOutcome::ParseError(
            parse_err,
        )));
    }
    DatagramPath::InPlace
}

/// What every event of a record walk reports of the message the records came
/// in: a `Frame`'s own SN, reliability and priority, and whether it carried an
/// extension chain, or those of the fragment that completed a reassembled one.
#[cfg(feature = "codec-frame")]
#[derive(Clone, Copy)]
struct RecordCarrier {
    reliable: bool,
    sn: u64,
    priority: crate::qos::Priority,
    /// Read only into an owned outcome, which the heap profile alone delivers.
    #[cfg(feature = "alloc")]
    has_ext: bool,
}

/// Where a walk's records came from, which decides the two things the copying
/// paths do differently for the two: a `Frame`'s messages are counted
/// (`transport-stats`), a reassembled message's are stripped of the routing
/// namespace (`routing-namespace`), each as its copying path does it.
#[cfg(feature = "codec-frame")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordSource {
    Frame,
    #[cfg(feature = "reassembly")]
    Reassembled,
}

/// Put the one owned record of a walk into the outcome that reports it. A
/// growable record buffer and the outcome's list trade places, so the buffer's one
/// slot is reused for every record and nothing is allocated here; a fixed buffer
/// has no slot to hand over, so the message is moved into the list (which keeps
/// its room for the rest of the walk's records).
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    not(feature = "bounded-heapless")
))]
fn hand_record_to(
    messages: &mut alloc::vec::Vec<crate::network_message::NetworkMessage>,
    one: &mut crate::network_message::RecordBuf,
) {
    core::mem::swap(messages, one);
}

/// See the growable form. The record buffer holds one message, so the move is one
/// `pop`.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "bounded-heapless"
))]
fn hand_record_to(
    messages: &mut alloc::vec::Vec<crate::network_message::NetworkMessage>,
    one: &mut crate::network_message::RecordBuf,
) {
    while let Some(message) = one.pop() {
        messages.push(message);
    }
}

/// Undo [`hand_record_to`] once the outcome has been reported, so the walk's next
/// decode finds its record buffer as it left it: empty, and with its slot.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    not(feature = "bounded-heapless")
))]
fn take_record_back(
    messages: &mut alloc::vec::Vec<crate::network_message::NetworkMessage>,
    one: &mut crate::network_message::RecordBuf,
) {
    core::mem::swap(messages, one);
}

/// See the growable form: the fixed buffer was emptied by the hand-over, so what
/// is left to do is to drop the reported message and keep the list's room.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "bounded-heapless"
))]
fn take_record_back(
    messages: &mut alloc::vec::Vec<crate::network_message::NetworkMessage>,
    _one: &mut crate::network_message::RecordBuf,
) {
    messages.clear();
}

/// Decode `payload`'s records one at a time where they lie and hand each to
/// `on_event` before the next is decoded: a Push lent (`form` permitting) as
/// [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace), any
/// other record as a `Poll(FramePayload)` of the one owned message, decoded
/// into `record`. A payload with no record is reported as one `FramePayload`
/// with none, as the copying paths report it.
///
/// `extensions` yields the carrier's own chain, owned; it is asked once, and
/// only when an owned outcome is built. An error, from a record or from the
/// chain, ends the walk after the records before it were handed over.
#[cfg(feature = "codec-frame")]
#[allow(clippy::too_many_arguments)]
fn walk_records_in_place<R: SessionRuntime, T: TimeSource>(
    payload: &[u8],
    carrier: RecordCarrier,
    #[cfg(feature = "alloc")] extensions: &mut dyn FnMut() -> Result<
        alloc::vec::Vec<wz_codecs::ext_entry::ExtEntryOwned>,
        crate::parse_error::InboundParseError,
    >,
    form: crate::network_message::RecordForm,
    source: RecordSource,
    actions: &SessionLinkActions<R, T>,
    record: &mut crate::network_message::RecordBuf,
    on_event: &mut dyn FnMut(crate::driver_loop::IterationEvent<'_>),
) -> Result<(), crate::parse_error::InboundParseError> {
    use crate::driver_loop::IterationEvent;
    #[cfg(feature = "alloc")]
    use crate::network_message::WalkedRecord;
    #[cfg(feature = "alloc")]
    let RecordCarrier {
        reliable,
        sn,
        priority,
        has_ext,
    } = carrier;
    // A build with no allocator delivers no owned outcome, so it has no use for the
    // frame's own extension flag, for where the walk came from, or for the session
    // (each of the lent arms below is handed what it needs by the record).
    #[cfg(not(feature = "alloc"))]
    let RecordCarrier {
        reliable,
        sn,
        priority,
    } = carrier;
    #[cfg(not(feature = "alloc"))]
    let _ = (source, actions);
    #[cfg(feature = "alloc")]
    let empty = |extensions| DriverLoopOutcome::FramePayload {
        reliable,
        sn,
        messages: alloc::vec::Vec::new(),
        has_ext,
        extensions,
        priority,
    };
    #[cfg(feature = "alloc")]
    let mut outcome: Option<DriverLoopOutcome> = None;
    let mut dispatched = false;
    crate::network_message::try_for_each_record(payload, record, form, |one| {
        // A build with no allocator walks no owned record: every one is lent.
        #[cfg(all(
            not(feature = "alloc"),
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "session-slot"
            )
        ))]
        crate::driver_loop::report_lent_record(one, reliable, sn, priority, on_event);
        // ... and one with no allocator and no lent kind walks no record at all.
        #[cfg(all(
            not(feature = "alloc"),
            not(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "session-slot"
            ))
        ))]
        let _ = one;
        #[cfg(feature = "alloc")]
        match one {
            WalkedRecord::Owned(one) => {
                let outcome = match &mut outcome {
                    Some(outcome) => outcome,
                    None => outcome.insert(empty(extensions()?)),
                };
                if let DriverLoopOutcome::FramePayload { messages, .. } = outcome {
                    hand_record_to(messages, one);
                    if source == RecordSource::Frame {
                        *messages = count_rx_network_messages(actions, core::mem::take(messages));
                    }
                }
                // The reassembled message's copying path strips the namespace
                // off its outcome before the fan-out; so does this one.
                #[cfg(all(feature = "reassembly", feature = "routing-namespace"))]
                if source == RecordSource::Reassembled {
                    actions.apply_namespace_ingress(outcome);
                }
                on_event(IterationEvent::Poll(outcome));
                if let DriverLoopOutcome::FramePayload { messages, .. } = outcome {
                    take_record_back(messages, one);
                }
            }
            // Every lent kind becomes its in-place event in the one place that makes
            // them, shared with the multicast receive path.
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "session-slot"
            ))]
            lent => crate::driver_loop::report_lent_record(lent, reliable, sn, priority, on_event),
        }
        dispatched = true;
        Ok(())
    })?;
    if !dispatched {
        #[cfg(feature = "alloc")]
        on_event(IterationEvent::Poll(&empty(extensions()?)));
        // A frame with no record to deliver is a frame the session read and has
        // nothing to hand on; the heap profile's empty batch, without the batch.
        #[cfg(not(feature = "alloc"))]
        on_event(IterationEvent::Poll(&DriverLoopOutcome::EmptyFrame {
            reliable,
            sn,
            priority,
        }));
    }
    Ok(())
}

/// The admissible `Fragment` at the front of a unit, staged into its chain's
/// slot from where it lies ([`dispatch_datagram_reassembling`]).
#[cfg(feature = "reassembly")]
#[allow(clippy::too_many_arguments)]
fn fragment_in_place<R, T, const SLOTS: usize, const CAP: usize, S>(
    unit: &[u8],
    head: crate::inbound::FragmentHead<crate::inbound::InPlaceExtChain>,
    payload_at: usize,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    record: &mut crate::network_message::RecordBuf,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    now_ms: u64,
    on_event: &mut dyn FnMut(IterationEvent<'_>),
) -> DatagramPath
where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
{
    account_unit_in_place(unit, actions);
    actions.stamp_rx_activity();
    let priority = head.priority();
    let markers = head.markers();
    let crate::inbound::FragmentHead {
        reliable,
        sn,
        more,
        has_ext,
        ..
    } = head;
    // The copying `Fragment` arm's two gates, in its order; an SN rejection
    // reaches the hand-off, which clears the channel's chain.
    if let Some(refused) = refuse_frame(actions, engine, priority, reliable, sn) {
        report_outcome_reassembling(&refused, reasm, actions, now_ms, &mut *on_event);
        return DatagramPath::FragmentInPlace;
    }
    on_event(IterationEvent::InPlaceFragment(
        crate::driver_loop::InPlaceFragment::new(
            unit, payload_at, reliable, sn, more, has_ext, priority, markers,
        ),
    ));
    // Armed from the negotiated patch level, as the copying hand-off arms it,
    // and bounded by the session's configuration the same way.
    reasm.set_fragmentation_markers(actions.fragmentation_markers_negotiated());
    reasm.set_max_message_bytes(actions.params.link_rx.max_message_size);
    let sn_mask = actions.negotiated_sn_mask();
    // The chain key's peer half, copied out of the session's slot first: the
    // Router delivers a completed chain from inside the ingest, and what the
    // delivery dispatches must not run under that slot's lock. The Router keys
    // a chain on at most this many bytes of it.
    let mut peer = [0u8; crate::reassembly_dispatch::PEER_KEY_MAX];
    let peer_len = R::with_mutex_mut(&actions.inbound_peer_zid, |zid_slot| {
        let zid: &[u8] = zid_slot.as_deref().unwrap_or(&[]);
        let n = zid.len().min(peer.len());
        peer[..n].copy_from_slice(&zid[..n]);
        n
    });
    let mut dropped_by_decode = None;
    let ingest_outcome = reasm.ingest(
        ReassemblyFragment {
            peer_key: &peer[..peer_len],
            reliable,
            sn,
            more: u8::from(more),
            payload: &unit[payload_at..],
            priority,
            markers,
        },
        sn_mask,
        now_ms,
        |message| {
            // ARCHITECTURE section 9.3: the completed message is read in the
            // slot its fragments were staged into, borrowed for this call.
            let carrier = RecordCarrier {
                reliable,
                sn,
                priority,
                #[cfg(feature = "alloc")]
                has_ext: false,
            };
            dropped_by_decode = walk_records_in_place(
                message,
                carrier,
                #[cfg(feature = "alloc")]
                &mut || Ok(alloc::vec::Vec::new()),
                REASSEMBLED_RECORD_FORM,
                RecordSource::Reassembled,
                actions,
                record,
                &mut *on_event,
            )
            .err();
        },
    );
    // A reassembled message that does not decode is reported and dropped; the
    // session goes on, as on the copying path.
    if let Some(parse_err) = dropped_by_decode {
        on_event(IterationEvent::Poll(&DriverLoopOutcome::ParseError(
            parse_err,
        )));
    }
    if let Some(reason) = ReassemblyDropReason::from_ingest(ingest_outcome) {
        on_event(IterationEvent::ReassemblyDropped(reason));
    }
    DatagramPath::FragmentInPlace
}

/// What the in-place receive path reads at the front of a unit: an admissible
/// `Frame`, or (on a path that reassembles) an admissible `Fragment`, each
/// decoded up to its payload, with the offset at which the payload starts; or,
/// on a lean lowlatency session, a unit that is a batch from its first byte.
#[cfg(feature = "codec-frame")]
enum InPlaceUnit {
    Frame(
        crate::inbound::FrameHead<crate::inbound::InPlaceExtChain>,
        usize,
    ),
    #[cfg(feature = "reassembly")]
    Fragment(
        crate::inbound::FragmentHead<crate::inbound::InPlaceExtChain>,
        usize,
    ),
    /// A lean lowlatency unit: the whole unit is the batch.
    #[cfg(feature = "transport-lowlatency")]
    Lean,
}

/// The unit at `unit`'s front when [`dispatch_datagram`] may read it where it
/// lies, a `Fragment` only when `fragments` asks for one (a path that holds a
/// Router to stage it into); otherwise why the unit goes down the copying path.
/// A head that does not decode is also the copying path's: it decodes it again
/// and reports the error the way it always has.
#[cfg(feature = "codec-frame")]
fn in_place_unit<R: SessionRuntime, T: TimeSource>(
    unit: &[u8],
    actions: &SessionLinkActions<R, T>,
    fragments: bool,
) -> Result<InPlaceUnit, CopyReason> {
    use crate::ext_admit::ExtAdmission;
    // The compressed batch is un-wrapped into a buffer of its own: the copying
    // path's.
    #[cfg(feature = "transport-compression")]
    if actions.compresses_batches() {
        return Err(CopyReason::Compressed);
    }
    #[cfg(feature = "transport-lowlatency")]
    if actions.is_lowlatency() && actions.is_established() {
        // The lean transport frames nothing: a unit is a bare network message
        // batch, read in place, or a KeepAlive / Close, which the copying path
        // decodes as it does on any session.
        return if is_lean_network_unit(unit) {
            Ok(InPlaceUnit::Lean)
        } else {
            Err(CopyReason::NotAFrame)
        };
    }
    #[cfg(not(any(feature = "transport-compression", feature = "transport-lowlatency")))]
    let _ = actions;
    if let Some(head) = crate::inbound::parse_frame_in_place(unit) {
        let (head, payload_at) = head.map_err(|_| CopyReason::FrameHeadUndecodable)?;
        return match head.ext_admission() {
            ExtAdmission::Admissible => Ok(InPlaceUnit::Frame(head, payload_at)),
            _ => Err(CopyReason::FrameExtRefused),
        };
    }
    #[cfg(feature = "reassembly")]
    if fragments {
        if let Some(head) = crate::inbound::parse_fragment_in_place(unit) {
            let (head, payload_at) = head.map_err(|_| CopyReason::FragmentHeadUndecodable)?;
            return match head.ext_admission() {
                ExtAdmission::Admissible => Ok(InPlaceUnit::Fragment(head, payload_at)),
                _ => Err(CopyReason::FragmentExtRefused),
            };
        }
    }
    #[cfg(not(feature = "reassembly"))]
    let _ = fragments;
    let fragment = unit.first().map(|h| h & 0x1F) == Some(wz_codecs::wire_const::T_MID_FRAGMENT);
    Err(if fragment {
        CopyReason::Fragment
    } else {
        CopyReason::NotAFrame
    })
}
/// R77/R84 — compare the session's lease baseline against `params.lease` and
/// inject `SessionFsmUnicastEvent::LeaseExpired` when the window has elapsed,
/// so the session-fsm `lease.expired -> Closing(Expired)` transition fires.
/// Generic over `R: SessionRuntime` so the AP tokio loop and the lwIP MCU sync
/// loop share one lease comparator (Stage 4 SSOT). The two baseline stamps are
/// read through `R::with_mutex_mut` — the AP `std::sync::Mutex` and the MCU
/// `critical_section` mutex behind one seam; the reads are SEQUENTIAL, never
/// nested, so the non-reentrant MCU mutex is safe.
///
/// Baseline (R84) = `max(established_at, last_inbound_at)`: the RX-activity
/// stamp resets the window on EVERY successfully parsed inbound message
/// (R311la — zenoh-pico `_received` parity, unicast/rx.c:88; the former
/// KeepAlive-only stamp expired sustained data-only flows), the established
/// stamp covers the pre-first-inbound window so the lease has a defined start
/// at Established entry (session-fsm §2.5). Both `None` -> `NoBaseline` (no
/// FSM mutation).
///
/// `now_ms` is parameterised for test determinism; production callers pass
/// `clock.now_monotonic_ms()` (the same epoch [`SessionLinkActions::clock`]
/// carries). `params.lease_ms` is milliseconds by contract (R311ku —
/// the wire unit is an encode/decode boundary concern, `crate::lease`),
/// matching the `u64` ms scale of the stamps (R294).
///
/// R311kv — the governing window is `min(local, peer-advertised)`:
/// zenoh-pico adopts `min(open._lease, Z_TRANSPORT_LEASE)` when the
/// peer's OPEN arrives (unicast/transport.c:193/269) and expires the
/// session by it (unicast/lease.c:147). The same min(advertised,
/// local-cap) shape the multicast per-peer sweep applies (R311ks);
/// pre-OPEN (`peer_open_lease_ms` empty) the local window governs alone.
///
/// The check is the session FSM's lease monitor, so it runs only while the
/// machine has it started (`start_lease_monitor` on `Established` entry,
/// `stop_lease_monitor` on its exit): otherwise it answers
/// [`LeaseCheckOutcome::NotMonitored`] and raises nothing.
pub fn check_lease_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    now_ms: u64,
) -> LeaseCheckOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    if !R::with_mutex_mut(&actions.link.lease_armed, |armed| *armed) {
        return LeaseCheckOutcome::NotMonitored;
    }
    // R311kx — deadline arithmetic shared with the loop wake computation
    // (`lease_wake_deadline`): `deadline = baseline + adopted window`, so
    // "the wake fired" and "the window elapsed" cannot drift apart.
    match lease_wake_deadline(actions) {
        None => LeaseCheckOutcome::NoBaseline,
        Some(deadline_ms) if now_ms >= deadline_ms => {
            engine.process_event(E::LeaseExpired);
            LeaseCheckOutcome::Expired
        }
        Some(_) => LeaseCheckOutcome::WithinLease,
    }
}

/// R2678 (`session-close-ingress`) — drain a standing close request and inject
/// `SessionFsmUnicastEvent::SessionClose`, so the session-fsm
/// `session.close -> Closing` transition fires.
///
/// The peer of [`check_lease_deadline`], and deliberately the same shape: a
/// comparator that reads a fact off the shared [`SessionLinkActions`] and
/// raises on the engine the caller owns. Generic over `R: SessionRuntime` for
/// the same reason — the AP tokio loop and the MCU sync loop call this one
/// function, so "a rail message can close a session" means the same thing on
/// both profiles rather than being an AP-only verb.
///
/// Returns whether an event was raised, so a caller can tell "nobody asked"
/// from "asked, and the machine has been told". Draining is take-once
/// ([`SessionLinkActions::take_requested_close`]): the request is consumed here
/// and a later iteration will not re-raise it.
///
/// ⚠ This does NOT wait for the close to complete. `SessionClose` is an input
/// to the machine; the session reaches `Closed` through the ordinary Closing
/// path (the goodbye frame, `ClosingTimeout`, the terminal outcome the loop
/// already returns). A caller that wants to observe the effect must observe the
/// SESSION, not this function's return — which is also why the ingress carries
/// no reply channel: upstream's own admin handler is a Push primitive with no
/// response path, so success is observable as an effect or not at all.
#[cfg(feature = "session-close-ingress")]
pub fn check_requested_close<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> bool {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    if actions.take_requested_close() {
        engine.process_event(E::SessionClose);
        true
    } else {
        false
    }
}

/// R2922 — raise, as FSM events, every request staged on the session's
/// `OutOfBand` slot: what the session was asked from outside its drive loop.
/// Both drive loops call this at the head of every iteration — the AP tokio
/// loop (`wz_runtime_tokio::session_glue`) and the cooperative MCU pump
/// (`wz_runtime_coop::session_drive`) — and the AP loop also parks on
/// `OutOfBand::signalled`, so a request reaches a loop that is waiting on its
/// link.
///
/// R2922 is also a CORRECTION of [`check_requested_close`]'s own doc, which
/// said both loops called it. Neither did: only tests standing in for the
/// loop called it, so a rail close was staged and never raised on a running
/// session. This is the call the loops make.
///
/// Returns whether an event was raised.
pub fn check_out_of_band<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> bool {
    #[cfg(feature = "session-close-ingress")]
    if check_requested_close(actions, engine) {
        return true;
    }
    // R2923 — a sender's blocking message found no room in `wait_before_close`:
    // the statechart's `tx.congestion.exhaust -> Closing` with
    // `set_close_reason_unresponsive`, which nothing raised before.
    if actions.take_congestion_close() {
        use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
        engine.process_event(E::TxCongestionExhaust);
        return true;
    }
    false
}

/// R2678 (`session-close-ingress`) — the switchboard ingress for session
/// lifetime: an [`crate::switchboard::EventInjector`] that turns a matched row
/// into a close request on [`SessionLinkActions`] instead of into an engine
/// call.
//
// The link is spelled as a FULL PATH rather than `[`EventInjector`]`, which is
// what R2678 wrote and what took `wz-session-core` to 534 broken doc links
// against a budget of 533: the trait lives in `crate::switchboard` and nothing
// brings it into scope here, so the bare label resolved to nothing. The
// explicit-target form `[`EventInjector`](crate::switchboard::EventInjector)`
// would fix it too and is NOT chosen: it is the shape of all 16 `redundant
// explicit link target` errors already in this crate's budget, and it becomes
// one the moment anyone adds a `use` for the trait here.
///
/// This is what lets the session machine be a switchboard target without the
/// matcher and the engine ever being in scope together. Every other injector in
/// the tree wraps an SCE `Engine` (`wz-statechart-bridge`'s `EngineInjector`,
/// the generated per-machine ones); this one wraps the shared bundle, so the
/// keyexpr table, the matcher and the `EventInjector` port are all the ones
/// both profiles already share.
///
/// ⭐ It does NOT carry the event name as a literal. The name is asked of the
/// MACHINE — `StatePolicy::get_event_from_name` on the generated session
/// policy — so the mapping has exactly one definition, the generated one. A
/// second copy of `"session.close"` here is precisely the defect class that
/// open-debt item 777 records: a string agreed between two places by hand stays
/// agreed only until one of them is edited.
/// R2713 (`session-close-ingress` residual (a)) — who may close a session over
/// the rail.
///
/// A PORT rather than a call into the §5.16 policy kernel, and the direction is
/// forced rather than chosen: `wz-access-control` DEPENDS ON this crate (it
/// reads `keyexpr_includes_target` and `link::LinkSubject` from here), so a
/// call the other way is a cycle. Dependency inversion is the only shape that
/// leaves the gate where both profiles build it — which is the property this
/// atom asserts about every other piece of the close machinery, and a gate that
/// existed only in the AP runtime would withdraw it.
///
/// It is judged on the KEYEXPR because that is where the grammar puts the
/// target (`@/<zid>/<whatami>/session/<verb>/<peer-zid>`): "may close session X
/// only" is a statement about a key, which is exactly why the target was not
/// put in the payload. An AP host binds this to its §5.16 policy; an MCU host
/// binds a static one. Neither answer is reachable from here, and that is the
/// point.
///
/// ⚠ This does NOT replace the §5.16 ingress chain, which sees the face — the
/// subject zid, the link and the certificate name — and still runs upstream of
/// the switchboard on an AP host. It is the gate that cannot be FORGOTTEN: the
/// chain is wired by the host into the drive loop's stages, and a host that
/// never wires it leaves a destructive verb answered by a node no policy ever
/// consulted.
/// R2718 — the lifecycle grammar, PARSED:
/// `@/<zid>/<whatami>/session/<verb>/<peer-zid>`.
///
/// ⛔ UNTIL THIS TYPE, THE GRAMMAR WAS PROSE. It was written in the owner's
/// interface decision and repeated in the doc comment above, and MEASURED
/// before this was built: the literal appeared in exactly one doc comment and
/// in test strings, and in no code at all. A `close` row worked because the
/// switchboard PATTERN matched, and nothing ever read the key's structure.
///
/// That is why it has to exist rather than be a convenience. The whole reason
/// the target rides in the key is so "may close session X only" is expressible;
/// but an authority handed a raw `&str` must re-implement this grammar to say
/// which X, so every binder would carry its own copy and they would drift. One
/// definition, and both verbs read it.
///
/// It BORROWS the key rather than owning its parts: the caller already holds
/// the arriving keyexpr for the life of the call, and this crate is `no_std`
/// with `alloc` optional — a parse that allocated five `String`s per inbound
/// command would be the wrong shape for the MCU profile that shares it.
#[cfg(feature = "session-close-ingress")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleKey<'a> {
    /// The node the command addresses — the `<zid>` chunk.
    pub node_zid: &'a str,
    /// That node's role as the sender spelled it — the `<whatami>` chunk.
    pub whatami: &'a str,
    /// The verb: `close`, and later its siblings.
    pub verb: &'a str,
    /// The verb's argument, for the one verb that takes one: `reset`'s
    /// generation, `@/<zid>/<whatami>/session/reset/<generation>/<peer-zid>`
    /// (decision D6 of `docs/session-lifecycle-intent.md`). `None` for every
    /// other verb.
    pub argument: Option<&'a str>,
    /// WHICH session the verb acts on — the `<peer-zid>` chunk, and the reason
    /// the target is in the key instead of the payload.
    pub peer_zid: &'a str,
}

/// The verb whose key carries an argument, its generation (decision D6): a
/// reset is the one verb that is not idempotent by nature, so a duplicate is
/// told apart by the generation it carries.
#[cfg(feature = "session-close-ingress")]
pub const RESET_VERB: &str = "reset";

#[cfg(feature = "session-close-ingress")]
impl<'a> LifecycleKey<'a> {
    /// Parse an arriving keyexpr, or `None` when it is not a lifecycle key.
    ///
    /// Exactly six chunks, `@` first and the literal `session` fourth. A
    /// shorter, longer or differently-shaped key is NOT this grammar, and the
    /// caller refuses rather than guessing — a row's pattern may be a wildcard
    /// that matches keys this grammar does not describe, and admitting one
    /// would hand an authority a target it cannot have read.
    ///
    /// No chunk may be empty: `@//peer/session/close/x` names no node, and a
    /// blank target is the shape most likely to be read as "all of them".
    ///
    /// Decision D6 — `reset` alone takes one more chunk, its generation, between
    /// the verb and the target. Which verb takes an argument is the grammar's,
    /// not the caller's, so a seven-chunk key of any other verb is refused as
    /// one chunk long.
    pub fn parse(keyexpr: &'a str) -> Option<Self> {
        let mut chunks = keyexpr.split('/');
        let at = chunks.next()?;
        let node_zid = chunks.next()?;
        let whatami = chunks.next()?;
        let session = chunks.next()?;
        let verb = chunks.next()?;
        let argument = if verb == RESET_VERB {
            Some(chunks.next()?)
        } else {
            None
        };
        let peer_zid = chunks.next()?;
        if chunks.next().is_some() {
            return None;
        }
        if at != "@" || session != "session" {
            return None;
        }
        if node_zid.is_empty()
            || whatami.is_empty()
            || verb.is_empty()
            || peer_zid.is_empty()
            || argument.is_some_and(str::is_empty)
        {
            return None;
        }
        Some(Self {
            node_zid,
            whatami,
            verb,
            argument,
            peer_zid,
        })
    }
}

#[cfg(feature = "session-close-ingress")]
pub trait SessionLifecycleAuthority {
    /// Whether the close command this key carries may run.
    ///
    /// R2718 — takes the PARSED key, not the raw `&str` it used to. An
    /// authority's whole job is to answer about a target, and handing it a
    /// string obliged every binder to re-derive the grammar to find one.
    fn admits_close(&self, key: &LifecycleKey<'_>) -> bool;

    /// R2720 — whether the OPEN command this key carries may run.
    ///
    /// ⛔ DEFAULTED TO `false`, which is the only safe default and not a
    /// convenience: an authority written before this verb existed answered
    /// about closing and was never asked about opening, so reading its silence
    /// as consent would grant a capability nobody considered. Refusing is what
    /// its silence actually means.
    ///
    /// A SECOND METHOD rather than a `verb` parameter, because the two
    /// questions have different answers for the same target: "this peer's
    /// session may be torn down" and "this node may dial that peer" are not
    /// one permission, and a single predicate would make them impossible to
    /// separate in a policy.
    fn admits_open(&self, _key: &LifecycleKey<'_>) -> bool {
        false
    }

    /// Decision D6 — whether the RESET command this key carries may run: close
    /// the sessions with the peer once for the key's generation, leaving the
    /// peer in the node's intent so its machine connects again.
    ///
    /// Defaulted to `false` for the reason [`Self::admits_open`] is: an
    /// authority written before the verb existed was never asked about it. A
    /// third method rather than a reading of `admits_close`, because "this
    /// session may be torn down for good" and "this session may be cycled"
    /// are two permissions a policy can mean to grant apart.
    fn admits_reset(&self, _key: &LifecycleKey<'_>) -> bool {
        false
    }

    /// Decision D6 — whether the STATUS of the session this key names may be
    /// read: the sessions this node has with the peer and what its machines are
    /// doing for it.
    ///
    /// A read, and still refused by default for the reason [`Self::admits_open`]
    /// is: an authority written before the query existed never said who may learn
    /// which peers this node holds. A fourth method because reading a peer's state
    /// and changing it are permissions a policy can mean to grant apart.
    fn admits_status(&self, _key: &LifecycleKey<'_>) -> bool {
        false
    }
}

#[cfg(feature = "session-close-ingress")]
impl<A: SessionLifecycleAuthority + ?Sized> SessionLifecycleAuthority for &A {
    fn admits_close(&self, key: &LifecycleKey<'_>) -> bool {
        (**self).admits_close(key)
    }

    fn admits_open(&self, key: &LifecycleKey<'_>) -> bool {
        (**self).admits_open(key)
    }

    fn admits_reset(&self, key: &LifecycleKey<'_>) -> bool {
        (**self).admits_reset(key)
    }

    fn admits_status(&self, key: &LifecycleKey<'_>) -> bool {
        (**self).admits_status(key)
    }
}

/// R2720 — who can CREATE a session, for the node-scoped half of the grammar.
///
/// ⛔ A SEPARATE PORT FROM THE AUTHORITY AND FROM THE SESSION, and the split is
/// the finding rather than a layering preference. `close` acts on the session
/// the injector already holds — `SessionLinkActions` is right there. `open`'s
/// subject is a session that does not exist, so there is no bundle to ask; and
/// injecting the machine's own `outbound.start` into a RUNNING session is a
/// no-op, because that trigger sits only on the transition out of Init. The
/// collaborator for `open` is therefore node-scoped, and that is why it cannot
/// be the same object.
///
/// MEASURED, which is why this is an `Option` at the injector rather than a
/// required collaborator: AP has both halves of an open already — resolve the
/// key's `peer_zid` through `LinkstateNetwork::node_locators` and dial through
/// `ConnectReconcile::AddNode` — while no MCU crate depends on `wz-routing-graph`
/// at all, and `wz-session-lwip`'s `run_session` drives exactly ONE session
/// whose Acceptor/Initiator role is fixed before the loop starts. A profile
/// with no session manager has nothing to bind here, and forcing it to bind a
/// pretend one would be worse than saying so.
#[cfg(feature = "session-close-ingress")]
pub trait SessionOpener {
    /// Ask for a session to the peer this key names. `true` when the request
    /// was accepted — accepted, not completed: a dial is asynchronous, and this
    /// port answers about the ASK, exactly as the close half answers about the
    /// request rather than about the session having gone.
    fn request_open(&self, key: &LifecycleKey<'_>) -> bool;
}

#[cfg(feature = "session-close-ingress")]
impl<O: SessionOpener + ?Sized> SessionOpener for &O {
    fn request_open(&self, key: &LifecycleKey<'_>) -> bool {
        (**self).request_open(key)
    }
}

#[cfg(feature = "session-close-ingress")]
pub struct SessionLifecycleInjector<'a, R: SessionRuntime, T: TimeSource> {
    actions: &'a SessionLinkActions<R, T>,
    authority: &'a dyn SessionLifecycleAuthority,
    opener: Option<&'a dyn SessionOpener>,
}

#[cfg(feature = "session-close-ingress")]
impl<'a, R: SessionRuntime, T: TimeSource> SessionLifecycleInjector<'a, R, T> {
    /// Borrow the session's shared bundle as the lifetime-ingress port, the
    /// authority that says whether an arriving command may run, and the opener
    /// this node can create sessions through.
    ///
    /// The authority is a CONSTRUCTOR parameter, not a setter and not an
    /// `Option`: a host that wires this ingress cannot reach the verb without
    /// having answered who may use it. That is the same move the §5.16 kernel
    /// made when it took `Option<&Zid>` by parameter — "moves the question to
    /// the one place that owns policy, and makes it unskippable at a call
    /// site" — one layer out.
    ///
    /// R2720 — `opener` IS an `Option`, and the difference from the authority
    /// is not inconsistency. An authority is a DECISION every profile must
    /// make, so leaving it out would be fail-open. An opener is a CAPABILITY a
    /// profile may genuinely not have — a one-session MCU drive has no session
    /// manager to bind — and a host with none says `None` here rather than
    /// binding a pretend one. It is still a parameter, so the answer is stated
    /// at every call site rather than defaulted into.
    pub fn new(
        actions: &'a SessionLinkActions<R, T>,
        authority: &'a dyn SessionLifecycleAuthority,
        opener: Option<&'a dyn SessionOpener>,
    ) -> Self {
        Self {
            actions,
            authority,
            opener,
        }
    }
}

// The `'static` bound is the MACHINE's, not this port's: the generated
// `impl<A: SessionFsmUnicastActions + 'static> StatePolicy for
// SessionFsmUnicastPolicy<A>` is what makes `get_event_from_name` reachable, so
// naming that policy costs `T: 'static`. It sits on THIS impl rather than on
// the struct (R311y503's shape) so only the path that asks the machine pays it
// -- and it costs nothing in practice, because anything holding a session
// engine already satisfies it.
#[cfg(feature = "session-close-ingress")]
impl<R: SessionRuntime, T: TimeSource + 'static> crate::switchboard::EventInjector
    for SessionLifecycleInjector<'_, R, T>
{
    /// ⛔ THE SIGNAL SHAPE CANNOT CLOSE, and the emptiness is the gate rather
    /// than an omission. This shape is handed a name and nothing else, so an
    /// impl reading it cannot know WHICH session the request names and
    /// therefore cannot ask whether that one may be closed. Closing anyway
    /// would answer a destructive verb for a request nobody was able to judge.
    ///
    /// R2678 closed the session from here. That was the defect this residual
    /// names: the verb was reachable through the name alone.
    ///
    /// A close that arrives this way is a MISREGISTRATION, not a refusal — the
    /// row was registered with `register` where it needed `register_command` —
    /// so it is logged. The observable stays "nothing happened", because a
    /// refusal on this port is observable only as the absence of the effect and
    /// a second spelling of silence would be a different answer.
    fn inject(&mut self, event_name: &str, _event_data: &str) {
        use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
        use sce_rust_runtime::StatePolicy;
        type P<R2, T2> = SessionFsmUnicastPolicy<SessionActionsBinding<R2, T2>>;
        if <P<R, T> as StatePolicy>::get_event_from_name(event_name) == Some(E::SessionClose) {
            log::warn!(
                "SessionLifecycleInjector: a session-close event arrived on the SIGNAL \
                 path, which carries no keyexpr and so cannot be authorised; the row is \
                 ignored. Register it with `SwitchboardRegistry::register_command`."
            );
        }
    }

    /// A name the session machine reads as `SessionClose`, on a keyexpr the
    /// authority admits, becomes a close request. Every other name is ignored,
    /// exactly as `Engine::raise_external_by_name` graceful-ignores a name
    /// outside the document's enum.
    ///
    /// The return value is the EFFECT, not the arrival: a refused command
    /// reports `false`, so the dispatch count a caller reads does not rise and
    /// "nothing happened" is what a refusal looks like from every side.
    fn inject_command(&mut self, event_name: &str, keyexpr: &str) -> bool {
        use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
        use sce_rust_runtime::StatePolicy;
        type P<R2, T2> = SessionFsmUnicastPolicy<SessionActionsBinding<R2, T2>>;
        let event = <P<R, T> as StatePolicy>::get_event_from_name(event_name);
        // The machine's own mapping decides which verb a row carries: neither
        // name is spelled here, for the reason open-debt item 777 records.
        if event != Some(E::SessionClose) && event != Some(E::OutboundStart) {
            return false;
        }
        // R2718 — A KEY THAT IS NOT THIS GRAMMAR IS REFUSED, not passed on. A
        // row's pattern can be a wildcard, so matching does not make the
        // arriving key a lifecycle key; and an authority handed one it cannot
        // parse would be answering about a target it never read.
        let Some(key) = LifecycleKey::parse(keyexpr) else {
            log::warn!(
                "SessionLifecycleInjector: a lifecycle row matched a key that is \
                 not `@/<zid>/<whatami>/session/<verb>/<peer-zid>`; refusing, because \
                 an authority cannot name a target it cannot read."
            );
            return false;
        };
        // Decisions D2 and D9 of `docs/session-lifecycle-intent.md`: a
        // lifecycle verb runs only for a peer whose zid a key it proved INSIDE
        // A SECURE CHANNEL names. The command arrived on THIS session, so its
        // peer is the commander, and the authority below decides on that
        // peer's zid; an unproved zid is a claim anyone could make, so judging
        // it would be judging nothing. Refused before the authority is asked,
        // for both verbs, and said, for the reason the misregistration arm
        // above is said: from outside a refusal looks like nothing happening.
        if !self.actions.peer_identity_verified() {
            log::warn!(
                "SessionLifecycleInjector: a lifecycle command arrived from a peer \
                 whose zid no secure channel proved; refusing. Lifecycle verbs \
                 need a TLS or QUIC link whose peer certificate's key hashes to \
                 the peer's zid (docs/session-lifecycle-intent.md, D1 and D9)."
            );
            return false;
        }
        if event == Some(E::SessionClose) {
            if !self.authority.admits_close(&key) {
                return false;
            }
            self.actions.request_close();
            return true;
        }
        // R2720 — THE OPEN HALF, and it goes to a DIFFERENT collaborator. The
        // session this injector holds is not the one the command is about:
        // `outbound.start` on THIS machine would be a no-op, because that
        // trigger sits only on the transition out of Init. The verb means
        // "bring up a session to the peer this key names", which is the node's
        // work and not this session's.
        let Some(opener) = self.opener else {
            // ⛔ SAID, not silent. A profile with no session manager cannot
            // answer this verb, and a node that simply did nothing would be
            // indistinguishable from one that refused it on policy — the
            // distinction an operator needs and the observable this port
            // cannot carry.
            log::warn!(
                "SessionLifecycleInjector: an open command arrived and this host bound \
                 no opener, so nothing can create a session here; refusing. A profile \
                 that drives one session with its role fixed at construction has no \
                 session manager to bind."
            );
            return false;
        };
        if !self.authority.admits_open(&key) {
            return false;
        }
        opener.request_open(&key)
    }
}

/// Merge two optional baseline stamps to the most recent one — the R84
/// `max(established_at, <activity stamp>)` rule both wake computations
/// apply.
fn max_stamp(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x),
        (Some(x), Some(y)) => Some(x.max(y)),
    }
}

/// R311kx — absolute lease-expiry deadline (ms, the shared monotonic
/// epoch): `max(established_at, last_inbound_at) +
/// adopted_lease_ms`, or `None` pre-Established (no baseline). The wake
/// twin of [`check_lease_deadline`] — both drive loops arm their sleep /
/// busy-poll compare on this value and the comparator re-derives the same
/// deadline at fire time, so the two cannot disagree.
///
/// Closes the R311kw-carried wake-arming gap: the prior loop arming read
/// the inbound stamp alone with the LOCAL `params.lease_ms` window, so an
/// Established peer that never sent anything left the loop blocked on the
/// link poll forever (the R84 `established_at` comparator fallback was
/// unreachable — no wake ever fired to invoke it), and a shorter
/// peer-advertised lease (R311kv min) woke late by the difference.
/// R311la — the inbound stamp is the any-RX `last_inbound_at` (pico
/// `_received` parity), not the former KeepAlive-only slot.
///
/// `None` as well while the link's lease monitor is not running (before
/// `Established`, and after its exit released the monitor): a stamp left
/// from the established window is not a deadline anyone keeps.
pub fn lease_wake_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<u64> {
    if !R::with_mutex_mut(&actions.link.lease_armed, |armed| *armed) {
        return None;
    }
    let inbound = R::with_mutex_mut(&actions.link.last_inbound_at, |g| *g);
    let established = R::with_mutex_mut(&actions.link.established_at, |g| *g);
    max_stamp(established, inbound).map(|b| b.saturating_add(actions.adopted_lease_ms()))
}

/// R311kx — absolute next keepalive TX deadline (ms):
/// `max(established_at, last_outbound_at) + adopted_lease_ms /
/// LEASE_EXPIRE_FACTOR`, or `None` pre-Established. The TX-side wake twin
/// of [`lease_wake_deadline`]: the lease deadline watches the PEER's
/// silence, this one watches OURS — zenoh-pico's keep-alive task wakes
/// every `_lease / Z_TRANSPORT_LEASE_EXPIRE_FACTOR` and emits when
/// nothing was transmitted in the window (unicast/lease.c:191).
///
/// `.max(1)` keeps a degenerate 0 ms lease from hot-spinning the emitter;
/// the lease comparator expires such a session on its first check
/// regardless.
///
/// `None` whenever the link's keepalive worker is not running: the session
/// FSM starts it on `Established` entry and stops it on the exit, so a
/// session in `Closing` arms no keepalive wake on either drive loop and the
/// tokio pacer ends.
#[cfg(feature = "transport-keepalive")]
pub fn keepalive_wake_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<u64> {
    if !R::with_mutex_mut(&actions.link.keepalive_armed, |armed| *armed) {
        return None;
    }
    let outbound = R::with_mutex_mut(&actions.link.last_outbound_at, |g| *g);
    let established = R::with_mutex_mut(&actions.link.established_at, |g| *g);
    // A driver with a queue between hand-over and write reports when its writer last finished
    // a write, and that is when the line spoke (the stamp above then holds only the control
    // frames, which are the keepalives themselves). Folded in as a stamp on the session's
    // clock: the driver answers an elapsed time, so the two clocks need no common epoch.
    let driver = actions.link.link_driver();
    let written = if driver.reports_wire_writes() {
        driver
            .ms_since_wire_write()
            .map(|ago| actions.clock.now_monotonic_ms().saturating_sub(ago))
    } else {
        None
    };
    let interval = (actions.adopted_lease_ms() / crate::lease::LEASE_EXPIRE_FACTOR).max(1);
    max_stamp(max_stamp(established, outbound), written).map(|b| b.saturating_add(interval))
}

/// R311kx — run one keepalive TX deadline check: when the link's keepalive
/// worker is running, the transport is live, and the line has been idle for
/// `adopted_lease_ms / LEASE_EXPIRE_FACTOR` (no wire emit since the
/// [`keepalive_wake_deadline`] baseline), emit one KeepAlive through
/// [`SessionLinkActions::send_keep_alive`] — which re-stamps
/// `last_outbound_at`, opening the next idle window. The TX-emitter
/// closure of the R311kv asymmetry: without it a wz node publishing
/// nothing fell silent for its whole advertised lease and the peer
/// expired it (zenoh-pico's keep-alive task is the reference,
/// unicast/lease.c:172-214).
///
/// Shared by both drive loops (the AP `tokio::select!` sleep arm and the
/// lwIP busy-poll compare), exactly as [`check_lease_deadline`] is. No
/// FSM access — a KeepAlive emit is not a session-state trigger.
#[cfg(feature = "transport-keepalive")]
pub fn check_keepalive_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    now_ms: u64,
) -> crate::lease::KeepAliveCheckOutcome {
    use crate::lease::KeepAliveCheckOutcome as K;
    if !R::with_mutex_mut(&actions.link.transport_available, |g| *g) {
        return K::Inactive;
    }
    match keepalive_wake_deadline(actions) {
        // The worker is not running: never started, or stopped by the
        // machine's exit from Established.
        None => K::Inactive,
        Some(deadline_ms) if now_ms >= deadline_ms => {
            actions.send_keep_alive();
            K::Emitted
        }
        Some(_) => K::WithinInterval,
    }
}

/// The FSM engine [`new_session_engine`] yields, named once here.
///
/// R2364 — the alias exists because a driver that wants to STORE the engine
/// (rather than hold it in a local of an inference-typed `let`) has to write
/// the type out, and writing it out names `sce_rust_runtime::Engine`. That is
/// a dependency the AP profile happens to carry and the MCU session shell
/// (`wz-session-lwip`) does not: it reaches the engine only through this
/// crate's factory. Adding the sce dep to a crate that names no other sce
/// item, purely to spell a return type, would be a dependency edge bought
/// for a syntax problem. The alias lets any driver on any profile store the
/// engine with the dep graph unchanged, which is what the MCU
/// `SessionPump` does.
pub type SessionEngine<R, T> = Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>;

/// Build a session [`Engine`] over the generated engine-free
/// [`SessionFsmUnicastPolicy`], parameterised over a [`SessionActionsBinding`]
/// wrapping a clone of `actions`. Generic over `R: SessionRuntime` so the AP
/// tokio loop and the lwIP MCU sync loop construct the FSM engine the same way
/// (Stage 4b SSOT — wz-runtime-tokio's `new_session_engine<T>` delegates here).
/// The caller retains `actions` (to read trace / observe link state) and drives
/// the returned engine with `dispatch_link_event` / `check_lease_deadline`.
///
/// docs/adr/0038 — the policy is built with `new` in a build whose binding
/// performs every duty and with `new_simulated` in one that compiles a duty
/// body out, by [`SESSION_HOST_REALIZATION`]: a build is never refused for the
/// features it left out, and a build that has them all is still held, at
/// compile time, to a binding that declares it performs.
pub fn new_session_engine<R: SessionRuntime, T: TimeSource>(
    actions: &R::ActionsHandle<T>,
) -> SessionEngine<R, T> {
    // `SessionActionsBinding.inner` is private to this crate; construct through
    // the pub `::new` constructor (mirrors the AP `new_session_engine`).
    let binding = SessionActionsBinding::new(actions.clone());
    Engine::new(PolicyConstructor::<BINDING_PERFORMS>.build(binding))
}

/// [`new_session_engine`] built inside `slot`: the same engine, written where it will live, so a
/// caller that keeps it in a cell of a table never holds all of it (1 KB and more on the fixed
/// client) on its own stack. The slot may be uninitialised; whatever it held is not dropped.
pub fn new_session_engine_in<'s, R: SessionRuntime, T: TimeSource>(
    slot: &'s mut core::mem::MaybeUninit<SessionEngine<R, T>>,
    actions: &R::ActionsHandle<T>,
) -> &'s mut SessionEngine<R, T> {
    let binding = SessionActionsBinding::new(actions.clone());
    Engine::new_in_place(slot, PolicyConstructor::<BINDING_PERFORMS>.build(binding))
}

/// [`SESSION_HOST_REALIZATION`] as the constructor choice it makes.
const BINDING_PERFORMS: bool = SESSION_HOST_REALIZATION.is_performing();

/// Chooses the generated policy's constructor by a constant, so that only the
/// chosen one is ever instantiated. Naming `SessionFsmUnicastPolicy::new` in a
/// branch not taken would still evaluate its compile-time refusal for a
/// simulating binding, which is why this is a type and not an `if`.
struct PolicyConstructor<const PERFORMS: bool>;

trait BuildSessionPolicy<A: SessionFsmUnicastActions + 'static> {
    fn build(self, actions: A) -> SessionFsmUnicastPolicy<A>;
}

/// The id the unicast session machine is built under (SCE ADR 0045: a machine takes the id its
/// host gives, and the generated constructor refuses a text that is not an XML Nmtoken). One
/// constant, so the refusal below can never be met.
const UNICAST_SESSION_ID: &str = "wz-session-unicast";

impl<A: SessionFsmUnicastActions + 'static> BuildSessionPolicy<A> for PolicyConstructor<true> {
    fn build(self, actions: A) -> SessionFsmUnicastPolicy<A> {
        built_under_constant_id(
            SessionFsmUnicastPolicy::new_with_session_id(UNICAST_SESSION_ID, actions),
            "the unicast session id",
        )
    }
}

impl<A: SessionFsmUnicastActions + 'static> BuildSessionPolicy<A> for PolicyConstructor<false> {
    fn build(self, actions: A) -> SessionFsmUnicastPolicy<A> {
        built_under_constant_id(
            SessionFsmUnicastPolicy::new_simulated_with_session_id(UNICAST_SESSION_ID, actions),
            "the unicast session id",
        )
    }
}

// ── reassembly-pool drive (reassembly-gated; `reassembly` implies `codec-frame`,
//    so `parse_frame_payload` above is in scope here too) ──
#[cfg(all(feature = "reassembly", feature = "alloc"))]
use crate::driver_loop::reassembled_chain_outcome;
#[cfg(feature = "reassembly")]
use crate::driver_loop::{IterationEvent, ReassemblyDropReason};
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::{Fragment as ReassemblyFragment, ReassemblyDispatcher};

/// Report one driver-loop outcome, additionally driving the reassembly pool
/// when the outcome is a `Fragment`. On chain completion the reassembled bytes
/// re-enter `parse_frame_payload`, so the application's per-MID dispatch sees a
/// reassembled message exactly as it sees a `T_MID_FRAME` payload; the
/// resulting `FramePayload` (or `ParseError`) is reported as a second
/// `IterationEvent::Poll`. Non-terminal ingests (Begun / Continued / Aborted /
/// Refused) report only the `Fragment` outcome. The peer ZID (the §2.3 chain
/// key) is read from `actions.inbound_peer_zid` through `R::with_mutex_mut`.
///
/// Generic over the pool dims (`SLOTS` / `CAP`) so the AP (32 / 1 MiB) and MCU
/// (4 / 4096) profiles share one ingest path; the AP host passes its
/// `TokioReassembly`, the MCU loop its `CoopReassembly`.
///
/// A build with no allocator has no `Fragment` outcome to drive the pool with (the
/// fragment is staged where its datagram lies, `fragment_in_place`), so there the
/// outcome is reported and a channel-gate rejection clears its chain, and that is all.
#[cfg(feature = "reassembly")]
pub fn report_outcome_reassembling<R, T, const SLOTS: usize, const CAP: usize, S, F>(
    outcome: &DriverLoopOutcome,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    actions: &SessionLinkActions<R, T>,
    now_ms: u64,
    on_event: &mut F,
) where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
    F: FnMut(IterationEvent<'_>) + ?Sized,
{
    report_outcome_reassembling_with(outcome, reasm, actions, now_ms, &mut |_| {}, on_event);
}

/// [`report_outcome_reassembling`] for a loop that has an INGRESS decorator (the §5.16 policy of
/// a session that enforces one): `ingress` runs on the `FramePayload` a completed fragment chain
/// is turned into, before it is reported.
///
/// That outcome is the SECOND place an owned `FramePayload` is made. The first is the loop's own
/// decode of a whole frame, which the loop hands to its decorator; this one is made in here, from
/// the chain, and without this parameter it reached the application having skipped the
/// decorator, so a policy that denied a key, or capped a payload, held for every put that fit one
/// frame and for none that did not. A size cap is the policy a big payload most needs, and a big
/// payload is the one that is fragmented. The namespace strip right above it in the body is the
/// same shape of obligation, and has been paid here since it was written.
#[cfg(feature = "reassembly")]
pub fn report_outcome_reassembling_with<R, T, const SLOTS: usize, const CAP: usize, S, F, H>(
    outcome: &DriverLoopOutcome,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    actions: &SessionLinkActions<R, T>,
    now_ms: u64,
    ingress: &mut H,
    on_event: &mut F,
) where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
    F: FnMut(IterationEvent<'_>) + ?Sized,
    H: FnMut(&mut DriverLoopOutcome) + ?Sized,
{
    on_event(IterationEvent::Poll(outcome));
    // R311ke — a channel-gate rejection clears that channel's in-progress
    // reassembly chain (pico clears the dbuf + state on an out-of-order
    // FRAME or FRAGMENT, rx.c:112-113/166-168): a continuation superseded
    // by the rejection must never complete a chain from mixed generations.
    if let DriverLoopOutcome::RxSnRejected {
        priority, reliable, ..
    } = outcome
    {
        R::with_mutex_mut(&actions.inbound_peer_zid, |zid_slot| {
            let zid: &[u8] = zid_slot.as_deref().unwrap_or(&[]);
            // R311y215 (SN-safety F4) — clear only the (peer, reliable, priority)
            // chain the rejected frame's conduit owns, not a sibling priority's.
            reasm.abort_channel(zid, *priority, *reliable);
        });
        return;
    }
    #[cfg(not(feature = "alloc"))]
    let _ = (now_ms, ingress);
    #[cfg(feature = "alloc")]
    report_fragment_outcome(outcome, reasm, actions, now_ms, ingress, on_event);
}

/// The `Fragment` half of [`report_outcome_reassembling`]: drive the pool with the
/// fragment an owned outcome carries, and report what completed or was dropped.
#[cfg(all(feature = "reassembly", feature = "alloc"))]
fn report_fragment_outcome<R, T, const SLOTS: usize, const CAP: usize, S, F, H>(
    outcome: &DriverLoopOutcome,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP, S>,
    actions: &SessionLinkActions<R, T>,
    now_ms: u64,
    ingress: &mut H,
    on_event: &mut F,
) where
    R: SessionRuntime,
    T: TimeSource,
    S: crate::chain_staging::ChainStaging<SLOTS, CAP>,
    F: FnMut(IterationEvent<'_>) + ?Sized,
    H: FnMut(&mut DriverLoopOutcome) + ?Sized,
{
    let DriverLoopOutcome::Fragment {
        reliable,
        sn,
        more,
        payload,
        priority,
        markers,
        ..
    } = outcome
    else {
        return;
    };
    // R311y578 — arm the chain-boundary rules from the NEGOTIATED protocol
    // patch level before the fragment is classified. zenoh re-reads
    // `config.patch.has_fragmentation_markers()` per fragment
    // (`unicast/universal/rx.rs:155`); wz reads the settled session value,
    // which is why this is a bool write and not a negotiation.
    reasm.set_fragmentation_markers(actions.fragmentation_markers_negotiated());
    // The session's `transport/link/rx/max_message_size`, from its own
    // configuration rather than the host's Router construction, so every host
    // that drives a unicast session applies it.
    reasm.set_max_message_bytes(actions.params.link_rx.max_message_size);
    // The negotiated SN ring mask resolves BEFORE the peer-ZID guard:
    // `negotiated_sn_mask` takes the `inbound_peer_init_caps` mutex, and the
    // guard below documents that nothing inside it re-enters a session mutex
    // slot — hoisting keeps the two scopes disjoint instead of weakening
    // that invariant to "only disjoint slots nest".
    let sn_mask = actions.negotiated_sn_mask();
    // The peer ZID guard must wrap the whole `ingest` call: the completion
    // closure borrows `zid` for the chain-key lookup. `with_mutex_mut` scopes
    // that borrow to the closure (the AP std mutex and the MCU critical_section
    // mutex behind one seam); the non-reentrant MCU mutex is safe because
    // `ingest` does not re-enter the session's mutex slots.
    let mut completed: Option<DriverLoopOutcome> = None;
    let ingest_outcome = R::with_mutex_mut(&actions.inbound_peer_zid, |zid_slot| {
        let zid: &[u8] = zid_slot.as_deref().unwrap_or(&[]);
        // ARCHITECTURE section 9.3 -- the completed chain is LENT out of the
        // arena when it can be, so the reassembled message is decoded where its
        // fragments were staged and nothing copies it a second time.
        reasm.ingest_lending(
            ReassemblyFragment {
                peer_key: zid,
                reliable: *reliable,
                sn: *sn,
                more: u8::from(*more),
                payload: payload.as_slice(),
                // R311y215 — key the chain by (peer, reliable, priority).
                priority: *priority,
                // R311y578 — the `0x2 First` / `0x3 Drop` markers this
                // fragment carried; honoured iff the level armed above says
                // the peer emits them.
                markers: *markers,
            },
            sn_mask,
            now_ms,
            |chain| {
                // R311y221 — the reassembled whole-frame carries the chain's
                // band (the `(peer, reliable, priority)` key above), so a
                // fragmented prioritized Put delivers on the same band a
                // single-frame Put would.
                completed = Some(reassembled_chain_outcome(*reliable, *sn, *priority, chain));
            },
        )
    });
    if let Some(o) = completed {
        // §5.21 routing-namespace — strip the REASSEMBLED FramePayload (the
        // second owned-outcome mint point) before its observer fan-out, the
        // counterpart of the direct-outcome strip in
        // `drive_session_until_terminal`. A whole-frame FramePayload is stripped
        // by the caller; a fragment chain completes here, so its synthesized
        // FramePayload would otherwise reach the app un-stripped.
        let mut o = o;
        #[cfg(feature = "routing-namespace")]
        actions.apply_namespace_ingress(&mut o);
        // Then the loop's ingress decorator, in the order the loop applies the two to a whole
        // frame: a policy governs the keyexpr the namespace strip produced.
        ingress(&mut o);
        on_event(IterationEvent::Poll(&o));
    }
    // A terminal non-completion ingest — an out-of-order / capacity-overflow
    // Abort, or a per-peer-quota / pool-exhaustion Refusal — is otherwise
    // silent. Surface it (mapped to the feature-independent observer reason)
    // so the application can observe a malformed or abusive fragment stream
    // (the drop counterpart of the FramePayload completion).
    if let Some(reason) = ReassemblyDropReason::from_ingest(ingest_outcome) {
        on_event(IterationEvent::ReassemblyDropped(reason));
    }
}

// R311mh — `sweep_reporting` relocated to `crate::reassembly_dispatch`: it is a
// pure reassembly helper (no unicast actions / runtime generic, unlike its
// ingest twin `report_outcome_reassembling`), so housing it in this
// session-unicast-gated module wrongly coupled the multicast sweep SSOT to
// `session-unicast`. It now lives next to `ReassemblyDispatcher`.

// R2718 — the lifecycle grammar's own arms. They live beside the parser rather
// than in the tokio witness because the grammar is `wz-session-core`'s: both
// profiles read it, and a test that needed a session engine could only ever run
// on the one that has a tokio runtime.
#[cfg(all(test, feature = "session-close-ingress"))]
mod lifecycle_key_tests {
    use super::LifecycleKey;

    const WELL_FORMED: &str = "@/node-a/peer/session/close/peer-b";

    #[test]
    fn a_well_formed_key_yields_every_chunk() {
        let key = LifecycleKey::parse(WELL_FORMED).expect("parses");
        assert_eq!(key.node_zid, "node-a");
        assert_eq!(key.whatami, "peer");
        assert_eq!(key.verb, "close");
        // The TARGET is the point of the whole grammar: this is the chunk that
        // makes "may close session X only" expressible.
        assert_eq!(key.peer_zid, "peer-b");
    }

    // Each arm changes ONE thing about the well-formed key, so a refusal is
    // attributable to the chunk it names and not to the shape in general.
    #[test]
    fn a_key_that_is_not_this_grammar_is_refused() {
        for (why, keyexpr) in [
            ("no leading @", "x/node-a/peer/session/close/peer-b"),
            ("not the session plane", "@/node-a/peer/config/close/peer-b"),
            ("one chunk short", "@/node-a/peer/session/close"),
            ("one chunk long", "@/node-a/peer/session/close/peer-b/extra"),
            ("empty target", "@/node-a/peer/session/close/"),
            ("empty node", "@//peer/session/close/peer-b"),
            ("empty verb", "@/node-a/peer/session//peer-b"),
        ] {
            assert!(
                LifecycleKey::parse(keyexpr).is_none(),
                "{why}: `{keyexpr}` must not parse as a lifecycle key"
            );
        }
        // ANTI-VACUITY: the key every arm above was derived from DOES parse, so
        // the refusals are about what each one changed rather than about the
        // parser refusing everything.
        assert!(LifecycleKey::parse(WELL_FORMED).is_some());
    }

    // The verb chunk is READ, not assumed: a sibling verb on the same grammar
    // parses, which is what lets `open` join `close` on one door.
    #[test]
    fn the_verb_is_a_chunk_rather_than_a_constant() {
        let close = LifecycleKey::parse("@/node-a/peer/session/close/peer-b").expect("close");
        let open = LifecycleKey::parse("@/node-a/peer/session/open/peer-b").expect("open");
        assert_eq!(close.verb, "close");
        assert_eq!(open.verb, "open");
        assert_eq!(close.peer_zid, open.peer_zid);
        assert_eq!(close.argument, None);
    }

    // Decision D6 — `reset` alone carries its generation between the verb and
    // the target; a reset without one, or with an empty one, is not the grammar.
    #[test]
    fn a_reset_carries_its_generation_and_no_other_verb_carries_one() {
        let reset = LifecycleKey::parse("@/node-a/peer/session/reset/7/peer-b").expect("reset");
        assert_eq!(reset.verb, "reset");
        assert_eq!(reset.argument, Some("7"));
        assert_eq!(reset.peer_zid, "peer-b");
        for keyexpr in [
            "@/node-a/peer/session/reset/peer-b",
            "@/node-a/peer/session/reset//peer-b",
            "@/node-a/peer/session/reset/7/peer-b/extra",
            "@/node-a/peer/session/close/7/peer-b",
        ] {
            assert!(
                LifecycleKey::parse(keyexpr).is_none(),
                "`{keyexpr}` must not parse as a lifecycle key"
            );
        }
    }
}

// The participant seam of the mandatory-extension rule for the network messages:
// the one function every receive path of a framed batch goes through refuses a
// batch whose message holds an extension it does not define, with the M bit set,
// and passes the same batch with the bit clear
// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory() {`).
#[cfg(all(test, feature = "codec-frame", feature = "codec-push"))]
mod mandatory_extension_seam_tests {
    use super::*;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs_test_support::TestWire as _;

    /// A Push whose Put carries one UNIT extension with `header`.
    fn push_with_put_ext(header: u8) -> alloc::vec::Vec<u8> {
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
    fn a_mandatory_extension_the_message_does_not_define_refuses_the_batch() {
        let optional = crate::link::RxBytes::from(push_with_put_ext(0x03));
        assert!(parse_frame_payload_out_of_line(&optional).is_ok());
        let mandatory = crate::link::RxBytes::from(push_with_put_ext(0x13));
        assert_eq!(
            parse_frame_payload_out_of_line(&mandatory).unwrap_err(),
            InboundParseError::UnknownMandatoryExt { eid: 0x13 }
        );
    }
}
