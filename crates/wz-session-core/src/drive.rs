// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use sce_rust_runtime::Engine;

use wz_runtime_core::TimeSource;

use crate::driver_loop::DriverLoopOutcome;
use crate::inbound::inbound_to_fsm_event;
use crate::lease::LeaseCheckOutcome;
use crate::link::{LinkEvent, SessionRuntime};
// `InboundParseError` is named only as `::Codec(..)` in the codec-frame `Frame`
// arm (and the reassembly re-parse, which implies codec-frame); the `Err(err)`
// arm passes the value without naming the type.
#[cfg(feature = "codec-frame")]
use crate::parse_error::InboundParseError;
use crate::session_actions::{SessionActionsBinding, SessionLinkActions};
use crate::session_fsm_unicast::SessionFsmUnicastPolicy;
// `InboundFrame` is named by the ungated `Unknown` match arm; the codec-gated
// arms (`Frame` / `KeepAlive` / `Fragment` / `Init` / `Open` / `Close`) reuse it.
use crate::inbound::InboundFrame;
// parse_frame_payload backs the codec-frame `Frame` arm only.
#[cfg(feature = "codec-frame")]
use crate::network_message::parse_frame_payload;
// transport-lowlatency — the lean rx branch reads the leading message id
// (wire_const) and synthesizes an empty ext list (Vec); transport-compression's
// rx un-wrap holds the decompressed batch in a Vec too.
#[cfg(any(feature = "transport-lowlatency", feature = "transport-compression"))]
use alloc::vec::Vec;
#[cfg(feature = "transport-lowlatency")]
use wz_codecs::wire_const;

/// Drive one already-polled `LinkEvent` through the inbound chain so the
/// engine-free session FSM advances. The synchronous core of
/// `wz-runtime-tokio::poll_and_dispatch_one` (whose sole `.await` —
/// `driver.poll_event()` — stays in the tokio async wrapper). Generic over the
/// runtime so the lwIP MCU loop dispatches through the same SSOT.
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
        LinkEvent::Lost { cause } => {
            engine.process_event(E::LinkLost);
            DriverLoopOutcome::LinkLost(cause)
        }
        LinkEvent::Rx(rx) => {
            // transport-stats — count the RAW link bytes received (the on-the-
            // wire total, BEFORE the optional decompression below), the zenoh
            // rx_bytes parity point. The single inbound chokepoint every link
            // kind funnels through.
            #[cfg(feature = "transport-stats")]
            actions.stats.inc_rx(rx.bytes.len());
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
            #[cfg(feature = "transport-compression")]
            let bytes: &[u8] = decompressed.as_deref().unwrap_or(&rx.bytes);
            #[cfg(not(feature = "transport-compression"))]
            let bytes: &[u8] = &rx.bytes;
            dispatch_unit(bytes, actions, engine)
        }
    }
}

/// R311y632 (§17) — dispatch ONE framing unit that [`dispatch_link_event`]
/// has already un-wrapped.
///
/// Split out so the REMAINDER of a batch can re-enter WITHOUT being handed to
/// the decompressor a second time: compression wraps the whole unit, so bytes
/// that have already come out of it must not go back in.
/// [`dispatch_pending`] is the other caller.
fn dispatch_unit<R: SessionRuntime, T: TimeSource>(
    bytes: &[u8],
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;

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
    #[cfg(feature = "transport-lowlatency")]
    if actions.is_lowlatency() && actions.is_established() {
        // Dispatch the leading message id (zenoh lean rx,
        // codec/transport/mod.rs:60-73): KeepAlive / Close fall through
        // to the universal `handle_inbound` (their wire form is identical
        // in both modes — top-level transport messages, never
        // Frame-wrapped); any OTHER leading id is a bare NetworkMessage
        // (mids 0x19..=0x1F) decoded directly with no Frame(sn) wrapper.
        // Using the message-id constants (not the network-mid range)
        // keeps the test feature-robust: `T_MID_KEEP_ALIVE` is ungated,
        // and the `T_MID_CLOSE` arm rides `codec-close` exactly like the
        // `handle_inbound` decode arm it defers to.
        let lean_network = match bytes.first().map(|h| h & 0x1F) {
            None => false,
            Some(wire_const::T_MID_KEEP_ALIVE) => false,
            #[cfg(feature = "codec-close")]
            Some(wire_const::T_MID_CLOSE) => false,
            Some(_) => true,
        };
        if lean_network {
            return match parse_frame_payload(bytes) {
                Ok(messages) => DriverLoopOutcome::FramePayload {
                    reliable: true,
                    sn: 0,
                    messages,
                    has_ext: false,
                    extensions: Vec::new(),
                    // R311y221 — the lowlatency lean wire carries no Frame
                    // envelope and no ext_qos (zenoh lowlatency tracks no
                    // SN / no per-priority conduit), so the delivered band
                    // is DEFAULT.
                    priority: crate::qos::Priority::DEFAULT,
                },
                Err(codec_err) => {
                    engine.process_event(E::FramingError);
                    DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
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
    let parsed = actions.handle_inbound_consuming(bytes);
    if let Ok((_, consumed)) = &parsed {
        if *consumed > 0 && *consumed < bytes.len() {
            actions.park_pending_batch(&bytes[*consumed..]);
        }
    }
    match parsed.map(|(frame, _)| frame) {
        Ok(frame) => match inbound_to_fsm_event(&frame) {
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
                    E::OpenSynReceived => actions.cookie_valid(),
                    _ => true,
                };
                if !admit {
                    return DriverLoopOutcome::SideEffectOnly;
                }
                // R311y578 — take the `min(local, peer)` protocol PATCH
                // level off every admitted Init frame (zenoh-pico
                // `transport.c:237-241` runs the same cap on both sides).
                // wz has emitted its own patch ext since R121f1 and never
                // read the peer's; the negotiated level is the sole gate
                // on the Fragment chain-boundary markers, so a session
                // that never took it can only ever leave them off.
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
                // the unit OR the z64 QoSLink form at id 0x1.
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
                        } => Some(actions.with_auth(|d| d.accept_recv_open_syn(extensions))),
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
                engine.process_event(event);
                DriverLoopOutcome::AdvancedFsm
            }
            None => match frame {
                #[cfg(feature = "codec-frame")]
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
                    // negotiated `is_qos`); drop it rather than admit
                    // prioritized traffic onto a non-QoS transport. Under
                    // a non-QoS session `priority` is always DEFAULT, so
                    // this never fires; a QoS session accepts every
                    // priority on its own conduit.
                    #[cfg(feature = "transport-qos")]
                    if !actions.is_qos() && priority != crate::qos::Priority::DEFAULT {
                        return DriverLoopOutcome::RxSnRejected {
                            priority,
                            reliable,
                            sn,
                        };
                    }
                    // R311ke — per-channel RX SN gate (pico
                    // `_z_sn_precedes`, unicast/rx.c:108-131): a stale
                    // / duplicate / reordered frame drops before its
                    // payload reaches the application layer. R311y215 —
                    // the gate is per-(priority, reliable) conduit. The
                    // typed outcome lets `report_outcome_reassembling`
                    // clear the channel's in-progress chain (dbuf-clear
                    // parity) and observers count the drop.
                    if !actions.admit_rx_frame_sn(priority, reliable, sn) {
                        return DriverLoopOutcome::RxSnRejected {
                            priority,
                            reliable,
                            sn,
                        };
                    }
                    match parse_frame_payload(&payload) {
                        Ok(messages) => DriverLoopOutcome::FramePayload {
                            reliable,
                            sn,
                            messages,
                            has_ext,
                            extensions,
                            // R311y221 — the true decoded band (already
                            // in scope from the InboundFrame::Frame
                            // destructure above; gates the RX conduit at
                            // `admit_rx_frame_sn`). DEFAULT under non-QoS.
                            priority,
                        },
                        Err(codec_err) => {
                            engine.process_event(E::FramingError);
                            DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
                        }
                    }
                }
                #[cfg(feature = "codec-keep-alive")]
                InboundFrame::KeepAlive { .. } => DriverLoopOutcome::SideEffectOnly,
                // R311im — surface the decoded fragment to the drive
                // loop, which owns the stateful ReassemblyDispatcher +
                // clock. This pure helper cannot reassemble (no slot
                // pool, no `now_ms`), so it hands the fragment up.
                #[cfg(feature = "reassembly")]
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
                    // R311y215 (SN-safety F5) — as with Frame, drop a
                    // prioritized fragment on a non-QoS session.
                    #[cfg(feature = "transport-qos")]
                    if !actions.is_qos() && priority != crate::qos::Priority::DEFAULT {
                        return DriverLoopOutcome::RxSnRejected {
                            priority,
                            reliable,
                            sn,
                        };
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
                #[cfg(feature = "codec-join")]
                InboundFrame::Join { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                }
                // Transport OAM projects to `Some(FramingError)` for the same
                // reason a JOIN does — wz's unicast FSM has no operations
                // transition — so the outer Some arm took it.
                InboundFrame::Oam { .. } => {
                    unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
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
pub fn dispatch_pending<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> Option<DriverLoopOutcome> {
    let residue = actions.take_pending_batch()?;
    Some(dispatch_unit(&residue, actions, engine))
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
pub fn check_lease_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    now_ms: u64,
) -> LeaseCheckOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
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
pub fn lease_wake_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<u64> {
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
#[cfg(feature = "transport-keepalive")]
pub fn keepalive_wake_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<u64> {
    let outbound = R::with_mutex_mut(&actions.link.last_outbound_at, |g| *g);
    let established = R::with_mutex_mut(&actions.link.established_at, |g| *g);
    let interval = (actions.adopted_lease_ms() / crate::lease::LEASE_EXPIRE_FACTOR).max(1);
    max_stamp(established, outbound).map(|b| b.saturating_add(interval))
}

/// R311kx — run one keepalive TX deadline check: when the session is
/// Established, the transport is live, and the line has been idle for
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
    if !actions.is_established() || !R::with_mutex_mut(&actions.link.transport_available, |g| *g) {
        return K::Inactive;
    }
    match keepalive_wake_deadline(actions) {
        // Unreachable while Established (`established_at` is a baseline),
        // kept total for the enum's sake.
        None => K::Inactive,
        Some(deadline_ms) if now_ms >= deadline_ms => {
            actions.send_keep_alive();
            K::Emitted
        }
        Some(_) => K::WithinInterval,
    }
}

/// Build a session [`Engine`] over the generated engine-free
/// [`SessionFsmUnicastPolicy`], parameterised over a [`SessionActionsBinding`]
/// wrapping a clone of `actions`. Generic over `R: SessionRuntime` so the AP
/// tokio loop and the lwIP MCU sync loop construct the FSM engine the same way
/// (Stage 4b SSOT — wz-runtime-tokio's `new_session_engine<T>` delegates here).
/// The caller retains `actions` (to read trace / observe link state) and drives
/// the returned engine with `dispatch_link_event` / `check_lease_deadline`.
pub fn new_session_engine<R: SessionRuntime, T: TimeSource>(
    actions: &R::ActionsHandle<T>,
) -> Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>> {
    // `SessionActionsBinding.inner` is private to this crate; construct through
    // the pub `::new` constructor (mirrors the AP `new_session_engine`).
    let binding = SessionActionsBinding::new(actions.clone());
    Engine::new(SessionFsmUnicastPolicy::new(binding))
}

// ── reassembly-pool drive (reassembly-gated; `reassembly` implies `codec-frame`,
//    so `parse_frame_payload` above is in scope here too) ──
#[cfg(feature = "reassembly")]
use crate::driver_loop::{reassembled_frame_outcome, IterationEvent, ReassemblyDropReason};
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
    F: FnMut(IterationEvent<'_>),
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
        reasm.ingest(
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
            |msg| {
                // R311y221 — the reassembled whole-frame carries the chain's
                // band (the `(peer, reliable, priority)` key above), so a
                // fragmented prioritized Put delivers on the same band a
                // single-frame Put would.
                completed = Some(reassembled_frame_outcome(*reliable, *sn, *priority, msg));
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
        #[cfg(feature = "routing-namespace")]
        let mut o = o;
        #[cfg(feature = "routing-namespace")]
        actions.apply_namespace_ingress(&mut o);
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
