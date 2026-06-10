// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Inbound transport-frame decode SSOT.
//!
//! [`parse_inbound`] decodes one raw transport datagram into a typed
//! [`InboundFrame`]; [`inbound_to_fsm_event`] projects a parsed frame to the
//! matching `session_fsm_unicast` external event; `decode_ext_chain` is the
//! shared Z-flag ext-chain decoder both consume.
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! (tokio AP + lwIP MCU) decode through one SSOT — the MCU `#![no_std]`
//! profile cannot depend on the tokio crate. The owned `Vec` buffers in
//! `InboundFrame` make this the alloc-profile decoder; the no-alloc
//! borrowed-decode variant is a deferred follow-up (the module is `alloc`-
//! gated at the `lib.rs` declaration, mirroring `network_message` /
//! `driver_loop`).
//!
//! Per-import cfg gating mirrors the original session_glue placement: every
//! symbol that is consumed only inside the codec-gated decode arms folds
//! under the same `cfg(any(codec-*))` union predicate, so an arbitrary
//! feature subset (incl. `--no-default-features --features alloc`) stays
//! unused-import clean under `deny(warnings)`.

// `Vec`, the cursor, the wire constants, and the ext-entry types are all
// consumed only by the codec-gated decode arms + `InboundFrame` variants +
// `decode_ext_chain`, so they fold under the union predicate.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use alloc::vec::Vec;

use crate::parse_error::InboundParseError;

#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use crate::parse_error::MAX_EXT_CHAIN_DEPTH;
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use sce_forge_runtime::codec::SceCursor;
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use wz_codecs::ext_entry::{ExtEntry, ExtEntryOwned};
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
use wz_codecs::wire_const;

#[cfg(feature = "codec-close")]
use wz_codecs::close::Close;
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::{InitBody, InitBodyOwned};
#[cfg(feature = "codec-keep-alive")]
use wz_codecs::keep_alive::KeepAlive;
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::{OpenBody, OpenBodyOwned};

/// A decoded inbound transport-message frame.
///
/// R68a baseline. The variant set covers the three transport bodies
/// the Initiator side cares about during handshake + close:
/// `Init` / `Open` / `Close`. The `has_ext` field on each variant
/// records whether the parent header's Z flag was set so the caller
/// can dispatch ext-chain decoding (R68c) without re-parsing the
/// header byte; the chain itself is decoded by `decode_ext_chain`.
/// `Unknown { mid }` covers MIDs outside the {INIT, OPEN, CLOSE}
/// triad — the caller may forward them to a higher-layer dispatch
/// (e.g. KeepAlive / Frame / Fragment) or drop them.
///
/// No `Debug` derive: the wz-codecs structs (`InitBody`/`OpenBody`)
/// are sce-codegen output and only derive `Default`. Callers
/// pattern-match the variant and inspect typed fields directly; a
/// log-style print on the whole frame is rare and can be composed
/// at the call site if needed.
pub enum InboundFrame {
    /// `_Z_MID_T_INIT` (0x01). `is_ack` mirrors the
    /// `_Z_FLAG_T_INIT_A` discriminator; `has_ext` mirrors the
    /// transport-header Z flag and corresponds to
    /// `!extensions.is_empty()` when R68c decode succeeds.
    #[cfg(feature = "codec-init-body")]
    Init {
        is_ack: bool,
        has_ext: bool,
        body: InitBodyOwned,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `_Z_MID_T_OPEN` (0x02). `is_ack` mirrors `_Z_FLAG_T_OPEN_A`.
    /// `body.lease` is ALWAYS milliseconds — the `_Z_FLAG_T_OPEN_T`
    /// seconds form is projected back during parse (R311ku,
    /// [`crate::lease::lease_from_wire`]); the pre-ku shape exposed the
    /// raw wire value plus a `lease_in_seconds` flag that no consumer
    /// ever read.
    #[cfg(feature = "codec-open-body")]
    Open {
        is_ack: bool,
        has_ext: bool,
        body: OpenBodyOwned,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `_Z_MID_T_CLOSE` (0x03). `reason` is the single body byte.
    #[cfg(feature = "codec-close")]
    Close {
        reason: u8,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `_Z_MID_T_KEEP_ALIVE` (0x04). Empty-body liveness ping; the
    /// only payload is the optional ext chain (Z flag-gated). The
    /// FSM uses receipt to reset the lease timer per
    /// session-fsm §2.5 keepalive_interval semantics.
    #[cfg(feature = "codec-keep-alive")]
    KeepAlive {
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `_Z_MID_T_FRAME` (0x05). Established-session payload carrier:
    /// `reliable` mirrors `_Z_FLAG_T_FRAME_R`; `sn` is the VLE
    /// sequence number; `payload` is the tail bytes (the inner
    /// NetworkMessage batch — higher-layer codec dispatch is the
    /// caller's responsibility). Z-flagged frames have their ext
    /// chain decoded into `extensions` between `sn` and `payload`
    /// to mirror zenoh-pico's `_z_msg_ext_skip_non_mandatories`
    /// path (transport.c::_z_frame_decode L388).
    ///
    /// R311g — variant gated on `codec-frame`. When the feature is
    /// off the `T_MID_FRAME` arm in `parse_inbound` falls through to
    /// `InboundFrame::Unknown { mid: 0x05 }`, which the FSM dispatch
    /// in `inbound_to_fsm_event` maps to `FramingError` (graceful
    /// session teardown rather than silent data loss).
    #[cfg(feature = "codec-frame")]
    Frame {
        reliable: bool,
        sn: u64,
        payload: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `_Z_MID_T_FRAGMENT` (0x06). One fragment of a fragmented
    /// established-session message. Body mirrors `T_MID_FRAME` (VLE `sn`,
    /// optional Z-gated ext chain, tail `payload`); the per-fragment
    /// `reliable` (`FLAG_T_FRAGMENT_R`) and `more` (`FLAG_T_FRAGMENT_M`)
    /// discriminators live in the transport header byte. Not a
    /// session-state trigger (`inbound_to_fsm_event` returns `None`, like
    /// `Frame`): the drive loop feeds it to the `ReassemblyDispatcher`,
    /// which reassembles the chain and re-enters the `T_MID_FRAME` decode
    /// path on completion. R311im — gated on `reassembly`; when the
    /// feature is off the `0x06` arm falls through to `Unknown { mid: 0x06 }`,
    /// mapped to `FramingError` (graceful teardown rather than silent loss).
    #[cfg(feature = "reassembly")]
    Fragment {
        reliable: bool,
        sn: u64,
        more: bool,
        payload: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// MID outside the handshake/close/keepalive set.
    Unknown { mid: u8 },
}

/// Parse a single transport-message frame from `bytes`.
///
/// The first byte carries `(flags<<5) | mid` — the low 5 bits are
/// the message ID, the high 3 bits are the per-MID flag set + the
/// shared Z flag (`0x80`) for the ext chain. R68a baseline decodes
/// the body via the wz codec set and reports the Z flag via
/// `has_ext`; the ext-chain bytes themselves are left in the
/// trailing portion of `bytes` for R68c to consume.
///
/// R311g1 — `has_ext` / `cursor` are conditionally bound via
/// `#[cfg(any(feature = "codec-init-body", ..))]` matching the union
/// of feature predicates of the dispatch arms below. A build with
/// every codec feature off elides both bindings entirely, leaving
/// only the Unknown fall-through arm.
pub fn parse_inbound(bytes: &[u8]) -> Result<InboundFrame, InboundParseError> {
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mid = header & 0x1F;
    // R311g1 — `flags` extraction is gated on the same predicate as
    // the dispatch arms that consume it; when every codec-* is off
    // (minus-all-codecs lane) only the Unknown fall-through arm
    // remains and `flags` would otherwise be unused.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let flags = header & 0xE0;
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let has_ext = (flags & wire_const::FLAG_T_Z) != 0;
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame"
    ))]
    let mut cursor = SceCursor::new(&bytes[1..]);
    match mid {
        #[cfg(feature = "codec-init-body")]
        wire_const::T_MID_INIT => {
            let body = InitBody::decode(&mut cursor, (flags >> 6) & 1, (flags >> 5) & 1)?
                .try_into_owned()?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Init {
                is_ack: (flags & wire_const::FLAG_T_INIT_A) != 0,
                has_ext,
                body,
                extensions,
            })
        }
        #[cfg(feature = "codec-open-body")]
        wire_const::T_MID_OPEN => {
            let mut body = OpenBody::decode(&mut cursor, (flags >> 5) & 1)?.try_into_owned()?;
            // R311ku — the `_Z_FLAG_T_OPEN_T` seconds form is projected
            // back to milliseconds AT the wire boundary
            // ([`crate::lease::lease_from_wire`], pico decode parity
            // codec/transport.c:314), so no consumer ever sees the wire
            // unit — the same boundary rule as `multicast_join::decode_join`.
            body.lease =
                crate::lease::lease_from_wire((flags & wire_const::FLAG_T_OPEN_T) != 0, body.lease);
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Open {
                is_ack: (flags & wire_const::FLAG_T_OPEN_A) != 0,
                has_ext,
                body,
                extensions,
            })
        }
        #[cfg(feature = "codec-close")]
        wire_const::T_MID_CLOSE => {
            let body = Close::decode(&mut cursor)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::Close {
                reason: body.reason,
                has_ext,
                extensions,
            })
        }
        #[cfg(feature = "codec-frame")]
        wire_const::T_MID_FRAME => {
            // sn first (VLE), then optional ext chain (Z-gated),
            // then tail payload to end of cursor.
            let sn = cursor.read_vle_u64().map_err(InboundParseError::Codec)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            let remaining = cursor.remaining();
            let payload = cursor
                .peek_slice(remaining)
                .map_err(InboundParseError::Codec)?
                .to_vec();
            cursor
                .advance(remaining)
                .map_err(InboundParseError::Codec)?;
            Ok(InboundFrame::Frame {
                reliable: (flags & wire_const::FLAG_T_FRAME_R) != 0,
                sn,
                payload,
                has_ext,
                extensions,
            })
        }
        #[cfg(feature = "reassembly")]
        wire_const::T_MID_FRAGMENT => {
            // Body mirrors T_MID_FRAME: VLE sn, optional Z-gated ext chain,
            // then tail payload. The R (reliable) and M (more) bits live in
            // the header flags, not the body. (`reassembly` implies
            // `codec-frame`, so `flags` / `has_ext` / `cursor` are bound.)
            let sn = cursor.read_vle_u64().map_err(InboundParseError::Codec)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            let remaining = cursor.remaining();
            let payload = cursor
                .peek_slice(remaining)
                .map_err(InboundParseError::Codec)?
                .to_vec();
            cursor
                .advance(remaining)
                .map_err(InboundParseError::Codec)?;
            Ok(InboundFrame::Fragment {
                reliable: (flags & wire_const::FLAG_T_FRAGMENT_R) != 0,
                sn,
                more: (flags & wire_const::FLAG_T_FRAGMENT_M) != 0,
                payload,
                has_ext,
                extensions,
            })
        }
        #[cfg(feature = "codec-keep-alive")]
        wire_const::T_MID_KEEP_ALIVE => {
            // KeepAlive body is empty (zero-byte payload); the
            // decode call is a no-op but kept for symmetry with the
            // other MIDs and to preserve the "every wire-mapped
            // codec routes through its generated decoder" invariant.
            let _body = KeepAlive::decode(&mut cursor)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(InboundFrame::KeepAlive {
                has_ext,
                extensions,
            })
        }
        other => Ok(InboundFrame::Unknown { mid: other }),
    }
}

/// R69b — map a parsed inbound transport frame to the matching
/// session-FSM external event variant.
///
/// Drives the receive half of the unicast session lifecycle:
/// `inbound bytes ─→ parse_inbound ─→ inbound_to_fsm_event ─→
/// Engine::process_event` so the FSM consumes peer frames without
/// the caller hand-writing the discriminator match.
///
/// `Unknown { mid }` maps to `FramingError` because an unhandled
/// MID at this dispatch layer is a wire-spec violation — the peer
/// sent a transport-message ID the codec set does not implement,
/// and the FSM's framing-error transition is the correct response
/// (Close(generic) on the link).
///
/// `KeepAlive` returns `None` because it is NOT a state-transition
/// trigger in `session_fsm_unicast.scxml` — keepalive receipt only
/// resets the lease timer (a side effect orthogonal to the state
/// graph). Callers wire that side-effect on the `None` branch
/// rather than calling `Engine::process_event` with a spurious
/// event.
///
/// `Frame` returns `None` for the same reason at the FSM layer
/// (Frame receipt is the carrier for application-layer pub/sub
/// messages, not a session-state trigger). Callers on the `None`
/// branch route `Frame.payload` through `parse_frame_payload` to
/// surface the in-batch `NetworkMessage` records.
#[cfg(feature = "session-unicast")]
pub fn inbound_to_fsm_event(
    frame: &InboundFrame,
) -> Option<crate::session_fsm_unicast::SessionFsmUnicastEvent> {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match frame {
        #[cfg(feature = "codec-init-body")]
        InboundFrame::Init { is_ack: false, .. } => Some(E::InitSynReceived),
        #[cfg(feature = "codec-init-body")]
        InboundFrame::Init { is_ack: true, .. } => Some(E::InitAckReceived),
        #[cfg(feature = "codec-open-body")]
        InboundFrame::Open { is_ack: false, .. } => Some(E::OpenSynReceived),
        #[cfg(feature = "codec-open-body")]
        InboundFrame::Open { is_ack: true, .. } => Some(E::OpenAckReceived),
        #[cfg(feature = "codec-close")]
        InboundFrame::Close { .. } => Some(E::PeerClose),
        #[cfg(feature = "codec-keep-alive")]
        InboundFrame::KeepAlive { .. } => None,
        #[cfg(feature = "codec-frame")]
        InboundFrame::Frame { .. } => None,
        // R311im — Fragment is not a session-state trigger (like Frame);
        // the drive loop routes it to the ReassemblyDispatcher and, on
        // chain completion, the reassembled message re-enters the Frame
        // payload dispatch path.
        #[cfg(feature = "reassembly")]
        InboundFrame::Fragment { .. } => None,
        InboundFrame::Unknown { .. } => Some(E::FramingError),
    }
}

/// R68c — decode the trailing Z-flag-gated transport ext chain into the
/// lifetime-free owned mirror. Bounded by [`MAX_EXT_CHAIN_DEPTH`] so a
/// malformed peer cannot pin the decoder into an unbounded loop.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame"
))]
fn decode_ext_chain(cursor: &mut SceCursor<'_>) -> Result<Vec<ExtEntryOwned>, InboundParseError> {
    let mut entries = Vec::new();
    for _ in 0..MAX_EXT_CHAIN_DEPTH {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        // Deep-copy the borrowed decode view into the lifetime-free
        // owned mirror so the parsed chain can outlive the input
        // buffer in `InboundFrame::*.extensions`.
        entries.push(entry.try_into_owned().map_err(InboundParseError::Codec)?);
        if !z {
            return Ok(entries);
        }
    }
    Err(InboundParseError::ExtChainOverflow)
}
