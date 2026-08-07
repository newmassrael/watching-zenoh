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
use crate::ext_chain::decode_ext_chain;
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
use wz_codecs::ext_entry::ExtEntryOwned;
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
/// R311y578 — DERIVES `Debug`. The prior note here said it could not,
/// because "the wz-codecs structs (`InitBody`/`OpenBody`) are sce-codegen
/// output and only derive `Default`". That stopped being true: the codegen
/// emits `#[derive(Debug, Clone, PartialEq)]` on every `*Owned` mirror
/// (`out/wz-codecs/init_body.rs:250`, `open_body.rs:179`,
/// `ext_entry.rs:238`), so the derive costs nothing and was blocked only by
/// a stale reason.
///
/// It is not cosmetic. A consumer OUTSIDE this workspace measured the gap
/// as a hard compile error (`E0277`) on `panic!("{other:?}")` — anything
/// that hands a decode to a log, a test failure message, or a view had to
/// write a conversion layer first, for a type whose every field was already
/// printable. `Clone` / `PartialEq` are deliberately NOT derived: the
/// variants carry owned `Vec` payloads, and a decode is a one-shot value
/// that consumers move rather than copy.
///
/// `serde` remains ABSENT and is not closable here: it would have to land
/// on the codegen'd `*Owned` mirrors, whose derive set is SCE's
/// (`rust_derive_policy::RustDeriveCategory::CodecStruct`) and whose tree
/// is read-only from this workspace.
#[derive(Debug)]
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
        /// R311y215 — the QoS priority projected from the `ext_qos` transport
        /// extension (id `0x1`, z64), [`Priority::DEFAULT`](crate::qos::Priority)
        /// when the frame carries none (a pre-QoS / DEFAULT-priority frame). wz
        /// decodes this feature-agnostically; whether a non-DEFAULT priority is
        /// HONORED (per-priority RX conduit) or dropped (an un-negotiated QoS
        /// frame — SN-safety F5) is decided at the [`crate::drive`] admit seam
        /// against the session's negotiated `is_qos`.
        priority: crate::qos::Priority,
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
        /// R311y215 — the QoS priority projected from the fragment's `ext_qos`
        /// (id `0x1`, z64), present on EVERY fragment of a QoS chain so the
        /// reassembly dispatcher can key the chain by (peer, reliable, priority).
        /// [`Priority::DEFAULT`](crate::qos::Priority) for a pre-QoS chain.
        priority: crate::qos::Priority,
        /// R311y578 — the chain-boundary markers projected from the Fragment's
        /// own ext space (`0x2 First` / `0x3 Drop`,
        /// [`crate::extfragment::project_markers`]). Decoded feature-agnostically,
        /// like `priority`: wz reads whatever the peer sent, and whether the
        /// markers are ENFORCED is the reassembly Router's call against the
        /// negotiated patch level ([`crate::extpatch`]). Both `false` for a
        /// patch-0 peer, which emits neither.
        markers: crate::extfragment::FragmentMarkers,
    },
    /// MID outside the handshake/close/keepalive set.
    Unknown { mid: u8 },
}

/// R311y215 — project the QoS priority carried by a decoded Frame/Fragment ext
/// chain: the z64 `ext_qos` extension (id `0x1`, `crate::extqos::QOS_EXT_ID`)
/// packs the priority in the low 3 bits (zenoh transport `QoSType`,
/// `transport/mod.rs:268-286`). Returns [`Priority::DEFAULT`](crate::qos::Priority)
/// when no such ext is present — a pre-QoS frame, byte-identical to today. The
/// scan is feature-agnostic (wz reads whatever the peer sent); honoring vs
/// dropping a non-DEFAULT priority is the [`crate::drive`] admit seam's call.
#[cfg(feature = "codec-frame")]
fn ext_qos_priority(extensions: &[ExtEntryOwned]) -> crate::qos::Priority {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    for ext in extensions {
        // id 0x1 in the Frame/Fragment ext space is QoS (0x2 First / 0x3 Drop
        // are Fragment-only unit exts); the z64 body carries the priority.
        if ext.ext_id() == 0x01 {
            if let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &ext.body {
                return crate::qos::Priority::from_wire((z.value & 0x07) as u8);
            }
        }
    }
    crate::qos::Priority::DEFAULT
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
            let priority = ext_qos_priority(&extensions);
            Ok(InboundFrame::Frame {
                reliable: (flags & wire_const::FLAG_T_FRAME_R) != 0,
                sn,
                payload,
                has_ext,
                extensions,
                priority,
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
            let priority = ext_qos_priority(&extensions);
            // R311y578 — project the chain-boundary markers BEFORE the ext
            // chain moves into the variant. Both are unit exts in the
            // Fragment's own id space (0x2 First / 0x3 Drop); the projector
            // matches on extension identity, so the z64 `ext_qos` at 0x1
            // above is never mistaken for one.
            let markers = crate::extfragment::project_markers(&extensions);
            Ok(InboundFrame::Fragment {
                reliable: (flags & wire_const::FLAG_T_FRAGMENT_R) != 0,
                sn,
                more: (flags & wire_const::FLAG_T_FRAGMENT_M) != 0,
                payload,
                has_ext,
                extensions,
                priority,
                markers,
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

// R2 (R311ww) — `decode_ext_chain` moved to the shared `crate::ext_chain` SSOT
// (encode counterpart + the extauth dispatch's inner method chain consume it
// too); imported above. Was an inline `fn` here.

// ── R311y578 — G6: `InboundFrame` prints. Measured from OUTSIDE the
//    workspace as a hard `E0277` on `panic!("{other:?}")`, so the gap was
//    a compile error for every consumer that wanted to log, assert on, or
//    view a decode. ──
#[cfg(all(test, feature = "reassembly"))]
mod debug_surface_tests {
    use super::*;
    use alloc::format;

    /// The derive is not decorative: the rendering must carry the decoded
    /// FIELD VALUES, so a log line or a failing assertion says what the
    /// frame actually was. Asserted over a real `parse_inbound` decode of
    /// a real emitted wire, not over a hand-built value.
    #[test]
    fn a_decoded_fragment_renders_its_fields() {
        // T_MID_FRAGMENT (0x06) | R (0x20) | M (0x40): a reliable
        // continuation fragment, VLE sn = 9, payload "hi".
        let wire = [0x06 | 0x20 | 0x40, 0x09, b'h', b'i'];
        let frame = parse_inbound(&wire).expect("decode the fragment");
        let rendered = format!("{frame:?}");
        assert!(
            rendered.contains("Fragment"),
            "the variant is named: {rendered}"
        );
        assert!(
            rendered.contains("sn: 9"),
            "the decoded sequence number is rendered: {rendered}"
        );
        assert!(
            rendered.contains("reliable: true") && rendered.contains("more: true"),
            "the header-flag discriminators are rendered: {rendered}"
        );
        assert!(
            rendered.contains("104") && rendered.contains("105"),
            "the payload bytes are rendered: {rendered}"
        );
    }

    /// The rendering distinguishes two frames that differ only in a field
    /// — a `Debug` that collapsed to a variant name would pass the
    /// containment checks above while telling a consumer nothing.
    #[test]
    fn two_frames_differing_in_one_field_render_differently() {
        let a = parse_inbound(&[0x06 | 0x20, 0x01, b'x']).expect("decode a");
        let b = parse_inbound(&[0x06 | 0x20, 0x02, b'x']).expect("decode b");
        assert_ne!(format!("{a:?}"), format!("{b:?}"));
    }
}
