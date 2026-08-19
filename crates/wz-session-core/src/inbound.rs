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

// `Vec`, the cursor, the wire constants, and the ext-entry types used to fold
// under a `cfg(any(codec-*))` union: every consumer was a gated decode arm, so
// an arbitrary feature subset had to stay unused-import clean under
// `deny(warnings)`. The union is gone because `parse_inbound`'s transport-OAM
// arm is UNCONDITIONAL — it needs no generated body codec, so every build of
// this (already `alloc`-gated) module reads a z16, an ext chain and a body
// with these four.
use alloc::vec::Vec;

use crate::parse_error::InboundParseError;

use crate::ext_chain::decode_ext_chain;
use sce_forge_runtime::codec::SceCursor;
use wz_codecs::ext_entry::ExtEntryOwned;
use wz_codecs::wire_const;

#[cfg(feature = "codec-close")]
use wz_codecs::close::Close;
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::{InitBody, InitBodyOwned};
#[cfg(feature = "codec-join")]
use wz_codecs::join::JoinOwned;
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
    ///
    /// R311y839 — `session` mirrors `_Z_FLAG_T_CLOSE_S`, the SCOPE the peer asked
    /// for: `true` = tear the whole session down, `false` = drop only the link the
    /// frame arrived on. It sits here for the same reason `is_ack` sits on
    /// [`Self::Open`] and `reliable` on [`Self::Frame`] — the parent flag is a
    /// field of the message, and this arm was the one that dropped its flag on the
    /// floor. Without it a link-only Close and a session Close decoded to the same
    /// value, so no consumer could act on the difference zenoh's receiver branches
    /// on (`delete()` vs `del_link(link)`,
    /// `io/zenoh-transport/src/unicast/universal/rx.rs:60-73`) — and `false` is
    /// the value EVERY unicast Close zenoh 1.5.0 constructs carries
    /// (`unicast/link.rs:103-113`, `universal/transport.rs:383-403`,
    /// `lowlatency/transport.rs:91-108`).
    #[cfg(feature = "codec-close")]
    Close {
        reason: u8,
        session: bool,
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
    /// `_Z_MID_T_JOIN` (0x07). The MULTICAST peer announcement: version,
    /// whatami + zid, the optional S-gated capability pair (`sn_res` /
    /// `batch_size`), the lease, and the per-channel initial sequence numbers.
    ///
    /// R311y605 — decoded here because the PASSIVE observer reads a capture
    /// through this function, and a JOIN arrived as `Unknown { mid: 0x07 }`:
    /// on zenoh's multicast session group the announcement traffic IS the
    /// JOINs, so an analyzer over a multicast capture saw its most
    /// informative message as unnamed bytes.
    ///
    /// It is NOT admissible on a unicast session, and that is the drive
    /// seam's call rather than this one's: [`inbound_to_fsm_event`] maps it to
    /// `FramingError`, byte-for-byte the pre-R311y605 behaviour when it fell
    /// through to `Unknown`. The same separation `Frame`'s `priority` and
    /// `Fragment`'s `markers` already use — wz decodes whatever the peer
    /// sent, and whether it is HONORED is decided one layer up.
    ///
    /// `body.lease` is ALWAYS milliseconds: the `_Z_FLAG_T_JOIN_T` seconds
    /// form is projected back during decode (R311kr,
    /// [`crate::join_decode::decode_join`]), the same boundary rule
    /// `Open`'s lease follows.
    #[cfg(feature = "codec-join")]
    Join {
        has_ext: bool,
        body: JoinOwned,
        extensions: Vec<ExtEntryOwned>,
    },
    /// `id::OAM` (0x00) — operations and maintenance, the one transport MID
    /// whose body shape is chosen by the HEADER: bits 5..6 are the encoding
    /// (`iext::ENC_*`), and the ext chain is written BEFORE the body rather
    /// than after it (`zenoh-codec/src/transport/oam.rs`).
    ///
    /// UNGATED, alone among the arms, because it needs no generated body
    /// codec: `id` is a `z16`, the chain is the shared decoder, and the body
    /// is either absent, one VLE, or a length-prefixed run of bytes this
    /// decoder does not interpret. There is no `codec-oam` feature to select
    /// because there is nothing behind it to select.
    ///
    /// Decoded here for R311y605's reason, one MID over: the PASSIVE observer
    /// reads a capture through this function, and an OAM arrived as
    /// `Unknown { mid: 0x00 }` — which consumes ZERO bytes, so the batch walk
    /// stopped there and reported everything behind it as unaccounted for. A
    /// message that cannot be measured cannot be stepped over.
    ///
    /// `body` is the ZBuf run verbatim and is empty for the Unit and Z64
    /// encodings; `value` carries the Z64 and is `0` otherwise. `encoding` is
    /// kept rather than projected away because it is what says WHICH of the
    /// two is meaningful — and because upstream reserves 0b11, which never
    /// reaches this variant (the arm refuses it, as zenoh's decoder does).
    Oam {
        id: u16,
        encoding: u8,
        value: u64,
        body: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// MID outside the handshake/close/keepalive set.
    Unknown { mid: u8 },
}

impl InboundFrame {
    /// R311y630 (§14.1) — what a conforming PARTICIPANT must do with this
    /// frame's extension chain: [`ExtAdmission::UnknownMandatory`] means the
    /// peer marked an extension mandatory that this message's space does not
    /// define, and the whole message must be refused.
    ///
    /// A METHOD rather than a rejection inside [`parse_inbound`], because the
    /// two consumers of a decode have opposite obligations. An analyzer must
    /// still SEE the extension — "this frame carries a mandatory extension
    /// nobody implements" is the most useful sentence it can produce about
    /// such a frame — while a participant must refuse. The same separation
    /// `Frame`'s `priority`, `Fragment`'s `markers` and a JOIN on a unicast
    /// session already use: wz decodes whatever the peer sent, and whether the
    /// message is ADMISSIBLE is decided one layer up.
    ///
    /// `Unknown { mid }` answers [`ExtAdmission::Unjudged`]: this build cannot
    /// name the message, so it has no extension space to judge the chain
    /// against, and a reach limit reported as admission is exactly how an
    /// observer's blind spot becomes a participant's accepted message.
    pub fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        use crate::ext_admit::ExtAdmission;
        // Each arm names its own MID constant rather than deriving one from a
        // stored header byte: the variants do not carry the header, and the
        // MID is what SELECTED the variant, so the constant is the fact.
        #[cfg(any(
            feature = "codec-init-body",
            feature = "codec-open-body",
            feature = "codec-close",
            feature = "codec-keep-alive",
            feature = "codec-frame",
            feature = "codec-join"
        ))]
        fn judge(mid: u8, entries: &[ExtEntryOwned]) -> ExtAdmission {
            crate::ext_admit::judge_ext_chain(
                crate::ext_admit::ExtCarrier::Transport(mid),
                entries.iter().map(|e| e.header),
            )
        }
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { extensions, .. } => judge(wire_const::T_MID_INIT, extensions),
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open { extensions, .. } => judge(wire_const::T_MID_OPEN, extensions),
            #[cfg(feature = "codec-close")]
            InboundFrame::Close { extensions, .. } => judge(wire_const::T_MID_CLOSE, extensions),
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { extensions, .. } => {
                judge(wire_const::T_MID_KEEP_ALIVE, extensions)
            }
            #[cfg(feature = "codec-frame")]
            InboundFrame::Frame { extensions, .. } => judge(wire_const::T_MID_FRAME, extensions),
            #[cfg(feature = "reassembly")]
            InboundFrame::Fragment { extensions, .. } => {
                judge(wire_const::T_MID_FRAGMENT, extensions)
            }
            #[cfg(feature = "codec-join")]
            InboundFrame::Join { extensions, .. } => judge(wire_const::T_MID_JOIN, extensions),
            // Its own `judge_ext_chain` call rather than the local `judge`
            // helper: that helper folds under the `codec-*` union above and
            // this arm carries no gate, so it would vanish in a build that
            // still has this variant.
            InboundFrame::Oam { extensions, .. } => crate::ext_admit::judge_ext_chain(
                crate::ext_admit::ExtCarrier::Transport(wire_const::T_MID_OAM),
                extensions.iter().map(|e| e.header),
            ),
            InboundFrame::Unknown { .. } => ExtAdmission::Unjudged,
        }
    }

    /// R311y668 (§1.2a) — what this message IS, in one word: the variant's own
    /// identifier.
    ///
    /// # Why the name belongs to the type and not to the listing that prints it
    ///
    /// R311y667 gave the analyzer's `--messages` listing a name per message by
    /// reading the leading token of the derived `Debug` rendering, and the
    /// reason it gave for not matching was sound *in that crate*: these variants
    /// are individually `#[cfg]`-gated on seven `codec-*` features the analyzer
    /// does not own, so an exhaustive match there would MIRROR those gates, and
    /// a mirror drifts. A `_ =>` arm is worse — it is the arm that reports a new
    /// message kind as whatever the default happens to be.
    ///
    /// What that left behind is a name resting on a `Debug` shape nothing pins.
    /// Here there is no mirror to drift: the arms sit beside the variants under
    /// the same `#[cfg]`s, and exhaustiveness is the COMPILER's, so a variant
    /// added upstream fails this match rather than silently taking a fallback.
    /// That is the separation [`Self::ext_admission`] already uses, and it is
    /// why this is a method on the type rather than a function in the reader.
    ///
    /// `&'static str`, because the caller is a listing that prints a direction
    /// and an offset on the same line and a name is one field of it.
    pub fn kind_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { .. } => "Init",
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open { .. } => "Open",
            #[cfg(feature = "codec-close")]
            InboundFrame::Close { .. } => "Close",
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { .. } => "KeepAlive",
            #[cfg(feature = "codec-frame")]
            InboundFrame::Frame { .. } => "Frame",
            #[cfg(feature = "reassembly")]
            InboundFrame::Fragment { .. } => "Fragment",
            #[cfg(feature = "codec-join")]
            InboundFrame::Join { .. } => "Join",
            InboundFrame::Oam { .. } => "Oam",
            // NOT "Unknown message" and not the MID in hex: this is the
            // variant's name like every other arm, and the MID a reader needs is
            // on the variant for whoever wants it. A name that folded the byte
            // in would make two frames with different MIDs two different kinds.
            InboundFrame::Unknown { .. } => "Unknown",
        }
    }
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
    parse_inbound_consuming(bytes).map(|(frame, _)| frame)
}

/// R311y631 (§1.2b) — the same decode, told how many bytes it ATE.
///
/// # Why the length has to come out
///
/// One framing unit is not one transport message. Both reference
/// implementations decode a *batch*: zenoh reads `while !batch.is_empty()`
/// on the multicast datagram path
/// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`) and on the unicast
/// stream path (`.../unicast/universal/rx.rs:220`), and pico keeps the
/// residue of a datagram in its own buffer and decodes the NEXT message out
/// of it without reading a new datagram at all
/// (`vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`, advancing the read
/// position by exactly what one message consumed at `:99`). A reader that
/// decodes the front of a framing unit and stops is therefore not reading a
/// stricter dialect — it is dropping messages both peers would have processed.
///
/// The consumed length is the only thing a caller needs to walk to the next
/// message, and it is knowable only here: it is where the cursor stopped, and
/// the cursor is this function's local.
///
/// # What `0` means
///
/// `Ok((InboundFrame::Unknown { .. }, 0))` is NOT "an empty message". It is
/// *this decoder cannot say where that message ends* — an unrecognised MID has
/// no length this build knows how to skip — so a caller walking a batch must
/// stop and report the rest as unaccounted rather than guess a boundary.
/// [`InboundFrame::Frame`] and `Fragment` legitimately return `bytes.len()`:
/// they consume the remainder by construction, which is why upstream puts them
/// last in a batch (`zenoh-codec-1.5.0/src/transport/frame.rs:173`).
pub fn parse_inbound_consuming(bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
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
    // R311y879 — `codec-keep-alive` is DELIBERATELY absent from this third
    // union while it stays in the two above. The KeepAlive arm reads `has_ext`
    // but delegates the bytes to `decode_keep_alive`, which owns its own
    // cursor (R311y878's `#[inline(never)]` split), so a build that selects
    // only that codec binds an outer cursor nothing touches — and
    // `-D unused-mut` makes that a compile ERROR, not a warning. The three
    // unions are the same list minus one arm for that reason; they are not a
    // copy that drifted.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
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
            Ok((
                InboundFrame::Init {
                    is_ack: (flags & wire_const::FLAG_T_INIT_A) != 0,
                    has_ext,
                    body,
                    extensions,
                },
                bytes.len() - cursor.remaining(),
            ))
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
            Ok((
                InboundFrame::Open {
                    is_ack: (flags & wire_const::FLAG_T_OPEN_A) != 0,
                    has_ext,
                    body,
                    extensions,
                },
                bytes.len() - cursor.remaining(),
            ))
        }
        #[cfg(feature = "codec-close")]
        wire_const::T_MID_CLOSE => {
            let body = Close::decode(&mut cursor)?;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok((
                InboundFrame::Close {
                    reason: body.reason,
                    // R311y839 — the scope bit, read off the parent header exactly
                    // as the Open arm reads `FLAG_T_OPEN_A` and the Frame arm reads
                    // `FLAG_T_FRAME_R`.
                    session: (flags & wire_const::FLAG_T_CLOSE_S) != 0,
                    has_ext,
                    extensions,
                },
                bytes.len() - cursor.remaining(),
            ))
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
            Ok((
                InboundFrame::Frame {
                    reliable: (flags & wire_const::FLAG_T_FRAME_R) != 0,
                    sn,
                    payload,
                    has_ext,
                    extensions,
                    priority,
                },
                bytes.len() - cursor.remaining(),
            ))
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
            Ok((
                InboundFrame::Fragment {
                    reliable: (flags & wire_const::FLAG_T_FRAGMENT_R) != 0,
                    sn,
                    more: (flags & wire_const::FLAG_T_FRAGMENT_M) != 0,
                    payload,
                    has_ext,
                    extensions,
                    priority,
                    markers,
                },
                bytes.len() - cursor.remaining(),
            ))
        }
        #[cfg(feature = "codec-keep-alive")]
        wire_const::T_MID_KEEP_ALIVE => decode_keep_alive(has_ext, bytes),
        // R311y605 — the MULTICAST peer announcement. Self-contained rather
        // than riding the shared `cursor`: the generated `Join` codec has no
        // ext awareness, so the chain starts wherever the base body stopped
        // and `join_base_len` derives that from the codec's own consumption.
        // `decode_join` is the SSOT shared with the multicast participant path
        // (`crate::join_decode`), which is what keeps the S bit's two optional
        // fields and the T bit's lease UNIT projected in exactly one place.
        #[cfg(feature = "codec-join")]
        wire_const::T_MID_JOIN => {
            let (join, consumed) = crate::join_decode::decode_join_body(header, &bytes[1..])?;
            let body = join.try_into_owned()?;
            let join_has_ext = (header & wire_const::FLAG_T_Z) != 0;
            // R311y631 — hoisted out of the `if` so the consumed length can be
            // read off it in BOTH arms. With no chain it has advanced nothing,
            // which makes the subtraction below say `1 + consumed` — the base
            // body and nothing else — without a second expression to keep in
            // step with this one.
            let mut ext_cursor = SceCursor::new(&bytes[1 + consumed..]);
            let extensions = if join_has_ext {
                decode_ext_chain(&mut ext_cursor)?
            } else {
                Vec::new()
            };
            Ok((
                InboundFrame::Join {
                    has_ext: join_has_ext,
                    body,
                    extensions,
                },
                bytes.len() - ext_cursor.remaining(),
            ))
        }
        // Transport OAM, DELEGATED like the JOIN arm above rather than spelled
        // out here — see [`decode_oam`] for the second, measured reason.
        wire_const::T_MID_OAM => decode_oam(header, bytes),
        // Zero: see the `# What `0` means` section on this function.
        other => Ok((InboundFrame::Unknown { mid: other }, 0)),
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
    // R311y630 (§14.1) — THE MANDATORY-EXTENSION RULE, ahead of every
    // per-variant projection because it applies to all of them and because the
    // variants that answer `None` below (Frame / Fragment / KeepAlive) would
    // otherwise reach the drive loop's data path with a message no conforming
    // participant may act on. `FramingError` is the same response an
    // unimplemented MID gets, for the same reason: the peer sent something this
    // side has provably not understood, and Close(generic) on the link is the
    // wire-correct answer. Measured against the real `libzenohpico.so` — the
    // driving oracle's first run disagreed with pico on eighteen generated
    // strings and every one of them was this.
    if let crate::ext_admit::ExtAdmission::UnknownMandatory { .. } = frame.ext_admission() {
        return Some(E::FramingError);
    }
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
        // R311y605 — a JOIN is a MULTICAST message and has no place on a
        // unicast session, so it stays a framing error here. Deliberately
        // identical to the pre-R311y605 outcome, when it fell through to
        // `Unknown` and hit the arm below: gaining the ability to DECODE a
        // message must not change what the session FSM does with it.
        #[cfg(feature = "codec-join")]
        InboundFrame::Join { .. } => Some(E::FramingError),
        // Transport OAM, on the same rule the JOIN arm above states: gaining
        // the ability to DECODE a message must not change what the session FSM
        // does with it. wz's unicast FSM has no operations-and-maintenance
        // transition, so a peer that sends one is sending a message this side
        // cannot act on — byte-for-byte the outcome it had while it fell
        // through to `Unknown`. What changed is the OBSERVER's reach, which is
        // where the defect was.
        InboundFrame::Oam { .. } => Some(E::FramingError),
        InboundFrame::Unknown { .. } => Some(E::FramingError),
    }
}

/// The KEEP_ALIVE body (`T_MID_KEEP_ALIVE`, 0x04): empty, so the only thing to
/// read is the Z-gated ext chain behind it. The generated decoder is still
/// called — a no-op that keeps the "every wire-mapped codec routes through its
/// generated decoder" invariant.
///
/// # Why this one is a function, and `#[inline(never)]`
///
/// R311y878 — TO GIVE `codec-keep-alive` A NAME THE ELISION GATE CAN SEE.
/// `measure-codec-footprint.sh` judges a codec two ways: a byte delta between
/// two 2.7MB binaries, and a by-name witness. This codec had neither that held
/// — its byte lane has degraded every time `parse_inbound_consuming` grew
/// (208 -> 128 -> 96 -> floor 64, each re-pin recorded there), because what it
/// really measures at that magnitude is the CALLER's inline boundary; and a
/// name-set diff of the two binaries returned ZERO symbols present in the
/// baseline and absent without the feature, so there was nothing to pin as a
/// witness either. A bodyless message that is entirely inlined is invisible to
/// both halves of the gate.
///
/// Behind this boundary it is one symbol that exists in the baseline and does
/// not exist without the feature, which is the claim the catalog actually
/// makes. `CODEC_ELISION_WITNESS[codec-keep-alive]` names it.
#[cfg(feature = "codec-keep-alive")]
#[inline(never)]
fn decode_keep_alive(
    has_ext: bool,
    bytes: &[u8],
) -> Result<(InboundFrame, usize), InboundParseError> {
    let mut cursor = SceCursor::new(&bytes[1..]);
    let _body = KeepAlive::decode(&mut cursor)?;
    let extensions = if has_ext {
        decode_ext_chain(&mut cursor)?
    } else {
        Vec::new()
    };
    Ok((
        InboundFrame::KeepAlive {
            has_ext,
            extensions,
        },
        bytes.len() - cursor.remaining(),
    ))
}

/// The transport-OAM body (`T_MID_OAM`, 0x00), decoded off its own cursor.
///
/// # Why it is a function and not a match arm
///
/// The shape reason: it reads the wire in an order no other transport MID uses
/// — `id:z16`, then the ext chain, then a body whose ENCODING came from header
/// bits 5..6 — and it binds its own cursor because the shared one is bound
/// only under the `codec-*` union, which this arm does not join. That is the
/// same separation the JOIN arm's `decode_join_body` delegate already has.
///
/// # Why `#[inline(never)]`, which is the MEASURED half
///
/// Layer F judges each `codec-*` feature by the byte delta between two 2.7MB
/// binaries, so an arm that grows `parse_inbound_consuming` moves the CALLER's
/// inline boundary and surfaces as a NEIGHBOURING codec's elision changing.
/// Measured, not feared: with this body inline, `minus codec-keep-alive` read
/// -192 B against its 64 B floor and failed the gate; behind this boundary it
/// reads +240 B, which is what that codec elided before this arm existed. The
/// alternative was re-pinning that floor into the noise band, and the same
/// script says a re-pin there must arrive with a by-name elision witness —
/// which `codec-keep-alive` cannot supply, because a name-set diff of the two
/// binaries shows ZERO symbols present in the baseline and absent without it.
/// Keeping the boundary is therefore the honest fix and lowering the floor
/// would have been the silencing.
#[inline(never)]
fn decode_oam(header: u8, bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
    let mut cursor = SceCursor::new(&bytes[1..]);
    // The id's WIRE width is a full zint and its VALUE width is 16 bits, and
    // upstream bridges the two by TRUNCATING (`oam_id_from_wire`). Reading it
    // with the refusing `read_vle_u16` — which R311y878 did — makes this
    // decoder answer `Err` on a message stock zenoh reads to the end, and an
    // `Err` here consumes nothing, so the batch walk stops and every message
    // behind the OAM is lost. That is the very defect the arm was added to
    // remove, moved from the MID to one of its fields.
    let id = wz_codecs::wire_const::oam_id_from_wire(
        cursor.read_vle_u64().map_err(InboundParseError::Codec)?,
    );
    // `0x80` spelled out: `wire_const::FLAG_T_Z` is itself gated on the
    // `codec-*` union this function deliberately stays out of, and the ungated
    // `transport_flag_mask` table spells the same bit the same way.
    let has_ext = (header & 0x80) != 0;
    let extensions = if has_ext {
        decode_ext_chain(&mut cursor)?
    } else {
        Vec::new()
    };
    // The body LAST, and only after the chain: reversing the two would read
    // the first extension's header byte as a Z64 body.
    let encoding = (header & wire_const::FLAG_T_OAM_ENC) >> 5;
    let mut value = 0u64;
    let mut body = Vec::new();
    match encoding {
        0 => {}
        1 => {
            value = cursor.read_vle_u64().map_err(InboundParseError::Codec)?;
        }
        2 => {
            let n = cursor.read_vle_u64().map_err(InboundParseError::Codec)? as usize;
            body = cursor
                .peek_slice(n)
                .map_err(InboundParseError::Codec)?
                .to_vec();
            cursor.advance(n).map_err(InboundParseError::Codec)?;
        }
        // 0b11 is RESERVED and zenoh's own decoder returns `DidntRead` for it
        // (`transport/oam.rs`). Refused here for the same reason a corrupt body
        // is: a sender that wrote it wrote a message no conforming peer
        // retrieves, and reporting a length for it would step the batch walk
        // onto invented bytes.
        _ => return Err(InboundParseError::ReservedEncoding),
    }
    Ok((
        InboundFrame::Oam {
            id,
            encoding,
            value,
            body,
            has_ext,
            extensions,
        },
        bytes.len() - cursor.remaining(),
    ))
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

// ── R311y630 (§14.1) — the MANDATORY-extension rule at the PARTICIPANT seam.
//    Measured against the real `libzenohpico.so`: eighteen generated strings
//    were messages wz named and pico refused, and every one of them carried a
//    mandatory extension nothing defines. ──
#[cfg(all(test, feature = "session-unicast", feature = "codec-frame"))]
mod mandatory_ext_tests {
    use super::*;
    use crate::ext_admit::ExtAdmission;
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;

    /// A `T_MID_FRAME` with the Z flag, VLE sn, then the caller's ext chain and
    /// a one-byte payload. Built here rather than taken from a fixture because
    /// the ext HEADER is the whole variable under test.
    fn frame_with_chain(chain: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![wire_const::T_MID_FRAME | wire_const::FLAG_T_Z, 0x07];
        wire.extend_from_slice(chain);
        wire.push(0xEE);
        wire
    }

    /// THE GATE. A Frame is not a session-state trigger and answers `None`, so
    /// a mandatory extension nobody defines would otherwise reach the drive
    /// loop's DATA path — the frame would be delivered on a message this side
    /// has provably not understood. It must be a framing error instead, which
    /// is what both upstreams do with the whole message.
    #[test]
    fn a_frame_carrying_an_undefined_mandatory_extension_is_a_framing_error() {
        // id 0x4, UNIT encoding, M set, chain terminator.
        let frame = parse_inbound(&frame_with_chain(&[0x14])).expect("the frame still DECODES");
        assert!(
            matches!(
                frame.ext_admission(),
                ExtAdmission::UnknownMandatory { eid: 0x14 }
            ),
            "the decode must name the offending extension: {frame:?}"
        );
        assert!(matches!(
            inbound_to_fsm_event(&frame),
            Some(E::FramingError)
        ));
    }

    /// The DISCRIMINATING negative arm, and it is two-sided because two
    /// different mistakes would pass a one-sided one.
    ///
    /// A rule that refused every unrecognised extension would break the
    /// non-mandatory chains zenoh and pico both SKIP, and a rule that never
    /// consulted the per-message space would break the one mandatory extension
    /// the data plane defines (`frame::ext::QoS`, `zextz64!(0x1, true)` =
    /// `0x31`). Both must stay `None` — the Frame's own answer — and neither
    /// can be shown by the positive leg above.
    #[test]
    fn a_non_mandatory_or_understood_extension_leaves_the_frame_deliverable() {
        for chain in [
            // id 0x4, UNIT, mandatory bit CLEAR.
            &[0x04u8][..],
            // `frame::ext::QoS` — mandatory, and understood.
            &[0x31u8, 0x00][..],
        ] {
            let frame = parse_inbound(&frame_with_chain(chain)).expect("decode");
            assert_eq!(
                frame.ext_admission(),
                ExtAdmission::Admissible,
                "chain {chain:02X?} must be admissible"
            );
            assert!(
                inbound_to_fsm_event(&frame).is_none(),
                "chain {chain:02X?} must stay a data-plane frame"
            );
        }
    }

    /// The rule reaches the HANDSHAKE messages too, and there the effect is
    /// visible as a CHANGED event rather than as `None` becoming `Some`: an
    /// InitSyn that would have been `InitSynReceived` is a framing error when
    /// it carries an extension it marks mandatory and nothing defines.
    #[cfg(feature = "codec-init-body")]
    #[test]
    fn the_rule_overrides_the_handshake_projection_too() {
        // version, cbyte (zid_len-1 = 0, whatami peer), the 1-byte zid, then
        // the Z-gated chain. No S / A flags, so the base body ends there.
        let admissible = alloc::vec![
            wire_const::T_MID_INIT | wire_const::FLAG_T_Z,
            0x09,
            0x01,
            0xAA,
            0x04
        ];
        let frame = parse_inbound(&admissible).expect("decode the InitSyn");
        assert!(matches!(
            inbound_to_fsm_event(&frame),
            Some(E::InitSynReceived)
        ));

        let mut inadmissible = admissible.clone();
        // Same extension, mandatory marker set.
        *inadmissible.last_mut().expect("chain byte") = 0x14;
        let frame = parse_inbound(&inadmissible).expect("the InitSyn still DECODES");
        assert!(matches!(
            inbound_to_fsm_event(&frame),
            Some(E::FramingError)
        ));
    }
}

// ── R311y605 — the JOIN arm. `parse_inbound` is what the PASSIVE observer
//    reads a capture through, and it reported every multicast peer
//    announcement as `Unknown { mid: 0x07 }` — a successful parse, which is
//    why nothing downstream noticed. ──
#[cfg(all(test, feature = "codec-join"))]
mod join_tests {
    use super::*;

    /// Encode a JOIN through the codec, with the header byte's flags supplied
    /// by the caller. The fixture is the CODEC's bytes rather than a hand-laid
    /// string, so a decode that disagrees with the codec fails here.
    fn join_wire(flags: u8, join: &wz_codecs::join::Join<'_>) -> Vec<u8> {
        let s = u8::from(flags & wire_const::FLAG_T_JOIN_S != 0);
        let mut wire = alloc::vec![wire_const::T_MID_JOIN | flags];
        wire.extend_from_slice(&join.encode_to_vec(s));
        wire
    }

    fn sample() -> wz_codecs::join::Join<'static> {
        wz_codecs::join::Join {
            version: 0x09,
            // whatami = peer (0x01), zid_len-1 = 3.
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: Some(0x00),
            batch_size: Some(0x1000),
            lease: 10_000,
            next_sn_reliable: 7,
            next_sn_best_effort: 9,
        }
    }

    #[test]
    fn a_join_decodes_into_its_own_variant_with_its_fields() {
        let wire = join_wire(wire_const::FLAG_T_JOIN_S, &sample());
        match parse_inbound(&wire).expect("parse_inbound rejected the join") {
            InboundFrame::Join {
                has_ext,
                body,
                extensions,
            } => {
                assert!(!has_ext);
                assert!(extensions.is_empty());
                assert_eq!(body.version, 0x09);
                assert_eq!(body.zid.as_ref(), &[0xA0, 0xA1, 0xA2, 0xA3]);
                assert_eq!(body.sn_res, Some(0x00));
                assert_eq!(body.batch_size, Some(0x1000));
                assert_eq!(body.lease, 10_000);
                assert_eq!(body.next_sn_reliable, 7);
                assert_eq!(body.next_sn_best_effort, 9);
            }
            other => panic!("not a Join: {other:?}"),
        }
    }

    /// The S-clear form. The discriminating arm: a decode that read the two
    /// optionals unconditionally would consume two bytes too many and either
    /// fail or mis-report the lease, and the S-set leg above cannot see that.
    #[test]
    fn an_s_clear_join_carries_no_capability_pair() {
        let minimal = wz_codecs::join::Join {
            sn_res: None,
            batch_size: None,
            ..sample()
        };
        let wire = join_wire(0, &minimal);
        match parse_inbound(&wire).expect("parse_inbound rejected the minimal join") {
            InboundFrame::Join { body, .. } => {
                assert_eq!(body.sn_res, None);
                assert_eq!(body.batch_size, None);
                assert_eq!(body.lease, 10_000, "the lease must still be read");
                assert_eq!(body.next_sn_best_effort, 9);
            }
            other => panic!("not a Join: {other:?}"),
        }
    }

    /// The T flag makes the lease VLE SECONDS. Projected at this boundary, so
    /// no consumer of a decode ever sees the wire unit — the rule
    /// `Open`'s lease already follows, and the reason a pico beacon
    /// (lease 10000ms, sent as T=1 + VLE 10) is not read as 10ms.
    #[test]
    fn a_t_flagged_lease_is_projected_to_milliseconds() {
        let seconds = wz_codecs::join::Join {
            lease: 10,
            sn_res: None,
            batch_size: None,
            ..sample()
        };
        let wire = join_wire(wire_const::FLAG_T_JOIN_T, &seconds);
        match parse_inbound(&wire).expect("parse_inbound rejected the join") {
            InboundFrame::Join { body, .. } => assert_eq!(body.lease, 10_000),
            other => panic!("not a Join: {other:?}"),
        }
        // Negative arm: the same VLE without T is milliseconds already, so a
        // decode that multiplied unconditionally would show 10_000 here too.
        let wire = join_wire(0, &seconds);
        match parse_inbound(&wire).expect("parse_inbound rejected the join") {
            InboundFrame::Join { body, .. } => assert_eq!(body.lease, 10),
            other => panic!("not a Join: {other:?}"),
        }
    }

    /// A Z-flagged JOIN's ext chain starts where the BASE BODY stopped, which
    /// is why the arm derives that offset from the codec's own consumption
    /// rather than from the field widths. With S set the base body is longer by
    /// three bytes, so a hardcoded offset would read the chain from inside the
    /// body — and the QoS ext is the one zenoh and pico actually send.
    #[test]
    fn a_z_flagged_join_reads_its_ext_chain_after_the_base_body() {
        // `_Z_MSG_EXT_ID_JOIN_QOS` = id 0x1 | M (0x10) | ENC_ZBUF (0x40).
        const JOIN_QOS_EXT_HEADER: u8 = 0x51;
        let mut ext = alloc::vec![JOIN_QOS_EXT_HEADER, 2, 0x11, 0x22];
        let mut wire = join_wire(wire_const::FLAG_T_JOIN_S | wire_const::FLAG_T_Z, &sample());
        wire.append(&mut ext);
        match parse_inbound(&wire).expect("parse_inbound rejected the qos join") {
            InboundFrame::Join {
                has_ext,
                extensions,
                body,
            } => {
                assert!(has_ext);
                assert_eq!(
                    extensions.len(),
                    1,
                    "the chain must be read from after the base body: {extensions:?}"
                );
                assert_eq!(extensions[0].ext_id(), 0x01);
                // The body is still fully read — the chain did not eat into it.
                assert_eq!(body.next_sn_best_effort, 9);
            }
            other => panic!("not a Join: {other:?}"),
        }
    }

    /// A truncated JOIN is a codec ERROR, not an `Unknown` and not a silent
    /// empty body. Absence and failure are different verdicts.
    #[test]
    fn a_truncated_join_reports_the_codec_error() {
        let wire = join_wire(wire_const::FLAG_T_JOIN_S, &sample());
        let err = parse_inbound(&wire[..wire.len() - 2]).expect_err("a short join must not decode");
        assert!(
            matches!(err, InboundParseError::Codec(_)),
            "expected a codec error, got {err:?}"
        );
    }

    /// Gaining the ability to DECODE a JOIN must not change what the unicast
    /// session FSM does with one. It is a multicast message with no place on a
    /// unicast link, and it mapped to `FramingError` before this round by
    /// falling through to `Unknown` — so it maps to `FramingError` now.
    #[cfg(feature = "session-unicast")]
    #[test]
    fn a_join_on_a_unicast_session_is_still_a_framing_error() {
        use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
        let wire = join_wire(wire_const::FLAG_T_JOIN_S, &sample());
        let frame = parse_inbound(&wire).expect("decode the join");
        assert!(matches!(frame, InboundFrame::Join { .. }));
        assert!(matches!(
            inbound_to_fsm_event(&frame),
            Some(E::FramingError)
        ));
    }
}

// ── R311y668 (§1.2a) — the NAME. `kind_name` is the word a reader's listing puts
//    on the line, and until this round it came from the leading token of a
//    derived `Debug` rendering, in a crate that could not match these variants.
//    Every name below is asserted over a real `parse_inbound` decode of real
//    wire, on the house rule the `Debug` tests above follow: a name proven over
//    a hand-built value proves the constructor, not the decoder. ──
#[cfg(test)]
mod kind_name_tests {
    use super::*;
    use alloc::vec::Vec;

    /// Every variant this build can reach, as (wire, expected name).
    ///
    /// A VECTOR and not one test per variant, so the distinctness assertion
    /// below sees the whole set at once — two arms answering the same word is a
    /// listing that silently merges two message kinds, and no per-variant test
    /// can see it.
    // `vec![]` cannot express this: every element is `#[cfg]`-gated, and a macro
    // literal has no place to put the attribute. The lint is reading the shape and
    // not the reason.
    #[allow(clippy::vec_init_then_push)]
    fn reachable() -> Vec<(Vec<u8>, &'static str)> {
        let mut cases: Vec<(Vec<u8>, &'static str)> = Vec::new();

        #[cfg(feature = "codec-init-body")]
        // version, cbyte (zid_len-1 = 0, whatami peer), then the 1-byte zid.
        cases.push((
            alloc::vec![wire_const::T_MID_INIT, 0x09, 0x01, 0xAA],
            "Init",
        ));

        #[cfg(feature = "codec-open-body")]
        // The ACK form: `a` clears the cookie fields, so lease + initial_sn is
        // the whole body.
        cases.push((
            alloc::vec![
                wire_const::T_MID_OPEN | wire_const::FLAG_T_OPEN_A,
                0x0A,
                0x01
            ],
            "Open",
        ));

        #[cfg(feature = "codec-close")]
        cases.push((alloc::vec![wire_const::T_MID_CLOSE, 0x00], "Close"));

        #[cfg(feature = "codec-keep-alive")]
        cases.push((alloc::vec![wire_const::T_MID_KEEP_ALIVE], "KeepAlive"));

        #[cfg(feature = "codec-frame")]
        cases.push((
            alloc::vec![
                wire_const::T_MID_FRAME | wire_const::FLAG_T_FRAME_R,
                0x07,
                0xEE
            ],
            "Frame",
        ));

        #[cfg(feature = "reassembly")]
        cases.push((
            alloc::vec![
                wire_const::T_MID_FRAGMENT | wire_const::FLAG_T_FRAME_R,
                0x09,
                b'h'
            ],
            "Fragment",
        ));

        #[cfg(feature = "codec-join")]
        {
            let join = wz_codecs::join::Join {
                version: 0x09,
                cbyte: (3 << 4) | 0x01,
                zid: &[0xA0, 0xA1, 0xA2, 0xA3],
                sn_res: Some(0x00),
                batch_size: Some(0x1000),
                lease: 10_000,
                next_sn_reliable: 7,
                next_sn_best_effort: 9,
            };
            let mut wire = alloc::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
            wire.extend_from_slice(&join.encode_to_vec(1));
            cases.push((wire, "Join"));
        }

        // ALWAYS present: the fall-through arm is ungated, and a MID outside
        // every namespace is the one case a build with no codec feature at all
        // can still reach.
        cases.push((alloc::vec![0x1F], "Unknown"));
        cases
    }

    /// The names this build MUST be able to produce, stated INDEPENDENTLY of the
    /// vector above.
    ///
    /// The redundancy is the point, and it is the R311y634 rule: pin a SET,
    /// never a count. It is also not hypothetical — it is what went wrong while
    /// this test was being written. This crate's DEFAULT features carry no
    /// `codec-*` at all, so `cargo test -p wz-session-core` reaches only the
    /// ungated fall-through: the vector held ONE case and the suite reported ok
    /// with a deliberately wrong `Init => "Open"` sitting in the tree. A test
    /// that can pass by having nothing to check is not a gate, and the fix has
    /// two halves — this pin, and the lane that runs the module with the
    /// features ON (`scripts/run-ci.sh`, Layer C1bw).
    // `vec![]` cannot express this: every element is `#[cfg]`-gated, and a macro
    // literal has no place to put the attribute. The lint is reading the shape and
    // not the reason.
    #[allow(clippy::vec_init_then_push)]
    fn expected_names() -> Vec<&'static str> {
        let mut want: Vec<&'static str> = Vec::new();
        #[cfg(feature = "codec-init-body")]
        want.push("Init");
        #[cfg(feature = "codec-open-body")]
        want.push("Open");
        #[cfg(feature = "codec-close")]
        want.push("Close");
        #[cfg(feature = "codec-keep-alive")]
        want.push("KeepAlive");
        #[cfg(feature = "codec-frame")]
        want.push("Frame");
        #[cfg(feature = "reassembly")]
        want.push("Fragment");
        #[cfg(feature = "codec-join")]
        want.push("Join");
        want.push("Unknown");
        want
    }

    #[test]
    fn the_fixture_vector_reaches_every_variant_this_build_has() {
        let got: Vec<&'static str> = reachable().into_iter().map(|(_, n)| n).collect();
        for want in expected_names() {
            assert!(
                got.contains(&want),
                "`{want}` is a variant this build compiles and no fixture \
                 reaches it, so nothing checks its name: {got:?}"
            );
        }
    }

    #[test]
    fn every_reachable_variant_is_named_by_its_own_identifier() {
        for (wire, expected) in reachable() {
            let frame = parse_inbound(&wire).expect("the fixture wire decodes");
            assert_eq!(
                frame.kind_name(),
                expected,
                "wire {wire:02X?} decoded to {frame:?}, whose name must be \
                 `{expected}` -- a name that disagrees with the variant is how a \
                 listing renames a message without saying so"
            );
        }
    }

    /// The names must be pairwise DISTINCT. A word reused across two arms makes
    /// a listing report two message kinds as one, which reads as a capture that
    /// carried more of the first and none of the second.
    ///
    /// Over what `kind_name` ACTUALLY answers and not over the expectations in
    /// the vector: those are literals in this file, so a distinctness check on
    /// them would only assert that this file's own list has no duplicate in it.
    /// Measured while writing it — a probe changing `Init` to answer `"Open"`
    /// left that version of this test green.
    #[test]
    fn no_two_variants_answer_the_same_name() {
        let mut names: Vec<&'static str> = reachable()
            .into_iter()
            .map(|(wire, _)| {
                parse_inbound(&wire)
                    .expect("the fixture wire decodes")
                    .kind_name()
            })
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "two variants share a name: {names:?}");
    }
}
