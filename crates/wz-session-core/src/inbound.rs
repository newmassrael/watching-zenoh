// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Inbound transport-frame decode SSOT.
//!
//! [`parse_inbound`] decodes one raw transport datagram into a typed
//! [`InboundFrame`]; [`inbound_to_fsm_event`] projects a parsed frame to the
//! matching `session_fsm_unicast` external event. Every message, its
//! extension chain included, is read by its message's document.
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
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::parse_error::InboundParseError;

#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive"
))]
use crate::ext_chain::collect_handshake_ext_chain;
pub use crate::ext_chain::ExtChainOwned;
#[cfg(feature = "alloc")]
use crate::link::RxBytes;
// `CodecError` is named only by the `Frame` arm, which is `codec-frame`'s.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
use sce_forge_runtime::codec::CodecError;
// Named by the owned `Oam`/`Frame` decode (`alloc`), by the handshake arms, and by the
// frame-head readers of the in-place receive path; a slot profile with none of them has no
// cursor to name.
#[cfg(any(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    all(
        feature = "codec-frame",
        feature = "storage-profile",
        any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
use sce_forge_runtime::codec::SceCursor;
// Named by the heap variants.
#[cfg(feature = "alloc")]
use crate::transport_profile::ExtEntryOwned;
// The MID and flag constants: named by the heap `Oam` arm (`alloc`), by each
// handshake arm of `ext_admission`, by `is_init_syn` and by the frame-head readers of the
// in-place receive path.
#[cfg(any(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    all(
        feature = "codec-frame",
        feature = "storage-profile",
        any(
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
use wz_codecs::wire_const;

#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::InitBodyOwned;
#[cfg(all(feature = "alloc", feature = "codec-join"))]
use wz_codecs::join::JoinOwned;
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::OpenBodyOwned;
#[cfg(feature = "codec-close")]
use wz_codecs::transport_close::TransportCloseView;
#[cfg(feature = "codec-init-body")]
use wz_codecs::transport_init::TransportInitView;
#[cfg(feature = "codec-keep-alive")]
use wz_codecs::transport_keep_alive::TransportKeepAliveView;
#[cfg(feature = "codec-open-body")]
use wz_codecs::transport_open::TransportOpenView;

/// The storage profile a handshake body is decoded into, chosen with the rest of
/// the transport profile ([`crate::transport_profile::HandshakeStorage`]).
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
pub use crate::transport_profile::HandshakeStorage;

/// A decoded inbound transport-message frame.
///
/// R68a baseline. The variant set covers the three transport bodies
/// the Initiator side cares about during handshake + close:
/// `Init` / `Open` / `Close`. The `has_ext` field on each variant
/// records whether the parent header's Z flag was set so the caller
/// can dispatch ext-chain decoding (R68c) without re-parsing the
/// header byte; the chain itself is read by the message's document.
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
// Under `session-slot` a handshake message's extension chain is an inline array
// (`ExtChainOwned`), so the variants that carry one are much larger than the
// ones that do not. Boxing them would put the allocation back that the array is
// there to remove, so the size spread is the profile's deliberate trade.
#[allow(clippy::large_enum_variant)]
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
        body: InitBodyOwned<HandshakeStorage>,
        extensions: ExtChainOwned,
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
        body: OpenBodyOwned<HandshakeStorage>,
        extensions: ExtChainOwned,
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
        extensions: ExtChainOwned,
    },
    /// `_Z_MID_T_KEEP_ALIVE` (0x04). Empty-body liveness ping; the
    /// only payload is the optional ext chain (Z flag-gated). The
    /// FSM uses receipt to reset the lease timer per
    /// session-fsm §2.5 keepalive_interval semantics.
    #[cfg(feature = "codec-keep-alive")]
    KeepAlive {
        has_ext: bool,
        extensions: ExtChainOwned,
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
    #[cfg(all(feature = "alloc", feature = "codec-frame"))]
    Frame {
        reliable: bool,
        sn: u64,
        /// The batch of network messages the frame carries. A range of the
        /// unit it was decoded from when that unit was handed to
        /// [`parse_inbound_consuming_in`] lent, a copy of it otherwise. Reads
        /// are through `Deref` to `[u8]`, so a caller that only reads it need
        /// not care which.
        payload: RxBytes,
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
    #[cfg(all(feature = "alloc", feature = "reassembly"))]
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
    #[cfg(all(feature = "alloc", feature = "codec-join"))]
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
    ///
    /// Heap profile only (the body and the chain are owned): a build with no
    /// allocator reads a transport OAM as [`InboundFrame::Unknown`], and both
    /// project to the same framing error.
    #[cfg(feature = "alloc")]
    Oam {
        id: u16,
        encoding: u8,
        value: u64,
        body: Vec<u8>,
        has_ext: bool,
        extensions: Vec<ExtEntryOwned>,
    },
    /// A network body on a negotiated lowlatency link, without a Frame or SN.
    /// Only the passive observer constructs this envelope; the universal
    /// participant decoder does not accept it. The carried network decoder
    /// judges the complete body separately, as it does a Frame's payload.
    #[cfg(all(feature = "alloc", feature = "codec-frame"))]
    Network { payload: Vec<u8> },
    /// MID outside the handshake/close/keepalive set.
    Unknown { mid: u8 },
}

impl InboundFrame {
    /// R311y630 (§14.1) — what a conforming PARTICIPANT must do with this
    /// frame's extension chain: `ExtAdmission::UnknownMandatory` means the
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
    /// `Unknown { mid }` answers `ExtAdmission::Unjudged`: this build cannot
    /// name the message, so it has no extension space to judge the chain
    /// against, and a reach limit reported as admission is exactly how an
    /// observer's blind spot becomes a participant's accepted message.
    pub fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        use crate::ext_admit::ExtAdmission;
        // Each arm names its own MID constant rather than deriving one from a
        // stored header byte: the variants do not carry the header, and the
        // MID is what SELECTED the variant, so the constant is the fact.
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_INIT, extensions)
            }
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_OPEN, extensions)
            }
            #[cfg(feature = "codec-close")]
            InboundFrame::Close { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_CLOSE, extensions)
            }
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_KEEP_ALIVE, extensions)
            }
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Frame { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_FRAME, extensions)
            }
            #[cfg(all(feature = "alloc", feature = "reassembly"))]
            InboundFrame::Fragment { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_FRAGMENT, extensions)
            }
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_JOIN, extensions)
            }
            // Its own `judge_ext_chain` call rather than `judge_transport_chain`:
            // that helper folds under the `codec-*` union above and
            // this arm carries no gate, so it would vanish in a build that
            // still has this variant.
            #[cfg(feature = "alloc")]
            InboundFrame::Oam { extensions, .. } => crate::ext_admit::judge_ext_chain(
                crate::ext_admit::ExtCarrier::Transport(wire_const::T_MID_OAM),
                extensions.iter().map(|e| e.header),
            ),
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Network { .. } => ExtAdmission::Unjudged,
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
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Frame { .. } => "Frame",
            #[cfg(all(feature = "alloc", feature = "reassembly"))]
            InboundFrame::Fragment { .. } => "Fragment",
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { .. } => "Join",
            #[cfg(feature = "alloc")]
            InboundFrame::Oam { .. } => "Oam",
            // NOT "Unknown message" and not the MID in hex: this is the
            // variant's name like every other arm, and the MID a reader needs is
            // on the variant for whoever wants it. A name that folded the byte
            // in would make two frames with different MIDs two different kinds.
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Network { .. } => "Network",
            InboundFrame::Unknown { .. } => "Unknown",
        }
    }

    /// [`Self::kind_code`] of an `Init`.
    pub const KIND_INIT: u8 = 1;

    /// [`Self::kind_code`] of a `Join`.
    pub const KIND_JOIN: u8 = 7;

    /// R2102 (open-debt item 524) — the SAME fact as [`Self::kind_name`], as a
    /// number a fixed-layout record can carry.
    ///
    /// # Why a second projection rather than the name
    ///
    /// A live tap draining decoded messages over a C ABI takes BINARY records —
    /// that is the whole reason such a door exists rather than one more JSON
    /// document — and a `&'static str` is not a field of a fixed-layout struct.
    /// A consumer that had to receive the name would be receiving a pointer
    /// into this library's rodata, which is exactly the shape that ABI's memory
    /// rule refuses.
    ///
    /// # Why it sits HERE, beside the name
    ///
    /// For the reason [`Self::kind_name`]'s own doc gives: the arms are under
    /// the same `#[cfg]`s as the variants, so exhaustiveness is the COMPILER's
    /// and a variant added upstream fails this match. Written in the ABI crate
    /// instead, it would mirror seven feature gates that crate does not own —
    /// and a mirror drifts. The two projections are adjacent so that the round
    /// which adds a message kind is shown both at once.
    ///
    /// # The numbers are an ABI, and they only ever grow
    ///
    /// A consumer compiled against `WZ_DISSECT_KIND_FRAME == 5` keeps reading
    /// that value, so an arm's number is fixed once published. `0` is reserved
    /// for a message this reader could NOT decode — which is not a variant of
    /// this enum at all, and is assigned by the caller holding the `Result` —
    /// and `255` is `Unknown`, a message whose MID this build does not know.
    /// Those two are deliberately at the ends: a value that arrives in between
    /// and that a consumer has no case for is a kind this library gained, which
    /// is the only growth this scheme permits.
    pub fn kind_code(&self) -> u8 {
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { .. } => Self::KIND_INIT,
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open { .. } => 2,
            #[cfg(feature = "codec-close")]
            InboundFrame::Close { .. } => 3,
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { .. } => 4,
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Frame { .. } => 5,
            #[cfg(all(feature = "alloc", feature = "reassembly"))]
            InboundFrame::Fragment { .. } => 6,
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { .. } => Self::KIND_JOIN,
            #[cfg(feature = "alloc")]
            InboundFrame::Oam { .. } => 8,
            // 255 and not 9, for the reason the doc above states: an unknown
            // MID is not the ninth kind, it is the absence of a kind, and
            // leaving the low numbers contiguous is what lets a tenth arm be
            // added without a consumer's switch falling through to this one.
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Network { .. } => 9,
            // 10 and 11 are TAKEN, by the scouting namespace's
            // Scout and Hello (`ScoutingFrame::kind_code`): the two share one
            // published kind space, so the next transport arm here is 12.
            InboundFrame::Unknown { .. } => 255,
        }
    }

    /// The protocol version this message announces, for the two transport
    /// messages that carry one (Init and Join); `None` for every other kind.
    ///
    /// Beside [`Self::kind_name`] for the reason that method gives: the arms sit
    /// under the variants' own `#[cfg]`s.
    pub fn announced_version(&self) -> Option<u8> {
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { body, .. } => Some(body.version),
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { body, .. } => Some(body.version),
            _ => None,
        }
    }

    /// Why the zid this message names is no zid, for the messages that name
    /// one (Init and Join), and `None` for a zid and for every other kind. A
    /// participant refuses such a message where it reads it
    /// ([`InboundParseError::InvalidZid`]); an observer reads it and reports
    /// this on its row ([`parse_inbound_observed`]).
    pub fn names_no_zid(&self) -> Option<crate::session_zid::ZidError> {
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init { body, .. } => {
                crate::session_zid::SessionZid::new(body.zid.as_slice()).err()
            }
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { body, .. } => {
                crate::session_zid::SessionZid::new(body.zid.as_slice()).err()
            }
            _ => None,
        }
    }
}

/// What the session's judgement of one received transport message reads of it: the facts of
/// an Init, an Open, a Close or a KeepAlive, and for any other message only what kind it is.
///
/// Borrowed from wherever the message was read, so the one judgement (the projection to the
/// session machine's event, the record of a handshake's facts, the checks a handshake message
/// passes before the engine takes it) serves a message decoded into an [`InboundFrame`] and one
/// read where it lies in the receive buffer alike, and neither read is judged by a copy of the
/// other's rules.
#[derive(Debug, Clone, Copy)]
pub enum ControlFacts<'f> {
    /// An Init (`T_MID_INIT`).
    #[cfg(feature = "codec-init-body")]
    Init(InitFacts<'f>),
    /// An Open (`T_MID_OPEN`).
    #[cfg(feature = "codec-open-body")]
    Open(OpenFacts<'f>),
    /// A Close (`T_MID_CLOSE`): its reason byte, and whether it closes the whole session
    /// (`_Z_FLAG_T_CLOSE_S`) or only the link it arrived on.
    #[cfg(feature = "codec-close")]
    Close {
        /// The reason byte.
        reason: u8,
        /// The scope bit.
        session: bool,
    },
    /// A KeepAlive (`T_MID_KEEP_ALIVE`).
    #[cfg(feature = "codec-keep-alive")]
    KeepAlive,
    /// A Frame or a Fragment: data, which the session machine takes no event from.
    #[cfg(all(
        feature = "alloc",
        any(feature = "codec-frame", feature = "reassembly")
    ))]
    Data,
    /// A message a unicast participant refuses whatever it says, read to its end: a JOIN, a
    /// transport OAM, the observer's network envelope.
    Refused,
    /// A message this read does not take: an id this build has no reader for. It is refused as
    /// [`Self::Refused`] is, and it is no sign of the peer's life, since it was not read.
    ///
    /// It carries the borrow of the facts' lifetime because a build with no handshake reader has
    /// no other variant that does, and a lifetime parameter nothing names is refused.
    Unread(core::marker::PhantomData<&'f ()>),
}

/// The facts of an Init the judgement reads ([`ControlFacts::Init`]).
#[cfg(feature = "codec-init-body")]
#[derive(Debug, Clone, Copy)]
pub struct InitFacts<'f> {
    /// `_Z_FLAG_T_INIT_A`: an InitAck, where clear an InitSyn.
    pub is_ack: bool,
    /// The protocol version.
    pub version: u8,
    /// The peer's role, in its 2-bit wire form.
    pub whatami: u8,
    /// The peer's zid as the wire carries it.
    pub zid: &'f [u8],
    /// The sizing pair the S flag announces.
    pub s: Option<wz_codecs::init_body::InitBodyS>,
    /// The cookie an InitAck carries.
    pub cookie: Option<&'f [u8]>,
    /// The extension chain, as the message keeps it.
    pub extensions: &'f [crate::transport_profile::ExtEntryOwned],
}

/// The facts of an Open the judgement reads ([`ControlFacts::Open`]).
#[cfg(feature = "codec-open-body")]
#[derive(Debug, Clone, Copy)]
pub struct OpenFacts<'f> {
    /// `_Z_FLAG_T_OPEN_A`: an OpenAck, where clear an OpenSyn.
    pub is_ack: bool,
    /// The lease, in milliseconds whatever unit the wire wrote it in.
    pub lease: u64,
    /// The sender's initial sequence number.
    pub initial_sn: u64,
    /// The cookie an OpenSyn echoes.
    pub cookie: Option<&'f [u8]>,
    /// The extension chain, as the message keeps it.
    pub extensions: &'f [crate::transport_profile::ExtEntryOwned],
}

impl ControlFacts<'_> {
    /// The establishment message these facts are of, if they are of one.
    #[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
    pub fn handshake_message(&self) -> Option<crate::handshake_stray::HandshakeMessage> {
        use crate::handshake_stray::HandshakeMessage as M;
        match self {
            #[cfg(feature = "codec-init-body")]
            ControlFacts::Init(InitFacts { is_ack: false, .. }) => Some(M::InitSyn),
            #[cfg(feature = "codec-init-body")]
            ControlFacts::Init(InitFacts { is_ack: true, .. }) => Some(M::InitAck),
            #[cfg(feature = "codec-open-body")]
            ControlFacts::Open(OpenFacts { is_ack: false, .. }) => Some(M::OpenSyn),
            #[cfg(feature = "codec-open-body")]
            ControlFacts::Open(OpenFacts { is_ack: true, .. }) => Some(M::OpenAck),
            _ => None,
        }
    }
}

impl InboundFrame {
    /// What the session's judgement reads of this message ([`ControlFacts`]).
    pub fn control_facts(&self) -> ControlFacts<'_> {
        match self {
            #[cfg(feature = "codec-init-body")]
            InboundFrame::Init {
                is_ack,
                body,
                extensions,
                ..
            } => ControlFacts::Init(InitFacts {
                is_ack: *is_ack,
                version: body.version,
                whatami: body.whatami(),
                zid: body.zid.as_slice(),
                s: body.s,
                cookie: body.cookie.as_ref().map(|cookie| cookie.as_slice()),
                extensions,
            }),
            #[cfg(feature = "codec-open-body")]
            InboundFrame::Open {
                is_ack,
                body,
                extensions,
                ..
            } => ControlFacts::Open(OpenFacts {
                is_ack: *is_ack,
                lease: body.lease,
                initial_sn: body.initial_sn,
                cookie: body.cookie.as_ref().map(|cookie| cookie.as_slice()),
                extensions,
            }),
            #[cfg(feature = "codec-close")]
            InboundFrame::Close {
                reason, session, ..
            } => ControlFacts::Close {
                reason: *reason,
                session: *session,
            },
            #[cfg(feature = "codec-keep-alive")]
            InboundFrame::KeepAlive { .. } => ControlFacts::KeepAlive,
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Frame { .. } => ControlFacts::Data,
            #[cfg(all(feature = "alloc", feature = "reassembly"))]
            InboundFrame::Fragment { .. } => ControlFacts::Data,
            #[cfg(all(feature = "alloc", feature = "codec-join"))]
            InboundFrame::Join { .. } => ControlFacts::Refused,
            #[cfg(feature = "alloc")]
            InboundFrame::Oam { .. } => ControlFacts::Refused,
            #[cfg(all(feature = "alloc", feature = "codec-frame"))]
            InboundFrame::Network { .. } => ControlFacts::Refused,
            InboundFrame::Unknown { .. } => ControlFacts::Unread(core::marker::PhantomData),
        }
    }
}

/// The admission rule ([`crate::ext_admit::judge_ext_chain`]) over the chain of a transport
/// message of id `mid`, as each reader of a received message keeps it.
// The union of the readers that call it: the decoded message's arms (the Frame, Fragment and
// Join variants exist only with `alloc`, so a slot profile with their codecs on carries no caller
// for it) and the in-place reader of a control message.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    all(feature = "alloc", feature = "codec-frame"),
    all(feature = "alloc", feature = "reassembly"),
    all(feature = "alloc", feature = "codec-join")
))]
fn judge_transport_chain<C: crate::ext_chain::ChainHeaders + ?Sized>(
    mid: u8,
    chain: &C,
) -> crate::ext_admit::ExtAdmission {
    crate::ext_admit::judge_ext_chain(
        crate::ext_admit::ExtCarrier::Transport(mid),
        chain.chain_headers(),
    )
}

/// R311y215 — project the QoS priority carried by a decoded Frame/Fragment ext
/// chain: the z64 `ext_qos` extension (id `0x1`, `crate::extqos::QOS_EXT_ID`)
/// packs the priority in the low 3 bits (zenoh transport `QoSType`,
/// `transport/mod.rs:268-286`). Returns [`Priority::DEFAULT`](crate::qos::Priority)
/// when no such ext is present — a pre-QoS frame, byte-identical to today. The
/// scan is feature-agnostic (wz reads whatever the peer sent); honoring vs
/// dropping a non-DEFAULT priority is the [`crate::drive`] admit seam's call.
#[cfg(all(feature = "alloc", feature = "codec-frame"))]
fn ext_qos_priority(extensions: &[ExtEntryOwned]) -> crate::qos::Priority {
    extensions
        .iter()
        .find_map(qos_priority_of_entry)
        .unwrap_or(crate::qos::Priority::DEFAULT)
}

/// One entry's part in [`ext_qos_priority`]: the priority when the entry is the
/// transport QoS extension with its z64 body, `None` otherwise (and the scan
/// goes on). The QoS of a Frame/Fragment is `zextz64!(0x1, true)`, header
/// `0x31` (0x2 First / 0x3 Drop are Fragment-only unit exts), told by its
/// identity as upstream tells it; the z64 body carries the priority.
///
/// Over [`ExtEntryView`](crate::ext_view::ExtEntryView) so the owned chain and
/// one read where its message lies ([`InPlaceExtChain`]) answer by the same
/// rule.
// The union of its callers: the owned walk (`alloc`) and the in-place receive path.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        all(
            feature = "storage-profile",
            any(
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
fn qos_priority_of_entry<E: crate::ext_view::ExtEntryView>(
    ext: &E,
) -> Option<crate::qos::Priority> {
    if ext.eid() != crate::ext_header::network_eid::TRANSPORT_QOS {
        return None;
    }
    ext.zint()
        .map(|value| crate::qos::Priority::from_wire((value & 0x07) as u8))
}

/// A transport message's own extension chain, read where the message lies:
/// what the receive path that does not copy a unit (`drive::dispatch_datagram`)
/// needs of it, kept in fixed storage, so reading it allocates nothing.
///
/// The chain is read by the header's document (`transport_frame_header.scxml`,
/// `transport_fragment_header.scxml`) to the entry whose `Z` flag is clear,
/// whatever its length, and walked here once ([`KeptChain`]). What is kept is
/// what a participant acts on, folded as the walk goes so that the storage does
/// not grow with the chain: the mandatory-extension rule's verdict for the
/// message ([`crate::ext_admit::judge_ext_chain`]), the priority the QoS
/// extension carries, and the two chain-boundary markers of a Fragment. Each is
/// projected by the rule the owned chain is projected by ([`ext_qos_priority`],
/// [`crate::extfragment::FragmentMarkers::from_headers`]).
///
/// One difference from the owned decode, by construction: an entry is read and
/// never owned, so an entry whose body the fixed bounded backing could not own
/// is not a refusal here. No such body is acted on: the QoS value is a z64 and
/// the markers are unit extensions.
#[cfg(all(
    feature = "codec-frame",
    feature = "storage-profile",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct InPlaceExtChain {
    /// Whether the message carried a chain at all: read only to own the chain, which a build
    /// whose every record is lent never does.
    #[cfg(all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ))]
    chained: bool,
    /// The admission verdict, which only the unicast receive path asks for.
    #[cfg(feature = "session-unicast")]
    admission: crate::ext_admit::ExtAdmission,
    #[cfg(feature = "reassembly")]
    markers: crate::extfragment::FragmentMarkers,
    priority: crate::qos::Priority,
}

#[cfg(all(
    feature = "codec-frame",
    feature = "storage-profile",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
impl InPlaceExtChain {
    /// The chain of the Frame at the front of `unit`, OWNED: its header read
    /// again by its document and the entries kept as the owned decode keeps
    /// them. Empty when there is no chain.
    ///
    /// What a receive path hands a consumer that is given the owned chain (the
    /// `extensions` of a `FramePayload`), made only when one is: a frame whose
    /// every record is lent never pays for it.
    #[cfg(all(
        feature = "alloc",
        any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
    ))]
    pub(crate) fn owned(&self, unit: &[u8]) -> Result<Vec<ExtEntryOwned>, InboundParseError> {
        if !self.chained {
            return Ok(Vec::new());
        }
        decode_frame_head::<Vec<ExtEntryOwned>>(unit).map(|(head, _)| head.chain)
    }

    /// The priority the chain's QoS extension carries,
    /// [`Priority::DEFAULT`](crate::qos::Priority) when it has none.
    pub(crate) fn priority(&self) -> crate::qos::Priority {
        self.priority
    }

    /// The chain-boundary markers the chain carries.
    #[cfg(feature = "reassembly")]
    pub(crate) fn markers(&self) -> crate::extfragment::FragmentMarkers {
        self.markers
    }

    /// Whether a participant may act on the message this chain was kept for:
    /// the rule [`InboundFrame::ext_admission`] applies to the decoded message.
    #[cfg(feature = "session-unicast")]
    pub(crate) fn admission(&self) -> crate::ext_admit::ExtAdmission {
        self.admission
    }
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
/// [`InboundFrame::Frame`] and `Fragment` legitimately return `bytes.len()`. A
/// `Fragment`'s payload is the rest of its unit (upstream reads it as
/// `reader.read_zslice(reader.remaining())`). A `Frame`'s records end where a
/// message that is not a network one begins, which only a walk of the records
/// finds (`commons/zenoh-codec/src/transport/frame.rs` @ `reader.rewind(mark);`):
/// the payload handed out here is the tail of the unit, and the reader of the
/// batch cuts it where the walk ended and reads on from there.
pub fn parse_inbound_consuming(bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
    // Returned where it lies: the frame is not moved into a second `Ok`.
    let parsed = parse_inbound_observed(bytes);
    if let Ok((frame, _)) = &parsed {
        refuse_unnamed_zid(frame)?;
    }
    parsed
}

/// [`parse_inbound_consuming`] for a reader that observes a link and takes part
/// in nothing: a message that names a zid no node has is read and handed back,
/// so that a capture of a peer that sends one still reads past it, and the
/// reader reports [`InboundFrame::names_no_zid`] on its row. Every participant's
/// read refuses the same message ([`InboundParseError::InvalidZid`]).
pub fn parse_inbound_observed(bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
    #[cfg(feature = "alloc")]
    {
        parse_unit(bytes, None)
    }
    #[cfg(not(feature = "alloc"))]
    {
        parse_unit(bytes)
    }
}

/// A participant's refusal of a message that names a zid no node has: zenoh's
/// decoder reads the bytes of an id and refuses the message when they are not a
/// non-zero id of at most sixteen bytes
/// (`commons/zenoh-codec/src/core/zenohid.rs` @
/// `ZenohIdProto::try_from(&id[..size]).map_err(|_| DidntRead)`), so every zid a
/// session records of a peer is a [`crate::session_zid::SessionZid`].
fn refuse_unnamed_zid(frame: &InboundFrame) -> Result<(), InboundParseError> {
    match frame.names_no_zid() {
        Some(refused) => Err(InboundParseError::InvalidZid(refused)),
        None => Ok(()),
    }
}

/// [`parse_inbound_consuming`] over a unit that can be SHARED: a
/// [`InboundFrame::Frame`]'s payload is a range of `unit` rather than a copy of
/// it, so on a lent unit (see [`RxBytes::lend`]) the payload and the messages
/// later decoded out of it are all references to the one storage the link read
/// into.
///
/// The decode runs over `unit`'s own bytes, which is what makes a range of them
/// recognisable as part of `unit`; handing in a copy of the frame would decode
/// correctly and share nothing. On an owned unit the payload is a copy, which is
/// exactly what [`parse_inbound_consuming`] does, so a caller that has not made
/// its unit lent loses nothing by calling this.
#[cfg(feature = "alloc")]
pub fn parse_inbound_consuming_in(
    unit: &RxBytes,
) -> Result<(InboundFrame, usize), InboundParseError> {
    let parsed = parse_unit(unit.as_slice(), Some(unit));
    if let Ok((frame, _)) = &parsed {
        refuse_unnamed_zid(frame)?;
    }
    parsed
}

/// [`parse_inbound_consuming`] that writes the message into `out` and returns where it ended:
/// the session's receive, which keeps the message in one slot of its own frame and lends it to
/// each step that reads it (see `parse_unit_into`).
pub fn parse_inbound_consuming_into(
    bytes: &[u8],
    out: &mut InboundFrame,
) -> Result<usize, InboundParseError> {
    #[cfg(feature = "alloc")]
    let used = parse_unit_into(bytes, None, out)?;
    #[cfg(not(feature = "alloc"))]
    let used = parse_unit_into(bytes, out)?;
    refuse_unnamed_zid(out)?;
    Ok(used)
}

/// [`parse_inbound_consuming_into`] over a unit that can be shared (see
/// [`parse_inbound_consuming_in`]).
#[cfg(feature = "alloc")]
pub fn parse_inbound_consuming_in_into(
    unit: &RxBytes,
    out: &mut InboundFrame,
) -> Result<usize, InboundParseError> {
    let used = parse_unit_into(unit.as_slice(), Some(unit), out)?;
    refuse_unnamed_zid(out)?;
    Ok(used)
}

/// The form a Frame's or a Fragment's own extension chain is kept in, taken
/// from the entries its header's document read ([`decode_frame_head`],
/// [`decode_fragment_head`]): the owned entries of a decoded message, or the
/// [`InPlaceExtChain`] of one read where it lies. The document's view reads the
/// chain to the entry whose `Z` flag is clear, whatever its length, and neither
/// form refuses a chain for its length: the owned one grows, and the in-place one
/// keeps a fixed summary of it.
// Gated as the head decoders that name it.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        all(
            feature = "storage-profile",
            any(
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
pub(crate) trait KeptChain: Sized {
    /// The chain whose entries `walked` yields, in wire order, of a message of
    /// the transport id `mid`.
    fn keep<'a>(
        mid: u8,
        walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
    ) -> Result<Self, InboundParseError>;
}

#[cfg(all(feature = "alloc", feature = "codec-frame"))]
impl KeptChain for Vec<ExtEntryOwned> {
    /// Every entry is kept, so the message's id is not needed to judge it.
    fn keep<'a>(
        _mid: u8,
        walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
    ) -> Result<Self, InboundParseError> {
        crate::ext_chain::collect_ext_chain(walked)
    }
}

#[cfg(all(
    feature = "codec-frame",
    feature = "storage-profile",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
impl KeptChain for InPlaceExtChain {
    fn keep<'a>(
        mid: u8,
        walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
    ) -> Result<Self, InboundParseError> {
        #[cfg(feature = "session-unicast")]
        let carrier = crate::ext_admit::ExtCarrier::Transport(mid);
        #[cfg(not(feature = "session-unicast"))]
        let _ = mid;
        // The rule answers with the first entry it refuses, so that entry's header
        // is all of the chain its verdict needs.
        #[cfg(feature = "session-unicast")]
        let mut refused: Option<u8> = None;
        #[cfg(all(
            feature = "alloc",
            any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
        ))]
        let mut chained = false;
        #[cfg(feature = "reassembly")]
        let mut markers = crate::extfragment::FragmentMarkers::NONE;
        let mut priority = None;
        for entry in walked {
            #[cfg(all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ))]
            {
                chained = true;
            }
            #[cfg(feature = "session-unicast")]
            if refused.is_none()
                && crate::ext_admit::judge_ext_chain(carrier, [entry.header]).is_refusal()
            {
                refused = Some(entry.header);
            }
            #[cfg(feature = "reassembly")]
            {
                markers = markers.with_header(entry.header);
            }
            if priority.is_none() {
                priority = qos_priority_of_entry(&entry);
            }
        }
        Ok(Self {
            #[cfg(all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ))]
            chained,
            #[cfg(feature = "session-unicast")]
            admission: crate::ext_admit::judge_ext_chain(carrier, refused),
            #[cfg(feature = "reassembly")]
            markers,
            priority: priority.unwrap_or(crate::qos::Priority::DEFAULT),
        })
    }
}

/// What a `Frame` says about itself before its payload: the fields of
/// [`InboundFrame::Frame`] that are not the payload, with its own extension
/// chain as `C`: the owned entries the decoded `Frame` reports, or the
/// [`InPlaceExtChain`] a frame read where it lies keeps.
// Built by [`decode_frame_head`], so gated as it is.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        all(
            feature = "storage-profile",
            any(
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
#[derive(Debug)]
pub(crate) struct FrameHead<C> {
    pub(crate) reliable: bool,
    pub(crate) sn: u64,
    /// Read only into an owned outcome, which the heap profile alone delivers.
    #[cfg(feature = "alloc")]
    pub(crate) has_ext: bool,
    pub(crate) chain: C,
}

// The in-place receive path's helpers live where its one caller does: the
// unicast drive (`drive`, gated on `alloc` and `session-unicast`).
#[cfg(all(
    feature = "codec-frame",
    feature = "storage-profile",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
impl FrameHead<InPlaceExtChain> {
    /// Whether a participant may act on this frame's own extension chain: the
    /// rule [`InboundFrame::ext_admission`] applies to a decoded `Frame`. The unicast
    /// receive path's rule, as for a fragment.
    #[cfg(feature = "session-unicast")]
    pub(crate) fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        self.chain.admission()
    }

    /// The priority the frame's QoS extension carries.
    pub(crate) fn priority(&self) -> crate::qos::Priority {
        self.chain.priority()
    }
}

/// Decode the `Frame` at the front of `unit` up to its payload, and the offset
/// in `unit` at which the payload starts: the header, the SN and the extension
/// chain the Z flag announces, read by the header's document
/// (`sources/codecs/transport_frame_header.scxml`), the chain kept as `C`. The
/// payload is the rest of the unit; where its network messages end is the
/// reader of the batch's to find (L5).
///
/// The one decode of a frame's head, shared by [`parse_inbound_consuming_in`]'s
/// `Frame` arm (owned chain; the payload taken as a range or a copy) and
/// `parse_frame_in_place` (chain read in place; the payload left where it is).
// The union of those two callers.
#[cfg(all(
    feature = "codec-frame",
    any(
        feature = "alloc",
        all(
            feature = "storage-profile",
            any(
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            )
        )
    )
))]
fn decode_frame_head<C: KeptChain>(
    unit: &[u8],
) -> Result<(FrameHead<C>, usize), InboundParseError> {
    let mut cursor = SceCursor::new(unit);
    let view = wz_codecs::transport_frame_header::TransportFrameHeaderView::decode(&mut cursor)?;
    let chain = C::keep(
        wire_const::T_MID_FRAME,
        crate::ext_view::walked(view.extensions.as_ref()),
    )?;
    let head = FrameHead {
        reliable: (view.header & wire_const::FLAG_T_FRAME_R) != 0,
        sn: view.sn,
        #[cfg(feature = "alloc")]
        has_ext: (view.header & wire_const::FLAG_T_Z) != 0,
        chain,
    };
    Ok((head, unit.len() - cursor.remaining()))
}

/// The `Frame` at the front of `unit`, decoded up to its payload, and the
/// offset in `unit` at which the payload starts. `None` when the unit does
/// not begin with a `Frame`.
///
/// For a receive path that reads the payload where the unit lies, record by
/// record, instead of taking it as an [`RxBytes`]: nothing is copied and
/// nothing is shared. A `Frame` consumes the rest of its unit, so the payload
/// is `unit[offset..]`.
#[cfg(all(
    feature = "codec-frame",
    feature = "storage-profile",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
pub(crate) fn parse_frame_in_place(
    unit: &[u8],
) -> Option<Result<(FrameHead<InPlaceExtChain>, usize), InboundParseError>> {
    let header = *unit.first()?;
    if header & 0x1F != wire_const::T_MID_FRAME {
        return None;
    }
    Some(decode_frame_head(unit))
}

/// What a `Fragment` says about itself before its payload, with its own
/// extension chain as `C`: the owned entries [`InboundFrame::Fragment`]
/// reports, or the [`InPlaceExtChain`] a fragment read where it lies keeps.
// Built only by `decode_fragment_head`, so it exists exactly where that decode
// does: a build that reassembles but neither owns a heap nor runs a session has
// no receive path that reads a fragment.
#[cfg(all(
    feature = "reassembly",
    any(
        feature = "alloc",
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
#[derive(Debug)]
pub(crate) struct FragmentHead<C> {
    pub(crate) reliable: bool,
    pub(crate) sn: u64,
    pub(crate) more: bool,
    /// Read into an owned outcome (the heap profile's) and by the unicast receive path.
    #[cfg_attr(
        not(any(feature = "alloc", feature = "session-unicast")),
        allow(dead_code)
    )]
    pub(crate) has_ext: bool,
    pub(crate) chain: C,
}

/// Decode the `Fragment` at the front of `unit` up to its payload, and the
/// offset in `unit` at which the payload starts: the header (R, M, Z), the SN
/// and the extension chain, read by the header's document
/// (`sources/codecs/transport_fragment_header.scxml`), the chain kept as `C`.
/// The payload runs to the end of the unit.
///
/// The one decode of a fragment's head, shared by [`parse_inbound_consuming`]'s
/// `Fragment` arm (owned chain, payload copied) and [`parse_fragment_in_place`]
/// (chain read in place, payload left where it is), as [`decode_frame_head`] is
/// for a `Frame`.
// The union of those two callers, whose chain forms are the two `KeptChain`s.
#[cfg(all(
    feature = "reassembly",
    any(
        feature = "alloc",
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
fn decode_fragment_head<C: KeptChain>(
    unit: &[u8],
) -> Result<(FragmentHead<C>, usize), InboundParseError> {
    let mut cursor = SceCursor::new(unit);
    let view =
        wz_codecs::transport_fragment_header::TransportFragmentHeaderView::decode(&mut cursor)?;
    let chain = C::keep(
        wire_const::T_MID_FRAGMENT,
        crate::ext_view::walked(view.extensions.as_ref()),
    )?;
    let head = FragmentHead {
        reliable: (view.header & wire_const::FLAG_T_FRAGMENT_R) != 0,
        sn: view.sn,
        more: (view.header & wire_const::FLAG_T_FRAGMENT_M) != 0,
        has_ext: (view.header & wire_const::FLAG_T_Z) != 0,
        chain,
    };
    Ok((head, unit.len() - cursor.remaining()))
}

#[cfg(all(
    feature = "reassembly",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
impl FragmentHead<InPlaceExtChain> {
    /// The priority the fragment's QoS extension carries: the third part of
    /// its chain key.
    pub(crate) fn priority(&self) -> crate::qos::Priority {
        self.chain.priority()
    }

    /// The chain-boundary markers the fragment carries.
    pub(crate) fn markers(&self) -> crate::extfragment::FragmentMarkers {
        self.chain.markers()
    }

    /// Whether a participant may act on the fragment's own extension chain.
    /// The unicast receive path's rule; a group member's fragment is read as the
    /// owned decode reads it, which leaves its own chain to the records.
    #[cfg(feature = "session-unicast")]
    pub(crate) fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        self.chain.admission()
    }
}

/// The `Fragment` at the front of `unit`, decoded up to its payload with its
/// extension chain read in place, and the offset in `unit` at which the payload
/// starts. `None` when the unit does not begin with a `Fragment`.
///
/// For the receive path that stages a fragment's payload into its reassembly
/// slot from where the unit lies ([`parse_frame_in_place`]'s twin): nothing is
/// copied and nothing is allocated to read the head. A `Fragment` consumes the
/// rest of its unit, so the payload is `unit[offset..]`.
#[cfg(all(
    feature = "reassembly",
    any(
        feature = "session-unicast",
        all(feature = "session-multicast", not(feature = "alloc"))
    )
))]
pub(crate) fn parse_fragment_in_place(
    unit: &[u8],
) -> Option<Result<(FragmentHead<InPlaceExtChain>, usize), InboundParseError>> {
    let header = *unit.first()?;
    if header & 0x1F != wire_const::T_MID_FRAGMENT {
        return None;
    }
    Some(decode_fragment_head(unit))
}

/// The one decode behind [`parse_inbound_consuming`] and
/// [`parse_inbound_consuming_in`]. `origin`, when there is one, is the
/// [`RxBytes`] that `bytes` was taken from, and is only consulted by the arm
/// whose payload is a tail of the unit (`Frame`).
///
/// Out of line, for the stack: a handshake body is read into a few temporaries (the borrowed
/// body, its owned form, the extension chain and the `Result` it comes back in, each hundreds of
/// bytes on the fixed profile) before the frame is built. Inlined into the dispatch of a unit
/// those slots stay live while the session machine runs on the frame the parse returned, so
/// they add to the deepest point of the stack; as a function of its own they are gone when it
/// returns, and only the 720 bytes of its result stay.
///
/// The message is written into `out`, where the caller keeps it, and what is returned is where
/// it ended: a message of 720 bytes handed back by value is a copy of it in every frame it passes
/// through (the arm that builds it, this function, the one that decodes the unit, the one that
/// judges it), and the handshake's parse is the deepest path of the fixed-memory client's stack.
/// `out` is left as it was when the unit does not decode and as far decoded as it got when a
/// chain is not kept (a handshake chain past the bound, or a heap chain that does not decode).
#[inline(never)]
fn parse_unit_into(
    bytes: &[u8],
    #[cfg(feature = "alloc")] origin: Option<&RxBytes>,
    out: &mut InboundFrame,
) -> Result<usize, InboundParseError> {
    #[cfg(feature = "alloc")]
    debug_assert!(
        origin.map_or(true, |o| core::ptr::eq(o.as_slice(), bytes)),
        "the origin of a decode is the very bytes being decoded"
    );
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mid = header & 0x1F;
    // Every message below is read whole, header included, by its document or
    // by the document of its header, in a function of its own.
    //
    // The dispatch itself stays here: a document's variant on the masked id
    // reaches an arm for every tag, while upstream refuses an id it does not
    // know (`commons/zenoh-codec/src/transport/mod.rs` @
    // `impl<W> WCodec<&TransportMessage, &mut W> for Zenoh080`). Masked dispatch
    // with that refusal is what SCE ADR 0100 proposes; it is not in the pinned
    // language, so the batch of transport messages waits on it.
    match mid {
        #[cfg(feature = "codec-init-body")]
        wire_const::T_MID_INIT => parse_init(bytes, out),
        #[cfg(feature = "codec-open-body")]
        wire_const::T_MID_OPEN => parse_open(bytes, out),
        #[cfg(feature = "codec-close")]
        wire_const::T_MID_CLOSE => parse_close(bytes, out),
        #[cfg(all(feature = "alloc", feature = "codec-frame"))]
        wire_const::T_MID_FRAME => {
            let (head, payload_at) = decode_frame_head::<Vec<ExtEntryOwned>>(bytes)?;
            // The payload is the tail of the unit. With an origin it is a range
            // of it (a second reference to the storage when the unit is lent);
            // without one it is a copy, as it was before there was a choice.
            let payload = match origin {
                Some(unit) => unit
                    .subslice(payload_at..bytes.len())
                    .ok_or(InboundParseError::Codec(CodecError::NeedMoreBytes))?,
                None => RxBytes::from(bytes[payload_at..].to_vec()),
            };
            let FrameHead {
                reliable,
                sn,
                has_ext,
                chain: extensions,
            } = head;
            let priority = ext_qos_priority(&extensions);
            *out = InboundFrame::Frame {
                reliable,
                sn,
                payload,
                has_ext,
                extensions,
                priority,
            };
            Ok(bytes.len())
        }
        #[cfg(all(feature = "alloc", feature = "reassembly"))]
        wire_const::T_MID_FRAGMENT => {
            // The head mirrors a Frame's: the SN and the Z-gated chain after the
            // header, whose R (reliable) and M (more) bits are the flags; the
            // payload is the tail of the unit.
            let (
                FragmentHead {
                    reliable,
                    sn,
                    more,
                    has_ext,
                    chain: extensions,
                },
                payload_at,
            ) = decode_fragment_head::<Vec<ExtEntryOwned>>(bytes)?;
            let payload = bytes[payload_at..].to_vec();
            let priority = ext_qos_priority(&extensions);
            // R311y578 — project the chain-boundary markers BEFORE the ext
            // chain moves into the variant. Both are unit exts in the
            // Fragment's own id space (0x2 First / 0x3 Drop); the projector
            // matches on extension identity, so the z64 `ext_qos` at 0x1
            // above is never mistaken for one.
            let markers = crate::extfragment::project_markers(&extensions);
            *out = InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                has_ext,
                extensions,
                priority,
                markers,
            };
            Ok(bytes.len())
        }
        #[cfg(feature = "codec-keep-alive")]
        wire_const::T_MID_KEEP_ALIVE => decode_keep_alive(bytes, out),
        // R311y605 — the MULTICAST peer announcement, read by [`decode_join_message`] as the
        // transport OAM is read by [`decode_oam`].
        #[cfg(all(feature = "alloc", feature = "codec-join"))]
        wire_const::T_MID_JOIN => {
            let (frame, used) = decode_join_message(bytes)?;
            *out = frame;
            Ok(used)
        }
        // Transport OAM, DELEGATED like the JOIN arm above rather than spelled
        // out here — see [`decode_oam`] for the second, measured reason. A heap
        // profile's message, so it is handed back by value and written to `out`.
        #[cfg(feature = "alloc")]
        wire_const::T_MID_OAM => {
            let (frame, used) = decode_oam(bytes)?;
            *out = frame;
            Ok(used)
        }
        // Zero: see the `# What `0` means` section on this function.
        other => {
            *out = InboundFrame::Unknown { mid: other };
            Ok(0)
        }
    }
}

/// [`parse_unit_into`] for a caller that wants the message as a value: the public decoders
/// ([`parse_inbound_consuming`] and its shared-unit twin), whose callers are tests and the
/// profiles with a heap, and whose own frame holds the message.
#[inline(never)]
fn parse_unit(
    bytes: &[u8],
    #[cfg(feature = "alloc")] origin: Option<&RxBytes>,
) -> Result<(InboundFrame, usize), InboundParseError> {
    let mut frame = InboundFrame::Unknown { mid: 0 };
    #[cfg(feature = "alloc")]
    let used = parse_unit_into(bytes, origin, &mut frame)?;
    #[cfg(not(feature = "alloc"))]
    let used = parse_unit_into(bytes, &mut frame)?;
    Ok((frame, used))
}

/// The `Init` arm of [`parse_unit`], a function of its own for the reason `parse_unit` is one:
/// its temporaries (the message's view, the owned body, the extension chain) are gone when it
/// returns, and what `parse_unit` keeps under it is the one arm that ran.
///
/// The whole message, header included, is read by its document
/// (`sources/codecs/transport_init.scxml`) as a view: the body under the header's A and S
/// flags, and the chain the Z flag announces, which the view checks and holds as the bytes it
/// occupies. The body is then owned and the chain kept in the form the message holds.
#[cfg(feature = "codec-init-body")]
#[inline(never)]
fn parse_init(bytes: &[u8], out: &mut InboundFrame) -> Result<usize, InboundParseError> {
    let mut cursor = SceCursor::new(bytes);
    let view = TransportInitView::decode(&mut cursor)?;
    let header = view.header;
    let body = view.body.try_into_owned_in::<HandshakeStorage>()?;
    // The M (mandatory) bit is judged at the participant seam like every
    // other transport message's ([`InboundFrame::ext_admission`]), by the
    // extension's identity: the decode reads the chain, so a capture
    // sees an extension nobody here implements. R2437 refused it HERE
    // instead, by the 4-bit id against a list of ids, which let a known
    // id with the mandatory bit set (`0x58`, the region name as a
    // mandatory ZBuf) through and refused an unknown one at the decode.
    //
    // The frame is built in `out` and its chain is read where it lies: a chain read as a value
    // and moved in is 520 bytes beside the frame's 712, and a frame built in a local of this
    // function and handed back was a second one (the caller's slot for it being the first).
    *out = InboundFrame::Init {
        is_ack: (header & wire_const::FLAG_T_INIT_A) != 0,
        has_ext: (header & wire_const::FLAG_T_Z) != 0,
        body,
        extensions: ExtChainOwned::new(),
    };
    if let InboundFrame::Init { extensions, .. } = out {
        collect_handshake_ext_chain(
            wire_const::T_MID_INIT,
            crate::ext_view::walked(view.extensions.as_ref()),
            extensions,
        )?;
    }
    Ok(bytes.len() - cursor.remaining())
}

/// The `Open` arm of [`parse_unit`], out of line and read by its document
/// (`sources/codecs/transport_open.scxml`) as [`parse_init`] is.
#[cfg(feature = "codec-open-body")]
#[inline(never)]
fn parse_open(bytes: &[u8], out: &mut InboundFrame) -> Result<usize, InboundParseError> {
    let mut cursor = SceCursor::new(bytes);
    let view = TransportOpenView::decode(&mut cursor)?;
    let header = view.header;
    let mut body = view.body.try_into_owned_in::<HandshakeStorage>()?;
    // R311ku — the `_Z_FLAG_T_OPEN_T` seconds form is projected
    // back to milliseconds AT the wire boundary
    // ([`crate::lease::lease_from_wire`], pico decode parity
    // codec/transport.c:314), so no consumer ever sees the wire
    // unit — the same boundary rule as `multicast_join::decode_join`.
    body.lease =
        crate::lease::lease_from_wire((header & wire_const::FLAG_T_OPEN_T) != 0, body.lease);
    *out = InboundFrame::Open {
        is_ack: (header & wire_const::FLAG_T_OPEN_A) != 0,
        has_ext: (header & wire_const::FLAG_T_Z) != 0,
        body,
        extensions: ExtChainOwned::new(),
    };
    if let InboundFrame::Open { extensions, .. } = out {
        collect_handshake_ext_chain(
            wire_const::T_MID_OPEN,
            crate::ext_view::walked(view.extensions.as_ref()),
            extensions,
        )?;
    }
    Ok(bytes.len() - cursor.remaining())
}

/// The `Close` arm of [`parse_unit`], out of line and read by its document
/// (`sources/codecs/transport_close.scxml`) as [`parse_init`] is.
#[cfg(feature = "codec-close")]
#[inline(never)]
fn parse_close(bytes: &[u8], out: &mut InboundFrame) -> Result<usize, InboundParseError> {
    let mut cursor = SceCursor::new(bytes);
    let view = TransportCloseView::decode(&mut cursor)?;
    *out = InboundFrame::Close {
        reason: view.body.reason,
        // R311y839 — the scope bit, read off the header exactly as the Open
        // arm reads `FLAG_T_OPEN_A` and the Frame arm reads `FLAG_T_FRAME_R`.
        session: (view.header & wire_const::FLAG_T_CLOSE_S) != 0,
        has_ext: (view.header & wire_const::FLAG_T_Z) != 0,
        extensions: ExtChainOwned::new(),
    };
    if let InboundFrame::Close { extensions, .. } = out {
        collect_handshake_ext_chain(
            wire_const::T_MID_CLOSE,
            crate::ext_view::walked(view.extensions.as_ref()),
            extensions,
        )?;
    }
    Ok(bytes.len() - cursor.remaining())
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
    control_event(frame.ext_admission(), &frame.control_facts())
}

/// [`inbound_to_fsm_event`] over the facts of a message, whichever read them, and the
/// admission of its extension chain: the one projection both reads are judged by.
#[cfg(feature = "session-unicast")]
pub(crate) fn control_event(
    admission: crate::ext_admit::ExtAdmission,
    facts: &ControlFacts<'_>,
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
    if admission.is_refusal() {
        return Some(E::FramingError);
    }
    match facts {
        #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
        ControlFacts::Init(InitFacts { is_ack: false, .. }) => Some(E::InitSynReceived),
        // A build without the accepting role has no event for a peer's InitSyn or OpenSyn (the
        // session machine states that gate): they are not triggers of its machine, and the drive
        // loop drops them silently, as it drops any frame it will not admit.
        #[cfg(all(feature = "codec-init-body", not(feature = "session-unicast-accept")))]
        ControlFacts::Init(InitFacts { is_ack: false, .. }) => None,
        #[cfg(feature = "codec-init-body")]
        ControlFacts::Init(InitFacts { is_ack: true, .. }) => Some(E::InitAckReceived),
        #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
        ControlFacts::Open(OpenFacts { is_ack: false, .. }) => Some(E::OpenSynReceived),
        #[cfg(all(feature = "codec-open-body", not(feature = "session-unicast-accept")))]
        ControlFacts::Open(OpenFacts { is_ack: false, .. }) => None,
        #[cfg(feature = "codec-open-body")]
        ControlFacts::Open(OpenFacts { is_ack: true, .. }) => Some(E::OpenAckReceived),
        #[cfg(feature = "codec-close")]
        ControlFacts::Close { .. } => Some(E::PeerClose),
        // KeepAlive is not a state-transition trigger: its receipt resets the lease, a side
        // effect orthogonal to the state graph. Frame and Fragment carry data, which the
        // drive loop routes past the machine.
        #[cfg(feature = "codec-keep-alive")]
        ControlFacts::KeepAlive => None,
        #[cfg(all(
            feature = "alloc",
            any(feature = "codec-frame", feature = "reassembly")
        ))]
        ControlFacts::Data => None,
        // R311y605 — a JOIN is a MULTICAST message and a transport OAM has no
        // transition in wz's unicast machine: gaining the ability to DECODE a
        // message must not change what the session FSM does with it, so they stay
        // the framing error an unknown MID is.
        ControlFacts::Refused | ControlFacts::Unread(_) => Some(E::FramingError),
    }
}

/// One transport message that carries no data, read where it lies in the receive buffer: the
/// session's in-place receive hands every unit that is not a `Frame` or a `Fragment` it read
/// itself to [`read_control`]. A handshake body is the document's view of the bytes, so its
/// zid and cookie are ranges of the unit and nothing is copied out of it; only the extension
/// chain is kept, in the form the readers of each extension take.
///
/// Its life is the unit's: it is judged and dropped before the receive goes on to the next
/// message of the unit.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "session-unicast"
))]
pub(crate) enum ControlRead<'a> {
    /// An Init: its header, its body as the document's view, its chain.
    #[cfg(feature = "codec-init-body")]
    Init {
        header: u8,
        body: wz_codecs::init_body::InitBodyView<'a>,
        extensions: ExtChainOwned,
    },
    /// An Open: its header, its body as the document's view, its chain.
    #[cfg(feature = "codec-open-body")]
    Open {
        header: u8,
        body: wz_codecs::open_body::OpenBodyView<'a>,
        extensions: ExtChainOwned,
    },
    /// A Close: its reason, its scope bit, its chain.
    #[cfg(feature = "codec-close")]
    Close {
        reason: u8,
        session: bool,
        extensions: ExtChainOwned,
    },
    /// A KeepAlive: its chain.
    #[cfg(feature = "codec-keep-alive")]
    KeepAlive { extensions: ExtChainOwned },
    /// A message a unicast participant refuses whatever it says, read to its end
    /// ([`ControlFacts::Refused`]): a JOIN, a transport OAM.
    Refused,
    /// A message this reader does not take ([`ControlFacts::Unread`]): a `Frame` or a
    /// `Fragment` that reaches it, or an id this build has no reader for.
    ///
    /// It carries the unit's lifetime for the reason [`ControlFacts::Unread`] carries the facts'.
    Unread(core::marker::PhantomData<&'a ()>),
}

#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "session-unicast"
))]
impl ControlRead<'_> {
    /// What the session's judgement reads of this message ([`ControlFacts`]).
    pub(crate) fn facts(&self) -> ControlFacts<'_> {
        match self {
            #[cfg(feature = "codec-init-body")]
            ControlRead::Init {
                header,
                body,
                extensions,
            } => ControlFacts::Init(InitFacts {
                is_ack: (header & wire_const::FLAG_T_INIT_A) != 0,
                version: body.version,
                whatami: body.whatami(),
                zid: body.zid.inner(),
                s: body.s,
                cookie: body.cookie.as_ref().map(|cookie| *cookie.inner()),
                extensions,
            }),
            #[cfg(feature = "codec-open-body")]
            ControlRead::Open {
                header,
                body,
                extensions,
            } => ControlFacts::Open(OpenFacts {
                is_ack: (header & wire_const::FLAG_T_OPEN_A) != 0,
                // R311ku — the seconds form is projected back to milliseconds at the wire
                // boundary, as the decoded Open's lease is.
                lease: crate::lease::lease_from_wire(
                    (header & wire_const::FLAG_T_OPEN_T) != 0,
                    body.lease,
                ),
                initial_sn: body.initial_sn,
                cookie: body.cookie.as_ref().map(|cookie| *cookie.inner()),
                extensions,
            }),
            #[cfg(feature = "codec-close")]
            ControlRead::Close {
                reason, session, ..
            } => ControlFacts::Close {
                reason: *reason,
                session: *session,
            },
            #[cfg(feature = "codec-keep-alive")]
            ControlRead::KeepAlive { .. } => ControlFacts::KeepAlive,
            ControlRead::Refused => ControlFacts::Refused,
            ControlRead::Unread(_) => ControlFacts::Unread(core::marker::PhantomData),
        }
    }

    /// What a conforming participant must do with this message's extension chain, by the rule
    /// [`InboundFrame::ext_admission`] applies to the decoded message.
    pub(crate) fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        match self {
            #[cfg(feature = "codec-init-body")]
            ControlRead::Init { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_INIT, extensions)
            }
            #[cfg(feature = "codec-open-body")]
            ControlRead::Open { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_OPEN, extensions)
            }
            #[cfg(feature = "codec-close")]
            ControlRead::Close { extensions, .. } => {
                judge_transport_chain(wire_const::T_MID_CLOSE, extensions)
            }
            #[cfg(feature = "codec-keep-alive")]
            ControlRead::KeepAlive { extensions } => {
                judge_transport_chain(wire_const::T_MID_KEEP_ALIVE, extensions)
            }
            ControlRead::Refused | ControlRead::Unread(_) => {
                crate::ext_admit::ExtAdmission::Unjudged
            }
        }
    }
}

/// Read the transport message at the front of `bytes`, which carries no data, where it lies
/// ([`ControlRead`]), and where it ended: the reading
/// [`parse_inbound_consuming_into`] gives the same bytes, refusals and extents included, with
/// no handshake body copied out of the unit. `0` is an extent this reader cannot know (a
/// `Frame` or a `Fragment`, which it is not handed to read, or a message this build does not
/// read), as it is for the decoder.
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    feature = "session-unicast"
))]
pub(crate) fn read_control(bytes: &[u8]) -> Result<(ControlRead<'_>, usize), InboundParseError> {
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mut cursor = SceCursor::new(bytes);
    let read = match header & 0x1F {
        #[cfg(feature = "codec-init-body")]
        wire_const::T_MID_INIT => {
            let view = TransportInitView::decode(&mut cursor)?;
            // The fixed profile refuses a body its storage cannot hold, the cookie past its
            // capacity; the view holds any, so the decoder's storing is asked for its verdict.
            #[cfg(feature = "session-slot")]
            view.body.clone().try_into_owned_in::<HandshakeStorage>()?;
            let mut extensions = ExtChainOwned::new();
            collect_handshake_ext_chain(
                wire_const::T_MID_INIT,
                crate::ext_view::walked(view.extensions.as_ref()),
                &mut extensions,
            )?;
            // A zid that is no zid is refused, after the chain as the decoder refuses it
            // (`refuse_unnamed_zid`).
            if let Err(refused) = crate::session_zid::SessionZid::new(view.body.zid.inner()) {
                return Err(InboundParseError::InvalidZid(refused));
            }
            ControlRead::Init {
                header: view.header,
                body: view.body,
                extensions,
            }
        }
        #[cfg(feature = "codec-open-body")]
        wire_const::T_MID_OPEN => {
            let view = TransportOpenView::decode(&mut cursor)?;
            #[cfg(feature = "session-slot")]
            view.body.clone().try_into_owned_in::<HandshakeStorage>()?;
            let mut extensions = ExtChainOwned::new();
            collect_handshake_ext_chain(
                wire_const::T_MID_OPEN,
                crate::ext_view::walked(view.extensions.as_ref()),
                &mut extensions,
            )?;
            ControlRead::Open {
                header: view.header,
                body: view.body,
                extensions,
            }
        }
        #[cfg(feature = "codec-close")]
        wire_const::T_MID_CLOSE => {
            let view = TransportCloseView::decode(&mut cursor)?;
            let mut extensions = ExtChainOwned::new();
            collect_handshake_ext_chain(
                wire_const::T_MID_CLOSE,
                crate::ext_view::walked(view.extensions.as_ref()),
                &mut extensions,
            )?;
            ControlRead::Close {
                reason: view.body.reason,
                session: (view.header & wire_const::FLAG_T_CLOSE_S) != 0,
                extensions,
            }
        }
        #[cfg(feature = "codec-keep-alive")]
        wire_const::T_MID_KEEP_ALIVE => {
            let view = TransportKeepAliveView::decode(&mut cursor)?;
            let mut extensions = ExtChainOwned::new();
            collect_handshake_ext_chain(
                wire_const::T_MID_KEEP_ALIVE,
                crate::ext_view::walked(view.extensions.as_ref()),
                &mut extensions,
            )?;
            ControlRead::KeepAlive { extensions }
        }
        // A JOIN is refused whatever it says, but it is read to its end with the decoder's
        // refusals, in the decoder's order (the message, its chain, its zid), so the walk of the
        // unit steps over it as the decoder's reading does. Nothing of it is kept: the zid is
        // judged where it lies and the chain by the verdict alone.
        #[cfg(feature = "codec-join")]
        wire_const::T_MID_JOIN => {
            let view = wz_codecs::transport_join::TransportJoinView::decode(&mut cursor)?;
            crate::ext_chain::check_ext_chain(crate::ext_view::walked(view.extensions.as_ref()))?;
            if let Err(refused) = crate::session_zid::SessionZid::new(view.body.zid.into_inner()) {
                return Err(InboundParseError::InvalidZid(refused));
            }
            ControlRead::Refused
        }
        // A transport OAM likewise: its encoding and its chain are judged as the decoder judges
        // them, and nothing of it is kept.
        wire_const::T_MID_OAM => {
            use wz_codecs::transport_oam::{TransportOamView, TransportOamViewVariant};
            let view = TransportOamView::decode(&mut cursor)?;
            if matches!(view.body, TransportOamViewVariant::Default { .. }) {
                return Err(InboundParseError::ReservedEncoding);
            }
            crate::ext_chain::check_ext_chain(crate::ext_view::walked(view.extensions.as_ref()))?;
            ControlRead::Refused
        }
        _ => return Ok((ControlRead::Unread(core::marker::PhantomData), 0)),
    };
    Ok((read, bytes.len() - cursor.remaining()))
}

/// The KEEP_ALIVE message (`T_MID_KEEP_ALIVE`, 0x04): its body is empty, so the
/// only thing to read past the header is the Z-gated ext chain behind it. The
/// whole message is read by its document (`sources/codecs/transport_keep_alive.scxml`)
/// as [`parse_init`] reads an Init.
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
fn decode_keep_alive(bytes: &[u8], out: &mut InboundFrame) -> Result<usize, InboundParseError> {
    let mut cursor = SceCursor::new(bytes);
    let view = TransportKeepAliveView::decode(&mut cursor)?;
    // The frame first, in `out`, its chain kept where it will stay (see `parse_init`).
    *out = InboundFrame::KeepAlive {
        has_ext: (view.header & wire_const::FLAG_T_Z) != 0,
        extensions: ExtChainOwned::new(),
    };
    if let InboundFrame::KeepAlive { extensions, .. } = out {
        collect_handshake_ext_chain(
            wire_const::T_MID_KEEP_ALIVE,
            crate::ext_view::walked(view.extensions.as_ref()),
            extensions,
        )?;
    }
    Ok(bytes.len() - cursor.remaining())
}

/// The JOIN (`T_MID_JOIN`, 0x07), read whole by its document
/// (`sources/codecs/transport_join.scxml`) off its own cursor: the generated `Join` codec has
/// no ext awareness, so the chain starts wherever the base body stopped. The lease is projected
/// to milliseconds as every Join reader here projects it (`crate::join_decode` is the SSOT the
/// multicast participant shares, which keeps the S bit's two optional fields and the T bit's
/// lease UNIT projected in one place). The in-place reader of a control message
/// (`read_control`) gives the same refusals without the owned body or chain, since a
/// participant refuses a JOIN whatever it says; a test holds the two readers to each other
/// on every wire and every prefix of it.
#[cfg(all(feature = "alloc", feature = "codec-join"))]
fn decode_join_message(bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
    let mut cursor = SceCursor::new(bytes);
    let view = wz_codecs::transport_join::TransportJoinView::decode(&mut cursor)?;
    let join_has_ext = (view.header & wire_const::FLAG_T_Z) != 0;
    let mut body = view.body.try_into_owned()?;
    body.lease =
        crate::lease::lease_from_wire((view.header & wire_const::FLAG_T_JOIN_T) != 0, body.lease);
    let extensions =
        crate::ext_chain::collect_ext_chain(crate::ext_view::walked(view.extensions.as_ref()))?;
    Ok((
        InboundFrame::Join {
            has_ext: join_has_ext,
            body,
            extensions,
        },
        bytes.len() - cursor.remaining(),
    ))
}

/// The transport OAM (`T_MID_OAM`, 0x00), read whole by its document
/// (`sources/codecs/transport_oam.scxml`) off its own cursor.
///
/// # Why it is a function and not a match arm
///
/// The shape reason: it reads the wire in an order no other transport MID uses
/// — `id:z16`, then the ext chain, then a body whose ENCODING came from header
/// bits 5..6 — and it binds its own cursor because the shared one is bound
/// only under the `codec-*` union, which this arm does not join. That is the
/// same separation the JOIN arm, which reads its message on a cursor of its
/// own through the message's document, already has.
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
#[cfg(feature = "alloc")]
#[inline(never)]
fn decode_oam(bytes: &[u8]) -> Result<(InboundFrame, usize), InboundParseError> {
    use wz_codecs::transport_oam::{TransportOamView, TransportOamViewVariant};

    let mut cursor = SceCursor::new(bytes);
    let view = TransportOamView::decode(&mut cursor)?;
    let (value, body) = match &view.body {
        TransportOamViewVariant::CodecZenohExtUnit(_) => (0, Vec::new()),
        TransportOamViewVariant::CodecZenohExtZint(z64) => (z64.value, Vec::new()),
        TransportOamViewVariant::CodecZenohExtZbuf(zbuf) => (0, zbuf.value.into_inner().to_vec()),
        // 0b11 is RESERVED and zenoh's own decoder returns `DidntRead` for it
        // (`transport/oam.rs`), where the document reads it through its default
        // arm. Refused here for the same reason a corrupt body is: a sender that
        // wrote it wrote a message no conforming peer retrieves, and reporting a
        // length for it would step the batch walk onto invented bytes.
        TransportOamViewVariant::Default { .. } => return Err(InboundParseError::ReservedEncoding),
    };
    let extensions =
        crate::ext_chain::collect_ext_chain(crate::ext_view::walked(view.extensions.as_ref()))?;
    Ok((
        InboundFrame::Oam {
            // The id's WIRE width is a full zint and its VALUE width is 16
            // bits, and upstream bridges the two by TRUNCATING
            // (`oam_id_from_wire`). Refusing a wider id would answer `Err` on a
            // message stock zenoh reads to the end, and an `Err` here consumes
            // nothing, so the batch walk would stop and lose every message
            // behind the OAM.
            id: wz_codecs::wire_const::oam_id_from_wire(view.id),
            encoding: view.enc(),
            value,
            body,
            has_ext: view.z(),
            extensions,
        },
        bytes.len() - cursor.remaining(),
    ))
}

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

    /// An entry with the reserved encoding and the `M` bit CLEAR still DECODES
    /// (as a unit, so the analyzer sees it) and is a framing error for a
    /// participant, as zenoh 1.10.2 refuses the message
    /// (`commons/zenoh-codec/src/common/extension.rs` @ `let body = match self.header & iext::ENC_MASK {`).
    /// Before this rule the same frame reached the data path.
    #[test]
    fn a_frame_carrying_a_reserved_encoding_extension_is_a_framing_error() {
        // id 0xF, encoding 0b11, M clear, chain terminator.
        let frame = parse_inbound(&frame_with_chain(&[0x6F])).expect("the frame still DECODES");
        assert_eq!(
            frame.ext_admission(),
            ExtAdmission::ReservedEncoding { eid: 0x6F },
            "{frame:?}"
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
    #[cfg(all(feature = "codec-init-body", feature = "session-unicast-accept"))]
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
        let mut wire = alloc::vec![wire_const::T_MID_JOIN | flags];
        wire.extend_from_slice(&join.encode_to_vec());
        wire
    }

    fn sample() -> wz_codecs::join::Join<'static> {
        wz_codecs::join::Join {
            version: 0x09,
            // whatami = peer (0x01), zid_len-1 = 3.
            cbyte: (3 << 4) | 0x01,
            zid: wz_codecs::Bounded::new(&[0xA0u8, 0xA1, 0xA2, 0xA3] as &[u8]).unwrap(),
            s: Some(wz_codecs::join::JoinS {
                sn_res: 0x00,
                batch_size: 0x1000,
            }),
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
                assert_eq!(body.s.map(|s| s.sn_res), Some(0x00));
                assert_eq!(body.s.map(|s| s.batch_size), Some(0x1000));
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
            s: None,
            ..sample()
        };
        let wire = join_wire(0, &minimal);
        match parse_inbound(&wire).expect("parse_inbound rejected the minimal join") {
            InboundFrame::Join { body, .. } => {
                assert_eq!(body.s, None);
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
            s: None,
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
                zid: wz_codecs::Bounded::new(&[0xA0u8, 0xA1, 0xA2, 0xA3] as &[u8]).unwrap(),
                s: Some(wz_codecs::join::JoinS {
                    sn_res: 0x00,
                    batch_size: 0x1000,
                }),
                lease: 10_000,
                next_sn_reliable: 7,
                next_sn_best_effort: 9,
            };
            let mut wire = alloc::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
            wire.extend_from_slice(&join.encode_to_vec());
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

    /// R2102 (open-debt item 524) — THE NUMBER IS PINNED, because it is an ABI.
    ///
    /// `kind_code` is what a C consumer of the live door switches on, and a
    /// consumer compiled today against `WZ_DISSECT_KIND_FRAME == 5` reads that
    /// value for as long as the library it links exports the symbol. So the
    /// number is not free to move the way an internal discriminant would be,
    /// and the literal below is where it is held down.
    ///
    /// Asserted over a real `parse_inbound` decode, on this module's own house
    /// rule: a code proven over a hand-built value proves the constructor and
    /// not the decoder. The table is keyed by the NAME so the two projections
    /// are checked against each other in one place — a round that renumbered
    /// one arm and not the other fails here rather than in a consumer.
    #[test]
    fn every_reachable_variant_answers_its_pinned_code() {
        for (wire, name) in reachable() {
            let want: u8 = match name {
                "Init" => 1,
                "Open" => 2,
                "Close" => 3,
                "KeepAlive" => 4,
                "Frame" => 5,
                "Fragment" => 6,
                "Join" => 7,
                "Oam" => 8,
                "Unknown" => 255,
                // A NAME this table does not know is a kind the enum gained
                // with no number written down for it, which is precisely the
                // event a consumer cannot survive silently.
                other => panic!(
                    "`{other}` is a message kind with no pinned code. Add it \
                     here AND to `wz_dissect.h`'s WZ_DISSECT_KIND_* set in the \
                     same commit -- a code a consumer has never been told \
                     about is one it has no case for."
                ),
            };
            let frame = parse_inbound(&wire).expect("the fixture wire decodes");
            assert_eq!(
                frame.kind_code(),
                want,
                "wire {wire:02X?} decoded to `{name}`, whose pinned code is \
                 {want} -- a code that moves renames a message for every \
                 consumer already compiled against it"
            );
        }
    }

    /// The codes must be pairwise DISTINCT, for the reason the names must be:
    /// two arms answering one number makes a live tap report two message kinds
    /// as one, which reads as traffic that carried more of the first and none
    /// of the second.
    ///
    /// Over what `kind_code` ACTUALLY answers rather than over the table in the
    /// test above — those are literals in this file, so a distinctness check on
    /// them would assert only that this file's own list has no duplicate.
    #[test]
    fn no_two_variants_answer_the_same_code() {
        let mut codes: Vec<u8> = reachable()
            .into_iter()
            .map(|(wire, _)| {
                parse_inbound(&wire)
                    .expect("the fixture wire decodes")
                    .kind_code()
            })
            .collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), before, "two variants share a code: {codes:?}");
    }
}

// The priority of a Frame / Fragment is read from the transport QoS, which is
// told by its identity: `frame::ext::QoS = zextz64!(0x1, true)`, header `0x31`
// (`commons/zenoh-protocol/src/transport/frame.rs` @
// `pub type QoS = zextz64!(0x1, true);`), matched by `iext::eid`
// (`commons/zenoh-codec/src/transport/frame.rs` @ `ext::QoS::ID => {`). The
// same id with the mandatory bit clear is an unknown extension there.
#[cfg(all(test, feature = "codec-frame"))]
mod frame_qos_identity_tests {
    use super::*;
    use crate::ext_header::{lookalike_headers, network_eid, EXT_FLAG_Z};
    use crate::transport_profile::ExtEntryOwnedVariant;
    use wz_codecs::ext_zint::ExtZint;

    fn zint(header: u8, value: u64) -> ExtEntryOwned {
        ExtEntryOwned {
            header,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        }
    }

    #[test]
    fn the_transport_qos_is_told_by_its_identity_not_its_id() {
        let want = crate::qos::Priority::from_wire(3);
        for header in [
            network_eid::TRANSPORT_QOS,
            network_eid::TRANSPORT_QOS | EXT_FLAG_Z,
        ] {
            assert_eq!(
                ext_qos_priority(&[zint(header, 3)]),
                want,
                "{header:#04x} is the transport QoS"
            );
        }
        for header in lookalike_headers(network_eid::TRANSPORT_QOS).filter(|h| (h >> 5) & 3 == 1) {
            assert_eq!(
                ext_qos_priority(&[zint(header, 3)]),
                crate::qos::Priority::DEFAULT,
                "{header:#04x} shares only the id with the transport QoS"
            );
        }
    }
}

// An Init declares no MANDATORY extension, so one with the M bit set is refused
// whatever its id: upstream's reader matches `iext::eid(ext)` against the nine
// it knows, every one of them `zextX!(_, false)`
// (`commons/zenoh-codec/src/transport/init.rs` @ `match iext::eid(ext) {`), and
// `extension::skip` refuses what is left when it is mandatory. The decode arm
// used to refuse by the 4-bit id against a list of ids, which let `0x58`, the
// region name as a mandatory ZBuf, through as a KNOWN extension; the decode now
// reads every chain and the participant seam judges it, as for every other
// transport message.
#[cfg(all(
    test,
    feature = "codec-init-body",
    feature = "session-unicast",
    feature = "session-unicast-accept"
))]
mod init_mandatory_identity_tests {
    use super::*;

    /// An InitSyn with one extension chain entry: header, then the body the
    /// header's encoding needs (nothing, a zint 0, a ZBuf of length 0).
    fn init_with(header: u8) -> Vec<u8> {
        // version, cbyte (zid_len-1 = 0, whatami peer), the 1-byte zid.
        let mut wire = alloc::vec![
            wire_const::T_MID_INIT | wire_const::FLAG_T_Z,
            0x09,
            0x01,
            0xAA
        ];
        wire.push(header);
        if (header >> 5) & 3 != 0 {
            wire.push(0x00);
        }
        wire
    }

    #[test]
    fn a_mandatory_extension_is_refused_on_an_init_whatever_its_id() {
        use crate::ext_admit::ExtAdmission;
        use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
        for id in 0u8..16 {
            for enc in 0u8..3 {
                let optional = id | (enc << 5);
                let mandatory = optional | crate::ext_header::EXT_FLAG_M;
                let frame = parse_inbound(&init_with(optional)).expect("the optional one decodes");
                assert_eq!(
                    frame.ext_admission(),
                    ExtAdmission::Admissible,
                    "{optional:#04x} is not mandatory and is skipped"
                );
                assert!(matches!(
                    inbound_to_fsm_event(&frame),
                    Some(E::InitSynReceived)
                ));
                let frame = parse_inbound(&init_with(mandatory)).expect("the decode reads it");
                assert_eq!(
                    frame.ext_admission(),
                    ExtAdmission::UnknownMandatory { eid: mandatory },
                    "{mandatory:#04x} is mandatory and unknown"
                );
                assert!(matches!(
                    inbound_to_fsm_event(&frame),
                    Some(E::FramingError)
                ));
            }
        }
    }
}

// A link's question of a datagram from a source it has no session with: does it ask
// for one? A header read (`crate::datagram_peer::is_init_syn`, where its own cases
// are tested), so it must agree with what the full decode calls an InitSyn.
#[cfg(all(test, feature = "codec-init-body", feature = "session-unicast"))]
mod init_syn_header_tests {
    use super::*;
    use crate::datagram_peer::is_init_syn;

    #[test]
    fn it_agrees_with_the_full_decode() {
        for wire in [
            alloc::vec![wire_const::T_MID_INIT, 0x09, 0x01, 0xAA],
            alloc::vec![
                wire_const::T_MID_INIT | wire_const::FLAG_T_INIT_A,
                0x09,
                0x01,
                0xAA,
                0x00
            ],
        ] {
            let decoded_as_syn = matches!(
                parse_inbound(&wire),
                Ok(InboundFrame::Init { is_ack: false, .. })
            );
            assert_eq!(is_init_syn(&wire), decoded_as_syn, "{wire:?}");
        }
    }
}

// The zid an INIT names is refused where the message is read when it is zero, as zenoh's
// decoder refuses it; its length is the header's four bits plus one, so always 1..=16.
#[cfg(all(test, feature = "codec-init-body"))]
mod init_zid_tests {
    use super::*;
    use crate::session_zid::ZidError;

    /// An InitSyn from a peer whose zid is `zid`, with no sizing fields and no extensions.
    fn init_syn(zid: &[u8]) -> alloc::vec::Vec<u8> {
        let mut wire = alloc::vec![
            wire_const::T_MID_INIT,
            0x09,
            0x01 | (((zid.len() as u8) - 1) << 4)
        ];
        wire.extend_from_slice(zid);
        wire
    }

    #[test]
    fn an_init_naming_a_zero_zid_is_refused_and_a_zid_with_zero_bytes_is_not() {
        assert_eq!(
            parse_inbound(&init_syn(&[0x00])).err(),
            Some(InboundParseError::InvalidZid(ZidError::AllZero { len: 1 }))
        );
        assert_eq!(
            parse_inbound(&init_syn(&[0x00; 16])).err(),
            Some(InboundParseError::InvalidZid(ZidError::AllZero { len: 16 }))
        );
        // Control: the same message with one byte that is not zero is read, wherever it lies.
        assert!(matches!(
            parse_inbound(&init_syn(&[0x00, 0x01])),
            Ok(InboundFrame::Init { is_ack: false, .. })
        ));
        assert!(matches!(
            parse_inbound(&init_syn(&[0xAA])),
            Ok(InboundFrame::Init { is_ack: false, .. })
        ));
    }
}

/// The in-place reader of a control message is held to the decoder: on every wire, and on every
/// prefix of it, the two read the same facts, the same extent, the same chain verdict and the
/// same event, or refuse with the same error.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "codec-frame",
    feature = "session-unicast"
))]
mod control_read_tests {
    use super::*;
    use alloc::{format, vec, vec::Vec};

    // `vec![]` cannot express this: elements are `#[cfg]`-gated.
    #[allow(clippy::vec_init_then_push)]
    fn wires() -> Vec<Vec<u8>> {
        use wire_const::*;
        let mut wires: Vec<Vec<u8>> = Vec::new();
        #[cfg(feature = "codec-init-body")]
        {
            // version, cbyte (zid length - 1 in the high nibble, the role below), the zid.
            wires.push(vec![T_MID_INIT, 0x09, 0x01, 0xAA]);
            // A zid of one zero byte names no node.
            wires.push(vec![T_MID_INIT, 0x09, 0x01, 0x00]);
            // The S pair: sn_res, then batch_size little-endian.
            wires.push(vec![
                T_MID_INIT | FLAG_T_INIT_S,
                0x09,
                0x01,
                0xAA,
                0x00,
                0x00,
                0x10,
            ]);
            // An InitAck with a cookie, and with the S pair and a cookie.
            wires.push(vec![
                T_MID_INIT | FLAG_T_INIT_A,
                0x09,
                0x12,
                0xAA,
                0xBB,
                0x03,
                0x01,
                0x02,
                0x03,
            ]);
            wires.push(vec![
                T_MID_INIT | FLAG_T_INIT_A | FLAG_T_INIT_S,
                0x09,
                0x12,
                0xAA,
                0xBB,
                0x00,
                0x00,
                0x08,
                0x02,
                0xC0,
                0xC1,
            ]);
            // A chain: a z64 at id 0x7, then a mandatory unit extension of an id no Init defines.
            wires.push(vec![T_MID_INIT | FLAG_T_Z, 0x09, 0x01, 0xAA, 0x27, 0x01]);
            wires.push(vec![T_MID_INIT | FLAG_T_Z, 0x09, 0x01, 0xAA, 0x1F]);
            wires.push(vec![
                T_MID_INIT | FLAG_T_Z,
                0x09,
                0x01,
                0xAA,
                0xA7,
                0x01,
                0x1F,
            ]);
            // Another version.
            wires.push(vec![T_MID_INIT, 0x08, 0x01, 0xAA]);
        }
        #[cfg(feature = "codec-open-body")]
        {
            // lease, initial_sn; the T flag writes the lease in seconds.
            wires.push(vec![T_MID_OPEN | FLAG_T_OPEN_A, 0x0A, 0x01]);
            wires.push(vec![T_MID_OPEN | FLAG_T_OPEN_A | FLAG_T_OPEN_T, 0x0A, 0x01]);
            // An OpenSyn echoes a cookie.
            wires.push(vec![T_MID_OPEN, 0x0A, 0x01, 0x02, 0xC1, 0xC2]);
            wires.push(vec![T_MID_OPEN | FLAG_T_Z, 0x0A, 0x01, 0x00, 0x27, 0x01]);
        }
        #[cfg(feature = "codec-close")]
        {
            wires.push(vec![T_MID_CLOSE, 0x00]);
            wires.push(vec![T_MID_CLOSE | FLAG_T_CLOSE_S, 0x07]);
        }
        #[cfg(feature = "codec-keep-alive")]
        {
            wires.push(vec![T_MID_KEEP_ALIVE]);
            wires.push(vec![T_MID_KEEP_ALIVE | FLAG_T_Z, 0x1F]);
        }
        wires.push(vec![T_MID_FRAME | FLAG_T_FRAME_R, 0x07, 0xEE]);
        wires.push(vec![T_MID_FRAGMENT | FLAG_T_FRAGMENT_R, 0x09, b'h']);
        // The OAM's four encodings, the last reserved.
        wires.push(vec![T_MID_OAM, 0x01]);
        wires.push(vec![T_MID_OAM | 0x20, 0x01, 0x05]);
        wires.push(vec![T_MID_OAM | 0x40, 0x01, 0x02, 0xAB, 0xCD]);
        wires.push(vec![T_MID_OAM | 0x60, 0x01]);
        wires.push(vec![T_MID_OAM | FLAG_T_Z, 0x01, 0x27, 0x01]);
        // A ZBuf extension (id 0x2, not mandatory), read to its end and copied nowhere.
        wires.push(vec![T_MID_OAM | FLAG_T_Z, 0x01, 0x42, 0x02, 0xAB, 0xCD]);
        #[cfg(feature = "codec-join")]
        {
            let join = wz_codecs::join::Join {
                version: 0x09,
                cbyte: (3 << 4) | 0x01,
                zid: wz_codecs::Bounded::new(&[0xA0u8, 0xA1, 0xA2, 0xA3] as &[u8]).unwrap(),
                s: Some(wz_codecs::join::JoinS {
                    sn_res: 0x00,
                    batch_size: 0x1000,
                }),
                lease: 10_000,
                next_sn_reliable: 7,
                next_sn_best_effort: 9,
            };
            let mut wire = vec![T_MID_JOIN | FLAG_T_JOIN_S];
            wire.extend_from_slice(&join.encode_to_vec());
            wires.push(wire.clone());
            // The QoS extension (id 0x1, mandatory, a ZBuf) behind the body.
            wire[0] |= FLAG_T_Z;
            wire.extend_from_slice(&[0x51, 0x02, 0xAB, 0xCD]);
            wires.push(wire);
            // A zid of zeros, which names no node: refused by both readers, after the chain.
            let unnamed = wz_codecs::join::Join {
                zid: wz_codecs::Bounded::new(&[0u8, 0, 0, 0] as &[u8]).unwrap(),
                ..join
            };
            let mut wire = vec![T_MID_JOIN | FLAG_T_JOIN_S];
            wire.extend_from_slice(&unnamed.encode_to_vec());
            wires.push(wire);
        }
        wires.push(vec![0x1F]);
        wires
    }

    /// The reader against the decoder on one wire.
    fn agree_on(wire: &[u8]) {
        let mid = wire.first().map(|header| header & 0x1F);
        let read = read_control(wire);
        // A Frame or a Fragment is the in-place receive's to read; handed here it is a message
        // this reader does not take, of an extent it does not know.
        if matches!(
            mid,
            Some(wire_const::T_MID_FRAME | wire_const::T_MID_FRAGMENT)
        ) {
            let (message, used) = read.unwrap_or_else(|err| panic!("{wire:02x?}: {err:?}"));
            assert!(
                matches!(message.facts(), ControlFacts::Unread(_)),
                "{wire:02x?}"
            );
            assert_eq!(used, 0, "{wire:02x?}");
            return;
        }
        let decoded = parse_inbound_consuming(wire);
        match (read, decoded) {
            (Ok((message, used)), Ok((frame, decoded_used))) => {
                let facts = message.facts();
                let frame_facts = frame.control_facts();
                assert_eq!(
                    format!("{facts:?}"),
                    format!("{frame_facts:?}"),
                    "{wire:02x?}"
                );
                assert_eq!(used, decoded_used, "{wire:02x?}");
                assert_eq!(
                    format!("{:?}", control_event(message.ext_admission(), &facts)),
                    format!("{:?}", inbound_to_fsm_event(&frame)),
                    "{wire:02x?}"
                );
                if !matches!(facts, ControlFacts::Refused | ControlFacts::Unread(_)) {
                    assert_eq!(
                        format!("{:?}", message.ext_admission()),
                        format!("{:?}", frame.ext_admission()),
                        "{wire:02x?}"
                    );
                }
            }
            (Err(read), Err(decoded)) => {
                assert_eq!(format!("{read:?}"), format!("{decoded:?}"), "{wire:02x?}");
            }
            (read, decoded) => panic!(
                "{wire:02x?}: read {:?}, decoded {:?}",
                read.map(|(message, used)| (format!("{:?}", message.facts()), used)),
                decoded.map(|(frame, used)| (frame.kind_name(), used))
            ),
        }
    }

    #[test]
    fn the_in_place_reader_agrees_with_the_decoder_on_every_wire_and_prefix() {
        for wire in wires() {
            for end in 0..=wire.len() {
                agree_on(&wire[..end]);
            }
        }
    }

    /// The wires the decoder is known to read are read by the in-place reader too, so the
    /// agreement above is not an agreement of two refusals.
    #[test]
    fn the_in_place_reader_reads_the_handshake_facts() {
        #[cfg(feature = "codec-init-body")]
        {
            let wire = [
                wire_const::T_MID_INIT | wire_const::FLAG_T_INIT_A,
                0x09,
                0x12,
                0xAA,
                0xBB,
                0x03,
                0x01,
                0x02,
                0x03,
            ];
            let (message, used) = read_control(&wire).expect("an InitAck");
            assert_eq!(used, wire.len());
            match message.facts() {
                ControlFacts::Init(init) => {
                    assert!(init.is_ack);
                    assert_eq!(init.version, 0x09);
                    assert_eq!(init.whatami, 0x02);
                    assert_eq!(init.zid, &[0xAA, 0xBB]);
                    assert_eq!(init.cookie, Some(&[0x01u8, 0x02, 0x03][..]));
                    assert!(init.s.is_none());
                }
                other => panic!("{other:?}"),
            }
            assert!(matches!(
                read_control(&[wire_const::T_MID_INIT, 0x09, 0x01, 0x00]),
                Err(InboundParseError::InvalidZid(_))
            ));
        }
        #[cfg(feature = "codec-open-body")]
        {
            let wire = [
                wire_const::T_MID_OPEN | wire_const::FLAG_T_OPEN_A | wire_const::FLAG_T_OPEN_T,
                0x0A,
                0x01,
            ];
            let (message, _) = read_control(&wire).expect("an OpenAck");
            match message.facts() {
                ControlFacts::Open(open) => {
                    assert!(open.is_ack);
                    assert_eq!(open.lease, 10_000, "seconds on the wire, milliseconds read");
                    assert_eq!(open.initial_sn, 1);
                }
                other => panic!("{other:?}"),
            }
        }
        #[cfg(feature = "codec-close")]
        {
            let (message, _) =
                read_control(&[wire_const::T_MID_CLOSE | wire_const::FLAG_T_CLOSE_S, 0x07])
                    .expect("a Close");
            assert!(matches!(
                message.facts(),
                ControlFacts::Close {
                    reason: 0x07,
                    session: true
                }
            ));
        }
        // An OAM is read to its end and refused; an id no reader takes is not read.
        let (message, used) = read_control(&[wire_const::T_MID_OAM, 0x01]).expect("an OAM");
        assert!(matches!(message.facts(), ControlFacts::Refused));
        assert_eq!(used, 2);
        let (message, used) = read_control(&[0x1F]).expect("an unread id");
        assert!(matches!(message.facts(), ControlFacts::Unread(_)));
        assert_eq!(used, 0);
    }
}
