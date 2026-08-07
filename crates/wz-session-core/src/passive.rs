// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y578 (G2) — the PASSIVE session-context tracker: reading a zenoh
//! session you did not take part in.
//!
//! ## What this exists for
//!
//! Every decoder in this crate already takes bytes and nothing else
//! ([`crate::inbound::parse_inbound`],
//! [`crate::network_message::parse_frame_payload`]). What wz did not have is
//! the thing that tells those decoders WHERE a message starts and WHAT
//! contract the bytes were written under, for a session wz is watching rather
//! than holding.
//!
//! A participant never needs it. It knows the negotiated parameters because it
//! negotiated them, and its link layer was configured with the framing before
//! the first byte moved. An observer knows neither, and both are load-bearing:
//!
//! - **Framing is not fixed.** A stream link length-prefixes every frame with
//!   a 2-byte LE `u16` — until the session negotiates `LowLatency` (`0x5` on
//!   BOTH Inits) and reaches Established, after which the prefix is a 4-byte
//!   LE `u32` (`wz-runtime-tokio/src/stream_link.rs:55-62`, zenoh
//!   `unicast/lowlatency/link.rs`). Read the wrong width for one frame and
//!   every subsequent boundary in that direction is wrong.
//! - **The batch body is not always the batch body.** With `Compression`
//!   (`0x6` on both Inits) negotiated, a post-establishment frame body is an
//!   lz4-wrapped batch ([`crate::compression`]).
//! - **Fragment chains carry rules only above a patch level** — the `0x7`
//!   level ([`crate::extpatch`]) decides whether the `First` / `Drop` markers
//!   mean anything ([`crate::extfragment`]).
//!
//! ## The negotiation an observer must reproduce
//!
//! zenoh finalises each capability at the Init exchange with `&=` on each
//! side, so the session's value is the AND of the two offers; the patch level
//! is the `min` of the two announcements. A participant computes its half and
//! trusts the peer to compute the same. An observer sees BOTH halves and must
//! do the whole thing itself — which is why [`PassiveSession`] tracks per
//! DIRECTION and folds, rather than reusing
//! [`crate::session_actions::SessionLinkActions`]'s single-sided state.
//!
//! ## What this module is NOT
//!
//! No I/O. It takes byte slices and returns decoded frames. Capture ingest
//! (pcap / AF_PACKET, TCP flow reassembly, offset mapping) is G1 and belongs
//! above this layer; what this module owns is the part that needs to
//! understand zenoh.

use alloc::vec::Vec;

use crate::ext_header::{establishment_ext_id as est_ext, ext_eid};
use crate::inbound::{parse_inbound, InboundFrame};
#[cfg(feature = "codec-frame")]
use crate::network_message::{parse_frame_payload_best_effort, BatchParse};
use crate::parse_error::InboundParseError;
use crate::peer_init_caps::PeerInitCaps;
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::{
    Fragment as ReasmFragment, IngestOutcome, ReassemblyConfig, ReassemblyDispatcher,
};
use wz_codecs::ext_entry::ExtEntryOwned;

/// The universal stream length-prefix width: 2-byte LE `u16`.
pub const PREFIX_WIDTH_UNIVERSAL: usize = 2;

/// The lowlatency stream length-prefix width: 4-byte LE `u32`, in force only
/// once a session that negotiated `LowLatency` reaches Established.
pub const PREFIX_WIDTH_LOWLATENCY: usize = 4;

/// A stream frame's payload may never exceed the `u16` batch ceiling, which is
/// what bounds the 4-byte prefix's untrusted `u32`. The participant-side read
/// applies the same cap (`wz-runtime-tokio/src/lib.rs:1541`, zenoh's
/// "Batch len is invalid" rejection); an observer that skipped it would let a
/// corrupt capture ask for a ~4 GiB buffer.
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

/// Which half of a session a byte stream carries.
///
/// Named for the ROLE rather than for an address, because a capture may not
/// tell you which side dialled. The tracker never needs to know: it folds the
/// two directions symmetrically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// The half whose first Init this observer saw. Conventionally the
    /// initiator, but the tracker does not depend on it.
    A,
    /// The other half.
    B,
}

impl Direction {
    /// The opposite half.
    pub fn peer(self) -> Self {
        match self {
            Direction::A => Direction::B,
            Direction::B => Direction::A,
        }
    }
}

/// How far the observed session has progressed.
///
/// Deliberately NOT the session FSM ([`crate::session_fsm_unicast`]). That
/// machine models a session wz OWNS — it has roles, timers, and terminal
/// states an observer cannot drive. This is the observer's much smaller
/// question: which of the framing / decoding contracts is in force right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPhase {
    /// No Init seen yet in either direction. Universal framing.
    #[default]
    Unseen,
    /// One direction's Init has been seen; the capabilities are half-folded
    /// and NOT yet final.
    HalfInit,
    /// Both Inits seen: every capability is negotiated. Framing is still
    /// universal — lowlatency reframes at Established, not at Init.
    InitComplete,
    /// An Open has been seen after the Init exchange. From here the
    /// negotiated framing and body wrapping are in force.
    Established,
    /// A Close was seen. Later bytes on this session are not decodable as
    /// part of it.
    Closed,
}

/// The parameters an observer infers from watching a handshake — the shape a
/// participant would have been configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowContext {
    /// How far the session has progressed.
    pub phase: SessionPhase,
    /// `LowLatency` (`0x5`) offered by BOTH sides. Once
    /// [`SessionPhase::Established`], the stream prefix is 4 bytes.
    pub lowlatency: bool,
    /// `Compression` (`0x6`) offered by BOTH sides. Once established, frame
    /// bodies are lz4-wrapped batches.
    pub compression: bool,
    /// `QoS` (`0x1`) offered by BOTH sides — whether a non-DEFAULT `ext_qos`
    /// priority on a Frame or Fragment is meaningful.
    pub qos: bool,
    /// The `min` of both sides' `0x7` announcements, `None` until at least one
    /// Init has been seen. `Some(0)` and `None` are DIFFERENT: the first says
    /// a peer announced no patch extension, the second that no Init was
    /// observed at all — a distinction that matters to a reader which attached
    /// mid-session.
    pub patch: Option<u8>,
    /// Whether an `Auth` (`0x3`) extension rode either Init. An observer that
    /// sees one knows a decode failure downstream may be authentication, not
    /// corruption.
    pub auth_offered: bool,
    /// Whether a `Shm` (`0x2`) extension rode either Init — a payload may
    /// carry a descriptor into a segment the observer cannot map.
    pub shm_offered: bool,
    /// Whether a `MultiLink` (`0x4`) extension rode either Init: this session
    /// may span more flows than the one being read.
    pub multilink_offered: bool,
    /// R311y583 (A5) — the session's effective size parameters, `None` until
    /// an InitAck has been observed.
    ///
    /// Taken from the ACK and not folded, because the negotiation is not a
    /// fold: zenoh requires every InitAck size parameter to be less than or
    /// equal to the InitSyn's and REJECTS a peer that enlarges one
    /// (`peer_init_caps::init_ack_exceeds_advertisement`, zenoh-pico
    /// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION`). So the acceptor's answer IS the
    /// session value, and an observer can read it directly — it has the
    /// `is_ack` bit that tells the two Inits apart, which is the one thing
    /// this needs that a `&=` fold would throw away.
    ///
    /// Decoded through [`PeerInitCaps::from_init_body`] rather than by
    /// re-splitting the packed `sn_res` byte here: that byte is
    /// `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)` and the S-clear
    /// defaults are non-obvious, so a second decoder would be a second place
    /// to get it wrong.
    pub caps: Option<PeerInitCaps>,
}

impl Default for FlowContext {
    fn default() -> Self {
        Self {
            phase: SessionPhase::Unseen,
            // Every capability starts TRUE and is ANDed down by each Init
            // observed, mirroring zenoh's `state.is_x &= other_ext.is_some()`.
            // The `phase` guard below is what keeps an un-negotiated `true`
            // from ever being READ as a negotiated one.
            lowlatency: true,
            compression: true,
            qos: true,
            patch: None,
            auth_offered: false,
            shm_offered: false,
            multilink_offered: false,
            caps: None,
        }
    }
}

impl FlowContext {
    /// The stream length-prefix width in force RIGHT NOW.
    ///
    /// The reframing is gated on BOTH `lowlatency` being negotiated and the
    /// session having reached Established, because that is exactly when the
    /// participant's link flips its own flag
    /// (`stream_link.rs:55-62`: the lowlatency open helper sets it "at
    /// Established"). A handshake frame on a lowlatency-bound session is still
    /// 2-byte-prefixed, so an observer that flipped at Init would mis-frame
    /// the Open exchange.
    pub fn prefix_width(&self) -> usize {
        if self.lowlatency_active() {
            PREFIX_WIDTH_LOWLATENCY
        } else {
            PREFIX_WIDTH_UNIVERSAL
        }
    }

    /// Lowlatency is NEGOTIATED and IN FORCE.
    pub fn lowlatency_active(&self) -> bool {
        self.negotiated() && self.lowlatency && self.phase == SessionPhase::Established
    }

    /// Compression is NEGOTIATED and IN FORCE — frame bodies are wrapped.
    pub fn compression_active(&self) -> bool {
        self.negotiated() && self.compression && self.phase == SessionPhase::Established
    }

    /// Whether the Init exchange completed, i.e. whether the capability
    /// fields are a NEGOTIATION rather than a partial fold. Reading
    /// `lowlatency` before this is reading the identity element of an `&=`,
    /// not an answer.
    pub fn negotiated(&self) -> bool {
        matches!(
            self.phase,
            SessionPhase::InitComplete | SessionPhase::Established | SessionPhase::Closed
        )
    }

    /// zenoh `PatchType::has_fragmentation_markers` over the negotiated level
    /// — whether the Fragment `First` / `Drop` markers may be enforced on this
    /// flow ([`crate::extfragment`]). `false` while no Init has been seen.
    /// R311y583 (A5) — the SN ring mask this session's fragment chains are
    /// compared at ([`crate::sn::mask_from_res`]).
    ///
    /// `None` until an InitAck has been observed, and a caller must NOT
    /// substitute a default: a mask that is too WIDE reads a legitimate
    /// wraparound as a gap, and one too NARROW reads a gap as a wraparound.
    /// Both produce a reassembly verdict that looks decisive and is not, which
    /// is why this returns an absence rather than a guess.
    pub fn sn_mask(&self) -> Option<u64> {
        self.caps.map(|c| crate::sn::mask_from_res(c.seq_num_res))
    }

    pub fn fragmentation_markers(&self) -> bool {
        self.patch
            .is_some_and(crate::extpatch::has_fragmentation_markers)
    }

    /// Fold ONE side's Init ext chain in. Idempotent per direction is the
    /// CALLER's business — [`PassiveSession`] tracks which directions have
    /// been folded so a retransmitted Init cannot double-AND a capability
    /// back on.
    fn fold_init(&mut self, extensions: &[ExtEntryOwned]) {
        self.lowlatency &= has_est_ext(extensions, est_ext::LOWLATENCY);
        self.compression &= has_est_ext(extensions, est_ext::COMPRESSION);
        self.qos &= has_est_ext(extensions, est_ext::QOS);
        self.auth_offered |= has_any_ext_id(extensions, est_ext::AUTH);
        self.shm_offered |= has_any_ext_id(extensions, est_ext::SHM);
        self.multilink_offered |= has_any_ext_id(extensions, est_ext::MULTILINK);
        let announced = crate::extpatch::peer_patch(extensions);
        self.patch = Some(match self.patch {
            Some(prev) => crate::extpatch::negotiate_patch(prev, announced),
            None => announced,
        });
    }
}

/// Presence of a UNIT-encoded capability offer at `id`. Matches on the
/// extension IDENTITY (encoding bits included), so a z64 or ZBuf entry
/// sharing the 4-bit id field is not read as the offer — the R311y505 defect,
/// which an observer is MORE exposed to than a participant is, since it reads
/// every peer's chain rather than only the ones wz interoperates with.
fn has_est_ext(extensions: &[ExtEntryOwned], id: u8) -> bool {
    extensions.iter().any(|e| ext_eid(e.header) == id)
}

/// Presence of ANY entry on the 4-bit id field, whatever its encoding. Used
/// for the "was this offered at all" flags, where the observer wants to know
/// that the id was on the wire even in a form it does not decode (zenoh's
/// `Shm` is a ZBuf while wz's offer is a UNIT — both are an SHM offer as far
/// as "can I expect descriptors" is concerned).
fn has_any_ext_id(extensions: &[ExtEntryOwned], id: u8) -> bool {
    extensions
        .iter()
        .any(|e| crate::ext_header::ext_id(e.header) == id)
}

/// One decoded transport message plus where it sat in its direction's stream.
#[derive(Debug)]
pub struct PassiveFrame {
    /// The direction this frame travelled.
    pub direction: Direction,
    /// Byte offset of the frame's LENGTH PREFIX within that direction's
    /// stream, counted from the first byte the observer was given. The anchor
    /// a capture-side layer (G1) maps back to a packet.
    pub stream_offset: usize,
    /// Width of the length prefix that framed it — recorded rather than
    /// recomputed, since the width can change between frames on the same
    /// stream.
    pub prefix_width: usize,
    /// The decoded transport message, or the decode error.
    pub frame: Result<InboundFrame, InboundParseError>,
    /// The flow context AS OF this frame (after folding it in). Copied rather
    /// than borrowed so a consumer can keep a decoded frame beside the
    /// contract it was read under.
    pub context: FlowContext,
    /// R311y583 (A2) — what this frame carried ABOVE the transport layer.
    ///
    /// Before A2 the tracker stopped here and every consumer re-did the same
    /// three connections itself: decompress the body when the session
    /// negotiated it, walk the batch, and drive a chain over Fragments. All
    /// three need the negotiated context, which is the thing this type exists
    /// to hold, so leaving them out made the context inferred and then unused
    /// by its own crate.
    pub carried: Carried,
}

/// R311y583 (A2) — the layer above a transport frame, as far as an observer
/// can take it.
///
/// Every arm that is not [`Carried::Batch`] names a REASON rather than
/// collapsing to an empty batch. A dissector's whole value is that "nothing
/// here" and "something here I could not read, and here is why" are different
/// answers on screen.
#[derive(Debug)]
#[cfg(feature = "codec-frame")]
pub enum Carried {
    /// The frame carries no network batch: a handshake message, a keepalive,
    /// or a frame this build's features cannot decode.
    Nothing,
    /// The batch this frame carried, walked best-effort — every record that
    /// decoded, plus where the walk stopped if it did
    /// ([`crate::network_message::parse_frame_payload_best_effort`]).
    Batch(BatchParse),
    /// The session negotiated `Compression` and lz4 refused the body. NOT an
    /// empty batch: the bytes were there and are unreadable, which is a
    /// different fact from a frame that carried nothing.
    Undecompressible,
    /// A fragment that did not complete a chain, and what the chain router
    /// made of it — including the refusals and aborts, which are exactly the
    /// events a loss-tracking view wants.
    #[cfg(feature = "reassembly")]
    Fragment(IngestOutcome),
    /// A fragment that COMPLETED a chain, and the batch reassembled out of it.
    #[cfg(feature = "reassembly")]
    Reassembled(BatchParse),
    /// A fragment arrived before this observer saw an InitAck, so the
    /// session's SN resolution is unknown and no chain can be tracked.
    ///
    /// Not a guess with a default mask: a mask that is too wide reads a
    /// wraparound as a gap and one too narrow reads a gap as a wraparound, so
    /// a defaulted verdict would look decisive and be arbitrary. The ordinary
    /// cause is a capture that started mid-session.
    #[cfg(feature = "reassembly")]
    FragmentWithoutResolution,
}

/// Why the observer cannot produce the next frame yet, or at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveStall {
    /// Not enough buffered bytes for the next prefix + payload. Push more.
    NeedMoreBytes,
    /// A length prefix asked for more than [`MAX_FRAME_PAYLOAD`]. The stream
    /// is desynchronised — for a stream-oriented capture this usually means
    /// the reader started mid-frame — and the direction is abandoned, because
    /// nothing in the framing lets it resynchronise.
    Desynchronised {
        /// Offset of the offending prefix.
        stream_offset: usize,
        /// The length it asked for.
        claimed_len: usize,
    },
}

/// Per-direction stream buffer + cursor.
#[derive(Debug, Default)]
struct DirectionStream {
    buf: Vec<u8>,
    /// Bytes already consumed and drained from `buf`, so `stream_offset`
    /// stays absolute across compactions.
    consumed: usize,
    desynchronised: bool,
}

/// The passive observer for ONE session, both directions.
///
/// Feed it bytes with [`Self::push`] and pull decoded frames with
/// [`Self::next_frame`]. It never blocks, never allocates per frame beyond the
/// decode itself, and holds only the unconsumed tail of each direction.
// No `Debug`: the chain routers hold a staging buffer per slot and
// `ReassemblyDispatcher` deliberately does not derive it either — a debug
// print of an observer mid-reassembly would dump every buffered chain.
pub struct PassiveSession {
    context: FlowContext,
    a: DirectionStream,
    b: DirectionStream,
    /// R311y583 (A2) — one chain router PER DIRECTION.
    ///
    /// A participant keys chains by peer zid because it faces many peers over
    /// one router. An observer faces exactly two half-sessions and may never
    /// learn either zid (a capture that starts mid-session has no Init), so
    /// the direction IS the peer key here and the split is structural rather
    /// than a lookup.
    ///
    /// `CAP` is advisory on the `alloc` backing this module requires
    /// ([`crate::bounded::BoundedVec`]), so the 64 KiB default costs nothing
    /// until fragments actually arrive; it is a const parameter so a
    /// constrained observer can still bound it.
    #[cfg(feature = "reassembly")]
    reasm: [ReassemblyDispatcher<PASSIVE_CHAIN_SLOTS, PASSIVE_CHAIN_CAP>; 2],
    /// R311y585 (A4) — the per-direction `id -> keyexpr` bindings, folded
    /// from every `Declare` this observer decodes.
    ///
    /// Kept HERE rather than left to the consumer for the reason A2 was
    /// written for: a context that is inferred and then unused by its own
    /// crate makes every consumer redo the same work. The Declares arrive
    /// inside the batches `carried` already decodes, so folding them is one
    /// pass over data that has been walked anyway.
    #[cfg(all(feature = "dissect", feature = "codec-declare"))]
    keyexprs: crate::passive_keyexpr::KeyexprTables,
    /// Which directions have contributed an Init. A retransmission (a capture
    /// with duplicates, a TCP retransmit the reassembler let through) must not
    /// fold twice: `&=` is idempotent but `min` on the patch level is only
    /// idempotent for the same value, and the phase transition is not.
    init_seen: [bool; 2],
}

/// Hand-written so a debug print never dumps buffered chain bytes: the chain
/// routers hold every fragment staged so far, and a consumer that derives
/// `Debug` over a `PassiveSession` (as `wz_capture::FlowDissection` does)
/// would otherwise print a capture's payloads into its own logs. The
/// occupancy gauge is what a reader actually wants there.
impl core::fmt::Debug for PassiveSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("PassiveSession");
        d.field("context", &self.context)
            .field("a", &self.a)
            .field("b", &self.b)
            .field("init_seen", &self.init_seen);
        #[cfg(feature = "reassembly")]
        d.field(
            "open_chains",
            &[self.reasm[0].active_chains(), self.reasm[1].active_chains()],
        );
        d.finish()
    }
}

// Derivable ONLY in the arm without `reassembly`, where the chain routers
// are absent; with them it initialises each from an explicit config.
#[allow(clippy::derivable_impls)]
impl Default for PassiveSession {
    fn default() -> Self {
        Self {
            context: FlowContext::default(),
            a: DirectionStream::default(),
            b: DirectionStream::default(),
            init_seen: [false; 2],
            #[cfg(all(feature = "dissect", feature = "codec-declare"))]
            keyexprs: crate::passive_keyexpr::KeyexprTables::new(),
            #[cfg(feature = "reassembly")]
            reasm: core::array::from_fn(|_| {
                // An observer cannot enforce a deadline it has no clock for
                // (see `next_frame`), so the timeout is inert here and the
                // quota is the only live defence. Markers start off and are
                // pushed in per frame from the negotiated patch level.
                ReassemblyDispatcher::new(ReassemblyConfig::new(PASSIVE_CHAIN_QUOTA, u64::MAX))
            }),
        }
    }
}

/// Concurrently-open chains one observed direction may hold. Matches the AP
/// participant's per-peer quota shape; an observer has no way to punish a
/// peer that opens chains it never finishes, so the bound is the defence.
#[cfg(feature = "reassembly")]
const PASSIVE_CHAIN_QUOTA: u16 = 4;

/// Chain slots per direction.
///
/// Not const parameters on [`PassiveSession`]: a struct's const-param DEFAULT
/// does not participate in inference, so `PassiveSession::new()` would fail to
/// resolve at every call site and every consumer would have to spell the two
/// numbers out. The passive path already requires `alloc`, so it is a host
/// shape and a second, constrained instantiation would have no user.
#[cfg(feature = "reassembly")]
pub const PASSIVE_CHAIN_SLOTS: usize = 4;

/// Reassembled-message ceiling per chain. Advisory on the `alloc` backing
/// ([`crate::bounded::BoundedVec`]), so it costs nothing until fragments
/// arrive; it still bounds what a corrupt or hostile chain can accumulate.
#[cfg(feature = "reassembly")]
pub const PASSIVE_CHAIN_CAP: usize = 65_536;

impl PassiveSession {
    /// A fresh observer with no bytes and no inferred context.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current inferred context. Read it BESIDE a frame rather than after
    /// a batch: [`PassiveFrame::context`] carries the value as of that frame,
    /// and this one moves.
    pub fn context(&self) -> FlowContext {
        self.context
    }

    /// Append raw stream bytes for one direction, in order. The caller (G1's
    /// capture layer, or a test) owns ordering and de-duplication; this is a
    /// byte sink, not a TCP reassembler.
    pub fn push(&mut self, direction: Direction, bytes: &[u8]) {
        self.stream_mut(direction).buf.extend_from_slice(bytes);
    }

    /// Decode the next complete frame in `direction`, or say why not.
    ///
    /// Each call re-reads [`FlowContext::prefix_width`], so a session that
    /// reframes to the 4-byte prefix at Established is followed across the
    /// boundary without the caller doing anything.
    pub fn next_frame(&mut self, direction: Direction) -> Result<PassiveFrame, PassiveStall> {
        let width = self.context.prefix_width();
        let stream = self.stream_mut(direction);
        if stream.desynchronised {
            return Err(PassiveStall::NeedMoreBytes);
        }
        if stream.buf.len() < width {
            return Err(PassiveStall::NeedMoreBytes);
        }
        let payload_len = match width {
            PREFIX_WIDTH_LOWLATENCY => {
                u32::from_le_bytes([stream.buf[0], stream.buf[1], stream.buf[2], stream.buf[3]])
                    as usize
            }
            _ => u16::from_le_bytes([stream.buf[0], stream.buf[1]]) as usize,
        };
        let stream_offset = stream.consumed;
        if payload_len > MAX_FRAME_PAYLOAD {
            stream.desynchronised = true;
            return Err(PassiveStall::Desynchronised {
                stream_offset,
                claimed_len: payload_len,
            });
        }
        if stream.buf.len() < width + payload_len {
            return Err(PassiveStall::NeedMoreBytes);
        }
        let body: Vec<u8> = stream.buf[width..width + payload_len].to_vec();
        stream.buf.drain(..width + payload_len);
        stream.consumed += width + payload_len;

        let frame = parse_inbound(&body);
        if let Ok(ref f) = frame {
            self.fold(direction, f);
        }
        let carried = self.decode_carried(direction, &frame);
        Ok(PassiveFrame {
            direction,
            stream_offset,
            prefix_width: width,
            frame,
            context: self.context,
            carried,
        })
    }

    /// R311y585 (A4) — the key-expression bindings observed so far.
    ///
    /// Read it to turn a decoded message's numeric `WireExpr` into a path:
    /// `tables.resolve(frame.direction, &push.keyexpr)`. The direction must
    /// be the one the MESSAGE travelled, because the wire expression's `M`
    /// bit is read relative to its sender.
    #[cfg(all(feature = "dissect", feature = "codec-declare"))]
    pub fn keyexprs(&self) -> &crate::passive_keyexpr::KeyexprTables {
        &self.keyexprs
    }

    /// Fold every `Declare` in a freshly-walked batch into the tables.
    #[cfg(all(feature = "dissect", feature = "codec-declare"))]
    fn fold_keyexprs(&mut self, direction: Direction, batch: &BatchParse) {
        for m in &batch.messages {
            if let crate::network_message::NetworkMessage::Declare(d) = m {
                self.keyexprs.observe_declare(direction, d);
            }
        }
    }

    /// R311y584 (A3) — decode ONE datagram, which is one whole wire message.
    ///
    /// The datagram sibling of [`Self::next_frame`], and a separate entry
    /// point rather than a flag on that one, because the FRAMING differs and
    /// nothing else does. A datagram link carries no length prefix at all —
    /// UDP preserves message boundaries, so one datagram is exactly one wire
    /// message (`wz-runtime-tokio/src/udp_pipeline.rs:34-36`) — which means
    /// there is no buffer to append to, no boundary to search for, and no
    /// desynchronisation to recover from. Everything ABOVE the framing is
    /// shared: the same fold, the same negotiated context, the same
    /// [`Carried`] decode.
    ///
    /// `offset` is whatever coordinate the caller wants the frame reported
    /// against — a packet index, a byte offset into a file. This layer never
    /// interprets it, because for a datagram there is no stream for it to be
    /// an offset INTO.
    ///
    /// Infallible in the [`PassiveStall`] sense: a datagram is either
    /// decodable or not, and "not" arrives as an `Err` inside
    /// [`PassiveFrame::frame`] rather than as a reason to wait for more bytes.
    pub fn next_datagram(
        &mut self,
        direction: Direction,
        bytes: &[u8],
        offset: usize,
    ) -> PassiveFrame {
        let frame = parse_inbound(bytes);
        if let Ok(ref f) = frame {
            self.fold(direction, f);
        }
        let carried = self.decode_carried(direction, &frame);
        PassiveFrame {
            direction,
            stream_offset: offset,
            // Recorded as zero rather than as one of the two stream widths:
            // a datagram has no prefix, and reporting 2 here would be a
            // measurement of nothing.
            prefix_width: 0,
            frame,
            context: self.context,
            carried,
        }
    }

    /// R311y583 (A2) — take one decoded transport frame the rest of the way.
    ///
    /// Runs AFTER [`Self::fold`], so the context this reads is the one in
    /// force for this frame rather than the one before it. That ordering is
    /// load-bearing in exactly one place and it is a real capture: the Open
    /// that establishes a compressed session is itself uncompressed, and the
    /// first frame after it is not.
    #[cfg(feature = "codec-frame")]
    fn decode_carried(
        &mut self,
        direction: Direction,
        frame: &Result<InboundFrame, InboundParseError>,
    ) -> Carried {
        // `direction` selects a chain router, and there are none without
        // `reassembly`.
        #[cfg(not(feature = "reassembly"))]
        let _ = direction;
        let Ok(f) = frame else {
            return Carried::Nothing;
        };
        match f {
            InboundFrame::Frame { payload, .. } => match self.batch_of(payload) {
                Some(b) => {
                    #[cfg(all(feature = "dissect", feature = "codec-declare"))]
                    self.fold_keyexprs(direction, &b);
                    Carried::Batch(b)
                }
                None => Carried::Undecompressible,
            },
            #[cfg(feature = "reassembly")]
            InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                priority,
                markers,
                ..
            } => {
                let Some(sn_mask) = self.context.sn_mask() else {
                    return Carried::FragmentWithoutResolution;
                };
                let markers_on = self.context.fragmentation_markers();
                let idx = usize::from(direction == Direction::B);
                let router = &mut self.reasm[idx];
                router.set_fragmentation_markers(markers_on);
                let mut joined: Option<Vec<u8>> = None;
                // The peer key is the DIRECTION, one byte, because an observer
                // holds one router per half-session (see the field docs).
                let key = [idx as u8];
                let outcome = router.ingest(
                    ReasmFragment {
                        peer_key: &key,
                        reliable: *reliable,
                        sn: *sn,
                        more: u8::from(*more),
                        payload,
                        priority: *priority,
                        markers: *markers,
                    },
                    sn_mask,
                    // An observer has no monotonic clock — a capture's
                    // timestamps are the CAPTURE's, not this session's, and a
                    // replayed file has none at all. The config's window is
                    // `u64::MAX` for the same reason, so this instant only
                    // ever arms a deadline nothing sweeps; the per-direction
                    // quota is what bounds a chain that never completes.
                    0,
                    |bytes| joined = Some(bytes.to_vec()),
                );
                match joined {
                    Some(bytes) => match self.batch_of(&bytes) {
                        Some(b) => {
                            #[cfg(all(feature = "dissect", feature = "codec-declare"))]
                            self.fold_keyexprs(direction, &b);
                            Carried::Reassembled(b)
                        }
                        None => Carried::Undecompressible,
                    },
                    None => Carried::Fragment(outcome),
                }
            }
            _ => Carried::Nothing,
        }
    }

    /// Decompress if the session negotiated it, then walk the batch.
    ///
    /// `None` means the body was lz4-wrapped and would not decompress. The
    /// ceiling passed to [`crate::compression::decompress_batch`] is the same
    /// [`MAX_FRAME_PAYLOAD`] that bounds an untrusted length prefix, so a
    /// corrupt block cannot ask this observer for an arbitrary allocation.
    #[cfg(feature = "codec-frame")]
    fn batch_of(&self, body: &[u8]) -> Option<BatchParse> {
        if self.context.compression_active() {
            // A build WITHOUT `transport-compression` reports the same
            // absence, and that is the honest answer rather than a bug: the
            // bytes are lz4 and this observer cannot read them. Saying so
            // beats handing the caller a batch parsed out of compressed
            // bytes, which decodes to confident nonsense.
            #[cfg(not(feature = "transport-compression"))]
            return None;
            #[cfg(feature = "transport-compression")]
            {
                let plain = crate::compression::decompress_batch(body, MAX_FRAME_PAYLOAD)?;
                return Some(parse_frame_payload_best_effort(&plain));
            }
        }
        Some(parse_frame_payload_best_effort(body))
    }

    /// Advance the observed context by one decoded frame.
    ///
    /// Init folds the capabilities (once per direction). Open advances to
    /// Established — and only from `InitComplete`, so a capture that starts
    /// mid-session and sees an Open with no Inits does NOT claim a
    /// negotiation it never observed. Close ends the session.
    fn fold(&mut self, direction: Direction, frame: &InboundFrame) {
        match frame {
            InboundFrame::Init {
                is_ack,
                body,
                extensions,
                ..
            } => {
                let idx = usize::from(direction == Direction::B);
                if self.init_seen[idx] {
                    return;
                }
                self.init_seen[idx] = true;
                self.context.fold_init(extensions);
                // R311y583 (A5) — the ACK's size parameters ARE the session's.
                // See `FlowContext::caps` for why this is an assignment and
                // not a fold.
                if *is_ack {
                    self.context.caps =
                        Some(PeerInitCaps::from_init_body(body.sn_res, body.batch_size));
                }
                self.context.phase = if self.init_seen[0] && self.init_seen[1] {
                    SessionPhase::InitComplete
                } else {
                    SessionPhase::HalfInit
                };
            }
            InboundFrame::Open { .. } => {
                if self.context.phase == SessionPhase::InitComplete {
                    self.context.phase = SessionPhase::Established;
                }
            }
            InboundFrame::Close { .. } => {
                self.context.phase = SessionPhase::Closed;
            }
            _ => {}
        }
    }

    fn stream_mut(&mut self, direction: Direction) -> &mut DirectionStream {
        match direction {
            Direction::A => &mut self.a,
            Direction::B => &mut self.b,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Frame `body` the way a stream link would, at `width` bytes of LE
    /// length prefix.
    fn framed(body: &[u8], width: usize) -> Vec<u8> {
        let mut out = Vec::new();
        match width {
            PREFIX_WIDTH_LOWLATENCY => out.extend_from_slice(&(body.len() as u32).to_le_bytes()),
            _ => out.extend_from_slice(&(body.len() as u16).to_le_bytes()),
        }
        out.extend_from_slice(body);
        out
    }

    /// A minimal Init wire: header `T_MID_INIT` with the Z bit, an InitBody,
    /// then the ext chain the caller supplies. Built through the production
    /// encoders so the fixture cannot drift from what wz emits.
    fn init_wire(is_ack: bool, exts: Vec<ExtEntryOwned>) -> Vec<u8> {
        let mut flags = 0u8;
        if is_ack {
            flags |= wz_codecs::wire_const::FLAG_T_INIT_A;
        }
        if !exts.is_empty() {
            flags |= wz_codecs::wire_const::FLAG_T_Z;
        }
        let mut wire = vec![flags | wz_codecs::wire_const::T_MID_INIT];
        let body = wz_codecs::init_body::InitBody {
            version: 0x09,
            // `cbyte` = `whatami.to_wire() | ((zid_len - 1) << 4)`
            // (`handshake_encode::init_cbyte`): Peer (0x01) with a 4-byte
            // zid is `0x01 | (3 << 4)` = `0x31`. Getting this wrong makes
            // the decoder read the wrong zid width, which is why it is
            // spelled out rather than guessed.
            cbyte: 0x31,
            zid: &[0xAA; 4],
            sn_res: None,
            batch_size: None,
            // The cookie is A-gated on Init: an InitAck carries it, an
            // InitSyn does not (`out/wz-codecs/init_body.rs:103-112`). The
            // fixture keeps it empty; presence, not content, is what the
            // decoder's field walk depends on.
            cookie_len: if is_ack { Some(0) } else { None },
            cookie: if is_ack { Some(&[]) } else { None },
        };
        // `encode(sink, s, a)`: the S (resolution present) and A (is-ack)
        // discriminators ride the parent header, so the codec takes them.
        wire.extend_from_slice(&body.encode_to_vec(0, u8::from(is_ack)));
        if !exts.is_empty() {
            wire.extend_from_slice(&crate::ext_chain::encode_ext_chain(&exts));
        }
        wire
    }

    /// R311y583 (A2) — a `T_MID_FRAME` carrying `payload` as its batch.
    fn frame_wire(sn: u64, payload: &[u8]) -> Vec<u8> {
        let mut wire =
            vec![wz_codecs::wire_const::T_MID_FRAME | wz_codecs::wire_const::FLAG_T_FRAME_R];
        crate::vle::encode_vle_u64_into(&mut wire, sn);
        wire.extend_from_slice(payload);
        wire
    }

    /// One `T_MID_FRAGMENT`. `more` set means the chain continues.
    #[cfg(feature = "reassembly")]
    fn fragment_wire(sn: u64, more: bool, payload: &[u8]) -> Vec<u8> {
        let mut flags = wz_codecs::wire_const::FLAG_T_FRAGMENT_R;
        if more {
            flags |= wz_codecs::wire_const::FLAG_T_FRAGMENT_M;
        }
        let mut wire = vec![wz_codecs::wire_const::T_MID_FRAGMENT | flags];
        crate::vle::encode_vle_u64_into(&mut wire, sn);
        wire.extend_from_slice(payload);
        wire
    }

    /// One encoded OAM record — a real network message through the real
    /// encoder, so the batch fixture cannot drift from what wz emits.
    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::oam::Oam {
            id,
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// Drive a session to Established so the post-handshake contracts are in
    /// force, and return it. `exts` rides BOTH Inits, which is what makes a
    /// capability negotiated rather than merely offered.
    fn established(exts: Vec<ExtEntryOwned>) -> PassiveSession {
        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&init_wire(false, exts.clone()), 2));
        s.push(Direction::B, &framed(&init_wire(true, exts), 2));
        s.next_frame(Direction::A).expect("init syn");
        s.next_frame(Direction::B).expect("init ack");
        s.push(Direction::A, &framed(&open_wire(false), 2));
        s.push(Direction::B, &framed(&open_wire(true), 2));
        s.next_frame(Direction::A).expect("open syn");
        s.next_frame(Direction::B).expect("open ack");
        assert_eq!(s.context().phase, SessionPhase::Established);
        s
    }

    fn open_wire(is_ack: bool) -> Vec<u8> {
        let mut flags = 0u8;
        if is_ack {
            flags |= wz_codecs::wire_const::FLAG_T_OPEN_A;
        }
        let mut wire = vec![flags | wz_codecs::wire_const::T_MID_OPEN];
        wire.extend_from_slice(
            &wz_codecs::open_body::OpenBody {
                lease: 10_000,
                initial_sn: 0,
                // INVERTED against Init: on Open the cookie rides the SYN
                // (`a == 0`), not the ACK (`out/wz-codecs/open_body.rs:67-79`).
                cookie_len: if is_ack { None } else { Some(0) },
                cookie: if is_ack { None } else { Some(&[]) },
            }
            .encode_to_vec(u8::from(is_ack)),
        );
        wire
    }

    fn unit_ext(id: u8) -> ExtEntryOwned {
        ExtEntryOwned {
            header: id,
            body: wz_codecs::ext_entry::ExtEntryOwnedVariant::CodecZenohExtUnit(
                wz_codecs::ext_unit::ExtUnit::default(),
            ),
        }
    }

    /// THE reframing case, which no wz-to-wz fixture reaches: a session that
    /// negotiates `LowLatency` on both Inits switches its stream prefix from
    /// 2 bytes to 4 AT ESTABLISHED — not at Init.
    ///
    /// The assertion is that the SAME observer reads the handshake at width 2
    /// and the post-Open frame at width 4 without being told. An observer that
    /// flipped at Init would mis-frame the Open; one that never flipped would
    /// mis-frame everything after it.
    #[test]
    fn a_lowlatency_session_reframes_at_established_and_not_before() {
        let ll = || vec![unit_ext(est_ext::LOWLATENCY)];
        let mut s = PassiveSession::new();

        // Handshake: 2-byte prefixes on both sides.
        s.push(Direction::A, &framed(&init_wire(false, ll()), 2));
        s.push(Direction::B, &framed(&init_wire(true, ll()), 2));
        s.push(Direction::A, &framed(&open_wire(false), 2));

        let f = s.next_frame(Direction::A).expect("InitSyn");
        assert!(matches!(f.frame, Ok(InboundFrame::Init { .. })));
        assert_eq!(f.prefix_width, PREFIX_WIDTH_UNIVERSAL);
        assert_eq!(f.context.phase, SessionPhase::HalfInit);

        let f = s.next_frame(Direction::B).expect("InitAck");
        assert_eq!(f.context.phase, SessionPhase::InitComplete);
        assert!(f.context.lowlatency, "both sides offered 0x5");
        assert!(
            !f.context.lowlatency_active(),
            "negotiated is not yet IN FORCE — the Open still rides the 2-byte prefix"
        );
        assert_eq!(f.context.prefix_width(), PREFIX_WIDTH_UNIVERSAL);

        let f = s.next_frame(Direction::A).expect("OpenSyn");
        assert_eq!(
            f.prefix_width, PREFIX_WIDTH_UNIVERSAL,
            "the Open itself was framed under the OLD width"
        );
        assert_eq!(f.context.phase, SessionPhase::Established);
        assert!(f.context.lowlatency_active(), "in force from here");

        // From here the wire is 4-byte prefixed. A KeepAlive is the smallest
        // post-establishment frame that decodes.
        let ka = vec![wz_codecs::wire_const::T_MID_KEEP_ALIVE];
        s.push(Direction::A, &framed(&ka, 4));
        let f = s
            .next_frame(Direction::A)
            .expect("post-establishment frame");
        assert_eq!(
            f.prefix_width, PREFIX_WIDTH_LOWLATENCY,
            "the observer followed the reframing with no caller involvement"
        );
        assert!(f.frame.is_ok(), "and the body still decodes: {:?}", f.frame);
    }

    /// The negative arm: without the `0x5` offer on BOTH sides the width never
    /// moves. One-sided offers are the interesting half — `&=` must reject
    /// them.
    #[test]
    fn one_sided_lowlatency_never_reframes() {
        for (a, b) in [
            (vec![unit_ext(est_ext::LOWLATENCY)], vec![]),
            (vec![], vec![unit_ext(est_ext::LOWLATENCY)]),
            (vec![], vec![]),
        ] {
            let mut s = PassiveSession::new();
            s.push(Direction::A, &framed(&init_wire(false, a), 2));
            s.push(Direction::B, &framed(&init_wire(true, b), 2));
            s.push(Direction::A, &framed(&open_wire(false), 2));
            for dir in [Direction::A, Direction::B, Direction::A] {
                let _ = s.next_frame(dir);
            }
            let ctx = s.context();
            assert_eq!(ctx.phase, SessionPhase::Established);
            assert!(!ctx.lowlatency, "an AND over a missing offer is false");
            assert_eq!(ctx.prefix_width(), PREFIX_WIDTH_UNIVERSAL);
        }
    }

    /// A reader that attaches AFTER the handshake sees an Open with no Inits.
    /// It must not claim a negotiation — the `Open` -> Established transition
    /// is guarded on having actually observed both Inits, so a mid-session
    /// attach stays honest about what it does not know.
    #[test]
    fn a_mid_session_attach_does_not_invent_a_negotiation() {
        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&open_wire(false), 2));
        let f = s.next_frame(Direction::A).expect("the Open decodes");
        assert!(
            matches!(f.frame, Ok(InboundFrame::Open { .. })),
            "got {:?}",
            f.frame
        );
        let ctx = s.context();
        assert_eq!(
            ctx.phase,
            SessionPhase::Unseen,
            "an Open without Inits does not establish anything the observer knows"
        );
        assert!(!ctx.negotiated());
        assert_eq!(ctx.patch, None);
        assert!(!ctx.fragmentation_markers());
    }

    /// A retransmitted Init in the SAME direction must not be folded twice.
    /// `&=` is idempotent, but the phase transition is not: a second fold of
    /// direction A would read as "both sides seen" and declare a negotiation
    /// off one peer.
    #[test]
    fn a_repeated_init_on_one_direction_does_not_complete_the_fold() {
        let mut s = PassiveSession::new();
        let wire = framed(&init_wire(false, vec![]), 2);
        s.push(Direction::A, &wire);
        s.push(Direction::A, &wire);
        let _ = s.next_frame(Direction::A);
        let _ = s.next_frame(Direction::A);
        assert_eq!(s.context().phase, SessionPhase::HalfInit);
        assert!(!s.context().negotiated());
    }

    /// The oversize-prefix guard, exercised on the ONLY path that can reach
    /// it. A 2-byte prefix cannot exceed [`MAX_FRAME_PAYLOAD`] by
    /// construction — its type is the cap — so the guard is reachable only
    /// once a lowlatency session has reframed to the untrusted 4-byte `u32`.
    /// Testing it on a `u16` stream would have asserted nothing while reading
    /// as though it had.
    ///
    /// The direction is then ABANDONED, not retried: nothing in the framing
    /// lets a reader that started mid-frame resynchronise, so the honest
    /// answer is to say so once and stop.
    #[test]
    fn an_oversize_prefix_desynchronises_instead_of_allocating() {
        let ll = || vec![unit_ext(est_ext::LOWLATENCY)];
        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&init_wire(false, ll()), 2));
        s.push(Direction::B, &framed(&init_wire(true, ll()), 2));
        s.push(Direction::A, &framed(&open_wire(false), 2));
        for dir in [Direction::A, Direction::B, Direction::A] {
            s.next_frame(dir).expect("handshake decodes");
        }
        assert_eq!(s.context().prefix_width(), PREFIX_WIDTH_LOWLATENCY);

        // 0x00FF_FFFF = 16 MiB, well past the batch ceiling.
        s.push(Direction::A, &[0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::Desynchronised {
                // The two frames already consumed on A: its Init and its Open.
                stream_offset: framed(&init_wire(false, ll()), 2).len()
                    + framed(&open_wire(false), 2).len(),
                claimed_len: 0x00FF_FFFF,
            }),
            "the guard fires with the offending offset and the length it asked for"
        );
        // Abandoned: more bytes do not revive the direction.
        s.push(
            Direction::A,
            &framed(&[wz_codecs::wire_const::T_MID_KEEP_ALIVE], 4),
        );
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes),
            "a desynchronised direction stays abandoned"
        );
        // ...and the OTHER direction is untouched: desync is per-stream.
        s.push(
            Direction::B,
            &framed(&[wz_codecs::wire_const::T_MID_KEEP_ALIVE], 4),
        );
        assert!(
            s.next_frame(Direction::B).is_ok(),
            "the peer direction still decodes"
        );
    }

    /// Partial bytes stall rather than mis-decode, and the stall clears when
    /// the rest arrives — the property a streaming capture depends on.
    #[test]
    fn a_split_frame_stalls_then_completes() {
        let wire = framed(&init_wire(false, vec![]), 2);
        let mut s = PassiveSession::new();
        s.push(Direction::A, &wire[..1]);
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes)
        );
        s.push(Direction::A, &wire[1..wire.len() - 1]);
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes),
            "one byte short is still short"
        );
        s.push(Direction::A, &wire[wire.len() - 1..]);
        let f = s.next_frame(Direction::A).expect("now complete");
        assert!(matches!(f.frame, Ok(InboundFrame::Init { .. })));
        assert_eq!(f.stream_offset, 0);
    }

    /// `stream_offset` is ABSOLUTE within the direction, so a capture-side
    /// layer can map a decoded frame back to the byte that carried it. It must
    /// keep counting across consumed frames, not restart per frame.
    #[test]
    fn stream_offsets_are_absolute_within_a_direction() {
        let first = framed(&init_wire(false, vec![]), 2);
        let second = framed(&open_wire(false), 2);
        let mut s = PassiveSession::new();
        s.push(Direction::A, &first);
        s.push(Direction::A, &second);
        let a = s.next_frame(Direction::A).expect("first");
        let b = s.next_frame(Direction::A).expect("second");
        assert_eq!(a.stream_offset, 0);
        assert_eq!(
            b.stream_offset,
            first.len(),
            "the second frame's offset is the first frame's total wire length"
        );
    }

    /// R311y583 (A2) — the layer the tracker used to stop short of. Before
    /// this, `carried` did not exist and every consumer walked the batch
    /// itself.
    #[test]
    fn a_frame_carries_its_batch_decoded() {
        let mut s = established(vec![]);
        let mut batch = oam_record(7);
        batch.extend_from_slice(&oam_record(8));
        s.push(Direction::A, &framed(&frame_wire(0, &batch), 2));

        let f = s.next_frame(Direction::A).expect("frame");
        match f.carried {
            Carried::Batch(b) => {
                assert!(b.is_complete(), "clean batch must not halt: {:?}", b.halt);
                assert_eq!(b.messages.len(), 2);
            }
            other => panic!("expected a decoded batch, got {other:?}"),
        }
    }

    /// A frame is not the only thing on the wire, and the handshake messages
    /// must NOT acquire a phantom empty batch — "carried nothing" and
    /// "carried an empty batch" are different facts.
    #[test]
    fn handshake_frames_carry_nothing() {
        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&init_wire(false, vec![]), 2));
        let f = s.next_frame(Direction::A).expect("init");
        assert!(matches!(f.carried, Carried::Nothing));
    }

    /// A chain across two fragments: the first opens it, the second completes
    /// it and the reassembled bytes are walked as a batch. This is the whole
    /// of the fragment half of A2 — a consumer previously got two opaque
    /// Fragment frames and had to run a dispatcher itself.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_chain_reassembles_into_a_batch() {
        let mut s = established(vec![]);
        // Split ONE OAM record down the middle, so the halves are individually
        // undecodable and only the join can produce a message. A fixture split
        // on a record boundary would pass even if the join never happened.
        let record = oam_record(9);
        let (head, tail) = record.split_at(1);

        s.push(Direction::A, &framed(&fragment_wire(0, true, head), 2));
        let first = s.next_frame(Direction::A).expect("fragment 1");
        assert!(
            matches!(first.carried, Carried::Fragment(IngestOutcome::Begun)),
            "expected a chain start, got {:?}",
            first.carried
        );

        s.push(Direction::A, &framed(&fragment_wire(1, false, tail), 2));
        let last = s.next_frame(Direction::A).expect("fragment 2");
        match last.carried {
            Carried::Reassembled(b) => {
                assert!(b.is_complete(), "reassembled batch halted: {:?}", b.halt);
                assert_eq!(b.messages.len(), 1);
            }
            other => panic!("expected a reassembled batch, got {other:?}"),
        }
    }

    /// A capture that starts mid-session has no InitAck, so the SN resolution
    /// is unknown and the observer says so instead of picking a mask. A
    /// defaulted mask reads a wraparound as a gap or the reverse, and either
    /// verdict would look decisive.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_without_an_observed_initack_is_named_not_guessed() {
        let mut s = PassiveSession::new();
        assert_eq!(s.context().sn_mask(), None);
        s.push(Direction::A, &framed(&fragment_wire(0, true, b"x"), 2));
        let f = s.next_frame(Direction::A).expect("fragment");
        assert!(
            matches!(f.carried, Carried::FragmentWithoutResolution),
            "got {:?}",
            f.carried
        );
    }

    /// R311y583 (A5) — the InitAck's size parameters ARE the session's, and
    /// the observer reads them off the ACK rather than folding both Inits.
    #[test]
    fn the_initack_supplies_the_size_parameters() {
        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&init_wire(false, vec![]), 2));
        s.next_frame(Direction::A).expect("syn");
        assert!(
            s.context().caps.is_none(),
            "a SYN alone must not settle the size parameters"
        );
        s.push(Direction::B, &framed(&init_wire(true, vec![]), 2));
        s.next_frame(Direction::B).expect("ack");
        let caps = s.context().caps.expect("the ACK settles them");
        // The fixture sends no S-bit fields, so these are the wire defaults
        // `decode_wire_caps` applies, not values this test invented.
        assert_eq!(caps.seq_num_res, 2);
        assert_eq!(caps.batch_size, 65535);
        assert_eq!(s.context().sn_mask(), Some(crate::sn::mask_from_res(2)));
    }

    /// R311y585 (A4) — the tables are FOLDED by the observer, not merely
    /// available to it. Without this leg `KeyexprTables` would be a library
    /// with no caller, which is the exact criticism A2 was written for.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn a_declare_inside_a_frame_populates_the_keyexpr_tables() {
        use crate::passive_keyexpr::Resolved;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;

        let path = "demo/robots/";
        let keyexpr = WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(path.len() as u64),
                suffix: Some(sce_forge_runtime::codec::SceString::from_view(path).expect("fits")),
            }),
        };
        // The headers carry the wire MIDs, and `Default` is what bakes them
        // (`out/wz-codecs/declare.rs` variant-default-uniformity). Writing 0
        // here is what the first version of this fixture did: the batch still
        // decoded, as an `Unknown` record, and the table stayed empty — which
        // is why the batch assertion below counts the messages instead of
        // merely matching the arm.
        let declare: wz_codecs::declare::DeclareOwned = wz_codecs::declare::DeclareOwned {
            // The MID ALONE: `Default`'s header also carries flags (I / Z),
            // and announcing an ext chain that `extensions: None` then does
            // not write leaves the decoder reading the next record's bytes as
            // a chain. Masking to the MID is what makes this one record.
            header: wz_codecs::declare::Declare::default().header & 0x1F,
            interest_id: None,
            extensions: None,
            body: wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexprOwned {
                    // N (`0x20`) announces the wireexpr's SUFFIX. The parent header
                    // carries it, not the wireexpr, so leaving it clear makes
                    // the encoder write the id and DROP the suffix — which the
                    // first version of this fixture did, and the trailing
                    // "demo/robots/" bytes then decoded as a second, Unknown
                    // record.
                    header: wz_codecs::decl_kexpr::DeclKexpr::default().header | 0x20,
                    id: 42,
                    keyexpr,
                },
            ),
        };
        // Through the real encoder, so the fixture is a batch wz could have
        // emitted rather than a byte string that happens to parse.
        let record = declare
            .try_as_borrowed()
            .expect("owned -> borrowed")
            .encode_to_vec();

        let mut s = established(vec![]);
        assert!(s.keyexprs().is_empty(Direction::A));
        s.push(Direction::A, &framed(&frame_wire(0, &record), 2));
        let f = s.next_frame(Direction::A).expect("frame");
        match &f.carried {
            Carried::Batch(b) => assert_eq!(
                b.messages.len(),
                1,
                "the Declare must decode as exactly one record: {:?}",
                b.halt
            ),
            other => panic!("expected a batch, got {other:?}"),
        }

        assert_eq!(s.keyexprs().len(Direction::A), 1);
        // A later Push from the SAME direction, local-rooted on that id.
        let later = WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 42,
                suffix_len: Some(6),
                suffix: Some(
                    sce_forge_runtime::codec::SceString::from_view("1/pose").expect("fits"),
                ),
            }),
        };
        assert_eq!(
            s.keyexprs().resolve(Direction::A, &later),
            Resolved::Literal(alloc::string::String::from("demo/robots/1/pose"))
        );
    }
}
