// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use crate::chain_loss::ChainLoss;
use crate::ext_header::{establishment_ext_id as est_ext, ext_eid};
use crate::inbound::{parse_inbound_consuming, InboundFrame};
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

    /// R311y585 (A5) — the batch ceiling the acceptor agreed to, `None` until
    /// an InitAck has been observed.
    pub fn batch_size(&self) -> Option<u16> {
        self.caps.map(|c| c.batch_size)
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

/// R2206 (open-debt item 561) — WHICH COORDINATE [`PassiveFrame::stream_offset`]
/// is in, said by the caller that chose it.
///
/// # Why the number cannot say this for itself
///
/// `stream_offset` has carried two meanings since the datagram path was added:
/// a byte offset into one direction's reassembled stream, and an INDEX handed
/// in by a caller that has no stream — [`PassiveSession::next_datagram_on`]
/// takes the coordinate as an argument precisely because a datagram link has no
/// byte position of its own. They are small integers either way and cannot be
/// told apart by looking, which is the whole reason the capture layer publishes
/// an `anchor_space` beside the anchor.
///
/// It published it from a SECOND place: a match over the message lists,
/// written by hand, with nothing joining it to the caller that actually chose
/// the number. Item 561 is what that cost — the serial line feeds
/// `next_datagram_on` with a capture PACKET INDEX and was labelled
/// `StreamBytes`, so a consumer told to switch on the field was told the wrong
/// thing, in exactly the field that exists to stop it guessing.
///
/// So the discriminant travels WITH the number, set where the number is chosen.
/// There is one place that constructs a [`PassiveFrame`] and two callers that
/// hand it a coordinate; each of the two says which space it is in, and no
/// layer above gets a second opinion to keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OffsetSpace {
    /// An INDEX the caller supplied — a capture packet's position, counting
    /// from zero. Global to the capture, so two such anchors are comparable
    /// across lists. It must not be added to a byte span.
    PacketIndex,
    /// A byte offset within one direction of this flow's stream, counted from
    /// the first byte the observer was given. Absolute only within that
    /// direction of that list.
    StreamBytes,
}

/// R2206 (open-debt item 561) — A COORDINATE AND THE SPACE IT IS IN, together,
/// because separately is how item 561 happened.
///
/// The two were separate for as long as the datagram path existed: a caller
/// handed in a `usize` and something else, one crate away, decided what kind of
/// number it had been. This type is the seam where that stops — the observer's
/// framing walk takes ONE argument for the anchor, so a caller cannot supply
/// the number and leave the space to be guessed later.
///
/// [`PassiveFrame`] still carries the two as separate fields. That is not an
/// inconsistency: dozens of readers index `stream_offset` and folding it into a
/// struct would be a churn with no invariant behind it — the invariant is about
/// what a PRODUCER may leave unsaid, and a produced frame has already said it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// The number: a byte offset or an index, per [`Self::space`].
    pub offset: usize,
    /// Which of the two [`Self::offset`] is.
    pub space: OffsetSpace,
}

impl Anchor {
    /// A byte offset within one direction of a stream.
    pub const fn bytes(offset: usize) -> Self {
        Self {
            offset,
            space: OffsetSpace::StreamBytes,
        }
    }

    /// An index the caller supplied — a capture packet's position.
    pub const fn packet(index: usize) -> Self {
        Self {
            offset: index,
            space: OffsetSpace::PacketIndex,
        }
    }
}

/// One decoded transport message plus where it sat in its direction's stream.
#[derive(Debug)]
pub struct PassiveFrame {
    /// The direction this frame travelled.
    pub direction: Direction,
    /// Byte offset of the frame's LENGTH PREFIX within that direction's
    /// stream, counted from the first byte the observer was given. The anchor
    /// a capture-side layer (G1) maps back to a packet.
    ///
    /// ⚠ R2206 — OR AN INDEX. Read it according to [`Self::offset_space`],
    /// which is on this struct for the reason that field's own doc gives.
    pub stream_offset: usize,
    /// R2206 (open-debt item 561) — which coordinate [`Self::stream_offset`] is
    /// in, from the caller that chose it. See [`OffsetSpace`].
    pub offset_space: OffsetSpace,
    /// R311y631 (§1.2b) — position of this message WITHIN its framing unit,
    /// counted from zero.
    ///
    /// [`Self::stream_offset`] names the framing unit and stops there: on a
    /// datagram link it is a packet index, so every message batched into one
    /// packet carries the same value. That was unambiguous only while a framing
    /// unit held exactly one message, which is not what either reference
    /// implementation does — both walk the unit to its end
    /// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`,
    /// `vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`). This is the
    /// second coordinate that keeps two messages of one batch distinguishable.
    ///
    /// A separate field rather than a finer `stream_offset`, because the two
    /// answer different questions and one of them is already load-bearing: a
    /// capture-side layer maps `stream_offset` back to a packet
    /// (`wz-capture`'s run map), and moving it to name a byte inside the unit
    /// would silently change what every existing consumer of that anchor
    /// resolves.
    pub batch_index: usize,
    /// R311y645 (§1.1n / §4.37) — byte offset of this transport message within
    /// its framing unit, counted from zero.
    ///
    /// [`Self::batch_index`] beside it is the ORDINAL of the same message, and
    /// the two come apart the moment a unit's messages differ in length: the
    /// second message of every unit has ordinal `1` and a different offset in
    /// each. R311y641 computed this coordinate at the record layer and
    /// deliberately did NOT keep the transport one, because at that point
    /// nothing consumed it and a second coordinate with no consumer is the
    /// defect R311y639 closed elsewhere.
    ///
    /// What made it worth keeping is [`Self::batch_base`]: without this, a
    /// record's offset can only be stated against the payload it happened to
    /// sit in, and "at the front of the payload" was being read as "at the
    /// front of the unit".
    pub unit_offset: usize,
    /// R311y645 (§1.1n / §4.37) — where the bytes behind [`Carried::Batch`]
    /// begin within THIS MESSAGE, or `None` when those bytes were never on the
    /// wire in that form.
    ///
    /// Message-relative and not unit-relative, so that each of these two fields
    /// states ONE measured fact rather than a sum: this is the width of the
    /// header, the sn and the ext chain ahead of the payload, and
    /// [`Self::unit_offset`] is where the message itself stands. A consumer
    /// wanting a record's place in the unit adds them (`wz-capture`'s
    /// `agg::record_unit_offset` is that one door).
    ///
    /// `None` is not "this frame carried no batch". It is the honest answer for
    /// the three cases where a wire coordinate does not survive: a message that
    /// is not a `Frame` at all, a batch decompressed out of an lz4 body, and a
    /// batch REASSEMBLED from the payloads of several fragments. The last two
    /// produce a buffer that exists only inside this reader, so a record within
    /// it has an offset into that buffer and NO offset into the capture —
    /// handing out the buffer's offset is how a fabricated coordinate gets read
    /// as a measured one.
    pub batch_offset: Option<usize>,
    /// Width of the length prefix that framed it — recorded rather than
    /// recomputed, since the width can change between frames on the same
    /// stream.
    ///
    /// Recorded on every message of a batch, not only the first: the prefix
    /// framed the whole unit, so it is the width this message arrived under.
    pub prefix_width: usize,
    /// R311y687 (§1.1n) — the length the prefix DECLARED, in bytes.
    ///
    /// # Why the reader should not read it again
    ///
    /// Recorded for the same reason [`Self::prefix_width`] is, and it closes
    /// the last place outside this module that knew how a zenoh stream is
    /// framed. `wz-analyze` re-read the two prefix bytes to find where the unit
    /// ended, which made the framing rule live in two crates -- and the copy
    /// was not merely redundant, it was WRONG about a batch: it sliced from the
    /// unit's start for every message in it, so the second message of a unit
    /// was walked as the first.
    ///
    /// Like `prefix_width`, it is on every message of the unit rather than the
    /// first: the prefix framed the whole unit, so it is the length this
    /// message arrived under, and [`Self::unit_offset`] is where inside it this
    /// message stands.
    pub unit_len: usize,
    /// The decoded transport message, or the decode error.
    pub frame: Result<InboundFrame, InboundParseError>,
    /// The flow context AS OF this frame (after folding it in). Copied rather
    /// than borrowed so a consumer can keep a decoded frame beside the
    /// contract it was read under.
    pub context: FlowContext,
    /// R311y585 (A5) — the frame's wire length exceeded the `batch_size` the
    /// InitAck agreed to.
    ///
    /// A PROTOCOL VIOLATION by the sender, and the first consumer the
    /// negotiated ceiling ever had: it was decoded, stored, and read by
    /// nothing. `false` whenever no InitAck was observed — an unknown ceiling
    /// cannot be exceeded, and reporting a violation against a ceiling this
    /// observer guessed would be worse than reporting none.
    ///
    /// Not an error: the frame decoded, and a dissector shows it with the
    /// violation flagged rather than dropping it. Dropping is what makes a
    /// non-conforming peer invisible.
    pub exceeds_negotiated_batch: bool,
    /// R311y583 (A2) — what this frame carried ABOVE the transport layer.
    ///
    /// Before A2 the tracker stopped here and every consumer re-did the same
    /// three connections itself: decompress the body when the session
    /// negotiated it, walk the batch, and drive a chain over Fragments. All
    /// three need the negotiated context, which is the thing this type exists
    /// to hold, so leaving them out made the context inferred and then unused
    /// by its own crate.
    pub carried: Carried,
    /// R311y608 — this message cannot occur on the link that carried it, so it
    /// was decoded and reported but NOT folded into the session context.
    ///
    /// Only ever true for an INIT or an OPEN on a multicast-capability link
    /// (see [`PassiveSession::next_datagram_on`]). Always `false` on a stream
    /// link, which is unicast by construction.
    ///
    /// A flag rather than an error, for the reason
    /// [`Self::exceeds_negotiated_batch`] is one: the bytes decoded, and what
    /// makes them worth showing is precisely that they arrived where they
    /// cannot belong.
    pub inadmissible_on_link: bool,
    /// R311y609 (C12) — what this frame's SEQUENCE NUMBER says about what the
    /// reader did not see. `None` for every message that carries no SN
    /// (handshake, keepalive, close, join).
    #[cfg(feature = "codec-frame")]
    pub sn_verdict: Option<SnVerdict>,
    /// R311y609 — set on the first frame after a resynchronisation, and on no
    /// other. `None` on a stream that never lost its framing, and always
    /// `None` on a datagram link, which has no framing to lose.
    pub resync: Option<StreamResync>,
    /// R311y615 (§1.1f) — the capture clock as of this frame, or `None` when
    /// the byte source never supplied one.
    ///
    /// # Why it is here and not left to the caller
    ///
    /// The instant reached [`PassiveSession`] from R311y594 on and was spent
    /// entirely on expiring reassembly chains; nothing handed it back. A
    /// consumer therefore held decoded frames with no time attached to them and
    /// could not answer any question of the form "how long between these two" —
    /// which is every question an exchange plane asks. Re-deriving it outside
    /// meant tracking, per direction, which packet produced which frame, and a
    /// stream frame does not correspond to a packet at all.
    ///
    /// # What it measures, and what it does not
    ///
    /// The instant THIS OBSERVER saw the bytes. On a tap beside the querier
    /// that is the querier's round trip to within the tap's own delay; on a tap
    /// beside the responder it is not, and no arithmetic here can tell the two
    /// apart. A latency computed from these is a latency AT THE VANTAGE POINT,
    /// which is the honest claim and the only one a passive reader can make.
    pub observed_at_ms: Option<u64>,
    /// R311y611 — flag bits this header set that its own MID does not define.
    ///
    /// Zero for every conforming sender, and that is the point: reserved bits
    /// are reserved, so a non-zero value says the peer's wire-spec vintage is
    /// not this reader's. A differential oracle must NAME that rather than
    /// swallow it — and, before R311y611, the stream path did neither: it
    /// called the frame a loss of framing and skipped past real data, while the
    /// datagram path over the same bytes decoded it without comment.
    ///
    /// Always zero on the datagram path, which has no such gate to disagree
    /// with.
    pub reserved_header_bits: u8,
    /// R311y630 (§14.1) — the extension identity that makes this frame
    /// inadmissible to a conforming PARTICIPANT: the chain carries it with the
    /// mandatory marker set and the message's extension space does not define
    /// it, so both upstream implementations refuse the whole message
    /// ([`crate::ext_admit`]).
    ///
    /// `None` for a conforming sender, and for a MID this build cannot name —
    /// the two are told apart by [`PassiveFrame::frame`] itself, which is
    /// `Unknown` in the second case.
    ///
    /// Reported rather than swallowed, and reported rather than turned into a
    /// refusal, because those are the observer's two failure modes and this
    /// field is what avoids both. Swallowing it makes the analyzer quieter
    /// than either implementation about a frame neither would accept;
    /// refusing it would delete the analyzer's ability to SAY what is wrong,
    /// which is the one thing a capture reader can contribute that a
    /// participant cannot. A participant reading the same decode gets its
    /// refusal from [`crate::inbound::inbound_to_fsm_event`].
    ///
    /// Genre note: this is a fact about the SENDER, like
    /// [`PassiveFrame::reserved_header_bits`] beside it, not a shortfall in
    /// the reader's own rows — so it does not belong in a completeness
    /// verdict, and the capture layer's `is_complete` deliberately does not
    /// consult it.
    pub undefined_mandatory_ext: Option<u8>,
}

/// R311y609 (C12) — what the observer makes of ONE data frame's sequence
/// number, judged against the previous frame on the SAME conduit.
///
/// The conduit is `(priority, reliability)`, not the direction: zenoh mints
/// one SN series per `(Priority, Reliability)` pair
/// (`io/zenoh-transport/src/unicast/universal/rx.rs`, the shape
/// [`crate::sn::RxSn`] mirrors on the participant side), so judging a
/// direction's frames on one counter would read every interleave of two
/// conduits as a gap and every return to the first as a rewind. A verdict
/// like that looks decisive and is arbitrary.
#[cfg(feature = "codec-frame")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnVerdict {
    /// No InitAck (or JOIN) was observed, so the ring MASK is unknown.
    ///
    /// NOT a defaulted verdict, for the reason
    /// [`Carried::FragmentWithoutResolution`] is not one: a mask too wide
    /// reads a wraparound as a gap and one too narrow reads a gap as a
    /// wraparound. The ordinary cause is a capture that started mid-session.
    WithoutResolution,
    /// The first frame seen on this conduit — a BASELINE, not a judgement.
    /// A reader that started mid-session cannot know what came before it.
    Baseline,
    /// Exactly one step after the previous frame on this conduit.
    Continuous,
    /// `missing` frames the SENDER numbered between the previous frame on
    /// this conduit and this one never reached this reader.
    ///
    /// The wire's own loss accounting, and a DIFFERENT question from
    /// [`StreamResync::skipped`] (bytes this reader could not parse) or from
    /// a capture engine's own drop counter (packets the kernel never handed
    /// over). A capture whose three numbers disagree is telling you where the
    /// loss happened.
    Gap {
        /// How many SNs the sender used and this reader never saw.
        missing: u64,
    },
    /// The same SN as the previous frame on this conduit: a retransmission,
    /// or a capture that recorded one packet twice.
    Duplicate,
    /// Behind the previous frame, or past the forward half-window — reorder,
    /// or a stale datagram. Named apart from [`Self::Gap`] because a
    /// participant DROPS these ([`crate::sn::RxSn::admit`]) and an observer
    /// must not count them as loss.
    OutOfWindow,
}

/// R311y609 (C12) — cumulative per-direction sequence-number accounting.
#[cfg(feature = "codec-frame")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnAccounting {
    /// Data frames (Frame + Fragment) seen in this direction.
    pub frames: u64,
    /// Frames the sender numbered and this reader never saw, summed over
    /// every [`SnVerdict::Gap`].
    pub missing: u64,
    /// How many gaps that total is spread across — one gap of 100 and a
    /// hundred gaps of 1 are different captures.
    pub gaps: u64,
    /// [`SnVerdict::Duplicate`] count.
    pub duplicates: u64,
    /// [`SnVerdict::OutOfWindow`] count.
    pub out_of_window: u64,
    /// Frames judged [`SnVerdict::WithoutResolution`] — the size of the
    /// UNJUDGED population, without which `missing = 0` is unreadable.
    pub without_resolution: u64,
}

/// R311y608 — does the link a datagram arrived on have a HANDSHAKE?
///
/// Named after what it decides rather than after the link kind, because the
/// two links that answer [`Self::Absent`] have nothing else in common: UDP
/// multicast is IP and raweth is L2 with no addresses this layer can read. What
/// they share is pico's multicast receive path, which is the whole content of
/// the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkHandshake {
    /// A unicast link. INIT and OPEN establish the session on it — the shape
    /// every `tcp/...`, `udp/...` unicast, vsock and ws link takes.
    Present,
    /// A multicast-capability link: UDP multicast, or pico's raweth. There is
    /// no handshake to observe, and an INIT or OPEN seen here is discarded by
    /// every real participant.
    Absent,
}

/// Is this one of the two messages a multicast-capability link discards?
///
/// Written over the DECODED frame rather than over the MID byte, so a build
/// without `codec-init-body` — where those bytes come back
/// `Unknown { mid: 0x01 }` — answers `false` and folds nothing either way. The
/// alternative, masking the header here, would have this function claim
/// knowledge of a message the build cannot name.
fn is_handshake_message(frame: &InboundFrame) -> bool {
    match frame {
        #[cfg(feature = "codec-init-body")]
        InboundFrame::Init { .. } => true,
        #[cfg(feature = "codec-open-body")]
        InboundFrame::Open { .. } => true,
        _ => false,
    }
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
    ///
    /// R311y609 — ALSO what a desynchronised direction answers while its
    /// resynchronisation scan has not yet found a boundary it can confirm.
    /// The two are the same fact from the reader's side: more bytes may
    /// change the answer.
    NeedMoreBytes,
    /// The framing is not where this reader thinks it is, announced ONCE at
    /// the offset where the evidence appeared.
    ///
    /// R311y609 — the direction is no longer abandoned. Subsequent calls run
    /// the resynchronisation scan ([`PassiveSession::with_resync_depth`]) and
    /// the frame that resumes carries a [`StreamResync`] saying how much was
    /// skipped. A reader that wants the old terminal behaviour asks for depth
    /// 0.
    Desynchronised {
        /// Offset of the length prefix the evidence appeared at.
        stream_offset: usize,
        /// What the evidence was.
        reason: DesyncReason,
    },
}

/// R311y609 — WHY a direction is judged desynchronised.
///
/// Three arms rather than one, because a reader acts on them differently: an
/// oversize length is a corrupt or mid-frame start, and a run of implausible
/// headers on an otherwise healthy capture is more likely a MID this build's
/// wire-spec vintage does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncReason {
    /// A length prefix asked for more than [`MAX_FRAME_PAYLOAD`].
    ///
    /// Reachable ONLY on a lowlatency stream's 4-byte prefix: a `u16` prefix
    /// cannot exceed the cap by construction, which is precisely why this was
    /// never the common case and why [`Self::ImplausibleHeader`] exists.
    OversizeLength {
        /// The length it asked for.
        claimed_len: usize,
    },
    /// The framed body opened with a byte no transport header can be
    /// (`wz_codecs::wire_const::is_credible_transport_header`).
    ///
    /// THE COMMON CASE, and before R311y609 it was invisible: a 2-byte prefix
    /// read at the wrong boundary frames some arbitrary run of payload bytes,
    /// `parse_inbound` answers `Unknown { mid }` for 25 of the 32 MID values,
    /// and the reader walks the rest of the capture at a wrong boundary
    /// reporting confident nonsense. Nothing above could tell.
    ImplausibleHeader {
        /// The byte that cannot be a transport header.
        header: u8,
    },
    /// The length prefix framed an EMPTY body. Every transport message is at
    /// least its own header byte, so a zero-length frame is a boundary error
    /// rather than a message.
    EmptyFrame,
    /// R311y610 — the SOURCE of the bytes said it lost some, before this reader
    /// looked at them ([`PassiveSession::note_gap`]).
    ///
    /// The only arm that is not an inference. The three above are this reader
    /// noticing that bytes cannot mean what the framing claims; this one is the
    /// layer below reporting a hole it measured — a forced TCP gap, a capture
    /// that started mid-stream. It matters that they are distinguishable,
    /// because it is the one case where a boundary error is KNOWN rather than
    /// suspected, and the reader must not spend evidence deciding it.
    CaptureGap {
        /// Bytes the source says are absent from the stream at this point.
        /// Zero when the source knows the framing is unknown but not by how
        /// much — a capture that began without a SYN.
        bytes_missing: u64,
    },
}

/// R311y609 — a direction that desynchronised and found its framing again.
///
/// Carried on the FIRST frame decoded after the recovery, because that is the
/// frame whose offset would otherwise be an unexplained jump. A dissector that
/// resumed silently would report a hole as though the wire had none — the same
/// objection [`PassiveSession::observe_at`] answers for expired chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamResync {
    /// Absolute offset where the direction desynchronised.
    pub desync_offset: usize,
    /// The evidence that desynchronised it.
    pub reason: DesyncReason,
    /// Absolute offset the reader resumed at.
    pub resumed_offset: usize,
    /// Bytes between the two: what this reader will never decode. The number
    /// a loss-accounting view wants, and it is NOT the same as the wire's own
    /// loss — see [`SnAccounting`], which counts what the SENDER numbered.
    pub skipped: usize,
    /// How many chained candidate frames confirmed the resumed boundary.
    ///
    /// Reported rather than assumed, because it IS the confidence: the scan
    /// accepts an offset only when `depth` consecutive frames each carry a
    /// credible header and an in-range length, and a reader weighing an
    /// implausible-looking resync wants to know how much evidence stood
    /// behind it.
    pub confirmed: usize,
}

/// R311y609 — per-direction resynchronisation accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResyncAccounting {
    /// Times this direction desynchronised.
    pub desyncs: u64,
    /// Times it found its framing again.
    pub recoveries: u64,
    /// Total bytes skipped across those recoveries.
    pub skipped_bytes: u64,
}

/// Per-direction stream buffer + cursor.
#[derive(Debug, Default)]
struct DirectionStream {
    buf: Vec<u8>,
    /// Bytes already consumed and drained from `buf`, so `stream_offset`
    /// stays absolute across compactions.
    consumed: usize,
    /// R311y609 — `Some` while this direction is looking for its framing.
    ///
    /// Nothing is consumed while it is set, so `buf[0]` stays the byte at
    /// `consumed` and the scan cursor below is an index into `buf` that
    /// survives across calls.
    desync: Option<DesyncState>,
    /// R311y609 — the recovery to hand to the next frame decoded.
    pending_resync: Option<StreamResync>,
    /// R311y609 — cumulative, for a reader that wants the flow's health
    /// rather than one frame's story.
    accounting: ResyncAccounting,
}

/// R311y609 — the live state of one direction's resynchronisation scan.
#[derive(Debug, Clone, Copy)]
struct DesyncState {
    /// Absolute offset the desynchronisation was judged at.
    ///
    /// The announcing [`PassiveStall::Desynchronised`] is returned by the call
    /// that DETECTS it and by no later one: repeating the stall on every
    /// subsequent call would drown the event that matters in the event that
    /// does not, and a caller that polls would see the same desync a thousand
    /// times.
    at_offset: usize,
    reason: DesyncReason,
    /// Index into `buf` of the lowest candidate offset not yet REFUTED.
    ///
    /// A candidate that failed for lack of bytes is not refuted, and the
    /// cursor does NOT follow past it — it advances only across a contiguous
    /// run of refutations, so no offset is abandoned unexamined.
    scan_cursor: usize,
    /// Buffer length at which the scan can produce a different answer.
    ///
    /// When every offset examined was REFUTED there is no unresolved candidate
    /// to wait on, and the next answer can only come from a longer buffer — so
    /// the threshold becomes one byte past the current length rather than
    /// "never". Getting that arm wrong freezes a scan that is working.
    rescan_at: usize,
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
    /// R311y594 — the OBSERVATION instant, in the same milliseconds
    /// [`ReassemblyConfig::reassembly_timeout_ms`] is expressed in.
    ///
    /// An observer's clock is not its own: it is the capture's. A pcap packet
    /// carries the time it was seen and a live tap knows when it arrived, so
    /// the instant is an INPUT rather than something to read off the host —
    /// which also makes a replayed file deterministic, and makes replaying it
    /// at 100x not expire chains that never expired in the original.
    ///
    /// Stays `None` unless a caller advances it ([`Self::observe_at`]), which
    /// is exactly the pre-R311y594 behaviour: a deadline armed at 0 against a
    /// `u64::MAX` window is one nothing can reach.
    ///
    /// R311y615 (§1.1f) — UNGATED, and `Option` rather than `u64`, for two
    /// reasons that only appeared once a consumer wanted the instant for
    /// something other than expiry.
    ///
    /// The gate was wrong because the clock is not a reassembly concept: it is
    /// the capture's, and a build without `reassembly` still reads pcap
    /// timestamps and still wants to know WHEN a frame went past. Expiry was
    /// merely its first consumer.
    ///
    /// The `Option` is what keeps a LATENCY from being fabricated. A `0`
    /// default is indistinguishable from a capture whose first packet is at
    /// epoch, so two frames of an unstamped session would subtract to a
    /// confident `0 ms` round trip. `None` makes "this observer was never told
    /// the time" a fact a consumer has to handle rather than a plausible
    /// measurement it cannot detect.
    observed_at: Option<u64>,
    /// R311y609 (C12) — last SN seen per `[direction][conduit]`, where the
    /// conduit index is [`sn_conduit`]. `None` = nothing seen there yet, which
    /// is what makes the first frame a [`SnVerdict::Baseline`] rather than a
    /// gap from zero.
    #[cfg(feature = "codec-frame")]
    sn_last: [[Option<u64>; SN_CONDUITS]; 2],
    /// R311y609 (C12) — cumulative, per direction.
    #[cfg(feature = "codec-frame")]
    sn_accounting: [SnAccounting; 2],
    /// R311y611 (§1.4b) — messages decoded whose header set a flag bit its own
    /// MID does not define, per direction.
    ///
    /// Reachable only on the datagram path: a stream link's credible-header
    /// gate refuses such a byte and desynchronises instead, and says so. So
    /// this is the counter for the path where nothing else was speaking.
    reserved_headers: [u64; 2],
    /// R311y630 (§14.1) — frames decoded that carry a mandatory extension
    /// their message's space does not define, per direction.
    ///
    /// Reachable on BOTH ingestion paths, unlike `reserved_headers` above: the
    /// credible-header gate judges the transport header byte and has nothing
    /// to say about the extension chain that follows it, so a stream link
    /// decodes such a frame exactly as a datagram link does.
    undefined_mandatory_exts: [u64; 2],
    /// R311y631 (§1.2b) — bytes inside a framing unit that no decoded message
    /// accounts for, per direction.
    ///
    /// Non-zero when the batch walk stopped before the unit was exhausted: a
    /// message that failed to decode, or one whose MID this build does not know
    /// and therefore cannot measure the length of. Both leave a tail whose
    /// contents are unknown, and the walk refuses to guess a boundary inside it.
    ///
    /// This is the counter §1.2b was opened for. Before it, a batch's second
    /// message was not reported ANYWHERE — not as a skipped packet, because the
    /// packet was not skipped, and not as a desynchronisation, because the
    /// framing was never in question. Now the messages are decoded, and what
    /// remains genuinely unreadable is counted here instead of being silent.
    unaccounted_batch_bytes: [u64; 2],
    /// R311y631 (§1.2b) — messages already decoded out of a framing unit and
    /// not yet handed to the caller, per direction.
    ///
    /// [`PassiveSession::next_frame`] yields ONE message per call, which is the
    /// shape every caller loops on. A framing unit yields N, so the surplus
    /// waits here rather than being returned in a `Vec` the caller would have
    /// to remember to drain — a caller that forgot is exactly the silence this
    /// round is closing.
    pending: [alloc::collections::VecDeque<PassiveFrame>; 2],
    /// R311y609 — how many chained candidate frames must agree before the
    /// resynchronisation scan accepts a boundary. `0` disables recovery.
    resync_depth: usize,
}

/// R311y609 (C12) — SN conduits per direction: one per
/// `(Priority, Reliability)` pair, the same split zenoh mints on.
#[cfg(feature = "codec-frame")]
const SN_CONDUITS: usize = crate::qos::Priority::NUM * 2;

/// R311y609 (C12) — index of one conduit within a direction.
#[cfg(feature = "codec-frame")]
fn sn_conduit(priority: crate::qos::Priority, reliable: bool) -> usize {
    priority.wire_byte() as usize * 2 + usize::from(reliable)
}

/// R311y609 — how many chained candidate frames confirm a resynchronised
/// boundary by default.
///
/// CHOSEN FROM A MEASUREMENT, not from taste, and the estimate it replaced was
/// wrong in the interesting direction.
///
/// A credible transport header is 42 of 256 bytes
/// (`wz_codecs::wire_const::is_credible_transport_header`), which suggests a
/// chain of `d` costs `(42/256)^d` per candidate offset. That model says
/// almost nothing false survives `d = 6`. What
/// `the_resync_scan_lands_on_the_true_boundary_across_noise` actually measures
/// is that a wrong resume needs only ONE lucky hop that lands on the true
/// boundary, after which it inherits the real chain — so wrong resumes are far
/// more common than the model predicts, and also far less harmful.
///
/// The swept numbers at 10 trials per cell, noise runs of 512 / 8192 / 65536
/// bytes in front of 12000 real frames:
///
/// - every depth recovers in every trial, and after the final recovery NO
///   frame is reported off a true boundary (drift 0),
/// - `d = 4` resumes wrongly more often (14 recoveries where 6 and 8 need 10),
/// - `d = 6` and `d = 8` are indistinguishable on every measure,
/// - the worst lead-in — frames reported before the framing rejoins the truth
///   — is 4.
///
/// So 6 is the SMALLEST depth that ties the deepest one swept, and depth costs
/// latency: a direction resumes only once `d` more frames are buffered, and a
/// capture that ends inside the scan never resumes at all. That is the honest
/// failure; the alternative, resuming on thin evidence, reports a wrong
/// boundary as confidently as a right one.
pub const DEFAULT_RESYNC_DEPTH: usize = 6;

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
                // `u64::MAX` keeps the deadline unreachable for a caller that
                // never advances the clock, which is every caller that has one
                // stream of bytes and no time to attach to them. A caller that
                // DOES have timestamps builds with
                // `PassiveSession::with_reassembly_window` instead. Markers
                // start off and are pushed in per frame from the negotiated
                // patch level.
                ReassemblyDispatcher::new(ReassemblyConfig::new(PASSIVE_CHAIN_QUOTA, u64::MAX))
            }),
            observed_at: None,
            #[cfg(feature = "codec-frame")]
            sn_last: [[None; SN_CONDUITS]; 2],
            #[cfg(feature = "codec-frame")]
            sn_accounting: [SnAccounting::default(); 2],
            reserved_headers: [0; 2],
            undefined_mandatory_exts: [0; 2],
            unaccounted_batch_bytes: [0; 2],
            pending: core::array::from_fn(|_| alloc::collections::VecDeque::new()),
            resync_depth: DEFAULT_RESYNC_DEPTH,
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
    ///
    /// Its reassembly deadline is unreachable — see
    /// [`Self::with_reassembly_window`] for the caller that has a clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y594 — an observer whose half-finished chains EXPIRE.
    ///
    /// `window_ms` is the per-chain deadline, armed when the chain opens and
    /// enforced by [`Self::observe_at`]. A window is only meaningful to a
    /// caller that also advances the clock; one that does not gets the same
    /// behaviour as [`Self::new`] no matter what it passes here, which is why
    /// the window is a CONSTRUCTOR argument rather than a setter — changing it
    /// mid-flight would re-arm deadlines that are already running and there is
    /// no honest answer to what they should become.
    ///
    /// Without a window the per-direction quota (4) is the whole defence, and
    /// a quota is a bound on CONCURRENCY, not on DURATION: a peer that opens
    /// four chains and abandons them holds those slots for as long as the
    /// reader runs. Bounded for a file that ends; not for a live tap.
    /// R311y609 — how much evidence this observer demands before it resumes a
    /// desynchronised direction. See [`DEFAULT_RESYNC_DEPTH`].
    ///
    /// A BUILDER rather than a constructor, so it composes with
    /// [`Self::with_reassembly_window`], and a setter is honest here where it
    /// was not for the reassembly window: changing the depth mid-flight
    /// affects only scans that have not yet accepted, and there is no armed
    /// state to re-interpret.
    ///
    /// `0` restores the pre-R311y609 behaviour exactly: a desynchronised
    /// direction is abandoned. Kept reachable because it is also the arm that
    /// PROVES the recovery does something — a test that cannot turn a feature
    /// off cannot show it was the feature that acted.
    pub fn with_resync_depth(mut self, depth: usize) -> Self {
        self.resync_depth = depth;
        self
    }

    #[cfg(feature = "reassembly")]
    pub fn with_reassembly_window(window_ms: u64) -> Self {
        Self {
            reasm: core::array::from_fn(|_| {
                ReassemblyDispatcher::new(ReassemblyConfig::new(PASSIVE_CHAIN_QUOTA, window_ms))
            }),
            ..Self::default()
        }
    }

    /// Advance the observation clock to `now_ms` and abort every chain whose
    /// deadline has passed. Returns how many were aborted.
    ///
    /// COUNTED, not silent: an expired chain is data the reader will never see
    /// completed, and a dissection that drops it without saying so reports a
    /// hole as if it were the wire's. The caller decides whether to surface it.
    ///
    /// Monotonicity is the CALLER's to keep — a capture whose packets are out
    /// of order would otherwise walk the clock backwards. Going backwards is
    /// harmless here (nothing expires), which is the right failure for a
    /// timestamp that cannot be trusted.
    ///
    /// R311y615 — UNGATED. Without `reassembly` there is nothing to sweep and
    /// the answer is always `0`, but the clock still advances: the instant is
    /// now carried on every frame ([`PassiveFrame::observed_at_ms`]) and a
    /// consumer measuring latency needs it whether or not this build can
    /// reassemble.
    pub fn observe_at(&mut self, now_ms: u64) -> usize {
        self.observe_at_counting(now_ms).chains
    }

    /// R311y713 (§B7) — the same sweep, reporting the BYTES that went with the
    /// chains as well as their number.
    ///
    /// The staged bytes exist only until the slot is released, so this is the
    /// one instant they can be counted; see
    /// [`crate::reassembly_dispatch::ReassemblyDispatcher::sweep_counting`].
    pub fn observe_at_counting(&mut self, now_ms: u64) -> ChainLoss {
        self.observed_at = Some(now_ms);
        #[cfg(feature = "reassembly")]
        {
            let mut loss = self.reasm[0].sweep_counting(now_ms);
            loss.absorb(self.reasm[1].sweep_counting(now_ms));
            loss
        }
        #[cfg(not(feature = "reassembly"))]
        {
            ChainLoss::default()
        }
    }

    /// R311y655 — abandon every chain still open, WHATEVER its deadline says.
    ///
    /// The deadline sweep in [`Self::observe_at`] answers "has this chain waited
    /// too long"; this answers a question the observer cannot ask itself at all:
    /// "is anything more coming". Only the caller knows that a capture ended, a
    /// file ran out, or a link closed — the same argument R311y609's
    /// `force_oldest_gap` was written for, one layer up, and the reason it is a
    /// separate verb rather than a destructor: calling it on a live tap would
    /// abandon a chain that was still going to complete.
    ///
    /// UNGATED, like [`Self::observe_at`] beside it and for the same reason: a
    /// build without `reassembly` holds no chains, so `0` is the true answer and
    /// a caller must not have to know which features this binary carries.
    ///
    /// Does NOT touch the observation clock. `observe_at(u64::MAX)` would sweep
    /// the same slots and would leave every later frame stamped at the end of
    /// time.
    pub fn abandon_open_chains(&mut self) -> usize {
        self.abandon_open_chains_counting().chains
    }

    /// R311y713 (§B7) — the same, reporting the bytes the abandoned chains had
    /// already gathered.
    pub fn abandon_open_chains_counting(&mut self) -> ChainLoss {
        #[cfg(feature = "reassembly")]
        {
            // `u64::MAX` is what makes the deadline unreachable-in-reverse: a
            // slot is kept when `now < deadline`, so the largest instant there
            // is expires every open slot including the ones built with no
            // window at all, whose deadline is that same value.
            let mut loss = self.reasm[0].sweep_counting(u64::MAX);
            loss.absorb(self.reasm[1].sweep_counting(u64::MAX));
            loss
        }
        #[cfg(not(feature = "reassembly"))]
        {
            ChainLoss::default()
        }
    }

    /// The observation instant last handed to [`Self::observe_at`], or `0` if
    /// none ever was.
    ///
    /// Kept for the reassembly-deadline reading it was written for, where `0`
    /// IS the pre-clock value. A consumer that must tell "never told" from
    /// "told, at zero" reads [`Self::observed_at`] instead.
    pub fn now_ms(&self) -> u64 {
        self.observed_at.unwrap_or(0)
    }

    /// R311y615 (§1.1f) — the observation instant, or `None` when this observer
    /// was never given one.
    pub fn observed_at(&self) -> Option<u64> {
        self.observed_at
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

    /// R311y610 — the byte source declares a DISCONTINUITY at the current write
    /// point: everything pushed after this call belongs to a different, unknown
    /// framing offset than everything pushed before it.
    ///
    /// Call it BEFORE pushing the bytes on the far side of the hole, and after
    /// draining what the near side yielded — anything still buffered is on the
    /// wrong side of a boundary this reader can no longer place, and the scan
    /// will step over it and count it in [`StreamResync::skipped`]. Returns
    /// `true` when this call is what desynchronised the direction, `false` when
    /// it was already looking for its framing (a second hole inside a scan
    /// changes nothing — the scan is already running and its `desync_offset`
    /// must keep naming the FIRST loss).
    ///
    /// # Why the source has to say so, and R311y609 could not
    ///
    /// R311y609 gave the reader a detector — a length prefix and the header
    /// byte behind it — and measured what it costs to rely on it: 45-68% of the
    /// frames after a hole, AT EVERY SCAN DEPTH, because the loss happens
    /// before the scan starts. A 2-byte prefix read off spliced bytes claims up
    /// to [`MAX_FRAME_PAYLOAD`], 42 of 256 byte values pass as a credible
    /// header, and when both happen the reader consumes that many REAL bytes as
    /// one body and never suspects a thing. No deeper scan helps, because
    /// nothing has told the scan to run.
    ///
    /// The evidence that settles it is not on the wire at all — it is the fact
    /// that the layer below LOST bytes, which that layer measured and this one
    /// cannot see. So it is handed across rather than inferred, and the reader
    /// then spends its depth-`N` corroboration on finding the boundary instead
    /// of on discovering that it needs to.
    pub fn note_gap(&mut self, direction: Direction, bytes_missing: u64) -> bool {
        let stream = self.stream_mut(direction);
        let fresh = stream.desync.is_none();
        let _ = stream.desynchronise(DesyncReason::CaptureGap { bytes_missing });
        fresh
    }

    /// Decode the next complete frame in `direction`, or say why not.
    ///
    /// Each call re-reads [`FlowContext::prefix_width`], so a session that
    /// reframes to the 4-byte prefix at Established is followed across the
    /// boundary without the caller doing anything.
    ///
    /// R311y631 (§1.2b) — ONE framing unit can hold several messages, so a
    /// call that reads an envelope decodes all of them and returns the first;
    /// the rest are handed out by the following calls, before any new bytes are
    /// read. Every caller already loops until [`PassiveStall`], so this widens
    /// what those loops see without any of them changing.
    pub fn next_frame(&mut self, direction: Direction) -> Result<PassiveFrame, PassiveStall> {
        if let Some(frame) = self.pending[usize::from(direction == Direction::B)].pop_front() {
            return Ok(frame);
        }
        let width = self.context.prefix_width();
        let depth = self.resync_depth;
        let stream = self.stream_mut(direction);

        // R311y609 — a desynchronised direction is no longer terminal: the
        // detecting call announced it, and every later one scans.
        if stream.desync.is_some() {
            match stream.try_resync(width, depth) {
                Some(resync) => stream.pending_resync = Some(resync),
                None => return Err(PassiveStall::NeedMoreBytes),
            }
        }

        if stream.buf.len() < width {
            return Err(PassiveStall::NeedMoreBytes);
        }
        let payload_len = read_prefix(&stream.buf, 0, width);
        let stream_offset = stream.consumed;
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(stream.desynchronise(DesyncReason::OversizeLength {
                claimed_len: payload_len,
            }));
        }
        if payload_len == 0 {
            return Err(stream.desynchronise(DesyncReason::EmptyFrame));
        }
        // The header byte decides the boundary, and it arrives long before the
        // rest of the body — so it is judged HERE rather than after the wait.
        // A wrong 2-byte prefix routinely frames tens of kilobytes; waiting for
        // them before noticing would hand the scan a starting point that is
        // already past the boundary it is looking for.
        if stream.buf.len() < width + 1 {
            return Err(PassiveStall::NeedMoreBytes);
        }
        let header = stream.buf[width];
        if !wz_codecs::wire_const::is_credible_transport_header(header) {
            return Err(stream.desynchronise(DesyncReason::ImplausibleHeader { header }));
        }
        if stream.buf.len() < width + payload_len {
            return Err(PassiveStall::NeedMoreBytes);
        }
        let body: Vec<u8> = stream.buf[width..width + payload_len].to_vec();
        stream.buf.drain(..width + payload_len);
        stream.consumed += width + payload_len;
        let resync = stream.pending_resync.take();

        // A byte STREAM is a unicast link by construction — zenoh has no
        // multicast stream transport — so `inadmissible_on_link` cannot arise
        // here, which is what `LinkHandshake::Present` says.
        let mut walked = self
            .decode_framing_unit(
                direction,
                &body,
                // The one caller that counts BYTES: `stream.consumed` is where
                // this unit's length prefix stood in the direction's stream.
                Anchor::bytes(stream_offset),
                width,
                LinkHandshake::Present,
                resync,
            )
            .into_iter();
        match walked.next() {
            Some(first) => {
                self.pending[usize::from(direction == Direction::B)].extend(walked);
                Ok(first)
            }
            // Structurally unreachable: `payload_len == 0` desynchronised
            // above, so the unit handed to the walk is non-empty and the walk
            // yields at least one message for it. `NeedMoreBytes` is the answer
            // that loses nothing if that ever stops holding.
            None => Err(PassiveStall::NeedMoreBytes),
        }
    }

    /// R311y631 (§1.2b) — decode EVERY transport message in one framing unit.
    ///
    /// # Why a unit is not a message
    ///
    /// It was read as one until this round, on both ingestion paths, and the
    /// claim that justified it — "zenoh puts exactly one wire message in each
    /// datagram" — cited this workspace's own sender rather than either
    /// reference implementation. Both of those batch. zenoh loops
    /// `while !batch.is_empty()` over a received unit on the datagram path
    /// (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`) and on the stream path
    /// (`.../unicast/universal/rx.rs:220`); pico does not even re-read the link
    /// while its buffer still holds bytes, decoding the next message straight
    /// out of the residue (`vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`)
    /// after advancing by exactly one message's length (`:99`). Batching is on
    /// by default in zenoh's transmission pipeline, so this is the ordinary
    /// case and not a corner of the protocol.
    ///
    /// A `Frame` or `Fragment` consumes the remainder by construction
    /// (`zenoh-codec-1.5.0/src/transport/frame.rs:173`), which is why a real
    /// batch looks like `[KeepAlive][Frame]` and never `[Frame][KeepAlive]` —
    /// and why the message that used to be dropped here is so often the DATA
    /// one.
    ///
    /// # What is per-unit and what is per-message
    ///
    /// The negotiated batch ceiling and the resynchronisation record belong to
    /// the UNIT: the InitAck agreed a size for the whole batch, and a recovery
    /// happened once, at its boundary. So `exceeds_negotiated_batch` is
    /// computed on the unit and carried by every message in it, and `resync` is
    /// attached to the first message only. Everything else — the fold, the SN
    /// verdict, the carried payload, the reserved header bits, the mandatory
    /// extension check — is a property of one message and is computed per
    /// message.
    ///
    /// R2206 (open-debt item 561) — the anchor arrives as an [`Anchor`], which
    /// is a coordinate AND the space it is in, because a caller that could hand
    /// in the number alone is what item 561 was.
    ///
    /// Inferring the space from `prefix_width == 0` would work today and is a
    /// guess: the width is a fact about FRAMING and the space is a fact about
    /// what the caller counted, and the two agree only for as long as no link
    /// arrives that frames without a prefix over a stream. A caller that knows
    /// which number it handed in is the only party that does.
    fn decode_framing_unit(
        &mut self,
        direction: Direction,
        bytes: &[u8],
        anchor: Anchor,
        prefix_width: usize,
        handshake: LinkHandshake,
        mut resync: Option<StreamResync>,
    ) -> Vec<PassiveFrame> {
        let Anchor {
            offset,
            space: offset_space,
        } = anchor;
        let exceeds_negotiated_batch = self.exceeds_batch(bytes.len());
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut batch_index = 0usize;
        while pos < bytes.len() {
            let rest = &bytes[pos..];
            // R311y611 (§1.4b) — counted BEFORE the admissibility branch below:
            // a reserved bit is a fact about the SENDER's wire-spec vintage,
            // and it is one whether or not this link was entitled to carry the
            // message. Read off THIS message's header, so a batch's second
            // message is judged as well as its first — the stream path's
            // credible-header gate gets to see only the first.
            let reserved = rest
                .first()
                .and_then(|h| wz_codecs::wire_const::reserved_transport_flags(*h))
                .unwrap_or(0);
            if reserved != 0 {
                self.reserved_headers[usize::from(direction == Direction::B)] += 1;
            }
            let (frame, consumed) = match parse_inbound_consuming(rest) {
                Ok((f, n)) => (Ok(f), n),
                Err(e) => (Err(e), 0),
            };
            // R311y631 — A MESSAGE THAT CANNOT BE MEASURED CANNOT BE LOCATED,
            // and a record whose position is unknown is not evidence.
            //
            // Past the front of the unit, `consumed == 0` says the walk does
            // not know where this candidate starts or ends: either the decode
            // failed, or the MID carries no length this build can skip. The
            // bytes are counted as unaccounted-for and the walk stops. It does
            // NOT emit a record for them, because the only reason the walk is
            // standing here is that the PREVIOUS message claimed to end here —
            // and if that claim was wrong, everything read from this offset is
            // manufactured. A scouting HELLO read on a transport flow is the
            // fixture that proves it: `S_MID_HELLO` and `T_MID_OPEN` are both
            // `0x02`, the Open body decodes off the front of a Hello, and the
            // locator list behind it would otherwise be reported as a second
            // transport message that nobody sent.
            //
            // At the FRONT of the unit the record IS emitted, error and all:
            // there the offset is not in question — the caller handed these
            // bytes over as one framing unit — so an undecodable datagram
            // still reports the decode error rather than vanishing.
            if consumed == 0 && pos > 0 {
                self.unaccounted_batch_bytes[usize::from(direction == Direction::B)] +=
                    (bytes.len() - pos) as u64;
                break;
            }
            let inadmissible = handshake == LinkHandshake::Absent
                && frame.as_ref().is_ok_and(is_handshake_message);
            if let Ok(ref f) = frame {
                if !inadmissible {
                    self.fold(direction, f);
                }
            }
            // R311y609 (C12) — an inadmissible message is not folded, and it is
            // not NUMBERED either: an INIT on a multicast link carries no SN,
            // and a data frame that reaches here has one whatever the link is.
            #[cfg(feature = "codec-frame")]
            let sn_verdict = self.track_sn(direction, &frame);
            let carried = self.decode_carried(direction, &frame);
            let undefined_mandatory_ext = self.note_undefined_mandatory_ext(direction, &frame);
            let batch_offset = self.batch_offset_of(&frame, consumed);
            out.push(PassiveFrame {
                direction,
                stream_offset: offset,
                offset_space,
                batch_index,
                unit_offset: pos,
                unit_len: bytes.len(),
                batch_offset,
                undefined_mandatory_ext,
                prefix_width,
                frame,
                context: self.context,
                exceeds_negotiated_batch,
                carried,
                inadmissible_on_link: inadmissible,
                #[cfg(feature = "codec-frame")]
                sn_verdict,
                resync: resync.take(),
                observed_at_ms: self.observed_at,
                reserved_header_bits: reserved,
            });
            batch_index += 1;
            if consumed == 0 {
                // Front of the unit, and unmeasurable: the record above is the
                // verdict on the whole unit, and the bytes behind it are still
                // unaccounted for. Counting them is what makes an undecodable
                // datagram say how much it could not explain.
                self.unaccounted_batch_bytes[usize::from(direction == Direction::B)] +=
                    (bytes.len() - pos) as u64;
                break;
            }
            pos += consumed;
        }
        out
    }

    /// R311y631 (§1.2b) — bytes of a framing unit no decoded message accounts
    /// for, cumulative, in `direction`.
    ///
    /// See [`PassiveSession::decode_framing_unit`] for when it moves. Zero is
    /// the ordinary reading: every message of every batch was decoded and its
    /// length was known.
    pub fn unaccounted_batch_bytes(&self, direction: Direction) -> u64 {
        self.unaccounted_batch_bytes[usize::from(direction == Direction::B)]
    }

    /// R311y609 (C12) — the SN accounting for one direction so far.
    #[cfg(feature = "codec-frame")]
    pub fn sn_accounting(&self, direction: Direction) -> SnAccounting {
        self.sn_accounting[usize::from(direction == Direction::B)]
    }

    /// R311y609 — the resynchronisation accounting for one direction so far.
    /// Always zero on a datagram link, which has no framing to lose.
    pub fn resync_accounting(&self, direction: Direction) -> ResyncAccounting {
        self.stream(direction).accounting
    }

    /// R311y611 (§1.4b) — messages this direction decoded whose header set a
    /// bit its MID does not define. See [`PassiveFrame::reserved_header_bits`].
    pub fn reserved_headers(&self, direction: Direction) -> u64 {
        self.reserved_headers[usize::from(direction == Direction::B)]
    }

    /// R311y630 (§14.1) — frames this direction decoded that carry a mandatory
    /// extension their message's space does not define. See
    /// [`PassiveFrame::undefined_mandatory_ext`].
    pub fn undefined_mandatory_exts(&self, direction: Direction) -> u64 {
        self.undefined_mandatory_exts[usize::from(direction == Direction::B)]
    }

    /// R311y630 — the per-frame verdict, and the counter bump that goes with
    /// it, in ONE place because both ingestion paths need both and a fact
    /// recorded at one site and counted at another is how the two drift.
    fn note_undefined_mandatory_ext(
        &mut self,
        direction: Direction,
        frame: &Result<InboundFrame, InboundParseError>,
    ) -> Option<u8> {
        let Ok(frame) = frame else { return None };
        let crate::ext_admit::ExtAdmission::UnknownMandatory { eid } = frame.ext_admission() else {
            return None;
        };
        self.undefined_mandatory_exts[usize::from(direction == Direction::B)] += 1;
        Some(eid)
    }

    /// R311y610 — bytes pushed into this direction and not yet consumed.
    ///
    /// The one accumulation this type owns, and therefore the one a live tap
    /// has to be able to watch: a direction looking for its framing consumes
    /// NOTHING while it scans, so [`RESYNC_SCAN_WINDOW`] is what keeps that
    /// from being unbounded. A number that can only be inferred from the
    /// caller's own bookkeeping is a bound nobody can check.
    pub fn buffered(&self, direction: Direction) -> usize {
        self.stream(direction).buf.len()
    }

    /// R311y609 (C12) — judge one decoded frame's sequence number against the
    /// last one seen on its conduit, and fold the verdict into the direction's
    /// accounting.
    ///
    /// Returns `None` for every message that carries no SN, which is what
    /// keeps a keepalive-only stretch of a capture from looking like a gap.
    #[cfg(feature = "codec-frame")]
    fn track_sn(
        &mut self,
        direction: Direction,
        frame: &Result<InboundFrame, InboundParseError>,
    ) -> Option<SnVerdict> {
        let (sn, reliable, priority) = match frame {
            Ok(InboundFrame::Frame {
                sn,
                reliable,
                priority,
                ..
            }) => (*sn, *reliable, *priority),
            #[cfg(feature = "reassembly")]
            Ok(InboundFrame::Fragment {
                sn,
                reliable,
                priority,
                ..
            }) => (*sn, *reliable, *priority),
            _ => return None,
        };
        let idx = usize::from(direction == Direction::B);
        let acc = &mut self.sn_accounting[idx];
        acc.frames += 1;
        let Some(mask) = self.context.sn_mask() else {
            acc.without_resolution += 1;
            return Some(SnVerdict::WithoutResolution);
        };
        let conduit = sn_conduit(priority, reliable);
        let slot = &mut self.sn_last[idx][conduit];
        let verdict = match *slot {
            None => SnVerdict::Baseline,
            Some(last) if (sn & mask) == (last & mask) => SnVerdict::Duplicate,
            Some(last) if !crate::sn::precedes(mask, last, sn) => SnVerdict::OutOfWindow,
            Some(last) => {
                // `precedes` held, so the modular distance is in `1..=half`.
                let step = sn.wrapping_sub(last) & mask;
                if step == 1 {
                    SnVerdict::Continuous
                } else {
                    SnVerdict::Gap { missing: step - 1 }
                }
            }
        };
        match verdict {
            SnVerdict::Duplicate => acc.duplicates += 1,
            SnVerdict::OutOfWindow => acc.out_of_window += 1,
            SnVerdict::Gap { missing } => {
                acc.gaps += 1;
                acc.missing += missing;
            }
            _ => {}
        }
        // A stale or duplicated SN does NOT move the baseline — the same rule
        // `RxSn::admit` applies on the participant side, and for the same
        // reason: letting a reordered datagram rewind the counter would turn
        // the next in-order frame into a fabricated gap.
        if !matches!(verdict, SnVerdict::Duplicate | SnVerdict::OutOfWindow) {
            *slot = Some(sn);
        }
        Some(verdict)
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

    /// R311y584 (A3) — decode ONE datagram, which is one whole BATCH.
    ///
    /// The datagram sibling of [`Self::next_frame`], and a separate entry
    /// point rather than a flag on that one, because the FRAMING differs and
    /// nothing else does. A datagram link carries no length prefix at all —
    /// UDP preserves the boundary of the unit, so the datagram itself delimits
    /// the batch — which means there is no buffer to append to, no boundary to
    /// search for, and no desynchronisation to recover from. Everything ABOVE
    /// the framing is shared: the same fold, the same negotiated context, the
    /// same [`Carried`] decode.
    ///
    /// R311y631 (§1.2b) — it returns the messages the datagram held, which is
    /// not always one. The `Vec` is the point: a caller cannot read the first
    /// element and be silently correct, which is what the previous signature
    /// let every caller do. See [`Self::decode_framing_unit`] for the upstream
    /// evidence that a datagram batches.
    ///
    /// `offset` is whatever coordinate the caller wants the frames reported
    /// against — a packet index, a byte offset into a file. This layer never
    /// interprets it, because for a datagram there is no stream for it to be
    /// an offset INTO; [`PassiveFrame::batch_index`] separates messages that
    /// share one.
    ///
    /// Infallible in the [`PassiveStall`] sense: a datagram is either
    /// decodable or not, and "not" arrives as an `Err` inside
    /// [`PassiveFrame::frame`] rather than as a reason to wait for more bytes.
    /// An EMPTY datagram yields an empty `Vec` — there is no message in it to
    /// report, and inventing an `Err` for one would be a decode failure this
    /// reader made up.
    pub fn next_datagram(
        &mut self,
        direction: Direction,
        bytes: &[u8],
        offset: usize,
    ) -> Vec<PassiveFrame> {
        self.next_datagram_on(direction, bytes, offset, LinkHandshake::Present)
    }

    /// R311y608 — the same, told whether the link that carried it HAS a
    /// handshake.
    ///
    /// # Why an observer needs to be told
    ///
    /// A handshake is a property of the LINK, not of the bytes. pico gives
    /// every multicast-capability link — UDP multicast and its raweth L2 link
    /// alike — the multicast receive path, and that path takes an INIT or an
    /// OPEN and deliberately does nothing with it: "multicast transports are
    /// not expected to handle INIT messages"
    /// (`vendor/zenoh-pico/src/transport/multicast/rx.c:493-504`). It decodes
    /// the message and drops it on the floor.
    ///
    /// An observer that FOLDS one has invented a session no participant has:
    /// the peer's zid, its lease and its negotiated capabilities all enter a
    /// context that describes nothing, and every frame reported afterwards is
    /// judged against it — including [`PassiveFrame::exceeds_negotiated_batch`],
    /// which would then flag violations of a ceiling nobody agreed to.
    ///
    /// The message is still REPORTED, and flagged
    /// ([`PassiveFrame::inadmissible_on_link`]). Dropping it would hide the one
    /// thing worth seeing: an INIT on a link that cannot have one is an
    /// anomaly, and a dissector that shows nothing there is indistinguishable
    /// from one that failed to decode.
    ///
    /// The raweth case is the one that made this reachable, and it is
    /// reachable ONLY through the link type: pico sets
    /// `Z_LINK_CAP_TRANSPORT_RAWETH` on every raweth link unconditionally
    /// (`src/transport/raweth/link.c:476`) and routes it into
    /// `_z_new_transport_multicast` (`src/transport/multicast/transport.c:42`),
    /// whatever the destination MAC is — its own default mapping addresses
    /// `aa:bb:cc:dd:ee:ff` (`raweth/link.c:66`), whose I/G bit is CLEAR, so a
    /// reader that judged L2 multicast by that bit would miss pico's default
    /// deployment entirely.
    pub fn next_datagram_on(
        &mut self,
        direction: Direction,
        bytes: &[u8],
        offset: usize,
        handshake: LinkHandshake,
    ) -> Vec<PassiveFrame> {
        // `prefix_width` 0 rather than one of the two stream widths: a datagram
        // has no prefix, and reporting 2 here would be a measurement of
        // nothing. `resync` `None`: a datagram link has no framing to lose, so
        // there is no boundary to be wrong about.
        //
        // R311y611 — AND THIS IS THE PATH WHERE NOBODY WAS SAYING ANYTHING
        // about reserved header bits: a datagram has no header gate, and
        // `parse_inbound` dispatches on `header & 0x1F` and ignores the
        // reserved bits exactly as zenoh's own decoder does. The walk reads
        // them per message.
        //
        // R2206 (open-debt item 561) — AND THE SPACE IS THE CALLER'S INDEX, not
        // a byte count. This path has no stream to count bytes in; `offset` is
        // whatever coordinate the caller had for the thing that carried these
        // bytes, which for every caller in this tree is a capture packet index.
        // Saying so HERE is the fix for item 561: the capture layer used to say
        // it a second time, from a match over its message lists, and the serial
        // line was labelled with the answer the OTHER caller of this function
        // deserved.
        self.decode_framing_unit(direction, bytes, Anchor::packet(offset), 0, handshake, None)
    }

    /// R311y585 (A5) — did this frame's wire length break the negotiated
    /// ceiling? Never true before an InitAck: see
    /// [`PassiveFrame::exceeds_negotiated_batch`].
    fn exceeds_batch(&self, wire_len: usize) -> bool {
        self.context
            .batch_size()
            .is_some_and(|max| wire_len > max as usize)
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
                    // R311y594 — the observation instant, which an observer
                    // takes from the capture rather than from the host (see
                    // `now_ms`). Stays 0 for a caller that never advances it,
                    // and a deadline armed at 0 against the default
                    // `u64::MAX` window is unreachable — so this is the
                    // previous behaviour until someone supplies a clock.
                    self.observed_at.unwrap_or(0),
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

    /// R311y645 (§1.1n / §4.37) — where a `Frame`'s payload begins within the
    /// message, when the bytes of that payload are the wire's own.
    ///
    /// The length is not re-derived from the layout: the payload is the
    /// message's TAIL, so everything ahead of it — the header, the sn and the
    /// Z-gated ext chain — is exactly the difference between what the decode
    /// consumed and what it kept. A reader that re-walked the header instead
    /// would be a second opinion on a length this walk already measured, and
    /// the two could disagree.
    ///
    /// Answers `None` for a COMPRESSED session even though the offset would be
    /// arithmetically available: what sits at that offset on the wire is an lz4
    /// block, and the batch's records were walked out of the decompressed
    /// bytes. Their offsets index a buffer this reader made.
    #[cfg(feature = "codec-frame")]
    fn batch_offset_of(
        &self,
        frame: &Result<InboundFrame, InboundParseError>,
        consumed: usize,
    ) -> Option<usize> {
        let Ok(InboundFrame::Frame { payload, .. }) = frame else {
            return None;
        };
        if self.context.compression_active() {
            return None;
        }
        consumed.checked_sub(payload.len())
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

    fn stream(&self, direction: Direction) -> &DirectionStream {
        match direction {
            Direction::A => &self.a,
            Direction::B => &self.b,
        }
    }
}

/// R311y609 — read a length prefix of `width` bytes at `at`.
///
/// The caller has already checked that `buf` holds them; a shared reader
/// because the resynchronisation scan must read prefixes exactly the way
/// [`PassiveSession::next_frame`] does, and a second copy of the width match
/// is a second place for the two to disagree.
fn read_prefix(buf: &[u8], at: usize, width: usize) -> usize {
    match width {
        PREFIX_WIDTH_LOWLATENCY => {
            u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize
        }
        _ => u16::from_le_bytes([buf[at], buf[at + 1]]) as usize,
    }
}

/// R311y609 — how one candidate frame in a resynchronisation chain came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidate {
    /// The bytes at this offset cannot be a frame, whatever arrives later.
    /// The scan may advance past this offset for good.
    Refuted,
    /// Consistent so far, and it ends at this absolute buffer index.
    Framed(usize),
    /// Not enough bytes to say, and `needed` is the buffer length at which it
    /// could be judged again.
    ///
    /// The number is carried rather than discarded because it is what keeps
    /// the scan affordable: no verdict anywhere in the buffer can change until
    /// the buffer reaches the SMALLEST `needed` among the unresolved
    /// candidates, so the whole walk is skipped until then.
    Short { needed: usize },
}

/// R311y609 — test the bytes at `at` as one framed transport message.
fn candidate_at(buf: &[u8], at: usize, width: usize) -> Candidate {
    if buf.len() < at + width {
        return Candidate::Short { needed: at + width };
    }
    let len = read_prefix(buf, at, width);
    if len == 0 || len > MAX_FRAME_PAYLOAD {
        return Candidate::Refuted;
    }
    if buf.len() < at + width + 1 {
        return Candidate::Short {
            needed: at + width + 1,
        };
    }
    if !wz_codecs::wire_const::is_credible_transport_header(buf[at + width]) {
        return Candidate::Refuted;
    }
    if buf.len() < at + width + len {
        return Candidate::Short {
            needed: at + width + len,
        };
    }
    Candidate::Framed(at + width + len)
}

/// R311y609 — how far past a desynchronisation the true boundary can hide.
///
/// Every transport frame is at most [`MAX_FRAME_PAYLOAD`] plus its prefix, so
/// ANY window of that many consecutive received bytes contains at least one
/// real frame boundary. That makes the window a guarantee rather than a
/// heuristic: a scan that crosses it without confirming anything has not been
/// unlucky, it has been looking at bytes whose framing it cannot recover.
pub const RESYNC_SCAN_WINDOW: usize = MAX_FRAME_PAYLOAD + PREFIX_WIDTH_LOWLATENCY;

impl DirectionStream {
    /// R311y609 — judge this direction desynchronised and start a scan.
    ///
    /// Consumes NOTHING. That is the load-bearing part: the scan begins at the
    /// suspect boundary itself, so a boundary hiding one byte later is found,
    /// and the frame offsets a consumer sees stay monotonic — a reader that
    /// had swallowed the suspect frame first would either lose up to 64 KiB of
    /// real bytes to a bogus length or have to report offsets that go
    /// backwards.
    fn desynchronise(&mut self, reason: DesyncReason) -> PassiveStall {
        let at_offset = self.consumed;
        if self.desync.is_none() {
            self.accounting.desyncs += 1;
            self.desync = Some(DesyncState {
                at_offset,
                reason,
                scan_cursor: 0,
                rescan_at: 0,
            });
        }
        PassiveStall::Desynchronised {
            stream_offset: at_offset,
            reason,
        }
    }

    /// R311y609 — look for a boundary `depth` chained frames agree on.
    ///
    /// Returns the recovery on success, having dropped the skipped bytes and
    /// cleared the desynchronised state. `None` means "not yet" — either the
    /// scan has no confirmable boundary in the bytes it holds, or `depth` is 0
    /// and recovery is switched off.
    ///
    /// # Why it does not stop at the first unresolved candidate
    ///
    /// It did, in the first version of this function, and the measurement is
    /// what caught it: `a_resync_scan_over_random_bytes` accepted a boundary
    /// in 0 of 400 noise buffers AT EVERY DEPTH, which is not a scan
    /// discriminating — it is a scan that never ran. A 2-byte prefix read off
    /// arbitrary bytes claims ~32 KiB on average, so nearly every candidate is
    /// short of data, and stopping on the first of them parked the cursor at
    /// the desynchronisation point forever. Real payload bytes do the same
    /// thing for the same reason.
    ///
    /// So an unresolved candidate no longer blocks the ones after it.
    /// CONFIRMED EVIDENCE BEATS UNRESOLVED POSSIBILITY: the scan may accept a
    /// later boundary while an earlier one is still unproven, and what makes
    /// that honest rather than sloppy is that [`StreamResync::skipped`] says
    /// how much it stepped over. The cursor still advances only across a
    /// CONTIGUOUS refuted prefix, so no offset is abandoned unexamined.
    fn try_resync(&mut self, width: usize, depth: usize) -> Option<StreamResync> {
        let state = self.desync?;
        if depth == 0 {
            return None;
        }
        // Nothing anywhere in the buffer can change verdict until it reaches
        // the smallest length some unresolved candidate was waiting for.
        // Without this the whole buffer is re-walked on every pushed segment.
        if self.buf.len() < state.rescan_at {
            return None;
        }
        let mut cursor = state.scan_cursor;
        let mut rescan_at = usize::MAX;
        let mut accepted = None;
        let mut candidate = cursor;
        while candidate < self.buf.len() {
            let mut at = candidate;
            let mut confirmed = 0usize;
            let verdict = loop {
                if confirmed == depth {
                    break Candidate::Framed(at);
                }
                match candidate_at(&self.buf, at, width) {
                    Candidate::Framed(next) => {
                        at = next;
                        confirmed += 1;
                    }
                    other => break other,
                }
            };
            match verdict {
                Candidate::Framed(_) => {
                    accepted = Some(candidate);
                    break;
                }
                // Refuted for good — the bytes cannot change. The cursor
                // follows only while the refutations are contiguous from it.
                Candidate::Refuted => {
                    if candidate == cursor {
                        cursor += 1;
                    }
                }
                // Unresolved. Remember when it could be judged again, and keep
                // looking at the offsets after it.
                Candidate::Short { needed } => rescan_at = rescan_at.min(needed),
            }
            candidate += 1;
        }
        let Some(offset) = accepted else {
            let state = self.desync.as_mut().expect("state was Some");
            state.scan_cursor = cursor;
            // Nothing unresolved means nothing to wait FOR: only a longer
            // buffer can change the answer.
            state.rescan_at = if rescan_at == usize::MAX {
                self.buf.len() + 1
            } else {
                rescan_at
            };
            // The window is a GUARANTEE, not a budget: any run of
            // `RESYNC_SCAN_WINDOW` received bytes holds at least one true
            // frame boundary. Having examined that many without confirming
            // one, this reader cannot recover the framing of those bytes, so
            // it drops them — bounded memory, and the skip stays visible in
            // the accounting because `skipped` is measured off `consumed`.
            if cursor > RESYNC_SCAN_WINDOW {
                let drop = cursor - RESYNC_SCAN_WINDOW;
                self.buf.drain(..drop);
                self.consumed += drop;
                let state = self.desync.as_mut().expect("state was Some");
                state.scan_cursor -= drop;
                state.rescan_at = state.rescan_at.saturating_sub(drop);
            }
            return None;
        };
        self.buf.drain(..offset);
        self.consumed += offset;
        self.desync = None;
        self.accounting.recoveries += 1;
        let skipped = self.consumed - state.at_offset;
        self.accounting.skipped_bytes += skipped as u64;
        Some(StreamResync {
            desync_offset: state.at_offset,
            reason: state.reason,
            resumed_offset: self.consumed,
            skipped,
            confirmed: depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::parse_inbound;
    use alloc::vec;

    /// R311y631 (§1.2b) — the ONE message a unit was expected to hold.
    ///
    /// Asserting the length here rather than indexing `[0]` is what keeps a
    /// single-message expectation honest: a walk that started reporting extra
    /// records would otherwise be invisible to every caller of this helper.
    fn sole(frames: Vec<PassiveFrame>) -> PassiveFrame {
        assert_eq!(
            frames.len(),
            1,
            "expected one message in this framing unit, got {}: {:?}",
            frames.len(),
            frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        frames.into_iter().next().expect("length asserted above")
    }

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
        establish(PassiveSession::new(), exts)
    }

    /// The handshake walk, over a session the caller built — so a test that
    /// needs a non-default construction (a reassembly window) drives the SAME
    /// handshake rather than a second copy of it that can drift from this one.
    fn establish(mut s: PassiveSession, exts: Vec<ExtEntryOwned>) -> PassiveSession {
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
    /// R311y609 — the direction is announced ONCE and then scans. With
    /// recovery switched off (`with_resync_depth(0)`) it is abandoned, which
    /// is the pre-R311y609 behaviour this test asserted before, kept as the
    /// arm that proves the recovery is what acts.
    #[test]
    fn an_oversize_prefix_desynchronises_instead_of_allocating() {
        let ll = || vec![unit_ext(est_ext::LOWLATENCY)];
        let mut s = PassiveSession::new().with_resync_depth(0);
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
                reason: DesyncReason::OversizeLength {
                    claimed_len: 0x00FF_FFFF
                },
            }),
            "the guard fires with the offending offset and the length it asked for"
        );
        // Abandoned: more bytes do not revive the direction at depth 0.
        s.push(
            Direction::A,
            &framed(&[wz_codecs::wire_const::T_MID_KEEP_ALIVE], 4),
        );
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes),
            "a desynchronised direction stays abandoned when recovery is off"
        );
        // The announcement is not repeated: a caller that polls must not see
        // the same desynchronisation a thousand times.
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes),
            "the desynchronisation is announced once, not on every call"
        );
        assert_eq!(
            s.resync_accounting(Direction::A).desyncs,
            1,
            "and it is counted once"
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
        assert_eq!(
            s.resync_accounting(Direction::B),
            ResyncAccounting::default()
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

    /// R311y594 — a chain that never completes EXPIRES once the clock passes
    /// its window, and the expiry is COUNTED.
    ///
    /// The half-chain is left open deliberately: this is the live-tap shape,
    /// where the second fragment never arrives and the quota alone would hold
    /// the slot for as long as the reader runs.
    #[cfg(feature = "reassembly")]
    #[test]
    fn an_abandoned_chain_expires_once_the_observed_clock_passes_the_window() {
        let mut s = establish(PassiveSession::with_reassembly_window(5_000), vec![]);
        let record = oam_record(9);
        let (head, _) = record.split_at(1);

        s.push(Direction::A, &framed(&fragment_wire(0, true, head), 2));
        s.next_frame(Direction::A).expect("fragment 1");

        // The deadline was armed at the clock's value when the chain opened,
        // which is 0 — nothing has advanced it yet.
        assert_eq!(
            s.observe_at(4_999),
            0,
            "a chain inside its window must not be aborted"
        );
        assert_eq!(s.observe_at(5_000), 1, "the deadline is reached AT 5_000");
        assert_eq!(
            s.observe_at(60_000),
            0,
            "an expired chain is gone, not expired again on every sweep"
        );
        assert_eq!(s.now_ms(), 60_000);
    }

    /// The CONTROL that keeps the test above from passing on an expiry that
    /// fires unconditionally: the default constructor's window is unreachable,
    /// so the same abandoned chain survives a clock advanced past any deadline
    /// a caller could have meant.
    ///
    /// This is also the compatibility claim — every pre-R311y594 consumer built
    /// with `new()` and none of them acquired an expiry by upgrading.
    #[cfg(feature = "reassembly")]
    #[test]
    fn the_default_observer_has_no_reachable_deadline() {
        let mut s = established(vec![]);
        let record = oam_record(9);
        let (head, _) = record.split_at(1);

        s.push(Direction::A, &framed(&fragment_wire(0, true, head), 2));
        s.next_frame(Direction::A).expect("fragment 1");

        assert_eq!(
            s.observe_at(u64::MAX - 1),
            0,
            "the default window is unreachable, so nothing may expire"
        );
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
    ///
    /// R311y713 — gated on BOTH features it uses, not on one of them. The
    /// tables are `all(dissect, codec-declare)` and this asked for
    /// `codec-declare` alone, so any selection carrying the second without the
    /// first failed to compile the test build. Found by `cargo clippy -p
    /// wz-capture -p wz-session-core`, a selection no lane makes: the arms
    /// C1bn does make each happened to carry both or neither.
    #[cfg(all(feature = "dissect", feature = "codec-declare"))]
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
                    // R311y804: the body's own Z-gated chain, absent here for the
                    // reason the header comment above already gives.
                    extensions: None,
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

    /// R311y585 (A5) — the negotiated ceiling gets a consumer, and the
    /// control leg is what makes it mean anything: the SAME frame is not a
    /// violation when the ceiling is large, and is one when it is small.
    #[test]
    fn a_frame_over_the_negotiated_batch_size_is_flagged_not_dropped() {
        // The fixture InitAck advertises no S-bit fields, so the ceiling is
        // the wire default 65535 and nothing can exceed it.
        let mut wide = established(vec![]);
        assert_eq!(wide.context().batch_size(), Some(65535));
        let payload = alloc::vec![0x5Au8; 64];
        wide.push(Direction::A, &framed(&frame_wire(0, &payload), 2));
        let f = wide.next_frame(Direction::A).expect("frame");
        assert!(
            !f.exceeds_negotiated_batch,
            "a frame well under the ceiling must not be flagged"
        );

        // Now the same frame against a session whose acceptor agreed to 16.
        let mut narrow = PassiveSession::new();
        narrow.context.caps = Some(crate::peer_init_caps::PeerInitCaps {
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 16,
        });
        narrow.push(Direction::A, &framed(&frame_wire(0, &payload), 2));
        let g = narrow.next_frame(Direction::A).expect("frame");
        assert!(
            g.exceeds_negotiated_batch,
            "a frame past the ceiling the acceptor agreed to is a violation"
        );
    }

    /// Before an InitAck there is no ceiling, so there is nothing to exceed.
    /// Guessing one and reporting a violation against it would be worse than
    /// reporting none.
    #[test]
    fn an_unknown_ceiling_cannot_be_exceeded() {
        let mut s = PassiveSession::new();
        assert_eq!(s.context().batch_size(), None);
        s.push(Direction::A, &framed(&init_wire(false, vec![]), 2));
        let f = s.next_frame(Direction::A).expect("init");
        assert!(!f.exceeds_negotiated_batch);
    }

    // ─── R311y609 — desynchronisation: detection, then recovery ───

    /// A body that opens with a byte no transport header can be. All-zero
    /// after the first byte, so every candidate offset INSIDE it reads a
    /// zero-length prefix and is refuted for good — which makes the
    /// resynchronisation scan below deterministic instead of data-dependent.
    fn bogus_frame(header: u8) -> Vec<u8> {
        let mut body = vec![header];
        body.extend_from_slice(&[0u8; 20]);
        framed(&body, 2)
    }

    /// THE DEFECT R311y609 CLOSES, stated as the thing that used to happen.
    ///
    /// A stream read at the wrong boundary frames arbitrary payload bytes, and
    /// `parse_inbound` answers `Unknown { mid }` for 25 of the 32 MID values —
    /// an `Ok`. Nothing above the framing could tell a wrong boundary from a
    /// message this build cannot name, so the reader walked the whole capture
    /// misframed, reporting confident nonsense. The first assertion is that
    /// old behaviour, which still holds one layer down; the second is the
    /// layer that now refuses it.
    #[test]
    fn a_body_that_cannot_be_a_transport_header_desynchronises_rather_than_decoding() {
        // 0x1F is not a transport MID, and the decoder says so with an `Ok`.
        assert!(matches!(
            parse_inbound(&[0x1F, 0xAA, 0xBB]),
            Ok(InboundFrame::Unknown { mid: 0x1F })
        ));

        let mut s = PassiveSession::new();
        s.push(Direction::A, &bogus_frame(0x1F));
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::Desynchronised {
                stream_offset: 0,
                reason: DesyncReason::ImplausibleHeader { header: 0x1F },
            }),
            "the boundary is judged before the body is trusted"
        );
        assert_eq!(s.resync_accounting(Direction::A).desyncs, 1);
    }

    /// The detector fires on the HEADER, which arrives with the prefix, not
    /// after the body. A wrong 2-byte prefix routinely frames tens of
    /// kilobytes; a reader that waited for them would begin its scan far past
    /// the boundary it is looking for.
    #[test]
    fn the_boundary_is_judged_before_the_body_has_arrived() {
        let mut s = PassiveSession::new();
        // Prefix claims 60000 bytes; only the prefix and one header byte are
        // pushed.
        s.push(Direction::A, &[0x60, 0xEA, 0x1F]);
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::Desynchronised {
                stream_offset: 0,
                reason: DesyncReason::ImplausibleHeader { header: 0x1F },
            }),
            "3 bytes are enough to refuse a 60002-byte frame"
        );
    }

    /// A zero-length frame is a boundary error, not a message: every transport
    /// message is at least its own header byte.
    #[test]
    fn a_zero_length_prefix_desynchronises() {
        let mut s = PassiveSession::new();
        s.push(Direction::A, &[0x00, 0x00, 0x04]);
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::Desynchronised {
                stream_offset: 0,
                reason: DesyncReason::EmptyFrame,
            })
        );
    }

    /// THE RECOVERY. A capture with a hole desynchronises, scans, and resumes
    /// at the true boundary — reporting how far it skipped and on how much
    /// evidence, so the hole is visible rather than silently closed.
    #[test]
    fn a_desynchronised_stream_resumes_at_the_true_boundary() {
        let good: Vec<Vec<u8>> = (0..DEFAULT_RESYNC_DEPTH as u64)
            .map(|i| framed(&frame_wire(i, &oam_record(i)), 2))
            .collect();
        let bogus = bogus_frame(0x1F);

        let mut s = PassiveSession::new();
        s.push(Direction::A, &bogus);
        assert!(s.next_frame(Direction::A).is_err(), "desynchronises");
        for g in &good {
            s.push(Direction::A, g);
        }
        let f = s
            .next_frame(Direction::A)
            .expect("the scan finds the boundary");
        assert_eq!(
            f.resync,
            Some(StreamResync {
                desync_offset: 0,
                reason: DesyncReason::ImplausibleHeader { header: 0x1F },
                resumed_offset: bogus.len(),
                skipped: bogus.len(),
                confirmed: DEFAULT_RESYNC_DEPTH,
            }),
            "the recovery names the hole it stepped over"
        );
        assert!(
            matches!(f.frame, Ok(InboundFrame::Frame { sn: 0, .. })),
            "and the frame it resumed on is the real one"
        );
        // The rest of the stream decodes normally, and carries no resync.
        for expect in 1..DEFAULT_RESYNC_DEPTH as u64 {
            let f = s.next_frame(Direction::A).expect("continues");
            assert_eq!(f.resync, None, "the recovery is reported once");
            assert!(matches!(f.frame, Ok(InboundFrame::Frame { sn, .. }) if sn == expect));
        }
        let acc = s.resync_accounting(Direction::A);
        assert_eq!(
            acc,
            ResyncAccounting {
                desyncs: 1,
                recoveries: 1,
                skipped_bytes: bogus.len() as u64,
            }
        );
    }

    /// The scan will not resume on THIN evidence: one frame short of the depth
    /// is still a stall, and the frame that completes the chain is what
    /// releases it. Without this the depth would be a decoration — a scan that
    /// accepted whatever was buffered would pass the test above too.
    #[test]
    fn a_resync_needs_its_whole_chain_before_it_resumes() {
        let good: Vec<Vec<u8>> = (0..DEFAULT_RESYNC_DEPTH as u64)
            .map(|i| framed(&frame_wire(i, &oam_record(i)), 2))
            .collect();
        let mut s = PassiveSession::new();
        s.push(Direction::A, &bogus_frame(0x1F));
        assert!(s.next_frame(Direction::A).is_err());

        for (i, g) in good.iter().enumerate() {
            s.push(Direction::A, g);
            if i + 1 < DEFAULT_RESYNC_DEPTH {
                assert_eq!(
                    s.next_frame(Direction::A).err(),
                    Some(PassiveStall::NeedMoreBytes),
                    "{} of {DEFAULT_RESYNC_DEPTH} frames is not a boundary",
                    i + 1
                );
            }
        }
        assert!(
            s.next_frame(Direction::A).is_ok(),
            "the last frame of the chain releases the scan"
        );
    }

    /// A candidate that failed for LACK OF BYTES is not refuted, and the scan
    /// cursor must park on it rather than step past. The arm that shows it: a
    /// boundary whose confirming chain arrives one byte at a time — a scan
    /// that advanced past viable offsets would have walked off the true one
    /// long before the bytes that prove it.
    #[test]
    fn the_scan_cursor_parks_on_a_viable_candidate_rather_than_stepping_past() {
        let good: Vec<u8> = (0..DEFAULT_RESYNC_DEPTH as u64)
            .flat_map(|i| framed(&frame_wire(i, &oam_record(i)), 2))
            .collect();
        let mut s = PassiveSession::new();
        s.push(Direction::A, &bogus_frame(0x1F));
        assert!(s.next_frame(Direction::A).is_err());
        for byte in &good {
            s.push(Direction::A, &[*byte]);
            let _ = s.next_frame(Direction::A);
        }
        let acc = s.resync_accounting(Direction::A);
        assert_eq!(
            acc.recoveries, 1,
            "the boundary is still found byte by byte"
        );
    }

    /// R311y611 (§1.4b) — THE TWO LISTS A STREAM READER CONSULTS, PINNED
    /// AGAINST EACH OTHER.
    ///
    /// A stream reader asks two different questions of the same byte, and only
    /// one of them exists on a datagram link: `parse_inbound` asks "what
    /// message is this", and `is_credible_transport_header` asks "could a
    /// conforming sender have written this at all". Nothing compared them, and
    /// they disagree on FOURTEEN of the 256 values.
    ///
    /// Every one of the fourteen is a known MID with a RESERVED bit set — the
    /// decoder dispatches on `header & 0x1F` and ignores those bits, exactly as
    /// zenoh's own decoder does, while the gate refuses the byte. This test
    /// exists to say that the asymmetry is DELIBERATE and to catch it moving:
    /// the stream reader loses such a frame and NAMES the loss
    /// (`DesyncReason::ImplausibleHeader` plus a `StreamResync` counting the
    /// skip), which is the honest half; a datagram reader decodes it and
    /// reports the bits in [`PassiveFrame::reserved_header_bits`], which is the
    /// other half. Relaxing the gate to close the gap was TRIED and measured:
    /// it costs recoveries on the unannounced path, because acceptance goes
    /// from 42 of 256 to 56.
    ///
    /// A SECOND class of disagreement joined when `parse_inbound` learned
    /// transport OAM: eight more values, named by the decoder and refused by
    /// the gate, and refused for a different reason — `0x00` is the weakest
    /// byte in the space to resume a lost stream on, and admitting it was
    /// measured to take the resync scan's worst trial from 42% recovered to 0%
    /// at 8192 bytes of noise. The assertion below PARTITIONS the two classes
    /// rather than widening the count, because a single number would let
    /// either reason drift into the other's slot.
    #[test]
    // R311y631 (§7.10) — `reassembly` joined the list because the ASSERTION
    // reads it. `is_credible_transport_header` accepts `T_MID_FRAGMENT`
    // (`0x06`) unconditionally, and the arm of `parse_inbound` that names it is
    // gated on `reassembly`; without the feature the byte is credible and
    // `Unknown`, and this test fails on eight values for a reason that has
    // nothing to do with what it is about. Its guard has to select every
    // feature its claim depends on, not most of them — the same rule this
    // workspace applies to a negative arm's `#[cfg]`.
    #[cfg(all(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-frame",
        feature = "codec-join",
        feature = "reassembly"
    ))]
    fn the_header_gate_and_the_decoder_disagree_on_reserved_bits_and_on_oam() {
        use crate::inbound::InboundFrame;
        use wz_codecs::wire_const::{is_credible_transport_header, reserved_transport_flags};

        let mut refused_but_named = alloc::vec![];
        let mut accepted_but_unnamed = alloc::vec![];
        for header in 0u8..=255 {
            // A bare header is enough: `parse_inbound` answers
            // `Unknown { mid }` for a MID it does not dispatch, and anything
            // else — a decode error included — means it RECOGNISED the MID.
            let named = !matches!(parse_inbound(&[header]), Ok(InboundFrame::Unknown { .. }));
            match (is_credible_transport_header(header), named) {
                (false, true) => refused_but_named.push(header),
                (true, false) => accepted_but_unnamed.push(header),
                _ => {}
            }
        }
        assert!(
            accepted_but_unnamed.is_empty(),
            "with every codec compiled, a byte the gate calls credible must be \
             a byte this build can name: {accepted_but_unnamed:02X?}"
        );
        // The refusals split into TWO classes with two different reasons, and
        // partitioning them here is what keeps the second from being read as a
        // wider version of the first.
        let (oam, reserved_bits): (Vec<u8>, Vec<u8>) = refused_but_named
            .into_iter()
            .partition(|h| h & 0x1F == wz_codecs::wire_const::T_MID_OAM);
        assert_eq!(
            reserved_bits.len(),
            14,
            "4 CLOSE + 6 KEEP_ALIVE + 4 FRAME, each with a bit its MID does \
             not define: {reserved_bits:02X?}"
        );
        for header in reserved_bits {
            let reserved = reserved_transport_flags(header)
                .expect("a named MID is a known MID, so the mask exists");
            assert_ne!(
                reserved, 0,
                "{header:#04x} is refused for a reason other than a reserved \
                 bit — the gate and the decoder have drifted on something this \
                 test does not describe"
            );
        }
        // The SECOND class: transport OAM. All eight of its header bytes are
        // named by the decoder and refused by the gate, and unlike the
        // fourteen above the reason is not a reserved bit — the MID is absent
        // from `transport_flag_mask` on purpose, because `0x00` is the weakest
        // byte in the space to RESUME a lost stream on. The price of admitting
        // it was measured (`wz_codecs::wire_const`'s
        // `oam_is_a_transport_mid_this_gate_still_refuses`): the worst trial of
        // the resync scan below fell from 42% recovered to 0% at 8192 bytes of
        // noise.
        //
        // Eight, not six: the reserved 0b11 encoding is named too, because the
        // decoder REFUSES it and a refusal is a recognition — see
        // `InboundParseError::ReservedEncoding`.
        assert_eq!(
            oam.len(),
            8,
            "every OAM header must be named and refused, not some of them: \
             {oam:02X?}"
        );
        for header in oam {
            assert_eq!(
                reserved_transport_flags(header),
                None,
                "{header:#04x} has a flag mask, so it is in the gate's table \
                 after all and this partition is describing the wrong thing"
            );
        }
    }

    /// R311y611 (§1.4b) — and the datagram path REPORTS the bits it decodes
    /// past, which before this round nothing did.
    #[test]
    fn a_datagram_reports_the_reserved_header_bits_it_decoded_past() {
        let mut s = PassiveSession::new();
        // KEEP_ALIVE defines no flag but Z, so 0x40 is reserved.
        let clean = sole(s.next_datagram(Direction::A, &[crate::wire_const::T_MID_KEEP_ALIVE], 0));
        assert_eq!(clean.reserved_header_bits, 0, "the control arm");
        assert!(clean.frame.is_ok());

        let odd = sole(s.next_datagram(
            Direction::A,
            &[crate::wire_const::T_MID_KEEP_ALIVE | 0x40],
            0,
        ));
        assert_eq!(
            odd.reserved_header_bits, 0x40,
            "the peer set a bit this wire-spec vintage does not define, and \
             the frame decodes anyway — so the bit is the only evidence"
        );
        assert!(
            odd.frame.is_ok(),
            "reporting it must not turn a decodable message into an error: \
             zenoh's own decoder ignores the bit"
        );
    }

    /// R311y630 (§14.1) — THE OBSERVER'S HALF of the mandatory-extension rule.
    ///
    /// A participant refuses such a frame and the link goes down; a capture
    /// reader must still decode it AND say what is wrong with it, because
    /// "this frame carries a mandatory extension nothing defines" is the whole
    /// explanation for a session that keeps dying and is the one sentence
    /// neither implementation's own logs will produce for the person holding
    /// the capture.
    ///
    /// Two arms, and the control one is the discriminator: an analyzer that
    /// simply refused every unrecognised extension would satisfy the first
    /// assertion and would ALSO flag the non-mandatory chains zenoh and pico
    /// both skip — which is most real traffic.
    #[test]
    #[cfg(feature = "codec-keep-alive")]
    fn a_datagram_reports_the_undefined_mandatory_extension_it_decoded() {
        let mut s = PassiveSession::new();
        // KEEP_ALIVE + Z, then one ext: id 0x4, UNIT, chain terminator.
        let header = crate::wire_const::T_MID_KEEP_ALIVE | crate::wire_const::FLAG_T_Z;

        let clean = sole(s.next_datagram(Direction::A, &[header, 0x04], 0));
        assert_eq!(clean.undefined_mandatory_ext, None, "the control arm");
        assert!(clean.frame.is_ok());
        assert_eq!(s.undefined_mandatory_exts(Direction::A), 0);

        // The same extension with the mandatory marker set.
        let flagged = sole(s.next_datagram(Direction::A, &[header, 0x14], 0));
        assert_eq!(
            flagged.undefined_mandatory_ext,
            Some(0x14),
            "the peer marked an extension mandatory that KEEP_ALIVE's space \
             does not define — both upstreams refuse the message on that"
        );
        assert!(
            flagged.frame.is_ok(),
            "reporting it must not cost the analyzer the DECODE: the observer's \
             contribution is naming the fault, not repeating the refusal"
        );
        assert_eq!(s.undefined_mandatory_exts(Direction::A), 1);
        assert_eq!(
            s.undefined_mandatory_exts(Direction::B),
            0,
            "the counter is per direction"
        );
    }

    /// R311y610 (§4.1) — the SOURCE says it lost bytes, and that is evidence
    /// this reader could never have derived from the bytes themselves.
    ///
    /// Announced at a boundary that is in fact intact, so the scan confirms
    /// offset 0 and skips nothing: the point is that the reason survives to the
    /// frame that resumes, because a consumer told "the framing restarted here"
    /// acts differently depending on whether the capture lost bytes or this
    /// reader mis-read them.
    #[test]
    fn a_gap_the_source_reports_desynchronises_the_direction_it_names() {
        let good: Vec<u8> = (0..DEFAULT_RESYNC_DEPTH as u64)
            .flat_map(|i| framed(&frame_wire(i, &oam_record(i)), 2))
            .collect();
        let mut s = PassiveSession::new();
        assert!(
            s.note_gap(Direction::A, 37),
            "the first announcement is what desynchronises"
        );
        assert!(
            !s.note_gap(Direction::A, 11),
            "a second hole inside the same scan must not restate the offset"
        );
        assert_eq!(
            s.resync_accounting(Direction::A).desyncs,
            1,
            "one scan, not one per hole"
        );
        // The OTHER direction is untouched: a hole is a property of one
        // half-connection, and both share this session's context.
        assert_eq!(s.resync_accounting(Direction::B).desyncs, 0);
        assert!(matches!(
            s.next_frame(Direction::B),
            Err(PassiveStall::NeedMoreBytes)
        ));

        s.push(Direction::A, &good);
        let frame = s.next_frame(Direction::A).expect("the chain confirms 0");
        let resync = frame.resync.expect("the resumption is reported");
        assert_eq!(
            (resync.desync_offset, resync.resumed_offset, resync.skipped),
            (0, 0, 0),
            "the announced boundary was intact, so nothing is stepped over"
        );
        assert_eq!(
            resync.reason,
            DesyncReason::CaptureGap { bytes_missing: 37 },
            "the FIRST hole's size, and it is not an inference"
        );
    }

    /// R311y610 (§4.3) — the scan's memory bound, which had no test.
    ///
    /// [`RESYNC_SCAN_WINDOW`] is a GUARANTEE: any run of that many received
    /// bytes contains a real frame boundary, so a scan that crosses it without
    /// confirming one cannot recover those bytes and drops them. Reaching the
    /// branch needs a scan that refutes 64 KiB, and every corpus built from
    /// plausible bytes recovers long before that — so this one refuses at every
    /// offset by construction: a zero length prefix is refuted whatever follows
    /// it, so a run of zeros has no viable candidate anywhere in it.
    #[test]
    fn a_scan_that_confirms_nothing_drops_the_bytes_it_cannot_frame() {
        let noise = alloc::vec![0u8; RESYNC_SCAN_WINDOW + 4096];
        let mut s = PassiveSession::new();
        assert!(s.note_gap(Direction::A, 0));
        s.push(Direction::A, &noise);
        assert!(matches!(
            s.next_frame(Direction::A),
            Err(PassiveStall::NeedMoreBytes)
        ));
        assert_eq!(
            s.buffered(Direction::A),
            RESYNC_SCAN_WINDOW + 1,
            "the unframeable bytes past the window are dropped, not retained \
             — and the ONE extra is the last byte, which is short of a length \
             prefix and so unresolved rather than refuted, which is exactly \
             the distinction the cursor is not allowed to blur"
        );

        // And the drop is VISIBLE: the recovery names every byte it stepped
        // over, including the ones no longer held.
        let good: Vec<u8> = (0..DEFAULT_RESYNC_DEPTH as u64)
            .flat_map(|i| framed(&frame_wire(i, &oam_record(i)), 2))
            .collect();
        s.push(Direction::A, &good);
        let frame = s.next_frame(Direction::A).expect("the chain confirms");
        let resync = frame.resync.expect("the resumption is reported");
        assert_eq!(
            resync.skipped,
            noise.len(),
            "skipped counts the dropped bytes too, or the accounting would \
             lose exactly what memory did"
        );
        assert_eq!(
            s.resync_accounting(Direction::A).skipped_bytes,
            noise.len() as u64
        );
    }

    /// THE MEASUREMENT THE DEFAULT DEPTH IS CHOSEN FROM.
    ///
    /// The question is not "does the scan accept noise" but "given `noise`
    /// bytes between the desynchronisation and the true boundary, does it land
    /// ON the boundary", so the corpus is noise FOLLOWED BY a real chain and
    /// the verdict is compared against the offset the boundary is known to be
    /// at.
    ///
    /// An earlier version measured pure noise in a 4096-byte buffer and got
    /// 0/400 at every depth. That number was an artefact twice over: the scan
    /// was parked (see [`DirectionStream::try_resync`]), and once unparked a
    /// buffer that small refutes most candidates for free, because a 2-byte
    /// prefix off arbitrary bytes claims ~32 KiB and there is nowhere to put
    /// it. Both would have read as "the depth discriminates beautifully".
    ///
    /// A wrong boundary is also SELF-CORRECTING and visible: the chain is only
    /// `d` frames long, so the reader desynchronises again within a few frames
    /// and the accounting shows repeated recoveries. That is why a rate in the
    /// low percent is a usable answer rather than a disqualifying one.
    #[test]
    fn the_resync_scan_lands_on_the_true_boundary_across_noise() {
        // xorshift64*, so the corpus is deterministic across machines and
        // across runs — a measurement nobody can reproduce is an anecdote.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        const TRIALS: usize = 10;
        // The real region must be LONGER THAN ONE MAXIMUM FRAME, and finding
        // that out is itself a result: a shorter one let the reader's very
        // first read swallow a plausible-but-bogus 60 KB length, jump past
        // every real frame, and stall on `NeedMoreBytes` having never
        // desynchronised at all. That is not an artefact of the fixture — it
        // is what a mid-frame attach does to a flow that then ENDS, and it is
        // recorded in this round's carry rather than papered over here.
        const REAL_FRAMES: u64 = 12_000;
        let one = |i: u64| framed(&frame_wire(i, &oam_record(i)), 2);
        let real: Vec<u8> = (0..REAL_FRAMES).flat_map(one).collect();
        assert!(
            real.len() > MAX_FRAME_PAYLOAD,
            "the fixture must outlast one bogus maximum-length frame"
        );

        // The offsets a correctly-framed reader would report, for a given
        // amount of noise in front of the real chain.
        let boundaries = |noise_len: usize| -> alloc::collections::BTreeSet<usize> {
            let mut at = noise_len;
            (0..REAL_FRAMES)
                .map(|i| {
                    let here = at;
                    at += one(i).len();
                    here
                })
                .collect()
        };

        let mut worst_at_default = usize::MAX;
        for noise_len in [512usize, 8192, 65536] {
            // ONE corpus per noise length, reused across depths: an unpaired
            // sweep made a deeper chain look WORSE than a shallower one, which
            // a depth-`d+1` chain being a depth-`d` chain forbids, and that
            // impossibility is how the flaw was spotted.
            let corpus: Vec<Vec<u8>> = (0..TRIALS)
                .map(|_| {
                    let mut buf: Vec<u8> = (0..noise_len).map(|_| (next() >> 24) as u8).collect();
                    buf.extend_from_slice(&real);
                    buf
                })
                .collect();
            let truth = boundaries(noise_len);
            for depth in [4usize, 6, 8] {
                let mut worst_recovered = usize::MAX;
                let mut total_resyncs = 0usize;
                let mut trials_without_recovery = 0usize;
                let mut wrong_after_last_resync = 0usize;
                let mut worst_lead_in = 0usize;
                for buf in &corpus {
                    // END TO END, through the real entry point: a scan that
                    // resumes on a framing which steps over the boundary is
                    // not stuck there — the next implausible header
                    // desynchronises it again, and the rescan starts closer.
                    // Judging the scan on ONE acceptance would have scored
                    // that self-correction as a permanent failure.
                    let mut s = PassiveSession::new().with_resync_depth(depth);
                    s.push(Direction::A, buf);
                    let mut recovered = 0usize;
                    let mut resyncs_here = 0usize;
                    // After the LAST recovery: how many frames the reader
                    // reports before its framing rejoins the true boundaries
                    // (`lead_in`), and how many it reports off them AFTERWARDS
                    // (`drift`). The second must be zero — a framing that
                    // rejoined the truth and then left it again is the
                    // confident-nonsense failure this round exists to remove.
                    let (mut lead_in, mut drift, mut rejoined) = (0usize, 0usize, false);
                    loop {
                        match s.next_frame(Direction::A) {
                            Ok(f) => {
                                if f.resync.is_some() {
                                    total_resyncs += 1;
                                    resyncs_here += 1;
                                    lead_in = 0;
                                    drift = 0;
                                    rejoined = false;
                                }
                                if truth.contains(&f.stream_offset) {
                                    recovered += 1;
                                    rejoined = true;
                                } else if rejoined {
                                    drift += 1;
                                } else {
                                    lead_in += 1;
                                }
                            }
                            Err(PassiveStall::Desynchronised { .. }) => {}
                            Err(PassiveStall::NeedMoreBytes) => break,
                        }
                    }
                    if resyncs_here == 0 {
                        trials_without_recovery += 1;
                    }
                    wrong_after_last_resync += drift;
                    worst_lead_in = worst_lead_in.max(lead_in);
                    worst_recovered = worst_recovered.min(recovered);
                }
                let pct = worst_recovered * 100 / truth.len();
                std::eprintln!(
                    "noise {noise_len:>5}  depth {depth:>2}: worst trial kept \
                     {worst_recovered:>5} of {} real frames ({pct}%), \
                     {total_resyncs} resyncs, {trials_without_recovery} trials \
                     never recovered, lead-in {worst_lead_in}, drift \
                     {wrong_after_last_resync}, over {TRIALS} trials",
                    truth.len()
                );
                if depth == DEFAULT_RESYNC_DEPTH {
                    worst_at_default = worst_at_default.min(pct);
                    // THE TWO CLAIMS THIS ROUND MAKES, and neither is "the
                    // first accepted boundary is always right" — at long noise
                    // runs it is not, and it does not need to be, because a
                    // wrong resume is corrected by the next desynchronisation.
                    //
                    // (1) Recovery is REACHABLE: a hole no longer ends the
                    //     direction. Today's number here is 0 of 10 trials.
                    assert_eq!(
                        trials_without_recovery, 0,
                        "noise {noise_len}: a trial never recovered its framing"
                    );
                    // (2) Recovery STICKS: once the reader has resumed for the
                    //     last time, every frame it reports sits on a real
                    //     boundary. A recovery that drifted again would be the
                    //     confident-nonsense failure this whole round exists
                    //     to remove.
                    assert_eq!(
                        wrong_after_last_resync, 0,
                        "noise {noise_len}: the framing rejoined the true \
                         boundaries and then left them again"
                    );
                    // The lead-in is the cost of resuming a frame or two early
                    // on a chain that runs INTO the boundary. Bounded, not
                    // zero, and bounded is the honest claim.
                    assert!(
                        worst_lead_in <= 8,
                        "noise {noise_len}: {worst_lead_in} frames before the \
                         framing rejoined the truth"
                    );
                }
            }
        }
        // The FRACTION kept is a weaker number and it is reported rather than
        // pinned tight, because what limits it is not the scan: the loss is
        // identical at every depth, and its cause is a read that happens
        // BEFORE any desynchronisation — a 2-byte prefix off arbitrary bytes
        // claims up to 65535, and a credible header behind it (42 of 256) is
        // enough for the reader to swallow that much real data as one frame.
        // Nothing in the framing refutes it. That is a SECOND defect, measured
        // here and carried, not fixed by resynchronisation.
        assert!(
            worst_at_default >= 30,
            "at depth {DEFAULT_RESYNC_DEPTH} the worst trial kept only \
             {worst_at_default}% of the real frames after the hole"
        );
    }

    /// Recovery OFF is a real setting, not a rhetorical one: at depth 0 the
    /// scan never runs and the direction stays abandoned however many frames
    /// arrive. The damage-probe arm for every test above.
    #[test]
    fn depth_zero_abandons_the_direction_exactly_as_before() {
        let mut s = PassiveSession::new().with_resync_depth(0);
        s.push(Direction::A, &bogus_frame(0x1F));
        assert!(s.next_frame(Direction::A).is_err());
        for i in 0..(DEFAULT_RESYNC_DEPTH as u64 * 4) {
            s.push(Direction::A, &framed(&frame_wire(i, &oam_record(i)), 2));
        }
        assert_eq!(
            s.next_frame(Direction::A).err(),
            Some(PassiveStall::NeedMoreBytes),
            "no amount of evidence revives a direction whose recovery is off"
        );
        assert_eq!(s.resync_accounting(Direction::A).recoveries, 0);
    }

    // ─── R311y609 (C12) — sequence-number loss accounting ───

    /// The plane this closes: a reader that sees frames 0, 1, 5 must be able
    /// to say THREE were lost, and say it per conduit.
    #[test]
    fn a_sequence_number_gap_counts_the_frames_the_reader_never_saw() {
        let mut s = established(vec![]);
        assert!(
            s.context().sn_mask().is_some(),
            "an InitAck was observed, so the ring is known"
        );
        for sn in [0u64, 1, 5, 6] {
            s.push(Direction::A, &framed(&frame_wire(sn, &oam_record(sn)), 2));
        }
        let verdicts: Vec<Option<SnVerdict>> = (0..4)
            .map(|_| s.next_frame(Direction::A).expect("frame").sn_verdict)
            .collect();
        assert_eq!(
            verdicts,
            vec![
                Some(SnVerdict::Baseline),
                Some(SnVerdict::Continuous),
                Some(SnVerdict::Gap { missing: 3 }),
                Some(SnVerdict::Continuous),
            ]
        );
        let acc = s.sn_accounting(Direction::A);
        assert_eq!(acc.frames, 4);
        assert_eq!(acc.missing, 3);
        assert_eq!(acc.gaps, 1);
        assert_eq!(acc.duplicates, 0);
        assert_eq!(acc.without_resolution, 0);
        // The peer direction is a separate account.
        assert_eq!(s.sn_accounting(Direction::B), SnAccounting::default());
    }

    /// A message that carries no sequence number gets no verdict — otherwise a
    /// keepalive-only stretch of a capture would read as loss.
    #[test]
    fn a_message_without_a_sequence_number_gets_no_verdict() {
        let mut s = established(vec![]);
        s.push(
            Direction::A,
            &framed(&[wz_codecs::wire_const::T_MID_KEEP_ALIVE], 2),
        );
        assert_eq!(s.next_frame(Direction::A).expect("ka").sn_verdict, None);
        assert_eq!(s.sn_accounting(Direction::A).frames, 0);
    }

    /// Without an InitAck there is no ring mask, and a gap verdict would be
    /// arbitrary: too wide reads a wraparound as a gap, too narrow the
    /// reverse. The population of unjudged frames is COUNTED, because
    /// `missing = 0` is unreadable without it.
    #[test]
    fn an_unresolved_session_reports_absence_rather_than_a_gap() {
        let mut s = PassiveSession::new();
        assert_eq!(s.context().sn_mask(), None);
        for sn in [0u64, 9] {
            s.push(Direction::A, &framed(&frame_wire(sn, &oam_record(sn)), 2));
        }
        for _ in 0..2 {
            assert_eq!(
                s.next_frame(Direction::A).expect("frame").sn_verdict,
                Some(SnVerdict::WithoutResolution)
            );
        }
        let acc = s.sn_accounting(Direction::A);
        assert_eq!(acc.without_resolution, 2);
        assert_eq!((acc.missing, acc.gaps), (0, 0), "absence is not zero loss");
    }

    /// A duplicate and a reorder are NOT loss, and neither may move the
    /// baseline — the rule `RxSn::admit` applies on the participant side. A
    /// tracker that let a stale SN rewind the counter would fabricate a gap
    /// out of the next in-order frame.
    #[test]
    fn a_duplicate_and_a_reorder_are_not_counted_as_loss() {
        let mut s = established(vec![]);
        for sn in [4u64, 5, 5, 3, 6] {
            s.push(Direction::A, &framed(&frame_wire(sn, &oam_record(sn)), 2));
        }
        let verdicts: Vec<Option<SnVerdict>> = (0..5)
            .map(|_| s.next_frame(Direction::A).expect("frame").sn_verdict)
            .collect();
        assert_eq!(
            verdicts,
            vec![
                Some(SnVerdict::Baseline),
                Some(SnVerdict::Continuous),
                Some(SnVerdict::Duplicate),
                Some(SnVerdict::OutOfWindow),
                // 6 follows 5, NOT 3: the stale SNs did not move the baseline.
                Some(SnVerdict::Continuous),
            ]
        );
        let acc = s.sn_accounting(Direction::A);
        assert_eq!((acc.missing, acc.gaps), (0, 0));
        assert_eq!((acc.duplicates, acc.out_of_window), (1, 1));
    }

    /// The conduit split, which is the whole reason the tracker is not one
    /// counter per direction: zenoh mints a separate SN series per
    /// `(Priority, Reliability)`, so a reliable 0,1 interleaved with a
    /// best-effort 0,1 is FOUR continuous frames, not a gap and a rewind.
    #[test]
    fn conduits_are_judged_separately_rather_than_as_one_series() {
        let best_effort = |sn: u64| {
            let mut wire = vec![wz_codecs::wire_const::T_MID_FRAME];
            crate::vle::encode_vle_u64_into(&mut wire, sn);
            wire.extend_from_slice(&oam_record(sn));
            wire
        };
        let mut s = established(vec![]);
        s.push(Direction::A, &framed(&frame_wire(0, &oam_record(0)), 2));
        s.push(Direction::A, &framed(&best_effort(0), 2));
        s.push(Direction::A, &framed(&frame_wire(1, &oam_record(1)), 2));
        s.push(Direction::A, &framed(&best_effort(1), 2));
        let verdicts: Vec<Option<SnVerdict>> = (0..4)
            .map(|_| s.next_frame(Direction::A).expect("frame").sn_verdict)
            .collect();
        assert_eq!(
            verdicts,
            vec![
                Some(SnVerdict::Baseline),
                Some(SnVerdict::Baseline),
                Some(SnVerdict::Continuous),
                Some(SnVerdict::Continuous),
            ],
            "the reliable and best-effort series do not see each other"
        );
        assert_eq!(s.sn_accounting(Direction::A).missing, 0);
    }

    /// The ring seam: a wraparound is CONTINUOUS, not a gap of nearly the
    /// whole ring. The modular arithmetic is `crate::sn`'s and this asserts
    /// the tracker uses it rather than a plain subtraction.
    #[test]
    fn a_wraparound_is_continuous_rather_than_a_gap() {
        let mut s = established(vec![]);
        let mask = s.context().sn_mask().expect("negotiated");
        for sn in [mask, 0] {
            s.push(Direction::A, &framed(&frame_wire(sn, &oam_record(0)), 2));
        }
        assert_eq!(
            s.next_frame(Direction::A).expect("frame").sn_verdict,
            Some(SnVerdict::Baseline)
        );
        assert_eq!(
            s.next_frame(Direction::A).expect("frame").sn_verdict,
            Some(SnVerdict::Continuous),
            "SN 0 follows SN {mask} on a ring of {mask}"
        );
        assert_eq!(s.sn_accounting(Direction::A).missing, 0);
    }

    /// The two loss numbers answer DIFFERENT questions and a capture with a
    /// hole shows both: `skipped` is what this reader could not parse,
    /// `missing` is what the sender numbered and nobody saw. Reporting one as
    /// the other is how a dissector blames the wire for its own gap.
    #[test]
    fn skipped_bytes_and_missing_frames_are_different_numbers() {
        let mut s = established(vec![]);
        s.push(Direction::A, &framed(&frame_wire(0, &oam_record(0)), 2));
        s.next_frame(Direction::A).expect("baseline");
        // A hole in the capture: the bytes of frames 1..=3 never arrive, and
        // what does arrive is misframed rubbish followed by frame 4 onward.
        let bogus = bogus_frame(0x1F);
        s.push(Direction::A, &bogus);
        assert!(s.next_frame(Direction::A).is_err(), "desynchronises");
        for sn in 4..(4 + DEFAULT_RESYNC_DEPTH as u64) {
            s.push(Direction::A, &framed(&frame_wire(sn, &oam_record(sn)), 2));
        }
        let f = s.next_frame(Direction::A).expect("resumes");
        assert_eq!(f.resync.expect("recovered").skipped, bogus.len());
        assert_eq!(
            f.sn_verdict,
            Some(SnVerdict::Gap { missing: 3 }),
            "the wire numbered three frames this reader never saw"
        );
        assert_eq!(s.sn_accounting(Direction::A).missing, 3);
        assert_eq!(
            s.resync_accounting(Direction::A).skipped_bytes,
            bogus.len() as u64
        );
    }

    /// R311y631 (§1.2b) — THE CONSUMED LENGTH IS ASSERTED BY LANDING ON A
    /// SENTINEL, never by writing a number down.
    ///
    /// Every case is one real message, built by the production encoders, with a
    /// one-byte KeepAlive appended. If `parse_inbound_consuming` reports a
    /// length that is even one byte off, the walk starts the next decode inside
    /// or past the sentinel and the second message is not a KeepAlive — so the
    /// assertion is on the DECODER's own arithmetic and not on this test
    /// author's idea of each body's layout. That distinction is the whole
    /// reason the number is trustworthy: a hand-written expected length would
    /// agree with a hand-written encoder and prove nothing about the wire.
    #[test]
    fn every_measurable_message_reports_the_length_that_lands_on_the_next_one() {
        let sentinel = crate::wire_const::T_MID_KEEP_ALIVE;
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("InitSyn", init_wire(false, Vec::new())),
            ("InitAck", init_wire(true, Vec::new())),
            (
                "InitSyn with an extension chain",
                init_wire(false, vec![unit_ext(est_ext::COMPRESSION)]),
            ),
            ("OpenSyn", open_wire(false)),
            ("OpenAck", open_wire(true)),
            ("KeepAlive", vec![sentinel]),
            ("Close", {
                let mut w = vec![wz_codecs::wire_const::T_MID_CLOSE];
                w.extend_from_slice(&wz_codecs::close::Close { reason: 0 }.encode_to_vec());
                w
            }),
        ];
        cases.push(("KeepAlive with the Z bit and one extension", {
            let mut w = vec![sentinel | wz_codecs::wire_const::FLAG_T_Z];
            w.extend_from_slice(&crate::ext_chain::encode_ext_chain(&[unit_ext(
                est_ext::COMPRESSION,
            )]));
            w
        }));

        for (name, message) in cases {
            let mut unit = message.clone();
            unit.push(sentinel);

            let (_, consumed) =
                crate::inbound::parse_inbound_consuming(&unit).unwrap_or_else(|e| {
                    panic!(
                        "{name}: the fixture must decode before its length means anything: {e:?}"
                    )
                });
            assert_eq!(
                consumed,
                message.len(),
                "{name}: the decoder claims to have eaten {consumed} of the \
                 {} bytes its own encoder wrote",
                message.len()
            );

            let mut s = PassiveSession::new();
            let frames = s.next_datagram(Direction::A, &unit, 0);
            assert_eq!(
                frames.len(),
                2,
                "{name}: the walk must reach the sentinel behind it, got {:?}",
                frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
            );
            assert!(
                matches!(frames[1].frame, Ok(InboundFrame::KeepAlive { .. })),
                "{name}: the walk landed somewhere other than the sentinel: {:?}",
                frames[1].frame
            );
            assert_eq!(
                s.unaccounted_batch_bytes(Direction::A),
                0,
                "{name}: every byte of the unit was attributed"
            );
            assert_eq!(frames[0].batch_index, 0, "{name}");
            assert_eq!(frames[1].batch_index, 1, "{name}");
        }
    }

    /// Transport OAM (MID 0x00), MEASURED BY LANDING ON THE SENTINEL — the
    /// same discipline as the sweep above, and the reason this MID needed an
    /// arm in `parse_inbound` at all.
    ///
    /// As `Unknown { mid: 0x00 }` it consumed ZERO bytes, so a batch carrying
    /// one reported everything behind it as unaccounted for and the walk
    /// stopped: the analyzer lost the rest of the unit to a message it merely
    /// could not name. That is R311y605's JOIN defect one MID over, and the
    /// assertion that separates the two states is `frames.len()`, not the
    /// naming.
    ///
    /// The fixture is hand-built from UPSTREAM's writer (`zenoh-codec/src/
    /// transport/oam.rs` writes header, `id:z16`, extensions, payload — the
    /// chain BEFORE the body, which no other transport MID does), because wz
    /// has no OAM encoder to build it from. The ext entry is the mandatory
    /// `qos` upstream declares for this carrier, so the admissibility leg is
    /// judged rather than `Unjudged`.
    #[test]
    #[cfg(feature = "codec-keep-alive")]
    fn a_transport_oam_is_measured_so_the_batch_walk_reaches_what_follows_it() {
        let sentinel = crate::wire_const::T_MID_KEEP_ALIVE;
        let body = [0xDEu8, 0xAD, 0xBE, 0xEF];

        let mut oam = alloc::vec![wz_codecs::wire_const::T_MID_OAM | 0x40 | 0x80];
        crate::vle::encode_vle_u64_into(&mut oam, 300); // id:z16
        oam.push(0x01 | 0x10 | 0x20); // ext qos: id 1, MANDATORY, z64, chain end
        crate::vle::encode_vle_u64_into(&mut oam, 7);
        crate::vle::encode_vle_u64_into(&mut oam, body.len() as u64);
        oam.extend_from_slice(&body);
        let oam_len = oam.len();

        let mut unit = oam.clone();
        unit.push(sentinel);

        let (frame, consumed) =
            crate::inbound::parse_inbound_consuming(&unit).expect("the OAM decodes");
        assert_eq!(
            consumed, oam_len,
            "the decoder claims to have eaten {consumed} of the {oam_len} \
             bytes upstream's writer would have written"
        );
        match &frame {
            InboundFrame::Oam {
                id,
                encoding,
                body: decoded,
                extensions,
                ..
            } => {
                assert_eq!(*id, 300);
                assert_eq!(*encoding, 2, "ENC_ZBUF");
                assert_eq!(decoded.as_slice(), &body);
                assert_eq!(extensions.len(), 1);
            }
            other => panic!("not an Oam: {other:?}"),
        }
        // The chain is JUDGED, not merely carried: `qos` is the one mandatory
        // extension this carrier declares, so a reader can say the message is
        // admissible instead of reporting a reach limit.
        assert_eq!(
            frame.ext_admission(),
            crate::ext_admit::ExtAdmission::Admissible
        );

        let mut s = PassiveSession::new();
        let frames = s.next_datagram(Direction::A, &unit, 0);
        assert_eq!(
            frames.len(),
            2,
            "the walk must reach the sentinel behind the OAM, got {:?}",
            frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        assert!(matches!(
            frames[1].frame,
            Ok(InboundFrame::KeepAlive { .. })
        ));
        assert_eq!(s.unaccounted_batch_bytes(Direction::A), 0);

        // The RESERVED encoding (0b11) is refused rather than measured, which
        // is upstream's own answer (`_ => return Err(DidntRead)`). A length
        // reported for it would step the walk onto bytes whose meaning the
        // spec declines to define.
        let reserved = alloc::vec![wz_codecs::wire_const::T_MID_OAM | 0x60, 0x01, sentinel];
        assert!(matches!(
            crate::inbound::parse_inbound_consuming(&reserved),
            Err(crate::parse_error::InboundParseError::ReservedEncoding)
        ));
    }

    /// The SAME halt, one field in: an OAM whose `id` zint is wider than the
    /// `u16` it decodes into.
    ///
    /// R311y878 gave `T_MID_OAM` an arm so a batch could walk past it, and
    /// read the id with the REFUSING `vle_u16`. Upstream does not refuse:
    /// `OamId = u16` (`zenoh-protocol/src/transport/oam.rs:16`) is read on the
    /// plain `Zenoh080`, whose derive is `let x: u64 = self.read(reader)?;
    /// Ok(x as u16)` (`zenoh-codec/src/core/zint.rs`, `uint_impl!(u16)`). So a
    /// unit stock zenoh reads to the end still stopped this walk dead, and
    /// every message batched behind the OAM was lost again — the arm had moved
    /// the halt from the MID to one of its fields rather than removing it.
    ///
    /// Measured the way the arm itself was: by LANDING ON THE SENTINEL. The
    /// discriminator is `frames.len()`, not the id.
    #[test]
    #[cfg(feature = "codec-keep-alive")]
    fn an_oam_id_wider_than_u16_must_not_stop_the_batch_walk_either() {
        let sentinel = crate::wire_const::T_MID_KEEP_ALIVE;
        let body = [0xDEu8, 0xAD, 0xBE, 0xEF];
        // 0x1_0002 needs three VLE bytes and truncates to 2 — a value a
        // conforming peer reaches, and a width `vle_u16` refuses.
        let wide = 0x1_0002u64;

        let mut oam = alloc::vec![wz_codecs::wire_const::T_MID_OAM | 0x40];
        crate::vle::encode_vle_u64_into(&mut oam, wide);
        crate::vle::encode_vle_u64_into(&mut oam, body.len() as u64);
        oam.extend_from_slice(&body);
        let oam_len = oam.len();

        let mut unit = oam.clone();
        unit.push(sentinel);

        let (frame, consumed) =
            crate::inbound::parse_inbound_consuming(&unit).expect("upstream decodes this OAM");
        assert_eq!(
            consumed, oam_len,
            "the decoder must eat the whole message, wide id included"
        );
        match &frame {
            InboundFrame::Oam { id, .. } => assert_eq!(
                *id, 2,
                "the decoder reported an id the receiving peer never computes"
            ),
            other => panic!("not an Oam: {other:?}"),
        }

        let mut s = PassiveSession::new();
        let frames = s.next_datagram(Direction::A, &unit, 0);
        assert_eq!(
            frames.len(),
            2,
            "the walk must reach the sentinel behind the OAM, got {:?}",
            frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        assert!(matches!(
            frames[1].frame,
            Ok(InboundFrame::KeepAlive { .. })
        ));
        assert_eq!(s.unaccounted_batch_bytes(Direction::A), 0);
    }

    /// R311y631 (§1.2b) — and the COUNTER-CASE that says why a batch ends with
    /// a data frame: a `Frame` eats the remainder, sentinel and all.
    ///
    /// Not a defect and not a shortfall — it is what the wire says. zenoh's own
    /// decoder reads a Frame's payload as `reader.remaining()`
    /// (`zenoh-codec-1.5.0/src/transport/frame.rs:173`), so a sender that put
    /// anything behind a Frame in one unit would have written a message no
    /// conforming peer can retrieve. Asserted here so that the walk's stopping
    /// point is a MEASURED property of the codec rather than a coincidence
    /// nobody would notice changing.
    #[test]
    fn a_frame_eats_the_rest_of_its_unit_which_is_why_it_ends_a_batch() {
        let sentinel = crate::wire_const::T_MID_KEEP_ALIVE;
        let mut unit = frame_wire(3, &oam_record(1));
        let frame_len = unit.len();
        unit.push(sentinel);

        let (_, consumed) =
            crate::inbound::parse_inbound_consuming(&unit).expect("the frame decodes");
        assert_eq!(
            consumed,
            frame_len + 1,
            "a Frame consumes to the end of its unit, so the sentinel is part \
             of its payload rather than a message behind it"
        );

        let mut s = PassiveSession::new();
        let frames = s.next_datagram(Direction::A, &unit, 0);
        assert_eq!(frames.len(), 1, "one Frame, and nothing after it");
        assert_eq!(s.unaccounted_batch_bytes(Direction::A), 0);
    }

    /// R311y631 (§1.2b) — THE STREAM HALF, which R311y626's pin never reached.
    ///
    /// A length prefix delimits a BATCH exactly as a datagram boundary does —
    /// zenoh runs the same `while !batch.is_empty()` loop on its unicast stream
    /// path (`zenoh-transport-1.5.0/src/unicast/universal/rx.rs:220`) — so the
    /// message behind a KeepAlive inside one envelope was being dropped here
    /// too. `next_frame` keeps its one-message-per-call shape, which is what
    /// lets every existing caller's `while let Ok(..)` loop pick up the second
    /// message without being rewritten.
    #[test]
    fn a_stream_envelope_holding_two_messages_yields_both() {
        let mut body = vec![crate::wire_const::T_MID_KEEP_ALIVE];
        body.extend_from_slice(&frame_wire(7, &oam_record(9)));

        let mut s = PassiveSession::new();
        s.push(Direction::A, &framed(&body, PREFIX_WIDTH_UNIVERSAL));

        let first = s.next_frame(Direction::A).expect("the KeepAlive in front");
        let second = s.next_frame(Direction::A).expect("the Frame behind it");
        assert!(
            matches!(first.frame, Ok(InboundFrame::KeepAlive { .. })),
            "{:?}",
            first.frame
        );
        match &second.frame {
            Ok(InboundFrame::Frame { sn, .. }) => assert_eq!(*sn, 7, "the Frame's own sn"),
            other => panic!("the second message of the envelope is a Frame: {other:?}"),
        }
        assert_eq!(
            first.stream_offset, second.stream_offset,
            "ONE envelope, so one anchor -- which is why the batch index exists"
        );
        assert_eq!(first.batch_index, 0);
        assert_eq!(second.batch_index, 1);
        assert_eq!(
            first.prefix_width, PREFIX_WIDTH_UNIVERSAL,
            "the prefix framed the whole unit, so it is every message's width"
        );
        assert_eq!(second.prefix_width, PREFIX_WIDTH_UNIVERSAL);
        assert!(
            matches!(s.next_frame(Direction::A), Err(PassiveStall::NeedMoreBytes)),
            "and the envelope is then exhausted rather than replayed"
        );
        assert_eq!(s.unaccounted_batch_bytes(Direction::A), 0);
    }

    /// R311y631 (§1.2b) — a tail the walk cannot MEASURE is counted, and is not
    /// reported as a message.
    ///
    /// `0x08` is no MID zenoh defines (the space is `0x00..=0x07`), so nothing
    /// can say where that candidate ends. Emitting a record for it would place
    /// a message at an offset this reader guessed; the bytes are counted
    /// instead. That is the difference between this round and the silence
    /// §1.2b named: the loss now has a number, and the number is in the
    /// direction it arrived on.
    ///
    /// The fixture was `0x00` until transport OAM gained a decode arm, and the
    /// premise written beside it — "no MID zenoh defines" — was FALSE the
    /// whole time: `0x00` is `id::OAM`. It passed because this reader could
    /// not name it, which is the fixture agreeing with the defect rather than
    /// with the wire.
    #[test]
    fn a_batch_tail_that_cannot_be_measured_is_counted_rather_than_silent() {
        let mut unit = vec![crate::wire_const::T_MID_KEEP_ALIVE];
        unit.extend_from_slice(&[0x08, 0x11, 0x22]);

        let mut s = PassiveSession::new();
        let frames = s.next_datagram(Direction::A, &unit, 0);
        assert_eq!(
            frames.len(),
            1,
            "the KeepAlive is reported and the unmeasurable tail is NOT: {:?}",
            frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        assert_eq!(
            s.unaccounted_batch_bytes(Direction::A),
            3,
            "three bytes the walk could not attribute to any message"
        );
        assert_eq!(
            s.unaccounted_batch_bytes(Direction::B),
            0,
            "and they are charged to the direction they arrived on"
        );
    }

    /// R311y631 (§1.2b) — at the FRONT of a unit the same byte still reports
    /// itself, because there the offset is not in question.
    ///
    /// The asymmetry is deliberate and is the whole of the rule: past the front
    /// the walk only stands where the previous message SAID the next one began,
    /// and a record read from a guessed offset is manufactured. At offset zero
    /// the caller handed these bytes over as one unit, so an undecodable
    /// datagram still says what it could not read instead of vanishing.
    ///
    /// `0x08` for the reason given on the sibling above: the `0x00` this used
    /// to use is `id::OAM`, and a fixture that needs an UNNAMEABLE MID must
    /// pick one outside the space rather than one this reader had not yet
    /// learned.
    #[test]
    fn an_unmeasurable_message_at_the_front_of_a_unit_still_reports_itself() {
        let mut s = PassiveSession::new();
        let frames = s.next_datagram(Direction::A, &[0x08, 0x11], 0);
        assert_eq!(frames.len(), 1);
        assert!(
            matches!(frames[0].frame, Ok(InboundFrame::Unknown { mid: 8 })),
            "{:?}",
            frames[0].frame
        );
        assert_eq!(
            s.unaccounted_batch_bytes(Direction::A),
            2,
            "and the whole unit is unaccounted for, because its extent is what \
             is unknown"
        );
    }
}
