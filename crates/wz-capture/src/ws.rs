// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y602 — RFC6455 deframing, so a zenoh session carried over `ws/...`
//! is dissected instead of quietly producing nothing.
//!
//! ## Why this is the hole that mattered
//!
//! Every other gap in this crate announces itself. An unhandled link type, an
//! IPv4 fragment, a non-IP packet — each becomes a typed
//! [`SkipReason`](crate::link::SkipReason) attached to the packet it came
//! from, so a dissection with a hole says where the hole is. WebSocket was the
//! exception, and not by design: a `ws/...` zenoh link is ordinary TCP, so the
//! packets decapsulate perfectly, reassemble perfectly, and hand
//! `wz_session_core::passive` a byte stream that begins `GET / HTTP/1.1` and
//! continues in RFC6455 frames. Nothing refuses it. The stream simply never
//! decodes, and the analyzer reports a capture with no zenoh messages in it —
//! which is indistinguishable from a capture that genuinely had none.
//!
//! It is not a rare configuration either: zenoh's `transport_ws` is in its
//! DEFAULT feature set (`zenoh/Cargo.toml:45`) and the link is native
//! `tokio-tungstenite`, not a browser-only path.
//!
//! ## The framing contract, measured rather than assumed
//!
//! zenoh's ws link reports `is_streamed() = false`
//! (`io/zenoh-links/zenoh-link-ws/src/unicast.rs:225`) and its `write` hands
//! the whole buffer to one `Message::Binary` (`:143`), with `recv` taking one
//! Binary back and rejecting Text / Ping / Pong outright (`:102`). So the
//! WebSocket MESSAGE boundary is the framing, exactly as a UDP datagram
//! boundary is — no length prefix — which is why a deframed message goes to
//! the crate's DATAGRAM ingestion and not through the stream assembler's
//! prefixed path.
//!
//! ⚠ **One deliberate limit, named because it is a real edge and not an
//! oversight.** A non-streamed zenoh link receives a whole BATCH per write,
//! and a batch may hold more than one transport message; this crate's decode
//! seam (`parse_inbound`) reports no consumed length, so every ingestion in
//! this crate — TCP prefixed unit, UDP datagram, raweth frame, and now a ws
//! message — reads exactly ONE transport message per unit. Adding ws on that
//! same contract is consistent with the tree; changing the contract is a
//! separate round and needs a decode entry that reports consumption.
//!
//! ## What is skipped, and counted
//!
//! Control frames (Close / Ping / Pong) and Text frames carry no zenoh, so
//! they are dropped — but [`WsDeframer::skipped_frames`] counts them, because
//! this module exists to end a silent hole and must not open a smaller one.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// A continuation of the previous frame's message.
const OP_CONTINUATION: u8 = 0x0;
/// UTF-8 text. zenoh never sends it and its own `recv` treats one as an error.
const OP_TEXT: u8 = 0x1;
/// The one zenoh uses: a whole batch per frame.
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Largest single frame payload, and largest reassembled message, this
/// deframer will buffer.
///
/// zenoh's own batch ceiling is 65535 (a `u16` length), so 16 MiB is far above
/// anything real. It exists because the length field is 64 bits wide and read
/// from a capture: a corrupt or mis-detected stream can claim an allocation
/// nothing bounds, and refusing is the only safe answer to a number that
/// cannot be true.
pub const MAX_WS_PAYLOAD: usize = 1 << 24;

/// Largest HTTP preamble tolerated before the flow is judged not to be
/// WebSocket after all. Real upgrade handshakes are a few hundred bytes.
const MAX_PREAMBLE: usize = 64 * 1024;

/// R311y612 — widest RFC6455 frame header: the two mandatory bytes, the
/// 64-bit extended length, and a client mask key.
const MAX_WS_HEADER: usize = 2 + 8 + 4;

/// R311y612 — how far past a lost boundary the true one can hide.
///
/// A GUARANTEE and not a budget, on the same argument as
/// [`wz_session_core::passive::RESYNC_SCAN_WINDOW`]: zenoh's ws `write` hands
/// ONE batch to ONE `Message::Binary`, and a batch is bounded by
/// [`MAX_FRAME_PAYLOAD`](wz_session_core::passive::MAX_FRAME_PAYLOAD), so any
/// run of this many consecutive received bytes contains at least one real
/// frame boundary. A scan that crosses it without confirming one has not been
/// unlucky — it is looking at bytes whose framing it cannot recover.
///
/// ⚠ Deliberately NOT [`MAX_WS_PAYLOAD`]. The two answer different questions
/// and the asymmetry is the point: the accept cap is generous because a
/// capture is untrusted and a single oversize frame must be refused rather
/// than allocated, while the window is derived from what a zenoh link can
/// actually write. Keying the window off the accept cap would make it 16 MiB
/// of buffered noise per desynchronised direction.
pub const WS_RESYNC_SCAN_WINDOW: usize =
    wz_session_core::passive::MAX_FRAME_PAYLOAD + MAX_WS_HEADER;

/// R311y612 — chained frames a candidate boundary must confirm before this
/// reader resumes on it.
///
/// Measured rather than picked, and the first guess was WRONG:
/// `the_ws_chain_discriminator_refuses_noise` sweeps depths over pseudo-random
/// corpora and over real length-prefixed zenoh streams — the two things a ws
/// boundary must never be confused with — and reports the false-accept rate at
/// each. Over 4 KiB buffers it reads
/// `noise [40, 34, 2, 0, …] / zenoh-stream [40, 33, 2, 0, …]` out of 40, so 4
/// is the SHALLOWEST depth that refuses both corpora outright and the test
/// asserts exactly that rather than a number.
///
/// ⚠ The cost is named because it is real: a ws flow with fewer than four
/// messages left after a hole is not recovered. That loss is REPORTED —
/// [`WsDeframer::desynchronised`] stays set and the accounting counts the
/// desynchronisation — which is the difference between this and the silence
/// the round is closing.
pub const WS_CHAIN_DEPTH: usize = 4;

/// R311y612 — WHY a ws direction lost its frame boundary.
///
/// Separate arms because a reader acts on them differently, exactly as
/// [`DesyncReason`](wz_session_core::passive::DesyncReason) does one framing
/// layer down: [`Self::CaptureGap`] is the layer BELOW reporting a hole it
/// measured, while every other arm is this reader concluding that bytes cannot
/// mean what RFC6455 says they do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDesyncReason {
    /// The byte source said it lost bytes here ([`WsDeframer::note_gap`]).
    ///
    /// The only arm that is not an inference, and the one §4.2 was about.
    CaptureGap {
        /// Bytes the source says are absent, or 0 when it knows the stream is
        /// discontinuous but not by how much.
        bytes_missing: u64,
    },
    /// A frame header this reader cannot honour: an RSV extension bit, or a
    /// length above [`MAX_WS_PAYLOAD`].
    UnusableHeader,
    /// A reserved opcode — this is not the protocol the classifier decided it
    /// was.
    ReservedOpcode {
        /// The opcode that is not one of the six RFC6455 defines.
        opcode: u8,
    },
    /// A Binary frame opened while an earlier message was still unfinished, or
    /// a Continuation arrived with no message to continue. Either way the
    /// frame boundary is not where this reader thought.
    MessageBoundary,
    /// Detected as WebSocket on its opening literal, then the HTTP preamble
    /// never terminated within `MAX_PREAMBLE`.
    PreambleNeverEnded,
    /// R311y612 (§4.1) — the flow was classified as WebSocket with its opening
    /// LOST to a hole, so there is no preamble to step over and no boundary
    /// yet known. Not a failure: the deframer starts here and scans.
    OpeningLost,
}

/// R311y612 — a ws direction that lost its framing and found it again.
///
/// Carried on the FIRST message decoded after the recovery, for the reason
/// [`StreamResync`](wz_session_core::passive::StreamResync) is: that message's
/// offset would otherwise be an unexplained jump, and a dissector that resumed
/// silently reports a hole as though the wire had none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsResync {
    /// Absolute stream offset where the direction lost its framing.
    pub desync_offset: usize,
    /// The evidence that lost it.
    pub reason: WsDesyncReason,
    /// Absolute stream offset the reader resumed at.
    pub resumed_offset: usize,
    /// Bytes between the two: what this reader will never deframe.
    pub skipped: usize,
    /// Chained frames that confirmed the resumed boundary. Reported rather
    /// than assumed because it IS the confidence.
    pub confirmed: usize,
}

/// R311y612 — cumulative resynchronisation accounting for one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WsResyncAccounting {
    /// Times this direction lost its frame boundary.
    pub desyncs: u64,
    /// Times it found one again.
    pub recoveries: u64,
    /// Total bytes stepped over across those recoveries.
    pub skipped_bytes: u64,
}

/// R311y612 — the scan's state while a direction is looking for its framing.
#[derive(Debug, Clone, Copy)]
struct WsDesyncState {
    /// Absolute offset the direction desynchronised at.
    at_offset: usize,
    reason: WsDesyncReason,
    /// Index into `buf` the contiguous refuted prefix has reached.
    scan_cursor: usize,
    /// Buffer length below which no verdict anywhere can change.
    rescan_at: usize,
}

/// R311y612 — how one candidate boundary came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsCandidate {
    /// These bytes cannot open a frame, whatever arrives later.
    Refuted,
    /// Consistent, and the frame ends at this index.
    Framed(usize),
    /// Undecidable on the bytes held; `needed` is the buffer length at which
    /// it could be judged again.
    Short {
        /// Buffer length the verdict is waiting for.
        needed: usize,
    },
}

/// R311y612 — THE DISCRIMINATOR. Do the bytes at `at` open one RFC6455 frame
/// carrying zenoh?
///
/// Every clause is a refusal the specification writes down, not a heuristic —
/// which is what makes a chain of these evidence rather than a guess:
///
/// - RFC6455 §5.2: RSV1..3 are zero absent a negotiated extension, and zenoh
///   negotiates none.
/// - §5.2: six opcodes are defined; the other ten are reserved.
/// - §5.5: a control frame is never fragmented and never exceeds 125 bytes.
/// - §5.2: the length uses the MINIMAL encoding, so a 16-bit extended length
///   below 126 and a 64-bit one below 65536 are both violations — the two
///   clauses that do most of the refusing on arbitrary bytes.
/// - §5.2: the 64-bit length's most significant bit is zero.
///
/// The last clause is this crate's rather than RFC6455's, and it is the one
/// that makes the scan affordable: a non-empty Binary frame opens a zenoh
/// BATCH, so its first payload byte must be a byte a zenoh transport header
/// could be (`is_credible_transport_header`, 42 of 256). Without it the
/// per-offset false-accept rate is a frame-shape rate; with it the question
/// asked is the one this crate actually has — "is this ws carrying zenoh" —
/// and `the_ws_chain_discriminator_refuses_noise` measures both.
fn ws_candidate_at(buf: &[u8], at: usize, assembling: bool) -> WsCandidate {
    if buf.len() < at + 2 {
        return WsCandidate::Short { needed: at + 2 };
    }
    let b0 = buf[at];
    let b1 = buf[at + 1];
    if (b0 & 0x70) != 0 {
        return WsCandidate::Refuted;
    }
    let opcode = b0 & 0x0F;
    if !matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return WsCandidate::Refuted;
    }
    // RFC6455 §5.4 — the sequencing rule, and MEASURED to be the clause that
    // carries this discriminator. Without it a run of 0x00 bytes reads as an
    // unbounded chain of unfragmented continuations, which is exactly what a
    // zenoh stream's little-endian length prefix looks like: the high byte of a
    // short length is 0x00, i.e. FIN clear + opcode CONTINUATION, and any
    // second byte under 126 completes a "frame". The first sweep measured 28 of
    // 40 REAL zenoh streams accepted at depth 3 for precisely that reason.
    // A continuation with nothing to continue, or a data frame opening while a
    // message is unfinished, is a protocol violation and not a boundary.
    if (opcode == OP_CONTINUATION) != assembling && (opcode & 0x08) == 0 {
        return WsCandidate::Refuted;
    }
    let fin = (b0 & 0x80) != 0;
    let masked = (b1 & 0x80) != 0;
    let len7 = (b1 & 0x7F) as usize;
    if (opcode & 0x08) != 0 && (!fin || len7 > 125) {
        return WsCandidate::Refuted;
    }
    let mut cursor = at + 2;
    let payload_len = match len7 {
        126 => {
            if buf.len() < cursor + 2 {
                return WsCandidate::Short { needed: cursor + 2 };
            }
            let n = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
            cursor += 2;
            if n < 126 {
                return WsCandidate::Refuted;
            }
            n
        }
        127 => {
            if buf.len() < cursor + 8 {
                return WsCandidate::Short { needed: cursor + 8 };
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[cursor..cursor + 8]);
            cursor += 8;
            let n = u64::from_be_bytes(raw);
            if n > MAX_WS_PAYLOAD as u64 || n <= u16::MAX as u64 {
                return WsCandidate::Refuted;
            }
            n as usize
        }
        n => n,
    };
    let mut key = [0u8; 4];
    if masked {
        if buf.len() < cursor + 4 {
            return WsCandidate::Short { needed: cursor + 4 };
        }
        key.copy_from_slice(&buf[cursor..cursor + 4]);
        cursor += 4;
    }
    if opcode == OP_BINARY && payload_len > 0 {
        if buf.len() < cursor + 1 {
            return WsCandidate::Short { needed: cursor + 1 };
        }
        let header = buf[cursor] ^ if masked { key[0] } else { 0 };
        if !wz_session_core::wire_const::is_credible_transport_header(header) {
            return WsCandidate::Refuted;
        }
    }
    let end = cursor + payload_len;
    if buf.len() < end {
        return WsCandidate::Short { needed: end };
    }
    WsCandidate::Framed(end)
}

/// R311y612 — does a chain of `depth` frames confirm a boundary at `at`?
///
/// The classification half of the discriminator: [`FlowDissection`] asks it of
/// a flow whose HTTP opening was lost to a hole, where the literal that would
/// have settled the question can never arrive.
///
/// [`FlowDissection`]: crate::FlowDissection
fn chain_confirms(buf: &[u8], at: usize, depth: usize) -> WsCandidate {
    let mut at = at;
    let mut confirmed = 0usize;
    // A chain begins where a MESSAGE begins: after a hole the message that was
    // being assembled is abandoned, so a resume point mid-fragmentation is not
    // one this reader could use even if the bytes allowed it.
    let mut assembling = false;
    loop {
        if confirmed == depth {
            return WsCandidate::Framed(at);
        }
        match ws_candidate_at(buf, at, assembling) {
            WsCandidate::Framed(next) => {
                let b0 = buf[at];
                let opcode = b0 & 0x0F;
                if (opcode & 0x08) == 0 {
                    assembling = (b0 & 0x80) == 0;
                }
                at = next;
                confirmed += 1;
            }
            other => return other,
        }
    }
}

/// R311y612 (§4.1) — do these bytes hold a WebSocket frame boundary that
/// `depth` chained frames agree on?
///
/// The public face of `chain_confirms`, for a caller deciding what a flow IS
/// rather than where its next frame starts. `true` is evidence of WebSocket;
/// `false` is "not on the bytes so far", never "definitely not" — which is why
/// its caller keeps asking as more arrive.
pub fn carries_ws_frames(bytes: &[u8], depth: usize) -> bool {
    (0..bytes.len()).any(|at| matches!(chain_confirms(bytes, at, depth), WsCandidate::Framed(_)))
}

/// The two literals a WebSocket-carrying direction can open with: the client's
/// request line and the server's status line. Either alone is enough, which is
/// what lets a ONE-SIDED capture still be recognised — only the server's
/// direction is the normal result of a SPAN port on the wrong side, and
/// refusing to classify it would put this crate's worst failure mode straight
/// back.
const OPENINGS: [&[u8]; 2] = [b"GET ", b"HTTP"];

/// What a direction's opening bytes say about whether it carries WebSocket.
///
/// Three answers and not two, and the third is the one that matters: a caller
/// that must choose between `Yes` and `No` on too few bytes will either stall a
/// short first message forever or misclassify one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeVerdict {
    /// An HTTP upgrade handshake.
    Yes,
    /// Not one — and settled, however few bytes there are.
    No,
    /// Still consistent with an opening, and shorter than it. Wait.
    NeedMore,
}

/// Does this direction's opening look like the HTTP half of a WebSocket
/// upgrade?
///
/// Answers `No` the moment the bytes DIVERGE from both openings rather than
/// waiting for a fixed width, and that is not an optimisation. A framed
/// KeepAlive is three bytes (`[1, 0, 0x0F]`), so a detector that demanded four
/// before deciding would hold a flow whose entire first message is shorter than
/// its threshold — forever, with no error. That defect was written, and the
/// negative test below is what caught it.
///
/// A zenoh stream link cannot be mistaken for an opening: its first two bytes
/// are a little-endian length prefix, so `GET ` would be a 17991-byte first
/// message and `HTTP` a 21576-byte one. Both are legal numbers, so the
/// discrimination is not on legality but on these being the literal opening of
/// the other protocol.
pub fn http_upgrade_verdict(prefix: &[u8]) -> UpgradeVerdict {
    let mut need_more = false;
    for opening in OPENINGS {
        if prefix.len() >= opening.len() {
            if &prefix[..opening.len()] == opening {
                return UpgradeVerdict::Yes;
            }
        } else if opening.starts_with(prefix) {
            need_more = true;
        }
    }
    if need_more {
        UpgradeVerdict::NeedMore
    } else {
        UpgradeVerdict::No
    }
}

/// One direction of a WebSocket-carried byte stream, turned into the zenoh
/// batches it holds.
///
/// Fed the same reassembled bytes the stream path would receive, and drained
/// with [`next_message`](Self::next_message) until it says no. Each message
/// comes back with the ABSOLUTE stream offset its first frame started at, so
/// `FlowDissection::packet_for` still resolves a decoded message to the packet
/// that carried it — the attribution this whole crate exists for survives the
/// extra framing layer.
#[derive(Debug)]
pub struct WsDeframer {
    /// Bytes not yet consumed. `buf[0]` sits at stream offset `base`.
    buf: Vec<u8>,
    /// Absolute stream offset of `buf[0]`.
    base: usize,
    /// Has the HTTP upgrade preamble been stepped over?
    preamble_done: bool,
    /// Payload of the message being assembled across continuation frames.
    partial: Vec<u8>,
    /// Stream offset of the FIRST frame of `partial`, or `None` when no
    /// message is in progress.
    partial_offset: Option<usize>,
    /// R311y612 — `Some` while this direction is looking for its framing.
    ///
    /// Was a terminal `bool` until R311y612 (§4.2): a deframer that had lost
    /// the boundary reported every later byte of the flow as nothing, which is
    /// the silent-hole failure this module exists to end, one framing layer up.
    /// Nothing is consumed while it is set, so `buf[0]` stays the byte at
    /// `base` and the scan cursor below survives across calls.
    desync: Option<WsDesyncState>,
    /// R311y612 — the recoveries to hand to the next message decoded.
    ///
    /// R311y613 (§4.5) made it a QUEUE. Once a structural desynchronisation
    /// recovers WITHIN a single [`Self::next_message`] call, a second one can
    /// follow before that call returns a message, and a single slot would let
    /// the later recovery overwrite the earlier — the flow would report one
    /// recovery where two happened, which is the accounting error the split
    /// between `desyncs` and `recoveries` exists to make impossible.
    pending_resync: VecDeque<WsResync>,
    /// R311y612 — cumulative, for a reader that wants this direction's health
    /// rather than one message's story.
    accounting: WsResyncAccounting,
    /// R311y612 — chained frames a candidate boundary must confirm. 0 switches
    /// recovery off, which is what makes the pre-R311y612 behaviour a
    /// measurable arm rather than a memory.
    chain_depth: usize,
    /// Frames dropped because their opcode carries no zenoh.
    skipped_frames: usize,
}

impl Default for WsDeframer {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            base: 0,
            preamble_done: false,
            partial: Vec::new(),
            partial_offset: None,
            desync: None,
            pending_resync: VecDeque::new(),
            accounting: WsResyncAccounting::default(),
            chain_depth: WS_CHAIN_DEPTH,
            skipped_frames: 0,
        }
    }
}

impl WsDeframer {
    /// A fresh deframer positioned at stream offset 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y612 (§4.1) — a deframer for a flow classified as WebSocket with
    /// its HTTP opening LOST to a hole.
    ///
    /// There is no preamble to step over and no boundary yet known, so it
    /// starts in the scanning state at `base` rather than pretending offset 0
    /// is a frame header. The alternative — the pre-R311y612 behaviour — was
    /// to call such a flow a plain zenoh stream, which decodes its ws frame
    /// headers as length prefixes and reports confident nonsense.
    pub fn after_lost_opening(base: usize) -> Self {
        Self {
            base,
            preamble_done: true,
            desync: Some(WsDesyncState {
                at_offset: base,
                reason: WsDesyncReason::OpeningLost,
                scan_cursor: 0,
                rescan_at: 0,
            }),
            accounting: WsResyncAccounting {
                desyncs: 1,
                ..WsResyncAccounting::default()
            },
            ..Self::default()
        }
    }

    /// R311y612 — how many chained frames must confirm a boundary before this
    /// deframer resumes on it. `0` disables recovery entirely.
    pub fn with_chain_depth(mut self, depth: usize) -> Self {
        self.chain_depth = depth;
        self
    }

    /// Append newly-reassembled bytes for this direction.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// R311y610 — the byte source lost bytes at the current write point, so
    /// this deframer's idea of where the next frame header sits is stale.
    ///
    /// R311y612 (§4.2) — no longer terminal. It DISCARDS the buffered tail
    /// first, and that is the part that matters: those bytes are the near side
    /// of the hole, they can never complete a frame with what follows, and a
    /// scan that started among them could confirm a boundary that predates the
    /// gap and then read straight across it. Dropping them makes "no message
    /// is fabricated across an announced hole" a STRUCTURAL property of this
    /// function rather than a fixture that happened not to hold enough bytes.
    /// This is deliberately stricter than the stream path one layer down,
    /// which scans from the suspect boundary itself.
    pub fn note_gap(&mut self, bytes_missing: u64) {
        let dropped = self.buf.len();
        self.buf.clear();
        self.base += dropped;
        self.desynchronise(WsDesyncReason::CaptureGap { bytes_missing });
    }

    /// R311y612 — judge this direction desynchronised and start a scan.
    ///
    /// Consumes nothing: the scan begins at the suspect boundary itself, so a
    /// boundary hiding one byte later is found and the offsets a consumer sees
    /// stay monotonic.
    fn desynchronise(&mut self, reason: WsDesyncReason) {
        // A message assembled across continuation frames is abandoned with the
        // boundary that framed it. Keeping it would let a recovery graft the
        // far side of a hole onto the near side — a fabricated message, which
        // is the one outcome worse than reporting none.
        self.partial = Vec::new();
        self.partial_offset = None;
        if self.desync.is_none() {
            self.accounting.desyncs += 1;
            self.desync = Some(WsDesyncState {
                at_offset: self.base,
                reason,
                scan_cursor: 0,
                rescan_at: 0,
            });
        }
    }

    /// Has this direction stopped making sense as RFC6455?
    ///
    /// Reported rather than silent for the same reason
    /// [`SkipReason`](crate::link::SkipReason) is: a consumer that sees no
    /// messages needs to know whether the wire was empty or the reader gave
    /// up. R311y612 — now a state a direction can LEAVE, so a consumer
    /// polling it sees recovery as well as loss.
    pub fn desynchronised(&self) -> bool {
        self.desync.is_some()
    }

    /// R311y612 — why this direction is currently desynchronised.
    pub fn desync_reason(&self) -> Option<WsDesyncReason> {
        self.desync.map(|d| d.reason)
    }

    /// R311y612 — take the oldest recovery owed to the message just returned.
    ///
    /// Drained by the caller immediately after [`Self::next_message`], so a
    /// recovery is attributed to the first message decoded after it and to no
    /// other.
    ///
    /// R311y613 (§4.5) — drain it in a `while let`, not an `if let`: one call
    /// to [`Self::next_message`] can now recover more than once before it
    /// returns a message, and each recovery is a separate record.
    pub fn take_resync(&mut self) -> Option<WsResync> {
        self.pending_resync.pop_front()
    }

    /// R311y612 — this direction's cumulative framing health.
    pub fn accounting(&self) -> WsResyncAccounting {
        self.accounting
    }

    /// Frames dropped because they were Close / Ping / Pong / Text.
    pub fn skipped_frames(&self) -> usize {
        self.skipped_frames
    }

    /// R311y612 — bytes held and not yet deframed. The scan's memory, which
    /// [`WS_RESYNC_SCAN_WINDOW`] is what bounds.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// R311y612 — look for a boundary `chain_depth` frames agree on.
    ///
    /// The same shape as the stream path's
    /// [`try_resync`](wz_session_core::passive) and for the same measured
    /// reason: an UNRESOLVED candidate must not block the offsets after it.
    /// A ws length field read off arbitrary bytes routinely claims more than
    /// the buffer holds, so a scan that stopped at the first short candidate
    /// would park at the desynchronisation point and never move — the defect
    /// R311y609 measured one layer down as "0 of 400 at every depth", which
    /// is not a scan discriminating but a scan that never ran.
    fn try_resync(&mut self) -> Option<WsResync> {
        let state = self.desync?;
        if self.chain_depth == 0 {
            return None;
        }
        if self.buf.len() < state.rescan_at {
            return None;
        }
        let mut cursor = state.scan_cursor;
        let mut rescan_at = usize::MAX;
        let mut accepted = None;
        let mut candidate = cursor;
        while candidate < self.buf.len() {
            match chain_confirms(&self.buf, candidate, self.chain_depth) {
                WsCandidate::Framed(_) => {
                    accepted = Some(candidate);
                    break;
                }
                WsCandidate::Refuted => {
                    if candidate == cursor {
                        cursor += 1;
                    }
                }
                WsCandidate::Short { needed } => rescan_at = rescan_at.min(needed),
            }
            candidate += 1;
        }
        let Some(offset) = accepted else {
            let state = self.desync.as_mut().expect("state was Some");
            state.scan_cursor = cursor;
            state.rescan_at = if rescan_at == usize::MAX {
                self.buf.len() + 1
            } else {
                rescan_at
            };
            // The window is a GUARANTEE (see `WS_RESYNC_SCAN_WINDOW`): having
            // examined that many bytes without confirming a boundary, this
            // reader cannot recover their framing, so it drops them. Bounded
            // memory, and the skip stays visible because `skipped` is measured
            // off the desynchronisation offset.
            if cursor > WS_RESYNC_SCAN_WINDOW {
                let drop = cursor - WS_RESYNC_SCAN_WINDOW;
                self.buf.drain(..drop);
                self.base += drop;
                let state = self.desync.as_mut().expect("state was Some");
                state.scan_cursor -= drop;
                state.rescan_at = state.rescan_at.saturating_sub(drop);
            }
            return None;
        };
        self.buf.drain(..offset);
        self.base += offset;
        self.desync = None;
        // A confirmed chain IS a frame boundary, so whatever preamble state
        // this deframer was in is settled by evidence rather than by a search
        // for `\r\n\r\n` that would now run over frame bytes.
        self.preamble_done = true;
        self.accounting.recoveries += 1;
        let skipped = self.base - state.at_offset;
        self.accounting.skipped_bytes += skipped as u64;
        Some(WsResync {
            desync_offset: state.at_offset,
            reason: state.reason,
            resumed_offset: self.base,
            skipped,
            confirmed: self.chain_depth,
        })
    }

    /// The next complete zenoh-carrying message, with the stream offset its
    /// first frame began at.
    ///
    /// # R311y613 (§4.5) — why a desynchronisation does not return here
    ///
    /// R311y612 made a desynchronised direction recoverable but left every
    /// STRUCTURAL detection returning `None` on the spot, and the caller's
    /// shape is `while let Some(msg) = next_message()`
    /// (`Dissection::feed_websocket`). So a reserved opcode or a broken message
    /// boundary ENDED THE CALLER'S LOOP: every remaining byte of that push went
    /// undeframed, and the recovery only ran if more bytes happened to arrive
    /// later in their own push. On the ordinary shape — one TCP segment
    /// carrying the damage and the frames after it — the flow reported nothing
    /// after the damage, which is precisely the silence §4.2 closed for the
    /// ANNOUNCED half and left open for this one.
    ///
    /// Measured, not reasoned: `every_structural_desync_recovers_and_not_only_
    /// the_announced_one` red with `0` of 6 messages recovered on all three
    /// structural reasons before this loop existed.
    ///
    /// The scan therefore runs at the TOP of a loop rather than once on entry,
    /// and a structural detection continues into it. `try_resync` returning
    /// `None` is still the exit — that is "no boundary confirmed yet", the one
    /// honest reason to hand nothing back.
    pub fn next_message(&mut self) -> Option<(usize, Vec<u8>)> {
        loop {
            // R311y612 — a desynchronised direction is no longer terminal: the
            // detecting call recorded it, and every later one scans.
            if self.desync.is_some() {
                let resync = self.try_resync()?;
                self.pending_resync.push_back(resync);
            }
            if !self.preamble_done && !self.step_over_preamble() {
                return None;
            }
            if let Some(msg) = self.deframe_until_desync() {
                return msg;
            }
            // Desynchronised inside the frame walk. Round the loop: the scan at
            // the top is what decides whether this reader comes back.
        }
    }

    /// Deframe until a message is ready, the buffer runs out, or the framing
    /// stops making sense.
    ///
    /// `None` means "desynchronised — the caller should scan and retry", which
    /// is a different answer from `Some(None)` ("nothing more in the buffer")
    /// and is exactly the distinction [`Self::next_message`] lost before
    /// R311y613.
    fn deframe_until_desync(&mut self) -> Option<Option<(usize, Vec<u8>)>> {
        loop {
            let frame_start = self.base;
            let frame = match self.take_frame() {
                Frame::Need => return Some(None),
                Frame::Bad(reason) => {
                    self.desynchronise(reason);
                    return None;
                }
                Frame::Got(f) => f,
            };
            match frame.opcode {
                OP_CLOSE | OP_PING | OP_PONG | OP_TEXT => {
                    // Control frames may be interleaved INSIDE a fragmented
                    // message (RFC6455 §5.4), so dropping one must not touch
                    // `partial` — clearing it here would truncate the message
                    // being assembled around it.
                    self.skipped_frames += 1;
                }
                OP_BINARY => {
                    if self.partial_offset.is_some() {
                        // A new message starting while one is unfinished means
                        // the frame boundary is not where this reader thinks.
                        self.desynchronise(WsDesyncReason::MessageBoundary);
                        return None;
                    }
                    self.partial = frame.payload;
                    self.partial_offset = Some(frame_start);
                    if frame.fin {
                        return Some(self.take_partial());
                    }
                }
                OP_CONTINUATION => {
                    if self.partial_offset.is_none() {
                        self.desynchronise(WsDesyncReason::MessageBoundary);
                        return None;
                    }
                    if self.partial.len() + frame.payload.len() > MAX_WS_PAYLOAD {
                        self.desynchronise(WsDesyncReason::UnusableHeader);
                        return None;
                    }
                    self.partial.extend_from_slice(&frame.payload);
                    if frame.fin {
                        return Some(self.take_partial());
                    }
                }
                opcode => {
                    // A reserved opcode means this is not the protocol we
                    // think it is; guessing past it would invent messages.
                    self.desynchronise(WsDesyncReason::ReservedOpcode { opcode });
                    return None;
                }
            }
        }
    }

    /// Hand back the assembled message and reset the accumulator.
    fn take_partial(&mut self) -> Option<(usize, Vec<u8>)> {
        let offset = self.partial_offset.take()?;
        Some((offset, core::mem::take(&mut self.partial)))
    }

    /// Consume the HTTP upgrade handshake. `false` means "not yet all here".
    fn step_over_preamble(&mut self) -> bool {
        const END: &[u8] = b"\r\n\r\n";
        if let Some(at) = find(&self.buf, END) {
            let cut = at + END.len();
            self.buf.drain(..cut);
            self.base += cut;
            self.preamble_done = true;
            return true;
        }
        if self.buf.len() > MAX_PREAMBLE {
            // Detected as WebSocket on four bytes and then never terminated:
            // whatever this stream is, it is not an upgrade handshake.
            self.desynchronise(WsDesyncReason::PreambleNeverEnded);
        }
        false
    }

    /// Parse and consume ONE frame off the front of the buffer.
    fn take_frame(&mut self) -> Frame {
        if self.buf.len() < 2 {
            return Frame::Need;
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let fin = (b0 & 0x80) != 0;
        // RSV1..3 are extension bits. zenoh negotiates no extension, so a set
        // bit means the payload is transformed in a way this reader cannot
        // undo — and a compressed payload handed on as if it were plain would
        // decode into confident nonsense.
        if (b0 & 0x70) != 0 {
            return Frame::Bad(WsDesyncReason::UnusableHeader);
        }
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len7 = (b1 & 0x7F) as usize;

        let mut cursor = 2usize;
        let payload_len = match len7 {
            126 => {
                if self.buf.len() < cursor + 2 {
                    return Frame::Need;
                }
                let n = u16::from_be_bytes([self.buf[cursor], self.buf[cursor + 1]]) as usize;
                cursor += 2;
                n
            }
            127 => {
                if self.buf.len() < cursor + 8 {
                    return Frame::Need;
                }
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.buf[cursor..cursor + 8]);
                cursor += 8;
                let n = u64::from_be_bytes(raw);
                // On a 32-bit target the cast would wrap; refusing above the
                // cap first makes the conversion total.
                if n > MAX_WS_PAYLOAD as u64 {
                    return Frame::Bad(WsDesyncReason::UnusableHeader);
                }
                n as usize
            }
            n => n,
        };
        if payload_len > MAX_WS_PAYLOAD {
            return Frame::Bad(WsDesyncReason::UnusableHeader);
        }
        let mut key = [0u8; 4];
        if masked {
            if self.buf.len() < cursor + 4 {
                return Frame::Need;
            }
            key.copy_from_slice(&self.buf[cursor..cursor + 4]);
            cursor += 4;
        }
        let total = cursor + payload_len;
        if self.buf.len() < total {
            return Frame::Need;
        }
        let mut payload = self.buf[cursor..total].to_vec();
        if masked {
            // Client-to-server frames are masked by RFC6455 §5.3, so the
            // dialer's whole half of a zenoh session arrives XORed. Skipping
            // this would leave that direction decoding into noise while the
            // acceptor's direction read fine — a half-working dissection,
            // which is worse than none.
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i & 3];
            }
        }
        self.buf.drain(..total);
        self.base += total;
        Frame::Got(ParsedFrame {
            fin,
            opcode,
            payload,
        })
    }
}

/// One parsed RFC6455 frame.
struct ParsedFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// What [`WsDeframer::take_frame`] found.
enum Frame {
    /// A whole frame.
    Got(ParsedFrame),
    /// Not all here yet — wait for more bytes.
    Need,
    /// This is not RFC6455, and why.
    Bad(WsDesyncReason),
}

/// First index of `needle` in `haystack`. `no_std` and no dependencies, so the
/// naive scan is written out; the inputs are one HTTP preamble.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build one RFC6455 frame the way a real endpoint would.
    /// R311y613 — `pub(crate)` so the FLOW-level tests build their damage with
    /// the same helper the deframer's own tests do. A second frame builder is
    /// how two fixtures come to disagree about the wire.
    pub(crate) fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 | opcode } else { opcode });
        let masked_bit = if mask.is_some() { 0x80u8 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(masked_bit | n as u8),
            n if n <= u16::MAX as usize => {
                out.push(masked_bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(masked_bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                for (i, b) in payload.iter().enumerate() {
                    out.push(b ^ key[i & 3]);
                }
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    const UPGRADE: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";

    #[test]
    fn the_detector_answers_for_both_halves_of_the_handshake() {
        assert_eq!(http_upgrade_verdict(b"GET / HTTP/1.1"), UpgradeVerdict::Yes);
        assert_eq!(
            http_upgrade_verdict(b"HTTP/1.1 101 Switching Protocols"),
            UpgradeVerdict::Yes
        );
    }

    /// THE ONE THAT CAUGHT A REAL STALL. A framed KeepAlive is three bytes, so
    /// a verdict that waited for four would hold such a flow forever — no
    /// messages, no error, which is the exact failure this module exists to
    /// end, reintroduced one layer up. Divergence must settle it at byte one.
    #[test]
    fn a_short_zenoh_opening_is_settled_without_waiting_for_four_bytes() {
        assert_eq!(http_upgrade_verdict(&[1, 0, 0x0F]), UpgradeVerdict::No);
        assert_eq!(http_upgrade_verdict(&[1]), UpgradeVerdict::No);
        assert_eq!(http_upgrade_verdict(&[0x0F]), UpgradeVerdict::No);
    }

    /// The other half of the same rule: bytes that are still consistent with an
    /// opening must NOT be decided early, or a one-byte-at-a-time arrival would
    /// classify a real handshake as a plain stream on its first `G`.
    #[test]
    fn a_prefix_of_an_opening_waits() {
        assert_eq!(http_upgrade_verdict(b"G"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"GE"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"H"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"HTT"), UpgradeVerdict::NeedMore);
        // ...but a byte that leaves both openings is settled at once.
        assert_eq!(http_upgrade_verdict(b"GX"), UpgradeVerdict::No);
    }

    #[test]
    fn a_masked_binary_frame_comes_back_unmasked() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(
            true,
            OP_BINARY,
            b"zenoh",
            Some([0xAA, 0xBB, 0xCC, 0xDD]),
        ));
        let (offset, msg) = d.next_message().expect("one message");
        assert_eq!(&msg[..], b"zenoh");
        assert_eq!(
            offset,
            UPGRADE.len(),
            "the offset is where the FRAME started, past the preamble"
        );
        assert!(d.next_message().is_none());
        assert!(!d.desynchronised());
    }

    /// THE ONE THAT MATTERS for a real capture: the dialer's whole half of a
    /// zenoh session is masked, so an unmasking bug leaves exactly one
    /// direction decoding into noise.
    #[test]
    fn masked_and_unmasked_halves_yield_the_same_bytes() {
        let payload = b"\x0f-the-same-bytes";
        let mut client = WsDeframer::new();
        client.push(UPGRADE);
        client.push(&frame(true, OP_BINARY, payload, Some([1, 2, 3, 4])));
        let mut server = WsDeframer::new();
        server.push(b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
        server.push(&frame(true, OP_BINARY, payload, None));
        assert_eq!(
            client.next_message().expect("client message").1,
            server.next_message().expect("server message").1
        );
    }

    #[test]
    fn a_fragmented_message_reassembles_and_keeps_its_first_offset() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        let start = UPGRADE.len();
        d.push(&frame(false, OP_BINARY, b"ze", None));
        // A Ping interleaved between fragments is legal (RFC6455 §5.4) and
        // must not truncate the message being assembled.
        d.push(&frame(true, OP_PING, b"", None));
        d.push(&frame(true, OP_CONTINUATION, b"noh", None));
        let (offset, msg) = d.next_message().expect("the reassembled message");
        assert_eq!(&msg[..], b"zenoh");
        assert_eq!(offset, start, "attributed to the FIRST fragment");
        assert_eq!(d.skipped_frames(), 1, "the Ping is counted, not hidden");
    }

    #[test]
    fn a_16_bit_extended_length_is_read() {
        let payload = alloc::vec![0x5Au8; 300];
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(true, OP_BINARY, &payload, None));
        assert_eq!(d.next_message().expect("300-byte message").1.len(), 300);
    }

    #[test]
    fn a_frame_arriving_in_pieces_waits_instead_of_guessing() {
        let bytes = frame(true, OP_BINARY, b"zenoh", None);
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        for byte in &bytes[..bytes.len() - 1] {
            d.push(&[*byte]);
            assert!(d.next_message().is_none(), "incomplete frame must wait");
        }
        d.push(&bytes[bytes.len() - 1..]);
        assert_eq!(&d.next_message().expect("now complete").1[..], b"zenoh");
        assert!(!d.desynchronised());
    }

    #[test]
    fn an_impossible_length_desynchronises_rather_than_allocating() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        // 127 => a 64-bit length, here u64::MAX.
        d.push(&[0x82, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(d.next_message().is_none());
        assert!(
            d.desynchronised(),
            "a length nothing could satisfy must stop the reader, not size a Vec"
        );
    }

    /// R311y610 — an announced hole stops this deframer, and the arm that
    /// matters is what it stops it from DOING.
    ///
    /// The spliced bytes below are a complete, well-formed ws frame — a
    /// deframer that read across the hole would hand up a message assembled
    /// from two runs the sender never wrote adjacently, and nothing in RFC6455
    /// would object. So the assertion is not "it reports the gap"; it is that
    /// the message that would have been fabricated is not produced.
    ///
    /// R311y612 — and it now holds STRUCTURALLY rather than by arithmetic:
    /// `note_gap` discards the near-side tail, so there are no pre-hole bytes
    /// left for a scan to join to the post-hole ones. Before R311y612 the
    /// deframer simply stopped forever, which passed this test and failed the
    /// one below it.
    #[test]
    fn an_announced_gap_stops_the_deframer_fabricating_a_message() {
        let bytes = frame(true, OP_BINARY, b"zenoh", None);
        let mut intact = WsDeframer::new();
        intact.push(UPGRADE);
        intact.push(&bytes);
        assert_eq!(
            &intact.next_message().expect("the control arm decodes").1[..],
            b"zenoh",
            "these bytes ARE a message, which is what makes the other arm a test"
        );

        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&bytes[..2]);
        d.note_gap(9);
        d.push(&bytes[2..]);
        assert!(
            d.next_message().is_none(),
            "the same bytes must not become a message across an announced hole"
        );
        assert!(d.desynchronised());
        assert_eq!(
            d.desync_reason(),
            Some(WsDesyncReason::CaptureGap { bytes_missing: 9 }),
            "the size of the hole is the source's measurement, not an inference"
        );
    }

    /// One zenoh batch inside one ws BINARY frame, unmasked. A bare KeepAlive
    /// is the shortest thing zenoh puts on a ws link and its MID is a credible
    /// transport header, which is what the chain discriminator anchors on.
    fn zenoh_frame(n: u8) -> Vec<u8> {
        let mut payload = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        payload.extend_from_slice(&[n; 3]);
        frame(true, OP_BINARY, &payload, None)
    }

    /// R311y612 (§4.2) — THE ROUND'S DEFECT, with the arm that proves it was
    /// one.
    ///
    /// A ws flow that loses one segment used to report every LATER message on
    /// the flow as absent — the deframer's desynchronisation was terminal, so a
    /// capture with one dropped packet came back saying the session went silent
    /// at that byte. The control arm is the same corpus at `chain_depth = 0`,
    /// which IS the pre-R311y612 behaviour: it must produce nothing after the
    /// hole, or this test is measuring something that was never broken.
    #[test]
    fn an_announced_gap_no_longer_ends_the_flow() {
        let mut after = Vec::new();
        for i in 0..6u8 {
            after.extend_from_slice(&zenoh_frame(i));
        }

        let mut dead = WsDeframer::new().with_chain_depth(0);
        dead.push(UPGRADE);
        dead.note_gap(40);
        dead.push(&after);
        assert!(
            dead.next_message().is_none(),
            "recovery off is the pre-R311y612 reader, and it must stay silent \
             — an arm that recovers anyway would make the live arm vacuous"
        );

        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        // A truncated frame header on the near side of the hole: the exact
        // shape that would let a reader claim a 63-bit length across it.
        d.push(&zenoh_frame(9)[..2]);
        d.note_gap(40);
        d.push(&after);

        let (offset, first) = d.next_message().expect("the reader finds a boundary");
        let resync = d.take_resync().expect("the recovery is REPORTED");
        assert_eq!(
            resync.reason,
            WsDesyncReason::CaptureGap { bytes_missing: 40 }
        );
        assert_eq!(
            resync.resumed_offset, offset,
            "the recovery names the offset the first message after it starts at"
        );
        assert_eq!(
            resync.skipped,
            offset - resync.desync_offset,
            "skipped is what this reader will never deframe, measured and not \
             asserted"
        );
        assert_eq!(resync.confirmed, WS_CHAIN_DEPTH);
        assert_eq!(
            first[0],
            wz_session_core::wire_const::T_MID_KEEP_ALIVE,
            "the resumed boundary is a real one, not a plausible-looking offset"
        );

        let mut decoded = 1usize;
        while d.next_message().is_some() {
            decoded += 1;
        }
        assert_eq!(
            decoded, 6,
            "every message after the hole decodes; before R311y612 this was 0"
        );
        assert!(!d.desynchronised());
        assert_eq!(
            d.accounting(),
            WsResyncAccounting {
                desyncs: 1,
                recoveries: 1,
                skipped_bytes: resync.skipped as u64,
            }
        );
    }

    /// R311y612 — a recovery must not graft the far side of a hole onto the
    /// near side, and the fixture makes that the ONLY way to succeed wrongly.
    ///
    /// The near side is the first half of a message whose second half is the
    /// hole's far side. A deframer that kept its buffered tail and scanned
    /// through it would confirm the boundary that predates the gap and hand up
    /// `zenoh` — a message the sender never wrote as one run.
    #[test]
    fn a_recovery_never_joins_the_two_sides_of_a_hole() {
        let straddling = frame(true, OP_BINARY, b"\x0fzenoh-payload", None);
        let mut tail = Vec::new();
        for i in 0..6u8 {
            tail.extend_from_slice(&zenoh_frame(i));
        }

        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&straddling[..6]);
        d.note_gap(4);
        d.push(&straddling[6..]);
        d.push(&tail);

        let mut seen = Vec::new();
        while let Some((_, msg)) = d.next_message() {
            seen.push(msg);
        }
        assert_eq!(
            seen.len(),
            6,
            "only the six intact frames after the hole; the straddling message \
             must not be reassembled across it"
        );
        for msg in &seen {
            assert_ne!(
                &msg[..],
                b"\x0fzenoh-payload",
                "the two sides of the hole were joined into a message"
            );
        }
    }

    /// R311y613 (§4.5) — THE STRUCTURAL DESYNCS RECOVER, not only the announced
    /// one.
    ///
    /// R311y612 built one recovery path and reached it from one direction. Every
    /// [`WsDesyncReason`] routes through the same `desynchronise` → `try_resync`
    /// pair, so the CODE was shared from the start — but a shared seam is a
    /// claim until something drives both ends of it, and the three STRUCTURAL
    /// reasons (a reserved opcode, a broken message boundary, an unusable
    /// header) had only their DETECTION proven. Whether the reader then came
    /// back was untested, and "it is the same function" is exactly the argument
    /// that has been wrong here before.
    ///
    /// Each arm is a table row rather than three near-copies, and each carries
    /// its own `chain_depth = 0` control: without it a green here would be
    /// consistent with a deframer that never desynchronised on that input at
    /// all, and the test would be measuring nothing.
    #[test]
    fn every_structural_desync_recovers_and_not_only_the_announced_one() {
        // Six good frames after the damage: more than `WS_CHAIN_DEPTH`, so the
        // scan has a chain to confirm AND messages left over to hand up.
        let mut tail = Vec::new();
        for i in 0..6u8 {
            tail.extend_from_slice(&zenoh_frame(i));
        }

        // Each row: what to push before the tail, and the reason it must be
        // reported as. The damage is built by the same `frame` helper the good
        // frames are, so a row cannot be wrong about its own wire shape.
        let rows: Vec<(&str, Vec<u8>, WsDesyncReason)> = alloc::vec![
            (
                // Opcode 0x3 is reserved: not a protocol this reader knows.
                "reserved opcode",
                frame(true, 0x3, b"\x01reserved", None),
                WsDesyncReason::ReservedOpcode { opcode: 0x3 },
            ),
            (
                // A CONTINUATION with no message open — the frame boundary is
                // not where this reader believes it is.
                "message boundary",
                frame(true, OP_CONTINUATION, b"\x01orphan", None),
                WsDesyncReason::MessageBoundary,
            ),
            (
                // A non-final BINARY opens a message; a second BINARY starting
                // while it is unfinished is the other half of the same fault.
                "interrupted message",
                {
                    let mut v = frame(false, OP_BINARY, b"\x01first", None);
                    v.extend_from_slice(&frame(true, OP_BINARY, b"\x01second", None));
                    v
                },
                WsDesyncReason::MessageBoundary,
            ),
        ];

        for (name, damage, reason) in rows {
            // THE CONTROL. `chain_depth = 0` is the pre-R311y612 reader; if it
            // produces messages after the damage, this row's damage never
            // desynchronised anything and the live arm below proves nothing.
            let mut dead = WsDeframer::new().with_chain_depth(0);
            dead.push(UPGRADE);
            dead.push(&damage);
            dead.push(&tail);
            let mut before_recovery = 0usize;
            while dead.next_message().is_some() {
                before_recovery += 1;
            }
            assert!(
                dead.desynchronised(),
                "{name}: the fixture did not desynchronise the reader at all"
            );
            assert_eq!(
                dead.desync_reason(),
                Some(reason),
                "{name}: desynchronised for a different reason than the row claims"
            );

            let mut d = WsDeframer::new();
            d.push(UPGRADE);
            d.push(&damage);
            d.push(&tail);
            let mut recovered = 0usize;
            while d.next_message().is_some() {
                recovered += 1;
            }
            assert_eq!(
                recovered,
                before_recovery + 6,
                "{name}: the six frames after the damage did not come back"
            );
            assert!(
                !d.desynchronised(),
                "{name}: still desynchronised at the end"
            );

            let acc = d.accounting();
            assert_eq!(acc.desyncs, 1, "{name}: expected exactly one desync");
            assert_eq!(acc.recoveries, 1, "{name}: the recovery was not counted");
            // A STRUCTURAL desync skips nothing, and that is the honest number
            // rather than a missing one: the damaged frame is CONSUMED by
            // `take_frame` and only then judged, so `base` is already past it
            // when the desynchronisation is recorded and the scan confirms the
            // very next boundary. The announced (`CaptureGap`) arm is the
            // opposite shape — it drops the buffered near side and reports what
            // it dropped — which is why the two cannot share one expectation.
            assert_eq!(
                acc.skipped_bytes, 0,
                "{name}: a structural recovery resumed somewhere other than the \
                 boundary right after the damage"
            );
        }
    }

    /// R311y613 (§4.5) — and the recovery is REPORTED with the reason that
    /// caused it, so a reader is never told the flow was clean.
    ///
    /// Separate from the sweep above because it asserts about the
    /// [`WsResync`] RECORD rather than about message counts, and folding the
    /// two would let a missing record hide behind a right count.
    #[test]
    fn a_structural_recovery_names_the_reason_it_recovered_from() {
        let mut tail = Vec::new();
        for i in 0..6u8 {
            tail.extend_from_slice(&zenoh_frame(i));
        }
        let damage = frame(true, 0x3, b"\x01reserved", None);

        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&damage);
        d.push(&tail);

        let (offset, first) = d.next_message().expect("the reader comes back");
        let resync = d.take_resync().expect("and says so");
        assert_eq!(
            resync.reason,
            WsDesyncReason::ReservedOpcode { opcode: 0x3 }
        );
        assert_eq!(
            resync.resumed_offset, offset,
            "the record names the offset the first message after it starts at"
        );
        assert_eq!(
            resync.skipped,
            offset - resync.desync_offset,
            "skipped is measured off the desynchronisation point, not asserted"
        );
        assert_eq!(resync.confirmed, WS_CHAIN_DEPTH);
        assert_eq!(
            first[0],
            wz_session_core::wire_const::T_MID_KEEP_ALIVE,
            "the boundary resumed at is a real one"
        );
    }

    /// R311y612 (§4.1) — a flow classified as WebSocket with its HTTP opening
    /// LOST finds its first frame boundary by scanning, and the preamble is
    /// what it scans over.
    ///
    /// Load-bearing detail: HTTP is ASCII, and ASCII is refuted at essentially
    /// every offset by the discriminator's own clauses (a letter sets bit 0x40
    /// or 0x20, which are RSV bits; `\r` is a reserved opcode; `\n` is a
    /// control opcode with FIN clear). So the scan walks the preamble it was
    /// never told about and lands on the first real frame.
    #[test]
    fn a_deframer_with_no_opening_scans_to_the_first_boundary() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(UPGRADE);
        for i in 0..6u8 {
            bytes.extend_from_slice(&zenoh_frame(i));
        }
        let mut d = WsDeframer::after_lost_opening(0);
        d.push(&bytes);
        let (offset, first) = d.next_message().expect("the scan finds the frames");
        assert_eq!(
            offset,
            UPGRADE.len(),
            "the boundary found is the first real frame, past the preamble"
        );
        assert_eq!(first[0], wz_session_core::wire_const::T_MID_KEEP_ALIVE);
        let resync = d.take_resync().expect("the lost opening is reported");
        assert_eq!(resync.reason, WsDesyncReason::OpeningLost);
        assert_eq!(resync.skipped, UPGRADE.len());
    }

    /// R311y612 — the scan's memory bound, on the same argument as the stream
    /// path's: `WS_RESYNC_SCAN_WINDOW` is a GUARANTEE, so bytes past it that
    /// confirmed nothing cannot be framed and are dropped rather than held.
    ///
    /// A run of 0x7F refuses at every offset by construction (`0x7F & 0x70`
    /// sets RSV bits), which is what makes the branch reachable at all — every
    /// corpus of plausible bytes recovers long before 64 KiB.
    #[test]
    fn a_ws_scan_that_confirms_nothing_drops_what_it_cannot_frame() {
        let noise = alloc::vec![0x7Fu8; WS_RESYNC_SCAN_WINDOW + 4096];
        let mut d = WsDeframer::after_lost_opening(0);
        d.push(&noise);
        assert!(d.next_message().is_none());
        assert!(d.desynchronised());
        assert!(
            d.buffered() <= WS_RESYNC_SCAN_WINDOW + 1,
            "unframeable bytes past the window are dropped, not retained; held \
             {}",
            d.buffered()
        );

        let mut good = Vec::new();
        for i in 0..6u8 {
            good.extend_from_slice(&zenoh_frame(i));
        }
        d.push(&good);
        d.next_message().expect("the chain confirms");
        let resync = d.take_resync().expect("the resumption is reported");
        assert_eq!(
            resync.skipped,
            noise.len(),
            "skipped counts the DROPPED bytes too, or the accounting loses \
             exactly what memory did"
        );
    }

    /// R311y612 — THE MEASUREMENT the default depth is read off.
    ///
    /// A chain discriminator is only worth having if it refuses the two things
    /// a ws boundary must never be confused with: arbitrary bytes, and a REAL
    /// length-prefixed zenoh stream (the other framing this crate carries, and
    /// the one a misclassification actually swaps for). Both corpora are swept
    /// at several depths and the accept rate is printed, so the number in
    /// `WS_CHAIN_DEPTH` is a reading rather than a preference.
    ///
    /// The assertion is on the SET of depths that hold, not on one: a depth-`d`
    /// chain is a prefix of a depth-`d+1` chain, so an accept rate that rises
    /// with depth would be an impossibility, and checking for it is what
    /// caught the same flaw one framing layer down.
    #[test]
    fn the_ws_chain_discriminator_refuses_noise() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        const TRIALS: usize = 40;
        const LEN: usize = 4096;

        // Corpus 1: arbitrary bytes.
        let noise: Vec<Vec<u8>> = (0..TRIALS)
            .map(|_| (0..LEN).map(|_| (next() >> 24) as u8).collect())
            .collect();
        // Corpus 2: a REAL zenoh stream — 2-byte little-endian length prefix
        // then the message — which is precisely what a misclassified ws flow
        // would be read as, and the other way round.
        let streams: Vec<Vec<u8>> = (0..TRIALS)
            .map(|_| {
                let mut buf = Vec::new();
                while buf.len() < LEN {
                    let mut body = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
                    let n = 1 + ((next() >> 32) as usize % 40);
                    body.extend((0..n).map(|_| (next() >> 24) as u8));
                    buf.extend_from_slice(&(body.len() as u16).to_le_bytes());
                    buf.extend_from_slice(&body);
                }
                buf
            })
            .collect();

        let rate = |corpus: &[Vec<u8>], depth: usize| -> usize {
            corpus
                .iter()
                .filter(|buf| carries_ws_frames(buf, depth))
                .count()
        };

        let mut noise_rates = Vec::new();
        let mut stream_rates = Vec::new();
        for depth in 1..=8usize {
            let n = rate(&noise, depth);
            let s = rate(&streams, depth);
            std::eprintln!(
                "ws chain depth {depth}: noise {n}/{TRIALS} accepted, \
                 zenoh-stream {s}/{TRIALS} accepted"
            );
            noise_rates.push(n);
            stream_rates.push(s);
        }
        for w in noise_rates.windows(2) {
            assert!(
                w[1] <= w[0],
                "a deeper chain cannot accept more often: {noise_rates:?}"
            );
        }
        for w in stream_rates.windows(2) {
            assert!(
                w[1] <= w[0],
                "a deeper chain cannot accept more often: {stream_rates:?}"
            );
        }
        let at_default = WS_CHAIN_DEPTH - 1;
        assert_eq!(
            noise_rates[at_default], 0,
            "at the shipped depth the discriminator must refuse every noise \
             buffer; got {noise_rates:?}"
        );
        assert_eq!(
            stream_rates[at_default], 0,
            "and every REAL zenoh stream, which is the corpus a \
             misclassification would actually swap for; got {stream_rates:?}"
        );
        // ...and it is the SHALLOWEST depth that does, so the constant is not
        // quietly deeper than the evidence asks for. A recovery costs a whole
        // extra message per unit of depth on a flow that has few left, so
        // "deeper is always safer" is not free and is not assumed here.
        assert!(
            at_default == 0 || noise_rates[at_default - 1] > 0 || stream_rates[at_default - 1] > 0,
            "one depth shallower already refuses everything, so WS_CHAIN_DEPTH \
             is deeper than measured: noise {noise_rates:?} stream \
             {stream_rates:?}"
        );
    }

    #[test]
    fn a_reserved_bit_stops_the_reader() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        // RSV1 set: a negotiated extension transformed the payload.
        d.push(&[0xC2, 0x02, 0x00, 0x00]);
        assert!(d.next_message().is_none());
        assert!(d.desynchronised());
    }

    #[test]
    fn a_continuation_without_a_start_is_not_invented_into_a_message() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(true, OP_CONTINUATION, b"orphan", None));
        assert!(d.next_message().is_none());
        assert!(d.desynchronised());
    }
}
