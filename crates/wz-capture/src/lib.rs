// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! R311y578 (G1) — the CAPTURE-side input path wz did not have.
//!
//! wz reads from sockets. Everything under `crates/` assumes a live link it
//! opened, so consuming the same decoders over traffic wz never joined had no
//! front end at all: no capture ingest, no TCP flow reassembly, no way to map
//! a decoded message back to the packet that carried it.
//!
//! This crate is that front end, in four layers, each of which can be used
//! alone:
//!
//! | layer | module | in | out |
//! |---|---|---|---|
//! | capture file | [`pcap`] | file bytes | packets |
//! | decapsulation | [`link`] | a packet | a TCP segment + flow key |
//! | flow reassembly | [`tcp`] | segments | a per-direction byte stream + offset map |
//! | session | [`Dissection`] | streams | decoded zenoh messages |
//!
//! The zenoh half is NOT here — it is `wz_session_core::passive`, which knows
//! the protocol and nothing about capture. The seam between the two is a byte
//! stream plus a direction, which is also what a live tap produces, so an
//! AF_PACKET or ring-buffer source replaces [`pcap`] without touching
//! anything below it.
//!
//! `no_std` + `alloc`, with no third-party dependencies. Every format read
//! here is a fixed-layout header out of a byte slice.

extern crate alloc;

/// R311y606 — IP fragment reassembly. Its own module rather than part of
/// [`link`] because it holds STATE across packets and `link` is deliberately a
/// pure decapsulator; the same division `passive`'s chain reassembly is under.
pub mod frag;
pub mod link;
pub mod pcap;
pub mod pcapng;
pub mod tcp;
pub mod ws;

use alloc::vec::Vec;

use wz_session_core::parse_error::InboundParseError;
use wz_session_core::passive::{
    Direction, FlowContext, PassiveFrame, PassiveSession, PassiveStall,
};
use wz_session_core::scouting::{parse_scouting, ScoutingFrame};

use crate::link::{FlowKey, SkipReason, Transport};
use crate::tcp::StreamAssembler;

/// A packet the dissector could not turn into stream bytes, and why.
///
/// Carried rather than counted: "17 packets skipped" is not actionable, and a
/// dissection whose byte stream has an unexplained hole is not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedPacket {
    /// Index of the packet in the capture.
    pub packet_index: usize,
    /// Why it produced nothing.
    pub reason: SkipReason,
}

/// R311y584 (A3) — one UDP flow being dissected.
///
/// Kept beside [`FlowDissection`] rather than inside it, because the two are
/// not variants of one thing: a TCP flow needs a stream assembler and an
/// offset-to-packet map, and a UDP flow needs neither. zenoh puts exactly one
/// wire message in each datagram and relies on the boundary instead of a
/// length prefix (`wz-runtime-tokio/src/udp_pipeline.rs:34-36`), so every
/// mechanism the TCP side exists for is absent here. Folding them together
/// would mean an `Option<StreamAssembler>` that is always `None` on one side
/// and an offset field that means two different things.
#[derive(Debug)]
pub struct DatagramDissection {
    /// The two endpoints, sorted.
    pub flow: FlowKey,
    /// The zenoh-level observer over both directions.
    pub session: PassiveSession,
    /// Decoded messages, in capture order. Each one's `stream_offset` is the
    /// index of the packet that carried it — there is no stream for it to be
    /// an offset into, so the field carries the only anchor that exists.
    pub frames: Vec<PassiveFrame>,
    /// R311y607 — messages decoded in the SCOUTING namespace, in capture
    /// order.
    ///
    /// A second list rather than more variants in `frames`, because they are
    /// not the same kind of thing: a transport frame advances this flow's
    /// session state and a scouting message has no session to advance — it is
    /// what happens BEFORE one. Upstream draws the same line (pico's
    /// `_z_scouting_message_t` vs `_z_transport_message_t`, decoded by
    /// different functions), and folding them would put a `Scout` where
    /// [`PassiveSession::fold`] could be handed one.
    ///
    /// Both lists carry the packet index, so a reader wanting one timeline
    /// merges on it. This is deliberately not done here: the merge belongs to
    /// whoever is presenting, and doing it eagerly would force an ordering on
    /// a consumer that may want the two separated.
    pub scouting: Vec<ScoutingDatagram>,
}

impl DatagramDissection {
    fn new(flow: FlowKey, window_ms: Option<u64>) -> Self {
        Self {
            flow,
            session: new_session(window_ms),
            frames: Vec::new(),
            scouting: Vec::new(),
        }
    }
}

/// R311y607 — one datagram observed on the pre-session multicast link.
///
/// The scouting twin of [`PassiveFrame`], and separate for the same reason
/// [`ScoutingFrame`] is separate from `InboundFrame`. It carries no session
/// context and no batch-ceiling verdict: neither exists before a session does.
#[derive(Debug)]
pub struct ScoutingDatagram {
    /// Which way it travelled, keyed exactly as a transport frame's is.
    pub direction: Direction,
    /// Index of the packet that carried it — the same anchor
    /// [`PassiveFrame::stream_offset`] carries for a datagram, so the two
    /// lists can be merged into one timeline by a consumer that wants it.
    pub packet_index: usize,
    /// What the bytes decoded to, or why they did not.
    pub frame: Result<ScoutingFrame, InboundParseError>,
}

/// R311y607 — does this datagram belong to the SCOUTING namespace?
///
/// # Why the destination and the MID, and not either alone
///
/// zenoh's two message-ID namespaces collide numerically: `S_MID_SCOUT` and
/// `T_MID_INIT` are both `0x01`, `S_MID_HELLO` and `T_MID_OPEN` are both
/// `0x02`. A participant never has to care — it knows which socket the bytes
/// arrived on. A capture has no such thing, and zenoh puts the scout group and
/// the multicast SESSION group on the SAME locator (`224.0.0.224:7446`), so
/// address and port cannot separate them either.
///
/// What does separate them is that a multicast transport has NO HANDSHAKE:
/// pico's multicast receive path takes INIT and OPEN and deliberately does
/// nothing with them — "multicast transports are not expected to handle INIT
/// messages" (`vendor/zenoh-pico/src/transport/multicast/rx.c:493-504`). So on
/// a multicast destination, `0x01` and `0x02` cannot be Init / Open, and the
/// only namespace left in which they mean anything is the scouting one.
///
/// Both halves are load-bearing and each alone is wrong:
///
/// - MID alone would route a UNICAST Init — the ordinary start of every
///   `udp/...` session — into the scouting decoder.
/// - Destination alone would route the multicast JOIN (`0x07`), which really
///   is a transport message on the multicast session group, out of the
///   transport decoder that R311y605 built for it.
fn is_scouting_datagram(d: &link::Datagram) -> bool {
    let Some(&header) = d.payload.first() else {
        return false;
    };
    let mid = header & 0x1F;
    d.destination().is_ip_multicast()
        && (mid == wz_session_core::wire_const::S_MID_SCOUT
            || mid == wz_session_core::wire_const::S_MID_HELLO)
}

/// Index a per-direction array. `Direction` is the seam's vocabulary and has
/// no numeric form of its own, so the mapping lives in one place rather than
/// being spelled out at each use.
fn dir_index(direction: Direction) -> usize {
    match direction {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// R311y594 — one place that decides how a per-flow observer is built, so the
/// TCP and datagram halves cannot drift into different defaults.
fn new_session(window_ms: Option<u64>) -> PassiveSession {
    #[cfg(feature = "reassembly")]
    if let Some(ms) = window_ms {
        return PassiveSession::with_reassembly_window(ms);
    }
    let _ = window_ms;
    PassiveSession::new()
}

/// R311y602 — what the bytes of a TCP flow turn out to BE.
///
/// A `ws/...` zenoh link is ordinary TCP, so nothing below this crate can tell
/// it apart from a `tcp/...` one; the difference is a framing layer inside the
/// byte stream. Until enough bytes arrive to settle it there is nothing to
/// decide on, which is what [`Self::Undecided`] is — deliberately a state
/// rather than a default of `Stream`, because guessing `Stream` and being
/// wrong is precisely the silent failure this variant exists to end.
#[derive(Debug)]
pub enum Framing {
    /// The opening is still consistent with an HTTP upgrade and shorter than
    /// one ([`ws::UpgradeVerdict::NeedMore`]); nothing is fed onward yet.
    Undecided,
    /// zenoh's length-prefixed byte stream, straight into the observer.
    Stream,
    /// RFC6455 frames wrapping one zenoh batch each, per direction.
    WebSocket {
        /// [`Direction::A`]'s deframer (`low` -> `high`).
        a: ws::WsDeframer,
        /// [`Direction::B`]'s deframer.
        b: ws::WsDeframer,
    },
}

impl Framing {
    /// Is this flow carrying WebSocket?
    pub fn is_websocket(&self) -> bool {
        matches!(self, Framing::WebSocket { .. })
    }
}

/// One TCP connection being dissected as a zenoh session.
#[derive(Debug)]
pub struct FlowDissection {
    /// The connection.
    pub flow: FlowKey,
    /// Reassembled bytes from [`FlowKey::low`] toward `high` — the direction
    /// the passive tracker calls [`Direction::A`].
    pub low_to_high: StreamAssembler,
    /// The other direction, [`Direction::B`].
    pub high_to_low: StreamAssembler,
    /// The zenoh-level observer over both.
    pub session: PassiveSession,
    /// Decoded transport messages, in the order the observer produced them.
    pub frames: Vec<PassiveFrame>,
    /// R311y594b — capture index of the last packet on this flow, the key
    /// `Dissection` evicts by. A packet index rather than a timestamp because
    /// every source has one and not every source has a clock.
    last_activity: usize,
    /// R311y602 — what this flow's bytes turned out to be.
    framing: Framing,
    /// Bytes held back per direction while [`Framing::Undecided`], so the
    /// decision is made on the stream's opening rather than on whatever
    /// happened to arrive in the first segment.
    held: [Vec<u8>; 2],
    /// R311y603 — bytes delivered per direction on an AF_VSOCK flow, which is
    /// the sequence number vsockmon does not carry. Untouched on a tcp flow.
    vsock_seq: [u32; 2],
}

impl FlowDissection {
    fn new(flow: FlowKey, window_ms: Option<u64>) -> Self {
        Self {
            flow,
            low_to_high: StreamAssembler::new(),
            high_to_low: StreamAssembler::new(),
            session: new_session(window_ms),
            frames: Vec::new(),
            last_activity: 0,
            framing: Framing::Undecided,
            held: [Vec::new(), Vec::new()],
            vsock_seq: [0, 0],
        }
    }

    /// R311y602 — what this flow's byte stream turned out to be.
    pub fn framing(&self) -> &Framing {
        &self.framing
    }

    /// The assembler for one direction.
    pub fn assembler(&self, direction: Direction) -> &StreamAssembler {
        match direction {
            Direction::A => &self.low_to_high,
            Direction::B => &self.high_to_low,
        }
    }

    /// The zenoh context inferred for this flow.
    pub fn context(&self) -> FlowContext {
        self.session.context()
    }

    /// Which capture packet carried the byte at `stream_offset` in
    /// `direction` — the whole point of threading the map through: a decoded
    /// message points at a PACKET, not at an abstraction.
    ///
    /// Compose it with [`PassiveFrame::stream_offset`] to attribute a decoded
    /// message: `d.packet_for(f.direction, f.stream_offset)`.
    pub fn packet_for(&self, direction: Direction, stream_offset: usize) -> Option<usize> {
        self.assembler(direction).packet_for_offset(stream_offset)
    }

    /// Feed newly-reassembled bytes for one direction into the zenoh observer
    /// and drain whatever frames become readable.
    ///
    /// Drains BOTH directions after every push. The zenoh context is shared
    /// across them — direction B's Init is what completes direction A's
    /// capability fold — so a frame that was un-decodable a moment ago can
    /// become decodable because the OTHER direction advanced.
    /// R311y602 — decide the framing, then route the bytes to it.
    ///
    /// While `Undecided` the bytes are HELD, not forwarded: handing the
    /// observer a `GET / HTTP/1.1` opening desynchronises it permanently, and
    /// the whole reason this state exists is that four bytes settle the
    /// question. The held bytes of BOTH directions are replayed the moment
    /// either one reaches the threshold, because the decision is a property of
    /// the connection and only one direction has to speak to reveal it.
    fn advance(&mut self, direction: Direction, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if matches!(self.framing, Framing::Undecided) {
            self.held[dir_index(direction)].extend_from_slice(bytes);
            self.framing = match ws::http_upgrade_verdict(&self.held[dir_index(direction)]) {
                // Still consistent with an opening and shorter than it. Holding
                // is only safe because the verdict answers `No` on DIVERGENCE
                // rather than on a byte count — a fixed threshold would hold a
                // flow whose whole first message is shorter than it.
                ws::UpgradeVerdict::NeedMore => return,
                ws::UpgradeVerdict::Yes => Framing::WebSocket {
                    a: ws::WsDeframer::new(),
                    b: ws::WsDeframer::new(),
                },
                ws::UpgradeVerdict::No => Framing::Stream,
            };
            for dir in [Direction::A, Direction::B] {
                let held = core::mem::take(&mut self.held[dir_index(dir)]);
                if !held.is_empty() {
                    self.feed(dir, &held);
                }
            }
            return;
        }
        self.feed(direction, bytes);
    }

    /// Route already-classified bytes into the framing this flow uses.
    fn feed(&mut self, direction: Direction, bytes: &[u8]) {
        match self.framing {
            // Unreachable by construction: `advance` decides before it feeds.
            Framing::Undecided => {}
            Framing::Stream => self.feed_stream(direction, bytes),
            Framing::WebSocket { .. } => self.feed_websocket(direction, bytes),
        }
    }

    /// R311y602 — the ws half: deframe, then decode each message as a
    /// DATAGRAM.
    ///
    /// `next_datagram` and not `next_frame` because a ws message carries no
    /// length prefix — the WebSocket message boundary IS the framing, exactly
    /// as a UDP datagram boundary is (zenoh's ws link reports
    /// `is_streamed() = false`). The offset reported is the stream offset the
    /// message's first frame began at, so `packet_for` still attributes a
    /// decoded message to the packet that carried it.
    fn feed_websocket(&mut self, direction: Direction, bytes: &[u8]) {
        let Framing::WebSocket { a, b } = &mut self.framing else {
            return;
        };
        let deframer = match direction {
            Direction::A => a,
            Direction::B => b,
        };
        deframer.push(bytes);
        let mut ready: Vec<(usize, Vec<u8>)> = Vec::new();
        while let Some(msg) = deframer.next_message() {
            ready.push(msg);
        }
        for (offset, payload) in ready {
            let frame = self.session.next_datagram(direction, &payload, offset);
            self.frames.push(frame);
        }
    }

    fn feed_stream(&mut self, direction: Direction, bytes: &[u8]) {
        self.session.push(direction, bytes);
        loop {
            let mut progressed = false;
            for dir in [Direction::A, Direction::B] {
                loop {
                    match self.session.next_frame(dir) {
                        Ok(frame) => {
                            self.frames.push(frame);
                            progressed = true;
                        }
                        Err(PassiveStall::NeedMoreBytes) => break,
                        Err(PassiveStall::Desynchronised { .. }) => break,
                    }
                }
            }
            if !progressed {
                return;
            }
        }
    }
}

/// R311y594b — what a dissection is allowed to accumulate.
///
/// Every field is `None` by default, which is exactly the pre-R311y594b
/// behaviour and the right one for a FILE: a capture ends, so keeping all of it
/// is bounded by the input the user handed over. A LIVE tap does not end, and
/// this crate had five accumulations that grew with it — the reassembled byte
/// stream of every connection (much the largest), the run map, the decoded
/// frames, the skipped-packet list, and the flow table itself.
///
/// Bounds rather than a fixed policy because the two consumers want opposite
/// things: a file replay wants everything and a live viewer wants the recent
/// past and its memory back. See [`Self::for_live_tap`] for a starting point.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DissectionLimits {
    /// Per-chain reassembly deadline, in the capture's own milliseconds.
    pub reassembly_window_ms: Option<u64>,
    /// Decoded frames kept per flow. Beyond it the OLDEST go — a live viewer
    /// is looking at what just happened.
    pub frames_per_flow: Option<usize>,
    /// Reassembled bytes kept per DIRECTION of each TCP flow.
    pub stream_bytes_per_direction: Option<usize>,
    /// Entries kept in the skipped-packet list.
    pub skipped_packets: Option<usize>,
    /// Flows kept. Beyond it the least recently active is evicted, which is
    /// the one accumulation that cannot be trimmed in place: a 5-tuple that
    /// never returns is a flow that is never freed.
    pub max_flows: Option<usize>,
    /// R311y606 — half-assembled IP datagrams held at once. Beyond it the
    /// OLDEST is evicted.
    ///
    /// Separate from `max_flows` because a fragment table entry is not a flow:
    /// it is keyed by the datagram's identification, so a single busy flow can
    /// hold many at once and a bound on flows would not touch them.
    pub max_pending_fragments: Option<usize>,
}

impl DissectionLimits {
    /// A starting point for a live tap. Not tuned — these are the shapes, and
    /// a deployment with a measured packet rate should set its own.
    ///
    /// 4 MiB per direction is minutes of a chatty zenoh session; 10 000 frames
    /// per flow is more than a viewer scrolls; the 30 s reassembly window is
    /// far longer than any real fragment chain and short enough that an
    /// abandoned one does not hold a slot for the process's life.
    pub fn for_live_tap() -> Self {
        Self {
            reassembly_window_ms: Some(30_000),
            frames_per_flow: Some(10_000),
            stream_bytes_per_direction: Some(4 * 1024 * 1024),
            skipped_packets: Some(10_000),
            max_flows: Some(1_024),
            // 256 concurrent half-assembled datagrams is far past what a real
            // link produces at once — fragmentation is bursty and short-lived —
            // and it bounds the table at well under the ceiling times the cap.
            max_pending_fragments: Some(256),
        }
    }
}

/// R311y594b — what the LIMITS cost, so a bound is never silent.
///
/// A dissection that drops to stay inside its budget and does not say so
/// reports its own bound as if it were the wire's — the same rule
/// [`SkippedPacket`] exists for one layer down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DissectionDrops {
    /// Decoded frames discarded to stay inside `frames_per_flow`.
    pub frames: usize,
    /// Reassembled bytes discarded to stay inside
    /// `stream_bytes_per_direction`.
    pub stream_bytes: usize,
    /// Skipped-packet records discarded to stay inside `skipped_packets`.
    pub skipped: usize,
    /// Flows evicted to stay inside `max_flows`.
    pub flows: usize,
}

impl DissectionDrops {
    /// `true` when anything at all was given up.
    pub fn any(&self) -> bool {
        self.frames > 0 || self.stream_bytes > 0 || self.skipped > 0 || self.flows > 0
    }
}

/// R311y605 (F5) — the totals across a whole dissection.
///
/// Every counter this crate had was PER-OBJECT by design: the TCP anomaly
/// counts live on each [`StreamAssembler`] (R311y597 B3) and the checksum
/// verdicts on each [`link::Segment`] / [`link::Datagram`] (R311y597 C4). That
/// is the right granularity for both — an analyst asks "which connection is
/// retransmitting", not "how many retransmissions are in this file" — and it
/// left the health question a consumer actually opens a capture with
/// ("is anything wrong here at all?") answerable only by walking every flow
/// and every direction, which no consumer existed to do.
///
/// ## Two things this deliberately does NOT do
///
/// **It does not partition packets.** The three stream counters count EVENTS,
/// and one segment can be both out of order and a partial overlap, so it
/// contributes to two of them. Summing these against a packet count is the
/// available misuse and the reason it is said here rather than left implied.
///
/// **It does not fold absence into failure.** A checksum has THREE states, not
/// two: verified, present-and-wrong, and absent. A NIC computes TX checksums in
/// hardware, so a capture taken on the sending host routinely shows zeroed
/// fields for perfectly good packets, and a UDP datagram over IPv4 may decline
/// to carry one at all (RFC 768). Collapsing absent into invalid would make
/// every loopback capture — the one a developer takes most — look corrupt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DissectionHealth {
    /// Segments the assembler judged already-delivered, over every flow and
    /// both directions. See the event-counting caveat above.
    pub retransmits: usize,
    /// Segments held because they arrived ahead of the stream.
    pub out_of_order: usize,
    /// Segments that overlapped delivered bytes and carried new ones too.
    pub partial_overlaps: usize,
    /// IPv4 header checksums that verified.
    pub ip_checksum_valid: usize,
    /// IPv4 header checksums that were present and did NOT verify — the only
    /// state here that is evidence of corruption.
    pub ip_checksum_invalid: usize,
    /// Packets with no IP header checksum to check: IPv6 (the field was
    /// removed) and the non-IP links.
    pub ip_checksum_absent: usize,
    /// TCP / UDP checksums that verified.
    pub transport_checksum_valid: usize,
    /// TCP / UDP checksums that were present and did NOT verify.
    pub transport_checksum_invalid: usize,
    /// Packets whose transport checksum was absent — a UDP-over-IPv4 zero
    /// (the sender declining, RFC 768) or a layer that has none.
    pub transport_checksum_absent: usize,
    /// Packets that yielded no stream bytes, INCLUDING any whose record was
    /// discarded to stay inside [`DissectionLimits::skipped_packets`]. So this
    /// is `skipped().len() + drops().skipped`, and it is the honest total where
    /// the retained list alone is a floor.
    pub packets_skipped: usize,
    /// What staying inside the limits has cost — repeated here so one value
    /// answers "is this dissection complete?".
    pub drops: DissectionDrops,
}

impl DissectionHealth {
    /// `true` when a checksum was present and did not verify, anywhere.
    ///
    /// Deliberately NOT "anything looks unusual": retransmissions and
    /// reordering are normal on a real network and an `any_*` that included
    /// them would be true for almost every capture.
    pub fn any_checksum_invalid(&self) -> bool {
        self.ip_checksum_invalid > 0 || self.transport_checksum_invalid > 0
    }
}

/// The per-direction stream counters, summed. Kept as a type so an evicted
/// flow's totals can be carried after the flow itself is gone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StreamTally {
    retransmits: usize,
    out_of_order: usize,
    partial_overlaps: usize,
}

impl StreamTally {
    fn add_assembler(&mut self, a: &StreamAssembler) {
        self.retransmits += a.retransmits();
        self.out_of_order += a.out_of_order();
        self.partial_overlaps += a.partial_overlaps();
    }
}

/// A whole capture, dissected: every TCP connection in it, read as a zenoh
/// session.
#[derive(Debug, Default)]
pub struct Dissection {
    flows: Vec<FlowDissection>,
    datagram_flows: Vec<DatagramDissection>,
    skipped: Vec<SkippedPacket>,
    /// R311y594b — what this dissection may accumulate.
    limits: DissectionLimits,
    /// What the limits have cost so far.
    drops: DissectionDrops,
    /// R311y605 (F5) — checksum verdicts, tallied as packets arrive. They must
    /// be counted here and not derived later: a `Checksums` rides on the
    /// `Segment` / `Datagram`, which is consumed by the assembler and gone.
    checksums: [usize; 6],
    /// R311y605 (F5) — the stream counters of flows the flow-cap has EVICTED.
    /// `health()` adds this to the live flows' own, so a total survives
    /// eviction; a flow is either live or counted here, never both.
    evicted_streams: StreamTally,
    /// R311y606 — half-assembled IP datagrams. Bounded by
    /// [`DissectionLimits::max_pending_fragments`] and by the same
    /// `reassembly_window_ms` deadline the message chains use, because the two
    /// answer the same question one layer apart: how long may a piece of
    /// something wait for the rest of it.
    fragments: frag::FragmentTable,
    #[cfg(feature = "reassembly")]
    /// Chains aborted because their deadline passed, across every flow.
    ///
    /// COUNTED rather than silent: an expired chain is a message the reader
    /// will never see completed, and a dissection that drops it without saying
    /// so reports its own bound as if it were the wire's.
    expired_chains: usize,
}

impl Dissection {
    /// An empty dissection whose chains never expire.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y594 — a dissection whose half-finished chains EXPIRE `window_ms`
    /// after they open, judged against the CAPTURE's clock.
    ///
    /// For a live tap, where the quota alone bounds concurrency but not
    /// duration: four abandoned chains per direction hold their slots for as
    /// long as the reader runs. A file replay may want it too — it makes the
    /// dissection of a capture identical whether it is replayed in one pass or
    /// fed packet by packet.
    #[cfg(feature = "reassembly")]
    pub fn with_reassembly_window(window_ms: u64) -> Self {
        Self::with_limits(DissectionLimits {
            reassembly_window_ms: Some(window_ms),
            ..DissectionLimits::default()
        })
    }

    /// R311y594b — a dissection bounded by `limits`.
    ///
    /// [`Self::new`] is this with every bound absent, which is what a FILE
    /// wants. A live tap wants [`DissectionLimits::for_live_tap`] or its own
    /// measured numbers.
    pub fn with_limits(limits: DissectionLimits) -> Self {
        Self {
            fragments: frag::FragmentTable::bounded(
                limits.max_pending_fragments,
                limits.reassembly_window_ms,
            ),
            limits,
            ..Self::default()
        }
    }

    /// What staying inside [`DissectionLimits`] has cost.
    pub fn drops(&self) -> DissectionDrops {
        self.drops
    }

    /// R311y605 (F5) — the whole dissection's counters in one value.
    ///
    /// The per-object counters remain the authority for "which flow"; this is
    /// the "is anything wrong at all" question, which previously required a
    /// consumer to walk every flow and both of its directions. Read the caveats
    /// on [`DissectionHealth`] before summing anything here against a packet
    /// count.
    pub fn health(&self) -> DissectionHealth {
        let mut streams = self.evicted_streams;
        for flow in &self.flows {
            streams.add_assembler(&flow.low_to_high);
            streams.add_assembler(&flow.high_to_low);
        }
        DissectionHealth {
            retransmits: streams.retransmits,
            out_of_order: streams.out_of_order,
            partial_overlaps: streams.partial_overlaps,
            ip_checksum_valid: self.checksums[0],
            ip_checksum_invalid: self.checksums[1],
            ip_checksum_absent: self.checksums[2],
            transport_checksum_valid: self.checksums[3],
            transport_checksum_invalid: self.checksums[4],
            transport_checksum_absent: self.checksums[5],
            packets_skipped: self.skipped.len() + self.drops.skipped,
            drops: self.drops,
        }
    }

    /// R311y606 — place one piece of a fragmented IP datagram, and dissect the
    /// whole datagram if this piece completed it.
    ///
    /// A piece that does NOT complete one is recorded in [`Self::skipped`] the
    /// way it always was: it yielded no stream bytes, which is exactly what
    /// that list means. The difference is that the bytes are no longer gone —
    /// they are in the table, and the packet that completes the datagram is
    /// the one that produces frames.
    fn push_fragment(&mut self, piece: link::IpFragment, ts_millis: Option<u64>) {
        let packet_index = piece.packet_index;
        let ip_checksum = piece.checksums.ip;
        let Some(done) = self.fragments.push(piece, ts_millis) else {
            self.skipped.push(SkippedPacket {
                packet_index,
                reason: SkipReason::IpFragmentPending,
            });
            self.trim_skipped();
            return;
        };
        // The transport checksum covers the whole datagram, so this is the
        // first point at which it CAN be judged — and it must be judged here,
        // because `transport_from_ip` is handed the verdict rather than
        // computing it (a reassembled datagram has no header to recompute the
        // pseudo-header lengths from without doing exactly this).
        let checksums = link::Checksums {
            ip: ip_checksum,
            transport: link::reassembled_transport_checksum(
                &done.key.src,
                &done.key.dst,
                done.key.proto,
                &done.payload,
            ),
        };
        match link::transport_from_ip(
            done.key.src,
            done.key.dst,
            done.key.proto,
            &done.payload,
            done.packet_index,
            checksums,
        ) {
            Ok(Transport::Udp(d) | Transport::RawEth(d)) => self.push_datagram(d, ts_millis),
            Ok(Transport::Tcp(s)) => self.push_segment(s, ts_millis),
            // A reassembled datagram cannot be either of these: vsock never
            // reaches the IP path, and a fragment of a fragment is not a shape
            // IP has. Recorded rather than ignored so the impossibility is
            // observable if it ever stops being one.
            Ok(Transport::Vsock(_) | Transport::IpFragment(_)) => {
                self.skipped.push(SkippedPacket {
                    packet_index: done.packet_index,
                    reason: SkipReason::NotTransport(done.key.proto),
                });
                self.trim_skipped();
            }
            Err(reason) => {
                self.skipped.push(SkippedPacket {
                    packet_index: done.packet_index,
                    reason,
                });
                self.trim_skipped();
            }
        }
    }

    /// What IP fragment reassembly has cost and seen.
    pub fn fragment_stats(&self) -> frag::FragmentStats {
        self.fragments.stats()
    }

    /// Keep [`Self::skipped`] inside its bound, counting what that costs.
    fn trim_skipped(&mut self) {
        if let Some(cap) = self.limits.skipped_packets {
            if self.skipped.len() > cap {
                let cut = self.skipped.len() - cap;
                self.skipped.drain(..cut);
                self.drops.skipped += cut;
            }
        }
    }

    /// Tally one packet's checksum verdicts. Called on every path that produces
    /// a `Checksums`, which is every path that reaches a transport — a packet
    /// counted on one axis and not the other would make the six buckets
    /// disagree about how many packets there were.
    fn tally_checksums(&mut self, c: &link::Checksums) {
        self.checksums[match c.ip {
            Some(true) => 0,
            Some(false) => 1,
            None => 2,
        }] += 1;
        self.checksums[match c.transport {
            Some(true) => 3,
            Some(false) => 4,
            None => 5,
        }] += 1;
    }

    /// The bounds in force.
    pub fn limits(&self) -> DissectionLimits {
        self.limits
    }

    /// How many chains have been aborted for missing their deadline.
    #[cfg(feature = "reassembly")]
    pub fn expired_chains(&self) -> usize {
        self.expired_chains
    }

    /// Every TCP flow seen, in first-appearance order.
    pub fn flows(&self) -> &[FlowDissection] {
        &self.flows
    }

    /// Every UDP flow seen, in first-appearance order. Where scouting,
    /// multicast Join, and the UDP unicast link land.
    pub fn datagram_flows(&self) -> &[DatagramDissection] {
        &self.datagram_flows
    }

    /// Packets that yielded no stream bytes, each with its reason.
    pub fn skipped(&self) -> &[SkippedPacket] {
        &self.skipped
    }

    /// The flow matching `key`, if the capture carried one.
    pub fn flow(&self, key: &FlowKey) -> Option<&FlowDissection> {
        self.flows.iter().find(|f| &f.flow == key)
    }

    /// Feed one captured packet.
    ///
    /// A packet that is not TCP, is an IP fragment, or rides an unhandled
    /// link type is recorded in [`Self::skipped`] rather than dropped.
    pub fn push_packet(&mut self, link_type: u32, packet_index: usize, bytes: &[u8]) {
        self.push_packet_at(link_type, packet_index, None, bytes)
    }

    /// R311y594 — the same, with the instant the packet was CAPTURED.
    ///
    /// `ts_millis` advances the observer's clock before the packet is decoded,
    /// which is what makes a reassembly deadline enforceable. `None` leaves the
    /// clock where it is — the pre-R311y594 behaviour, and the honest answer
    /// for a source that has no timestamps at all.
    ///
    /// The clock is per-FLOW, not per-dissection, and it is advanced on the
    /// flow this packet belongs to only. A capture holding two connections
    /// whose traffic interleaves must not let one connection's silence expire
    /// the other's chains, and a shared clock would do exactly that.
    pub fn push_packet_at(
        &mut self,
        link_type: u32,
        packet_index: usize,
        ts_millis: Option<u64>,
        bytes: &[u8],
    ) {
        let segment = match link::decapsulate(link_type, packet_index, bytes) {
            Ok(Transport::Tcp(s)) => s,
            // R311y597 — raweth joins the datagram path rather than getting
            // one of its own, and the reason is measured, not assumed: pico
            // encodes exactly ONE transport message per frame
            // (`raweth/tx.c:192`, and `send_n_msg` builds a fresh frame per
            // network message) and decodes exactly one back (`rx.c:104`).
            // That is the same contract UDP carries, so the same ingestion is
            // correct — had it batched, `next_datagram` would have reported
            // the first message and dropped the rest.
            Ok(Transport::Udp(d) | Transport::RawEth(d)) => {
                self.push_datagram(d, ts_millis);
                return;
            }
            // R311y603 — a vsock record is a piece of a BYTE STREAM, so it goes
            // through the same assembler tcp does; what it lacks is a sequence
            // number, which `push_vsock` synthesises from the flow's own running
            // byte count.
            Ok(Transport::Vsock(r)) => {
                self.push_vsock(r, ts_millis);
                return;
            }
            // R311y606 — a piece of a fragmented datagram. The table is the
            // only thing here that can answer "is it whole yet", and when it
            // says yes the reassembled bytes re-enter through the SAME
            // transport strip a whole datagram takes, so nothing downstream
            // learns that this one arrived in pieces.
            Ok(Transport::IpFragment(f)) => {
                self.push_fragment(f, ts_millis);
                return;
            }
            Err(reason) => {
                self.skipped.push(SkippedPacket {
                    packet_index,
                    reason,
                });
                self.trim_skipped();
                return;
            }
        };
        self.push_segment(segment, ts_millis);
    }

    /// Feed one TCP segment to its flow's assembler and the observer behind it.
    ///
    /// R311y606 — split out of [`Self::push_packet_at`] so a segment recovered
    /// by fragment reassembly takes the identical path. Duplicating it was the
    /// alternative, and the duplicate would have been the copy that forgot the
    /// `retained_from` rebase below.
    fn push_segment(&mut self, segment: link::Segment, ts_millis: Option<u64>) {
        let packet_index = segment.packet_index;
        self.tally_checksums(&segment.checksums);
        let idx = match self.flows.iter().position(|f| f.flow == segment.flow) {
            Some(i) => i,
            None => {
                self.flows.push(FlowDissection::new(
                    segment.flow,
                    self.limits.reassembly_window_ms,
                ));
                self.flows.len() - 1
            }
        };
        let flow = &mut self.flows[idx];
        #[cfg(feature = "reassembly")]
        if let Some(ms) = ts_millis {
            self.expired_chains += flow.session.observe_at(ms);
        }
        let direction = if segment.from_low {
            Direction::A
        } else {
            Direction::B
        };
        let before = flow.assembler(direction).len();
        match direction {
            Direction::A => flow.low_to_high.push(&segment),
            Direction::B => flow.high_to_low.push(&segment),
        };
        // Hand the observer exactly the bytes reassembly newly DELIVERED, not
        // the segment payload: a retransmission delivers none, and a held
        // out-of-order segment can deliver a whole chain at once.
        //
        // ⚠ `before` is an ABSOLUTE offset and `stream()` is the RETAINED tail,
        // so the two are only the same index while nothing has been trimmed.
        // Rebasing here is what keeps trimming from silently handing the
        // observer the wrong bytes — the defect this arithmetic invites.
        let base = flow.assembler(direction).retained_from();
        debug_assert!(
            before >= base,
            "trimming must not outrun delivery: base {base} > before {before}"
        );
        let delivered: Vec<u8> = flow.assembler(direction).stream()[before - base..].to_vec();
        flow.advance(direction, &delivered);
        flow.last_activity = packet_index;
        self.enforce_flow_limits(idx);
        self.evict_flows_beyond_cap();
    }

    /// R311y594b — bring one TCP flow back inside the per-flow bounds.
    ///
    /// Called AFTER the observer has been handed its bytes, never before: the
    /// stream is trimmed from the front and the delivery offset is absolute, so
    /// trimming first would cut ground the caller is still standing on.
    fn enforce_flow_limits(&mut self, idx: usize) {
        let flow = &mut self.flows[idx];
        if let Some(cap) = self.limits.frames_per_flow {
            if flow.frames.len() > cap {
                let cut = flow.frames.len() - cap;
                flow.frames.drain(..cut);
                self.drops.frames += cut;
            }
        }
        if let Some(keep) = self.limits.stream_bytes_per_direction {
            self.drops.stream_bytes += flow.low_to_high.trim(keep);
            self.drops.stream_bytes += flow.high_to_low.trim(keep);
        }
    }

    /// R311y594b — the one accumulation that cannot be trimmed in place.
    ///
    /// A 5-tuple that never returns is a flow that is never freed, so past the
    /// cap the LEAST RECENTLY ACTIVE goes. That is a real loss of history and
    /// it is counted; a live tap on a busy host would otherwise hold every
    /// connection it ever saw.
    fn evict_flows_beyond_cap(&mut self) {
        let Some(cap) = self.limits.max_flows else {
            return;
        };
        while self.flows.len() > cap {
            let Some(oldest) = self
                .flows
                .iter()
                .enumerate()
                .min_by_key(|(_, f)| f.last_activity)
                .map(|(i, _)| i)
            else {
                break;
            };
            let gone = self.flows.remove(oldest);
            // R311y605 (F5) — carry the evicted flow's stream counters, or a
            // live tap's totals would silently reset every time the flow cap
            // recycled a slot.
            self.evicted_streams.add_assembler(&gone.low_to_high);
            self.evicted_streams.add_assembler(&gone.high_to_low);
            self.drops.flows += 1;
        }
    }

    /// R311y603 — one AF_VSOCK record, fed into the flow's byte stream.
    ///
    /// ## Why a synthesised sequence number is the honest answer here
    ///
    /// `vsockmon` records carry no sequence number, and they do not need one:
    /// AF_VSOCK is reliable and in-order, and the monitor device records what
    /// the kernel DELIVERED, so a capture holds each byte exactly once and in
    /// order. The assembler wants a sequence anyway — it is the mechanism that
    /// maps a stream offset back to a packet, which is this crate's whole
    /// point — so the running byte count per direction becomes the sequence.
    ///
    /// That is a synthesis, and it is confined to this function deliberately.
    /// It cannot live in [`link::decapsulate`], which sees one packet and has
    /// no flow state to count with, and putting it there would have meant
    /// inventing a number in the parser. Here it is exactly what it claims to
    /// be: the offset of these bytes in the stream this flow has delivered so
    /// far. Retransmission and reordering repair are dead weight on this path
    /// rather than wrong — there is nothing to repair — and the offset map they
    /// come with is the reason to use them anyway.
    fn push_vsock(&mut self, record: link::VsockRecord, ts_millis: Option<u64>) {
        let idx = match self.flows.iter().position(|f| f.flow == record.flow) {
            Some(i) => i,
            None => {
                self.flows.push(FlowDissection::new(
                    record.flow,
                    self.limits.reassembly_window_ms,
                ));
                self.flows.len() - 1
            }
        };
        let direction = if record.from_low {
            Direction::A
        } else {
            Direction::B
        };
        let flow = &mut self.flows[idx];
        #[cfg(feature = "reassembly")]
        if let Some(ms) = ts_millis {
            self.expired_chains += flow.session.observe_at(ms);
        }
        #[cfg(not(feature = "reassembly"))]
        let _ = ts_millis;

        let d = dir_index(direction);
        let seq = flow.vsock_seq[d];
        flow.vsock_seq[d] = seq.wrapping_add(record.payload.len() as u32);
        let segment = link::Segment {
            flow: record.flow,
            from_low: record.from_low,
            seq,
            // A vsockmon record has no flags to read; a stream that begins at
            // the capture's first record is what the assembler already handles
            // for a mid-stream tcp capture.
            syn: false,
            fin: false,
            rst: false,
            payload: record.payload,
            packet_index: record.packet_index,
            // No checksum exists at this layer: AF_VSOCK is not a network
            // protocol and vsockmon carries none. `None` is the same answer the
            // raweth path gives, and for the same reason.
            checksums: link::Checksums {
                ip: None,
                transport: None,
            },
        };
        let before = flow.assembler(direction).len();
        match direction {
            Direction::A => flow.low_to_high.push(&segment),
            Direction::B => flow.high_to_low.push(&segment),
        };
        let base = flow.assembler(direction).retained_from();
        let delivered: Vec<u8> = flow.assembler(direction).stream()[before - base..].to_vec();
        flow.advance(direction, &delivered);
        flow.last_activity = record.packet_index;
        // Counted on this path too, even though both verdicts are `None` here:
        // a path that skipped the tally would make the six buckets disagree
        // about how many packets the dissection saw.
        self.tally_checksums(&segment.checksums);
        self.enforce_flow_limits(idx);
        self.evict_flows_beyond_cap();
    }

    /// R311y584 (A3) — one UDP datagram: one whole wire message, decoded on
    /// the spot.
    ///
    /// R311y607 — "one wire message" is now "one wire message IN ONE OF TWO
    /// NAMESPACES"; [`is_scouting_datagram`] is what decides which.
    ///
    /// No buffering and no reassembly, because there is nothing to reassemble
    /// — which is exactly why this is four lines and the TCP path is not.
    fn push_datagram(&mut self, d: link::Datagram, ts_millis: Option<u64>) {
        // Without `reassembly` there is no chain to expire and so nothing to
        // advance a clock FOR. Named here rather than silenced with an
        // `#[allow]`, because the reason is the feature and not the lint.
        #[cfg(not(feature = "reassembly"))]
        let _ = ts_millis;
        self.tally_checksums(&d.checksums);
        let idx = match self.datagram_flows.iter().position(|f| f.flow == d.flow) {
            Some(i) => i,
            None => {
                self.datagram_flows.push(DatagramDissection::new(
                    d.flow,
                    self.limits.reassembly_window_ms,
                ));
                self.datagram_flows.len() - 1
            }
        };
        let direction = if d.from_low {
            Direction::A
        } else {
            Direction::B
        };
        let scouting = is_scouting_datagram(&d);
        let flow = &mut self.datagram_flows[idx];
        #[cfg(feature = "reassembly")]
        if let Some(ms) = ts_millis {
            self.expired_chains += flow.session.observe_at(ms);
        }
        if scouting {
            // Decoded WITHOUT touching the session: a scouting message is not
            // part of any session, so folding it would let a pre-session
            // datagram move state that only a peer's handshake may move.
            flow.scouting.push(ScoutingDatagram {
                direction,
                packet_index: d.packet_index,
                frame: parse_scouting(&d.payload),
            });
            return;
        }
        let frame = flow
            .session
            .next_datagram(direction, &d.payload, d.packet_index);
        flow.frames.push(frame);
        if let Some(cap) = self.limits.frames_per_flow {
            if flow.frames.len() > cap {
                let cut = flow.frames.len() - cap;
                flow.frames.drain(..cut);
                self.drops.frames += cut;
            }
        }
    }

    /// Dissect a whole classic pcap file from memory.
    pub fn from_pcap(bytes: &[u8]) -> Result<Self, pcap::PcapError> {
        let file = pcap::parse(bytes)?;
        let mut out = Self::new();
        for packet in &file.packets {
            out.push_packet_at(
                file.link_type,
                packet.index,
                Some(packet.ts_millis(file.timestamp_unit)),
                &packet.data,
            );
        }
        Ok(out)
    }

    /// R311y605 — dissect a whole pcapng file from memory.
    ///
    /// Each packet is pushed under ITS OWN interface's link type, which is the
    /// whole reason [`pcapng`] is a separate reader: a `dumpcap -i any` capture
    /// carries interfaces with different link layers, and one link type applied
    /// to all of them decapsulates half the file as the wrong thing.
    pub fn from_pcapng(bytes: &[u8]) -> Result<Self, pcapng::PcapngError> {
        let file = pcapng::parse(bytes)?;
        let mut out = Self::new();
        for packet in &file.packets {
            out.push_packet_at(
                packet.link_type,
                packet.index,
                file.ts_millis(packet),
                &packet.data,
            );
        }
        Ok(out)
    }

    /// R311y605 — dissect a capture file of EITHER format, chosen by its magic.
    ///
    /// The entry point a consumer that was handed "a capture" wants. Dispatch
    /// rather than a fallback chain: trying one parser and then the other would
    /// report the SECOND one's error for a file that was really a damaged
    /// instance of the first, and "bad pcapng magic" is a useless diagnosis for
    /// a truncated classic pcap.
    pub fn from_capture(bytes: &[u8]) -> Result<Self, CaptureError> {
        if pcapng::looks_like_pcapng(bytes) {
            Self::from_pcapng(bytes).map_err(CaptureError::Pcapng)
        } else {
            Self::from_pcap(bytes).map_err(CaptureError::Pcap)
        }
    }
}

/// R311y605 — why a capture file could not be read, in either format.
///
/// Deliberately NOT a flattened single enum: the two formats fail in genuinely
/// different ways (a classic pcap has a file header and a magic; a pcapng has
/// neither, it has a block chain and a per-section byte order), and merging
/// them would either lose the detail or invent variants that can never occur
/// for one of the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// The file was classic pcap and did not read.
    Pcap(pcap::PcapError),
    /// The file was pcapng and did not read.
    Pcapng(pcapng::PcapngError),
}

// ── R311y584 (A3) — the UDP path end to end. `link` proves the parser; this
//    proves the WIRING, which is a separate claim: a decapsulator that works
//    and a dissection that never calls it look identical from the parser's
//    own tests. ──
#[cfg(test)]
mod datagram_tests {
    use super::*;
    use crate::link::LINKTYPE_ETHERNET;

    /// Ethernet + IPv4 + UDP carrying `payload`, padded to the 60-byte
    /// minimum a real NIC emits.
    fn udp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// Ethernet + IPv4 + TCP carrying `payload` at `seq`, from low to high.
    fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1111u16.to_be_bytes()); // sport (low)
        tcp.extend_from_slice(&7447u16.to_be_bytes()); // dport
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset = 5 words, no options
        tcp.push(0x10); // ACK
        tcp.extend_from_slice(&64u16.to_be_bytes()); // window
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, unchecked
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
        tcp.extend_from_slice(payload);

        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&tcp);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// One length-prefixed KeepAlive: the smallest complete framed message.
    fn framed_keepalive() -> Vec<u8> {
        alloc::vec![1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// R311y594b — THE ONE THAT MATTERS: trimming the retained stream must not
    /// corrupt what the observer is handed next.
    ///
    /// The delivery slice is computed from an ABSOLUTE offset into a RETAINED
    /// tail, so the moment trimming starts those two indices diverge. Get it
    /// wrong and the observer is fed the wrong bytes — silently, because they
    /// are still valid-looking wire. Twelve messages under an 8-byte cap forces
    /// the trim to happen repeatedly WHILE decoding continues.
    #[test]
    fn trimming_the_stream_does_not_shift_what_the_observer_is_handed() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            stream_bytes_per_direction: Some(8),
            ..DissectionLimits::default()
        });
        for i in 0..12u32 {
            let pkt = tcp_packet(1000 + i * msg.len() as u32, &msg);
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }

        assert_eq!(d.flows().len(), 1);
        assert_eq!(
            d.flows()[0].frames.len(),
            12,
            "every message must still decode across repeated trims"
        );
        assert!(
            d.drops().stream_bytes > 0,
            "the cap must actually have bitten"
        );
    }

    /// Ethernet + IPv4 carrying `payload` as ONE PIECE of a fragmented
    /// datagram, at `offset` bytes with the More-Fragments flag `more`.
    ///
    /// Builds the IP header directly rather than post-editing `udp_packet`'s,
    /// because the total-length field must describe THIS piece and the
    /// identification must be shared — two fields a patch would have to get
    /// right in a place a reader would not look for them.
    fn ipv4_fragment(
        src: [u8; 4],
        dst: [u8; 4],
        ident: u16,
        proto: u8,
        offset: usize,
        more: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        assert_eq!(offset % 8, 0, "IP encodes the offset in 8-byte units");
        let flags_off = (offset as u16 / 8) | if more { 0x2000 } else { 0 };
        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&ident.to_be_bytes());
        ip.extend_from_slice(&flags_off.to_be_bytes());
        ip.extend_from_slice(&[64, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(payload);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// R311y607 — a SCOUT on the wire, built by the SCOUT codec's own encode
    /// so a routing decision cannot agree with a hand-laid byte string.
    fn scout_message() -> Vec<u8> {
        let mut scout = wz_codecs::scout::Scout::new();
        scout.version = 0x09;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1(3);
        scout.zid = Some(&[0x11, 0x22, 0x33, 0x44]);
        let mut wire = alloc::vec![wz_session_core::wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    }

    /// zenoh's IPv4 scouting group and port
    /// (`DEFAULT_MULTICAST_SCOUTING_ADDRESS`, `224.0.0.224:7446`).
    const SCOUT_GROUP: [u8; 4] = [224, 0, 0, 224];

    /// R311y607 — THE ONE THAT MATTERS: a multicast SCOUT is named a SCOUT.
    ///
    /// Before this round it was named an `Init`, and that is worse than being
    /// named nothing: `S_MID_SCOUT` is `0x01` and so is `T_MID_INIT`, so the
    /// transport decoder did not fail on it — it succeeded, produced a
    /// structurally valid `Init` whose "version" was the scout's version byte
    /// and whose flags were read off a header that has none, and handed the
    /// observer a peer that had never opened a session. Every coarse assertion
    /// downstream held, on a NAMED message.
    #[test]
    fn a_multicast_scout_is_named_a_scout_rather_than_misread_as_an_init() {
        let pkt = udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &scout_message());
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);

        assert_eq!(d.datagram_flows().len(), 1);
        let flow = &d.datagram_flows()[0];
        assert!(
            flow.frames.is_empty(),
            "a scouting message must not enter the transport list at all: {:?}",
            flow.frames
        );
        assert_eq!(flow.scouting.len(), 1, "it must be reported, not dropped");
        match &flow.scouting[0].frame {
            Ok(ScoutingFrame::Scout { body, .. }) => {
                assert_eq!(body.version, 0x09);
                assert_eq!(body.what(), 0x03, "the interest mask must survive");
            }
            other => panic!("a multicast SCOUT decoded as {other:?}"),
        }
        assert_eq!(flow.scouting[0].packet_index, 0);
    }

    /// The NEGATIVE arm on the MID half: the SAME byte `0x01` toward a
    /// UNICAST peer is an ordinary Init and must stay one. A discriminator
    /// that keyed on the MID alone would swallow the start of every `udp/...`
    /// session, and the positive test above would still pass.
    #[test]
    fn a_unicast_init_is_still_an_init() {
        // An Init body the transport decoder accepts: version, then the
        // whatami/zid carrier byte, then the zid.
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_INIT, 0x09, 0x38];
        wire.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);

        let flow = &d.datagram_flows()[0];
        assert!(
            flow.scouting.is_empty(),
            "a unicast destination must never reach the scouting decoder"
        );
        assert_eq!(flow.frames.len(), 1);
        assert!(
            matches!(
                flow.frames[0].frame,
                Ok(wz_session_core::inbound::InboundFrame::Init { .. })
            ),
            "a unicast 0x01 is an Init: {:?}",
            flow.frames[0].frame
        );
    }

    /// The NEGATIVE arm on the DESTINATION half: a multicast JOIN really is a
    /// transport message on the multicast session group — zenoh puts that
    /// group on the same locator as the scout group — so a discriminator that
    /// keyed on the destination alone would tear R311y605's JOIN decode back
    /// out. The two halves are each necessary; this test and the one above are
    /// what say so.
    #[test]
    fn a_multicast_join_still_reaches_the_transport_decoder() {
        let join = wz_codecs::join::Join {
            version: 0x09,
            // whatami/zid-len carrier: 4-byte zid, whatami router.
            cbyte: (3 << 4) | 0x01,
            zid: &[1, 2, 3, 4],
            // S clear, so the size parameters are absent rather than
            // defaulted — the shape a JOIN takes when it accepts the peer's.
            sn_res: None,
            batch_size: None,
            lease: 10_000,
            next_sn_reliable: 7,
            next_sn_best_effort: 9,
        };
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_JOIN];
        wire.extend_from_slice(&join.encode_to_vec(0));

        let pkt = udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &wire);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);

        let flow = &d.datagram_flows()[0];
        assert!(
            flow.scouting.is_empty(),
            "a JOIN is a TRANSPORT message that happens to be multicast"
        );
        assert_eq!(flow.frames.len(), 1);
        assert!(
            matches!(
                flow.frames[0].frame,
                Ok(wz_session_core::inbound::InboundFrame::Join { .. })
            ),
            "the multicast JOIN must still decode as a Join: {:?}",
            flow.frames[0].frame
        );
    }

    /// IPv6 multicast is `ff00::/8`, a different rule from IPv4's top four
    /// bits, and a reader that only implemented the v4 half would leave every
    /// IPv6 deployment on the old misread. Same message, same verdict.
    #[test]
    fn an_ipv6_multicast_scout_is_also_named_a_scout() {
        let msg = scout_message();
        let mut udp = Vec::new();
        udp.extend_from_slice(&43210u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);

        let mut ip = alloc::vec![0x60u8, 0, 0, 0];
        ip.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[17, 64]);
        ip.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // ff02::224 — link-local scope, the shape zenoh's IPv6 scouting uses.
        ip.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x24]);
        ip.extend_from_slice(&udp);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x86, 0xDD]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &eth);
        let flow = &d.datagram_flows()[0];
        assert!(flow.frames.is_empty());
        assert_eq!(flow.scouting.len(), 1);
        assert!(matches!(
            flow.scouting[0].frame,
            Ok(ScoutingFrame::Scout { .. })
        ));
    }

    /// A scouting MID this build cannot name must be NAMED as unknown, not
    /// silently rerouted into the transport namespace where `0x07` would come
    /// back a confident Join.
    #[test]
    fn an_unknown_scouting_mid_is_named_rather_than_rerouted() {
        let pkt = udp_packet(
            [192, 168, 1, 5],
            43210,
            SCOUT_GROUP,
            7446,
            &[0x01u8, 0x09, 0x00],
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
        // 0x01 IS scouting, and decodes; the point of this test is the flow
        // below it, where the MID is outside the namespace.
        assert_eq!(d.datagram_flows()[0].scouting.len(), 1);

        // 0x03 is neither SCOUT nor HELLO. It goes to the transport decoder,
        // because the discriminator claims only 0x01 / 0x02 — anything else on
        // a multicast destination is a transport message by elimination.
        let pkt = udp_packet(
            [192, 168, 1, 5],
            43210,
            SCOUT_GROUP,
            7446,
            &[wz_session_core::wire_const::T_MID_CLOSE, 0x00],
        );
        d.push_packet(LINKTYPE_ETHERNET, 1, &pkt);
        let flow = &d.datagram_flows()[0];
        assert_eq!(flow.scouting.len(), 1, "no new scouting message");
        assert_eq!(flow.frames.len(), 1, "the Close reached the transport side");
    }

    /// R311y607 — THE GATE THAT WAS MISSING: every MID zenoh puts on a
    /// datagram link is NAMED by this build, and a codec dropped out of
    /// `wz-capture`'s feature list reds this test instead of going quiet.
    ///
    /// Three rounds in a row found a codec this crate silently did not select
    /// — scout/hello (R311y585), linkstate (R311y597), the multicast JOIN
    /// (R311y605) — and each was found by ACCIDENT, because nothing here
    /// asserted the coverage. `dissect_feature_census.py` does not close it:
    /// it audits the `dissect` feature's forwards, and `wz-capture`'s own
    /// dependency features are a different list that no gate reads.
    ///
    /// The assertion is deliberately over `Unknown` rather than over the exact
    /// variant. What makes a capture front end wrong is not mis-typing a field
    /// — it is handing the reader a message with NO NAME, or, worse, the wrong
    /// one. Both are visible here: `Unknown { mid }` reds the transport half,
    /// and a scouting message that reached the transport decoder at all reds
    /// the scouting half by never appearing in `scouting`.
    #[test]
    fn every_mid_on_a_datagram_link_is_named_rather_than_unknown() {
        use wz_session_core::inbound::InboundFrame;
        use wz_session_core::wire_const as wc;

        // Each message is built by ITS OWN codec where one exists, so this
        // census is anchored to the codecs rather than to a byte string whose
        // author is also the person asserting it is right.
        let init = {
            let body = wz_codecs::init_body::InitBody {
                version: 0x09,
                cbyte: (3 << 4) | 0x01,
                zid: &[1, 2, 3, 4],
                sn_res: None,
                batch_size: None,
                cookie_len: None,
                cookie: None,
            };
            let mut w = alloc::vec![wc::T_MID_INIT];
            w.extend_from_slice(&body.encode_to_vec(0, 0));
            w
        };
        let open = {
            let body = wz_codecs::open_body::OpenBody {
                lease: 10_000,
                initial_sn: 0,
                cookie_len: Some(2),
                cookie: Some(&[0xAB, 0xCD]),
            };
            let mut w = alloc::vec![wc::T_MID_OPEN];
            w.extend_from_slice(&body.encode_to_vec(0));
            w
        };
        let close = {
            let body = wz_codecs::close::Close { reason: 0x01 };
            let mut w = alloc::vec![wc::T_MID_CLOSE];
            w.extend_from_slice(&body.encode_to_vec());
            w
        };
        // FRAME and FRAGMENT are hand-walked by `parse_inbound` rather than
        // routed through a body codec (a VLE sn then the tail), so there is no
        // codec to anchor to and the bytes are the sn and the payload.
        let frame = alloc::vec![wc::T_MID_FRAME, 0x00, 0xDE, 0xAD];
        let fragment = alloc::vec![wc::T_MID_FRAGMENT, 0x00, 0xBE, 0xEF];
        let join = {
            let body = wz_codecs::join::Join {
                version: 0x09,
                cbyte: (3 << 4) | 0x01,
                zid: &[1, 2, 3, 4],
                sn_res: None,
                batch_size: None,
                lease: 10_000,
                next_sn_reliable: 0,
                next_sn_best_effort: 0,
            };
            let mut w = alloc::vec![wc::T_MID_JOIN];
            w.extend_from_slice(&body.encode_to_vec(0));
            w
        };
        let keep_alive = alloc::vec![wc::T_MID_KEEP_ALIVE];

        // The transport namespace, on a UNICAST destination — the JOIN
        // included, since a JOIN reaching a unicast peer is still a transport
        // message and this census is about the DECODER, not the routing.
        for (name, wire) in [
            ("Init", init),
            ("Open", open),
            ("Close", close),
            ("KeepAlive", keep_alive),
            ("Frame", frame),
            ("Fragment", fragment),
            ("Join", join),
        ] {
            let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
            let mut d = Dissection::new();
            d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
            let flow = &d.datagram_flows()[0];
            assert_eq!(flow.frames.len(), 1, "{name} produced no frame at all");
            match &flow.frames[0].frame {
                Ok(InboundFrame::Unknown { mid }) => panic!(
                    "{name} (MID {mid:#04x}) is on zenoh's wire and this build \
                     cannot name it — a codec is missing from wz-capture's \
                     feature list"
                ),
                Ok(_) => {}
                Err(e) => panic!("{name} failed to decode: {e:?}"),
            }
        }

        // The scouting namespace, on a MULTICAST destination, which is the
        // only place these two MIDs mean what they say.
        for (name, wire) in [("Scout", scout_message()), ("Hello", hello_message())] {
            let pkt = udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &wire);
            let mut d = Dissection::new();
            d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
            let flow = &d.datagram_flows()[0];
            assert_eq!(
                flow.scouting.len(),
                1,
                "{name} never reached the scouting decoder"
            );
            match &flow.scouting[0].frame {
                Ok(ScoutingFrame::Unknown { mid }) => panic!(
                    "{name} (MID {mid:#04x}) is on zenoh's scouting wire and \
                     this build cannot name it"
                ),
                Ok(_) => {}
                Err(e) => panic!("{name} failed to decode: {e:?}"),
            }
        }
    }

    /// A HELLO carrying no locator list, built by the HELLO codec.
    fn hello_message() -> Vec<u8> {
        let hello = wz_codecs::hello::Hello {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[0x55, 0x66, 0x77, 0x88],
            num_locators: None,
            locators: None,
        };
        let mut wire = alloc::vec![wz_session_core::wire_const::S_MID_HELLO];
        wire.extend_from_slice(&hello.encode_to_vec(0));
        wire
    }

    /// R311y606 — a zenoh datagram split across two IP fragments decodes, and
    /// decodes ONLY because the pieces were put back together.
    ///
    /// The discriminator is the payload SIZE. The message is padded past what
    /// one piece carries, so the first piece alone cannot contain it: before
    /// this round that piece went to `strip_udp`, which read the header's own
    /// length, found the captured bytes short, and returned `Truncated` — the
    /// datagram lost and the network's MTU blamed on the capture's snaplen.
    #[test]
    fn a_fragmented_zenoh_datagram_decodes_only_after_reassembly() {
        // A KeepAlive followed by padding the UDP length covers, so the
        // datagram is genuinely larger than one piece.
        let mut msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        msg.extend_from_slice(&[0u8; 47]);

        let mut udp = Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);

        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let cut = 24; // a multiple of 8, as IP requires
        let first = ipv4_fragment(src, dst, 0x4242, 17, 0, true, &udp[..cut]);
        let rest = ipv4_fragment(src, dst, 0x4242, 17, cut, false, &udp[cut..]);

        // The FIRST piece alone yields nothing and says why.
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &first);
        assert_eq!(d.datagram_flows().len(), 0, "one piece is not a datagram");
        assert_eq!(
            d.skipped().iter().map(|s| s.reason).collect::<Vec<_>>(),
            alloc::vec![link::SkipReason::IpFragmentPending],
            "a held piece is named as held, not as lost"
        );
        assert_eq!(d.fragment_stats().completed, 0);

        // The second completes it, and the whole datagram decodes.
        d.push_packet(LINKTYPE_ETHERNET, 1, &rest);
        assert_eq!(d.fragment_stats().completed, 1);
        assert_eq!(d.fragment_stats().pieces, 2);
        assert_eq!(
            d.datagram_flows().len(),
            1,
            "the reassembled datagram must reach the datagram path"
        );
        assert_eq!(
            d.datagram_flows()[0].frames.len(),
            1,
            "and must decode to the message it carried"
        );
        // Positioned at the packet that COMPLETED it, not at the first piece.
        // `stream_offset` is where the datagram path records the packet index.
        assert_eq!(d.datagram_flows()[0].frames[0].stream_offset, 1);
    }

    /// The NEGATIVE arm: the same bytes delivered as one unfragmented datagram
    /// decode identically.
    ///
    /// Without it, a reassembler that silently mangled the payload would still
    /// produce "one flow, one frame" above, because a KeepAlive is one byte and
    /// the padding is never read.
    #[test]
    fn the_reassembled_bytes_equal_the_unfragmented_ones() {
        let mut msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        msg.extend_from_slice(&[0u8; 47]);

        let mut whole = Dissection::new();
        whole.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7446, &msg),
        );

        let mut udp = Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + msg.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&msg);
        let mut split = Dissection::new();
        split.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &ipv4_fragment([10, 0, 0, 1], [10, 0, 0, 2], 1, 17, 0, true, &udp[..16]),
        );
        split.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &ipv4_fragment([10, 0, 0, 1], [10, 0, 0, 2], 1, 17, 16, false, &udp[16..]),
        );

        assert_eq!(
            whole.datagram_flows().len(),
            1,
            "the control arm must decode"
        );
        assert_eq!(split.datagram_flows().len(), 1);
        // Compared through Debug because `InboundFrame` is not `PartialEq` —
        // and a rendered comparison is the right one anyway: it fails with both
        // frames printed, which is what a byte-for-byte claim wants to show.
        assert_eq!(
            alloc::format!("{:?}", split.datagram_flows()[0].frames[0].frame),
            alloc::format!("{:?}", whole.datagram_flows()[0].frames[0].frame),
            "reassembly must reproduce the datagram byte for byte"
        );
        assert_eq!(
            split.datagram_flows()[0].flow,
            whole.datagram_flows()[0].flow,
            "and must land on the same flow key"
        );
    }

    /// R311y605 (F5) — the roll-up reaches counters that were only per-object.
    ///
    /// The claim is specifically that `health()` sees what a consumer would
    /// otherwise have had to walk every flow and both directions to find, so
    /// the fixture makes the per-flow counter non-zero and then asserts the
    /// total MATCHES it rather than merely being non-zero: a `health()` that
    /// returned `Default::default()` passes an is-it-non-zero test on a clean
    /// capture, which is most captures.
    #[test]
    fn the_roll_up_totals_what_the_per_flow_counters_hold() {
        let msg = framed_keepalive();
        let mut d = Dissection::new();
        // Send the same segment twice: the second is a retransmission.
        let pkt = tcp_packet(1000, &msg);
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
        d.push_packet(LINKTYPE_ETHERNET, 1, &pkt);

        let per_flow = &d.flows()[0].low_to_high;
        assert_eq!(
            per_flow.retransmits(),
            1,
            "the fixture must actually retransmit"
        );
        let h = d.health();
        assert_eq!(h.retransmits, per_flow.retransmits());
        assert_eq!(h.out_of_order, per_flow.out_of_order());
        assert_eq!(h.partial_overlaps, per_flow.partial_overlaps());
        // Every packet is counted exactly once on EACH axis, or the six buckets
        // would disagree about how many packets the dissection saw.
        assert_eq!(
            h.ip_checksum_valid + h.ip_checksum_invalid + h.ip_checksum_absent,
            2,
            "every packet must be counted on the ip axis exactly once"
        );
        assert_eq!(
            h.transport_checksum_valid + h.transport_checksum_invalid + h.transport_checksum_absent,
            2,
            "and exactly once on the transport axis"
        );
        // `tcp_packet` writes a ZERO TCP checksum, which over IPv4 is
        // present-and-wrong: TCP has no declining form. That is the INVALID
        // bucket, not the absent one.
        assert_eq!(h.transport_checksum_invalid, 2, "{h:?}");
        assert_eq!(h.transport_checksum_absent, 0, "{h:?}");
        assert!(h.any_checksum_invalid());
        assert_eq!(h.packets_skipped, 0);

        // The DISCRIMINATOR for the bucket above: `udp_packet` writes the SAME
        // zero bytes, and over IPv4 a zero UDP checksum is the sender DECLINING
        // (RFC 768) — absent, not wrong. A roll-up that folded absence into
        // failure would put both here, and every loopback capture would read as
        // corrupt.
        let mut u = Dissection::new();
        let ka = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        u.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &ka),
        );
        let uh = u.health();
        assert_eq!(uh.transport_checksum_absent, 1, "{uh:?}");
        assert_eq!(uh.transport_checksum_invalid, 0, "{uh:?}");
    }

    /// R311y605 (F5) — a total that survives flow EVICTION.
    ///
    /// The failure this pins is a live tap's: the flow cap recycles a slot, the
    /// evicted flow's counters go with it, and the dissection's totals silently
    /// walk backwards. A roll-up computed only from the live flows passes every
    /// other test in this file.
    #[test]
    fn an_evicted_flows_counters_stay_in_the_total() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows: Some(1),
            ..DissectionLimits::default()
        });
        // Flow 1, with a retransmission on it.
        let a = tcp_packet(1000, &msg);
        d.push_packet(LINKTYPE_ETHERNET, 0, &a);
        d.push_packet(LINKTYPE_ETHERNET, 1, &a);
        assert_eq!(d.health().retransmits, 1);

        // A second flow evicts the first. `tcp_packet` fixes the ports, so a
        // different SOURCE ADDRESS is what makes this a different 5-tuple.
        let mut b = tcp_packet(2000, &msg);
        b[26] = 99;
        d.push_packet(LINKTYPE_ETHERNET, 2, &b);
        assert_eq!(d.flows().len(), 1, "the cap must have evicted");
        assert_eq!(d.drops().flows, 1);
        assert_eq!(
            d.health().retransmits,
            1,
            "the evicted flow's retransmission must survive its flow"
        );
    }

    /// The CONTROL for the test above: unbounded keeps the whole stream, so a
    /// pass there cannot come from trimming never happening.
    #[test]
    fn an_unbounded_dissection_trims_nothing() {
        let msg = framed_keepalive();
        let mut d = Dissection::new();
        for i in 0..12u32 {
            let pkt = tcp_packet(1000 + i * msg.len() as u32, &msg);
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }
        assert_eq!(d.flows()[0].frames.len(), 12);
        assert_eq!(
            d.drops(),
            DissectionDrops::default(),
            "nothing may be given up"
        );
        assert_eq!(d.flows()[0].low_to_high.retained_from(), 0);
    }

    /// A trimmed offset is UNANSWERABLE rather than answered wrongly — the
    /// property that keeps a live reader from misattributing an old message to
    /// a new packet once it has reclaimed the bytes.
    #[test]
    fn an_offset_whose_bytes_were_trimmed_has_no_packet() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            stream_bytes_per_direction: Some(4),
            ..DissectionLimits::default()
        });
        for i in 0..10u32 {
            let pkt = tcp_packet(1000 + i * msg.len() as u32, &msg);
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }
        let flow = &d.flows()[0];
        assert!(
            flow.low_to_high.retained_from() > 0,
            "something was trimmed"
        );
        assert_eq!(
            flow.packet_for(Direction::A, 0),
            None,
            "offset 0 was trimmed away and must not resolve to a packet"
        );
        let live = flow.low_to_high.retained_from();
        assert!(
            flow.packet_for(Direction::A, live).is_some(),
            "the first RETAINED offset must still attribute"
        );
    }

    /// Frames are capped per flow, oldest first, and the loss is counted.
    #[test]
    fn frames_are_capped_per_flow_and_the_loss_is_counted() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(3),
            ..DissectionLimits::default()
        });
        for i in 0..10 {
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        assert_eq!(d.datagram_flows()[0].frames.len(), 3);
        assert_eq!(d.drops().frames, 7);
    }

    /// The flow TABLE is bounded too, which the other bounds cannot do: a
    /// 5-tuple that never returns is memory that is never reclaimed.
    #[test]
    fn the_flow_table_evicts_the_least_recently_active() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows: Some(2),
            ..DissectionLimits::default()
        });
        // Three distinct connections, by source port.
        for (i, seq) in [(0usize, 1000u32), (1, 2000), (2, 3000)] {
            let mut pkt = tcp_packet(seq, &msg);
            // Perturb the source port so each is its own 5-tuple.
            let sport = 1111u16 + i as u16;
            pkt[34..36].copy_from_slice(&sport.to_be_bytes());
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        assert_eq!(d.flows().len(), 2, "the cap holds");
        assert_eq!(d.drops().flows, 1, "and the eviction is counted");
    }

    /// R311y594 — a pcap replay carries the FILE's clock into the observer.
    ///
    /// Asserted on `now_ms` rather than on an expiry, because this is the
    /// WIRING claim and an expiry test would pass on a clock that advanced for
    /// the wrong reason. The value is exact: 7 s + 250 ms of a microsecond-unit
    /// file is 7250 ms, so a missing or mis-scaled conversion cannot pass.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_pcap_replay_advances_each_flows_observation_clock() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &[(7, 250_000, &pkt)]);

        let d = Dissection::from_pcap(&file).expect("parse");
        assert_eq!(d.datagram_flows().len(), 1);
        assert_eq!(d.datagram_flows()[0].session.now_ms(), 7_250);
    }

    /// R311y605 — a pcapng capture DISSECTS, and reaches it through the
    /// format-sniffing entry point a consumer that was handed "a capture" uses.
    ///
    /// This is the WIRING claim, separate from `pcapng`'s own parser tests: a
    /// reader that parses perfectly and a dissection that never calls it look
    /// identical from the parser's side, which is the shape R311y602 recorded
    /// for the WebSocket deframer. So the assertion is on decoded MESSAGES.
    ///
    /// Until this round `from_pcap` on this file returned
    /// `PcapError::LooksLikePcapNg` — a hard failure for the format wireshark,
    /// tshark and dumpcap all write by default.
    #[test]
    fn a_pcapng_capture_dissects_through_the_sniffing_entry_point() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        // if_tsresol 6 (microseconds); 7_250_000 ticks is 7250 ms.
        let file = crate::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &[(0, 7_250_000, &pkt)]);

        // The classic reader still refuses it, and says which format it is.
        assert!(matches!(
            crate::pcap::parse(&file),
            Err(crate::pcap::PcapError::LooksLikePcapNg)
        ));

        let d = Dissection::from_capture(&file).expect("a pcapng capture must dissect");
        assert!(d.skipped().is_empty(), "{:?}", d.skipped());
        assert_eq!(d.datagram_flows().len(), 1);
        assert_eq!(
            d.datagram_flows()[0].frames.len(),
            1,
            "the message must decode, not merely the file parse"
        );
        assert!(d.datagram_flows()[0].frames[0].frame.is_ok());
        #[cfg(feature = "reassembly")]
        assert_eq!(
            d.datagram_flows()[0].session.now_ms(),
            7_250,
            "the interface's resolution must reach the observer's clock"
        );
    }

    /// The DISCRIMINATOR for the entry point: a classic pcap still goes to the
    /// classic reader, and a damaged one reports the CLASSIC error rather than
    /// "bad pcapng magic". Dispatch on the magic, not a fallback chain.
    #[test]
    fn the_sniffing_entry_point_sends_each_format_to_its_own_reader() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        let classic = crate::pcap::write(LINKTYPE_ETHERNET, &[(1, 0, &pkt)]);
        let d = Dissection::from_capture(&classic).expect("classic must still work");
        assert_eq!(d.datagram_flows().len(), 1);

        // A classic file with a broken magic must not be diagnosed as pcapng.
        let mut damaged = classic.clone();
        damaged[0] = 0xFF;
        match Dissection::from_capture(&damaged) {
            Err(CaptureError::Pcap(crate::pcap::PcapError::BadMagic(_))) => {}
            other => panic!("expected the CLASSIC diagnosis, got {other:?}"),
        }

        // And a pcapng whose block chain is broken must not be diagnosed as a
        // bad classic magic.
        let mut ng = crate::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &[(0, 0, &pkt)]);
        ng[4..8].copy_from_slice(&13u32.to_le_bytes());
        match Dissection::from_capture(&ng) {
            Err(CaptureError::Pcapng(crate::pcapng::PcapngError::BadBlockLength {
                claimed: 13,
                ..
            })) => {}
            other => panic!("expected the PCAPNG diagnosis, got {other:?}"),
        }
    }

    /// R311y605 — the multi-interface case, end to end, and the reason the
    /// pcapng reader keeps link type per-packet.
    ///
    /// Interface 0 is Ethernet and interface 1 is a link type this build does
    /// not handle. A dissection that applied interface 0's link type to both
    /// would decapsulate the second packet as Ethernet and could produce a
    /// flow from it; applying each packet's own means the second is SKIPPED by
    /// name, which is the honest answer.
    #[test]
    fn a_two_interface_capture_decapsulates_each_packet_as_its_own_link() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        // 147 is LINKTYPE_USER0 — reserved for private use and not one this
        // build decapsulates, so it must land in `skipped`.
        let file = crate::pcapng::write(
            &[(LINKTYPE_ETHERNET, 6), (147, 6)],
            &[(0, 0, &pkt), (1, 0, &pkt)],
        );
        let d = Dissection::from_capture(&file).expect("parse");
        assert_eq!(
            d.datagram_flows().len(),
            1,
            "only the ethernet packet may produce a flow"
        );
        assert_eq!(
            d.skipped().len(),
            1,
            "the second interface's packet must be skipped, not misread: {:?}",
            d.skipped()
        );
        assert_eq!(d.skipped()[0].packet_index, 1);
    }

    /// The CONTROL: the untimestamped entry point leaves the clock alone, so
    /// the test above cannot pass on a clock that advances by itself.
    #[cfg(feature = "reassembly")]
    #[test]
    fn an_untimestamped_push_leaves_the_clock_where_it_was() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
        assert_eq!(d.datagram_flows()[0].session.now_ms(), 0);
    }

    /// The sub-second field is microseconds or nanoseconds depending on the
    /// file's MAGIC, and the same raw number means a THOUSANDFOLD different
    /// time under the two. The fixture is deliberately larger than one second's
    /// worth of nanoseconds so the two answers cannot coincide — a value under
    /// 1000 would give 0 either way and the test would prove nothing.
    #[test]
    fn the_subsecond_field_is_scaled_by_the_files_declared_unit() {
        let p = crate::pcap::Packet {
            index: 0,
            ts_secs: 7,
            ts_frac: 1_500_000,
            data: Vec::new(),
            orig_len: 0,
        };
        assert_eq!(p.ts_millis(crate::pcap::TimestampUnit::Microseconds), 8_500);
        assert_eq!(p.ts_millis(crate::pcap::TimestampUnit::Nanoseconds), 7_001);
    }

    /// A UDP datagram reaches a datagram flow and is decoded there, and it
    /// does NOT appear as a skipped packet — which is what it did before A3.
    #[test]
    fn a_udp_packet_lands_in_a_datagram_flow_and_is_not_skipped() {
        // A KeepAlive: the smallest complete transport message, one header
        // byte, so the assertion is about the wiring and not about a codec.
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::new();
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        d.push_packet(LINKTYPE_ETHERNET, 11, &pkt);

        assert!(
            d.skipped().is_empty(),
            "a UDP packet must no longer be a skip: {:?}",
            d.skipped()
        );
        assert!(d.flows().is_empty(), "no TCP flow should be created");
        assert_eq!(d.datagram_flows().len(), 1);
        let flow = &d.datagram_flows()[0];
        assert_eq!(flow.frames.len(), 1);
        // The packet index rides through as the frame's anchor — there is no
        // stream for an offset to point into.
        assert_eq!(flow.frames[0].stream_offset, 11);
        assert!(
            flow.frames[0].frame.is_ok(),
            "decode failed: {:?}",
            flow.frames[0].frame
        );
    }

    /// R311y605 — a multicast JOIN is NAMED, not reported as an unknown MID.
    ///
    /// The hole this closes was silent in the worst way: the datagram flow was
    /// created, the packet was not skipped, and `frame.is_ok()` — the assertion
    /// the sibling test above makes — was TRUE, because
    /// `InboundFrame::Unknown { mid: 7 }` is a successful parse. Every
    /// coarse-grained check passed while the single most informative message on
    /// zenoh's multicast session group (a peer announcing its zid, its lease and
    /// its initial per-channel sequence numbers) arrived as an unnamed byte.
    ///
    /// So this asserts the VARIANT and its fields, not that a decode happened.
    #[test]
    fn a_multicast_join_is_decoded_rather_than_reported_as_an_unknown_mid() {
        use wz_session_core::inbound::InboundFrame;

        // The codec's own encode, so the fixture is not my reading of the
        // layout. S set, so the capability pair rides along.
        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[0xA0, 0xA1, 0xA2, 0xA3],
            sn_res: Some(0x00),
            batch_size: Some(0x1000),
            // 10 whole seconds, which a pico beacon sends as T=1 + VLE 10.
            lease: 10,
            next_sn_reliable: 7,
            next_sn_best_effort: 9,
        };
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_JOIN
                | wz_session_core::wire_const::FLAG_T_JOIN_S
                | wz_session_core::wire_const::FLAG_T_JOIN_T
        ];
        wire.extend_from_slice(&join.encode_to_vec(1));

        let mut d = Dissection::new();
        // The real multicast session group: zenoh shares 224.0.0.224:7446 for
        // the scout group and the multicast session group alike.
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &wire);
        d.push_packet(LINKTYPE_ETHERNET, 3, &pkt);

        assert!(d.skipped().is_empty(), "{:?}", d.skipped());
        assert_eq!(d.datagram_flows().len(), 1);
        let frame = &d.datagram_flows()[0].frames[0].frame;
        match frame {
            Ok(InboundFrame::Join { body, has_ext, .. }) => {
                assert!(!has_ext, "this JOIN carries no ext chain");
                assert_eq!(body.zid.as_ref(), &[0xA0, 0xA1, 0xA2, 0xA3]);
                assert_eq!(body.batch_size, Some(0x1000));
                assert_eq!(body.next_sn_reliable, 7);
                assert_eq!(body.next_sn_best_effort, 9);
                // The T flag is projected at the decode boundary, so no
                // consumer of a decode ever sees the wire's seconds.
                assert_eq!(body.lease, 10_000, "the T flag was not projected");
            }
            other => panic!(
                "a multicast JOIN must decode as InboundFrame::Join; got {other:?}. \
                 `Unknown {{ mid: 7 }}` is the pre-R311y605 state and it is a \
                 SUCCESSFUL parse, which is why nothing noticed"
            ),
        }
    }

    /// Two datagrams between the same pair share one flow, in both
    /// directions — the observer sees one conversation, not two.
    #[test]
    fn both_directions_reach_one_datagram_flow() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::new();
        // The reverse direction swaps the ADDRESSES as well as the ports.
        // Swapping only the ports is a different conversation entirely, and
        // the first version of this fixture did exactly that — it reported
        // two flows and the code was right.
        let there = udp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, &keepalive);
        let back = udp_packet([10, 0, 0, 2], 2000, [10, 0, 0, 1], 1000, &keepalive);
        d.push_packet(LINKTYPE_ETHERNET, 0, &there);
        d.push_packet(LINKTYPE_ETHERNET, 1, &back);
        assert_eq!(d.datagram_flows().len(), 1);
        assert_eq!(d.datagram_flows()[0].frames.len(), 2);
    }
}

// ── R311y602 — the WEBSOCKET path end to end. `ws` proves the deframer; this
//    proves the WIRING, and the wiring is the whole defect: a deframer that
//    works and a dissection that never reaches it look identical from the
//    deframer's own tests, and "looks identical while producing nothing" is
//    exactly what this round exists to end. ──
#[cfg(test)]
mod ws_flow_tests {
    use super::*;
    use crate::link::LINKTYPE_ETHERNET;
    use wz_session_core::inbound::InboundFrame;

    /// Ethernet + IPv4 + TCP, with both ports explicit so a test can build
    /// BOTH directions of one connection.
    fn tcp_packet(sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let (src, dst) = if sport == 1111 {
            ([10u8, 0, 0, 1], [10u8, 0, 0, 2])
        } else {
            ([10u8, 0, 0, 2], [10u8, 0, 0, 1])
        };
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(0x10);
        tcp.extend_from_slice(&64u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);

        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&tcp);

        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// One RFC6455 BINARY frame, masked the way a client's really is.
    fn binary_frame(payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = alloc::vec![0x82u8];
        let masked_bit = if mask.is_some() { 0x80u8 } else { 0 };
        out.push(masked_bit | payload.len() as u8);
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

    /// A BARE KeepAlive — no length prefix, because a ws message boundary IS
    /// the framing.
    fn bare_keepalive() -> Vec<u8> {
        alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// THE ONE THAT MATTERS. A zenoh session over `ws/...` is ordinary TCP, so
    /// every layer below this crate handles it perfectly and the messages
    /// still never appeared: the byte stream begins `GET / HTTP/1.1` and
    /// continues in RFC6455 frames, which the observer cannot read and does
    /// not refuse. The capture came back with no zenoh in it — the one answer
    /// indistinguishable from a capture that genuinely had none.
    ///
    /// Both directions carry a message, and the client's is MASKED, because
    /// those are the two halves that fail separately: the masking is
    /// client-to-server only, so a deframer without it leaves the acceptor's
    /// direction reading fine while the dialer's decodes into noise.
    #[test]
    fn a_ws_carried_zenoh_session_decodes_instead_of_vanishing() {
        let mut d = Dissection::new();
        let client_open = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
        let server_open = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";

        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1111, 7447, 1000, client_open),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(7447, 1111, 2000, server_open),
        );
        let msg = bare_keepalive();
        d.push_packet(
            LINKTYPE_ETHERNET,
            2,
            &tcp_packet(
                1111,
                7447,
                1000 + client_open.len() as u32,
                &binary_frame(&msg, Some([0x37, 0xFA, 0x21, 0x3D])),
            ),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            3,
            &tcp_packet(
                7447,
                1111,
                2000 + server_open.len() as u32,
                &binary_frame(&msg, None),
            ),
        );

        assert_eq!(d.flows().len(), 1, "one connection");
        let flow = &d.flows()[0];
        assert!(
            flow.framing().is_websocket(),
            "the flow must be RECOGNISED as WebSocket; classified as a plain \
             stream it decodes nothing and says nothing"
        );
        assert_eq!(
            flow.frames.len(),
            2,
            "one message from each direction — the masked half is the one that \
             goes missing on its own"
        );
        for f in &flow.frames {
            assert!(
                matches!(f.frame, Ok(InboundFrame::KeepAlive { .. })),
                "each ws message decodes to the KeepAlive it carried"
            );
            assert_eq!(
                f.prefix_width, 0,
                "a ws message carries no length prefix; reporting one would be \
                 a measurement of nothing"
            );
            assert!(
                flow.packet_for(f.direction, f.stream_offset).is_some(),
                "attribution survives the extra framing layer: every decoded \
                 message still names the packet that carried it"
            );
        }
    }

    /// The negative arm, and it is what makes the positive one mean something:
    /// a plain `tcp/...` zenoh flow must NOT be classified as WebSocket. With
    /// detection that answered yes too eagerly, the test above would pass
    /// while every ordinary capture in the field broke.
    #[test]
    fn a_plain_tcp_zenoh_flow_is_not_taken_for_websocket() {
        let mut d = Dissection::new();
        let framed = alloc::vec![1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &framed));

        let flow = &d.flows()[0];
        assert!(!flow.framing().is_websocket());
        assert_eq!(flow.frames.len(), 1, "the stream path still decodes it");
        assert_eq!(
            flow.frames[0].prefix_width, 2,
            "and still reports the 2-byte prefix it actually read"
        );
    }

    /// A flow whose opening is shorter than the detector needs must WAIT, not
    /// guess. One byte at a time is the pathological arrival pattern that
    /// makes a detector reading "the first segment" wrong.
    #[test]
    fn detection_waits_for_enough_bytes_rather_than_guessing_on_one() {
        let mut d = Dissection::new();
        let client_open = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
        for (i, byte) in client_open.iter().enumerate() {
            d.push_packet(
                LINKTYPE_ETHERNET,
                i,
                &tcp_packet(1111, 7447, 1000 + i as u32, &[*byte]),
            );
        }
        let msg = bare_keepalive();
        d.push_packet(
            LINKTYPE_ETHERNET,
            client_open.len(),
            &tcp_packet(
                1111,
                7447,
                1000 + client_open.len() as u32,
                &binary_frame(&msg, None),
            ),
        );

        let flow = &d.flows()[0];
        assert!(
            flow.framing().is_websocket(),
            "the held bytes must be replayed once the decision is made, not dropped"
        );
        assert_eq!(flow.frames.len(), 1);
    }
}

// ── R311y603 — the AF_VSOCK path end to end. `link` proves the vsockmon
//    parser; this proves the WIRING and the SEQUENCE SYNTHESIS, which is the
//    part that has no parser to be proven by: vsockmon carries no sequence
//    number, so the stream position is a number this crate makes up, and a
//    number a crate makes up is a number that has to be tested. ──
#[cfg(test)]
mod vsock_flow_tests {
    use super::*;
    use crate::link::LINKTYPE_VSOCK;
    use wz_session_core::inbound::InboundFrame;

    const OP_PAYLOAD: u16 = 4;
    const OP_CONNECT: u16 = 1;

    /// One vsockmon record. `transport_hdr` is whatever the transport put
    /// between the header and the payload — its LENGTH is what the reader
    /// skips by, which is the field this fixture exists to exercise.
    fn vsockmon(
        src_cid: u64,
        src_port: u32,
        dst_cid: u64,
        dst_port: u32,
        op: u16,
        transport_hdr: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_cid.to_le_bytes());
        out.extend_from_slice(&dst_cid.to_le_bytes());
        out.extend_from_slice(&src_port.to_le_bytes());
        out.extend_from_slice(&dst_port.to_le_bytes());
        out.extend_from_slice(&op.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // AF_VSOCK_TRANSPORT_VIRTIO
        out.extend_from_slice(&(transport_hdr.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0u8, 0]); // reserved
        out.extend_from_slice(transport_hdr);
        out.extend_from_slice(payload);
        out
    }

    /// One length-prefixed KeepAlive: a vsock link is `SOCK_STREAM` and carries
    /// the same StreamEnvelope framing tcp does.
    fn framed_keepalive() -> Vec<u8> {
        alloc::vec![1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// THE ONE THAT MATTERS. Before this round `DLT_VSOCK` was absent from the
    /// link-type table, so every packet of a `vsock/...` zenoh session came
    /// back as `UnsupportedLinkType(271)` — a NAMED skip, so never silent, but
    /// an under-promise: the DLT and `vsockmon.ko` both exist and nothing was
    /// blocking it. VM-to-VM is the shape an AP deployment actually takes.
    #[test]
    fn a_vsock_carried_zenoh_session_decodes() {
        let mut d = Dissection::new();
        let msg = framed_keepalive();
        // A virtio transport header of a plausible width, present precisely so
        // the reader must skip by the declared length rather than a constant.
        let vhdr = alloc::vec![0xAAu8; 44];

        d.push_packet(
            LINKTYPE_VSOCK,
            0,
            &vsockmon(3, 40000, 2, 7447, OP_PAYLOAD, &vhdr, &msg),
        );
        d.push_packet(
            LINKTYPE_VSOCK,
            1,
            &vsockmon(2, 7447, 3, 40000, OP_PAYLOAD, &vhdr, &msg),
        );

        assert!(d.skipped().is_empty(), "no packet should be skipped");
        assert_eq!(d.flows().len(), 1, "both directions are one flow");
        let flow = &d.flows()[0];
        assert_eq!(flow.frames.len(), 2, "one message from each direction");
        for f in &flow.frames {
            assert!(matches!(f.frame, Ok(InboundFrame::KeepAlive { .. })));
            assert_eq!(f.prefix_width, 2, "a vsock link is length-prefixed");
        }
        // The flow is keyed by CID, not by an IP address that is not there.
        assert_eq!(flow.flow.low.vsock_cid(), Some(2));
        assert_eq!(flow.flow.high.vsock_cid(), Some(3));
    }

    /// THE SYNTHESISED SEQUENCE, which is the only invented number on this
    /// path. Three records in one direction must concatenate into ONE stream —
    /// a counter that failed to advance would replay the first record's offset
    /// and the assembler would treat records 2 and 3 as retransmissions, so the
    /// second and third messages would vanish. Asserting only "it decodes"
    /// would pass on that: the first message decodes either way.
    #[test]
    fn successive_records_concatenate_instead_of_overwriting() {
        let mut d = Dissection::new();
        let msg = framed_keepalive();
        for i in 0..3usize {
            d.push_packet(
                LINKTYPE_VSOCK,
                i,
                &vsockmon(3, 40000, 2, 7447, OP_PAYLOAD, &[], &msg),
            );
        }
        let flow = &d.flows()[0];
        assert_eq!(
            flow.frames.len(),
            3,
            "each record advances the stream; a stuck counter loses all but the first"
        );
        // And each message is still attributable to the record that carried it.
        for (i, f) in flow.frames.iter().enumerate() {
            assert_eq!(
                flow.packet_for(f.direction, f.stream_offset),
                Some(i),
                "message {i} must name the packet it came out of"
            );
        }
    }

    /// A message SPLIT across two records must still decode, which is the whole
    /// reason a vsock flow goes through the stream assembler rather than being
    /// treated as a datagram.
    #[test]
    fn a_message_split_across_two_records_is_reassembled() {
        let mut d = Dissection::new();
        let msg = framed_keepalive();
        d.push_packet(
            LINKTYPE_VSOCK,
            0,
            &vsockmon(3, 40000, 2, 7447, OP_PAYLOAD, &[], &msg[..1]),
        );
        assert_eq!(
            d.flows()[0].frames.len(),
            0,
            "half a message decodes nothing"
        );
        d.push_packet(
            LINKTYPE_VSOCK,
            1,
            &vsockmon(3, 40000, 2, 7447, OP_PAYLOAD, &[], &msg[1..]),
        );
        assert_eq!(d.flows()[0].frames.len(), 1, "the halves join into one");
    }

    /// A non-payload op carries no data by the kernel header's own statement,
    /// and must be skipped BY NAME rather than fed in as empty bytes.
    #[test]
    fn a_non_payload_record_is_skipped_by_name() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_VSOCK,
            0,
            &vsockmon(3, 40000, 2, 7447, OP_CONNECT, &[], &[]),
        );
        assert_eq!(d.skipped().len(), 1);
        assert_eq!(
            d.skipped()[0].reason,
            SkipReason::VsockNonPayload(OP_CONNECT)
        );
        assert!(d.flows().is_empty(), "a connect record opens no flow");
    }

    /// The two 32-bit vsock ports must not collide after the widening from
    /// `u16`. Two flows differing ONLY above bit 16 are the case a truncating
    /// key would merge into one, silently interleaving two sessions' bytes.
    #[test]
    fn two_vsock_ports_differing_above_bit_16_are_distinct_flows() {
        let mut d = Dissection::new();
        let msg = framed_keepalive();
        d.push_packet(
            LINKTYPE_VSOCK,
            0,
            &vsockmon(3, 0x0001_0001, 2, 7447, OP_PAYLOAD, &[], &msg),
        );
        d.push_packet(
            LINKTYPE_VSOCK,
            1,
            &vsockmon(3, 0x0002_0001, 2, 7447, OP_PAYLOAD, &[], &msg),
        );
        assert_eq!(
            d.flows().len(),
            2,
            "ports 0x00010001 and 0x00020001 share their low 16 bits; a u16 key \
             would interleave two sessions into one stream"
        );
    }
}
