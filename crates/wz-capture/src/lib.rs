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

pub mod link;
pub mod pcap;
pub mod tcp;

use alloc::vec::Vec;

use wz_session_core::passive::{
    Direction, FlowContext, PassiveFrame, PassiveSession, PassiveStall,
};

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
}

impl DatagramDissection {
    fn new(flow: FlowKey, window_ms: Option<u64>) -> Self {
        Self {
            flow,
            session: new_session(window_ms),
            frames: Vec::new(),
        }
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
        }
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
    fn advance(&mut self, direction: Direction, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
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
            limits,
            ..Self::default()
        }
    }

    /// What staying inside [`DissectionLimits`] has cost.
    pub fn drops(&self) -> DissectionDrops {
        self.drops
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
            Err(reason) => {
                self.skipped.push(SkippedPacket {
                    packet_index,
                    reason,
                });
                if let Some(cap) = self.limits.skipped_packets {
                    if self.skipped.len() > cap {
                        let cut = self.skipped.len() - cap;
                        self.skipped.drain(..cut);
                        self.drops.skipped += cut;
                    }
                }
                return;
            }
        };
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
            self.flows.remove(oldest);
            self.drops.flows += 1;
        }
    }

    /// R311y584 (A3) — one UDP datagram: one whole wire message, decoded on
    /// the spot.
    ///
    /// No buffering and no reassembly, because there is nothing to reassemble
    /// — which is exactly why this is four lines and the TCP path is not.
    fn push_datagram(&mut self, d: link::Datagram, ts_millis: Option<u64>) {
        // Without `reassembly` there is no chain to expire and so nothing to
        // advance a clock FOR. Named here rather than silenced with an
        // `#[allow]`, because the reason is the feature and not the lint.
        #[cfg(not(feature = "reassembly"))]
        let _ = ts_millis;
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
        let flow = &mut self.datagram_flows[idx];
        #[cfg(feature = "reassembly")]
        if let Some(ms) = ts_millis {
            self.expired_chains += flow.session.observe_at(ms);
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
