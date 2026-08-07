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

use crate::link::{FlowKey, SkipReason};
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
}

impl FlowDissection {
    fn new(flow: FlowKey) -> Self {
        Self {
            flow,
            low_to_high: StreamAssembler::new(),
            high_to_low: StreamAssembler::new(),
            session: PassiveSession::new(),
            frames: Vec::new(),
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

/// A whole capture, dissected: every TCP connection in it, read as a zenoh
/// session.
#[derive(Debug, Default)]
pub struct Dissection {
    flows: Vec<FlowDissection>,
    skipped: Vec<SkippedPacket>,
}

impl Dissection {
    /// An empty dissection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every flow seen, in first-appearance order.
    pub fn flows(&self) -> &[FlowDissection] {
        &self.flows
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
        let segment = match link::decapsulate(link_type, packet_index, bytes) {
            Ok(s) => s,
            Err(reason) => {
                self.skipped.push(SkippedPacket {
                    packet_index,
                    reason,
                });
                return;
            }
        };
        let idx = match self.flows.iter().position(|f| f.flow == segment.flow) {
            Some(i) => i,
            None => {
                self.flows.push(FlowDissection::new(segment.flow));
                self.flows.len() - 1
            }
        };
        let flow = &mut self.flows[idx];
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
        let delivered: Vec<u8> = flow.assembler(direction).stream()[before..].to_vec();
        flow.advance(direction, &delivered);
    }

    /// Dissect a whole classic pcap file from memory.
    pub fn from_pcap(bytes: &[u8]) -> Result<Self, pcap::PcapError> {
        let file = pcap::parse(bytes)?;
        let mut out = Self::new();
        for packet in &file.packets {
            out.push_packet(file.link_type, packet.index, &packet.data);
        }
        Ok(out)
    }
}
