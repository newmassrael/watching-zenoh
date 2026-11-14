// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The decryption pass over a dissection, in one place for every composition
//! root that holds both the dissector and this crate.
//!
//! The command line (`wz-analyze`) and the C ABI (`wz-capi-dissect`) both open a
//! capture's TLS flows with the keys it carries and the keys a caller hands in,
//! and both recover its QUIC flows. A copy of the pass in each would be two
//! opinions about which keys apply, in which order, and when the pass may run
//! at all, so the pass lives here, beside the openers it drives.
//!
//! Two shapes, because a capture comes in two:
//!
//! * a FILE, whose records are all in before the pass starts: [`decrypt_capture`]
//!   runs the TLS half ([`open_tls`]) and the QUIC half ([`open_quic`]) once;
//! * a FEED, whose records and keys keep arriving: [`LiveDecryptor`] keeps the
//!   keys and one opener per flow between calls, and each call opens what was
//!   kept since the last. A QUIC flow's packets are offered to it as the feed
//!   takes them in ([`LiveDecryptor::offer_packet`], or as the
//!   [`wz_capture::PacketTap`] of a followed container), because the
//!   dissection keeps no QUIC payload to be read again.
//!
//! Both shapes open and frame a QUIC flow through one piece of code
//! (`QuicFlowPass`): the file pass offers every datagram first and frames once,
//! the feed frames what was recovered since its last call.
//!
//! The rule both shapes keep: the TLS pass runs only where there ARE keys. Run
//! with none, every flow would be declined as `no_key_for_session` -- keys were
//! supplied and none are for this session -- which is false about a run that
//! had no keys at all; `no_keys_supplied` is what such a flow keeps saying. The
//! QUIC half runs either way: the Initial space needs no key.
//!
//! No key byte leaves this module in a value a caller can print: [`KeyLog`],
//! [`CaptureOpener`] and the QUIC opener redact their secrets in `Debug`, and
//! nothing here formats one.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use wz_capture::link::FlowKey;
use wz_capture::quic::{QuicDecryption, QuicStreamFeed};
use wz_capture::tls::{Direction, FlowOpeners, RecordOpener, MAX_KEPT_RECORDS_PER_DIRECTION};
use wz_capture::{CapturedFrame, DecryptionSummary, Dissection, PacketTap, PlaintextSink};

use crate::capture::CaptureOpener;
use crate::keylog::{KeyLog, SecretsBlockError};
use crate::quic::connection::{DirectionCensus, QuicFlowOpener, SequenceKey};
use crate::quic::{PacketSpace, QuicVersion};

/// What the TLS half of a pass did, and with which keys.
#[derive(Debug)]
pub struct TlsPass {
    /// The opener the pass drove: the key log it drew on, and what its
    /// directions observed about their epochs.
    pub opener: CaptureOpener,
    /// Decryption Secrets Blocks of another protocol's secrets, skipped, so "no
    /// keys" and "someone else's keys" stay apart.
    pub foreign_secrets_blocks: usize,
    /// The pass's own summary; all zeros where no key was held, because the
    /// pass did not run.
    pub summary: DecryptionSummary,
}

/// Open the TLS flows of a dissection of a whole capture: the keys the capture
/// carried in its Decryption Secrets Blocks first, then `keylog` (NSS key log
/// text) folded in.
///
/// `sink` is offered each direction's plaintext while it exists
/// ([`Dissection::decrypt_with_sink`]); `()` when nothing wants it.
pub fn open_tls<S: PlaintextSink>(
    dissection: &mut Dissection,
    keylog: Option<&[u8]>,
    sink: &mut S,
) -> TlsPass {
    let (mut opener, foreign_secrets_blocks) =
        CaptureOpener::from_secrets_blocks(dissection.decryption_secrets());
    if let Some(text) = keylog {
        opener.absorb(KeyLog::parse(text));
    }
    let summary = if opener.log().is_empty() {
        DecryptionSummary::default()
    } else {
        dissection.decrypt_with_sink(&mut opener, sink)
    };
    TlsPass {
        opener,
        foreign_secrets_blocks,
        summary,
    }
}

/// R311y698 (§1.2a) — one QUIC flow, as far as the pass got into it.
#[derive(Debug, Clone)]
pub struct QuicFlowOutcome {
    /// The five-tuple.
    pub flow: FlowKey,
    /// Per-direction tallies, `[A, B]`.
    pub census: [DirectionCensus; 2],
    /// Which direction the client is, settled by whoever sent the first Initial.
    pub client_direction: Option<Direction>,
    /// The version the connection declared.
    pub version: Option<QuicVersion>,
    /// Whether the key log held this connection's secrets.
    pub keys_installed: bool,
    /// Whether a ClientHello was found and its random read.
    pub client_hello_seen: bool,
    /// R311y710 (Y2) — the connection's identity was ADOPTED from a key log
    /// holding exactly one connection, rather than read off the wire.
    ///
    /// A PREMISE where `client_hello_seen` is evidence, and carried apart for
    /// the reason `QuicCensus::declared` is carried apart from recognition one
    /// crate over: a reader acts differently on "I saw this" and "I assumed
    /// this", and a rendering that shows only the consequence shows neither.
    pub identity_adopted: bool,
    /// Each recovered sequence: direction, which one, and how many contiguous
    /// bytes came out.
    pub sequences: Vec<(Direction, SequenceKey, usize)>,
    /// Sequences the table's bound refused, `[A, B]`.
    pub sequences_dropped: [usize; 2],
}

/// R311y698 (§1.2a) — open every QUIC flow the dissection found, from the
/// capture's own packets.
///
/// `push_datagram` on the dissection side counts a QUIC packet and keeps no
/// payload, so the bytes are read where they are: in the caller's container,
/// walked once more by the walk every reader of a container uses
/// ([`wz_capture::CaptureCursor`]). Each QUIC flow's datagrams go to its own
/// [`QuicFlowOpener`] in capture order, and what comes out is framed as zenoh
/// ([`Dissection::feed_quic_stream_with_sink`],
/// [`Dissection::feed_quic_datagram_with_sink`]). The cost is that one extra
/// walk, paid only by a capture that HAS a QUIC flow.
///
/// It runs whether or not a key is held: the Initial packet space needs none,
/// so a QUIC capture with no key log still yields its handshake, its version,
/// its connection ID and its ClientHello, which is what tells a reader whether
/// the key log they are about to fetch is the right one.
///
/// A container that does not walk the second time opens nothing and still
/// counts its QUIC flows as offered: none opened is the honest answer, none
/// there is not.
pub fn open_quic<S: PlaintextSink>(
    capture: &[u8],
    dissection: &mut Dissection,
    log: &KeyLog,
    cid_len: Option<usize>,
    sink: &mut S,
) -> (QuicDecryption, Vec<QuicFlowOutcome>) {
    let keys = quic_flow_keys(dissection);
    let mut summary = QuicDecryption {
        flows_offered: keys.len(),
        ..Default::default()
    };
    if keys.is_empty() {
        return (summary, Vec::new());
    }
    let mut passes: Vec<QuicFlowPass> = keys
        .iter()
        .map(|flow| QuicFlowPass::new(*flow, log, cid_len))
        .collect();

    let mut cursor = wz_capture::CaptureCursor::new();
    let walked = cursor.walk(capture, |event| {
        if let wz_capture::CaptureEvent::Frame(packet) = event {
            if let Some((flow, direction, payload)) =
                udp_datagram(packet.link_type, packet.index, packet.data)
            {
                if let Some(pass) = passes.iter_mut().find(|p| p.flow == flow) {
                    pass.offer(direction, packet.index, payload);
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    });
    if !matches!(walked, Ok(wz_capture::CaptureWalk::Halted { .. })) {
        return (summary, Vec::new());
    }

    let mut flows = Vec::new();
    for mut pass in passes {
        pass.tally(&mut summary);
        summary.framing.absorb(pass.feed(dissection, sink));
        flows.push(pass.outcome());
    }
    // R311y718 — the stall, measured from the FINISHED dissection rather than
    // folded per offer: a stream fed twice has one leftover and not two.
    summary.framing.bytes_undecoded = dissection
        .datagram_flows()
        .iter()
        .flat_map(|f| f.quic_streams.iter())
        .map(|s| s.undecoded_bytes() as usize)
        .sum();
    (summary, flows)
}

/// The flows the dissection marked QUIC, in its own order: the order both
/// shapes frame them in.
fn quic_flow_keys(dissection: &Dissection) -> Vec<FlowKey> {
    dissection
        .datagram_flows()
        .iter()
        .filter(|f| f.quic.is_some())
        .map(|f| f.flow)
        .collect()
}

/// The UDP datagram one captured packet carries, if it carries one: its flow,
/// which half of it the packet is on, and its payload.
///
/// The direction rule the field walk uses: two readers of one capture that
/// disagree about which half a packet is on would file a client's stream under
/// the server.
fn udp_datagram(link_type: u32, index: usize, data: &[u8]) -> Option<(FlowKey, Direction, &[u8])> {
    let Ok(wz_capture::link::Transport::Udp(datagram)) =
        wz_capture::link::decapsulate(link_type, index, data)
    else {
        return None;
    };
    let direction = if datagram.from_low {
        Direction::A
    } else {
        Direction::B
    };
    Some((datagram.flow, direction, datagram.payload))
}

/// The array index a direction takes, matching the opener's.
fn dir_index(direction: Direction) -> usize {
    match direction {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// One QUIC flow being opened, and how far into what it recovered the
/// dissection has been handed. The file pass and the live decryptor each drive
/// one per flow, so a flow is opened, counted and framed by this code whichever
/// shape its capture comes in.
struct QuicFlowPass {
    flow: FlowKey,
    opener: QuicFlowOpener,
    /// Per direction, each sequence's stream offset up to which its bytes were
    /// offered to the dissection. A sequence absent here was never offered.
    offered: [BTreeMap<SequenceKey, u64>; 2],
}

impl QuicFlowPass {
    /// A fresh opener over `log`.
    fn new(flow: FlowKey, log: &KeyLog, cid_len: Option<usize>) -> Self {
        let opener = QuicFlowOpener::new(log.clone());
        // R311y709 (Y2) — the declared short-header connection id length
        // reaches the OPENER, or it is a flag nothing acts on.
        let opener = match cid_len {
            Some(len) => opener.declaring_short_connection_id_len(len),
            None => opener,
        };
        Self {
            flow,
            opener,
            offered: [BTreeMap::new(), BTreeMap::new()],
        }
    }

    /// Offer one UDP payload of this flow, in capture order.
    ///
    /// R311y719 — the CAPTURE PACKET INDEX travels with the offer: the only
    /// coordinate that survives decryption for an RFC 9221 datagram.
    fn offer(&mut self, direction: Direction, index: usize, payload: &[u8]) {
        self.opener.push_datagram(direction, index, payload);
    }

    /// Whether a packet that carries application data (0-RTT or 1-RTT) opened,
    /// in either direction: from then on stream bytes may have been framed, so
    /// passing the flow's packets again through a fresh opener would frame
    /// them twice.
    fn opened_application(&self) -> bool {
        self.opener.census().iter().any(|c| {
            c.opened_per_space[PacketSpace::ZeroRtt.index()] > 0
                || c.opened_per_space[PacketSpace::OneRtt.index()] > 0
        })
    }

    /// Hand the dissection what the opener recovered since the last call, and
    /// let go of the stream bytes handed on.
    ///
    /// Per direction: each sequence's bytes past what was offered before, then
    /// each RFC 9221 datagram. A sequence is offered the first time it is seen,
    /// empty or not, and after that only when it grew, so one call after every
    /// datagram (the file pass) offers each sequence once and whole, as it
    /// always did, and a call after each packet (a feed) offers only the tail.
    fn feed<S: PlaintextSink>(
        &mut self,
        dissection: &mut Dissection,
        sink: &mut S,
    ) -> QuicStreamFeed {
        let mut framing = QuicStreamFeed::default();
        let Self {
            flow,
            opener,
            offered,
        } = self;
        for direction in [Direction::A, Direction::B] {
            let offered = &mut offered[dir_index(direction)];
            for (key, reassembler) in opener.sequences(direction) {
                let delivered = reassembler.delivered();
                let from = match offered.get(&key) {
                    Some(&at) if at == delivered => continue,
                    Some(&at) => at,
                    None => reassembler.start(),
                };
                let skip = from.saturating_sub(reassembler.start()) as usize;
                let tail = reassembler.stream().get(skip..).unwrap_or_default();
                // R311y718 (§1.2a) — the recovered bytes go on to the zenoh
                // framer. CRYPTO is offered too and refused by the framer rather
                // than filtered here: handshake bytes carry no zenoh, and the
                // framer counting them is what tells a capture whose every
                // stream is CRYPTO from one that recovered nothing.
                let (stream_id, handshake) = match key {
                    SequenceKey::Stream(id) => (id, false),
                    SequenceKey::Crypto(space) => (space.index() as u64, true),
                };
                framing.absorb(dissection.feed_quic_stream_with_sink(
                    *flow, direction, stream_id, handshake, tail, sink,
                ));
                offered.insert(key, delivered);
            }
            // R311y719 — and the RFC 9221 datagrams, each anchored by the index
            // of the capture packet it came out of: the only coordinate that
            // survives decryption for a datagram. Taken, so each is fed once.
            for (origin, payload) in opener.take_datagrams(direction) {
                framing.absorb(
                    dissection
                        .feed_quic_datagram_with_sink(*flow, direction, origin, &payload, sink),
                );
            }
            // The dissection keeps the plaintext its messages are read from, so
            // the opener's copy of what was handed on is a second one.
            opener.release_streams(direction);
        }
        framing
    }

    /// Fold this flow's tallies into a capture's summary.
    fn tally(&self, summary: &mut QuicDecryption) {
        let census = self.opener.census();
        let packets: usize = census.iter().map(|c| c.packets).sum();
        let opened: usize = census.iter().map(|c| c.opened).sum();
        summary.packets += packets;
        summary.packets_opened += opened;
        summary.packets_no_keys += census.iter().map(|c| c.no_keys).sum::<usize>();
        summary.packets_refused += census.iter().map(|c| c.refused).sum::<usize>();
        summary.crypto_bytes += census.iter().map(|c| c.crypto_bytes).sum::<usize>();
        summary.stream_bytes += census.iter().map(|c| c.stream_bytes).sum::<usize>();
        summary.datagram_bytes += census.iter().map(|c| c.datagram_bytes).sum::<usize>();
        summary.walks_stopped += census.iter().map(|c| c.walks_stopped).sum::<usize>();
        if self.opener.identity_adopted() {
            summary.flows_identity_adopted += 1;
        }
        // A flow is WHOLE when every packet in it opened. Zero packets is not
        // whole: a QUIC flow the dissection counted and this pass saw none of is
        // a disagreement between two reads of one file, not a success.
        if packets > 0 && opened == packets {
            summary.flows_opened += 1;
        }
    }

    /// As far as the pass got into the flow.
    fn outcome(&self) -> QuicFlowOutcome {
        let opener = &self.opener;
        let mut sequences = Vec::new();
        for direction in [Direction::A, Direction::B] {
            for (key, reassembler) in opener.sequences(direction) {
                sequences.push((direction, key, reassembler.delivered() as usize));
            }
        }
        QuicFlowOutcome {
            flow: self.flow,
            census: opener.census(),
            client_direction: opener.client_direction(),
            version: opener.version(),
            keys_installed: opener.keys_installed(),
            client_hello_seen: opener.client_hello_seen(),
            identity_adopted: opener.identity_adopted(),
            sequences,
            sequences_dropped: opener.sequences_dropped(),
        }
    }
}

/// What one pass over a whole capture did: the TLS half and the QUIC half.
#[derive(Debug)]
pub struct Decryption {
    /// The TLS half.
    pub tls: TlsPass,
    /// The QUIC half's summary.
    pub quic: QuicDecryption,
    /// Each QUIC flow, as far as the pass got into it.
    pub quic_flows: Vec<QuicFlowOutcome>,
}

/// The whole pass over a dissection of `capture`: TLS with the capture's keys
/// and `keylog`, then QUIC with the same keys.
///
/// TLS FIRST, and before anything that walks the dissection's messages: a flow
/// whose plaintext the pass opens carries messages only after it, and a plane
/// folded before would count the ciphertext-only view and report a floor as a
/// total. The QUIC half draws on the key log the TLS half assembled, so a key
/// in a Decryption Secrets Block reaches a QUIC flow exactly as an external one
/// does.
pub fn decrypt_capture<S: PlaintextSink>(
    dissection: &mut Dissection,
    capture: &[u8],
    keylog: Option<&[u8]>,
    quic_cid_len: Option<usize>,
    sink: &mut S,
) -> Decryption {
    let tls = open_tls(dissection, keylog, sink);
    let (quic, quic_flows) = open_quic(capture, dissection, tls.opener.log(), quic_cid_len, sink);
    Decryption {
        tls,
        quic,
        quic_flows,
    }
}

/// The pass over a dissection that is still being fed, kept between calls.
///
/// It holds the keys (the dissection's own Decryption Secrets Blocks, read as
/// they arrive, and every key log a caller hands in), one TLS opener per flow it
/// began, which is what lets a flow continue on a later call
/// ([`Dissection::decrypt_continuing`]), and one QUIC opener per QUIC flow. Keys
/// that arrive put every TLS flow that opened nothing back in front of the next
/// pass ([`Dissection::reopen_unopened`]) and pass every QUIC flow that opened
/// no application data again, through a fresh opener, over the packets it kept;
/// a flow that opened goes on from where it stopped.
///
/// # What a QUIC flow keeps
///
/// The dissection keeps no QUIC payload, so a packet that arrives before its
/// key is kept here, with every other packet of its flow in arrival order: a
/// fresh opener needs the Initial packets too, for the ClientHello that names
/// the connection's secrets. At most [`MAX_KEPT_RECORDS_PER_DIRECTION`] a
/// direction, the bound kept TLS records have. Past it the NEWEST is not kept,
/// where TLS lets go of the oldest: a QUIC flow passed again without its first
/// flight derives no key at all. Once a packet carrying application data
/// opens, the flow will not be passed again, so what it kept goes and nothing
/// more is kept.
///
/// `Debug` shows how many connections it holds keys for and how many flows it
/// keeps an opener for, never a key.
#[derive(Default)]
pub struct LiveDecryptor {
    log: Arc<KeyLog>,
    /// How many of the dissection's Decryption Secrets Blocks are in `log`.
    blocks_read: usize,
    /// Of those, the blocks of another protocol's secrets, skipped.
    foreign_secrets_blocks: usize,
    /// Keys arrived since the last TLS pass.
    grew: bool,
    /// Keys arrived since the QUIC flows that opened no application data were
    /// last passed again.
    quic_grew: bool,
    openers: BTreeMap<FlowKey, CaptureOpener>,
    /// One per QUIC flow, from the first packet the dissection had marked it
    /// QUIC at.
    quic: BTreeMap<FlowKey, LiveQuicFlow>,
    /// What the framer did with every QUIC offer so far.
    quic_framing: QuicStreamFeed,
}

impl core::fmt::Debug for LiveDecryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LiveDecryptor")
            .field("connections", &self.log.len())
            .field("blocks_read", &self.blocks_read)
            .field("foreign_secrets_blocks", &self.foreign_secrets_blocks)
            .field("openers", &self.openers.len())
            .field("quic_flows", &self.quic.len())
            .finish()
    }
}

/// One QUIC flow of a feed: its pass, and the packets kept for a fresh opener.
struct LiveQuicFlow {
    pass: QuicFlowPass,
    /// Every packet offered while no application data opened, in arrival
    /// order, up to the bound a direction.
    kept: Vec<KeptQuicPacket>,
    /// Packets in `kept`, per direction.
    kept_per_direction: [usize; 2],
    /// Packets the bound did not keep, per direction.
    unkept: [usize; 2],
    /// Application data opened: nothing is kept from here on.
    settled: bool,
}

/// One packet a QUIC flow keeps: its UDP payload, its half and its number.
struct KeptQuicPacket {
    direction: Direction,
    index: usize,
    payload: Vec<u8>,
}

impl LiveQuicFlow {
    fn new(flow: FlowKey, log: &KeyLog) -> Self {
        Self {
            pass: QuicFlowPass::new(flow, log, None),
            kept: Vec::new(),
            kept_per_direction: [0, 0],
            unkept: [0, 0],
            settled: false,
        }
    }

    /// Offer one packet to the opener, and keep it while the flow may yet be
    /// passed again.
    fn offer(&mut self, direction: Direction, index: usize, payload: &[u8]) {
        self.pass.offer(direction, index, payload);
        if self.settled {
            return;
        }
        if self.pass.opened_application() {
            self.settle();
            return;
        }
        let d = dir_index(direction);
        if self.kept_per_direction[d] >= MAX_KEPT_RECORDS_PER_DIRECTION {
            self.unkept[d] += 1;
            return;
        }
        self.kept_per_direction[d] += 1;
        self.kept.push(KeptQuicPacket {
            direction,
            index,
            payload: payload.to_vec(),
        });
    }

    /// Pass the kept packets again, in arrival order, through a fresh opener
    /// over `log`. A flow that opened application data is never passed again:
    /// its stream bytes may have been framed already. One that opened only its
    /// handshake framed none, and the fresh opener is what reads the secrets a
    /// later key log brought for it.
    fn reopen(&mut self, log: &KeyLog) {
        if self.settled || self.kept.is_empty() {
            return;
        }
        self.pass = QuicFlowPass::new(self.pass.flow, log, None);
        for packet in &self.kept {
            self.pass
                .offer(packet.direction, packet.index, &packet.payload);
        }
        if self.pass.opened_application() {
            self.settle();
        }
    }

    fn settle(&mut self) {
        self.settled = true;
        self.kept = Vec::new();
        self.kept_per_direction = [0, 0];
    }

    /// The bytes the kept packets hold allocated.
    fn kept_memory(&self) -> usize {
        self.kept.capacity() * core::mem::size_of::<KeptQuicPacket>()
            + self
                .kept
                .iter()
                .map(|packet| packet.payload.capacity())
                .sum::<usize>()
    }
}

impl LiveDecryptor {
    /// One holding no keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold an NSS key log in, and return how many connections it named.
    ///
    /// Zero is an answer and not an error: the text may hold no line this
    /// reader can act on. Text naming a connection moves the next pass, which
    /// passes again over every flow that opened nothing.
    pub fn absorb(&mut self, text: &[u8]) -> usize {
        let parsed = KeyLog::parse(text);
        let named = parsed.len();
        if named > 0 {
            self.grew = true;
            self.quic_grew = true;
        }
        Arc::make_mut(&mut self.log).absorb(parsed);
        named
    }

    /// Offer one packet the feed has just taken in to the QUIC opener of its
    /// flow, if it is a UDP datagram of a flow `dissection` has marked QUIC.
    ///
    /// Call it after `dissection` has read the packet, so a flow's first QUIC
    /// packet is the one that marks it. What the opener recovers is framed by
    /// the next [`Self::run`]. The capture's Decryption Secrets Blocks read so
    /// far are folded in first, so a key that arrived ahead of a connection's
    /// first flight opens it as it arrives.
    pub fn offer_packet(
        &mut self,
        dissection: &Dissection,
        link_type: u32,
        index: usize,
        data: &[u8],
    ) {
        if self.quic.is_empty() && !dissection.datagram_flows().iter().any(|f| f.quic.is_some()) {
            return;
        }
        self.absorb_secrets_blocks(dissection);
        if core::mem::take(&mut self.quic_grew) {
            self.reopen_quic();
        }
        let Some((flow, direction, payload)) = udp_datagram(link_type, index, data) else {
            return;
        };
        let live = match self.quic.entry(flow) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(slot) => {
                let marked = dissection
                    .datagram_flows()
                    .iter()
                    .any(|f| f.flow == flow && f.quic.is_some());
                if !marked {
                    return;
                }
                slot.insert(LiveQuicFlow::new(flow, &self.log))
            }
        };
        live.offer(direction, index, payload);
    }

    /// What the framer did with every QUIC offer so far, summed over the flows
    /// and the calls. `bytes_undecoded` is the largest any one offer left.
    pub fn quic_framing(&self) -> QuicStreamFeed {
        self.quic_framing
    }

    /// Each QUIC flow, as far as the pass has got into it.
    pub fn quic_flows(&self) -> Vec<QuicFlowOutcome> {
        self.quic.values().map(|live| live.pass.outcome()).collect()
    }

    /// The bytes the QUIC flows' kept packets hold allocated: bounded per flow
    /// and direction, and zero for a flow that opened application data.
    pub fn quic_packets_memory(&self) -> usize {
        self.quic.values().map(LiveQuicFlow::kept_memory).sum()
    }

    /// QUIC packets the bound did not keep, over every flow held: packets a
    /// later key cannot open.
    pub fn quic_packets_unkept(&self) -> usize {
        self.quic
            .values()
            .map(|live| live.unkept.iter().sum::<usize>())
            .sum()
    }

    /// Fold in the Decryption Secrets Blocks `dissection` met since the last
    /// read.
    fn absorb_secrets_blocks(&mut self, dissection: &Dissection) {
        let blocks = dissection.decryption_secrets();
        if blocks.len() == self.blocks_read {
            return;
        }
        for block in blocks.iter().skip(self.blocks_read) {
            match KeyLog::from_secrets_block(block.secrets_type, &block.secrets) {
                Ok(parsed) => {
                    if !parsed.is_empty() {
                        self.grew = true;
                        self.quic_grew = true;
                    }
                    Arc::make_mut(&mut self.log).absorb(parsed);
                }
                Err(SecretsBlockError::UnknownSecretsType(_)) => {
                    self.foreign_secrets_blocks += 1;
                }
            }
        }
        self.blocks_read = blocks.len();
    }

    /// Pass every QUIC flow that opened no application data again over the
    /// packets it kept, with the keys held now.
    fn reopen_quic(&mut self) {
        let log = &self.log;
        for live in self.quic.values_mut() {
            live.reopen(log);
        }
    }

    /// Frame what the QUIC openers recovered since the last call, in the
    /// dissection's order of its flows, and let go of the flows it no longer
    /// holds.
    fn feed_quic(&mut self, dissection: &mut Dissection) {
        if self.quic.is_empty() {
            return;
        }
        if core::mem::take(&mut self.quic_grew) {
            self.reopen_quic();
        }
        let order = quic_flow_keys(dissection);
        let mut fed = 0usize;
        for flow in &order {
            if let Some(live) = self.quic.get_mut(flow) {
                self.quic_framing
                    .absorb(live.pass.feed(dissection, &mut ()));
                fed += 1;
            }
        }
        if fed < self.quic.len() {
            let held: BTreeSet<FlowKey> = order.into_iter().collect();
            self.quic.retain(|flow, _| held.contains(flow));
        }
    }

    /// How many connections the keys held name.
    pub fn connections(&self) -> usize {
        self.log.len()
    }

    /// Decryption Secrets Blocks of another protocol's secrets, skipped.
    pub fn foreign_secrets_blocks(&self) -> usize {
        self.foreign_secrets_blocks
    }

    /// Open what `dissection` kept since the last call: read the Decryption
    /// Secrets Blocks it met since, then, where any key is held, continue the
    /// TLS pass, and frame what the QUIC openers recovered since the last call
    /// (the QUIC half runs with no key too: the Initial space needs none).
    ///
    /// TLS first, as [`decrypt_capture`] runs it. The summary is the TLS
    /// pass's; all zeros where no key is held.
    pub fn run(&mut self, dissection: &mut Dissection) -> DecryptionSummary {
        self.absorb_secrets_blocks(dissection);
        let summary = if self.log.is_empty() {
            DecryptionSummary::default()
        } else {
            self.continue_tls(dissection)
        };
        self.feed_quic(dissection);
        summary
    }

    /// The TLS half of [`Self::run`], where a key is held.
    fn continue_tls(&mut self, dissection: &mut Dissection) -> DecryptionSummary {
        if core::mem::take(&mut self.grew) {
            dissection.reopen_unopened();
        }
        let summary = dissection.decrypt_continuing(self);
        // A begun flow took its secrets out of the log, so its opener lets go of
        // the log; an opener whose flow the dissection no longer holds goes.
        for opener in self.openers.values_mut() {
            opener.shed_log();
        }
        if self.openers.len() > dissection.flows().len() {
            let held: BTreeSet<FlowKey> = dissection.flows().iter().map(|f| f.flow).collect();
            self.openers.retain(|flow, _| held.contains(flow));
        }
        summary
    }
}

/// The hook a followed container shows each packet to: the packet is offered
/// as [`LiveDecryptor::offer_packet`] offers it.
impl PacketTap for LiveDecryptor {
    fn on_packet(&mut self, dissection: &Dissection, packet: &CapturedFrame<'_>) {
        self.offer_packet(dissection, packet.link_type, packet.index, packet.data);
    }
}

impl FlowOpeners for LiveDecryptor {
    fn opener(&mut self, flow: FlowKey, fresh: bool) -> &mut dyn RecordOpener {
        if fresh {
            self.openers
                .insert(flow, CaptureOpener::sharing(Arc::clone(&self.log)));
        }
        let log = &self.log;
        self.openers
            .entry(flow)
            .or_insert_with(|| CaptureOpener::sharing(Arc::clone(log)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::fixture::{
        application_secret, client_hello, crypto_frame, datagram_frame, log_text, long_header,
        protect, short_header, stream_frame, ICID, SCID,
    };
    use crate::quic::QuicKeys;
    use crate::Suite;
    use wz_capture::link::LINKTYPE_ETHERNET;
    use wz_capture::session_table::{session_table, Encryption};

    /// The ClientHello random the key log names.
    const RANDOM: [u8; 32] = [0x4d; 32];

    /// The KeepAlive MID with every flag clear: a whole message in one byte.
    const KEEPALIVE: u8 = 0x04;

    /// A framed unit on a QUIC stream: `u16` little-endian length, then the
    /// message.
    fn unit(message: &[u8]) -> Vec<u8> {
        let mut out = (message.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(message);
        out
    }

    /// Ethernet/IPv4/UDP between the client, 10.0.0.1:51000, and the server,
    /// 10.0.0.2:4433.
    fn udp(from_client: bool, payload: &[u8]) -> Vec<u8> {
        let (sport, dport) = if from_client {
            (51000u16, 4433u16)
        } else {
            (4433, 51000)
        };
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);
        let (from, to) = if from_client {
            ([10u8, 0, 0, 1], [10u8, 0, 0, 2])
        } else {
            ([10u8, 0, 0, 2], [10u8, 0, 0, 1])
        };
        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&from);
        ip.extend_from_slice(&to);
        wz_packet_fixtures::fill_ipv4_checksum(&mut ip);
        ip.extend_from_slice(&udp);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// One 1-RTT packet addressed to `dcid`.
    fn one_rtt(keys: &QuicKeys, dcid: &[u8], number: u32, payload: &[u8]) -> Vec<u8> {
        let (h, o) = short_header(dcid, number);
        protect(keys, u64::from(number), &h, o, payload)
    }

    /// The two Initial packets: the client's carrying its ClientHello, and the
    /// server's, whose source connection id is what the client's short headers
    /// carry.
    fn initials() -> [Vec<u8>; 2] {
        let (client, server) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let first = crypto_frame(0, &client_hello(&RANDOM));
        let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
        let client_first = protect(&client, 0, &h, o, &first);
        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
        let server_first = protect(&server, 0, &h, o, &reply);
        [udp(true, &client_first), udp(false, &server_first)]
    }

    /// One connection in capture order: the two Initials, two client 1-RTT
    /// packets carrying two KeepAlives on stream 0, cut inside the second one
    /// so the packet that completes it carries a message the one before began,
    /// and a server 1-RTT packet carrying a KeepAlive on stream 0 and one in an
    /// RFC 9221 datagram.
    fn connection() -> Vec<Vec<u8>> {
        const CUT: usize = 4;
        let client = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let server = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(true, 0));
        let mut stream = unit(&[KEEPALIVE]);
        stream.extend_from_slice(&unit(&[KEEPALIVE]));
        let mut answer = stream_frame(0, 0, &unit(&[KEEPALIVE]));
        answer.extend_from_slice(&datagram_frame(&[KEEPALIVE]));
        let [client_first, server_first] = initials();
        let head = one_rtt(&client, &SCID, 1, &stream_frame(0, 0, &stream[..CUT]));
        let tail = one_rtt(
            &client,
            &SCID,
            2,
            &stream_frame(0, CUT as u8, &stream[CUT..]),
        );
        vec![
            client_first,
            server_first,
            udp(true, &head),
            udp(true, &tail),
            udp(false, &one_rtt(&server, &[], 1, &answer)),
        ]
    }

    /// The packets as a pcapng file.
    fn file(packets: &[Vec<u8>]) -> Vec<u8> {
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        wz_capture::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &refs)
    }

    /// The file read whole and passed once, as a document door reads it.
    fn read_whole(file: &[u8], keylog: Option<&str>) -> Dissection {
        let mut d = Dissection::from_capture(file).expect("the capture reads");
        decrypt_capture(&mut d, file, keylog.map(str::as_bytes), None, &mut ());
        d
    }

    /// The packets fed one at a time, as a handle's push feeds them: read,
    /// offered, run. `keylog` is handed in before the first.
    fn fed(packets: &[Vec<u8>], keylog: Option<&str>) -> (Dissection, LiveDecryptor) {
        let mut d = Dissection::new();
        let mut live = LiveDecryptor::new();
        if let Some(text) = keylog {
            live.absorb(text.as_bytes());
            live.run(&mut d);
        }
        for (i, packet) in packets.iter().enumerate() {
            push(&mut d, &mut live, i, packet);
        }
        (d, live)
    }

    /// One packet the way a handle's push takes it in.
    fn push(d: &mut Dissection, live: &mut LiveDecryptor, index: usize, packet: &[u8]) {
        d.push_packet_at_nanos(
            LINKTYPE_ETHERNET,
            index,
            Some(1_000_000_000 + index as u64 * 100_000),
            packet,
        );
        live.offer_packet(d, LINKTYPE_ETHERNET, index, packet);
        live.run(d);
    }

    /// One message recovered from inside QUIC: its list (a stream's id, or
    /// `None` for the RFC 9221 datagrams), its half, its anchor, its place in
    /// its unit and whether it decoded.
    type Recovered = (Option<u64>, Direction, usize, usize, bool);

    /// Every message the dissection recovered from inside QUIC, in list order.
    fn recovered(d: &Dissection) -> Vec<Recovered> {
        let mut out = Vec::new();
        for flow in d.datagram_flows() {
            for stream in &flow.quic_streams {
                for m in stream.frames().iter() {
                    out.push((
                        Some(stream.id),
                        m.direction,
                        m.stream_offset,
                        m.batch_index,
                        m.frame.is_ok(),
                    ));
                }
            }
            for m in flow.quic_datagrams().iter() {
                out.push((
                    None,
                    m.direction,
                    m.stream_offset,
                    m.batch_index,
                    m.frame.is_ok(),
                ));
            }
        }
        out
    }

    /// The one row's `encrypted` finding.
    fn encryption(d: &Dissection) -> Encryption {
        let rows = session_table(d).rows;
        assert_eq!(rows.len(), 1, "one connection, one row");
        rows[0].encryption
    }

    /// KEYS FIRST: a flow fed packet by packet recovers what the file pass
    /// recovers, message for message, and the KeepAlive cut across two packets
    /// is framed from the bytes the stream keeps, so no offer goes unwalked.
    #[test]
    fn a_fed_quic_flow_with_its_keys_first_reads_as_the_file_pass_does() {
        let packets = connection();
        let keys = log_text(&RANDOM, 1);
        let whole = read_whole(&file(&packets), Some(&keys));
        let want = recovered(&whole);
        assert_eq!(
            want.len(),
            4,
            "three KeepAlives on stream 0 and one in a datagram: {want:?}"
        );
        assert!(want.iter().all(|m| m.4), "every message decodes: {want:?}");
        assert_eq!(encryption(&whole), Encryption::DecryptedQuic);

        let (d, live) = fed(&packets, Some(&keys));
        assert_eq!(recovered(&d), want);
        assert_eq!(encryption(&d), Encryption::DecryptedQuic);
        let framing = live.quic_framing();
        assert_eq!(framing.messages, 4, "{framing:?}");
        assert_eq!(
            (
                framing.appends_not_walked,
                framing.messages_straddling_offers
            ),
            (0, 0),
            "an offer that completes a message begun earlier is walked: {framing:?}"
        );
        assert_eq!(
            live.quic_packets_memory(),
            0,
            "a flow whose application data opened keeps nothing"
        );
    }

    /// KEYS AFTER THE PACKETS: the flow keeps what it could not open, and the
    /// key log passes it again through a fresh opener, to the same messages.
    #[test]
    fn a_fed_quic_flow_whose_keys_arrive_late_is_read_from_what_it_kept() {
        let packets = connection();
        let keys = log_text(&RANDOM, 1);
        let want = recovered(&read_whole(&file(&packets), Some(&keys)));

        let (mut d, mut live) = fed(&packets, None);
        assert!(recovered(&d).is_empty(), "no key, no application data");
        assert_eq!(encryption(&d), Encryption::EncryptedUnreadable);
        assert!(
            live.quic_packets_memory() > 0,
            "so the flow's packets are kept"
        );

        assert_eq!(live.absorb(keys.as_bytes()), 1);
        live.run(&mut d);
        assert_eq!(recovered(&d), want);
        assert_eq!(encryption(&d), Encryption::DecryptedQuic);
        assert_eq!(live.quic_packets_memory(), 0, "and then let go of");
        assert_eq!(live.quic_packets_unkept(), 0);
    }

    /// NO KEY: the Initial space opens anyway, so the version, the ClientHello
    /// and both Initials are read, the three 1-RTT packets wait for a key, and
    /// the row stays unreadable. The file pass says the same of the same
    /// packets.
    #[test]
    fn a_fed_quic_flow_with_no_key_reads_its_initial_space_and_nothing_more() {
        let packets = connection();
        let (d, live) = fed(&packets, None);
        assert!(recovered(&d).is_empty());
        assert_eq!(encryption(&d), Encryption::EncryptedUnreadable);

        let flows = live.quic_flows();
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.version, Some(QuicVersion::V1));
        assert!(
            flow.client_hello_seen,
            "the ClientHello is in the Initial space"
        );
        assert!(!flow.keys_installed);
        let initial: usize = flow
            .census
            .iter()
            .map(|c| c.opened_per_space[PacketSpace::Initial.index()])
            .sum();
        assert_eq!(initial, 2, "both Initial packets open with no key");
        let waiting: usize = flow.census.iter().map(|c| c.no_keys).sum();
        assert_eq!(waiting, 3, "the 1-RTT packets wait for a key");

        let capture = file(&packets);
        let mut whole = Dissection::from_capture(&capture).expect("reads");
        let (_, file_flows) = open_quic(&capture, &mut whole, &KeyLog::default(), None, &mut ());
        assert_eq!(file_flows.len(), 1);
        assert_eq!(file_flows[0].census, flow.census);
        assert_eq!(file_flows[0].client_hello_seen, flow.client_hello_seen);
    }

    /// A FOLLOWED CONTAINER shows the decryptor every packet through its tap,
    /// owned and lent, and reads as the file pass does, with the keys first
    /// and with the keys after.
    #[test]
    fn a_followed_quic_capture_reads_as_the_file_pass_does_through_both_doors() {
        let packets = connection();
        let keys = log_text(&RANDOM, 1);
        let capture = file(&packets);
        let want = recovered(&read_whole(&capture, Some(&keys)));

        let mut d = Dissection::new();
        let mut live = LiveDecryptor::new();
        live.absorb(keys.as_bytes());
        let mut cursor = wz_capture::CaptureCursor::new();
        d.follow_container_tapped(&mut cursor, &capture, &mut live)
            .expect("the container follows");
        live.run(&mut d);
        assert_eq!(recovered(&d), want, "owned, keys first");

        let mut d = Dissection::new();
        let mut live = LiveDecryptor::new();
        let mut cursor = wz_capture::CaptureCursor::new();
        let lent: Arc<dyn wz_capture::LentCapture> = Arc::new(capture.clone());
        d.follow_lent_tapped(&mut cursor, lent, &mut live)
            .expect("the container follows");
        live.run(&mut d);
        assert!(recovered(&d).is_empty(), "lent, before the keys");
        live.absorb(keys.as_bytes());
        live.run(&mut d);
        assert_eq!(recovered(&d), want, "lent, keys after");
    }

    /// THE KEPT PACKETS ARE BOUNDED, a direction at a time, and the bound keeps
    /// the oldest: past it the flow's figure stops growing and what it did not
    /// keep is counted. A key then opens the flow from its first flight, the
    /// kept 1-RTT packets are read, and nothing more is kept.
    #[test]
    fn a_quic_flow_keeps_at_most_the_bound_a_direction_and_nothing_once_it_opens() {
        let client = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let past = 7usize;
        let one_rtt_packets = MAX_KEPT_RECORDS_PER_DIRECTION + past;
        let mut packets: Vec<Vec<u8>> = initials().into();
        for n in 1..=one_rtt_packets as u32 {
            packets.push(udp(
                true,
                &one_rtt(&client, &SCID, n, &datagram_frame(&[KEEPALIVE])),
            ));
        }
        // The client's Initial and this many of its 1-RTT packets fill its
        // direction's bound.
        let kept_one_rtt = MAX_KEPT_RECORDS_PER_DIRECTION - 1;
        let at_bound = 2 + kept_one_rtt;

        let mut d = Dissection::new();
        let mut live = LiveDecryptor::new();
        for (i, packet) in packets[..at_bound].iter().enumerate() {
            push(&mut d, &mut live, i, packet);
        }
        let full = live.quic_packets_memory();
        assert!(full > 0);
        assert_eq!(live.quic_packets_unkept(), 0);
        // THE CEILING, from the bound and not from a measurement: a flow keeps
        // at most the bound a direction, each packet's bytes once, in a list
        // that holds at most twice what it keeps.
        let largest = packets.iter().map(Vec::len).max().expect("packets");
        let ceiling =
            2 * (2 * MAX_KEPT_RECORDS_PER_DIRECTION) * core::mem::size_of::<KeptQuicPacket>()
                + 2 * MAX_KEPT_RECORDS_PER_DIRECTION * largest;
        assert!(full <= ceiling, "{full} bytes kept, past {ceiling}");
        for (i, packet) in packets.iter().enumerate().skip(at_bound) {
            push(&mut d, &mut live, i, packet);
        }
        assert_eq!(
            live.quic_packets_memory(),
            full,
            "past the bound the figure does not move"
        );
        assert_eq!(live.quic_packets_unkept(), one_rtt_packets - kept_one_rtt);

        live.absorb(log_text(&RANDOM, 1).as_bytes());
        live.run(&mut d);
        let datagrams = recovered(&d);
        assert_eq!(
            datagrams.len(),
            kept_one_rtt,
            "every kept 1-RTT packet is read, and none the bound did not keep"
        );
        assert!(datagrams.iter().all(|m| m.0.is_none() && m.4));
        assert_eq!(
            live.quic_packets_memory(),
            0,
            "the opened flow keeps nothing"
        );
        assert_eq!(
            live.quic_packets_unkept(),
            one_rtt_packets - kept_one_rtt,
            "and what was lost stays counted"
        );
    }
}
