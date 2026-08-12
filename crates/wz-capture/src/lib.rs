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

// R311y612 — the measurement tests PRINT their corpora's accept rates, so the
// number a constant is read off is in the run's output rather than only in a
// comment. `std` under `cfg(test)` only: the crate itself stays `no_std`, and
// the harness that runs these tests is hosted by construction.
#[cfg(test)]
extern crate std;

/// R311y613 (§1.1f) — the first ANALYSIS plane over the decode: per-keyexpr
/// throughput. Its own module because it is the first thing here that folds
/// ACROSS messages rather than decoding one, and because keyexpr resolution
/// needs both id spaces — something only an observer of both directions has.
pub mod agg;
/// R311y615 (§1.1f) — the second ANALYSIS plane: Query/Reply exchanges and
/// their latency at the tap.
///
/// Gated on `network-codecs` where [`agg`] is not, and the difference is not
/// arbitrary. A throughput table without the network codecs still resolves
/// `id == 0` literals and answers a smaller question correctly; an exchange
/// table without `Request` / `Response` / `ResponseFinal` has no record it can
/// correlate at all, so its every answer would be a structural zero. A plane
/// that cannot be fed is absent rather than empty.
#[cfg(feature = "network-codecs")]
pub mod exchange;
/// R311y713 (§B1) — the exit every flow takes, as a type rather than as prose
/// beside each door. Private: its whole purpose is that nothing outside can add
/// to the carried counters, and a `pub` module would hand that back.
mod exit;
/// R311y714 (§1.1f) — the capture read as NODES: zids, their roles, and the
/// links where both ends named themselves. The one plane whose unit is not a
/// flow.
pub mod node;
use exit::ExitingFlow as _;
/// R311y616 (§1.1f) — the FILTER LANGUAGE: a selector a reader types, compiled
/// into a three-valued predicate over records.
///
/// UNGATED, unlike [`exchange`]: the language is text and a tree walk, and its
/// one external call is the keyexpr matcher, which `wz-session-core` ships
/// unconditionally. A build without the network codecs has fewer records to
/// judge and judges them by the same rules.
pub mod filter;
/// R311y606 — IP fragment reassembly. Its own module rather than part of
/// [`link`] because it holds STATE across packets and `link` is deliberately a
/// pure decapsulator; the same division `passive`'s chain reassembly is under.
pub mod frag;
pub mod link;
/// R311y669 (§1.2a) — RECOGNISING QUIC, so a QUIC capture stops being read as
/// zenoh.
///
/// Not a symmetry with [`tls`] but a correction: measured before it existed, a
/// QUIC exchange on a zenoh port reported four decoded messages including an
/// `Init` and a `Fragment`, out of a capture holding no zenoh at all. A QUIC
/// short header's first byte IS a flagged zenoh MID, so the module's whole
/// design question is what may decide — see its own note.
pub mod quic;
// R311y724 — DELIBERATELY UNDOCUMENTED HERE, and the reason is a trap this
// round paid for. An outer `///` on a `mod` declaration is CONCATENATED with
// the module's own `//!` docs, and the merged block then resolves its
// intra-doc links in THIS module's scope -- so every link the module makes to
// its own items (`MessageList`, `Discarded`, the `Deref` it imports) becomes
// `no item named ... in scope` and C1bz reds with a broken-link budget of
// zero. Measured: four broken links appeared the moment this line gained a
// doc comment and vanished when it lost one. The module's note is in
// `messages.rs`, which is where it belongs.
pub mod messages;
/// R311y617 (§1.1f) — the PAYLOAD sub-decoder: what is INSIDE a Put, judged
/// against the encoding the sender declared rather than rendered on its word.
///
/// The decision half is UNGATED (naming an encoding and validating bytes needs
/// no codec); the census plane over a whole capture is gated on
/// `network-codecs`, which is where `Push` / `Request` / `Response` come from.
pub mod payload;
pub mod pcap;
pub mod pcapng;
/// R311y615 (§1.1f) — the EXPORT plane: the analysis tables rendered for
/// something that is not a Rust caller, with their loss counters structurally
/// attached.
pub mod report;
pub mod serial;
pub mod tcp;
/// R311y648 (§1.2a) — RECOGNISING TLS, and deliberately not decrypting it.
///
/// UNGATED and dependency-free, like every other module here: reading a 5-byte
/// record header and walking the chain needs nothing but the bytes. The
/// decryption that will consume this lives on the far side of this crate's own
/// seam (a byte stream plus a direction), in a crate that may take the
/// workspace's already-pinned crypto — `wz-capture` keeps its zero third-party
/// dependencies.
pub mod tls;
pub mod ws;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use wz_session_core::chain_loss::ChainLoss;
use wz_session_core::parse_error::InboundParseError;
use wz_session_core::passive::{
    Direction, FlowContext, PassiveFrame, PassiveSession, PassiveStall,
};
use wz_session_core::scouting_message::{parse_scouting, ScoutingFrame};

use crate::link::{FlowKey, SkipReason, Transport};
use crate::tcp::StreamAssembler;

/// R311y643 (§1.1e) — every packet this build could not read, BY REASON.
///
/// # A count is not a diagnosis
///
/// `packets_skipped` has always been one number, and the reasons behind it are
/// not one kind of thing. "40 packets skipped" over an Ethernet capture full of
/// ARP is a healthy capture; the same number over a capture whose LINK TYPE this
/// build does not decapsulate means the file was never read at all. Both
/// rendered identically, and the second is indistinguishable from "this
/// deployment carried no zenoh traffic" — which is the wrong conclusion about a
/// working system, reached from a correct number.
///
/// That case is not hypothetical here. wz drives three links with no assigned
/// libpcap DLT — unix sockets, unix pipes and serial — so a capture of one
/// arrives under a private-use or vendor link type, is refused packet by packet,
/// and produces an empty dissection with a plausible-looking skip count.
///
/// # Counted at the door, never derived from the list
///
/// [`Dissection::skipped`] is CAPPED
/// ([`DissectionLimits::skipped_packets`]) and its overflow is dropped, so a
/// census folded from it would be silently short on exactly the large captures
/// that need one. These counters are incremented where the skip is decided,
/// which is the only place the total is known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkipCensus {
    /// The capture's link type is not decapsulated by this build.
    pub unsupported_link_type: usize,
    /// The LINK TYPES behind that count — a SET, because the actionable fact is
    /// WHICH one, and a reader holding it can say "DLT 147" rather than "some
    /// packets were skipped". A count alone cannot name what to add.
    pub unsupported_link_types: BTreeSet<u32>,
    /// Shorter than the headers it declared.
    pub truncated: usize,
    /// Not IP: ARP, LLDP, and the ordinary furniture of a real capture.
    pub not_ip: usize,
    /// IP, but neither TCP nor UDP.
    pub not_transport: usize,
    /// An IPv4 fragment other than the first, recorded by a consumer that does
    /// not reassemble.
    pub ipv4_fragment: usize,
    /// A piece of a datagram still waiting for the rest of it.
    pub ip_fragment_pending: usize,
    /// A vsock packet carrying no payload (a control op).
    pub vsock_non_payload: usize,
    /// An IPv6 extension chain this reader may not walk past — ESP, the two
    /// experimental numbers, or one longer than the bound.
    pub ipv6_extension_chain: usize,
    /// An IPv6 fragment other than the first.
    pub ipv6_fragment: usize,
}

impl SkipCensus {
    /// Every skip, whatever the reason — equal to
    /// [`DissectionHealth::packets_skipped`] and computed independently of it, so
    /// the two disagreeing would mean one of them stopped seeing a path.
    pub fn total(&self) -> usize {
        self.unsupported_link_type
            + self.truncated
            + self.not_ip
            + self.not_transport
            + self.ipv4_fragment
            + self.ip_fragment_pending
            + self.vsock_non_payload
            + self.ipv6_extension_chain
            + self.ipv6_fragment
    }

    /// `true` when nothing was skipped at all.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    fn note(&mut self, reason: SkipReason) {
        match reason {
            SkipReason::UnsupportedLinkType(dlt) => {
                self.unsupported_link_type += 1;
                self.unsupported_link_types.insert(dlt);
            }
            SkipReason::Truncated => self.truncated += 1,
            SkipReason::NotIp => self.not_ip += 1,
            SkipReason::NotTransport(_) => self.not_transport += 1,
            SkipReason::Ipv4Fragment => self.ipv4_fragment += 1,
            SkipReason::IpFragmentPending => self.ip_fragment_pending += 1,
            SkipReason::VsockNonPayload(_) => self.vsock_non_payload += 1,
            SkipReason::Ipv6ExtensionChain(_) => self.ipv6_extension_chain += 1,
            SkipReason::Ipv6Fragment => self.ipv6_fragment += 1,
        }
    }
}

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
    pub frames: messages::MessageList,
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
    /// R311y651 (§4.4) — the index of the last packet seen on this flow, which
    /// is what makes "least recently active" answerable here as it already was
    /// for a stream flow.
    last_activity: usize,
    /// R311y669 (§1.2a) — QUIC, once a long header has established that this
    /// flow is QUIC. `None` until then, and never guessed: the recognition rule
    /// requires a long header precisely because a short header's first byte is
    /// indistinguishable from a flagged zenoh MID
    /// ([`crate::quic`]). While it is `Some`, datagrams on this flow are COUNTED
    /// and not handed to the zenoh observer — which is the whole correction, as
    /// the alternative measured as four decoded messages that did not exist.
    pub quic: Option<quic::QuicCensus>,
    /// R311y709 (§1.2a) — bytes recovered for this flow against bytes handed on.
    ///
    /// On a QUIC flow `fed` stays zero for the life of the capture, which is
    /// R311y705's finding expressed as a count rather than as a paragraph.
    residue: ByteResidue,
    /// R311y713 (§B6) — chains THIS flow lost, and how much was in them.
    chain_loss: ChainLoss,
    /// R311y713 (§B4) — the CAPTURE INSTANT of the last packet on this flow,
    /// where the source had one. See [`Dissection::least_recently_active`].
    last_seen_ms: Option<u64>,
    /// R311y718 (§1.2a) — the zenoh sessions recovered OUT of this flow's QUIC
    /// streams, one per stream id.
    ///
    /// # Why a list beside `frames` rather than more entries in it
    ///
    /// [`PassiveFrame::stream_offset`] means a different thing on each of the
    /// two lists, and nothing in a frame says which. On [`Self::frames`] it is
    /// the index of the PACKET that carried the message, because a datagram has
    /// no stream to be an offset into; on a recovered QUIC stream it is a byte
    /// offset within that stream, exactly as it is on a TCP flow. Folding the
    /// two would put a third meaning into a field two consumers already resolve
    /// (`packet_for`, the run map) with no discriminator to branch on — which is
    /// R311y713's coordinate defect, one list over.
    ///
    /// # Why one session per stream id
    ///
    /// zenoh's QUIC link is STREAMED (`is_streamed()` is `true`,
    /// `zenoh-link-quic/src/unicast.rs:184`) and opens ONE bidirectional stream
    /// per link (`open_bi()`, `:330`; the acceptor's `accept_bi()`, `:524`), so
    /// the bytes inside it are the ordinary length-prefixed batch stream this
    /// crate already frames. Both halves of a bidi stream share one id, which is
    /// why the id keys a whole [`PassiveSession`] rather than one direction of
    /// one: the zenoh handshake is an exchange, and splitting the two halves
    /// into separate sessions would leave each looking at a monologue.
    ///
    /// A LIST and not one session, because "one stream per link" is a property
    /// of today's zenoh and not of QUIC: a second stream on the same connection
    /// is a second independent byte stream, and feeding it into the first one's
    /// framer would lay one length prefix over another's payload.
    pub quic_streams: Vec<QuicStreamDissection>,
    /// R311y719 (§1.2a) — messages decoded out of this flow's recovered RFC
    /// 9221 DATAGRAM frames, which is how zenoh's
    /// `transport-link-quic-datagram` sends a batch.
    ///
    /// # Why not [`Self::frames`], whose coordinate these share
    ///
    /// They really do share it — a recovered datagram's anchor is the index of
    /// the QUIC packet that carried it, exactly as a cleartext datagram's is —
    /// so folding them in would be sound for every consumer that only READS the
    /// coordinate. One consumer RESOLVES it: the field walk re-reads the packet
    /// out of the capture file and dissects its payload. For a cleartext
    /// datagram that payload is the message; for one of these it is the QUIC
    /// packet's CIPHERTEXT, and the walk would report field names read out of
    /// protected bytes. A confidently wrong row is the failure this crate
    /// exists to prevent, and the discriminator that avoids it is the list.
    ///
    /// Their fields come from the sink instead, taken while the recovered
    /// plaintext was alive — the same route [`Self::quic_streams`] uses.
    pub quic_datagrams: messages::MessageList,
}

/// R311y718 (§1.2a) — one recovered QUIC stream, framed as zenoh.
///
/// The QUIC half of it — packet protection, frame walking, reassembly — is a
/// caller's job (`wz-capture` carries no cipher, see [`crate::quic`]). What
/// arrives here is the contiguous byte prefix that came out of that work, and
/// what happens to it here is precisely what happens to a `tcp/...` flow's
/// reassembled bytes.
#[derive(Debug)]
pub struct QuicStreamDissection {
    /// The QUIC stream id these bytes were recovered from.
    pub id: u64,
    /// The zenoh-level observer over both directions of that stream.
    pub session: PassiveSession,
    /// Decoded transport messages. `stream_offset` is a byte offset within the
    /// RECOVERED stream of its own direction — see [`DatagramDissection`] on
    /// why that cannot share a list with the packet-indexed ones.
    pub frames: messages::MessageList,
    /// Bytes handed to the framer, per direction.
    fed: [u64; 2],
}

impl QuicStreamDissection {
    /// Bytes this stream's framer was given, per direction.
    ///
    /// The denominator for "how much of what QUIC recovered turned into zenoh":
    /// a stream whose messages are zero and whose `fed` is large is a framing
    /// disagreement, and one where both are zero is a stream that carried
    /// nothing. Without this they are the same row.
    pub fn fed(&self) -> [u64; 2] {
        self.fed
    }

    /// R311y718 — bytes this stream was given that NO message came out of.
    ///
    /// # Why the count exists, and why it is not `fed - messages`
    ///
    /// Feeding a framer is not reading. A recovered stream carrying bytes that
    /// are not zenoh — or a zenoh stream cut short by a hole QUIC could not
    /// recover — is pushed in, waits for a length prefix that never completes,
    /// and yields nothing. A report that counted the offer as the read would
    /// call such a capture whole, which is the over-report R311y716 shipped in
    /// the alert path and R311y705 caught one layer up.
    ///
    /// So the measure is what the framer CONSUMED: each direction's last frame
    /// ends at `stream_offset + prefix_width + unit_len`, and everything past
    /// that is still pending. Taking the last frame's end rather than summing
    /// the frames is deliberate — the sum would be wrong the moment a framing
    /// unit is skipped, and the offsets are the session's own coordinates
    /// rather than this function's arithmetic.
    pub fn undecoded_bytes(&self) -> u64 {
        let mut left = 0u64;
        for (index, fed) in self.fed.iter().enumerate() {
            let direction = idx_direction(index);
            let consumed = self
                .frames
                .iter()
                .filter(|f| f.direction == direction)
                .map(|f| (f.stream_offset + f.prefix_width + f.unit_len) as u64)
                .max()
                .unwrap_or(0);
            left += fed.saturating_sub(consumed);
        }
        left
    }
}

impl DatagramDissection {
    fn new(flow: FlowKey, window_ms: Option<u64>) -> Self {
        Self {
            flow,
            session: new_session(window_ms),
            frames: messages::MessageList::new(),
            scouting: Vec::new(),
            last_activity: 0,
            quic: None,
            residue: ByteResidue::default(),
            chain_loss: ChainLoss::default(),
            last_seen_ms: None,
            quic_streams: Vec::new(),
            quic_datagrams: messages::MessageList::new(),
        }
    }

    /// R311y718 — transport messages decoded on this flow, over BOTH of the
    /// lists that hold them.
    ///
    /// Every capture-wide count goes through this rather than through
    /// `frames.len()`, so that a plane taught about the datagram half is taught
    /// about the QUIC half with it. The lesson is R311y700's: a new list that
    /// reaches one row producer reports the rest as empty.
    pub fn decoded_messages(&self) -> usize {
        self.frame_lists().map(<[_]>::len).sum()
    }

    /// R311y718 — every list of decoded transport messages this flow holds.
    ///
    /// # Why the planes iterate this instead of naming `frames`
    ///
    /// Four census planes walk the datagram table — throughput, exchanges,
    /// payloads, nodes — and each named `flow.frames` directly. A second list
    /// therefore reached whichever plane its author remembered, and the rest
    /// reported the flow as if the list were not there. That has happened four
    /// times in this workspace (R311y668, y678, y699, y700), and the last two
    /// were consecutive rounds.
    ///
    /// So the enumeration is a method rather than a convention: a plane that
    /// walks this is right for lists that do not exist yet, and a list added
    /// here reaches every plane at once. The rows keep their own coordinate
    /// meanings — see [`Self::quic_streams`] — so this is deliberately an
    /// iterator of SLICES and not a flattened frame iterator, which would fuse
    /// two offset spaces into one sequence.
    pub fn frame_lists(&self) -> impl Iterator<Item = &[PassiveFrame]> {
        core::iter::once(self.frames.as_slice())
            .chain(self.quic_streams.iter().map(|s| s.frames.as_slice()))
            .chain(core::iter::once(self.quic_datagrams.as_slice()))
    }

    /// R311y713 (§B6) — the chains this flow lost, whatever the cause.
    ///
    /// The capture-wide counters say how much was lost and never WHERE, which
    /// is the first thing a reader diagnosing one asks. Per flow, the answer is
    /// a 5-tuple away.
    pub fn chain_loss(&self) -> ChainLoss {
        self.chain_loss
    }

    /// R311y709 — this flow's recovered-against-fed counts.
    pub fn residue(&self) -> ByteResidue {
        self.residue
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
///
/// # R311y608 — and why the destination is only half the exchange
///
/// The rule above is sound for the REQUEST and blind to the RESPONSE. zenoh's
/// scout responder answers from a unicast socket straight back to the asker —
/// `socket.send_to(wbuf.as_slice(), peer)` on the socket
/// `get_best_match(&peer.ip(), ucast_sockets)` returns
/// (`zenoh/src/net/runtime/orchestrator.rs:1167-1180`) — so a HELLO's
/// destination is UNICAST and `is_ip_multicast()` is false for every one of
/// them. `S_MID_HELLO` is `0x02` and so is `T_MID_OPEN`, so each answered
/// scout produced a confident `Open`: the same misread R311y607 closed on the
/// request half, still open on the reply half.
///
/// Nothing in a HELLO's own bytes can settle it — a participant knows because
/// the reply arrives on the socket it scouted FROM (pico reads it with
/// `_z_link_recv_zbuf` on the link `__z_scout_loop` opened,
/// `vendor/zenoh-pico/src/session/scout.c:54-68`). A passive observer has no
/// socket, so it keeps the one thing that survives into a capture: WHICH
/// ENDPOINT ASKED. A `0x02` addressed to an endpoint that was seen sending a
/// SCOUT is the answer to it; a `0x02` addressed to anyone else is an Open.
///
/// [`ScoutingCorrelation`] is that memory, and it is why this is a method on
/// [`Dissection`] rather than a free function over one datagram.
fn scouting_mid(d: &link::Datagram) -> Option<u8> {
    let &header = d.payload.first()?;
    let mid = header & 0x1F;
    (mid == wz_session_core::wire_const::S_MID_SCOUT
        || mid == wz_session_core::wire_const::S_MID_HELLO)
        .then_some(mid)
}

/// R311y608 — which kind of datagram link a [`link::Datagram`] came off.
///
/// Both kinds are carried by the same struct — that is R311y597's decision and
/// a sound one, since pico puts exactly one wire message in each — so the kind
/// is lost the moment the two arms are collapsed. It has to be threaded because
/// ONE question depends on it and no field of the datagram answers it: does
/// this link have a handshake?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramLink {
    /// A UDP datagram. Whether it has a handshake depends on the destination:
    /// unicast does, a multicast group does not.
    Udp,
    /// pico's raweth L2 link. NEVER has a handshake, whatever the destination
    /// MAC says.
    RawEth,
}

impl DatagramLink {
    /// Does a session handshake happen on this link?
    ///
    /// The raweth answer is unconditional, and that is the whole reason this
    /// enum exists rather than an address rule: pico sets
    /// `Z_LINK_CAP_TRANSPORT_RAWETH` on every raweth link
    /// (`vendor/zenoh-pico/src/transport/raweth/link.c:476`) and hands that
    /// capability to `_z_new_transport_multicast`
    /// (`src/transport/multicast/transport.c:42-45`), whose receive path
    /// discards INIT and OPEN. The destination MAC is not consulted anywhere in
    /// that chain — and pico's own default mapping addresses
    /// `aa:bb:cc:dd:ee:ff` (`raweth/link.c:66`), whose I/G bit is CLEAR, so the
    /// obvious "L2 multicast is the low bit of the first octet" rule would read
    /// pico's default deployment as a unicast link with a handshake and be
    /// wrong about every frame on it.
    ///
    /// No scouting arm, and that is measured too: pico's scout loop takes the
    /// locator apart and REFUSES anything whose protocol is not `udp`
    /// (`src/session/scout.c:38-48`, `_Z_ERR_TRANSPORT_NOT_AVAILABLE`), and
    /// zenoh's Rust implementation has no raweth link at all. So a SCOUT cannot
    /// travel here — the `0x01` this arm makes inadmissible is not a scout
    /// being rescued, it is a message no participant sends and none accepts.
    fn handshake(self, d: &link::Datagram) -> wz_session_core::passive::LinkHandshake {
        use wz_session_core::passive::LinkHandshake;
        match self {
            DatagramLink::RawEth => LinkHandshake::Absent,
            DatagramLink::Udp if d.destination().is_ip_multicast() => LinkHandshake::Absent,
            DatagramLink::Udp => LinkHandshake::Present,
        }
    }
}

/// R311y608 — the endpoints observed ASKING, so the answers can be recognised.
///
/// A bounded, insertion-ordered set rather than a `BTreeSet`: the bound has to
/// evict the OLDEST to be useful on a long live tap (a scouting host that has
/// gone silent is the one whose slot should go), and the cardinality is the
/// number of distinct scouting hosts in a capture — small enough that a linear
/// scan is cheaper than the ordering a tree would maintain.
///
/// Eviction is COUNTED, not silent: dropping an asker turns its next answer
/// back into an `Open`, so a bound that bit without saying so would look
/// exactly like the defect this type exists to fix.
#[derive(Debug, Default)]
struct ScoutingCorrelation {
    askers: Vec<link::Endpoint>,
}

impl ScoutingCorrelation {
    /// Record that `who` sent a SCOUT. Returns how many askers were evicted.
    fn observed_scout_from(&mut self, who: link::Endpoint, cap: Option<usize>) -> usize {
        if self.askers.contains(&who) {
            return 0;
        }
        self.askers.push(who);
        match cap {
            Some(max) if self.askers.len() > max => {
                let cut = self.askers.len() - max;
                self.askers.drain(..cut);
                cut
            }
            _ => 0,
        }
    }

    /// Did `who` ask? — i.e. is a HELLO addressed there an ANSWER?
    fn asked(&self, who: &link::Endpoint) -> bool {
        self.askers.contains(who)
    }
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

/// R311y661 — the inverse of [`dir_index`].
fn idx_direction(index: usize) -> Direction {
    if index == 0 {
        Direction::A
    } else {
        Direction::B
    }
}

/// R311y661 (§1.2a) — rewrite decrypted frames' offsets from PLAINTEXT space
/// into the flow's TCP stream space.
///
/// `spans` is `(plaintext_offset, stream_offset)` for each opened record, in
/// order: the record starting at plaintext offset `p` began at stream offset
/// `s`. A frame at plaintext offset `f` belongs to the LAST span whose `p <= f`,
/// and takes that span's `s`.
///
/// The frame's position INSIDE the record is deliberately not added to `s`.
/// Those are two different measures — plaintext bytes and ciphertext bytes — and
/// adding one to the other would produce a number in neither space, which is a
/// worse answer than the record's own start. What the offset must support is
/// `packet_for`, and every byte of a record arrives in the packet that completes
/// it or earlier, so the record's start resolves to a packet that genuinely
/// carried this frame's bytes.
fn remap_decrypted_offsets(frames: &mut [PassiveFrame], spans: &[(usize, usize)]) {
    for frame in frames {
        let span = spans
            .iter()
            .rev()
            .find(|(plain_at, _)| *plain_at <= frame.stream_offset);
        if let Some((_, stream_offset)) = span {
            frame.stream_offset = *stream_offset;
        }
    }
}

/// R311y677 (§1.1n) — one direction's opened plaintext, offered to a
/// [`PlaintextSink`] while it exists.
#[derive(Debug, Clone, Copy)]
pub struct DecryptedStream<'a> {
    /// The connection it belongs to.
    pub flow: link::FlowKey,
    /// Which half of it.
    pub direction: Direction,
    /// Every `application_data` record of this direction, opened and
    /// concatenated in wire order. This is the byte stream the session was fed,
    /// and the space the messages in it are framed in.
    pub plaintext: &'a [u8],
    /// R311y678 — the frames the session decoded OUT OF [`Self::plaintext`],
    /// with their coordinates still in its space.
    ///
    /// Offered so a consumer never has to walk the framing a second time. It is
    /// not a convenience: a consumer walking it itself holds a second opinion
    /// about where the messages are, and nothing in this crate compares the two
    /// — a capture they disagreed about would report one `messages decoded` and
    /// a different set underneath it.
    ///
    /// Valid only during the call. `remap_decrypted_offsets` rewrites every one
    /// of these `stream_offset`s into ciphertext space the moment it returns,
    /// which is what makes this window the only one.
    pub frames: &'a [wz_session_core::passive::PassiveFrame],
    /// `(offset within `plaintext`, stream offset of the RECORD it came out of)`,
    /// in increasing order of the first.
    ///
    /// The map that lets a consumer report a plaintext finding in the
    /// coordinate space the rest of the report uses — the same map
    /// `remap_decrypted_offsets` applies to the frames, offered rather than
    /// applied so a consumer can also stay in plaintext space if that is the
    /// question it is answering.
    pub record_origins: &'a [(usize, usize)],
}

impl DecryptedStream<'_> {
    /// The stream offset of the record `at` came out of, for reporting a
    /// plaintext position in the report's coordinate space.
    ///
    /// `None` only when `at` precedes the first record, which cannot happen for
    /// an offset inside [`Self::plaintext`] and is answered rather than panicked
    /// on for the same reason `BatchParse::span_of` answers `None`.
    pub fn record_origin(&self, at: usize) -> Option<usize> {
        self.record_origins
            .iter()
            .rev()
            .find(|(plain_at, _)| *plain_at <= at)
            .map(|(_, stream_offset)| *stream_offset)
    }
}

/// R311y677 (§1.1n) — a consumer of the plaintext a decryption pass opens.
///
/// Implemented by `()` as a no-op, which is what [`Dissection::decrypt_with`]
/// passes: a caller who does not want the plaintext must not pay for it, and
/// must not have to say so.
pub trait PlaintextSink {
    /// One direction of one flow, fully opened.
    ///
    /// Called before the frames are decoded from it, so a sink sees exactly the
    /// bytes the session will see. It borrows: nothing here obliges a sink to
    /// keep any of it, and a sink that does keep some owns that bound itself.
    fn on_plaintext(&mut self, stream: DecryptedStream<'_>);

    /// R311y719 — one recovered RFC 9221 DATAGRAM and the messages in it.
    ///
    /// A SECOND method rather than a `DecryptedStream` with a flag, because the
    /// coordinate contract differs and that is the whole reason a sink needs
    /// telling apart. In [`DecryptedStream`] a frame's `stream_offset` is an
    /// offset INTO `plaintext`, which is what lets a sink slice the message out
    /// of it. On a datagram it is the index of the capture PACKET, and a sink
    /// that sliced with it would take bytes from an arbitrary place in the
    /// payload and call them a message. Same shape as the split between the two
    /// lists this feeds ([`DatagramDissection::quic_datagrams`]).
    ///
    /// REQUIRED rather than defaulted: a defaulted no-op would let a sink
    /// silently miss a producer, which is the omission this workspace has
    /// shipped four times (R311y668, y678, y699, y700). `()` opts out
    /// explicitly below.
    fn on_recovered_datagram(&mut self, datagram: RecoveredDatagram<'_>);
}

/// R311y719 (§1.2a) — one RFC 9221 datagram a decryptor recovered, with the
/// messages this crate framed out of it.
///
/// The datagram twin of [`DecryptedStream`], and its fields say the difference:
/// there is one PAYLOAD rather than a stream, and one PACKET INDEX rather than
/// a map back into a ciphertext record — a recovered datagram came out of
/// exactly one capture packet, so the anchor is a number and not a lookup.
#[derive(Debug)]
pub struct RecoveredDatagram<'a> {
    /// The flow it belongs to.
    pub flow: FlowKey,
    /// Which way it travelled.
    pub direction: Direction,
    /// The capture packet the QUIC packet carrying it was in.
    pub packet_index: usize,
    /// The recovered batch, whole.
    pub payload: &'a [u8],
    /// The messages framed out of it. Their `unit_offset` and `unit_len` are
    /// offsets into [`Self::payload`]; their `stream_offset` is
    /// [`Self::packet_index`] and must not be used to slice it.
    pub frames: &'a [PassiveFrame],
}

impl PlaintextSink for () {
    fn on_plaintext(&mut self, _stream: DecryptedStream<'_>) {}
    fn on_recovered_datagram(&mut self, _datagram: RecoveredDatagram<'_>) {}
}

/// R311y661 (§1.2a) — what one [`Dissection::decrypt_with`] pass did.
///
/// Returned rather than only recorded per flow, because the caller's question
/// is usually capture-wide ("did supplying these keys accomplish anything") and
/// answering it by folding [`Dissection::encrypted_flows`] means a caller
/// reimplementing this loop.
///
/// `flows - decrypted - refused` is not a fourth category: a flow the opener
/// accepted and whose records then refused the keys is counted in `flows` and in
/// neither of the other two, which is exactly the partial state
/// [`tls::NotDecrypted::RecordRefusedKeys`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DecryptionSummary {
    /// Encrypted flows this pass considered.
    pub flows: usize,
    /// Flows every kept record of which opened.
    pub decrypted: usize,
    /// Flows the opener declined before any record was tried.
    pub refused: usize,
    /// Records opened, over every flow and direction.
    pub records: usize,
    /// zenoh transport messages decoded out of the plaintext.
    ///
    /// The number the whole track exists to move off zero.
    pub frames: usize,
    /// R311y684 (§1.1n) — flows a PREVIOUS pass already settled, which this one
    /// skipped.
    ///
    /// # The silence this ends
    ///
    /// The pass is idempotent by flow, and it has to be: a stream reader handed
    /// the same bytes twice decodes them twice, and the second set of frames
    /// would look exactly as real as the first (R311y661). But the skip was
    /// SILENT, so a second pass reported `flows: 0` — byte-identical to the
    /// summary of a capture that had no encrypted flow in it at all.
    ///
    /// That matters because of [`Dissection::decrypt_with_sink`]: a caller
    /// installing a sink on a second pass receives NOTHING, and had no way to
    /// tell that from "this capture had no plaintext to offer". Counted here,
    /// the two are different numbers, which is the same rule every bound in
    /// this crate follows — a skip that reports nothing reports itself as the
    /// wire.
    pub already_opened: usize,
}

/// R311y615 — which of a [`Dissection`]'s two flow vectors an index refers to.
///
/// Exists only so [`Dissection::advance_clock`] can be written once for both:
/// the stream and datagram families keep separate vectors, and passing the
/// session by reference instead would hold a borrow across the counter update
/// the function also has to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowKind {
    Stream,
    Datagram,
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
    /// R311y612 (§4.1) — a hole landed INSIDE the opening literal, so the
    /// bytes that would have settled `Undecided` can never arrive.
    ///
    /// A state rather than the `Stream` default it used to collapse to, and
    /// for exactly the reason [`Self::Undecided`] is a state: guessing was the
    /// silent failure. Until R311y612 a hole in the first four bytes of a real
    /// ws flow classified the whole connection as a length-prefixed stream,
    /// which then reads RFC6455 frame headers as length prefixes — a confident
    /// misread, and the worse half of the failure mode this module exists to
    /// end. The question moves to the bytes AFTER the hole and is answered by
    /// [`ws::carries_ws_frames`], which is a measurement.
    OpeningLost,
    /// zenoh's length-prefixed byte stream, straight into the observer.
    Stream,
    /// RFC6455 frames wrapping one zenoh batch each, per direction.
    ///
    /// R311y612 — BOXED. The deframers grew a scan state and an accounting
    /// block, and an unboxed pair made every `Framing` in the tree — including
    /// the `Undecided` one every non-ws flow holds forever — carry their
    /// footprint. The indirection is paid only by flows that are actually ws.
    WebSocket {
        /// [`Direction::A`]'s deframer (`low` -> `high`).
        a: alloc::boxed::Box<ws::WsDeframer>,
        /// [`Direction::B`]'s deframer.
        b: alloc::boxed::Box<ws::WsDeframer>,
    },
    /// R311y648 (§1.2a) — a TLS record stream. The zenoh session is inside it
    /// and this build has no key material, so the bytes are COUNTED and not
    /// fed to the observer.
    ///
    /// A state of its own rather than `Stream` with an error, because the two
    /// are opposite findings: a stream that fails to decode is a wz defect or a
    /// corrupt capture, and this is a capture working exactly as designed whose
    /// contents are lawfully unavailable. Before this arm existed the flow was
    /// classified `Stream`, the reader took the record header's first two bytes
    /// as a little-endian length prefix, waited forever for bytes that never
    /// satisfied it, and reported ZERO frames with ZERO desyncs, ZERO skips and
    /// ZERO gaps — a healthy-looking flow with nothing in it, which reads as
    /// "this deployment carried no zenoh traffic".
    ///
    /// BOXED for the reason the ws pair is: the per-direction pending buffers
    /// would otherwise sit in every `Undecided` flow in the tree.
    Encrypted(alloc::boxed::Box<tls::TlsFlowState>),
}

impl Framing {
    /// Is this flow carrying WebSocket?
    pub fn is_websocket(&self) -> bool {
        matches!(self, Framing::WebSocket { .. })
    }

    /// R311y648 — is this flow's zenoh session inside an encrypted transport?
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Framing::Encrypted(_))
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
    pub frames: messages::MessageList,
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
    /// R311y612 (§4.1) — per direction, how many held bytes arrived BEFORE the
    /// hole that lost the opening, and how many bytes that hole swallowed.
    ///
    /// The anchor every later decision needs: whichever framing wins,
    /// `held[dir][..before_gap[dir]]` is the near side of the hole and the
    /// rest is the far side, and the two must not be handed on as one run.
    opening_gap: [Option<(usize, u64)>; 2],
    /// R311y612 — resynchronisations the ws deframers reported, in order, with
    /// the direction each belongs to.
    ws_resyncs: Vec<(Direction, ws::WsResync)>,
    /// R311y709 (§1.2a) — bytes recovered for this flow against bytes handed on.
    residue: ByteResidue,
    /// R311y713 (§B6) — chains THIS flow lost, and how much was in them.
    chain_loss: ChainLoss,
    /// R311y713 (§B4) — the CAPTURE INSTANT of the last packet on this flow.
    last_seen_ms: Option<u64>,
}

/// R311y612 (§4.1) — post-hole bytes held per direction while deciding whether
/// a flow whose opening was lost carries WebSocket.
///
/// Bounded, and the bound is what keeps the decision from being another silent
/// hole: a flow that goes quiet after the gap must still be reported, so
/// [`Dissection::finish`] flushes whatever is held. 8 KiB is above any
/// plausible run of three zenoh ws frames on a session that is doing anything
/// at all, and small enough that the deferral costs one packet's latency
/// rather than a capture's.
const WS_CLASSIFY_BUDGET: usize = 8 * 1024;

impl FlowDissection {
    /// R311y709 — this flow's recovered-against-fed counts.
    pub fn residue(&self) -> ByteResidue {
        self.residue
    }

    /// R311y713 (§B6) — the chains this flow lost, whatever the cause.
    ///
    /// The three capture-wide counters — expired, abandoned, evicted — say how
    /// many and, since R311y713, how much; none of them says WHICH FLOW, which
    /// is the first thing a reader diagnosing a loss asks. A capture with one
    /// bad link and nine good ones reads as uniformly lossy without this.
    pub fn chain_loss(&self) -> ChainLoss {
        self.chain_loss
    }

    fn new(flow: FlowKey, window_ms: Option<u64>, gap_patience: Option<usize>) -> Self {
        Self {
            flow,
            low_to_high: StreamAssembler::new().with_gap_patience(gap_patience),
            high_to_low: StreamAssembler::new().with_gap_patience(gap_patience),
            session: new_session(window_ms),
            frames: messages::MessageList::new(),
            last_activity: 0,
            framing: Framing::Undecided,
            held: [Vec::new(), Vec::new()],
            vsock_seq: [0, 0],
            opening_gap: [None, None],
            ws_resyncs: Vec::new(),
            residue: ByteResidue::default(),
            chain_loss: ChainLoss::default(),
            last_seen_ms: None,
        }
    }

    /// R311y612 — every ws resynchronisation this flow reported, in order.
    ///
    /// Exposed per flow and not only as a total because the number a reader
    /// wants first is WHERE: a recovery names the offsets either side of what
    /// it will never deframe, and `packet_for` turns those into packets.
    pub fn ws_resyncs(&self) -> &[(Direction, ws::WsResync)] {
        &self.ws_resyncs
    }

    /// R311y612 — the ws framing health of both directions, summed.
    pub fn ws_accounting(&self) -> ws::WsResyncAccounting {
        let Framing::WebSocket { a, b } = &self.framing else {
            return ws::WsResyncAccounting::default();
        };
        let (x, y) = (a.accounting(), b.accounting());
        ws::WsResyncAccounting {
            desyncs: x.desyncs + y.desyncs,
            recoveries: x.recoveries + y.recoveries,
            skipped_bytes: x.skipped_bytes + y.skipped_bytes,
        }
    }

    /// R311y602 — what this flow's byte stream turned out to be.
    pub fn framing(&self) -> &Framing {
        &self.framing
    }

    /// R311y648 (§1.2a) — this flow's encrypted-transport finding, or `None`
    /// when its bytes are the zenoh session itself.
    ///
    /// `Some` is not a failure. It is the most this reader can honestly say
    /// about a `tls/...` or `quic/...` deployment without key material, and it
    /// is strictly more than the ZERO frames and perfect health the flow
    /// reported before the finding existed.
    pub fn encrypted(&self) -> Option<tls::EncryptedFlow> {
        match &self.framing {
            Framing::Encrypted(state) => Some(tls::EncryptedFlow {
                per_direction: state.census(),
                // R311y661 — what a decryption pass FOUND, and only where one
                // ran. The unconditional `NoKeysSupplied` this replaced was a
                // false statement about every capture that carried its own key
                // log: the reader had parsed those keys out of the file's
                // Decryption Secrets Block and dropped them on the floor.
                not_decrypted: match state.outcome {
                    Some(outcome) => outcome,
                    None => Some(tls::NotDecrypted::NoKeysSupplied),
                },
                not_decrypted_per_direction: state.outcome_per_direction,
                decrypted_records: state.opened,
                client_direction: state.client_direction.map(|d| {
                    if d == 0 {
                        Direction::A
                    } else {
                        Direction::B
                    }
                }),
                client_random: state.client_random,
                kept_records: state.kept.clone(),
                records_dropped: state.dropped,
                negotiated_suite: state.suite,
            }),
            _ => None,
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
        // R311y709 — THE recovery point for a stream flow. Counted here and not
        // in `feed`, because what is being counted is what reassembly produced:
        // bytes that are held (`Undecided`, `OpeningLost`) were recovered just
        // as much as bytes that dispatch, and a run that is held and later
        // dropped is exactly the difference this measures. Held bytes replay
        // through `feed` rather than through here, so nothing is counted twice.
        self.residue.recovered += bytes.len() as u64;
        if matches!(self.framing, Framing::OpeningLost) {
            self.held[dir_index(direction)].extend_from_slice(bytes);
            self.decide_after_opening_lost(false);
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
                    a: alloc::boxed::Box::new(ws::WsDeframer::new()),
                    b: alloc::boxed::Box::new(ws::WsDeframer::new()),
                },
                // R311y648 (§1.2a) — the ws question is asked FIRST and this one
                // only where it answered `No`, which is not an ordering
                // preference: a `wss://` flow opens with the HTTP upgrade in
                // cleartext and becomes TLS afterwards, so a TLS test in front
                // would take the upgrade's own bytes as the question. Where ws
                // has settled `No`, a ClientHello is the next thing this reader
                // can be sure of.
                ws::UpgradeVerdict::No => {
                    match tls::client_hello_verdict(&self.held[dir_index(direction)]) {
                        tls::TlsVerdict::NeedMore => return,
                        // R311y659 (§1.2a) — and the RANDOM is read here and
                        // nowhere else: this is the one place a ClientHello has
                        // been positively identified, and the bytes it was
                        // identified from are still in hand. Reading it later
                        // would mean finding the opening again in a stream this
                        // flow has since replayed.
                        tls::TlsVerdict::Yes => {
                            let mut state = alloc::boxed::Box::<tls::TlsFlowState>::default();
                            state.client_random =
                                tls::client_hello_random(&self.held[dir_index(direction)]);
                            // R311y661 — and WHICH SIDE sent it, recorded here
                            // for the same reason the random is: this is the
                            // one place the hello has been positively
                            // identified, and the direction it arrived on is
                            // known only here. A decryptor picks between the
                            // client's and the server's traffic secret with it.
                            state.client_direction = Some(dir_index(direction));
                            Framing::Encrypted(state)
                        }
                        // R311y649 (§1.2a) — and where the ClientHello question
                        // says `No`, the CHAIN question gets its turn before
                        // `Stream` becomes the answer. A ClientHello is the
                        // client's first record: a capture that began
                        // mid-session has none, and a SPAN port on the wrong
                        // side of the link gives only the server's half. Both
                        // used to land here as `Stream`, where the reader takes
                        // the record header's first two bytes as a
                        // little-endian length prefix — measured on a
                        // mid-session fixture as a decoded `Close` no peer
                        // sent, carrying a `FlowContext` that claimed a
                        // negotiated session.
                        tls::TlsVerdict::No => match tls::record_chain_verdict(
                            &self.held[dir_index(direction)],
                            tls::TLS_CHAIN_DEPTH,
                        ) {
                            tls::TlsVerdict::Yes => {
                                Framing::Encrypted(alloc::boxed::Box::default())
                            }
                            // A consistent chain shorter than the depth. HELD,
                            // and bounded: reaching the depth ends the hold,
                            // breaking the chain ends it, and `finish` settles
                            // whatever the capture ended in the middle of.
                            tls::TlsVerdict::NeedMore => return,
                            tls::TlsVerdict::No => Framing::Stream,
                        },
                    }
                }
            };
            self.replay_held();
            return;
        }
        self.feed(direction, bytes);
    }

    /// Hand every held direction's bytes to the framing just decided.
    ///
    /// R311y612 — and CUT at the hole when there was one: `opening_gap` says
    /// how much of a direction's held run is the near side, so the far side is
    /// delivered as its own run with the gap announced between them. Handing
    /// both halves on as one run is the swallow R311y610 closed one layer up,
    /// and it would arrive here through the replay if the split were dropped.
    fn replay_held(&mut self) {
        for dir in [Direction::A, Direction::B] {
            let held = core::mem::take(&mut self.held[dir_index(dir)]);
            if held.is_empty() {
                continue;
            }
            match self.opening_gap[dir_index(dir)] {
                None => self.feed(dir, &held),
                Some((before, missing)) => {
                    if before > 0 {
                        self.feed(dir, &held[..before]);
                    }
                    self.note_framing_gap(dir, missing);
                    if before < held.len() {
                        self.feed(dir, &held[before..]);
                    }
                }
            }
        }
    }

    /// R311y612 (§4.1) — decide what a flow whose opening was lost turns out
    /// to be, on the evidence of the bytes AFTER the hole.
    ///
    /// `flush` forces the fallback: a capture that ends while this flow is
    /// still undecided must be reported, not held. Without it the state added
    /// to end one silent hole would open a quieter one.
    fn decide_after_opening_lost(&mut self, flush: bool) {
        let mut evidence = false;
        let mut tls_evidence = false;
        let mut examined = 0usize;
        for dir in [Direction::A, Direction::B] {
            let before = self.opening_gap[dir_index(dir)]
                .map(|(b, _)| b)
                .unwrap_or(0);
            let held = &self.held[dir_index(dir)];
            let post = &held[before.min(held.len())..];
            examined = examined.max(post.len());
            if ws::carries_ws_frames(post, ws::WS_CHAIN_DEPTH) {
                evidence = true;
            }
            // R311y649 (§1.2a) — the same question the far side gets asked
            // about ws, asked about TLS. Weaker BY CONSTRUCTION and the
            // weakness is stated: the far side of a hole usually begins in the
            // MIDDLE of a record, where no chain walks, so this finds a flow
            // only when the hole happened to end on a record boundary — the
            // shape of a dropped segment that carried whole records. When it
            // does not, the `Stream` fallback below is what the flow gets, and
            // that is the pre-R311y649 answer rather than a new silence.
            if matches!(
                tls::record_chain_verdict(post, tls::TLS_CHAIN_DEPTH),
                tls::TlsVerdict::Yes
            ) {
                tls_evidence = true;
            }
        }
        if evidence {
            self.framing = Framing::WebSocket {
                a: alloc::boxed::Box::new(ws::WsDeframer::after_lost_opening(
                    self.opening_gap[0].map(|(b, _)| b).unwrap_or(0),
                )),
                b: alloc::boxed::Box::new(ws::WsDeframer::after_lost_opening(
                    self.opening_gap[1].map(|(b, _)| b).unwrap_or(0),
                )),
            };
            // The deframer starts AT the near side's end and scans, so the
            // near-side bytes are already accounted for and only the far side
            // is pushed. Replaying through `replay_held` would announce a gap
            // to a deframer that was built knowing about it.
            for dir in [Direction::A, Direction::B] {
                let held = core::mem::take(&mut self.held[dir_index(dir)]);
                let before = self.opening_gap[dir_index(dir)]
                    .map(|(b, _)| b)
                    .unwrap_or(0);
                if before < held.len() {
                    self.feed(dir, &held[before..]);
                }
            }
            return;
        }
        // R311y649 — after ws and not before it: a `wss://` flow is BOTH, and
        // its cleartext upgrade is the evidence that names the link.
        if tls_evidence {
            self.framing = Framing::Encrypted(alloc::boxed::Box::default());
            // Through `replay_held`, not the ws path's far-side-only feed: the
            // near side's records were a consistent chain before the hole and
            // are countable, and the gap announced between the two halves is
            // what drops the pending tail so no record is joined across it.
            self.replay_held();
            return;
        }
        if !flush && examined <= WS_CLASSIFY_BUDGET {
            return;
        }
        // Measured, not assumed: `WS_CLASSIFY_BUDGET` bytes of the far side
        // held no chain of `WS_CHAIN_DEPTH` ws frames carrying zenoh. That is
        // what makes the fallback a finding rather than the default it was.
        self.framing = Framing::Stream;
        self.replay_held();
    }

    /// Hand the observer exactly the bytes reassembly newly DELIVERED since
    /// absolute offset `before` — not the segment payload: a retransmission
    /// delivers none, and a held out-of-order segment can deliver a whole chain
    /// at once.
    ///
    /// ⚠ `before` is an ABSOLUTE offset and [`StreamAssembler::stream`] is the
    /// RETAINED tail, so the two are only the same index while nothing has been
    /// trimmed. Rebasing here is what keeps trimming from silently handing the
    /// observer the wrong bytes — the defect this arithmetic invites.
    ///
    /// R311y610 — and the run is cut at every discontinuity the push recorded,
    /// which is why this is one function both link layers call rather than the
    /// four lines each of them used to inline.
    fn deliver_from(&mut self, direction: Direction, before: usize) {
        let splices = match direction {
            Direction::A => self.low_to_high.take_splices(),
            Direction::B => self.high_to_low.take_splices(),
        };
        let base = self.assembler(direction).retained_from();
        debug_assert!(
            before >= base,
            "trimming must not outrun delivery: base {base} > before {before}"
        );
        let delivered: Vec<u8> = self.assembler(direction).stream()[before - base..].to_vec();
        self.advance_spliced(direction, before, &delivered, &splices);
    }

    /// R311y610 — hand the observer bytes that CONTAIN discontinuities, telling
    /// it where each one is instead of letting it read across them.
    ///
    /// `from` is the absolute stream offset `bytes` begins at, and every splice
    /// names the absolute offset of the first byte on its far side, so the
    /// delivered run is cut at each of them. Without the cut this function
    /// would be `advance` and the reader below would frame the far side of a
    /// hole against the near side of it — the §4.1 defect R311y609 measured at
    /// 45-68% of the frames after a hole.
    fn advance_spliced(
        &mut self,
        direction: Direction,
        from: usize,
        bytes: &[u8],
        splices: &[crate::tcp::Splice],
    ) {
        let mut cut = 0usize;
        for splice in splices {
            // A splice recorded by THIS push cannot precede the run it split.
            let at = splice.at_offset.saturating_sub(from).min(bytes.len());
            if at > cut {
                self.advance(direction, &bytes[cut..at]);
            }
            self.note_gap(direction, splice.bytes_missing);
            cut = at;
        }
        self.advance(direction, &bytes[cut..]);
    }

    /// R311y610 — tell whichever framing this flow uses that the bytes it is
    /// about to receive are not the continuation of the ones it has.
    ///
    /// While `Undecided` the verdict is forced from what is held: a hole inside
    /// the opening cannot later complete a `GET / HTTP/1.1`, and
    /// [`ws::UpgradeVerdict::NeedMore`] means precisely "still consistent with
    /// one, and not finished". Resolving it to a stream rather than guessing ws
    /// keeps the decision on evidence — and the gap announced immediately after
    /// is what stops that decision from being read as a confident one.
    fn note_gap(&mut self, direction: Direction, bytes_missing: u64) {
        if matches!(self.framing, Framing::Undecided) {
            // R311y612 (§4.1) — BOTH directions are consulted, not just the one
            // the hole landed in. A hole in the client's `GET ` says nothing
            // about the server's `HTTP/1.1 101`, and a flow that has already
            // shown one of the two literals is settled by evidence; the
            // pre-R311y612 read of one direction threw that away.
            let verdicts = [
                ws::http_upgrade_verdict(&self.held[0]),
                ws::http_upgrade_verdict(&self.held[1]),
            ];
            self.opening_gap[dir_index(direction)] =
                Some((self.held[dir_index(direction)].len(), bytes_missing));
            self.framing = if verdicts.contains(&ws::UpgradeVerdict::Yes) {
                Framing::WebSocket {
                    a: alloc::boxed::Box::new(ws::WsDeframer::new()),
                    b: alloc::boxed::Box::new(ws::WsDeframer::new()),
                }
            } else if verdicts.contains(&ws::UpgradeVerdict::No) {
                // R311y649 (§1.2a) — ws answering `No` no longer means "zenoh
                // stream"; it means the chain question's turn. A hole that
                // lands while THAT question is still `NeedMore` took the very
                // bytes that would have settled it, which is what
                // `OpeningLost` means — and `OpeningLost` already knows to
                // decide on the far side. Forcing `Stream` here is the
                // pre-R311y649 answer, and it hands the far side's records to
                // a reader that takes their headers for length prefixes.
                if self.opening_chain_undecided() {
                    Framing::OpeningLost
                } else {
                    Framing::Stream
                }
            } else {
                // Every direction is still a PREFIX of an opening, so nothing
                // seen so far can settle it and nothing later will: the bytes
                // that would have are the ones the hole took. Decide on the far
                // side instead of guessing.
                Framing::OpeningLost
            };
            if matches!(self.framing, Framing::OpeningLost) {
                return;
            }
            self.replay_held();
            return;
        }
        self.note_framing_gap(direction, bytes_missing);
    }

    /// R311y649 (§1.2a) — was some direction being HELD for record-chain
    /// evidence when the hole arrived?
    ///
    /// Deliberately NOT "does the near side look encrypted": a near side that
    /// answers `Yes` cannot exist here, because `advance` asks the same question
    /// on the same bytes and settles the framing before any hole can be
    /// announced. The reachable state is the UNDECIDED one — a chain that is
    /// consistent and shallower than [`tls::TLS_CHAIN_DEPTH`] — and the bytes
    /// that would have settled it are exactly the ones the hole took.
    ///
    /// Asked on the NEAR side only. Bytes past a hole begin wherever they begin,
    /// so a chain walked across one is a chain this reader invented.
    fn opening_chain_undecided(&self) -> bool {
        [Direction::A, Direction::B].into_iter().any(|dir| {
            let held = &self.held[dir_index(dir)];
            let near = &held[..self.opening_gap[dir_index(dir)]
                .map(|(before, _)| before)
                .unwrap_or(held.len())
                .min(held.len())];
            !near.is_empty()
                && matches!(
                    tls::record_chain_verdict(near, tls::TLS_CHAIN_DEPTH),
                    tls::TlsVerdict::NeedMore
                )
        })
    }

    /// R311y649 (§1.2a) — a flow still `Undecided` when the capture ENDS must be
    /// reported, not held.
    ///
    /// R311y612 wrote this rule for [`Framing::OpeningLost`] and it applies here
    /// verbatim: bytes held for a verdict that never comes are bytes reported as
    /// absent, which is the silent hole in a new place. It became reachable for
    /// more than a truncated `GET ` when [`tls::record_chain_verdict`] started
    /// holding a flow whose record chain is consistent and shallower than
    /// [`tls::TLS_CHAIN_DEPTH`].
    ///
    /// The fallback is `Stream`, and it is a FALLBACK rather than a finding —
    /// stated here rather than hidden: a direction that ended holding exactly
    /// one well-formed record never reached the depth, so its bytes go to the
    /// zenoh reader, which is what this crate does with bytes it cannot name.
    fn settle_undecided(&mut self) {
        if !matches!(self.framing, Framing::Undecided) {
            return;
        }
        self.framing = Framing::Stream;
        self.replay_held();
    }

    /// R311y650 (§1.2a) — the exit EVERY flow takes when no further byte of it
    /// will be read, wherever that happens.
    ///
    /// R311y612 wrote the rule for [`Framing::OpeningLost`] and R311y649 wrote
    /// it for [`Framing::Undecided`], and both wrote it at ONE call site:
    /// [`Dissection::finish`]. A flow has a second way out of the table — the
    /// flow cap evicts the least recently active one — and it left through that
    /// door still holding its bytes, so every counter those bytes would have
    /// moved read zero. That is the same silence from a third direction, and it
    /// is the one a LIVE TAP hits rather than a file reader: a file ends and
    /// calls `finish`, a tap recycles slots forever and never does.
    ///
    /// Stating it as one verb both exits call is the point. Two exits that each
    /// remember to settle is a pair that drifts, which is exactly how the
    /// eviction path came to be missing the rule for eleven rounds.
    fn settle_on_exit(&mut self) {
        if matches!(self.framing, Framing::OpeningLost) {
            self.decide_after_opening_lost(true);
        }
        self.settle_undecided();
    }

    /// Tell an ALREADY-DECIDED framing that its bytes are discontinuous.
    fn note_framing_gap(&mut self, direction: Direction, bytes_missing: u64) {
        match &mut self.framing {
            // A hole while still holding the opening is recorded, not
            // announced: `replay_held` is what cuts the held run at it.
            Framing::Undecided | Framing::OpeningLost => {}
            Framing::Stream => {
                self.session.note_gap(direction, bytes_missing);
            }
            // R311y612 (§4.2) — no longer terminal. The deframer discards its
            // buffered near-side tail and scans for a boundary that
            // `ws::WS_CHAIN_DEPTH` frames confirm, so a ws flow that loses one
            // segment reports that loss and then keeps decoding, instead of
            // reporting every later message on the flow as absent.
            Framing::WebSocket { a, b } => match direction {
                Direction::A => a.note_gap(bytes_missing),
                Direction::B => b.note_gap(bytes_missing),
            },
            // R311y648 — a hole breaks the record CHAIN, so the held tail is
            // dropped rather than joined across it: the bytes after a gap begin
            // wherever they begin, and treating them as the continuation of the
            // record before it would count a record this reader invented.
            // Counting stops for that direction, which is why the census is a
            // FLOOR after a gap and the report says so through the same
            // `gaps_forced` counter every other framing feeds.
            // R311y661 — and the direction's STREAM COORDINATE steps over the
            // hole, which the bare `clear()` did not do. See
            // `TlsFlowState::note_gap`.
            Framing::Encrypted(state) => {
                state.note_gap(dir_index(direction), bytes_missing);
            }
        }
    }

    /// Route already-classified bytes into the framing this flow uses.
    fn feed(&mut self, direction: Direction, bytes: &[u8]) {
        match self.framing {
            // Unreachable by construction: `advance` decides before it feeds.
            Framing::Undecided | Framing::OpeningLost => {}
            Framing::Stream => self.feed_stream(direction, bytes),
            Framing::WebSocket { .. } => self.feed_websocket(direction, bytes),
            // R311y648 — COUNTED and not decoded. Handing ciphertext to the
            // observer is how the flow used to report zero frames and perfect
            // health at the same time.
            Framing::Encrypted(_) => self.feed_encrypted(direction, bytes),
        }
    }

    /// R311y648 (§1.2a) — walk one direction's records without reading them.
    fn feed_encrypted(&mut self, direction: Direction, bytes: &[u8]) {
        let Framing::Encrypted(state) = &mut self.framing else {
            return;
        };
        state.push(dir_index(direction), bytes);
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
        let mut resyncs: Vec<ws::WsResync> = Vec::new();
        while let Some(msg) = deframer.next_message() {
            // R311y612 — drained HERE and not after the loop, so a recovery is
            // attributed to the message decoded right after it. A flow that
            // resynchronises twice in one push would otherwise report the
            // second recovery and lose the first.
            //
            // R311y613 (§4.5) — `while` and not `if`. A single `next_message`
            // now recovers as many times as it has to before it can return a
            // message, so one call can owe more than one record.
            while let Some(resync) = deframer.take_resync() {
                resyncs.push(resync);
            }
            ready.push(msg);
        }
        // A scan that has not confirmed a boundary yet still HAPPENED, and a
        // recovery that lands with no message behind it in this push must not
        // be dropped on the floor.
        while let Some(resync) = deframer.take_resync() {
            resyncs.push(resync);
        }
        for resync in resyncs {
            self.ws_resyncs.push((direction, resync));
        }
        for (offset, payload) in ready {
            // R311y709 — the payload, which is what a decoder sees. The frame
            // headers this deframer consumed are recovered and never fed, and
            // that difference is a fact about ws rather than a defect.
            self.residue.fed += payload.len() as u64;
            // R311y631 (§1.2b) — a ws message delimits a BATCH, not a message.
            // zenoh's ws link reports `is_streamed() == false`, which is why
            // this side calls the datagram entry point at all; the same call
            // now yields every transport message the frame carried.
            let batch = self.session.next_datagram(direction, &payload, offset);
            self.frames.append(batch);
        }
    }

    fn feed_stream(&mut self, direction: Direction, bytes: &[u8]) {
        // R311y709 — reaches a decoder. This is also the entry point decrypted
        // PLAINTEXT arrives at, which is why `unfed` saturates: a TLS flow
        // recovers ciphertext and feeds the smaller thing inside it.
        self.residue.fed += bytes.len() as u64;
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
/// R311y713 (§B2) — how many flow tables a [`Dissection`] keeps: the stream
/// table and the datagram table.
///
/// Named because [`DissectionLimits::max_flows_held`] multiplies by it, and a
/// bare `2` in that expression is exactly the kind of constant that stays `2`
/// after a third table lands.
const FLOW_TABLES: usize = 2;

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
    /// Flows kept IN EACH FLOW TABLE. Beyond it the least recently active is
    /// evicted, which is the one accumulation that cannot be trimmed in place:
    /// a 5-tuple that never returns is a flow that is never freed.
    ///
    /// R311y651 (§4.4) — "each table" and not "both together", stated because
    /// it is a choice. A shared budget would let a chatty multicast group evict
    /// the unicast session a reader is actually watching, making which flow
    /// survives depend on traffic it has nothing to do with. The cost is that
    /// the bound admits up to twice the number, and that is the trade taken.
    ///
    /// R311y713 (§B2) — and the field is NAMED for it now. The trade above was
    /// stated in this doc from the day it was made and the field was still
    /// called `max_flows`, so a caller sizing memory off the name was wrong by
    /// a factor of two and the doc that would have told them was one hop away.
    /// The decision is unchanged; what changed is that the name no longer
    /// contradicts it. [`Self::max_flows_held`] is the number that sizing
    /// wants.
    ///
    /// Until R311y651 this bounded the STREAM table alone. A UDP-only capture —
    /// scouting on a multicast group is exactly one — grew a flow per 5-tuple
    /// forever, on a limit whose whole purpose is that it cannot.
    pub max_flows_per_table: Option<usize>,
    /// R311y606 — half-assembled IP datagrams held at once. Beyond it the
    /// oldest-STARTED is evicted.
    ///
    /// R311y713 (§B5) — "oldest" here does NOT mean what it means three fields
    /// up. [`Self::max_flows_per_table`] evicts the least recently ACTIVE, and
    /// this evicts the one that has been waiting LONGEST, whatever arrived
    /// into it most recently. Both are deliberate and they are opposite: a
    /// quiet flow may still be a session a reader is watching, while a
    /// fragment chain that has been open longest is the one least likely ever
    /// to complete. Two policies under one word is how a reader ends up
    /// reasoning about the wrong one, so the word is spelled out at both.
    ///
    /// Separate from `max_flows_per_table` because a fragment table entry is not a flow:
    /// it is keyed by the datagram's identification, so a single busy flow can
    /// hold many at once and a bound on flows would not touch them.
    pub max_pending_fragments: Option<usize>,
    /// R311y608 — endpoints remembered as having sent a SCOUT. Beyond it the
    /// OLDEST asker goes, and [`DissectionDrops::scout_askers`] says so.
    ///
    /// Its own bound rather than a share of `max_flows_per_table`, because an asker is
    /// not a flow either: one host scouting on a schedule keeps a single slot
    /// for the life of the tap while its flows come and go.
    pub max_scout_askers: Option<usize>,
    /// R311y718 (§1.2a) — recovered QUIC streams framed as zenoh, PER DATAGRAM
    /// FLOW. Beyond it a new stream id is REFUSED, and
    /// [`quic::QuicStreamFeed::streams_refused`] says so.
    ///
    /// Refusal rather than eviction, and the asymmetry with every other bound
    /// here is deliberate: the streams already held carry the zenoh session
    /// state of this connection, so admitting a newcomer by dropping the oldest
    /// would discard the handshake and leave the survivor decoding a stream it
    /// has no session for. A bound that trades a readable half for an
    /// unreadable one is worse than the growth it prevents.
    ///
    /// Its own bound rather than a share of `max_flows_per_table` for the reason
    /// the two above it are: a stream is not a flow, and one QUIC connection can
    /// open many while occupying a single slot in the datagram table.
    pub quic_streams_per_flow: Option<usize>,
    /// R311y722 (§D M3) — frames a declared SERIAL line holds while it waits
    /// for a handshake to name which wire is the initiator's.
    ///
    /// Beyond it the line COMMITS to its positional mapping and decodes,
    /// eagerly from then on. Nothing is discarded: the bound converts a wait
    /// into a DECISION, which is what makes it safe to set — a bound that threw
    /// the held frames away would trade the capture's contents for its memory
    /// budget, and every other bound here trades only recency.
    ///
    /// `None` is unbounded and is right for a FILE, which ends. A live tap on a
    /// line whose handshake it never captures would otherwise hold every frame
    /// for the life of the process.
    pub serial_frames_before_attribution: Option<usize>,
}

impl DissectionLimits {
    /// R311y713 (§B2) — flows a [`Dissection`] may hold AT ONCE, over every
    /// table, which is the number a caller sizing memory needs.
    ///
    /// [`Self::max_flows_per_table`] times the number of flow tables. The
    /// multiplier is not a constant a reader has to trust:
    /// `the_flow_bound_is_the_one_a_caller_can_size_against` fills both tables
    /// past the cap and holds this figure against what the dissection actually
    /// holds, so the day a third table appears the test says so.
    pub fn max_flows_held(&self) -> Option<usize> {
        self.max_flows_per_table.map(|n| n * FLOW_TABLES)
    }

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
            max_flows_per_table: Some(1_024),
            // 256 concurrent half-assembled datagrams is far past what a real
            // link produces at once — fragmentation is bursty and short-lived —
            // and it bounds the table at well under the ceiling times the cap.
            max_pending_fragments: Some(256),
            // One slot per scouting host. 1 024 is the same order as
            // `max_flows_per_table` and each entry is an `Endpoint`, so the whole set is
            // smaller than a single flow's frame list.
            max_scout_askers: Some(1_024),
            // zenoh opens ONE bidirectional stream per QUIC link
            // (`zenoh-link-quic/src/unicast.rs:330`), so 16 is an order above
            // what the traffic this tool watches produces, and each entry costs
            // a `PassiveSession` plus its frame list — the same order as a flow.
            // Set well above the expected one rather than at it, because the
            // bound REFUSES: sizing it tight would make a peer that opens a
            // second stream lose it, and the point of the ceiling is the
            // runaway case, not the second case.
            quic_streams_per_flow: Some(16),
            // A handshake is the FIRST thing a serial link does, so a line that
            // has read 256 frames without one is a tap that started mid-session
            // and will never see it. Far past the two or three frames a
            // captured handshake takes, and far short of a leak.
            serial_frames_before_attribution: Some(256),
        }
    }
}

/// R311y723 (§1.1f) — THE COMPILE-TIME CENSUS OF MESSAGE LISTS.
///
/// # What this is, and why it is a test rather than the enumeration itself
///
/// [`Dissection::message_lists`] is the door every census plane walks, and
/// R311y722 gated it with a lint that reads field TYPES. A lint catches a list
/// nobody wired; it cannot catch a list added to a struct whose enumeration is
/// then not updated, because at that moment the type is right and only the
/// wiring is missing.
///
/// The destructures below are EXHAUSTIVE — no `..` anywhere — which is the
/// mechanism `the_live_tap_preset_bounds_every_axis_it_has` already uses in
/// this file for the same class of problem: a new field does not make these
/// wrong, it makes them NOT COMPILE, and the author adding the field is the one
/// who decides whether it holds decoded messages.
///
/// Kept out of `message_lists` itself deliberately. Putting a 25-field pattern
/// in the production path would make the door unreadable, and the forcing is
/// identical either way — `cargo test` does not build.
#[cfg(test)]
mod message_list_census {
    use super::*;

    /// Every field of [`Dissection`], classified.
    ///
    /// The three bound names are the lists; everything else is `_` and that is
    /// a CLAIM the reader can check against the field's own doc.
    #[test]
    fn every_dissection_field_is_classified_as_a_message_list_or_not() {
        let d = Dissection::new();
        let Dissection {
            // ── holds decoded messages ──
            flows,
            datagram_flows,
            serial_frames,
            // ── does not ──
            skipped: _,
            skip_census: _,
            limits: _,
            drops: _,
            declared_quic_ports: _,
            declared_serial_linktypes: _,
            serial: _,
            // Recovered serial FRAMES awaiting a direction, not decoded
            // messages: they are still COBS payloads at this point.
            serial_pending: _,
            // One entry per message in `serial_frames`, holding the serial
            // frame it came out of -- an origin, not a message.
            serial_origins: _,
            serial_session: _,
            checksums: _,
            carry: _,
            fragments: _,
            #[cfg(feature = "reassembly")]
                expired_chains: _,
            capture_reported_drops: _,
            scouts: _,
            gap_patience: _,
            capture_origin_ms: _,
            abandoned_chains: _,
            // The census OF discarded messages, which is the opposite of a list
            // a plane should walk: these are gone.
            dropped_frames: _,
            chain_bytes_lost: _,
            decryption_secrets: _,
        } = &d;

        // AND THE THREE ARE THE ENUMERATION. Without this the pattern above
        // would only prove that someone typed the names, not that the door
        // opens onto them.
        let enumerated: usize = d.message_lists().map(|(_, frames)| frames.len()).sum();
        let named: usize = flows.iter().map(|f| f.frames.len()).sum::<usize>()
            + datagram_flows
                .iter()
                .map(|f| f.frame_lists().map(<[_]>::len).sum::<usize>())
                .sum::<usize>()
            + serial_frames.len();
        assert_eq!(
            enumerated, named,
            "the lists named in the pattern above and the lists the planes walk \
             must be the same set"
        );
    }

    /// Every field of [`FlowDissection`], classified.
    #[test]
    fn every_stream_flow_field_is_classified() {
        let FlowDissection {
            frames: _,
            flow: _,
            low_to_high: _,
            high_to_low: _,
            session: _,
            last_activity: _,
            framing: _,
            held: _,
            vsock_seq: _,
            opening_gap: _,
            ws_resyncs: _,
            residue: _,
            chain_loss: _,
            last_seen_ms: _,
        } = FlowDissection::new(FlowKey::serial_line(), None, None);
    }

    /// Every field of [`DatagramDissection`], classified.
    ///
    /// Three of these are lists, and `frame_lists` is what must name all three.
    #[test]
    fn every_datagram_flow_field_is_classified() {
        let DatagramDissection {
            frames: _,
            quic_datagrams: _,
            quic_streams: _,
            flow: _,
            session: _,
            // Scouting messages are in the Scout/Hello namespace, not the
            // transport one, so they are not `PassiveFrame` and cannot be in
            // an enumeration typed on it. `node::nodes` walks them separately.
            scouting: _,
            last_activity: _,
            quic: _,
            residue: _,
            chain_loss: _,
            last_seen_ms: _,
        } = DatagramDissection::new(FlowKey::serial_line(), None);
    }

    /// Every field of [`QuicStreamDissection`], classified.
    #[test]
    fn every_quic_stream_field_is_classified() {
        let QuicStreamDissection {
            frames: _,
            id: _,
            session: _,
            fed: _,
        } = QuicStreamDissection {
            id: 0,
            session: new_session(None),
            frames: messages::MessageList::new(),
            fed: [0, 0],
        };
    }
}

#[cfg(test)]
mod live_tap_tests {
    use super::*;

    /// R311y709 (G2) — THE LIVE-TAP PRESET BOUNDS EVERY AXIS, AND A NEW AXIS
    /// BREAKS THIS TEST AT COMPILE TIME.
    ///
    /// MEASURED: `DissectionLimits::for_live_tap` had ZERO references anywhere
    /// in the workspace -- no caller, no test -- while two doc comments send a
    /// deployment to it as "a starting point". So nothing established that it
    /// still is one.
    ///
    /// A preset of numbers cannot lie about behaviour, but it can rot in one
    /// specific way, and that way is silent: add a field to `DissectionLimits`
    /// and this preset leaves it `None`, so the "starting point for a live tap"
    /// quietly stops bounding an axis a long-running process now grows on. That
    /// is the [`DissectionDrops`] rule turned inward -- a bound that is not
    /// there is worse than one that is, because nothing reports its absence.
    ///
    /// The destructuring below is EXHAUSTIVE -- no `..` -- which is the whole
    /// mechanism: a new field does not make this test fail, it makes it not
    /// compile, and the author adding the field is the one who decides what the
    /// live tap should bound it at.
    #[test]
    fn the_live_tap_preset_bounds_every_axis_it_has() {
        let DissectionLimits {
            reassembly_window_ms,
            frames_per_flow,
            stream_bytes_per_direction,
            skipped_packets,
            max_flows_per_table,
            max_pending_fragments,
            max_scout_askers,
            quic_streams_per_flow,
            serial_frames_before_attribution,
        } = DissectionLimits::for_live_tap();

        for (name, bound) in [
            (
                "reassembly_window_ms",
                reassembly_window_ms.map(|v| v as usize),
            ),
            ("frames_per_flow", frames_per_flow),
            ("stream_bytes_per_direction", stream_bytes_per_direction),
            ("skipped_packets", skipped_packets),
            ("max_flows_per_table", max_flows_per_table),
            ("max_pending_fragments", max_pending_fragments),
            ("max_scout_askers", max_scout_askers),
            ("quic_streams_per_flow", quic_streams_per_flow),
            (
                "serial_frames_before_attribution",
                serial_frames_before_attribution,
            ),
        ] {
            let Some(v) = bound else {
                panic!("{name} is unbounded in the live-tap preset");
            };
            assert!(v > 0, "{name} is bounded at zero, which taps nothing");
        }
    }

    /// R311y709 (G2) — AND IT REACHES A DISSECTION.
    ///
    /// The other half of "zero references": a preset nobody installs is not
    /// known to be installable. This is the cheapest statement that it is, and
    /// it reads the limits back rather than trusting the constructor -- a
    /// `with_limits` that dropped its argument would pass a test that only
    /// checked the call did not panic.
    #[test]
    fn the_live_tap_preset_installs_and_reads_back() {
        let d = Dissection::with_limits(DissectionLimits::for_live_tap());
        assert_eq!(
            d.limits(),
            DissectionLimits::for_live_tap(),
            "the dissection must carry the limits it was given"
        );
    }

    /// R311y746 (debt-carry-N11) — AND IT REPORTS THE BOUND IT BIT.
    ///
    /// The two tests above establish that the preset bounds every axis and that
    /// a dissection carries it. Neither runs a capture THROUGH it, and that
    /// third gap is where a real divergence lived undetected: `health()` copied
    /// the raw drop counters while `drops()` composed `flows` from the
    /// retirement count (R311y713 §B1), so the single preset whose caps
    /// actually bite had no test that read a bite back through either door.
    ///
    /// This is the `DissectionDrops` rule applied to the preset itself: a bound
    /// that bites and reports nothing is worse than no bound, because nothing
    /// says the numbers beside it are a floor. Asserted through BOTH readers,
    /// since one of them is the one that was wrong.
    #[test]
    fn the_live_tap_preset_reports_the_bound_it_bit() {
        let limits = DissectionLimits::for_live_tap();
        let cap = limits
            .max_flows_per_table
            .expect("the preset bounds the flow table");
        let mut d = Dissection::with_limits(limits);
        // One length-prefixed KeepAlive: the smallest complete framed message,
        // so each flow carries a decoded message rather than bare bytes.
        let msg = [1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        // One 5-tuple past the cap. The SOURCE PORT is what distinguishes them
        // and it sits at the start of the TCP header: 14 bytes of Ethernet, 20
        // of IPv4.
        for i in 0..=cap {
            let mut p = crate::datagram_tests::tcp_packet(1000, &msg);
            let port = 20_000u16 + i as u16;
            p[34..36].copy_from_slice(&port.to_be_bytes());
            d.push_packet(crate::link::LINKTYPE_ETHERNET, i, &p);
        }
        assert_eq!(
            d.flows().len(),
            cap,
            "the preset's flow cap must have bitten, or this proves nothing"
        );
        assert_eq!(d.drops().flows, 1, "and the bite must be counted");
        assert_eq!(
            d.health().drops,
            d.drops(),
            "both readers of the ledger report the same bite"
        );
    }
}

/// R311y709 (§1.2a) — BYTES RECOVERED AGAINST BYTES HANDED TO A DECODER.
///
/// # The question this answers
///
/// This reader recovers bytes — out of TCP reassembly, out of a datagram
/// payload — and then hands some of them to something that reads them. The
/// difference has never been measured, and R311y705 showed why it matters: the
/// QUIC pass recovered application bytes, no reader in this build took zenoh out
/// of them, and the capture reported itself COMPLETE with a test asserting it.
/// That was found by reading the code. Nothing counted it.
///
/// So this counts it, everywhere, and the register's open question is the whole
/// point: **is the difference non-zero anywhere other than QUIC?**
///
/// # What it deliberately does NOT do
///
/// It moves NO verdict. [`crate::report::CaptureReport::is_complete`] does not
/// read it and a test pins that it does not. The reason is the R311y705 lesson
/// read the other way round: a number wired into a verdict on the round it is
/// first measured is a number nobody has ever seen the range of, and the shapes
/// below are not yet known to be the only ones. Measure first; a verdict is its
/// own round, with its own evidence.
///
/// # The differences that are EXPECTED, so a reader can tell them from news
///
/// - A **TLS** flow recovers ciphertext and feeds plaintext, so a perfectly
///   decrypted flow still shows the record layer's overhead — 5 header bytes, a
///   16-byte tag and the inner content type, per record.
/// - A **WebSocket** flow feeds message payloads, so the frame headers show.
/// - A flow whose opening was LOST and turned out to be ws feeds only the far
///   side of the hole (`FlowDissection::decide_after_opening_lost` builds the
///   deframer already knowing the near side), so the near side shows.
/// - A **QUIC** flow feeds NOTHING, by construction, which is the R311y705
///   finding restated as a number rather than as prose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteResidue {
    /// Bytes this reader recovered and handed to this flow.
    pub recovered: u64,
    /// Of those, the bytes that reached something that reads them.
    pub fed: u64,
}

impl ByteResidue {
    /// Recovered and never handed on.
    ///
    /// Saturating because `fed` can exceed nothing here today and the assertion
    /// that it never will is one this type must not make: plaintext is fed on a
    /// flow whose recovered bytes were ciphertext, and an expansion — a
    /// decompressing layer, say — would be a legitimate future shape rather
    /// than a reason to panic in a reporting path.
    pub fn unfed(&self) -> u64 {
        self.recovered.saturating_sub(self.fed)
    }

    /// Fold another flow's counts in.
    pub fn absorb(&mut self, other: Self) {
        self.recovered += other.recovered;
        self.fed += other.fed;
    }
}

// R311y746 (debt-carry-N11) — `DroppedFrameCensus` moved to `messages`, beside
// the `Discarded` receipt it is now the sole consumer of. Re-exported here so
// `wz_capture::DroppedFrameCensus` keeps resolving; see that module for why the
// two types share one privacy boundary.
pub use messages::DroppedFrameCensus;

/// R311y713 (§B4) — pick the flow to evict: the LEAST RECENTLY ACTIVE, by the
/// capture's own clock where every candidate has one.
///
/// `last_activity` is a PACKET INDEX, which is file order and not time order.
/// The two agree on a single-interface capture and part company on a pcapng
/// written by `dumpcap -i any`, where each interface's packets are contiguous
/// in the file and interleaved in time: the flow whose last packet came LATER
/// on the wire can sit EARLIER in the file, so the index picks the wrong flow
/// to throw away. Measured on exactly that shape before this function existed
/// (`an_eviction_follows_the_captures_clock_when_it_has_one`).
///
/// The clock is used only when EVERY candidate has one. A capture with no
/// timestamps at all — which is why the index exists — keeps the index, and a
/// half-stamped table does too rather than ordering a `None` against a `Some`:
/// there is no honest answer to "is a flow with no clock older than one with",
/// and inventing one would decide an eviction on a coin toss dressed as a
/// rule.
fn least_recently_active<F>(
    rows: &[F],
    clock: impl Fn(&F) -> Option<u64>,
    index: impl Fn(&F) -> usize,
) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    if rows.iter().all(|f| clock(f).is_some()) {
        return rows
            .iter()
            .enumerate()
            .min_by_key(|(i, f)| (clock(f).unwrap_or(0), index(f), *i))
            .map(|(i, _)| i);
    }
    rows.iter()
        .enumerate()
        .min_by_key(|(_, f)| index(f))
        .map(|(i, _)| i)
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
    /// Flows evicted to stay inside `max_flows_per_table`.
    pub flows: usize,
    /// R311y651 (§4.4) — scouting datagrams discarded to stay inside
    /// `frames_per_flow`.
    ///
    /// Its own field rather than folded into `frames`, for the reason
    /// [`DatagramDissection::scouting`] is its own list: a scouting message is
    /// not a transport frame, and a reader diagnosing a discovery problem needs
    /// to know which of the two lists the bound bit.
    pub scouting: usize,
    /// R311y608 — scouting askers forgotten to stay inside
    /// `max_scout_askers`.
    ///
    /// The most consequential of the five, per lost entry: forgetting an asker
    /// does not lose a record, it changes how a LATER message is READ. The next
    /// HELLO answering that endpoint has no evidence of an exchange behind it
    /// and decodes as an `Open` — the exact misread R311y608 closed. A bound
    /// that bit silently would look like the bug coming back.
    pub scout_askers: usize,
}

impl DissectionDrops {
    /// `true` when anything at all was given up.
    pub fn any(&self) -> bool {
        self.frames > 0
            || self.stream_bytes > 0
            || self.skipped > 0
            || self.flows > 0
            || self.scouting > 0
            || self.scout_askers > 0
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
    /// R311y609 — carried here for the same reason the three above are: a
    /// flow the cap EVICTS must not take its losses with it, or a live tap
    /// reports a healthier capture the longer it runs.
    gaps_forced: usize,
    bytes_missing: u64,
}

impl StreamTally {
    fn add_assembler(&mut self, a: &StreamAssembler) {
        self.retransmits += a.retransmits();
        self.out_of_order += a.out_of_order();
        self.partial_overlaps += a.partial_overlaps();
        self.gaps_forced += a.gaps_forced();
        self.bytes_missing += a.bytes_missing();
    }
}

/// R311y609 — what the FRAMING lost, at both of the layers that can lose it.
///
/// Three independent measurements of "missing", and a reader that conflates
/// them cannot tell which layer to blame:
///
/// - `gaps_forced` / `gap_bytes_missing` — the TCP SEQUENCE SPACE says these
///   bytes were sent and the capture does not contain them. Proof, not
///   inference: the sender numbered them.
/// - `desyncs` / `recoveries` / `resync_skipped_bytes` — bytes THIS READER
///   could not frame. A hole leaves the observer mid-frame, and what it skips
///   getting back in step is its own loss, not the wire's.
/// - `sn_*` — messages the sender NUMBERED and nobody saw
///   ([`wz_session_core::passive::SnAccounting`]). The wire's own accounting,
///   and the only one of the three that survives a capture with no holes at
///   all — a peer whose frames are lost upstream shows here and nowhere else.
///
/// Beside [`Dissection::capture_reported_drops`] — the capture tool's own
/// admission — that makes four answers to "what is missing", each from a
/// different witness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FramingHealth {
    /// Gaps the assemblers gave up on, over every flow and both directions.
    pub gaps_forced: usize,
    /// Sequence-space bytes those gaps skipped.
    pub gap_bytes_missing: u64,
    /// Times a direction lost the zenoh framing.
    pub desyncs: u64,
    /// Times it found the framing again.
    pub recoveries: u64,
    /// Bytes skipped getting back in step.
    pub resync_skipped_bytes: u64,
    /// Data frames observed, the denominator for everything below.
    pub sn_frames: u64,
    /// Frames the sender numbered and this reader never saw.
    pub sn_missing: u64,
    /// How many gaps that total is spread across.
    pub sn_gaps: u64,
    /// Repeated sequence numbers.
    pub sn_duplicates: u64,
    /// Sequence numbers behind the window: reorder or a stale datagram, NOT
    /// loss.
    pub sn_out_of_window: u64,
    /// Frames no ring resolution was observed for, so no verdict was possible.
    /// Without it `sn_missing = 0` is unreadable.
    pub sn_without_resolution: u64,
    /// R311y611 (§1.4b) — messages decoded whose header set a flag bit its own
    /// MID does not define.
    ///
    /// A FIFTH witness, and to a different question than the four above: those
    /// count what is MISSING, this counts what arrived and should not have.
    /// Non-zero says the peer's wire-spec vintage is not this reader's, which
    /// is the one thing a differential oracle must never swallow. Always zero
    /// on a stream link, whose credible-header gate refuses the byte and
    /// reports the refusal as a desynchronisation instead.
    pub reserved_headers: u64,
    /// R311y630 (§14.1) — messages decoded that carry a mandatory extension
    /// their message's extension space does not define.
    ///
    /// A SIXTH witness, and to the same question as `reserved_headers` beside
    /// it rather than to the four above: what ARRIVED and should not have. Both
    /// upstream implementations refuse such a message whole
    /// (`zenoh-codec-1.5.0/src/common/extension.rs:33-36`, pico's
    /// `_z_msg_ext_unknown_error`), so a non-zero value says the capture holds
    /// traffic no conforming peer would have acted on. The analyzer's job is to
    /// SAY that, which is the thing neither implementation's own logs do — they
    /// drop the message and close the link.
    ///
    /// Reachable on BOTH link kinds, unlike `reserved_headers`: the transport
    /// header's credible-header gate has nothing to say about the extension
    /// chain that follows it.
    ///
    /// Deliberately NOT part of [`crate::report::CaptureReport::is_complete`],
    /// for the reason `reserved_headers` is not: it is a fact about the SENDER,
    /// not a shortfall in this reader's rows.
    pub undefined_mandatory_exts: u64,
    /// R311y631 (§1.2b) — bytes inside a framing unit that no decoded message
    /// accounts for.
    ///
    /// A SEVENTH witness, and back on the side of the four that count what is
    /// MISSING. A framing unit holds a batch, and the walk over it stops at the
    /// first message it cannot measure — a decode failure, or a MID whose
    /// length this build cannot skip. What is left is unreadable rather than
    /// merely unread, and this is the number that says how much.
    ///
    /// Non-zero is the ordinary reading for a capture that started mid-batch or
    /// carries a foreign dialect; zero says every byte of every unit was
    /// attributed to a message that decoded. Before R311y631 there was no
    /// number here at all and the tail of a batch was silent: not a skipped
    /// packet, because the packet was read, and not a desynchronisation,
    /// because the framing was never in question.
    ///
    /// Reachable on BOTH link kinds — every ingestion path walks its unit
    /// through the same [`wz_session_core::passive::PassiveSession`] entry.
    pub unaccounted_batch_bytes: u64,
    /// R311y612 (§4.2) — times a WebSocket direction lost its RFC6455 frame
    /// boundary.
    ///
    /// Its OWN counter and not folded into [`Self::desyncs`], because the two
    /// are losses of different framings and a reader acting on them acts
    /// differently: a zenoh-framing desync is inside a stream this reader still
    /// has, while a ws-framing one means the message boundary itself is gone
    /// and every zenoh message in the lost run is unrecoverable rather than
    /// merely mis-bounded.
    pub ws_desyncs: u64,
    /// R311y612 — times a WebSocket direction found a boundary again.
    pub ws_recoveries: u64,
    /// R311y612 — bytes stepped over getting back in step, ws framing.
    pub ws_resync_skipped_bytes: u64,
}

/// R311y612 — fold one flow's ws framing accounting into the total.
fn add_ws(h: &mut FramingHealth, a: ws::WsResyncAccounting) {
    h.ws_desyncs += a.desyncs;
    h.ws_recoveries += a.recoveries;
    h.ws_resync_skipped_bytes += a.skipped_bytes;
}

/// R311y609 — fold one direction's sequence-number accounting into the total.
fn add_sn(h: &mut FramingHealth, a: wz_session_core::passive::SnAccounting) {
    h.sn_frames += a.frames;
    h.sn_missing += a.missing;
    h.sn_gaps += a.gaps;
    h.sn_duplicates += a.duplicates;
    h.sn_out_of_window += a.out_of_window;
    h.sn_without_resolution += a.without_resolution;
}

/// A whole capture, dissected: every TCP connection in it, read as a zenoh
/// session.
#[derive(Debug)]
pub struct Dissection {
    /// R311y713 (§B1) — a [`exit::FlowTable`] rather than a `Vec`, so a flow
    /// can only leave it through the accounted exit. See [`exit`].
    flows: exit::FlowTable<FlowDissection>,
    datagram_flows: exit::FlowTable<DatagramDissection>,
    skipped: Vec<SkippedPacket>,
    /// R311y643 (§1.1e) — the by-reason census, counted at the door rather than
    /// folded from `skipped` above, which is capped.
    skip_census: SkipCensus,
    /// R311y594b — what this dissection may accumulate.
    limits: DissectionLimits,
    /// What the limits have cost so far.
    drops: DissectionDrops,
    /// R311y670 (§1.2a) — UDP ports the CALLER declares to be QUIC.
    ///
    /// The discriminator that does not exist in the bytes, supplied by whoever
    /// has it — exactly the role an external key log plays for TLS. MEASURED, and
    /// the measurement is why this field exists rather than a cleverer rule: a
    /// lone QUIC 1-RTT packet whose first byte is `0x46` decodes as a COMPLETE
    /// zenoh Fragment with ZERO unaccounted bytes, and the capture reports
    /// itself `complete`. No residue signal catches it, because `Fragment`
    /// consumes to the end of the datagram by construction. A mid-connection
    /// QUIC capture is genuinely indistinguishable from zenoh at the byte level,
    /// so the only honest ways to settle it are a long header (which such a
    /// capture lacks) or a caller who knows.
    declared_quic_ports: alloc::vec::Vec<u16>,
    /// R311y720 (§D M3) — link types the CALLER declared as carrying raw zenoh
    /// serial bytes. See [`serial`] for why nothing here reads a pseudo-header.
    declared_serial_linktypes: alloc::vec::Vec<u32>,
    /// The tapped serial line, once a declared packet has arrived. `None` on
    /// every capture that declared none, which is nearly all of them.
    serial: Option<alloc::boxed::Box<serial::SerialLine>>,
    /// Frames recovered off that line and not yet decoded — see
    /// `finish_serial` for why the decode waits.
    serial_pending: alloc::vec::Vec<serial::SerialFrame>,
    /// Messages decoded out of that line, in capture order.
    ///
    /// R311y721 — a CONTIGUOUS list, with [`Self::serial_origins`] beside it
    /// holding the serial frame each came out of, one entry per message. Two
    /// lists rather than a list of pairs because the census planes take
    /// `&[PassiveFrame]`, and a plane that had to be handed a pair would be a
    /// plane taught about serial -- which is exactly the coupling
    /// [`Self::message_lists`] exists to remove.
    serial_frames: messages::MessageList,
    /// The serial frame each of [`Self::serial_frames`] was decoded from, at
    /// the same index. One serial frame can yield several messages, so this is
    /// per MESSAGE and not per frame.
    serial_origins: alloc::vec::Vec<serial::SerialFrame>,
    /// The zenoh session over that line. One, because a serial link is point
    /// to point: the two wires are its two directions, not two sessions.
    serial_session: PassiveSession,
    /// R311y605 (F5) — checksum verdicts, tallied as packets arrive. They must
    /// be counted here and not derived later: a `Checksums` rides on the
    /// `Segment` / `Datagram`, which is consumed by the assembler and gone.
    checksums: [usize; 6],
    /// R311y713 (§B1) — everything the flows that have LEFT are still owed.
    ///
    /// One value where R311y605 / R311y610 / R311y650 / R311y656 / R311y666
    /// each added a field, and the consolidation is the point rather than
    /// tidiness: its counters are private to [`exit`], so no code here can add
    /// to them except by retiring a whole flow. Six rounds added a carry to
    /// this struct one counter at a time, each after finding the previous exit
    /// site had missed it.
    carry: exit::ExitCarry,
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
    /// R311y607 — packets the CAPTURE TOOL reported dropping, summed over every
    /// interface. `None` when the file stated nothing.
    ///
    /// Distinct from every other counter on this struct, all of which are what
    /// THIS reader did. See [`Self::capture_reported_drops`].
    capture_reported_drops: Option<u64>,
    /// R311y608 — which endpoints have been observed SCOUTING, so the unicast
    /// HELLOs answering them are read as answers and not as `Open`s.
    ///
    /// Dissection-wide and not per-flow, because the exchange spans two flows:
    /// a SCOUT is keyed `(asker, group)` and its answer `(asker, responder)`.
    scouts: ScoutingCorrelation,
    /// R311y609 — how long a flow's assembler waits on a gap before stepping
    /// over it ([`crate::tcp::DEFAULT_GAP_PATIENCE`]). `None` waits forever,
    /// which is the pre-R311y609 behaviour.
    ///
    /// NOT a [`DissectionLimits`] field, and the reason is that type's own
    /// contract: every limit there is `None` by default because a file ends
    /// and keeping all of it is bounded. This is the opposite shape — the
    /// default must be ENABLED, since a capture with a hole is not a policy
    /// choice a caller opts into.
    gap_patience: Option<usize>,
    /// R311y638 (§1.1r) — the earliest capture instant this dissection was
    /// shown, over every packet whatever it decoded to.
    ///
    /// The MINIMUM rather than the first one handed in: a pcapng holding two
    /// interfaces can present packets out of order, and a "start" that a
    /// later-arriving earlier packet could move would make one capture answer
    /// `elapsed` two ways depending on read order.
    ///
    /// Over every PACKET and not over every decoded record, because the
    /// capture's timeline began when the tool started writing — a file whose
    /// first 200 packets are someone else's traffic did not start at record
    /// one.
    capture_origin_ms: Option<u64>,
    /// R311y655 (§1.1f) — chains still OPEN when the caller said the capture
    /// had ended, abandoned by [`Self::finish`].
    ///
    /// A separate number from `expired_chains` and not a share of it, on the
    /// rule `DissectionDrops` keeps its five fields apart: the two have the same
    /// consequence and different CAUSES, and a reader acts on them differently.
    /// A chain that missed the reassembly deadline is a bound this reader can be
    /// asked to widen; a chain still open when the file ran out is nothing
    /// anyone can widen, and telling a reader to raise a window would be advice
    /// about the wrong thing.
    ///
    /// UNCONDITIONAL where `expired_chains` is `reassembly`-gated, because the
    /// verb it counts is: a build that reassembles nothing abandons nothing and
    /// answers `0`.
    abandoned_chains: usize,
    /// R311y713 (§B10) — what the frames the bounds discarded had said.
    dropped_frames: DroppedFrameCensus,
    /// R311y713 (§B7) — bytes that had already arrived into chains this reader
    /// gave up on, over every cause and every flow.
    ///
    /// The number three rounds recorded as having no witness at all. Counted
    /// where the fragments still exist — the sweep — because the staging is
    /// handed back to the arena the instant after, so nothing downstream can
    /// derive it. `expired_chains` says four messages are missing; this says
    /// whether that was four fragments or four megabytes, and only the second
    /// is a capture worth taking again.
    chain_bytes_lost: u64,
    /// R311y656 (§4.4) — chains still open on a flow the FLOW CAP evicted.
    ///
    /// The third cause and the third number, on the rule that separated the
    /// first two: what a reader DOES about it differs. A chain past its deadline
    /// asks for a wider window, a chain still open when the file ended asks for
    /// nothing, and this one asks for a larger `max_flows_per_table` — advice about the
    /// wrong knob is worse than none, which is why they are not one field.
    /// R311y713 — now carried by [`exit::ExitCarry::chains`] and read through
    /// [`Self::evicted_chains`]; the distinction above is unchanged.
    /// R311y661 (§1.2a) — the Decryption Secrets Blocks the capture FILE
    /// carried, kept so a caller can build an opener out of the capture's own
    /// key material.
    ///
    /// Empty for a live tap, for a classic pcap (the format has no such block),
    /// and for a pcapng that simply carried none.
    ///
    /// ## Why this had to be carried rather than looked up again
    ///
    /// `pcapng::parse` has read these blocks since R311y658 and `from_pcapng`
    /// threw them away — it copied the packets into the dissection and dropped
    /// everything else the file said. So the keys were in the file, were parsed,
    /// and were unreachable from the object the report is made of; the report
    /// then said `no_keys_supplied` about exactly that file. A consumer could
    /// only have fixed it by parsing the file a second time itself, which is a
    /// second reader of the same bytes and the drift this crate keeps closing.
    decryption_secrets: Vec<pcapng::DecryptionSecrets>,
}

/// Hand-written for ONE field: `gap_patience` defaults to
/// [`crate::tcp::DEFAULT_GAP_PATIENCE`] rather than to `None`, and a derive
/// would have shipped the waits-forever arm as the default.
impl Default for Dissection {
    fn default() -> Self {
        Self {
            flows: exit::FlowTable::default(),
            datagram_flows: exit::FlowTable::default(),
            skipped: Vec::new(),
            skip_census: SkipCensus::default(),
            declared_quic_ports: Vec::new(),
            declared_serial_linktypes: Vec::new(),
            serial: None,
            serial_pending: Vec::new(),
            serial_frames: messages::MessageList::new(),
            serial_origins: Vec::new(),
            serial_session: new_session(DissectionLimits::default().reassembly_window_ms),
            limits: DissectionLimits::default(),
            drops: DissectionDrops::default(),
            checksums: [0; 6],
            carry: exit::ExitCarry::default(),
            fragments: frag::FragmentTable::default(),
            #[cfg(feature = "reassembly")]
            expired_chains: 0,
            capture_reported_drops: None,
            scouts: ScoutingCorrelation::default(),
            gap_patience: Some(crate::tcp::DEFAULT_GAP_PATIENCE),
            capture_origin_ms: None,
            abandoned_chains: 0,
            dropped_frames: DroppedFrameCensus::default(),
            chain_bytes_lost: 0,
            decryption_secrets: Vec::new(),
        }
    }
}

impl Dissection {
    /// An empty dissection whose chains never expire.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y609 — how long each flow's assembler waits on a gap before
    /// stepping over it. Applies to flows created AFTER the call.
    ///
    /// `None` restores the pre-R311y609 behaviour: a capture that lost a
    /// segment holds every later segment of that direction forever, and
    /// nothing downstream ever sees them.
    pub fn set_gap_patience(&mut self, patience: Option<usize>) {
        self.gap_patience = patience;
    }

    /// R311y609 — what the FRAMING lost, at both layers. See
    /// [`FramingHealth`] for why the three groups are not one number.
    ///
    /// Evicted flows are INCLUDED for the assembler half (via the same tally
    /// [`Self::health`] uses), so the figure does not improve as a live tap
    /// recycles flows. The session half — resynchronisation and sequence
    /// numbers — goes with the evicted flow, and that is stated rather than
    /// silently rolled in: those counters live inside `PassiveSession`, which
    /// the eviction drops whole.
    pub fn framing_health(&self) -> FramingHealth {
        let mut streams = self.carry.streams();
        // R311y610 (§4.4) — the session half of what eviction took with it. Its
        // gap fields are always zero and are OVERWRITTEN from `streams` below,
        // which is why one type can carry both halves without double-counting.
        let mut h = self.carry.sessions();
        for flow in &self.flows {
            streams.add_assembler(&flow.low_to_high);
            streams.add_assembler(&flow.high_to_low);
            add_ws(&mut h, flow.ws_accounting());
            for dir in [Direction::A, Direction::B] {
                let r = flow.session.resync_accounting(dir);
                h.desyncs += r.desyncs;
                h.recoveries += r.recoveries;
                h.resync_skipped_bytes += r.skipped_bytes;
                h.reserved_headers += flow.session.reserved_headers(dir);
                h.undefined_mandatory_exts += flow.session.undefined_mandatory_exts(dir);
                h.unaccounted_batch_bytes += flow.session.unaccounted_batch_bytes(dir);
                add_sn(&mut h, flow.session.sn_accounting(dir));
            }
        }
        // A datagram flow has no framing to lose, and every sequence number on
        // it still counts: multicast loss is exactly what this measures.
        for flow in &self.datagram_flows {
            for dir in [Direction::A, Direction::B] {
                h.reserved_headers += flow.session.reserved_headers(dir);
                h.undefined_mandatory_exts += flow.session.undefined_mandatory_exts(dir);
                h.unaccounted_batch_bytes += flow.session.unaccounted_batch_bytes(dir);
                add_sn(&mut h, flow.session.sn_accounting(dir));
            }
        }
        h.gaps_forced = streams.gaps_forced;
        h.gap_bytes_missing = streams.bytes_missing;
        h
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
        // R311y713 (§B1) — `flows` is composed from the retirement count rather
        // than incremented at the eviction sites, so counting the eviction is
        // part of the one act that also accounts for it.
        DissectionDrops {
            flows: self.carry.flows(),
            ..self.drops
        }
    }

    /// R311y605 (F5) — the whole dissection's counters in one value.
    ///
    /// The per-object counters remain the authority for "which flow"; this is
    /// the "is anything wrong at all" question, which previously required a
    /// consumer to walk every flow and both of its directions. Read the caveats
    /// on [`DissectionHealth`] before summing anything here against a packet
    /// count.
    pub fn health(&self) -> DissectionHealth {
        let mut streams = self.carry.streams();
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
            // R311y746 (debt-carry-N11) — `self.drops()` and NOT the raw field.
            // `drops()` composes `flows` from the retirement count (R311y713
            // §B1) and this line copied the field beside it, so every consumer
            // that asks through `health()` — including the C ABI's `health`
            // JSON, which is the shipped surface — read a hard zero for the
            // eviction count while `drops()` read the truth. One ledger, and
            // both doors now go through the one composition.
            drops: self.drops(),
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
            self.note_skip(packet_index, SkipReason::IpFragmentPending);
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
            // R311y608 — `Udp` unconditionally, and it is not a shortcut:
            // `transport_from_ip` answers only `Tcp` or `Udp` (`link.rs:536`),
            // because a raweth frame is recognised BEFORE the IP walk and never
            // has an IP header to be fragmented.
            Ok(Transport::Udp(d) | Transport::RawEth(d)) => {
                self.push_datagram(d, ts_millis, DatagramLink::Udp)
            }
            Ok(Transport::Tcp(s)) => self.push_segment(s, ts_millis),
            // A reassembled datagram cannot be either of these: vsock never
            // reaches the IP path, and a fragment of a fragment is not a shape
            // IP has. Recorded rather than ignored so the impossibility is
            // observable if it ever stops being one.
            Ok(Transport::Vsock(_) | Transport::IpFragment(_)) => {
                self.note_skip(done.packet_index, SkipReason::NotTransport(done.key.proto));
            }
            Err(reason) => {
                self.note_skip(done.packet_index, reason);
            }
        }
    }

    /// What IP fragment reassembly has cost and seen.
    pub fn fragment_stats(&self) -> frag::FragmentStats {
        self.fragments.stats()
    }

    /// R311y607 — packets the CAPTURE TOOL said it lost, or `None` if the file
    /// made no such statement.
    ///
    /// Every other counter this type exposes answers "what did the DISSECTOR
    /// discard", which is a question about wz's own caps. This one answers
    /// "what never reached the file at all", and only the writer can answer it
    /// — a `dumpcap` whose kernel ring overflowed records an `isb_ifdrop` and
    /// then hands over a capture with a hole where those packets were.
    ///
    /// It matters because the hole is not inert. A TCP stream missing a run of
    /// bytes desynchronises, and this crate's assembler has no resynchronise
    /// path (`tcp.rs`), so every message after the gap is lost. Without this
    /// figure the only available reading of that outcome is "the dissector is
    /// broken"; with it, the capture indicts itself.
    ///
    /// `None` and `Some(0)` are deliberately different: no ISB at all is not a
    /// claim that nothing was dropped. A classic pcap always answers `None` —
    /// the format has nowhere to put the figure.
    pub fn capture_reported_drops(&self) -> Option<u64> {
        self.capture_reported_drops
    }

    /// R311y607/y608 — which of zenoh's two message namespaces this datagram
    /// belongs to: `Some(mid)` for the scouting one, `None` for the transport
    /// one.
    ///
    /// Returns the MID rather than a bool so the caller can tell a question
    /// from an answer without re-masking the header — the SCOUT is what has to
    /// be remembered, and only it.
    ///
    /// Two sufficient conditions, and neither subsumes the other:
    ///
    /// 1. A MULTICAST destination (R311y607). A multicast transport has no
    ///    handshake at all, so `0x01` / `0x02` there cannot be Init / Open.
    /// 2. A HELLO addressed to an endpoint this capture saw SCOUT (R311y608).
    ///    The answer travels back unicast, so rule 1 is blind to it, and
    ///    nothing in its bytes distinguishes it from an `Open`.
    ///
    /// Everything else is transport, INCLUDING a `0x02` toward an endpoint
    /// that never asked. That fallback is the load-bearing half: it is the
    /// second message of every `udp/...` handshake, and a rule that claimed it
    /// would be the same misread pointed the other way.
    fn datagram_namespace(&self, d: &link::Datagram) -> Option<u8> {
        let mid = scouting_mid(d)?;
        if d.destination().is_ip_multicast() {
            return Some(mid);
        }
        if mid == wz_session_core::wire_const::S_MID_HELLO && self.scouts.asked(&d.destination()) {
            return Some(mid);
        }
        None
    }

    /// Keep [`Self::skipped`] inside its bound, counting what that costs.
    /// R311y643 (§1.1e) — the ONE place a skip is recorded.
    ///
    /// Four sites used to push onto `skipped` and call `trim_skipped`
    /// themselves; each was a place a new reason could be added without ever
    /// reaching a total. The census is incremented here, BEFORE the trim, so a
    /// capture past the cap still counts what it dropped.
    fn note_skip(&mut self, packet_index: usize, reason: SkipReason) {
        self.skip_census.note(reason);
        self.skipped.push(SkippedPacket {
            packet_index,
            reason,
        });
        self.trim_skipped();
    }

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
    /// R311y638 (§1.1r) — the earliest instant this capture carried, or `None`
    /// when it carried no clock at all.
    ///
    /// The origin the filter language's `elapsed` term counts from. A consumer
    /// that folds two captures into one table must decide which origin governs
    /// rather than inheriting one silently, which is why this is exposed
    /// instead of being applied inside the planes.
    pub fn capture_origin_ms(&self) -> Option<u64> {
        self.capture_origin_ms
    }

    pub fn limits(&self) -> DissectionLimits {
        self.limits
    }

    /// How many chains have been aborted for missing their deadline.
    ///
    /// R311y654 (§1.1f) — UNCONDITIONAL, where the field it reads is not. A
    /// build without `reassembly` reassembles nothing and therefore expires
    /// nothing, so `0` is the true answer and not a stub — and a consumer
    /// asking "was anything abandoned here" must not have to know which
    /// features this binary was built with to ask.
    pub fn expired_chains(&self) -> usize {
        #[cfg(feature = "reassembly")]
        {
            self.expired_chains
        }
        #[cfg(not(feature = "reassembly"))]
        {
            0
        }
    }

    /// R311y655 (§1.1f) — how many chains were still open when the capture
    /// ended. See [`Self::expired_chains`] for why the two are counted apart.
    pub fn abandoned_chains(&self) -> usize {
        self.abandoned_chains
    }

    /// R311y713 (§B10) — what the messages `frames_per_flow` discarded said.
    ///
    /// Reported beside [`Self::drops`] rather than inside it because the two
    /// are read at different moments: the count answers "did a bound bite",
    /// which every reader must ask, and this answers "does it matter", which
    /// only a reader whose bound bit needs.
    pub fn dropped_frame_census(&self) -> DroppedFrameCensus {
        self.dropped_frames
    }

    /// R311y713 (§B7) — bytes lost with every chain this reader gave up on,
    /// whichever of the three causes took it.
    ///
    /// ONE number across the three causes on purpose, where the counts are
    /// three: the counts are read to decide which knob to turn, and this is
    /// read to decide whether the capture is worth reading at all. Per flow,
    /// [`FlowDissection::chain_loss`] answers where it went.
    pub fn chain_bytes_lost(&self) -> u64 {
        self.chain_bytes_lost + self.carry.chain_bytes()
    }

    /// R311y656 (§4.4) — how many chains were still open on flows the cap
    /// evicted. See [`Self::expired_chains`] for why the three are apart.
    pub fn evicted_chains(&self) -> usize {
        self.carry.chains()
    }

    /// Every TCP flow seen, in first-appearance order.
    pub fn flows(&self) -> &[FlowDissection] {
        &self.flows
    }

    /// R311y648 (§1.2a) — every flow whose zenoh session is inside an
    /// encrypted transport, with what this reader could count of it.
    ///
    /// The capture-wide answer to "is this report empty because nothing
    /// happened, or because it happened where I cannot see it". A reader who
    /// never looks at an individual flow still gets it, because
    /// [`CaptureReport`](report::CaptureReport) carries the total and the
    /// verdict.
    pub fn encrypted_flows(&self) -> Vec<tls::EncryptedFlow> {
        self.flows.iter().filter_map(|f| f.encrypted()).collect()
    }

    /// R311y666 (§1.2a) — transport messages this reader decoded, over every
    /// flow it HELD rather than every flow it still holds.
    ///
    /// The capture-wide question, and the one every summary must ask: the live
    /// tables are what a reader LOOKS at, and a flow the cap evicted took its
    /// decoded messages with it. Same shape as [`Self::encrypted_census`], and
    /// added for the same reason R311y650 added that one.
    pub fn decoded_messages(&self) -> usize {
        // R311y720 — the serial line's messages are in the total, on the rule
        // every other producer here answers to: a count that named some of the
        // lists would report a serial capture as having decoded nothing.
        self.serial_frames.len()
            + self.carry.messages()
            + self.flows.iter().map(|f| f.frames.len()).sum::<usize>()
            + self
                .datagram_flows
                .iter()
                .map(|f| f.decoded_messages())
                .sum::<usize>()
    }

    /// R311y720 (§D M3) — what the declared serial line turned out to hold,
    /// or `None` when no serial link type was declared or none arrived.
    ///
    /// An `Option` and not a zeroed census, because the two are different
    /// findings: a capture with no serial in it and a declared line that
    /// carried nothing would otherwise render identically, and the second is
    /// the one that means the declaration is wrong.
    pub fn serial_census(&self) -> Option<serial::SerialCensus> {
        self.serial.as_ref().map(|line| line.census())
    }

    /// R311y720 — the zenoh messages decoded off that line, with the serial
    /// frame each came out of.
    ///
    /// Paired rather than split, because the two halves answer together: the
    /// `PassiveFrame` says what zenoh message it was and the `SerialFrame` says
    /// which wire and which capture packet carried it. A reader given only the
    /// first cannot point at the bytes.
    pub fn serial_messages(&self) -> impl Iterator<Item = (&serial::SerialFrame, &PassiveFrame)> {
        self.serial_origins.iter().zip(self.serial_frames.iter())
    }

    /// R311y721 — the serial line's decoded messages alone, as the census
    /// planes take them.
    pub fn serial_frames(&self) -> &[PassiveFrame] {
        &self.serial_frames
    }

    /// R311y721 (§1.1f) — EVERY list of decoded transport messages this
    /// capture holds, with the flow key each stands under.
    ///
    /// # Why the census planes walk this and name no table
    ///
    /// Four planes census the decoded messages — throughput (`agg`), exchanges
    /// (`exchange`), payloads (`payload`) and nodes (`node`) — and each used to
    /// name the tables it knew about. That makes every new producer reach
    /// whichever plane its author remembered, and this workspace has shipped
    /// that omission five times (R311y668, y678, y699, y700, and R311y720's own
    /// carry, which recorded a whole serial line reaching the flow listing and
    /// none of the planes).
    ///
    /// [`DatagramDissection::frame_lists`] fixed it INSIDE the datagram table
    /// and the fifth instance walked straight past it, because a serial line is
    /// in neither table: it is point to point, has no addresses, and belongs to
    /// no 5-tuple. So the enumeration moves up here, where a producer that is
    /// not a flow at all can still be in it.
    ///
    /// SLICES and not a flattened frame iterator, deliberately: each list keeps
    /// its own coordinate meaning (see [`DatagramDissection::quic_streams`]),
    /// and fusing them into one sequence would fuse three offset spaces.
    pub fn message_lists(&self) -> impl Iterator<Item = (FlowKey, &[PassiveFrame])> {
        self.flows
            .iter()
            .map(|f| (f.flow, f.frames.as_slice()))
            .chain(
                self.datagram_flows
                    .iter()
                    .flat_map(|f| f.frame_lists().map(move |frames| (f.flow, frames))),
            )
            .chain(core::iter::once((
                // The key a serial line stands under: empty in every field,
                // because a serial link is point to point and there is one per
                // capture. See `FlowKey::serial_line`.
                FlowKey::serial_line(),
                self.serial_frames.as_slice(),
            )))
    }

    /// R311y661 (§1.2a) — the Decryption Secrets Blocks the capture file
    /// carried, in file order.
    ///
    /// What a caller builds a [`tls::RecordOpener`] out of. Handed on UNPARSED,
    /// exactly as `pcapng` read them: their `secrets_type` says which protocol's
    /// secrets they are, and a reader that guessed would parse another
    /// protocol's block as a TLS key log and report it as an empty one.
    pub fn decryption_secrets(&self) -> &[pcapng::DecryptionSecrets] {
        &self.decryption_secrets
    }

    /// R311y661 (§1.2a) — open every encrypted flow's kept records with
    /// `opener`, and feed the plaintext to the zenoh reader.
    ///
    /// This is the round that made the whole TLS track reach a report. Before
    /// it the chain was proven end to end in a test and had NO production
    /// caller: a capture carrying its own keys still reported zero frames and
    /// `no_keys_supplied`, which is a false statement about a file this reader
    /// could open.
    ///
    /// ## What it does, and the three things it refuses to do
    ///
    /// For each flow recognised as encrypted, the opener is asked once whether
    /// the flow can be served at all, and then given each kept record of each
    /// direction in index order. The plaintext of the `application_data` ones is
    /// pushed through the SAME `feed_stream` path a cleartext `tcp/...` flow
    /// uses — the zenoh session inside TLS is an ordinary length-prefixed byte
    /// stream, so a second reader for it would be a second implementation of
    /// what this crate already does.
    ///
    /// 1. It does not feed non-`application_data` plaintext onward. A
    ///    post-handshake `NewSessionTicket` is `handshake` INSIDE a record whose
    ///    outer type reads `application_data`, and injecting it into a
    ///    length-prefixed stream desynchronises everything after it.
    /// 2. It does not skip a record that refused the keys. The direction stops
    ///    at that index and says so: a byte stream with a hole punched in it
    ///    does not resume, it decodes garbage that looks like data.
    /// 3. It does not run twice over a flow. A second pass would push the same
    ///    plaintext into a reader that has already consumed it.
    ///
    /// ## The coordinate
    ///
    /// Frames decoded here are offset within the PLAINTEXT stream, which is a
    /// different space from the TCP one — shorter by every record header and
    /// AEAD tag. Reporting that number as `stream_offset` would make
    /// [`FlowDissection::packet_for`] resolve it against the TCP-space run map
    /// and silently name the wrong packet, which is R311y645's defect exactly.
    /// Each frame is therefore mapped back to the stream offset of the RECORD
    /// its bytes came out of, via [`tls::EncryptedRecord::stream_offset`].
    pub fn decrypt_with(&mut self, opener: &mut impl tls::RecordOpener) -> DecryptionSummary {
        self.decrypt_with_sink(opener, &mut ())
    }

    /// R311y677 (§1.1n) — [`Self::decrypt_with`], handing the opened plaintext
    /// to a caller who asked for it, at the one moment it exists.
    ///
    /// # Why a sink and not a stored buffer
    ///
    /// The plaintext is built here, fed to the session, and dropped with the
    /// call. A consumer that wants it — the field walker is the first — has no
    /// way to ask afterwards: the frames' coordinates are remapped to the
    /// CIPHERTEXT record they came out of (see the note above, which is
    /// deliberate and load bearing for `packet_for`), and the plaintext offset
    /// they had is not kept.
    ///
    /// Keeping the plaintext instead would add an eighth accumulation that grows
    /// with the input, to a crate whose bound discipline
    /// ([`DissectionLimits`], and a paired [`DissectionDrops`] counter for every
    /// bound that bites) exists because seven was already too many. It is also
    /// the third copy of a flow's bytes, which this workspace already carries as
    /// an open item.
    ///
    /// So the data is OFFERED rather than stored. A caller who wants it takes
    /// what it needs under its own bound; a caller who does not pays nothing,
    /// because `()` implements [`PlaintextSink`] as a no-op and this method is
    /// what [`Self::decrypt_with`] has always been. Same inversion as
    /// [`tls::RecordOpener`], for the same reason: the knowledge belongs to the
    /// caller and the moment belongs to this loop.
    pub fn decrypt_with_sink(
        &mut self,
        opener: &mut impl tls::RecordOpener,
        sink: &mut impl PlaintextSink,
    ) -> DecryptionSummary {
        let mut summary = DecryptionSummary::default();
        for flow in &mut self.flows {
            let Framing::Encrypted(state) = &mut flow.framing else {
                continue;
            };
            // (3) above. A pass that already ran owns this flow's frames.
            // R311y684 — counted rather than silently skipped: this is the one
            // fact that separates "already done" from "nothing to do", and a
            // caller offering a sink on a second pass needs it.
            if state.outcome.is_some() {
                summary.already_opened += 1;
                continue;
            }
            summary.flows += 1;
            let client_direction = state.client_direction.map(idx_direction);
            if let Err(reason) = opener.begin_flow(state.client_random.as_ref(), client_direction) {
                state.outcome = Some(Some(reason));
                summary.refused += 1;
                continue;
            }
            let mut refusal = None;
            // R311y669 — and the reason PER DIRECTION beside it. `refusal` keeps
            // the first, which is the flow's one-word summary; this keeps both, so
            // a flow whose halves fail differently no longer names one of the two
            // remedies a reader needs.
            let mut per_direction: [Option<tls::NotDecrypted>; 2] = [None, None];
            // Per direction: the opened plaintext, and the map from a byte
            // offset within it back to the record that produced it.
            let mut plaintext: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
            let mut spans: [Vec<(usize, usize)>; 2] = [Vec::new(), Vec::new()];
            for index in 0..2usize {
                let direction = idx_direction(index);
                // R311y668 — a direction the opener holds no key for is reported
                // as such rather than attempted. Attempting it produced
                // `RecordRefusedKeys { index: 0 }`, whose documented cause is the
                // EPOCH, for the commonest arrangement there is: an
                // `SSLKEYLOGFILE` from one of the two peers, carrying one side's
                // traffic secret. The reader was sent to look at key rotation for
                // a key that was never in the log.
                //
                // Guarded on the direction having records, because a direction
                // with nothing in it is not missing anything: a capture of a
                // one-way flow would otherwise report a reason about a half that
                // carried no ciphertext.
                if !state.kept[index].is_empty() && !opener.has_keys(direction) {
                    let reason = tls::NotDecrypted::NoKeyForDirection { direction };
                    refusal.get_or_insert(reason);
                    per_direction[index] = Some(reason);
                    continue;
                }
                for record in &state.kept[index] {
                    match opener.open(direction, record) {
                        Some(opened) => {
                            state.opened[index] += 1;
                            summary.records += 1;
                            // (1) above.
                            if opened.content_type == tls::CT_APPLICATION_DATA {
                                spans[index].push((plaintext[index].len(), record.stream_offset));
                                plaintext[index].extend_from_slice(&opened.plaintext);
                            }
                        }
                        None => {
                            // (2) above — this direction stops here.
                            let reason = tls::NotDecrypted::RecordRefusedKeys {
                                direction,
                                index: record.index,
                            };
                            refusal.get_or_insert(reason);
                            per_direction[index] = Some(reason);
                            break;
                        }
                    }
                }
            }
            state.outcome = Some(refusal);
            state.outcome_per_direction = per_direction;
            if refusal.is_none() {
                summary.decrypted += 1;
            }
            for index in 0..2usize {
                if plaintext[index].is_empty() {
                    continue;
                }
                let before = flow.frames.len();
                flow.feed_stream(idx_direction(index), &plaintext[index]);
                // R311y678 — OFFERED here: after the session has framed the
                // plaintext and BEFORE the remap below rewrites those frames'
                // coordinates into ciphertext space.
                //
                // R311y677 offered it one line earlier, before the frames
                // existed, which left a consumer no way to know where the
                // messages were and forced it to walk the framing itself. That
                // is a SECOND OPINION about where the messages are, beside the
                // session's, and nothing compared them: a capture the two
                // disagreed about would report one count in `messages decoded`
                // and a different set of rows underneath it.
                //
                // This window is the only one where the plaintext, the frames,
                // and the frames' plaintext coordinates all exist at once.
                sink.on_plaintext(DecryptedStream {
                    flow: flow.flow,
                    direction: idx_direction(index),
                    plaintext: &plaintext[index],
                    frames: &flow.frames[before..],
                    record_origins: &spans[index],
                });
                remap_decrypted_offsets(&mut flow.frames[before..], &spans[index]);
                summary.frames += flow.frames.len() - before;
            }
        }
        summary
    }

    /// R311y718 (§1.2a) — frame one recovered QUIC stream's bytes as zenoh.
    ///
    /// # The seam, and why it points this way
    ///
    /// This is the QUIC twin of [`Self::decrypt_with`], and it is inverted
    /// because the two layers are: TLS records arrive INSIDE a byte stream this
    /// crate already reassembles, so the loop belongs here and the cipher is a
    /// caller's trait ([`tls::RecordOpener`]). A QUIC stream is the other way
    /// round — reassembly happens after decryption, both of them behind a cipher
    /// this crate may not carry, so the caller owns the loop and hands the
    /// RESULT back. What the caller cannot own is the framing: the bytes inside
    /// zenoh's QUIC link are the ordinary length-prefixed batch stream
    /// (`is_streamed()` is `true`, `zenoh-link-quic/src/unicast.rs:184`), and a
    /// second framer for them would be a second implementation of the one thing
    /// this crate exists to do.
    ///
    /// # What a caller must hand over
    ///
    /// `bytes` is the CONTIGUOUS PREFIX of one direction of one stream, from
    /// offset zero, and the whole of it each time — the same contract a
    /// reassembler's `stream()` already meets. Feeding a suffix, or feeding
    /// across a hole, would push bytes into a length-prefixed framer at the
    /// wrong offset, and that does not fail loudly: it decodes garbage that
    /// looks like data, which is the failure `Framing::OpeningLost` exists to
    /// prevent one transport over. A caller re-offering a stream that has grown
    /// must therefore offer only the NEW tail; this method appends.
    ///
    /// Handshake bytes are the caller's to withhold, and offering them is
    /// counted rather than framed
    /// ([`quic::QuicStreamFeed::handshake_offers`]) — CRYPTO carries the TLS
    /// exchange, which has no length-prefixed zenoh in it at all.
    ///
    /// # What it refuses
    ///
    /// An offer for a flow this dissection does not hold is counted, not
    /// created: a QUIC flow the datagram table evicted is gone, and
    /// resurrecting it here would make the flow count depend on which pass ran
    /// last. An offer past [`DissectionLimits::quic_streams_per_flow`] is
    /// refused rather than admitted by eviction — see that field for why the
    /// asymmetry is deliberate.
    pub fn feed_quic_stream(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        stream_id: u64,
        handshake: bool,
        bytes: &[u8],
    ) -> quic::QuicStreamFeed {
        self.feed_quic_stream_with_sink(flow, direction, stream_id, handshake, bytes, &mut ())
    }

    /// R311y718 (§1.2a) — [`Self::feed_quic_stream`], offering the recovered
    /// bytes to a sink as well as to the framer.
    ///
    /// The QUIC twin of [`Self::decrypt_with_sink`], and it exists for the same
    /// reason: the field layer needs the BYTES and the FRAMES at once, and the
    /// only moment both exist is inside this call. Without it a `--fields` run
    /// over a `quic/...` capture prints nothing and says nothing about why —
    /// the flow decodes messages, and the walk that turns a message into named
    /// fields never sees them.
    ///
    /// # The one offer it will not hand on
    ///
    /// A frame's `stream_offset` is absolute within its direction's recovered
    /// stream, while `bytes` is what THIS offer added. The two agree only while
    /// the offer starts at zero, which is every offer the analyzer's own pass
    /// makes (one per direction per stream) and not a guarantee of the
    /// contract. So an offer that APPENDS is framed as usual and not walked,
    /// counted in [`quic::QuicStreamFeed::appends_not_walked`]. Handing it on
    /// anyway would slice the tail at an offset into the whole, which does not
    /// fail loudly -- it names the wrong bytes as a message's fields, and a
    /// field layer that can be quietly wrong is worse than one that is quietly
    /// absent.
    pub fn feed_quic_stream_with_sink(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        stream_id: u64,
        handshake: bool,
        bytes: &[u8],
        sink: &mut impl PlaintextSink,
    ) -> quic::QuicStreamFeed {
        let mut feed = quic::QuicStreamFeed::default();
        if handshake {
            feed.handshake_offers += 1;
            return feed;
        }
        let cap = self.limits.quic_streams_per_flow;
        let Some(dg) = self.datagram_flows.iter_mut().find(|f| f.flow == flow) else {
            feed.flow_absent += 1;
            return feed;
        };
        let index = match dg.quic_streams.iter().position(|s| s.id == stream_id) {
            Some(index) => index,
            None => {
                if cap.is_some_and(|n| dg.quic_streams.len() >= n) {
                    feed.streams_refused += 1;
                    return feed;
                }
                dg.quic_streams.push(QuicStreamDissection {
                    id: stream_id,
                    session: new_session(self.limits.reassembly_window_ms),
                    frames: messages::MessageList::new(),
                    fed: [0, 0],
                });
                dg.quic_streams.len() - 1
            }
        };
        let stream = &mut dg.quic_streams[index];
        // Read BEFORE the offer is added: this is what says whether the frames
        // about to be produced are offset into `bytes` or into a longer stream
        // `bytes` is only the tail of.
        // R311y749 (N6) — the stream coordinate of this offer's FIRST byte.
        // R311y718 read the same fact as a bool (`fed == 0`) because it only
        // had to decide whether to walk; the number is what lets an appending
        // offer be walked instead of refused.
        let base = stream.fed[dir_index(direction)];
        stream.fed[dir_index(direction)] += bytes.len() as u64;
        feed.bytes_fed += bytes.len();
        let before = stream.frames.len();
        stream.session.push(direction, bytes);
        loop {
            let mut progressed = false;
            for dir in [Direction::A, Direction::B] {
                loop {
                    match stream.session.next_frame(dir) {
                        Ok(frame) => {
                            stream.frames.push(frame);
                            progressed = true;
                        }
                        Err(PassiveStall::NeedMoreBytes) => break,
                        Err(PassiveStall::Desynchronised { .. }) => break,
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        // Read BEFORE the cap loop below, which discards from the FRONT: after
        // a trim the count is still right and the index `before` is not.
        let added = stream.frames.len() - before;
        feed.messages += added;
        // R311y719 — and the list is BOUNDED, against the same ceiling every
        // other decoded-message list on this flow answers to. Its own loop
        // rather than a share of `enforce_datagram_message_cap` because the
        // coordinate spaces differ: those three lists are packet-indexed and
        // these frames are offset in stream bytes, so "which is oldest" is only
        // answerable within each group. Accounted exactly as the others are —
        // a bound that discards decoded messages and does not say so is the
        // defect `DissectionDrops` exists to prevent.
        if let Some(cap) = self.limits.frames_per_flow {
            while stream.frames.len() > cap {
                let Some(receipt) = stream.frames.discard_oldest() else {
                    break;
                };
                self.dropped_frames.absorb(receipt);
                self.drops.frames += 1;
            }
        }
        // OFFERED here, for the same reason the TLS half offers where it does:
        // this is the one window in which the bytes, the frames and the frames'
        // coordinates into those bytes all exist together.
        //
        // R311y749 (N6) — AND AN APPENDING OFFER IS WALKED TOO, by making the
        // contract true rather than by giving up on it. `DecryptedStream`
        // promises that a frame's `stream_offset` indexes `plaintext`; a
        // frame's offset is absolute within its direction's stream, so the two
        // agree only at `base == 0`. The frames this offer produced are
        // therefore REBASED for the duration of the call and restored after it,
        // which leaves every other reader of this stream in absolute space.
        //
        // The window is computed from the COUNT this offer added rather than
        // from `before`, because the cap loop above discards from the FRONT:
        // after a trim, `before` names a frame that is no longer there.
        let window_start = stream.frames.len().saturating_sub(added);
        // A message that began in bytes an earlier offer carried has its head in
        // bytes nothing holds any more, so no coordinate can address it. At most
        // one, and it is the first: every later message starts where the
        // previous ended. The other-direction guard is defensive — this offer
        // pushed on one direction — and costs one comparison.
        let mut walk_from = window_start;
        while walk_from < stream.frames.len()
            && (stream.frames[walk_from].direction != direction
                || (stream.frames[walk_from].stream_offset as u64) < base)
        {
            walk_from += 1;
            feed.messages_straddling_offers += 1;
        }
        if walk_from < stream.frames.len() {
            let shift = base as usize;
            for f in stream.frames[walk_from..].iter_mut() {
                f.stream_offset -= shift;
            }
            sink.on_plaintext(DecryptedStream {
                flow,
                direction,
                plaintext: bytes,
                frames: &stream.frames[walk_from..],
                record_origins: &[],
            });
            for f in stream.frames[walk_from..].iter_mut() {
                f.stream_offset += shift;
            }
        } else if added > 0 {
            // Framed, and addressable by nothing: the whole window straddled.
            feed.appends_not_walked += 1;
        }
        // R311y709 — the flow's recovered/fed ledger. A QUIC flow's `fed` was
        // zero for the life of every capture until this method existed, which
        // was the accurate statement then and would be a false one now: these
        // bytes came out of datagrams this flow counted as recovered, and they
        // have now reached a decoder.
        dg.residue.fed += bytes.len() as u64;
        feed
    }

    /// R311y719 (§1.2a) — decode one recovered RFC 9221 DATAGRAM as zenoh.
    ///
    /// The datagram twin of [`Self::feed_quic_stream`], and the two differ in
    /// exactly the way the transports do. A stream is a byte stream and needs a
    /// framer with memory across offers; an RFC 9221 datagram is WHOLE,
    /// unordered and never retransmitted, which is why the opener does not
    /// reassemble it and why this needs no per-stream state at all. It is the
    /// same shape a cleartext multicast datagram takes through this crate: one
    /// unit, walked to its end, every message in it kept.
    ///
    /// `packet_index` is the capture packet the QUIC packet carrying it was in
    /// — the caller's, because it is the only coordinate that survives
    /// decryption and this crate cannot recover it from the bytes.
    ///
    /// The messages land in [`DatagramDissection::quic_datagrams`] rather than
    /// beside the cleartext ones; that field says why.
    pub fn feed_quic_datagram(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        packet_index: usize,
        bytes: &[u8],
    ) -> quic::QuicStreamFeed {
        self.feed_quic_datagram_with_sink(flow, direction, packet_index, bytes, &mut ())
    }

    /// R311y719 — [`Self::feed_quic_datagram`], offering the recovered batch to
    /// a sink as well as to the observer.
    ///
    /// Same reason its stream twin has one: the recovered bytes exist only
    /// inside this call, and the field layer cannot get them back afterwards --
    /// the capture packet holds the QUIC ciphertext, not this.
    pub fn feed_quic_datagram_with_sink(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        packet_index: usize,
        bytes: &[u8],
        sink: &mut impl PlaintextSink,
    ) -> quic::QuicStreamFeed {
        let mut feed = quic::QuicStreamFeed::default();
        let Some(dg) = self.datagram_flows.iter_mut().find(|f| f.flow == flow) else {
            feed.flow_absent += 1;
            return feed;
        };
        feed.bytes_fed += bytes.len();
        // HANDSHAKE PRESENT, read out of the reference implementation rather
        // than inferred from the word "datagram": zenoh's
        // `transport-link-quic-datagram` is a UNICAST link
        // (`zenoh-link-quic_datagram/src/unicast.rs`, and `is_streamed()` is
        // `false` at :164, which is why these bytes arrive here and not through
        // `feed_quic_stream`). A unicast zenoh link establishes its session
        // with INIT and OPEN, so those messages are meaningful on this path.
        // `Absent` is the multicast-capability answer -- UDP multicast and
        // pico's raweth -- and claiming it here would have this reader discard
        // the very exchange that names the peers.
        let batch = dg.session.next_datagram_on(
            direction,
            bytes,
            packet_index,
            wz_session_core::passive::LinkHandshake::Present,
        );
        feed.messages += batch.len();
        let before = dg.quic_datagrams.len();
        dg.quic_datagrams.append(batch);
        // OFFERED with the payload still in hand, which is the only moment it
        // exists: the capture packet this came out of holds the QUIC
        // ciphertext, so a later walk of the file cannot recover it.
        sink.on_recovered_datagram(RecoveredDatagram {
            flow,
            direction,
            packet_index,
            payload: bytes,
            frames: &dg.quic_datagrams[before..],
        });
        dg.residue.fed += bytes.len() as u64;
        let idx = self
            .datagram_flows
            .iter()
            .position(|f| f.flow == flow)
            .expect("the flow found above");
        self.enforce_datagram_message_cap(idx);
        feed
    }

    /// R311y650 (§1.2a) — how much of this capture was encrypted, over every
    /// flow it HELD rather than every flow it still holds.
    ///
    /// The capture-wide question, and the one every summary must ask instead of
    /// [`Self::encrypted_flows`]: that list is the live table, so a flow the cap
    /// evicted left it — and with it the report's only statement that part of
    /// this capture was unreadable. `encrypted_flows` remains the right call for
    /// a reader who wants to LOOK at a flow, which an evicted one no longer is.
    pub fn encrypted_census(&self) -> tls::EncryptedTotals {
        let mut totals = self.carry.encrypted();
        for flow in &self.flows {
            if let Some(e) = flow.encrypted() {
                totals.add_flow(&e.per_direction);
            }
        }
        totals
    }

    /// Every UDP flow seen, in first-appearance order. Where scouting,
    /// multicast Join, and the UDP unicast link land.
    /// R311y709 (§1.2a) — every flow's recovered-against-fed counts, summed.
    ///
    /// BOTH tables, which this workspace has had to be told four times
    /// (R311y668, y678, y699, y700): `flows()` is the stream half and a total
    /// built from it alone silently omits every UDP flow — including, here, the
    /// exact flows the measurement was created for.
    pub fn byte_residue(&self) -> ByteResidue {
        // R311y713 (§B1) — starting from the RETIRED flows' residue rather than
        // from zero. R311y709 added this counter to both live tables and to no
        // carry, so a capture that evicted a flow reported less recovered
        // residue than it had recovered — the same silence the five carries
        // before it were each added to end.
        let mut total = self.carry.residue();
        for f in &self.flows {
            total.absorb(f.residue);
        }
        for f in &self.datagram_flows {
            total.absorb(f.residue);
        }
        total
    }

    pub fn datagram_flows(&self) -> &[DatagramDissection] {
        &self.datagram_flows
    }

    /// Packets that yielded no stream bytes, each with its reason.
    ///
    /// CAPPED by [`DissectionLimits::skipped_packets`]; the overflow is counted
    /// in [`DissectionDrops::skipped`] and the whole population, by reason, is
    /// [`Self::skip_census`].
    pub fn skipped(&self) -> &[SkippedPacket] {
        &self.skipped
    }

    /// R311y643 (§1.1e) — every skipped packet by REASON, uncapped.
    ///
    /// The answer to "did this build fail to read the file, or did the file
    /// carry no zenoh traffic", which `packets_skipped` alone cannot give.
    pub fn skip_census(&self) -> &SkipCensus {
        &self.skip_census
    }

    /// The flow matching `key`, if the capture carried one.
    pub fn flow(&self, key: &FlowKey) -> Option<&FlowDissection> {
        self.flows.iter().find(|f| &f.flow == key)
    }

    /// R311y610 — no further packet is coming. Give up on every gap still open
    /// and decode what was waiting behind it.
    ///
    /// # Why this cannot be folded into the last `push_packet`
    ///
    /// An open gap is stepped over on PATIENCE — a count of later segments on
    /// the same direction ([`crate::tcp::DEFAULT_GAP_PATIENCE`]) — and a
    /// capture that stops within that many segments of a hole never spends it.
    /// The tail then stays held forever: `force_oldest_gap` existed from
    /// R311y609 with NO caller for exactly this reason, because "the capture
    /// ended" is a fact only the caller has. A live tap never ends, and calling
    /// this on one would step over a gap that was still going to fill, which is
    /// why it is a separate verb rather than a destructor.
    ///
    /// Idempotent, and safe to interleave with more packets — it forces the
    /// gaps that are open NOW, and a flow with none is untouched. Returns the
    /// number of gaps it forced.
    pub fn finish(&mut self) -> usize {
        // R311y720 (§D M3) — FIRST, because the serial line's direction mapping
        // is final only now and everything below reads decoded messages.
        self.finish_serial();
        let mut forced = 0usize;
        // R311y713 (§B1) — the obligations are [`exit::ExitingFlow`], the same
        // act the flow cap performs on its way past. What differs between the
        // two exits is only where the numbers are BOOKED: the end of a capture
        // is not a loss, so nothing here is an eviction and the flows stay in
        // their tables.
        for idx in 0..self.flows.len() {
            let tally = self.flows[idx].perform_exit();
            forced += tally.gaps_forced;
            self.abandoned_chains += tally.chains.chains;
            self.chain_bytes_lost += tally.chains.bytes;
            self.enforce_flow_limits(idx);
        }
        // Both flow tables, because both hold sessions and a datagram flow is
        // where fragments actually arrive. A chain opened by the LAST fragment
        // on a flow is never swept — the sweep runs when the NEXT packet
        // advances that flow's clock, and there is no next packet.
        let mut abandoned = ChainLoss::default();
        for flow in self.datagram_flows.iter_mut() {
            abandoned.absorb(flow.perform_exit().chains);
        }
        self.abandoned_chains += abandoned.chains;
        self.chain_bytes_lost += abandoned.bytes;
        forced
    }

    /// R311y713 (§B1) — take one stream flow out of its table, for the probe
    /// that shows [`exit::Exiting`]'s destructor is a gate.
    ///
    /// `cfg(test)` because it is the ONE way to obtain an unretired flow, and a
    /// shipped one would be the hole this module closes.
    #[cfg(test)]
    fn take_stream_flow_for_test(&mut self, idx: usize) -> exit::Exiting<FlowDissection> {
        self.flows.take(idx)
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
        self.push_packet_on(link_type, packet_index, 0, ts_millis, bytes)
    }

    /// R311y720 (§D M3) — [`Self::push_packet_at`], naming the capture
    /// INTERFACE the packet arrived on.
    ///
    /// Only the serial path reads it, and it reads it because a serial line is
    /// two wires: the interface is the one fact in the file that stands in for
    /// which wire, and every other link type carries its addresses in the
    /// packet. `push_packet_at` passes `0`, which is right for a pcap (one
    /// interface by construction) and for every declared link type but this
    /// one.
    pub fn push_packet_on(
        &mut self,
        link_type: u32,
        packet_index: usize,
        interface_id: u32,
        ts_millis: Option<u64>,
        bytes: &[u8],
    ) {
        // BEFORE decapsulation, because a declared serial link type has no link
        // header for `decapsulate` to strip -- the bytes ARE the serial stream.
        // Declared and never sniffed: see `serial`'s module doc for why a
        // pseudo-header this machine cannot verify must not be parsed.
        if self.declared_serial_linktypes.contains(&link_type) {
            self.push_serial(interface_id, packet_index, ts_millis, bytes);
            return;
        }
        self.push_packet_inner(link_type, packet_index, ts_millis, bytes)
    }

    /// R311y720 (§D M3) — one read of a declared serial line.
    ///
    /// The frames that complete inside these bytes are decoded as zenoh
    /// DATAGRAMS, which is what the link is: `Z_LINK_CAP_FLOW_DATAGRAM`
    /// (`vendor/zenoh-pico/src/link/unicast/serial.c:68`), so one frame carries
    /// one transport message and there is no length prefix to frame. Handshake
    /// frames are counted and NOT decoded -- an `INIT` with an empty payload is
    /// the link's own exchange, not zenoh's, and handing its zero bytes to the
    /// transport decoder would produce an undecodable-message row per
    /// handshake.
    ///
    /// `LinkHandshake::Present` because the link is UNICAST
    /// (`serial.c:67`), so the zenoh session on it really does open with INIT
    /// and OPEN -- the same reading `feed_quic_datagram` states for the other
    /// unicast datagram link.
    fn push_serial(
        &mut self,
        interface_id: u32,
        packet_index: usize,
        ts_millis: Option<u64>,
        bytes: &[u8],
    ) {
        let limit = self.limits.serial_frames_before_attribution;
        let line = self
            .serial
            .get_or_insert_with(|| alloc::boxed::Box::new(serial::SerialLine::with_limit(limit)));
        // COLLECTED, not decoded. The direction of a serial frame is not
        // knowable when it arrives: the handshake that names which wire is the
        // initiator's may come after it, and R311y720 MEASURED the consequence
        // of decoding eagerly -- the frames ahead of the handshake kept the
        // POSITIONAL guess while the ones after it were measured, so one
        // capture reported two different attributions and neither was labelled.
        //
        // So the whole line is decoded at `finish`, when the mapping is final.
        // The cost is one buffered frame list per line, which is the order a
        // single flow's frames already are.
        let frames = line.push(interface_id, packet_index, bytes);
        // R311y722 — once the mapping is SETTLED, nothing needs holding: the
        // direction of each frame is knowable as it arrives, so the buffer
        // drains here and stops growing. Settled means either a handshake
        // proved the roles or the bound committed to the positional mapping;
        // both are final by construction (`SerialLine` refuses to move a
        // settled mapping), which is exactly what makes draining safe.
        let settled = line.census().roles_witnessed || line.census().committed_positionally;
        self.serial_pending.extend(frames);
        if settled {
            self.decode_pending_serial();
        }
        let _ = ts_millis;
    }

    /// R311y722 — decode whatever the line is holding, under the mapping it has
    /// now. Called as each packet lands once the mapping is settled, and once
    /// more at [`Self::finish`] for a capture whose mapping never settled.
    fn decode_pending_serial(&mut self) {
        let Some(line) = self.serial.as_ref() else {
            return;
        };
        let pending = core::mem::take(&mut self.serial_pending);
        for frame in pending {
            // The LINK's own exchange, not zenoh's. An `INIT` carries an empty
            // payload, and handing zero bytes to the transport decoder would
            // put an undecodable-message row in the listing per handshake.
            if serial::is_handshake(frame.header) {
                continue;
            }
            let direction = line.direction_of(frame.interface);
            let batch = self.serial_session.next_datagram_on(
                direction,
                &frame.payload,
                frame.packet_index,
                wz_session_core::passive::LinkHandshake::Present,
            );
            for decoded in batch {
                // The two lists move together, here and nowhere else, which is
                // what keeps the index correspondence a local invariant rather
                // than a convention.
                self.serial_frames.push(decoded);
                self.serial_origins.push(frame.clone());
            }
        }
    }

    /// R311y720 (§D M3) — decode the buffered serial line, once its direction
    /// mapping is final.
    ///
    /// Called from [`Self::finish`], which is where every end-of-capture
    /// decision in this crate already lives.
    fn finish_serial(&mut self) {
        // Everything still held: a capture whose mapping never settled -- no
        // handshake, and fewer frames than the bound -- decodes here under the
        // positional mapping, which the census reports as such.
        self.decode_pending_serial();
    }
    fn push_packet_inner(
        &mut self,
        link_type: u32,
        packet_index: usize,
        ts_millis: Option<u64>,
        bytes: &[u8],
    ) {
        // R311y638 (§1.1r) — recorded BEFORE decapsulation, so a packet this
        // reader cannot decode still counts as part of the capture's timeline.
        // It is the capture that started, not the zenoh traffic in it.
        // R311y638 (§1.1r) — recorded BEFORE decapsulation, so a packet this
        // reader cannot decode still counts as part of the capture's timeline.
        // It is the capture that started, not the zenoh traffic in it.
        if let Some(ts) = ts_millis {
            self.capture_origin_ms = Some(match self.capture_origin_ms {
                Some(earliest) => earliest.min(ts),
                None => ts,
            });
        }
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
            // R311y608 — and the two arms are told apart HERE, because this is
            // the last place that knows which one it was. A raweth link has no
            // handshake whatever its destination MAC says (see
            // [`link_handshake`]), and its `Endpoint` is a MAC that no address
            // rule downstream can read.
            Ok(Transport::Udp(d)) => {
                self.push_datagram(d, ts_millis, DatagramLink::Udp);
                return;
            }
            Ok(Transport::RawEth(d)) => {
                self.push_datagram(d, ts_millis, DatagramLink::RawEth);
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
                self.note_skip(packet_index, reason);
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
                    self.gap_patience,
                ));
                self.flows.len() - 1
            }
        };
        // R311y615 (§1.1f) — UNGATED, and BEFORE the flow borrow. The clock's
        // first consumer was chain expiry, which is what put it behind
        // `reassembly`; its second is `PassiveFrame::observed_at_ms`, which
        // every build has. A build without `reassembly` sweeps nothing and
        // still stamps its frames.
        self.advance_clock(idx, ts_millis, FlowKind::Stream);
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
        flow.deliver_from(direction, before);
        flow.last_activity = packet_index;
        // R311y713 (§B4) — and the CAPTURE INSTANT beside the file position.
        // `or` and not assignment: a source that stamps some packets and not
        // others must not un-know a time it was told.
        flow.last_seen_ms = ts_millis.or(flow.last_seen_ms);
        self.enforce_flow_limits(idx);
        self.evict_flows_beyond_cap();
    }

    /// R311y615 (§1.1f) — advance one flow's observation clock, and account for
    /// whatever that expired.
    ///
    /// One function for both flow families because the two differ only in which
    /// vector holds the session, and the accounting rule below is the part that
    /// must not be written twice: the clock advance is UNCONDITIONAL and the
    /// expiry tally is not. A build without `reassembly` has no chains, so
    /// `observe_at` answers `0` and there is no counter to fold it into — but
    /// the frames it stamps are exactly as stamped as a full build's.
    fn advance_clock(&mut self, idx: usize, ts_millis: Option<u64>, kind: FlowKind) {
        let Some(ms) = ts_millis else {
            return;
        };
        // R311y713 (§B6/§B7) — the sweep reports what it dropped, and the flow
        // it dropped it FROM records its own share on the way past. The
        // capture-wide counter below cannot answer "which link is losing", and
        // the sweep is the only place that knows.
        let expired = match kind {
            FlowKind::Stream => {
                let loss = self.flows[idx].session.observe_at_counting(ms);
                self.flows[idx].chain_loss.absorb(loss);
                loss
            }
            FlowKind::Datagram => {
                let loss = self.datagram_flows[idx].session.observe_at_counting(ms);
                self.datagram_flows[idx].chain_loss.absorb(loss);
                loss
            }
        };
        #[cfg(feature = "reassembly")]
        {
            self.expired_chains += expired.chains;
            self.chain_bytes_lost += expired.bytes;
        }
        #[cfg(not(feature = "reassembly"))]
        {
            let _ = expired;
        }
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
                // R311y713 (§B10) — censused BEFORE the drain, which is the
                // only moment the messages still exist to be read.
                for _ in 0..cut {
                    // R311y723 — one receipt per message, each taken and
                    // counted. The `drain` this replaced could have been
                    // written without the loop body and would have compiled;
                    // this cannot.
                    let Some(receipt) = flow.frames.discard_oldest() else {
                        break;
                    };
                    self.dropped_frames.absorb(receipt);
                }
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
        let Some(cap) = self.limits.max_flows_per_table else {
            return;
        };
        while self.flows.len() > cap {
            let Some(oldest) =
                least_recently_active(&self.flows, |f| f.last_seen_ms, |f| f.last_activity)
            else {
                break;
            };
            // R311y713 (§B1) — the flow is LEAVING, and everything that used to
            // be written out here one counter at a time is now the one act
            // `absorb_stream` performs: the exit obligations first (the open
            // gaps, the framing verdict, the chains), then every counter it
            // held. Six rounds each added one carry to this loop after finding
            // the previous version had missed it; the counters are private to
            // [`exit`] now, so a seventh cannot be missed here — there is
            // nothing here to miss it with.
            let gone = self.flows.take(oldest);
            self.carry.absorb_stream(gone);
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
                    self.gap_patience,
                ));
                self.flows.len() - 1
            }
        };
        let direction = if record.from_low {
            Direction::A
        } else {
            Direction::B
        };
        self.advance_clock(idx, ts_millis, FlowKind::Stream);
        let flow = &mut self.flows[idx];

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
        flow.deliver_from(direction, before);
        flow.last_activity = record.packet_index;
        flow.last_seen_ms = ts_millis.or(flow.last_seen_ms);
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
    /// NAMESPACES"; [`Dissection::datagram_namespace`] is what decides which.
    ///
    /// R311y608 — and `link` says which KIND of datagram link carried it, a
    /// fact that exists only above this call: both kinds arrive as a
    /// [`link::Datagram`], and a raweth one's endpoints are MACs that no
    /// address rule can read.
    ///
    /// No buffering and no reassembly, because there is nothing to reassemble
    /// — which is exactly why this is four lines and the TCP path is not.
    fn push_datagram(&mut self, d: link::Datagram, ts_millis: Option<u64>, link: DatagramLink) {
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
        // Decided BEFORE the flow is borrowed, and against `self`, because the
        // answer depends on an exchange that spans two DIFFERENT flows: the
        // SCOUT's key is (asker, group) and the HELLO's is (asker, responder).
        let scouting = self.datagram_namespace(&d);
        if scouting == Some(wz_session_core::wire_const::S_MID_SCOUT) {
            // Recorded on the ROUTING decision, not on a successful decode: a
            // build with `codec-hello` and without `codec-scout` still has to
            // recognise the answers, and it cannot name the question.
            let evicted = self
                .scouts
                .observed_scout_from(d.source(), self.limits.max_scout_askers);
            self.drops.scout_askers += evicted;
        }
        self.advance_clock(idx, ts_millis, FlowKind::Datagram);
        let flow = &mut self.datagram_flows[idx];
        flow.last_activity = d.packet_index;
        flow.last_seen_ms = ts_millis.or(flow.last_seen_ms);
        // R311y709 — THE recovery point for a datagram flow. Before the QUIC
        // branch on purpose: a datagram counted as QUIC was recovered exactly as
        // much as one that is decoded, and the branch that follows is precisely
        // where the two stop being the same.
        flow.residue.recovered += d.payload.len() as u64;

        // R311y669 (§1.2a) — QUIC, BEFORE the scouting question and before the
        // zenoh decode, because it is the question of whether either applies.
        //
        // Order is deliberate and asymmetric. An established QUIC flow takes
        // every datagram; a flow not yet known to be QUIC is tested by the SOUND
        // rule only. That is what keeps a zenoh datagram whose first byte
        // resembles a short header (`T_MID_INIT | 0x40` = `0x41`) out of here:
        // the sound rule needs a long header with a known version, which zenoh
        // does not produce.
        match &mut flow.quic {
            Some(census) => {
                match quic::recognise_on_quic_flow(&d.payload) {
                    Some(p) => census.add(p),
                    // Counted, not ignored. A QUIC flow carrying a datagram this
                    // reader cannot name is a fact, and absorbing it into the
                    // packet count would claim a packet that was never read.
                    None => census.add_unrecognised(d.payload.len()),
                }
                self.evict_datagram_flows_beyond_cap();
                return;
            }
            None => {
                // Recognition first, declaration second, and the order matters
                // for what gets RECORDED rather than for what happens: a
                // declared flow whose long header this reader can also read is
                // evidence as well as premise, and the census should say so.
                if let Some(p) = quic::recognise_long(&d.payload) {
                    let mut census = quic::QuicCensus::default();
                    census.add(p);
                    flow.quic = Some(census);
                    self.evict_datagram_flows_beyond_cap();
                    return;
                }
                // R311y670 — the caller DECLARED this port. Nothing in the bytes
                // could have told us (measured: a 1-RTT packet decodes as a
                // complete zenoh Fragment with no residue and the capture reports
                // itself whole), so this is the only way such a flow is ever
                // classified — and it is marked as a premise, not as evidence.
                // `FlowKey`'s port is `u32` because a vsock port is; a declared
                // UDP port is 16 bits and is widened rather than the key being
                // narrowed, which would alias two vsock flows onto one.
                if self
                    .declared_quic_ports
                    .iter()
                    .any(|p| u32::from(*p) == d.flow.low.port || u32::from(*p) == d.flow.high.port)
                {
                    let mut census = quic::QuicCensus {
                        declared: true,
                        ..Default::default()
                    };
                    match quic::recognise_on_quic_flow(&d.payload) {
                        Some(p) => census.add(p),
                        None => census.add_unrecognised(d.payload.len()),
                    }
                    flow.quic = Some(census);
                    self.evict_datagram_flows_beyond_cap();
                    return;
                }
            }
        }

        if scouting.is_some() {
            // Decoded WITHOUT touching the session: a scouting message is not
            // part of any session, so folding it would let a pre-session
            // datagram move state that only a peer's handshake may move.
            // R311y709 — `parse_scouting` reads these bytes, so they are fed.
            // A scouting datagram advances no session, which is a different
            // question from whether anything read it.
            flow.residue.fed += d.payload.len() as u64;
            flow.scouting.push(ScoutingDatagram {
                direction,
                packet_index: d.packet_index,
                frame: parse_scouting(&d.payload),
            });
            // R311y651 (§4.4) — bounded by the SAME limit the frame list is,
            // because it answers the same question — how many decoded messages
            // of this flow are kept — and a second knob for one axis is a knob
            // a caller sets once and forgets. Until now this list had no bound
            // at all: a tap on a scouting group grows one entry per SCOUT for
            // as long as the process runs, which is the leak `frames_per_flow`
            // exists to prevent, one list over.
            self.enforce_datagram_message_cap(idx);
            self.evict_datagram_flows_beyond_cap();
            return;
        }
        // R311y631 (§1.2b) — one datagram, every message it batched.
        flow.residue.fed += d.payload.len() as u64;
        let batch = flow.session.next_datagram_on(
            direction,
            &d.payload,
            d.packet_index,
            link.handshake(&d),
        );
        flow.frames.append(batch);
        self.enforce_datagram_message_cap(idx);
        self.evict_datagram_flows_beyond_cap();
    }

    /// R311y713 (§B3) — hold one datagram flow's DECODED MESSAGES inside
    /// `frames_per_flow`, across both of the lists it keeps them in.
    ///
    /// R311y651 bounded the scouting list by this same limit on the argument
    /// that it answers the same question — how many decoded messages of this
    /// flow are kept — and then applied it to each list separately, so a flow
    /// that both scouts and carries traffic held up to twice the number the
    /// limit names. Its own argument asks for one budget: if the two lists
    /// answer one question they must share the answer's bound.
    ///
    /// What goes is the OLDEST message of the flow, whichever list holds it,
    /// which is the rule `frames_per_flow` already states one list at a time.
    /// Both lists carry the packet index, so "oldest" is answerable across
    /// them without inventing an ordering.
    fn enforce_datagram_message_cap(&mut self, idx: usize) {
        let Some(cap) = self.limits.frames_per_flow else {
            return;
        };
        loop {
            let flow = &self.datagram_flows[idx];
            // R311y719 — THREE lists, not two. `quic_datagrams` holds messages
            // decoded out of recovered RFC 9221 batches and is bounded here
            // with the other two, because it answers the same question: how
            // many decoded messages of this flow are kept. A list outside this
            // sum is a list that grows without limit on a live tap, which is
            // the defect R311y713 closed for the pair and would have reopened
            // for the trio.
            //
            // All three are in the PACKET coordinate space, which is what makes
            // "oldest" answerable across them. `quic_streams` deliberately is
            // not in this sum: its frames are offset in stream bytes, and a
            // comparison across the two spaces would evict by a number that
            // means different things in each. That list is bounded where it is
            // fed, against the same ceiling.
            if flow.frames.len() + flow.scouting.len() + flow.quic_datagrams.len() <= cap {
                return;
            }
            // The oldest of the three, by the one coordinate they share.
            let oldest = [
                flow.frames.first().map(|f| (f.stream_offset, 0u8)),
                flow.scouting.first().map(|s| (s.packet_index, 1u8)),
                flow.quic_datagrams.first().map(|f| (f.stream_offset, 2u8)),
            ]
            .into_iter()
            .flatten()
            .min();
            // Unreachable while the sum exceeds a cap, and a `return` rather
            // than a panic: a bound that cannot be met must not take the
            // capture down with it.
            let Some((_, which)) = oldest else {
                return;
            };
            let flow = &mut self.datagram_flows[idx];
            match which {
                1 => {
                    flow.scouting.remove(0);
                    self.drops.scouting += 1;
                }
                2 => {
                    let Some(receipt) = flow.quic_datagrams.discard_oldest() else {
                        return;
                    };
                    self.dropped_frames.absorb(receipt);
                    self.drops.frames += 1;
                }
                _ => {
                    let Some(receipt) = flow.frames.discard_oldest() else {
                        return;
                    };
                    self.dropped_frames.absorb(receipt);
                    self.drops.frames += 1;
                }
            }
        }
    }

    /// R311y651 (§4.4) — the datagram table's half of `max_flows_per_table`.
    ///
    /// A separate walk from the stream table's rather than a generic one over
    /// both, because what has to be CARRIED off an evicted flow differs: a
    /// stream flow has assemblers and a ws framing to account for and a
    /// datagram flow has neither, and a shared function would have to ask
    /// which kind it was holding at every line.
    ///
    /// What is common is the rule, and it is R311y610's: the session counters
    /// go with the flow unless they are carried, and `framing_health` reads
    /// those exact fields off `datagram_flows` — so evicting without this carry
    /// would make a live tap's multicast loss figures improve every time a slot
    /// recycled.
    fn evict_datagram_flows_beyond_cap(&mut self) {
        let Some(cap) = self.limits.max_flows_per_table else {
            return;
        };
        while self.datagram_flows.len() > cap {
            let Some(oldest) = least_recently_active(
                &self.datagram_flows,
                |f| f.last_seen_ms,
                |f| f.last_activity,
            ) else {
                break;
            };
            // R311y713 (§B1) — the same act, on the table where fragments
            // actually arrive. Writing the two retirements next to each other
            // in [`exit`] is what surfaced that this one had never carried the
            // MESSAGES it decoded, though the stream path has since R311y666.
            let gone = self.datagram_flows.take(oldest);
            self.carry.absorb_datagram(gone);
        }
    }

    /// Dissect a whole classic pcap file from memory.
    pub fn from_pcap(bytes: &[u8]) -> Result<Self, pcap::PcapError> {
        Self::from_pcap_declaring_quic(bytes, &[])
    }

    /// R311y670 — [`Self::from_pcap`], told which UDP ports carry QUIC. See
    /// [`Self::from_capture_declaring_quic`] for why a caller must be able to.
    pub fn from_pcap_declaring_quic(
        bytes: &[u8],
        quic_udp_ports: &[u16],
    ) -> Result<Self, pcap::PcapError> {
        Self::from_pcap_declaring(bytes, quic_udp_ports, &[])
    }

    /// R311y720 (§D M3) — the same, also declaring serial link types.
    ///
    /// A pcap file has ONE interface by construction, so a serial capture in
    /// this format cannot separate the two wires — which is exactly what
    /// [`serial::SerialCensus::direction_unattributed`] then reports.
    pub fn from_pcap_declaring(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
    ) -> Result<Self, pcap::PcapError> {
        Self::from_pcap_declaring_bounded(
            bytes,
            quic_udp_ports,
            serial_linktypes,
            DissectionLimits::default(),
        )
    }

    /// R311y748 — the same, under a caller's own [`DissectionLimits`].
    ///
    /// # Why a file reader takes limits at all
    ///
    /// `DissectionLimits::default()` is every field `None`, and that is right
    /// for the common case this crate was built for: a file ENDS, so keeping
    /// all of it is bounded by the file. It stops being right the moment the
    /// file is larger than the reader's memory, and until this existed the only
    /// answer was "read it anyway" — the caller could state a bound to
    /// [`Self::with_limits`] and then had no way to feed a capture FILE through
    /// it, because every `from_*` constructor here called [`Self::new`].
    ///
    /// So the bound becomes an argument rather than a second dissection type.
    /// What it costs is stated by the same [`DissectionDrops`] the live tap uses
    /// — a bound that bites is never silent — which is why this is a parameter
    /// and not a truncation the reader performs quietly.
    pub fn from_pcap_declaring_bounded(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
        limits: DissectionLimits,
    ) -> Result<Self, pcap::PcapError> {
        let file = pcap::parse(bytes)?;
        let mut out = Self::with_limits(limits);
        out.declared_serial_linktypes = serial_linktypes.to_vec();
        // Declared BEFORE the first packet, which is the whole point: a flow is
        // established as QUIC by its first datagram, so a declaration arriving
        // afterwards would have let that datagram through the zenoh decoder.
        out.declared_quic_ports = quic_udp_ports.to_vec();
        for packet in &file.packets {
            out.push_packet_at(
                file.link_type,
                packet.index,
                Some(packet.ts_millis(file.timestamp_unit)),
                &packet.data,
            );
        }
        // R311y610 — a FILE has a last packet, so the patience an open gap is
        // waiting on will never be spent. This is the caller that knows it.
        out.finish();
        Ok(out)
    }

    /// R311y605 — dissect a whole pcapng file from memory.
    ///
    /// Each packet is pushed under ITS OWN interface's link type, which is the
    /// whole reason [`pcapng`] is a separate reader: a `dumpcap -i any` capture
    /// carries interfaces with different link layers, and one link type applied
    /// to all of them decapsulates half the file as the wrong thing.
    pub fn from_pcapng(bytes: &[u8]) -> Result<Self, pcapng::PcapngError> {
        Self::from_pcapng_declaring_quic(bytes, &[])
    }

    /// R311y670 — [`Self::from_pcapng`], told which UDP ports carry QUIC. See
    /// [`Self::from_capture_declaring_quic`] for why a caller must be able to.
    pub fn from_pcapng_declaring_quic(
        bytes: &[u8],
        quic_udp_ports: &[u16],
    ) -> Result<Self, pcapng::PcapngError> {
        Self::from_pcapng_declaring(bytes, quic_udp_ports, &[])
    }

    /// R311y720 (§D M3) — the same, also declaring serial link types.
    pub fn from_pcapng_declaring(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
    ) -> Result<Self, pcapng::PcapngError> {
        Self::from_pcapng_declaring_bounded(
            bytes,
            quic_udp_ports,
            serial_linktypes,
            DissectionLimits::default(),
        )
    }

    /// R311y748 — the same, under a caller's own [`DissectionLimits`]. See
    /// [`Self::from_pcap_declaring_bounded`] for why a file reader takes them.
    pub fn from_pcapng_declaring_bounded(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
        limits: DissectionLimits,
    ) -> Result<Self, pcapng::PcapngError> {
        let file = pcapng::parse(bytes)?;
        let mut out = Self::with_limits(limits);
        out.declared_serial_linktypes = serial_linktypes.to_vec();
        // See `from_pcap_declaring_quic`: before the first packet, not after.
        out.declared_quic_ports = quic_udp_ports.to_vec();
        // R311y661 (§1.2a) — the file's own key material, carried instead of
        // discarded. See `Dissection::decryption_secrets`.
        out.decryption_secrets = file.decryption_secrets.clone();
        // R311y607 — carried BEFORE the packets, so a caller that stops early
        // still learns the capture was incomplete.
        out.capture_reported_drops = file
            .interface_stats
            .iter()
            .filter_map(|s| s.dropped)
            .try_fold(0u64, |acc, d| acc.checked_add(d));
        for packet in &file.packets {
            // R311y720 — the INTERFACE travels with the packet. Only the serial
            // path reads it, and it is the one fact in the file that stands in
            // for which wire of a two-wire line the bytes came off.
            out.push_packet_on(
                packet.link_type,
                packet.index,
                packet.interface_id,
                file.ts_millis(packet),
                &packet.data,
            );
        }
        // R311y610 — see `from_pcap`.
        out.finish();
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
        Self::from_capture_declaring_quic(bytes, &[])
    }

    /// R311y670 (§1.2a) — [`Self::from_capture`], told which UDP ports carry
    /// QUIC.
    ///
    /// # Why a caller has to be able to say this
    ///
    /// R311y669 recognised QUIC by its LONG header, which is the only sound rule
    /// available: a short header's first byte is a flagged zenoh MID, so no
    /// byte-level test separates them. That leaves a capture which begins
    /// mid-connection, and MEASURED, its output is the worst this crate produces:
    /// one QUIC 1-RTT packet beginning `0x46` decoded as a complete zenoh
    /// `Fragment`, left ZERO unaccounted bytes, and the report said `complete`.
    /// Every counter agreed the capture had been read whole.
    ///
    /// Nothing in the bytes can fix that, and a heuristic would trade this
    /// misread for its mirror image — real zenoh silently reported as an
    /// unopened QUIC flow. So the fact comes from outside, the way an external
    /// key log does for TLS: the person holding the capture knows which port
    /// their QUIC endpoint listens on, and saying so is one flag.
    ///
    /// A declared flow is marked as DECLARED in its census, because "I recognised
    /// this" and "I was told this" are different claims and a reader must be able
    /// to tell which one they are reading.
    /// R311y720 (§D M3) — read a capture in which `serial_linktypes` carry raw
    /// zenoh SERIAL bytes.
    ///
    /// DECLARED, and the declaration is the whole design: `LINKTYPE_RTAC_SERIAL`
    /// (250) has a pseudo-header this machine cannot verify -- `pcap/dlt.h`
    /// gives the number and no layout -- so a reader that parsed one would
    /// report a guessed direction bit as a measurement. The caller names the
    /// link type, exactly as `from_capture_declaring_quic` has the caller name
    /// a UDP port, and what this crate then reads is what it can verify: the
    /// COBS envelope, the CRC32 and the handshake flags, all three pinned
    /// against zenoh-pico's own sources. See [`serial`].
    pub fn from_capture_declaring_serial(
        bytes: &[u8],
        serial_linktypes: &[u32],
    ) -> Result<Self, CaptureError> {
        Self::from_capture_declaring(bytes, &[], serial_linktypes)
    }

    /// R311y720 — both declarations at once, which is what the analyzer passes.
    pub fn from_capture_declaring(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
    ) -> Result<Self, CaptureError> {
        Self::from_capture_declaring_bounded(
            bytes,
            quic_udp_ports,
            serial_linktypes,
            DissectionLimits::default(),
        )
    }

    /// R311y748 — the format-dispatching reader, under a caller's own bounds.
    ///
    /// See [`Self::from_pcap_declaring_bounded`] for why a file reader takes
    /// limits. This is the one every other bounded entry point should go
    /// through, including the C ABI's: the dispatch on magic is the same fact
    /// whether or not a bound is stated, and writing it twice is how the two
    /// formats came to disagree about anything before.
    pub fn from_capture_declaring_bounded(
        bytes: &[u8],
        quic_udp_ports: &[u16],
        serial_linktypes: &[u32],
        limits: DissectionLimits,
    ) -> Result<Self, CaptureError> {
        if pcapng::looks_like_pcapng(bytes) {
            Self::from_pcapng_declaring_bounded(bytes, quic_udp_ports, serial_linktypes, limits)
                .map_err(CaptureError::Pcapng)
        } else {
            Self::from_pcap_declaring_bounded(bytes, quic_udp_ports, serial_linktypes, limits)
                .map_err(CaptureError::Pcap)
        }
    }

    /// R311y748 — [`Self::from_capture`], under a caller's own bounds.
    pub fn from_capture_bounded(
        bytes: &[u8],
        limits: DissectionLimits,
    ) -> Result<Self, CaptureError> {
        Self::from_capture_declaring_bounded(bytes, &[], &[], limits)
    }

    pub fn from_capture_declaring_quic(
        bytes: &[u8],
        quic_udp_ports: &[u16],
    ) -> Result<Self, CaptureError> {
        if pcapng::looks_like_pcapng(bytes) {
            Self::from_pcapng_declaring_quic(bytes, quic_udp_ports).map_err(CaptureError::Pcapng)
        } else {
            Self::from_pcap_declaring_quic(bytes, quic_udp_ports).map_err(CaptureError::Pcap)
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
    ///
    /// R311y613 — `pub(crate)` so `agg`'s tests drive the SAME entry point
    /// rather than a second packet builder of their own. A plane whose tests
    /// hand-feed frames is testing its fold and not its wiring.
    pub(crate) fn udp_packet(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
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
    pub(crate) fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
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

    /// R311y655 — the same packet from HIGH to LOW: addresses swapped as well
    /// as ports, which is what keeps it the same 5-tuple in the other direction
    /// rather than a second flow.
    ///
    /// Gated to match its CALLERS rather than more widely: a fixture built in an
    /// arm nothing calls it from is dead code, and `-D dead-code` finds it in
    /// exactly the arm a default-features run never compiles. R311y715 —
    /// UNGATED now, because the rule cuts the other way as soon as a second
    /// caller appears: the node census (`node.rs`) needs a reverse-direction
    /// packet to prove a link takes an INIT from BOTH ends, and it is not a
    /// reassembly test. A helper gated more narrowly than its callers fails to
    /// resolve in the arm between them, which is the same shape as `ChainLoss`
    /// two screens up.
    pub(crate) fn tcp_packet_reverse(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&7447u16.to_be_bytes());
        tcp.extend_from_slice(&1111u16.to_be_bytes());
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
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
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

    /// R311y609 — one length-prefixed `T_MID_FRAME` carrying `sn` and a
    /// four-byte body, through the real VLE encoder.
    ///
    /// `codec-frame` is not optional for this crate — a capture front end
    /// reads what is on the wire — so there is no cfg here.
    pub(crate) fn framed_frame(sn: u8) -> Vec<u8> {
        assert!(sn < 0x80, "the one-byte VLE arm");
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_session_core::wire_const::FLAG_T_FRAME_R,
            sn,
        ];
        wire.extend_from_slice(&[0x1F, 0x00, 0x00, 0x00]);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// R311y610 — the same, carrying `len` bytes of pseudo-random payload.
    ///
    /// [`framed_frame`] carries four fixed low-valued bytes, and a stream of
    /// those can never exercise the defect §4.1 names: a two-byte prefix read
    /// off `1F 00` claims 31, not 40000. A capture of real traffic carries USER
    /// BYTES, and a length prefix read off user bytes claims 32 KiB on average.
    /// The payload is an opaque tail to `parse_inbound`, so the frame still
    /// decodes as the frame it is — the entropy is in the part the transport
    /// layer does not read, exactly as it is on the wire.
    fn framed_frame_with_payload(sn: u8, len: usize, seed: u32) -> Vec<u8> {
        assert!(sn < 0x80, "the one-byte VLE arm");
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_session_core::wire_const::FLAG_T_FRAME_R,
            sn,
        ];
        let mut x = seed;
        for _ in 0..len {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            wire.push((x >> 16) as u8);
        }
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// The fixture above writes a VLE by hand, which is the "author's idea of
    /// the layout" the other fixtures in this module avoid. It is checked
    /// against the REAL decoder instead of trusted: if a one-byte VLE ever
    /// stops meaning what this assumes, this fails rather than the interlock
    /// test failing for an unrelated-looking reason.
    #[test]
    fn the_frame_fixture_decodes_as_the_frame_it_claims() {
        let wire = framed_frame(0x42);
        assert_eq!(
            u16::from_le_bytes([wire[0], wire[1]]) as usize,
            wire.len() - 2
        );
        match wz_session_core::inbound::parse_inbound(&wire[2..]) {
            Ok(wz_session_core::inbound::InboundFrame::Frame { sn, reliable, .. }) => {
                assert_eq!((sn, reliable), (0x42, true));
            }
            other => panic!("the fixture is not a Frame: {other:?}"),
        }
    }

    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;

    // R311y621 (§1.1k) — LIFTED here from `agg::tests`, which is gated on
    // `network-codecs`. The plane's behaviour WITHOUT the network codecs needs
    // the same Push on the wire, and a second builder in that module would be
    // the copy that drifts -- the reason `frame_carrying` is `pub(crate)` too.
    // Encoding a Push never needed the feature: `wz-capture` names `codec-push`
    // on its `wz-codecs` line unconditionally, and `network-codecs` selects what
    // the DECODER (`wz-session-core`) can name. That asymmetry IS the fixture.
    /// `M=1` — the id lives in the SENDER's space.
    pub(crate) fn sender_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
        Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            }),
        }
    }

    /// A `Push` carrying `payload` under `keyexpr`, built by the Push codec.
    ///
    /// The header is `Push::default().header` plus the `N` bit rather than a
    /// literal, so the MID the generated `Default` bakes cannot be lost here.
    ///
    /// R311y616 (§4.10) — and the `N` bit is now
    /// [`FLAG_N_N`](wz_codecs::wire_const::FLAG_N_N) rather than the number
    /// `0x20`, which is the other half of the same rule: a fixture that spells
    /// a flag as a literal is a byte string wearing a struct.
    /// R311y644 (§1.1p) — a `Push` whose `MsgPut` carries a SOURCE timestamp.
    ///
    /// `stamped_ms` is a wall-clock instant in milliseconds; it is converted to
    /// the NTP64 word zenoh puts on the wire through
    /// [`Ntp64`](wz_session_core::ntp64::Ntp64), the same type the reader uses,
    /// so the fixture cannot agree with the reader on a layout the wire does not
    /// have. The `T` flag is NAMED, because a fixture that set the wrong one of
    /// the three PUT flags stopped decoding rather than losing its timestamp
    /// (R311y617 added the names on the strength of exactly that).
    /// Gated to match its only consumers: both tests that drive the delay axis
    /// live behind `network-codecs`, and an ungated fixture would be dead code
    /// the no-default lane fails on rather than a wider reach.
    #[cfg(feature = "network-codecs")]
    pub(crate) fn push_stamped(
        keyexpr: Wireexpr<'static>,
        payload: &[u8],
        stamped_ms: u64,
    ) -> Vec<u8> {
        let has_suffix = match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        };
        let n_flag = if has_suffix {
            wz_codecs::wire_const::FLAG_N_N
        } else {
            0
        };
        let word = wz_session_core::ntp64::Ntp64::from_unix(
            stamped_ms / 1000,
            ((stamped_ms % 1000) * 1_000_000) as u32,
        )
        .as_word();
        const ZID: [u8; 16] = [7u8; 16];
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n_flag,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                header: wz_codecs::msg_put::MsgPut::default().header
                    | wz_codecs::wire_const::FLAG_Z_PUT_T,
                timestamp: Some(wz_codecs::timestamp::Timestamp {
                    time: word,
                    zid_len: ZID.len() as u64,
                    zid: &ZID,
                }),
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    pub(crate) fn push(keyexpr: Wireexpr<'static>, payload: &[u8]) -> Vec<u8> {
        let has_suffix = match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        };
        let n_flag = if has_suffix {
            wz_codecs::wire_const::FLAG_N_N
        } else {
            0
        };
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n_flag,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// R311y621 (§1.4i) — the establishment ext chain that OFFERS COMPRESSION.
    ///
    /// The entry is built out of the ext codec's own types at the id
    /// `wz-session-core` names, not spelled as a byte: a fixture that writes
    /// `0x06` is a byte string wearing a struct (the R311y616 rule). The chain
    /// SERIALISER is `pub(crate)` to `wz-session-core`, so the one-entry case
    /// is written here instead of reached for — and a one-entry chain IS the
    /// entry, because `ext_chain::encode_ext_chain` sets the continuation `Z`
    /// bit on every entry BUT the last. `the_compression_offer_is_the_entry_
    /// the_ext_codec_names` is what keeps that reading honest.
    fn compression_offer() -> Vec<u8> {
        let entry: wz_codecs::ext_entry::ExtEntryOwned = wz_codecs::ext_entry::ExtEntryOwned {
            header: wz_session_core::ext_header::establishment_ext_id::COMPRESSION,
            body: wz_codecs::ext_entry::ExtEntryOwnedVariant::CodecZenohExtUnit(
                wz_codecs::ext_unit::ExtUnit::default(),
            ),
        };
        entry.as_borrowed().encode_to_vec()
    }

    /// One `T_MID_INIT` datagram trailing `ext_bytes` as its chain, through the
    /// InitBody codec's own encode.
    fn init_datagram(is_ack: bool, ext_bytes: &[u8]) -> Vec<u8> {
        let mut flags = 0u8;
        if is_ack {
            flags |= wz_codecs::wire_const::FLAG_T_INIT_A;
        }
        if !ext_bytes.is_empty() {
            flags |= wz_codecs::wire_const::FLAG_T_Z;
        }
        let mut wire = alloc::vec![flags | wz_session_core::wire_const::T_MID_INIT];
        let body = wz_codecs::init_body::InitBody {
            version: 0x09,
            // `whatami.to_wire() | ((zid_len - 1) << 4)`: Peer (0x01) with a
            // 4-byte zid. Getting this wrong makes the decoder read the wrong
            // zid width, so it is spelled out rather than guessed.
            cbyte: 0x31,
            zid: &[0xAA; 4],
            sn_res: None,
            batch_size: None,
            // A-gated: the ACK carries the cookie field, the SYN does not.
            cookie_len: if is_ack { Some(0) } else { None },
            cookie: if is_ack { Some(&[]) } else { None },
        };
        // The S (resolution present) and A (is-ack) discriminators ride the
        // parent header, so the codec takes them as arguments.
        wire.extend_from_slice(&body.encode_to_vec(0, u8::from(is_ack)));
        wire.extend_from_slice(ext_bytes);
        wire
    }

    /// One `T_MID_OPEN` datagram. INVERTED against Init: the cookie rides the
    /// SYN here, not the ACK.
    fn open_datagram(is_ack: bool) -> Vec<u8> {
        let mut flags = 0u8;
        if is_ack {
            flags |= wz_codecs::wire_const::FLAG_T_OPEN_A;
        }
        let mut wire = alloc::vec![flags | wz_session_core::wire_const::T_MID_OPEN];
        wire.extend_from_slice(
            &wz_codecs::open_body::OpenBody {
                lease: 10_000,
                initial_sn: 0,
                cookie_len: if is_ack { None } else { Some(0) },
                cookie: if is_ack { None } else { Some(&[]) },
            }
            .encode_to_vec(u8::from(is_ack)),
        );
        wire
    }

    /// One `T_MID_FRAME` datagram carrying `body` as its batch, at sn 0.
    fn frame_datagram(body: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_codecs::wire_const::FLAG_T_FRAME_R,
            // sn 0, the one-byte VLE arm `the_frame_fixture_decodes_as_the_
            // frame_it_claims` pins against the real decoder.
            0x00,
        ];
        wire.extend_from_slice(body);
        wire
    }

    /// R311y621 (§1.4i) — a capture of a session that NEGOTIATED COMPRESSION,
    /// ending in one data frame.
    ///
    /// `wz-capture` does not carry `wz-session-core/transport-compression`, so
    /// that last frame's body is lz4 this build cannot open, and
    /// `PassiveSession::batch_of` answers `Carried::Undecompressible` — the
    /// honest answer rather than a batch parsed out of compressed bytes, which
    /// would decode to confident nonsense. What the three analysis planes then
    /// do with it is what §1.4i is about.
    ///
    /// `pub(crate)` for the reason [`frame_carrying`] is: the throughput,
    /// exchange and payload planes must drive the SAME capture, and a second
    /// handshake builder in each of their test modules is the copy that drifts.
    pub(crate) fn compressed_session_dissection() -> Dissection {
        let offer = compression_offer();
        let mut d = Dissection::new();
        for (i, (from_low, message)) in [
            (true, init_datagram(false, &offer)),
            (false, init_datagram(true, &offer)),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            (true, frame_datagram(&[0xDE, 0xAD, 0xBE, 0xEF])),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &packet);
        }
        d
    }

    /// R311y645 (§4.38) — a capture whose data arrives as a COMPLETED fragment
    /// chain: a full handshake, then `record` split across two `T_MID_FRAGMENT`
    /// datagrams.
    ///
    /// The handshake is what separates this from
    /// [`midsession_fragment_dissection`]: with an InitAck observed the session
    /// has an SN resolution, so the chain is tracked and completes, and the
    /// reassembled bytes become a real `Carried::Reassembled` batch with real
    /// records in it. That is the only shape in which a record exists whose
    /// bytes were never contiguous on the wire.
    /// Gated on BOTH features, matching its consumers rather than only the one
    /// it names: the record it splits is a network record, so every test that
    /// drives it is `network-codecs`-gated too, and a fixture gated more widely
    /// than its callers is dead code in exactly the arm nothing builds locally
    /// (the R311y644 mistake, caught the same way).
    #[cfg(all(feature = "reassembly", feature = "network-codecs"))]
    pub(crate) fn reassembled_record_dissection(record: &[u8]) -> Dissection {
        let split = record.len() / 2;
        assert!(split > 0, "the record must be splittable to be fragmented");
        let fragment = |sn: u8, more: bool, piece: &[u8]| {
            let mut wire = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAGMENT
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                    | if more {
                        wz_codecs::wire_const::FLAG_T_FRAGMENT_M
                    } else {
                        0
                    },
                sn,
            ];
            wire.extend_from_slice(piece);
            wire
        };
        let mut d = Dissection::new();
        for (i, (from_low, message)) in [
            (true, init_datagram(false, &[])),
            (false, init_datagram(true, &[])),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            (true, fragment(0, true, &record[..split])),
            (true, fragment(1, false, &record[split..])),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &packet);
        }
        d
    }

    /// R311y621 (§1.4i) — a capture that STARTED MID-SESSION: a Fragment and no
    /// InitAck before it.
    ///
    /// The observer has no SN resolution, so it cannot tell a wraparound from a
    /// gap and refuses to pick a mask — `Carried::FragmentWithoutResolution`.
    /// The chain that fragment belonged to never becomes a batch, and the
    /// planes have to say so rather than report a capture with nothing in it.
    #[cfg(feature = "reassembly")]
    pub(crate) fn midsession_fragment_dissection() -> Dissection {
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_FRAGMENT
                | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                | wz_codecs::wire_const::FLAG_T_FRAGMENT_M,
            0x00,
        ];
        wire.extend_from_slice(&[0xDE, 0xAD]);
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire),
        );
        d
    }

    /// The offer above is written by hand at the CHAIN level, so what it writes
    /// is checked against the ext codec rather than trusted: one byte, whose
    /// extension identity is COMPRESSION and whose continuation bit is CLEAR.
    /// A chain that grew a Z bit would negotiate nothing and leave every
    /// counter below at zero, which reads exactly like a plane that works.
    #[test]
    fn the_compression_offer_is_the_entry_the_ext_codec_names() {
        let bytes = compression_offer();
        assert_eq!(bytes.len(), 1, "a UNIT ext is one byte: {bytes:?}");
        assert_eq!(
            wz_session_core::ext_header::ext_eid(bytes[0]),
            wz_session_core::ext_header::establishment_ext_id::COMPRESSION
        );
        assert_eq!(
            bytes[0] & wz_codecs::wire_const::FLAG_T_Z,
            0,
            "the last entry of a chain terminates it"
        );
    }

    /// THE ANCHOR the `Undecompressible` pages rest on, asserted instead of
    /// assumed.
    ///
    /// Load-bearing in a way a reader should not have to infer: a fixture that
    /// failed to negotiate, or stopped short of Established, would produce a
    /// readable batch and leave every gap counter at zero — and a test asserting
    /// "the counter is 1" would then fail for a reason that has nothing to do
    /// with the plane it is about.
    #[test]
    fn the_compressed_fixture_negotiates_compression_and_establishes() {
        let d = compressed_session_dissection();
        let flow = &d.datagram_flows()[0];
        let context = flow.session.context();
        assert_eq!(
            context.phase,
            wz_session_core::passive::SessionPhase::Established,
            "the handshake must complete: {context:?}"
        );
        assert!(
            context.compression_active(),
            "compression must be NEGOTIATED and in force: {context:?}"
        );
        assert!(
            matches!(
                flow.frames.last().map(|f| &f.carried),
                Some(wz_session_core::passive::Carried::Undecompressible)
            ),
            "the frame after it is a body this build cannot open: {:?}",
            flow.frames.last().map(|f| &f.carried)
        );
        assert_eq!(
            d.health().packets_skipped,
            0,
            "no packet may be skipped, or the planes would have a second cause"
        );
    }

    /// The same anchor for the mid-session capture: the observer must NAME the
    /// unresolvable fragment rather than merely fail to reassemble it.
    #[cfg(feature = "reassembly")]
    #[test]
    fn the_midsession_fixture_yields_a_fragment_with_no_resolution() {
        let d = midsession_fragment_dissection();
        let flow = &d.datagram_flows()[0];
        assert!(
            flow.session.context().sn_mask().is_none(),
            "no InitAck was observed, so there is no SN resolution"
        );
        assert!(
            matches!(
                flow.frames.first().map(|f| &f.carried),
                Some(wz_session_core::passive::Carried::FragmentWithoutResolution)
            ),
            "got {:?}",
            flow.frames.first().map(|f| &f.carried)
        );
        assert_eq!(d.health().packets_skipped, 0);
    }

    /// R311y643 (§1.1e) — a capture this build cannot decapsulate says WHICH
    /// link type it refused, and a healthy capture with ordinary furniture in it
    /// says something else entirely.
    ///
    /// THE FAILURE THIS ENDS. wz drives three links with no assigned libpcap
    /// DLT — unix sockets, unix pipes and serial — so a capture of one arrives
    /// under a private-use or vendor link type and is refused packet by packet.
    /// The result was an empty dissection and a plausible skip COUNT, which is
    /// indistinguishable from "this deployment carried no zenoh traffic": a
    /// wrong conclusion about a working system, reached from a correct number.
    ///
    /// The control leg is what makes the census a diagnosis rather than a
    /// second spelling of the count: an ARP packet on an ETHERNET capture is
    /// also a skip, and it must land somewhere else with no link type named.
    #[test]
    fn a_link_type_this_build_cannot_read_is_named_and_arp_is_not_it() {
        // 250 is `LINKTYPE_RTAC_SERIAL`; nothing in this build decapsulates it,
        // which is exactly the position a serial capture is in.
        let mut d = Dissection::new();
        for i in 0..3 {
            d.push_packet(250, i, &[0xAA; 20]);
        }
        let sk = d.skip_census();
        assert_eq!(sk.unsupported_link_type, 3);
        assert_eq!(
            sk.unsupported_link_types
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            alloc::vec![250],
            "the SET is the actionable fact, not the count"
        );
        assert_eq!(sk.not_ip, 0, "the reason must be the specific one");
        assert_eq!(
            sk.total(),
            d.health().packets_skipped,
            "two counts, one truth"
        );
        assert!(d.flows().is_empty() && d.datagram_flows().is_empty());

        // THE CONTROL: an ARP frame on Ethernet is skipped too, and is NOT a
        // link-type refusal. A census that folded every skip into one bucket
        // would satisfy the assertions above and be useless.
        let mut arp = Dissection::new();
        let mut frame = alloc::vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x06;
        frame.extend_from_slice(&[0u8; 28]);
        arp.push_packet(crate::link::LINKTYPE_ETHERNET, 0, &frame);
        let a = arp.skip_census();
        assert_eq!(a.not_ip, 1);
        assert_eq!(a.unsupported_link_type, 0);
        assert!(
            a.unsupported_link_types.is_empty(),
            "a readable capture names no unreadable link type"
        );
    }

    /// R311y643 (§1.1e) — the census counts EVERY skip, including the ones the
    /// capped list threw away.
    ///
    /// The trap this exists for: `skipped()` is bounded by
    /// `DissectionLimits::skipped_packets` and its overflow is dropped, so a
    /// census folded from that list would be silently short on exactly the large
    /// captures that need one. Driven with a cap of ONE so the list holds a
    /// single entry while the census holds all five.
    #[test]
    fn the_skip_census_survives_the_cap_the_skipped_list_does_not() {
        let mut d = Dissection::with_limits(DissectionLimits {
            skipped_packets: Some(1),
            ..DissectionLimits::default()
        });
        for i in 0..5 {
            d.push_packet(250, i, &[0xAA; 20]);
        }
        assert_eq!(d.skipped().len(), 1, "the list really is capped");
        assert_eq!(d.drops().skipped, 4, "and the overflow really was dropped");
        // R311y653 — and it is the LAST one, not the first. The five records
        // differ only in their packet index, so until this line a list that
        // kept the oldest passed exactly as one that kept the newest, and
        // `skipped()` is the list a reader scrolls to see what just went wrong.
        assert_eq!(
            d.skipped()[0].packet_index,
            4,
            "the surviving record must be the most recent: {:?}",
            d.skipped()
        );
        assert_eq!(
            d.skip_census().unsupported_link_type,
            5,
            "the census counted what the list could not keep"
        );
        assert_eq!(d.skip_census().total(), d.health().packets_skipped);
    }

    /// THE INTERLOCK, and the reason R311y609 had to touch two layers.
    ///
    /// A capture that lost a TCP segment held every later segment of that
    /// direction FOREVER (`tcp.rs`), so the bytes after the hole never reached
    /// `PassiveSession` at all. Fixing the zenoh framing's resynchronisation
    /// alone would have been unreachable in exactly the case that motivates
    /// it — the fix would have been provable only against a synthetic byte
    /// stream, never against a capture.
    ///
    /// Here the hole is a dropped PACKET, the way a capture loses one, and the
    /// assertion chain runs the whole way down: the assembler gives up on the
    /// gap, the spliced bytes land mid-frame, the observer says so, and it
    /// finds the framing again.
    #[test]
    fn a_dropped_packet_reaches_the_observer_and_it_resynchronises() {
        // A byte stream of small frames, chopped into segments whose size is
        // not a multiple of the frame size — so a lost segment splices the
        // stream MID-FRAME rather than tidily on a boundary.
        let stream: Vec<u8> = (0..600u32)
            .map(|i| (i % 0x80) as u8)
            .flat_map(framed_frame)
            .collect();
        const SEG: usize = 37;
        assert_ne!(
            SEG % framed_frame(0).len(),
            0,
            "a segment that held whole frames would splice on a boundary and              prove nothing"
        );
        let segments: Vec<&[u8]> = stream.chunks(SEG).collect();
        const LOST: usize = 7;

        let run = |patience: Option<usize>| {
            let mut d = Dissection::new();
            d.set_gap_patience(patience);
            for (i, seg) in segments.iter().enumerate() {
                if i == LOST {
                    continue; // the packet the capture never recorded
                }
                let pkt = tcp_packet(1000 + (i * SEG) as u32, seg);
                d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
            }
            d
        };

        // The pre-R311y609 arm: the gap is never given up on, so nothing after
        // it is ever handed to the observer.
        let held = run(None);
        let f = &held.flows()[0];
        assert_eq!(held.framing_health().gaps_forced, 0);
        assert_eq!(
            f.assembler(Direction::A).held_segments(),
            segments.len() - LOST - 1,
            "every segment after the hole is still waiting on it"
        );
        let decoded_before = f.frames.len();

        // And with the default patience: the assembler steps over the hole,
        // the observer desynchronises on the splice, and it recovers.
        let d = run(Some(4));
        let f = &d.flows()[0];
        let fh = d.framing_health();
        assert_eq!(
            (fh.gaps_forced, fh.gap_bytes_missing),
            (1, SEG as u64),
            "one gap, and it names the bytes the capture does not contain"
        );
        assert_eq!((fh.desyncs, fh.recoveries), (1, 1));
        // R311y716 (§C G1) — AND BOTH REACH THE VERDICT BY NAME. R311y715
        // severed each of the verdict's legs and found `gaps_forced` and
        // `desyncs` among the nine that bound nothing; they were unpayable
        // while the verdict was a bool, because they are COUPLED -- a forced
        // gap desynchronises the framing behind it, so no fixture trips one
        // alone and a fixture tripping both proves neither. Answering with the
        // SET is what makes this assertion possible: sever either leg and this
        // line reds on the one that went missing.
        let reasons = crate::report::CaptureReport::of(&d).reasons();
        assert!(
            reasons.contains(&crate::report::VerdictReason::GapsForced)
                && reasons.contains(&crate::report::VerdictReason::Desyncs),
            "the hole and the splice it caused must BOTH be named: {reasons:?}"
        );
        // R311y727 (N19) — and the WHOLE list. The containment claim above
        // holds while every other leg fires too, so on its own it cannot
        // notice a guard that widened.
        assert_eq!(
            reasons,
            alloc::vec![
                crate::report::VerdictReason::GapsForced,
                crate::report::VerdictReason::Desyncs
            ],
            "the forced gap and the desync it caused, and nothing else"
        );
        let resync = f.session.resync_accounting(Direction::A);
        assert_eq!(resync.desyncs, 1, "the splice is DETECTED, not decoded");
        assert_eq!(resync.recoveries, 1, "and the framing is found again");
        assert!(
            f.frames.len() > decoded_before * 4,
            "frames decoded: {} with recovery vs {decoded_before} without",
            f.frames.len()
        );
        // The recovery is reported ON a frame, so a reader sees the hole.
        let carried = f
            .frames
            .iter()
            .filter_map(|fr| fr.resync)
            .collect::<Vec<_>>();
        assert_eq!(carried.len(), 1);
        assert!(
            carried[0].skipped > 0
                && carried[0].confirmed == wz_session_core::passive::DEFAULT_RESYNC_DEPTH,
            "{:?}",
            carried[0]
        );
    }

    /// R311y610 (§4.1) — THE HOLE IS ANNOUNCED, so the reader never frames the
    /// far side of it against the near side.
    ///
    /// The interlock above proves recovery at ONE splice offset. Moving the
    /// lost packet moves the splice through every phase of the frame, and that
    /// is where R311y609's measured 45-68% loss lived: at a phase whose two
    /// spliced bytes claim a large length and whose third byte is one of the 42
    /// credible ones, the reader consumed thousands of REAL bytes as a single
    /// body and never desynchronised at all. No scan depth changes that,
    /// because nothing has told the scan to run.
    ///
    /// BOTH ARMS READ THE SAME SPLICED BYTES. The only difference is whether
    /// the layer that lost them said so, which is what makes this a measurement
    /// of the announcement rather than of the fixture.
    #[test]
    fn announcing_the_hole_stops_the_reader_swallowing_the_frames_after_it() {
        use wz_session_core::inbound::InboundFrame;
        const N: u8 = 100;
        const SEG: usize = 37;
        const PAYLOAD: usize = 24;
        let stream: Vec<u8> = (0..N)
            .flat_map(|sn| framed_frame_with_payload(sn, PAYLOAD, u32::from(sn) + 1))
            .collect();
        let unit = framed_frame_with_payload(0, PAYLOAD, 1).len();
        assert_ne!(
            SEG % unit,
            0,
            "a segment holding whole frames would splice on a boundary and \
             sweep one phase over and over"
        );
        let segments: Vec<&[u8]> = stream.chunks(SEG).collect();

        // What the assembler delivers once it steps over the hole: the two
        // runs, adjacent, with nothing in the bytes to say they were not.
        let spliced = |lost: usize| -> Vec<u8> {
            let mut out = stream[..lost * SEG].to_vec();
            out.extend_from_slice(&stream[((lost + 1) * SEG).min(stream.len())..]);
            out
        };

        // ARM 1 — through the real front end, which announces the splice.
        let announced = |lost: usize| -> Vec<u64> {
            let mut d = Dissection::new();
            d.set_gap_patience(Some(4));
            for (i, seg) in segments.iter().enumerate() {
                if i == lost {
                    continue;
                }
                let pkt = tcp_packet(1000 + (i * SEG) as u32, seg);
                d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
            }
            d.finish();
            d.flows()[0]
                .frames
                .iter()
                .filter_map(|f| match &f.frame {
                    Ok(InboundFrame::Frame { sn, .. }) => Some(*sn),
                    _ => None,
                })
                .collect()
        };

        // ARM 2 — the same bytes handed over as one contiguous run, which is
        // what every caller did before R311y610.
        let unannounced = |lost: usize| -> Vec<u64> {
            let mut s = wz_session_core::passive::PassiveSession::new();
            s.push(Direction::A, &spliced(lost));
            let mut out = Vec::new();
            loop {
                match s.next_frame(Direction::A) {
                    Ok(f) => {
                        if let Ok(InboundFrame::Frame { sn, .. }) = &f.frame {
                            out.push(*sn);
                        }
                    }
                    Err(PassiveStall::NeedMoreBytes) => break,
                    // Announced once, at detection; the calls after it scan.
                    Err(PassiveStall::Desynchronised { .. }) => {}
                }
            }
            out
        };

        let mut worst_announced = usize::MAX;
        let mut worst_unannounced = usize::MAX;
        let mut worst_at = 0usize;
        for lost in 1..30 {
            let a = announced(lost);
            assert!(
                a.windows(2).all(|w| w[0] < w[1]) && a.iter().all(|sn| *sn < u64::from(N)),
                "lost packet {lost} produced a fabricated or out-of-order \
                 sequence, which is the mis-framing this test exists to catch: \
                 {a:?}"
            );
            assert!(
                a.len() + 8 >= usize::from(N),
                "lost packet {lost}: only {} of {N} frames survived a {SEG}-byte \
                 hole; sns {a:?}",
                a.len()
            );
            worst_announced = worst_announced.min(a.len());
            let u = unannounced(lost).len();
            if u < worst_unannounced {
                worst_unannounced = u;
                worst_at = lost;
            }
        }
        // THE NEGATIVE ARM. Without it the assertion above is a claim about
        // this fixture rather than about the announcement. Measured on the
        // first run: 3 frames of 100 survive unannounced against 97 announced,
        // and the collapse is total rather than partial because a prefix read
        // off payload bytes claims 32 KiB on average — more than this whole
        // capture holds, so the reader waits for bytes that never come.
        assert!(
            worst_unannounced * 4 < worst_announced,
            "the same bytes unannounced kept {worst_unannounced} frames at \
             worst (lost packet {worst_at}) against {worst_announced} \
             announced — if these are close the fixture never reaches the \
             phase where the swallow happens, and it is proving nothing"
        );
    }

    /// R311y610 (§4.2) — a capture that ENDS with a gap open.
    ///
    /// The patience is a count of LATER segments, so a file that stops within
    /// one of a hole never spends it and the tail stays held forever.
    /// `force_oldest_gap` shipped in R311y609 with no caller for exactly this
    /// reason: "no more packets are coming" is a fact only the caller has.
    #[test]
    fn a_capture_that_ends_on_an_open_gap_is_finished_by_the_caller() {
        let stream: Vec<u8> = (0..40u8).flat_map(framed_frame).collect();
        const SEG: usize = 37;
        let segments: Vec<&[u8]> = stream.chunks(SEG).collect();
        const LOST: usize = 5;

        let mut d = Dissection::new();
        for (i, seg) in segments.iter().enumerate() {
            if i == LOST {
                continue;
            }
            let pkt = tcp_packet(1000 + (i * SEG) as u32, seg);
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        // The default patience is far longer than this capture, so the hole is
        // still open and everything behind it is still held.
        let held = d.flows()[0].assembler(Direction::A).held_segments();
        assert_eq!(
            held,
            segments.len() - LOST - 1,
            "the whole tail should still be waiting on the gap"
        );
        let before = d.flows()[0].frames.len();
        assert_eq!(d.framing_health().gaps_forced, 0);

        assert_eq!(d.finish(), 1, "one gap was open, so one gap is forced");
        let fh = d.framing_health();
        assert_eq!((fh.gaps_forced, fh.gap_bytes_missing), (1, SEG as u64));
        assert_eq!(
            d.flows()[0].assembler(Direction::A).held_segments(),
            0,
            "nothing is left waiting on a gap that was given up on"
        );
        assert_eq!(
            (fh.desyncs, fh.recoveries),
            (1, 1),
            "the tail is not merely delivered, it is delivered as a DISCONTINUITY"
        );
        assert!(
            d.flows()[0].frames.len() > before + held,
            "frames after finish: {} vs {before} before, over {held} released \
             segments",
            d.flows()[0].frames.len()
        );
        // Idempotent: a second call has no gap left to force.
        assert_eq!(d.finish(), 0);
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
    pub(crate) fn scout_message() -> Vec<u8> {
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
    pub(crate) const SCOUT_GROUP: [u8; 4] = [224, 0, 0, 224];

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

    /// R311y608 — THE OTHER HALF OF THE EXCHANGE, and it does not come back on
    /// the group it was asked on.
    ///
    /// zenoh's scout responder answers from a UNICAST socket straight to the
    /// asker — `socket.send_to(wbuf.as_slice(), peer)` where `peer` is the
    /// address the SCOUT arrived FROM, on the socket
    /// `get_best_match(&peer.ip(), ucast_sockets)` picks
    /// (`zenoh/src/net/runtime/orchestrator.rs:1167-1180`). So a HELLO's
    /// destination is unicast, R311y607's destination-is-multicast half is
    /// false for it, and `S_MID_HELLO` is `0x02` — the same byte as
    /// `T_MID_OPEN`. Every HELLO in every capture came back a confident `Open`:
    /// the reply half of scouting was misread exactly the way the request half
    /// was before R311y607.
    ///
    /// What separates them is the EXCHANGE, which is the only thing that can:
    /// the reply is addressed to the endpoint the request was sent from, and
    /// pico reads it on the very socket it scouted from
    /// (`_z_link_recv_zbuf(&zl, ..)` on the link `__z_scout_loop` opened,
    /// `src/session/scout.c:54-68`). A passive observer has no socket, so it
    /// keeps the correlation instead.
    #[test]
    fn a_hello_is_still_an_answer_after_the_cap_evicted_the_scouts_flow() {
        // R311y713 (§B9) — the two mechanisms have never been driven together.
        // The asker memory is dissection-wide precisely BECAUSE the exchange
        // spans two flows, and the flow cap deletes flows: if the memory had
        // been hung off the scout's flow, an eviction between the SCOUT and
        // the HELLO would turn the answer back into the `Open` misread
        // R311y608 closed. That is a real sequence on a live tap — a busy host
        // recycles slots between a scout and its answer — and nothing pinned
        // that the two do not interact.
        let asker = [192, 168, 1, 5];
        let asker_port = 43210;
        let mut d = Dissection::with_limits(DissectionLimits {
            // One datagram flow at a time: the scout's flow CANNOT survive to
            // the hello, so a rule that needed it would have to fail.
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(asker, asker_port, SCOUT_GROUP, 7446, &scout_message()),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet(
                [192, 168, 1, 9],
                7447,
                asker,
                asker_port,
                &hello_with_locators(),
            ),
        );
        assert_eq!(
            d.drops().flows,
            1,
            "the fixture must actually evict the scout's flow"
        );
        let reply = &d.datagram_flows()[0];
        assert_eq!(reply.scouting.len(), 1, "the HELLO must be reported");
        assert!(
            matches!(&reply.scouting[0].frame, Ok(ScoutingFrame::Hello { .. })),
            "an evicted scout flow must not turn its answer back into an \
             Open: {:?}",
            reply.scouting[0].frame
        );
        assert!(
            reply.frames.is_empty(),
            "and it must not enter the transport list: {:?}",
            reply.frames
        );
    }

    #[test]
    fn the_hello_answering_a_scout_comes_back_unicast_and_is_still_a_hello() {
        let asker = [192, 168, 1, 5];
        let asker_port = 43210;
        let scout = udp_packet(asker, asker_port, SCOUT_GROUP, 7446, &scout_message());
        // The responder speaks from its own unicast locator port, to the exact
        // (address, port) the scout came from.
        let hello = udp_packet(
            [192, 168, 1, 9],
            7447,
            asker,
            asker_port,
            &hello_with_locators(),
        );

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &scout);
        d.push_packet(LINKTYPE_ETHERNET, 1, &hello);

        // Two flows: the scout's is toward the group, the hello's is between
        // the two hosts. They are different keys and that is the point — a
        // per-flow rule could never have connected them.
        assert_eq!(d.datagram_flows().len(), 2, "{:?}", d.datagram_flows());
        let reply = d
            .datagram_flows()
            .iter()
            .find(|f| f.flow.high.addr() == [192, 168, 1, 9])
            .expect("the reply flow, the one with no multicast endpoint");
        assert!(
            reply.frames.is_empty(),
            "a HELLO must not enter the transport list: {:?}",
            reply.frames
        );
        assert_eq!(reply.scouting.len(), 1, "the HELLO must be reported");
        match &reply.scouting[0].frame {
            Ok(ScoutingFrame::Hello { body, .. }) => {
                assert_eq!(body.version, 0x09);
                assert_eq!(body.whatami(), 0x01, "the whatami must survive");
                let locators = body.locators.as_ref().expect("the L flag was set");
                assert_eq!(locators.len(), 1);
                assert_eq!(
                    locators[0].locator.as_str(),
                    PEER_LOCATOR,
                    "the locator list is the whole point of a HELLO — it is how \
                     the asker learns where to connect"
                );
            }
            other => panic!("the unicast HELLO decoded as {other:?}"),
        }

        // R311y608 (closing the R311y607 carry): the scouting route does not
        // merely produce a different VALUE, it must not move session state.
        // Asserted on the observer rather than on the frame count, because a
        // fold spliced into the scouting branch would leave both lists exactly
        // as they are here and change only this.
        assert!(
            matches!(
                reply.session.context().phase,
                wz_session_core::passive::SessionPhase::Unseen
            ),
            "a scouting message has no session to advance: {:?}",
            reply.session.context()
        );
    }

    /// THE MISREAD, stated as an assertion that PASSES ON THE BROKEN BUILD.
    ///
    /// A real HELLO sets `FLAG_S_HELLO_L` for its locator list, and that bit is
    /// `0x20` — the same bit `FLAG_T_OPEN_A` is (`wz-codecs/src/lib.rs:554`
    /// and `:701`). So the header zenoh puts on the wire, read in the transport
    /// namespace, is not a malformed anything: it is a well-formed OpenAck,
    /// whose `lease` is the HELLO's version byte. Before R311y608 that is what
    /// every answered scout produced, and this arm is what says the ambiguity
    /// is real rather than asserted.
    #[test]
    fn the_same_hello_bytes_read_as_transport_are_a_confident_open_ack() {
        let misread = wz_session_core::inbound::parse_inbound(&hello_with_locators())
            .expect("this is the defect: it does not fail, it misreads");
        assert!(
            matches!(
                misread,
                wz_session_core::inbound::InboundFrame::Open { is_ack: true, .. }
            ),
            "a HELLO read in the transport namespace comes back an OpenAck, not \
             an error: {misread:?}"
        );
    }

    /// The NEGATIVE arm on the correlation: the SAME unicast HELLO bytes, with
    /// no SCOUT ever observed from that endpoint, stay on the transport side.
    ///
    /// This is what stops the fix from becoming the previous defect pointing
    /// the other way. `0x02` toward a unicast peer is `T_MID_OPEN` — the second
    /// message of every `udp/...` handshake — and a rule that read the MID
    /// alone would swallow all of them while the positive test above still
    /// passed.
    ///
    /// It also states the residual honestly: with no exchange in the capture
    /// there is no evidence, and an observer that guessed "scouting" here would
    /// be asserting something the bytes do not carry.
    #[test]
    fn an_unsolicited_unicast_0x02_is_still_an_open() {
        let hello = udp_packet(
            [192, 168, 1, 9],
            7447,
            [192, 168, 1, 5],
            43210,
            &hello_with_locators(),
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &hello);

        let flow = &d.datagram_flows()[0];
        assert!(
            flow.scouting.is_empty(),
            "with no SCOUT observed there is no evidence of an exchange"
        );
        assert_eq!(flow.frames.len(), 1, "it stays on the transport side");
        assert!(
            matches!(
                flow.frames[0].frame,
                Ok(wz_session_core::inbound::InboundFrame::Open { .. })
            ),
            "an unsolicited 0x02 is an Open: {:?}",
            flow.frames[0].frame
        );
    }

    /// The correlation is keyed on the ENDPOINT that asked, not on the address
    /// — two processes on one host scout from different ports, and a HELLO
    /// answering one of them is not evidence about the other.
    #[test]
    fn a_hello_to_a_port_that_never_scouted_is_not_an_answer() {
        let asker = [192, 168, 1, 5];
        let scout = udp_packet(asker, 43210, SCOUT_GROUP, 7446, &scout_message());
        // Same host, a DIFFERENT port: an ordinary udp session's Open.
        let hello = udp_packet([192, 168, 1, 9], 7447, asker, 51000, &hello_with_locators());

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &scout);
        d.push_packet(LINKTYPE_ETHERNET, 1, &hello);

        let reply = d
            .datagram_flows()
            .iter()
            .find(|f| f.flow.high.addr() == [192, 168, 1, 9])
            .expect("the reply flow");
        assert!(
            reply.scouting.is_empty(),
            "the scout came from :43210 and this is addressed to :51000"
        );
        assert_eq!(reply.frames.len(), 1);
    }

    /// The bound on remembered askers BITES and SAYS SO — and what it costs is
    /// not a lost record but a changed READING: the forgotten asker's next
    /// answer decodes as an `Open` again.
    #[test]
    fn forgetting_an_asker_is_counted_because_it_changes_a_later_reading() {
        let mut d = Dissection::with_limits(DissectionLimits {
            max_scout_askers: Some(1),
            ..DissectionLimits::default()
        });
        let first = [192, 168, 1, 5];
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(first, 43210, SCOUT_GROUP, 7446, &scout_message()),
        );
        // A second asker evicts the first.
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet([192, 168, 1, 6], 43211, SCOUT_GROUP, 7446, &scout_message()),
        );
        assert_eq!(d.drops().scout_askers, 1, "the bound must not be silent");
        assert!(d.drops().any());

        // The answer to the FORGOTTEN asker is back to being an Open.
        d.push_packet(
            LINKTYPE_ETHERNET,
            2,
            &udp_packet([192, 168, 1, 9], 7447, first, 43210, &hello_with_locators()),
        );
        let reply = d
            .datagram_flows()
            .iter()
            .find(|f| f.flow.high.addr() == [192, 168, 1, 9])
            .expect("the reply flow");
        assert!(
            reply.scouting.is_empty(),
            "this is the COST of the bound, and the counter above is what \
             separates it from the defect coming back"
        );
    }

    /// An Init body the transport decoder accepts, on the wire.
    pub(crate) fn init_message() -> Vec<u8> {
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_INIT, 0x09, 0x38];
        wire.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        wire
    }

    /// Ethernet carrying pico's raweth framing, built with `raweth_link`'s OWN
    /// framer so the fixture cannot agree with a hand-laid reading.
    ///
    /// The destination MAC is pico's DEFAULT mapping,
    /// `aa:bb:cc:dd:ee:ff` (`vendor/zenoh-pico/src/transport/raweth/link.c:66`)
    /// — deliberately, because its I/G bit is CLEAR. Any rule that judged this
    /// link by the address would call it unicast.
    pub(crate) fn raweth_packet(payload: &[u8]) -> Vec<u8> {
        use wz_session_core::raweth_link::{frame, RawEthHeader, DEFAULT_ETHTYPE};
        let h = RawEthHeader::new(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x30, 0x03, 0xC8, 0x37, 0x25, 0xA1],
            DEFAULT_ETHTYPE,
            payload.len() as u16,
        );
        frame(&h, payload).expect("raweth frame")
    }

    /// R311y608 — an INIT on a raweth link is REPORTED and NOT FOLDED.
    ///
    /// pico gives every raweth link `Z_LINK_CAP_TRANSPORT_RAWETH`
    /// (`raweth/link.c:476`) and routes that capability into
    /// `_z_new_transport_multicast` (`multicast/transport.c:42-45`), whose
    /// receive path takes an INIT and does nothing with it (`multicast/rx.c`
    /// `:493-504`). So no participant on this link has a session from these
    /// bytes — and an observer that folded them would hold a peer's zid, lease
    /// and negotiated capabilities for a session that does not exist, and would
    /// judge every later frame against that fiction.
    ///
    /// The discriminator is the LINK TYPE and it has to be: the destination MAC
    /// here is pico's own default, whose I/G bit is clear.
    #[test]
    fn an_init_on_a_raweth_link_is_reported_but_never_folded() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &raweth_packet(&init_message()));

        let flow = &d.datagram_flows()[0];
        assert_eq!(flow.frames.len(), 1, "it must still be SHOWN");
        assert!(
            matches!(
                flow.frames[0].frame,
                Ok(wz_session_core::inbound::InboundFrame::Init { .. })
            ),
            "the bytes decode — that was never the problem: {:?}",
            flow.frames[0].frame
        );
        assert!(
            flow.frames[0].inadmissible_on_link,
            "and the report must say the link cannot carry it"
        );
        assert!(
            matches!(
                flow.session.context().phase,
                wz_session_core::passive::SessionPhase::Unseen
            ),
            "no session may come into existence from a message pico discards: \
             {:?}",
            flow.session.context()
        );
    }

    /// The NEGATIVE arm: everything raweth actually carries still folds. A
    /// guard that suppressed the whole link would be a worse defect than the
    /// one it replaced — raweth's traffic IS the multicast transport's
    /// (JOIN, FRAME, KEEP_ALIVE), and pico handles all of it.
    #[test]
    fn a_join_on_a_raweth_link_is_admissible() {
        let join = wz_codecs::join::Join {
            version: 0x09,
            cbyte: (3 << 4) | 0x01,
            zid: &[1, 2, 3, 4],
            sn_res: None,
            batch_size: None,
            lease: 10_000,
            next_sn_reliable: 7,
            next_sn_best_effort: 9,
        };
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_JOIN];
        wire.extend_from_slice(&join.encode_to_vec(0));

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &raweth_packet(&wire));

        let flow = &d.datagram_flows()[0];
        assert_eq!(flow.frames.len(), 1);
        assert!(
            !flow.frames[0].inadmissible_on_link,
            "a JOIN is exactly what this link exists to carry: {:?}",
            flow.frames[0].frame
        );
    }

    /// The same INIT over UNICAST UDP still establishes a session — the guard
    /// must key on the link and not on the message.
    #[test]
    fn the_same_init_over_unicast_udp_still_folds() {
        let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &init_message());
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);

        let flow = &d.datagram_flows()[0];
        assert!(!flow.frames[0].inadmissible_on_link);
        assert!(
            !matches!(
                flow.session.context().phase,
                wz_session_core::passive::SessionPhase::Unseen
            ),
            "a unicast Init DOES open a session: {:?}",
            flow.session.context()
        );
    }

    /// The NEGATIVE arm on the MID half: the SAME byte `0x01` toward a
    /// UNICAST peer is an ordinary Init and must stay one. A discriminator
    /// that keyed on the MID alone would swallow the start of every `udp/...`
    /// session, and the positive test above would still pass.
    #[test]
    fn a_unicast_init_is_still_an_init() {
        let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &init_message());
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
    /// R311y611 (§1.4b) — the census's message list, shared by the three
    /// framings that carry it.
    ///
    /// Extracted so the datagram, stream and WebSocket censuses cannot drift
    /// apart: a MID added here is demanded of all three, and a census that
    /// covered one link kind is exactly how the stream path went unchecked
    /// from R311y607 to R311y611.
    pub(crate) fn transport_census() -> Vec<(&'static str, Vec<u8>)> {
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
        #[allow(unused_mut)] // the `reassembly` arm below is what mutates it
        let mut census = alloc::vec![
            ("Init", init),
            ("Open", open),
            ("Close", close),
            ("KeepAlive", keep_alive),
            ("Frame", frame),
            ("Join", join),
        ];
        // R311y609 — FRAGMENT is the one MID whose decoder is behind a
        // wz-capture feature (`reassembly`, default-on), so a
        // `--no-default-features` build genuinely cannot name it and the
        // census must not demand it. Gated rather than dropped: without the
        // arm, the default build would stop checking the MID this crate is
        // most likely to lose.
        //
        // This surfaced only once the crate COMPILED without its default
        // feature — before that the census never ran there at all.
        #[cfg(feature = "reassembly")]
        census.push(("Fragment", fragment));
        #[cfg(not(feature = "reassembly"))]
        let _ = fragment;
        census
    }

    /// R311y607 — see [`transport_census`]. The DATAGRAM half.
    #[test]
    fn every_mid_on_a_datagram_link_is_named_rather_than_unknown() {
        use wz_session_core::inbound::InboundFrame;

        for (name, wire) in transport_census() {
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

    /// R311y611 (§1.4b) — THE STREAM HALF, which the R311y607 census did not
    /// cover and which asks one question more.
    ///
    /// A datagram link hands `parse_inbound` a whole message and is done. A
    /// stream link consults a SECOND list first — the credible-header gate
    /// R311y609 added for resynchronisation — and a MID the decoder can name
    /// but that gate refuses does not merely go unnamed here: the reader calls
    /// it loss of framing and skips forward. The two lists are pinned against
    /// each other in `wz-session-core`
    /// (`the_header_gate_and_the_decoder_disagree_only_on_reserved_bits`);
    /// this drives the wiring that consults them.
    ///
    /// `desyncs == 0` is therefore the assertion that is new here. A census
    /// that only checked for `Unknown` would pass while every message in it
    /// desynchronised the reader, because a desynchronised direction produces
    /// no frame to be Unknown.
    #[test]
    fn every_mid_on_a_stream_link_is_named_rather_than_unknown() {
        use wz_session_core::inbound::InboundFrame;

        for (name, wire) in transport_census() {
            let mut framed = (wire.len() as u16).to_le_bytes().to_vec();
            framed.extend_from_slice(&wire);
            let mut d = Dissection::new();
            d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));

            let flow = &d.flows()[0];
            assert_eq!(
                flow.session.resync_accounting(Direction::A).desyncs,
                0,
                "{name} desynchronised a synchronised reader — its header byte \
                 is one the decoder names and the credible-header gate refuses"
            );
            assert_eq!(flow.frames.len(), 1, "{name} produced no frame at all");
            let f = &flow.frames[0];
            assert_eq!(f.prefix_width, 2, "{name} read the wrong framing");
            assert_eq!(
                f.reserved_header_bits, 0,
                "{name}'s own fixture sets a reserved bit"
            );
            match &f.frame {
                Ok(InboundFrame::Unknown { mid }) => panic!(
                    "{name} (MID {mid:#04x}) is on zenoh's wire and this build \
                     cannot name it over a STREAM link"
                ),
                Ok(_) => {}
                Err(e) => panic!("{name} failed to decode on a stream: {e:?}"),
            }
        }
    }

    /// R311y613 (§1.4b) — the NETWORK namespace's census list, built by each
    /// record's own codec exactly as [`transport_census`] is.
    ///
    /// The transport census asks whether the FRAME is named. It cannot ask
    /// anything about what the frame CARRIES, because a Frame whose batch
    /// decoded to nothing at all is still `Ok(InboundFrame::Frame { .. })` —
    /// which is why three rounds of transport censuses passed over a build that
    /// could not name a single data-plane message.
    #[cfg(feature = "network-codecs")]
    pub(crate) fn network_census() -> Vec<(&'static str, Vec<u8>)> {
        use wz_codecs::wire_const::FLAG_N_N;
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_local::WireexprLocal;

        // Every record is `Codec::default()` — the generated `Default` bakes
        // that codec's own wire MID into the header byte — with only the fields
        // the census needs set. Nothing here is a hand-laid byte string.
        let literal = |s: &'static str| Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(s.len() as u64),
                suffix: Some(s),
            }),
        };

        // `..Default::default()` on every one, and each named `header` derived
        // from that same default rather than written as a literal. The generated
        // `Default` bakes the codec's own wire MID into the header byte, and a
        // hand-written `header: 0x1D | 0x20` would be a byte string again — the
        // exact way a fixture has three times lost a flag `Default` was baking.
        //
        // R311y616 (§4.10) — the flag half of that same rule, finally: the `N`
        // bit is `wire_const::FLAG_N_N` and no longer the literal `0x20` these
        // three lines had spelled since R311y613. R311y615 named the constant
        // and left the fixtures writing the number; a constant with one
        // consumer is a naming exercise, not a single source.
        let push = wz_codecs::push::Push {
            // N: the keyexpr carries a suffix.
            header: wz_codecs::push::Push::default().header | FLAG_N_N,
            keyexpr: literal("census/push"),
            ..Default::default()
        }
        .encode_to_vec();
        let request = wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | FLAG_N_N,
            rid: 1,
            keyexpr: literal("census/request"),
            ..Default::default()
        }
        .encode_to_vec();
        let response = wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header | FLAG_N_N,
            request_id: 1,
            keyexpr: literal("census/response"),
            ..Default::default()
        }
        .encode_to_vec();
        let response_final = wz_codecs::response_final::ResponseFinal {
            request_id: 1,
            ..Default::default()
        }
        .encode_to_vec();
        let declare = wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    header: wz_session_core::wire_const::D_MID_KEXPR
                        | wz_session_core::wire_const::FLAG_D_N,
                    id: 1,
                    keyexpr: literal("census/declare"),
                },
            ),
            ..Default::default()
        }
        .encode_to_vec();
        let interest = wz_codecs::interest::Interest {
            interest_id: 1,
            body: None,
            ..Default::default()
        }
        .encode_to_vec();
        let oam = wz_codecs::oam::Oam::default().encode_to_vec();

        alloc::vec![
            ("Push", push),
            ("Request", request),
            ("Response", response),
            ("ResponseFinal", response_final),
            ("Declare", declare),
            ("Interest", interest),
            ("Oam", oam),
        ]
    }

    /// Wrap one network record in the transport Frame that carries it on the
    /// wire — the same envelope [`transport_census`]'s `Frame` entry uses,
    /// with a real batch in place of its two filler bytes.
    ///
    /// R311y621 (§1.1k) — UNGATED. It composes a MID byte, a zero SN and a
    /// slice, none of which needs a codec feature, and the build that cannot
    /// DECODE the record inside is exactly the build whose reach §1.1k asks
    /// about.
    pub(crate) fn frame_carrying(record: &[u8]) -> Vec<u8> {
        let mut w = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
        w.extend_from_slice(record);
        w
    }

    /// R311y630 (§14.1) — the undefined-mandatory-extension count REACHES the
    /// capture layer, on BOTH link kinds, and reaches the export.
    ///
    /// Both kinds because the module doc claims both, and the claim is exactly
    /// the sort a single-path test leaves standing: `reserved_headers` beside
    /// it IS datagram-only, because the credible-header gate refuses those
    /// bytes on a stream, and it would be easy to assume the same asymmetry
    /// here. It does not hold — the gate judges the transport header and says
    /// nothing about the chain behind it — so a stream link decodes such a
    /// frame exactly as a datagram link does, and this drives one of each to
    /// say so rather than to assume it.
    ///
    /// The counter is deliberately absent from `is_complete`, and the last
    /// assertion pins that: it is a fact about the SENDER, and a report that
    /// called itself incomplete because a peer misbehaved would be measuring
    /// the wrong thing.
    #[test]
    fn an_undefined_mandatory_extension_reaches_the_capture_layer_on_both_links() {
        // KEEP_ALIVE + Z, then one ext: id 0x4, UNIT, mandatory, terminator.
        let offender = alloc::vec![
            wz_session_core::wire_const::T_MID_KEEP_ALIVE | wz_session_core::wire_const::FLAG_T_Z,
            0x14
        ];
        // The same chain without the mandatory marker — the control.
        let clean = alloc::vec![offender[0], 0x04];

        for (name, wire, expected) in [("offender", &offender, 1u64), ("control", &clean, 0u64)] {
            let mut datagram = Dissection::new();
            datagram.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire),
            );
            assert_eq!(
                datagram.framing_health().undefined_mandatory_exts,
                expected,
                "{name}: datagram link"
            );

            let mut stream = Dissection::new();
            let mut framed = alloc::vec![wire.len() as u8, 0];
            framed.extend_from_slice(wire);
            stream.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(0, &framed));
            assert_eq!(
                stream.framing_health().undefined_mandatory_exts,
                expected,
                "{name}: stream link — the credible-header gate judges the \
                 header, not the chain behind it"
            );

            // The export carries it, in both renderings.
            let report = crate::report::CaptureReport::of(&datagram);
            assert!(
                report
                    .to_json()
                    .contains(&alloc::format!("\"undefined_mandatory_exts\":{expected}")),
                "{name}: the JSON must carry the field unconditionally"
            );
            assert_eq!(
                report.to_text().contains("undefined-mandatory-extension"),
                expected > 0,
                "{name}: the text rendering prints it only when non-zero"
            );
            assert!(
                report.is_complete(),
                "{name}: a misbehaving SENDER does not make this reader's rows \
                 short, and `is_complete` must not claim it does"
            );
        }
    }

    /// R311y631 (§1.2b) — the UNACCOUNTED-BYTES counter reaches the capture
    /// layer on both link kinds, and both renderings of the document.
    ///
    /// The half R311y631's own probe found missing: zeroing the session-level
    /// increment reddened two `wz-session-core` tests and left every
    /// `wz-capture` test green, which is the signature of a counter that is
    /// wired but not witnessed.
    ///
    /// The offender is the smallest batch whose tail cannot be measured — a
    /// KeepAlive, then a byte no MID names. `0x00` is not a transport MID
    /// (`wz-codecs`'s space starts at `T_MID_INIT` = `0x01`), so nothing can
    /// say where that candidate ends and the two bytes behind the KeepAlive are
    /// unreadable rather than merely unread.
    ///
    /// Both link kinds, because the two ingestion paths reach the walk by
    /// different routes and a counter proved on one is a counter proved on
    /// half: the stream side's credible-header gate judges the FIRST header
    /// byte of an envelope and has nothing to say about what follows the first
    /// message.
    #[test]
    fn an_unwalkable_batch_tail_reaches_the_capture_layer_on_both_links() {
        let offender = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE, 0x00, 0x11];
        // The same KeepAlive with a MEASURABLE message behind it — the control,
        // and the arm that would stay at zero if the walk simply gave up.
        let clean = alloc::vec![
            wz_session_core::wire_const::T_MID_KEEP_ALIVE,
            wz_session_core::wire_const::T_MID_KEEP_ALIVE
        ];

        // R311y728 (N18) — THE SMALLEST EVIDENCE. Both arms above lose more
        // than one byte, so a guard reading `> 1` where `> 0` was meant would
        // call this capture whole and every test would agree with it: the
        // boundary sweep measured exactly that and this arm is what kills it.
        // One trailing byte is the least a batch can be short by.
        let smallest = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE, 0x00];

        for (name, wire, expected, frames) in [
            ("offender", &offender, 2u64, 1usize),
            ("smallest", &smallest, 1u64, 1usize),
            ("control", &clean, 0u64, 2usize),
        ] {
            let mut datagram = Dissection::new();
            datagram.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire),
            );
            assert_eq!(
                datagram.framing_health().unaccounted_batch_bytes,
                expected,
                "{name}: datagram link"
            );
            assert_eq!(
                datagram.datagram_flows()[0].frames.len(),
                frames,
                "{name}: and only the messages it could place are reported"
            );

            let mut stream = Dissection::new();
            let mut framed = alloc::vec![wire.len() as u8, 0];
            framed.extend_from_slice(wire);
            stream.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(0, &framed));
            assert_eq!(
                stream.framing_health().unaccounted_batch_bytes,
                expected,
                "{name}: stream link — a length prefix delimits a BATCH, and \
                 the credible-header gate reads only its first header byte"
            );
            assert_eq!(
                stream.flows()[0].frames.len(),
                frames,
                "{name}: the stream half reports the same set"
            );

            let report = crate::report::CaptureReport::of(&datagram);
            assert!(
                report
                    .to_json()
                    .contains(&alloc::format!("\"unaccounted_batch_bytes\":{expected}")),
                "{name}: the JSON must carry the field unconditionally"
            );
            assert_eq!(
                report.to_text().contains("left unaccounted for"),
                expected > 0,
                "{name}: the text rendering prints it only when non-zero"
            );
            // R311y725 (N2) — and the leg is named, not merely counted. A
            // witness that asserts `is_complete` alone cannot say WHICH leg it
            // trips, which is the state `verdict_reason_lint` measured.
            assert_eq!(
                report
                    .reasons()
                    .contains(&crate::report::VerdictReason::UnaccountedBatchBytes),
                expected > 0,
                "{name}: the batch shortfall is this fixture's own leg: {:?}",
                report.reasons()
            );
            // R311y727 (N19) -- and the WHOLE list, not just this leg.
            assert_eq!(
                report.reasons(),
                if expected > 0 {
                    alloc::vec![crate::report::VerdictReason::UnaccountedBatchBytes]
                } else {
                    alloc::vec![]
                },
                "{name}: the batch shortfall is the whole of this verdict"
            );
            assert_eq!(
                report.is_complete(),
                expected == 0,
                "{name}: unlike `reserved_headers`, this one IS a shortfall in \
                 this reader's rows -- bytes it could not read at all"
            );
        }
    }

    /// R311y613 (§1.4b) — THE MISSING HALF: every MID zenoh puts INSIDE a
    /// frame's batch is named by this build.
    ///
    /// # What this measures that no existing gate did
    ///
    /// `wz-capture` selects its `wz-session-core` features by hand, and the
    /// R311y607 census gates that list against the TRANSPORT MID space only.
    /// The network space is dispatched by a second, independent set of `#[cfg]`
    /// arms (`network_message::decode_one_record`), and a MID missing an arm
    /// there does not go merely unnamed: the walk absorbs the REST OF THE BATCH
    /// verbatim and halts, so one unfeatured record makes every record behind
    /// it in the same frame invisible too.
    ///
    /// That is the state this test was written to red on, and did: Push,
    /// Request, Response, ResponseFinal and Declare — the whole pub/sub and
    /// query plane — decoded as `Unknown { mid }` with `halt = UnknownMid`,
    /// while every transport census stayed green because the FRAME around them
    /// was named perfectly.
    ///
    /// `halt.is_none()` is therefore load-bearing beside the `Unknown` check:
    /// a batch that halts has stopped reading, and a census that only looked at
    /// `messages[0]` would pass on a build that reads exactly one record per
    /// frame and drops the rest.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn every_network_mid_inside_a_frame_is_named_rather_than_unknown() {
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::passive::Carried;

        for (name, record) in network_census() {
            let wire = frame_carrying(&record);
            let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
            let mut d = Dissection::new();
            d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
            let flow = &d.datagram_flows()[0];
            assert_eq!(flow.frames.len(), 1, "{name}: the frame never arrived");
            match &flow.frames[0].carried {
                Carried::Batch(batch) => {
                    assert_eq!(
                        batch.halt, None,
                        "{name}: the batch walk halted — every record behind it \
                         in this frame is invisible to the reader"
                    );
                    assert_eq!(
                        batch.messages.len(),
                        1,
                        "{name}: expected exactly the one record the fixture put there"
                    );
                    if let NetworkMessage::Unknown { mid, .. } = &batch.messages[0] {
                        panic!(
                            "{name} (network MID {mid:#04x}) is on zenoh's wire \
                             and this build cannot name it — a codec is missing \
                             from wz-capture's wz-session-core feature list"
                        );
                    }
                }
                other => panic!("{name}: the frame carried {other:?}, not a batch"),
            }
        }
    }

    /// R311y613 — and the same census over a STREAM link, for the reason
    /// R311y611 gave when it took the transport census to three framings: the
    /// batch is reached through a different path on each, and a census that
    /// covered one link kind is exactly how the network space went unchecked
    /// for six rounds.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn every_network_mid_inside_a_frame_is_named_over_a_stream_too() {
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::passive::Carried;

        for (name, record) in network_census() {
            let wire = frame_carrying(&record);
            let mut framed = (wire.len() as u16).to_le_bytes().to_vec();
            framed.extend_from_slice(&wire);
            let mut d = Dissection::new();
            d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));

            let flow = &d.flows()[0];
            assert_eq!(
                flow.session.resync_accounting(Direction::A).desyncs,
                0,
                "{name} desynchronised a synchronised stream reader"
            );
            assert_eq!(flow.frames.len(), 1, "{name}: the frame never arrived");
            match &flow.frames[0].carried {
                Carried::Batch(batch) => {
                    assert_eq!(batch.halt, None, "{name}: the batch walk halted");
                    if let NetworkMessage::Unknown { mid, .. } = &batch.messages[0] {
                        panic!(
                            "{name} (network MID {mid:#04x}) is unnamed over a \
                             STREAM link"
                        );
                    }
                }
                other => panic!("{name}: the frame carried {other:?}, not a batch"),
            }
        }
    }

    /// R311y607 — the capture tool's drop count reaches the DISSECTION, not
    /// only the pcapng parser.
    ///
    /// A figure read out of a block and left in the parser's return value has
    /// no consumer, and this crate has that pattern already
    /// (`DissectionHealth`). The assertion is therefore over the surface a
    /// reader actually holds.
    #[test]
    fn a_dissection_carries_what_the_capture_tool_admitted_losing() {
        // Two interfaces, so the sum is a sum rather than a copy of one.
        let mut file = pcapng::write(&[(1, 6), (1, 6)], &[(0, 1_000_000, &[0u8; 4])]);
        file.extend_from_slice(&isb_block(0, Some(9)));
        file.extend_from_slice(&isb_block(1, Some(8)));

        let d = Dissection::from_capture(&file).expect("the capture parses");
        assert_eq!(
            d.capture_reported_drops(),
            Some(17),
            "both interfaces' losses, summed"
        );
        assert!(
            !d.drops().any(),
            "and NOT confused with what this dissector itself discarded"
        );

        // A file that says nothing answers None, which is not Some(0): a
        // classic pcap has nowhere to put the figure at all.
        let plain = Dissection::from_capture(&pcap::write(LINKTYPE_ETHERNET, &[])).expect("parse");
        assert_eq!(plain.capture_reported_drops(), None);
    }

    /// One ISB carrying only `isb_ifdrop`. Kept beside its user rather than
    /// shared with `pcapng`'s own tests: that module asserts the LAYOUT, and
    /// this one asserts the figure reaches a consumer.
    fn isb_block(interface_id: u32, dropped: Option<u64>) -> Vec<u8> {
        let mut opts = Vec::new();
        if let Some(v) = dropped {
            opts.extend_from_slice(&5u16.to_le_bytes()); // isb_ifdrop
            opts.extend_from_slice(&8u16.to_le_bytes());
            opts.extend_from_slice(&v.to_le_bytes());
        }
        opts.extend_from_slice(&0u32.to_le_bytes()); // opt_endofopt
        let total = (24 + opts.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0000_0005u32.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // ts_high, ts_low
        out.extend_from_slice(&opts);
        out.extend_from_slice(&total.to_le_bytes());
        out
    }

    /// A HELLO carrying no locator list, built by the HELLO codec.
    /// The locator a HELLO in these tests advertises.
    pub(crate) const PEER_LOCATOR: &str = "udp/192.168.1.9:7447";

    /// R311y608 — the HELLO zenoh actually puts on the wire: WITH its locator
    /// list, which the responder always fills (`locators: self.get_locators()`,
    /// `zenoh/src/net/runtime/orchestrator.rs:1164`).
    ///
    /// The list is what makes this the realistic shape and also what makes the
    /// misread confident: carrying it sets `FLAG_S_HELLO_L`, which is `0x20`,
    /// which in the transport namespace is `FLAG_T_OPEN_A`. The bare-HELLO
    /// fixture next to this one has no flags at all and is the shape a
    /// locator-less answer takes.
    pub(crate) fn hello_with_locators() -> Vec<u8> {
        use wz_session_core::codec_owned::{owned_bytes, owned_string};
        let zid = [0x55u8, 0x66, 0x77, 0x88];
        let owned: wz_codecs::hello::HelloOwned = wz_codecs::hello::HelloOwned {
            version: 0x09,
            cbyte: (((zid.len() as u8) - 1) << 4) | 0x01,
            zid: owned_bytes(&zid).expect("zid"),
            num_locators: Some(1),
            locators: Some(alloc::vec![wz_codecs::locator::LocatorOwned {
                locator_len: PEER_LOCATOR.len() as u64,
                locator: owned_string(PEER_LOCATOR).expect("locator"),
            }]),
        };
        let body = owned
            .try_as_borrowed()
            .expect("borrowed projection")
            .encode_to_vec(1);
        let mut wire = alloc::vec![
            wz_session_core::wire_const::S_MID_HELLO | wz_session_core::wire_const::FLAG_S_HELLO_L
        ];
        wire.extend_from_slice(&body);
        wire
    }

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
            max_flows_per_table: Some(1),
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

    /// R311y746 (debt-carry-N11) — ONE drop ledger, and both doors onto it must
    /// answer with the same numbers.
    ///
    /// [`Dissection::drops`] COMPOSES `flows` from the retirement count rather
    /// than reading the raw field (R311y713 §B1), and [`Dissection::health`] was
    /// written beside it copying `self.drops` straight through. So the same
    /// question asked through `health().drops` answered zero where `drops()`
    /// answered the eviction count — two readers of one fact, disagreeing, which
    /// is the shape this crate has closed four times at other seams and had left
    /// open at this one.
    ///
    /// Asserted as an EQUALITY between the two doors rather than against a
    /// literal: a literal would have to be restated every time a composed field
    /// is added, and restating it is exactly how the second door fell behind.
    #[test]
    fn the_two_doors_onto_the_drop_ledger_agree() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            frames_per_flow: Some(1),
            ..DissectionLimits::default()
        });
        // Two 5-tuples, so the cap evicts; several messages on each, so the
        // per-flow frame cap bites as well. Both composed counters move.
        let a = tcp_packet(1000, &msg);
        d.push_packet(LINKTYPE_ETHERNET, 0, &a);
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1000 + msg.len() as u32, &msg),
        );
        let mut b = tcp_packet(2000, &msg);
        b[26] = 99;
        d.push_packet(LINKTYPE_ETHERNET, 2, &b);
        assert!(
            d.drops().flows > 0,
            "the fixture must evict, or it proves nothing"
        );
        assert!(
            d.drops().frames > 0,
            "the fixture must trim a frame, or it proves nothing"
        );
        assert_eq!(
            d.health().drops,
            d.drops(),
            "health() and drops() are two doors onto one ledger"
        );
    }

    /// R311y713 (§B1) — the flow cap must give a leaving flow the SAME exit
    /// `finish` gives it, and forcing the open gap is part of that exit.
    ///
    /// `finish` performs three obligations (force the open gaps, settle the
    /// framing, abandon the open chains) and the eviction path performed two.
    /// The third is the one measured here: a flow evicted while a hole is still
    /// open leaves holding every byte that arrived BEHIND the hole, so the
    /// messages in them are decoded by nobody and counted by nobody — the
    /// silence R311y650 and R311y656 each closed from a different direction,
    /// from the direction neither looked.
    #[test]
    fn an_evicted_flow_forces_its_open_gap() {
        let msg = framed_keepalive();
        // The same flow, held behind the same hole, taken through the two
        // different doors. Stated as a DIFFERENCE rather than as two magic
        // numbers because the number is not the claim — "an eviction is the
        // same exit as the end of a capture" is, and a number would have to be
        // re-derived by hand every time the framing changes.
        let fixture = |d: &mut Dissection| {
            // No patience at all: a gap is stepped over only when somebody
            // decides no further packet is coming, which is exactly the
            // decision an exit is.
            d.set_gap_patience(None);
            d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &msg));
            // A hole one message wide, then a whole message behind it.
            let far = 1000 + 2 * msg.len() as u32;
            d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet(far, &msg));
            assert_eq!(
                d.decoded_messages(),
                1,
                "the fixture must hold the far message behind an open hole"
            );
        };

        let mut ended = Dissection::new();
        fixture(&mut ended);
        ended.finish();
        assert_eq!(
            ended.framing_health().gaps_forced,
            1,
            "the fixture must actually leave a hole for the exit to force"
        );
        assert!(
            ended.byte_residue().recovered > 0,
            "and the exit must recover the bytes behind it"
        );

        let mut evicted = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        fixture(&mut evicted);
        // A second 5-tuple evicts the first flow. `tcp_packet` fixes the ports,
        // so a different SOURCE ADDRESS is what makes this a different 5-tuple.
        let mut other = tcp_packet(2000, &msg);
        other[26] = 99;
        evicted.push_packet(LINKTYPE_ETHERNET, 2, &other);
        assert_eq!(evicted.flows().len(), 1, "the cap must have evicted");
        assert_eq!(evicted.drops().flows, 1);

        assert_eq!(
            evicted.framing_health().gaps_forced,
            ended.framing_health().gaps_forced,
            "the hole the evicted flow left holding must be forced too"
        );
        assert_eq!(
            evicted.decoded_messages(),
            ended.decoded_messages() + 1,
            "and whatever the exit decodes, it must decode on both doors \
             (+1 for the second flow, which only the evicting dissection has)"
        );
        assert_eq!(
            evicted.byte_residue().recovered,
            ended.byte_residue().recovered + msg.len() as u64,
            "and the retired flow's recovered bytes must not leave with it"
        );
    }

    /// R311y716 (§C G1) — the WIRE'S OWN accounting of what it sent reaches
    /// the verdict.
    ///
    /// The last of the nine legs R311y715 found bound by nothing, and the one
    /// that needed a fixture rather than a redesign: R311y715 tried three
    /// numbered datagrams and got `sn_without_resolution`, because a reader
    /// with no handshake cannot judge a sequence number at all -- it does not
    /// know the resolution the peers negotiated, so a jump from 1 to 4 might be
    /// a wrap. The handshake is the missing ingredient, not a bigger gap.
    ///
    /// `sn_missing` is the sharpest witness the page has: it survives a capture
    /// with no holes of its own, because the SENDER numbered what it sent.
    #[test]
    fn frames_the_sender_numbered_and_this_capture_lacks_reach_the_verdict() {
        let frame = |sn: u8| {
            alloc::vec![
                wz_session_core::wire_const::T_MID_FRAME
                    | wz_session_core::wire_const::FLAG_T_FRAME_R,
                sn,
                0x1F,
                0x00,
                0x00,
                0x00,
            ]
        };
        let mut d = Dissection::new();
        let mut at = 0usize;
        let feed = |d: &mut Dissection, from_low: bool, message: &[u8], at: &mut usize| {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, message)
            };
            d.push_packet(LINKTYPE_ETHERNET, *at, &packet);
            *at += 1;
        };
        // The handshake FIRST: it is what publishes the sn resolution, and
        // without it every frame below is unjudged rather than judged fine.
        feed(&mut d, true, &init_datagram(false, &[]), &mut at);
        feed(&mut d, false, &init_datagram(true, &[]), &mut at);
        feed(&mut d, true, &open_datagram(false), &mut at);
        feed(&mut d, false, &open_datagram(true), &mut at);
        for sn in [0u8, 1, 4] {
            feed(&mut d, true, &frame(sn), &mut at);
        }
        d.finish();

        let fh = d.framing_health();
        assert_eq!(
            fh.sn_without_resolution, 0,
            "the handshake must have resolved the numbering, or this fixture              measures the reader instead of the wire: {fh:?}"
        );
        assert_eq!(fh.sn_missing, 2, "frames 2 and 3: {fh:?}");
        let reasons = crate::report::CaptureReport::of(&d).reasons();
        assert!(
            reasons.contains(&crate::report::VerdictReason::SnMissing),
            "two frames the sender numbered are not in this capture, and the              page must say so: {reasons:?}"
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            reasons,
            alloc::vec![crate::report::VerdictReason::SnMissing],
            "the wire's own accounting is the only thing short here"
        );

        // R311y728 (N18) — AND THE SMALLEST EVIDENCE. The capture above loses
        // TWO frames, so a guard reading `> 1` where `> 0` was meant still
        // fires on it and nothing in the suite would notice the reader had
        // stopped reporting a SINGLE lost frame. The boundary sweep measured
        // exactly that survival. One gap is the least the wire can report, and
        // it is the case an operator most needs told.
        let mut one = Dissection::new();
        let mut at = 0usize;
        feed(&mut one, true, &init_datagram(false, &[]), &mut at);
        feed(&mut one, false, &init_datagram(true, &[]), &mut at);
        feed(&mut one, true, &open_datagram(false), &mut at);
        feed(&mut one, false, &open_datagram(true), &mut at);
        for sn in [0u8, 1, 3] {
            feed(&mut one, true, &frame(sn), &mut at);
        }
        one.finish();
        let fh = one.framing_health();
        assert_eq!(fh.sn_missing, 1, "frame 2 alone: {fh:?}");
        assert_eq!(
            crate::report::CaptureReport::of(&one).reasons(),
            alloc::vec![crate::report::VerdictReason::SnMissing],
            "one frame is enough to make the totals a floor, and it is the \
             whole of this verdict"
        );
    }

    /// R311y713 (§B8) — a session CLOSING under an open chain is not a fourth
    /// way to lose one, and this is the measurement that says so.
    ///
    /// The register carried "a fourth chain-loss cause is already visible: the
    /// session RESET path, and nobody has looked" for several rounds. Looked
    /// at: `PassiveSession::fold` answers a `Close` by moving the phase to
    /// `Closed` and does not touch the reassembler at all
    /// (`wz-session-core/src/passive.rs:1907-1909`), so a chain open at that
    /// moment stays in its slot and is caught by one of the three causes that
    /// already exist. The item is refuted rather than paid, and this test is
    /// what keeps the refutation true: a close that started reclaiming slots
    /// would make the count below read zero.
    ///
    /// R311y715 — gated on the feature whose property it states. Without
    /// `reassembly` a `0x06` is `Unknown { mid: 6 }`, no chain is ever opened,
    /// and the exit honestly abandons none: the test would then assert that a
    /// mechanism this build does not have lost something, which is a false
    /// statement about a correct build rather than a finding.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_session_closing_under_an_open_chain_loses_nothing_extra() {
        let fragment = |sn: u8, piece: &[u8]| {
            let mut wire = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAGMENT
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_M,
                sn,
            ];
            wire.extend_from_slice(piece);
            wire
        };
        let mut d = Dissection::with_limits(DissectionLimits {
            reassembly_window_ms: Some(600_000),
            ..DissectionLimits::default()
        });
        for (i, (from_low, message)) in [
            (true, init_datagram(false, &[])),
            (false, init_datagram(true, &[])),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            // A chain opens, and then the session is CLOSED under it.
            (true, fragment(0, &[0xDE, 0xAD])),
            (
                false,
                alloc::vec![wz_session_core::wire_const::T_MID_CLOSE, 0x00],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, Some(10), &packet);
        }
        assert_eq!(
            d.abandoned_chains() + d.expired_chains() + d.evicted_chains(),
            0,
            "the close itself must not reclaim the chain, or the loss would \
             be counted at a moment no cause names"
        );

        d.finish();
        assert_eq!(
            d.abandoned_chains(),
            1,
            "and the chain the close left open is still caught by the exit"
        );
        assert_eq!(
            d.chain_bytes_lost(),
            2,
            "with its bytes, on the cause that did catch it"
        );
    }

    /// R311y713 (§B4) — an eviction follows the CAPTURE'S CLOCK, not the order
    /// the packets happen to sit in the file.
    ///
    /// `last_activity` is a packet index. On a `dumpcap -i any` pcapng each
    /// interface's packets are contiguous in the file and interleaved in time,
    /// so the flow whose last packet arrived LATER can sit EARLIER in it —
    /// and "least recently active" then throws away the wrong flow. This
    /// fixture is that shape: flow B's packet is later in the file and EARLIER
    /// on the clock, so an index-ordered eviction drops flow A. Measured
    /// exactly that way before the fix; the register carried it as a decision
    /// that rested on an unmeasured assumption.
    #[test]
    fn an_eviction_follows_the_captures_clock_when_it_has_one() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        // Flow A: file position 0, clock 9000 — the RECENT one.
        let a = tcp_packet(1000, &msg);
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(9_000), &a);
        // Flow B: file position 1, clock 1000 — older on the wire, newer in
        // the file. A second interface's traffic, as a merged capture holds it.
        let mut b = tcp_packet(2000, &msg);
        b[26] = 99;
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(1_000), &b);
        assert_eq!(d.drops().flows, 1, "the cap must have evicted one of them");
        assert_eq!(d.flows().len(), 1);
        assert_eq!(
            d.flows()[0].flow.low.port,
            1111,
            "the flow kept must be the one active LATEST on the capture's own \
             clock, not the one latest in file order"
        );
    }

    /// R311y713 (§B4) — and a capture with NO clock keeps the packet index,
    /// which is the reason the index is there at all.
    ///
    /// The fallback is not decoration: a source with no timestamps is what
    /// `last_activity` was written for, and a rule that ordered `None` against
    /// `Some` would decide an eviction on nothing.
    #[test]
    fn an_eviction_falls_back_to_file_order_without_a_clock() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &msg));
        let mut b = tcp_packet(2000, &msg);
        b[26] = 99;
        d.push_packet(LINKTYPE_ETHERNET, 1, &b);
        assert_eq!(d.drops().flows, 1);
        // `FlowKey` sorts its endpoints, so the second flow's 99.0.0.1 is its
        // HIGH end — naming the address rather than a side is what keeps this
        // assertion about the eviction rather than about the sort.
        assert_eq!(
            d.flows()[0].flow.high.addr(),
            &[99, 0, 0, 1],
            "with no clock the later packet's flow is the one kept"
        );
    }

    /// R311y713 (§B10) — a bound that discards messages must say WHAT it
    /// discarded, not only how many.
    ///
    /// `drops.frames` has counted them since R311y594b and nothing named them,
    /// so a trimmed capture could not answer whether the bound took a hundred
    /// keepalives or the `Close` that explains why the session ended. Both
    /// renderings are asserted in this one run: a fact rendered in two places
    /// is a fact that can drift, and this workspace has measured that drift.
    #[test]
    fn a_bound_that_discards_frames_says_what_they_were() {
        const CAP: usize = 2;
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(CAP),
            ..DissectionLimits::default()
        });
        // A close early in the stream and keepalives after it, on one TCP
        // flow. The close is what the bound takes, which is the whole point:
        // the count cannot tell that apart from a keepalive going.
        let close = {
            let wire = alloc::vec![wz_session_core::wire_const::T_MID_CLOSE, 0x00];
            let mut out = (wire.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(&wire);
            out
        };
        let mut stream = Vec::new();
        stream.extend_from_slice(&framed_keepalive());
        stream.extend_from_slice(&close);
        for _ in 0..5 {
            stream.extend_from_slice(&framed_keepalive());
        }
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &stream));

        let c = d.dropped_frame_census();
        assert_eq!(
            c.total(),
            d.drops().frames,
            "the census and the count must be two views of one trim"
        );
        assert!(c.total() > 0, "the fixture must actually trip the bound");
        assert_eq!(c.close(), 1, "and the CLOSE must be named as gone: {c:?}");
        assert_eq!(c.keep_alive(), c.total() - 1, "the rest were keepalives");

        let rep = crate::report::CaptureReport::of(&d);
        assert!(
            rep.to_text()
                .contains("frames discarded by frames_per_flow")
                && rep.to_text().contains("close 1"),
            "the text must name it: {}",
            rep.to_text()
        );
        assert!(
            rep.to_json().contains("\"dropped_frames\":{\"total\":")
                && rep.to_json().contains("\"close\":1"),
            "and so must the export: {}",
            rep.to_json()
        );
    }

    /// R311y713 (§B3) — one datagram flow's two message lists share the one
    /// bound that names them.
    ///
    /// Measured before the fix on this fixture: `frames_per_flow: Some(4)` and
    /// a flow that both scouts and carries traffic held EIGHT decoded messages.
    /// A reader sizing a live tap off the limit was wrong by the same factor
    /// §B2 names one layer up, for the same reason — a bound applied per list
    /// rather than per thing the lists hold.
    #[test]
    fn a_datagram_flows_two_lists_share_one_message_bound() {
        const CAP: usize = 4;
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(CAP),
            ..DissectionLimits::default()
        });
        // Alternating on ONE 5-tuple: a scout, then a transport message, ten
        // times over. The scouting port is what puts a datagram in the other
        // list, so both lists fill from the same flow.
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let scout = scout_message();
        for i in 0..10usize {
            d.push_packet(
                LINKTYPE_ETHERNET,
                i * 2,
                &udp_packet([10, 0, 0, 1], 43210, SCOUT_GROUP, 7446, &scout),
            );
            d.push_packet(
                LINKTYPE_ETHERNET,
                i * 2 + 1,
                &udp_packet([10, 0, 0, 1], 43210, SCOUT_GROUP, 7446, &keepalive),
            );
        }
        let flow = &d.datagram_flows()[0];
        assert!(
            !flow.frames.is_empty() && !flow.scouting.is_empty(),
            "the fixture must fill BOTH lists, or it cannot see the doubling"
        );
        assert_eq!(
            flow.frames.len() + flow.scouting.len(),
            CAP,
            "the flow's decoded messages, over both lists, must fit the bound"
        );
        assert!(
            d.drops().frames > 0 && d.drops().scouting > 0,
            "and both lists must have been bitten, each on its own counter"
        );
    }

    /// R311y713 (§B2) — the flow bound a caller can size memory against, held
    /// against what the dissection ACTUALLY holds.
    ///
    /// `max_flows_per_table` is per table by a decision R311y651 made and
    /// argued for, and the cost it named — the bound admits twice the number —
    /// sat in a doc comment while the field was called `max_flows`. This is
    /// that arithmetic with a witness instead of a sentence: both tables are
    /// driven past the cap and the total held must be exactly what
    /// [`DissectionLimits::max_flows_held`] promises. A third flow table would
    /// break it here rather than in a deployment's memory figures.
    #[test]
    fn the_flow_bound_is_the_one_a_caller_can_size_against() {
        let msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let limits = DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        };
        let mut d = Dissection::with_limits(limits);
        // Six stream 5-tuples and six datagram ones, well past the cap on both.
        for i in 0..6u8 {
            let mut pkt = tcp_packet(1000, &framed_keepalive());
            pkt[26] = 100 + i;
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
            d.push_packet(
                LINKTYPE_ETHERNET,
                100 + i as usize,
                &udp_packet([10, 1, 1, i], 7447, [10, 1, 2, i], 7447, &msg),
            );
        }
        let held = d.flows().len() + d.datagram_flows().len();
        assert_eq!(
            Some(held),
            limits.max_flows_held(),
            "the promised bound and the held flows must be the same number"
        );
        assert!(
            held > limits.max_flows_per_table.unwrap(),
            "and it must be the TOTAL, not one table's share — the whole point \
             is that a caller reading the per-table field sizes for half"
        );
    }

    /// R311y713 (§B1) — and the count of what this reader decoded must not walk
    /// backwards when a MULTICAST slot recycles either.
    ///
    /// R311y666 gave the stream table this carry and the datagram table never
    /// got one, which nothing had noticed because the two retirements were
    /// eighty lines apart. Written next to each other in [`exit`], the omission
    /// is one missing line rather than a comparison nobody makes: a tap on a
    /// scouting group is exactly where `max_flows_per_table` recycles hardest, so this is
    /// the table where the number moved wrong FASTEST.
    #[test]
    fn an_evicted_datagram_flows_messages_stay_in_the_total() {
        let msg = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &msg),
        );
        assert_eq!(d.decoded_messages(), 1, "the fixture must decode one");

        // A second datagram 5-tuple evicts the first.
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet([10, 0, 0, 3], 7447, [10, 0, 0, 4], 7447, &msg),
        );
        assert_eq!(d.datagram_flows().len(), 1, "the cap must have evicted");
        assert_eq!(d.drops().flows, 1);
        assert_eq!(
            d.decoded_messages(),
            2,
            "the evicted datagram flow's message must survive its flow"
        );
    }

    /// R311y610 (§4.4) — the SESSION half of the same carry, which R311y605
    /// could not have covered and R311y609 left open.
    ///
    /// `retransmits` above lives on a [`StreamAssembler`], and the F5 carry
    /// reaches it. Desynchronisations and sequence-number losses live inside
    /// `PassiveSession`, which the assembler carry never touched, so a live tap
    /// recycling a flow slot dropped exactly the numbers that say traffic was
    /// LOST — and it dropped them downward, toward a healthier-looking capture.
    #[test]
    fn an_evicted_flows_losses_stay_in_the_total() {
        let stream: Vec<u8> = (0..40u8).flat_map(framed_frame).collect();
        const SEG: usize = 37;
        let segments: Vec<&[u8]> = stream.chunks(SEG).collect();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.set_gap_patience(Some(2));
        for (i, seg) in segments.iter().enumerate() {
            if i == 3 {
                continue;
            }
            let pkt = tcp_packet(1000 + (i * SEG) as u32, seg);
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        let before = d.framing_health();
        assert!(
            before.desyncs == 1 && before.recoveries == 1 && before.resync_skipped_bytes > 0,
            "the fixture must actually lose and regain the framing: {before:?}"
        );
        assert!(before.sn_frames > 0, "and number some frames: {before:?}");

        // A second 5-tuple evicts it.
        let mut other = tcp_packet(2000, &framed_keepalive());
        other[26] = 99;
        d.push_packet(LINKTYPE_ETHERNET, segments.len(), &other);
        assert_eq!(d.flows().len(), 1, "the cap must have evicted");

        let after = d.framing_health();
        assert_eq!(
            (
                after.desyncs,
                after.recoveries,
                after.resync_skipped_bytes,
                after.sn_frames,
                after.gaps_forced
            ),
            (
                before.desyncs,
                before.recoveries,
                before.resync_skipped_bytes,
                before.sn_frames,
                before.gaps_forced
            ),
            "no loss counter may move when a flow is evicted: {before:?} -> {after:?}"
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
        // R311y653 — WHICH three, which is what "oldest first" MEANS and what
        // this test could not see: every packet here is the same keepalive, so
        // a cap that kept the FIRST three answered identically. The anchor is
        // the packet index each frame carries -- on a datagram flow the offset
        // IS that index, because there is no stream for it to be an offset
        // into. Falsified: `truncate(cap)` in place of the drain reds this.
        let kept: Vec<usize> = d.datagram_flows()[0]
            .frames
            .iter()
            .map(|f| f.stream_offset)
            .collect();
        assert_eq!(
            kept,
            alloc::vec![7, 8, 9],
            "a live viewer is looking at what JUST happened, so the oldest go"
        );
    }

    /// R311y653 — the STREAM path's frame cap, which had no test of its own at
    /// all: the only `frames_per_flow` fixture in this file drives a DATAGRAM
    /// flow, and the two paths trim in different functions.
    ///
    /// The order is the claim. `frames_per_flow`'s doc says "Beyond it the
    /// OLDEST go — a live viewer is looking at what just happened", and until
    /// this test a trim that kept the oldest instead passed every one of the
    /// 326. The anchor is each frame's stream offset, which on a stream flow is
    /// a real position and not a stand-in.
    #[test]
    fn the_stream_paths_frame_cap_keeps_the_most_recent() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(3),
            ..DissectionLimits::default()
        });
        for i in 0..10u32 {
            let pkt = tcp_packet(1000 + i * msg.len() as u32, &msg);
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }
        assert_eq!(d.flows()[0].frames.len(), 3);
        assert_eq!(d.drops().frames, 7);
        let kept: Vec<usize> = d.flows()[0]
            .frames
            .iter()
            .map(|f| f.stream_offset)
            .collect();
        let unit = msg.len();
        assert_eq!(
            kept,
            alloc::vec![7 * unit, 8 * unit, 9 * unit],
            "the OLDEST must go, which is the half of this bound that decides \
             what a live viewer sees"
        );
    }

    /// The flow TABLE is bounded too, which the other bounds cannot do: a
    /// 5-tuple that never returns is memory that is never reclaimed.
    #[test]
    fn the_flow_table_evicts_the_least_recently_active() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
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

        // R311y652 — THE LEG THIS TEST WAS NAMED FOR, and did not have. Found by
        // falsification: neutering `last_activity` on the stream path left all
        // 325 tests green, because three flows created in order are also three
        // flows active in order, and an insertion-order table answers that
        // fixture exactly as an LRU does. R311y594b's rule has been unwitnessed
        // since it was written.
        //
        // These three separate the orders: the FIRST flow is spoken for again
        // before the third arrives, so an LRU keeps it and a FIFO drops it.
        let at = |port: u16, seq: u32| {
            let mut pkt = tcp_packet(seq, &msg);
            pkt[34..36].copy_from_slice(&port.to_be_bytes());
            pkt
        };
        let mut e = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        });
        e.push_packet(LINKTYPE_ETHERNET, 0, &at(2221, 1000));
        e.push_packet(LINKTYPE_ETHERNET, 1, &at(2222, 1000));
        // Spoken for again, one message further along its own stream.
        e.push_packet(LINKTYPE_ETHERNET, 2, &at(2221, 1000 + msg.len() as u32));
        e.push_packet(LINKTYPE_ETHERNET, 3, &at(2223, 1000));
        assert_eq!(e.flows().len(), 2);
        let ports: Vec<u32> = e
            .flows()
            .iter()
            .map(|f| f.flow.low.port.min(f.flow.high.port))
            .collect();
        assert_eq!(
            ports,
            alloc::vec![2221, 2223],
            "the LEAST RECENTLY ACTIVE must go, not the first admitted"
        );
    }

    /// R311y651 (§4.4) — the DATAGRAM flow table is bounded too.
    ///
    /// Measured before the fix, on this fixture: `max_flows_per_table: Some(2)` and forty
    /// 5-tuples produced FORTY flows and `drops.flows == 0`. `max_flows_per_table` exists
    /// because "a 5-tuple that never returns is a flow that is never freed", and
    /// the plane where that is most true — scouting, where every host on a
    /// multicast group is its own 5-tuple and none of them ever closes — was the
    /// one the bound did not reach.
    #[test]
    fn the_datagram_flow_table_is_bounded_by_the_same_limit() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        });
        for i in 0..40u16 {
            let pkt = udp_packet([10, 0, 0, 1], 7000 + i, [224, 0, 0, 224], 7446, &keepalive);
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }
        assert_eq!(
            d.datagram_flows().len(),
            2,
            "the cap must hold on this table"
        );
        assert_eq!(d.drops().flows, 38, "and every eviction must be counted");
        // R311y725 (N2) — a bound that discarded reaches the VERDICT, by name.
        // The counter alone says a flow went; this says the capture's totals
        // are a floor because of it.
        assert!(
            crate::report::CaptureReport::of(&d)
                .reasons()
                .contains(&crate::report::VerdictReason::BoundsDiscarded),
            "{:?}",
            crate::report::CaptureReport::of(&d).reasons()
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![crate::report::VerdictReason::BoundsDiscarded],
            "the bound is the whole of this verdict"
        );

        // THE SECOND LEG, and it earned its place by falsification: never
        // writing `last_activity` at all leaves the sweep above green, because
        // every flow then ties at zero and the tie falls to insertion order --
        // which in the sweep IS activity order. These three flows separate the
        // two orders: the FIRST one is touched again before the third arrives,
        // so an LRU keeps it and an insertion-order table drops it.
        let ports = |d: &Dissection| -> Vec<u32> {
            d.datagram_flows()
                .iter()
                .map(|f| f.flow.high.port.min(f.flow.low.port))
                .collect()
        };
        let mut e = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        });
        let at = |port: u16| udp_packet([10, 0, 0, 1], port, [224, 0, 0, 224], 7446, &keepalive);
        e.push_packet(LINKTYPE_ETHERNET, 0, &at(7000));
        e.push_packet(LINKTYPE_ETHERNET, 1, &at(7001));
        // 7000 is spoken for again, which is the whole distinction.
        e.push_packet(LINKTYPE_ETHERNET, 2, &at(7000));
        e.push_packet(LINKTYPE_ETHERNET, 3, &at(7002));
        assert_eq!(e.datagram_flows().len(), 2);
        assert_eq!(
            ports(&e),
            alloc::vec![7000, 7002],
            "the LEAST RECENTLY ACTIVE must go, not the first admitted"
        );
    }

    /// R311y725 (N7) — THE QUIC PER-FLOW STREAM BOUND HAS A WITNESS, and the
    /// witness binds the bound to the VERDICT rather than to the counter.
    ///
    /// `QuicStreamFeed::streams_refused` has been exported in the JSON since
    /// R311y718 and no fixture in this workspace had ever crossed the bound, so
    /// the number was a field nothing could move. That is the shape R311y715
    /// measured across the verdict's own legs: a guard that binds nothing leaves
    /// every test green when it is severed.
    ///
    /// Two legs, and the second is the one worth having. The first is that the
    /// bound REFUSES — `quic_streams_per_flow` streams are admitted and the next
    /// offer is turned away rather than evicting one of them. The second is that
    /// the refused offer's bytes are then MISSING from the report: they were
    /// recovered by a decryption pass and no framer ever saw them, so
    /// `quic_bytes_nobody_decodes` must fire. A refusal the verdict cannot see
    /// would be a capture reporting `complete` while a whole stream's traffic sat
    /// outside every row.
    ///
    /// The control at the end is what keeps this from being vacuous: at exactly
    /// the bound, nothing is refused and — with every recovered byte fed and
    /// decoded — the verdict is silent. Without it, a `feed` that refused
    /// EVERYTHING would satisfy both assertions above.
    ///
    /// MEASURED while writing this, and it is why the fixture uses
    /// [`DissectionLimits::for_live_tap`] rather than the default: the default
    /// preset leaves `quic_streams_per_flow` at `None`, so a file replay admits
    /// streams without end and this counter is unreachable there. The bound is a
    /// live-tap fact, and a witness built on the default limits would have been
    /// the second kind of vacuous test — one whose subject never exists.
    #[test]
    fn the_quic_stream_bound_refuses_and_the_refusal_reaches_the_verdict() {
        let unit = framed_keepalive();
        // The flow has to exist before a stream can be offered to it: a QUIC
        // stream is recovered FROM a datagram flow's packets, and an offer for a
        // flow this dissection does not hold is a different finding
        // (`flow_absent`) that this test must not accidentally measure.
        let open_flow = |d: &mut Dissection| {
            let pkt = udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &[]);
            d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
            d.datagram_flows()[0].flow
        };

        let mut d = Dissection::with_limits(DissectionLimits::for_live_tap());
        let flow = open_flow(&mut d);
        let cap = d
            .limits()
            .quic_streams_per_flow
            .expect("the live-tap preset bounds this table");

        let mut feed = quic::QuicStreamFeed::default();
        for id in 0..=(cap as u64) {
            feed.absorb(d.feed_quic_stream(flow, Direction::A, id, false, &unit));
        }
        assert_eq!(
            feed.streams_refused, 1,
            "one offer past the bound must be REFUSED, not admitted by evicting \
             a stream that already carries session state"
        );
        assert_eq!(
            d.datagram_flows()[0].quic_streams.len(),
            cap,
            "the table must hold exactly the bound"
        );
        // The VALUE and not the flag: the refused offer's bytes must be absent
        // from what a framer was given, which is what makes them unread below.
        assert_eq!(
            feed.bytes_fed,
            cap * unit.len(),
            "a refused offer's bytes must not be counted as fed"
        );
        assert_eq!(feed.messages, cap, "each admitted stream decoded its unit");

        // What a decryptor recovered: every offer's bytes, including the one the
        // bound turned away. This is the premise the verdict reads.
        let quic = quic::QuicDecryption {
            stream_bytes: (cap + 1) * unit.len(),
            framing: feed,
            ..quic::QuicDecryption::default()
        };
        let report = report::CaptureReport::of(&d).with_quic_decryption(&quic);
        assert!(
            report
                .reasons()
                .contains(&report::VerdictReason::QuicBytesNobodyDecodes),
            "bytes a bound refused are bytes nobody decodes: {:?}",
            report.reasons()
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            report.reasons(),
            alloc::vec![report::VerdictReason::QuicBytesNobodyDecodes],
            "the refused offer is the whole of this verdict"
        );

        // THE CONTROL. At exactly the bound nothing is refused, and with every
        // recovered byte fed and framed the same verdict is silent -- so the
        // reason above followed the refusal and not the fixture.
        let mut e = Dissection::with_limits(DissectionLimits::for_live_tap());
        let flow = open_flow(&mut e);
        let mut ok = quic::QuicStreamFeed::default();
        for id in 0..(cap as u64) {
            ok.absorb(e.feed_quic_stream(flow, Direction::A, id, false, &unit));
        }
        assert_eq!(ok.streams_refused, 0, "the bound itself must be admitted");
        let quic = quic::QuicDecryption {
            stream_bytes: ok.bytes_fed,
            framing: ok,
            ..quic::QuicDecryption::default()
        };
        let report = report::CaptureReport::of(&e).with_quic_decryption(&quic);
        assert!(
            !report
                .reasons()
                .contains(&report::VerdictReason::QuicBytesNobodyDecodes),
            "ANTI-VACUITY: an unrefused capture must not raise it: {:?}",
            report.reasons()
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            report.reasons(),
            alloc::vec![],
            "and the control capture is short of NOTHING"
        );
    }

    /// R311y749 (debt-carry-N6) — A SECOND OFFER ON ONE STREAM IS WALKED, in
    /// the coordinate space the sink contract promises.
    ///
    /// # What was wrong, and why it was only half wrong
    ///
    /// [`PlaintextSink::on_recovered_datagram`]'s doc states the rule this
    /// turns on: in a [`DecryptedStream`] a frame's `stream_offset` is an offset
    /// INTO `plaintext`, which is what lets a sink slice the message out. A
    /// frame's offset is absolute within its direction's recovered stream, so
    /// the two agree only while an offer starts at zero. R311y718 saw that and
    /// refused to walk an appending offer at all, counting it in
    /// `appends_not_walked` — right, because naming the wrong bytes as a
    /// message's fields is worse than naming none.
    ///
    /// It left a live tap with NO field walk, though: a tap feeds a stream
    /// incrementally, so every offer after the first was counted and dropped.
    /// The fix is to make the contract true rather than to give up on it — the
    /// offered frames are rebased into this offer's space, so a sink slices
    /// correctly, and restored afterwards so every other reader still sees
    /// absolute coordinates.
    ///
    /// The assertion is the SLICE and not the number: an offset that merely
    /// changed would satisfy a `!= 3` check while still naming the wrong bytes.
    #[test]
    fn a_second_offer_on_one_quic_stream_is_walked_in_its_own_space() {
        /// A sink that keeps what it was shown, since the claim is about what
        /// reached one.
        #[derive(Default)]
        struct Recorder {
            /// `(plaintext, the offered frames' offsets)` per call.
            calls: alloc::vec::Vec<(alloc::vec::Vec<u8>, alloc::vec::Vec<usize>)>,
        }
        impl PlaintextSink for Recorder {
            fn on_plaintext(&mut self, stream: DecryptedStream<'_>) {
                self.calls.push((
                    stream.plaintext.to_vec(),
                    stream.frames.iter().map(|f| f.stream_offset).collect(),
                ));
            }
            fn on_recovered_datagram(&mut self, _d: RecoveredDatagram<'_>) {}
        }

        let unit = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits::for_live_tap());
        let pkt = udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &[]);
        d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
        let flow = d.datagram_flows()[0].flow;

        let mut sink = Recorder::default();
        let first = d.feed_quic_stream_with_sink(flow, Direction::A, 7, false, &unit, &mut sink);
        assert_eq!(first.messages, 1, "the first offer must decode its unit");
        let second = d.feed_quic_stream_with_sink(flow, Direction::A, 7, false, &unit, &mut sink);
        assert_eq!(second.messages, 1, "and so must the second");
        assert_eq!(
            second.appends_not_walked, 0,
            "an appending offer whose messages are all inside it is walkable"
        );

        assert_eq!(sink.calls.len(), 2, "both offers must reach the sink");
        for (i, (plaintext, offsets)) in sink.calls.iter().enumerate() {
            assert_eq!(plaintext.as_slice(), unit.as_slice(), "call {i}");
            assert_eq!(offsets.len(), 1, "call {i}: one message each");
            let at = offsets[0];
            // THE SLICE. `plaintext[at..]` must BE the message, which is the
            // one thing an absolute offset could not deliver: the second
            // offer's frame is at 3 in stream space and `plaintext` is 3 bytes
            // long, so the old coordinate did not merely mislead — it did not
            // land in the buffer at all.
            assert!(
                at < plaintext.len(),
                "call {i}: offset {at} is outside the offered bytes"
            );
            assert_eq!(
                &plaintext[at..],
                unit.as_slice(),
                "call {i}: the offset must name the message's first byte"
            );
        }

        // AND THE FLOW'S OWN COORDINATES ARE UNTOUCHED. The rebase is for the
        // duration of the offer; a reader of the stream afterwards must still
        // see absolute offsets, or this fix would have traded one wrong
        // coordinate space for another.
        let stream = &d.datagram_flows()[0].quic_streams[0];
        assert_eq!(
            stream
                .frames
                .iter()
                .map(|f| f.stream_offset)
                .collect::<alloc::vec::Vec<_>>(),
            alloc::vec![0, unit.len()],
            "the stream's own frames stay in stream space"
        );
    }

    /// R311y749 (debt-carry-N6) — AND THE MESSAGE THAT SPANS THE BOUNDARY IS
    /// COUNTED RATHER THAN MIS-ADDRESSED.
    ///
    /// The other half of the fix above, and the half that keeps it honest. A
    /// message whose head arrived in an earlier offer has those bytes nowhere:
    /// a recovered QUIC stream is framed, not buffered. No coordinate can point
    /// a sink at its fields, so it is excluded from the walk and named in
    /// [`quic::QuicStreamFeed::messages_straddling_offers`] — the rule R311y718
    /// applied to a whole offer, kept for the one message it is still true of.
    ///
    /// Both legs in one fixture because they differ by one byte of input: a
    /// second offer that carries ONLY the tail of a straddling message walks
    /// nothing at all, and the same offer plus a whole message walks that one.
    #[test]
    fn a_message_that_spans_two_quic_offers_is_named_not_walked() {
        #[derive(Default)]
        struct Recorder {
            calls: alloc::vec::Vec<(alloc::vec::Vec<u8>, alloc::vec::Vec<usize>)>,
        }
        impl PlaintextSink for Recorder {
            fn on_plaintext(&mut self, stream: DecryptedStream<'_>) {
                self.calls.push((
                    stream.plaintext.to_vec(),
                    stream.frames.iter().map(|f| f.stream_offset).collect(),
                ));
            }
            fn on_recovered_datagram(&mut self, _d: RecoveredDatagram<'_>) {}
        }
        let unit = framed_keepalive();
        let open = |d: &mut Dissection| {
            let pkt = udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &[]);
            d.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
            d.datagram_flows()[0].flow
        };

        // LEG ONE — the offer carries only the straddler's tail, so the walk has
        // nothing it can address and the whole offer is unwalked.
        let mut d = Dissection::with_limits(DissectionLimits::for_live_tap());
        let flow = open(&mut d);
        let mut sink = Recorder::default();
        // The length prefix alone: the framer stalls, holding a message whose
        // body has not arrived.
        let head =
            d.feed_quic_stream_with_sink(flow, Direction::A, 1, false, &unit[..2], &mut sink);
        assert_eq!(head.messages, 0, "a prefix alone must decode nothing");
        assert_eq!(sink.calls.len(), 0, "and offer nothing to walk");
        let tail =
            d.feed_quic_stream_with_sink(flow, Direction::A, 1, false, &unit[2..], &mut sink);
        assert_eq!(tail.messages, 1, "the tail completes the message");
        assert_eq!(
            (tail.messages_straddling_offers, tail.appends_not_walked),
            (1, 1),
            "its head is in bytes nothing holds, so it is named and the offer \
             is unwalked"
        );
        assert_eq!(sink.calls.len(), 0, "nothing addressable reached the sink");

        // LEG TWO — the same tail followed by a WHOLE message in one offer. The
        // straddler is still named; the message inside the offer is walked, at
        // the offset that slices it out of these bytes.
        let mut e = Dissection::with_limits(DissectionLimits::for_live_tap());
        let flow = open(&mut e);
        let mut sink = Recorder::default();
        e.feed_quic_stream_with_sink(flow, Direction::A, 1, false, &unit[..2], &mut sink);
        let mut rest = alloc::vec::Vec::from(&unit[2..]);
        rest.extend_from_slice(&unit);
        let both = e.feed_quic_stream_with_sink(flow, Direction::A, 1, false, &rest, &mut sink);
        assert_eq!(both.messages, 2, "the completed one and the whole one");
        assert_eq!(
            (both.messages_straddling_offers, both.appends_not_walked),
            (1, 0),
            "one message is unaddressable and the offer is still walked"
        );
        assert_eq!(sink.calls.len(), 1, "the walkable half reached the sink");
        let (plaintext, offsets) = &sink.calls[0];
        assert_eq!(plaintext.as_slice(), rest.as_slice());
        assert_eq!(offsets.len(), 1, "only the addressable message is offered");
        assert_eq!(
            &plaintext[offsets[0]..],
            unit.as_slice(),
            "and its offset slices the message out of THESE bytes"
        );
    }

    /// R311y651 (§4.4) — and R311y610's rule on the plane it was not written
    /// for: an evicted datagram flow's SEQUENCE accounting stays in the total.
    ///
    /// `framing_health` reads `sn_accounting` off `datagram_flows` — multicast
    /// loss is exactly what that measures — so a cap that evicted without
    /// carrying would make a live tap's loss figures IMPROVE every time a slot
    /// recycled. Adding the bound without this carry would have shipped the
    /// R311y610 defect on a second plane in the same commit that closed the leak.
    #[test]
    fn an_evicted_datagram_flows_sequence_accounting_stays_in_the_total() {
        let frame = |sn: u8| {
            alloc::vec![
                wz_session_core::wire_const::T_MID_FRAME
                    | wz_session_core::wire_const::FLAG_T_FRAME_R,
                sn,
                0x1F,
                0x00,
                0x00,
                0x00,
            ]
        };
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        // One flow, numbered frames, and NO handshake in front of them -- so the
        // reader counts them and cannot judge them, which is the ordinary shape
        // of a mid-session multicast capture and puts both a count and an
        // unresolved tally on the flow before it is evicted.
        for (i, sn) in [0u8, 1, 4].into_iter().enumerate() {
            let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &frame(sn));
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        let before = d.framing_health();
        assert!(
            before.sn_frames > 0 && before.sn_without_resolution > 0,
            "the fixture must number frames AND fail to judge some: {before:?}"
        );

        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let other = udp_packet([10, 0, 0, 9], 7448, [224, 0, 0, 224], 7446, &keepalive);
        d.push_packet(LINKTYPE_ETHERNET, 3, &other);
        assert_eq!(d.datagram_flows().len(), 1, "the cap must have evicted");

        let after = d.framing_health();
        assert_eq!(
            (
                after.sn_frames,
                after.sn_missing,
                after.sn_gaps,
                after.sn_without_resolution
            ),
            (
                before.sn_frames,
                before.sn_missing,
                before.sn_gaps,
                before.sn_without_resolution
            ),
            "no loss counter may move when a datagram flow is evicted: \
             {before:?} -> {after:?}"
        );
    }

    /// R311y730 (N22) — EVERY BOUND COUNTER, AT EXACTLY ONE DISCARD.
    ///
    /// The mutation sweep's predicate layer relaxes `DissectionDrops::any` by
    /// one per counter and requires a test to redden. Four of them survived it,
    /// and the reason is visible in every bound test around this one: they
    /// overshoot their cap on purpose — thirty SCOUTs against a cap of three,
    /// ten frames against three — because what they are about is WHICH entries
    /// survive. Nothing in the tree landed on the boundary, so a reader that
    /// stopped reporting the FIRST discard would have passed the whole suite.
    ///
    /// Each arm is its own dissection and asserts the OTHER counters are zero,
    /// because `any()` is a disjunction: a second non-zero counter would keep
    /// the verdict up on its own and the arm would prove nothing about this one.
    #[test]
    fn each_bound_counter_is_witnessed_at_exactly_one() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];

        // FRAMES: a cap of three, and a fourth frame.
        let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &keepalive);
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(3),
            ..DissectionLimits::default()
        });
        for i in 0..4 {
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        assert_eq!(
            (d.drops().frames, d.drops().skipped, d.drops().scouting),
            (1, 0, 0),
            "exactly one frame, and nothing else: {:?}",
            d.drops()
        );
        assert_eq!(d.drops().stream_bytes, 0);
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![crate::report::VerdictReason::BoundsDiscarded],
            "one discarded frame is the whole of this verdict"
        );

        // SKIPPED: a cap of one, and a second unreadable packet.
        let mut d = Dissection::with_limits(DissectionLimits {
            skipped_packets: Some(1),
            ..DissectionLimits::default()
        });
        for i in 0..2 {
            d.push_packet(250, i, &[0xAA; 20]);
        }
        assert_eq!(
            (d.drops().skipped, d.drops().frames, d.drops().scouting),
            (1, 0, 0),
            "exactly one skip record, and nothing else: {:?}",
            d.drops()
        );
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![
                crate::report::VerdictReason::PacketsSkipped,
                crate::report::VerdictReason::BoundsDiscarded,
            ],
            "MEASURED: a capture that drops a skip RECORD necessarily skipped \
             packets too, so both legs are up and the pin has to name both"
        );

        // SCOUTING: the same cap, and a fourth SCOUT.
        let scout = [wz_session_core::wire_const::S_MID_SCOUT, 0x00, 0x01, 0x00];
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(3),
            ..DissectionLimits::default()
        });
        for i in 0..4 {
            let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &scout);
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        assert_eq!(
            (d.drops().scouting, d.drops().frames, d.drops().skipped),
            (1, 0, 0),
            "exactly one SCOUT, and nothing else: {:?}",
            d.drops()
        );
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![crate::report::VerdictReason::BoundsDiscarded],
            "one discarded SCOUT is the whole of this verdict"
        );

        // STREAM BYTES: a direction budget, and one byte past it.
        let payload = [0x11u8; 8];
        let mut d = Dissection::with_limits(DissectionLimits {
            stream_bytes_per_direction: Some(payload.len() - 1),
            ..DissectionLimits::default()
        });
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(0, &payload));
        assert_eq!(
            (d.drops().stream_bytes, d.drops().frames, d.drops().skipped),
            (1, 0, 0),
            "exactly one byte, and nothing else: {:?}",
            d.drops()
        );
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![
                crate::report::VerdictReason::BoundsDiscarded,
                crate::report::VerdictReason::Desyncs,
            ],
            "MEASURED: trimming the head of a stream loses the framing with it, \
             so the desync is this fixture's own consequence and the pin names \
             both. Severing the bound still reds this line on the first name"
        );
    }

    /// R311y651 (§4.4) — the SCOUTING list is bounded, and by the same limit
    /// the frame list beside it is.
    ///
    /// Measured before the fix: `frames_per_flow: Some(3)` and thirty SCOUTs on
    /// one flow left thirty entries. The scouting list is the one a live tap
    /// grows fastest — a discovery group carries a SCOUT per host per interval
    /// forever — and it was the one list on a flow with no bound at all.
    #[test]
    fn the_scouting_list_is_bounded_and_the_loss_is_counted() {
        let scout = [wz_session_core::wire_const::S_MID_SCOUT, 0x00, 0x01, 0x00];
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(3),
            ..DissectionLimits::default()
        });
        for i in 0..30 {
            let pkt = udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, &scout);
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        assert_eq!(d.datagram_flows().len(), 1, "one 5-tuple, one flow");
        assert_eq!(d.datagram_flows()[0].scouting.len(), 3);
        // R311y653 — and the three are the LAST three. R311y651 wrote this
        // bound with the same blind spot it had just closed elsewhere: thirty
        // identical SCOUTs make a cap that keeps the first three
        // indistinguishable from one that keeps the last.
        let kept: Vec<usize> = d.datagram_flows()[0]
            .scouting
            .iter()
            .map(|s| s.packet_index)
            .collect();
        assert_eq!(kept, alloc::vec![27, 28, 29]);
        assert_eq!(
            d.drops().scouting,
            27,
            "a bound that bites silently reports itself as the wire: {:?}",
            d.drops()
        );
        assert_eq!(
            d.drops().frames,
            0,
            "and the two lists' losses must stay distinguishable"
        );
        assert!(d.drops().any(), "the roll-up must see it");
        // AND IT REACHES THE EXPORT. A loss that stops at the typed struct is a
        // loss the consumer summing the JSON is never told about, which is the
        // shape this whole object exists to refuse.
        let rep = crate::report::CaptureReport::of(&d);
        assert!(
            rep.to_json().contains("\"scouting\":27"),
            "{}",
            rep.to_json()
        );
        assert!(!rep.is_complete(), "{}", rep.to_text());
    }

    /// R311y651 (§4.4) — and the capture the bound was MISSING for, which is
    /// the one where every packet takes the early return.
    ///
    /// A scouting datagram never reaches the frame path: it is decoded into its
    /// own list and the function returns. So a tap on a discovery group — where
    /// every host is its own 5-tuple, none of them ever closes, and SCOUTs
    /// arrive forever — is exactly the capture whose flow table grows without
    /// end, and it is the one an eviction call on the frame path alone does not
    /// touch. Found by falsifying R311y651: dropping the scouting path's call
    /// left all 324 tests green.
    #[test]
    fn a_scouting_only_capture_is_bounded_too() {
        let scout = [wz_session_core::wire_const::S_MID_SCOUT, 0x00, 0x01, 0x00];
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        });
        for i in 0..25u16 {
            // A DIFFERENT SOURCE HOST each time, which is what a discovery
            // group looks like: one asker per node, all to the same group.
            let pkt = udp_packet(
                [10, 0, 0, (i + 1) as u8],
                7447,
                [224, 0, 0, 224],
                7446,
                &scout,
            );
            d.push_packet(LINKTYPE_ETHERNET, i as usize, &pkt);
        }
        assert_eq!(
            d.datagram_flows().len(),
            2,
            "a scouting-only capture grows one flow per host forever"
        );
        assert_eq!(d.drops().flows, 23);
        // ANTI-VACUITY: the packets really did take the scouting path, so this
        // is not the frame path's eviction being measured a second time.
        assert!(
            d.datagram_flows().iter().all(|f| !f.scouting.is_empty())
                && d.datagram_flows().iter().all(|f| f.frames.is_empty()),
            "the fixture must drive the SCOUTING branch"
        );
    }

    /// R311y654 (§1.1f) — a chain this reader ABANDONED on its own deadline
    /// reaches the verdict, the export and the page.
    ///
    /// Measured before the fix: `expired_chains()` read 1, `is_complete()`
    /// answered TRUE, and the number appeared nowhere in the JSON or the text.
    /// The counter was added in R311y594 with the words "COUNTED rather than
    /// silent" and had, in the whole workspace, NO consumer at all -- not the
    /// verdict, not the export, not one test. A capture whose message the
    /// analyzer gave up waiting for reported itself complete and did not
    /// mention it, which is a bound reporting itself as the wire's: the exact
    /// statement the counter's own doc says it exists to prevent.
    ///
    /// The clock is what makes this reachable and it is the CAPTURE's, not the
    /// host's: the last packet is stamped 9 s into a 1 s window.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_chain_abandoned_on_this_readers_deadline_reaches_the_verdict() {
        let fragment = |sn: u8, more: bool, piece: &[u8]| {
            let mut wire = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAGMENT
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                    | if more {
                        wz_codecs::wire_const::FLAG_T_FRAGMENT_M
                    } else {
                        0
                    },
                sn,
            ];
            wire.extend_from_slice(piece);
            wire
        };
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::with_limits(DissectionLimits {
            reassembly_window_ms: Some(1_000),
            ..DissectionLimits::default()
        });
        // A handshake, so the session has an SN resolution and the chain is
        // TRACKED rather than refused -- without it the fragment is
        // `FragmentWithoutResolution` and nothing ever opens to expire.
        for (i, (from_low, ts, message)) in [
            (true, 0u64, init_datagram(false, &[])),
            (false, 0, init_datagram(true, &[])),
            (true, 0, open_datagram(false)),
            (false, 0, open_datagram(true)),
            // The chain opens and its second piece never comes.
            (true, 10, fragment(0, true, &[0xDE, 0xAD])),
            // Nine seconds later, on the same flow: the sweep runs.
            (true, 9_000, keepalive.clone()),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, Some(ts), &packet);
        }
        assert_eq!(
            d.expired_chains(),
            1,
            "the fixture must actually abandon a chain, or every assertion \
             below is about a capture that had nothing to report"
        );

        let rep = crate::report::CaptureReport::of(&d);
        assert!(
            !rep.is_complete(),
            "a capture missing a message this reader gave up on is not complete: \
             {}",
            rep.to_text()
        );
        // R311y725 (N2) — BY NAME. `!is_complete()` is satisfied by any leg, so
        // a witness that only asserts it cannot tell its own reason from a
        // neighbour's; `verdict_reason_lint` reads this naming and refuses a
        // variant no test names.
        assert!(
            rep.reasons()
                .contains(&crate::report::VerdictReason::ExpiredChains),
            "the deadline is the leg this fixture trips: {:?}",
            rep.reasons()
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            rep.reasons(),
            alloc::vec![crate::report::VerdictReason::ExpiredChains],
            "the deadline is the whole of this verdict"
        );
        assert!(
            rep.to_json()
                .contains(
                    "\"reassembly\":{\"expired_chains\":1,\"abandoned_at_end\":0,\"abandoned_on_eviction\":0}"
                ),
            "{}",
            rep.to_json()
        );
        assert!(
            rep.to_text()
                .contains("ABANDONED on this reader's own deadline"),
            "{}",
            rep.to_text()
        );
    }

    /// The CONTROL, and the leg that keeps the field structural: a capture that
    /// abandoned nothing still carries the field, at zero, and stays complete.
    ///
    /// Without it a consumer would have to test for the key's presence to learn
    /// whether this build reassembles -- the same rule R311y648's encrypted
    /// object is structural for.
    #[test]
    fn a_capture_that_abandoned_nothing_carries_the_field_at_zero() {
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut d = Dissection::new();
        d.push_packet_at(
            LINKTYPE_ETHERNET,
            0,
            Some(0),
            &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &keepalive),
        );
        assert_eq!(d.expired_chains(), 0);
        let rep = crate::report::CaptureReport::of(&d);
        assert!(
            rep.to_json()
                .contains(
                    "\"reassembly\":{\"expired_chains\":0,\"abandoned_at_end\":0,\"abandoned_on_eviction\":0}"
                ),
            "the field is structural, in every feature arm: {}",
            rep.to_json()
        );
        assert!(!rep.to_text().contains("ABANDONED"), "{}", rep.to_text());
        assert!(rep.is_complete(), "{}", rep.to_text());
    }

    /// R311y655 (§1.1f) — a chain still OPEN when the capture ends is abandoned
    /// and said so, rather than held forever by a sweep that never runs.
    ///
    /// The sweep is driven by the NEXT packet on the same flow advancing that
    /// flow's clock. A chain opened by the LAST fragment on a flow therefore has
    /// no sweep coming: measured before this round, such a capture reported
    /// `expired_chains == 0`, `complete: true`, and the text said "capture:
    /// complete" while the message the fragment belonged to was in no total
    /// anywhere.
    ///
    /// It is verbatim R311y609's argument for `force_oldest_gap`, one layer in:
    /// "no further packet is coming" is a fact only the caller has, which is why
    /// the new verb is called from `finish` and not from a destructor.
    ///
    /// Counted APART from the deadline sweep, and the text says why: a reader
    /// told a chain expired can widen the window, and a reader told the file ran
    /// out cannot.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_chain_still_open_when_the_capture_ends_is_abandoned_and_said_so() {
        let fragment = |sn: u8, more: bool, piece: &[u8]| {
            let mut wire = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAGMENT
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                    | if more {
                        wz_codecs::wire_const::FLAG_T_FRAGMENT_M
                    } else {
                        0
                    },
                sn,
            ];
            wire.extend_from_slice(piece);
            wire
        };
        let mut d = Dissection::with_limits(DissectionLimits {
            // A window LONGER than the capture, on purpose: this fixture must
            // not be rescuable by the deadline sweep, or it would be measuring
            // R311y654's leg a second time.
            reassembly_window_ms: Some(600_000),
            ..DissectionLimits::default()
        });
        for (i, (from_low, ts, message)) in [
            (true, 0u64, init_datagram(false, &[])),
            (false, 0, init_datagram(true, &[])),
            (true, 0, open_datagram(false)),
            (false, 0, open_datagram(true)),
            // THE LAST PACKET opens a chain. Nothing follows it, so nothing
            // advances this flow's clock again.
            (true, 10, fragment(0, true, &[0xDE, 0xAD])),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, Some(ts), &packet);
        }
        // ANTI-VACUITY: nothing has expired and nothing may have, so whatever
        // the verdict says after `finish` is said by the new verb alone.
        assert_eq!(d.abandoned_chains(), 0, "not until the caller says so");
        assert_eq!(
            d.expired_chains(),
            0,
            "and the deadline must NOT be reached"
        );
        assert!(
            crate::report::CaptureReport::of(&d).is_complete(),
            "the pre-finish verdict is the one this round changes"
        );

        d.finish();
        assert_eq!(d.abandoned_chains(), 1);
        // R311y725 (N2) — and the verdict NAMES it, which the pre-`finish`
        // assertion above cannot: that one is about `is_complete` alone.
        assert!(
            crate::report::CaptureReport::of(&d)
                .reasons()
                .contains(&crate::report::VerdictReason::AbandonedChains),
            "a chain still open at the end is its own leg: {:?}",
            crate::report::CaptureReport::of(&d).reasons()
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            crate::report::CaptureReport::of(&d).reasons(),
            alloc::vec![crate::report::VerdictReason::AbandonedChains],
            "the chain left open is the whole of this verdict"
        );
        // R311y713 (§B7/§B6) — and WHAT WAS IN IT, and WHOSE it was. Three
        // rounds recorded that the bytes of a lost chain were counted by
        // nothing; the fragment above carries two, and the sweep is the only
        // moment they can be counted because the staging goes back to the
        // arena immediately after.
        assert_eq!(
            d.chain_bytes_lost(),
            2,
            "the abandoned chain's two staged bytes must be reported"
        );
        let lost_by = &d.datagram_flows()[0];
        assert_eq!(
            (lost_by.chain_loss().chains, lost_by.chain_loss().bytes),
            (1, 2),
            "and the FLOW that lost them must be able to say so — a \
             capture-wide counter cannot name the link that is losing"
        );
        assert_eq!(
            d.expired_chains(),
            0,
            "a chain the file ran out on did not miss a deadline, and folding \
             the two would tell a reader to widen a window that was never hit"
        );
        let rep = crate::report::CaptureReport::of(&d);
        assert!(!rep.is_complete(), "{}", rep.to_text());
        assert!(
            rep.to_json().contains(
                "\"expired_chains\":0,\"abandoned_at_end\":1,\"abandoned_on_eviction\":0"
            ),
            "{}",
            rep.to_json()
        );
        assert!(
            rep.to_text().contains("still OPEN when the capture ended"),
            "{}",
            rep.to_text()
        );

        // IDEMPOTENT, which `finish`'s own contract requires: a second call
        // abandons nothing further rather than counting the same chain twice.
        d.finish();
        assert_eq!(d.abandoned_chains(), 1);

        // THE STREAM LEG, and it earned its place by falsification: with only
        // the datagram fixture above, deleting `finish`'s walk over the STREAM
        // flow table left every test green. The two tables hold the same kind
        // of session and a TCP capture ends on an open chain exactly as a UDP
        // one does.
        let framed = |wire: &[u8]| {
            let mut out = (wire.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(wire);
            out
        };
        let mut e = Dissection::with_limits(DissectionLimits {
            reassembly_window_ms: Some(600_000),
            ..DissectionLimits::default()
        });
        let mut seq_low = 1000u32;
        let mut seq_high = 5000u32;
        for (i, (from_low, wire)) in [
            (true, init_datagram(false, &[])),
            (false, init_datagram(true, &[])),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            (true, fragment(0, true, &[0xDE, 0xAD])),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = framed(&wire);
            let (seq, pkt) = if from_low {
                let s = seq_low;
                seq_low += bytes.len() as u32;
                (s, tcp_packet(s, &bytes))
            } else {
                let s = seq_high;
                seq_high += bytes.len() as u32;
                (s, tcp_packet_reverse(s, &bytes))
            };
            let _ = seq;
            e.push_packet_at(LINKTYPE_ETHERNET, i, Some(10), &pkt);
        }
        assert_eq!(e.flows().len(), 1, "the fixture must be a STREAM flow");
        assert_eq!(e.abandoned_chains(), 0);
        e.finish();
        assert_eq!(
            e.abandoned_chains(),
            1,
            "a TCP capture ends on an open chain exactly as a UDP one does"
        );
    }

    /// R311y656 (§4.4) — a half-assembled message that leaves with an evicted
    /// flow is counted, and counted as its own cause.
    ///
    /// R311y655's carry stated this as a HYPOTHESIS reasoned from the code, and
    /// this is the measurement: before the fix an evicted flow holding an open
    /// chain moved neither `expired_chains` nor `abandoned_chains`. The capture
    /// was already marked incomplete by `drops.flows`, so the shortfall was
    /// visible — as a dropped FLOW. That a partially reassembled MESSAGE went
    /// with it was in no number anywhere, which is the R311y650 shape exactly:
    /// the loss counter carried and the finding did not.
    ///
    /// Its own field rather than a share of the other two because the ACTION
    /// differs: this one asks for a larger `max_flows_per_table`, and telling a reader to
    /// widen a reassembly window would be advice about the wrong knob.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_chain_that_leaves_with_an_evicted_flow_is_counted_as_its_own_cause() {
        let fragment = |sn: u8, more: bool, piece: &[u8]| {
            let mut wire = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAGMENT
                    | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
                    | if more {
                        wz_codecs::wire_const::FLAG_T_FRAGMENT_M
                    } else {
                        0
                    },
                sn,
            ];
            wire.extend_from_slice(piece);
            wire
        };
        let mut d = Dissection::with_limits(DissectionLimits {
            // Far longer than the capture, so the deadline sweep can rescue
            // nothing and the number below is the eviction's alone.
            reassembly_window_ms: Some(600_000),
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        for (i, (from_low, message)) in [
            (true, init_datagram(false, &[])),
            (false, init_datagram(true, &[])),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            (true, fragment(0, true, &[0xDE, 0xAD])),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = if from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &message)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, Some(10), &packet);
        }
        assert_eq!(d.evicted_chains(), 0, "nothing has been evicted yet");

        // A second 5-tuple takes the only slot.
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        d.push_packet_at(
            LINKTYPE_ETHERNET,
            9,
            Some(11),
            &udp_packet([10, 0, 0, 9], 43211, [10, 0, 0, 2], 7447, &keepalive),
        );
        assert_eq!(d.datagram_flows().len(), 1, "the cap must have evicted");
        assert_eq!(d.drops().flows, 1);

        assert_eq!(
            (d.evicted_chains(), d.abandoned_chains(), d.expired_chains()),
            (1, 0, 0),
            "the chain left with the flow and only ONE of the three causes may \
             claim it"
        );
        let rep = crate::report::CaptureReport::of(&d);
        assert!(!rep.is_complete());
        assert!(
            rep.to_json().contains("\"abandoned_on_eviction\":1"),
            "{}",
            rep.to_json()
        );
        assert!(
            rep.to_text()
                .contains("raising max_flows_per_table is what would have kept"),
            "the reader must be pointed at the knob that would have helped: {}",
            rep.to_text()
        );

        // AND `finish` MUST NOT COUNT IT AGAIN: the flow is gone, so there is
        // nothing left to abandon and the three numbers stand.
        d.finish();
        assert_eq!(
            (d.evicted_chains(), d.abandoned_chains()),
            (1, 0),
            "a chain counted once must not be counted twice by the exit after it"
        );

        // THE STREAM LEG, and it earned its place the same way R311y655's did:
        // with only the datagram fixture, dropping the STREAM eviction's
        // abandonment left every test green. Two tables, two evictions, two
        // witnesses.
        let framed = |wire: &[u8]| {
            let mut out = (wire.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(wire);
            out
        };
        let mut e = Dissection::with_limits(DissectionLimits {
            reassembly_window_ms: Some(600_000),
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        let mut seq_low = 1000u32;
        let mut seq_high = 5000u32;
        for (i, (from_low, wire)) in [
            (true, init_datagram(false, &[])),
            (false, init_datagram(true, &[])),
            (true, open_datagram(false)),
            (false, open_datagram(true)),
            (true, fragment(0, true, &[0xDE, 0xAD])),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = framed(&wire);
            let pkt = if from_low {
                let s = seq_low;
                seq_low += bytes.len() as u32;
                tcp_packet(s, &bytes)
            } else {
                let s = seq_high;
                seq_high += bytes.len() as u32;
                tcp_packet_reverse(s, &bytes)
            };
            e.push_packet_at(LINKTYPE_ETHERNET, i, Some(10), &pkt);
        }
        assert_eq!(e.flows().len(), 1, "the fixture must be a STREAM flow");
        assert_eq!(e.evicted_chains(), 0);
        // A second 5-tuple, by source ADDRESS since the helper fixes the ports.
        let mut other = tcp_packet(
            9000,
            &framed(&[wz_session_core::wire_const::T_MID_KEEP_ALIVE]),
        );
        other[26] = 99;
        e.push_packet_at(LINKTYPE_ETHERNET, 9, Some(11), &other);
        assert_eq!(e.flows().len(), 1, "the cap must have evicted");
        assert_eq!(
            e.evicted_chains(),
            1,
            "a TCP flow leaves with its half-assembled message exactly as a UDP \
             one does"
        );
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

    /// R311y615 (§1.1f) — the capture instant reaches the FRAME, and it does so
    /// in EVERY feature arm.
    ///
    /// Deliberately ungated, and that is the whole assertion. The clock lived
    /// behind `reassembly` from R311y594 to R311y615 because expiry was its
    /// only consumer; a frame's timestamp is not a reassembly concept, and a
    /// build that reads pcap and cannot say when a packet arrived can answer no
    /// latency question at all. This test is pinned in Layer C1bt's
    /// `--no-default-features` SET, so re-gating the clock removes it from that
    /// build and the lane says so instead of the count quietly shrinking.
    ///
    /// The `None` leg is what keeps the `Some` leg from being free: a field
    /// hardwired to `Some(0)` would satisfy the first assertion and fail the
    /// second.
    #[test]
    fn a_frame_carries_the_capture_instant_in_every_feature_arm() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &keepalive);

        let mut stamped = Dissection::new();
        stamped.push_packet_at(LINKTYPE_ETHERNET, 0, Some(4_242), &pkt);
        assert_eq!(
            stamped.datagram_flows()[0].frames[0].observed_at_ms,
            Some(4_242),
            "the instant handed to push_packet_at must reach the frame"
        );

        let mut unstamped = Dissection::new();
        unstamped.push_packet(LINKTYPE_ETHERNET, 0, &pkt);
        assert_eq!(
            unstamped.datagram_flows()[0].frames[0].observed_at_ms,
            None,
            "a source with no clock must not produce a plausible one"
        );
    }

    /// R311y631 (§1.2b) — a datagram carrying MORE THAN ONE transport message
    /// now yields ALL of them. R311y626 pinned the loss here; this is the same
    /// fixture with the answer changed.
    ///
    /// # What R311y626 got wrong
    ///
    /// Its rationale said one message per datagram "is right for zenoh's own
    /// UDP framing", citing this workspace's own sender. Neither reference
    /// implementation reads it that way. zenoh loops `while !batch.is_empty()`
    /// over a received unit (`zenoh-transport-1.5.0/src/multicast/rx.rs:287`),
    /// and pico does not even re-read the link while its buffer still holds
    /// bytes (`vendor/zenoh-pico/src/transport/multicast/rx.c:68-77`). So the
    /// silence was not a strict reading of a lax wire — it was messages both
    /// peers process and this observer dropped.
    ///
    /// # Why the second message is a KEEPALIVE and not a FRAME
    ///
    /// A `Frame` consumes the remainder of its unit by construction, so a real
    /// batch ends with one and a fixture that put a Frame first could never
    /// have a second message at all. Two KeepAlives is the smallest batch that
    /// can exist, which is what makes it the discriminator: one byte each, no
    /// body to get wrong, and the count is the whole assertion.
    #[test]
    fn a_datagram_carrying_two_messages_yields_both() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut two = Vec::new();
        two.extend_from_slice(&keepalive);
        two.extend_from_slice(&keepalive);

        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &two),
        );

        let flow = &d.datagram_flows()[0];
        assert_eq!(
            flow.frames.len(),
            2,
            "both messages of the batch are reported: {:?}",
            flow.frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        for (i, f) in flow.frames.iter().enumerate() {
            assert!(
                matches!(
                    f.frame,
                    Ok(wz_session_core::inbound::InboundFrame::KeepAlive { .. })
                ),
                "message {i} decodes as the KeepAlive it is: {:?}",
                f.frame
            );
            assert_eq!(
                f.stream_offset, 0,
                "both rode packet 0, and that is what the anchor names"
            );
            assert_eq!(
                f.batch_index, i,
                "and the batch index is what separates them"
            );
        }
        // Nothing was lost, so nothing is unaccounted for. The counter is the
        // OTHER half of this round: it is what speaks when the walk cannot
        // finish, and a silent zero here is what proves it is not just always
        // reporting something.
        assert_eq!(
            d.framing_health().unaccounted_batch_bytes,
            0,
            "every byte of the datagram was attributed to a decoded message"
        );
        assert_eq!(d.health().packets_skipped, 0);
        assert_eq!(d.framing_health().desyncs, 0);
    }

    /// R311y623 (§1.1x) — THE MIXED CASE, which neither leg above reaches: the
    /// observer's clock is STICKY, so an unstamped packet BEHIND a stamped one
    /// on the same flow inherits the earlier instant rather than reporting
    /// none.
    ///
    /// Correct for an advancing clock and required by the reassembly deadline —
    /// a sweep cannot run on a time that keeps vanishing — and it means a
    /// MIXED-STAMP SOURCE reports instants nobody told this observer. The
    /// consequence is load-bearing rather than academic: R311y620's three
    /// `time`-is-undecided pages depend on their captures being unstamped
    /// THROUGHOUT, and a single stamped packet in front would have made every
    /// later record answer a `time` term with an inherited number.
    ///
    /// Pinned rather than fixed. The two alternatives are both worse — a clock
    /// that resets to `None` breaks expiry, and one that refuses mixed sources
    /// rejects a real pcap — so what this round owes is a witness, not a
    /// change. Before it, nothing in the workspace said the behaviour was
    /// chosen.
    #[test]
    fn the_capture_clock_is_sticky_and_an_unstamped_packet_inherits_it() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &keepalive);

        let mut d = Dissection::new();
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(1_000), &pkt);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, None, &pkt);
        d.push_packet_at(LINKTYPE_ETHERNET, 2, Some(3_000), &pkt);

        let frames = &d.datagram_flows()[0].frames;
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].observed_at_ms, Some(1_000));
        assert_eq!(
            frames[1].observed_at_ms,
            Some(1_000),
            "the unstamped packet reports a time it was never given"
        );
        assert_eq!(
            frames[2].observed_at_ms,
            Some(3_000),
            "and a later stamp moves the clock on"
        );
    }

    /// THE OTHER HALF, and the one R311y620's undecided pages rest on: a
    /// capture with NO stamp anywhere leaves every frame's instant absent.
    ///
    /// Its own page rather than a fourth assertion above, because it is a
    /// different claim: the first says the clock STICKS once set, this says it
    /// is never set by accident. A `now_ms()` of 0 read as a time is exactly
    /// how an unmeasured capture starts answering time questions.
    #[test]
    fn a_capture_with_no_stamp_anywhere_leaves_every_frame_timeless() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let pkt = udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &keepalive);

        let mut d = Dissection::new();
        for i in 0..3 {
            d.push_packet_at(LINKTYPE_ETHERNET, i, None, &pkt);
        }

        let flow = &d.datagram_flows()[0];
        assert!(
            flow.frames.iter().all(|f| f.observed_at_ms.is_none()),
            "no frame may carry an instant: {:?}",
            flow.frames
                .iter()
                .map(|f| f.observed_at_ms)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            flow.session.observed_at(),
            None,
            "and the observer must be able to say it was never told, \
             which `now_ms()` reporting 0 cannot"
        );
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

    /// R311y611 (§1.4b) — THE THIRD FRAMING, and the census had to reach it
    /// separately because it reaches the decoder by a THIRD route.
    ///
    /// A ws flow is neither of the other two: the bytes arrive over TCP, but a
    /// ws message boundary IS the framing, so `feed_websocket` calls
    /// `next_datagram` and the length prefix the stream path reads is absent.
    /// A codec missing from this crate's feature list, or a deframer that
    /// dropped a message kind, shows here and in neither of the other
    /// censuses.
    #[test]
    fn every_mid_on_a_websocket_link_is_named_rather_than_unknown() {
        for (name, wire) in crate::datagram_tests::transport_census() {
            let mut d = Dissection::new();
            let upgrade = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
            d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, upgrade));
            d.push_packet(
                LINKTYPE_ETHERNET,
                1,
                &tcp_packet(
                    1111,
                    7447,
                    1000 + upgrade.len() as u32,
                    &binary_frame(&wire, Some([0x11, 0x22, 0x33, 0x44])),
                ),
            );

            let flow = &d.flows()[0];
            assert!(
                flow.framing().is_websocket(),
                "{name}: the flow was not recognised as WebSocket, so this \
                 census would silently be measuring the stream path again"
            );
            assert_eq!(flow.frames.len(), 1, "{name} produced no frame at all");
            let f = &flow.frames[0];
            assert_eq!(
                f.prefix_width, 0,
                "{name}: a ws message carries no length prefix"
            );
            match &f.frame {
                Ok(InboundFrame::Unknown { mid }) => panic!(
                    "{name} (MID {mid:#04x}) is on zenoh's wire and this build \
                     cannot name it over a WEBSOCKET link"
                ),
                Ok(_) => {}
                Err(e) => panic!("{name} failed to decode over ws: {e:?}"),
            }
        }
    }

    /// R311y613 (§4.5) — THE DEFECT THIS ROUND FOUND, at the layer that had
    /// it.
    ///
    /// `WsDeframer` could recover from a structural desynchronisation and
    /// `feed_websocket` could not USE that: its loop is
    /// `while let Some(msg) = next_message()`, and every structural detection
    /// returned `None` on the spot, so the loop ended and the rest of the
    /// segment was never deframed. A deframer-level test drives `next_message`
    /// itself and calls it again after the `None`, which is exactly what the
    /// production caller does not do — so the defect lived one layer above
    /// where the recovery was built, and only a flow-level fixture reaches it.
    ///
    /// ONE packet carries the damage and the frames after it, which is the
    /// ordinary shape: a TCP segment holds many ws frames. Before R311y613 this
    /// flow reported the messages before the damage and nothing after it.
    #[test]
    fn a_structural_desync_mid_segment_does_not_end_the_flow() {
        // Two good messages, a reserved-opcode frame, then six more.
        let mut stream = Vec::new();
        let mut expected_before = 0;
        for i in 0..2u8 {
            stream.extend_from_slice(&zenoh_ws_frame(i));
            expected_before += 1;
        }
        stream.extend_from_slice(&crate::ws::tests::frame(true, 0x3, b"\x01reserved", None));
        for i in 2..8u8 {
            stream.extend_from_slice(&zenoh_ws_frame(i));
        }

        let mut d = Dissection::new();
        let upgrade = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, upgrade));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + upgrade.len() as u32, &stream),
        );

        let flow = &d.flows()[0];
        assert!(flow.framing().is_websocket());
        assert_eq!(
            flow.frames.len(),
            expected_before + 6,
            "the six messages AFTER the reserved opcode did not come back; \
             before R311y613 this was {expected_before}"
        );

        // And the loss is REPORTED rather than papered over — a flow that
        // recovered silently would be the other failure this crate exists to
        // avoid.
        let resyncs = flow.ws_resyncs();
        assert_eq!(resyncs.len(), 1, "exactly one recovery, and it is recorded");
        assert_eq!(
            resyncs[0].1.reason,
            ws::WsDesyncReason::ReservedOpcode { opcode: 0x3 }
        );
        assert_eq!(flow.ws_accounting().recoveries, 1);
        // R311y716 (§C G1) — AND IT REACHES THE VERDICT BY NAME. One of the
        // nine legs R311y715 found bound by nothing, and unpayable while the
        // verdict was a bool: a ws desync is detected by stepping over bytes,
        // so the same fixture shortens the rows more than one way. The SET is
        // what lets this line name its own leg without having to isolate it.
        let reasons = crate::report::CaptureReport::of(&d).reasons();
        assert!(
            reasons.contains(&crate::report::VerdictReason::WsDesyncs),
            "the WebSocket framing was lost and found, and the page must say \
             so: {reasons:?}"
        );
        // R311y727 (N19) -- and the WHOLE list, so this witness holds every
        // other leg QUIET as well as naming its own.
        assert_eq!(
            reasons,
            alloc::vec![crate::report::VerdictReason::WsDesyncs],
            "the WebSocket desync is the whole of this verdict"
        );
    }

    /// One zenoh batch in one unmasked ws BINARY frame — the flow-level twin of
    /// `ws::tests::zenoh_frame`, kept here because this module's `frame` helper
    /// is the one these fixtures are built with.
    fn zenoh_ws_frame(n: u8) -> Vec<u8> {
        // R311y631 (§1.2b / §1.4a) — ONE transport message per ws message, with
        // `n` riding INSIDE it as the sequence number.
        //
        // It was a KeepAlive followed by three copies of `n` as filler, and
        // filler is exactly what a batch walk reads as further messages —
        // `n == 1` is `T_MID_INIT`. A `Frame` consumes the remainder of its
        // framing unit by construction
        // (`zenoh-codec-1.5.0/src/transport/frame.rs:173`), so this shape holds
        // one message whatever the body is, which keeps this test about ws
        // RECOVERY instead of quietly becoming a test about batching.
        let mut payload = alloc::vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_codecs::wire_const::FLAG_T_FRAME_R,
            n, // sn, the one-byte VLE arm
        ];
        payload.extend_from_slice(&[0x1F, 0x00, 0x00, 0x00]);
        crate::ws::tests::frame(true, 0x2, &payload, None)
    }

    /// R311y613 (§1.4b) — the NETWORK census over the third framing, on the
    /// same rule R311y611 set for the transport one: a census that covered one
    /// link kind is how a space goes unchecked.
    ///
    /// The `is_websocket()` guard is the same one, and load-bearing for the
    /// same reason — without it a flow that failed ws detection would run the
    /// stream path and this test would silently re-measure the sibling.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn every_network_mid_inside_a_frame_is_named_over_websocket_too() {
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::passive::Carried;

        for (name, record) in crate::datagram_tests::network_census() {
            let wire = crate::datagram_tests::frame_carrying(&record);
            let mut d = Dissection::new();
            let upgrade = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
            d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, upgrade));
            d.push_packet(
                LINKTYPE_ETHERNET,
                1,
                &tcp_packet(
                    1111,
                    7447,
                    1000 + upgrade.len() as u32,
                    &binary_frame(&wire, Some([0x11, 0x22, 0x33, 0x44])),
                ),
            );

            let flow = &d.flows()[0];
            assert!(
                flow.framing().is_websocket(),
                "{name}: the flow was not recognised as WebSocket, so this \
                 census would silently be measuring the stream path again"
            );
            assert_eq!(flow.frames.len(), 1, "{name}: the frame never arrived");
            match &flow.frames[0].carried {
                Carried::Batch(batch) => {
                    assert_eq!(batch.halt, None, "{name}: the batch walk halted over ws");
                    if let NetworkMessage::Unknown { mid, .. } = &batch.messages[0] {
                        panic!(
                            "{name} (network MID {mid:#04x}) is unnamed over a \
                             WEBSOCKET link"
                        );
                    }
                }
                other => panic!("{name}: the frame carried {other:?}, not a batch"),
            }
        }
    }

    /// R311y612 (§4.1 + §4.2) — the WIRING of the hole path, both arms.
    ///
    /// Drive a real ws flow whose HTTP opening is cut by a hole two bytes in,
    /// then the same shape carrying a real LENGTH-PREFIXED zenoh stream. One
    /// discriminator answers both, and it must answer them DIFFERENTLY — a
    /// classifier that always says WebSocket would pass the first arm alone,
    /// which is why the negative arm is in the same test and not a sibling.
    ///
    /// Before R311y612 both arms answered `Stream`: a hole inside the opening
    /// forced that verdict, so the ws arm's RFC6455 frame headers were then
    /// read as zenoh length prefixes — a confident misread of every byte on
    /// the connection, and one nothing reported.
    #[test]
    fn a_hole_in_the_opening_is_decided_on_the_far_side_rather_than_guessed() {
        // Two bytes, a PREFIX of `GET ` — so `http_upgrade_verdict` answers
        // `NeedMore`, and the bytes that would settle it are the hole's.
        const HELD: usize = 2;
        const LOST: usize = 24;

        let drive = |stream: &[u8]| -> Dissection {
            let mut d = Dissection::new();
            d.set_gap_patience(Some(4));
            d.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &tcp_packet(1111, 7447, 1000, &stream[..HELD]),
            );
            // Sequence space HELD..HELD+LOST is never captured.
            for (i, chunk) in stream[HELD + LOST..].chunks(16).enumerate() {
                let at = HELD + LOST + i * 16;
                d.push_packet(
                    LINKTYPE_ETHERNET,
                    i + 1,
                    &tcp_packet(1111, 7447, 1000 + at as u32, chunk),
                );
            }
            d.finish();
            d
        };

        let mut ws_stream = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n".to_vec();
        for _ in 0..8 {
            ws_stream.extend_from_slice(&binary_frame(
                &bare_keepalive(),
                Some([0x11, 0x22, 0x33, 0x44]),
            ));
        }
        let d = drive(&ws_stream);
        let flow = &d.flows()[0];
        assert!(
            flow.framing().is_websocket(),
            "a hole in the opening must not turn a ws flow into a stream — \
             that is the §4.1 defect, and it made every later byte a misread"
        );
        let named = flow
            .frames
            .iter()
            .filter(|f| matches!(f.frame, Ok(InboundFrame::KeepAlive { .. })))
            .count();
        assert!(
            named >= 4,
            "the messages after the hole must decode; got {named} of 8 \
             ({:?})",
            flow.frames.iter().map(|f| &f.frame).collect::<Vec<_>>()
        );
        let acct = flow.ws_accounting();
        assert_eq!(
            (acct.desyncs, acct.recoveries),
            (2, 1),
            "the lost opening is REPORTED and then recovered from, not silently \
             assumed away. TWO desynchronisations because the opening belongs to \
             the CONNECTION: neither direction's frame boundary is known once it \
             is gone, and B is left scanning because this fixture gives it no \
             bytes to recover on. One recovery, on the direction that has any."
        );
        assert_eq!(flow.ws_resyncs().len(), 1);
        assert_eq!(
            flow.ws_resyncs()[0].1.reason,
            ws::WsDesyncReason::OpeningLost
        );

        // THE NEGATIVE ARM, on the identical shape: a real length-prefixed
        // zenoh stream, whose first byte is `H` so the verdict is `NeedMore`
        // for the same reason and the same `OpeningLost` path is entered.
        let mut tcp_stream: Vec<u8> = Vec::new();
        // A first frame whose 2-byte little-endian length reads `H\0` = 72.
        let filler = alloc::vec![0xA5u8; 71];
        let mut first = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        first.extend_from_slice(&filler);
        tcp_stream.extend_from_slice(&(first.len() as u16).to_le_bytes());
        tcp_stream.extend_from_slice(&first);
        assert_eq!(&tcp_stream[..1], b"H", "the fixture must reach NeedMore");
        for _ in 0..8 {
            tcp_stream.extend_from_slice(&[1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]);
        }
        let d = drive(&tcp_stream);
        let flow = &d.flows()[0];
        assert!(
            !flow.framing().is_websocket(),
            "a length-prefixed zenoh stream with a hole in its first bytes must \
             NOT be taken for WebSocket; a discriminator that always answers ws \
             passes the arm above and is worse than the defect it replaces"
        );
        assert!(
            matches!(flow.framing(), Framing::Stream),
            "and it must SETTLE — a flow left Undecided at `finish` reports \
             nothing, which is the silent hole in a new place"
        );
    }

    /// R311y612 (§4.1) — a hole in ONE direction's opening is settled by the
    /// OTHER direction's, when that one already carries the literal.
    ///
    /// The pre-R311y612 read consulted only the direction the hole landed in.
    /// A client `GET ` cut by a hole says nothing about a server that has
    /// already sent `HTTP/1.1 101`, and throwing that evidence away is a
    /// judgement where a measurement was available.
    #[test]
    fn the_other_directions_opening_settles_a_hole_in_this_one() {
        let mut d = Dissection::new();
        d.set_gap_patience(Some(4));
        // B speaks first and completely: the server's status line.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(
                7447,
                1111,
                2000,
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            ),
        );
        // A's opening is cut two bytes in.
        d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet(1111, 7447, 1000, b"GE"));
        let msg = binary_frame(&bare_keepalive(), Some([1, 2, 3, 4]));
        for i in 0..4usize {
            d.push_packet(
                LINKTYPE_ETHERNET,
                2 + i,
                &tcp_packet(1111, 7447, 1000 + 40 + (i * msg.len()) as u32, &msg),
            );
        }
        d.finish();

        let flow = &d.flows()[0];
        assert!(
            flow.framing().is_websocket(),
            "the server's `HTTP/1.1 101` is evidence and it was already held"
        );
        assert_eq!(
            flow.ws_accounting().desyncs,
            1,
            "exactly one direction lost its framing: A's, to the hole"
        );
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

    /// R311y652 — the vsock path's own LRU, which had no witness either.
    ///
    /// A third writer of `last_activity` and a third eviction decision resting
    /// on it. Neutering this one left all 325 tests green, exactly as the stream
    /// path's did: every vsock fixture creates its flows in activity order, and
    /// a table that never orders anything answers that identically.
    ///
    /// AF_VSOCK is the case where it matters most sharply, because the synthesis
    /// this module exists to test is per-flow: evicting the wrong flow throws
    /// away the running byte count that IS this path's sequence number, and the
    /// flow that comes back afterwards starts over at zero.
    #[test]
    fn the_vsock_flow_table_evicts_the_least_recently_active() {
        let msg = framed_keepalive();
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(2),
            ..DissectionLimits::default()
        });
        let at = |port: u32| vsockmon(3, port, 2, 7447, OP_PAYLOAD, &[], &msg);
        d.push_packet(LINKTYPE_VSOCK, 0, &at(0x0001_0001));
        d.push_packet(LINKTYPE_VSOCK, 1, &at(0x0002_0001));
        // Spoken for again before the third arrives -- the only shape that
        // separates "least recently active" from "first admitted".
        d.push_packet(LINKTYPE_VSOCK, 2, &at(0x0001_0001));
        d.push_packet(LINKTYPE_VSOCK, 3, &at(0x0003_0001));

        assert_eq!(d.flows().len(), 2, "the cap holds");
        assert_eq!(d.drops().flows, 1, "and the eviction is counted");
        let ports: Vec<u32> = d
            .flows()
            .iter()
            // MAX and not MIN: a vsock port is a 32-bit number far above the
            // 7447 on the other end, which is the opposite of the TCP case.
            .map(|f| f.flow.low.port.max(f.flow.high.port))
            .collect();
        assert_eq!(
            ports,
            alloc::vec![0x0001_0001, 0x0003_0001],
            "the LEAST RECENTLY ACTIVE must go, not the first admitted"
        );
    }
}

// ── R311y648 (§1.2a) — the ENCRYPTED-FLOW path. A zenoh deployment over
//    `tls/...` or `quic/...` is the ordinary production shape, and a capture of
//    one has to say what it is rather than what it failed to be. ──
#[cfg(test)]
mod tls_flow_tests {
    use super::*;
    use crate::link::LINKTYPE_ETHERNET;

    /// One TLS record: content type, legacy version, big-endian length.
    fn record(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![content_type, version[0], version[1]];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

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

    /// A TLS 1.3 connection as it appears on the wire: a ClientHello, the
    /// server's flight, then application data both ways.
    fn tls_dissection() -> Dissection {
        let hello = record(0x16, [0x03, 0x01], &[0x01, 0x00, 0x00, 0x30]);
        let server = record(0x16, [0x03, 0x03], &[0x02, 0x00, 0x00, 0x28]);
        let ccs = record(0x14, [0x03, 0x03], &[0x01]);
        let app_a = record(0x17, [0x03, 0x03], &[0xAB; 40]);
        // 800 bytes ON PURPOSE. Read as a zenoh stream this record's first two
        // bytes are a LITTLE-endian length prefix of 0x0317 = 791, and the unit
        // that follows opens with 0x03 -- `T_MID_CLOSE`. So a reader that let
        // ciphertext reach the observer does not merely get confused: it decodes
        // a Close nobody sent. `frames == 0` below is what holds that shut.
        let app_b = record(0x17, [0x03, 0x03], &[0xCD; 800]);

        let mut d = Dissection::new();
        let mut a_seq = 1000u32;
        let mut b_seq = 5000u32;
        let mut i = 0usize;
        let mut push = |d: &mut Dissection, from_a: bool, bytes: &[u8], seq: &mut u32| {
            let pkt = if from_a {
                tcp_packet(1111, 7447, *seq, bytes)
            } else {
                tcp_packet(7447, 1111, *seq, bytes)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
            *seq += bytes.len() as u32;
            i += 1;
        };
        push(&mut d, true, &hello, &mut a_seq);
        let mut flight = server.clone();
        flight.extend_from_slice(&ccs);
        flight.extend_from_slice(&app_b);
        push(&mut d, false, &flight, &mut b_seq);
        push(&mut d, true, &app_a, &mut a_seq);
        d
    }

    /// R311y725 (N4) — a PLAINTEXT ServerHello naming `suite`, with
    /// `session_id_len` bytes of `legacy_session_id_echo` in front of the field.
    ///
    /// The echo length is a parameter because it is the one variable-length
    /// field before the suite, so it is the only thing that can turn the offset
    /// into a walk. A fixture that only ever used one length would pass against
    /// a reader that had hard-coded the offset for it.
    fn server_hello(suite: u16, session_id_len: usize) -> Vec<u8> {
        let mut hs = alloc::vec![0x03, 0x03];
        hs.extend_from_slice(&[0x5A; 32]);
        hs.push(session_id_len as u8);
        hs.extend(core::iter::repeat_n(0x11, session_id_len));
        hs.extend_from_slice(&suite.to_be_bytes());
        // `legacy_compression_method`, then an empty extensions vector. Neither
        // is read; they are here so the handshake length is the real one.
        hs.push(0);
        hs.extend_from_slice(&[0x00, 0x00]);
        let mut body = alloc::vec![0x02];
        body.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&hs);
        record(0x16, [0x03, 0x03], &body)
    }

    /// [`tls_dissection`] with the server's flight opening on `hello` — the
    /// same five records and the same two application records, so every figure
    /// but the AEAD overhead is unchanged between the variants.
    fn tls_dissection_with(hello_record: &[u8]) -> Dissection {
        let hello = record(0x16, [0x03, 0x01], &[0x01, 0x00, 0x00, 0x30]);
        let ccs = record(0x14, [0x03, 0x03], &[0x01]);
        let app_a = record(0x17, [0x03, 0x03], &[0xAB; 40]);
        let app_b = record(0x17, [0x03, 0x03], &[0xCD; 800]);

        let mut d = Dissection::new();
        let mut a_seq = 1000u32;
        let mut b_seq = 5000u32;
        let mut i = 0usize;
        let mut push = |d: &mut Dissection, from_a: bool, bytes: &[u8], seq: &mut u32| {
            let pkt = if from_a {
                tcp_packet(1111, 7447, *seq, bytes)
            } else {
                tcp_packet(7447, 1111, *seq, bytes)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
            *seq += bytes.len() as u32;
            i += 1;
        };
        push(&mut d, true, &hello, &mut a_seq);
        let mut flight = hello_record.to_vec();
        flight.extend_from_slice(&ccs);
        flight.extend_from_slice(&app_b);
        push(&mut d, false, &flight, &mut b_seq);
        push(&mut d, true, &app_a, &mut a_seq);
        d
    }

    /// R311y725 (N4) — THE PLAINTEXT FLOOR IS MEASURED AGAINST THE NEGOTIATED
    /// SUITE, not against the widest tag any suite could have used.
    ///
    /// ## What the register carried
    ///
    /// N4: "the TLS plaintext floor is measured WITHOUT the suite -- the
    /// handshake carries a cipher suite and this reader does not pull it out;
    /// pulling it out tightens the floor by 8 bytes per record on CCM_8".
    /// R311y716 wrote the floor and said so in its own doc comment: 16 is the
    /// largest tag, subtracting it can only understate the plaintext, and that
    /// is what a floor must do. True, and loose — the suite is on the wire, in
    /// the clear, in the one handshake message TLS 1.3 does not protect.
    ///
    /// ## The four legs
    ///
    /// 1. A `TLS_AES_128_CCM_8_SHA256` connection is READ as one, and its
    ///    overhead is 9 bytes per record rather than 17.
    /// 2. THE VALUE, not the flag: the floor rises by exactly 8 bytes per
    ///    application record against the same capture negotiating AES-GCM.
    /// 3. The suite survives a variable-length `legacy_session_id_echo`, which
    ///    is the only field that makes the offset a walk.
    /// 4. ANTI-VACUITY: a capture with no readable ServerHello reports `None`
    ///    and keeps the widest tag, so leg 2's difference followed the SUITE and
    ///    not the fixture.
    #[test]
    fn the_plaintext_floor_is_measured_against_the_negotiated_cipher_suite() {
        // The fixture's two application records, whose declared lengths are what
        // the census counts.
        const APPLICATION_BYTES: u64 = 40 + 800;
        const APPLICATION_RECORDS: u64 = 2;

        let census = |d: &Dissection| d.encrypted_flows()[0].totals();

        // (1) CCM_8, whose whole point is the truncated tag.
        let ccm = tls_dissection_with(&server_hello(0x1305, 32));
        assert_eq!(
            ccm.encrypted_flows()[0].negotiated_suite,
            Some(0x1305),
            "the ServerHello names the suite in the clear and this reader must \
             read it"
        );
        assert_eq!(
            crate::tls::suite_name(0x1305),
            Some("TLS_AES_128_CCM_8_SHA256")
        );
        assert_eq!(
            census(&ccm).aead_overhead_bytes,
            APPLICATION_RECORDS * (8 + 1),
            "an 8-byte tag plus the inner content type, per application record"
        );
        assert_eq!(
            census(&ccm).application_bytes,
            APPLICATION_BYTES,
            "the ciphertext count is untouched -- only what is subtracted moved"
        );

        // (2) THE VALUE. The same capture under AES-128-GCM, whose tag is 16.
        let gcm = tls_dissection_with(&server_hello(0x1301, 32));
        assert_eq!(gcm.encrypted_flows()[0].negotiated_suite, Some(0x1301));
        assert_eq!(
            census(&gcm).aead_overhead_bytes,
            APPLICATION_RECORDS * (16 + 1)
        );
        assert_eq!(
            census(&ccm).application_bytes_at_least() - census(&gcm).application_bytes_at_least(),
            APPLICATION_RECORDS * 8,
            "reading the suite is worth exactly 8 bytes per record on CCM_8, \
             which is the number the register carried"
        );

        // (3) The echo length is the only variable-length field in front of the
        // suite. A reader that had hard-coded the offset passes leg (1) and
        // fails here.
        for echo in [0usize, 1, 32] {
            let d = tls_dissection_with(&server_hello(0x1305, echo));
            assert_eq!(
                d.encrypted_flows()[0].negotiated_suite,
                Some(0x1305),
                "a {echo}-byte legacy_session_id_echo must not move the suite"
            );
        }

        // (4) ANTI-VACUITY. The original fixture's ServerHello is a handshake
        // header with no body, so there is no suite to read and the floor must
        // stay exactly where R311y716 left it.
        let unknown = tls_dissection();
        assert_eq!(
            unknown.encrypted_flows()[0].negotiated_suite,
            None,
            "a truncated ServerHello must not be read as a suite"
        );
        assert_eq!(
            census(&unknown).aead_overhead_bytes,
            APPLICATION_RECORDS * (crate::tls::AEAD_TAG_UNKNOWN + 1),
            "not knowing keeps the WIDEST tag, which is the only direction a \
             floor may be wrong in"
        );
        assert_eq!(
            census(&unknown).application_bytes_at_least(),
            census(&gcm).application_bytes_at_least(),
            "and it agrees with the 16-byte suite, which is what makes the \
             pre-R311y725 number the unknown case rather than a regression"
        );
    }

    /// R311y648 (§1.2a) — THE DEFECT. A capture of a `tls/...` deployment used
    /// to report a flow with ZERO frames and PERFECT health, which reads as
    /// "this deployment carried no zenoh traffic".
    ///
    /// Measured before the fix and recorded here so the shape is not lost:
    /// `frames=0 desyncs=0 recoveries=0 skipped=0`, every framing-health field
    /// zero, and `complete: true`. Not one counter in the report disagreed with
    /// "nothing happened". That is the worst output this crate can produce --
    /// worse than a decode error, which at least points at itself.
    ///
    /// The flow is now NAMED, and the assertions are about what a reader can
    /// act on: which flows, how many records, how many bytes, and why the
    /// plaintext is absent.
    #[test]
    fn a_tls_flow_is_named_as_encrypted_rather_than_reported_empty() {
        let d = tls_dissection();
        assert_eq!(d.flows().len(), 1);
        assert!(
            d.flows()[0].framing().is_encrypted(),
            "the flow must not be classified as a zenoh byte stream"
        );

        let enc = d.encrypted_flows();
        assert_eq!(enc.len(), 1);
        let totals = enc[0].totals();
        // The fixture is ClientHello / ServerHello / CCS / two application
        // records -- five records, two of them application data.
        assert_eq!(totals.records, 5, "{:?}", enc[0]);
        assert_eq!(totals.application_records, 2);
        assert_eq!(
            totals.application_bytes,
            40 + 800,
            "the ciphertext bytes, which bound the zenoh session inside"
        );
        // THE LEG THAT KEEPS CIPHERTEXT OUT OF THE DECODER. This fixture's
        // application record decodes as a zenoh Close if it ever reaches the
        // observer, so a build that counted the records AND fed them onward
        // would report a message no peer sent -- the same confident-wrong-answer
        // class the empty flow was, pointing the other way.
        assert_eq!(
            d.flows()[0].frames.len(),
            0,
            "ciphertext must never reach the zenoh decoder"
        );
        // R311y661 — with NO decryption pass run over this dissection, which is
        // now the thing that makes the statement true rather than a constant.
        assert_eq!(
            enc[0].not_decrypted,
            Some(crate::tls::NotDecrypted::NoKeysSupplied)
        );
        // Both directions are counted, not just the one that settled the
        // question: a census of the client alone would report half a session.
        assert_eq!(
            enc[0].per_direction[0].records, 2,
            "the client sent a ClientHello and one application record"
        );
        assert_eq!(
            enc[0].per_direction[1].records, 3,
            "the server sent ServerHello, CCS and one application record"
        );

        // AND THE VERDICT MOVES. The old report said `complete` about a
        // capture it could not see into, which is the half that makes the
        // silence dangerous rather than merely unhelpful.
        let report = crate::report::CaptureReport::of(&d);
        assert!(!report.is_complete(), "{}", report.to_text());
        // R311y664 — the reason moved into a bracketed tag so the sentence can
        // also state the OPPOSITE outcome. It is still the reason, and a
        // keyless dissection still names it.
        assert!(
            report.to_text().contains("NOT DECRYPTED")
                && report.to_text().contains("[no_keys_supplied]"),
            "the text must say why: {}",
            report.to_text()
        );
        let json = report.to_json();
        assert!(
            json.contains("\"flows\":1")
                && json.contains("\"application_bytes\":840")
                && json.contains("\"decrypted\":false")
                && json.contains("\"reason\":\"no_keys_supplied\""),
            "the export must carry the finding: {json}"
        );
    }

    /// R311y659 (§1.2a) — the ClientHello's RANDOM reaches the report, which is
    /// the only thing that can tie a flow to the secrets in the capture's own
    /// key log.
    ///
    /// A key log holds every session a process ever made, keyed by this
    /// 32-byte field. Without it R311y658's parsed secrets have nothing to be
    /// selected BY, which is why this is the first move of the wiring rather
    /// than part of it.
    ///
    /// The reader is a SEPARATE question from `client_hello_verdict` and not a
    /// widening of it: that function's narrowness is what R311y649 measured as
    /// load-bearing, so this one decides nothing and only reads a field out of
    /// bytes already decided about.
    #[test]
    fn the_client_hello_random_reaches_the_report() {
        // A ClientHello whose body is 0x30 = 48 bytes: version(2) + random(32)
        // + the rest. The random is a recognisable ramp so a wrong offset
        // cannot land on it by accident.
        let mut body = alloc::vec![0x03u8, 0x03];
        body.extend((0..32u8).map(|i| i.wrapping_mul(5).wrapping_add(1)));
        body.resize(0x30, 0);
        let mut hello_body = alloc::vec![0x01u8, 0x00, 0x00, body.len() as u8];
        hello_body.extend_from_slice(&body);
        let hello = record(0x16, [0x03, 0x01], &hello_body);
        let app = record(0x17, [0x03, 0x03], &[0xAB; 40]);

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &hello));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + hello.len() as u32, &app),
        );
        d.finish();
        assert!(
            d.flows()[0].framing().is_encrypted(),
            "the fixture must be TLS"
        );

        let expected: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
        assert_eq!(
            d.encrypted_flows()[0].client_random,
            Some(expected),
            "the random must arrive from the wire, at the RFC 8446 offset"
        );

        // A CAPTURE THAT STOPPED INSIDE THE RANDOM answers `None`, not a
        // zero-padded value. Found by falsification: with the full-length
        // fixture alone, padding a partial read to 32 bytes passed -- and a
        // padded random would key a connection under something no key log
        // contains, which is a lookup that fails for a reason nobody can see.
        for cut in [11usize, 20, 42] {
            assert_eq!(
                crate::tls::client_hello_random(&hello[..cut.min(hello.len())]),
                None,
                "a random cut at {cut} must not be completed by this reader"
            );
        }
        assert_eq!(
            crate::tls::client_hello_random(&hello[..43]),
            Some(expected),
            "and 43 bytes is exactly enough, so the bound above is not \
             refusing everything"
        );
    }

    /// THE OTHER HALF, and it is a real limit rather than an omission: a flow
    /// recognised by its record CHAIN has no ClientHello to read a random from,
    /// so it cannot be matched to a key log at all.
    ///
    /// `None` and not 32 zero bytes, so a caller has to say so rather than look
    /// up a connection that no log contains.
    #[test]
    fn a_flow_recognised_by_its_chain_has_no_random_to_offer() {
        let d = mid_session_tls();
        assert!(d.flows()[0].framing().is_encrypted());
        assert_eq!(
            d.encrypted_flows()[0].client_random,
            None,
            "a mid-session capture has no ClientHello in it"
        );
    }

    /// R311y660 (§1.2a) — what the kept records are NUMBERED by, and what is
    /// not kept at all.
    ///
    /// Three legs, and all three earned their place by falsification: with the
    /// end-to-end fixture alone, keeping ChangeCipherSpec records, numbering
    /// from `kept.len()`, and handing a half-record on all passed.
    #[test]
    fn the_kept_records_are_numbered_by_what_is_protected() {
        let app = |n: u8| record(0x17, [0x03, 0x03], &[n; 20]);
        let ccs = record(0x14, [0x03, 0x03], &[0x01]);

        // LEG 1 -- a ChangeCipherSpec consumes no number. It is plaintext
        // middlebox compatibility (RFC 8446 §5) and is not protected, so
        // counting it would put every later record one place too far along and
        // every later record would fail to open.
        let mut stream = app(0xA0);
        stream.extend_from_slice(&ccs);
        stream.extend_from_slice(&app(0xA1));
        stream.extend_from_slice(&app(0xA2));
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &stream));
        d.finish();
        let flow = &d.encrypted_flows()[0];
        assert_eq!(
            flow.kept_records[0]
                .iter()
                .map(|r| r.index)
                .collect::<Vec<_>>(),
            alloc::vec![0, 1, 2],
            "the CCS between them must not consume a sequence number"
        );
        assert_eq!(flow.kept_records[0].len(), 3, "and must not be kept");
        assert_eq!(
            flow.per_direction[0].records, 4,
            "the CENSUS still counts it -- it was on the wire"
        );

        // LEG 2 -- a record the capture stopped INSIDE is not handed on. Half a
        // record cannot be opened, and handing it to a decryptor would make its
        // failure look like a wrong key.
        // TWO whole records and then a partial one: the recogniser needs
        // `TLS_CHAIN_DEPTH` complete records before it will call the flow
        // encrypted at all, so a fixture with one would be measuring the
        // recogniser rather than the keeper.
        let mut cut = app(0xB0);
        let whole = cut.len();
        cut.extend_from_slice(&app(0xB1));
        cut.extend_from_slice(&app(0xB2)[..10]);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &cut));
        d.finish();
        let flow = &d.encrypted_flows()[0];
        assert_eq!(flow.kept_records[0].len(), 2, "only the whole ones");
        assert_eq!(flow.kept_records[0][0].bytes.len(), whole);
        assert_eq!(
            flow.per_direction[0].trailing_bytes, 5,
            "and the shortfall is still named -- as the PAYLOAD bytes present, \
             which is what `carries_tls_records` has always counted: the header \
             was read, and 10 bytes of a 25-byte record leaves 5 behind it"
        );

        // LEG 3 -- past the bound the OLDEST goes, and the survivors keep the
        // numbers they were given. Numbering from the kept list's length would
        // renumber every record each time one was dropped, and every one of
        // them would then open at the wrong sequence.
        let mut d = Dissection::new();
        let mut seq = 1000u32;
        for i in 0..(crate::tls::MAX_KEPT_RECORDS_PER_DIRECTION + 4) {
            let r = app((i % 251) as u8);
            d.push_packet(LINKTYPE_ETHERNET, i, &tcp_packet(1111, 7447, seq, &r));
            seq += r.len() as u32;
        }
        d.finish();
        let flow = &d.encrypted_flows()[0];
        assert_eq!(
            flow.kept_records[0].len(),
            crate::tls::MAX_KEPT_RECORDS_PER_DIRECTION
        );
        assert_eq!(flow.records_dropped[0], 4, "and the loss is counted");
        assert_eq!(
            flow.kept_records[0][0].index, 4,
            "the first SURVIVOR keeps the number it was given, which is what a \
             decryptor opens it at"
        );
        // AND THE LAST ONE, which is the leg that separates a running counter
        // from the kept list's length. The first survivor was numbered before
        // the bound ever bit, so it cannot tell them apart -- every record
        // after the first drop can.
        assert_eq!(
            flow.kept_records[0].last().expect("the list is full").index,
            (crate::tls::MAX_KEPT_RECORDS_PER_DIRECTION + 3) as u64,
            "a record numbered from the LIST would restart at the cap and every \
             record after the first drop would open at the wrong sequence"
        );
    }

    /// R311y648 — the census counts RECORDS, and stops counting when the chain
    /// breaks rather than inventing one out of the bytes that broke it.
    ///
    /// A recognised flow keeps being walked, and what follows a TLS handshake
    /// is not guaranteed to be TLS: a gap, a mid-capture splice, or a
    /// misrecognition puts bytes there that open no record. The walk refuses
    /// them and the census stays where it was -- which is the difference
    /// between "5 records" and "5 records and one I made up".
    ///
    /// Driven with bytes that pass the VERSION check and fail the content-type
    /// one, so the leg under test is the content type and not the pair.
    #[test]
    fn a_chain_that_stops_being_tls_stops_the_census() {
        let d = tls_dissection();
        let before = d.encrypted_flows()[0].per_direction[0].records;

        let mut d = tls_dissection();
        // `0xFF` is no content type; `0x03 0x03` is a legal version, and the
        // length that follows is well-formed. Only the first byte refuses it.
        let junk = alloc::vec![0xFFu8, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        // CONTIGUOUS with what the client already sent (9-byte ClientHello +
        // 45-byte application record from seq 1000), so this drives the chain
        // walk and not the gap path -- a hole would clear the pending tail for
        // a different reason and the leg would prove nothing.
        d.push_packet(LINKTYPE_ETHERNET, 9, &tcp_packet(1111, 7447, 1054, &junk));

        assert_eq!(
            d.encrypted_flows()[0].per_direction[0].records,
            before,
            "bytes that open no record must not become one"
        );
    }

    /// THE CONTROL, and the leg that makes the recogniser a measurement rather
    /// than a prefix match.
    ///
    /// A zenoh stream frames every unit with a 2-byte LITTLE-endian length, so
    /// a 790-byte unit whose first message is an `INIT` is `[0x16, 0x03, 0x01,
    /// ..]` -- byte for byte the opening of a TLS 1.0 ClientHello record. A
    /// detector that matched those three bytes would classify a real zenoh flow
    /// as encrypted and produce exactly the silence it exists to end, pointing
    /// the other way.
    ///
    /// Driven with the ambiguous prefix ON PURPOSE, so the test fails if the
    /// discriminator is ever weakened to a prefix.
    #[test]
    fn a_zenoh_stream_that_opens_like_a_client_hello_is_still_a_zenoh_stream() {
        // A 790-byte unit: the length prefix is [0x16, 0x03] little-endian.
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE; 790];
        unit[0] = wz_session_core::wire_const::T_MID_INIT;
        let mut framed = alloc::vec![0x16u8, 0x03];
        framed.extend_from_slice(&unit);
        // ANTI-VACUITY: the bytes really are the ambiguous shape.
        assert_eq!(&framed[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(
            crate::tls::client_hello_verdict(&framed),
            crate::tls::TlsVerdict::No,
            "a zenoh unit must not answer Yes to the ClientHello question"
        );

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &framed));
        d.finish();
        assert_eq!(d.flows().len(), 1);
        assert!(
            !d.flows()[0].framing().is_encrypted(),
            "a zenoh stream was classified as TLS -- the recogniser is a prefix match"
        );
        assert!(
            d.encrypted_flows().is_empty(),
            "and it must not reach the report"
        );
        // R311y649 — AND IT MUST SETTLE. Until this leg the control passed on
        // `Undecided`, which is `!is_encrypted()` for a reason that is not the
        // claim: R311y649's chain question HOLDS this fixture (its first
        // record's big-endian length reads 0x0404 = 1028, longer than the 792
        // bytes there are), so without `settle_undecided` the flow ends the
        // capture holding every byte and reporting nothing. That is the silence
        // this whole track exists to refuse, arrived at from the other side.
        assert!(
            matches!(d.flows()[0].framing(), Framing::Stream),
            "a flow held for a verdict that never comes is a flow reported as \
             absent; framing={:?}",
            d.flows()[0].framing()
        );
        assert!(
            !d.flows()[0].frames.is_empty(),
            "and the held bytes must reach the zenoh reader, not be dropped"
        );

        // THE SECOND LEG, and it earned its place by falsification: the fixture
        // above is refused at the handshake-TYPE check, so the length-consistency
        // rule beside it was never driven -- removing that rule left all 312
        // tests green. These two drive it and nothing else: every other check
        // passes for both, and they differ only in whether the ClientHello's own
        // 3-byte length accounts for the record it sits in.
        //
        // Record length 0x0404 = 1028, handshake type 0x01.
        let head = |hs_len: [u8; 3]| {
            let mut v = alloc::vec![0x16u8, 0x03, 0x01, 0x04, 0x04, 0x01];
            v.extend_from_slice(&hs_len);
            v.resize(5 + 1028, 0);
            v
        };
        assert_eq!(
            crate::tls::client_hello_verdict(&head([0x00, 0x00, 0x00])),
            crate::tls::TlsVerdict::No,
            "a handshake claiming 0 bytes inside a 1028-byte record is not a ClientHello"
        );
        assert_eq!(
            crate::tls::client_hello_verdict(&head([0x00, 0x04, 0x00])),
            crate::tls::TlsVerdict::Yes,
            "and one that accounts for the whole record is -- so the leg decides, \
             rather than refusing everything"
        );
    }

    /// The other control: a PLAINTEXT capture says nothing about encryption in
    /// the text and still carries the structural zeroes in the export, so a
    /// consumer never tests for a key's presence to learn the capture was
    /// readable.
    #[test]
    fn a_plaintext_capture_carries_the_encrypted_fields_at_zero() {
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut framed = (keepalive.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(&keepalive);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &framed));
        assert_eq!(d.flows()[0].frames.len(), 1, "the control really decodes");

        let report = crate::report::CaptureReport::of(&d);
        assert!(
            !report.to_text().contains("NOT DECRYPTED"),
            "{}",
            report.to_text()
        );
        assert!(
            report.to_json().contains("\"encrypted\":{\"flows\":0"),
            "the field is structural: {}",
            report.to_json()
        );
        assert!(report.is_complete(), "{}", report.to_text());
    }

    /// A capture that began MID-SESSION: no handshake anywhere, both directions
    /// opening on `application_data`. The ordinary result of attaching a SPAN
    /// port to a link that was already up.
    fn mid_session_tls() -> Dissection {
        // 800 bytes for the reason `tls_dissection`'s does: read as a zenoh
        // stream the record's first two bytes are a LITTLE-endian 0x0317 = 791
        // and the unit that follows opens with 0x03, `T_MID_CLOSE`.
        let app_b = record(0x17, [0x03, 0x03], &[0xCD; 800]);
        let app_a = record(0x17, [0x03, 0x03], &[0xAB; 40]);
        let mut d = Dissection::new();
        let mut a_seq = 1000u32;
        let mut b_seq = 5000u32;
        let mut i = 0usize;
        let mut push = |d: &mut Dissection, from_a: bool, bytes: &[u8], seq: &mut u32| {
            let pkt = if from_a {
                tcp_packet(1111, 7447, *seq, bytes)
            } else {
                tcp_packet(7447, 1111, *seq, bytes)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
            *seq += bytes.len() as u32;
            i += 1;
        };
        push(&mut d, true, &app_a, &mut a_seq);
        push(&mut d, false, &app_b, &mut b_seq);
        push(&mut d, true, &app_a, &mut a_seq);
        d.finish();
        d
    }

    /// R311y649 (§1.2a) — THE DEFECT R311y648 LEFT BEHIND, and it is worse than
    /// the one that round closed.
    ///
    /// R311y648 recognised a TLS flow by its ClientHello, which is the CLIENT's
    /// first record and nothing else. A capture that began mid-session, or that
    /// caught only the server's half, has no ClientHello in it — so it fell
    /// through to `Framing::Stream`, and the stream reader took the record
    /// header's first two bytes as a little-endian length prefix.
    ///
    /// Measured before the fix: the flow was `Stream`, `encrypted_flows()` was
    /// EMPTY, the report called the capture `complete`, and the server's
    /// direction decoded a `Close` NOBODY SENT — the confident-wrong-answer this
    /// crate exists to refuse, produced out of ciphertext.
    #[test]
    fn a_capture_that_began_mid_session_is_still_recognised_as_encrypted() {
        let d = mid_session_tls();
        assert_eq!(d.flows().len(), 1);
        assert!(
            d.flows()[0].framing().is_encrypted(),
            "a mid-session TLS capture must not be read as a zenoh byte stream; \
             framing={:?} frames={:?}",
            d.flows()[0].framing(),
            d.flows()[0].frames
        );
        assert_eq!(
            d.flows()[0].frames.len(),
            0,
            "and NO message may be decoded out of ciphertext -- this fixture's \
             server record reads as a zenoh Close if it ever reaches the observer"
        );

        let enc = d.encrypted_flows();
        assert_eq!(enc.len(), 1);
        let totals = enc[0].totals();
        assert_eq!(totals.records, 3, "{:?}", enc[0]);
        assert_eq!(totals.application_records, 3);
        assert_eq!(totals.application_bytes, 40 + 800 + 40);
        let report = crate::report::CaptureReport::of(&d);
        assert!(!report.is_complete(), "{}", report.to_text());
    }

    /// R311y649 (§1.2a) — the other capture R311y648 could not name: a SPAN port
    /// on the wrong side of the link, which sees only the server's half.
    ///
    /// `ws::OPENINGS` already carries both literals for exactly this reason, and
    /// its comment says why: "refusing to classify it would put this crate's
    /// worst failure mode straight back". The TLS recogniser had only the
    /// client's opening, so it did.
    #[test]
    fn a_capture_of_only_the_servers_half_is_recognised() {
        let mut flight = record(0x16, [0x03, 0x03], &[0x02, 0x00, 0x00, 0x28]);
        flight.extend_from_slice(&record(0x14, [0x03, 0x03], &[0x01]));
        flight.extend_from_slice(&record(0x17, [0x03, 0x03], &[0xCD; 800]));
        // ANTI-VACUITY: the ClientHello question really does refuse this, so
        // the chain is what carries the finding and not a widened hello check.
        assert_eq!(
            crate::tls::client_hello_verdict(&flight),
            crate::tls::TlsVerdict::No,
            "a ServerHello must not be admitted by the ClientHello question"
        );

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(7447, 1111, 5000, &flight));
        d.finish();
        assert!(
            d.flows()[0].framing().is_encrypted(),
            "framing={:?}",
            d.flows()[0].framing()
        );
        assert_eq!(d.flows()[0].frames.len(), 0);
        let enc = d.encrypted_flows();
        assert_eq!(enc[0].per_direction[1].records, 3);
        assert_eq!(enc[0].per_direction[0].records, 0, "the client is absent");
        assert_eq!(enc[0].totals().application_bytes, 800);
    }

    /// R311y649 — `TLS_CHAIN_DEPTH` is a READING, and this is the measurement
    /// it is read off.
    ///
    /// One record header is a coincidence a zenoh stream can produce: a unit
    /// whose little-endian length prefix reads `[0x16, 0x03]` and whose first
    /// message id is small IS a well-formed TLS record header, byte for byte.
    /// At depth 1 the recogniser therefore calls a real zenoh flow encrypted —
    /// the failure this module exists to prevent, pointing the other way. The
    /// second record has to land where the first one's BIG-endian length says,
    /// and the next unit of a little-endian stream does not.
    #[test]
    fn one_record_is_a_coincidence_and_the_depth_is_what_refuses_it() {
        // A 790-byte zenoh unit, framed. Bytes 1..3 of the unit are the ones a
        // TLS reader takes for a big-endian record length: 0x000A = 10, so the
        // record COMPLETES inside this stream and the walk moves on.
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE; 790];
        unit[0] = wz_session_core::wire_const::T_MID_INIT;
        unit[1] = 0x00;
        unit[2] = 0x0A;
        let mut framed = alloc::vec![0x16u8, 0x03];
        framed.extend_from_slice(&unit);
        assert_eq!(&framed[..3], &[0x16, 0x03, 0x01], "the ambiguous shape");

        assert_eq!(
            crate::tls::record_chain_verdict(&framed, 1),
            crate::tls::TlsVerdict::Yes,
            "one record IS satisfied by a zenoh stream -- if this ever says No \
             the fixture stopped driving the leg and the depth below proves \
             nothing"
        );
        assert_eq!(
            crate::tls::record_chain_verdict(&framed, crate::tls::TLS_CHAIN_DEPTH),
            crate::tls::TlsVerdict::No,
            "and the second record is what refuses it"
        );

        // END TO END, at the depth the crate actually uses.
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &framed));
        d.finish();
        assert!(!d.flows()[0].framing().is_encrypted());
        assert!(matches!(d.flows()[0].framing(), Framing::Stream));
    }

    /// R311y649 (§1.2a) — a hole in the opening of a flow that was being held
    /// for chain evidence must not force `Stream`.
    ///
    /// The two decision sites drifting apart is the defect. `advance` learned
    /// the chain question; `note_gap` had not, so a TLS flow that lost a segment
    /// while its chain was still one record deep went straight back to being
    /// read as a zenoh byte stream — and every record after the hole with it.
    #[test]
    fn a_hole_while_the_chain_is_still_shallow_does_not_force_a_stream() {
        let app = record(0x17, [0x03, 0x03], &[0xCD; 40]);
        let mut d = Dissection::new();
        d.set_gap_patience(Some(4));
        // One record: consistent, shallower than the depth, so it is HELD.
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &app));
        assert!(
            matches!(d.flows()[0].framing(), Framing::Undecided),
            "the fixture must reach the held state or the hole below lands \
             somewhere else: {:?}",
            d.flows()[0].framing()
        );
        // A dropped segment carrying exactly one whole record, so the far side
        // resumes ON a record boundary -- the only shape the far-side chain
        // question can settle, and stated as such in `decide_after_opening_lost`.
        let mut after = record(0x17, [0x03, 0x03], &[0xEE; 40]);
        after.extend_from_slice(&record(0x17, [0x03, 0x03], &[0xEE; 40]));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + 45 + 45, &after),
        );
        d.finish();

        assert!(
            d.flows()[0].framing().is_encrypted(),
            "framing={:?} frames={:?}",
            d.flows()[0].framing(),
            d.flows()[0].frames
        );
        assert_eq!(
            d.flows()[0].frames.len(),
            0,
            "and no message may be decoded out of the far side"
        );
        // The near side counted, the gap dropped its tail, the far side
        // counted: 1 + 2 records, and NOT a fourth invented across the hole.
        assert_eq!(d.encrypted_flows()[0].per_direction[0].records, 3);
    }

    /// One plain zenoh keepalive, framed — the SECOND 5-tuple every eviction
    /// test below needs, and deliberately the most ordinary flow there is: the
    /// finding under test must survive being displaced by traffic that is
    /// itself unremarkable.
    fn evicting_flow(d: &mut Dissection, index: usize) {
        let mut framed = 1u16.to_le_bytes().to_vec();
        framed.push(wz_session_core::wire_const::T_MID_KEEP_ALIVE);
        d.push_packet(
            LINKTYPE_ETHERNET,
            index,
            &tcp_packet(2222, 7447, 3000, &framed),
        );
    }

    /// R311y716 (§E 8.13 / 8.14) — the encrypted census states a RANGE and
    /// says what a gap took.
    ///
    /// Two findings this crate has carried since R311y648, both of the same
    /// kind: a number that claims more than it knows. `application_bytes` is
    /// CIPHERTEXT -- every TLS 1.3 record hides an AEAD tag and the true inner
    /// content type inside the protected fragment -- and the page printed it as
    /// "N byte(s) of application data", which told a reader they were missing
    /// more zenoh than they are. And a hole in an encrypted direction drops the
    /// partial record this reader was holding; the loss was recorded in
    /// R311y666 and reached NOTHING, so the census quietly became a floor while
    /// every figure beside it read as a total.
    ///
    /// That the old text was pinned by nothing is itself measured: changing it
    /// to a range left all 401 tests green.
    #[test]
    fn the_encrypted_census_states_its_ceiling_as_one_and_names_what_a_gap_took() {
        let hello = record(0x16, [0x03, 0x01], &[0x01, 0x00, 0x00, 0x30]);
        let app = record(0x17, [0x03, 0x03], &[0xAB; 40]);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &hello));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + hello.len() as u32, &app),
        );
        d.finish();

        let enc = d.encrypted_census();
        assert_eq!(
            (enc.census.application_records, enc.census.application_bytes),
            (1, 40),
            "the fixture must carry ONE application record of forty bytes, or \
             the arithmetic below is about something else"
        );
        // 40 ciphertext bytes less one record's AEAD tag (16, the largest any
        // TLS 1.3 suite uses) and its inner content type byte.
        assert_eq!(enc.census.application_bytes_at_least(), 23);

        let report = crate::report::CaptureReport::of(&d);
        let text = report.to_text();
        let json = report.to_json();
        // R311y725 (N4) — the sentence now names what the floor was subtracted
        // against, and this fixture has no readable ServerHello, so it says so.
        // The RANGE is unchanged, which is the point: not knowing the suite
        // keeps the widest tag and therefore the number this test already had.
        assert!(
            text.contains(
                "23-40 byte(s) of application data (the upper figure \
                 is ciphertext; the lower subtracts 17 byte(s) of AEAD \
                 overhead, suite unknown)"
            ),
            "the page must state the RANGE and its basis: {text}"
        );
        assert!(
            json.contains("\"application_bytes\":40,\"application_bytes_at_least\":23"),
            "and the export must carry both figures: {json}"
        );
        assert!(
            json.contains("\"lost_bytes\":0"),
            "with the gap loss present and zero, not absent: {json}"
        );
        // R311y725 (N2) — an encrypted flow nobody opened is its OWN leg of the
        // verdict, and this is the only fixture in the crate that produces one
        // in isolation. Named rather than left to `is_complete`, which any leg
        // satisfies.
        assert_eq!(
            report.reasons(),
            alloc::vec![crate::report::VerdictReason::EncryptedFlowsUnopened],
            "{text}"
        );
        assert!(
            !text.contains("went with a gap"),
            "and the page must not mention a gap this capture did not have: \
             {text}"
        );

        // AND THE GAP ARM. A hole in the encrypted direction takes the partial
        // record with it, and both renderings have to say so.
        let mut holed = Dissection::new();
        holed.set_gap_patience(Some(1));
        holed.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &hello));
        // A segment 200 bytes further along than the previous one ends: the
        // bytes between are a hole this capture does not contain.
        holed.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + hello.len() as u32 + 200, &app),
        );
        holed.push_packet(
            LINKTYPE_ETHERNET,
            2,
            &tcp_packet(
                1111,
                7447,
                1000 + hello.len() as u32 + 200 + app.len() as u32,
                &app,
            ),
        );
        holed.finish();
        assert!(
            holed.framing_health().gaps_forced > 0,
            "the assembler must have STEPPED OVER the hole, or nothing ever \
             told the TLS walk there was one: {:?}",
            holed.framing_health()
        );
        let lost = holed.encrypted_census().census.lost_bytes;
        assert!(
            lost > 0,
            "the fixture must lose bytes to the hole: {:?}",
            holed.encrypted_census().census
        );
        let holed_report = crate::report::CaptureReport::of(&holed);
        assert!(
            holed_report
                .to_text()
                .contains(&alloc::format!("{lost} byte(s) of it went with a gap")),
            "the page must name what the hole took: {}",
            holed_report.to_text()
        );
        assert!(
            holed_report
                .to_json()
                .contains(&alloc::format!("\"lost_bytes\":{lost}")),
            "and so must the export: {}",
            holed_report.to_json()
        );
    }

    /// R311y650 (§1.2a) — an encrypted flow the FLOW CAP evicted is still an
    /// encrypted flow, and the report has to say so.
    ///
    /// Measured before the fix, on this fixture: `encrypted_flows()` went empty,
    /// the JSON's `encrypted.flows` went from 1 back to 0, and the text's "NOT
    /// DECRYPTED" line disappeared entirely — leaving a report that named a
    /// dropped flow and never said what was in it. R311y648's whole finding,
    /// deleted by a bound.
    ///
    /// This is the third counter to need the eviction carry (R311y605 took the
    /// stream tally, R311y610 the session one) and the first that is a FINDING
    /// rather than a loss tally, which is why it was missed: the two before it
    /// were numbers about the reader, and this one is a statement about the
    /// capture.
    #[test]
    fn an_evicted_encrypted_flows_finding_stays_in_the_report() {
        let hello = record(0x16, [0x03, 0x01], &[0x01, 0x00, 0x00, 0x30]);
        let app_a = record(0x17, [0x03, 0x03], &[0xAB; 40]);
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &hello));
        d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet(1111, 7447, 1009, &app_a));
        // ANTI-VACUITY: the flow really is recognised BEFORE the eviction, so a
        // pass below cannot come from a fixture that was never encrypted.
        assert!(
            d.flows()[0].framing().is_encrypted(),
            "framing={:?}",
            d.flows()[0].framing()
        );
        let before = d.encrypted_census();
        assert_eq!((before.flows, before.census.records), (1, 2));

        evicting_flow(&mut d, 2);
        d.finish();
        assert_eq!(d.flows().len(), 1, "the cap must have evicted");
        assert_eq!(d.drops().flows, 1);
        assert!(
            d.encrypted_flows().is_empty(),
            "the evicted flow is no longer one a reader can LOOK at -- which is \
             exactly why the census below cannot be read off this list"
        );

        let after = d.encrypted_census();
        assert_eq!(
            (
                after.flows,
                after.census.records,
                after.census.application_records,
                after.census.application_bytes
            ),
            (1, 2, 1, 40),
            "a census of what this reader COULD NOT see must never walk backwards"
        );
        let rep = crate::report::CaptureReport::of(&d);
        // R311y664 — and here the reason TAG is absent, which is a real
        // difference and not a gap in the assertion: this flow was EVICTED, so
        // it is in the census and not in the live table, and a per-flow reason
        // is exactly what eviction takes with it. The finding survives, which is
        // what R311y650 added this line for.
        assert!(
            rep.to_text().contains("NOT DECRYPTED"),
            "the person reading this capture is otherwise told only that a flow \
             was dropped: {}",
            rep.to_text()
        );
        assert!(
            rep.to_json().contains("\"encrypted\":{\"flows\":1")
                && rep.to_json().contains("\"application_bytes\":40"),
            "{}",
            rep.to_json()
        );
        assert!(!rep.is_complete(), "{}", rep.to_text());
    }

    /// A flow that has DEFINITIVELY lost its framing and is still deciding what
    /// it is — the resting `OpeningLost` state, reached the way a live tap
    /// reaches it and not by `finish`.
    ///
    /// The far side is a zenoh-framed unit carrying bytes no message accounts
    /// for. Neither a TLS chain nor a ws frame, so the evidence after the hole
    /// is INCONCLUSIVE and the flow rests rather than deciding on its own —
    /// which is what makes the exit, not the arrival, the thing under test.
    fn flow_resting_in_opening_lost() -> Dissection {
        let far_side = || {
            let mut v = alloc::vec![88u8, 0x02];
            v.push(wz_session_core::wire_const::T_MID_KEEP_ALIVE);
            v.resize(602, 0x00);
            v
        };
        let app = record(0x17, [0x03, 0x03], &[0xCD; 40]);
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        // PATIENCE 1: the hole has to be ANNOUNCED while the capture is still
        // running, and a live tap announces it by spending patience on later
        // segments.
        d.set_gap_patience(Some(1));
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &app));
        let mut seq = 1000u32 + 45 + 45;
        for i in 0..2 {
            d.push_packet(
                LINKTYPE_ETHERNET,
                1 + i,
                &tcp_packet(1111, 7447, seq, &far_side()),
            );
            seq += 602;
        }
        // ANTI-VACUITY for every caller: the flow really is still deciding. If
        // this ever reads `Encrypted` or `Stream` the flow settled on arrival
        // and no exit is under test.
        assert!(
            matches!(d.flows()[0].framing(), Framing::OpeningLost),
            "framing={:?}",
            d.flows()[0].framing()
        );
        assert_eq!(
            d.framing_health().desyncs,
            0,
            "the loss must not be recorded before the flow leaves"
        );
        d
    }

    /// R311y650 (§1.2a) — a flow the cap evicts takes the SAME exit a flow at
    /// the end of a capture takes.
    ///
    /// R311y612 and R311y649 both wrote "a flow that will not be read again must
    /// decide", and both wrote it at ONE call site: [`Dissection::finish`]. The
    /// flow table has a second door, and this is the state that makes walking
    /// out of it visible — `OpeningLost`, a flow that has definitively lost its
    /// framing and knows it.
    ///
    /// The claim is R311y610's, one exit later: a loss counter must never walk
    /// backwards. Measured before the fix, on this fixture, `desyncs` read 0
    /// after the eviction. The flow had lost the framing; the number that says
    /// so was never written, because the bytes that would have written it left
    /// with the flow still held.
    ///
    /// It is the LIVE-TAP case specifically. A file ends and calls `finish`; a
    /// tap recycles slots forever and never does — so this test never calls it
    /// either.
    #[test]
    fn an_evicted_flow_settles_the_verdict_it_was_still_holding() {
        let mut d = flow_resting_in_opening_lost();

        evicting_flow(&mut d, 4);
        assert_eq!(d.flows().len(), 1, "the cap must have evicted");
        // NO `finish` HERE, deliberately: it is the verb this path does not get.
        assert_eq!(
            d.framing_health().desyncs,
            1,
            "a flow evicted while still deciding decided nothing, and the loss it \
             had already suffered left with it: health={:?}",
            d.framing_health()
        );
    }

    /// R311y650 — and the door R311y612 wrote the rule for, which nothing was
    /// holding shut.
    ///
    /// Found by falsifying R311y650: deleting the `OpeningLost` arm of
    /// `settle_on_exit` reds the eviction test above and NOTHING ELSE, at every
    /// feature arm. R311y612's flush — "a flow still deciding when the capture
    /// ends must be reported, not held" — had no test that fails when it is
    /// removed, because every fixture written for it decided on its own before
    /// `finish` was ever reached.
    ///
    /// Same fixture as the eviction test, same assertion, other exit. That is
    /// the point: one rule, two doors, and now a witness at each.
    #[test]
    fn a_flow_still_deciding_when_the_capture_ends_settles_too() {
        let mut d = flow_resting_in_opening_lost();
        d.finish();
        assert_eq!(
            d.framing_health().desyncs,
            1,
            "a capture that ended on a flow that had lost its framing reported \
             none: health={:?}",
            d.framing_health()
        );
        assert!(
            !matches!(d.flows()[0].framing(), Framing::OpeningLost),
            "and the flow must not still be deciding: {:?}",
            d.flows()[0].framing()
        );
    }

    /// R311y650 (§1.2a) — and the state that has no verdict to reach: a flow
    /// HELD by the chain question, evicted.
    ///
    /// The held bytes are the finding here. Settling hands them to the zenoh
    /// reader, which is what makes them countable; without it they leave with
    /// the flow and every counter they would have moved reads zero — a live
    /// tap's loss accounting walking backwards, which is the one direction
    /// R311y610 says it must never move.
    ///
    /// The fixture is a ZENOH unit and not a TLS one on purpose. It is the
    /// `Undecided` state's actual population: `prelude_verdict` requires the
    /// third byte to be `<= 4`, so the only zenoh units that can hold the chain
    /// are the ones opening with a small unflagged message id, and this is one.
    #[test]
    fn an_evicted_flow_that_was_still_held_accounts_for_its_bytes() {
        // LE length 0x0317 = 791, so as TLS this is one `application_data`
        // record whose BE length 0x0314 = 788 lands the run EXACTLY on the
        // record boundary -- consistent, one record deep, and therefore held.
        let mut unit = alloc::vec![0x00u8; 791];
        unit[0] = wz_session_core::wire_const::T_MID_KEEP_ALIVE;
        unit[1] = 0x03;
        unit[2] = 0x14;
        let mut framed = alloc::vec![0x17u8, 0x03];
        framed.extend_from_slice(&unit);
        assert_eq!(
            crate::tls::record_chain_verdict(&framed, crate::tls::TLS_CHAIN_DEPTH),
            crate::tls::TlsVerdict::NeedMore,
            "the fixture must reach the HELD state or this test drives another one"
        );

        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &framed));
        assert!(
            matches!(d.flows()[0].framing(), Framing::Undecided),
            "framing={:?}",
            d.flows()[0].framing()
        );
        assert_eq!(d.framing_health().unaccounted_batch_bytes, 0);

        evicting_flow(&mut d, 1);
        assert_eq!(d.flows().len(), 1, "the cap must have evicted");
        assert_eq!(
            d.framing_health().unaccounted_batch_bytes,
            788,
            "the held bytes left with the flow and nothing recorded that they \
             were ever there: health={:?}",
            d.framing_health()
        );
        assert!(
            !crate::report::CaptureReport::of(&d).is_complete(),
            "and the verdict must carry the shortfall"
        );
    }

    // ── R311y661 (§1.2a) — the PRODUCTION path. R311y657..660 proved a capture
    //    can be decrypted, in a test that built its own everything; nothing
    //    called any of it from the reader, so a capture carrying its own keys
    //    still reported `no_keys_supplied` and zero frames.
    //
    //    The opener here is a FAKE and carries no cryptography, which is the
    //    point: what these tests gate is the WIRING — that records reach an
    //    opener, that plaintext reaches the zenoh reader, that a refusal stops a
    //    direction, that offsets come back in the right space. wz-capture has no
    //    third-party dependency and these lanes run everywhere it does. The real
    //    cipher is gated against rustls in `wz-tls-record`. ──

    /// An opener that "decrypts" by stripping the 5-byte record header.
    ///
    /// Records are built by the fixtures below as `header || content_type ||
    /// plaintext`, so opening one is a slice — the same shape a real AEAD
    /// produces (inner content type at the end, here at the front for legibility)
    /// with none of its machinery.
    struct FakeOpener {
        /// Indices this opener refuses, per direction.
        refuse: [alloc::collections::BTreeSet<u64>; 2],
        /// Flows it declines outright, and with what reason.
        decline: Option<crate::tls::NotDecrypted>,
        /// What `begin_flow` was told, in call order.
        seen: Vec<(Option<[u8; 32]>, Option<Direction>)>,
        /// Every `(direction, index)` it was asked to open.
        asked: Vec<(Direction, u64)>,
        /// R311y668 — directions this opener holds NO key material for, which is
        /// what a half key log produces. `[false, false]` is the ordinary fake:
        /// it serves both sides.
        keyless: [bool; 2],
    }

    impl FakeOpener {
        fn new() -> Self {
            Self {
                refuse: [
                    alloc::collections::BTreeSet::new(),
                    alloc::collections::BTreeSet::new(),
                ],
                decline: None,
                seen: Vec::new(),
                asked: Vec::new(),
                keyless: [false, false],
            }
        }
    }

    impl crate::tls::RecordOpener for FakeOpener {
        fn begin_flow(
            &mut self,
            client_random: Option<&[u8; 32]>,
            client_direction: Option<Direction>,
        ) -> Result<(), crate::tls::NotDecrypted> {
            self.seen.push((client_random.copied(), client_direction));
            match self.decline {
                Some(reason) => Err(reason),
                None => Ok(()),
            }
        }

        fn open(
            &mut self,
            direction: Direction,
            record: &crate::tls::EncryptedRecord,
        ) -> Option<crate::tls::OpenedRecord> {
            self.asked.push((direction, record.index));
            // R311y668 — a keyless direction opens NOTHING, which is what makes
            // this fake faithful to the arrangement it models: a real opener with
            // no secret for a direction returns `None` from the first record it
            // is handed, indistinguishably from a record that failed the AEAD.
            // A fake that answered `has_keys(false)` and still opened would make
            // the guard above look load-bearing when it was not.
            if self.keyless[dir_index(direction)]
                || self.refuse[dir_index(direction)].contains(&record.index)
            {
                return None;
            }
            let body = record.bytes.get(5..)?;
            Some(crate::tls::OpenedRecord {
                content_type: *body.first()?,
                plaintext: body[1..].to_vec(),
            })
        }

        fn has_keys(&self, direction: Direction) -> bool {
            !self.keyless[dir_index(direction)]
        }
    }

    /// A TLS record whose "plaintext" is `content_type || payload`, which is
    /// what [`FakeOpener`] opens.
    fn protected(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = alloc::vec![content_type];
        body.extend_from_slice(payload);
        record(0x17, [0x03, 0x03], &body)
    }

    /// One framed zenoh KeepAlive — the unit a decrypted record must yield.
    fn framed_unit(id: u8) -> Vec<u8> {
        let unit = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE, id];
        let mut out = (unit.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&unit);
        out
    }

    /// A ClientHello carrying `random`, well-formed enough for the recogniser.
    fn hello_with_random(random: &[u8; 32]) -> Vec<u8> {
        let mut body = alloc::vec![0x03u8, 0x03];
        body.extend_from_slice(random);
        body.resize(0x30, 0);
        let mut handshake = alloc::vec![0x01u8, 0x00, 0x00, body.len() as u8];
        handshake.extend_from_slice(&body);
        record(0x16, [0x03, 0x01], &handshake)
    }

    /// A client-side TLS flow: a ClientHello then `records`, one packet each.
    fn decryptable_flow(random: &[u8; 32], records: &[Vec<u8>]) -> Dissection {
        let mut d = Dissection::new();
        let mut seq = 1000u32;
        let mut i = 0usize;
        let mut push = |d: &mut Dissection, bytes: &[u8], seq: &mut u32| {
            d.push_packet(LINKTYPE_ETHERNET, i, &tcp_packet(1111, 7447, *seq, bytes));
            *seq += bytes.len() as u32;
            i += 1;
        };
        push(&mut d, &hello_with_random(random), &mut seq);
        for r in records {
            push(&mut d, r, &mut seq);
        }
        d.finish();
        d
    }

    /// R311y661 — THE ROUND. A capture whose keys are available decodes zenoh
    /// frames, and the flow stops saying its plaintext is absent.
    #[test]
    fn a_flow_whose_records_open_yields_zenoh_frames_and_says_it_was_decrypted() {
        let random = [7u8; 32];
        let records: Vec<Vec<u8>> = (0..3u8)
            .map(|i| protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)))
            .collect();
        let mut d = decryptable_flow(&random, &records);

        // BEFORE: the pre-R311y661 state, asserted so the test cannot pass by
        // the frames having been there all along.
        assert_eq!(d.flows()[0].frames.len(), 0, "ciphertext decodes nothing");
        assert_eq!(
            d.encrypted_flows()[0].not_decrypted,
            Some(crate::tls::NotDecrypted::NoKeysSupplied)
        );

        let mut opener = FakeOpener::new();
        let summary = d.decrypt_with(&mut opener);

        assert_eq!(
            opener.seen,
            alloc::vec![(Some(random), Some(Direction::A))],
            "the opener is told the flow's identity AND which side is the client \
             -- without the second it picks a traffic secret by coin flip"
        );
        assert_eq!(summary.flows, 1);
        assert_eq!(summary.decrypted, 1);
        assert_eq!(summary.records, 3);
        assert_eq!(summary.frames, 3, "summary={summary:?}");
        assert_eq!(
            d.flows()[0].frames.len(),
            3,
            "THE POINT: the zenoh session inside TLS is now decoded"
        );
        let enc = d.encrypted_flows();
        assert_eq!(enc[0].not_decrypted, None, "and the flow says so");
        assert_eq!(enc[0].decrypted_records, [3, 0]);
    }

    /// R311y661 — and the offsets those frames carry are in the flow's TCP
    /// stream space, not the plaintext's.
    ///
    /// THE DISCRIMINATOR for R311y645's defect class. Plaintext space is shorter
    /// than TCP space by every record header, so the two agree only for the
    /// first record and diverge by a growing amount after it. A frame carrying
    /// its plaintext offset resolves, through `packet_for`, to a packet that is
    /// merely NEARBY — and resolves silently, because both numbers are valid
    /// offsets into a stream that exists.
    #[test]
    fn a_decrypted_frames_offset_resolves_to_the_packet_that_carried_it() {
        let random = [7u8; 32];
        let records: Vec<Vec<u8>> = (0..3u8)
            .map(|i| protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)))
            .collect();
        let mut d = decryptable_flow(&random, &records);
        d.decrypt_with(&mut FakeOpener::new());

        let frames: Vec<usize> = d.flows()[0]
            .frames
            .iter()
            .map(|f| f.stream_offset)
            .collect();
        // The hello is 5 (record header) + 4 (handshake header) + 48 (body) =
        // 57 bytes; each protected record is 5 header + 1 inner type + 4 unit =
        // 10. So the records begin at 57, 67 and 77 of the TCP stream, while
        // their plaintext begins at 0, 4 and 8.
        assert_eq!(
            frames,
            alloc::vec![57, 67, 77],
            "offsets must be TCP-space; plaintext space would read [0, 4, 8]"
        );

        // AND THE COORDINATE IS USED, not merely stored: each frame resolves to
        // the packet its record actually arrived in. Packet 0 is the hello, so
        // the three records are packets 1, 2 and 3.
        let resolved: Vec<Option<usize>> = d.flows()[0]
            .frames
            .iter()
            .map(|f| d.flows()[0].packet_for(f.direction, f.stream_offset))
            .collect();
        assert_eq!(
            resolved,
            alloc::vec![Some(1), Some(2), Some(3)],
            "a decrypted frame must attribute to the packet that carried it"
        );
    }

    /// R311y661 — a record whose INNER type is not `application_data` must not
    /// reach the zenoh reader.
    ///
    /// The failure this closes is invisible without it: TLS 1.3 puts the real
    /// content type INSIDE the protected payload and leaves the outer one
    /// reading `application_data` for everything after the ServerHello, so a
    /// post-handshake `NewSessionTicket` — which servers send routinely, mid
    /// session, with no warning — is indistinguishable from traffic until it is
    /// opened. Feeding its bytes into a length-prefixed stream desynchronises
    /// every message after it.
    #[test]
    fn a_post_handshake_message_is_opened_and_not_fed_to_the_zenoh_reader() {
        let random = [7u8; 32];
        // A NewSessionTicket between two data records. Its body is deliberately
        // framed-unit-shaped, so a build that fed it onward would decode it as a
        // zenoh message rather than merely stumbling.
        let records = alloc::vec![
            protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0)),
            protected(crate::tls::CT_HANDSHAKE, &framed_unit(1)),
            protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(2)),
        ];
        let mut d = decryptable_flow(&random, &records);
        let summary = d.decrypt_with(&mut FakeOpener::new());

        assert_eq!(
            summary.records, 3,
            "all three OPEN -- that is not the question"
        );
        assert_eq!(
            summary.frames, 2,
            "only the two application-data ones are zenoh"
        );
        // WHICH two, and not merely how many: the offsets name the records the
        // frames came out of. The ticket sits at 67, between them, so a build
        // that fed it onward reads [57, 67, 77] here.
        let offsets: Vec<usize> = d.flows()[0]
            .frames
            .iter()
            .map(|f| f.stream_offset)
            .collect();
        assert_eq!(
            offsets,
            alloc::vec![57, 77],
            "the handshake record's payload must not appear as a frame"
        );
        assert_eq!(
            d.encrypted_flows()[0].not_decrypted,
            None,
            "and the flow is still fully decrypted -- a ticket is not a failure"
        );
    }

    /// R311y661 — a record that refuses the keys stops its direction and is
    /// named.
    ///
    /// Skipping it and carrying on is the tempting shape and the wrong one: the
    /// bytes after a hole in a length-prefixed stream do not begin where the
    /// reader thinks they do, so a skip converts one unreadable record into
    /// arbitrary garbage decoded confidently. The epoch makes this the ORDINARY
    /// case — TLS 1.3 restarts the AEAD sequence on every key change — so the
    /// state is reached by real captures, not just by this test.
    #[test]
    fn a_record_that_refuses_the_keys_stops_its_direction_and_is_named() {
        let random = [7u8; 32];
        let records: Vec<Vec<u8>> = (0..4u8)
            .map(|i| protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)))
            .collect();
        let mut d = decryptable_flow(&random, &records);

        let mut opener = FakeOpener::new();
        opener.refuse[0].insert(2);
        let summary = d.decrypt_with(&mut opener);

        assert_eq!(
            opener.asked,
            alloc::vec![(Direction::A, 0), (Direction::A, 1), (Direction::A, 2),],
            "record 3 must never be asked for: the direction stopped at 2"
        );
        assert_eq!(summary.records, 2);
        assert_eq!(
            summary.decrypted, 0,
            "a partially-opened flow is not decrypted"
        );
        assert_eq!(summary.frames, 2, "and the two that DID open are kept");
        let enc = d.encrypted_flows();
        assert_eq!(
            enc[0].not_decrypted,
            Some(crate::tls::NotDecrypted::RecordRefusedKeys {
                direction: Direction::A,
                index: 2,
            }),
            "the index a reader needs in order to find the epoch boundary"
        );
        assert_eq!(
            enc[0].decrypted_records,
            [2, 0],
            "partial is a real state and the count must show it"
        );
    }

    /// R311y661 — an opener that declines the flow reports ITS reason, and no
    /// record is tried.
    #[test]
    fn a_declined_flow_reports_the_openers_reason_and_opens_nothing() {
        let random = [7u8; 32];
        let records = alloc::vec![protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0))];
        let mut d = decryptable_flow(&random, &records);

        let mut opener = FakeOpener::new();
        opener.decline = Some(crate::tls::NotDecrypted::NoKeyForSession);
        let summary = d.decrypt_with(&mut opener);

        assert!(opener.asked.is_empty(), "a declined flow costs no attempts");
        assert_eq!(summary.refused, 1);
        assert_eq!(summary.frames, 0);
        assert_eq!(
            d.encrypted_flows()[0].not_decrypted,
            Some(crate::tls::NotDecrypted::NoKeyForSession),
            "and NOT `no_keys_supplied` -- keys were supplied, they were the \
             wrong ones, and the two send a reader to different places"
        );
    }

    /// R311y661 — a mid-session flow has no identity to be selected by, and the
    /// opener is the layer that says so.
    ///
    /// The reason must survive as its own variant rather than collapsing into
    /// `no_keys_supplied`: this capture cannot be fixed by finding a key log,
    /// only by capturing from the handshake.
    #[test]
    fn a_mid_session_flow_is_announced_with_no_identity() {
        let mut d = Dissection::new();
        let records: Vec<Vec<u8>> = (0..2u8)
            .map(|i| protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)))
            .collect();
        let mut stream = Vec::new();
        for r in &records {
            stream.extend_from_slice(r);
        }
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &stream));
        d.finish();

        let mut opener = FakeOpener::new();
        opener.decline = Some(crate::tls::NotDecrypted::NoSessionIdentity);
        d.decrypt_with(&mut opener);

        assert_eq!(
            opener.seen,
            alloc::vec![(None, None)],
            "no ClientHello means no random AND no client direction"
        );
        assert_eq!(
            d.encrypted_flows()[0].not_decrypted,
            Some(crate::tls::NotDecrypted::NoSessionIdentity)
        );
    }

    /// R311y661 — a second pass must not push the same plaintext through a
    /// reader that has already consumed it.
    ///
    /// A `Dissection` is a long-lived object with public mutators; nothing stops
    /// a caller running the pass twice, and a stream reader handed the same
    /// bytes again decodes them again. The frames would double and the second
    /// set would be as real-looking as the first.
    #[test]
    fn a_second_decryption_pass_does_not_decode_the_same_records_twice() {
        let random = [7u8; 32];
        let records: Vec<Vec<u8>> = (0..2u8)
            .map(|i| protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)))
            .collect();
        let mut d = decryptable_flow(&random, &records);
        d.decrypt_with(&mut FakeOpener::new());
        assert_eq!(d.flows()[0].frames.len(), 2);

        let mut again = FakeOpener::new();
        let summary = d.decrypt_with(&mut again);
        assert!(
            again.seen.is_empty(),
            "the flow is already settled; it must not be offered again"
        );
        assert_eq!(summary.flows, 0);
        assert_eq!(d.flows()[0].frames.len(), 2, "and no frame is duplicated");
        // R311y684 — and the skip is COUNTED. Without this the summary of a
        // second pass is byte-identical to the summary of a capture with no
        // encrypted flow in it, which is what a caller installing a sink on a
        // second pass would have to tell apart to know its sink got nothing.
        assert_eq!(
            summary.already_opened, 1,
            "the flow this pass skipped because an earlier one settled it must \
             be counted, or 'already done' and 'nothing to do' are one summary"
        );
    }

    /// R311y684 (§1.1n) — "already done" and "nothing to do" are DIFFERENT
    /// summaries, driven side by side in one test.
    ///
    /// The discriminator is the whole point: asserting a count on the second
    /// pass alone would pass just as well if the field counted something else
    /// entirely, so the capture with nothing to decrypt is run through the same
    /// assertion and must answer zero.
    #[test]
    fn a_pass_with_nothing_to_do_and_one_already_done_do_not_read_alike() {
        let random = [9u8; 32];
        let records = alloc::vec![protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0))];
        let mut settled = decryptable_flow(&random, &records);
        settled.decrypt_with(&mut FakeOpener::new());
        let second = settled.decrypt_with(&mut FakeOpener::new());

        // A capture with no encrypted flow at all: the OTHER way to get a pass
        // that opens nothing.
        let mut nothing = Dissection::new();
        let empty = nothing.decrypt_with(&mut FakeOpener::new());

        assert_eq!(
            (empty.flows, empty.records, empty.already_opened),
            (0, 0, 0),
            "a capture with nothing to decrypt reports nothing on every axis"
        );
        assert_eq!(
            (second.flows, second.records),
            (0, 0),
            "and so does a second pass, on the two axes it shares"
        );
        assert_eq!(
            second.already_opened, 1,
            "which is why the third axis has to differ: it is the only thing \
             separating the two"
        );
    }

    /// R311y661 — the report's `decrypted` and `reason` are facts now.
    ///
    /// Both were constants: `false` was in the format string and the reason
    /// resolved to `no_keys_supplied` whatever had happened.
    #[test]
    fn the_report_states_what_the_decryption_pass_actually_found() {
        let random = [7u8; 32];
        let records = alloc::vec![protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0))];
        let mut d = decryptable_flow(&random, &records);

        let before = crate::report::CaptureReport::of(&d).to_json();
        assert!(
            before.contains("\"decrypted\":false")
                && before.contains("\"reason\":\"no_keys_supplied\""),
            "the no-keys state must still read as it did: {before}"
        );

        d.decrypt_with(&mut FakeOpener::new());
        let after = crate::report::CaptureReport::of(&d).to_json();
        assert!(
            after.contains("\"decrypted\":true"),
            "a decrypted capture must say so: {after}"
        );
        assert!(
            after.contains("\"reason\":\"none\""),
            "and carry no reason for an absence that is not there: {after}"
        );
        assert!(
            after.contains("\"records_decrypted\":1") && after.contains("\"flows_decrypted\":1"),
            "with the counts a reader checks it against: {after}"
        );
    }

    /// R311y661 — a record after a HOLE carries the offset the hole put it at.
    ///
    /// The claim under test is arithmetic that no other test can see: a
    /// direction that lost a segment resumes further along its stream than the
    /// bytes before it ended, and a coordinate that ignored the loss would name,
    /// for every later record, a position occupied by something else. `packet_for`
    /// resolves such a number without complaint — it is a valid offset into a
    /// stream that exists — so the wrong answer arrives as a confident one.
    ///
    /// Before this round the encrypted arm's gap handler only cleared the held
    /// tail; there was no coordinate to keep, so there was nothing to notice.
    #[test]
    fn a_record_after_a_hole_carries_the_offset_the_hole_put_it_at() {
        let random = [7u8; 32];
        let hello = hello_with_random(&random);
        let first = protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0));
        let after = protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(1));

        let mut d = Dissection::new();
        d.set_gap_patience(Some(4));
        let mut opening = hello.clone();
        opening.extend_from_slice(&first);
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1111, 7447, 1000, &opening),
        );
        // A 50-byte hole, then a record that begins exactly on a boundary.
        const HOLE: u32 = 50;
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1111, 7447, 1000 + opening.len() as u32 + HOLE, &after),
        );
        d.finish();

        let enc = d.encrypted_flows();
        let offsets: Vec<usize> = enc[0].kept_records[0]
            .iter()
            .map(|r| r.stream_offset)
            .collect();
        // The hello is 57 and the first record 10, so it sits at 57. The second
        // begins 50 bytes of hole later: 57 + 10 + 50 = 117.
        assert_eq!(
            offsets,
            alloc::vec![57, 117],
            "a coordinate blind to the hole would read [57, 67] -- and 67 is a \
             real offset in this stream, so nothing downstream would object"
        );
    }

    /// R311y661 — the capture-wide `decrypted` claim is false while ANY flow is
    /// not, and the reason says `mixed` rather than naming one flow's problem as
    /// the capture's.
    ///
    /// The single-flow tests cannot see either half: with one flow, "all flows
    /// decrypted" and "this flow decrypted" are the same statement, and the
    /// reason has nothing to disagree with. The pre-R311y661 code read
    /// `encrypted_flows().first()` and presented that flow's reason as the
    /// capture's, which is wrong the moment two flows differ.
    #[test]
    fn a_capture_is_not_decrypted_while_one_of_its_flows_is_not() {
        let random = [7u8; 32];
        let records = alloc::vec![protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0))];
        let mut d = decryptable_flow(&random, &records);
        // A SECOND encrypted flow, on its own 5-tuple, with no ClientHello --
        // so it is recognised by its chain and has no identity to be keyed by.
        let mut chain = Vec::new();
        for i in 0..2u8 {
            chain.extend_from_slice(&protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)));
        }
        d.push_packet(LINKTYPE_ETHERNET, 9, &tcp_packet(2222, 7447, 1000, &chain));
        d.finish();
        assert_eq!(d.encrypted_flows().len(), 2, "the fixture needs two flows");

        /// Serves the flow that has an identity and declines the one that does
        /// not — which is what a real key log does.
        struct ByIdentity;
        impl crate::tls::RecordOpener for ByIdentity {
            fn begin_flow(
                &mut self,
                client_random: Option<&[u8; 32]>,
                _client_direction: Option<Direction>,
            ) -> Result<(), crate::tls::NotDecrypted> {
                match client_random {
                    Some(_) => Ok(()),
                    None => Err(crate::tls::NotDecrypted::NoSessionIdentity),
                }
            }
            fn open(
                &mut self,
                _direction: Direction,
                record: &crate::tls::EncryptedRecord,
            ) -> Option<crate::tls::OpenedRecord> {
                let body = record.bytes.get(5..)?;
                Some(crate::tls::OpenedRecord {
                    content_type: *body.first()?,
                    plaintext: body[1..].to_vec(),
                })
            }
            // It keys by SESSION identity and, for a flow it accepted, serves
            // both directions of it.
            fn has_keys(&self, _direction: Direction) -> bool {
                true
            }
        }

        let summary = d.decrypt_with(&mut ByIdentity);
        assert_eq!(summary.flows, 2);
        assert_eq!(summary.decrypted, 1);
        assert_eq!(summary.refused, 1);

        let json = crate::report::CaptureReport::of(&d).to_json();
        assert!(
            json.contains("\"decrypted\":false"),
            "one flow of two is not a decrypted capture: {json}"
        );
        assert!(
            json.contains("\"flows_decrypted\":1"),
            "and the partial state must be readable: {json}"
        );
        assert!(
            json.contains("\"reason\":\"no_session_identity\""),
            "one undecrypted flow, so its reason IS the capture's: {json}"
        );

        // AND WITH TWO DIFFERENT REFUSALS the reason must stop naming one of
        // them. A third flow, declined for another cause.
        let mut third = Vec::new();
        for i in 0..2u8 {
            third.extend_from_slice(&protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)));
        }
        let mut hello_flow = hello_with_random(&[9u8; 32]);
        hello_flow.extend_from_slice(&third);
        d.push_packet(
            LINKTYPE_ETHERNET,
            10,
            &tcp_packet(3333, 7447, 1000, &hello_flow),
        );
        d.finish();

        struct AlwaysNoKey;
        impl crate::tls::RecordOpener for AlwaysNoKey {
            fn begin_flow(
                &mut self,
                _client_random: Option<&[u8; 32]>,
                _client_direction: Option<Direction>,
            ) -> Result<(), crate::tls::NotDecrypted> {
                Err(crate::tls::NotDecrypted::NoKeyForSession)
            }
            fn open(
                &mut self,
                _direction: Direction,
                _record: &crate::tls::EncryptedRecord,
            ) -> Option<crate::tls::OpenedRecord> {
                None
            }
            // It declines every flow at `begin_flow`, so nothing ever reaches
            // the per-direction question. Answering `true` states that: what it
            // withholds is the SESSION key, not one direction's.
            fn has_keys(&self, _direction: Direction) -> bool {
                true
            }
        }
        d.decrypt_with(&mut AlwaysNoKey);
        let json = crate::report::CaptureReport::of(&d).to_json();
        assert!(
            json.contains("\"reason\":\"mixed\""),
            "two flows refused for DIFFERENT causes: naming either one as the \
             capture's reason sends a reader to the wrong remedy: {json}"
        );
    }

    /// R311y668 (§1.2a) — a direction with NO KEY is named as such, not as a
    /// record that refused the keys.
    ///
    /// The commonest arrangement there is: `SSLKEYLOGFILE` written by one of the
    /// two peers gives that side's traffic secret and not the other's. MEASURED
    /// before the fix, against real rustls-sealed records in
    /// `wz-tls-record/tests/end_to_end.rs`: such a flow reported
    /// `RecordRefusedKeys { direction: B, index: 0 }`, whose documented cause is
    /// the EPOCH -- so a reader was sent to look at key rotation for a key that
    /// was never in the log. Both remedies are concrete and they are different
    /// ones: get the other peer's log, versus recapture across the rotation.
    #[test]
    fn a_direction_with_no_key_names_the_direction_and_not_a_refused_record() {
        let random = [11u8; 32];
        let mut d = Dissection::new();
        let mut at = 0usize;
        // Direction A: the ClientHello and one record.
        let mut client = hello_with_random(&random);
        client.extend_from_slice(&protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(0)));
        d.push_packet(
            LINKTYPE_ETHERNET,
            at,
            &tcp_packet(1111, 7447, 1000, &client),
        );
        at += 1;
        // Direction B: two records, from the high port back to the low one.
        let mut server = Vec::new();
        for i in 1..3u8 {
            server.extend_from_slice(&protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)));
        }
        d.push_packet(
            LINKTYPE_ETHERNET,
            at,
            &tcp_packet(7447, 1111, 5000, &server),
        );
        d.finish();
        assert_eq!(
            (
                d.encrypted_flows()[0].kept_records[0].len(),
                d.encrypted_flows()[0].kept_records[1].len()
            ),
            (1, 2),
            "the fixture must hold records on BOTH sides or it cannot show a \
             one-sided key at all"
        );

        let mut opener = FakeOpener::new();
        opener.keyless[dir_index(Direction::B)] = true;
        d.decrypt_with(&mut opener);

        assert_eq!(
            d.encrypted_flows()[0].not_decrypted,
            Some(crate::tls::NotDecrypted::NoKeyForDirection {
                direction: Direction::B
            }),
            "the reason must name the direction whose key is missing"
        );
        // And the records were never ATTEMPTED. A reason derived from a failed
        // attempt would still be `RecordRefusedKeys` no matter what string the
        // report printed, so this is the half of the claim the reason alone does
        // not carry.
        assert!(
            !opener.asked.iter().any(|(dir, _)| *dir == Direction::B),
            "a direction with no key must not be handed records at all: {:?}",
            opener.asked
        );
        // A's records still opened: a one-sided key reads one side, and reporting
        // the flow as wholly unread would be its own wrong answer.
        assert_eq!(d.encrypted_flows()[0].decrypted_records, [1, 0]);

        let json = crate::report::CaptureReport::of(&d).to_json();
        assert!(
            json.contains("\"reason\":\"no_key_for_direction\""),
            "and the finding must reach the rendering, which is the only thing a \
             person running this ever sees: {json}"
        );
    }

    /// R311y669 (§1.2a) — a flow whose two halves fail DIFFERENTLY reports both.
    ///
    /// R311y668 carried this as a narrowing and it is one: the flow-level reason
    /// is `Option::get_or_insert`, so it keeps the first refusal a pass meets and
    /// direction A is walked first. A flow whose A hits an epoch boundary and
    /// whose B has no key at all told a reader to go recapture the rotation and
    /// said nothing about the missing secret -- one of the two remedies it needed.
    ///
    /// Nothing about the summary changed. What changed is that the summary is no
    /// longer the only thing recorded.
    #[test]
    fn a_flow_whose_two_directions_fail_differently_reports_both_reasons() {
        let random = [13u8; 32];
        let mut d = Dissection::new();
        // A: the hello and two records, the SECOND of which the opener refuses --
        // the epoch shape.
        let mut client = hello_with_random(&random);
        for i in 0..2u8 {
            client.extend_from_slice(&protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(i)));
        }
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &client));
        // B: one record, on a direction the opener holds no key for at all.
        let server = protected(crate::tls::CT_APPLICATION_DATA, &framed_unit(9));
        d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet(7447, 1111, 5000, &server));
        d.finish();

        let mut opener = FakeOpener::new();
        opener.refuse[dir_index(Direction::A)].insert(1);
        opener.keyless[dir_index(Direction::B)] = true;
        d.decrypt_with(&mut opener);

        let flow = &d.encrypted_flows()[0];
        // The summary is unchanged: A is walked first, so A's reason is it.
        assert_eq!(
            flow.not_decrypted,
            Some(crate::tls::NotDecrypted::RecordRefusedKeys {
                direction: Direction::A,
                index: 1
            }),
            "the one-word summary still answers with the first refusal met"
        );
        // THE ROUND: both halves are readable, and B's is the one the summary
        // could never have carried.
        assert_eq!(
            flow.not_decrypted_per_direction,
            [
                Some(crate::tls::NotDecrypted::RecordRefusedKeys {
                    direction: Direction::A,
                    index: 1
                }),
                Some(crate::tls::NotDecrypted::NoKeyForDirection {
                    direction: Direction::B
                })
            ],
            "each direction's own reason must survive the summary"
        );
        // A's FIRST record still opened. A flow reported as wholly unread would
        // be a third wrong answer.
        assert_eq!(flow.decrypted_records, [1, 0]);
    }

    /// R311y666 (§1.2a) — the decoded-message count does not walk backwards
    /// when the flow cap recycles a slot.
    ///
    /// R311y665 added the count reading the live tables and named this in its
    /// own carry rather than fixing it. It is the sixth counter to need the
    /// same repair (R311y605 streams, R311y610 sessions, R311y650 the encrypted
    /// census, R311y656 chains), and the argument has not changed: a census of
    /// what this reader SAW may only ever go up. A live tap recycles slots
    /// forever, so on one the number would fall as the capture went on -- and a
    /// falling total reads as messages that were never there.
    #[test]
    fn the_decoded_message_count_survives_an_eviction() {
        let mut d = Dissection::with_limits(DissectionLimits {
            max_flows_per_table: Some(1),
            ..DissectionLimits::default()
        });
        // A plaintext zenoh flow, so the messages are decoded without keys.
        let mut unit = alloc::vec![0x02u8, 0x00];
        unit.extend_from_slice(&[wz_session_core::wire_const::T_MID_KEEP_ALIVE, 0x00]);
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1111, 7447, 1000, &unit));
        d.finish();
        let before = d.decoded_messages();
        assert_eq!(before, 1, "the fixture must decode one message");

        // A second 5-tuple, which the cap of one evicts the first for.
        d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet(2222, 7447, 1000, &unit));
        d.finish();
        assert_eq!(d.drops().flows, 1, "the fixture must have evicted");
        assert_eq!(
            d.decoded_messages(),
            2,
            "the evicted flow's message must still be counted -- reading the \
             live table alone answers 1 here, which is FEWER than before the \
             second flow arrived"
        );
        assert!(
            crate::report::CaptureReport::of(&d)
                .to_json()
                .contains("\"messages_decoded\":2"),
            "and the report must carry the same number"
        );
    }

    /// R311y661 — a capture FILE's own key material reaches the dissection.
    ///
    /// `from_pcapng` parsed the Decryption Secrets Blocks since R311y658 and
    /// dropped them: the keys were in the file, were read, and were unreachable
    /// from the object the report is made of. A consumer could only recover them
    /// by parsing the file a second time.
    #[test]
    fn a_capture_files_own_decryption_secrets_reach_the_dissection() {
        const TLSK: u32 = 0x544c_534b;
        let log = b"CLIENT_TRAFFIC_SECRET_0 0011 2233\n";
        let mut file = crate::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &[(0, 0, &[0u8; 60])]);

        let mut body = TLSK.to_le_bytes().to_vec();
        body.extend_from_slice(&(log.len() as u32).to_le_bytes());
        body.extend_from_slice(log);
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let total = (12 + body.len()) as u32;
        let mut dsb = 0x0000_000Au32.to_le_bytes().to_vec();
        dsb.extend_from_slice(&total.to_le_bytes());
        dsb.extend_from_slice(&body);
        dsb.extend_from_slice(&total.to_le_bytes());
        file.extend_from_slice(&dsb);

        let d = Dissection::from_pcapng(&file).expect("the file parses");
        assert_eq!(
            d.decryption_secrets().len(),
            1,
            "the file said it carried keys and the dissection must be able to \
             hand them to an opener"
        );
        assert_eq!(d.decryption_secrets()[0].secrets_type, TLSK);
        assert_eq!(d.decryption_secrets()[0].secrets, log);
    }
}
