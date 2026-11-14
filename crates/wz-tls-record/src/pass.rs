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
//!   kept since the last. It opens TLS only, because the QUIC half reads the
//!   capture's own packets again and a feed does not keep them.
//!
//! The rule both shapes keep: the TLS pass runs only where there ARE keys. Run
//! with none, every flow would be declined as `no_key_for_session` -- keys were
//! supplied and none are for this session -- which is false about a run that
//! had no keys at all; `no_keys_supplied` is what such a flow keeps saying.
//!
//! No key byte leaves this module in a value a caller can print: [`KeyLog`],
//! [`CaptureOpener`] and the QUIC opener redact their secrets in `Debug`, and
//! nothing here formats one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use wz_capture::link::FlowKey;
use wz_capture::quic::QuicDecryption;
use wz_capture::tls::{Direction, FlowOpeners, RecordOpener};
use wz_capture::{DecryptionSummary, Dissection, PlaintextSink};

use crate::capture::CaptureOpener;
use crate::keylog::{KeyLog, SecretsBlockError};
use crate::quic::connection::{DirectionCensus, QuicFlowOpener, SequenceKey};
use crate::quic::QuicVersion;

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
    let keys: Vec<FlowKey> = dissection
        .datagram_flows()
        .iter()
        .filter(|f| f.quic.is_some())
        .map(|f| f.flow)
        .collect();
    let mut summary = QuicDecryption {
        flows_offered: keys.len(),
        ..Default::default()
    };
    if keys.is_empty() {
        return (summary, Vec::new());
    }
    let mut openers: Vec<(FlowKey, QuicFlowOpener)> = keys
        .iter()
        .map(|flow| {
            let opener = QuicFlowOpener::new(log.clone());
            // R311y709 (Y2) — the declared short-header connection id length
            // reaches the OPENER, or it is a flag nothing acts on.
            (
                *flow,
                match cid_len {
                    Some(len) => opener.declaring_short_connection_id_len(len),
                    None => opener,
                },
            )
        })
        .collect();

    let mut cursor = wz_capture::CaptureCursor::new();
    let walked = cursor.walk(capture, |event| {
        if let wz_capture::CaptureEvent::Frame(packet) = event {
            offer_datagram(&mut openers, packet.link_type, packet.index, packet.data);
        }
        core::ops::ControlFlow::Continue(())
    });
    if !matches!(walked, Ok(wz_capture::CaptureWalk::Halted { .. })) {
        return (summary, Vec::new());
    }

    let mut flows = Vec::new();
    for (flow, opener) in openers {
        let census = opener.census();
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
        if opener.identity_adopted() {
            summary.flows_identity_adopted += 1;
        }
        // A flow is WHOLE when every packet in it opened. Zero packets is not
        // whole: a QUIC flow the dissection counted and this pass saw none of is
        // a disagreement between two reads of one file, not a success.
        if packets > 0 && opened == packets {
            summary.flows_opened += 1;
        }
        let mut sequences = Vec::new();
        for direction in [Direction::A, Direction::B] {
            for (key, reassembler) in opener.sequences(direction) {
                sequences.push((direction, key, reassembler.stream().len()));
                // R311y718 (§1.2a) — the recovered bytes go on to the zenoh
                // framer. CRYPTO is offered too and refused by the framer rather
                // than filtered here: handshake bytes carry no zenoh, and the
                // framer counting them is what tells a capture whose every
                // stream is CRYPTO from one that recovered nothing.
                let (stream_id, handshake) = match key {
                    SequenceKey::Stream(id) => (id, false),
                    SequenceKey::Crypto(space) => (space.index() as u64, true),
                };
                summary
                    .framing
                    .absorb(dissection.feed_quic_stream_with_sink(
                        flow,
                        direction,
                        stream_id,
                        handshake,
                        reassembler.stream(),
                        sink,
                    ));
            }
            // R311y719 — and the RFC 9221 datagrams, each anchored by the index
            // of the capture packet it came out of: the only coordinate that
            // survives decryption for a datagram.
            for (origin, payload) in opener.datagrams(direction) {
                summary.framing.absorb(
                    dissection
                        .feed_quic_datagram_with_sink(flow, direction, *origin, payload, sink),
                );
            }
        }
        flows.push(QuicFlowOutcome {
            flow,
            census,
            client_direction: opener.client_direction(),
            version: opener.version(),
            keys_installed: opener.keys_installed(),
            client_hello_seen: opener.client_hello_seen(),
            identity_adopted: opener.identity_adopted(),
            sequences,
            sequences_dropped: opener.sequences_dropped(),
        });
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

/// Hand one captured packet to the QUIC opener of its flow, if it is a UDP
/// datagram of one.
fn offer_datagram(
    openers: &mut [(FlowKey, QuicFlowOpener)],
    link_type: u32,
    index: usize,
    data: &[u8],
) {
    let Ok(wz_capture::link::Transport::Udp(datagram)) =
        wz_capture::link::decapsulate(link_type, index, data)
    else {
        return;
    };
    let Some((_, opener)) = openers.iter_mut().find(|(f, _)| *f == datagram.flow) else {
        return;
    };
    // The direction rule the field walk uses: two readers of one capture that
    // disagree about which half a packet is on would file a client's stream
    // under the server.
    let direction = if datagram.from_low {
        Direction::A
    } else {
        Direction::B
    };
    // R311y719 — the CAPTURE PACKET INDEX travels with the offer: the only
    // coordinate that survives decryption for an RFC 9221 datagram.
    opener.push_datagram(direction, index, datagram.payload);
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

/// The TLS pass of a dissection that is still being fed, kept between calls.
///
/// It holds the keys (the dissection's own Decryption Secrets Blocks, read as
/// they arrive, and every key log a caller hands in) and one opener per flow it
/// began, which is what lets a flow continue on a later call
/// ([`Dissection::decrypt_continuing`]). Keys that arrive put every flow that
/// opened nothing back in front of the next pass
/// ([`Dissection::reopen_unopened`]); a flow that opened a record goes on from
/// where it stopped.
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
    /// Keys arrived since the last pass.
    grew: bool,
    openers: BTreeMap<FlowKey, CaptureOpener>,
}

impl core::fmt::Debug for LiveDecryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LiveDecryptor")
            .field("connections", &self.log.len())
            .field("blocks_read", &self.blocks_read)
            .field("foreign_secrets_blocks", &self.foreign_secrets_blocks)
            .field("openers", &self.openers.len())
            .finish()
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
        }
        Arc::make_mut(&mut self.log).absorb(parsed);
        named
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
    /// pass.
    pub fn run(&mut self, dissection: &mut Dissection) -> DecryptionSummary {
        let blocks = dissection.decryption_secrets();
        for block in blocks.iter().skip(self.blocks_read) {
            match KeyLog::from_secrets_block(block.secrets_type, &block.secrets) {
                Ok(parsed) => {
                    if !parsed.is_empty() {
                        self.grew = true;
                    }
                    Arc::make_mut(&mut self.log).absorb(parsed);
                }
                Err(SecretsBlockError::UnknownSecretsType(_)) => {
                    self.foreign_secrets_blocks += 1;
                }
            }
        }
        self.blocks_read = blocks.len();
        if self.log.is_empty() {
            return DecryptionSummary::default();
        }
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
