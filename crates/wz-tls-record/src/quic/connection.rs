// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y698 (§1.2a) — THE CALLER'S STATE. One QUIC connection, followed.
//!
//! ## What was missing, and why it was one item rather than five
//!
//! R311y694..697 built every primitive a QUIC packet needs: Initial keys from a
//! connection ID, header protection, the AEAD, a long-header walk, version
//! refusal, packet number reconstruction, the frame table, ordered reassembly.
//! Each was gated against rustls and none of them had a caller. The store's own
//! register recorded five separate open items -- a short header is not walked, a
//! packet number reconstruction has nobody holding `largest_opened`, no logic
//! picks which secret goes with which packet type, the reassembler table is
//! unkeyed, its bound is outside the crate's accounting -- and they are all the
//! same item, because every one of them is a fact a reader of a FLOW keeps and a
//! reader of a PACKET cannot.
//!
//! So this is that reader. It is deliberately not in `wz-capture`: that crate
//! carries zero third-party dependencies because its decode path builds for the
//! MCU profiles, and everything here reaches for a cipher.
//!
//! ## The chain, in the order a capture forces
//!
//! 1. A client's **Initial** packet is opened with keys derived from the
//!    connection ID in its own header — the one QUIC space a passive reader can
//!    open with nothing but the capture.
//! 2. Its **CRYPTO** frames reassemble into the TLS handshake, whose first
//!    message is the **ClientHello**, whose `Random` is what an NSS key log is
//!    indexed by. QUIC carries handshake messages with no TLS record layer, so
//!    this is a different read from `wz_capture::tls::client_hello_random` and
//!    the two are pinned against each other below.
//! 3. That `Random` yields the **Handshake** and **1-RTT** secrets, which open
//!    everything else.
//!
//! Each link is a fact read off the wire rather than configured, which is what
//! makes the whole chain available to a reader who has only a capture and a key
//! log — and what makes a mid-connection capture, which has no step 1, refuse by
//! name instead of silently reporting an empty session.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use wz_capture::tls::Direction;

use super::frames::{self, PieceOf, StreamReassembler};
use super::{LongHeader, PacketSpace, QuicKeys, QuicOpenError, QuicVersion};
use crate::keylog::{KeyLog, SecretLabel};
use crate::Suite;

/// The array index a direction takes, matching `capture::CaptureOpener`'s.
fn dir_index(direction: Direction) -> usize {
    match direction {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// R311y698 — what happened to ONE packet.
///
/// Per packet and not per datagram: a QUIC datagram routinely coalesces an
/// Initial and a Handshake packet, and a reader told only "the datagram was
/// opened" could not say which half it holds keys for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketOutcome {
    /// Opened, and what came out.
    Opened {
        /// Which space's keys opened it.
        space: PacketSpace,
        /// The FULL packet number, reconstructed.
        number: u64,
        /// How many plaintext bytes the AEAD produced.
        plaintext_bytes: usize,
        /// How many pieces of a byte sequence its frames carried.
        pieces: usize,
    },
    /// Not opened, and why. The space is `None` where this reader could not get
    /// far enough to name one.
    Refused {
        /// The space, where the header got far enough to say.
        space: Option<PacketSpace>,
        /// The reason, which is the whole point of refusing rather than
        /// skipping: a reader sent to their key log and a reader sent to their
        /// capture are looking for different things.
        why: QuicOpenError,
    },
}

/// R311y698 — one direction's tally.
///
/// Per direction from the start, which is the convention every other per-flow
/// census in this workspace follows and which `wz_capture::quic::QuicCensus`
/// does not (its own open item). The two halves of a connection fail
/// differently — a key log with only the client's secrets opens one and not the
/// other — and a summed figure cannot say so.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DirectionCensus {
    /// Packets seen, coalesced ones counted individually.
    pub packets: usize,
    /// Packets whose AEAD authenticated.
    pub opened: usize,
    /// Packets refused for want of a key for their space.
    pub no_keys: usize,
    /// Packets refused for any other reason.
    pub refused: usize,
    /// Opened packets per space, indexed by [`PacketSpace::index`].
    pub opened_per_space: [usize; 4],
    /// Frames walked.
    pub frames: usize,
    /// Frame walks that stopped at a type this reader does not know. Nonzero
    /// means a packet's later frames were NOT read, and any stream it carried
    /// is short by an unknown amount.
    pub walks_stopped: usize,
    /// CRYPTO bytes delivered in order.
    pub crypto_bytes: usize,
    /// STREAM bytes delivered in order.
    pub stream_bytes: usize,
    /// RFC 9221 DATAGRAM frames, which carry application bytes with no order.
    pub datagrams: usize,
    /// Their bytes.
    pub datagram_bytes: usize,
}

/// Which byte sequence a reassembler belongs to.
///
/// The space is part of a CRYPTO key because each packet space has its OWN
/// CRYPTO stream starting at offset zero: a reader that folded them would lay
/// the server's Handshake bytes over its Initial ones and hand the TLS layer a
/// message no endpoint sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SequenceKey {
    /// The handshake stream of one packet space.
    Crypto(PacketSpace),
    /// One application stream.
    Stream(u64),
}

/// R311y698 — the bounds this reader keeps, named where a caller can set them.
///
/// The register carried "the reassembler is outside the bound discipline" as an
/// open item, and the accurate form of it is that a reassembler bounds ITSELF
/// while the TABLE of them was unbounded — a connection opening streams is an
/// accumulation that grows with the input, which is the shape this workspace
/// bounds everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicLimits {
    /// Out-of-order bytes one sequence may hold. `None` is unbounded.
    pub buffered_bytes_per_sequence: Option<usize>,
    /// How many sequences one direction may track at once.
    pub sequences_per_direction: usize,
}

impl Default for QuicLimits {
    /// A ceiling rather than a measurement, and said so: 64 KiB is a QUIC
    /// endpoint's own default initial stream flow-control window in more than
    /// one implementation, so a sequence holding more than that behind a hole
    /// is already outside what a conforming sender would have in flight. The
    /// stream count is this crate's own and is not read from anywhere.
    fn default() -> Self {
        Self {
            buffered_bytes_per_sequence: Some(64 * 1024),
            sequences_per_direction: 64,
        }
    }
}

/// One packet space's keys, with the suite still to be settled.
///
/// Same shape and same reason as `capture::EpochState`: an NSS key log records
/// a secret and not a cipher suite, the secret's LENGTH pins the hash and
/// through it the candidates, and the AEAD tag settles which by opening a
/// packet. 48 bytes is SHA384 and unique; 32 leaves two.
#[derive(Debug)]
struct SpaceKeys {
    candidates: Vec<QuicKeys>,
}

impl SpaceKeys {
    /// The candidates a secret of this width admits, or `None` for a width no
    /// TLS 1.3 suite derives.
    fn from_secret(secret: &[u8]) -> Option<Self> {
        let suites: &[Suite] = match secret.len() {
            48 => &[Suite::Aes256GcmSha384],
            32 => &[Suite::Aes128GcmSha256, Suite::Chacha20Poly1305Sha256],
            _ => return None,
        };
        Some(Self {
            candidates: suites
                .iter()
                .map(|suite| QuicKeys::derive(*suite, secret))
                .collect(),
        })
    }

    /// A single, already-known key set (the Initial space, whose suite RFC 9001
    /// §5.2 names rather than negotiates).
    fn settled(keys: QuicKeys) -> Self {
        Self {
            candidates: alloc::vec![keys],
        }
    }
}

/// R311y698 (§1.2a) — one QUIC connection, followed across both directions.
///
/// Fed whole UDP payloads in capture order. Everything it knows it learned from
/// those payloads and the key log it was built with; nothing here is configured
/// except the bounds.
pub struct QuicFlowOpener {
    log: KeyLog,
    limits: QuicLimits,
    /// The version the first long header declared.
    version: Option<QuicVersion>,
    /// The direction that sent the first Initial packet, which is the client's
    /// by construction: a server's first packet is a response.
    client_direction: Option<Direction>,
    /// The connection ID the Initial keys were derived from, kept so a reader
    /// can be told which one it was.
    initial_connection_id: Option<Vec<u8>>,
    /// The ClientHello `Random`, read out of the Initial CRYPTO stream.
    client_random: Option<[u8; 32]>,
    /// Whether the key log has already been consulted for that random.
    keys_installed: bool,
    /// Per direction, per space. 1-RTT holds one entry per key generation.
    keys: [[Option<SpaceKeys>; 4]; 2],
    /// Per direction, the 1-RTT generations past the first.
    one_rtt_generations: [Vec<SpaceKeys>; 2],
    /// Per direction, which 1-RTT generation is current.
    one_rtt_at: [usize; 2],
    /// Per direction, per space, the largest packet number opened.
    largest: [[Option<u64>; 4]; 2],
    /// Per direction, how long the connection ID in front of a SHORT header's
    /// packet number is. Not on the wire: learned from the SOURCE connection ID
    /// of the OTHER direction's long headers, because packets travelling one way
    /// are addressed to the connection ID the other end chose for itself.
    short_connection_id_len: [Option<usize>; 2],
    /// The ordered sequences, per direction.
    sequences: [BTreeMap<SequenceKey, StreamReassembler>; 2],
    /// Sequences the table's bound refused.
    sequences_dropped: [usize; 2],
    /// RFC 9221 datagrams, whole and in arrival order.
    datagrams: [Vec<Vec<u8>>; 2],
    /// Frame types seen, for a reader that wants to know a connection closed.
    frame_types: [Vec<u64>; 2],
    census: [DirectionCensus; 2],
    /// R311y709 (Y2) — this flow's identity was ADOPTED from a key log holding
    /// exactly one connection, rather than read from a ClientHello it saw.
    identity_adopted: bool,
}

impl core::fmt::Debug for QuicFlowOpener {
    /// Never the keys, for the reason [`QuicKeys`] gives.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicFlowOpener")
            .field("version", &self.version)
            .field("client_direction", &self.client_direction)
            .field("client_random", &self.client_random.map(|_| "<redacted>"))
            .field("census", &self.census)
            .finish()
    }
}

impl QuicFlowOpener {
    /// A reader for one connection, with the key log it may need past the
    /// Initial space.
    ///
    /// An EMPTY log is a usable caller: the Initial space needs none, so a
    /// capture with no keys at all still yields the handshake's first flight —
    /// which is where a connection ID, a version, and a ClientHello are, and is
    /// therefore where a reader learns whether their key log is the right one.
    pub fn new(log: KeyLog) -> Self {
        Self::with_limits(log, QuicLimits::default())
    }

    /// The same, with the accumulation bounds named.
    pub fn with_limits(log: KeyLog, limits: QuicLimits) -> Self {
        Self {
            log,
            limits,
            version: None,
            client_direction: None,
            initial_connection_id: None,
            client_random: None,
            keys_installed: false,
            keys: [[None, None, None, None], [None, None, None, None]],
            one_rtt_generations: [Vec::new(), Vec::new()],
            one_rtt_at: [0, 0],
            largest: [[None; 4]; 2],
            short_connection_id_len: [None, None],
            sequences: [BTreeMap::new(), BTreeMap::new()],
            sequences_dropped: [0, 0],
            datagrams: [Vec::new(), Vec::new()],
            frame_types: [Vec::new(), Vec::new()],
            census: [DirectionCensus::default(); 2],
            identity_adopted: false,
        }
    }

    /// R311y709 (Y2) — open a capture that begins MID-CONNECTION, on two
    /// declarations that are held apart on purpose.
    ///
    /// # Why a declaration at all
    ///
    /// A 1-RTT packet does not carry the length of the connection id in front
    /// of its packet number; both endpoints remember it from a handshake this
    /// capture does not contain ([`Self::open_short`] refuses by name for
    /// exactly that). Nothing in the bytes can supply it, so it comes from the
    /// caller — the same shape `--quic <port>` already takes for the recognition
    /// question one crate over, and marked as a PREMISE for the same reason: a
    /// wrong length takes the header-protection sample from the wrong bytes and
    /// the failure then looks like a wrong key.
    ///
    /// # And why the OTHER half is not a declaration
    ///
    /// Keys are indexed by the ClientHello random, which a mid-connection
    /// capture also does not contain. This does NOT ask the caller for it. It
    /// adopts the identity only when the key log holds EXACTLY ONE connection,
    /// where the operator's two inputs identify each other and there is nothing
    /// to guess between; a log holding several leaves the flow unopened rather
    /// than picking one.
    ///
    /// WHICH DIRECTION IS THE CLIENT is then settled by EVIDENCE and not by a
    /// third premise: both parties' application secrets are installed as
    /// candidates in both directions, and the AEAD tag picks — the same 128-bit
    /// check [`Self::open`] already settles the cipher suite and the key
    /// generation with, rather than the guess "whoever spoke first".
    ///
    /// # The limit this mode has, stated rather than discovered
    ///
    /// Key updates are not followed here. The generation ladder is per
    /// direction and this mode has not established which direction is which
    /// until a packet opens, so the rungs are left uninstalled. A mid-connection
    /// capture that spans a rekey opens the packets before it and refuses the
    /// ones after — refuses, not misreads.
    pub fn declaring_short_connection_id_len(mut self, len: usize) -> Self {
        self.short_connection_id_len = [Some(len), Some(len)];
        self.adopt_lone_identity();
        self
    }

    /// R311y709 (Y2) — was this flow's identity ADOPTED rather than read?
    ///
    /// Carried so a report can say so. "I saw the ClientHello this key indexes"
    /// and "the log held one connection and I assumed it was this one" are
    /// different claims, and a reader acts differently on them.
    pub fn identity_adopted(&self) -> bool {
        self.identity_adopted
    }

    /// Adopt the key log's connection when it holds exactly one.
    fn adopt_lone_identity(&mut self) {
        if self.keys_installed || self.client_random.is_some() {
            return;
        }
        let mut randoms = self.log.client_randoms();
        let Some(only) = randoms.next().copied() else {
            return;
        };
        if randoms.next().is_some() {
            // Two or more. Nothing here can tell which connection these packets
            // belong to, and picking would produce a confident wrong answer of
            // exactly the kind this module exists to end.
            return;
        }
        let Some(secrets) = self.log.get(&only) else {
            return;
        };
        // Both parties' application secrets, as candidates in BOTH directions.
        let mut derived: Vec<QuicKeys> = Vec::new();
        for is_server in [false, true] {
            if let Some((_, secret)) = secrets.application_secrets(is_server).into_iter().next() {
                if let Some(keys) = SpaceKeys::from_secret(secret) {
                    derived.extend(keys.candidates);
                }
            }
        }
        if derived.is_empty() {
            return;
        }
        for index in [0usize, 1] {
            self.keys[index][PacketSpace::OneRtt.index()] = Some(SpaceKeys {
                candidates: derived.clone(),
            });
        }
        self.client_random = Some(only);
        self.identity_adopted = true;
        self.keys_installed = true;
    }

    /// Offer one UDP payload, in capture order.
    ///
    /// Returns one outcome per QUIC packet inside it. A datagram routinely
    /// coalesces several: a client's first flight is an Initial and a Handshake
    /// packet in one datagram, and a reader that stopped at the first would hold
    /// half a handshake.
    pub fn push_datagram(&mut self, direction: Direction, payload: &[u8]) -> Vec<PacketOutcome> {
        let d = dir_index(direction);
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < payload.len() {
            let rest = &payload[at..];
            self.census[d].packets += 1;
            let first = rest[0];
            if first & 0x80 == 0 {
                // A short header runs to the end of the datagram: 1-RTT packets
                // carry no length, so one can only be the last packet in a
                // datagram. Whatever the outcome, the walk ends here.
                out.push(self.open_short(direction, rest));
                break;
            }
            // THE VERSION FIRST, before the walk uses the type bits: a Version
            // Negotiation packet carries version 0 and its type bits mean
            // nothing, so a reader that walked it as an Initial would report a
            // token length read out of a connection ID.
            let Some(raw) = rest.get(1..5) else {
                out.push(self.refuse(d, None, QuicOpenError::TruncatedHeader));
                break;
            };
            let raw = u32::from_be_bytes(raw.try_into().expect("four bytes"));
            let Some(version) = QuicVersion::from_wire(raw) else {
                out.push(self.refuse(d, None, QuicOpenError::UnsupportedVersion(raw)));
                break;
            };
            self.version.get_or_insert(version);
            let header = match LongHeader::parse(rest) {
                Ok(header) => header,
                Err(why) => {
                    out.push(self.refuse(d, None, why));
                    break;
                }
            };
            let end = header
                .packet_number_offset
                .saturating_add(header.remainder_len)
                .min(rest.len());
            if end <= header.packet_number_offset {
                // A declared length that leaves no room for a packet number is
                // one this reader cannot step past, and stepping by a guess
                // would resume the walk in the middle of a packet.
                out.push(self.refuse(d, None, QuicOpenError::TruncatedPacketNumber));
                break;
            }
            out.push(self.open_long(direction, version, &header, &rest[..end]));
            at += end;
        }
        out
    }

    /// Open one long-header packet, learning from its header first.
    fn open_long(
        &mut self,
        direction: Direction,
        version: QuicVersion,
        header: &LongHeader,
        packet: &[u8],
    ) -> PacketOutcome {
        let d = dir_index(direction);
        // WHAT THE HEADER TEACHES, whether or not the packet opens: a source
        // connection ID is the address the OTHER direction will write into its
        // short headers, and it is the only place that length is ever stated.
        //
        // ZERO IS AN ANSWER. An endpoint that needs no routing may choose an
        // EMPTY connection id, and RFC 9000 §5.1 says so explicitly; short
        // headers addressed to it then carry none. MEASURED -- this line began
        // as `if !source_connection_id.is_empty()`, every unit test passed
        // because both fixtures gave the server a four-byte id, and the
        // capture-level test found the server's own 1-RTT packet refused for
        // want of a length that had been on the wire all along.
        self.short_connection_id_len[1 - d] = Some(header.source_connection_id.len());
        let Some(space) = PacketSpace::from_long_packet_type(header.packet_type) else {
            return self.refuse(d, None, QuicOpenError::RetryNotRead);
        };
        if space == PacketSpace::Initial {
            // The first Initial in the capture is the client's: a server's
            // first packet is a response to one. Its DESTINATION connection ID
            // is what both directions' Initial keys come from — a server's own
            // Initial is addressed to a different one, so deriving from every
            // Initial would replace working keys with wrong ones.
            if self.client_direction.is_none() {
                self.client_direction = Some(direction);
                self.initial_connection_id = Some(header.destination_connection_id.clone());
                let (client, server) =
                    QuicKeys::initial(version, &header.destination_connection_id);
                self.keys[d][PacketSpace::Initial.index()] = Some(SpaceKeys::settled(client));
                self.keys[1 - d][PacketSpace::Initial.index()] = Some(SpaceKeys::settled(server));
            }
        }
        self.open(direction, space, packet, header.packet_number_offset)
    }

    /// Open one short-header (1-RTT) packet.
    fn open_short(&mut self, direction: Direction, packet: &[u8]) -> PacketOutcome {
        let d = dir_index(direction);
        let Some(cid_len) = self.short_connection_id_len[d] else {
            // Q3's honest limit, named. A 1-RTT packet does not carry the length
            // of the connection ID in front of its packet number; both endpoints
            // remember it from the handshake. A capture that begins after that
            // handshake has nowhere to read it from, and a guess of zero takes
            // the protection sample from the wrong bytes and blames the key.
            return self.refuse(
                d,
                Some(PacketSpace::OneRtt),
                QuicOpenError::UnknownConnectionIdLength,
            );
        };
        self.open(direction, PacketSpace::OneRtt, packet, 1 + cid_len)
    }

    /// The common half: unmask, reconstruct the number, authenticate, walk.
    fn open(
        &mut self,
        direction: Direction,
        space: PacketSpace,
        packet: &[u8],
        pn_offset: usize,
    ) -> PacketOutcome {
        let d = dir_index(direction);
        let s = space.index();
        if self.keys[d][s].is_none() {
            self.census[d].no_keys += 1;
            return PacketOutcome::Refused {
                space: Some(space),
                why: QuicOpenError::NoKeysForSpace(space),
            };
        }
        // R311y698 — the 1-RTT KEY PHASE picks the generation, and the header
        // protection key does NOT change with it (RFC 9001 §6). A reader that
        // re-derived `quic hp` from the new secret would fail to unmask the
        // first packet after every update, and the failure would look like a
        // wrong key rather than a wrong rule.
        let phase_candidate = if space == PacketSpace::OneRtt {
            self.one_rtt_next_generation(d)
        } else {
            None
        };

        let candidates = self.keys[d][s]
            .as_ref()
            .expect("just checked")
            .candidates
            .len();
        let mut last = QuicOpenError::NotAuthenticated;
        for candidate in 0..candidates {
            match self.try_open(d, s, candidate, packet, pn_offset, None) {
                Ok(opened) => {
                    // The suite is SETTLED by the tag: a 128-bit check that
                    // passed is the suite, and the others are dropped so a later
                    // packet cannot silently pick a different one.
                    if candidates > 1 {
                        let keys = self.keys[d][s].as_mut().expect("just checked");
                        let winner = keys.candidates.remove(candidate);
                        keys.candidates.clear();
                        keys.candidates.push(winner);
                    }
                    return self.deliver(direction, space, opened);
                }
                Err(why) => last = why,
            }
        }
        // Nothing in the current generation. If a key phase says the sender
        // rekeyed, the NEXT generation is the one remaining explanation.
        if let Some(next) = phase_candidate {
            if let Ok(opened) = self.try_open(d, s, 0, packet, pn_offset, Some(next)) {
                self.one_rtt_at[d] = next;
                return self.deliver(direction, space, opened);
            }
        }
        self.refuse(d, Some(space), last)
    }

    /// The 1-RTT generation past the current one, if the key log carried it.
    ///
    /// # Why the key PHASE bit is not read here
    ///
    /// RFC 9001 §6 puts the phase in the protected byte, so it can only be read
    /// after the header is unmasked -- and the mask is not authenticated, so a
    /// bit read out of it is a claim rather than a fact. The AEAD is what
    /// settles it: the current generation is tried first and the next one only
    /// if that fails, which reaches the same answer through a 128-bit check
    /// instead of an unauthenticated bit. Stated because trusting the masked
    /// bit is the shortcut this module refuses everywhere else.
    fn one_rtt_next_generation(&self, d: usize) -> Option<usize> {
        let next = self.one_rtt_at[d] + 1;
        (next <= self.one_rtt_generations[d].len()).then_some(next)
    }

    /// One trial: a private copy of the packet, unmasked and authenticated.
    ///
    /// A copy per trial and not one buffer reused, because unmasking is in
    /// place: a candidate that failed has already scrambled the header, and the
    /// next candidate would be reading bytes the first one wrote.
    fn try_open(
        &self,
        d: usize,
        s: usize,
        candidate: usize,
        packet: &[u8],
        pn_offset: usize,
        generation: Option<usize>,
    ) -> Result<OpenedPacket, QuicOpenError> {
        let base = &self.keys[d][s]
            .as_ref()
            .ok_or(QuicOpenError::NotAuthenticated)?
            .candidates[candidate];
        // The header protection key is always the FIRST generation's; only the
        // packet protection key follows the phase.
        let packet_keys = match generation {
            None if self.one_rtt_at[d] == 0 || s != PacketSpace::OneRtt.index() => base.clone(),
            None => self.one_rtt_generations[d]
                .get(self.one_rtt_at[d] - 1)
                .and_then(|k| k.candidates.first())
                .ok_or(QuicOpenError::NotAuthenticated)?
                .clone()
                .with_header_protection_of(base),
            Some(next) => self.one_rtt_generations[d]
                .get(next - 1)
                .and_then(|k| k.candidates.first())
                .ok_or(QuicOpenError::NotAuthenticated)?
                .clone()
                .with_header_protection_of(base),
        };
        let mut buf = packet.to_vec();
        let header = base.unprotect_header(&mut buf, pn_offset)?;
        let number = super::reconstruct_packet_number(
            self.largest[d][s],
            header.truncated_packet_number,
            header.packet_number_len,
        );
        let (aad, body) = buf.split_at_mut(header.payload_offset.min(packet.len()));
        let plaintext = packet_keys.open(number, aad, body)?.to_vec();
        Ok(OpenedPacket { number, plaintext })
    }

    /// Account for one opened packet and walk what it carried.
    fn deliver(
        &mut self,
        direction: Direction,
        space: PacketSpace,
        opened: OpenedPacket,
    ) -> PacketOutcome {
        let d = dir_index(direction);
        let s = space.index();
        self.largest[d][s] = Some(match self.largest[d][s] {
            Some(previous) => previous.max(opened.number),
            None => opened.number,
        });
        self.census[d].opened += 1;
        self.census[d].opened_per_space[s] += 1;

        let mut types: Vec<u64> = Vec::new();
        let walked = frames::walk_with(&opened.plaintext, &mut |ty| types.push(ty));
        self.census[d].frames += types.len();
        for ty in types {
            if !self.frame_types[d].contains(&ty) {
                self.frame_types[d].push(ty);
            }
        }
        let pieces = match walked {
            Ok(pieces) => pieces,
            Err(_) => {
                // A walk that stopped read SOME frames and this reader keeps
                // none of them: a piece taken from a walk that then lost its
                // place is a piece whose offset was believed on the strength of
                // a parse that failed. Counted so the shortfall is visible.
                self.census[d].walks_stopped += 1;
                Vec::new()
            }
        };
        let count = pieces.len();
        for piece in &pieces {
            self.file_piece(d, space, piece);
        }
        PacketOutcome::Opened {
            space,
            number: opened.number,
            plaintext_bytes: opened.plaintext.len(),
            pieces: count,
        }
    }

    /// File one piece under the sequence it belongs to.
    fn file_piece(&mut self, d: usize, space: PacketSpace, piece: &frames::StreamPiece<'_>) {
        let key = match piece.of {
            PieceOf::Crypto => SequenceKey::Crypto(space),
            PieceOf::Stream(id) => SequenceKey::Stream(id),
            PieceOf::Datagram => {
                // NOT reassembled: an RFC 9221 datagram is whole, unordered and
                // never retransmitted, and filing it at offset zero would make
                // the second one look like a resend of the first.
                self.census[d].datagrams += 1;
                self.census[d].datagram_bytes += piece.data.len();
                self.datagrams[d].push(piece.data.to_vec());
                return;
            }
        };
        if !self.sequences[d].contains_key(&key)
            && self.sequences[d].len() >= self.limits.sequences_per_direction
        {
            // The TABLE's bound, which is the half that was missing: each
            // reassembler bounded its own hold and nothing bounded how many
            // there were.
            self.sequences_dropped[d] += 1;
            return;
        }
        let bound = self.limits.buffered_bytes_per_sequence;
        let reassembler = self.sequences[d]
            .entry(key)
            .or_insert_with(|| StreamReassembler::new(bound));
        let delivered = reassembler.push(piece.offset, piece.data, piece.fin);
        if matches!(piece.of, PieceOf::Crypto) {
            self.census[d].crypto_bytes += delivered;
            if space == PacketSpace::Initial {
                self.learn_from_initial_crypto(d);
            }
        } else {
            self.census[d].stream_bytes += delivered;
        }
    }

    /// The ClientHello's `Random`, and the keys it unlocks.
    fn learn_from_initial_crypto(&mut self, d: usize) {
        if self.keys_installed || Some(d) != self.client_direction.map(dir_index) {
            return;
        }
        let Some(reassembler) = self.sequences[d].get(&SequenceKey::Crypto(PacketSpace::Initial))
        else {
            return;
        };
        let Some(random) = client_hello_random(reassembler.stream()) else {
            return;
        };
        self.client_random = Some(random);
        self.install_keys(random);
    }

    /// Install every secret the key log holds for this connection.
    fn install_keys(&mut self, random: [u8; 32]) {
        let Some(client) = self.client_direction else {
            return;
        };
        let Some(secrets) = self.log.get(&random) else {
            // The log does not know this connection. Left uninstalled and NOT
            // marked done, so a later ClientHello on this flow can retry against
            // the same log.
            //
            // R311y708 (Y4) — this comment used to end "a caller may absorb a
            // second log and try again", which named a method with zero callers
            // and zero tests. The operator's real remedy is a second `--keylog`
            // on the command line, which merges BEFORE any opener is built; that
            // flag was silently keeping only the last file until this round, so
            // the capability lived where nobody could reach it and was broken
            // where everybody typed it.
            return;
        };
        let c = dir_index(client);
        let s = 1 - c;
        let mut plan: Vec<(usize, PacketSpace, Vec<u8>)> = Vec::new();
        for (index, space, label) in [
            (c, PacketSpace::ZeroRtt, SecretLabel::ClientEarly),
            (c, PacketSpace::Handshake, SecretLabel::ClientHandshake),
            (s, PacketSpace::Handshake, SecretLabel::ServerHandshake),
        ] {
            if let Some(secret) = secrets.get(label) {
                plan.push((index, space, secret.to_vec()));
            }
        }
        // The application secrets come as a GENERATION LIST: a long-lived
        // session rekeys, and each generation is a different secret protecting
        // different packets. The first is the space's keys and the rest are the
        // ladder a key phase walks.
        let mut ladders: Vec<(usize, Vec<Vec<u8>>)> = Vec::new();
        for (index, is_server) in [(c, false), (s, true)] {
            let generations: Vec<Vec<u8>> = secrets
                .application_secrets(is_server)
                .into_iter()
                .map(|(_, secret)| secret.to_vec())
                .collect();
            if !generations.is_empty() {
                ladders.push((index, generations));
            }
        }
        for (index, space, secret) in plan {
            if let Some(keys) = SpaceKeys::from_secret(&secret) {
                self.keys[index][space.index()] = Some(keys);
            }
        }
        for (index, generations) in ladders {
            let mut iter = generations.into_iter();
            if let Some(first) = iter.next() {
                if let Some(keys) = SpaceKeys::from_secret(&first) {
                    self.keys[index][PacketSpace::OneRtt.index()] = Some(keys);
                }
            }
            self.one_rtt_generations[index] = iter
                .filter_map(|secret| SpaceKeys::from_secret(&secret))
                .collect();
        }
        self.keys_installed = true;
    }

    /// Count a refusal and describe it.
    fn refuse(
        &mut self,
        d: usize,
        space: Option<PacketSpace>,
        why: QuicOpenError,
    ) -> PacketOutcome {
        self.census[d].refused += 1;
        PacketOutcome::Refused { space, why }
    }

    /// The per-direction tallies, `[A, B]`.
    pub fn census(&self) -> [DirectionCensus; 2] {
        self.census
    }

    /// One direction's ordered sequences.
    pub fn sequences(
        &self,
        direction: Direction,
    ) -> impl Iterator<Item = (SequenceKey, &StreamReassembler)> {
        self.sequences[dir_index(direction)]
            .iter()
            .map(|(key, value)| (*key, value))
    }

    /// One sequence's bytes, in order, as far as they are contiguous.
    pub fn sequence(&self, direction: Direction, key: SequenceKey) -> Option<&[u8]> {
        self.sequences[dir_index(direction)]
            .get(&key)
            .map(|r| r.stream())
    }

    /// The RFC 9221 datagrams one direction carried, whole and in arrival order.
    pub fn datagrams(&self, direction: Direction) -> &[Vec<u8>] {
        &self.datagrams[dir_index(direction)]
    }

    /// Sequences the table's bound refused, `[A, B]`.
    pub fn sequences_dropped(&self) -> [usize; 2] {
        self.sequences_dropped
    }

    /// The frame types one direction sent, each once, in first-seen order.
    pub fn frame_types(&self, direction: Direction) -> &[u64] {
        &self.frame_types[dir_index(direction)]
    }

    /// The version the connection declared, once a long header has been seen.
    pub fn version(&self) -> Option<QuicVersion> {
        self.version
    }

    /// Which direction the client is, settled by whoever sent the first
    /// Initial packet.
    pub fn client_direction(&self) -> Option<Direction> {
        self.client_direction
    }

    /// The connection ID the Initial keys were derived from.
    pub fn initial_connection_id(&self) -> Option<&[u8]> {
        self.initial_connection_id.as_deref()
    }

    /// The ClientHello `Random` this reader read out of the handshake, which is
    /// what a key log is indexed by.
    pub fn client_random(&self) -> Option<[u8; 32]> {
        self.client_random
    }

    /// Whether the key log held this connection's secrets.
    pub fn keys_installed(&self) -> bool {
        self.keys_installed
    }
}

/// One packet, opened.
struct OpenedPacket {
    number: u64,
    plaintext: Vec<u8>,
}

/// R311y698 (§1.2a) — the `Random` of a ClientHello at the head of a QUIC
/// CRYPTO stream.
///
/// # Why this is not `wz_capture::tls::client_hello_random`
///
/// That function reads a ClientHello inside a TLS RECORD, and its offset
/// includes the five-byte record header. QUIC has no record layer at all: RFC
/// 9001 §4 carries TLS handshake messages directly in CRYPTO frames, so the
/// same message begins five bytes earlier. A reader that reused the TLS offset
/// would take its 32 bytes from five bytes into the random and five bytes into
/// the session ID, and the key log lookup would simply miss — which looks
/// exactly like a key log for another connection.
///
/// The two are pinned against each other in this module's tests, feeding one
/// ClientHello body to both readers with and without the record header.
pub fn client_hello_random(crypto: &[u8]) -> Option<[u8; 32]> {
    // handshake type 1 = client_hello. Checked rather than assumed: a CRYPTO
    // stream in the server direction opens with a ServerHello, and reading its
    // random as the client's would index the key log with the wrong 32 bytes.
    if *crypto.first()? != 0x01 {
        return None;
    }
    // type(1) + length(3) + legacy_version(2).
    const RANDOM_AT: usize = 6;
    crypto.get(RANDOM_AT..RANDOM_AT + 32)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::KeyLog;

    // R311y698 — the packet builders live in `quic::fixture`, not here.
    //
    // `wz-analyze` must build a QUIC capture to prove its pass runs, and a
    // second copy of the packet layout over there would be a second opinion
    // about where a header ends -- exactly the shape R311y678 closed on the
    // TLS side by making one walk serve both readers.
    use super::super::fixture::*;

    /// R311y698 (§1.2a) — THE CHAIN. A capture is walked from a connection ID
    /// on the wire to the bytes of a 1-RTT stream, and nothing but the capture
    /// and a key log goes in.
    ///
    /// This is the item the register carried as "there is no caller". Each step
    /// below was a primitive with a test and no way to reach it:
    ///
    /// 1. The client's Initial opens from the connection ID in its own header.
    /// 2. Its CRYPTO frames reassemble into a ClientHello, whose `Random` is
    ///    what a key log is indexed by — read at a DIFFERENT offset from TLS's,
    ///    because QUIC has no record layer.
    /// 3. That `Random` installs the 1-RTT secrets.
    /// 4. The server's long header teaches this reader how long the connection
    ///    ID in a client SHORT header is, which is stated nowhere on the wire.
    /// 5. A 1-RTT packet opens, and its STREAM frame's bytes come out in order.
    #[test]
    fn a_connection_is_followed_from_its_connection_id_to_a_one_rtt_stream() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (_, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);

        // 1. The client's Initial, carrying its ClientHello, protected BY THE
        //    ORACLE. rustls seals this one -- the same fixture the packet
        //    protection tests use -- so the chain's entry point is gated by an
        //    independent implementation and not by this module's own inverse.
        let hello = client_hello(&random);
        let payload = crypto_frame(0, &hello);
        let (packet, _) = super::super::tests::protected_initial(0, &payload);
        // ANTI-VACUITY: the ClientHello must not be lying in the packet in the
        // clear, or "this reader opened it" is a statement about a buffer.
        assert!(
            !packet.windows(hello.len()).any(|w| w == &hello[..]),
            "the fixture must actually be protected"
        );

        let mut opener = QuicFlowOpener::new(log_for(&random, 1));
        let outcomes = opener.push_datagram(Direction::A, &packet);
        assert!(
            matches!(
                outcomes.as_slice(),
                [PacketOutcome::Opened {
                    space: PacketSpace::Initial,
                    number: 0,
                    ..
                }]
            ),
            "the client Initial opens: {outcomes:?}"
        );
        // 2 and 3: the random was read at the QUIC offset and the log consulted.
        assert_eq!(
            opener.client_random(),
            Some(random),
            "the ClientHello random is read out of the CRYPTO stream"
        );
        assert!(
            opener.keys_installed(),
            "and it found this connection's keys"
        );
        assert_eq!(opener.client_direction(), Some(Direction::A));
        assert_eq!(opener.initial_connection_id(), Some(&ICID[..]));

        // 4. The server's Initial, which is where the client's short-header
        //    connection ID length comes from.
        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (header, pn_offset) = long_header(LongHeader::INITIAL, &[], &SCID, reply.len(), 0);
        let packet = protect(&server_initial, 0, &header, pn_offset, &reply);
        let outcomes = opener.push_datagram(Direction::B, &packet);
        assert!(
            matches!(outcomes.as_slice(), [PacketOutcome::Opened { .. }]),
            "the server Initial opens with the other half of the same derivation: {outcomes:?}"
        );

        // 5. A 1-RTT packet from the client, addressed to the server's
        //    connection ID, carrying a stream.
        let keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, b"a zenoh session");
        let (header, pn_offset) = short_header(&SCID, 1);
        let packet = protect(&keys, 1, &header, pn_offset, &payload);
        let outcomes = opener.push_datagram(Direction::A, &packet);
        assert!(
            matches!(
                outcomes.as_slice(),
                [PacketOutcome::Opened {
                    space: PacketSpace::OneRtt,
                    number: 1,
                    ..
                }]
            ),
            "the 1-RTT packet opens, and its packet number is reconstructed: {outcomes:?}"
        );
        assert_eq!(
            opener.sequence(Direction::A, SequenceKey::Stream(0)),
            Some(&b"a zenoh session"[..]),
            "and the stream's bytes come out"
        );

        let census = opener.census();
        assert_eq!(census[0].opened, 2, "two client packets");
        assert_eq!(census[1].opened, 1, "one server packet");
        assert_eq!(census[0].stream_bytes, 15);
        assert_eq!(
            census[0].opened_per_space[PacketSpace::Initial.index()],
            1,
            "the spaces are counted apart"
        );
        assert_eq!(census[0].opened_per_space[PacketSpace::OneRtt.index()], 1);
    }

    /// R311y698 (§1.2a) — a SHORT header before any long one is refused BY
    /// NAME, and the same packet opens once a long header has been seen.
    ///
    /// ## Why both halves are one test
    ///
    /// The connection ID length in front of a 1-RTT packet number is not on the
    /// wire: both endpoints remember it from the handshake. So a capture that
    /// begins mid-connection cannot locate the packet number at all — and the
    /// refusal has to be distinguishable from "the key is wrong", because a
    /// reader acts differently on the two. Asserting the refusal alone would
    /// pass in a build that refused every short header; asserting the success
    /// alone would not show that the length is what was missing.
    #[test]
    fn a_short_header_needs_a_length_only_the_handshake_states() {
        let random: [u8; 32] = core::array::from_fn(|i| i as u8);
        let keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, b"zenoh");
        let (header, pn_offset) = short_header(&SCID, 0);
        let packet = protect(&keys, 0, &header, pn_offset, &payload);

        let mut cold = QuicFlowOpener::new(log_for(&random, 1));
        let outcomes = cold.push_datagram(Direction::A, &packet);
        assert_eq!(
            outcomes,
            alloc::vec![PacketOutcome::Refused {
                space: Some(PacketSpace::OneRtt),
                why: QuicOpenError::UnknownConnectionIdLength,
            }],
            "a mid-connection capture cannot locate the packet number"
        );

        // The SAME packet, after a server long header taught the length.
        let mut warm = QuicFlowOpener::new(log_for(&random, 1));
        let hello = client_hello(&random);
        let first = crypto_frame(0, &hello);
        let (h, o) = long_header(LongHeader::INITIAL, &ICID, &[], first.len(), 0);
        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        warm.push_datagram(Direction::A, &protect(&client_initial, 0, &h, o, &first));
        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(LongHeader::INITIAL, &[], &SCID, reply.len(), 0);
        warm.push_datagram(Direction::B, &protect(&server_initial, 0, &h, o, &reply));

        let outcomes = warm.push_datagram(Direction::A, &packet);
        assert!(
            matches!(outcomes.as_slice(), [PacketOutcome::Opened { .. }]),
            "and the same bytes open once the length is known: {outcomes:?}"
        );
    }

    /// R311y709 (Y2) — A MID-CONNECTION CAPTURE OPENS ON A DECLARED LENGTH,
    /// AND THE DIRECTION IS SETTLED BY THE AEAD RATHER THAN GUESSED.
    ///
    /// The three arms are the whole claim and no two of them are the same test:
    ///
    /// 1. **Undeclared** — the refusal the test above pins, restated here as the
    ///    baseline this round moves. Without it the second arm proves only that
    ///    something opens, not that the declaration is what opened it.
    /// 2. **Declared** — the identical bytes open. The packet is sealed with the
    ///    CLIENT's application secret and pushed on direction A, and nothing
    ///    told this opener that A is the client: both parties' secrets went in
    ///    as candidates in both directions and the 128-bit tag picked.
    /// 3. **Ambiguous log** — the same declaration over a log holding TWO
    ///    connections leaves the flow unopened. This is the arm that stops the
    ///    feature from being "assume the first one": there is no rule here that
    ///    picks between two connections, and the refusal is the design.
    #[test]
    fn a_mid_connection_capture_opens_on_a_declared_length_and_never_on_a_guess() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(3));
        let keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, b"zenoh");
        let (header, pn_offset) = short_header(&SCID, 0);
        let packet = protect(&keys, 0, &header, pn_offset, &payload);

        // 1. THE BASELINE.
        let mut undeclared = QuicFlowOpener::new(log_for(&random, 1));
        assert_eq!(
            undeclared.push_datagram(Direction::A, &packet),
            alloc::vec![PacketOutcome::Refused {
                space: Some(PacketSpace::OneRtt),
                why: QuicOpenError::UnknownConnectionIdLength,
            }],
            "without the declaration this capture is still unreadable"
        );
        assert!(
            !undeclared.identity_adopted(),
            "and nothing was assumed about which connection it is"
        );

        // 2. THE SAME BYTES, DECLARED.
        let mut declared =
            QuicFlowOpener::new(log_for(&random, 1)).declaring_short_connection_id_len(SCID.len());
        assert!(
            declared.identity_adopted(),
            "a log holding one connection identifies this one"
        );
        let outcomes = declared.push_datagram(Direction::A, &packet);
        assert!(
            matches!(
                outcomes.as_slice(),
                [PacketOutcome::Opened {
                    space: PacketSpace::OneRtt,
                    ..
                }]
            ),
            "the declared length locates the packet number and the tag does the \
             rest: {outcomes:?}"
        );
        assert_eq!(
            declared.census()[0].stream_bytes,
            5,
            "and the application bytes came out"
        );

        // 3. AN AMBIGUOUS LOG IS NOT A GUESS.
        let other: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(200));
        let mut both = KeyLog::parse(log_text(&random, 1).as_bytes());
        both.absorb(KeyLog::parse(log_text(&other, 1).as_bytes()));
        assert_eq!(
            both.client_randoms().count(),
            2,
            "the population: one connection in this log would make the arm vacuous"
        );
        let mut ambiguous = QuicFlowOpener::new(both).declaring_short_connection_id_len(SCID.len());
        assert!(
            !ambiguous.identity_adopted(),
            "two connections and no way to tell which -- so none is adopted"
        );
        let outcomes = ambiguous.push_datagram(Direction::A, &packet);
        assert!(
            matches!(
                outcomes.as_slice(),
                [PacketOutcome::Refused {
                    space: Some(PacketSpace::OneRtt),
                    why: QuicOpenError::NoKeysForSpace(PacketSpace::OneRtt),
                }]
            ),
            "and the refusal names the space rather than blaming the length: \
             {outcomes:?}"
        );
    }

    /// R311y698 (§1.2a) — a datagram carrying TWO packets is opened as two.
    ///
    /// A client's first flight is routinely an Initial and a Handshake packet
    /// coalesced into one UDP datagram, and a reader that stopped at the first
    /// would hold half a handshake and report the other half as absent. The
    /// second packet's extent comes from the FIRST one's declared length, so a
    /// reader that computed it wrongly would land mid-packet and refuse.
    #[test]
    fn a_datagram_that_coalesces_two_packets_opens_both() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(9));
        let log = log_for(&random, 1);
        let (client_initial, _) = QuicKeys::initial(QuicVersion::V1, &ICID);

        let hello = client_hello(&random);
        let first_payload = crypto_frame(0, &hello);
        let (h, o) = long_header(LongHeader::INITIAL, &ICID, &[], first_payload.len(), 0);
        let mut datagram = protect(&client_initial, 0, &h, o, &first_payload);

        let handshake_keys = {
            let secrets = log.get(&random).expect("the log holds it");
            let secret = secrets
                .get(SecretLabel::ClientHandshake)
                .expect("a handshake secret");
            QuicKeys::derive(Suite::Aes128GcmSha256, secret)
        };
        let second_payload = crypto_frame(0, b"\x0b\x00\x00\x02ab");
        let (h, o) = long_header(LongHeader::HANDSHAKE, &ICID, &SCID, second_payload.len(), 0);
        datagram.extend_from_slice(&protect(&handshake_keys, 0, &h, o, &second_payload));

        let mut opener = QuicFlowOpener::new(log);
        let outcomes = opener.push_datagram(Direction::A, &datagram);
        assert_eq!(
            outcomes.len(),
            2,
            "two packets in one datagram: {outcomes:?}"
        );
        assert!(matches!(
            outcomes[0],
            PacketOutcome::Opened {
                space: PacketSpace::Initial,
                ..
            }
        ));
        assert!(
            matches!(
                outcomes[1],
                PacketOutcome::Opened {
                    space: PacketSpace::Handshake,
                    ..
                }
            ),
            "the second is the HANDSHAKE space, under different keys: {outcomes:?}"
        );
        // AND THE SPACES ARE SEPARATE SEQUENCES: both CRYPTO frames were at
        // offset 0, and a reader that folded them would have laid one over the
        // other and reported one stream.
        assert_eq!(
            opener
                .sequence(Direction::A, SequenceKey::Crypto(PacketSpace::Initial))
                .map(<[u8]>::len),
            Some(hello.len())
        );
        assert_eq!(
            opener
                .sequence(Direction::A, SequenceKey::Crypto(PacketSpace::Handshake))
                .map(<[u8]>::len),
            Some(6),
            "the handshake space's CRYPTO stream is its own, also starting at zero"
        );
    }

    /// R311y698 (§1.2a) — with no key for a space, the refusal says SO, rather
    /// than saying the key did not work.
    ///
    /// The two send a reader to different places: no key at all is a key log
    /// question, and a key that failed is a capture question. A reader told the
    /// wrong one looks in the wrong place.
    #[test]
    fn a_space_with_no_key_is_refused_differently_from_a_key_that_failed() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5));
        let (client_initial, _) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let hello = client_hello(&random);
        let payload = crypto_frame(0, &hello);
        let (h, o) = long_header(LongHeader::INITIAL, &ICID, &[], payload.len(), 0);
        let initial = protect(&client_initial, 0, &h, o, &payload);

        // AN EMPTY LOG still opens the Initial space, which is the property
        // that makes a keyless capture worth reading at all.
        let mut opener = QuicFlowOpener::new(KeyLog::default());
        assert!(matches!(
            opener.push_datagram(Direction::A, &initial).as_slice(),
            [PacketOutcome::Opened { .. }]
        ));
        assert!(
            !opener.keys_installed(),
            "and an empty log installs nothing"
        );

        let keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let (h, o) = long_header(LongHeader::HANDSHAKE, &ICID, &SCID, 4, 0);
        let packet = protect(&keys, 0, &h, o, b"abcd");
        assert_eq!(
            opener.push_datagram(Direction::A, &packet),
            alloc::vec![PacketOutcome::Refused {
                space: Some(PacketSpace::Handshake),
                why: QuicOpenError::NoKeysForSpace(PacketSpace::Handshake),
            }],
            "no key for the space is its own answer"
        );

        // AND WITH A KEY that is simply the wrong one, the AEAD refuses.
        let mut wrong = QuicFlowOpener::new(log_for(&random, 1));
        wrong.push_datagram(Direction::A, &initial);
        let outcomes = wrong.push_datagram(Direction::A, &packet);
        assert_eq!(
            outcomes,
            alloc::vec![PacketOutcome::Refused {
                space: Some(PacketSpace::Handshake),
                why: QuicOpenError::NotAuthenticated,
            }],
            "a key that does not open it is a different statement: {outcomes:?}"
        );
    }

    /// R311y698 (§1.2a) — a 1-RTT KEY UPDATE is followed, and the header
    /// protection key does NOT move with it.
    ///
    /// RFC 9001 §6 replaces the packet protection key and keeps the header
    /// protection key. A reader that re-derived `quic hp` from the new secret
    /// would fail to unmask the first packet of every generation, and the
    /// failure arrives as a wrong packet number — so it reads as a bad key
    /// rather than a bad rule, which is the kind of mistake that survives.
    #[test]
    fn a_rekeyed_connection_is_followed_into_the_next_generation() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));
        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let mut opener = QuicFlowOpener::new(log_for(&random, 2));

        let hello = client_hello(&random);
        let payload = crypto_frame(0, &hello);
        let (h, o) = long_header(LongHeader::INITIAL, &ICID, &[], payload.len(), 0);
        opener.push_datagram(Direction::A, &protect(&client_initial, 0, &h, o, &payload));
        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(LongHeader::INITIAL, &[], &SCID, reply.len(), 0);
        opener.push_datagram(Direction::B, &protect(&server_initial, 0, &h, o, &reply));

        // Generation 0, then generation 1 with the FIRST generation's header
        // protection key — which is what a conforming sender does.
        let generation0 = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let generation1 = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 1))
            .with_header_protection_of(&generation0);

        let payload = stream_frame(0, 0, b"before ");
        let (h, o) = short_header(&SCID, 0);
        opener.push_datagram(Direction::A, &protect(&generation0, 0, &h, o, &payload));

        let payload = stream_frame(0, 7, b"after");
        let (h, o) = short_header(&SCID, 1);
        let outcomes =
            opener.push_datagram(Direction::A, &protect(&generation1, 1, &h, o, &payload));
        assert!(
            matches!(outcomes.as_slice(), [PacketOutcome::Opened { .. }]),
            "the packet under the new key opens: {outcomes:?}"
        );
        assert_eq!(
            opener.sequence(Direction::A, SequenceKey::Stream(0)),
            Some(&b"before after"[..]),
            "and the stream continues across the rekey"
        );
    }

    /// R311y698 (§1.2a) — the number of sequences one direction tracks is
    /// BOUNDED, and what the bound refused is counted.
    ///
    /// Each reassembler already bounded its own out-of-order hold; nothing
    /// bounded how many reassemblers there were, and a connection opening
    /// streams is an accumulation that grows with the input.
    #[test]
    fn the_sequence_table_is_bounded_and_says_what_it_refused() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let mut opener = QuicFlowOpener::with_limits(
            log_for(&random, 1),
            QuicLimits {
                buffered_bytes_per_sequence: Some(16),
                sequences_per_direction: 2,
            },
        );

        let hello = client_hello(&random);
        let payload = crypto_frame(0, &hello);
        let (h, o) = long_header(LongHeader::INITIAL, &ICID, &[], payload.len(), 0);
        opener.push_datagram(Direction::A, &protect(&client_initial, 0, &h, o, &payload));
        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(LongHeader::INITIAL, &[], &SCID, reply.len(), 0);
        opener.push_datagram(Direction::B, &protect(&server_initial, 0, &h, o, &reply));

        // The Initial CRYPTO stream is already one of the client's two.
        let keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        for (index, id) in [0u8, 4, 8].into_iter().enumerate() {
            let payload = stream_frame(id, 0, b"x");
            let (h, o) = short_header(&SCID, index as u32);
            let packet = protect(&keys, index as u64, &h, o, &payload);
            assert!(matches!(
                opener.push_datagram(Direction::A, &packet).as_slice(),
                [PacketOutcome::Opened { .. }]
            ));
        }
        // ANTI-VACUITY: the packets all OPENED, so the drop below is the table's
        // bound biting and not a decryption failure.
        assert_eq!(opener.census()[0].opened, 4);
        assert_eq!(
            opener.sequences(Direction::A).count(),
            2,
            "the table holds its bound"
        );
        assert_eq!(
            opener.sequences_dropped(),
            [2, 0],
            "and the two sequences it would not open are counted, per direction"
        );
    }

    /// R311y698 (§1.2a) — the QUIC ClientHello reader and the TLS one are
    /// OFFSET BY A RECORD HEADER, and neither is the other.
    ///
    /// QUIC carries TLS handshake messages with no record layer (RFC 9001 §4),
    /// so the same ClientHello begins five bytes earlier. A reader that reused
    /// `wz_capture::tls::client_hello_random` would take 32 bytes straddling the
    /// random and the session id, and the key log lookup would miss — which
    /// looks exactly like a key log for a different connection, and would have
    /// been debugged as one.
    #[test]
    fn the_quic_client_hello_offset_is_the_tls_one_without_a_record_header() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(2));
        let hello = client_hello(&random);
        // The SAME message with a TLS record header in front of it.
        let mut framed = alloc::vec![
            0x16u8,
            0x03,
            0x01,
            (hello.len() >> 8) as u8,
            hello.len() as u8
        ];
        framed.extend_from_slice(&hello);

        assert_eq!(
            client_hello_random(&hello),
            Some(random),
            "the QUIC reader finds it in a bare handshake message"
        );
        assert_eq!(
            wz_capture::tls::client_hello_random(&framed),
            Some(random),
            "and the TLS reader finds the same bytes behind a record header"
        );
        // NEITHER READS THE OTHER'S SHAPE, which is the half that matters: a
        // reader that mixed them up would not fail, it would return the wrong
        // 32 bytes.
        assert_ne!(
            wz_capture::tls::client_hello_random(&hello),
            Some(random),
            "the TLS offset applied to a bare message reads the wrong bytes"
        );
        assert_eq!(
            client_hello_random(&framed),
            None,
            "and the QUIC reader refuses a record, because byte zero is not a \
             handshake type it accepts"
        );
    }

    /// R311y698 (§1.2a) — a Retry packet is refused by its own name.
    ///
    /// R311y695 refused it as a truncation, which is a statement about the
    /// capture: the packet is whole and this reader simply does not read it.
    /// A reader acting on the wrong diagnosis goes looking for a cut file.
    #[test]
    fn a_retry_packet_is_refused_by_name_and_not_as_a_truncation() {
        let mut packet = alloc::vec![0x80 | (LongHeader::RETRY << 4)];
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.push(0);
        packet.push(SCID.len() as u8);
        packet.extend_from_slice(&SCID);
        packet.extend_from_slice(&[0u8; 16]); // token and integrity tag
        assert_eq!(
            LongHeader::parse(&packet).err(),
            Some(QuicOpenError::RetryNotRead)
        );

        let mut opener = QuicFlowOpener::new(KeyLog::default());
        assert_eq!(
            opener.push_datagram(Direction::A, &packet),
            alloc::vec![PacketOutcome::Refused {
                space: None,
                why: QuicOpenError::RetryNotRead,
            }]
        );
    }

    /// R311y698 (§1.2a) — a version this reader has no salt for is NAMED before
    /// its type bits are believed.
    ///
    /// A Version Negotiation packet declares version 0 and its type bits mean
    /// nothing at all. A reader that walked it as whatever those bits said would
    /// read a token length out of a connection ID and report a parse failure
    /// about a packet it simply does not support.
    #[test]
    fn an_unsupported_version_is_named_before_its_type_bits_are_walked() {
        let mut packet = alloc::vec![0xc3u8];
        packet.extend_from_slice(&0u32.to_be_bytes()); // version negotiation
        packet.push(SCID.len() as u8);
        packet.extend_from_slice(&SCID);
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        let mut opener = QuicFlowOpener::new(KeyLog::default());
        assert_eq!(
            opener.push_datagram(Direction::A, &packet),
            alloc::vec![PacketOutcome::Refused {
                space: None,
                why: QuicOpenError::UnsupportedVersion(0),
            }]
        );
        assert_eq!(opener.census()[0].refused, 1);
    }
}
