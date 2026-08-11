// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y661 (§1.2a) — the JOIN. `wz-capture` finds the records and this crate
//! opens them.
//!
//! R311y657..660 built each link of the chain and proved it: a record opens
//! given a secret, a key log parses out of a capture file, a flow reports the
//! `Random` the log is indexed by, the protected records are kept and numbered.
//! R311y660 then drove the whole chain in ONE test — and that test was the only
//! caller. Nothing in the reader called any of it, so a capture carrying its own
//! keys still reported `no_keys_supplied` and zero frames, which is a false
//! statement about a file this workspace can read.
//!
//! [`CaptureOpener`] is the piece that was missing. It implements
//! `wz_capture::tls::RecordOpener`, which is a trait in the OTHER crate: the
//! dependency is inverted so that `wz-capture` keeps its zero third-party
//! dependencies and never learns what an AEAD is, while a caller who has a
//! capture and a key log gets plaintext without writing the loop themselves.

use alloc::vec::Vec;

extern crate alloc;

use wz_capture::tls::{
    Direction, EncryptedRecord, NotDecrypted, OpenedRecord, RecordOpener, MIN_PROTECTED_RECORD,
};

use crate::keylog::{KeyLog, SecretLabel, SecretsBlockError};
use crate::{Suite, TrafficKeys};

/// R311y661 (§1.2a) — opens a capture's encrypted records from the capture's
/// own key log.
///
/// ## Why the suite is discovered rather than configured
///
/// An NSS key log records a secret and the connection it belongs to. It does
/// NOT record the cipher suite — that is in the ServerHello, which this crate
/// deliberately does not parse (R311y649's narrowness is load bearing on the
/// capture side and widening it here would be the same mistake in a new place).
///
/// The secret's LENGTH is a measurement that narrows it: it is the hash's output
/// width, so 48 bytes is SHA384 and pins `TLS_AES_256_GCM_SHA384` uniquely,
/// while 32 bytes is SHA256 and leaves two candidates. The first record of the
/// direction settles which by being opened — an AEAD tag is a 128-bit check, so
/// a suite that opens a record is the suite, and one that does not is refused
/// rather than assumed.
///
/// A secret of any other length names no TLS 1.3 suite and is refused outright,
/// which is the [`Suite::from_code_point`] rule applied to the other end of the
/// same fact.
#[derive(Debug)]
pub struct CaptureOpener {
    log: KeyLog,
    /// The flow currently being opened, per direction.
    directions: [Option<DirectionState>; 2],
    /// R311y671 (§1.2a) — the epoch witness of every flow this opener has
    /// FINISHED, per direction.
    ///
    /// `directions` is replaced at each [`RecordOpener::begin_flow`], so a
    /// capture-wide answer has to survive that reset — the same carry
    /// `wz_capture`'s `evicted_*` totals exist for, and for the same reason: a
    /// figure read off the live state answers about whichever flow happened to be
    /// last.
    retired: [EpochWitness; 2],
    /// R311y672 (§1.2a) — direction `i` owes the peer a `KeyUpdate`.
    ///
    /// The obligation is the whole reason the `request_update` byte is worth
    /// reading: RFC 8446 §4.6.3 says a party receiving `update_requested` MUST
    /// send its own `KeyUpdate` in reply. That is the ONE fact in this protocol
    /// that crosses the two directions, and it therefore cannot live in
    /// [`DirectionState`] — which is why until this round the byte was skipped
    /// and each direction counted only its own messages.
    /// R311y685 (§1.2a) — `update_requested` messages this direction owes a
    /// reply to, as a COUNT.
    ///
    /// It was a bool, so a peer that asked twice before being answered had its
    /// second request silently absorbed: the obligation could not exceed one and
    /// `requests_unanswered` could not exceed one per direction per connection.
    /// A count is what the protocol's own shape allows -- RFC 8446 §4.6.3 puts
    /// the receiver under an obligation per message received, and nothing in it
    /// says a sender may only have one outstanding.
    ///
    /// One reply discharges ONE request, which is a rule this reader states
    /// rather than one the RFC settles: a single `KeyUpdate` arguably satisfies
    /// every request outstanding at the moment it is sent. Stated here, and
    /// chosen because the alternative silently forgives a peer that ignored the
    /// first ask -- and "an expected key change did not arrive" is the fact this
    /// number exists to report.
    owed: [usize; 2],
}

/// R311y662 (§1.2a) — one EPOCH of one direction: the secret in force between
/// two key changes, and the suite once a record has settled it.
#[derive(Debug)]
struct EpochState {
    secret: Vec<u8>,
    /// Suites still consistent with the secret's length; emptied as the first
    /// record settles one.
    candidates: Vec<Suite>,
    /// The keys, once a suite has been settled by opening a record.
    settled: Option<TrafficKeys>,
}

impl EpochState {
    fn new(secret: Vec<u8>) -> Option<Self> {
        // The secret's width is the HASH's output width, which pins the hash and
        // through it the candidate suites.
        let candidates = match secret.len() {
            48 => alloc::vec![Suite::Aes256GcmSha384],
            32 => alloc::vec![Suite::Aes128GcmSha256, Suite::Chacha20Poly1305Sha256],
            // No TLS 1.3 suite derives a traffic secret of any other length.
            _ => return None,
        };
        Some(Self {
            secret,
            candidates,
            settled: None,
        })
    }

    /// Open one record at `seq`, settling the suite on the first success.
    fn open(&mut self, seq: u64, record: &[u8]) -> Option<OpenedRecord> {
        if let Some(keys) = &self.settled {
            let mut buf = record.to_vec();
            let opened = keys.open(seq, &mut buf).ok()?;
            return Some(OpenedRecord {
                content_type: opened.content_type,
                plaintext: opened.plaintext.to_vec(),
            });
        }
        for suite in self.candidates.clone() {
            let keys = TrafficKeys::derive(suite, &self.secret);
            let mut buf = record.to_vec();
            let Ok(opened) = keys.open(seq, &mut buf) else {
                continue;
            };
            let out = OpenedRecord {
                content_type: opened.content_type,
                plaintext: opened.plaintext.to_vec(),
            };
            // Settled by MEASUREMENT: this suite authenticated a real record of
            // this direction. Pinned so every later record costs one attempt.
            self.settled = Some(keys);
            self.candidates.clear();
            return Some(out);
        }
        None
    }
}

/// One direction's epochs, and which one the records are currently in.
///
/// ## Why this is not one secret
///
/// R311y661 opened a direction with its application secret and stopped at the
/// first record that refused. On a fixture whose capture begins after the
/// handshake that is every record; on a REAL capture it is none of them.
///
/// A zenoh `tls/...` session captured from its start carries, in one direction
/// and in this order: the ClientHello in cleartext, then the encrypted handshake
/// flight — EncryptedExtensions, Certificate, CertificateVerify, Finished —
/// under the HANDSHAKE traffic secret, and only then the session under the
/// application one. Every record of both epochs has an outer content type of
/// `application_data` (RFC 8446 §5.2 hides the real type inside), so
/// `wz-capture` keeps and numbers them all, and the application secret opens
/// none of the first group.
///
/// So R311y661's own carry was right that "a capture of a full handshake
/// decrypts its application records only if the reader knows how many handshake
/// records preceded them" — and that is the ordinary shape, not a corner. The
/// number cannot be read off the wire: the `Finished` that ends the handshake
/// epoch is itself encrypted, so a reader without keys cannot see the boundary.
///
/// ## The trial
///
/// It is found by TRYING. The AEAD tag is a 128-bit authenticator, so a record
/// that opens under a key opened under the right one; a record that refuses the
/// current epoch and opens under the NEXT one at sequence zero is the first
/// record of that next epoch. That index becomes the base, and every later
/// sequence is counted from it — which is exactly what TLS does, since the
/// sequence restarts at zero on every key change.
#[derive(Debug)]
struct DirectionState {
    /// Epochs in the order TLS enters them: handshake, then application.
    epochs: Vec<EpochState>,
    /// Which epoch the records are currently in.
    at: usize,
    /// The record index at which the current epoch's sequence numbering starts.
    base: u64,
    /// R311y666 (§1.2a) — records the capture LOST, discovered so far, which is
    /// how far this reader's numbering lags the sender's sequence.
    ///
    /// A hole swallows records whole and they are never walked, so
    /// `index - base` undercounts the sequence by exactly the number lost. The
    /// figure is not read off the wire — the lost records' boundaries went with
    /// them — it is found by trying, once, at the first record after each hole.
    skew: u64,
    /// R311y671 (§1.2a) — what this direction OBSERVED about its own epoch
    /// changes, as opposed to what the trial INFERRED.
    witness: EpochWitness,
    /// A post-handshake `KeyUpdate` has been read on this direction and the epoch
    /// it announces has not been entered yet.
    ///
    /// The whole reason this field exists: the epoch boundary is found by
    /// FAILURE — the current epoch refuses a record and the next one accepts it —
    /// and the message that CAUSED the change is a record this reader now opens
    /// and reads right past. A boundary that can be confirmed and is not is a
    /// boundary asserted on a probability.
    pending_key_update: bool,
    /// R311y672 (§1.2a) — the index of the first APPLICATION epoch, which is the
    /// line between boundaries TLS announces and boundaries it does not.
    ///
    /// Every boundary at or below this index is one the protocol crosses in
    /// silence: 0-RTT to handshake, and handshake to the first application
    /// generation, are both ended by a `Finished` that is itself encrypted under
    /// the OLD key, so no `KeyUpdate` exists to confirm them and none ever will.
    /// Every boundary ABOVE it is a rekey, and RFC 8446 §4.6.3 says a rekey is
    /// announced — so an unconfirmed one there is a different fact entirely.
    ///
    /// Derived from what SURVIVED [`EpochState::new`] rather than from the label
    /// list, because a secret of an unusable width is dropped and would otherwise
    /// shift every index below it.
    first_application_epoch: usize,
    /// R311y685 (§1.2a) — has this direction opened a record yet?
    ///
    /// Asked one question -- was this the FIRST -- which is what separates the
    /// epoch climb of a capture that began mid-session from a rekey inside one
    /// this reader was already watching.
    ///
    /// R311y691 made it a BOOL, reversing that round's own reasoning. It kept a
    /// count on the grounds that "how many records of this direction opened" is
    /// a fact the witness may want next; nothing wanted it, and a degree of
    /// freedom kept for a speculative future consumer is the exact shape this
    /// track has spent eight rounds removing from elsewhere in the crate. The
    /// count is one `+= 1` away if a consumer ever appears.
    opened_a_record: bool,
    /// R311y692 (§1.2a) — has this direction let go of handshake bytes since its
    /// last key change?
    ///
    /// One question, one bool -- the R311y691 rule, applied where it was learnt.
    /// TAKEN at the advance rather than read, because dropped bytes can explain
    /// the next boundary and not every boundary after it.
    abandoned_since_advance: bool,
    /// R311y686 (§1.2a) — handshake bytes held for a message whose rest is in a
    /// record that has not arrived.
    ///
    /// Per DIRECTION, because a handshake stream is: the two sides' messages
    /// are independent and a fragment of one never completes the other. Bounded
    /// by [`MAX_HANDSHAKE_CARRY`], with what the bound let go of counted on the
    /// witness.
    handshake_carry: alloc::vec::Vec<u8>,
}

/// R311y671 (§1.2a) — one direction's epoch changes, observed against inferred.
///
/// # Why the two numbers must be separate
///
/// R311y662 finds an epoch boundary by trial: the current epoch refuses a record,
/// the next accepts it at sequence zero, and the reader advances. That is sound
/// -- a 128-bit AEAD tag is what decides -- but it is EVIDENCE OF ARRIVAL, not
/// evidence of cause. R311y667 then applied the resync window in every epoch, and
/// R311y668's register recorded the residue honestly: the ORDER in which the
/// window and the epoch advance are tried is a declaration, not a proof, and a
/// record that authenticates under the wrong one authenticates all the same.
///
/// A post-handshake `KeyUpdate` (RFC 8446 §4.6.3) is the independent witness. The
/// party sending it switches its OWN sending key for the record after it, so the
/// message and the epoch change are in the same direction, in that order. An
/// advance with a `KeyUpdate` behind it is confirmed by the sender's own
/// announcement; an advance without one is the trial's word alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpochWitness {
    /// Post-handshake `KeyUpdate` messages read on this direction.
    pub key_updates: usize,
    /// R311y672 — of those, the ones carrying `update_requested`.
    ///
    /// RFC 8446 §4.6.3 gives `KeyUpdate` a one-byte body, and that byte is an
    /// instruction to the PEER: `update_requested` (1) obliges the other side to
    /// send its own `KeyUpdate` in reply, `update_not_requested` (0) does not.
    /// Until this round the byte was not read at all, so a message demanding a
    /// reply and a message merely announcing were the same number.
    pub updates_requested: usize,
    /// R311y672 — `KeyUpdate`s on this direction that discharged an outstanding
    /// `update_requested` from the peer.
    ///
    /// The only cross-direction fact this protocol offers. An advance on THIS
    /// direction backed by such a message is confirmed twice over: by its own
    /// announcement, and by the peer's demand that it happen.
    pub updates_answering: usize,
    /// R311y672 — `update_requested` messages sent on the OTHER direction that
    /// this one never answered, at the point the flow ended.
    ///
    /// A peer that ignores the obligation, or -- far likelier -- a capture that
    /// ended before the reply. Either way it is the reason an expected advance on
    /// this direction is absent, and nothing else in the report says so.
    pub requests_unanswered: usize,
    /// Epoch advances the trial made.
    ///
    /// Always the sum of [`Self::advances_confirmed`],
    /// [`Self::advances_unannounced`] and [`Self::advances_unwitnessed`]: every
    /// advance is classified into exactly one of the three.
    pub epoch_advances: usize,
    /// Advances that had an unconsumed `KeyUpdate` behind them.
    ///
    /// Never greater than [`Self::epoch_advances`]. Equal to it is the ordinary
    /// shape of a rekeying session captured whole; less than it means at least
    /// one boundary rests on the trial alone -- which is not a defect (the first
    /// application epoch follows the handshake with no `KeyUpdate` at all, and a
    /// capture that begins mid-session missed the announcement) but IS a fact a
    /// reader weighing the decryption should have.
    pub advances_confirmed: usize,
    /// R311y672 — unconfirmed advances across a boundary TLS NEVER announces.
    ///
    /// 0-RTT to handshake, and handshake to the first application generation.
    /// Both are ended by an encrypted `Finished` rather than by a `KeyUpdate`, so
    /// no announcement exists to find. Expected, harmless, and the ordinary shape
    /// of any capture taken from the start of a connection.
    pub advances_unannounced: usize,
    /// R311y672 — unconfirmed advances across a boundary TLS DOES announce.
    ///
    /// A rekey with no `KeyUpdate` behind it. Every one of these is either a
    /// capture that began mid-session (the announcement went past before the tap
    /// started), a capture with a hole over the announcing record, or a boundary
    /// the trial reached on a 128-bit coincidence. **This is the number worth
    /// looking at**, and until this round it was summed with the harmless kind
    /// above into a single "unconfirmed" figure that could not tell them apart.
    pub advances_unwitnessed: usize,
    /// R311y685 (§1.2a) — of [`Self::advances_unwitnessed`], the ones this
    /// direction reached BEFORE it had opened a single record.
    ///
    /// The capture began mid-session: the trial had to climb to the epoch the
    /// traffic was already in, and every announcement below it went past before
    /// the tap started. Nothing was missed by this reader that was ever there to
    /// see.
    pub advances_before_first_record: usize,
    /// R311y685 (§1.2a) — of [`Self::advances_unwitnessed`], the ones committed
    /// on a record with a HOLE in front of it.
    ///
    /// The announcing `KeyUpdate` is one of the records the capture lost. Also
    /// nothing this reader could have done -- but a different remedy from the
    /// one above, because it says the capture is incomplete rather than late.
    pub advances_after_hole: usize,
    /// R311y685 (§1.2a) — of [`Self::advances_unwitnessed`], the residue.
    ///
    /// A rekey inside a capture this reader was already watching, with no hole
    /// in front of the record that crossed it. Either the announcement was in a
    /// record this reader could not read as one -- a `KeyUpdate` split across
    /// two records is the known case, and is not reassembled -- or the trial
    /// crossed on a 128-bit coincidence.
    ///
    /// **This is the only one of the three that says something about this
    /// reader**, which is why the three are not one number: the first two are
    /// facts about the capture and were being summed with it.
    pub advances_unexplained: usize,
    /// R311y692 (§1.2a) — of [`Self::advances_unwitnessed`], the ones on a
    /// direction that had LET GO OF handshake bytes since its last advance.
    ///
    /// [`Self::advances_unexplained`] summed two things R311y686's own carry
    /// named: a 128-bit coincidence, and an announcement this reader could not
    /// read. The second has a signal now that the carry exists -- a tail dropped
    /// past its bound, or one abandoned when a record of another content type
    /// interrupted it, is precisely an announcement whose bytes this reader
    /// stopped being able to assemble.
    ///
    /// Not proof that THIS advance's announcement was in those bytes. It is the
    /// difference between "no explanation" and "an explanation this reader
    /// already reported, on this direction, since the last time the keys moved".
    pub advances_after_abandoned_handshake: usize,
    /// R311y686 (§1.2a) — of [`Self::key_updates`], the ones whose bytes began
    /// in an EARLIER record.
    ///
    /// TLS may split a handshake message across records, and until this round
    /// the scan gave up at the first message it could not complete: a
    /// `KeyUpdate` behind a `NewSessionTicket` big enough to fill a record was
    /// invisible, and the boundary it announced was counted as unwitnessed. The
    /// figure exists because "this reader found it" and "this reader had to
    /// reassemble it to find it" are different claims about the same message.
    pub key_updates_reassembled: usize,
    /// R311y686 (§1.2a) — handshake bytes this reader held for a message that
    /// never completed, and then let go of.
    ///
    /// Two causes, both counted here rather than being silent: a tail past the
    /// carry's bound, and a record of another content type arriving while a
    /// handshake message was still open (RFC 8446 §5.1 forbids that
    /// interleaving, so it means a record was lost). A carry that is dropped
    /// without saying so is an announcement this reader silently stopped
    /// looking for.
    pub handshake_bytes_abandoned: usize,
}

impl EpochWitness {
    /// Fold another direction-witness in — how a finished flow's numbers survive
    /// the point its state is replaced.
    fn plus(self, other: Self) -> Self {
        Self {
            key_updates: self.key_updates + other.key_updates,
            updates_requested: self.updates_requested + other.updates_requested,
            updates_answering: self.updates_answering + other.updates_answering,
            requests_unanswered: self.requests_unanswered + other.requests_unanswered,
            epoch_advances: self.epoch_advances + other.epoch_advances,
            advances_confirmed: self.advances_confirmed + other.advances_confirmed,
            advances_unannounced: self.advances_unannounced + other.advances_unannounced,
            advances_unwitnessed: self.advances_unwitnessed + other.advances_unwitnessed,
            advances_before_first_record: self.advances_before_first_record
                + other.advances_before_first_record,
            advances_after_hole: self.advances_after_hole + other.advances_after_hole,
            advances_unexplained: self.advances_unexplained + other.advances_unexplained,
            advances_after_abandoned_handshake: self.advances_after_abandoned_handshake
                + other.advances_after_abandoned_handshake,
            key_updates_reassembled: self.key_updates_reassembled + other.key_updates_reassembled,
            handshake_bytes_abandoned: self.handshake_bytes_abandoned
                + other.handshake_bytes_abandoned,
        }
    }
}

/// The handshake message type of a post-handshake `KeyUpdate` (RFC 8446 §4.6.3).
const HS_KEY_UPDATE: u8 = 24;

/// The `KeyUpdateRequest` value obliging the peer to rekey (RFC 8446 §4.6.3).
const KEY_UPDATE_REQUESTED: u8 = 1;

/// A `KeyUpdate` body is exactly one byte wide (RFC 8446 §4.6.3).
const KEY_UPDATE_BODY_LEN: usize = 1;

/// The fixed header of a TLS handshake message: one type byte, then a `uint24`
/// body length (RFC 8446 §4).
const HS_HEADER_LEN: usize = 4;

/// R311y672 (§1.2a) — the `KeyUpdate` messages in one decrypted `handshake`
/// record.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct KeyUpdateScan {
    /// Well-formed `KeyUpdate` messages found.
    seen: usize,
    /// Of those, ones carrying `update_requested`.
    requested: usize,
    /// R311y686 — of those, ones whose bytes began in an earlier record.
    reassembled: usize,
    /// R311y686 — handshake bytes let go of without completing a message.
    abandoned: usize,
}

/// Walk the handshake messages of one decrypted record and report its
/// `KeyUpdate`s.
///
/// # Why this is a walk and not a look at the first byte
///
/// R311y671 tested `plaintext.first() == Some(&HS_KEY_UPDATE)`, which is two
/// claims at once and both are wrong at the edges. A handshake record may carry
/// SEVERAL messages back to back, and post-handshake the common pair is a
/// `NewSessionTicket` followed by something else — so a `KeyUpdate` that is not
/// first was invisible. In the other direction, any record whose first plaintext
/// byte happened to be 24 was counted as a `KeyUpdate` without the length ever
/// being checked, so a malformed or truncated message confirmed an epoch
/// boundary it never announced.
///
/// The walk answers both by reading the framing the RFC actually specifies, and
/// stops at the first message whose declared body runs past the record. That tail
/// is not a defect to report: a handshake message may be FRAGMENTED across
/// records, and this crate does not reassemble them — a limit worth naming
/// (a `KeyUpdate` is 5 bytes and is never split in practice, but a large
/// `NewSessionTicket` in front of one may be).
/// R311y686 (§1.2a) — the widest handshake tail this reader will hold waiting
/// for the rest of its message.
///
/// A TLS record's plaintext is at most 2^14 bytes and a handshake message may
/// declare 2^24-1, so a message CAN legally need more than this. The bound is
/// this crate's standing rule rather than the protocol's ceiling: an
/// accumulation that grows with the input needs a bound, and a bound that bites
/// needs a counter — which [`EpochWitness::handshake_bytes_abandoned`] is. A
/// `NewSessionTicket` or a `KeyUpdate`, which are what this scan is walking
/// past and looking for, are orders of magnitude under it.
const MAX_HANDSHAKE_CARRY: usize = 16 * 1024;

/// R311y686 (§1.2a) — walk the handshake stream of ONE DIRECTION, across the
/// records it is split over.
///
/// # What was lost, and how much
///
/// R311y672 made this scan read the RFC's framing rather than the first byte,
/// which found a `KeyUpdate` hiding behind a `NewSessionTicket` in the same
/// record. Its own note recorded what it still could not do -- "fragmented or
/// truncated: the rest of this message is in another record this walk does not
/// have" -- and `break` there discards not only that message but EVERY message
/// after it in the stream. A ticket large enough to fill a record therefore hid
/// the `KeyUpdate` behind it completely, and the boundary it announced was
/// counted as an unwitnessed rekey: this reader blaming a coincidence for a
/// message it had in its hand, one record later.
///
/// # Why a carry and not a bigger look
///
/// The bytes of the second half simply are not in this record. The only reader
/// that can see the whole message is one that holds the tail until the next
/// record of the same direction arrives, which is what this does — and holds it
/// under a bound, with the count of what the bound let go of.
fn scan_key_updates(carry: &mut alloc::vec::Vec<u8>, plaintext: &[u8]) -> KeyUpdateScan {
    let mut scan = KeyUpdateScan::default();
    // How much of the buffer below came from EARLIER records. A message
    // beginning under this line is one that needed the carry to be found.
    let carried = carry.len();
    carry.extend_from_slice(plaintext);
    let mut at = 0usize;
    while at + HS_HEADER_LEN <= carry.len() {
        let msg_type = carry[at];
        let len = u32::from_be_bytes([0, carry[at + 1], carry[at + 2], carry[at + 3]]) as usize;
        let body = at + HS_HEADER_LEN;
        let Some(end) = body.checked_add(len) else {
            break;
        };
        if end > carry.len() {
            // The rest of this message is in a record that has not arrived.
            // Everything from here is held rather than discarded, which is the
            // whole of this round.
            break;
        }
        if msg_type == HS_KEY_UPDATE && len == KEY_UPDATE_BODY_LEN {
            scan.seen += 1;
            if carry[body] == KEY_UPDATE_REQUESTED {
                scan.requested += 1;
            }
            if at < carried {
                scan.reassembled += 1;
            }
        }
        at = end;
    }
    // Consumed messages go; the incomplete tail stays.
    carry.drain(..at);
    if carry.len() > MAX_HANDSHAKE_CARRY {
        scan.abandoned = carry.len();
        carry.clear();
    }
    scan
}

/// R311y666 (§1.2a) — the most sequence offsets tried at one record after a
/// hole.
///
/// The window is normally bounded by the hole's own size (see
/// [`wz_capture::tls::EncryptedRecord::lost_before`]); this is the second bound,
/// on the loss itself. A capture that dropped a megabyte would otherwise ask for
/// tens of thousands of AEAD attempts on one record, and a reader that cannot
/// resynchronise within this many is a reader whose remaining plaintext is not
/// worth an unbounded search.
const MAX_RESYNC_ATTEMPTS: u64 = 4096;

impl DirectionState {
    /// Build from the secrets a key log carried for this direction, in epoch
    /// order. `None` when none of them names a TLS 1.3 hash width.
    ///
    /// R311y672 — each secret arrives PAIRED with whether it is an application
    /// generation, because [`Self::first_application_epoch`] cannot be recovered
    /// afterwards: a secret of an unusable width is dropped here, and counting
    /// labels instead of survivors would put the line one index off in exactly
    /// the case the drop happened.
    fn new(secrets: &[(&[u8], bool)]) -> Option<Self> {
        let mut epochs: Vec<EpochState> = Vec::new();
        let mut first_application = None;
        for (secret, is_application) in secrets {
            let Some(epoch) = EpochState::new(secret.to_vec()) else {
                continue;
            };
            if *is_application && first_application.is_none() {
                first_application = Some(epochs.len());
            }
            epochs.push(epoch);
        }
        if epochs.is_empty() {
            return None;
        }
        Some(Self {
            // No application epoch survived: every boundary this direction can
            // reach is one the protocol crosses in silence, which `len()` states
            // by putting the line past the last index.
            first_application_epoch: first_application.unwrap_or(epochs.len()),
            epochs,
            at: 0,
            base: 0,
            skew: 0,
            witness: EpochWitness::default(),
            pending_key_update: false,
            opened_a_record: false,
            abandoned_since_advance: false,
            handshake_carry: alloc::vec::Vec::new(),
        })
    }

    /// R311y672 — classify and count one advance's worth of epoch steps.
    ///
    /// A single record can carry the reader across MORE than one boundary: a hole
    /// that spans a rekey leaves the trial to walk two epochs before one
    /// authenticates. Each step is therefore classified on its own, and the
    /// pending announcement — of which there is at most one — confirms the FIRST,
    /// because that is the step the sender announced when it wrote the message.
    /// ## R311y685 — and an unwitnessed advance says WHICH of its three causes
    ///
    /// R311y672 named this bucket and its own doc listed three causes it sums:
    /// a capture that began mid-session, a hole over the announcing record, and
    /// a 128-bit coincidence. Two of the three are facts about the CAPTURE and
    /// the third is a fact about this READER, so a figure summing them answers
    /// neither -- the same objection that split `unannounced` off in the first
    /// place, one bucket further in.
    ///
    /// Both are attributed from state this direction already holds: an advance
    /// reached before any record opened is the mid-session climb, and one
    /// committed on a record with a hole in front of it is an announcement that
    /// went into the hole. What is left is the residue.
    fn count_advance(&mut self, to: usize, after_hole: bool) {
        let mut pending = core::mem::take(&mut self.pending_key_update);
        let before_first = !self.opened_a_record;
        // R311y692 — taken, not read: an abandoned tail explains at most the
        // NEXT key change, and leaving it set would attribute every later one
        // to the same dropped bytes.
        let after_abandon = core::mem::take(&mut self.abandoned_since_advance);
        for target in (self.at + 1)..=to {
            self.witness.epoch_advances += 1;
            if pending {
                self.witness.advances_confirmed += 1;
                pending = false;
            } else if target <= self.first_application_epoch {
                self.witness.advances_unannounced += 1;
            } else {
                self.witness.advances_unwitnessed += 1;
                // Attributed in the order the causes EXCLUDE each other: a
                // direction that has opened nothing cannot have had a hole in
                // front of a record it never read.
                if before_first {
                    self.witness.advances_before_first_record += 1;
                } else if after_hole {
                    self.witness.advances_after_hole += 1;
                } else if after_abandon {
                    self.witness.advances_after_abandoned_handshake += 1;
                } else {
                    self.witness.advances_unexplained += 1;
                }
            }
        }
    }

    /// Open one record, resynchronising after a hole and advancing the epoch
    /// when the current one refuses and the next one accepts at sequence zero.
    ///
    /// ## The two ways a sequence can be wrong, and why they are answered in
    /// this order
    ///
    /// A hole makes the number too SMALL by however many records it swallowed;
    /// a key change makes it too LARGE, because the sender restarted at zero.
    /// The hole is answered first and only where the capture says there was one,
    /// so a record that simply refuses is never mistaken for a resynchronisation
    /// problem — and the search is bounded by the hole's own byte count, which
    /// is a measurement rather than a window someone picked.
    ///
    /// ## R311y667 — the two can happen AT THE SAME RECORD
    ///
    /// A key change and a hole are independent events, so a capture can lose
    /// segments across the moment the keys rotate. The record that then arrives
    /// is the first this reader SEES of the new epoch and is not that epoch's
    /// sequence zero — records of it went into the hole. R311y666 searched the
    /// window in the CURRENT epoch only and tried the next one at zero exactly,
    /// so this record opened under neither and the direction stopped.
    ///
    /// Every epoch therefore gets the same window, and the window is the same
    /// measurement in each: the hole's byte count bounds how many records fitted
    /// in it whichever key was protecting them.
    ///
    /// ## And the state is not moved by a failure
    ///
    /// R311y666 advanced `at` and `base` while SEARCHING, so a record that
    /// opened under nothing left this direction describing an epoch it never
    /// entered. Harmless while the caller stops at the first refusal, and
    /// exactly the kind of state that is wrong the moment something reads it.
    /// The walk now happens on a copy and is committed only where a record
    /// actually opened.
    fn open(
        &mut self,
        record: &EncryptedRecord,
        owed: bool,
    ) -> Option<(OpenedRecord, KeyUpdateScan)> {
        // At most this many records fitted in the hole, whichever epoch they
        // belonged to. Zero where there was no hole, which makes the loop below
        // one attempt per epoch -- the R311y662 behaviour exactly.
        let window = (record.lost_before / MIN_PROTECTED_RECORD).min(MAX_RESYNC_ATTEMPTS);
        let (mut at, mut base, mut skew) = (self.at, self.base, self.skew);
        loop {
            let from = (record.index - base) + skew;
            for k in 0..=window {
                if let Some(opened) = self.epochs[at].open(from + k, &record.bytes) {
                    // Found, and by AUTHENTICATION rather than by inference: the
                    // tag is a 128-bit check, so the offset that opens the record
                    // is the offset. COMMITTED here and only here -- `k` holds
                    // for every later record of this epoch, which is why it is
                    // accumulated rather than applied once.
                    // R311y671 — an advance is CONFIRMED where the sender's own
                    // `KeyUpdate` preceded it. Counted here, at the commit, so a
                    // walk that authenticated under nothing leaves no witness
                    // behind either (the R311y667 rule this loop already keeps).
                    if at > self.at {
                        self.count_advance(at, record.lost_before > 0);
                    }
                    self.at = at;
                    self.base = base;
                    self.skew = skew + k;
                    // A post-handshake KeyUpdate announces that the SENDER's next
                    // record uses the next key. Read here rather than by the
                    // caller because the caller is handed only
                    // `CT_APPLICATION_DATA` onward -- a KeyUpdate's inner type is
                    // `handshake`, so nothing downstream ever sees one.
                    let scan = if opened.content_type == wz_capture::tls::CT_HANDSHAKE {
                        scan_key_updates(&mut self.handshake_carry, &opened.plaintext)
                    } else {
                        // R311y686 — RFC 8446 §5.1 forbids interleaving a
                        // handshake message's fragments with another content
                        // type, so a record of another type arriving while one
                        // is still open means a record went missing. The tail is
                        // let go of and SAID, rather than being held against a
                        // continuation that is never coming.
                        let mut scan = KeyUpdateScan::default();
                        if !self.handshake_carry.is_empty() {
                            scan.abandoned = self.handshake_carry.len();
                            self.handshake_carry.clear();
                        }
                        scan
                    };
                    // R311y685 — counted at the COMMIT, like everything else on
                    // this path: a walk that authenticated under nothing leaves
                    // no state behind, which is the R311y667 rule this loop
                    // already keeps.
                    self.opened_a_record = true;
                    // R311y686 — counted whether or not a message completed:
                    // the bytes this reader let go of are a fact about what it
                    // could no longer be looking for.
                    self.witness.handshake_bytes_abandoned += scan.abandoned;
                    if scan.abandoned > 0 {
                        self.abandoned_since_advance = true;
                    }
                    if scan.seen > 0 {
                        self.witness.key_updates += scan.seen;
                        self.witness.updates_requested += scan.requested;
                        self.witness.key_updates_reassembled += scan.reassembled;
                        // R311y672 — the peer asked for this one. At most one
                        // reply discharges at most one request, so this counts a
                        // record, not a message.
                        if owed {
                            self.witness.updates_answering += 1;
                        }
                        self.pending_key_update = true;
                    }
                    return Some((opened, scan));
                }
            }
            // This epoch refused every offset. If there is a later one, the
            // record is a candidate for being its first SEEN record -- at
            // sequence zero if nothing was lost, and within the window if
            // something was.
            if at + 1 >= self.epochs.len() {
                // Nothing opened it, so nothing about this direction changes.
                return None;
            }
            at += 1;
            base = record.index;
            // A new epoch numbers from zero and has lost nothing YET.
            skew = 0;
        }
    }
}

impl CaptureOpener {
    /// Build one from a key log.
    pub fn new(log: KeyLog) -> Self {
        Self {
            log,
            directions: [None, None],
            retired: [EpochWitness::default(); 2],
            owed: [0, 0],
        }
    }

    /// R311y671 (§1.2a) — what the two directions of the flow most recently
    /// opened OBSERVED about their epoch changes, `[A, B]`.
    ///
    /// See [`EpochWitness`]: the epoch boundary is found by trial, and a
    /// post-handshake `KeyUpdate` is the sender's own announcement of the same
    /// event. Until this existed the reader OPENED those messages and read past
    /// them -- a boundary that could be confirmed and was not.
    pub fn epoch_witness(&self) -> [EpochWitness; 2] {
        core::array::from_fn(|i| {
            let live = self.directions[i]
                .as_ref()
                .map(|d| d.witness)
                .unwrap_or_default();
            let mut out = self.retired[i].plus(live);
            // R311y692 — a handshake TAIL still outstanding when the report is
            // read is one that never completed, and it is composed here for
            // exactly the reason the obligation below is: it is only ever true
            // of the PRESENT, since the next record of this direction may
            // finish the message.
            //
            // Both halves are needed and they cannot double count: a flow the
            // opener has moved past had its state REPLACED, so its tail is
            // counted into `retired` at that moment and is no longer in any live
            // buffer. Measured -- with only the retirement half, a capture whose
            // LAST flow held a tail reported zero, because nothing ever retires
            // the flow that is still current.
            out.handshake_bytes_abandoned += self.directions[i]
                .as_ref()
                .map(|d| d.handshake_carry.len())
                .unwrap_or(0);
            // R311y672 — an obligation still standing at the moment the report is
            // read is one that was never discharged. Composed here rather than
            // stored, because "unanswered" is only ever true of the PRESENT: the
            // very next record of this direction may answer it.
            out.requests_unanswered += self.owed[i];
            out
        })
    }

    /// R311y661 — build one from a capture file's own Decryption Secrets
    /// Blocks, as [`wz_capture::Dissection::decryption_secrets`] hands them out.
    ///
    /// Blocks of another registered secrets type are SKIPPED and counted, not
    /// parsed: a WireGuard key set read as an NSS key log reports every line as
    /// unparsed, which reads as "this key log is corrupt" about something that
    /// was never one. That distinction is
    /// [`KeyLog::from_secrets_block`]'s whole reason for existing and is
    /// preserved here rather than flattened.
    ///
    /// Returns the opener and the number of blocks skipped, so a caller that
    /// finds no keys can tell "the file carried none" from "the file carried
    /// someone else's".
    pub fn from_secrets_blocks(blocks: &[wz_capture::pcapng::DecryptionSecrets]) -> (Self, usize) {
        let mut log = KeyLog::default();
        let mut skipped = 0usize;
        for block in blocks {
            match KeyLog::from_secrets_block(block.secrets_type, &block.secrets) {
                Ok(parsed) => log.absorb(parsed),
                Err(SecretsBlockError::UnknownSecretsType(_)) => skipped += 1,
            }
        }
        (Self::new(log), skipped)
    }

    /// The key log this opener draws on.
    pub fn log(&self) -> &KeyLog {
        &self.log
    }

    /// R311y664 (§1.2a) — fold another key log in, for the ordinary case where
    /// the keys arrive in a SEPARATE file from the capture.
    ///
    /// A capture written by one tool and an `SSLKEYLOGFILE` written by the
    /// process under test is the usual pair; keys embedded in the capture's own
    /// Decryption Secrets Blocks are the rarer arrangement. Merged rather than
    /// preferred either way, because either source may hold connections the
    /// other does not.
    pub fn absorb(&mut self, log: KeyLog) {
        self.log.absorb(log);
    }
}

impl RecordOpener for CaptureOpener {
    fn begin_flow(
        &mut self,
        client_random: Option<&[u8; 32]>,
        client_direction: Option<Direction>,
    ) -> Result<(), NotDecrypted> {
        // R311y692 — the outgoing flow's WITNESS and any handshake tail it is
        // still holding are carried off BEFORE this, and this line is why the
        // carry has to happen there: it drops both directions, so anything read
        // out of them afterwards is gone. Measured -- the first version of this
        // round put the tail's accounting in the retire loop below and got zero
        // on a two-connection capture, because the loop runs after this line and
        // sees `None`.
        //
        // Kept HERE rather than moved down: a flow whose identity is missing
        // must not keep the previous flow's state, and that is exactly what
        // this line prevents on the early return below.
        for i in 0..2usize {
            if let Some(d) = &self.directions[i] {
                self.retired[i] = self.retired[i].plus(d.witness);
                self.retired[i].handshake_bytes_abandoned += d.handshake_carry.len();
            }
            if self.owed[i] > 0 {
                self.retired[i].requests_unanswered += self.owed[i];
            }
        }
        self.directions = [None, None];
        self.owed = [0, 0];
        // Both halves of the identity are required and the reason is the same
        // for each: without the random there is nothing to select an entry BY,
        // and without the direction there is nothing to say which of the two
        // application secrets protects which side. Guessing the second is a coin
        // flip whose failure is an authentication error indistinguishable from a
        // wrong key log.
        let (Some(random), Some(client_direction)) = (client_random, client_direction) else {
            return Err(NotDecrypted::NoSessionIdentity);
        };
        let secrets = self.log.get(random).ok_or(NotDecrypted::NoKeyForSession)?;
        // R311y662 — the EPOCHS of each direction, in the order TLS enters them.
        // The handshake secret is not optional decoration: on a capture taken
        // from the start of the connection the first kept records are the
        // encrypted handshake flight, and a direction holding only the
        // application secret opens none of them and stops at index 0.
        // R311y663 — and every APPLICATION generation after it, in generation
        // order. A long-lived session rekeys, and each rekey is another epoch
        // whose sequence restarts at zero; the trial walks them in exactly the
        // order TLS enters them.
        // R311y666 — and the 0-RTT epoch in FRONT of the handshake one, for the
        // client only. A resuming client sends application data under the early
        // secret BEFORE the handshake epoch begins, so it is the first epoch its
        // direction enters; a server never sends 0-RTT data and has no early
        // secret at all.
        // R311y672 — each secret is TAGGED with whether it is an application
        // generation. That flag is what separates the boundaries TLS announces
        // from the ones it crosses in silence, and it is knowable only here,
        // where the labels are still in hand.
        let epochs_of = |early: Option<SecretLabel>, handshake: SecretLabel, server: bool| {
            let mut out: Vec<(&[u8], bool)> = early
                .and_then(|l| secrets.get(l))
                .into_iter()
                .chain(secrets.get(handshake))
                .map(|s| (s, false))
                .collect();
            out.extend(
                secrets
                    .application_secrets(server)
                    .into_iter()
                    .map(|(_, s)| (s, true)),
            );
            out
        };
        let client = epochs_of(
            Some(SecretLabel::ClientEarly),
            SecretLabel::ClientHandshake,
            false,
        );
        let server = epochs_of(None, SecretLabel::ServerHandshake, true);
        if client.is_empty() && server.is_empty() {
            // The entry exists and carries nothing this crate can act on.
            return Err(NotDecrypted::NoKeyForSession);
        }
        let client_index = match client_direction {
            Direction::A => 0,
            Direction::B => 1,
        };
        // R311y671 — the outgoing flow's witness is carried BEFORE its state is
        // dropped. Retiring it afterwards is not possible: the numbers live in
        // the value being replaced.
        self.directions[client_index] = DirectionState::new(&client);
        self.directions[1 - client_index] = DirectionState::new(&server);
        Ok(())
    }

    fn open(&mut self, direction: Direction, record: &EncryptedRecord) -> Option<OpenedRecord> {
        let at = match direction {
            Direction::A => 0,
            Direction::B => 1,
        };
        // Read BEFORE the direction is borrowed: the obligation lives on the
        // opener precisely because it is the one fact neither direction owns.
        let owed = self.owed[at] > 0;
        let (opened, scan) = self.directions[at].as_mut()?.open(record, owed)?;
        if scan.seen > 0 {
            // This direction has now sent a `KeyUpdate`, which discharges ONE
            // of whatever it owed. R311y685: it used to discharge all of them,
            // because there could only ever be one.
            self.owed[at] = self.owed[at].saturating_sub(1);
            // And RFC 8446 §4.6.3 puts the PEER under one per message that
            // asked -- `requested` counts messages in this record, so two asks
            // in one record are two obligations and not one.
            self.owed[1 - at] += scan.requested;
        }
        Some(opened)
    }

    /// R311y668 — a direction is armed exactly when [`begin_flow`] found at least
    /// one epoch secret for it, which is what the `Option` here already records:
    /// `DirectionState::new` answers `None` for an empty epoch list.
    ///
    /// So this reads the state rather than re-deriving it from the log. Asking
    /// the log again would be a second answer to one question, and the two would
    /// disagree the moment `begin_flow` changed which labels it accepts — which it
    /// has, twice (R311y662 handshake epochs, R311y666 the 0-RTT one).
    ///
    /// [`begin_flow`]: RecordOpener::begin_flow
    fn has_keys(&self, direction: Direction) -> bool {
        let at = match direction {
            Direction::A => 0,
            Direction::B => 1,
        };
        self.directions[at].is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write as _;
        let mut s = alloc::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// A 32-byte secret leaves two suites open and the record settles which.
    ///
    /// The measurement this rests on: a traffic secret is as wide as its hash's
    /// output, so its length pins the hash and not the AEAD. Asserting the
    /// candidate list here keeps the claim from drifting into "we try
    /// everything".
    /// R311y692 (§1.2a) — a handshake TAIL is counted whether the flow holding
    /// it is current or has been replaced, and the two halves cannot double
    /// count.
    ///
    /// # Why two halves and not one
    ///
    /// R311y686 bounded the carry and counted what the bound let go of. Two
    /// lifetime events were left: the opener moving to another connection,
    /// which REPLACES both directions, and the report being read while a flow
    /// is still current. Measured -- with only the retirement half, a capture
    /// whose last flow held a tail reported zero, because nothing ever retires
    /// the flow that is still current.
    ///
    /// Driven on the opener directly rather than through a capture, because
    /// what is under test is the ACCOUNTING at those two moments and a capture
    /// would have to defeat the decryption path to reach either.
    #[test]
    fn a_handshake_tail_is_counted_current_or_replaced() {
        let random = [0x5Au8; 32];
        let secret = alloc::vec![0x11u8; 48];
        let log = KeyLog::parse(
            alloc::format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                hex(&random),
                hex(&secret)
            )
            .as_bytes(),
        );
        let mut opener = CaptureOpener::new(log);
        let mut held = DirectionState::new(&[(&secret[..], true)]).expect("a usable secret");
        held.handshake_carry.extend_from_slice(&[0x18, 0x00]);
        opener.directions[0] = Some(held);

        // CURRENT: the flow still holds it, and the report is being read now.
        let seen: usize = opener
            .epoch_witness()
            .iter()
            .map(|w| w.handshake_bytes_abandoned)
            .sum();
        assert_eq!(
            seen, 2,
            "a tail outstanding when the report is read has not completed and \
             must be counted"
        );

        // REPLACED: the opener moves to another connection.
        opener
            .begin_flow(Some(&random), Some(Direction::A))
            .expect("the log holds this connection");
        let after: usize = opener
            .epoch_witness()
            .iter()
            .map(|w| w.handshake_bytes_abandoned)
            .sum();
        assert_eq!(
            after, 2,
            "and it is counted ONCE -- the replaced flow's tail moves into the \
             retired witness and is no longer in any live buffer, so the two \
             halves cannot both claim it"
        );
    }

    #[test]
    fn a_secrets_length_narrows_the_suite_and_a_record_settles_it() {
        let sha256 = EpochState::new(alloc::vec![0u8; 32]).expect("32 is a hash width");
        assert_eq!(
            sha256.candidates,
            alloc::vec![Suite::Aes128GcmSha256, Suite::Chacha20Poly1305Sha256],
            "SHA256 leaves the AEAD undecided"
        );
        let sha384 = EpochState::new(alloc::vec![0u8; 48]).expect("48 is a hash width");
        assert_eq!(
            sha384.candidates,
            alloc::vec![Suite::Aes256GcmSha384],
            "SHA384 pins the suite uniquely"
        );
        assert!(
            EpochState::new(alloc::vec![0u8; 33]).is_none(),
            "a width no TLS 1.3 hash produces must be refused, not guessed at"
        );
        // R311y662 — and a direction built from NO usable secret is refused, so
        // an unusable width cannot become an epoch that silently opens nothing.
        assert!(DirectionState::new(&[(&[0u8; 33][..], true)]).is_none());
    }

    /// R311y662 — the epochs are ordered handshake-then-application, which is
    /// the order TLS enters them and therefore the order records appear in.
    ///
    /// Reversed, the trial would begin with the application secret, fail on the
    /// handshake flight, advance to the handshake secret and take the FIRST
    /// handshake record as the start of the second epoch — arriving at the right
    /// plaintext by the wrong route and then refusing every real application
    /// record, since there is no third epoch to advance into.
    #[test]
    fn the_epochs_of_a_direction_are_in_the_order_tls_enters_them() {
        let random = [9u8; 32];
        let handshake = alloc::vec![1u8; 48];
        let application = alloc::vec![2u8; 48];
        let log = KeyLog::parse(
            alloc::format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\nCLIENT_TRAFFIC_SECRET_0 {} {}\n",
                hex(&random),
                hex(&handshake),
                hex(&random),
                hex(&application)
            )
            .as_bytes(),
        );
        let mut opener = CaptureOpener::new(log);
        opener
            .begin_flow(Some(&random), Some(Direction::A))
            .expect("both secrets are present");
        let state = opener.directions[0].as_ref().expect("the client direction");
        assert_eq!(state.epochs.len(), 2, "handshake and application");
        assert_eq!(
            state.epochs[0].secret, handshake,
            "the handshake epoch comes FIRST -- it is the one the first kept \
             records belong to"
        );
        assert_eq!(state.epochs[1].secret, application);
        assert_eq!(state.at, 0, "and the trial starts in it");
    }

    /// R311y667 — a record that opens under NO epoch leaves the direction
    /// exactly as it found it.
    ///
    /// ## Why this test is here and not in the integration suite
    ///
    /// It was tried there first and could not be written: the caller stops a
    /// direction at its first refusal, so nothing downstream ever reads the
    /// state a failed walk left behind, and every assertion available through
    /// the public surface passed with the defect present. A claim whose witness
    /// cannot be built is not a claim -- so the observation is made where the
    /// state IS observable, on the type that owns it.
    ///
    /// The defect it pins is R311y666's: the walk advanced `at` and `base` as it
    /// searched, so a record that authenticated under nothing left this
    /// direction describing an epoch it had never entered. Harmless while
    /// nothing reads it, and wrong the moment something does.
    #[test]
    fn a_record_that_opens_under_no_epoch_leaves_the_direction_untouched() {
        let mut state = DirectionState::new(&[(&[1u8; 48][..], false), (&[2u8; 48][..], true)])
            .expect("two epochs of a valid width");
        assert_eq!((state.at, state.base, state.skew), (0, 0, 0));

        // A record no key opens: the bytes are not a sealed record at all.
        let mut bytes = alloc::vec![0x17u8, 0x03, 0x03, 0x00, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        let record = EncryptedRecord {
            index: 7,
            stream_offset: 0,
            lost_before: 0,
            bytes,
        };
        assert!(state.open(&record, false).is_none(), "nothing can open it");
        assert_eq!(
            (state.at, state.base, state.skew),
            (0, 0, 0),
            "the search walked both epochs and must have left neither pointer \
             moved: a failed walk is not a state change"
        );

        // And with a hole in front of it, so the window is walked too.
        let wide = EncryptedRecord {
            index: 9,
            stream_offset: 0,
            lost_before: 10_000,
            ..record.clone()
        };
        assert!(state.open(&wide, false).is_none());
        assert_eq!((state.at, state.base, state.skew), (0, 0, 0));
    }

    /// A flow with no identity is declined by name.
    #[test]
    fn a_flow_without_an_identity_is_declined_as_such() {
        let mut opener = CaptureOpener::new(KeyLog::default());
        assert_eq!(
            opener.begin_flow(None, Some(Direction::A)),
            Err(NotDecrypted::NoSessionIdentity)
        );
        // And the DIRECTION is equally required: with a random but no side, the
        // client's and the server's secrets cannot be told apart.
        assert_eq!(
            opener.begin_flow(Some(&[0u8; 32]), None),
            Err(NotDecrypted::NoSessionIdentity)
        );
    }

    /// A log that does not carry this connection is a different refusal from a
    /// log that does not exist.
    #[test]
    fn a_log_without_this_connection_says_so() {
        let random = [9u8; 32];
        let log = KeyLog::parse(
            alloc::format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                hex(&[1u8; 32]),
                hex(&[2u8; 32])
            )
            .as_bytes(),
        );
        let mut opener = CaptureOpener::new(log);
        assert_eq!(
            opener.begin_flow(Some(&random), Some(Direction::A)),
            Err(NotDecrypted::NoKeyForSession),
            "the log is real and holds another connection"
        );
    }

    /// R311y662 — an entry carrying ONLY handshake secrets is accepted, and
    /// this reverses R311y661.
    ///
    /// That round declined such an entry with `NoKeyForSession`, on the belief
    /// that handshake secrets "protect records this reader does not keep". That
    /// belief was wrong: RFC 8446 §5.2 puts `application_data` in the OUTER
    /// content type of every protected record including the handshake flight, so
    /// `wz-capture` keeps and numbers those too. A key log holding only the
    /// handshake secrets opens exactly them — a partial view, but a real one,
    /// and refusing it threw away plaintext the reader had the key for.
    #[test]
    fn an_entry_with_only_handshake_secrets_is_accepted_for_the_flight_it_opens() {
        let random = [9u8; 32];
        let log = KeyLog::parse(
            alloc::format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                hex(&random),
                hex(&[2u8; 48])
            )
            .as_bytes(),
        );
        let mut opener = CaptureOpener::new(log);
        assert_eq!(
            opener.begin_flow(Some(&random), Some(Direction::A)),
            Ok(()),
            "the handshake flight IS kept -- its records read application_data \
             on the outside"
        );
        let state = opener.directions[0].as_ref().expect("the client direction");
        assert_eq!(
            state.epochs.len(),
            1,
            "one epoch, so a record past the key change has nothing to advance \
             into and is refused rather than mis-opened"
        );
    }

    /// R311y662 — an entry with no secret this crate can act on is still
    /// declined.
    #[test]
    fn an_entry_with_no_usable_secret_is_declined() {
        let random = [9u8; 32];
        // An exporter secret: a real key log label, and not one that protects
        // records.
        let log = KeyLog::parse(
            alloc::format!("EXPORTER_SECRET {} {}\n", hex(&random), hex(&[2u8; 48])).as_bytes(),
        );
        let mut opener = CaptureOpener::new(log);
        assert_eq!(
            opener.begin_flow(Some(&random), Some(Direction::A)),
            Err(NotDecrypted::NoKeyForSession)
        );
    }

    /// Blocks of another protocol's secrets are counted, not parsed into an
    /// empty log.
    #[test]
    fn another_protocols_secrets_block_is_skipped_and_counted() {
        let blocks = alloc::vec![
            wz_capture::pcapng::DecryptionSecrets {
                secrets_type: 0x5747_4B4C, // "WGKL" -- a WireGuard key set.
                secrets: alloc::vec![1, 2, 3],
                truncated: false,
            },
            wz_capture::pcapng::DecryptionSecrets {
                secrets_type: crate::keylog::SECRETS_TYPE_TLS_KEY_LOG,
                secrets: alloc::format!(
                    "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                    hex(&[3u8; 32]),
                    hex(&[4u8; 32])
                )
                .into_bytes(),
                truncated: false,
            },
        ];
        let (opener, skipped) = CaptureOpener::from_secrets_blocks(&blocks);
        assert_eq!(skipped, 1, "the WireGuard block is skipped BY TYPE");
        assert_eq!(
            opener.log().len(),
            1,
            "and the TLS one is read: skipping must not mean giving up"
        );
    }

    /// Two TLS key log blocks in one file both reach the log.
    ///
    /// A capture written in sections, or one merged from two files, carries more
    /// than one Decryption Secrets Block. Keeping only the last would lose every
    /// connection but the final section's, silently.
    #[test]
    fn two_key_log_blocks_in_one_file_both_reach_the_log() {
        let blocks = alloc::vec![
            wz_capture::pcapng::DecryptionSecrets {
                secrets_type: crate::keylog::SECRETS_TYPE_TLS_KEY_LOG,
                secrets: alloc::format!(
                    "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                    hex(&[3u8; 32]),
                    hex(&[4u8; 32])
                )
                .into_bytes(),
                truncated: false,
            },
            wz_capture::pcapng::DecryptionSecrets {
                secrets_type: crate::keylog::SECRETS_TYPE_TLS_KEY_LOG,
                secrets: alloc::format!(
                    "SERVER_TRAFFIC_SECRET_0 {} {}\n",
                    hex(&[5u8; 32]),
                    hex(&[6u8; 32])
                )
                .into_bytes(),
                truncated: false,
            },
        ];
        let (opener, skipped) = CaptureOpener::from_secrets_blocks(&blocks);
        assert_eq!(skipped, 0);
        assert_eq!(opener.log().len(), 2, "both connections must be present");
    }
}
