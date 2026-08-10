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
    fn new(secrets: &[&[u8]]) -> Option<Self> {
        let epochs: Vec<EpochState> = secrets
            .iter()
            .filter_map(|s| EpochState::new(s.to_vec()))
            .collect();
        if epochs.is_empty() {
            return None;
        }
        Some(Self {
            epochs,
            at: 0,
            base: 0,
            skew: 0,
        })
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
    fn open(&mut self, record: &EncryptedRecord) -> Option<OpenedRecord> {
        // R311y666 — after a hole, find how far the numbering slipped. At most
        // `lost_before / MIN_PROTECTED_RECORD` records fitted in it.
        if record.lost_before > 0 {
            let window = (record.lost_before / MIN_PROTECTED_RECORD).min(MAX_RESYNC_ATTEMPTS);
            let from = (record.index - self.base) + self.skew;
            for k in 0..=window {
                if let Some(opened) = self.epochs[self.at].open(from + k, &record.bytes) {
                    // Found, and by AUTHENTICATION rather than by inference: the
                    // tag is a 128-bit check, so the offset that opens the record
                    // is the offset. It holds for every later record of this
                    // epoch, which is why it is accumulated rather than applied
                    // once.
                    self.skew += k;
                    return Some(opened);
                }
            }
            // Not recoverable within the window. Fall through: the record may
            // still be the first of the NEXT epoch, whose sequence starts over
            // and owes nothing to the hole.
        }
        loop {
            let seq = (record.index - self.base) + self.skew;
            if let Some(opened) = self.epochs[self.at].open(seq, &record.bytes) {
                return Some(opened);
            }
            // The current epoch refused. If there is a later one, this record is
            // a candidate for being its FIRST -- so it is retried at sequence
            // zero, which is where a key change restarts the count.
            if self.at + 1 >= self.epochs.len() {
                return None;
            }
            self.at += 1;
            self.base = record.index;
            // A new epoch numbers from zero and has lost nothing YET.
            self.skew = 0;
        }
    }
}

impl CaptureOpener {
    /// Build one from a key log.
    pub fn new(log: KeyLog) -> Self {
        Self {
            log,
            directions: [None, None],
        }
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
        self.directions = [None, None];
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
        let epochs_of = |early: Option<SecretLabel>, handshake: SecretLabel, server: bool| {
            let mut out: Vec<&[u8]> = early
                .and_then(|l| secrets.get(l))
                .into_iter()
                .chain(secrets.get(handshake))
                .collect();
            out.extend(
                secrets
                    .application_secrets(server)
                    .into_iter()
                    .map(|(_, s)| s),
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
        self.directions[client_index] = DirectionState::new(&client);
        self.directions[1 - client_index] = DirectionState::new(&server);
        Ok(())
    }

    fn open(&mut self, direction: Direction, record: &EncryptedRecord) -> Option<OpenedRecord> {
        let at = match direction {
            Direction::A => 0,
            Direction::B => 1,
        };
        self.directions[at].as_mut()?.open(record)
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
        assert!(DirectionState::new(&[&[0u8; 33][..]]).is_none());
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
