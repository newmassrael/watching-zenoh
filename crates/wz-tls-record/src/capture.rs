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

use wz_capture::tls::{Direction, NotDecrypted, OpenedRecord, RecordOpener};

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
}

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
        })
    }

    /// Open one record, advancing the epoch when the current one refuses it and
    /// the next one accepts it at sequence zero.
    fn open(&mut self, index: u64, record: &[u8]) -> Option<OpenedRecord> {
        loop {
            let base = self.base;
            if let Some(opened) = self.epochs[self.at].open(index.saturating_sub(base), record) {
                return Some(opened);
            }
            // The current epoch refused. If there is a later one, this record is
            // a candidate for being its FIRST -- so it is retried at sequence
            // zero, which is where a key change restarts the count.
            if self.at + 1 >= self.epochs.len() {
                return None;
            }
            self.at += 1;
            self.base = index;
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
        let client: [Option<&[u8]>; 2] = [
            secrets.get(SecretLabel::ClientHandshake),
            secrets.get(SecretLabel::ClientApplication),
        ];
        let server: [Option<&[u8]>; 2] = [
            secrets.get(SecretLabel::ServerHandshake),
            secrets.get(SecretLabel::ServerApplication),
        ];
        let client: Vec<&[u8]> = client.into_iter().flatten().collect();
        let server: Vec<&[u8]> = server.into_iter().flatten().collect();
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

    fn open(&mut self, direction: Direction, index: u64, record: &[u8]) -> Option<OpenedRecord> {
        let at = match direction {
            Direction::A => 0,
            Direction::B => 1,
        };
        self.directions[at].as_mut()?.open(index, record)
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
