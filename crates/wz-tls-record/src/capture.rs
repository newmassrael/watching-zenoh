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

/// One direction's key material and its suite, once a record has settled it.
#[derive(Debug)]
struct DirectionState {
    secret: Vec<u8>,
    /// Suites still consistent with the secret's length; emptied as the first
    /// record settles one.
    candidates: Vec<Suite>,
    /// The keys, once a suite has been settled by opening a record.
    settled: Option<TrafficKeys>,
}

impl DirectionState {
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

    /// Open one record, settling the suite on the first success.
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
        let (Some(random), Some(client)) = (client_random, client_direction) else {
            return Err(NotDecrypted::NoSessionIdentity);
        };
        let secrets = self.log.get(random).ok_or(NotDecrypted::NoKeyForSession)?;
        let client_secret = secrets.get(SecretLabel::ClientApplication);
        let server_secret = secrets.get(SecretLabel::ServerApplication);
        if client_secret.is_none() && server_secret.is_none() {
            // The entry exists and carries only handshake secrets, which protect
            // records this reader does not keep. Reported as no key for the
            // session, because that is what it is for the records in hand.
            return Err(NotDecrypted::NoKeyForSession);
        }
        let client_index = match client {
            Direction::A => 0,
            Direction::B => 1,
        };
        self.directions[client_index] = client_secret.and_then(|s| DirectionState::new(s.to_vec()));
        self.directions[1 - client_index] =
            server_secret.and_then(|s| DirectionState::new(s.to_vec()));
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
        let sha256 = DirectionState::new(alloc::vec![0u8; 32]).expect("32 is a hash width");
        assert_eq!(
            sha256.candidates,
            alloc::vec![Suite::Aes128GcmSha256, Suite::Chacha20Poly1305Sha256],
            "SHA256 leaves the AEAD undecided"
        );
        let sha384 = DirectionState::new(alloc::vec![0u8; 48]).expect("48 is a hash width");
        assert_eq!(
            sha384.candidates,
            alloc::vec![Suite::Aes256GcmSha384],
            "SHA384 pins the suite uniquely"
        );
        assert!(
            DirectionState::new(alloc::vec![0u8; 33]).is_none(),
            "a width no TLS 1.3 hash produces must be refused, not guessed at"
        );
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

    /// An entry carrying only handshake secrets cannot open the records this
    /// reader keeps.
    #[test]
    fn an_entry_with_only_handshake_secrets_is_no_key_for_the_records_kept() {
        let random = [9u8; 32];
        let log = KeyLog::parse(
            alloc::format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                hex(&random),
                hex(&[2u8; 32])
            )
            .as_bytes(),
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
