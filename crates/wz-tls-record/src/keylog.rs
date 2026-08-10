// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y658 (§1.2a) — the NSS key log, which is how a secret actually reaches
//! this crate.
//!
//! ## Why the parser is here and not in the file reader
//!
//! `wz-capture` owns the capture FILE and now keeps a Decryption Secrets
//! Block's payload instead of counting it and walking on (R311y658). It hands
//! those bytes on unparsed, because what they MEAN is TLS vocabulary — label
//! names, a client random, a per-direction traffic secret — and a pcapng parser
//! that grew those concepts would be carrying a protocol it cannot use.
//!
//! ## The format
//!
//! One record per line, whitespace-separated, three fields:
//!
//! ```text
//! <LABEL> <client_random_hex_32_bytes> <secret_hex>
//! ```
//!
//! The label says which secret it is; the client random is the 32-byte
//! `Random` from the ClientHello and is what ties the line to a CONNECTION,
//! since a key log holds every session a process ever made. Lines beginning
//! with `#` are comments, and blank lines occur.
//!
//! ## What is deliberately refused
//!
//! `CLIENT_RANDOM` — the TLS 1.2 master secret — is RECOGNISED AND REFUSED
//! rather than ignored. It is the label a TLS 1.2 capture produces, and this
//! crate decrypts TLS 1.3 only: silently skipping it would make "no secrets for
//! this connection" the report for a file that is full of them, which is a
//! wrong statement about the capture rather than a missing feature.
//! [`KeyLog::refused`] counts what was recognised and not usable, and
//! [`KeyLog::unparsed`] counts lines that were not records at all.

use alloc::string::String;
use alloc::vec::Vec;

extern crate alloc;

/// The 32-byte ClientHello `Random`, which is what a key log line is keyed by.
pub type ClientRandom = [u8; 32];

/// Which secret a key log line carries.
///
/// The four TLS 1.3 labels this crate can act on. An enum rather than the raw
/// label string so a caller selecting "the application secret for this
/// direction" cannot select it by spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretLabel {
    /// `CLIENT_HANDSHAKE_TRAFFIC_SECRET` — the client's handshake records.
    ClientHandshake,
    /// `SERVER_HANDSHAKE_TRAFFIC_SECRET` — the server's handshake records.
    ServerHandshake,
    /// `CLIENT_TRAFFIC_SECRET_N` — the client's application records under the
    /// `N`th application key.
    ///
    /// R311y663 (§1.2a) — the GENERATION is part of the label, and until this
    /// round it was not: the variant meant `_0` and every later one was refused
    /// by name, so a session that rekeyed decrypted up to the update and stopped.
    /// The enum was asserting that a connection has one application secret per
    /// direction, which is true only of a session short enough never to rekey —
    /// and a zenoh session is long-lived by design.
    ClientApplication(u32),
    /// `SERVER_TRAFFIC_SECRET_N` — the server's, likewise.
    ServerApplication(u32),
}

impl SecretLabel {
    /// The label a line spells, or `None` for one this crate does not act on.
    ///
    /// The application secrets are matched as stem-plus-DIGITS and the digits
    /// are KEPT. Never as a bare prefix: `CLIENT_TRAFFIC_SECRET_0` and
    /// `CLIENT_TRAFFIC_SECRET_1` are different secrets protecting different
    /// records, and filing the second under the first decrypts nothing while
    /// claiming to hold the key.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => return Some(Self::ClientHandshake),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => return Some(Self::ServerHandshake),
            _ => {}
        }
        for (stem, make) in [
            (
                "CLIENT_TRAFFIC_SECRET_",
                Self::ClientApplication as fn(u32) -> Self,
            ),
            (
                "SERVER_TRAFFIC_SECRET_",
                Self::ServerApplication as fn(u32) -> Self,
            ),
        ] {
            if let Some(rest) = label.strip_prefix(stem) {
                // Parsed rather than prefix-matched, so `_10` is generation ten
                // and not a malformed `_1`.
                return rest.parse::<u32>().ok().map(make);
            }
        }
        None
    }

    /// The generation of an application secret, or `None` for a handshake one.
    pub fn generation(self) -> Option<u32> {
        match self {
            Self::ClientHandshake | Self::ServerHandshake => None,
            Self::ClientApplication(n) | Self::ServerApplication(n) => Some(n),
        }
    }
}

/// R311y659 — is this first field a label the NSS key log format defines?
///
/// Wider than [`SecretLabel::from_label`] on purpose: that answers "can this
/// crate act on it", and this answers "was this a key log record at all". The
/// gap between the two is exactly what [`KeyLog::refused`] reports, and it is
/// the useful half of the answer — `CLIENT_RANDOM` means bring a TLS 1.2
/// reader, and a later `_N` means bring key update support.
fn is_keylog_label(label: &str) -> bool {
    const KNOWN: [&str; 6] = [
        "CLIENT_RANDOM",
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "EARLY_EXPORTER_SECRET",
        "EXPORTER_SECRET",
    ];
    if KNOWN.contains(&label) {
        return true;
    }
    // R311y663 — the numbered application secrets are ACTIONABLE now, at every
    // generation, so they never reach this function: `SecretLabel::from_label`
    // takes them first. What remains here is the shape that looks like one and
    // is not — a generation this reader cannot parse as a `u32`, which is a key
    // log record it recognises and cannot use, exactly what `refused` means.
    for stem in ["CLIENT_TRAFFIC_SECRET_", "SERVER_TRAFFIC_SECRET_"] {
        if let Some(rest) = label.strip_prefix(stem) {
            return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
        }
    }
    false
}

/// One connection's secrets, as a key log carried them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ConnectionSecrets {
    entries: Vec<(SecretLabel, Vec<u8>)>,
}

impl core::fmt::Debug for ConnectionSecrets {
    /// The labels and the lengths, never the bytes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_list();
        for (label, secret) in &self.entries {
            list.entry(&format_args!("{label:?}: <{} byte(s)>", secret.len()));
        }
        list.finish()
    }
}

impl ConnectionSecrets {
    /// The secret for one label, if the log carried it.
    pub fn get(&self, label: SecretLabel) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, s)| s.as_slice())
    }

    /// Every label this connection has a secret for, in the order the log gave
    /// them.
    pub fn labels(&self) -> impl Iterator<Item = SecretLabel> + '_ {
        self.entries.iter().map(|(l, _)| *l)
    }

    /// `true` when both directions have a generation-zero APPLICATION secret,
    /// which is the minimum for reading a session's payload both ways.
    ///
    /// Its own question rather than two `get` calls at every call site, because
    /// "half a connection" is a state a reader must be told about: with one
    /// direction's secret a report can show what one peer said and would
    /// otherwise look like a session where the other peer was silent — the
    /// exact confusion R311y648 was written to end.
    pub fn has_both_application_directions(&self) -> bool {
        self.get(SecretLabel::ClientApplication(0)).is_some()
            && self.get(SecretLabel::ServerApplication(0)).is_some()
    }

    /// R311y663 (§1.2a) — one direction's application secrets, ORDERED BY
    /// GENERATION.
    ///
    /// The order is the epochs' order, and it must come from the generation
    /// rather than from the order the log's lines happened to arrive in: a key
    /// log is appended to by a running process and a capture may hold a
    /// truncated or interleaved copy, so line order is not key order. Sorting by
    /// a number the label states is the only reading that does not depend on how
    /// the file was assembled.
    pub fn application_secrets(&self, server: bool) -> Vec<(u32, &[u8])> {
        let mut out: Vec<(u32, &[u8])> = self
            .entries
            .iter()
            .filter_map(|(label, secret)| match (label, server) {
                (SecretLabel::ClientApplication(n), false)
                | (SecretLabel::ServerApplication(n), true) => Some((*n, secret.as_slice())),
                _ => None,
            })
            .collect();
        out.sort_by_key(|(n, _)| *n);
        out
    }
}

/// Every connection a key log carried, and what could not be used.
#[derive(Clone, Default)]
pub struct KeyLog {
    connections: Vec<(ClientRandom, ConnectionSecrets)>,
    refused: Vec<String>,
    unparsed: usize,
}

impl core::fmt::Debug for KeyLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyLog")
            .field("connections", &self.connections.len())
            .field("refused", &self.refused)
            .field("unparsed", &self.unparsed)
            .finish()
    }
}

/// The registered pcapng secrets type for an NSS key log — `"TLSK"` as a
/// big-endian word (draft-tuexen-opsawg-pcapng §4.7).
pub const SECRETS_TYPE_TLS_KEY_LOG: u32 = 0x544c_534b;

/// Why a Decryption Secrets Block was not read as a key log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsBlockError {
    /// The block carries a registered secrets type this crate does not read —
    /// a WireGuard or ZigBee key set, for instance.
    UnknownSecretsType(u32),
}

impl KeyLog {
    /// R311y659 (§1.2a) — parse a Decryption Secrets Block, CHECKING its type.
    ///
    /// The entry point a capture reader should use, and the reason it exists is
    /// that the untyped one cannot refuse: handed a block of some other
    /// registered secrets type, [`Self::parse`] counts every line as unparsed
    /// and reports an empty log. That is true and useless -- "this capture's
    /// secrets are for a protocol I do not read" and "this capture's key log is
    /// corrupt" send a reader to different places.
    pub fn from_secrets_block(
        secrets_type: u32,
        secrets: &[u8],
    ) -> Result<Self, SecretsBlockError> {
        if secrets_type != SECRETS_TYPE_TLS_KEY_LOG {
            return Err(SecretsBlockError::UnknownSecretsType(secrets_type));
        }
        Ok(Self::parse(secrets))
    }

    /// Parse an NSS key log.
    ///
    /// Never fails: a key log is a growing text file that a capture may hold a
    /// truncated or interleaved copy of, so a line this reader cannot use is
    /// COUNTED rather than fatal. What it must not do is lose the count —
    /// see [`Self::refused`] and [`Self::unparsed`].
    pub fn parse(text: &[u8]) -> Self {
        let mut out = Self::default();
        for line in text.split(|b| *b == b'\n') {
            let line = core::str::from_utf8(line).unwrap_or("").trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(label), Some(random), Some(secret)) =
                (fields.next(), fields.next(), fields.next())
            else {
                out.unparsed += 1;
                continue;
            };
            let Some(label) = SecretLabel::from_label(label) else {
                // R311y659 — `refused` means RECOGNISED AND NOT ACTIONABLE, so
                // only a real key log label may enter it. Anything else is not
                // a record at all. Found by a test: with any first field
                // admitted here, a block of some other protocol's secrets
                // reported a LIST OF REFUSED LABELS made of its own bytes,
                // which reads as "this is a key log I could not use" about
                // something that was never one.
                if is_keylog_label(label) {
                    out.refused.push(String::from(label));
                } else {
                    out.unparsed += 1;
                }
                continue;
            };
            let (Some(random), Some(secret)) = (unhex_random(random), unhex(secret)) else {
                out.unparsed += 1;
                continue;
            };
            let slot = match out.connections.iter_mut().find(|(r, _)| *r == random) {
                Some((_, s)) => s,
                None => {
                    out.connections.push((random, ConnectionSecrets::default()));
                    &mut out.connections.last_mut().expect("just pushed").1
                }
            };
            // A repeated label for one connection REPLACES rather than appends:
            // a key log appended to across a re-handshake carries the newer
            // line last, and two secrets under one label would make which one a
            // caller gets depend on iteration order.
            match slot.entries.iter_mut().find(|(l, _)| *l == label) {
                Some((_, existing)) => *existing = secret,
                None => slot.entries.push((label, secret)),
            }
        }
        out
    }

    /// R311y661 (§1.2a) — fold another log's contents into this one.
    ///
    /// A capture file may carry more than one Decryption Secrets Block: a
    /// pcapng written in sections has one per section, and a file merged from
    /// two captures has both. Keeping only the last would lose every connection
    /// but the final block's, and would do it silently — the log would simply
    /// report fewer connections than the file described.
    ///
    /// The merge rule is `parse`'s own, applied one layer up: a repeated label
    /// for a connection REPLACES, so the later block wins, and the refused and
    /// unparsed tallies ADD, because they count lines and the lines are all
    /// still there.
    pub fn absorb(&mut self, other: Self) {
        for (random, secrets) in other.connections {
            let slot = match self.connections.iter_mut().find(|(r, _)| *r == random) {
                Some((_, s)) => s,
                None => {
                    self.connections
                        .push((random, ConnectionSecrets::default()));
                    &mut self.connections.last_mut().expect("just pushed").1
                }
            };
            for (label, secret) in secrets.entries {
                match slot.entries.iter_mut().find(|(l, _)| *l == label) {
                    Some((_, existing)) => *existing = secret,
                    None => slot.entries.push((label, secret)),
                }
            }
        }
        self.refused.extend(other.refused);
        self.unparsed += other.unparsed;
    }

    /// The secrets for one connection, selected by its ClientHello random.
    pub fn get(&self, random: &ClientRandom) -> Option<&ConnectionSecrets> {
        self.connections
            .iter()
            .find(|(r, _)| r == random)
            .map(|(_, s)| s)
    }

    /// How many connections the log carried.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// `true` when the log carried no connection this crate can act on.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Every client random the log carried, in first-seen order.
    pub fn client_randoms(&self) -> impl Iterator<Item = &ClientRandom> {
        self.connections.iter().map(|(r, _)| r)
    }

    /// Labels this reader RECOGNISED as key log records and cannot act on —
    /// `CLIENT_RANDOM` (TLS 1.2) above all, and the `_1`-and-later application
    /// secrets a key update produces.
    ///
    /// Its own list rather than a count, because which label was refused is
    /// what tells a reader whether the capture needs TLS 1.2 support or key
    /// update support. Duplicates are kept: the number of lines matters.
    pub fn refused(&self) -> &[String] {
        &self.refused
    }

    /// Lines that were not key log records at all — too few fields, or a field
    /// that is not hex.
    pub fn unparsed(&self) -> usize {
        self.unparsed
    }
}

/// The 32-byte client random, or `None` unless it is exactly that.
///
/// Exactly 32 and not "at least": a short random would key a connection under a
/// prefix of the real one and never match a capture.
fn unhex_random(text: &str) -> Option<ClientRandom> {
    let bytes = unhex(text)?;
    bytes.try_into().ok()
}

/// Lowercase or uppercase hex to bytes; `None` on an odd length or a non-hex
/// digit.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    const RANDOM_A: &str = "0011223344556677889900112233445566778899001122334455667788990011";
    const RANDOM_B: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn random(hex: &str) -> ClientRandom {
        unhex_random(hex).expect("a 32-byte fixture")
    }

    /// R311y658 — a key log as a TLS 1.3 stack writes one.
    #[test]
    fn a_tls13_key_log_yields_both_directions_of_each_connection() {
        let text = format!(
            "# comment a stack writes at the top\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {RANDOM_A} 0102030405060708090a0b0c0d0e0f10\n\
             SERVER_HANDSHAKE_TRAFFIC_SECRET {RANDOM_A} 1112131415161718191a1b1c1d1e1f20\n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 2122232425262728292a2b2c2d2e2f30\n\
             SERVER_TRAFFIC_SECRET_0 {RANDOM_A} 3132333435363738393a3b3c3d3e3f40\n\
             \n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM_B} 4142434445464748494a4b4c4d4e4f50\n"
        );
        let log = KeyLog::parse(text.as_bytes());

        assert_eq!(log.len(), 2, "two connections, keyed by client random");
        assert_eq!(
            log.unparsed(),
            0,
            "the comment and the blank are not errors"
        );
        assert!(log.refused().is_empty());

        let a = log.get(&random(RANDOM_A)).expect("connection A");
        assert!(a.has_both_application_directions());
        assert_eq!(
            a.get(SecretLabel::ClientApplication(0)),
            Some(
                &[
                    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                    0x2e, 0x2f, 0x30
                ][..]
            )
        );
        assert_eq!(
            a.get(SecretLabel::ServerHandshake),
            Some(
                &[
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                    0x1e, 0x1f, 0x20
                ][..]
            )
        );

        // HALF A CONNECTION IS ITS OWN STATE, and the reason it has a question
        // of its own: with one direction's secret a report shows what one peer
        // said and reads exactly like a session where the other was silent.
        let b = log.get(&random(RANDOM_B)).expect("connection B");
        assert!(!b.has_both_application_directions());
        assert!(b.get(SecretLabel::ServerApplication(0)).is_none());
    }

    /// R311y658 — a TLS 1.2 line is REFUSED BY NAME, not skipped.
    ///
    /// `CLIENT_RANDOM` is what a TLS 1.2 capture's key log is full of. Silently
    /// dropping it would report "no secrets for this connection" about a file
    /// that carries nothing but secrets, which is a wrong statement about the
    /// capture rather than a missing feature -- and the two need different
    /// answers from whoever reads the report.
    #[test]
    fn a_tls12_master_secret_is_refused_by_name_rather_than_ignored() {
        let text = format!("CLIENT_RANDOM {RANDOM_A} 0102030405060708\n");
        let log = KeyLog::parse(text.as_bytes());
        assert!(log.is_empty(), "nothing this crate can act on");
        assert_eq!(log.unparsed(), 0, "it WAS a well-formed record");
        assert_eq!(log.refused(), &["CLIENT_RANDOM".to_string()]);
    }

    /// R311y663 — a key update's later secrets are KEPT, each under its own
    /// generation, and this REVERSES R311y659's refusal of them.
    ///
    /// That round refused `_1` by name and was right to, given what the enum
    /// could then express: one application secret per direction. Refusing was
    /// strictly better than filing the second under the first, which decrypts
    /// nothing while claiming to hold the key. But the refusal was never the
    /// goal — it was the honest response to a missing feature, and a session
    /// long enough to rekey (which a zenoh session is) stopped decrypting at the
    /// update.
    ///
    /// The claim R311y659 was protecting is unchanged and still gated below:
    /// `_1` must not overwrite `_0`. What changed is that `_1` is now a secret
    /// of its own rather than a line thrown away.
    #[test]
    fn a_later_application_secret_is_kept_under_its_own_generation() {
        let text = format!(
            "CLIENT_TRAFFIC_SECRET_1 {RANDOM_A} 0102030405060708\n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 1112131415161718\n"
        );
        let log = KeyLog::parse(text.as_bytes());
        assert!(
            log.refused().is_empty(),
            "a generation this reader can act on is not a refusal: {:?}",
            log.refused()
        );
        let c = log.get(&random(RANDOM_A)).expect("the connection");
        assert_eq!(
            c.get(SecretLabel::ClientApplication(0)),
            Some(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18][..]),
            "the _0 line must not have been overwritten by the _1 one"
        );
        assert_eq!(
            c.get(SecretLabel::ClientApplication(1)),
            Some(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..]),
            "and the _1 line is a secret now, not a discarded one"
        );
        // ORDERED BY GENERATION and not by line order -- the file above states
        // them backwards on purpose, because a key log is appended to by a
        // running process and a capture may hold an interleaved copy.
        assert_eq!(
            c.application_secrets(false)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>(),
            alloc::vec![0, 1],
            "the epochs must come out in the order TLS enters them, whatever \
             order the lines arrived in"
        );
    }

    /// R311y663 — a generation this reader cannot parse is still a refusal.
    ///
    /// The gap `refused` exists to report did not close, it moved: a label
    /// shaped like an application secret whose number does not fit a `u32` is a
    /// key log record recognised and not actionable, which is what the list
    /// means.
    #[test]
    fn a_generation_that_does_not_parse_is_refused_rather_than_dropped() {
        let text = format!("CLIENT_TRAFFIC_SECRET_99999999999 {RANDOM_A} 01020304\n");
        let log = KeyLog::parse(text.as_bytes());
        assert!(log.is_empty(), "nothing usable came of it");
        assert_eq!(
            log.refused(),
            &["CLIENT_TRAFFIC_SECRET_99999999999".to_string()],
            "and it must not be counted as a line that was never a record"
        );
        assert_eq!(log.unparsed(), 0);
    }

    /// Malformed lines are COUNTED, which is what keeps a truncated key log
    /// from reading as a complete one.
    #[test]
    fn lines_that_are_not_records_are_counted_rather_than_dropped() {
        let text = format!(
            "CLIENT_TRAFFIC_SECRET_0 {RANDOM_A}\n\
             CLIENT_TRAFFIC_SECRET_0 nothex {RANDOM_A}\n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 0102030\n\
             CLIENT_TRAFFIC_SECRET_0 00112233 01020304\n"
        );
        let log = KeyLog::parse(text.as_bytes());
        assert!(log.is_empty());
        assert_eq!(
            log.unparsed(),
            4,
            "two fields, a non-hex random, an odd-length secret, and a short random"
        );
    }

    /// A random shorter than 32 bytes must not key a connection: it would file
    /// the secret under a prefix of the real random and never match a capture.
    #[test]
    fn a_short_client_random_does_not_key_a_connection() {
        assert!(unhex_random("00112233").is_none());
        assert!(unhex_random(RANDOM_A).is_some());
        // 33 bytes: longer is refused for the same reason shorter is.
        let long = format!("{RANDOM_A}ff");
        assert!(unhex_random(&long).is_none());
    }

    /// The log is re-read as a stack appends to it, so the LAST line for a
    /// label wins rather than a second entry appearing beside the first.
    #[test]
    fn a_repeated_label_replaces_rather_than_duplicating() {
        let text = format!(
            "CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 01020304\n\
             CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 05060708\n"
        );
        let log = KeyLog::parse(text.as_bytes());
        let c = log.get(&random(RANDOM_A)).expect("one connection");
        assert_eq!(c.labels().count(), 1, "one label, not two");
        assert_eq!(
            c.get(SecretLabel::ClientApplication(0)),
            Some(&[0x05, 0x06, 0x07, 0x08][..]),
            "the later line wins"
        );
    }

    /// Neither rendering may carry key material.
    #[test]
    fn no_debug_rendering_carries_a_secret() {
        let text = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} deadbeefdeadbeef\n");
        let log = KeyLog::parse(text.as_bytes());
        let shown = format!("{log:?}");
        assert!(!shown.contains("222"), "{shown}");
        let conn = format!("{:?}", log.get(&random(RANDOM_A)).unwrap());
        assert!(conn.contains("8 byte(s)"), "{conn}");
        assert!(
            !conn.contains("222") && !conn.contains("deadbeef"),
            "{conn}"
        );
    }

    /// R311y658 — THE TWO HALVES COMPOSE: a secret that came out of a key log
    /// derives keys through this crate's own schedule.
    ///
    /// Small but load-bearing. The parser and the key schedule were written in
    /// different rounds and nothing else joins them, so a `Vec<u8>` that came
    /// out of a hex decode and a `&[u8]` the schedule expects could drift into
    /// two different ideas of what a secret is -- a length, an ordering -- with
    /// both halves green.
    #[test]
    fn a_secret_from_the_log_feeds_the_key_schedule() {
        // 32 bytes, which is what a SHA-256 suite's traffic secret is.
        let secret_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let text = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} {secret_hex}\n");
        let log = KeyLog::parse(text.as_bytes());
        let secret = log
            .get(&random(RANDOM_A))
            .and_then(|c| c.get(crate::keylog::SecretLabel::ClientApplication(0)))
            .expect("the log carried it");
        assert_eq!(secret.len(), 32, "a SHA-256 traffic secret");

        let keys = crate::TrafficKeys::derive(crate::Suite::Aes128GcmSha256, secret);
        assert_eq!(keys.suite(), crate::Suite::Aes128GcmSha256);
        // The derivation is pinned elsewhere (differentially, against rustls);
        // what THIS asserts is that the bytes crossed the seam intact, which a
        // hex decode that reversed or truncated would break.
        let other = crate::TrafficKeys::derive(crate::Suite::Aes128GcmSha256, &[0u8; 32]);
        assert_ne!(
            keys.nonce(0),
            other.nonce(0),
            "a secret that arrived as zeroes would derive the same iv as one"
        );
    }

    /// R311y659 — `refused` means RECOGNISED, so arbitrary text does not enter
    /// it. Found by writing the test below: with any first field admitted, a
    /// block of another protocol's secrets reported a list of "refused labels"
    /// built out of its own bytes.
    #[test]
    fn only_a_real_keylog_label_is_reported_as_refused() {
        let text = format!(
            "not a tls key log at all\n\
             CLIENT_RANDOM {RANDOM_A} 0102\n\
             SERVER_TRAFFIC_SECRET_7 {RANDOM_A} 0102\n\
             CLIENT_TRAFFIC_SECRET_ {RANDOM_A} 0102\n\
             EXPORTER_SECRET {RANDOM_A} 0102\n"
        );
        let log = KeyLog::parse(text.as_bytes());
        assert_eq!(
            log.refused(),
            &["CLIENT_RANDOM".to_string(), "EXPORTER_SECRET".to_string()],
            "only labels the format defines -- and R311y663 moved \
             SERVER_TRAFFIC_SECRET_7 OUT of this list by making generation 7 a \
             secret this crate can act on"
        );
        assert_eq!(
            log.get(&random(RANDOM_A))
                .and_then(|c| c.get(SecretLabel::ServerApplication(7)))
                .map(|s| s.len()),
            Some(2),
            "and it is kept rather than merely un-refused"
        );
        assert_eq!(
            log.unparsed(),
            2,
            "the prose line and the unnumbered stem are not records: {log:?}"
        );
    }

    /// R311y659 — a block of some OTHER registered secrets type is refused by
    /// its type rather than parsed into an empty log.
    ///
    /// The untyped entry point cannot tell the two apart: handed a WireGuard
    /// key set it counts every line as unparsed and reports "no connections",
    /// which reads exactly like a corrupt TLS key log. The type is in the block
    /// and checking it is the only place that distinction can be made.
    #[test]
    fn a_secrets_block_of_another_type_is_refused_by_its_type() {
        const WIREGUARD: u32 = 0x5747_4b4c;
        let body = b"not a tls key log at all\n";
        assert_eq!(
            KeyLog::from_secrets_block(WIREGUARD, body).unwrap_err(),
            SecretsBlockError::UnknownSecretsType(WIREGUARD)
        );
        // THE CONTROL, and what makes the refusal a discrimination rather than
        // a rejection of everything: the same bytes under the TLSK type are
        // read, and reported as unparsed lines rather than as nothing.
        let log = KeyLog::from_secrets_block(SECRETS_TYPE_TLS_KEY_LOG, body)
            .expect("the registered TLS key log type");
        assert!(log.is_empty());
        assert_eq!(log.unparsed(), 1, "the line WAS looked at");
        assert!(
            log.refused().is_empty(),
            "and prose must not be reported as a refused LABEL: {log:?}"
        );

        let text = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM_A} 01020304\n");
        let log = KeyLog::from_secrets_block(SECRETS_TYPE_TLS_KEY_LOG, text.as_bytes())
            .expect("the registered type");
        assert_eq!(log.len(), 1);
    }

    /// Hex is accepted in either case, because stacks differ and a log written
    /// in uppercase is not a broken log.
    #[test]
    fn hex_is_read_in_either_case() {
        let upper = RANDOM_A.to_uppercase();
        assert_eq!(unhex_random(&upper), unhex_random(RANDOM_A));
    }
}
