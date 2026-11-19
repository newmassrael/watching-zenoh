// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHY A TLS LINK DID OR DID NOT COME UP: what its handshake said.
//!
//! An encrypted zenoh link that never carries a session tells its reader only
//! that nothing could be decrypted. The reason is in the handshake, and much of
//! it is plaintext on the wire:
//!
//! * the server name the client asked for (the ClientHello's `server_name`
//!   extension, RFC 6066 section 3);
//! * the version the server chose (its ServerHello's `supported_versions`
//!   extension for TLS 1.3, RFC 8446 section 4.2.1, or its legacy version);
//! * an alert sent before the sender's ChangeCipherSpec, with its level and
//!   number (RFC 8446 section 6): a client refusing a certificate signed by a
//!   CA it does not trust sends `unknown_ca` (48) or `bad_certificate` (42);
//! * under TLS 1.2 and below, the server's certificate: its subject, its issuer
//!   and its validity, read from the first certificate of the chain.
//!
//! TLS 1.3 encrypts its certificate and every alert after the ServerHello.
//! Those are read here only out of the records a key log opened
//! ([`TlsHandshake::observe_opened`]); without one they are protected records
//! like any other.
//!
//! # Whether the handshake completed
//!
//! `yes` when application data flowed both ways after it: under TLS 1.2 and
//! below, both directions changed cipher spec and each sent a protected
//! record; under TLS 1.3, the client sent two protected records (its Finished
//! and data) and the server one. `no` when a fatal alert was read. `undecided`
//! otherwise, which is also what a capture without the ServerHello reads.

use alloc::string::String;
use alloc::vec::Vec;

/// How many handshake bytes one direction holds while a message is incomplete.
pub const HANDSHAKE_BYTES_HELD: usize = 65_536;
/// How many alerts a flow keeps.
pub const ALERTS_HELD: usize = 8;

const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const TLS_1_3: u16 = 0x0304;

/// Where handshake bytes were read: in the clear, or out of a record a key log
/// opened.
const CLEAR: usize = 0;
const OPENED: usize = 1;

/// Whether the handshake completed. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Application data flowed both ways after it.
    Yes,
    /// A fatal alert was read.
    No,
    /// Neither is known.
    Undecided,
}

impl Completion {
    /// The word this answer is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Completion::Yes => "yes",
            Completion::No => "no",
            Completion::Undecided => "undecided",
        }
    }

    /// Every answer, from an exhaustive match.
    pub fn all() -> [Completion; 3] {
        let one = |c: Completion| match c {
            Completion::Yes | Completion::No | Completion::Undecided => c,
        };
        [
            one(Completion::Yes),
            one(Completion::No),
            one(Completion::Undecided),
        ]
    }

    /// Every word, sorted.
    #[cfg(test)]
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|c| c.name()).collect();
        words.sort_unstable();
        words
    }
}

/// One alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// The direction that sent it, 0 for `a`.
    pub direction: usize,
    /// 1 warning, 2 fatal.
    pub level: u8,
    /// The alert's number.
    pub description: u8,
}

/// What a certificate says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The subject's distinguished name, `CN=...,O=...`.
    pub subject: String,
    /// The issuer's.
    pub issuer: String,
    /// The start of its validity, `YYYY-MM-DDTHH:MM:SSZ`.
    pub not_before: String,
    /// The end of its validity.
    pub not_after: String,
}

/// What one TLS flow's handshake said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsHandshake {
    /// The server name the ClientHello asked for.
    pub sni: Option<String>,
    /// The version the ServerHello chose.
    pub version: Option<u16>,
    /// The direction of the ClientHello, 0 for `a`.
    pub client: Option<usize>,
    /// The alerts read, the first [`ALERTS_HELD`].
    pub alerts: Vec<Alert>,
    /// Alerts past that bound.
    pub alerts_more: u64,
    /// The server's first certificate, when it was sent in the clear or opened.
    pub certificate: Option<Certificate>,
    /// Per direction: it changed cipher spec.
    pub changed_cipher: [bool; 2],
    /// Per direction: protected records after the ServerHello.
    pub protected: [u64; 2],
    /// Handshake bytes not yet a whole message, per layer (in the clear, then
    /// opened) and direction.
    held: [[Vec<u8>; 2]; 2],
    overflowed: [[bool; 2]; 2],
    fatal: bool,
}

impl TlsHandshake {
    /// One whole record, its five-byte header included, sent by direction `d`.
    pub fn observe(&mut self, d: usize, record: &[u8]) {
        let Some((&content_type, fragment)) = record.first().zip(record.get(5..)) else {
            return;
        };
        match content_type {
            CT_CHANGE_CIPHER_SPEC => self.changed_cipher[d] = true,
            CT_ALERT if !self.changed_cipher[d] => self.alert(d, fragment),
            CT_HANDSHAKE if !self.changed_cipher[d] => self.hold(CLEAR, d, fragment),
            CT_APPLICATION_DATA if self.version.is_some() => self.protected[d] += 1,
            _ => {}
        }
    }

    /// One protected record a key log opened: its inner content type and its
    /// plaintext. TLS 1.3 sends its certificate and every alert after the
    /// ServerHello this way.
    pub fn observe_opened(&mut self, d: usize, content_type: u8, plaintext: &[u8]) {
        match content_type {
            CT_ALERT => self.alert(d, plaintext),
            CT_HANDSHAKE => self.hold(OPENED, d, plaintext),
            _ => {}
        }
    }

    /// Whether the handshake completed: see the module doc.
    pub fn completion(&self) -> Completion {
        if self.fatal {
            return Completion::No;
        }
        let (Some(version), Some(client)) = (self.version, self.client) else {
            return Completion::Undecided;
        };
        let server = 1 - client;
        let done = if version >= TLS_1_3 {
            self.protected[client] >= 2 && self.protected[server] >= 1
        } else {
            self.changed_cipher == [true, true]
                && self.protected[client] >= 1
                && self.protected[server] >= 1
        };
        if done {
            Completion::Yes
        } else {
            Completion::Undecided
        }
    }

    /// An alert's two bytes: its level and its number.
    fn alert(&mut self, d: usize, body: &[u8]) {
        let [level, description] = *body else {
            return;
        };
        if level == 2 {
            self.fatal = true;
        }
        if self.alerts.len() < ALERTS_HELD {
            self.alerts.push(Alert {
                direction: d,
                level,
                description,
            });
        } else {
            self.alerts_more += 1;
        }
    }

    /// Handshake bytes, which one message may span several records of.
    fn hold(&mut self, layer: usize, d: usize, bytes: &[u8]) {
        if self.overflowed[layer][d] {
            return;
        }
        self.held[layer][d].extend_from_slice(bytes);
        if self.held[layer][d].len() > HANDSHAKE_BYTES_HELD {
            self.held[layer][d] = Vec::new();
            self.overflowed[layer][d] = true;
            return;
        }
        self.read_messages(layer, d);
    }

    fn read_messages(&mut self, layer: usize, d: usize) {
        loop {
            let held = &self.held[layer][d];
            if held.len() < 4 {
                return;
            }
            let len = usize::from(held[1]) << 16 | usize::from(held[2]) << 8 | usize::from(held[3]);
            if held.len() < 4 + len {
                return;
            }
            let kind = held[0];
            let body: Vec<u8> = held[4..4 + len].to_vec();
            self.held[layer][d].drain(..4 + len);
            match kind {
                HS_CLIENT_HELLO if layer == CLEAR => {
                    self.client = Some(d);
                    if let Some(sni) = client_hello_sni(&body) {
                        self.sni = Some(sni);
                    }
                }
                HS_SERVER_HELLO if layer == CLEAR => {
                    if self.client.is_none() {
                        self.client = Some(1 - d);
                    }
                    self.version = server_hello_version(&body);
                }
                HS_CERTIFICATE if self.certificate.is_none() && self.client != Some(d) => {
                    // TLS 1.3 puts a request context before the list and
                    // extensions after each entry (RFC 8446 section 4.4.2).
                    self.certificate = match self.version {
                        Some(v) if v >= TLS_1_3 => first_certificate_13(&body),
                        _ => first_certificate(&body),
                    };
                }
                _ => {}
            }
        }
    }
}

/// A cursor over big-endian length-prefixed fields.
struct Reader<'b>(&'b [u8]);

impl<'b> Reader<'b> {
    fn take(&mut self, n: usize) -> Option<&'b [u8]> {
        let (head, rest) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    /// A field whose length is `prefix` bytes wide.
    fn vec(&mut self, prefix: usize) -> Option<&'b [u8]> {
        let n = match prefix {
            1 => self.u8()?,
            2 => self.u16()?,
            _ => self.u24()?,
        };
        self.take(n)
    }
}

/// The extensions of a hello whose fields before them `skip` reads past.
fn extensions<'b>(
    body: &'b [u8],
    skip: impl FnOnce(&mut Reader<'b>) -> Option<()>,
) -> Option<Vec<(u16, &'b [u8])>> {
    let mut r = Reader(body);
    skip(&mut r)?;
    let mut list = Reader(r.vec(2)?);
    let mut out = Vec::new();
    while !list.0.is_empty() {
        let kind = list.u16()? as u16;
        out.push((kind, list.vec(2)?));
    }
    Some(out)
}

/// The `host_name` a ClientHello's `server_name` extension names.
fn client_hello_sni(body: &[u8]) -> Option<String> {
    let exts = extensions(body, |r| {
        r.take(2 + 32)?;
        r.vec(1)?;
        r.vec(2)?;
        r.vec(1)?;
        Some(())
    })?;
    let (_, value) = exts.into_iter().find(|(k, _)| *k == EXT_SERVER_NAME)?;
    let mut names = Reader(Reader(value).vec(2)?);
    while !names.0.is_empty() {
        let kind = names.u8()?;
        let name = names.vec(2)?;
        if kind == 0 {
            return core::str::from_utf8(name).ok().map(String::from);
        }
    }
    None
}

/// The version a ServerHello chose: its `supported_versions` selection when it
/// carries one, its legacy version otherwise.
fn server_hello_version(body: &[u8]) -> Option<u16> {
    let legacy = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let exts = extensions(body, |r| {
        r.take(2 + 32)?;
        r.vec(1)?;
        r.take(2 + 1)?;
        Some(())
    });
    let selected = exts
        .into_iter()
        .flatten()
        .find(|(k, v)| *k == EXT_SUPPORTED_VERSIONS && v.len() == 2)
        .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]));
    Some(selected.unwrap_or(legacy))
}

/// The first certificate of a TLS 1.2 Certificate message: the list's length,
/// then each certificate's length and DER.
fn first_certificate(body: &[u8]) -> Option<Certificate> {
    let mut list = Reader(Reader(body).vec(3)?);
    certificate(list.vec(3)?)
}

/// The first certificate of a TLS 1.3 Certificate message: the request
/// context, then the list, whose first entry starts with the DER.
fn first_certificate_13(body: &[u8]) -> Option<Certificate> {
    let mut r = Reader(body);
    r.vec(1)?;
    let mut list = Reader(r.vec(3)?);
    certificate(list.vec(3)?)
}

/// One DER element: its tag, its contents and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, at) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len << 8 | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let contents = b.get(at..at.checked_add(len)?)?;
    Some((tag, contents, &b[at + len..]))
}

/// Subject, issuer and validity out of a certificate's DER (RFC 5280 section
/// 4.1).
fn certificate(der: &[u8]) -> Option<Certificate> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // The optional explicit version, [0].
    if rest.first() == Some(&0xA0) {
        rest = tlv(rest)?.2;
    }
    let (_, _, rest) = tlv(rest)?; // serialNumber
    let (_, _, rest) = tlv(rest)?; // signature
    let (_, issuer, rest) = tlv(rest)?;
    let (_, validity, rest) = tlv(rest)?;
    let (_, subject, _) = tlv(rest)?;
    let (before_tag, before, after) = tlv(validity)?;
    let (after_tag, after, _) = tlv(after)?;
    Some(Certificate {
        subject: name(subject)?,
        issuer: name(issuer)?,
        not_before: time(before_tag, before)?,
        not_after: time(after_tag, after)?,
    })
}

/// A distinguished name as `KEY=value` pairs, comma-separated, in the order
/// the certificate writes them.
fn name(mut rdns: &[u8]) -> Option<String> {
    let mut out = String::new();
    while !rdns.is_empty() {
        let (_, set, rest) = tlv(rdns)?;
        rdns = rest;
        let mut set = set;
        while !set.is_empty() {
            let (_, pair, rest) = tlv(set)?;
            set = rest;
            let (_, oid, value) = tlv(pair)?;
            let (_, text, _) = tlv(value)?;
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(&attribute(oid));
            out.push('=');
            out.push_str(&String::from_utf8_lossy(text));
        }
    }
    Some(out)
}

/// An attribute type's short name, or its dotted OID.
fn attribute(oid: &[u8]) -> String {
    let short = match oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x07] => Some("L"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x0A] => Some("O"),
        [0x55, 0x04, 0x0B] => Some("OU"),
        _ => None,
    };
    if let Some(short) = short {
        return String::from(short);
    }
    use core::fmt::Write as _;
    let mut dotted = String::new();
    let mut value = 0u64;
    for byte in oid {
        value = value << 7 | u64::from(byte & 0x7F);
        if byte & 0x80 != 0 {
            continue;
        }
        // The first subidentifier holds the first two arcs (X.690 8.19.4).
        if dotted.is_empty() {
            let (a, b) = if value < 80 {
                (value / 40, value % 40)
            } else {
                (2, value - 80)
            };
            let _ = write!(dotted, "{a}.{b}");
        } else {
            let _ = write!(dotted, ".{value}");
        }
        value = 0;
    }
    dotted
}

/// A UTCTime (`YYMMDDHHMMSSZ`) or a GeneralizedTime (`YYYYMMDDHHMMSSZ`) as
/// `YYYY-MM-DDTHH:MM:SSZ`.
fn time(tag: u8, text: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(text).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let full = match (tag, digits.len()) {
        // RFC 5280 section 4.1.2.5.1: a two-digit year of 50 or more is 19YY.
        (0x17, 12) => {
            let century = if digits.as_bytes()[0] >= b'5' {
                "19"
            } else {
                "20"
            };
            alloc::format!("{century}{digits}")
        }
        (0x18, 14) => String::from(digits),
        _ => return None,
    };
    Some(alloc::format!(
        "{}-{}-{}T{}:{}:{}Z",
        &full[0..4],
        &full[4..6],
        &full[6..8],
        &full[8..10],
        &full[10..12],
        &full[12..14]
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    /// A record of `content_type` carrying `body`.
    pub(crate) fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![content_type, 0x03, 0x03];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    fn u16_vec(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn u24_vec(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend_from_slice(body);
        out
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16_vec(data));
        out
    }

    /// A ClientHello record asking for `sni`.
    pub(crate) fn client_hello(sni: &str) -> Vec<u8> {
        let mut entry = vec![0u8];
        entry.extend_from_slice(&u16_vec(sni.as_bytes()));
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&u16_vec(&[0x13, 0x01]));
        body.extend_from_slice(&[1, 0]);
        let mut exts = extension(EXT_SERVER_NAME, &u16_vec(&entry));
        exts.extend_from_slice(&extension(
            EXT_SUPPORTED_VERSIONS,
            &[4, 0x03, 0x04, 0x03, 0x03],
        ));
        body.extend_from_slice(&u16_vec(&exts));
        record(CT_HANDSHAKE, &message(HS_CLIENT_HELLO, &body))
    }

    /// A ServerHello choosing TLS 1.3 when `thirteen`, TLS 1.2 otherwise.
    pub(crate) fn server_hello(thirteen: bool) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[9u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let exts = if thirteen {
            extension(EXT_SUPPORTED_VERSIONS, &[0x03, 0x04])
        } else {
            Vec::new()
        };
        body.extend_from_slice(&u16_vec(&exts));
        record(CT_HANDSHAKE, &message(HS_SERVER_HELLO, &body))
    }

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    fn dn(pairs: &[(&[u8], &str)]) -> Vec<u8> {
        let mut rdns = Vec::new();
        for (oid, value) in pairs {
            let mut pair = der(0x06, oid);
            pair.extend_from_slice(&der(0x0C, value.as_bytes()));
            rdns.extend_from_slice(&der(0x31, &der(0x30, &pair)));
        }
        der(0x30, &rdns)
    }

    /// A certificate's DER whose subject is `CN=router,O=Acme` and whose issuer
    /// is `CN=Acme CA,1.2.840.113549.1.9.1=ca@acme`.
    pub(crate) fn certificate_der() -> Vec<u8> {
        let mut tbs = der(0xA0, &der(0x02, &[2]));
        tbs.extend_from_slice(&der(0x02, &[0x01, 0x23]));
        tbs.extend_from_slice(&der(
            0x30,
            &der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2]),
        ));
        tbs.extend_from_slice(&dn(&[
            (&[0x55, 0x04, 0x03], "Acme CA"),
            (
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01],
                "ca@acme",
            ),
        ]));
        let mut validity = der(0x17, b"991231235959Z");
        validity.extend_from_slice(&der(0x18, b"20501231235959Z"));
        tbs.extend_from_slice(&der(0x30, &validity));
        tbs.extend_from_slice(&dn(&[
            (&[0x55, 0x04, 0x03], "router"),
            (&[0x55, 0x04, 0x0A], "Acme"),
        ]));
        let mut cert = der(0x30, &tbs);
        cert.extend_from_slice(&der(
            0x30,
            &der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2]),
        ));
        cert.extend_from_slice(&der(0x03, &[0, 1, 2, 3]));
        der(0x30, &cert)
    }

    fn expected_certificate() -> Certificate {
        Certificate {
            subject: String::from("CN=router,O=Acme"),
            issuer: String::from("CN=Acme CA,1.2.840.113549.1.9.1=ca@acme"),
            not_before: String::from("1999-12-31T23:59:59Z"),
            not_after: String::from("2050-12-31T23:59:59Z"),
        }
    }

    /// A TLS 1.2 handshake whose client refused the server's certificate:
    /// direction `a` is the client.
    pub(crate) fn refused_by_the_client() -> TlsHandshake {
        let mut h = TlsHandshake::default();
        h.observe(0, &client_hello("router.local"));
        h.observe(1, &server_hello(false));
        let list = u24_vec(&u24_vec(&certificate_der()));
        h.observe(1, &record(CT_HANDSHAKE, &message(HS_CERTIFICATE, &list)));
        h.observe(0, &record(CT_ALERT, &[2, 48]));
        h
    }

    /// A TLS 1.3 handshake that completed, `b` the client.
    pub(crate) fn completed_with_b_the_client() -> TlsHandshake {
        let mut h = TlsHandshake::default();
        h.observe(1, &client_hello("peer"));
        h.observe(0, &server_hello(true));
        h.observe(0, &record(CT_CHANGE_CIPHER_SPEC, &[1]));
        h.observe(0, &record(CT_APPLICATION_DATA, &[0; 40]));
        h.observe(1, &record(CT_CHANGE_CIPHER_SPEC, &[1]));
        h.observe(1, &record(CT_APPLICATION_DATA, &[0; 40]));
        h.observe(1, &record(CT_APPLICATION_DATA, &[0; 40]));
        h
    }

    /// Handshakes that between them hold every word a document writes. Its one reader is the
    /// document's test (`fields_json`), which is behind `dissect`.
    #[cfg(feature = "dissect")]
    pub(crate) fn every_word() -> Vec<TlsHandshake> {
        let mut only_hello = TlsHandshake::default();
        only_hello.observe(0, &client_hello("x"));
        vec![
            refused_by_the_client(),
            completed_with_b_the_client(),
            only_hello,
        ]
    }

    #[test]
    fn a_refused_certificate_names_its_alert_and_the_certificate() {
        let h = refused_by_the_client();
        assert_eq!(h.sni.as_deref(), Some("router.local"));
        assert_eq!(h.version, Some(0x0303));
        assert_eq!(h.client, Some(0));
        assert_eq!(
            h.alerts,
            vec![Alert {
                direction: 0,
                level: 2,
                description: 48
            }]
        );
        assert_eq!(h.certificate, Some(expected_certificate()));
        assert_eq!(h.completion(), Completion::No);
    }

    #[test]
    fn a_completed_tls_1_3_handshake_reads_yes_and_names_no_certificate() {
        let h = completed_with_b_the_client();
        assert_eq!(h.version, Some(TLS_1_3));
        assert_eq!(h.client, Some(1));
        assert_eq!(h.certificate, None);
        assert_eq!(h.completion(), Completion::Yes);
        // One protected record short of the client's Finished and data.
        let mut short = TlsHandshake::default();
        short.observe(1, &client_hello("peer"));
        short.observe(0, &server_hello(true));
        short.observe(0, &record(CT_APPLICATION_DATA, &[0; 40]));
        short.observe(1, &record(CT_APPLICATION_DATA, &[0; 40]));
        assert_eq!(short.completion(), Completion::Undecided);
    }

    #[test]
    fn a_hello_split_over_two_records_is_read_once_whole() {
        let hello = client_hello("split.example");
        let body = &hello[5..];
        let (first, second) = body.split_at(20);
        let mut h = TlsHandshake::default();
        h.observe(0, &record(CT_HANDSHAKE, first));
        assert_eq!(h.sni, None);
        h.observe(0, &record(CT_HANDSHAKE, second));
        assert_eq!(h.sni.as_deref(), Some("split.example"));
    }

    #[test]
    fn an_alert_after_a_change_of_cipher_spec_is_not_read_in_the_clear() {
        let mut h = TlsHandshake::default();
        h.observe(0, &client_hello("x"));
        h.observe(1, &server_hello(false));
        h.observe(0, &record(CT_CHANGE_CIPHER_SPEC, &[1]));
        h.observe(0, &record(CT_ALERT, &[2, 48]));
        assert!(h.alerts.is_empty());
        assert_eq!(h.completion(), Completion::Undecided);
    }

    #[test]
    fn a_tls_1_3_alert_and_certificate_are_read_out_of_opened_records() {
        let mut h = TlsHandshake::default();
        h.observe(0, &client_hello("router.local"));
        h.observe(1, &server_hello(true));
        // The server's Certificate, as its opened record's plaintext: a
        // request context, then one entry with its extensions.
        let mut entry = u24_vec(&certificate_der());
        entry.extend_from_slice(&u16_vec(&[]));
        let mut body = vec![0u8];
        body.extend_from_slice(&u24_vec(&entry));
        h.observe_opened(1, CT_HANDSHAKE, &message(HS_CERTIFICATE, &body));
        h.observe_opened(0, CT_ALERT, &[2, 48]);
        assert_eq!(h.certificate, Some(expected_certificate()));
        assert_eq!(h.alerts.len(), 1);
        assert_eq!(h.alerts[0].direction, 0);
        assert_eq!(h.completion(), Completion::No);
    }

    #[test]
    fn alerts_past_the_bound_are_counted() {
        let mut h = TlsHandshake::default();
        for _ in 0..ALERTS_HELD + 3 {
            h.observe(0, &record(CT_ALERT, &[1, 0]));
        }
        assert_eq!(h.alerts.len(), ALERTS_HELD);
        assert_eq!(h.alerts_more, 3);
        // A warning is not fatal.
        assert_eq!(h.completion(), Completion::Undecided);
    }

    /// THE CLAIM'S OWN CASE, through a capture: a client that does not trust
    /// the server's CA refuses its certificate, and the field document says
    /// with which alert, and whose certificate it was.
    #[cfg(all(feature = "fixtures", feature = "dissect"))]
    #[test]
    fn a_capture_of_a_refused_certificate_names_the_alert_on_its_flow() {
        let list = u24_vec(&u24_vec(&certificate_der()));
        let mut server = server_hello(false);
        server.extend_from_slice(&record(CT_HANDSHAKE, &message(HS_CERTIFICATE, &list)));
        let hello = client_hello("router.local");
        let alert = record(CT_ALERT, &[2, 48]);
        let file = crate::fixtures::tcp_connection_capture(&[
            (true, &hello),
            (false, &server),
            (true, &alert),
        ]);
        let d = crate::Dissection::from_capture(&file).expect("the capture reads");
        let crate::Framing::Encrypted(state) = d.flows()[0].framing() else {
            panic!("the flow is TLS: {:?}", d.flows()[0].framing());
        };
        assert_eq!(state.handshake().alerts[0].description, 48);
        let doc = crate::fields_json::fields_json(&d, &file, None, None);
        assert!(
            doc.contains(
                "\"handshake\":{\"tls\":{\"sni\":\"router.local\",\"version\":771,\
                 \"client\":\"a\",\"completed\":\"no\",\"alerts\":[{\"direction\":\"a\",\
                 \"level\":2,\"description\":48}],\"alerts_more\":0,\
                 \"certificate\":{\"subject\":\"CN=router,O=Acme\""
            ),
            "{doc}"
        );
        assert!(doc.contains("\"websocket\":null,\"quic\":null}"), "{doc}");
    }

    #[test]
    fn a_malformed_certificate_names_none_and_does_not_panic() {
        let der = certificate_der();
        for cut in 0..der.len() {
            assert_eq!(certificate(&der[..cut]), None, "cut at {cut}");
        }
        assert_eq!(time(0x17, b"9912312359Z"), None);
        assert_eq!(time(0x17, b"99123123595xZ"), None);
    }
}
