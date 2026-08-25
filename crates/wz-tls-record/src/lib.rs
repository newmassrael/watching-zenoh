// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y657 (§1.2a) — the TLS 1.3 RECORD layer: a traffic secret and a
//! ciphertext record in, the plaintext and its real content type out.
//!
//! ## Why this is a crate and not a module of `wz-capture`
//!
//! R311y648 through R311y650 taught `wz-capture` to RECOGNISE an encrypted
//! flow — to say "this is TLS, here is how much of it there was, and I cannot
//! see inside" instead of reporting an idle connection. Recognition is worth
//! more than decryption and it came first, but it is not the end: a reader
//! shown a census still cannot see the session.
//!
//! `wz-capture` carries zero third-party dependencies, and that is load-bearing
//! rather than aesthetic — the same decode path builds for the MCU profiles.
//! So the cipher goes on the far side of the seam that crate already draws (its
//! module doc: the boundary is a byte stream plus a direction), and this is
//! that side.
//!
//! ## Where the split actually falls, and why it was not a choice
//!
//! It was read off the pinned versions rather than preferred:
//!
//! - `ring` 0.17.14 makes `hkdf::Prk::new_less_safe` public (`src/hkdf.rs:117`)
//!   — the entry point for a caller who ALREADY HOLDS a secret, which is
//!   exactly the position an offline analyzer is in. Its `aead::LessSafeKey`
//!   opens a record with an explicitly supplied nonce.
//! - rustls 0.23.40 keeps `hkdf_expand_label` `pub(crate)`
//!   (`src/tls13/key_schedule.rs:889`). The label encoding, the key/iv
//!   derivation, the per-record nonce and the AAD are not reachable.
//!
//! So the PRIMITIVES are borrowed and the TLS 1.3 PROTOCOL LAYER is this
//! crate's own. That is the correct division for a wire analyzer in any case:
//! the protocol layer is the part a capture disagrees with.
//!
//! ## What is here and what is deliberately not
//!
//! Here: [`HkdfLabel`] encoding (RFC 8446 §7.1), [`TrafficKeys::derive`],
//! the nonce construction (RFC 8446 §5.3), and [`TrafficKeys::open`] which
//! takes a whole record so the AAD is the record's own header.
//!
//! Not here, and not by omission: the handshake, the key schedule ABOVE a
//! traffic secret (this crate starts at `{client,server}_traffic_secret_N`,
//! which is what a keylog or a pcapng Decryption Secrets Block carries), key
//! update, TLS 1.2, and QUIC. Each of those is its own decision.

pub mod capture;
pub mod keylog;
pub mod quic;

use ring::aead;
use ring::hkdf;

/// The three TLS 1.3 cipher suites, as a capture can name them.
///
/// A closed set because RFC 8446 defines a closed set: five suites, of which
/// the two CCM ones are not offered by any zenoh stack this workspace builds
/// against, and adding one is a decision with a round behind it rather than a
/// match arm someone widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `TLS_AES_128_GCM_SHA256` (0x1301).
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (0x1302).
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
    Chacha20Poly1305Sha256,
}

impl Suite {
    /// The suite's wire code point, as it appears in a ServerHello.
    pub fn code_point(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// The suite a code point names, or `None` for one this crate does not
    /// carry — REFUSED rather than defaulted, because a wrong suite produces a
    /// confident failure to decrypt that reads exactly like a wrong key.
    pub fn from_code_point(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    fn hkdf_algorithm(self) -> hkdf::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => hkdf::HKDF_SHA256,
            Self::Aes256GcmSha384 => hkdf::HKDF_SHA384,
        }
    }

    pub(crate) fn aead_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    /// The AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        self.aead_algorithm().key_len()
    }

    /// R311y694 — the HASH length in bytes, which is the width of a traffic
    /// secret this suite produces.
    ///
    /// Distinct from [`Self::key_len`] and worth its own accessor for the one
    /// suite where they differ: AES-256-GCM-SHA384 has a 32-byte key and a
    /// 48-byte secret, so a caller sizing a secret by the key length derives
    /// two thirds of one and gets a confident failure to decrypt.
    pub fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }

    /// R311y694 — the header-protection algorithm QUIC uses with this suite
    /// (RFC 9001 §5.4.3).
    ///
    /// A SEPARATE algorithm family from the AEAD: header protection is a raw
    /// block operation (AES-ECB, or a ChaCha20 block) rather than an
    /// authenticated one, and `ring` models it as such.
    pub(crate) fn quic_hp_algorithm(self) -> &'static aead::quic::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::quic::AES_128,
            Self::Aes256GcmSha384 => &aead::quic::AES_256,
            Self::Chacha20Poly1305Sha256 => &aead::quic::CHACHA20,
        }
    }
}

/// The record header's fixed width: type, legacy version, length.
pub const RECORD_HEADER: usize = 5;

/// The AEAD nonce width every TLS 1.3 suite uses (RFC 8446 §5.3).
pub const NONCE_LEN: usize = 12;

/// RFC 8446 §7.1 — the `HkdfLabel` structure, encoded.
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// Written out here rather than borrowed because rustls keeps its own copy
/// private, and because this is the structure a capture disagrees with: an
/// implementation that omits the `"tls13 "` prefix, or that writes the output
/// length in the wrong byte order, derives keys that decrypt nothing — and the
/// failure is indistinguishable from a wrong secret unless the encoding itself
/// is under test.
///
/// `context` is always empty for the two labels this crate uses (`key` and
/// `iv`), and the parameter is kept anyway: a caller deriving `finished` or a
/// resumption secret needs it, and a function that silently could not express
/// it would be discovered by whoever adds one.
pub fn hkdf_label(output_len: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    out.extend_from_slice(&output_len.to_be_bytes());
    // The prefixed label is length-delimited by a SINGLE byte, and RFC 8446
    // bounds it at 255 -- with the 6-byte prefix that caps `label` at 249. A
    // caller cannot reach that with any label in the RFC, so this is an
    // assertion of the encoding's own invariant rather than input validation.
    let prefixed = 6 + label.len();
    debug_assert!(prefixed <= 255, "HkdfLabel label is a one-byte length");
    out.push(prefixed as u8);
    out.extend_from_slice(b"tls13 ");
    out.extend_from_slice(label);
    debug_assert!(
        context.len() <= 255,
        "HkdfLabel context is a one-byte length"
    );
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

/// `ring`'s expand needs a `KeyType` to say how many bytes come out; a TLS
/// caller knows the length as a number.
struct ByteLen(usize);

impl hkdf::KeyType for ByteLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// RFC 8446 §7.1 — `HKDF-Expand-Label`.
///
/// The one place the label structure and the expand are joined, so a caller
/// cannot build a label and expand it with a different length than the one
/// encoded inside it. That mismatch is legal to write, produces key material,
/// and is wrong.
pub fn expand_label(suite: Suite, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let prk = hkdf::Prk::new_less_safe(suite.hkdf_algorithm(), secret);
    let info = hkdf_label(out.len() as u16, label, context);
    let info = [info.as_slice()];
    let okm = prk
        .expand(&info, ByteLen(out.len()))
        .expect("output length is bounded by 255 * HashLen for every TLS label");
    okm.fill(out)
        .expect("the okm was built for exactly this length");
}

/// One direction's record-protection keys, derived from its traffic secret.
///
/// A direction rather than a connection: TLS 1.3 numbers the two directions
/// separately and re-derives on every key update, so "the connection's key" is
/// not a thing that exists.
#[derive(Clone)]
pub struct TrafficKeys {
    suite: Suite,
    key: Vec<u8>,
    iv: [u8; NONCE_LEN],
}

impl core::fmt::Debug for TrafficKeys {
    /// Prints the SUITE and nothing else. A `Debug` that spilled key material
    /// into a log would undo the reason a capture tool is trusted with it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficKeys")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .finish()
    }
}

impl TrafficKeys {
    /// RFC 8446 §7.3 — derive `key` and `iv` from a traffic secret.
    ///
    /// The secret is what a keylog line or a pcapng Decryption Secrets Block
    /// carries (`CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, and the
    /// handshake pair), which is why this crate starts here rather than at the
    /// handshake.
    pub fn derive(suite: Suite, traffic_secret: &[u8]) -> Self {
        let mut key = vec![0u8; suite.key_len()];
        expand_label(suite, traffic_secret, b"key", &[], &mut key);
        let mut iv = [0u8; NONCE_LEN];
        expand_label(suite, traffic_secret, b"iv", &[], &mut iv);
        Self { suite, key, iv }
    }

    /// The suite these keys protect records with.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// RFC 8446 §5.3 — the per-record nonce.
    ///
    /// The record sequence number, big-endian, left-padded to the IV's width
    /// and XORed with the IV. The padding is the part that is easy to get
    /// wrong and impossible to notice on the first record: with `seq == 0`
    /// every construction agrees, so a nonce built by XORing an 8-byte sequence
    /// into the FRONT of the IV opens record 0 and nothing after it.
    pub fn nonce(&self, seq: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        let seq = seq.to_be_bytes();
        for (n, s) in nonce[NONCE_LEN - seq.len()..].iter_mut().zip(seq.iter()) {
            *n ^= *s;
        }
        nonce
    }

    /// Open one record IN PLACE.
    ///
    /// `record` is the WHOLE record, header included, because the header is
    /// the AAD (RFC 8446 §5.2) — passing the ciphertext alone would leave the
    /// caller to reconstruct five bytes it already has, and a reconstruction
    /// that disagrees with the wire authenticates nothing.
    ///
    /// Returns where the plaintext is and what content type it really was: TLS
    /// 1.3 puts the true type at the END of the plaintext, after any zero
    /// padding, and writes `application_data` in the header of every record
    /// including handshake ones.
    pub fn open<'a>(&self, seq: u64, record: &'a mut [u8]) -> Result<Opened<'a>, OpenError> {
        if record.len() < RECORD_HEADER {
            return Err(OpenError::Truncated);
        }
        let (header, body) = record.split_at_mut(RECORD_HEADER);
        let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if body.len() < declared {
            return Err(OpenError::Truncated);
        }
        let body = &mut body[..declared];
        let key = aead::UnboundKey::new(self.suite.aead_algorithm(), &self.key)
            .map_err(|_| OpenError::BadKeyLength)?;
        let key = aead::LessSafeKey::new(key);
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(seq));
        // The AAD is the header bytes as they are ON THE WIRE, not a header
        // this reader rebuilt from what it expects them to say.
        let aad = aead::Aad::from(&*header);
        let plain_len = key
            .open_in_place(nonce, aad, body)
            .map_err(|_| OpenError::Unauthenticated)?
            .len();
        let plain = &body[..plain_len];
        // RFC 8446 §5.4: strip zero padding from the end; the last non-zero
        // byte is the real content type. A record that is all padding carries
        // no type and is malformed rather than empty.
        let end = plain
            .iter()
            .rposition(|b| *b != 0)
            .ok_or(OpenError::NoContentType)?;
        Ok(Opened {
            content_type: plain[end],
            plaintext: &body[..end],
        })
    }
}

/// What one opened record turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened<'a> {
    /// The REAL content type, taken from the end of the plaintext. The header's
    /// type is `application_data` on every TLS 1.3 record and says nothing.
    pub content_type: u8,
    /// The plaintext, with the type byte and any padding removed.
    pub plaintext: &'a [u8],
}

/// Why a record did not open.
///
/// An enum rather than a bool for the reason [`crate::Suite::from_code_point`]
/// refuses instead of defaulting: "the tag did not verify" and "this record was
/// cut off by the capture" are different facts about the CAPTURE, and a reader
/// chasing a decryption failure acts on them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Fewer bytes than the record's own header says it has — where the
    /// capture stopped, not a decode failure.
    Truncated,
    /// The AEAD tag did not verify: a wrong secret, a wrong sequence number, a
    /// wrong suite, or a record this key never protected.
    Unauthenticated,
    /// The key material is not the length the suite requires.
    BadKeyLength,
    /// The plaintext was entirely padding, so no content type is in it.
    NoContentType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::{AeadKey, Iv, OutboundPlainMessage};
    use rustls::crypto::tls13::OkmBlock;

    /// The three suites, paired with the rustls objects that are this crate's
    /// oracle. `aead_alg` and `hkdf_provider` are public fields of
    /// `rustls::Tls13CipherSuite` (rustls-0.23.40 src/tls13/mod.rs:21,28),
    /// reached through the public suite statics.
    fn oracle(suite: Suite) -> &'static rustls::Tls13CipherSuite {
        let s = match suite {
            Suite::Aes128GcmSha256 => rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            Suite::Aes256GcmSha384 => rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            Suite::Chacha20Poly1305Sha256 => {
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
        };
        // R311y657 — `SupportedCipherSuite::tls13()` rather than a match on the
        // enum, and the reason is a MEASUREMENT: how many variants that enum
        // has depends on whether anything in the build turned on rustls's
        // `tls12` feature. Matched exhaustively, this compiles alone and fails
        // `cargo test --workspace` (E0004, a variant appears); given a wildcard
        // arm, it compiles under the workspace and fails `-D warnings` alone
        // (the arm is unreachable). Only the workspace lane sees the first half
        // and only the isolated one sees the second, so the accessor -- which
        // rustls cfgs internally -- is the only spelling that is right in both.
        s.tls13().expect("the statics above are TLS 1.3 suites")
    }

    /// R311y657 — rustls can SEAL for this crate only where its public API lets
    /// a caller hand it a key, and that is a MEASURED limit rather than a
    /// choice: `AeadKey`'s only public constructor is `From<[u8; 32]>`
    /// (rustls-0.23.40 src/crypto/cipher.rs:327) and `AeadKey::new(&[u8])` is
    /// `pub(crate)`. So the sealing oracle is reachable for the two 32-byte
    /// suites and NOT for `TLS_AES_128_GCM_SHA256`, whose key is 16.
    ///
    /// Stated here rather than worked around. The alternative -- sealing the
    /// 16-byte suite with `ring`, this crate's own dependency -- would mean
    /// writing the nonce and the AAD a second time in the test, where the
    /// second copy can share the first one's mistake. The AES-128 derivation is
    /// still differential (the key-schedule test covers all three), and only
    /// its RECORD leg rides on the other two suites exercising the same code
    /// with a different algorithm object.
    fn sealing_key(keys: &TrafficKeys) -> Option<AeadKey> {
        let k: [u8; 32] = keys.key.as_slice().try_into().ok()?;
        Some(AeadKey::from(k))
    }

    const SUITES: [Suite; 3] = [
        Suite::Aes128GcmSha256,
        Suite::Aes256GcmSha384,
        Suite::Chacha20Poly1305Sha256,
    ];

    /// A traffic secret of the suite's hash length. Not random: a fixture that
    /// varies per run cannot be quoted in a failure report.
    fn secret(suite: Suite, seed: u8) -> Vec<u8> {
        let len = match suite {
            Suite::Aes256GcmSha384 => 48,
            _ => 32,
        };
        (0..len).map(|i| seed ^ (i as u8).wrapping_mul(7)).collect()
    }

    /// R311y657 — THE DERIVATION IS DIFFERENTIAL, not self-consistent.
    ///
    /// This crate's `expand_label` and rustls's own key schedule are two
    /// independent implementations of RFC 8446 §7.1, and they must produce the
    /// same key and the same iv from the same secret. rustls's
    /// `hkdf_expand_label` is `pub(crate)`, so the oracle is assembled from the
    /// pieces it DOES export -- `expander_for_okm` plus `expand_slice` -- and
    /// this crate's own `hkdf_label` bytes are deliberately NOT reused for it.
    /// The label structure is rebuilt here by hand, so an error in
    /// `hkdf_label` cannot cancel itself out.
    #[test]
    fn the_key_schedule_agrees_with_rustls_for_every_suite() {
        for suite in SUITES {
            let secret = secret(suite, 0xA5);
            let ours = TrafficKeys::derive(suite, &secret);
            let expander = oracle(suite)
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(&secret));

            // The label structure, rebuilt by hand rather than called: an
            // oracle that shares the code under test proves nothing.
            let by_hand = |label: &[u8], len: u16| -> Vec<u8> {
                let mut v = len.to_be_bytes().to_vec();
                v.push((6 + label.len()) as u8);
                v.extend_from_slice(b"tls13 ");
                v.extend_from_slice(label);
                v.push(0);
                v
            };

            let mut their_key = vec![0u8; suite.key_len()];
            expander
                .expand_slice(&[&by_hand(b"key", suite.key_len() as u16)], &mut their_key)
                .unwrap();
            let mut their_iv = [0u8; NONCE_LEN];
            expander
                .expand_slice(&[&by_hand(b"iv", NONCE_LEN as u16)], &mut their_iv)
                .unwrap();

            assert_eq!(ours.key, their_key, "key disagrees for {suite:?}");
            assert_eq!(ours.iv, their_iv, "iv disagrees for {suite:?}");
        }
    }

    /// R311y657 — AND THE RECORD OPENS: rustls seals, this crate opens.
    ///
    /// The strongest leg available offline, and the one that gates the parts
    /// rustls does not export: the per-record nonce, the header-as-AAD, and the
    /// content type hidden at the end of the plaintext. A round trip through
    /// this crate's own seal would gate none of them, because every mistake
    /// would be made twice and cancel.
    ///
    /// Driven at SEQUENCE NUMBERS PAST ZERO on purpose. At `seq == 0` every
    /// nonce construction agrees -- XOR with zero is the identity -- so a
    /// fixture that only ever opened the first record of a connection would
    /// pass with the sequence padded into the wrong end of the IV.
    #[test]
    fn a_record_rustls_sealed_opens_with_the_keys_this_crate_derived() {
        for suite in SUITES {
            let secret = secret(suite, 0x3C);
            let keys = TrafficKeys::derive(suite, &secret);
            let Some(sealing) = sealing_key(&keys) else {
                assert_eq!(
                    suite,
                    Suite::Aes128GcmSha256,
                    "exactly one suite is out of rustls's public reach; if a \
                     second one arrives here the oracle has silently narrowed"
                );
                continue;
            };
            let mut enc = oracle(suite).aead_alg.encrypter(sealing, Iv::from(keys.iv));

            for seq in [0u64, 1, 2, 255, 256, 65_536, 0x0102_0304_0506_0708] {
                let payload: Vec<u8> = (0..37u8).map(|i| i.wrapping_mul(3)).collect();
                let sealed = enc
                    .encrypt(
                        OutboundPlainMessage {
                            typ: rustls::ContentType::ApplicationData,
                            version: rustls::ProtocolVersion::TLSv1_2,
                            payload: rustls::crypto::cipher::OutboundChunks::Single(&payload),
                        },
                        seq,
                    )
                    .unwrap();
                let mut record = sealed.encode();

                let opened = keys
                    .open(seq, &mut record)
                    .unwrap_or_else(|e| panic!("{suite:?} seq={seq}: {e:?}"));
                assert_eq!(opened.plaintext, &payload[..], "{suite:?} seq={seq}");
                assert_eq!(
                    opened.content_type,
                    u8::from(rustls::ContentType::ApplicationData),
                    "{suite:?} seq={seq}"
                );
            }
        }
    }

    /// THE DISCRIMINATOR the test above needs: a record opened at the WRONG
    /// sequence number must fail, or "it opened" says nothing about the nonce.
    ///
    /// This is the leg that makes the sequence numbers in the test above load
    /// bearing rather than decorative.
    #[test]
    fn a_record_opened_at_the_wrong_sequence_number_is_refused() {
        // A 32-byte suite, because the sealing oracle is only reachable there.
        let suite = Suite::Aes256GcmSha384;
        let keys = TrafficKeys::derive(suite, &secret(suite, 0x11));
        let mut enc = oracle(suite).aead_alg.encrypter(
            sealing_key(&keys).expect("a 32-byte suite"),
            Iv::from(keys.iv),
        );
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(b"zenoh"),
                },
                7,
            )
            .unwrap();
        let encoded = sealed.encode();

        assert_eq!(
            keys.open(7, &mut encoded.clone())
                .map(|o| o.plaintext.to_vec()),
            Ok(b"zenoh".to_vec()),
            "the control must open at its own sequence number"
        );
        for wrong in [0u64, 6, 8, 71] {
            assert_eq!(
                keys.open(wrong, &mut encoded.clone()).err(),
                Some(OpenError::Unauthenticated),
                "a record must not open at sequence {wrong}"
            );
        }
    }

    /// The header is the AAD, and this is what says so: flipping one byte of
    /// the header -- the length field, which a reader is most tempted to
    /// recompute -- must make the tag fail.
    #[test]
    fn the_header_is_authenticated_and_not_merely_skipped() {
        let suite = Suite::Chacha20Poly1305Sha256;
        let keys = TrafficKeys::derive(suite, &secret(suite, 0x77));
        let mut enc = oracle(suite).aead_alg.encrypter(
            sealing_key(&keys).expect("a 32-byte suite"),
            Iv::from(keys.iv),
        );
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(b"watching"),
                },
                3,
            )
            .unwrap();
        let encoded = sealed.encode();
        assert!(
            keys.open(3, &mut encoded.clone()).is_ok(),
            "the control opens"
        );

        // The legacy version byte: carried on the wire, meaningless to the
        // protocol, and INSIDE the AAD -- so a reader that normalised it would
        // authenticate a header the sender never wrote.
        let mut tampered = encoded.clone();
        tampered[2] ^= 0x01;
        assert_eq!(
            keys.open(3, &mut tampered).err(),
            Some(OpenError::Unauthenticated)
        );
    }

    /// A record shorter than its own header, and one whose body is shorter than
    /// the length it declares: TRUNCATED, which is where the capture stopped,
    /// and not `Unauthenticated`, which would send a reader looking for a wrong
    /// key.
    #[test]
    fn a_cut_off_record_is_named_truncated_rather_than_unauthenticated() {
        let keys = TrafficKeys::derive(Suite::Aes128GcmSha256, &[0u8; 32]);
        assert_eq!(
            keys.open(0, &mut [0x17, 0x03]).err(),
            Some(OpenError::Truncated)
        );
        let mut short = alloc_record(0x17, 40);
        short.truncate(RECORD_HEADER + 10);
        assert_eq!(keys.open(0, &mut short).err(), Some(OpenError::Truncated));
    }

    /// A header claiming `len` bytes, with `len` bytes of nothing behind it.
    fn alloc_record(content_type: u8, len: u16) -> Vec<u8> {
        let mut v = alloc::vec![content_type, 0x03, 0x03];
        v.extend_from_slice(&len.to_be_bytes());
        v.resize(RECORD_HEADER + usize::from(len), 0);
        v
    }

    /// R311y657 — the label ENCODING is pinned byte for byte, because every
    /// other test in this file would pass with a label that is wrong in a way
    /// both sides share. Two of the three fields here have been got wrong by
    /// real implementations: the output length is big-endian, and the label
    /// carries the `"tls13 "` prefix INSIDE its own one-byte length.
    #[test]
    fn the_hkdf_label_is_encoded_as_rfc_8446_writes_it() {
        assert_eq!(
            hkdf_label(16, b"key", &[]),
            alloc::vec![
                0x00, 0x10, 0x09, b't', b'l', b's', b'1', b'3', b' ', b'k', b'e', b'y', 0x00
            ],
        );
        assert_eq!(
            hkdf_label(12, b"iv", &[]),
            alloc::vec![0x00, 0x0C, 0x08, b't', b'l', b's', b'1', b'3', b' ', b'i', b'v', 0x00],
        );
        // A context is length-delimited and appended, which nothing else in
        // this crate exercises today -- and the field exists so whoever derives
        // `finished` does not have to widen this function under time pressure.
        assert_eq!(
            hkdf_label(4, b"x", &[0xAA, 0xBB]),
            alloc::vec![
                0x00, 0x04, 0x07, b't', b'l', b's', b'1', b'3', b' ', b'x', 0x02, 0xAA, 0xBB
            ],
        );
    }

    /// The nonce is the IV with the sequence XORed into its TAIL. Pinned
    /// against a hand-written expectation rather than against the code, because
    /// the failure mode is a sequence that lands in the wrong end and opens
    /// record zero perfectly.
    #[test]
    fn the_nonce_xors_the_sequence_into_the_tail_of_the_iv() {
        let keys = TrafficKeys {
            suite: Suite::Aes128GcmSha256,
            key: alloc::vec![0u8; 16],
            iv: [0xFF; NONCE_LEN],
        };
        assert_eq!(keys.nonce(0), [0xFF; NONCE_LEN], "seq 0 changes nothing");
        assert_eq!(
            keys.nonce(1),
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE],
        );
        assert_eq!(
            keys.nonce(0x0102_0304_0506_0708),
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7],
        );
    }

    /// A suite this crate does not carry is REFUSED, not defaulted: a wrong
    /// suite produces a confident failure to decrypt that reads exactly like a
    /// wrong key.
    #[test]
    fn an_unknown_cipher_suite_is_refused_rather_than_guessed() {
        for suite in SUITES {
            assert_eq!(Suite::from_code_point(suite.code_point()), Some(suite));
        }
        // 0x1304 and 0x1305 are the CCM suites: real TLS 1.3 code points that
        // this crate does not carry, which is exactly the case that must refuse
        // rather than fall through to AES-GCM.
        for unknown in [0x0000u16, 0x1300, 0x1304, 0x1305, 0xC02F] {
            assert_eq!(Suite::from_code_point(unknown), None, "{unknown:#06x}");
        }
    }

    /// Key material must not reach a log through `Debug`.
    #[test]
    fn the_debug_rendering_carries_no_key_material() {
        let keys = TrafficKeys::derive(Suite::Aes128GcmSha256, &[0x5A; 32]);
        let shown = alloc::format!("{keys:?}");
        assert!(shown.contains("redacted"), "{shown}");
        for byte in keys.key.iter().chain(keys.iv.iter()) {
            assert!(
                !shown.contains(&alloc::format!("{byte}")) || *byte < 10,
                "a key byte reached the Debug rendering: {shown}"
            );
        }
    }

    extern crate alloc;
}
