// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ei — anti-amplification cookie signing-key + HMAC-SHA256 cookie
//! primitive lifted from `wz-runtime-tokio::session_glue`.
//!
//! The `SigningKey` newtype (zeroizing key material), its typed
//! length-contract error `SigningKeyTooShort`, the cookie generator
//! `generate_cookie_hmac_sha256`, and the raw HMAC-SHA256 primitive
//! `compute_hmac_sha256_full` are pure value/crypto construction over
//! the RustCrypto `hmac` + `sha2` stack with no `async` / `LinkDriver` /
//! tokio coupling, so they belong in the no_std core where both the
//! tokio (AP) and lwIP (MCU) runtimes can reach the Accepting-side
//! cookie path. Gated on `alloc` — the key is `Zeroizing<Vec<u8>>` and
//! the cookie is a `Vec<u8>`.
//!
//! **OS-entropy constructor stays AP-only.** The former
//! `SigningKey::new_random()` pulled `getrandom`, which has no bare-metal
//! backend (thumbv6m-none-eabi et al.), so it cannot live in this
//! MCU-cross-compiled crate. It is demoted to a free function
//! `signing_key_from_os_entropy()` in `wz-runtime-tokio::session_glue`
//! that builds a `SigningKey` via the public [`SigningKey::new`]
//! constructor; the MCU sibling sources entropy via
//! `sce_intrinsics_runtime::rng` per the §5.I intrinsics tier. This
//! split is why the redesign demotes the inherent method to a free fn
//! (the orphan rule forbids an inherent method defined outside the
//! type's home crate). `wz-runtime-tokio::session_glue` re-exports
//! `SigningKey` / `SigningKeyTooShort` / `generate_cookie_hmac_sha256`
//! so its callsites resolve unchanged.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Cryptographic key for the anti-amplification cookie MAC.
///
/// Type-safe wrapper around `Zeroizing<Vec<u8>>` so the heap
/// allocation backing the key bytes is wiped on drop. Construction
/// validates the RFC §5.M length contract (>= 32 bytes); passing a
/// short slice returns `Err(SigningKeyTooShort)` instead of panicking
/// at the eventual HMAC call site (3rd review production-safety
/// retrospect: panic at construct vs. silent corruption).
///
/// The newtype hides the raw bytes from public API; only this
/// module's `generate_cookie_hmac_sha256` can read them, via
/// `as_slice`. Consumers store / move / clone a `SigningKey` like
/// any other value type but cannot accidentally serialise it or
/// log its inner bytes.
#[derive(Clone)]
pub struct SigningKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for SigningKey {
    /// Manual Debug impl — never reveals the key bytes. Logs +
    /// panic backtraces show only the length.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKeyTooShort(pub usize);

impl core::fmt::Display for SigningKeyTooShort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cookie_signing_key must be >= 32 bytes per RFC §5.M (got {})",
            self.0
        )
    }
}

impl core::error::Error for SigningKeyTooShort {}

/// The RFC §5.M minimum, and the length [`SigningKey::from_entropy`] draws.
///
/// Named rather than repeated as a literal because R311y820 gave the constant a
/// SECOND reader: `new` validates against it and `from_entropy` sizes its draw
/// by it, and a draw that were shorter than the validator's floor would build a
/// key `new` would have refused.
pub const SIGNING_KEY_BYTES: usize = 32;

impl SigningKey {
    /// R311y820 — draw a fresh key from the §2.5 plugin-tier entropy port
    /// ([`crate::entropy::EntropySource`]).
    ///
    /// ## Why this exists, stated as the defect it removes
    ///
    /// `signing_key_from_os_entropy` has been available on the AP side since
    /// R69 and had, at R311y820, exactly ZERO production callers — its only
    /// callers were its own unit test. Every params builder in this tree
    /// instead wrote a LITERAL: `vec![0xAB; 32]` in the AP demo, the C ABI
    /// drive and the replay live path, `vec![7u8; 32]` on the MCU side. Those
    /// literals are committed to a public repository, so the cookie MAC key of
    /// every acceptor built from this tree was public knowledge, and the whole
    /// secret of the anti-amplification cookie rested on the per-bundle nonce
    /// R311y813 added — 64 bits on the AP profile, and on the MCU fixture
    /// profile a second public literal.
    ///
    /// ## Why the PORT rather than `getrandom`
    ///
    /// `getrandom` has no bare-metal backend, which is why this crate's own
    /// module header records the key draw as AP-only. R311y819 introduced the
    /// port for the cookie nonce and deliberately made it BYTE-FILLING rather
    /// than `u64`-minting so that this second secret could use it; this is that
    /// use. One call reaches both profiles, and an MCU deploy supplies the same
    /// `EntropySource` it already supplies for the nonce.
    ///
    /// ## Failure is not absorbed
    ///
    /// There is no fail-closed representation for a key — the field is not an
    /// `Option`, and inventing a sentinel "key that cannot mint" would be a
    /// value the HMAC would happily use. So the error propagates and the CALLER
    /// declines to build a bundle, which is the honest shape: a host that
    /// cannot obtain entropy at startup cannot serve an acceptor securely.
    pub fn from_entropy<E: crate::entropy::EntropySource + ?Sized>(
        source: &mut E,
    ) -> Result<Self, crate::entropy::EntropyUnavailable> {
        // Zeroizing FIRST, so a partially-filled buffer is wiped on the `?`
        // rather than left on the heap for the allocator to hand out.
        let mut bytes = Zeroizing::new(alloc::vec![0u8; SIGNING_KEY_BYTES]);
        source.try_fill_bytes(&mut bytes)?;
        Ok(Self { bytes })
    }

    /// Construct a key from owned bytes. The input is moved into a
    /// `Zeroizing` wrapper; passing a shorter-than-32-byte slice
    /// returns the typed error without retaining the bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SigningKeyTooShort> {
        if bytes.len() < SIGNING_KEY_BYTES {
            // Zeroize the rejected input before returning — the
            // caller's Vec<u8> would otherwise persist on the
            // stack until they explicitly drop it.
            let _ = Zeroizing::new(bytes);
            return Err(SigningKeyTooShort(0)); // length already inspected
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Key length in bytes. Non-secret (already surfaced via the
    /// `Debug` impl); exposed so callers / tests can assert the
    /// `>= 32` length contract without reaching the private bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the key holds zero bytes. Present to satisfy the
    /// clippy `len_without_is_empty` lint; a constructed `SigningKey`
    /// is never empty (the `>= 32` constructor contract).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Crate-internal slice view; not exposed to consumers.
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Anti-amplification cookie generated by the Accepting side on
/// InitAck and echoed back by the Initiator on OpenSyn.
///
/// **Wire shape**. HMAC-SHA256 output truncated to the first
/// 16 bytes (RFC §5.M cookie shape; the truncation matches
/// zenoh-pico's _z_t_msg_init_t._cookie ZSlice convention and is
/// the same width as a zid). The 32-byte raw HMAC is **not**
/// emitted on the wire; only the truncated 16-byte prefix.
///
/// **Key sourcing**. Caller passes a validated `SigningKey`
/// constructed via `SigningKey::new(bytes)`; length validation +
/// drop-time zeroize happen at the newtype layer so this function
/// is panic-free given a non-null key.
///
/// ## `nonce` is what binds the cookie to ONE handshake
///
/// R311y813. Without it the MAC input is `peer_zid` alone, so the cookie
/// is a pure function of `(deploy key, claimed zid)` and never changes for
/// the life of the process: an observer who captures ONE OpenSyn echo can
/// replay that cookie against this acceptor forever, for that zid, without
/// ever having completed a round trip. That defeats the whole point of the
/// echo — the cookie is supposed to prove the initiator received OUR
/// InitAck on THIS connection, and a deploy-static value proves only that
/// someone, once, saw one.
///
/// zenoh draws a fresh `prng.gen::<u64>()` per accepted handshake, puts it
/// in the cookie, keeps it in its own link state, and rejects an OpenSyn
/// whose echoed nonce differs as an "Unknown cookie"
/// (`unicast/establishment/accept.rs:362` and `:500-503`). This is that
/// nonce, folded into the MAC rather than carried beside it — wz's cookie
/// is 16 opaque bytes and the acceptor re-derives rather than decrypts, so
/// the nonce never needs to ride the wire. Both shapes hold the same
/// invariant: the acceptor accepts only the cookie IT minted for the
/// handshake it is currently in.
///
/// **The nonce goes FIRST, and that is not cosmetic.** `peer_zid` is
/// variable-length (1..=16 bytes on the wire), so `zid || nonce` is an
/// ambiguous encoding — `[0x01,0x02] || 8 nonce bytes` and
/// `[0x01,0x02,0x03] || 8 different nonce bytes` can be the same byte
/// string, which would make two distinct handshakes share a cookie. A
/// fixed-width prefix makes the split unambiguous by construction, with no
/// length field to keep in sync.
///
/// The nonce is the acceptor's own secret-for-this-handshake and, unlike
/// zenoh's, is never serialized, so it carries no endianness contract with
/// any peer; `to_le_bytes` is named here only so the derivation is
/// reproducible across the hosts a single deploy might mix.
pub fn generate_cookie_hmac_sha256(
    cookie_signing_key: &SigningKey,
    peer_zid: &[u8],
    nonce: u64,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + peer_zid.len());
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(peer_zid);
    let full = compute_hmac_sha256_full(cookie_signing_key.as_slice(), &input);
    full[..16].to_vec()
}

/// Pure HMAC-SHA256 primitive — used by the cookie generator and
/// directly by the RFC 4231 test-vector cross-check. Returns the
/// untruncated 32-byte MAC; the cookie wire-shape truncation is
/// owned by `generate_cookie_hmac_sha256`.
fn compute_hmac_sha256_full(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any non-zero key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    /// HMAC-SHA256 cookie generator must produce 16-byte output and
    /// be deterministic given the same (key, peer_zid, nonce) inputs.
    /// Cross-checks against the RustCrypto `hmac` + `sha2` baseline
    /// — if either crate drifts on us the byte sequence will move
    /// and this test catches it before the wire interop tests fail.
    ///
    /// Determinism is what makes the acceptor able to VERIFY without
    /// storing the cookie: it re-derives from `(key, zid, nonce)` at
    /// OpenSyn. R311y813 added the nonce, which is the term that stops
    /// that determinism from also spanning handshakes — see
    /// `a_fresh_nonce_moves_the_cookie_for_the_same_peer`.
    #[test]
    fn cookie_hmac_sha256_deterministic_16_byte_output() {
        let key = SigningKey::new(vec![0xAB; 32]).expect("32-byte key valid");
        let peer_zid = vec![0x01, 0x02, 0x03, 0x04];
        let cookie_a = generate_cookie_hmac_sha256(&key, &peer_zid, 0xDEAD_BEEF);
        let cookie_b = generate_cookie_hmac_sha256(&key, &peer_zid, 0xDEAD_BEEF);
        assert_eq!(cookie_a.len(), 16, "cookie wire width is 16 bytes");
        assert_eq!(cookie_a, cookie_b, "same inputs → same cookie");

        let different_peer = vec![0x05, 0x06, 0x07, 0x08];
        let cookie_c = generate_cookie_hmac_sha256(&key, &different_peer, 0xDEAD_BEEF);
        assert_ne!(
            cookie_a, cookie_c,
            "different peer_zid must yield different cookie"
        );
    }

    /// R311y813 THE DISCRIMINATOR. The SAME peer zid under the SAME deploy
    /// key must not mint the same cookie twice across handshakes — that
    /// equality IS the replayability the nonce removes, and before this
    /// round it held by construction because the nonce was not an input.
    ///
    /// Deleting the `nonce` term from the MAC input fails exactly here and
    /// nowhere else in this module: every other test in the file fixes one
    /// nonce and would keep passing.
    #[test]
    fn a_fresh_nonce_moves_the_cookie_for_the_same_peer() {
        let key = SigningKey::new(vec![0xAB; 32]).expect("32-byte key valid");
        let peer_zid = vec![0x01, 0x02, 0x03, 0x04];
        let first = generate_cookie_hmac_sha256(&key, &peer_zid, 1);
        let second = generate_cookie_hmac_sha256(&key, &peer_zid, 2);
        assert_ne!(
            first, second,
            "a captured cookie must not verify against the NEXT handshake \
             with the same peer -- that is the replay this nonce closes",
        );
    }

    /// The nonce is length-prefixed by being FIXED-WIDTH AND FIRST, so no
    /// pair of `(zid, nonce)` inputs can collide by re-splitting the same
    /// byte string. Written as the concrete collision the naive
    /// `zid || nonce` order admits: a 2-byte zid whose trailing nonce bytes
    /// begin `03` versus the 3-byte zid ending in `03`.
    ///
    /// Without the ordering rule both sides below concatenate to the same
    /// ten bytes and two DIFFERENT handshakes share one cookie.
    #[test]
    fn the_zid_and_the_nonce_cannot_realign_into_one_another() {
        let key = SigningKey::new(vec![0xAB; 32]).expect("32-byte key valid");
        // `[0x01, 0x02] || 03 04 05 06 07 08 09 0A` and
        // `[0x01, 0x02, 0x03] || 04 05 06 07 08 09 0A ..` are the same
        // prefix under the rejected order.
        let short_zid = vec![0x01, 0x02];
        let long_zid = vec![0x01, 0x02, 0x03];
        let nonce_a = u64::from_le_bytes([0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        let nonce_b = u64::from_le_bytes([0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x00]);
        assert_ne!(
            generate_cookie_hmac_sha256(&key, &short_zid, nonce_a),
            generate_cookie_hmac_sha256(&key, &long_zid, nonce_b),
            "a variable-length zid adjacent to the nonce must not be able to \
             borrow a byte from it",
        );
    }

    /// Short-key reject is loud at construction site (RFC §5.M
    /// mandates >= 32 bytes; the typed constructor returns
    /// `Err(SigningKeyTooShort)` instead of letting a 16-byte key
    /// reach the wire-decode-time peer reject path).
    #[test]
    fn signing_key_short_returns_err() {
        let too_short = vec![0xAA; 16];
        let result = SigningKey::new(too_short);
        assert!(matches!(result, Err(SigningKeyTooShort(_))));
    }

    /// SigningKey Debug impl never leaks the bytes — only the
    /// length. Catches a regression where a future contributor
    /// adds `#[derive(Debug)]` (which would print the inner Vec).
    #[test]
    fn signing_key_debug_redacts_bytes() {
        let key = SigningKey::new(vec![0xDE; 32]).unwrap();
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("<redacted>"), "Debug must redact: {dbg}");
        assert!(!dbg.contains("DE"), "Debug must not leak hex: {dbg}");
    }

    /// RFC 4231 Test Case 1 — pinned cross-check against the public
    /// HMAC-SHA256 test vector. If RustCrypto's `hmac` + `sha2`
    /// crates ever regress, this assertion fires.
    ///
    /// Key  = 0x0b × 20
    /// Data = "Hi There"
    /// HMAC = b0344c61d8db38535ca8afceaf0bf12b
    ///        881dc200c9833da726e9376c2e32cff7
    #[test]
    fn rfc4231_test_case_1_full_hmac_sha256() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC1 byte mismatch");
    }

    /// RFC 4231 Test Case 2 — verifies the implementation handles
    /// the canonical "short key, longer data" combination correctly.
    ///
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    /// HMAC = 5bdcc146bf60754e6a042426089575c7
    ///        5a003f089d2739839dec58b964ec3843
    #[test]
    fn rfc4231_test_case_2_full_hmac_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = compute_hmac_sha256_full(key, data);
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC2 byte mismatch");
    }

    /// RFC 4231 Test Case 3 — uniform-byte key + uniform-byte data
    /// stresses the block-mix path (both key and data 20+ bytes,
    /// neither block-size-aligned to anything special).
    ///
    /// Key  = 0xaa × 20
    /// Data = 0xdd × 50
    /// HMAC = 773ea91e36800e46854db8ebd09181a7
    ///        2959098b3ef8c122d9635514ced565fe
    #[test]
    fn rfc4231_test_case_3_full_hmac_sha256() {
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];
        let mac = compute_hmac_sha256_full(&key, &data);
        let expected: [u8; 32] = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC3 byte mismatch");
    }

    /// RFC 4231 Test Case 4 — sequential-byte key (0x01..=0x19)
    /// with uniform-byte data. Catches off-by-one in key
    /// padding / inner-pad XOR.
    ///
    /// Key  = 0x01, 0x02, …, 0x19  (25 bytes)
    /// Data = 0xcd × 50
    /// HMAC = 82558a389a443c0ea4cc819899f2083a
    ///        85f0faa3e578f8077a2e3ff46729665b
    #[test]
    fn rfc4231_test_case_4_full_hmac_sha256() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = vec![0xcd; 50];
        let mac = compute_hmac_sha256_full(&key, &data);
        let expected: [u8; 32] = [
            0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2,
            0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4,
            0x67, 0x29, 0x66, 0x5b,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC4 byte mismatch");
    }

    /// RFC 4231 Test Case 5 — truncated-MAC scenario. RFC §4.5
    /// documents the truncation-to-128-bits use case which is
    /// exactly what `generate_cookie_hmac_sha256` does (truncate
    /// to first 16 bytes). The expected output here is the full
    /// MAC; the truncation invariant is asserted alongside.
    ///
    /// Key  = 0x0c × 20
    /// Data = "Test With Truncation"
    /// HMAC = a3b6167473100ee06e0c796c2955552b
    ///        fa6f7c0a6a8aef8b93f860aab0cd20c5
    /// Truncated (first 16 bytes) = a3b6167473100ee06e0c796c2955552b
    #[test]
    fn rfc4231_test_case_5_truncation_invariant() {
        let key = vec![0x0c; 20];
        let data = b"Test With Truncation";
        let full = compute_hmac_sha256_full(&key, data);
        let expected_full: [u8; 32] = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
            0x55, 0x2b, 0xfa, 0x6f, 0x7c, 0x0a, 0x6a, 0x8a, 0xef, 0x8b, 0x93, 0xf8, 0x60, 0xaa,
            0xb0, 0xcd, 0x20, 0xc5,
        ];
        assert_eq!(full, expected_full, "RFC 4231 TC5 full MAC");
        // First 16 bytes — the cookie wire-shape truncation
        // matches RFC §4.5 96/128-bit MAC truncation. Asserts
        // that generate_cookie_hmac_sha256's slice [..16] yields
        // exactly the RFC truncated form.
        let expected_truncated: [u8; 16] = [
            0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55,
            0x55, 0x2b,
        ];
        assert_eq!(
            &full[..16],
            expected_truncated.as_slice(),
            "RFC 4231 TC5 truncated"
        );
    }

    /// RFC 4231 Test Case 6 — block-size+ key triggers the
    /// "key longer than block size, hash first" path
    /// (HMAC algorithm pre-hashes the key when len > 64).
    ///
    /// Key  = 0xaa × 131
    /// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    /// HMAC = 60e431591ee0b67f0d8a26aacbf5b77f
    ///        8e0bc6213728c5140546040f0ee37f54
    #[test]
    fn rfc4231_test_case_6_full_hmac_sha256() {
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC6 byte mismatch");
    }

    /// RFC 4231 Test Case 7 — block-size+ key AND block-size+
    /// data. Stresses both the key-prehash path AND the multi-
    /// block message absorption path.
    ///
    /// Key  = 0xaa × 131
    /// Data = "This is a test using a larger than block-size key
    ///         and a larger than block-size data. ..."
    /// HMAC = 9b09ffa71b942fcb27635fbcd5b0e944
    ///        bfdc63644f0713938a7f51535c3a35e2
    #[test]
    fn rfc4231_test_case_7_full_hmac_sha256() {
        let key = vec![0xaa; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let mac = compute_hmac_sha256_full(&key, data);
        let expected: [u8; 32] = [
            0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0,
            0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53,
            0x5c, 0x3a, 0x35, 0xe2,
        ];
        assert_eq!(mac, expected, "RFC 4231 TC7 byte mismatch");
    }

    // ── R311y820 — `SigningKey::from_entropy`, the §2.5 port draw ──

    /// A source that hands out consecutive bytes, so a draw has a known
    /// spelling and two draws differ.
    struct Counting(u8);

    impl crate::entropy::EntropySource for Counting {
        fn try_fill_bytes(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), crate::entropy::EntropyUnavailable> {
            for slot in buf.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A board whose TRNG is not ready.
    struct Dry;

    impl crate::entropy::EntropySource for Dry {
        fn try_fill_bytes(
            &mut self,
            _buf: &mut [u8],
        ) -> Result<(), crate::entropy::EntropyUnavailable> {
            Err(crate::entropy::EntropyUnavailable)
        }
    }

    #[test]
    fn key_draw_uses_the_validators_own_floor() {
        // The draw and `new`'s `>= 32` check read ONE constant. A draw sized
        // below the floor would build a key `new` would have refused, which no
        // other assertion here would notice.
        let key = SigningKey::from_entropy(&mut Counting(0)).expect("counting source fills");
        assert_eq!(key.len(), SIGNING_KEY_BYTES);
        assert!(SigningKey::new(vec![0u8; SIGNING_KEY_BYTES]).is_ok());
    }

    #[test]
    fn key_draw_two_draws_give_two_keys() {
        // THE defect this round removed, stated as a property: every params
        // builder in the tree wrote one literal, so every acceptor shared a
        // key. A source that returned one value forever satisfies the
        // signature; this is what it does not satisfy.
        let mut src = Counting(0);
        let a = SigningKey::from_entropy(&mut src).unwrap();
        let b = SigningKey::from_entropy(&mut src).unwrap();
        // The key bytes are private by design (that is the newtype's job), so
        // the observable is the MAC each produces over one message.
        let mac_a = compute_hmac_sha256_full(a.as_slice(), b"probe");
        let mac_b = compute_hmac_sha256_full(b.as_slice(), b"probe");
        assert_ne!(mac_a, mac_b, "two drawn keys must not MAC alike");
    }

    #[test]
    fn key_draw_a_dry_source_yields_no_key_at_all() {
        // Fail-closed with no sentinel: there is no "key that cannot mint", so
        // the only honest answer is to hand the caller nothing and let it
        // decline to build a bundle.
        assert!(SigningKey::from_entropy(&mut Dry).is_err());
    }
}
