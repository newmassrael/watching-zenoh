// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y819 — the §2.5 RNG PLUGIN-TIER PORT: the seam a profile plugs a real
//! entropy source into, so a session bundle's per-handshake secrets are drawn
//! at construction on every profile rather than only on the AP one.
//!
//! ## Why this is a port and not a call
//!
//! Round 11 ratified §2.5 (`intrinsics-runtime--symbol-surface/2-5-rng`) with
//! RNG in the PLUGIN tier, explicitly NOT in SCE's architecture-fixed
//! `BASELINE_SYMBOLS`, and gave the reason: "Impl multiplicity (HW TRNG /
//! ADC+Yarrow / getrandom / arc4random) places RNG in plugin tier." A
//! no_std core therefore cannot name its entropy source — there is no one
//! source to name. What it CAN do is declare the shape every source has, which
//! is this trait.
//!
//! ## What it is for
//!
//! `SessionLinkActions` (`crate::session_actions`, `alloc`-gated, hence a code
//! span rather than a link) holds two per-handshake secrets whose reuse is a
//! replay hazard, both fail-closed at `None`:
//!
//! - the anti-amplification cookie nonce (R311y813) — a reused nonce lets a
//!   captured OpenSyn cookie echo replay for the life of the deployment;
//! - the usrpwd / pubkey responder challenge nonce — a reused nonce lets a
//!   captured OpenSyn `{user, hmac}` replay against the responder.
//!
//! The AP profile draws both from `getrandom`. The MCU profile could not draw
//! at all, so `wz-mcu-session-acceptor` installed a CONSTANT and every board
//! built from this tree answered every handshake with one cookie per zid — the
//! exact defect R311y813 closed on the AP side, surviving on the profile whose
//! e2e is a fixture. This trait is the missing half: the MCU construction seam
//! (`wz_runtime_coop::session_runtime::new_session_actions` — a downstream
//! crate, so a code span) takes one of these and draws through it, so a board
//! integrator supplies a TYPE rather than remembering a call.
//!
//! ## Why `try_fill_bytes` and not `next_u64`
//!
//! `u64` is what the two nonce slots want today, but the same source must
//! reach the 32-byte cookie SIGNING key (`crate::signing_key::SigningKey`,
//! `alloc`-gated), which on the MCU is likewise a fixture constant today.
//! A byte-filling
//! primitive covers both and is the shape every real source already has
//! (`getrandom(&mut buf)`, a TRNG data register drained into a slice);
//! [`crate::entropy::EntropySource::try_next_u64`] is the derived convenience,
//! so an implementor writes one method.
//!
//! (Crate-ABSOLUTE, and so is the one below, for the reason `debt-carry-N13`
//! records: this module carries BOTH an outer `///` on its `pub mod` line in
//! `lib.rs` and this inner `//!`, and rustdoc merges the two and resolves the
//! result in the PARENT scope — where a bare `EntropySource` is not in scope.
//! Layer C1bz found both, which is the only gate that reaches this class.)
//!
//! `&mut self` because a real source is a peripheral or a stateful DRBG, not a
//! pure function. The AP implementor is a unit struct and ignores it.
//!
//! ## The error carries no detail, deliberately
//!
//! [`crate::entropy::EntropyUnavailable`] has no payload. A no_std board's
//! failure modes
//! (TRNG not clocked, health-test trip) have no portable spelling, and the
//! CALLER's response is the same for all of them — leave the slot at its
//! fail-closed `None` and refuse to admit an OpenSyn. A richer error would
//! invite a caller to branch on something it cannot act on.

/// A profile's entropy source could not produce the requested bytes.
///
/// Carries no detail on purpose (see the module note): every consumer's
/// response is the same fail-closed one, so there is nothing to branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

impl core::fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy source produced no bytes")
    }
}

impl core::error::Error for EntropyUnavailable {}

/// The §2.5 plugin-tier entropy port: a source of cryptographically usable
/// random bytes, supplied by the profile rather than named by the core.
///
/// Implement [`Self::try_fill_bytes`]; [`Self::try_next_u64`] is derived.
///
/// **Contract.** Bytes must be unpredictable to a party observing the wire.
/// The two consumers are replay defences, so a counter, a fixed constant, or a
/// PRNG seeded from a boot-constant satisfies the TYPE while defeating the
/// PURPOSE — which is why the in-tree fixture implementor names itself a
/// fixture and lives in the e2e crate rather than here.
pub trait EntropySource {
    /// Fill `buf` completely, or fail without promising anything about its
    /// contents. A partial fill must be reported as [`EntropyUnavailable`]
    /// rather than returned as success over a partly-written buffer.
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable>;

    /// Draw one `u64`, little-endian over 8 freshly filled bytes.
    ///
    /// The byte order is fixed here rather than left to implementors so two
    /// profiles drawing from the same underlying stream mint the same value —
    /// which is what lets a board's source be exercised against the AP one.
    fn try_next_u64(&mut self) -> Result<u64, EntropyUnavailable> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that hands out consecutive bytes, so the derived `try_next_u64`
    /// has a value with a known little-endian spelling.
    struct Counting(u8);

    impl EntropySource for Counting {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            for slot in buf.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A source that never produces bytes — the fail-closed half.
    struct Dry;

    impl EntropySource for Dry {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    #[test]
    fn try_next_u64_reads_eight_bytes_little_endian() {
        // Pins the byte order the trait fixes rather than leaves to
        // implementors: bytes 0..=7 little-endian is 0x0706_0504_0302_0100.
        let mut src = Counting(0);
        assert_eq!(src.try_next_u64().unwrap(), 0x0706_0504_0302_0100);
    }

    #[test]
    fn successive_draws_do_not_repeat() {
        // The property every consumer of this port actually depends on. A
        // source that returned one value forever would satisfy the signature.
        let mut src = Counting(0);
        let (a, b) = (src.try_next_u64().unwrap(), src.try_next_u64().unwrap());
        assert_ne!(a, b, "two draws off one source must differ");
    }

    #[test]
    fn a_dry_source_fails_the_derived_draw_too() {
        // The derived method must propagate rather than hand back a zeroed
        // buffer it happens to have on the stack — which is the one way a
        // fail-closed consumer could be handed a usable-looking secret.
        let mut src = Dry;
        assert_eq!(src.try_next_u64(), Err(EntropyUnavailable));
    }
}
