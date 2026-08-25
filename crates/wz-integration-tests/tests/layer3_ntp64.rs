// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 cross-impl differential — the NTP64 word COMPOSER (R311y263).
//!
//! ## What this found
//!
//! **zenoh-pico's NTP64 composer diverges from zenoh's own reference by exactly one
//! tick.** `_z_timestamp_ntp64_from_time` (vendor/zenoh-pico/src/protocol/core.c:66-72)
//! computes
//!
//! ```text
//! fractions = nanos * 2^32 / 1e9 + 1        // note the + 1
//! ```
//!
//! while zenoh stamps through `uhlc`, whose `impl From<Duration> for NTP64`
//! (uhlc-0.8.1/src/ntp64.rs:287-293) is
//!
//! ```text
//! (secs << 32) + (nanos * FRAC_PER_SEC / NANO_PER_SEC)   // no + 1
//! ```
//!
//! wz mirrors uhlc exactly (`Ntp64::from_unix`, wz-session-core/src/ntp64.rs:64-67), so
//! **wz agrees with zenoh and zenoh-pico is the outlier.** For the SAME instant, a pico
//! stamp is one NTP64 tick (2^-32 s, ~233 ps) ahead of a wz/zenoh stamp — including at
//! `(0s, 0ns)`, where zenoh says 0 and pico says 1.
//!
//! ## Why this is a PIN, not a proof, and not a wz fix
//!
//! A locked disagreement is the opposite of an interop proof, so this test claims NO
//! atom — the same treatment the corpus already gives the known pico canon anomalies
//! (`layer3_keyexpr_canon.rs`). And wz is NOT changed to match: wz's reference
//! is zenoh, not zenoh-pico, and bending wz to a foreign off-by-one would put it out of
//! step with every zenoh peer to match one pico quirk.
//!
//! The divergence does not break the WIRE — each side puts its own word on the wire and
//! the other decodes it faithfully (proven byte-for-byte by
//! `layer3_push_with_timestamp_and_attachment_byte_equivalent`). What it means is that
//! the same physical instant is LABELLED one tick apart by the two implementations, so a
//! cross-impl timestamp comparison is not exact. That is why `time-ntp64` is claimed
//! `partial` there and not full: the word's codec agrees, its construction does not.

/// zenoh-pico's NTP64 composer.
fn zenoh_pico_ntp64(seconds: u32, nanos: u32) -> u64 {
    // SAFETY: a pure arithmetic function over two scalars; no pointers, no allocation.
    unsafe { zenoh_pico_sys::_z_timestamp_ntp64_from_time(seconds, nanos) }
}

/// PIN the zenoh-pico +1-tick divergence, and pin wz to zenoh's own uhlc formula.
///
/// If a future zenoh-pico drops the `+ 1`, this test FAILS — which is the point: the
/// anomaly is then resolved and the claim on `time-ntp64` can be upgraded to full.
// wz-proves: none -- pins a wz/pico DIVERGENCE in the NTP64 composer (pico adds +1 tick vs zenoh's uhlc); a locked disagreement is not an interop proof
#[test]
fn ntp64_composition_pins_the_pico_plus_one_tick_divergence() {
    use wz_session_core::ntp64::Ntp64;

    // The boundaries where a fraction-scaling disagreement would surface: zero, exact
    // binary fractions (halves/quarters), the last representable nanosecond, and values
    // that do not land on a binary boundary and so expose the rounding rule.
    const NANOS: &[u32] = &[
        0,
        1,
        999_999_999,
        500_000_000,
        250_000_000,
        750_000_000,
        123_456_789,
        999_999_998,
        1_000,
        1_000_000,
    ];
    const SECONDS: &[u32] = &[0, 1, 1_700_000_000, u32::MAX];

    for &secs in SECONDS {
        for &nanos in NANOS {
            let wz = Ntp64::from_unix(u64::from(secs), nanos).as_word();
            let pico = zenoh_pico_ntp64(secs, nanos);

            // wz IS zenoh's uhlc formula, recomputed here so the test pins wz to the
            // REFERENCE rather than to itself.
            let uhlc = (u64::from(secs) << 32) + ((u64::from(nanos) << 32) / 1_000_000_000);
            assert_eq!(
                wz, uhlc,
                "wz must compose the NTP64 word exactly as zenoh's uhlc does \
                 ({secs}s, {nanos}ns): wz={wz:#018x} uhlc={uhlc:#018x}",
            );

            // ... and zenoh-pico is exactly one tick above it, for every input.
            assert_eq!(
                pico,
                wz + 1,
                "zenoh-pico's composer is expected to be exactly +1 tick vs zenoh/uhlc \
                 ({secs}s, {nanos}ns): wz={wz:#018x} pico={pico:#018x}. If this now FAILS, \
                 upstream pico has changed the `+ 1` at protocol/core.c:70 — re-check \
                 whether the divergence is resolved and time-ntp64 can go full.",
            );
        }
    }
}
