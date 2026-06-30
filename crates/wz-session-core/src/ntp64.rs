// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y104 — the NTP64 timestamp-word SSOT: the `(unix_secs << 32) | fraction`
//! layout uhlc's `NTP64` and a zenoh `Timestamp` carry, with the `2^32`
//! fraction-per-second magnitude defined in ONE place.
//!
//! Before this module the magnitude was stated four ways — `NTP64_SECOND`
//! (`(1u64 << 32) as f64`, advanced_cache), `FRAC_PER_SEC` (`1u64 << 32`,
//! storage_replication's `ntp64_to_ms`), and two inline `<< 32` shifts (the
//! wall-clock construction in timestamp_source) — plus a companion `0xFFFF_FFFF`
//! fraction mask (the `2^32 - 1` low-word mask) hand-rolled in `ntp64_to_ms`.
//! [`Ntp64`] folds the construction, extraction, and the millisecond conversion
//! into one type whose single [`FRAC_PER_SEC`](Ntp64::FRAC_PER_SEC) const is the
//! magnitude SSOT (the mask derives from it as `FRAC_PER_SEC - 1`).
//!
//! The newtype is a *construction / conversion* helper, not a pervasive field
//! type: the raw `u64` word still flows on the wire and seeds newer-wins
//! through [`crate::sample::TimestampHint::time`]; a site wraps the word with
//! [`Ntp64::from_word`] when it needs the typed view and unwraps with
//! [`Ntp64::as_word`] at the boundary.

/// An NTP64 timestamp word: unix seconds in the high 32 bits, a sub-second
/// fraction (in units of `1/2^32` second) in the low 32 bits — the layout
/// uhlc's `NTP64` (`uhlc-0.8.1/src/ntp64.rs:71`) and a zenoh `Timestamp` use.
///
/// A thin newtype over the raw word so the `2^32` magnitude and the
/// construction / extraction / conversion invariants live in one place. The raw
/// word still travels on the wire ([`crate::sample::TimestampHint::time`]); this
/// is the typed lens over it, not a replacement for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ntp64(u64);

impl Ntp64 {
    /// The number of fraction bits: NTP64 packs the sub-second fraction in the
    /// low 32 bits and the unix seconds in the high 32.
    pub const FRAC_BITS: u32 = 32;

    /// One whole second in NTP64 fraction units = `2^32`. THE magnitude SSOT —
    /// every `<< 32` / `>> 32` / `& 0xFFFF_FFFF` below derives from it.
    pub const FRAC_PER_SEC: u64 = 1 << Self::FRAC_BITS;

    /// The low-32-bits fraction mask (`2^32 - 1` = `0xFFFF_FFFF`).
    const FRAC_MASK: u64 = Self::FRAC_PER_SEC - 1;

    /// Wrap a raw NTP64 word — e.g. a
    /// [`TimestampHint::time`](crate::sample::TimestampHint) read off the wire.
    pub const fn from_word(word: u64) -> Self {
        Self(word)
    }

    /// The raw NTP64 word — what travels on the wire and seeds the newer-wins
    /// gate. The inverse of [`from_word`](Ntp64::from_word).
    pub const fn as_word(self) -> u64 {
        self.0
    }

    /// Build from unix `secs` + `subsec_nanos`: the seconds in the high 32 bits,
    /// the nanos scaled to NTP64 fraction units (`subsec_nanos * 2^32 / 1e9`).
    /// The wall-clock recipe the storage fallback stamp / HLC physical clock
    /// use. `secs << 32` wraps past ~year 2106 exactly as the raw shift it
    /// replaces did; `subsec_nanos < 1e9` keeps `nanos * 2^32 < 2^62` (no u64
    /// overflow).
    pub fn from_unix(secs: u64, subsec_nanos: u32) -> Self {
        let frac = (subsec_nanos as u64 * Self::FRAC_PER_SEC) / 1_000_000_000;
        Self((secs << Self::FRAC_BITS) | frac)
    }

    /// The whole-seconds part (`word >> 32`) — the unix epoch seconds.
    pub const fn whole_secs(self) -> u64 {
        self.0 >> Self::FRAC_BITS
    }

    /// The sub-second fraction part (`word & (2^32 - 1)`), in `1/2^32`-second
    /// units.
    pub const fn frac(self) -> u64 {
        self.0 & Self::FRAC_MASK
    }

    /// Milliseconds since the epoch, reproducing uhlc's
    /// `NTP64::to_duration().as_millis()` bit-for-bit so a wz replica buckets an
    /// event into the same digest interval as a zenoh replica
    /// (configuration.rs:197-201). The mirror:
    /// - `as_secs` = `word >> 32` (ntp64.rs:95);
    /// - `subsec_nanos` = `(frac * 1e9).div_ceil(2^32)` (ntp64.rs:109-112) — the
    ///   `div_ceil` (not a plain divide) is what makes `NTP64::from(Duration)`
    ///   round-trip, so it is required to land in zenoh's bucket;
    /// - `Duration::new(secs, subsec_nanos).as_millis()` = `secs * 1000 +
    ///   subsec_nanos / 1_000_000`.
    pub fn to_millis(self) -> u128 {
        const NANO_PER_SEC: u64 = 1_000_000_000;
        let secs = self.whole_secs() as u128;
        // frac < 2^32, so frac * 1e9 < 2^62 — no overflow in u64.
        let subsec_nanos = (self.frac() * NANO_PER_SEC).div_ceil(Self::FRAC_PER_SEC) as u128;
        secs * 1000 + subsec_nanos / 1_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frac_per_sec_is_two_to_the_32() {
        assert_eq!(Ntp64::FRAC_PER_SEC, 1u64 << 32);
        assert_eq!(Ntp64::FRAC_PER_SEC, 4_294_967_296);
        assert_eq!(Ntp64::FRAC_MASK, 0xFFFF_FFFF);
    }

    #[test]
    fn from_unix_packs_secs_high_and_nanos_low() {
        // Whole seconds land in the high 32 bits.
        assert_eq!(Ntp64::from_unix(35, 0).as_word(), 35u64 << 32);
        // 500ms = half a second = the top fraction bit (2^31).
        assert_eq!(Ntp64::from_unix(0, 500_000_000).as_word(), 1u64 << 31);
        // 250ms = a quarter second = 2^30.
        assert_eq!(Ntp64::from_unix(0, 250_000_000).as_word(), 1u64 << 30);
        // Combined: 1s + 500ms.
        assert_eq!(
            Ntp64::from_unix(1, 500_000_000).as_word(),
            (1u64 << 32) | (1u64 << 31)
        );
    }

    #[test]
    fn from_unix_matches_the_raw_shift_recipe_it_replaces() {
        // The exact arithmetic timestamp_source::wall_clock_ntp64 used to inline.
        for (secs, nanos) in [(0u64, 0u32), (1, 1), (1_700_000_000, 123_456_789)] {
            let frac = (u64::from(nanos) << 32) / 1_000_000_000;
            let expected = (secs << 32) | frac;
            assert_eq!(Ntp64::from_unix(secs, nanos).as_word(), expected);
        }
    }

    #[test]
    fn whole_secs_and_frac_round_trip_the_word() {
        let w = Ntp64::from_word((1_700_000_000u64 << 32) | 0x1234_5678);
        assert_eq!(w.whole_secs(), 1_700_000_000);
        assert_eq!(w.frac(), 0x1234_5678);
    }

    #[test]
    fn to_millis_is_uhlc_exact() {
        // Whole seconds.
        assert_eq!(Ntp64::from_word(0).to_millis(), 0);
        assert_eq!(Ntp64::from_word(35u64 << 32).to_millis(), 35_000);
        // Fractions: 2^31 = 500ms, 2^30 = 250ms (the div_ceil-exact values).
        assert_eq!(Ntp64::from_word(1u64 << 31).to_millis(), 500);
        assert_eq!(Ntp64::from_word(1u64 << 30).to_millis(), 250);
    }
}
