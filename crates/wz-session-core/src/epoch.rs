// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2914 — the time-since-epoch PORT: the seam a profile plugs its wall clock
//! into, so a timestamp can be minted on every profile rather than only on the
//! AP one.
//!
//! ## Why a port
//!
//! The no_std core lets an application stamp a sample (`Sample::with_timestamp`,
//! `set_push_timestamp`) and converts Unix time to the NTP64 word a timestamp
//! carries ([`crate::ntp64::Ntp64::from_unix`]). What it could not do is say
//! what time it is: the AP read `std::time::SystemTime` directly, and no MCU
//! profile had any source, where zenoh-pico's platform layer answers it on
//! every port (`_z_get_time_since_epoch`, the input of `z_timestamp_new`).
//! The source differs per board -- an RTC, SNTP, a host clock -- so the core
//! declares the shape, as it does for entropy ([`crate::entropy`]), and each
//! profile supplies the source.
//!
//! ## Why seconds and nanoseconds since the Unix epoch
//!
//! It is pico's `_z_time_since_epoch { secs, nanos }` and the input
//! [`crate::ntp64::Ntp64::from_unix`] takes, and it carries no timezone: the
//! reason `wz_runtime_core::TimeSource` keeps wall time out of the monotonic
//! clock contract ("every TimeSource must answer 'what timezone'") does not
//! arise for an instant counted from the epoch.
//!
//! ## The error carries no detail
//!
//! As [`crate::entropy::EntropyUnavailable`]: a board without a set clock has
//! no portable way to say why, and the caller's response is the same -- mint no
//! timestamp rather than one from a clock that does not know the date.

use crate::ntp64::Ntp64;

/// An instant as seconds and nanoseconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinceEpoch {
    /// Whole seconds since the Unix epoch.
    pub secs: u64,
    /// Nanoseconds past `secs`; below 1_000_000_000.
    pub nanos: u32,
}

/// A profile's epoch source could not say what time it is (no RTC, a clock
/// that was never set, a failed read). Carries no detail on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochUnavailable;

impl core::fmt::Display for EpochUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no time since the epoch is available")
    }
}

impl core::error::Error for EpochUnavailable {}

/// The time-since-epoch port: a profile's wall clock, read as an instant since
/// the Unix epoch. Implement [`Self::try_since_epoch`]; [`Self::try_now_ntp64`]
/// is derived.
///
/// **Contract.** The instant is UTC and counted from the Unix epoch. It need
/// not be monotonic -- a wall clock steps -- which is why a node that must
/// order its own stamps wraps it in a hybrid logical clock, as the AP's
/// `time-hlc` does.
pub trait EpochSource {
    /// The current instant, or [`EpochUnavailable`] when the source cannot tell.
    fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable>;

    /// The current instant as the NTP64 time a timestamp carries.
    fn try_now_ntp64(&self) -> Result<Ntp64, EpochUnavailable> {
        let t = self.try_since_epoch()?;
        Ok(Ntp64::from_unix(t.secs, t.nanos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(SinceEpoch);

    impl EpochSource for Fixed {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            Ok(self.0)
        }
    }

    struct Unset;

    impl EpochSource for Unset {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            Err(EpochUnavailable)
        }
    }

    #[test]
    fn the_derived_ntp64_is_the_one_from_unix_computes() {
        let at = SinceEpoch {
            secs: 1_700_000_000,
            nanos: 500_000_000,
        };
        let got = Fixed(at).try_now_ntp64().expect("a fixed source answers");
        assert_eq!(got, Ntp64::from_unix(at.secs, at.nanos));
        assert_eq!(got.whole_secs(), at.secs);
        assert_eq!(got.to_millis(), 1_700_000_000_500);
    }

    #[test]
    fn an_unset_clock_mints_nothing() {
        assert_eq!(Unset.try_now_ntp64(), Err(EpochUnavailable));
    }
}
