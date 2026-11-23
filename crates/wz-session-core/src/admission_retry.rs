// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Offering a publish again when no link had room: the part of the `publisher-admission-retry`
//! policy that every engine shares.
//!
//! # The decision
//!
//! A publish sent to several links is offered to each of them, and a link whose queue is full
//! makes the sender wait for room and then, for a droppable message, drop it and still report
//! success. The caller cannot tell a frame that was queued from one that was dropped, and cannot
//! ask for the drop to be avoided. [`crate::admission_retry::AdmissionRetry`] is what a publish
//! states to ask: how many further passes it may make and how long to wait between them. It is
//! a value of the publish, like its locality, so an engine applies it where it already fans the
//! publish out.
//!
//! # What a retry does
//!
//! The first pass offers the frame to every link it may use without waiting for room. When at
//! least one link queued it, nothing is retried: the links that had no room are skipped as a
//! congestion drop skips them, because offering the frame again would send it twice to the links
//! that took it. When no link queued it and at least one had no room, the sender waits
//! [`crate::admission_retry::AdmissionRetry::delay_ms`] and offers the frame again to the links
//! that had no room, up to [`crate::admission_retry::AdmissionRetry::attempts`] further passes.
//! The publish that still found no room ends having reached no link, without closing the
//! session; its wait is bounded by [`crate::admission_retry::AdmissionRetry::max_wait_ms`]. This
//! module holds only the value's rules; the engine that holds the links applies them.
//!
//! # The default is no retry
//!
//! `None` is a publish that waits for room as upstream's does, and it is the only one a session
//! without the policy has. A call that states a retry on such a session is refused by
//! [`crate::admission_retry::admit_by`] with a reason, not ignored. A retry with no
//! attempts is no retry and one with no delay is a spin, so neither can be built.

/// Why a retry could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRetryError {
    /// The retry allows no further pass, which is no retry.
    ZeroAttempts,
    /// The retry waits no time between passes, which is a spin.
    ZeroDelay,
    /// The build's `publisher-admission-retry` policy is off, so no publish may state a retry.
    PolicyOff,
}

impl core::fmt::Display for AdmissionRetryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroAttempts => f.write_str("an admission retry must allow at least one pass"),
            Self::ZeroDelay => {
                f.write_str("an admission retry must wait at least a millisecond between passes")
            }
            Self::PolicyOff => f.write_str(
                "this build does not let a publish state a retry for a link with no room \
                 (policy publisher-admission-retry is off)",
            ),
        }
    }
}

impl core::error::Error for AdmissionRetryError {}

/// A bounded retry a publish states for the case where no link had room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdmissionRetry {
    /// How many further passes follow the first one: at least 1.
    pub attempts: u8,
    /// How long to wait before each further pass, in milliseconds: at least 1.
    pub delay_ms: u16,
}

impl AdmissionRetry {
    /// A retry of `attempts` further passes with `delay_ms` between them. Refused when either is
    /// zero.
    pub const fn new(attempts: u8, delay_ms: u16) -> Result<Self, AdmissionRetryError> {
        if attempts == 0 {
            return Err(AdmissionRetryError::ZeroAttempts);
        }
        if delay_ms == 0 {
            return Err(AdmissionRetryError::ZeroDelay);
        }
        Ok(Self { attempts, delay_ms })
    }

    /// The longest the delays of this retry add up to, in milliseconds: the time a publish that
    /// finds no room spends waiting, besides the passes themselves.
    pub const fn max_wait_ms(self) -> u32 {
        (self.attempts as u32).saturating_mul(self.delay_ms as u32)
    }

    /// Whether this value is one [`Self::new`] would build. The fields are public, so a value
    /// built by hand can state a zero that `new` refuses.
    const fn check(self) -> Result<(), AdmissionRetryError> {
        match Self::new(self.attempts, self.delay_ms) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// `retry` admitted by a policy that is `enabled`, or the reason it is not: no retry is always
/// admitted, and a retry is admitted only when the policy is on and its numbers are ones
/// [`AdmissionRetry::new`] accepts. The policy is checked first, so a build without it says so
/// whatever the numbers are.
pub const fn admit(
    retry: Option<AdmissionRetry>,
    enabled: bool,
) -> Result<(), AdmissionRetryError> {
    match retry {
        None => Ok(()),
        Some(retry) => {
            if !enabled {
                return Err(AdmissionRetryError::PolicyOff);
            }
            retry.check()
        }
    }
}

/// [`admit`] by the `publisher-admission-retry` policy of `policy`, the snapshot of the session
/// the publish is made on: the call an entry point that holds that snapshot makes.
pub const fn admit_by(
    retry: Option<AdmissionRetry>,
    policy: &crate::policy::SessionPolicy,
) -> Result<(), AdmissionRetryError> {
    admit(retry, policy.publisher_admission_retry())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry(attempts: u8, delay_ms: u16) -> AdmissionRetry {
        AdmissionRetry::new(attempts, delay_ms).expect("a retry with both numbers set")
    }

    #[test]
    fn a_retry_needs_attempts_and_a_delay() {
        assert_eq!(
            AdmissionRetry::new(0, 10),
            Err(AdmissionRetryError::ZeroAttempts)
        );
        assert_eq!(
            AdmissionRetry::new(3, 0),
            Err(AdmissionRetryError::ZeroDelay)
        );
        // Both zero: the attempts are asked first.
        assert_eq!(
            AdmissionRetry::new(0, 0),
            Err(AdmissionRetryError::ZeroAttempts)
        );
        let built = AdmissionRetry::new(3, 10).expect("both set");
        assert_eq!(built.attempts, 3);
        assert_eq!(built.delay_ms, 10);
        assert!(AdmissionRetry::new(u8::MAX, u16::MAX).is_ok());
    }

    #[test]
    fn the_longest_wait_is_the_delays_added_up_and_does_not_overflow() {
        assert_eq!(retry(3, 10).max_wait_ms(), 30);
        assert_eq!(retry(1, 1).max_wait_ms(), 1);
        assert_eq!(
            retry(u8::MAX, u16::MAX).max_wait_ms(),
            u32::from(u8::MAX) * u32::from(u16::MAX)
        );
    }

    #[test]
    fn no_retry_is_admitted_whatever_the_policy() {
        assert_eq!(admit(None, false), Ok(()));
        assert_eq!(admit(None, true), Ok(()));
        assert_eq!(
            admit_by(None, &crate::policy::SessionPolicy::defaults()),
            Ok(())
        );
    }

    #[test]
    fn a_retry_needs_the_policy_on() {
        let stated = Some(retry(2, 5));
        assert_eq!(admit(stated, false), Err(AdmissionRetryError::PolicyOff));
        assert_eq!(admit(stated, true), Ok(()));
        let defaults = crate::policy::SessionPolicy::defaults();
        assert_eq!(
            admit_by(stated, &defaults).is_ok(),
            defaults.publisher_admission_retry()
        );
    }

    /// The snapshot a retry is asked with decides, not the build: a snapshot that selected the
    /// policy admits it and one that left it off refuses it.
    #[test]
    fn a_retry_is_admitted_by_the_snapshot_it_is_asked_with() {
        use crate::policy::{PublisherAdmissionRetry, SessionPolicy};
        use crate::policy_binding::PolicyValue;
        let stated = Some(retry(2, 5));
        assert_eq!(admit_by(None, &SessionPolicy::defaults()), Ok(()));
        if PublisherAdmissionRetry::DOMAIN.is_singleton() {
            return;
        }
        let mut on = SessionPolicy::defaults();
        on.select_publisher_admission_retry(PublisherAdmissionRetry::On)
            .expect("the domain holds both values");
        let mut off = on;
        off.select_publisher_admission_retry(PublisherAdmissionRetry::Off)
            .expect("the domain holds both values");
        assert_eq!(admit_by(stated, &on), Ok(()));
        assert_eq!(admit_by(stated, &off), Err(AdmissionRetryError::PolicyOff));
    }

    #[test]
    fn a_retry_built_by_hand_with_a_zero_is_refused_when_the_policy_is_on() {
        let no_attempts = AdmissionRetry {
            attempts: 0,
            delay_ms: 5,
        };
        let no_delay = AdmissionRetry {
            attempts: 2,
            delay_ms: 0,
        };
        assert_eq!(
            admit(Some(no_attempts), true),
            Err(AdmissionRetryError::ZeroAttempts)
        );
        assert_eq!(
            admit(Some(no_delay), true),
            Err(AdmissionRetryError::ZeroDelay)
        );
        // With the policy off the policy is what is said, not the numbers.
        assert_eq!(
            admit(Some(no_attempts), false),
            Err(AdmissionRetryError::PolicyOff)
        );
    }

    #[test]
    fn every_refusal_says_what_it_is() {
        use core::fmt::Write as _;

        struct Sink(usize);
        impl core::fmt::Write for Sink {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0 += s.len();
                Ok(())
            }
        }
        for error in [
            AdmissionRetryError::ZeroAttempts,
            AdmissionRetryError::ZeroDelay,
            AdmissionRetryError::PolicyOff,
        ] {
            let mut sink = Sink(0);
            write!(sink, "{error}").expect("a sink does not fail");
            assert!(sink.0 > 0, "{error:?} has a message");
        }
        let as_error: &dyn core::error::Error = &AdmissionRetryError::PolicyOff;
        assert!(as_error.source().is_none());
    }
}
