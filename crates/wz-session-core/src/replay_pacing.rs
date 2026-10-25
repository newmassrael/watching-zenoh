// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pace of a paced declaration replay (`docs/declaration-sync-pacing.md`): how many
//! declarations a turn sends and how long to wait between turns, and the pace a build states.
//!
//! The pace is a value and not a clock: it holds two numbers, reads no time and does no I/O, so
//! every host that replays in turns (the heap runtime's supervisor, the slot node) holds the same
//! type and keeps its own time. It sits beside [`crate::replay_cursor::ReplayCursor`], which says
//! which entries a turn sends, and this says how many and how often.

/// A pace of `burst` declarations a turn and `interval_ms` between turns. A host holds it as an
/// `Option`, so a test, or a caller that wants pacing on regardless of the build, can state it,
/// and the build states it through [`Self::from_build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPacing {
    burst: usize,
    interval_ms: u64,
}

impl ReplayPacing {
    /// A pace of `burst` declarations a turn and `interval_ms` between turns. Both must be at least
    /// 1: a turn that sends nothing would never finish, and no wait would run the turns together.
    pub const fn new(burst: usize, interval_ms: u64) -> Option<Self> {
        if burst == 0 || interval_ms == 0 {
            None
        } else {
            Some(Self { burst, interval_ms })
        }
    }

    /// The pace the build states: `None`, upstream's one call, unless the `declaration-sync-pacing`
    /// policy is on, in which case the pace is the burst and interval limits. The limits are
    /// checked where they are used, at compile time, so a build that sets one to zero does not
    /// build.
    pub const fn from_build() -> Option<Self> {
        const _: () = assert!(
            crate::caps::DECLARATION_SYNC_BURST_MESSAGES >= 1
                && crate::caps::DECLARATION_SYNC_INTERVAL_MS >= 1,
            "DECLARATION_SYNC_BURST_MESSAGES and DECLARATION_SYNC_INTERVAL_MS must be at least 1"
        );
        if crate::policy::SessionPolicy::from_build().declaration_sync_pacing {
            Self::new(
                crate::caps::DECLARATION_SYNC_BURST_MESSAGES,
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64,
            )
        } else {
            None
        }
    }

    /// The pace the build states ([`Self::from_build`]), evaluated when the crate is built: a
    /// `WZ_POLICY_*` value that is neither `on` nor `off` stops the build here, where a call to
    /// `from_build` at run time would take the node down when it started.
    pub const BUILD: Option<Self> = Self::from_build();

    /// Declarations sent in one turn.
    pub const fn burst(&self) -> usize {
        self.burst
    }

    /// Milliseconds between two turns.
    pub const fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pace of nothing is refused: a turn that sends nothing never finishes, and no wait would
    /// run the turns together.
    #[test]
    fn a_pace_needs_a_burst_and_a_wait_of_at_least_one() {
        assert_eq!(ReplayPacing::new(0, 10), None);
        assert_eq!(ReplayPacing::new(8, 0), None);
        let pace = ReplayPacing::new(8, 10).expect("a real pace");
        assert_eq!((pace.burst(), pace.interval_ms()), (8, 10));
    }

    /// The build states the pace through the policy: off is upstream's one call, on is the two
    /// limits. The test build states nothing, so this asserts the default and that the two agree.
    #[test]
    fn the_build_states_a_pace_exactly_when_the_policy_is_on() {
        let on = crate::policy::SessionPolicy::from_build().declaration_sync_pacing;
        assert_eq!(ReplayPacing::from_build().is_some(), on);
        assert_eq!(ReplayPacing::BUILD, ReplayPacing::from_build());
        if let Some(pace) = ReplayPacing::from_build() {
            assert_eq!(pace.burst(), crate::caps::DECLARATION_SYNC_BURST_MESSAGES);
            assert_eq!(
                pace.interval_ms(),
                crate::caps::DECLARATION_SYNC_INTERVAL_MS as u64
            );
        }
    }
}
