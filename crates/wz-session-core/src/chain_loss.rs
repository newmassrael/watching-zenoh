// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y713 (§B7) — what a reassembly sweep gave up on.
//!
//! # Why its own module rather than beside the dispatcher
//!
//! [`crate::reassembly_dispatch`] is `#[cfg(feature = "reassembly")]`, and the
//! verbs that RETURN this type are not: `PassiveSession::observe_at_counting`
//! and `abandon_open_chains_counting` answer honestly on a build that
//! reassembles nothing (no chains, so nothing lost) for the same reason their
//! counting predecessors did — a caller must not have to know which features
//! this binary carries. A return type gated more narrowly than the function
//! returning it does not compile in the feature arm between them, which is
//! exactly how this landed: `--features dissect` without `reassembly` failed
//! on `cannot find type ChainLoss` while the default build was green.

/// What a sweep gave up on: how many chains, and how much of
/// them had already arrived.
///
/// Two numbers rather than one because they answer different questions and a
/// reader needs both: the count says how many messages will never be seen, and
/// the bytes say how much of the capture went with them. A count alone cannot
/// distinguish four chains lost at one fragment each from four lost at a
/// megabyte each, and the second is a capture worth re-taking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainLoss {
    /// Chains abandoned.
    pub chains: usize,
    /// Bytes staged into them and now unreachable.
    pub bytes: u64,
}

impl ChainLoss {
    /// Fold another sweep's loss in.
    pub fn absorb(&mut self, other: Self) {
        self.chains += other.chains;
        self.bytes += other.bytes;
    }
}
