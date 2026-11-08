// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Delivering a publish to all of the links it reaches or to none: the part of the
//! `multi-route-atomic-tx` policy that every engine shares.
//!
//! # The decision
//!
//! A publish sent to several links is offered to each of them in turn, and a link whose queue is
//! full drops or waits on its own, so the links of one publish can end with different answers: the
//! frame reaches some and not others. A caller that treats the links as one route cannot use that.
//! A publish that states [`PublishOptions::atomic_tx`](crate::publish_options::PublishOptions)
//! asks for the other outcome: every link it may use takes the frame, or no link does.
//!
//! # Why it is two phases
//!
//! Asking each link whether it has room and then sending is not atomic: another sender can fill a
//! lane between the question and the send. So the publish first RESERVES room on every link (the
//! phase this module judges) and sends only when every reservation was granted, each frame under
//! the room it holds. A link that has no room ends the publish before anything was sent, so no
//! sequence number is spent, no queue holds a frame and no subscriber of the session is told;
//! the reservations that were granted are given back. This module holds only the rule of the
//! decision; the engine that holds the links reserves and sends.
//!
//! # The default is no atomicity
//!
//! A publish that states nothing is sent as upstream's is, to each link on its own terms, and it
//! is the only publish a build without the policy has. A call that states the atomic form in such
//! a build is refused by [`admit_in_build`] with a reason, not ignored.

/// What the reserving phase found for one link of a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegRoom {
    /// The link promised room for the frame.
    Granted,
    /// The link had no room to promise.
    NoRoom,
    /// The link takes no part in this publish: it is down, or it was never told the key. It
    /// owes the publish nothing, as a link the publish skips does without the policy.
    Absent,
}

/// How a publish ends once every link was asked to reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllOrNone {
    /// Every link that takes part promised room: each is sent its frame under its reservation,
    /// and the session's own subscribers are delivered to.
    Commit,
    /// Some link had no room: nothing is sent to any link or to any subscriber, and every
    /// reservation is given back.
    Abort,
}

/// The ending of a publish whose links answered `legs` when asked to reserve: [`AllOrNone::Abort`]
/// when any link had no room, otherwise [`AllOrNone::Commit`]. A publish with no link that takes
/// part (none, or all absent) commits, because there is nothing for it to be partial over.
pub fn decide(legs: &[LegRoom]) -> AllOrNone {
    if legs.contains(&LegRoom::NoRoom) {
        AllOrNone::Abort
    } else {
        AllOrNone::Commit
    }
}

/// Why the atomic form of a publish could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicTxError {
    /// The build's `multi-route-atomic-tx` policy is off, so no publish may state it.
    PolicyOff,
}

impl core::fmt::Display for AtomicTxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PolicyOff => f.write_str(
                "this build does not let a publish ask for all of its links or none \
                 (policy multi-route-atomic-tx is off)",
            ),
        }
    }
}

impl core::error::Error for AtomicTxError {}

/// A publish that `stated` the atomic form admitted by a policy that is `enabled`, or the reason
/// it is not: a publish that does not state it is always admitted, and one that does is admitted
/// only when the policy is on.
pub const fn admit(stated: bool, enabled: bool) -> Result<(), AtomicTxError> {
    if stated && !enabled {
        Err(AtomicTxError::PolicyOff)
    } else {
        Ok(())
    }
}

/// [`admit`] by this build's `multi-route-atomic-tx` policy: the call every entry point that takes
/// the atomic form from a caller makes.
pub const fn admit_in_build(stated: bool) -> Result<(), AtomicTxError> {
    admit(
        stated,
        crate::policy::SessionPolicy::from_build().multi_route_atomic_tx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_link_without_room_aborts_the_publish_whichever_it_is() {
        assert_eq!(
            decide(&[LegRoom::Granted, LegRoom::NoRoom, LegRoom::Granted]),
            AllOrNone::Abort
        );
        assert_eq!(decide(&[LegRoom::NoRoom]), AllOrNone::Abort);
        assert_eq!(
            decide(&[LegRoom::Absent, LegRoom::NoRoom]),
            AllOrNone::Abort,
            "an absent link does not hide the one that had no room"
        );
    }

    #[test]
    fn every_link_granted_commits_and_an_absent_link_owes_nothing() {
        assert_eq!(
            decide(&[LegRoom::Granted, LegRoom::Granted]),
            AllOrNone::Commit
        );
        assert_eq!(
            decide(&[LegRoom::Granted, LegRoom::Absent]),
            AllOrNone::Commit
        );
    }

    #[test]
    fn a_publish_with_no_link_taking_part_commits() {
        assert_eq!(decide(&[]), AllOrNone::Commit);
        assert_eq!(
            decide(&[LegRoom::Absent, LegRoom::Absent]),
            AllOrNone::Commit
        );
    }

    #[test]
    fn a_publish_that_does_not_state_it_is_admitted_whatever_the_policy() {
        assert_eq!(admit(false, false), Ok(()));
        assert_eq!(admit(false, true), Ok(()));
        assert_eq!(admit_in_build(false), Ok(()));
    }

    #[test]
    fn the_atomic_form_needs_the_policy_on() {
        assert_eq!(admit(true, false), Err(AtomicTxError::PolicyOff));
        assert_eq!(admit(true, true), Ok(()));
        let in_build = crate::policy::SessionPolicy::from_build().multi_route_atomic_tx;
        assert_eq!(admit_in_build(true).is_ok(), in_build);
    }

    #[test]
    fn the_refusal_says_what_it_is() {
        use core::fmt::Write as _;

        struct Sink(usize);
        impl core::fmt::Write for Sink {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0 += s.len();
                Ok(())
            }
        }
        let mut sink = Sink(0);
        write!(sink, "{}", AtomicTxError::PolicyOff).expect("a sink does not fail");
        assert!(sink.0 > 0, "the refusal has a message");
        let as_error: &dyn core::error::Error = &AtomicTxError::PolicyOff;
        assert!(as_error.source().is_none());
    }
}
