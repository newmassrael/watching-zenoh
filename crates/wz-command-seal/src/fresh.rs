// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a sealed command is fresh: its counter above its commander's last, and, for a commander
//! the node has taken no counter from since it started, proof that it was sealed after that start.
//!
//! The window is memory, so a node that starts again has forgotten every counter and would take a
//! command sealed before it started once more. OSCORE recovers a lost replay window with the Echo
//! option (RFC 8613, appendix B.1.2) and keeps no window across a start, and so does a node here
//! (decision D20 of `docs/session-lifecycle-intent.md`): it draws a value when it starts and
//! refuses a command from a commander it holds no counter for until the command carries that value
//! ([`SealError::EchoRequired`] hands it out). A command sealed before the start cannot carry it, so
//! none is taken twice, whatever the node's storage holds; a window written down and given back
//! would accept again every command taken after the copy was made, should the storage be rolled
//! back to it.
//!
//! Appendix B.1.1 is the sender's half, the commander's: it keeps its counter in nonvolatile memory
//! in steps of K and starts above the stored value, so it never needs a node to tell it its last.

use crate::{Echo, ReplayWindow, SealError, Sealed, Slot, Verified};

/// The replay window of a node, made with its policy, and the echo of its last start: the
/// freshness of every sealed command it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness<S> {
    window: ReplayWindow<S>,
    echo: Echo,
}

impl<S: AsRef<[Slot]> + AsMut<[Slot]>> Freshness<S> {
    /// A node that has just started, with a slot for each commander its policy grants and no
    /// counter in any: each commander's first command carries `echo`, a value the node drew from
    /// its entropy when it started and never used before.
    pub const fn started(window: ReplayWindow<S>, echo: Echo) -> Self {
        Self { window, echo }
    }

    /// The counters taken since the start.
    pub const fn window(&self) -> &ReplayWindow<S> {
        &self.window
    }

    /// Whether `sealed` would be taken, taking nothing: a counter not above its commander's last
    /// is [`SealError::Replay`], and a commander the window has taken no counter from is
    /// [`SealError::EchoRequired`] unless the command carries the node's echo. The echo of a
    /// commander the window holds a counter for is not read: its counter already refuses what it
    /// sealed before.
    ///
    /// A commander with no slot is not judged here: no grant names it, so the reference monitor
    /// refuses it before it asks the admission that takes the counter, and [`Self::take`] refuses
    /// it as [`SealError::NoContext`] should a policy permit it all the same.
    pub fn check(&self, sealed: &Sealed) -> Result<(), SealError> {
        let Some(slot) = self.window.slot(&sealed.commander) else {
            return Ok(());
        };
        match slot.last() {
            Some(last) if sealed.counter > last => Ok(()),
            Some(last) => Err(SealError::Replay { last }),
            None if sealed.echo == Some(self.echo) => Ok(()),
            None => Err(SealError::EchoRequired { echo: self.echo }),
        }
    }

    /// Take the counter of `verified`: the command, or the refusal of [`Self::check`], or
    /// [`SealError::NoContext`] for a commander with no slot. A refusal changes nothing.
    pub fn take(&mut self, verified: Verified) -> Result<Sealed, SealError> {
        self.check(verified.sealed())?;
        verified.take(&mut self.window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Object, Verb, Zid};

    const A: Zid = [0xa0; 16];
    const B: Zid = [0xb0; 16];
    const C: Zid = [0xc0; 16];
    const BOOT: Echo = [0x5e; 16];
    const EARLIER_BOOT: Echo = [0x4d; 16];

    fn command(commander: Zid, counter: u64, echo: Option<Echo>) -> Sealed {
        Sealed {
            commander,
            verb: Verb::Close,
            object: Object {
                peer: [0x20; 16],
                generation: None,
            },
            counter,
            echo,
        }
    }

    fn started(commanders: [Zid; 2]) -> Freshness<[Slot; 2]> {
        Freshness::started(ReplayWindow::granting(commanders.map(Slot::granted)), BOOT)
    }

    /// After a start the first command of a commander is refused with the node's echo, and the
    /// same command repeated with it is taken; one carrying another start's echo is refused too.
    /// Red if `check` let a commander with no counter through without the echo.
    #[test]
    fn a_commander_with_no_counter_is_asked_for_the_echo_and_taken_with_it() {
        let mut fresh = started([A, B]);
        assert_eq!(
            fresh.check(&command(A, 5, None)),
            Err(SealError::EchoRequired { echo: BOOT })
        );
        assert_eq!(
            fresh.check(&command(A, 5, Some(EARLIER_BOOT))),
            Err(SealError::EchoRequired { echo: BOOT }),
            "an echo of an earlier start proves nothing"
        );
        assert_eq!(fresh.window().last(&A), None, "a challenge takes nothing");
        assert_eq!(fresh.check(&command(A, 6, Some(BOOT))), Ok(()));
        assert_eq!(fresh.window.accept(&A, 6), Ok(()));
        // Held now: its counter refuses the earlier command, echo or none.
        assert_eq!(
            fresh.check(&command(A, 5, Some(BOOT))),
            Err(SealError::Replay { last: 6 })
        );
        assert_eq!(fresh.check(&command(A, 7, None)), Ok(()));
        // Another commander is still asked.
        assert_eq!(
            fresh.check(&command(B, 100, None)),
            Err(SealError::EchoRequired { echo: BOOT })
        );
    }

    /// A commander no grant names passes the check, which leaves it to the monitor, and its
    /// counter is never taken. Red if `take` gave it a slot, or `check` answered it with the
    /// echo of a context the node does not hold.
    #[test]
    fn a_commander_no_grant_names_is_left_to_the_monitor_and_never_taken() {
        let mut fresh = started([A, B]);
        assert_eq!(fresh.check(&command(C, 1, None)), Ok(()));
        let verified = Verified {
            sealed: command(C, 1, Some(BOOT)),
        };
        assert_eq!(fresh.take(verified), Err(SealError::NoContext));
        assert_eq!(fresh.window().last(&C), None);
    }
}
