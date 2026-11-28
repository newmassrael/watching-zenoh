// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a sealed command is fresh: its counter above its commander's last, and, for a commander
//! the node holds no counter for, proof that it was sealed after the node last started.
//!
//! The window is memory, so a node that starts again has forgotten every counter and would take a
//! command sealed before it started once more. OSCORE meets that loss two ways (RFC 8613, appendix
//! B.1), and both are here. With an echo (appendix B.1.2) the node draws a value when it starts and
//! refuses a command from a commander it holds no counter for until the command carries that value
//! ([`SealError::EchoRequired`] hands it out); a command sealed before the start cannot carry it,
//! so none is taken twice, and the node keeps no state across the start. A node that writes its
//! window down before it answers each command it takes and gives it back when it starts (appendix
//! B.1.1) has lost nothing, and needs no echo: [`Restart::Persisted`].

use crate::{Echo, ReplayWindow, SealError, Sealed, Verified};

/// What a node knows of the commands taken before it last started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// Nothing: a commander the window holds no counter for proves its command is newer than the
    /// start by carrying this echo, which the node drew when it started.
    Echo(Echo),
    /// Everything: the window was given back as it was written down after the last command the
    /// node took, so a counter it holds is the commander's last.
    Persisted,
}

/// The replay window of a node and what it knows of its last start: the freshness of every sealed
/// command it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness<const N: usize> {
    window: ReplayWindow<N>,
    restart: Restart,
}

impl<const N: usize> Freshness<N> {
    /// A node that has just started and remembers no counter: each commander's first command
    /// carries `echo`, a value the node drew from its entropy when it started and never used
    /// before.
    pub const fn echo(echo: Echo) -> Self {
        Self {
            window: ReplayWindow::new(),
            restart: Restart::Echo(echo),
        }
    }

    /// A node that gave back the window it wrote down: no echo is asked.
    pub const fn persisted(window: ReplayWindow<N>) -> Self {
        Self {
            window,
            restart: Restart::Persisted,
        }
    }

    /// What the node knows of its last start.
    pub const fn restart(&self) -> Restart {
        self.restart
    }

    /// The counters taken, which a node that persists its window writes down after each take.
    pub const fn window(&self) -> &ReplayWindow<N> {
        &self.window
    }

    /// Whether `sealed` would be taken, taking nothing: a counter not above its commander's last
    /// is [`SealError::Replay`]; a commander the window holds no counter for is
    /// [`SealError::EchoRequired`] unless the command carries the node's echo, and
    /// [`SealError::WindowFull`] when the window has no room for it. The echo of a commander the
    /// window holds is not read: its counter already refuses what it sealed before.
    pub fn check(&self, sealed: &Sealed) -> Result<(), SealError> {
        if let Some(last) = self.window.last(&sealed.commander) {
            return if sealed.counter > last {
                Ok(())
            } else {
                Err(SealError::Replay { last })
            };
        }
        if let Restart::Echo(echo) = self.restart {
            if sealed.echo != Some(echo) {
                return Err(SealError::EchoRequired { echo });
            }
        }
        if !self.window.has_room() {
            return Err(SealError::WindowFull);
        }
        Ok(())
    }

    /// Take the counter of `verified`: the command, or the refusal of [`Self::check`]. A refusal
    /// changes nothing.
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

    /// After a start the first command of a commander is refused with the node's echo, and the
    /// same command repeated with it is taken; one carrying another start's echo is refused too.
    /// Red if `check` let a commander with no counter through without the echo.
    #[test]
    fn a_commander_with_no_counter_is_asked_for_the_echo_and_taken_with_it() {
        let mut fresh = Freshness::<2>::echo(BOOT);
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

    /// A window given back as it was written down asks for no echo and still refuses a replay.
    #[test]
    fn a_persisted_window_asks_no_echo_and_refuses_what_it_took() {
        let mut written = ReplayWindow::<2>::new();
        assert_eq!(written.accept(&A, 9), Ok(()));
        let fresh = Freshness::persisted(written);
        assert_eq!(fresh.restart(), Restart::Persisted);
        assert_eq!(
            fresh.check(&command(A, 9, None)),
            Err(SealError::Replay { last: 9 })
        );
        assert_eq!(fresh.check(&command(A, 10, None)), Ok(()));
        assert_eq!(fresh.check(&command(B, 1, None)), Ok(()));
    }

    /// A full window refuses a new commander that carries the echo, and serves the held one.
    #[test]
    fn a_full_window_refuses_a_new_commander_even_with_the_echo() {
        let mut fresh = Freshness::<1>::echo(BOOT);
        assert_eq!(fresh.window.accept(&A, 1), Ok(()));
        assert_eq!(
            fresh.check(&command(B, 1, Some(BOOT))),
            Err(SealError::WindowFull)
        );
        assert_eq!(fresh.check(&command(A, 2, None)), Ok(()));
    }
}
