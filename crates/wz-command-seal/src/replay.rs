// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The counters a node has taken, one per commander: the replay protection of OSCORE (RFC 8613,
//! section 7.4) in its narrowest form, a counter that only rises.
//!
//! A lifecycle command is rare and its commander sends it and waits for the answer, so the
//! window OSCORE keeps for messages arriving out of order is not needed: a counter above the
//! commander's last is taken, any other is a replay. A commander with two commands in flight
//! gives the later counter to the one it sends later; the other, if it arrives second, is refused
//! and sent again with a new counter.
//!
//! The table has a fixed number of commanders and no allocator. A commander it has no room for is
//! refused ([`SealError::WindowFull`]), and no commander is ever evicted: forgetting one would
//! let every command it ever sealed be replayed once more.

use crate::{SealError, Zid};

/// The last counter taken from each of up to `N` commanders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow<const N: usize> {
    entries: [Option<(Zid, u64)>; N],
}

impl<const N: usize> ReplayWindow<N> {
    /// A window that has taken nothing.
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// How many commanders the window can hold.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The last counter taken from `commander`, if any was.
    pub fn last(&self, commander: &Zid) -> Option<u64> {
        self.iter()
            .find(|(held, _)| *held == commander)
            .map(|(_, counter)| counter)
    }

    /// Whether the window has room for a commander it holds no counter for.
    pub fn has_room(&self) -> bool {
        self.entries.iter().any(Option::is_none)
    }

    /// Every commander held and its last counter: what a node that keeps the window across a
    /// restart writes down, and gives back to [`Self::accept`] when it starts.
    pub fn iter(&self) -> impl Iterator<Item = (&Zid, u64)> + '_ {
        self.entries
            .iter()
            .flatten()
            .map(|(commander, counter)| (commander, *counter))
    }

    /// Take `counter` from `commander` if it is above the commander's last, and remember it.
    ///
    /// Refused as [`SealError::Replay`] when it is not above, and as
    /// [`SealError::WindowFull`] for a commander the window holds no counter for and has no room
    /// for. A refusal changes nothing.
    pub fn accept(&mut self, commander: &Zid, counter: u64) -> Result<(), SealError> {
        if let Some((_, last)) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|(held, _)| held == commander)
        {
            if counter <= *last {
                return Err(SealError::Replay { last: *last });
            }
            *last = counter;
            return Ok(());
        }
        let free = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(SealError::WindowFull)?;
        *free = Some((*commander, counter));
        Ok(())
    }
}

impl<const N: usize> Default for ReplayWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Zid = [0xa0; 16];
    const B: Zid = [0xb0; 16];
    const C: Zid = [0xc0; 16];

    #[test]
    fn a_rising_counter_is_taken_and_one_not_above_the_last_is_a_replay() {
        let mut window = ReplayWindow::<2>::new();
        assert_eq!(
            window.accept(&A, 0),
            Ok(()),
            "the first counter of a commander"
        );
        assert_eq!(window.accept(&A, 5), Ok(()));
        assert_eq!(window.accept(&A, 5), Err(SealError::Replay { last: 5 }));
        assert_eq!(window.accept(&A, 3), Err(SealError::Replay { last: 5 }));
        assert_eq!(window.last(&A), Some(5), "a refusal changes nothing");
        assert_eq!(window.accept(&A, 6), Ok(()));
        assert_eq!(window.last(&A), Some(6));
    }

    #[test]
    fn each_commander_has_its_own_counter() {
        let mut window = ReplayWindow::<2>::new();
        assert_eq!(window.accept(&A, 9), Ok(()));
        assert_eq!(window.accept(&B, 1), Ok(()), "A's counter is not B's");
        assert_eq!(window.last(&A), Some(9));
        assert_eq!(window.last(&B), Some(1));
        assert_eq!(window.last(&C), None);
    }

    #[test]
    fn a_full_window_refuses_a_new_commander_and_forgets_none() {
        let mut window = ReplayWindow::<2>::new();
        assert_eq!(window.capacity(), 2);
        assert_eq!(window.accept(&A, 1), Ok(()));
        assert_eq!(window.accept(&B, 1), Ok(()));
        assert_eq!(window.accept(&C, 1), Err(SealError::WindowFull));
        assert_eq!(window.last(&C), None);
        assert_eq!(
            window.accept(&A, 1),
            Err(SealError::Replay { last: 1 }),
            "A kept"
        );
        assert_eq!(
            window.accept(&B, 2),
            Ok(()),
            "a held commander is still served"
        );
        let held: std::vec::Vec<(Zid, u64)> = window.iter().map(|(z, c)| (*z, c)).collect();
        assert_eq!(held, [(A, 1), (B, 2)]);
    }

    #[test]
    fn a_window_of_no_commanders_takes_nothing() {
        let mut window = ReplayWindow::<0>::default();
        assert_eq!(window.accept(&A, 1), Err(SealError::WindowFull));
    }

    #[test]
    fn a_window_written_down_and_given_back_refuses_what_it_refused_before() {
        let mut before = ReplayWindow::<2>::new();
        assert_eq!(before.accept(&A, 7), Ok(()));
        let mut after = ReplayWindow::<2>::new();
        for (commander, counter) in before.iter() {
            assert_eq!(after.accept(commander, counter), Ok(()));
        }
        assert_eq!(after.accept(&A, 7), Err(SealError::Replay { last: 7 }));
        assert_eq!(after, before);
    }
}
