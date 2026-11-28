// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The counters a node takes, one slot per commander its policy grants: the replay protection of
//! OSCORE (RFC 8613, section 7.4) in its narrowest form, a counter that only rises, kept in what
//! OSCORE calls the recipient context.
//!
//! A lifecycle command is rare and its commander sends it and waits for the answer, so the
//! window OSCORE keeps for messages arriving out of order is not needed: a counter above the
//! commander's last is taken, any other is a replay. A commander with two commands in flight
//! gives the later counter to the one it sends later; the other, if it arrives second, is refused
//! and sent again with a new counter.
//!
//! OSCORE establishes a recipient context with the security context, before the first message
//! (RFC 8613, section 3), so the state a message is checked against exists before it arrives.
//! Here likewise (decision D19 of `docs/session-lifecycle-intent.md`): the window is made with the
//! policy, one slot for each distinct commander the declaration grants a verb to, at build time
//! on the fixed profile and once, when the declaration is read, on the heap profile. No slot is
//! free and none is evicted: forgetting a commander would let every command it ever sealed be
//! replayed once more. A commander with no slot is one no grant names; the node holds no context
//! for it, as OSCORE's recipient holds none for an unknown `kid` (RFC 8613, section 8.2, step 2),
//! and its counter is never taken ([`SealError::NoContext`]).

use crate::{SealError, Zid};

/// The replay state of one granted commander: its zid, and the last counter taken from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    commander: Zid,
    last: Option<u64>,
}

impl Slot {
    /// The slot of `commander`, which a grant names, before any command of it is taken.
    pub const fn granted(commander: Zid) -> Self {
        Self {
            commander,
            last: None,
        }
    }

    /// The commander the slot is for.
    pub const fn commander(&self) -> &Zid {
        &self.commander
    }

    /// The last counter taken from the commander, if any was.
    pub const fn last(&self) -> Option<u64> {
        self.last
    }
}

/// The slots of the commanders a node's policy grants, in the storage `S` holds them in: an
/// array the build sizes on the fixed profile, a boxed slice the declaration sizes on the heap
/// profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow<S> {
    slots: S,
}

impl<S: AsRef<[Slot]> + AsMut<[Slot]>> ReplayWindow<S> {
    /// The window of `slots`, each made with [`Slot::granted`] for a distinct commander. A zid
    /// given twice is looked up in its first slot, and the second is never written.
    pub const fn granting(slots: S) -> Self {
        Self { slots }
    }

    /// The commanders the window holds a slot for.
    pub fn commanders(&self) -> impl Iterator<Item = &Zid> + '_ {
        self.slots.as_ref().iter().map(Slot::commander)
    }

    /// The slot of `commander`: `None` for a commander no grant names.
    pub fn slot(&self, commander: &Zid) -> Option<&Slot> {
        self.slots
            .as_ref()
            .iter()
            .find(|slot| slot.commander == *commander)
    }

    /// The last counter taken from `commander`, if it has a slot and any was taken.
    pub fn last(&self, commander: &Zid) -> Option<u64> {
        self.slot(commander).and_then(Slot::last)
    }

    /// Take `counter` from `commander` if it is above the commander's last, and remember it.
    ///
    /// Refused as [`SealError::Replay`] when it is not above, and as [`SealError::NoContext`]
    /// for a commander with no slot. A refusal changes nothing.
    pub fn accept(&mut self, commander: &Zid, counter: u64) -> Result<(), SealError> {
        let slot = self
            .slots
            .as_mut()
            .iter_mut()
            .find(|slot| slot.commander == *commander)
            .ok_or(SealError::NoContext)?;
        if let Some(last) = slot.last {
            if counter <= last {
                return Err(SealError::Replay { last });
            }
        }
        slot.last = Some(counter);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Zid = [0xa0; 16];
    const B: Zid = [0xb0; 16];
    const C: Zid = [0xc0; 16];

    fn granting<const N: usize>(commanders: [Zid; N]) -> ReplayWindow<[Slot; N]> {
        ReplayWindow::granting(commanders.map(Slot::granted))
    }

    #[test]
    fn a_rising_counter_is_taken_and_one_not_above_the_last_is_a_replay() {
        let mut window = granting([A, B]);
        assert_eq!(
            window.last(&A),
            None,
            "a slot made with the policy holds no counter"
        );
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
        let mut window = granting([A, B]);
        assert_eq!(window.accept(&A, 9), Ok(()));
        assert_eq!(window.accept(&B, 1), Ok(()), "A's counter is not B's");
        assert_eq!(window.last(&A), Some(9));
        assert_eq!(window.last(&B), Some(1));
    }

    /// A commander no grant names has no slot, whatever the others took: its counter is never
    /// taken and no granted commander's slot is given to it. Red if `accept` made a slot for an
    /// unknown zid, or took one from a granted commander.
    #[test]
    fn a_commander_no_grant_names_has_no_slot_and_takes_none() {
        let mut window = granting([A, B]);
        assert_eq!(window.accept(&C, 1), Err(SealError::NoContext));
        assert_eq!(window.slot(&C), None);
        assert_eq!(window.accept(&A, 1), Ok(()));
        assert_eq!(window.accept(&B, 1), Ok(()));
        assert_eq!(window.accept(&C, 2), Err(SealError::NoContext));
        assert_eq!(
            window.commanders().copied().collect::<std::vec::Vec<_>>(),
            [A, B],
            "the slots are the policy's, before and after"
        );
    }

    #[test]
    fn a_window_of_no_grant_takes_nothing() {
        let mut window = granting([]);
        assert_eq!(window.accept(&A, 1), Err(SealError::NoContext));
    }

    /// The heap profile's storage: a slice the declaration sized, read as the array is.
    #[test]
    fn a_boxed_window_is_read_as_an_array_is() {
        let slots: std::boxed::Box<[Slot]> = [A, B].map(Slot::granted).into();
        let mut window = ReplayWindow::granting(slots);
        assert_eq!(window.accept(&B, 4), Ok(()));
        assert_eq!(window.accept(&B, 4), Err(SealError::Replay { last: 4 }));
        assert_eq!(window.accept(&C, 1), Err(SealError::NoContext));
    }
}
