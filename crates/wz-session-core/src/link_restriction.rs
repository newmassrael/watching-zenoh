// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which links an entity may use: the part of the `entity-link-restriction` policy that every
//! engine shares.
//!
//! # The decision
//!
//! [`crate::locality::Locality`] answers one question about an entity, whether it takes part in
//! traffic of this session, of other nodes, or of both. A node with several links, one to each
//! of several peers or a dialled one beside its listeners, has a second question that
//! locality cannot state: of the links, which ones. An entity may be declared to a node only on
//! the link that reaches the node's own region, a publisher may be wanted on one link and not
//! on the others, a queryable may serve the links of one port only.
//! [`crate::link_restriction::LinkRestriction`] is that answer, and it is a value of the
//! declaration, like locality, so the engines that hold several links apply it where they
//! already apply locality and nowhere else.
//!
//! # What names a link
//!
//! A link is named by a [`crate::link_restriction::LinkSlot`]: a small number the engine
//! derives from how the link came to be. Each listener of a session is one slot and the
//! dialling role is one slot, so the faces a listener accepts share its slot, and a restriction
//! naming the slot names all of them and the ones that arrive later. The numbering is the
//! engine's (it is stated where the engine derives it), and the restriction only holds the set.
//!
//! # The default is no restriction
//!
//! [`crate::link_restriction::LinkRestriction::Any`] is what an entity that states nothing has,
//! and it allows every link, including a link that has no slot: that is upstream's behaviour
//! and the only one a build without the policy has. A restricted entity
//! ([`crate::link_restriction::LinkRestriction::only`]) allows exactly the
//! slots it names; a link that has no slot (the engine could not number it) is not allowed,
//! because an unnamed link cannot have been named. The set is never empty: an entity that may
//! use no link is not a restriction, it is an entity that cannot be reached, and it is refused
//! where it is built.

/// How many slots a restriction can name. A restriction is one machine word, so it costs the
/// entity eight bytes and no allocation, and a build never needs the slot count as a limit.
pub const LINK_SLOTS: u8 = 64;

/// The number of a link, below [`LINK_SLOTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkSlot(u8);

impl LinkSlot {
    /// The slot `n`, or `None` when `n` is past [`LINK_SLOTS`].
    pub const fn new(n: u8) -> Option<Self> {
        if n < LINK_SLOTS {
            Some(Self(n))
        } else {
            None
        }
    }

    /// The number of the slot.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Why a restriction could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRestrictionError {
    /// The set names no link: an entity that may use none is unreachable, not restricted.
    Empty,
    /// A slot is past [`LINK_SLOTS`].
    SlotOutOfRange(u8),
    /// The build's `entity-link-restriction` policy is off, so no entity may state a set.
    PolicyOff,
}

impl core::fmt::Display for LinkRestrictionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("a link restriction must name at least one link"),
            Self::SlotOutOfRange(n) => {
                write!(
                    f,
                    "link slot {n} is past the {LINK_SLOTS} a restriction can name"
                )
            }
            Self::PolicyOff => f.write_str(
                "this build does not let an entity be limited to some links \
                 (policy entity-link-restriction is off)",
            ),
        }
    }
}

impl core::error::Error for LinkRestrictionError {}

/// The links an entity may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LinkRestriction {
    /// Every link, including one that has no slot. The default, and upstream's behaviour.
    #[default]
    Any,
    /// Exactly the links of these slots: a non-empty set, one bit per slot.
    Only(u64),
}

impl LinkRestriction {
    /// A restriction to the links of `slots`. Refused when `slots` is empty or names a slot
    /// past [`LINK_SLOTS`]; a slot named twice is named once.
    pub fn only(slots: impl IntoIterator<Item = u8>) -> Result<Self, LinkRestrictionError> {
        let mut mask = 0u64;
        for n in slots {
            let slot = LinkSlot::new(n).ok_or(LinkRestrictionError::SlotOutOfRange(n))?;
            mask |= 1u64 << slot.get();
        }
        if mask == 0 {
            return Err(LinkRestrictionError::Empty);
        }
        Ok(Self::Only(mask))
    }

    /// Whether the entity may use the link of `slot`. A link with no slot is allowed only by
    /// [`LinkRestriction::Any`].
    pub const fn allows(self, slot: Option<LinkSlot>) -> bool {
        match self {
            Self::Any => true,
            Self::Only(mask) => match slot {
                Some(slot) => mask & (1u64 << slot.get()) != 0,
                None => false,
            },
        }
    }

    /// Whether the entity is restricted at all.
    pub const fn is_restricted(self) -> bool {
        matches!(self, Self::Only(_))
    }

    /// This restriction, admitted by a policy that is `enabled` or refused: a restricted entity
    /// is [`LinkRestrictionError::PolicyOff`] when the policy is off, and no restriction is
    /// always admitted. The refusal is the whole of what the policy does, so a build without it
    /// has upstream's entities only and a call that states a set says so instead of being
    /// ignored.
    pub const fn admit(self, enabled: bool) -> Result<Self, LinkRestrictionError> {
        if self.is_restricted() && !enabled {
            Err(LinkRestrictionError::PolicyOff)
        } else {
            Ok(self)
        }
    }

    /// [`Self::admit`] by this build's `entity-link-restriction` policy: the call every entry
    /// point that takes a restriction from a caller makes.
    pub const fn admit_in_build(self) -> Result<Self, LinkRestrictionError> {
        self.admit(crate::policy::SessionPolicy::from_build().entity_link_restriction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u8) -> Option<LinkSlot> {
        LinkSlot::new(n)
    }

    #[test]
    fn the_default_allows_every_link_including_one_with_no_slot() {
        let any = LinkRestriction::default();
        assert_eq!(any, LinkRestriction::Any);
        assert!(!any.is_restricted());
        assert!(any.allows(None));
        assert!(any.allows(slot(0)));
        assert!(any.allows(slot(LINK_SLOTS - 1)));
    }

    #[test]
    fn a_restriction_allows_exactly_the_slots_it_names() {
        let only = LinkRestriction::only([1, 5, 63]).expect("three slots");
        assert!(only.is_restricted());
        for n in 0..LINK_SLOTS {
            let named = matches!(n, 1 | 5 | 63);
            assert_eq!(only.allows(slot(n)), named, "slot {n}");
        }
    }

    #[test]
    fn a_link_with_no_slot_is_not_allowed_by_a_restriction() {
        let only = LinkRestriction::only([0]).expect("one slot");
        assert!(!only.allows(None));
    }

    #[test]
    fn a_slot_named_twice_is_named_once() {
        assert_eq!(LinkRestriction::only([2, 2, 2]), LinkRestriction::only([2]));
    }

    #[test]
    fn the_policy_decides_whether_a_set_may_be_stated_and_nothing_else() {
        let only = LinkRestriction::only([4]).expect("one slot");
        // Off: no restriction passes, a restriction is refused.
        assert_eq!(LinkRestriction::Any.admit(false), Ok(LinkRestriction::Any));
        assert_eq!(only.admit(false), Err(LinkRestrictionError::PolicyOff));
        // On: both pass, unchanged.
        assert_eq!(LinkRestriction::Any.admit(true), Ok(LinkRestriction::Any));
        assert_eq!(only.admit(true), Ok(only));
        // The build's own answer is the policy's: off unless the build stated it.
        let in_build = crate::policy::SessionPolicy::from_build().entity_link_restriction;
        assert_eq!(only.admit_in_build().is_ok(), in_build);
        assert!(LinkRestriction::Any.admit_in_build().is_ok());
    }

    #[test]
    fn an_empty_set_and_a_slot_out_of_range_are_refused() {
        assert_eq!(
            LinkRestriction::only(core::iter::empty()),
            Err(LinkRestrictionError::Empty)
        );
        assert_eq!(
            LinkRestriction::only([3, LINK_SLOTS]),
            Err(LinkRestrictionError::SlotOutOfRange(LINK_SLOTS))
        );
        assert_eq!(LinkSlot::new(LINK_SLOTS), None);
        assert_eq!(LinkSlot::new(LINK_SLOTS - 1).map(LinkSlot::get), Some(63));
    }
}
