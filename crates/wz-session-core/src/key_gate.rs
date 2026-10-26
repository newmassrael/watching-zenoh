// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a closed key set refuses, and counts (`docs/closed-key-set.md`, phase 2).
//!
//! # What it is
//!
//! A [`KeyGate`] stands in front of the keys a host handles. An open gate admits every key and
//! looks at none, which is upstream's behaviour. A closed gate holds a
//! [`KeyCatalogue`](crate::key_catalogue::KeyCatalogue) and admits only what the catalogue has:
//! [`KeyGate::admit_key`] a key that is one of the set (a message's key, a peer's resource), and
//! [`KeyGate::admit_declared`] a key the image declares in the role being asked (a local
//! declaration of a subscriber, a publisher, a queryable). Both answer with the key's
//! [`KeyId`](crate::key_catalogue::KeyId), so what is admitted is already numbered.
//!
//! # The rules it states once
//!
//! * The answer is the refusal's reason, and every refusal is counted by it, saturating: a counter
//!   that wrapped would hide the refusals it exists to show. An open gate refuses nothing and
//!   counts nothing.
//! * A key is looked up as it is spelled. Nothing is split and nothing is matched: a key that a
//!   declared wildcard would cover is not in the set unless it is declared itself (decision D4).
//! * A pattern is a key of the set when it is declared, so declaring a subscriber on `a/**` is
//!   admitted by the text `a/**` and not by what it would match.
//! * The gate owns no table and no memory beyond its counters; the catalogue is borrowed, and the
//!   host decides where a refusal goes (a typed result, a drop, a close).
//!
//! # Where it is read
//!
//! Nowhere yet: no host calls it, and the `key-set` policy that would choose between the two gates
//! is not declared, because a switch that no host acts on would tell a deployer a build is closed
//! when nothing is. The policy lands with the first host that refuses on it.

use crate::key_catalogue::{EntityKind, KeyCatalogue, KeyId};

/// Why a closed gate did not admit a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The text is not a key of the set.
    OutsideSet,
    /// The text is a key of the set, and the image declares no entity of this kind on it.
    RoleNotDeclared(EntityKind),
}

/// What an admitted key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// The gate is open: the key was not looked at and has no number.
    Unchecked,
    /// The gate is closed and the key is this one of the set.
    Key(KeyId),
}

/// How many keys a gate refused, by reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Refused {
    /// Every reason together.
    pub total: usize,
    /// [`Refusal::OutsideSet`].
    pub outside_set: usize,
    /// [`Refusal::RoleNotDeclared`], for every kind.
    pub role_not_declared: usize,
}

/// The gate a host puts in front of its keys. See the module note.
#[derive(Debug, Clone, Copy)]
pub struct KeyGate<'a> {
    catalogue: Option<&'a KeyCatalogue<'a>>,
    refused: Refused,
}

impl<'a> KeyGate<'a> {
    /// The gate of an open image: admits every key, looks at none.
    pub const fn open() -> Self {
        Self {
            catalogue: None,
            refused: Refused {
                total: 0,
                outside_set: 0,
                role_not_declared: 0,
            },
        }
    }

    /// The gate of a closed image over its catalogue.
    pub const fn closed(catalogue: &'a KeyCatalogue<'a>) -> Self {
        Self {
            catalogue: Some(catalogue),
            ..Self::open()
        }
    }

    /// Whether the gate refuses anything.
    pub const fn is_closed(&self) -> bool {
        self.catalogue.is_some()
    }

    /// Admit a key that is one of the set: the key of a message, or of a resource a peer declares.
    pub fn admit_key(&mut self, text: &str) -> Result<Admitted, Refusal> {
        let Some(catalogue) = self.catalogue else {
            return Ok(Admitted::Unchecked);
        };
        match catalogue.find_exact(text) {
            Some(key) => Ok(Admitted::Key(key)),
            None => Err(self.refuse(Refusal::OutsideSet)),
        }
    }

    /// Admit a key the image declares as a `kind`: a local declaration. The key must be one of the
    /// set and the image must declare an entity of that kind on it.
    pub fn admit_declared(&mut self, text: &str, kind: EntityKind) -> Result<Admitted, Refusal> {
        let Some(catalogue) = self.catalogue else {
            return Ok(Admitted::Unchecked);
        };
        let Some(key) = catalogue.find_exact(text) else {
            return Err(self.refuse(Refusal::OutsideSet));
        };
        match catalogue.find_entity(kind, key) {
            Some(_) => Ok(Admitted::Key(key)),
            None => Err(self.refuse(Refusal::RoleNotDeclared(kind))),
        }
    }

    /// How many keys the gate refused, by reason.
    pub const fn refused(&self) -> Refused {
        self.refused
    }

    fn refuse(&mut self, reason: Refusal) -> Refusal {
        self.refused.total = self.refused.total.saturating_add(1);
        match reason {
            Refusal::OutsideSet => {
                self.refused.outside_set = self.refused.outside_set.saturating_add(1);
            }
            Refusal::RoleNotDeclared(_) => {
                self.refused.role_not_declared = self.refused.role_not_declared.saturating_add(1);
            }
        }
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_catalogue::tests::TABLE;

    #[test]
    fn an_open_gate_admits_everything_and_counts_nothing() {
        let mut gate = KeyGate::open();
        assert!(!gate.is_closed());
        for text in ["a", "a/b", "nothing", "", "a/**"] {
            assert_eq!(gate.admit_key(text), Ok(Admitted::Unchecked));
            assert_eq!(
                gate.admit_declared(text, EntityKind::Publisher),
                Ok(Admitted::Unchecked)
            );
        }
        assert_eq!(gate.refused(), Refused::default());
    }

    #[test]
    fn a_closed_gate_admits_the_keys_of_the_set_by_number() {
        let mut gate = KeyGate::closed(&TABLE);
        assert!(gate.is_closed());
        assert_eq!(gate.admit_key("a"), Ok(Admitted::Key(KeyId::new(0))));
        assert_eq!(gate.admit_key("a/*"), Ok(Admitted::Key(KeyId::new(1))));
        assert_eq!(gate.admit_key("a/b"), Ok(Admitted::Key(KeyId::new(2))));
        assert_eq!(gate.refused(), Refused::default());
    }

    #[test]
    fn a_closed_gate_refuses_a_key_outside_the_set_even_when_a_pattern_covers_it() {
        let mut gate = KeyGate::closed(&TABLE);
        // `a/*` is declared and covers `a/c`, which is not declared (decision D4).
        assert_eq!(gate.admit_key("a/c"), Err(Refusal::OutsideSet));
        assert_eq!(gate.admit_key(""), Err(Refusal::OutsideSet));
        assert_eq!(
            gate.admit_declared("a/c", EntityKind::Subscriber),
            Err(Refusal::OutsideSet)
        );
        assert_eq!(
            gate.refused(),
            Refused {
                total: 3,
                outside_set: 3,
                role_not_declared: 0
            }
        );
    }

    #[test]
    fn a_declaration_is_admitted_in_the_role_the_image_declares_and_refused_in_another() {
        let mut gate = KeyGate::closed(&TABLE);
        assert_eq!(
            gate.admit_declared("a/b", EntityKind::Publisher),
            Ok(Admitted::Key(KeyId::new(2)))
        );
        assert_eq!(
            gate.admit_declared("a/*", EntityKind::Subscriber),
            Ok(Admitted::Key(KeyId::new(1)))
        );
        // The key is in the set, the role is not declared on it.
        assert_eq!(
            gate.admit_declared("a/b", EntityKind::Subscriber),
            Err(Refusal::RoleNotDeclared(EntityKind::Subscriber))
        );
        assert_eq!(
            gate.admit_declared("a", EntityKind::Publisher),
            Err(Refusal::RoleNotDeclared(EntityKind::Publisher))
        );
        // A message's key does not need a role: `a/b` is one of the set whoever publishes it.
        assert_eq!(gate.admit_key("a/b"), Ok(Admitted::Key(KeyId::new(2))));
        assert_eq!(
            gate.refused(),
            Refused {
                total: 2,
                outside_set: 0,
                role_not_declared: 2
            }
        );
    }

    #[test]
    fn the_counters_saturate_and_never_wrap() {
        let mut gate = KeyGate::closed(&TABLE);
        gate.refused.total = usize::MAX;
        gate.refused.outside_set = usize::MAX;
        assert_eq!(gate.admit_key("x"), Err(Refusal::OutsideSet));
        assert_eq!(gate.refused().total, usize::MAX);
        assert_eq!(gate.refused().outside_set, usize::MAX);
    }
}
