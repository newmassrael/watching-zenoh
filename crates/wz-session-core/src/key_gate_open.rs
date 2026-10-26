// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key gate of a build that has no closed key set (`docs/closed-key-set.md`): the module a
//! build without the `key-set-closed` feature has in the place of `key_gate`.
//!
//! # What it is
//!
//! The same names and the same calls as the closed module, with the one answer an open gate
//! gives: every key is admitted, none is looked at, nothing is counted. The host code that asks
//! the gate is written once and does not know which build it is in.
//!
//! # Why it costs nothing
//!
//! * `KeyGate` has no field, so a table or a registry that holds one holds no byte.
//! * `KeyId`, `EntityId`, `ClassId` and `Refusal` have no value (an enum with no
//!   variant). A field of type `Option<EntityId>` on every subscriber row, or `Option<ClassId>`
//!   on every peer, can only be `None` and has no size; a match arm that reads a number is one
//!   the compiler can see is never taken, and the code behind it is not generated.
//! * Nothing here can be given a closed table, because there is none: the build that has a
//!   closed key set is the one with the feature, and a build whose `key-set` policy is `closed`
//!   without it does not compile (`KeyGate::of_build`).

use crate::policy::{KeySet, SessionPolicy};

/// A key of the closed set. Has no value here: no key is numbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyId {}

/// An entity the image declares. Has no value here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityId {}

/// A peer the image declares. Has no value here: no peer is a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassId {}

/// What an entity is, as far as a caller of the gate names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    /// Receives the samples on the keys its pattern intersects.
    Subscriber,
}

/// What a peer does with a key that an allowance decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOp {
    /// The peer sends a message on the key.
    Publish,
}

/// Why a closed gate did not admit a key. Has no value here: an open gate refuses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {}

/// What an admitted key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// The gate is open: the key was not looked at and has no number.
    Unchecked,
    /// The gate is closed and the key is this one of the set. Not constructible here.
    Key(KeyId),
}

/// How many keys a gate refused, by reason: always zero here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Refused {
    /// Every reason together.
    pub total: usize,
    /// A key that is not one of the set.
    pub outside_set: usize,
    /// A key of the set on which the image declares no entity of the kind asked.
    pub role_not_declared: usize,
    /// A peer the image does not declare.
    pub peer_unknown: usize,
    /// A declared peer whose row does not allow the operation.
    pub peer_not_allowed: usize,
}

/// The gate of an open image: admits every key and looks at none. Has no size.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyGate<'a> {
    _table: core::marker::PhantomData<&'a ()>,
}

impl<'a> KeyGate<'a> {
    /// The gate of an open image.
    pub const fn open() -> Self {
        Self {
            _table: core::marker::PhantomData,
        }
    }

    /// Whether the gate refuses anything: never.
    pub const fn is_closed(&self) -> bool {
        false
    }

    /// The gate the build's `key-set` policy states. A build that has no closed key set can only
    /// be open, so a policy of `closed` here is a build that asked for a mode it does not have,
    /// and it stops: enable the `key-set-closed` feature of this crate in the image's build.
    pub const fn of_build() -> KeyGate<'static> {
        const {
            assert!(
                !matches!(SessionPolicy::from_build().key_set, KeySet::Closed),
                "the `key-set` policy is `closed` and this build lacks the `key-set-closed` feature \
                 of wz-session-core: the closed key set is not compiled in"
            );
        }
        KeyGate::open()
    }

    /// Admit the key of a message a peer sent: every key.
    #[inline]
    pub fn admit_key_from(
        &mut self,
        _class: Option<ClassId>,
        _op: PeerOp,
        _text: &str,
    ) -> Result<Admitted, Refusal> {
        Ok(Admitted::Unchecked)
    }

    /// Admit a key that is one of the set: every key.
    #[inline]
    pub fn admit_key(&mut self, _text: &str) -> Result<Admitted, Refusal> {
        Ok(Admitted::Unchecked)
    }

    /// Admit a key the image declares as a `kind`: every key.
    #[inline]
    pub fn admit_declared(&mut self, _text: &str, _kind: EntityKind) -> Result<Admitted, Refusal> {
        Ok(Admitted::Unchecked)
    }

    /// Admit a local declaration and answer with its entity: every declaration, and no entity.
    #[inline]
    pub fn admit_entity(
        &mut self,
        _text: &str,
        _kind: EntityKind,
    ) -> Result<Option<EntityId>, Refusal> {
        Ok(None)
    }

    /// The entity the image declares on `text`: none.
    #[inline]
    pub fn entity_of(&self, _text: &str, _kind: EntityKind) -> Option<EntityId> {
        None
    }

    /// How many keys the gate refused, by reason: none.
    pub const fn refused(&self) -> Refused {
        Refused {
            total: 0,
            outside_set: 0,
            role_not_declared: 0,
            peer_unknown: 0,
            peer_not_allowed: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_gate_has_no_size_and_its_numbers_have_no_value() {
        assert_eq!(core::mem::size_of::<KeyGate<'static>>(), 0);
        assert_eq!(core::mem::size_of::<Option<EntityId>>(), 0);
        assert_eq!(core::mem::size_of::<Option<ClassId>>(), 0);
        assert_eq!(core::mem::size_of::<Option<KeyId>>(), 0);
    }

    #[test]
    fn an_open_gate_admits_everything_and_counts_nothing() {
        let mut gate = KeyGate::of_build();
        assert!(!gate.is_closed());
        for text in ["a", "a/b", "nothing", "", "a/**"] {
            assert_eq!(gate.admit_key(text), Ok(Admitted::Unchecked));
            assert_eq!(
                gate.admit_key_from(None, PeerOp::Publish, text),
                Ok(Admitted::Unchecked)
            );
            assert_eq!(
                gate.admit_declared(text, EntityKind::Subscriber),
                Ok(Admitted::Unchecked)
            );
            assert_eq!(gate.admit_entity(text, EntityKind::Subscriber), Ok(None));
            assert_eq!(gate.entity_of(text, EntityKind::Subscriber), None);
        }
        assert_eq!(gate.refused(), Refused::default());
    }
}
