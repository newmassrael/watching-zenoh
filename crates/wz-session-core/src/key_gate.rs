// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a closed key set refuses, and counts (`docs/closed-key-set.md`, phase 2).
//!
//! # What it is
//!
//! A [`KeyGate`] stands in front of the keys a host handles. An open gate admits every key and
//! looks at none, which is upstream's behaviour. A closed gate holds a
//! [`KeyCatalogue`] and admits only what the catalogue has:
//! [`KeyGate::admit_key`] a key that is one of the set (a message's key, a peer's resource), and
//! [`KeyGate::admit_declared`] a key the image declares in the role being asked (a local
//! declaration of a subscriber, a publisher, a queryable). Both answer with the key's
//! [`KeyId`], so what is admitted is already numbered.
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
//! The subscriber table holds one and applies it to the key of every message that arrives from a
//! peer, before a subscriber is looked up ([`crate::pubsub::SubscriberTable::set_key_gate`]). It
//! starts as [`KeyGate::of_build`], which the `key-set` policy decides. Selectors a peer asks with
//! (a query's, an interest's) are patterns and not data keys: they are not looked up here, and
//! nothing refuses them.

// The types a gate numbers with are re-exported here so that a caller names them through
// `key_gate` alone, which is the one path both builds of the gate have (the build without the
// `key-set-closed` feature defines the same names with no value: `key_gate_open.rs`).
use crate::key_allowance::PeerAllowance;
pub use crate::key_allowance::{ClassId, PeerOp};
use crate::key_catalogue::KeyCatalogue;
pub use crate::key_catalogue::{EntityId, EntityKind, KeyId};

/// Why a closed gate did not admit a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The text is not a key of the set.
    OutsideSet,
    /// The text is a key of the set, and the image declares no entity of this kind on it.
    RoleNotDeclared(EntityKind),
    /// The key is of the set, and the peer is not one the image declares: it is allowed nothing.
    PeerUnknown,
    /// The key is of the set and the peer is declared, and its row does not allow the operation on
    /// this key.
    PeerNotAllowed(PeerOp),
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
    /// [`Refusal::PeerUnknown`].
    pub peer_unknown: usize,
    /// [`Refusal::PeerNotAllowed`], for every operation.
    pub peer_not_allowed: usize,
}

/// The catalogue of a closed build that was given none: no key, so the gate over it refuses every
/// key. A closed image that forgot its table takes nothing, which is the safe way for it to be
/// wrong.
const NO_KEYS: KeyCatalogue<'static> = KeyCatalogue::new("", &[], &[0], &[], &[]);

/// The gate a host puts in front of its keys. See the module note.
#[derive(Debug, Clone, Copy)]
pub struct KeyGate<'a> {
    catalogue: Option<&'a KeyCatalogue<'a>>,
    /// What each declared peer may do on each key, when the image declares its peers.
    allowance: Option<&'a PeerAllowance<'a>>,
    refused: Refused,
    /// The key of the last message admitted: a stream's next message is on the same key, and one
    /// comparison with its text answers it where the search of the table would take several.
    last: Option<KeyId>,
}

impl<'a> KeyGate<'a> {
    /// The gate of an open image: admits every key, looks at none.
    pub const fn open() -> Self {
        Self {
            catalogue: None,
            allowance: None,
            refused: Refused {
                total: 0,
                outside_set: 0,
                role_not_declared: 0,
                peer_unknown: 0,
                peer_not_allowed: 0,
            },
            last: None,
        }
    }

    /// The gate of a closed image over its catalogue.
    pub const fn closed(catalogue: &'a KeyCatalogue<'a>) -> Self {
        Self {
            catalogue: Some(catalogue),
            ..Self::open()
        }
    }

    /// This gate, also holding what each declared peer may do. Without it a closed gate asks nothing
    /// of the peer a message came from; with it [`Self::admit_key_from`] does.
    pub const fn with_allowance(self, allowance: &'a PeerAllowance<'a>) -> Self {
        Self {
            allowance: Some(allowance),
            ..self
        }
    }

    /// The table of what each declared peer may do, `None` when the image declares none.
    pub const fn allowance(&self) -> Option<&'a PeerAllowance<'a>> {
        self.allowance
    }

    /// Admit the key of a message that a peer sent, for the peer's `class` (the row
    /// [`PeerAllowance::class_of`] found for its zid, `None` for a peer the image does not declare).
    /// The key must be one of the set, as for [`Self::admit_key`]; then, when the image declares its
    /// peers, the peer must be one of them and its row must allow `op` on the key. An open gate
    /// admits everything, and a closed one that declares no peers asks nothing of the peer.
    pub fn admit_key_from(
        &mut self,
        class: Option<ClassId>,
        op: PeerOp,
        text: &str,
    ) -> Result<Admitted, Refusal> {
        let admitted = self.admit_key(text)?;
        let (Some(allowance), Admitted::Key(key)) = (self.allowance, admitted) else {
            return Ok(admitted);
        };
        match class {
            None => Err(self.refuse(Refusal::PeerUnknown)),
            Some(class) if allowance.allows(class, op, key) => Ok(admitted),
            Some(_) => Err(self.refuse(Refusal::PeerNotAllowed(op))),
        }
    }

    /// Whether the gate refuses anything.
    pub const fn is_closed(&self) -> bool {
        self.catalogue.is_some()
    }

    /// The gate the build's `key-set` policy states: open, or closed over no keys until a host
    /// gives it its table with [`Self::closed`]. Every host starts from this and a host that knows
    /// better (a test, an image that has a table) sets its own.
    pub const fn of_build() -> KeyGate<'static> {
        match crate::policy::SessionPolicy::from_build().key_set {
            crate::policy::KeySet::Open => KeyGate::open(),
            crate::policy::KeySet::Closed => KeyGate::closed(&NO_KEYS),
        }
    }

    /// Admit a key that is one of the set: the key of a message, or of a resource a peer declares.
    pub fn admit_key(&mut self, text: &str) -> Result<Admitted, Refusal> {
        let Some(catalogue) = self.catalogue else {
            return Ok(Admitted::Unchecked);
        };
        if let Some(last) = self.last {
            if catalogue.text(last) == text {
                return Ok(Admitted::Key(last));
            }
        }
        match catalogue.find_exact(text) {
            Some(key) => {
                self.last = Some(key);
                Ok(Admitted::Key(key))
            }
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

    /// Admit a local declaration of an entity of `kind` on `text`, and answer with the entity the
    /// image declares there. `Ok(None)` for an open gate, which looks at nothing and has no
    /// entities. The refusals are those of [`Self::admit_declared`].
    pub fn admit_entity(
        &mut self,
        text: &str,
        kind: EntityKind,
    ) -> Result<Option<EntityId>, Refusal> {
        let Some(catalogue) = self.catalogue else {
            return Ok(None);
        };
        match self.admit_declared(text, kind)? {
            Admitted::Key(key) => Ok(catalogue.find_entity(kind, key)),
            Admitted::Unchecked => Ok(None),
        }
    }

    /// The entity of `kind` the image declares on `text`, without counting anything: a closed
    /// gate's table lookup, for a caller re-reading what it already holds. `None` for an open
    /// gate and for a text the image does not declare as that kind.
    pub fn entity_of(&self, text: &str, kind: EntityKind) -> Option<EntityId> {
        let catalogue = self.catalogue?;
        catalogue.find_entity(kind, catalogue.find_exact(text)?)
    }

    /// The table a closed gate holds, `None` for an open one.
    pub const fn catalogue(&self) -> Option<&'a KeyCatalogue<'a>> {
        self.catalogue
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
            Refusal::PeerUnknown => {
                self.refused.peer_unknown = self.refused.peer_unknown.saturating_add(1);
            }
            Refusal::PeerNotAllowed(_) => {
                self.refused.peer_not_allowed = self.refused.peer_not_allowed.saturating_add(1);
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
                ..Refused::default()
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
                role_not_declared: 2,
                ..Refused::default()
            }
        );
    }

    // Three keys, "a", "a/*" and "a/b" (the test table of `key_catalogue`), and two declared peers: A
    // may publish on key 2 ("a/b") and B on key 0 ("a").
    const PEER_A: [u8; 16] = [1; 16];
    const PEER_B: [u8; 16] = [2; 16];
    const PEERS: [[u8; 16]; 2] = [PEER_A, PEER_B];
    const PEER_BITS: [u8; 2] = [0b100, 0b001];
    const ALLOWANCE: PeerAllowance<'static> = PeerAllowance::new(&PEERS, 3, &PEER_BITS);

    #[test]
    fn a_message_from_a_declared_peer_is_admitted_on_the_keys_its_row_allows() {
        let mut gate = KeyGate::closed(&TABLE).with_allowance(&ALLOWANCE);
        let a = ALLOWANCE.class_of(&PEER_A);
        let b = ALLOWANCE.class_of(&PEER_B);
        let publish = PeerOp::Publish;
        assert_eq!(
            gate.admit_key_from(a, publish, "a/b"),
            Ok(Admitted::Key(KeyId::new(2)))
        );
        assert_eq!(
            gate.admit_key_from(b, publish, "a"),
            Ok(Admitted::Key(KeyId::new(0)))
        );
        // Declared peers, keys of the set, and the row does not allow it.
        assert_eq!(
            gate.admit_key_from(a, publish, "a"),
            Err(Refusal::PeerNotAllowed(publish))
        );
        assert_eq!(
            gate.admit_key_from(b, publish, "a/b"),
            Err(Refusal::PeerNotAllowed(publish))
        );
        assert_eq!(
            gate.refused(),
            Refused {
                total: 2,
                peer_not_allowed: 2,
                ..Refused::default()
            }
        );
    }

    #[test]
    fn a_peer_that_is_not_declared_is_allowed_nothing_and_the_set_is_asked_first() {
        let mut gate = KeyGate::closed(&TABLE).with_allowance(&ALLOWANCE);
        let stranger = ALLOWANCE.class_of(&[9; 16]);
        assert_eq!(stranger, None);
        assert_eq!(
            gate.admit_key_from(stranger, PeerOp::Publish, "a/b"),
            Err(Refusal::PeerUnknown)
        );
        // A key outside the set is refused as that, whoever sent it.
        assert_eq!(
            gate.admit_key_from(stranger, PeerOp::Publish, "a/c"),
            Err(Refusal::OutsideSet)
        );
        assert_eq!(
            gate.admit_key_from(ALLOWANCE.class_of(&PEER_A), PeerOp::Publish, "a/c"),
            Err(Refusal::OutsideSet)
        );
        assert_eq!(
            gate.refused(),
            Refused {
                total: 3,
                outside_set: 2,
                peer_unknown: 1,
                ..Refused::default()
            }
        );
    }

    #[test]
    fn a_gate_that_declares_no_peers_asks_nothing_of_the_peer() {
        let mut closed = KeyGate::closed(&TABLE);
        assert!(closed.allowance().is_none());
        assert_eq!(
            closed.admit_key_from(None, PeerOp::Publish, "a/b"),
            Ok(Admitted::Key(KeyId::new(2)))
        );
        let mut open = KeyGate::open().with_allowance(&ALLOWANCE);
        assert_eq!(
            open.admit_key_from(None, PeerOp::Publish, "anything"),
            Ok(Admitted::Unchecked)
        );
        assert_eq!(closed.refused().total + open.refused().total, 0);
    }

    #[test]
    fn the_key_just_admitted_is_answered_the_same_and_a_refusal_does_not_forget_it() {
        let mut gate = KeyGate::closed(&TABLE);
        for _ in 0..3 {
            assert_eq!(gate.admit_key("a/b"), Ok(Admitted::Key(KeyId::new(2))));
        }
        // Another key moves the memory; a refused one leaves it where it was.
        assert_eq!(gate.admit_key("a"), Ok(Admitted::Key(KeyId::new(0))));
        assert_eq!(gate.admit_key("a/c"), Err(Refusal::OutsideSet));
        assert_eq!(gate.admit_key("a"), Ok(Admitted::Key(KeyId::new(0))));
        // A text that only starts like the remembered key is not it.
        assert_eq!(gate.admit_key("a/"), Err(Refusal::OutsideSet));
        assert_eq!(gate.admit_key("a/b"), Ok(Admitted::Key(KeyId::new(2))));
        assert_eq!(gate.refused().total, 2);
    }

    #[test]
    fn the_gate_of_a_build_is_the_policy_it_states() {
        let gate = KeyGate::of_build();
        let closed =
            crate::policy::SessionPolicy::from_build().key_set == crate::policy::KeySet::Closed;
        assert_eq!(gate.is_closed(), closed);
        // A closed build that was given no table refuses every key.
        let mut over_nothing = KeyGate::closed(&NO_KEYS);
        assert_eq!(over_nothing.admit_key("a"), Err(Refusal::OutsideSet));
        assert_eq!(over_nothing.admit_key(""), Err(Refusal::OutsideSet));
        assert_eq!(over_nothing.refused().total, 2);
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
