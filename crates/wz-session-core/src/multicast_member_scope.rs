// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Open-debt item 913 — the declarations each member of a multicast group hands this node's
//! session, kept apart member by member.
//!
//! A group session's observer holds what the group declared to it in one table per kind, keyed
//! by the declaration's id, as a unicast session's holds what its one peer declared. On a group
//! the ids are each member's own: two zenoh-pico sessions on one group number their entities
//! from the same counter, so both declare their first subscriber under one id, and one member's
//! undeclaration then retracts the other's subscriber. zenoh-pico keeps a write filter's target
//! by the declaration's id AND its peer
//! (`vendor/zenoh-pico/src/net/filtering.c` @
//! `_z_filter_target_t target = {.decl_id = msg->id, .peer = (uintptr_t)peer};`), and drops every
//! target of a peer whose connection drops (`_Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED`).
//!
//! [`MemberDeclarations`] does both for the observer, which sees no peer: each member is given a
//! tag when it is admitted, every subscriber, queryable and token id the member declares or
//! retracts reaches the observer with the tag in its high half ([`MemberDeclarations::scope`]),
//! and when the member leaves, an undeclaration of each id it still holds is made
//! ([`MemberDeclarations::retracted`]). Both upstreams number an entity in 32 bits, so the
//! low half holds every id a member can send; an id past it is left as sent.

use alloc::collections::BTreeSet;

use crate::transport_profile::owned::DeclareOwnedVariant;

use crate::network_message::NetworkMessage;

/// The tags a dispatcher hands its members, from 1, so no member's scoped id is a raw one.
#[derive(Debug)]
pub(crate) struct MemberTags {
    next: u64,
}

impl MemberTags {
    pub(crate) const fn new() -> Self {
        Self { next: 1 }
    }

    /// The next member's declarations, under a tag no live member holds while fewer than 2^32
    /// members have come and gone.
    pub(crate) fn admit(&mut self) -> MemberDeclarations {
        let tag = self.next;
        self.next = if tag >= u64::from(u32::MAX) {
            1
        } else {
            tag + 1
        };
        MemberDeclarations {
            tag,
            subscribers: BTreeSet::new(),
            queryables: BTreeSet::new(),
            tokens: BTreeSet::new(),
        }
    }
}

/// One member's declarations as the session's observer holds them: the member's tag and the
/// raw ids it still has declared, per kind.
#[derive(Debug)]
pub(crate) struct MemberDeclarations {
    tag: u64,
    subscribers: BTreeSet<u64>,
    queryables: BTreeSet<u64>,
    tokens: BTreeSet<u64>,
}

impl MemberDeclarations {
    /// `id` under this member's tag; an id 0 (a retraction that names its key instead) or one
    /// past 32 bits is left as it is.
    fn scoped(&self, id: u64) -> u64 {
        if id == 0 || id > u64::from(u32::MAX) {
            id
        } else {
            (self.tag << 32) | id
        }
    }

    /// Note that this member declared (`declared`) or retracted the raw id `raw` of `kind`, and
    /// answer the id it reaches the observer under; `None` for an id that is not scoped (0, or
    /// past 32 bits), which is left as sent. The one rule of the owned and the lent forms.
    fn note(&mut self, kind: DeclKind, raw: u64, declared: bool) -> Option<u64> {
        if raw == 0 || raw > u64::from(u32::MAX) {
            return None;
        }
        let held = match kind {
            DeclKind::Subscriber => &mut self.subscribers,
            DeclKind::Queryable => &mut self.queryables,
            DeclKind::Token => &mut self.tokens,
        };
        if declared {
            held.insert(raw);
        } else {
            held.remove(&raw);
        }
        Some((self.tag << 32) | raw)
    }

    /// Put every subscriber, queryable and token id `messages` declare or retract under this
    /// member's tag, and keep the raw ids it holds declared.
    pub(crate) fn scope(&mut self, messages: &mut [NetworkMessage]) {
        for message in messages.iter_mut() {
            let NetworkMessage::Declare(declare) = message else {
                continue;
            };
            let (id, kind, declared) = match &mut declare.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                    (&mut d.id, DeclKind::Subscriber, true)
                }
                DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                    (&mut u.id, DeclKind::Subscriber, false)
                }
                DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                    (&mut d.id, DeclKind::Queryable, true)
                }
                DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                    (&mut u.id, DeclKind::Queryable, false)
                }
                DeclareOwnedVariant::CodecZenohDeclToken(d) => (&mut d.id, DeclKind::Token, true),
                DeclareOwnedVariant::CodecZenohUndeclToken(u) => {
                    (&mut u.id, DeclKind::Token, false)
                }
                _ => continue,
            };
            if let Some(scoped) = self.note(kind, *id, declared) {
                *id = scoped;
            }
        }
    }

    /// The lent form of [`Self::scope`] for one Declare read where its frame lies: a copy of it
    /// with the id under this member's tag, the raw id kept as `scope` keeps it, or `None` for a
    /// declaration this does not scope, which reaches the observer as it lies.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        not(feature = "transport-stats"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    pub(crate) fn scope_lent<'f>(
        &mut self,
        declare: &wz_codecs::lent::Declare<'f>,
    ) -> Option<wz_codecs::lent::Declare<'f>> {
        use wz_codecs::lent::DeclareVariant as V;
        let (kind, raw, declared) = match &declare.body {
            V::CodecZenohDeclSubscriber(d) => (DeclKind::Subscriber, d.id, true),
            V::CodecZenohUndeclSubscriber(u) => (DeclKind::Subscriber, u.id, false),
            V::CodecZenohDeclQueryable(d) => (DeclKind::Queryable, d.id, true),
            V::CodecZenohUndeclQueryable(u) => (DeclKind::Queryable, u.id, false),
            V::CodecZenohDeclToken(d) => (DeclKind::Token, d.id, true),
            V::CodecZenohUndeclToken(u) => (DeclKind::Token, u.id, false),
            _ => return None,
        };
        let scoped_id = self.note(kind, raw, declared)?;
        let mut scoped = declare.clone();
        match &mut scoped.body {
            V::CodecZenohDeclSubscriber(d) => d.id = scoped_id,
            V::CodecZenohUndeclSubscriber(u) => u.id = scoped_id,
            V::CodecZenohDeclQueryable(d) => d.id = scoped_id,
            V::CodecZenohUndeclQueryable(u) => u.id = scoped_id,
            V::CodecZenohDeclToken(d) => d.id = scoped_id,
            V::CodecZenohUndeclToken(u) => u.id = scoped_id,
            _ => {}
        }
        Some(scoped)
    }

    /// An undeclaration of every subscriber, queryable and token the member still holds, by its
    /// scoped id: what the session's observer is handed when the member leaves.
    pub(crate) fn retracted(&self) -> impl Iterator<Item = Retraction> + '_ {
        let subscribers = self.subscribers.iter().map(move |&id| Retraction {
            kind: DeclKind::Subscriber,
            id: self.scoped(id),
        });
        let queryables = self.queryables.iter().map(move |&id| Retraction {
            kind: DeclKind::Queryable,
            id: self.scoped(id),
        });
        let tokens = self.tokens.iter().map(move |&id| Retraction {
            kind: DeclKind::Token,
            id: self.scoped(id),
        });
        subscribers.chain(queryables).chain(tokens)
    }
}

/// The three kinds of declaration a member's id is scoped in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeclKind {
    /// A subscriber.
    Subscriber,
    /// A queryable.
    Queryable,
    /// A liveliness token.
    Token,
}

/// The undeclaration of one declaration a member that left still held, by the id it reached the
/// session's observer under: handed over owned ([`Self::owned`]) or, where the group's records
/// are lent, lent ([`Self::lent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retraction {
    kind: DeclKind,
    id: u64,
}

impl Retraction {
    /// The undeclaration as an owned message.
    pub(crate) fn owned(self) -> NetworkMessage {
        use crate::declare_build::{
            build_undeclare_queryable, build_undeclare_subscriber, build_undeclare_token,
        };
        let declare = match self.kind {
            DeclKind::Subscriber => build_undeclare_subscriber(self.id),
            DeclKind::Queryable => build_undeclare_queryable(self.id),
            DeclKind::Token => build_undeclare_token(self.id),
        };
        NetworkMessage::Declare(alloc::boxed::Box::new(declare))
    }

    /// The undeclaration as the lent Declare a frame read in place would hand over: the id-only
    /// form the owned one is, with no extension.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        not(feature = "transport-stats"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    pub(crate) fn lent(self) -> wz_codecs::lent::Declare<'static> {
        use wz_codecs::lent::DeclareVariant as V;
        use wz_codecs::wire_const;
        let body = match self.kind {
            DeclKind::Subscriber => {
                V::CodecZenohUndeclSubscriber(wz_codecs::lent::UndeclSubscriber {
                    header: wire_const::D_MID_UNDECL_SUBSCRIBER,
                    id: self.id,
                    extensions: None,
                })
            }
            DeclKind::Queryable => V::CodecZenohUndeclQueryable(wz_codecs::lent::UndeclQueryable {
                header: wire_const::D_MID_UNDECL_QUERYABLE,
                id: self.id,
                extensions: None,
            }),
            DeclKind::Token => V::CodecZenohUndeclToken(wz_codecs::lent::UndeclToken {
                header: wire_const::D_MID_UNDECL_TOKEN,
                id: self.id,
                extensions: None,
            }),
        };
        wz_codecs::lent::Declare {
            body,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn declare_subscriber(id: u64) -> NetworkMessage {
        NetworkMessage::Declare(alloc::boxed::Box::new(
            crate::declare_build::build_declare_subscriber(id, 0, Some("demo/mc/**"))
                .expect("the subscriber builds"),
        ))
    }

    fn subscriber_id(message: &NetworkMessage) -> u64 {
        match message {
            NetworkMessage::Declare(declare) => match &declare.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => d.id,
                DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => u.id,
                _ => panic!("not a subscriber declaration"),
            },
            _ => panic!("not a declaration"),
        }
    }

    /// Two members that declare one id reach the observer under two, and the one that leaves
    /// retracts only its own.
    #[test]
    fn two_members_one_id_stay_two_declarations() {
        let mut tags = MemberTags::new();
        let mut first = tags.admit();
        let mut second = tags.admit();
        let mut from_first = [declare_subscriber(2)];
        let mut from_second = [declare_subscriber(2)];
        first.scope(&mut from_first);
        second.scope(&mut from_second);
        assert_ne!(
            subscriber_id(&from_first[0]),
            subscriber_id(&from_second[0]),
            "one id from two members must reach the observer as two"
        );
        let retracted: Vec<NetworkMessage> = first.retracted().map(Retraction::owned).collect();
        assert_eq!(
            retracted.iter().map(subscriber_id).collect::<Vec<_>>(),
            [subscriber_id(&from_first[0])],
            "the leaving member retracts its own declaration and nothing else"
        );
    }

    /// A member's undeclaration ends what it holds, so its departure retracts nothing twice.
    #[test]
    fn an_undeclared_id_is_not_retracted_again() {
        let mut member = MemberTags::new().admit();
        let mut declared = [declare_subscriber(2)];
        member.scope(&mut declared);
        let mut undeclared = [NetworkMessage::Declare(alloc::boxed::Box::new(
            crate::declare_build::build_undeclare_subscriber(2),
        ))];
        member.scope(&mut undeclared);
        assert_eq!(subscriber_id(&undeclared[0]), subscriber_id(&declared[0]));
        assert!(member.retracted().next().is_none());
    }
}
