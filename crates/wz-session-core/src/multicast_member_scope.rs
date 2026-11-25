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
//!
//! Where the group's records are lent, the keyexprs a member declares are the member's too: every
//! record it sent reaches the observer under its tag, by which the session's one alias table of
//! the group binds and reads the member's keyexpr ids, and the ids it still holds are unbound when
//! it leaves, as zenoh-pico drops a peer's resources with the peer
//! (`vendor/zenoh-pico/src/transport/peer.c` @ `_z_resource_slist_free(&src->_remote_resources);`).
//! A member holds at most `MAX_MEMBER_KEYEXPRS` of them, in rows of its own, so one member cannot
//! take the room of the others.

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
            tag.saturating_add(1)
        };
        MemberDeclarations {
            tag,
            subscribers: BTreeSet::new(),
            queryables: BTreeSet::new(),
            tokens: BTreeSet::new(),
            #[cfg(all(
                feature = "session-unicast",
                feature = "rx-lent-control",
                any(not(feature = "transport-stats"), feature = "reassembly"),
                not(feature = "routing-namespace"),
                not(feature = "multicast-declarations"),
                not(feature = "multicast-ingress-gate")
            ))]
            keyexprs: MemberKeyexprs::new(),
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
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    keyexprs: MemberKeyexprs,
}

/// The keyexpr ids one member holds declared, in rows of its own.
#[cfg(all(
    feature = "session-unicast",
    feature = "rx-lent-control",
    any(not(feature = "transport-stats"), feature = "reassembly"),
    not(feature = "routing-namespace"),
    not(feature = "multicast-declarations"),
    not(feature = "multicast-ingress-gate")
))]
#[derive(Debug)]
struct MemberKeyexprs {
    ids: [crate::wire_id::ExprId; crate::caps::MAX_MEMBER_KEYEXPRS],
    held: usize,
}

#[cfg(all(
    feature = "session-unicast",
    feature = "rx-lent-control",
    any(not(feature = "transport-stats"), feature = "reassembly"),
    not(feature = "routing-namespace"),
    not(feature = "multicast-declarations"),
    not(feature = "multicast-ingress-gate")
))]
impl MemberKeyexprs {
    const fn new() -> Self {
        Self {
            ids: [0; crate::caps::MAX_MEMBER_KEYEXPRS],
            held: 0,
        }
    }

    fn held(&self) -> &[crate::wire_id::ExprId] {
        self.ids.get(..self.held).unwrap_or_default()
    }

    /// Note that the member declared `id`: `false` for a new id with every row held, which is
    /// not noted. A redeclared id is held already.
    fn declare(&mut self, id: crate::wire_id::ExprId) -> bool {
        if self.held().contains(&id) {
            return true;
        }
        let Some(row) = self.ids.get_mut(self.held) else {
            return false;
        };
        *row = id;
        // Below the rows' count, as the row just taken says.
        self.held = self.held.saturating_add(1);
        true
    }

    /// Note that the member retracted `id`.
    fn undeclare(&mut self, id: crate::wire_id::ExprId) {
        let at = self.held().iter().position(|held| *held == id);
        // A held id was found, so at least one is held.
        if let (Some(at), Some(last)) = (at, self.held.checked_sub(1)) {
            self.held = last;
            self.ids.swap(at, last);
        }
    }
}

/// A keyexpr of a new id a member declared past the ids it may hold (`MAX_MEMBER_KEYEXPRS`): no
/// alias is bound for it (`MemberDeclarations::scope_lent`).
#[cfg(all(
    feature = "session-unicast",
    feature = "rx-lent-control",
    any(not(feature = "transport-stats"), feature = "reassembly"),
    not(feature = "routing-namespace"),
    not(feature = "multicast-declarations"),
    not(feature = "multicast-ingress-gate")
))]
#[derive(Debug)]
pub(crate) struct PastBound;

impl MemberDeclarations {
    /// The tag the member's records reach the observer under.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    pub(crate) const fn tag(&self) -> u64 {
        self.tag
    }

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
            // A keyexpr is held in the member's own table (`MemberKeyexprs`), by its own id under
            // the member's tag, and is not an entity id this scopes.
            #[cfg(all(
                feature = "session-unicast",
                feature = "rx-lent-control",
                any(not(feature = "transport-stats"), feature = "reassembly"),
                not(feature = "routing-namespace"),
                not(feature = "multicast-declarations"),
                not(feature = "multicast-ingress-gate")
            ))]
            DeclKind::Keyexpr => return None,
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
    /// with the id under this member's tag, the raw id kept as `scope` keeps it, or the
    /// declaration as it lies for one this does not scope. A keyexpr the member declares or
    /// retracts is noted, and one of a new id past the ids it may hold is refused.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    pub(crate) fn scope_lent<'f>(
        &mut self,
        declare: &wz_codecs::lent::Declare<'f>,
    ) -> Result<Option<wz_codecs::lent::Declare<'f>>, PastBound> {
        use crate::wire_id::declared_expr_id;
        use wz_codecs::lent::DeclareVariant as V;
        let (kind, raw, declared) = match &declare.body {
            V::CodecZenohDeclSubscriber(d) => (DeclKind::Subscriber, d.id, true),
            V::CodecZenohUndeclSubscriber(u) => (DeclKind::Subscriber, u.id, false),
            V::CodecZenohDeclQueryable(d) => (DeclKind::Queryable, d.id, true),
            V::CodecZenohUndeclQueryable(u) => (DeclKind::Queryable, u.id, false),
            V::CodecZenohDeclToken(d) => (DeclKind::Token, d.id, true),
            V::CodecZenohUndeclToken(u) => (DeclKind::Token, u.id, false),
            V::CodecZenohDeclKexpr(d) => {
                return if self.keyexprs.declare(declared_expr_id(d.id)) {
                    Ok(None)
                } else {
                    Err(PastBound)
                };
            }
            V::CodecZenohUndeclKexpr(u) => {
                self.keyexprs.undeclare(declared_expr_id(u.id));
                return Ok(None);
            }
            _ => return Ok(None),
        };
        let Some(scoped_id) = self.note(kind, raw, declared) else {
            return Ok(None);
        };
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
        Ok(Some(scoped))
    }

    /// An undeclaration of every subscriber, queryable and token the member still holds, by its
    /// scoped id, and, where its records are lent, of every keyexpr it holds, by its own id under
    /// its tag: what the session's observer is handed when the member leaves.
    pub(crate) fn retracted(&self) -> impl Iterator<Item = Retraction> + '_ {
        let entity = move |kind: DeclKind, id: u64| Retraction {
            kind,
            id: self.scoped(id),
            #[cfg(all(
                feature = "session-unicast",
                feature = "rx-lent-control",
                any(not(feature = "transport-stats"), feature = "reassembly"),
                not(feature = "routing-namespace"),
                not(feature = "multicast-declarations"),
                not(feature = "multicast-ingress-gate")
            ))]
            sender: self.tag,
        };
        let subscribers = self
            .subscribers
            .iter()
            .map(move |&id| entity(DeclKind::Subscriber, id));
        let queryables = self
            .queryables
            .iter()
            .map(move |&id| entity(DeclKind::Queryable, id));
        let tokens = self
            .tokens
            .iter()
            .map(move |&id| entity(DeclKind::Token, id));
        let entities = subscribers.chain(queryables).chain(tokens);
        #[cfg(all(
            feature = "session-unicast",
            feature = "rx-lent-control",
            any(not(feature = "transport-stats"), feature = "reassembly"),
            not(feature = "routing-namespace"),
            not(feature = "multicast-declarations"),
            not(feature = "multicast-ingress-gate")
        ))]
        {
            entities.chain(self.keyexprs.held().iter().map(move |&id| Retraction {
                kind: DeclKind::Keyexpr,
                id: u64::from(id),
                sender: self.tag,
            }))
        }
        #[cfg(not(all(
            feature = "session-unicast",
            feature = "rx-lent-control",
            any(not(feature = "transport-stats"), feature = "reassembly"),
            not(feature = "routing-namespace"),
            not(feature = "multicast-declarations"),
            not(feature = "multicast-ingress-gate")
        )))]
        {
            entities
        }
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
    /// A keyexpr, by the member's own id: retracted lent, under the member's tag.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    Keyexpr,
}

/// The undeclaration of one declaration a member that left still held, by the id it reached the
/// session's observer under: handed over owned ([`Self::owned`]) or, where the group's records
/// are lent, lent (`Self::lent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retraction {
    kind: DeclKind,
    id: u64,
    /// The tag of the member that held it, which the lent form is handed under.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    sender: u64,
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
            #[cfg(all(
                feature = "session-unicast",
                feature = "rx-lent-control",
                any(not(feature = "transport-stats"), feature = "reassembly"),
                not(feature = "routing-namespace"),
                not(feature = "multicast-declarations"),
                not(feature = "multicast-ingress-gate")
            ))]
            DeclKind::Keyexpr => crate::declare_build::build_undeclare_kexpr(
                crate::wire_id::declared_expr_id(self.id),
            ),
        };
        NetworkMessage::Declare(alloc::boxed::Box::new(declare))
    }

    /// The undeclaration as the lent Declare a frame read in place would hand over: the id-only
    /// form the owned one is, with no extension.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
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
            DeclKind::Keyexpr => V::CodecZenohUndeclKexpr(wz_codecs::lent::UndeclKexpr {
                header: wire_const::D_MID_UNDECL_KEXPR,
                id: self.id,
                extensions: None,
            }),
        };
        wz_codecs::lent::Declare {
            body,
            ..Default::default()
        }
    }

    /// The tag of the member that held it, which its lent form is handed under.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    pub(crate) const fn sender(self) -> u64 {
        self.sender
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

    /// The lent Declare a frame read in place carries for `declare`.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    fn lent_wire(declare: &crate::transport_profile::owned::DeclareOwned) -> Vec<u8> {
        declare
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
    }

    /// What `member` makes of the keyexpr declaration (`declared`) or retraction of `id`.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    fn keyexpr_scope(member: &mut MemberDeclarations, id: u16, declared: bool) -> &'static str {
        let owned = if declared {
            crate::declare_build::build_declare_kexpr(id, "demo/member/key").expect("a keyexpr")
        } else {
            crate::declare_build::build_undeclare_kexpr(id)
        };
        let wire = lent_wire(&owned);
        let view =
            wz_codecs::lent::Declare::decode(&mut sce_forge_runtime::codec::SceCursor::new(&wire))
                .expect("it decodes");
        match member.scope_lent(&view) {
            Ok(None) => "as sent",
            Ok(Some(_)) => "scoped",
            Err(PastBound) => "past bound",
        }
    }

    /// A member holds as many keyexpr ids as its rows: one more new id is refused, a held id is
    /// declared again, and a retraction frees a row for the next.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    #[test]
    fn a_member_holds_its_keyexprs_to_its_rows() {
        let rows = crate::caps::MAX_MEMBER_KEYEXPRS;
        let past = u16::try_from(rows + 1).expect("the rows fit an id");
        let mut member = MemberTags::new().admit();
        for id in 1..past {
            assert_eq!(keyexpr_scope(&mut member, id, true), "as sent", "id {id}");
        }
        assert_eq!(
            keyexpr_scope(&mut member, past, true),
            "past bound",
            "one more new id than the member's rows"
        );
        if rows > 0 {
            assert_eq!(
                keyexpr_scope(&mut member, 1, true),
                "as sent",
                "a held id again"
            );
            assert_eq!(keyexpr_scope(&mut member, 1, false), "as sent");
            assert_eq!(
                keyexpr_scope(&mut member, past, true),
                "as sent",
                "the retraction freed a row"
            );
        }
    }

    /// A member that leaves retracts the keyexprs it still holds, each by its own id under its
    /// tag, and nothing of another member's.
    #[cfg(all(
        feature = "session-unicast",
        feature = "rx-lent-control",
        any(not(feature = "transport-stats"), feature = "reassembly"),
        not(feature = "routing-namespace"),
        not(feature = "multicast-declarations"),
        not(feature = "multicast-ingress-gate")
    ))]
    #[test]
    fn a_departed_member_retracts_its_keyexprs_under_its_tag() {
        if crate::caps::MAX_MEMBER_KEYEXPRS < 2 {
            return;
        }
        let mut tags = MemberTags::new();
        let mut leaving = tags.admit();
        let mut staying = tags.admit();
        for id in [3, 5] {
            keyexpr_scope(&mut leaving, id, true);
        }
        keyexpr_scope(&mut leaving, 5, false);
        keyexpr_scope(&mut staying, 3, true);
        let retracted: Vec<(u64, u64)> = leaving
            .retracted()
            .map(|retraction| {
                let declare = retraction.lent();
                match declare.body {
                    wz_codecs::lent::DeclareVariant::CodecZenohUndeclKexpr(u) => {
                        (u.id, retraction.sender())
                    }
                    _ => panic!("a keyexpr's retraction is an UndeclKexpr"),
                }
            })
            .collect();
        assert_eq!(
            retracted,
            [(3, leaving.tag())],
            "the id it still holds, under its own tag"
        );
        assert_ne!(leaving.tag(), staying.tag());
    }
}
