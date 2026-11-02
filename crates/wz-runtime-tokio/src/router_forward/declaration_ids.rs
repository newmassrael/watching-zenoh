// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The numbers of the declarations this node sends to a face that keeps them by id.
//!
//! A declaration this forwarder floods is SOURCED: its id is 0 and it names its key inline, and a
//! withdrawal names the key in `ext_wire_expr`, because the mesh keeps declarations by key. A
//! face that keeps them by id takes every such declaration as the one before it. Two faces are
//! of that kind:
//!
//! - The router that holds this node as a CLIENT ([`RouterForwarder::as_client_of_north`]) keeps
//!   a client's declarations by the id the client numbered them with
//!   (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `.remote_subs.remove(&id)`). A node that
//!   sends them all as id 0 has each replace the one before: of every key it declares, the
//!   router holds the last. A client numbers each declaration with an id of its own, one for each
//!   resource (`zenoh/src/net/routing/hat/client/pubsub.rs` @ `.next_id`),
//!   and withdraws it by that id.
//! - A peer south of this node keeps the liveliness tokens it is told by id. A token reaches it
//!   twice, in the flood of the token and in the answer to the interest that asked for the
//!   tokens held, and under two numbers the peer holds the token twice and the withdrawal, which
//!   names one of them, leaves it held. The pin's peer hat gives a token one id for a face
//!   (`zenoh/src/net/routing/hat/peer/token.rs` @ `local_tokens`), whatever way it is sent.
//!
//! The number is given where the declaration leaves for the face
//! ([`OnTables::number_declaration`]), so that every route to the face is numbered alike and the
//! tables stay as they are.

use super::*;

/// What a declaration is about, as a face tells the ids apart: its subscribers, its queryables
/// and its tokens each have their own.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Plane {
    Subscriber,
    Queryable,
    Token,
}

/// The ids this node gave the declarations it sent to one face, by the plane and key they are
/// about. Kept by the face and gone with it, as the pin's face context is.
#[derive(Default)]
pub(super) struct DeclarationIds {
    last: u64,
    given: HashMap<(Plane, String), u64>,
}

impl DeclarationIds {
    /// The id of the declaration of `key`: the one it was given before, or a new one. A key
    /// declared again (a queryable whose completeness changed, a token sent in the flood and
    /// again in an answer) is the same declaration and keeps its id, so the face takes it as
    /// the update it is.
    fn declare(&mut self, plane: Plane, key: String) -> u64 {
        if let Some(id) = self.given.get(&(plane, key.clone())) {
            return *id;
        }
        // 0 is the id of a sourced declaration, so a number of ours is never 0.
        self.last += 1;
        self.given.insert((plane, key), self.last);
        self.last
    }

    /// The id the declaration of `key` was given, which its withdrawal names. `None` for a key
    /// this node never declared to the face.
    fn withdraw(&mut self, plane: Plane, key: &str) -> Option<u64> {
        self.given.remove(&(plane, key.to_owned()))
    }
}

/// Which planes of declarations leave numbered for a face.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Numbered {
    /// None: the face keeps declarations by key, or by the id of the interest that asked.
    Nothing,
    /// Liveliness tokens alone.
    Tokens,
    /// Every plane.
    Everything,
}

impl Numbered {
    fn covers(self, plane: Plane) -> bool {
        match self {
            Self::Nothing => false,
            Self::Tokens => plane == Plane::Token,
            Self::Everything => true,
        }
    }
}

impl<T: std::ops::Deref<Target = Tables>> OnTables<'_, T> {
    /// What leaves numbered for `state`: everything for the router that holds this node as a
    /// client, tokens for a face of a south region the peer hat serves (its subscribers and
    /// queryables carry the id of the interest that asked for them).
    fn numbered_for(&self, state: &RouterFaceState) -> Numbered {
        if self.tables.numbers_every_declaration_to(state.tier) {
            Numbered::Everything
        } else if self.tables.serves_asking_peers(state.tier) {
            Numbered::Tokens
        } else {
            Numbered::Nothing
        }
    }

    /// Number a declaration that leaves for `state`; any other message, and any face that keeps
    /// declarations by key, is returned as it came.
    pub(super) fn number_declaration(
        &self,
        state: &RouterFaceState,
        mut msg: NetworkMessage,
    ) -> NetworkMessage {
        let numbered = self.numbered_for(state);
        if numbered == Numbered::Nothing || !matches!(msg, NetworkMessage::Declare(_)) {
            return msg;
        }
        let Some(key) = resolve_governed_keyexpr(&msg, &state.keyexpr_table) else {
            return msg;
        };
        let NetworkMessage::Declare(declare) = &mut msg else {
            return msg;
        };
        let mut ids = state.declaration_ids.guard();
        match &mut declare.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(s)
                if numbered.covers(Plane::Subscriber) =>
            {
                s.id = ids.declare(Plane::Subscriber, key);
            }
            DeclareOwnedVariant::CodecZenohDeclQueryable(q)
                if numbered.covers(Plane::Queryable) =>
            {
                q.id = ids.declare(Plane::Queryable, key);
            }
            DeclareOwnedVariant::CodecZenohDeclToken(t) if numbered.covers(Plane::Token) => {
                t.id = ids.declare(Plane::Token, key);
            }
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u)
                if numbered.covers(Plane::Subscriber) =>
            {
                if let Some(id) = ids.withdraw(Plane::Subscriber, &key) {
                    u.id = id;
                }
            }
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u)
                if numbered.covers(Plane::Queryable) =>
            {
                if let Some(id) = ids.withdraw(Plane::Queryable, &key) {
                    u.id = id;
                }
            }
            DeclareOwnedVariant::CodecZenohUndeclToken(u) if numbered.covers(Plane::Token) => {
                if let Some(id) = ids.withdraw(Plane::Token, &key) {
                    u.id = id;
                }
            }
            _ => {}
        }
        drop(ids);
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key has one id on a face whatever way it is sent, and its withdrawal names that id: the
    /// token a south peer is told in the flood and again in the answer is held once there.
    #[test]
    fn a_key_keeps_its_id_until_it_is_withdrawn() {
        let mut ids = DeclarationIds::default();
        let first = ids.declare(Plane::Token, "live/a".to_owned());
        assert_eq!(ids.declare(Plane::Token, "live/a".to_owned()), first);
        assert_eq!(ids.withdraw(Plane::Token, "live/a"), Some(first));
        assert_eq!(
            ids.withdraw(Plane::Token, "live/a"),
            None,
            "a withdrawn key has no id to name"
        );
        assert_ne!(
            ids.declare(Plane::Token, "live/a".to_owned()),
            first,
            "declared again, it is a new declaration"
        );
    }

    /// Two keys never share an id, and no id is 0, which is the id of a sourced declaration: the
    /// router that holds this node as a client keeps one declaration for each id.
    #[test]
    fn two_keys_have_two_ids_and_none_is_zero() {
        let mut ids = DeclarationIds::default();
        let a = ids.declare(Plane::Subscriber, "demo/a".to_owned());
        let b = ids.declare(Plane::Subscriber, "demo/b".to_owned());
        let q = ids.declare(Plane::Queryable, "demo/a".to_owned());
        assert!(a != 0 && b != 0 && q != 0);
        assert!(a != b && a != q && b != q);
    }

    /// A peer of the pin's peer hat keeps a node's queryables by the id they were sent with and
    /// holds the first resource of an id it already has, so a peer node numbers what it sends
    /// north, as the client of a router does. A router's own faces and the faces south of a peer
    /// node are not of that kind.
    #[test]
    fn a_peer_node_and_a_client_node_number_what_they_send_north() {
        let zid = Zid::from_slice(&[7, 7, 7, 7]);
        let numbers = |node: &RouterForwarder, region: Region| {
            node.on_tables().tables.numbers_every_declaration_to(region)
        };
        let peer = RouterForwarder::peer(zid);
        assert!(numbers(&peer, NORTH_REGION));
        assert!(
            !numbers(&peer, CLIENTS_REGION),
            "the clients south of a peer node are told by the interest that asked"
        );
        let router = RouterForwarder::new(zid);
        assert!(
            !numbers(&router, NORTH_REGION),
            "a router's north keeps declarations by key"
        );
        let client = RouterForwarder::peer(zid).as_client_of_north();
        assert!(numbers(&client, NORTH_REGION));
    }

    /// The planes a face is numbered for: a south peer's subscribers and queryables carry the id
    /// of the interest that asked, so only its tokens are numbered here.
    #[test]
    fn a_south_peer_is_numbered_for_tokens_alone() {
        assert!(Numbered::Tokens.covers(Plane::Token));
        assert!(!Numbered::Tokens.covers(Plane::Subscriber));
        assert!(!Numbered::Tokens.covers(Plane::Queryable));
        assert!(Numbered::Everything.covers(Plane::Queryable));
        assert!(!Numbered::Nothing.covers(Plane::Token));
    }
}
