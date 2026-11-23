// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The peers of a session, read one at a time ([`SessionEngine::next_peer`],
//! [`SessionEngine::next_group_member`]).
//!
//! A C ABI lists them to a C callback (zenoh-pico's `z_info_peers_zid` and
//! `z_info_routers_zid`), which must not run under the session's lock and must not cost a list
//! on the heap: each identity is copied out of one call, which takes the session and lets it go,
//! and handed on after. [`each_peer`] and [`each_group_member`] are that walk. A Rust caller
//! that wants the whole list as values reads it through [`PeerLists`].

use alloc::vec::Vec;

use wz_session_core::session_zid::SessionZid;

use crate::SessionEngine;

/// An established peer of a session: its zid, and the role it announced in its 2-bit wire form
/// (0 router, 1 peer, 2 client).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The zid its handshake carried.
    pub zid: SessionZid,
    /// The role it announced, as the wire carries it.
    pub whatami: u8,
}

/// Hand `each` every item `next` answers, in key order: `next(from)` is the item with the least
/// key at or past `from`.
fn walk<T>(mut next: impl FnMut(u64) -> Option<(u64, T)>, mut each: impl FnMut(T)) {
    let mut from = 0;
    while let Some((key, item)) = next(from) {
        each(item);
        match key.checked_add(1) {
            Some(after) => from = after,
            None => break,
        }
    }
}

/// Hand `each` every established peer of `engine`'s session ([`SessionEngine::next_peer`]),
/// with nothing of the session held while it runs.
pub fn each_peer<E: SessionEngine + ?Sized>(engine: &E, each: impl FnMut(PeerIdentity)) {
    walk(|from| engine.next_peer(from), each);
}

/// Hand `each` the zid of every member of the groups `engine`'s session joined
/// ([`SessionEngine::next_group_member`]), with nothing of the session held while it runs.
pub fn each_group_member<E: SessionEngine + ?Sized>(engine: &E, each: impl FnMut(SessionZid)) {
    walk(|from| engine.next_group_member(from), each);
}

/// A node a session knows of, as a C ABI lists them: an established peer, or a member of a group
/// the session joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownNode {
    /// An established peer, with the role it announced.
    Peer(PeerIdentity),
    /// A member of a group the session joined, whatever role it announced.
    GroupMember(SessionZid),
}

/// Hand `each` every established peer of `engine`'s session, then every member of the groups it
/// joined, with nothing of the session held while it runs: one walk, so a door that lists both
/// hands each to its callback from one place.
pub fn each_known_node<E: SessionEngine + ?Sized>(engine: &E, each: impl FnMut(KnownNode)) {
    walk_peers_then_members(
        |peers, from| {
            if peers {
                engine
                    .next_peer(from)
                    .map(|(key, peer)| (key, KnownNode::Peer(peer)))
            } else {
                engine
                    .next_group_member(from)
                    .map(|(key, zid)| (key, KnownNode::GroupMember(zid)))
            }
        },
        each,
    );
}

/// The walk of [`each_known_node`]: every item `next(true, ..)` answers, then every item
/// `next(false, ..)` does, each run of keys from `0`, through one body.
fn walk_peers_then_members<T>(
    mut next: impl FnMut(bool, u64) -> Option<(u64, T)>,
    mut each: impl FnMut(T),
) {
    for peers in [true, false] {
        walk(|from| next(peers, from), &mut each);
    }
}

/// The peers of a session as whole lists, for a Rust caller with a heap: what [`each_peer`] and
/// [`each_group_member`] hand on, collected.
pub trait PeerLists {
    /// The zid and the wire role of every established peer.
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)>;

    /// The zid of every member of every group the session joined.
    fn group_member_zids(&self) -> Vec<Vec<u8>>;
}

impl<E: SessionEngine + ?Sized> PeerLists for E {
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        let mut peers = Vec::new();
        each_peer(self, |peer| peers.push((peer.zid.to_vec(), peer.whatami)));
        peers
    }

    fn group_member_zids(&self) -> Vec<Vec<u8>> {
        let mut members = Vec::new();
        each_group_member(self, |zid| members.push(zid.to_vec()));
        members
    }
}

#[cfg(test)]
mod tests {
    use super::{walk, walk_peers_then_members};
    use alloc::vec::Vec;

    /// The peers are walked first, then the members, each run of keys asked from `0`. Turned red
    /// by a walk that carries the last key of the peers into the members, or skips either.
    #[test]
    fn peers_are_walked_then_members_each_from_the_first_key() {
        let peers = [(0u64, 'p'), (5, 'q')];
        let members = [(1u64, 'm')];
        let mut read = Vec::new();
        walk_peers_then_members(
            |are_peers, from| {
                let items: &[(u64, char)] = if are_peers { &peers } else { &members };
                items.iter().copied().find(|(key, _)| *key >= from)
            },
            |item| read.push(item),
        );
        assert_eq!(read, ['p', 'q', 'm']);
    }

    /// A walk asks from 0 and then past each key answered, so it reads every item once in key
    /// order whatever the gaps between the keys, and stops at the last.
    #[test]
    fn a_walk_reads_each_item_once_past_the_key_before() {
        let items = [(2u64, 'a'), (3, 'b'), (9, 'c')];
        let mut asked = Vec::new();
        let mut read = Vec::new();
        walk(
            |from| {
                asked.push(from);
                items.iter().copied().find(|(key, _)| *key >= from)
            },
            |item| read.push(item),
        );
        assert_eq!(read, ['a', 'b', 'c']);
        assert_eq!(
            asked,
            [0, 3, 4, 10],
            "each ask is past the key answered before it"
        );
    }

    /// An item at the last key ends the walk instead of asking past it.
    #[test]
    fn a_walk_ends_at_the_last_key() {
        let mut read = 0;
        walk(|from| (from == 0).then_some((u64::MAX, ())), |()| read += 1);
        assert_eq!(read, 1);
    }
}
