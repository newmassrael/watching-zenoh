// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch: a C program told what the peers of its session declare and retract.
//!
//! A peer's subscriber, queryable or liveliness token reaches the session as a declaration on
//! the link to that peer, and its retraction as an undeclaration naming the same id. A watch is
//! told each of them for one kind of entity ([`DeclPlane`]), and, in a build with the
//! `declarations-synced-event` capability, once per establishment of a link that the peer has
//! sent everything it held when the link came up ([`DeclWatchEvent::Synced`]). With the
//! `remote-declaration-watch` capability every event names the peer it came from, as the zenoh
//! id the link's handshake gave.
//!
//! A watch of subscribers or queryables is told first what each peer holds when the watch is
//! declared, as [`DeclWatchEvent::Declared`] events ahead of every live event of that link, then
//! what the peers declare from then on, on every link the session holds and every link that comes
//! up later; each declaration is told once. A watch of tokens hears only what comes after it: the
//! tokio engine keeps no table of the tokens a peer holds. A watch declared after a peer finished
//! its initial declarations is not told [`DeclWatchEvent::Synced`] for that link. A link that is
//! lost tells no undeclaration for what its peer
//! held: the declarations went with the link, and the next establishment is told from its start.
//! The members of a multicast group are not watched: a group carries no declaration of a peer
//! that the session's links hold.
//!
//! The port holds the vocabulary both sides name: the event an engine hands a watch and the sink
//! an ABI hands the engine. Whether an engine watches at all is the engine's
//! ([`crate::SessionEngine::declare_decl_watch`]); one that does not refuses as every declaration
//! of the port does ([`crate::Refusal`]).

use alloc::sync::Arc;

use wz_session_core::session_zid::SessionZid;

/// Which kind of a peer's declarations a watch is told of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclPlane {
    /// The peers' subscribers.
    Subscribers,
    /// The peers' queryables.
    Queryables,
    /// The peers' liveliness tokens.
    Tokens,
}

/// One event a declaration watch is told. What it borrows lives for the call it is handed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclWatchEvent<'a> {
    /// The peer declared an entity under `id`, on `keyexpr`.
    Declared {
        /// The id the peer declared it under, which its undeclaration names again.
        id: u64,
        /// The key expression it was declared on, resolved against the peer's own key
        /// expression declarations.
        keyexpr: &'a str,
        /// The zenoh id of the peer, as its link's handshake gave it; `None` in a build without
        /// `remote-declaration-watch`, and when the link no longer held an identity.
        peer: Option<&'a [u8]>,
    },
    /// The peer retracted the entity it had declared under `id`. The wire names no key.
    Undeclared {
        /// The id of the declaration retracted.
        id: u64,
        /// As [`DeclWatchEvent::Declared`]'s.
        peer: Option<&'a [u8]>,
    },
    /// The peer has sent every declaration it held when the link came up; what follows is live.
    /// Told once for each establishment of a link, and only in a build with
    /// `declarations-synced-event`.
    Synced {
        /// As [`DeclWatchEvent::Declared`]'s.
        peer: Option<&'a [u8]>,
    },
}

impl<'a> DeclWatchEvent<'a> {
    /// The bytes of the peer's zenoh id, when the event names one.
    pub fn peer(&self) -> Option<&'a [u8]> {
        match *self {
            Self::Declared { peer, .. } | Self::Undeclared { peer, .. } | Self::Synced { peer } => {
                peer
            }
        }
    }

    /// The peer's zenoh id as a value that is one: `None` when the event names no peer, and when
    /// the bytes it names are not a zenoh id (none, more than sixteen, or all zero), which a
    /// handshake that completed never gave.
    pub fn peer_zid(&self) -> Option<SessionZid> {
        self.peer().and_then(|bytes| SessionZid::new(bytes).ok())
    }

    /// The id of the declaration the event is about; `None` for [`DeclWatchEvent::Synced`],
    /// which is about none.
    pub fn declaration_id(&self) -> Option<u64> {
        match *self {
            Self::Declared { id, .. } | Self::Undeclared { id, .. } => Some(id),
            Self::Synced { .. } => None,
        }
    }

    /// The key expression of a [`DeclWatchEvent::Declared`]; `None` for the other two.
    pub fn keyexpr(&self) -> Option<&'a str> {
        match *self {
            Self::Declared { keyexpr, .. } => Some(keyexpr),
            Self::Undeclared { .. } | Self::Synced { .. } => None,
        }
    }
}

/// What a watch is told through: one sink for the whole watch, which an engine hands every event
/// of every link to.
///
/// An engine calls it where it hands out the session's callbacks and never under a lock of its
/// own, so the sink may call back into the session. With more than one link the calls may come
/// from more than one thread; an ABI that hands the events to a program serialises them itself.
/// The engine drops its last reference when the watch is undeclared or the session is closed,
/// after any call in flight has returned.
pub type DeclWatchSink = Arc<dyn Fn(DeclWatchEvent<'_>) + Send + Sync>;

/// The id of one declaration watch on one session, which undeclares it.
pub type DeclWatchId = u64;

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 3] = [0xa1, 0x00, 0x7f];

    #[test]
    fn each_event_answers_its_own_parts_and_none_of_the_others() {
        let declared = DeclWatchEvent::Declared {
            id: 9,
            keyexpr: "demo/watch/a",
            peer: Some(&PEER),
        };
        assert_eq!(declared.declaration_id(), Some(9));
        assert_eq!(declared.keyexpr(), Some("demo/watch/a"));
        assert_eq!(declared.peer(), Some(&PEER[..]));

        let undeclared = DeclWatchEvent::Undeclared { id: 9, peer: None };
        assert_eq!(undeclared.declaration_id(), Some(9));
        assert_eq!(undeclared.keyexpr(), None, "an undeclaration names no key");
        assert_eq!(undeclared.peer(), None);

        let synced = DeclWatchEvent::Synced { peer: Some(&PEER) };
        assert_eq!(
            synced.declaration_id(),
            None,
            "the sync is about no one declaration"
        );
        assert_eq!(synced.keyexpr(), None);
        assert_eq!(synced.peer(), Some(&PEER[..]));
    }

    #[test]
    fn a_peer_is_a_zid_only_when_its_bytes_are_one() {
        let named = DeclWatchEvent::Synced { peer: Some(&PEER) };
        let zid = named
            .peer_zid()
            .expect("three bytes, not all zero, are a zid");
        assert_eq!(&*zid, &PEER[..]);
        assert_eq!(&zid.to_padded()[..3], &PEER[..]);
        assert!(zid.to_padded()[3..].iter().all(|b| *b == 0));

        assert_eq!(DeclWatchEvent::Synced { peer: None }.peer_zid(), None);
        let refused: [&[u8]; 3] = [&[], &[0, 0], &[1; 17]];
        for bytes in refused {
            assert_eq!(
                DeclWatchEvent::Synced { peer: Some(bytes) }.peer_zid(),
                None,
                "{bytes:?} is no zid"
            );
        }
    }
}
