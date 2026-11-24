// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's state as its layer (L3) holds it, apart from what the links carry and from the
//! engine that drives both: what the session declared and asked, over every link, and the round its
//! deliveries go through.
//!
//! The state is a value with no I/O of its own. An engine names the parts it keeps of an engine of
//! its own kind through [`SessionParts`]: the registry of its tables, the plane its queryables
//! answer through, its pending gets and the like, each the engine's own type, and `()` for a part
//! its build leaves out, so a build without a plane keeps no field of it and no `cfg` of a
//! feature reaches the struct: this crate's features are unified across the workspace and the
//! engine's are not, so a field that followed either could be there for one and not the other.
//! What every engine keeps alike (the key arena, the count of the session's own requests, where the
//! matching listeners were last read) is this crate's.

use core::cell::Cell;

use crate::key_arena::KeySpace;
use crate::wire_id::RequestId;

/// The parts of a session's state an engine keeps in types of its own: each is `()` where the
/// engine's build leaves the part out.
pub trait SessionParts {
    /// What the application holds and what the peers declared. It is the session's, so it outlives
    /// each link: a new link is dispatched to the same registry.
    type Registry;
    /// Where a face coming up or going is reported.
    type Watchers;
    /// How many rows each table of the session's own declarations was lent: what a write filter of
    /// each plane is held to.
    type Entities;
    /// The plane the session's queryables answer through.
    type Queryables;
    /// The legs of the session's gets still pending on its links.
    type PendingGets;
    /// The plane the session's gets are handed their replies through.
    type Gets;
    /// The session's round of deliveries, which every link's gate asks before it reads a record.
    type Lane;
    /// The key ids every node of the deployment shares, which the session was opened with
    /// (`shared_key_ids`, an `Option` of them where the engine keeps them).
    type KeyIds;
    /// The ids of the session's gets of its own queryables ([`LocalRequests`]).
    type LocalRequests;
}

/// The session's part of an engine's state: the tables of what it declared and asked, over every
/// link. Its fields are dropped in the order they are declared, the registry first.
pub struct SessionState<P: SessionParts> {
    /// What the application holds and what the peers declared.
    pub registry: P::Registry,
    /// Where a face coming up or going is reported.
    pub watchers: P::Watchers,
    /// How many rows each table of the session's own declarations was lent.
    pub entities: P::Entities,
    /// The key arena the rows of those tables keep their keys in, lent with them.
    pub keys: KeySpace,
    /// The key ids every node of the deployment shares, which the session was opened with: each
    /// link it opens is handed them, its key expressions are declared under ids past theirs, and a
    /// key goes on the wire as the session's key-wire form says.
    pub key_ids: P::KeyIds,
    /// The ids of the session's gets of its own queryables.
    pub local_requests: P::LocalRequests,
    /// Where the matching listeners were last read.
    pub matching: MatchingRead,
    /// The plane the session's queryables answer through.
    pub plane: P::Queryables,
    /// The legs of the session's gets still pending on its links.
    pub pending_gets: P::PendingGets,
    /// The plane the session's gets are handed their replies through.
    pub gets: P::Gets,
    /// The session's round of deliveries.
    pub lane: P::Lane,
}

/// The request ids of a session's gets of its own queryables, counted apart from the ids its links
/// hand out: from 0, wrapping, as a link's own count does.
#[derive(Debug, Default)]
pub struct LocalRequests {
    next: RequestId,
}

impl LocalRequests {
    /// The next id, taken.
    pub fn take(&mut self) -> RequestId {
        let id = self.next;
        self.next = id.wrapping_add(1);
        id
    }
}

/// The count of the faces' writes the session's matching listeners were last read at: a verdict
/// read then holds until the count moves, and a step that finds it moved reads them again.
#[derive(Debug, Default)]
pub struct MatchingRead {
    at: Cell<u64>,
}

impl MatchingRead {
    /// Whether the faces were written since the listeners were last read, `written` being the
    /// count of their writes now.
    pub fn moved(&self, written: u64) -> bool {
        self.at.get() != written
    }

    /// The listeners were read at `written` writes of the faces.
    pub fn read_at(&self, written: u64) {
        self.at.set(written);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session's own request ids count from 0 and wrap past the last.
    #[test]
    fn local_request_ids_count_from_zero_and_wrap() {
        let mut ids = LocalRequests::default();
        assert_eq!((ids.take(), ids.take()), (0, 1));
        let mut last = LocalRequests {
            next: RequestId::MAX,
        };
        assert_eq!((last.take(), last.take()), (RequestId::MAX, 0));
    }

    /// The listeners read at no write yet are current until the faces are written, and current
    /// again once read at the new count.
    #[test]
    fn the_matching_listeners_are_read_again_once_the_faces_moved() {
        let read = MatchingRead::default();
        assert!(!read.moved(0), "nothing was written since the open");
        assert!(read.moved(1));
        read.read_at(1);
        assert!(!read.moved(1));
        assert!(read.moved(2));
    }
}
