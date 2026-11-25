// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What each connectivity listener whose history is being replayed was told of the session's
//! faces, kept on the rows that hold the faces (`wz_capi_port::told`), with nothing allocated.
//!
//! A face's row notes the listeners told it stands. A face that goes keeps the row it was told
//! as, its tomb, until each of those listeners was told it left: a taken face whose tomb is still
//! owed keeps its place in the face table past its link, departed, and the dial role's face keeps
//! one tomb beside the link it dials again, a second of another key taking a free place of the
//! table as a departed face. The places are the ones the open reserved for `max_faces`, and a
//! group's members keep theirs in the group's member rows (`group`).
//!
//! A face that stands comes before a departure owed: a departed place is given up for a face that
//! comes when the table has no other room (`faces_full`), and a second tomb of the dial role's
//! face that finds every place held is not kept. The listeners those were owed to are not told
//! that row left.
//!
//! A session's unicast face holds one link (no build of this engine aggregates links), so the
//! told unit is the face, and a key of any link past the first names no row.

use super::*;
use wz_capi_port::told::{ToldBits, ToldKey, ToldPlane};
use wz_runtime_coop::faces::FacePlaces;

/// A row of a face that went, as its listeners were told it, and those still to be told it left.
pub(super) struct Tomb {
    row: FaceLinkRow,
    bits: ToldBits,
}

/// A face's part in what the replaying listeners were told: who was told it stands, the tomb of a
/// row of it that went, and whether the face itself went and its place is kept for the tomb alone.
#[derive(Default)]
pub(super) struct FaceTold {
    bits: ToldBits,
    tomb: Option<Tomb>,
    departed: bool,
}

impl FaceTold {
    /// The place of a face that went, kept for `tomb` alone.
    fn departed(tomb: Tomb) -> Self {
        Self {
            bits: ToldBits::default(),
            tomb: Some(tomb),
            departed: true,
        }
    }

    /// Whether the face went and its place is kept for its tomb alone.
    #[cfg(any(feature = "listen", test))]
    fn is_departed(&self) -> bool {
        self.departed
    }

    /// Whether the place of a departed face is owed to no listener any more.
    fn is_spent(&self) -> bool {
        self.departed && self.tomb.is_none()
    }

    /// The face's row, read as `row`, went: the listeners told it stands are owed its departure,
    /// kept in this face's tomb, or joined to it when it is of the same key (no listener of the
    /// tomb is told the new row came before it was told the old one left, so the two sets are
    /// apart). The tomb handed back is one of another key, which this place has no room for.
    fn went(&mut self, row: Option<FaceLinkRow>) -> Option<Tomb> {
        let bits = core::mem::take(&mut self.bits);
        if bits.is_empty() {
            return None;
        }
        // A row a listener was told stands reads while its link is held, so `None` is a row no
        // listener was told.
        let row = row?;
        match &mut self.tomb {
            None => {
                self.tomb = Some(Tomb { row, bits });
                None
            }
            Some(tomb) if ToldKey::of_row(&tomb.row) == ToldKey::of_row(&row) => {
                tomb.bits = tomb.bits.union(bits);
                None
            }
            Some(_) => Some(Tomb { row, bits }),
        }
    }

    /// Whether `listener` of `plane` is still to be told the row of `key` left.
    fn owes(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.tomb.as_ref().is_some_and(|tomb| {
            ToldKey::of_row(&tomb.row) == *key && tomb.bits.has(plane, listener)
        })
    }

    /// Note `listener` of `plane` told the row of `key` left: whether it was owed that.
    fn tell_went(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        if !self.owes(plane, listener, key) {
            return false;
        }
        self.forget_tomb(plane, listener);
        true
    }

    /// The row whose departure `listener` of `plane` is owed here.
    fn first_gone(&self, plane: ToldPlane, listener: usize) -> Option<&FaceLinkRow> {
        self.tomb
            .as_ref()
            .filter(|tomb| tomb.bits.has(plane, listener))
            .map(|tomb| &tomb.row)
    }

    /// Note nothing more for `listener` of `plane`.
    fn forget(&mut self, plane: ToldPlane, listener: usize) {
        self.bits.clear(plane, listener);
        self.forget_tomb(plane, listener);
    }

    /// Take `listener` of `plane` off the tomb, which is let go of once it is owed to no one.
    fn forget_tomb(&mut self, plane: ToldPlane, listener: usize) {
        if let Some(tomb) = &mut self.tomb {
            tomb.bits.clear(plane, listener);
            if tomb.bits.is_empty() {
                self.tomb = None;
            }
        }
    }
}

/// The key of `face` when its row stands as `Core::face_link_at` reads it: its link is up and
/// its row names the link's ends.
fn standing_key<C: ClockSource + 'static, L: CoopLinks>(face: &Face<C, L>) -> Option<ToldKey> {
    let row = face.facts()?.standing_row()?;
    Some(ToldKey {
        zid: row.zid,
        is_multicast: false,
        link: 0,
    })
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// Note `listener` of `plane` told the row of `key` came (`SessionEngine::tell_came`):
    /// whether it is to be told. A row it is still owed the departure of under that key is not
    /// told again before that departure, so a reconnect reads as one, in order.
    pub(super) fn tell_came(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        if key.link != 0 || self.owes_departure(plane, listener, key) {
            return false;
        }
        #[cfg(feature = "group")]
        if key.is_multicast {
            return self
                .transport
                .groups
                .iter()
                .any(|group| group.tell_came(plane, listener, key));
        }
        for face in self.transport.links.faces_mut() {
            if standing_key(face) == Some(*key) {
                return face.told.bits.set(plane, listener);
            }
        }
        false
    }

    /// The row at cursor `at` of the links of the faces that stand (`SessionEngine::face_link_at`),
    /// in the order [`Self::standing_faces`] lists them: each face's from what its link said as it
    /// came up, then each group member's, copied into the row with nothing allocated.
    pub(super) fn face_link_at(&self, at: usize) -> Option<FaceLinkRow> {
        let mut at = at;
        let rows = self
            .transport
            .links
            .faces()
            .filter_map(|face| face.facts()?.standing_row());
        for row in rows {
            // A face holds one link, the row its facts keep: past it the cursor moves on by one.
            match at.checked_sub(1) {
                Some(rest) => at = rest,
                None => return Some(row.clone()),
            }
        }
        #[cfg(feature = "group")]
        for group in &self.transport.groups {
            match at.checked_sub(group.member_rows()) {
                Some(rest) => at = rest,
                None => return group.member_row(at),
            }
        }
        None
    }

    /// The faces that stand (`SessionEngine::face_snapshots`): each face's as its link said it
    /// came up, then each member of a group the session joined, a transport of its own as both
    /// upstreams report it (`group`).
    pub(super) fn standing_faces(&self) -> Vec<FaceSnapshot> {
        let faces = self.transport.links.faces().filter_map(|face| {
            // What the link says beyond its row is read off it here, with the snapshot that
            // takes the heap anyway: kept in the facts, its names would take the heap when
            // the link comes up, after the open.
            let link = face.link.wire().map_or_else(LinkFacts::default, |wire| {
                LinkFacts::of_actions(&*wire.actions)
            });
            face.facts()?.snapshot(&link)
        });
        #[cfg(feature = "group")]
        let faces = faces.chain(
            self.transport
                .groups
                .iter()
                .flat_map(|group| group.member_snapshots()),
        );
        faces.collect()
    }

    /// Whether `listener` of `plane` is still to be told the row of `key` left.
    fn owes_departure(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        #[cfg(feature = "group")]
        if self
            .transport
            .groups
            .iter()
            .any(|group| group.owes_departure(plane, listener, key))
        {
            return true;
        }
        self.transport
            .links
            .faces()
            .any(|face| face.told.owes(plane, listener, key))
    }

    /// Note `listener` of `plane` told the row of `key` left (`SessionEngine::tell_went`):
    /// whether it is to be told, which it is only when a tomb of that key owes it the departure.
    /// A departed face's place owed to no one more is let go of.
    pub(super) fn tell_went(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        #[cfg(feature = "group")]
        if self
            .transport
            .groups
            .iter()
            .any(|group| group.tell_went(plane, listener, key))
        {
            return true;
        }
        let Some(at) = self
            .transport
            .links
            .places_mut()
            .placed_mut()
            .find_map(|(at, face)| face.told.tell_went(plane, listener, key).then_some(at))
        else {
            return false;
        };
        self.let_go_if_spent(at);
        true
    }

    /// The first row whose departure `listener` of `plane` is owed
    /// (`SessionEngine::first_told_gone`), copied out of its tomb.
    pub(super) fn first_told_gone(&self, plane: ToldPlane, listener: usize) -> Option<FaceLinkRow> {
        if let Some(row) = self
            .transport
            .links
            .faces()
            .find_map(|face| face.told.first_gone(plane, listener))
        {
            return Some(row.clone());
        }
        #[cfg(feature = "group")]
        if let Some(row) = self
            .transport
            .groups
            .iter()
            .find_map(|group| group.first_told_gone(plane, listener))
        {
            return Some(row);
        }
        None
    }

    /// Note nothing more for `listener` of `plane` (`SessionEngine::forget_told`): its bits
    /// are cleared from every row, and a tomb, or a departed place, owed only to it is let go of.
    pub(super) fn forget_told(&mut self, plane: ToldPlane, listener: usize) {
        for face in self.transport.links.faces_mut() {
            face.told.forget(plane, listener);
        }
        // A place let go of moves no other face.
        for at in 0..self.transport.links.places() {
            self.let_go_if_spent(at);
        }
        #[cfg(feature = "group")]
        for group in &self.transport.groups {
            group.forget_told(plane, listener);
        }
    }

    /// The face at `at`, whose link is lost, went: the listeners told its row are owed its
    /// departure, read before the link is let go of. A tomb its place has no room for takes a
    /// free place of the session's as a departed face, kept from every face that comes until the
    /// tomb is owed to no one, and is not kept when there is none.
    pub(super) fn face_went(&mut self, at: usize) {
        let Some(face) = self.transport.links.face_mut(at) else {
            return;
        };
        if face.told.bits.is_empty() {
            return;
        }
        // The row it was told as, whether or not its session was seen to end before the loss.
        let row = face.facts.as_ref().and_then(|facts| facts.row.clone());
        let Some(apart) = face.told.went(row) else {
            return;
        };
        let Some(place) = self.session.registry.keep_place() else {
            return;
        };
        let id = self.transport.links.next_face_id();
        let departed = Face {
            id,
            link: Link::Waiting { at_us: u64::MAX },
            replay: Replay::idle(),
            facts: None,
            told: FaceTold::departed(apart),
        };
        if self.transport.links.place_face(place, departed).is_ok() {
            self.transport.links.advance_face_id();
        } else {
            self.session.registry.free_kept(place);
        }
    }

    /// Keep the taken face at `at`, whose link went, as a departed place while its tomb is owed:
    /// its tables go now, as a removed face's do, and its place, which no face takes meanwhile,
    /// once no listener is owed its departure. `false` for a face with no tomb, and for the dial
    /// role's, which stays. Only a face taken besides the dial (`listen`) is removed.
    #[cfg(feature = "listen")]
    pub(super) fn keep_departed(&mut self, at: usize) -> bool {
        let Some(face) = self.transport.links.face_mut(at) else {
            return false;
        };
        if face.id == DIAL_FACE || face.told.tomb.is_none() {
            return false;
        }
        face.told.departed = true;
        // A wait that is never due: the face is not dialled, and its value stays as it is.
        face.link = Link::Waiting { at_us: u64::MAX };
        let id = face.id;
        self.session.registry.depart(HeldFace::new(at, id));
        true
    }

    /// Let go of the place at `at` when it is a departed face's owed to no one.
    fn let_go_if_spent(&mut self, at: usize) {
        if self
            .transport
            .links
            .face(at)
            .is_some_and(|face| face.told.is_spent())
        {
            self.let_go_departed(at);
        }
    }

    /// Free the place at `at` a departed face kept, in the face table and the registry alike.
    fn let_go_departed(&mut self, at: usize) {
        self.transport.links.take_face(at);
        self.session.registry.free_kept(at);
    }

    /// Give up the first departed place, whose listeners are then not told its row left: what a
    /// face that comes to a full table takes (`faces_full`).
    #[cfg(feature = "listen")]
    pub(super) fn give_up_a_departure(&mut self) {
        // Found first and the walk let go of, so the place is freed with nothing of the table lent.
        let departed = self
            .transport
            .links
            .placed()
            .find_map(|(at, face)| face.told.is_departed().then_some(at));
        if let Some(at) = departed {
            self.let_go_departed(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::face::RowText;

    fn row(first: u8) -> FaceLinkRow {
        FaceLinkRow {
            zid: [first; 16],
            whatami: 1,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            link: 0,
            links: 1,
            src: RowText::of("udp/127.0.0.1:1"),
            dst: RowText::of("udp/127.0.0.1:2"),
            kind: None,
            mtu: 0,
            group_endpoint: None,
            lost_after: 0,
        }
    }

    fn told(listener: usize) -> FaceTold {
        let mut face = FaceTold::default();
        face.bits.set(ToldPlane::Transports, listener);
        face
    }

    /// A face no replaying listener was told keeps no tomb when it goes, and one that was told
    /// keeps the row it was told as until the listener was told it left.
    ///
    /// # Control
    ///
    /// Keeping the tomb past the `tell_went` (not letting go of it) reds the last assertion.
    #[test]
    fn a_face_keeps_its_tomb_only_while_a_listener_is_owed_its_departure() {
        let mut untold = FaceTold::default();
        assert!(untold.went(Some(row(1))).is_none());
        assert!(untold.tomb.is_none(), "no listener was told it: no tomb");

        let mut face = told(0);
        assert!(face.went(Some(row(1))).is_none(), "its own place holds it");
        assert!(face.bits.is_empty(), "the bits moved into the tomb");
        let key = ToldKey::of_row(&row(1));
        assert!(face.owes(ToldPlane::Transports, 0, &key));
        assert!(
            !face.owes(ToldPlane::Links, 0, &key),
            "a plane apart owes nothing"
        );
        assert_eq!(
            face.first_gone(ToldPlane::Transports, 0).map(|row| row.zid),
            Some([1; 16])
        );
        assert!(face.tell_went(ToldPlane::Transports, 0, &key));
        assert!(!face.tell_went(ToldPlane::Transports, 0, &key), "told once");
        assert!(face.tomb.is_none(), "a tomb owed to no one is let go of");
    }

    /// A second departure of the same key joins the tomb; one of another key is handed back for a
    /// place apart, and the tomb it found is kept whole.
    ///
    /// # Control
    ///
    /// Overwriting the tomb with the second row reds the assertion on listener 0's departure.
    #[test]
    fn a_departure_of_another_key_is_handed_back_and_one_of_the_same_key_joins() {
        let mut face = told(0);
        assert!(face.went(Some(row(1))).is_none());
        face.bits.set(ToldPlane::Transports, 1);
        assert!(face.went(Some(row(1))).is_none(), "the same key joins");
        let key = ToldKey::of_row(&row(1));
        assert!(face.owes(ToldPlane::Transports, 0, &key));
        assert!(face.owes(ToldPlane::Transports, 1, &key));

        face.bits.set(ToldPlane::Transports, 2);
        let apart = face
            .went(Some(row(2)))
            .expect("another key needs a place apart");
        assert_eq!(apart.row.zid, [2; 16]);
        assert!(apart.bits.has(ToldPlane::Transports, 2));
        assert!(
            face.owes(ToldPlane::Transports, 0, &key),
            "listener 0 is still owed the first row's departure"
        );
    }

    /// A departed place is spent once its tomb is owed to no one, and a listener forgotten is
    /// owed nothing.
    ///
    /// # Control
    ///
    /// `forget` that leaves the tomb's bit reds `is_spent`.
    #[test]
    fn a_departed_place_is_spent_once_its_last_listener_is_forgotten() {
        let mut bits = ToldBits::default();
        bits.set(ToldPlane::Links, 3);
        let mut place = FaceTold::departed(Tomb { row: row(4), bits });
        assert!(place.is_departed());
        assert!(!place.is_spent());
        place.forget(ToldPlane::Transports, 3);
        assert!(!place.is_spent(), "another plane's listener is no one here");
        place.forget(ToldPlane::Links, 3);
        assert!(place.is_spent());
    }
}
