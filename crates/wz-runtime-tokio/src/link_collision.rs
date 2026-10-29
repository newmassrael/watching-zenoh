// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Collision resolution for a node that holds one face per remote zid.
//!
//! Two nodes that each listen and each dial the other make two links between one pair, and a
//! session that keys routing state on the zid keeps one of them. This is the problem of a
//! CONNECTION COLLISION, and its textbook answer is the one BGP gives (RFC 4271 section 6.8) and
//! Erlang's distribution handshake gives: when the identity of the far end is known and a second
//! connection to it exists, compare the two identifiers, which both ends read alike, and keep the
//! connection the node with the lower one opened, so that neither end closes the connection the
//! other kept. "The first up" is not an answer to a collision: each end keeps the link that
//! completed first on ITS side, the two sides disagree, and each closes the link the other kept.
//! The rule itself is one pure function, [`wz_session_core::link_admission`], which the
//! cooperative engine's face table and the tokio engine's C-ABI registry call too.
//!
//! What this module adds is the part of the answer that is not a comparison and that a face loop
//! has to get right: WHEN the winner is admitted. The routing graph of a router or a peer keys a
//! link on the zid, so a node that admitted the winner while the held face was still being torn
//! down would let that face's teardown remove the link of the face that replaced it. The winner is
//! therefore PARKED while the held face is asked to close, and admitted only after the loop has
//! processed the held face's departure, through the same door a new link comes in by. A third link
//! to the node that arrives meanwhile is refused: the node is not held by a face that stays.
//!
//! No sockets and no futures: the state is two small tables, so the whole of the machine can be
//! read, and tested over every order two ends can complete their links in, without a runtime.

use std::collections::{BTreeMap, BTreeSet};

use wz_session_core::link_admission::SecondLink;

use crate::accept_loop::FaceId;

/// What the loop does with a link that completed its handshake to a node it may already hold.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// No face that stays links the loop to the node: the link is admitted as it is.
    Admit,
    /// A face that stays already does: the link is closed.
    Refuse,
    /// The new link is the one to keep. The face `held` is to be closed and the new link parked
    /// ([`LinkCollisions::park`]) until it has left.
    Replace { held: FaceId },
}

/// The held faces' directions and the links parked behind a face that is closing. `P` is what the
/// loop parks: the open it will admit once the held face has gone.
pub(crate) struct LinkCollisions<P> {
    /// The held faces this node dialled. A face not listed was accepted, which is also what a
    /// face the loop never told of ([`Self::admitted`]) reads as.
    dialled: BTreeSet<FaceId>,
    /// Held face -> the link waiting for it to leave.
    closing: BTreeMap<FaceId, P>,
}

impl<P> Default for LinkCollisions<P> {
    fn default() -> Self {
        Self {
            dialled: BTreeSet::new(),
            closing: BTreeMap::new(),
        }
    }
}

impl<P> LinkCollisions<P> {
    /// A face the loop holds from now, `dialled` when this node opened the link.
    pub(crate) fn admitted(&mut self, id: FaceId, dialled: bool) {
        if dialled {
            self.dialled.insert(id);
        }
    }

    /// The decision for a link `new_dialled` (or not) to the node `zid`, against the faces the
    /// loop holds (`held`: each face and the zid its peer named). `judge` is the forwarder's rule
    /// for two links to one node (held link's direction, new link's direction) and answers `None`
    /// when it has none, which keeps the first up. `can_replace` says whether a face can be
    /// closed on its own: a face that is one link of an aggregated session cannot.
    pub(crate) fn resolve(
        &self,
        held: &BTreeMap<FaceId, Option<Vec<u8>>>,
        zid: &[u8],
        new_dialled: bool,
        judge: impl FnOnce(bool, bool) -> Option<SecondLink>,
        can_replace: impl FnOnce(FaceId) -> bool,
    ) -> Resolution {
        // By the id and not its spelling: the wire trims a zid's trailing zero bytes and a
        // handshake keeps the bytes it was given.
        let Some(rival) = held.iter().find_map(|(id, held_zid)| {
            held_zid
                .as_deref()
                .filter(|held_zid| crate::zid_hex::same_zid(held_zid, zid))
                .map(|_| *id)
        }) else {
            return Resolution::Admit;
        };
        // The node is held by a face that is already on its way out for a link that won: this
        // link is a third, and the winner is the one that stays.
        if self.closing.contains_key(&rival) || !can_replace(rival) {
            return Resolution::Refuse;
        }
        match judge(self.dialled.contains(&rival), new_dialled) {
            Some(SecondLink::Replace) => Resolution::Replace { held: rival },
            Some(SecondLink::Refuse) | None => Resolution::Refuse,
        }
    }

    /// Park `winner` behind the face `held`, which has been asked to close.
    pub(crate) fn park(&mut self, held: FaceId, winner: P) {
        self.closing.insert(held, winner);
    }

    /// The face `id` has left the loop: what was parked behind it, if anything, is now free to be
    /// admitted. Called after the departure is fully processed, which is what the parking is for.
    pub(crate) fn departed(&mut self, id: FaceId) -> Option<P> {
        self.dialled.remove(&id);
        self.closing.remove(&id)
    }

    /// How many links wait for a face to leave.
    #[cfg(test)]
    pub(crate) fn parked(&self) -> usize {
        self.closing.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::link_admission::judge_second_link;

    const NODE: [u8; 4] = [0x42, 0, 0, 0];

    fn faces(rows: &[(u64, Option<&[u8]>)]) -> BTreeMap<FaceId, Option<Vec<u8>>> {
        rows.iter()
            .map(|(id, zid)| (FaceId(*id), zid.map(<[u8]>::to_vec)))
            .collect()
    }

    fn replace_always(_held: bool, _new: bool) -> Option<SecondLink> {
        Some(SecondLink::Replace)
    }

    #[test]
    fn a_link_to_a_node_no_face_holds_is_admitted() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(&faces(&[]), &NODE, true, replace_always, |_| true),
            Resolution::Admit
        );
        assert_eq!(
            tables.resolve(
                &faces(&[(1, Some(&[0x77]))]),
                &NODE,
                true,
                replace_always,
                |_| true
            ),
            Resolution::Admit,
            "a face to another node is no rival"
        );
    }

    #[test]
    fn a_face_that_named_no_node_is_no_rival() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(&faces(&[(1, None)]), &NODE, true, replace_always, |_| true),
            Resolution::Admit
        );
    }

    #[test]
    fn the_node_is_matched_by_the_id_and_not_by_its_spelling() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(
                &faces(&[(1, Some(&[0x42]))]),
                &NODE,
                true,
                |_, _| Some(SecondLink::Refuse),
                |_| true
            ),
            Resolution::Refuse,
            "[0x42] and [0x42, 0, 0, 0] are one node"
        );
    }

    #[test]
    fn a_forwarder_with_no_rule_keeps_the_first_up() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(
                &faces(&[(1, Some(&NODE))]),
                &NODE,
                true,
                |_, _| None,
                |_| true
            ),
            Resolution::Refuse
        );
    }

    #[test]
    fn a_link_the_rule_keeps_names_the_face_to_close() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(
                &faces(&[(7, Some(&NODE))]),
                &NODE,
                true,
                replace_always,
                |_| true
            ),
            Resolution::Replace { held: FaceId(7) }
        );
    }

    #[test]
    fn the_rule_is_given_the_directions_of_the_held_and_of_the_new_link() {
        let mut tables = LinkCollisions::<u32>::default();
        tables.admitted(FaceId(7), true);
        let mut seen = None;
        tables.resolve(
            &faces(&[(7, Some(&NODE))]),
            &NODE,
            false,
            |held, new| {
                seen = Some((held, new));
                None
            },
            |_| true,
        );
        assert_eq!(seen, Some((true, false)), "(held dialled, new dialled)");
        // A face the loop never told of was accepted.
        let tables = LinkCollisions::<u32>::default();
        let mut seen = None;
        tables.resolve(
            &faces(&[(7, Some(&NODE))]),
            &NODE,
            true,
            |held, new| {
                seen = Some((held, new));
                None
            },
            |_| true,
        );
        assert_eq!(seen, Some((false, true)));
    }

    #[test]
    fn a_face_that_cannot_be_closed_on_its_own_is_not_replaced() {
        let tables = LinkCollisions::<u32>::default();
        assert_eq!(
            tables.resolve(
                &faces(&[(7, Some(&NODE))]),
                &NODE,
                true,
                replace_always,
                |_| false
            ),
            Resolution::Refuse,
            "one link of an aggregated session is not a face of its own"
        );
    }

    #[test]
    fn a_third_link_while_a_replacement_is_under_way_is_refused() {
        let mut tables = LinkCollisions::default();
        let held = faces(&[(7, Some(&NODE))]);
        assert_eq!(
            tables.resolve(&held, &NODE, true, replace_always, |_| true),
            Resolution::Replace { held: FaceId(7) }
        );
        tables.park(FaceId(7), "winner");
        assert_eq!(tables.parked(), 1);
        assert_eq!(
            tables.resolve(&held, &NODE, true, replace_always, |_| true),
            Resolution::Refuse,
            "the winner is the link that stays, and it has not been admitted yet"
        );
    }

    #[test]
    fn what_was_parked_is_handed_back_once_and_only_when_its_face_has_left() {
        let mut tables = LinkCollisions::default();
        tables.admitted(FaceId(7), true);
        tables.admitted(FaceId(8), false);
        tables.park(FaceId(7), "winner");
        assert_eq!(
            tables.departed(FaceId(8)),
            None,
            "another face leaving frees nothing"
        );
        assert_eq!(tables.parked(), 1);
        assert_eq!(tables.departed(FaceId(7)), Some("winner"));
        assert_eq!(tables.departed(FaceId(7)), None, "and only once");
        assert_eq!(tables.parked(), 0);
        // The departed face's direction is forgotten, so a reused id starts as accepted.
        let mut seen = None;
        tables.resolve(
            &faces(&[(7, Some(&NODE))]),
            &NODE,
            true,
            |held, _| {
                seen = Some(held);
                None
            },
            |_| true,
        );
        assert_eq!(seen, Some(false));
    }

    /// One end of a pair of nodes that dialled each other, as the loop runs it: the link that
    /// completed first on this side is held, the other comes up and is decided by the rule the
    /// loops call, and a replaced face is closed, leaves, and has the winner admitted after it.
    /// Returns whether the link this end ends with is one THIS node dialled.
    fn ends_with_a_link_it_dialled(local: &[u8], remote: &[u8], first_dialled: bool) -> bool {
        let mut tables = LinkCollisions::<bool>::default();
        let mut held = faces(&[(1, Some(remote))]);
        tables.admitted(FaceId(1), first_dialled);
        let second_dialled = !first_dialled;
        let resolution = tables.resolve(
            &held,
            remote,
            second_dialled,
            |held_dialled, new_dialled| {
                Some(judge_second_link(held_dialled, new_dialled, local, remote))
            },
            |_| true,
        );
        match resolution {
            Resolution::Refuse => first_dialled,
            Resolution::Replace { held: closing } => {
                tables.park(closing, second_dialled);
                // The held face has been closed and its departure processed: it is no longer
                // held, and the link parked behind it is admitted.
                held.remove(&closing);
                let winner = tables.departed(closing).expect("the winner was parked");
                assert!(
                    held.is_empty(),
                    "the node is held by no face until the winner is"
                );
                winner
            }
            Resolution::Admit => unreachable!("the node is held"),
        }
    }

    #[test]
    fn both_ends_keep_the_same_link_whichever_completed_first_at_each() {
        // Node `a` dialled link X and node `b` dialled link Y. At each end the two links complete
        // in either order, so the ends can disagree about which is the first, which is exactly
        // when "the first up" has each end close the link the other kept.
        let zids: [(&[u8], &[u8]); 3] = [
            (&[0x10], &[0xa0]),
            (&[0xa0], &[0x10]),
            (&[0x01, 0x00], &[0xff]),
        ];
        for (a, b) in zids {
            for x_first_at_a in [true, false] {
                for x_first_at_b in [true, false] {
                    // At `a` the first link is X when it is the one `a` dialled; at `b` X is the
                    // link it accepted, and Y is the one it dialled.
                    let a_dialled_its_keeper = ends_with_a_link_it_dialled(a, b, x_first_at_a);
                    let b_dialled_its_keeper = ends_with_a_link_it_dialled(b, a, !x_first_at_b);
                    // X is dialled by `a` only and Y by `b` only, so the ends keep one link
                    // exactly when one of them dialled what it kept and the other did not.
                    assert_ne!(
                        a_dialled_its_keeper, b_dialled_its_keeper,
                        "a={a:?} b={b:?}, x first at a: {x_first_at_a}, at b: {x_first_at_b}: \
                         the ends keep different links"
                    );
                }
            }
        }
    }
}
