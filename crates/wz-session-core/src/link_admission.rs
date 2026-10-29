// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which of two links to one node a session keeps.
//!
//! A session holds one face for each remote zid, as zenoh's transport manager keeps one transport
//! for each (`max_links` is 1). A node that listens and dials can be reached by two links: one it
//! dialled and one it took off its port, or two that went the same way. This is the rule for the
//! second of them, and it is written once, here, so that every engine that decides the question
//! decides it the same way, because the question is asked at BOTH ends of the link and the two
//! answers must name one link:
//!
//! - Two links that went the same way (both dialled, or both taken off a port): the first up is
//!   kept. Each end saw the same two links in the same direction, and the one that completed
//!   first on this side is the one the peer completed first on its own, as the links are one pair.
//! - Two links that went opposite ways are two nodes that dialled each other at the same moment.
//!   "The first up" is then decided differently at the two ends (each keeps the link that
//!   completed first on ITS side, and each closes the link the other kept, which leaves none), so
//!   the rule reads only what both ends read alike: the two zids. The link kept is the one the
//!   node with the LOWER zid dialled.
//!
//! The function takes the zids and the directions and nothing of an engine, which is what lets the
//! cooperative engine's face table (`wz-capi-coop`) and a registry of another engine call the one
//! rule. Ungated, because it allocates nothing.

use crate::credential_identity::zid_from_wire;

/// What a session does with a link to a node it already holds a link to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondLink {
    /// Close the new link: the held one stays.
    Refuse,
    /// Close the held link: the new one takes its place.
    Replace,
}

/// A zid as the number it is, so that two nodes read the same order of two zids. An id that spells
/// no zid reads as 0.
fn zid_value(zid: &[u8]) -> u128 {
    zid_from_wire(zid).map_or(0, u128::from_le_bytes)
}

/// The fate of a NEW link to a node the session already holds a link to.
///
/// `held_dialled` and `new_dialled` say whether this session dialled each link (as opposed to
/// taking it off its port); `local_zid` is this session's own zid and `remote_zid` the node's.
/// The caller has established that both links reach `remote_zid`.
pub fn judge_second_link(
    held_dialled: bool,
    new_dialled: bool,
    local_zid: &[u8],
    remote_zid: &[u8],
) -> SecondLink {
    if held_dialled == new_dialled {
        return SecondLink::Refuse;
    }
    // The link the lower zid dialled wins: from here, a link this session dialled wins when this
    // session's zid is the lower one, and a link the node dialled when the node's is.
    let dialled_wins = zid_value(local_zid) < zid_value(remote_zid);
    if new_dialled == dialled_wins {
        SecondLink::Replace
    } else {
        SecondLink::Refuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two nodes `a` and `b` and two links between them, `x` dialled by `a` and `y` by `b`. Each
    /// end decides when its second link comes up; `first_at_a` and `first_at_b` say which of the
    /// two links completed first at that end. The link each end keeps is named by who dialled it.
    fn kept_at(first_is_x: bool, local: &[u8], remote: &[u8], local_dialled_x: bool) -> bool {
        // At this end, link x is `dialled` when this end is the one that dialled it.
        let x_dialled_here = local_dialled_x;
        let (held_dialled, new_dialled) = if first_is_x {
            (x_dialled_here, !x_dialled_here)
        } else {
            (!x_dialled_here, x_dialled_here)
        };
        match judge_second_link(held_dialled, new_dialled, local, remote) {
            // The new link is `y` when the first was `x`.
            SecondLink::Replace => !first_is_x,
            SecondLink::Refuse => first_is_x,
        }
    }

    #[test]
    fn two_links_that_went_the_same_way_keep_the_first() {
        for dialled in [true, false] {
            for (local, remote) in [([1u8], [2u8]), ([2], [1])] {
                assert_eq!(
                    judge_second_link(dialled, dialled, &local, &remote),
                    SecondLink::Refuse,
                    "the first up stays whichever zid is lower"
                );
            }
        }
    }

    #[test]
    fn both_ends_keep_the_same_link_whichever_completed_first_at_each() {
        // `a` dialled `x` and `b` dialled `y`. The zids are spelled the way they arrive (trimmed
        // and padded), so the order is read from the value, not the bytes.
        let zids: [(&[u8], &[u8]); 4] = [
            (&[0x10], &[0xa0]),
            (&[0xa0], &[0x10]),
            (&[0x01], &[0x01, 0x01]),
            (&[0x00, 0x01], &[0xff]),
        ];
        for (a, b) in zids {
            for first_at_a_is_x in [true, false] {
                for first_at_b_is_x in [true, false] {
                    // True when the end keeps `x`.
                    let a_keeps_x = kept_at(first_at_a_is_x, a, b, true);
                    let b_keeps_x = kept_at(first_at_b_is_x, b, a, false);
                    assert_eq!(
                        a_keeps_x, b_keeps_x,
                        "a={a:?} b={b:?} first at a {first_at_a_is_x} first at b {first_at_b_is_x}: \
                         the two ends keep different links"
                    );
                }
            }
        }
    }

    #[test]
    fn the_link_the_lower_zid_dialled_is_the_one_kept() {
        // `a` has the lower zid and dialled `x`: every ordering keeps `x`.
        for first_is_x in [true, false] {
            assert!(kept_at(first_is_x, &[0x10], &[0xa0], true));
            assert!(kept_at(first_is_x, &[0xa0], &[0x10], false));
        }
        // And with `b` the lower one, `y` is kept.
        for first_is_x in [true, false] {
            assert!(!kept_at(first_is_x, &[0xa0], &[0x10], true));
            assert!(!kept_at(first_is_x, &[0x10], &[0xa0], false));
        }
    }
}
