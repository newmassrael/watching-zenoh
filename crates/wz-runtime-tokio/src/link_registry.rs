// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node's links to each remote node, from the moment the handshake names the remote until the
//! link is gone: the table behind [`wz_session_core::link_admission::LinkAdmission`].
//!
//! A node that listens and dials meets a node that does the same twice at once: it dials the
//! node it scouted while the node dials it. Two links to one node would deliver every
//! declaration and sample twice, so one is kept. Which one, and WHEN it is decided, is the
//! subject of this table.
//!
//! # The rule
//!
//! For the link being admitted, the other links to the same node that are still alive:
//!
//! - One that is already ESTABLISHED keeps its place and the new link is refused, as a BGP
//!   session that is Established is not replaced by a connection that collides with it
//!   (RFC 4271 section 6.8) and as upstream's transport manager refuses a second link to a held node
//!   (`io/zenoh-transport/src/unicast/manager.rs` @ `init_existing_transport_unicast`).
//! - One that is still in its HANDSHAKE and went the same way as the new link keeps its place:
//!   the first reservation is kept.
//! - One that is still in its handshake and went the other way is two nodes that dialled each
//!   other at the same moment. Each end sees the two reservations in an order of its own, so the
//!   rule reads only what both ends read alike, the zids
//!   ([`wz_session_core::link_admission::judge_second_link`]): the link the lower zid dialled is
//!   kept, and the other is SUPERSEDED, which its initiator learns at [`confirm`] and closes on
//!   before it has declared anything.
//!
//! Only a link whose acceptor admitted it and whose initiator confirmed it carries a declaration
//! in either direction, because the acceptor answers the OpenSyn it admitted and the initiator
//! sends nothing before the OpenAck it took. A link that either end refused therefore carries
//! none, which is why two nodes that dial each other at once end with one link and the
//! application of neither sees a declaration twice.
//!
//! The acceptor's reservation is its admission: it sends the OpenAck next, and its link is
//! established from then on. The initiator's reservation (at the InitAck) is a claim that the
//! rival acceptor of the same node respects, and it is established at [`confirm`].
//!
//! [`confirm`]: LinkAdmission::confirm

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use wz_session_core::link_admission::{judge_second_link, LinkAdmission, SecondLink};

/// Where a link is in its life with the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Its handshake is running and the node has not yet been asked to let it through.
    Handshaking,
    /// Its handshake is through at this end: it is the node's link to its remote.
    Established,
    /// A link the rule prefers was admitted while this one was in its handshake, so this one
    /// ends when its initiator asks to confirm.
    Superseded,
}

/// One link's row.
#[derive(Debug)]
struct Link {
    /// Whether this node dialled the link.
    dialled: bool,
    /// The remote's zid, once the handshake has named it and the link was admitted.
    zid: Option<Vec<u8>>,
    state: State,
}

/// A node's link admission. One per node, shared by every loop that opens a link of it.
#[derive(Debug)]
pub struct LinkRegistry {
    local_zid: Vec<u8>,
    next_token: AtomicU64,
    links: Mutex<BTreeMap<u64, Link>>,
}

impl LinkRegistry {
    /// The admission of the node `local_zid`.
    pub fn new(local_zid: &[u8]) -> Self {
        Self {
            local_zid: local_zid.to_vec(),
            next_token: AtomicU64::new(1),
            links: Mutex::new(BTreeMap::new()),
        }
    }

    /// The table, poison-tolerant: a panic elsewhere cannot leave a `BTreeMap` torn, and a node
    /// that refused every later link because of it would be a worse failure.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Link>> {
        self.links
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many links the table holds (every state), for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

impl LinkAdmission for LinkRegistry {
    fn open(&self, dialled: bool) -> u64 {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(
            token,
            Link {
                dialled,
                zid: None,
                state: State::Handshaking,
            },
        );
        token
    }

    fn reserve(&self, token: u64, remote_zid: &[u8]) -> bool {
        // A link that names no node cannot collide with another.
        if remote_zid.is_empty() {
            return true;
        }
        let mut links = self.lock();
        let Some(dialled) = links.get(&token).map(|link| link.dialled) else {
            return true;
        };
        // Every rival is read before any is superseded: a link that is refused changes nothing.
        let mut superseded = Vec::new();
        for (rival_token, rival) in links.iter() {
            if *rival_token == token || rival.state == State::Superseded {
                continue;
            }
            let Some(rival_zid) = rival.zid.as_deref() else {
                continue;
            };
            if !crate::zid_hex::same_zid(rival_zid, remote_zid) {
                continue;
            }
            match rival.state {
                State::Established => return false,
                State::Handshaking if rival.dialled == dialled => return false,
                State::Handshaking => {
                    match judge_second_link(rival.dialled, dialled, &self.local_zid, remote_zid) {
                        SecondLink::Refuse => return false,
                        SecondLink::Replace => superseded.push(*rival_token),
                    }
                }
                State::Superseded => {}
            }
        }
        for rival_token in superseded {
            if let Some(rival) = links.get_mut(&rival_token) {
                rival.state = State::Superseded;
            }
        }
        if let Some(link) = links.get_mut(&token) {
            link.zid = Some(remote_zid.to_vec());
            // An acceptor sends its OpenAck next: from here the link is established at its end.
            link.state = if dialled {
                State::Handshaking
            } else {
                State::Established
            };
        }
        true
    }

    fn confirm(&self, token: u64) -> bool {
        let mut links = self.lock();
        match links.get_mut(&token) {
            None => true,
            // A link that was never reserved names no node: nothing to confirm against.
            Some(link) if link.zid.is_none() => true,
            Some(link) if link.state == State::Superseded => false,
            Some(link) => {
                link.state = State::Established;
                true
            }
        }
    }

    fn release(&self, token: u64) {
        self.lock().remove(&token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const LOW: [u8; 2] = [0x01, 0x00];
    const HIGH: [u8; 2] = [0x02, 0x00];

    #[test]
    fn a_link_with_no_rival_is_admitted_and_confirmed() {
        let node = LinkRegistry::new(&LOW);
        let link = node.open(true);
        assert!(node.reserve(link, &HIGH));
        assert!(node.confirm(link));
    }

    #[test]
    fn a_link_that_names_no_node_is_admitted() {
        let node = LinkRegistry::new(&LOW);
        let link = node.open(false);
        assert!(node.reserve(link, &[]));
        assert!(node.confirm(link));
    }

    #[test]
    fn an_established_link_keeps_its_place_whichever_way_the_new_one_went() {
        for new_dialled in [true, false] {
            for held_dialled in [true, false] {
                let node = LinkRegistry::new(&LOW);
                let held = node.open(held_dialled);
                assert!(node.reserve(held, &HIGH));
                assert!(node.confirm(held));
                let new = node.open(new_dialled);
                assert!(
                    !node.reserve(new, &HIGH),
                    "held dialled={held_dialled}, new dialled={new_dialled}: the established link stays"
                );
            }
        }
    }

    #[test]
    fn two_links_in_handshake_that_went_the_same_way_keep_the_first() {
        for dialled in [true, false] {
            let node = LinkRegistry::new(&LOW);
            let first = node.open(dialled);
            assert!(node.reserve(first, &HIGH));
            let second = node.open(dialled);
            assert!(!node.reserve(second, &HIGH));
            assert!(node.confirm(first), "the first is not disturbed");
        }
    }

    #[test]
    fn the_link_the_lower_zid_dialled_supersedes_one_in_handshake_that_the_higher_dialled() {
        // This node is the lower: its own dial is the one to keep.
        let node = LinkRegistry::new(&LOW);
        let taken_off_the_port = node.open(false);
        // An acceptor's reservation is established at once, so make the held link the
        // initiator's: this node dialled `held` and the node it dialled dialled it back.
        let held = node.open(true);
        assert!(node.reserve(held, &HIGH));
        assert!(
            !node.reserve(taken_off_the_port, &HIGH),
            "the lower node's own dial is the link to keep, the inbound one is refused"
        );
        assert!(node.confirm(held));

        // This node is the higher: the inbound link, which the lower dialled, wins.
        let node = LinkRegistry::new(&HIGH);
        let held = node.open(true);
        assert!(node.reserve(held, &LOW));
        let inbound = node.open(false);
        assert!(
            node.reserve(inbound, &LOW),
            "the link the lower zid dialled is admitted over this node's own dial"
        );
        assert!(
            !node.confirm(held),
            "and the dial it superseded is refused when its OpenAck is about to be taken"
        );
    }

    #[test]
    fn a_released_link_leaves_room() {
        let node = LinkRegistry::new(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &HIGH));
        let new = node.open(true);
        assert!(!node.reserve(new, &HIGH));
        node.release(held);
        assert!(node.reserve(new, &HIGH));
        node.release(new);
        assert_eq!(node.len(), 0, "both links are gone from the table");
    }

    #[test]
    fn a_zid_is_the_same_node_trimmed_or_padded() {
        let node = LinkRegistry::new(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &[0x02]));
        let new = node.open(false);
        assert!(!node.reserve(new, &[0x02, 0x00, 0x00]));
    }

    /// A step of the two links' handshakes, `(link, node, what)`: link 0 is dialled by A and
    /// accepted by B, link 1 is dialled by B and accepted by A.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// The initiator reserves at the InitAck.
        InitiatorReserve(usize),
        /// The acceptor reserves at the OpenSyn.
        AcceptorReserve(usize),
        /// The initiator confirms before it takes the OpenAck.
        InitiatorConfirm(usize),
    }

    /// Every order in which the six steps can happen, each link's three in the order of its
    /// handshake: the OpenSyn is sent after the initiator's InitAck reservation and the OpenAck
    /// after the acceptor's.
    fn interleavings() -> Vec<Vec<Step>> {
        fn go(next: [usize; 2], done: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
            if next == [3, 3] {
                out.push(done.clone());
                return;
            }
            for link in 0..2 {
                let step = match next[link] {
                    0 => Step::InitiatorReserve(link),
                    1 => Step::AcceptorReserve(link),
                    2 => Step::InitiatorConfirm(link),
                    _ => continue,
                };
                let mut advanced = next;
                advanced[link] += 1;
                done.push(step);
                go(advanced, done, out);
                done.pop();
            }
        }
        let mut out = Vec::new();
        go([0, 0], &mut Vec::new(), &mut out);
        out
    }

    /// Two nodes that dial each other at the same moment end with exactly one link that both
    /// ends took up, whatever the order their handshakes interleave in, and no link that one end
    /// took up is closed by the other after it carried a declaration.
    #[test]
    fn two_nodes_that_dial_each_other_at_once_end_with_one_link() {
        let mut orders = 0;
        for order in interleavings() {
            orders += 1;
            let a_zid = LOW;
            let b_zid = HIGH;
            let a = Arc::new(LinkRegistry::new(&a_zid));
            let b = Arc::new(LinkRegistry::new(&b_zid));
            // link 0: A initiates, B accepts. link 1: B initiates, A accepts.
            let tokens = [(a.open(true), b.open(false)), (a.open(false), b.open(true))];
            // A link that either end refused takes no further step.
            let mut dead = [false, false];
            // The links each end confirmed or admitted as acceptor: what carries declarations.
            let mut carried = [false, false];
            for step in &order {
                match *step {
                    Step::InitiatorReserve(link) if !dead[link] => {
                        let (node, remote, token) = if link == 0 {
                            (&a, &b_zid, tokens[0].0)
                        } else {
                            (&b, &a_zid, tokens[1].1)
                        };
                        dead[link] = !node.reserve(token, remote);
                    }
                    Step::AcceptorReserve(link) if !dead[link] => {
                        let (node, remote, token) = if link == 0 {
                            (&b, &a_zid, tokens[0].1)
                        } else {
                            (&a, &b_zid, tokens[1].0)
                        };
                        dead[link] = !node.reserve(token, remote);
                    }
                    Step::InitiatorConfirm(link) if !dead[link] => {
                        let (node, token) = if link == 0 {
                            (&a, tokens[0].0)
                        } else {
                            (&b, tokens[1].1)
                        };
                        if node.confirm(token) {
                            carried[link] = true;
                        } else {
                            dead[link] = true;
                        }
                    }
                    _ => {}
                }
            }
            let up = carried.iter().filter(|up| **up).count();
            assert_eq!(
                up, 1,
                "order {order:?}: {up} links carried declarations (dead {dead:?})"
            );
        }
        assert_eq!(
            orders, 20,
            "six steps in two chains of three: C(6,3) orders"
        );
    }
}
