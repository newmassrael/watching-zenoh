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
//! rule. The rule is ungated, because it allocates nothing; `LinkAdmission`, which asks it while
//! a link is still being established, is the heap profile's and so is not linked from here: a
//! build without a heap has no such item for a link to name.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use wz_runtime_core::Runtime;

#[cfg(feature = "alloc")]
use crate::credential_identity::canonical_zid;
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

/// The node's say, DURING a link's handshake, on whether the link may become a face.
///
/// [`judge_second_link`] decides which of two links to one node is kept. WHEN it is asked decides
/// what the application sees. Asked after both ends of a link have completed the handshake, each
/// end admits the link that came up first on its side, exchanges declarations over it, and only
/// then, when the rival comes up, closes the one the zid rule rejects: the declarations that crossed
/// the closed link were delivered and are delivered again over the kept one.
///
/// Upstream asks while the link is still being established, and so does this: the acceptor before
/// it sends the OpenAck, the initiator before it sends the OpenSyn and again before it takes the
/// OpenAck (`io/zenoh-transport/src/unicast/manager.rs` @ `init_transport_unicast`). A link that a
/// node refuses then carries nothing in either direction, because the acceptor that admitted it
/// is answered by an initiator that closes before it declares anything. The same shape as a BGP
/// session's collision detection, which is resolved before the session is Established
/// (RFC 4271 section 6.8), and as a TCP simultaneous open, which is merged before the connection is.
///
/// One value is held for each link, through its [`LinkLease`], and it asks four things in the order
/// of the handshake:
///
/// 1. [`LinkAdmission::open`]: a link of this direction exists (before any zid is known).
/// 2. [`LinkAdmission::reserve`]: the zid of the node on the other end is known (the initiator at
///    the InitAck, the acceptor at the OpenSyn). `false` closes the link.
/// 3. [`LinkAdmission::confirm`]: the initiator is about to take the OpenAck. `false` closes the
///    link, which a rival that the rule prefers has superseded since the reservation. The acceptor
///    has nothing to confirm: its reservation is its admission.
/// 4. [`LinkAdmission::release`]: the link is gone, or never got further than it did.
///
/// What an implementation decides, with the rule above, is [`judge_second_link`]'s for two links
/// still in the handshake and the established one's for a link that has come up: a link that has
/// is kept, as BGP keeps its Established one, which both ends read alike once both have it.
#[cfg(feature = "alloc")]
pub trait LinkAdmission: Send + Sync {
    /// A link `dialled` (or taken off a port) begins its handshake. The token names it in the
    /// calls below.
    fn open(&self, dialled: bool) -> u64;
    /// The link `token` learned the zid of its remote. `true` admits it to the node.
    fn reserve(&self, token: u64, remote_zid: &[u8]) -> bool;
    /// The initiator of the link `token` is about to take the OpenAck. `true` lets it.
    fn confirm(&self, token: u64) -> bool;
    /// The link `token` is gone. Harmless for a token that holds nothing.
    fn release(&self, token: u64);
}

/// A link's place in a node's [`LinkAdmission`], released when the link's session is dropped.
///
/// A node shares its admission among the links it holds as an `alloc::sync::Arc`, which a target
/// without atomics (ARMv6-M) has no type for: such a target holds at most the link its single
/// task drives, has no second link to admit, and has no lease either. An `Rc` is not the
/// answer: the session a link belongs to is `Send`, and a lease inside it must be too.
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
pub struct LinkLease {
    authority: alloc::sync::Arc<dyn LinkAdmission>,
    token: u64,
    /// The node the authority was last asked about, whatever it answered: what a link that was
    /// refused can still say of the node it was refused for.
    node: Option<Vec<u8>>,
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl LinkLease {
    /// The lease of a link `dialled` (or not), opened with `authority`.
    pub fn new(authority: alloc::sync::Arc<dyn LinkAdmission>, dialled: bool) -> Self {
        let token = authority.open(dialled);
        Self {
            authority,
            token,
            node: None,
        }
    }

    /// See [`LinkAdmission::reserve`]. The node is kept, admitted or not.
    pub fn reserve(&mut self, remote_zid: &[u8]) -> bool {
        self.node = Some(remote_zid.to_vec());
        self.authority.reserve(self.token, remote_zid)
    }

    /// The node the authority was last asked about ([`Self::reserve`]), or `None` before it was.
    pub fn node(&self) -> Option<&[u8]> {
        self.node.as_deref()
    }

    /// See [`LinkAdmission::confirm`].
    pub fn confirm(&self) -> bool {
        self.authority.confirm(self.token)
    }

    /// See [`LinkAdmission::release`]. Called by the node when the link's face leaves, and by the
    /// drop of the lease when the session goes.
    pub fn release(&self) {
        self.authority.release(self.token);
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl Drop for LinkLease {
    fn drop(&mut self) {
        self.authority.release(self.token);
    }
}

/// Where a link is in its life with the node.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkState {
    /// Its handshake is running and the node has not yet been asked to let it through.
    Handshaking,
    /// Its handshake is through at this end: it is the node's link to its remote.
    Established,
    /// A link the rule prefers was admitted while this one was in its handshake, so this one
    /// ends when its initiator asks to confirm.
    Superseded,
}

/// One link's row in a [`LinkBook`].
#[cfg(feature = "alloc")]
#[derive(Debug)]
struct LinkRow {
    /// Whether this node dialled the link.
    dialled: bool,
    /// The remote's zid, once the handshake has named it and the link was admitted.
    zid: Option<Vec<u8>>,
    state: LinkState,
}

/// A node's links to each remote node, from the moment the handshake names the remote until the
/// link is gone: the table behind [`LinkAdmission`], with no lock and no engine in it.
///
/// A node that listens and dials meets a node that does the same twice at once: it dials the
/// node it scouted while the node dials it. Two links to one node would deliver every
/// declaration and sample twice, so one is kept. Which one, and WHEN it is decided, is the
/// subject of this table, and it is written once here so that every engine that asks it (the
/// tokio runtime's nodes, the cooperative engine's face table) asks the same table.
///
/// # The rule
///
/// For the link being admitted, the other links to the same node that are still alive:
///
/// - One that is already ESTABLISHED keeps its place and the new link is refused, as a BGP
///   session that is Established is not replaced by a connection that collides with it
///   (RFC 4271 section 6.8) and as upstream's transport manager refuses a second link to a held node
///   (`io/zenoh-transport/src/unicast/manager.rs` @ `init_existing_transport_unicast`).
/// - One that is still in its HANDSHAKE and went the same way as the new link keeps its place:
///   the first reservation is kept.
/// - One that is still in its handshake and went the other way is two nodes that dialled each
///   other at the same moment. Each end sees the two reservations in an order of its own, so the
///   rule reads only what both ends read alike, the zids ([`judge_second_link`]): the link the
///   lower zid dialled is kept, and the other is SUPERSEDED, which its initiator learns at
///   [`LinkBook::confirm`] and closes on before it has declared anything.
///
/// Only a link whose acceptor admitted it and whose initiator confirmed it carries a declaration
/// in either direction, because the acceptor answers the OpenSyn it admitted and the initiator
/// sends nothing before the OpenAck it took. A link that either end refused therefore carries
/// none, which is why two nodes that dial each other at once end with one link and the
/// application of neither sees a declaration twice.
///
/// The acceptor's reservation is its admission: it sends the OpenAck next, and its link is
/// established from then on. The initiator's reservation (at the InitAck) is a claim that the
/// rival acceptor of the same node respects, and it is established at [`LinkBook::confirm`].
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct LinkBook {
    local_zid: Vec<u8>,
    next_token: u64,
    links: alloc::collections::BTreeMap<u64, LinkRow>,
}

#[cfg(feature = "alloc")]
impl LinkBook {
    /// The table of the node `local_zid`.
    pub fn new(local_zid: &[u8]) -> Self {
        Self {
            local_zid: local_zid.to_vec(),
            next_token: 1,
            links: alloc::collections::BTreeMap::new(),
        }
    }

    /// See [`LinkAdmission::open`].
    pub fn open(&mut self, dialled: bool) -> u64 {
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.links.insert(
            token,
            LinkRow {
                dialled,
                zid: None,
                state: LinkState::Handshaking,
            },
        );
        token
    }

    /// See [`LinkAdmission::reserve`].
    pub fn reserve(&mut self, token: u64, remote_zid: &[u8]) -> bool {
        // A link that names no node cannot collide with another.
        if remote_zid.is_empty() {
            return true;
        }
        let Some(dialled) = self.links.get(&token).map(|link| link.dialled) else {
            return true;
        };
        // Every rival is read before any is superseded: a link that is refused changes nothing.
        let mut superseded = Vec::new();
        for (rival_token, rival) in self.links.iter() {
            if *rival_token == token || rival.state == LinkState::Superseded {
                continue;
            }
            let Some(rival_zid) = rival.zid.as_deref() else {
                continue;
            };
            if canonical_zid(rival_zid) != canonical_zid(remote_zid) {
                continue;
            }
            match rival.state {
                LinkState::Established => return false,
                LinkState::Handshaking if rival.dialled == dialled => return false,
                LinkState::Handshaking => {
                    match judge_second_link(rival.dialled, dialled, &self.local_zid, remote_zid) {
                        SecondLink::Refuse => return false,
                        SecondLink::Replace => superseded.push(*rival_token),
                    }
                }
                LinkState::Superseded => {}
            }
        }
        for rival_token in superseded {
            if let Some(rival) = self.links.get_mut(&rival_token) {
                rival.state = LinkState::Superseded;
            }
        }
        if let Some(link) = self.links.get_mut(&token) {
            link.zid = Some(remote_zid.to_vec());
            // An acceptor sends its OpenAck next: from here the link is established at its end.
            link.state = if dialled {
                LinkState::Handshaking
            } else {
                LinkState::Established
            };
        }
        true
    }

    /// See [`LinkAdmission::confirm`].
    pub fn confirm(&mut self, token: u64) -> bool {
        match self.links.get_mut(&token) {
            None => true,
            // A link that was never reserved names no node: nothing to confirm against.
            Some(link) if link.zid.is_none() => true,
            Some(link) if link.state == LinkState::Superseded => false,
            Some(link) => {
                link.state = LinkState::Established;
                true
            }
        }
    }

    /// See [`LinkAdmission::release`].
    pub fn release(&mut self, token: u64) {
        self.links.remove(&token);
    }

    /// How many links the table holds, in every state.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Whether the table holds no link.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// A node's [`LinkAdmission`]: a [`LinkBook`] behind the lock the runtime `R` lends the session.
/// One per node, shared as an `Arc` by every loop that opens a link of it.
///
/// The lock is the runtime's own (`Runtime::Mutex`), so the tokio runtime's nodes take a
/// `std::sync::Mutex` and the cooperative engine the cell it lends its sessions, and the table
/// is the same in both.
#[cfg(feature = "alloc")]
pub struct LinkRegistry<R: Runtime> {
    book: R::Mutex<LinkBook>,
}

#[cfg(feature = "alloc")]
impl<R: Runtime> LinkRegistry<R> {
    /// The admission of the node `local_zid`.
    pub fn new(local_zid: &[u8]) -> Self {
        Self {
            book: R::new_mutex(LinkBook::new(local_zid)),
        }
    }

    /// How many links the table holds, in every state.
    pub fn len(&self) -> usize {
        R::with_mutex_mut(&self.book, |book| book.len())
    }

    /// Whether the table holds no link.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(feature = "alloc")]
impl<R: Runtime> core::fmt::Debug for LinkRegistry<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkRegistry")
            .field("links", &self.len())
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl<R: Runtime> LinkAdmission for LinkRegistry<R> {
    fn open(&self, dialled: bool) -> u64 {
        R::with_mutex_mut(&self.book, |book| book.open(dialled))
    }

    fn reserve(&self, token: u64, remote_zid: &[u8]) -> bool {
        R::with_mutex_mut(&self.book, |book| book.reserve(token, remote_zid))
    }

    fn confirm(&self, token: u64) -> bool {
        R::with_mutex_mut(&self.book, |book| book.confirm(token))
    }

    fn release(&self, token: u64) {
        R::with_mutex_mut(&self.book, |book| book.release(token));
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

/// The table's own rules, one node's table at a time, and the two nodes' tables together over every
/// order their handshakes can interleave in.
#[cfg(all(test, feature = "alloc"))]
mod book_tests {
    use super::*;

    const LOW: [u8; 2] = [0x01, 0x00];
    const HIGH: [u8; 2] = [0x02, 0x00];

    #[test]
    fn a_link_with_no_rival_is_admitted_and_confirmed() {
        let mut node = LinkBook::new(&LOW);
        let link = node.open(true);
        assert!(node.reserve(link, &HIGH));
        assert!(node.confirm(link));
    }

    #[test]
    fn a_link_that_names_no_node_is_admitted() {
        let mut node = LinkBook::new(&LOW);
        let link = node.open(false);
        assert!(node.reserve(link, &[]));
        assert!(node.confirm(link));
    }

    #[test]
    fn an_established_link_keeps_its_place_whichever_way_the_new_one_went() {
        for new_dialled in [true, false] {
            for held_dialled in [true, false] {
                let mut node = LinkBook::new(&LOW);
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
            let mut node = LinkBook::new(&LOW);
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
        let mut node = LinkBook::new(&LOW);
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
        let mut node = LinkBook::new(&HIGH);
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
        let mut node = LinkBook::new(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &HIGH));
        let new = node.open(true);
        assert!(!node.reserve(new, &HIGH));
        node.release(held);
        assert!(node.reserve(new, &HIGH));
        node.release(new);
        assert!(node.is_empty(), "both links are gone from the table");
    }

    #[test]
    fn a_zid_is_the_same_node_trimmed_or_padded() {
        let mut node = LinkBook::new(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &[0x02]));
        let new = node.open(false);
        assert!(!node.reserve(new, &[0x02, 0x00, 0x00]));
    }

    /// A step of the two links' handshakes: link 0 is dialled by A and accepted by B, link 1 is
    /// dialled by B and accepted by A.
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
            let mut a = LinkBook::new(&a_zid);
            let mut b = LinkBook::new(&b_zid);
            // link 0: A initiates, B accepts. link 1: B initiates, A accepts.
            let tokens = [(a.open(true), b.open(false)), (a.open(false), b.open(true))];
            // A link that either end refused takes no further step.
            let mut dead = [false, false];
            // The links each end confirmed or admitted as acceptor: what carries declarations.
            let mut carried = [false, false];
            for step in &order {
                match *step {
                    Step::InitiatorReserve(link) if !dead[link] => {
                        dead[link] = if link == 0 {
                            !a.reserve(tokens[0].0, &b_zid)
                        } else {
                            !b.reserve(tokens[1].1, &a_zid)
                        };
                    }
                    Step::AcceptorReserve(link) if !dead[link] => {
                        dead[link] = if link == 0 {
                            !b.reserve(tokens[0].1, &a_zid)
                        } else {
                            !a.reserve(tokens[1].0, &b_zid)
                        };
                    }
                    Step::InitiatorConfirm(link) if !dead[link] => {
                        let confirmed = if link == 0 {
                            a.confirm(tokens[0].0)
                        } else {
                            b.confirm(tokens[1].1)
                        };
                        if confirmed {
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
