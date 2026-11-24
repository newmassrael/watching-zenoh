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
//!   node with the LOWER zid dialled, lower in the order the build's `link-tie-order` policy
//!   states (zenoh's number by default, or zenoh-pico's byte-by-byte order), which both ends
//!   must state alike.
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
use crate::caps;
use crate::credential_identity::zid_from_wire;
#[cfg(feature = "alloc")]
use crate::credential_identity::{canonical_zid, CREDENTIAL_ZID_BYTES};
#[cfg(feature = "alloc")]
use crate::limit_binding::Quota;
#[cfg(feature = "alloc")]
use crate::limits::SessionLimits;
use crate::policy::LinkTieOrder;

/// What a session does with a link to a node it already holds a link to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondLink {
    /// Close the new link: the held one stays.
    Refuse,
    /// Close the held link: the new one takes its place.
    Replace,
}

/// A zid as the key the build's `link-tie-order` policy orders it by, so that two nodes that state
/// the same value read the same order of two zids. An id that spells no zid reads as 0.
///
/// The zid is first written in its sixteen-byte form, the wire's bytes followed by the zeros the
/// wire trimmed ([`zid_from_wire`]). `zid-number` reads those bytes as zenoh's number, the first
/// the least significant; `zid-bytes` reads them as a number whose first byte is the MOST
/// significant, which is the order of a byte-by-byte comparison from the first byte.
fn zid_order_key(order: LinkTieOrder, zid: &[u8]) -> u128 {
    zid_from_wire(zid).map_or(0, |bytes| match order {
        LinkTieOrder::ZidNumber => u128::from_le_bytes(bytes),
        LinkTieOrder::ZidBytes => u128::from_be_bytes(bytes),
    })
}

/// The fate of a NEW link to a node the session already holds a link to, the zids ordered by
/// `order`, the `link-tie-order` policy of the node's snapshot.
///
/// `held_dialled` and `new_dialled` say whether this session dialled each link (as opposed to
/// taking it off its port); `local_zid` is this session's own zid and `remote_zid` the node's.
/// The caller has established that both links reach `remote_zid`. A node's own tables order the
/// zids by the snapshot they were built with (`LinkBook::with_order`, the heap profile's).
pub fn judge_second_link_by(
    order: LinkTieOrder,
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
    let dialled_wins = zid_order_key(order, local_zid) < zid_order_key(order, remote_zid);
    if new_dialled == dialled_wins {
        SecondLink::Replace
    } else {
        SecondLink::Refuse
    }
}

/// The node's say, DURING a link's handshake, on whether the link may become a face.
///
/// [`judge_second_link_by`] decides which of two links to one node is kept. WHEN it is asked
/// decides what the application sees. Asked after both ends of a link have completed the
/// handshake, each end admits the link that came up first on its side, exchanges declarations
/// over it, and only then, when the rival comes up, closes the one the zid rule rejects: the
/// declarations that crossed the closed link were delivered and are delivered again over the kept
/// one.
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
/// What an implementation decides, with the rule above, is [`judge_second_link_by`]'s for two
/// links still in the handshake and the established one's for a link that has come up: a link
/// that has is kept, as BGP keeps its Established one, which both ends read alike once both have
/// it.
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
    /// refused can still say of the node it was refused for. Held in place, so that asking takes
    /// no memory after the session opened; bytes that spell no zid name no node.
    node: Option<crate::session_zid::SessionZid>,
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
        self.node = crate::session_zid::SessionZid::new(remote_zid).ok();
        self.authority.reserve(self.token, remote_zid)
    }

    /// The node the authority was last asked about ([`Self::reserve`]), or `None` before it was
    /// and for bytes that spell no zid.
    pub fn node(&self) -> Option<crate::session_zid::SessionZid> {
        self.node
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
    /// The token [`LinkBook::open`] gave the link.
    token: u64,
    /// Whether this node dialled the link.
    dialled: bool,
    /// The remote's zid as [`row_key`] keys it, once the handshake has named it and the link was
    /// admitted.
    zid: Option<[u8; CREDENTIAL_ZID_BYTES]>,
    state: LinkState,
}

/// The key every spelling of one zid shares in a [`LinkBook`]: its bytes up to the last that is
/// not zero ([`canonical_zid`]), padded with zeros to sixteen, so that a row holds it in place and
/// two keys are equal exactly when the zids are. `None` for bytes still longer than sixteen once
/// trimmed, which no handshake carries: its zid field is one to sixteen bytes.
#[cfg(feature = "alloc")]
fn row_key(zid: &[u8]) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
    let canonical = canonical_zid(zid);
    if canonical.len() > CREDENTIAL_ZID_BYTES {
        return None;
    }
    let mut key = [0u8; CREDENTIAL_ZID_BYTES];
    for (into, byte) in key.iter_mut().zip(canonical) {
        *into = *byte;
    }
    Some(key)
}

/// The token [`LinkBook::open`] gives a link it has no row for: the table is full. Never the
/// token of a row, as the tokens of rows start at 1 and skip it when they wrap.
#[cfg(feature = "alloc")]
const NO_ROW: u64 = 0;

/// The links a node whose sessions hold `limits` keeps in its [`LinkBook`] at once, the rows
/// the table reserves when it is made: the link it dials, each face `MAX_FACES` admits besides,
/// and each link `MAX_ACCEPT_PENDING` admits in its handshake (zenoh's
/// `transport/unicast/max_sessions` and `accept_pending`). A bound the snapshot leaves open,
/// which a heap build's defaults do, counts as the build's value of it ([`caps`]).
#[cfg(feature = "alloc")]
pub fn admitted_links(limits: &SessionLimits) -> usize {
    let held = |quota: Quota, build: usize| quota.most().unwrap_or(build);
    held(limits.max_faces(), caps::MAX_FACES)
        .saturating_add(held(limits.max_accept_pending(), caps::MAX_ACCEPT_PENDING))
        .saturating_add(1)
}

/// What `rival` says of the link `token`, `dialled` or not, being admitted to the node keyed
/// `key` (spelled `remote_zid`) by the node `local_zid` that orders zids by `order`: `None`
/// when it is no rival of the link (the link itself, one superseded, or one to another node).
#[cfg(feature = "alloc")]
fn rival_says(
    order: LinkTieOrder,
    local_zid: &[u8],
    rival: &LinkRow,
    token: u64,
    dialled: bool,
    key: &[u8; CREDENTIAL_ZID_BYTES],
    remote_zid: &[u8],
) -> Option<SecondLink> {
    if rival.token == token || rival.zid.as_ref() != Some(key) {
        return None;
    }
    match rival.state {
        LinkState::Superseded => None,
        LinkState::Established => Some(SecondLink::Refuse),
        LinkState::Handshaking if rival.dialled == dialled => Some(SecondLink::Refuse),
        LinkState::Handshaking => Some(judge_second_link_by(
            order,
            rival.dialled,
            dialled,
            local_zid,
            remote_zid,
        )),
    }
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
///   rule reads only what both ends read alike, the zids ([`judge_second_link_by`]): the link the
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
///
/// # Its rows
///
/// The table reserves its rows when it is made, as many as the node may hold links at once
/// ([`admitted_links`], or the engine's own count of its links), and takes no memory after:
/// a link is admitted, superseded and let go in rows that never move. A link opened while every
/// row is held has none, and is refused when it asks, as a link past the node's faces is.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct LinkBook {
    /// The node's own zid in its sixteen-byte form, zeros for bytes that spell none: either
    /// orders as the bytes it was made of do (`zid_order_key`).
    local_zid: [u8; CREDENTIAL_ZID_BYTES],
    /// How two zids are ordered when two links in their handshakes cross: the node's
    /// `link-tie-order`, fixed when the table is made.
    order: LinkTieOrder,
    next_token: u64,
    /// The rows the table was made with: `links` never holds more, so it never grows.
    rows: usize,
    links: Vec<LinkRow>,
}

#[cfg(feature = "alloc")]
impl LinkBook {
    /// The table of the node `local_zid`, whose two crossing links are judged by `order`, the
    /// `link-tie-order` of the node's snapshot, with a row reserved for each of the `rows` links
    /// the node may hold at once.
    pub fn with_order(local_zid: &[u8], order: LinkTieOrder, rows: usize) -> Self {
        Self {
            local_zid: zid_from_wire(local_zid).unwrap_or([0; CREDENTIAL_ZID_BYTES]),
            order,
            next_token: 1,
            rows,
            links: Vec::with_capacity(rows),
        }
    }

    /// See [`LinkAdmission::open`]. A link opened while every row is held is given a token of no
    /// row, which [`Self::reserve`] and [`Self::confirm`] refuse.
    pub fn open(&mut self, dialled: bool) -> u64 {
        if self.links.len() >= self.rows {
            return NO_ROW;
        }
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1).max(1);
        self.links.push(LinkRow {
            token,
            dialled,
            zid: None,
            state: LinkState::Handshaking,
        });
        token
    }

    /// The row of the link `token`.
    fn row_mut(&mut self, token: u64) -> Option<&mut LinkRow> {
        self.links.iter_mut().find(|link| link.token == token)
    }

    /// See [`LinkAdmission::reserve`].
    pub fn reserve(&mut self, token: u64, remote_zid: &[u8]) -> bool {
        // A link with no row has no place to hold a node in.
        if token == NO_ROW {
            return false;
        }
        // A link that names no node cannot collide with another.
        if remote_zid.is_empty() {
            return true;
        }
        let Some(dialled) = self
            .links
            .iter()
            .find(|link| link.token == token)
            .map(|link| link.dialled)
        else {
            return true;
        };
        let Some(key) = row_key(remote_zid) else {
            return true;
        };
        let (order, local_zid) = (self.order, self.local_zid);
        let says = |rival: &LinkRow| {
            rival_says(order, &local_zid, rival, token, dialled, &key, remote_zid)
        };
        // Every rival is read before any is superseded: a link that is refused changes nothing.
        if self
            .links
            .iter()
            .any(|rival| says(rival) == Some(SecondLink::Refuse))
        {
            return false;
        }
        for rival in self.links.iter_mut() {
            if says(rival) == Some(SecondLink::Replace) {
                rival.state = LinkState::Superseded;
            }
        }
        if let Some(link) = self.row_mut(token) {
            link.zid = Some(key);
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
        if token == NO_ROW {
            return false;
        }
        match self.row_mut(token) {
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
        if let Some(at) = self.links.iter().position(|link| link.token == token) {
            self.links.swap_remove(at);
        }
    }

    /// How many links the table holds, in every state.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Whether the table holds no link.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// How many links the table holds at most: the rows it was made with.
    pub fn rows(&self) -> usize {
        self.rows
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
    /// The admission of the node `local_zid`, judging crossing links by `order`, the
    /// `link-tie-order` of the node's snapshot, with a row reserved for each of the `rows` links
    /// the node may hold at once ([`LinkBook::with_order`]).
    pub fn with_order(local_zid: &[u8], order: LinkTieOrder, rows: usize) -> Self {
        Self {
            book: R::new_mutex(LinkBook::with_order(local_zid, order, rows)),
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
    use crate::policy::SessionPolicy;

    /// The order of the build defaults, which is what a node that selected none judges by.
    const DEFAULT_ORDER: LinkTieOrder = SessionPolicy::defaults().link_tie_order();

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
        match judge_second_link_by(DEFAULT_ORDER, held_dialled, new_dialled, local, remote) {
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
                    judge_second_link_by(DEFAULT_ORDER, dialled, dialled, &local, &remote),
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

    /// Two zids the two orders rank oppositely: `[0x01, 0x02]` is the number 0x0201 and `[0x02]`
    /// the number 0x02, so by number the second is lower, but byte by byte the first is (0x01 <
    /// 0x02 at the first byte). The second spelling is trimmed, as the wire trims trailing zeros.
    const BY_NUMBER_HIGHER: &[u8] = &[0x01, 0x02];
    const BY_NUMBER_LOWER: &[u8] = &[0x02];

    /// Whether the node `local` keeps the link it dialled when `remote` dialled it at the same
    /// moment, the dialled link being the held one.
    fn keeps_its_own_dial(order: LinkTieOrder, local: &[u8], remote: &[u8]) -> bool {
        judge_second_link_by(order, true, false, local, remote) == SecondLink::Refuse
    }

    #[test]
    fn zid_number_keeps_the_link_of_the_zid_that_is_the_lower_number() {
        let order = LinkTieOrder::ZidNumber;
        assert_eq!(order.id(), "zid-number");
        assert!(keeps_its_own_dial(order, BY_NUMBER_LOWER, BY_NUMBER_HIGHER));
        assert!(!keeps_its_own_dial(
            order,
            BY_NUMBER_HIGHER,
            BY_NUMBER_LOWER
        ));
    }

    #[test]
    fn zid_bytes_keeps_the_link_of_the_zid_that_is_lower_from_the_first_byte() {
        let order = LinkTieOrder::ZidBytes;
        assert_eq!(order.id(), "zid-bytes");
        assert!(keeps_its_own_dial(order, BY_NUMBER_HIGHER, BY_NUMBER_LOWER));
        assert!(!keeps_its_own_dial(
            order,
            BY_NUMBER_LOWER,
            BY_NUMBER_HIGHER
        ));
    }

    #[test]
    fn each_order_has_both_ends_keep_one_link_and_the_two_orders_keep_different_ones() {
        for order in [LinkTieOrder::ZidNumber, LinkTieOrder::ZidBytes] {
            // Exactly one of the two nodes keeps the link it dialled: one link survives.
            let a = keeps_its_own_dial(order, BY_NUMBER_HIGHER, BY_NUMBER_LOWER);
            let b = keeps_its_own_dial(order, BY_NUMBER_LOWER, BY_NUMBER_HIGHER);
            assert_ne!(
                a,
                b,
                "{}: both ends must name the same one link",
                order.id()
            );
        }
        // Two ends stating different orders each keep their own dial: each closes the link the
        // other kept, and neither link survives. This is why both ends must state one value.
        let a_by_bytes =
            keeps_its_own_dial(LinkTieOrder::ZidBytes, BY_NUMBER_HIGHER, BY_NUMBER_LOWER);
        let b_by_number =
            keeps_its_own_dial(LinkTieOrder::ZidNumber, BY_NUMBER_LOWER, BY_NUMBER_HIGHER);
        assert!(a_by_bytes && b_by_number);
    }
}

/// The table's own rules, one node's table at a time, and the two nodes' tables together over every
/// order their handshakes can interleave in.
#[cfg(all(test, feature = "alloc"))]
mod book_tests {
    use super::*;
    use crate::policy::SessionPolicy;

    const LOW: [u8; 2] = [0x01, 0x00];
    const HIGH: [u8; 2] = [0x02, 0x00];

    /// The rows a test's table reserves: more than any test below holds at once.
    const ROWS: usize = 8;

    /// The table of the node `local_zid` under the order of the build defaults, which is what a
    /// node that selected none holds.
    fn book(local_zid: &[u8]) -> LinkBook {
        LinkBook::with_order(local_zid, SessionPolicy::defaults().link_tie_order(), ROWS)
    }

    #[test]
    fn a_link_with_no_rival_is_admitted_and_confirmed() {
        let mut node = book(&LOW);
        let link = node.open(true);
        assert!(node.reserve(link, &HIGH));
        assert!(node.confirm(link));
    }

    #[test]
    fn a_link_that_names_no_node_is_admitted() {
        let mut node = book(&LOW);
        let link = node.open(false);
        assert!(node.reserve(link, &[]));
        assert!(node.confirm(link));
    }

    #[test]
    fn an_established_link_keeps_its_place_whichever_way_the_new_one_went() {
        for new_dialled in [true, false] {
            for held_dialled in [true, false] {
                let mut node = book(&LOW);
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
            let mut node = book(&LOW);
            let first = node.open(dialled);
            assert!(node.reserve(first, &HIGH));
            let second = node.open(dialled);
            assert!(!node.reserve(second, &HIGH));
            assert!(node.confirm(first), "the first is not disturbed");
        }
    }

    /// A table judges two crossing links by the order it was built with, not the build's: the
    /// two zids below are ranked oppositely by the two orders, so the same crossing keeps this
    /// node's own dial under one and the inbound link under the other.
    #[test]
    fn a_table_judges_crossing_links_by_the_order_it_was_built_with() {
        // By number `[0x01, 0x02]` is 0x0201 and `[0x02]` is 0x02; byte by byte the first is
        // lower.
        const LOCAL: &[u8] = &[0x01, 0x02];
        const REMOTE: &[u8] = &[0x02];
        let crossing = |order: LinkTieOrder| {
            let mut node = LinkBook::with_order(LOCAL, order, ROWS);
            let own_dial = node.open(true);
            assert!(node.reserve(own_dial, REMOTE));
            let inbound = node.open(false);
            let inbound_admitted = node.reserve(inbound, REMOTE);
            let own_dial_confirmed = node.confirm(own_dial);
            assert_ne!(
                inbound_admitted,
                own_dial_confirmed,
                "{}: exactly one of the two links survives",
                order.id()
            );
            own_dial_confirmed
        };
        assert!(
            crossing(LinkTieOrder::ZidBytes),
            "byte by byte this node is the lower: its own dial is kept"
        );
        assert!(
            !crossing(LinkTieOrder::ZidNumber),
            "by number this node is the higher: the inbound link is kept"
        );
    }

    #[test]
    fn the_link_the_lower_zid_dialled_supersedes_one_in_handshake_that_the_higher_dialled() {
        // This node is the lower: its own dial is the one to keep.
        let mut node = book(&LOW);
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
        let mut node = book(&HIGH);
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
        let mut node = book(&LOW);
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
        let mut node = book(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &[0x02]));
        let new = node.open(false);
        assert!(!node.reserve(new, &[0x02, 0x00, 0x00]));
    }

    /// A row keys a zid by its bytes once trimmed, so a spelling padded past sixteen bytes is the
    /// node it spells. Turned red by a key that refuses the length before it trims.
    #[test]
    fn a_zid_padded_past_sixteen_bytes_is_still_the_node_it_spells() {
        let mut node = book(&LOW);
        let held = node.open(false);
        assert!(node.reserve(held, &[0x02]));
        let mut padded = [0u8; 20];
        padded[0] = 0x02;
        let new = node.open(false);
        assert!(
            !node.reserve(new, &padded),
            "the padded spelling names the node the held link reaches"
        );
    }

    /// A link opened while every row is held is refused when it asks, at its reservation and its
    /// confirmation, and holds no row; a row let go is taken by the next link. Turned red by an
    /// `open` that gives a link past the rows a row of its own.
    #[test]
    fn a_link_past_the_rows_is_refused_and_a_row_let_go_is_taken_again() {
        let mut node = LinkBook::with_order(&LOW, SessionPolicy::defaults().link_tie_order(), 2);
        assert_eq!(node.rows(), 2);
        let first = node.open(false);
        let second = node.open(true);
        let past = node.open(false);
        assert!(
            !node.reserve(past, &[0x03]),
            "a link with no row is refused, to a node no other link reaches"
        );
        assert!(!node.confirm(past), "and is refused its confirmation");
        assert_eq!(node.len(), 2, "the refused link holds no row");
        node.release(past);
        assert_eq!(node.len(), 2, "letting go of it lets go of no row");
        assert!(
            node.reserve(first, &HIGH),
            "the links with rows are judged as before"
        );
        node.release(second);
        let again = node.open(false);
        assert!(
            node.reserve(again, &[0x03]),
            "the row the second link let go is the next link's"
        );
    }

    /// The table reserves its rows when it is made and never grows past them, however often its
    /// links come and go and however many more are opened. Turned red by a table that takes a row
    /// past the ones it was made with, which grows its storage.
    #[test]
    fn the_rows_are_reserved_when_the_table_is_made_and_never_grow() {
        let mut node = book(&LOW);
        let reserved = node.links.capacity();
        assert!(reserved >= ROWS, "the rows are reserved up front");
        for _ in 0..3 {
            let tokens: Vec<u64> = (0..ROWS + 2).map(|at| node.open(at % 2 == 0)).collect();
            for (at, token) in tokens.iter().enumerate() {
                let zid = [u8::try_from(at + 1).expect("a few links"), 0x10];
                node.reserve(*token, &zid);
            }
            assert_eq!(node.len(), ROWS, "the links past the rows hold none");
            assert_eq!(node.links.capacity(), reserved, "the storage never grew");
            for token in tokens {
                node.release(token);
            }
            assert!(node.is_empty());
        }
    }

    /// A node reserves a row for the link it dials, each face its sessions' `MAX_FACES` admits
    /// and each handshake their `MAX_ACCEPT_PENDING` admits; a bound left open counts as the
    /// build's value. Turned red by a count that leaves out any of the three.
    #[test]
    fn a_node_reserves_its_dial_its_faces_and_its_handshakes() {
        use crate::limits::SessionLimits;

        let mut limits = SessionLimits::defaults();
        if limits.select_max_faces(Quota::at_most(3)).is_ok()
            && limits.select_max_accept_pending(Quota::at_most(2)).is_ok()
        {
            assert_eq!(admitted_links(&limits), 1 + 3 + 2);
        }
        let mut open = SessionLimits::defaults();
        if open.select_max_faces(Quota::UNBOUNDED).is_ok()
            && open.select_max_accept_pending(Quota::at_most(2)).is_ok()
        {
            assert_eq!(admitted_links(&open), 1 + caps::MAX_FACES + 2);
        }
        assert!(
            admitted_links(&SessionLimits::BUILD) >= 1,
            "the dial has its row whatever the faces"
        );
    }

    /// An admission that refuses every link it is asked about.
    #[cfg(target_has_atomic = "ptr")]
    struct RefusesEverything;

    #[cfg(target_has_atomic = "ptr")]
    impl LinkAdmission for RefusesEverything {
        fn open(&self, _dialled: bool) -> u64 {
            1
        }

        fn reserve(&self, _token: u64, _remote_zid: &[u8]) -> bool {
            false
        }

        fn confirm(&self, _token: u64) -> bool {
            false
        }

        fn release(&self, _token: u64) {}
    }

    /// A lease names the node it was last asked about, refused or not, as the zid it spells, and
    /// no node for bytes that spell none. Turned red by a lease that forgets a refused node, or
    /// names one for bytes of zeros.
    #[cfg(target_has_atomic = "ptr")]
    #[test]
    fn a_lease_names_the_node_it_was_refused_for_and_none_for_bytes_that_spell_none() {
        use crate::session_zid::SessionZid;

        let mut lease = LinkLease::new(alloc::sync::Arc::new(RefusesEverything), true);
        assert_eq!(lease.node(), None, "no node before the question");
        assert!(!lease.reserve(&HIGH));
        assert_eq!(lease.node(), SessionZid::new(&HIGH).ok());
        assert!(!lease.reserve(&[0x00, 0x00]));
        assert_eq!(lease.node(), None, "bytes of zeros name no node");
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
            let mut a = book(&a_zid);
            let mut b = book(&b_zid);
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
