// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The gossip plane of a peer: how two nodes that each hold a link to a third come to dial
//! each other.
//!
//! zenoh's peer runs it by default, its config's gossip switch being on, and it is the whole of
//! what introduces peers when multicast scouting reaches nobody: a node that opens a link tells the
//! node at the far end every node it knows and where each can be reached, and passes on what it
//! learns of a neighbour to the others it holds (`zenoh/src/net/protocol/gossip.rs` @
//! `pub(crate) fn add_link(`). A node that learns of a peer it has no link to, and whose role its
//! autoconnect policy admits, dials it (`zenoh/src/net/protocol/gossip.rs` @
//! `if self.autoconnect.should_autoconnect(zid, whatami) {`).
//!
//! The decisions are the graph crate's, which holds them as `LinkstateNetwork` in its
//! single-hop gossip mode, written against that same upstream file: what a new link is told
//! (`build_new_link_bootstrap`), who hears of a link that was added
//! (`link_hears_link_added`), what a received list changes (`ingest_linkstate_list`) and what
//! of it is passed on (`build_reflood_for`). This module is the part around them that is not
//! the graph's: which faces exist and what they are, which roles the node gossips to, and what
//! a learnt node turns into.
//!
//! # Two layers, so the rules can be tested without a socket
//!
//! [`GossipCore`] is pure. It is told that a face came up, went down, or sent a list, and it
//! answers with what to send on which face and which nodes to dial; it does no I/O and holds
//! no lock. [`GossipPlane`] puts a lock around one and posts the dials. A host sends the
//! answered messages on its faces itself, because what a face is differs between hosts and the
//! plane should not know.
//!
//! The demo's `LinkstateForwarder` runs the same graph with the whole routing mesh around it.
//! This is the part of that which a session that routes nothing needs, so a session that only
//! wants to be introduced does not carry the mesh.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::oam::OamOwned;
use wz_codecs::whatami::WhatAmIMatcher;
use wz_routing_graph::{
    AutoConnect, AutoConnectStrategies, LinkId, LinkstateNetwork, WhatAmI, Zid,
};
use wz_runtime_core::TimeSource;
use wz_session_core::extbound::{region_and_bound_of, Bound};
use wz_session_core::link::SessionRuntime;
use wz_session_core::linkstate_oam::{
    build_linkstate_oam_owned, try_parse_linkstate_oam, LinkstateOam,
};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_actions::SessionLinkActions;

use crate::accept_loop::{DialIntent, DialIntentOrigin, DialIntentSender};

/// The roles a node of role `whatami` gossips to: `scouting/gossip/target`'s shipped default
/// (`commons/zenoh-config/src/defaults.rs` @ `pub mod gossip {`), a router or a peer for a
/// router or a peer and nobody for a client.
pub const fn default_target(whatami: WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Router | WhatAmI::Peer => WhatAmIMatcher::empty().router().peer(),
        WhatAmI::Client => WhatAmIMatcher::empty(),
    }
}

/// The roles a node of role `whatami` dials when gossip names them:
/// `scouting/gossip/autoconnect`'s shipped default, which is nobody for a router and every
/// role for a peer or a client. The tie-break under it is `always`.
pub const fn default_autoconnect(whatami: WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Router => WhatAmIMatcher::empty(),
        WhatAmI::Peer | WhatAmI::Client => WhatAmIMatcher::empty().router().peer().client(),
    }
}

/// What the handshake of a face says of the node at its far end: the identity gossip keys the
/// face on, in the forms the wire carried them.
#[derive(Clone, Debug, Default)]
pub struct FaceIdentity {
    /// The far end's zid, as its INIT carried it. `None` for a face the handshake gave none.
    pub zid: Option<Vec<u8>>,
    /// Its role in the 2-bit wire form (0 router, 1 peer, 2 client).
    pub whatami_wire: Option<u8>,
    /// The bound it announced on its Open.
    pub remote_bound: Option<Bound>,
}

impl FaceIdentity {
    /// The identity the session behind `actions` negotiated with its far end.
    pub fn of<R: SessionRuntime, T: TimeSource>(actions: &SessionLinkActions<R, T>) -> Self {
        Self {
            zid: actions.peer_zid(),
            whatami_wire: actions.peer_whatami_wire(),
            remote_bound: actions.peer_remote_bound(),
        }
    }

    /// The role, taking an absent or unknown wire value for a peer, as the routing plane does.
    fn whatami(&self) -> WhatAmI {
        self.whatami_wire
            .and_then(WhatAmI::from_wire)
            .unwrap_or(WhatAmI::Peer)
    }
}

/// One message for a face to send.
#[derive(Debug)]
pub struct Outbound {
    /// The face, by the id the host brought it up under.
    pub face: u64,
    /// The topology message, ready to go out as a network message.
    pub oam: OamOwned,
}

impl Outbound {
    /// The message in the form a session sends.
    pub fn into_message(self) -> NetworkMessage {
        NetworkMessage::Oam(self.oam)
    }
}

/// What the plane answers to one event.
#[derive(Debug, Default)]
pub struct Effects {
    /// Messages to send, each on the face it names. Reliable: topology is control traffic.
    pub sends: Vec<Outbound>,
    /// Nodes the plane learnt of and its policy admits dialling.
    pub dials: Vec<DialIntent>,
}

/// A face the plane knows of.
#[derive(Debug)]
struct Face {
    /// The face's link in the graph: absent for a face that is not a routing neighbour (no zid,
    /// this node's own zid, a client).
    link: Option<LinkId>,
    zid: Option<Zid>,
    whatami: WhatAmI,
}

/// The gossip rules of one node, with no I/O. See the module documentation.
pub struct GossipCore {
    net: LinkstateNetwork,
    /// The roles this node sends topology to.
    target: WhatAmIMatcher,
    /// The roles it dials, and the tie-break under them.
    autoconnect: AutoConnect,
    faces: BTreeMap<u64, Face>,
}

impl GossipCore {
    /// The rules of a node with `self_zid` and role `whatami`, under zenoh's shipped defaults:
    /// gossip single hop, to a router or a peer, dialling any role it learns of.
    ///
    /// `None` when `self_zid` is not a zid the graph can hold (empty, or all zero).
    pub fn new(self_zid: &[u8], whatami: WhatAmI) -> Option<Self> {
        let zid = Zid::try_from(self_zid).ok()?;
        let mut net = LinkstateNetwork::new(zid, whatami);
        // zenoh's peer mode is gossip (`routing.peer.mode` = "peer_to_peer"): the graph's own
        // default is the linkstate mode this crate's sessions do not run.
        net.set_full_linkstate(false);
        Some(Self {
            net,
            target: default_target(whatami),
            autoconnect: AutoConnect::with_strategies(
                zid,
                default_autoconnect(whatami),
                AutoConnectStrategies::default(),
            ),
            faces: BTreeMap::new(),
        })
    }

    /// Where this node can be reached, as locators. They ride every entry it sends about itself,
    /// so a node that is told of this one learns where to dial; set before the first face comes
    /// up and a neighbour has them from its first list.
    pub fn set_self_locators(&mut self, locators: Vec<String>) {
        self.net.set_self_locators(locators);
    }

    /// Whether a face of role `whatami` is sent topology.
    fn gossips_to(&self, whatami: WhatAmI) -> bool {
        self.target.matches(whatami)
    }

    /// A face came up: bring its far end into the graph and tell it, and the faces that hear of
    /// a new link, what upstream's `Gossip::add_link` tells.
    ///
    /// A face with no usable zid, one that is this node's own, and a client are held and not
    /// linked: a client is a leaf, and a node with no identity has nothing to be introduced by.
    pub fn face_up(&mut self, face: u64, who: &FaceIdentity) -> Effects {
        let self_zid = *self.net.self_zid();
        let whatami = who.whatami();
        let neighbour = who
            .zid
            .as_deref()
            .and_then(|bytes| Zid::try_from(bytes).ok())
            .filter(|zid| *zid != self_zid)
            .filter(|_| whatami != WhatAmI::Client);
        let Some(neighbour) = neighbour else {
            self.faces.insert(
                face,
                Face {
                    link: None,
                    zid: None,
                    whatami,
                },
            );
            return Effects::default();
        };
        // Whether this far end is new to the graph and not merely a new face: a second link to
        // a node already known tells the others less.
        let was_new = self.net.get_node(&neighbour).is_none();
        let self_whatami = self
            .net
            .get_node(&self_zid)
            .and_then(|node| node.whatami)
            .unwrap_or(WhatAmI::Peer);
        // The far end is a gateway of this node's region when it announced itself south of it,
        // or when the two roles put it there (`compute_auto_region`).
        let gateway = region_and_bound_of(self_whatami, whatami, who.remote_bound)
            .is_some_and(|(_, bound)| bound.is_south());
        let link = self.net.add_link_bound(neighbour, whatami, gateway);
        self.faces.insert(
            face,
            Face {
                link: Some(link),
                zid: Some(neighbour),
                whatami,
            },
        );

        let full = self.net.build_new_link_bootstrap(link);
        let delta = self
            .net
            .build_link_added_delta_for_existing(&neighbour, was_new);
        let mut effects = Effects::default();
        for (id, held) in &self.faces {
            if !self.gossips_to(held.whatami) {
                continue;
            }
            let list = if *id == face {
                // The new link is told every node.
                Some(&full)
            } else if held.zid == Some(neighbour) {
                // Another link to the same node: it learns of this change from the new link's
                // own bootstrap.
                None
            } else if held.link.is_some_and(|l| self.net.link_hears_link_added(l)) {
                delta.as_ref()
            } else {
                None
            };
            if let Some(oam) = list.and_then(Self::carrier) {
                effects.sends.push(Outbound { face: *id, oam });
            }
        }
        effects
    }

    /// A face went down: forget it and, with it, the node at its far end.
    ///
    /// Nothing is sent. Upstream's gossip removes the node and tells nobody
    /// (`Gossip::remove_link`): a node that is still reachable another way is told of again the
    /// next time one of its neighbours learns of it.
    pub fn face_down(&mut self, face: u64) {
        if let Some(Face {
            link: Some(link), ..
        }) = self.faces.remove(&face)
        {
            self.net.remove_link(link);
        }
    }

    /// `list` arrived on `face`: take in what it tells, pass on what that changed, and name the
    /// nodes it makes worth dialling.
    ///
    /// A list from a face that is not linked (a client, a face with no zid) is dropped, as
    /// upstream drops one from a link it does not hold.
    pub fn received(&mut self, face: u64, list: LinkstateListOwned) -> Effects {
        let Some(link) = self.faces.get(&face).and_then(|held| held.link) else {
            return Effects::default();
        };
        let changes = self.net.ingest_linkstate_list(link, list);
        let self_zid = *self.net.self_zid();
        let mut effects = Effects::default();

        // Upstream checks every entry it is told of, new or not: a node whose locators arrive
        // after it was first named is dialled when they do.
        for zid in changes.new.iter().chain(changes.updated.iter()) {
            // Itself, or a node it already holds a link to: upstream skips both, and a host that
            // dials by the intent asks the same of its own registry as well, since a link can
            // come up between this answer and the dial.
            if *zid == self_zid || self.faces.values().any(|held| held.zid == Some(*zid)) {
                continue;
            }
            let Some(whatami) = self.net.get_node(zid).and_then(|node| node.whatami) else {
                continue;
            };
            if !self.autoconnect.should_autoconnect(*zid, whatami) {
                continue;
            }
            // A node that advertised no locator is recorded and not a candidate.
            let Some(locators) = self.net.node_locators(zid).filter(|l| !l.is_empty()) else {
                continue;
            };
            effects.dials.push(DialIntent {
                zid: zid.as_slice().to_vec(),
                locators: locators.to_vec(),
                origin: DialIntentOrigin::Gossip,
            });
        }

        for (id, held) in &self.faces {
            if !self.gossips_to(held.whatami) {
                continue;
            }
            let reflood = self.net.build_reflood_for(&changes, held.zid, *id == face);
            if let Some(oam) = reflood.as_ref().and_then(Self::carrier) {
                effects.sends.push(Outbound { face: *id, oam });
            }
        }
        effects
    }

    /// `list` as the message that carries it. A list the codec cannot encode is not sent: the
    /// graph builds none, so this is a node that cannot be told rather than a node that is
    /// lied to.
    fn carrier(list: &LinkstateListOwned) -> Option<OamOwned> {
        match build_linkstate_oam_owned(list) {
            Ok(oam) => Some(oam),
            Err(err) => {
                log::debug!("gossip: a topology list did not encode: {err:?}");
                None
            }
        }
    }
}

/// A [`GossipCore`] behind a lock, posting the nodes it learns to dial.
///
/// The lock is held for the decision and released before anything is sent or posted, so a host
/// that sends under a lock of its own never holds this one across it.
pub struct GossipPlane {
    core: Mutex<GossipCore>,
    dials: DialIntentSender,
}

impl GossipPlane {
    /// A plane for a node with `self_zid` and role `whatami`, posting its dials to `dials`.
    /// `None` when `self_zid` is not one the graph can hold.
    pub fn new(self_zid: &[u8], whatami: WhatAmI, dials: DialIntentSender) -> Option<Self> {
        Some(Self {
            core: Mutex::new(GossipCore::new(self_zid, whatami)?),
            dials,
        })
    }

    fn core(&self) -> MutexGuard<'_, GossipCore> {
        // A panic under this lock leaves the graph as the panic found it, which is still a
        // graph; refusing every later face would turn one bad list into a session that never
        // meets anyone.
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// See [`GossipCore::set_self_locators`].
    pub fn set_self_locators(&self, locators: Vec<String>) {
        self.core().set_self_locators(locators);
    }

    /// A face came up. The messages to send are returned; the dials are posted.
    pub fn face_up(&self, face: u64, who: &FaceIdentity) -> Vec<Outbound> {
        let effects = self.core().face_up(face, who);
        self.post(effects)
    }

    /// A face went down.
    pub fn face_down(&self, face: u64) {
        self.core().face_down(face);
    }

    /// The network messages that arrived on `face`: every topology list among them is taken in.
    /// The messages to send are returned; the dials are posted.
    pub fn inbound(&self, face: u64, messages: &[NetworkMessage]) -> Vec<Outbound> {
        let mut sends = Vec::new();
        for message in messages {
            let NetworkMessage::Oam(oam) = message else {
                continue;
            };
            // An OAM that is not a topology list, or is a corrupt one, is not gossip's.
            let LinkstateOam::Decoded(list) = try_parse_linkstate_oam(oam) else {
                continue;
            };
            let effects = self.core().received(face, list);
            sends.extend(self.post(effects));
        }
        sends
    }

    /// Post the dials of `effects` and hand back its messages.
    fn post(&self, effects: Effects) -> Vec<Outbound> {
        for dial in effects.dials {
            // An unbounded send that fails means the session is closing and nothing drains the
            // dials any more; there is nothing to do with the node then.
            let _ = self.dials.send(dial);
        }
        effects.sends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire role bytes: router 0, peer 1, client 2.
    const WIRE_ROUTER: u8 = 0;
    const WIRE_PEER: u8 = 1;
    const WIRE_CLIENT: u8 = 2;

    fn zid(n: u8) -> Vec<u8> {
        vec![n; 16]
    }

    /// A list that says nothing, built by the graph as it builds the list of no nodes.
    fn empty_list() -> LinkstateListOwned {
        LinkstateNetwork::new(Zid::from_slice(&zid(9)), WhatAmI::Peer).build_linkstate_gossip(&[])
    }

    fn identity(zid: &[u8], wire: u8) -> FaceIdentity {
        FaceIdentity {
            zid: Some(zid.to_vec()),
            whatami_wire: Some(wire),
            remote_bound: None,
        }
    }

    /// A handful of nodes and the faces between them, with every message delivered.
    struct Mesh {
        nodes: Vec<(Vec<u8>, u8, GossipCore)>,
        /// (node, face) -> the (node, face) at the other end.
        wires: BTreeMap<(usize, u64), (usize, u64)>,
        next_face: u64,
        /// What each node was told to dial, in the order it was told.
        dialled: Vec<(usize, DialIntent)>,
        /// How many messages crossed, to see that a mesh settles.
        crossed: usize,
    }

    impl Mesh {
        fn new() -> Self {
            Self {
                nodes: Vec::new(),
                wires: BTreeMap::new(),
                next_face: 0,
                dialled: Vec::new(),
                crossed: 0,
            }
        }

        /// A node of wire role `wire`, reachable at `locator` when it has one.
        fn node(&mut self, id: u8, wire: u8, locator: Option<&str>) -> usize {
            let whatami = WhatAmI::from_wire(wire).expect("a role");
            let mut core = GossipCore::new(&zid(id), whatami).expect("a zid");
            if let Some(locator) = locator {
                core.set_self_locators(vec![locator.to_owned()]);
            }
            self.nodes.push((zid(id), wire, core));
            self.nodes.len() - 1
        }

        /// A link between two nodes, each side brought up on a face of its own, and the traffic
        /// it starts carried to the end.
        fn link(&mut self, a: usize, b: usize) -> (u64, u64) {
            let (fa, fb) = (self.next_face, self.next_face + 1);
            self.next_face += 2;
            self.wires.insert((a, fa), (b, fb));
            self.wires.insert((b, fb), (a, fa));
            let who_b = identity(&self.nodes[b].0.clone(), self.nodes[b].1);
            let who_a = identity(&self.nodes[a].0.clone(), self.nodes[a].1);
            let from_a = self.nodes[a].2.face_up(fa, &who_b);
            let from_b = self.nodes[b].2.face_up(fb, &who_a);
            let mut queue: Vec<(usize, Outbound)> = Vec::new();
            for effects in [(a, from_a), (b, from_b)] {
                let (node, effects) = effects;
                self.dialled
                    .extend(effects.dials.into_iter().map(|d| (node, d)));
                queue.extend(effects.sends.into_iter().map(|o| (node, o)));
            }
            self.pump(queue);
            (fa, fb)
        }

        /// Deliver every message until none is left. A mesh that never settles is a gossip storm
        /// and fails here rather than hangs.
        fn pump(&mut self, mut queue: Vec<(usize, Outbound)>) {
            while let Some((from, out)) = queue.pop() {
                self.crossed += 1;
                assert!(self.crossed < 500, "the mesh does not settle");
                let Some(&(to, face)) = self.wires.get(&(from, out.face)) else {
                    continue;
                };
                let NetworkMessage::Oam(oam) = out.into_message() else {
                    unreachable!("a gossip message is an OAM");
                };
                let LinkstateOam::Decoded(list) = try_parse_linkstate_oam(&oam) else {
                    panic!("a gossip message decodes as a topology list");
                };
                let effects = self.nodes[to].2.received(face, list);
                self.dialled
                    .extend(effects.dials.into_iter().map(|d| (to, d)));
                queue.extend(effects.sends.into_iter().map(|o| (to, o)));
            }
        }

        fn dials_of(&self, node: usize) -> Vec<&DialIntent> {
            self.dialled
                .iter()
                .filter(|(who, _)| *who == node)
                .map(|(_, d)| d)
                .collect()
        }
    }

    /// The case gossip exists for. B and C each connect to A and to nothing else: A is the only
    /// node that knows both. Each of B and C is told of the other and where it can be reached,
    /// by A, and is told to dial it.
    #[test]
    fn a_hub_introduces_the_two_peers_that_connected_to_it() {
        let mut mesh = Mesh::new();
        let a = mesh.node(1, WIRE_PEER, Some("tcp/10.0.0.1:7447"));
        let b = mesh.node(2, WIRE_PEER, Some("tcp/10.0.0.2:7447"));
        let c = mesh.node(3, WIRE_PEER, Some("tcp/10.0.0.3:7447"));
        mesh.link(b, a);
        mesh.link(c, a);

        let b_dials = mesh.dials_of(b);
        assert!(
            b_dials
                .iter()
                .any(|d| d.zid == zid(3) && d.locators == ["tcp/10.0.0.3:7447"]),
            "B is told to dial C where C said it is: {b_dials:?}"
        );
        let c_dials = mesh.dials_of(c);
        assert!(
            c_dials
                .iter()
                .any(|d| d.zid == zid(2) && d.locators == ["tcp/10.0.0.2:7447"]),
            "C is told to dial B where B said it is: {c_dials:?}"
        );
        assert!(
            b_dials
                .iter()
                .chain(c_dials.iter())
                .all(|d| d.origin == DialIntentOrigin::Gossip),
            "every one of them is gossip's"
        );
    }

    /// The order the two connect in does not matter: the one that came first is introduced by
    /// the hub forwarding what it learnt, the one that came second by the hub's bootstrap.
    #[test]
    fn who_connects_to_the_hub_first_does_not_change_who_is_introduced() {
        for first_is_b in [true, false] {
            let mut mesh = Mesh::new();
            let a = mesh.node(1, WIRE_PEER, Some("tcp/10.0.0.1:7447"));
            let b = mesh.node(2, WIRE_PEER, Some("tcp/10.0.0.2:7447"));
            let c = mesh.node(3, WIRE_PEER, Some("tcp/10.0.0.3:7447"));
            if first_is_b {
                mesh.link(b, a);
                mesh.link(c, a);
            } else {
                mesh.link(c, a);
                mesh.link(b, a);
            }
            assert!(
                mesh.dials_of(b).iter().any(|d| d.zid == zid(3)),
                "B dials C (B first: {first_is_b})"
            );
            assert!(
                mesh.dials_of(c).iter().any(|d| d.zid == zid(2)),
                "C dials B (B first: {first_is_b})"
            );
        }
    }

    /// A node that said where it can be reached nowhere is known and is not dialled: there is
    /// nothing to dial.
    #[test]
    fn a_node_with_no_locator_is_not_a_dial_candidate() {
        let mut mesh = Mesh::new();
        let a = mesh.node(1, WIRE_PEER, Some("tcp/10.0.0.1:7447"));
        let b = mesh.node(2, WIRE_PEER, Some("tcp/10.0.0.2:7447"));
        let c = mesh.node(3, WIRE_PEER, None);
        mesh.link(b, a);
        mesh.link(c, a);
        assert!(
            mesh.dials_of(b).iter().all(|d| d.zid != zid(3)),
            "B has nowhere to dial C at"
        );
        assert!(
            mesh.dials_of(c).iter().any(|d| d.zid == zid(2)),
            "C, which can dial, is still told of B"
        );
    }

    /// A router's shipped autoconnect names nobody: it is told of peers and dials none of them.
    #[test]
    fn a_router_dials_nobody_it_is_told_of() {
        let mut mesh = Mesh::new();
        let a = mesh.node(1, WIRE_PEER, Some("tcp/10.0.0.1:7447"));
        let r = mesh.node(2, WIRE_ROUTER, Some("tcp/10.0.0.2:7447"));
        let c = mesh.node(3, WIRE_PEER, Some("tcp/10.0.0.3:7447"));
        mesh.link(r, a);
        mesh.link(c, a);
        assert!(
            mesh.dials_of(r).is_empty(),
            "a router's policy admits no role"
        );
        assert!(
            mesh.dials_of(c).iter().any(|d| d.zid == zid(2)),
            "the peer is told of the router and dials it"
        );
    }

    /// A client is a leaf: it is held and not gossiped to, and nothing it sends is taken in. A
    /// peer behind the hub is not introduced to it.
    #[test]
    fn a_client_is_neither_told_nor_introduced() {
        let mut core = GossipCore::new(&zid(1), WhatAmI::Peer).expect("a zid");
        let up = core.face_up(7, &identity(&zid(9), WIRE_CLIENT));
        assert!(
            up.sends.is_empty() && up.dials.is_empty(),
            "a client is sent no topology on coming up"
        );
        let later = core.face_up(8, &identity(&zid(2), WIRE_PEER));
        assert!(
            later.sends.iter().all(|out| out.face != 7),
            "a peer coming up is not announced to the client"
        );
        let from_client = core.received(7, empty_list());
        assert!(
            from_client.sends.is_empty() && from_client.dials.is_empty(),
            "a list from a client is not taken in"
        );
    }

    /// A face that is this node's own zid, or has none, is held without a link: it is no
    /// neighbour, and a list on it is dropped.
    #[test]
    fn a_face_with_no_usable_identity_is_not_a_neighbour() {
        let mut core = GossipCore::new(&zid(1), WhatAmI::Peer).expect("a zid");
        for who in [
            identity(&zid(1), WIRE_PEER),
            FaceIdentity::default(),
            FaceIdentity {
                zid: Some(vec![0; 16]),
                whatami_wire: Some(WIRE_PEER),
                remote_bound: None,
            },
        ] {
            let up = core.face_up(3, &who);
            assert!(up.sends.is_empty(), "nothing is told to {who:?}");
            let got = core.received(3, empty_list());
            assert!(got.sends.is_empty() && got.dials.is_empty());
            core.face_down(3);
        }
    }

    /// A node whose face went down is forgotten, so a new link to it is told as a new one and
    /// the node is dialled again by whoever learns of it.
    #[test]
    fn a_node_whose_face_went_down_is_introduced_again_when_it_returns() {
        let mut mesh = Mesh::new();
        let a = mesh.node(1, WIRE_PEER, Some("tcp/10.0.0.1:7447"));
        let b = mesh.node(2, WIRE_PEER, Some("tcp/10.0.0.2:7447"));
        let c = mesh.node(3, WIRE_PEER, Some("tcp/10.0.0.3:7447"));
        mesh.link(b, a);
        let (_, face_on_a) = mesh.link(c, a);
        let before = mesh.dials_of(b).len();

        // C leaves A: A forgets it, sending nothing.
        mesh.nodes[a].2.face_down(face_on_a);
        // And comes back on a new face.
        mesh.link(c, a);
        assert!(
            mesh.dials_of(b).len() > before,
            "B is told of C again when C returns"
        );
    }

    /// Nothing about two nodes that are not each other's neighbour is sent to a face outside
    /// the gossip target: a router that gossips to routers only leaves a peer face alone.
    #[test]
    fn a_face_outside_the_target_is_sent_nothing() {
        let mut core = GossipCore::new(&zid(1), WhatAmI::Peer).expect("a zid");
        core.target = WhatAmIMatcher::empty().router();
        let up = core.face_up(1, &identity(&zid(2), WIRE_PEER));
        assert!(up.sends.is_empty(), "a peer is not a target: {up:?}");
        let up = core.face_up(2, &identity(&zid(3), WIRE_ROUTER));
        assert!(
            up.sends.iter().all(|out| out.face == 2),
            "only the router is told"
        );
        assert!(!up.sends.is_empty(), "and it is told");
    }

    /// The plane turns a network message into the same decision, and ignores what is not
    /// gossip: a list that decodes is taken in, any other message is passed over.
    #[test]
    fn the_plane_takes_in_topology_lists_and_nothing_else() {
        let (dials, mut posted) = tokio::sync::mpsc::unbounded_channel();
        let hub = GossipPlane::new(&zid(1), WhatAmI::Peer, dials).expect("a zid");
        hub.set_self_locators(vec!["tcp/10.0.0.1:7447".to_owned()]);
        let b = GossipPlane::new(
            &zid(2),
            WhatAmI::Peer,
            tokio::sync::mpsc::unbounded_channel().0,
        )
        .expect("a zid");
        b.set_self_locators(vec!["tcp/10.0.0.2:7447".to_owned()]);

        let to_b = hub.face_up(10, &identity(&zid(2), WIRE_PEER));
        let to_hub = b.face_up(20, &identity(&zid(1), WIRE_PEER));
        assert!(!to_b.is_empty() && !to_hub.is_empty(), "a link is told");

        // What B told the hub is taken in and the hub passes on nothing it has no one to tell.
        let messages: Vec<NetworkMessage> =
            to_hub.into_iter().map(Outbound::into_message).collect();
        let passed_on = hub.inbound(10, &messages);
        assert!(
            passed_on.iter().all(|out| out.face == 10),
            "the hub holds one face and answers on it only"
        );
        assert!(
            posted.try_recv().is_err(),
            "the hub is told of no node it does not have a link to"
        );
        // A message that is not an OAM is not gossip's.
        assert!(hub.inbound(10, &[]).is_empty());
    }

    /// The role bytes the handshake carries map as the routing plane maps them, an unknown one
    /// to a peer.
    #[test]
    fn an_unknown_role_is_taken_for_a_peer() {
        assert_eq!(identity(&zid(2), WIRE_ROUTER).whatami(), WhatAmI::Router);
        assert_eq!(identity(&zid(2), WIRE_CLIENT).whatami(), WhatAmI::Client);
        assert_eq!(identity(&zid(2), 3).whatami(), WhatAmI::Peer);
        assert_eq!(FaceIdentity::default().whatami(), WhatAmI::Peer);
    }
}
