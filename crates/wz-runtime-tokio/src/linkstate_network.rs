// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer routing topology graph (P4 routing, step c2a).
//!
//! The wz mirror of zenoh `net/protocol/network.rs` — the in-memory graph
//! a peer maintains of the mesh it has learned about, so it can later
//! compute a loop-free spanning tree to forward on. Each vertex is a peer
//! [`Node`] (its zid + advertised state); each [`Link`] holds the
//! `psid <-> zid` translation a received `LinkStateList` is decoded
//! against (a peer references nodes by a compact local `psid`, which this
//! side resolves to the global `zid`).
//!
//! This is pure host logic with no async coupling: the accept / peer
//! loops drive it in step c3 (feeding it parsed LinkStateLists and the
//! face lifecycle), and the spanning-tree / shortest-path computation is
//! step d. This atom (c2a) is the graph foundation + the psid<->zid
//! mappings; LinkStateList ingest (updating nodes from a decoded list,
//! with sn-staleness) is step c2b.
//!
//! `routing-peer`-gated (AP/full-node mesh routing; absent from the MCU
//! footprint). Backed by `petgraph` 0.6 (`StableUnGraph`, matching
//! zenoh's own petgraph), so node indices stay stable across removals.

use std::collections::HashMap;
use std::num::NonZeroU16;

use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableUnGraph;

/// A routing identity — the raw zid bytes, matching the wz face / session
/// `peer_zid` representation (`Vec<u8>`).
pub type Zid = Vec<u8>;

/// A local link id (the index the runtime assigns a peer face).
pub type LinkId = usize;

/// A peer-state id — the compact integer a peer uses to reference a node
/// inside its `LinkStateList` (zenoh `psid`). Resolved to a global [`Zid`]
/// through the receiving [`Link`]'s mapping.
pub type Psid = u64;

/// An edge weight (zenoh `LinkEdgeWeight`, `net/protocol/linkstate.rs:54`):
/// an optional explicit weight; absent means the default. A `NonZeroU16`
/// makes "unset" (the default-weight case) unrepresentable as a stored 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkEdgeWeight(Option<NonZeroU16>);

impl LinkEdgeWeight {
    /// The default edge weight when a peer advertises no explicit weight
    /// (zenoh `LinkEdgeWeight::DEFAULT_LINK_WEIGHT`).
    pub const DEFAULT: u16 = 100;

    /// From a wire value: 0 (the "no weight" sentinel) maps to unset.
    pub fn from_raw(value: u16) -> Self {
        LinkEdgeWeight(NonZeroU16::new(value))
    }

    /// The effective weight — the explicit value, or [`DEFAULT`] if unset.
    pub fn value(&self) -> u16 {
        self.0.map(NonZeroU16::get).unwrap_or(Self::DEFAULT)
    }

    /// Whether an explicit weight was advertised.
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

/// A node (vertex) in the topology graph — one peer's advertised state.
/// Mirrors zenoh `Node` (`network.rs:56-62`). `whatami` / `locators` are
/// the codec's host types (raw `u8` / UTF-8 strings); `whatami`
/// range-validation is the consumer's obligation (the codec carries the
/// raw byte, unlike zenoh which rejects an invalid `WhatAmI` at decode).
#[derive(Debug, Clone)]
pub struct Node {
    pub zid: Zid,
    pub whatami: Option<u8>,
    pub locators: Option<Vec<String>>,
    pub sn: u64,
    pub links: HashMap<Zid, LinkEdgeWeight>,
}

/// Per-link routing state — the `psid -> zid` translation a received
/// `LinkStateList` from this link is decoded against. Mirrors zenoh `Link`
/// (`network.rs:70-108`) minus the transport: the runtime owns the
/// face/transport; this holds only the routing identity and the mapping.
/// (zenoh's secondary `local_mappings` is a forwarding concern and lands
/// with the forwarding atom, not here.)
#[derive(Debug, Clone)]
pub struct Link {
    pub zid: Zid,
    mappings: HashMap<Psid, Zid>,
}

impl Link {
    /// A fresh link to the neighbour identified by `zid`, no mappings yet.
    pub fn new(zid: Zid) -> Self {
        Link {
            zid,
            mappings: HashMap::new(),
        }
    }

    /// Record that this link's peer refers to `zid` by `psid`
    /// (zenoh `set_zid_mapping`).
    pub fn set_zid_mapping(&mut self, psid: Psid, zid: Zid) {
        self.mappings.insert(psid, zid);
    }

    /// Resolve a `psid` this link's peer used to the global `zid`
    /// (zenoh `get_zid`).
    pub fn get_zid(&self, psid: Psid) -> Option<&Zid> {
        self.mappings.get(&psid)
    }
}

/// The linkstate-peer topology graph. Mirrors zenoh `Network` (the
/// petgraph of `Node`s + the per-link state), narrowed to the routing
/// state c2 owns: the self node, the neighbour links, and their
/// psid<->zid mappings. The spanning trees + shortest-path distances
/// (zenoh's `trees` / `distances`) are step d.
pub struct LinkstateNetwork {
    idx: NodeIndex,
    graph: StableUnGraph<Node, f64>,
    links: HashMap<LinkId, Link>,
    next_link_id: LinkId,
}

impl LinkstateNetwork {
    /// A graph seeded with the local (self) node — sn starts at 1, as in
    /// zenoh `Network::new` (`network.rs:156-162`).
    pub fn new(self_zid: Zid, self_whatami: u8) -> Self {
        let mut graph = StableUnGraph::default();
        let idx = graph.add_node(Node {
            zid: self_zid,
            whatami: Some(self_whatami),
            locators: None,
            sn: 1,
            links: HashMap::new(),
        });
        LinkstateNetwork {
            idx,
            graph,
            links: HashMap::new(),
            next_link_id: 0,
        }
    }

    /// The self node index.
    pub fn self_idx(&self) -> NodeIndex {
        self.idx
    }

    /// The self node's zid.
    pub fn self_zid(&self) -> &Zid {
        &self.graph[self.idx].zid
    }

    /// The number of nodes currently known (including self).
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Find a node index by zid — a linear scan, mirroring zenoh `get_idx`
    /// (`network.rs:256`); the learned mesh is small.
    pub fn get_idx(&self, zid: &Zid) -> Option<NodeIndex> {
        self.graph
            .node_indices()
            .find(|i| &self.graph[*i].zid == zid)
    }

    /// Look up a node by zid.
    pub fn get_node(&self, zid: &Zid) -> Option<&Node> {
        self.get_idx(zid).map(|i| &self.graph[i])
    }

    /// Insert a node for `zid` if absent, returning its index (the upsert
    /// primitive the LinkStateList ingest in c2b builds on). A freshly
    /// inserted node has sn 0 / unknown whatami until a link-state for it
    /// arrives.
    pub fn ensure_node(&mut self, zid: Zid) -> NodeIndex {
        if let Some(i) = self.get_idx(&zid) {
            return i;
        }
        self.graph.add_node(Node {
            zid,
            whatami: None,
            locators: None,
            sn: 0,
            links: HashMap::new(),
        })
    }

    /// Register a new link to a neighbour (zid), returning its link id.
    /// The runtime calls this when a peer face is established (step c3).
    pub fn add_link(&mut self, peer_zid: Zid) -> LinkId {
        let id = self.next_link_id;
        self.next_link_id += 1;
        self.links.insert(id, Link::new(peer_zid));
        id
    }

    /// Borrow a link by id.
    pub fn get_link(&self, id: LinkId) -> Option<&Link> {
        self.links.get(&id)
    }

    /// Mutably borrow a link by id (for recording psid<->zid mappings).
    pub fn get_link_mut(&mut self, id: LinkId) -> Option<&mut Link> {
        self.links.get_mut(&id)
    }

    /// Remove a link (the peer face went down). Returns the removed link.
    /// Node/edge pruning on link loss is the ingest/forwarding concern
    /// (c2b/d); this drops the per-link mapping state.
    pub fn remove_link(&mut self, id: LinkId) -> Option<Link> {
        self.links.remove(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: u8) -> Zid {
        vec![b, b, b, b]
    }

    #[test]
    fn link_edge_weight_default_and_explicit() {
        assert_eq!(LinkEdgeWeight::default().value(), 100);
        assert!(!LinkEdgeWeight::default().is_set());
        assert_eq!(
            LinkEdgeWeight::from_raw(0).value(),
            100,
            "0 => unset => default"
        );
        assert!(!LinkEdgeWeight::from_raw(0).is_set());
        assert_eq!(LinkEdgeWeight::from_raw(250).value(), 250);
        assert!(LinkEdgeWeight::from_raw(250).is_set());
    }

    #[test]
    fn new_seeds_self_node() {
        let net = LinkstateNetwork::new(zid(0x01), 2);
        assert_eq!(net.node_count(), 1);
        assert_eq!(net.self_zid(), &zid(0x01));
        assert_eq!(net.get_idx(&zid(0x01)), Some(net.self_idx()));
        let self_node = net.get_node(&zid(0x01)).unwrap();
        assert_eq!(self_node.whatami, Some(2));
        assert_eq!(self_node.sn, 1, "self sn starts at 1 (zenoh parity)");
    }

    #[test]
    fn ensure_node_is_idempotent_upsert() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let a = net.ensure_node(zid(0x07));
        assert_eq!(net.node_count(), 2);
        let again = net.ensure_node(zid(0x07));
        assert_eq!(a, again, "same zid => same node index");
        assert_eq!(net.node_count(), 2, "no duplicate node");
        // a freshly inserted (not-yet-advertised) node has sn 0.
        assert_eq!(net.get_node(&zid(0x07)).unwrap().sn, 0);
        assert!(net.get_idx(&zid(0x09)).is_none());
    }

    #[test]
    fn link_psid_to_zid_mapping() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let id = net.add_link(zid(0x07));
        assert_eq!(net.get_link(id).unwrap().zid, zid(0x07));

        let link = net.get_link_mut(id).unwrap();
        link.set_zid_mapping(5, zid(0xAB));
        assert_eq!(net.get_link(id).unwrap().get_zid(5), Some(&zid(0xAB)));
        assert_eq!(net.get_link(id).unwrap().get_zid(6), None);
    }

    #[test]
    fn add_and_remove_link() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let a = net.add_link(zid(0x07));
        let b = net.add_link(zid(0x08));
        assert_ne!(a, b, "distinct link ids");
        assert!(net.get_link(a).is_some());
        let removed = net.remove_link(a).expect("link present");
        assert_eq!(removed.zid, zid(0x07));
        assert!(net.get_link(a).is_none());
        assert!(net.get_link(b).is_some(), "removing one link leaves others");
    }
}
