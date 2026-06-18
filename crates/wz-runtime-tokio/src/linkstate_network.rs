// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer routing topology graph (P4 routing, step c2).
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
//! face lifecycle), and the spanning-tree / shortest-path computation over
//! the edges built here is step d. Built so far: c2a the graph foundation
//! + psid<->zid mappings, c2b the [`LinkstateNetwork::ingest_linkstate_list`]
//! node update under the sn-staleness gate, c2c the mutual-link edge
//! rebuild (`update_edge`). Deferred to later atoms: gossip / autoconnect
//! propagation, locator ingest, and the `local_mappings` forwarding table.
//!
//! `routing-peer`-gated (AP/full-node mesh routing; absent from the MCU
//! footprint). Backed by `petgraph` 0.6 (`StableUnGraph`, matching
//! zenoh's own petgraph), so node indices stay stable across removals.

use std::collections::HashMap;
use std::num::NonZeroU16;

use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableUnGraph;
use wz_codecs::linkstate_list::LinkstateListOwned;

/// WhatAmI role bytes (zenoh `WhatAmI`): a node advertises exactly one.
/// The codec carries the raw byte; the ingest validates against this set
/// (zenoh rejects an out-of-set value at decode — the c2 host obligation).
const WHATAMI_ROUTER: u8 = 1;
const WHATAMI_PEER: u8 = 2;
const WHATAMI_CLIENT: u8 = 4;

fn is_valid_whatami(w: u8) -> bool {
    matches!(w, WHATAMI_ROUTER | WHATAMI_PEER | WHATAMI_CLIENT)
}

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

/// A LinkState resolved from psid-space into zid-space — the intermediate
/// the ingest produces before applying it to the graph. Mirrors zenoh
/// `LocalLinkState` (`network.rs:96-103`), narrowed to what c2b applies
/// (locator ingest lands with the gossip/autoconnect atom).
struct LocalLinkState {
    sn: u64,
    zid: Zid,
    whatami: u8,
    links: HashMap<Zid, LinkEdgeWeight>,
}

/// What a LinkStateList ingest changed — the zids of nodes added or
/// updated. The driver (step c3) uses this to decide what to re-flood /
/// autoconnect. Mirrors the role of zenoh `Changes` (`network.rs:110`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub updated: Vec<Zid>,
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

    /// The number of edges (mutual links) in the topology graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// The weight of the edge between two nodes, if a mutual link exists.
    /// Used by the spanning-tree / shortest-path computation (step d) and
    /// by tests; the value carries the sub-1% tie-break jitter.
    pub fn edge_weight(&self, a: &Zid, b: &Zid) -> Option<f64> {
        let ia = self.get_idx(a)?;
        let ib = self.get_idx(b)?;
        let edge = self.graph.find_edge(ia, ib)?;
        self.graph.edge_weight(edge).copied()
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

    /// Ingest a `LinkStateList` received on link `src_link_id`: learn its
    /// psid<->zid mappings, then apply the (zid-resolved) link-states to
    /// the graph under the sn-staleness gate. Returns the nodes it changed.
    /// Mirrors zenoh's receive path: `convert_to_local_link_states` ->
    /// `process_linkstates_peer_to_peer` (`network.rs:457-616`).
    pub fn ingest_linkstate_list(
        &mut self,
        src_link_id: LinkId,
        list: LinkstateListOwned,
    ) -> Changes {
        let local = self.convert_to_local_link_states(src_link_id, list);
        self.process_linkstates(local)
    }

    /// Resolve a received list from psid-space to zid-space against the
    /// source link's mappings (registering newly-advertised psid->zid
    /// pairs), dropping entries whose node/whatami cannot be resolved.
    /// Mirrors zenoh `convert_to_local_link_states` (`network.rs:457`); the
    /// `set_local_psid_mapping` step (a forwarding-table concern) lands
    /// with the forwarding atom, so this needs only the source link.
    fn convert_to_local_link_states(
        &mut self,
        src_link_id: LinkId,
        list: LinkstateListOwned,
    ) -> Vec<LocalLinkState> {
        let src_link = match self.links.get_mut(&src_link_id) {
            Some(link) => link,
            // A list from an unknown link is dropped (zenoh logs + returns
            // empty, `network.rs:469-476`).
            None => return Vec::new(),
        };

        let mut out = Vec::with_capacity(list.link_states.len());
        for entry in list.link_states {
            // The entry's own zid: present (register the psid->zid mapping)
            // or referenced by a previously-learned psid.
            let zid = match entry.zid {
                Some(bytes) => {
                    let zid = bytes.as_slice().to_vec();
                    src_link.set_zid_mapping(entry.psid, zid.clone());
                    zid
                }
                None => match src_link.get_zid(entry.psid) {
                    Some(zid) => zid.clone(),
                    None => continue, // unknown psid mapping -> drop entry
                },
            };

            // whatami: absent defaults to Router; an out-of-range value is
            // dropped (the c2 host-validation obligation — zenoh rejects it
            // at decode, the wz codec carries the raw byte).
            let whatami = match entry.whatami {
                None => WHATAMI_ROUTER,
                Some(w) if is_valid_whatami(w) => w,
                Some(_) => continue,
            };

            // Resolve the entry's link psids to zids, attaching the
            // advertised weight (or the default when no weights block).
            let mut links = HashMap::with_capacity(entry.links.len());
            for (i, link) in entry.links.iter().enumerate() {
                if let Some(dst) = src_link.get_zid(link.psid) {
                    let weight = entry
                        .weights
                        .as_ref()
                        .and_then(|ws| ws.get(i))
                        .map(|w| LinkEdgeWeight::from_raw(w.weight))
                        .unwrap_or_default();
                    links.insert(dst.clone(), weight);
                }
                // unknown link psid -> drop that edge (zenoh, network.rs:544)
            }

            out.push(LocalLinkState {
                sn: entry.sn,
                zid,
                whatami,
                links,
            });
        }
        out
    }

    /// Apply zid-resolved link-states to the graph under the sn-staleness
    /// gate, then rebuild the changed node's edges. A new node is added; an
    /// existing node is updated only if the advertised sn is strictly newer
    /// (a stale or duplicate advertisement is ignored). Mirrors zenoh's
    /// `link_states` node-update + edge-rebuild (`network.rs:559-616,
    /// 728-783`) minus the gossip/autoconnect propagation (the c3 driver
    /// concern). Returns the changed nodes' zids.
    fn process_linkstates(&mut self, states: Vec<LocalLinkState>) -> Changes {
        let mut changes = Changes::default();
        for ls in states {
            let idx = match self.get_idx(&ls.zid) {
                None => self.graph.add_node(Node {
                    zid: ls.zid.clone(),
                    whatami: Some(ls.whatami),
                    // locator ingest lands with the gossip/autoconnect atom.
                    locators: None,
                    sn: ls.sn,
                    links: ls.links,
                }),
                Some(idx) => {
                    let node = &mut self.graph[idx];
                    // sn-staleness gate (zenoh network.rs:580): ignore a
                    // not-newer advertisement.
                    if node.sn >= ls.sn {
                        continue;
                    }
                    node.sn = ls.sn;
                    node.links = ls.links;
                    idx
                }
            };
            self.rebuild_edges(idx);
            changes.updated.push(self.graph[idx].zid.clone());
        }
        changes
    }

    /// Rebuild node `idx1`'s edges from its (just-updated) `links`: add or
    /// update an edge to every advertised destination that ALSO advertises
    /// `idx1` back (a mutual link), introducing a placeholder node for a
    /// not-yet-known destination, and pruning edges `idx1` no longer
    /// advertises. Mirrors zenoh's edge-rebuild loop (`network.rs:742-783`):
    /// an edge exists iff both endpoints advertise the link.
    fn rebuild_edges(&mut self, idx1: NodeIndex) {
        let zid1 = self.graph[idx1].zid.clone();
        let link_zids: Vec<Zid> = self.graph[idx1].links.keys().cloned().collect();

        // add / update mutual edges; introduce unknown destinations so a
        // later mutual advertisement can complete the edge.
        for dest in &link_zids {
            match self.get_idx(dest) {
                Some(idx2) => {
                    if idx2 != idx1 && self.graph[idx2].links.contains_key(&zid1) {
                        self.update_edge(idx1, idx2);
                    }
                }
                None => {
                    self.ensure_node(dest.clone());
                }
            }
        }

        // prune edges to neighbours `idx1` no longer advertises.
        let mut stale = Vec::new();
        let mut walker = self.graph.neighbors_undirected(idx1).detach();
        while let Some((edge, neighbour)) = walker.next(&self.graph) {
            if !link_zids.contains(&self.graph[neighbour].zid) {
                stale.push(edge);
            }
        }
        for edge in stale {
            self.graph.remove_edge(edge);
        }
    }

    /// Set the petgraph edge weight between two mutually-linked nodes. The
    /// weight is the stronger of the two advertised directions (or the
    /// default when neither is explicit), plus a deterministic sub-1%
    /// jitter derived from the ordered zid pair so equal-cost paths break
    /// ties identically on every peer. Mirrors zenoh `update_edge`
    /// (`network.rs:424-455`). `DefaultHasher::new()` is fixed-seed, so the
    /// jitter is reproducible across processes.
    fn update_edge(&mut self, idx1: NodeIndex, idx2: NodeIndex) {
        use std::hash::Hasher;

        let zid1 = self.graph[idx1].zid.clone();
        let zid2 = self.graph[idx2].zid.clone();

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        if zid1 > zid2 {
            hasher.write(zid2.as_slice());
            hasher.write(zid1.as_slice());
        } else {
            hasher.write(zid1.as_slice());
            hasher.write(zid2.as_slice());
        }

        let w1 = self.graph[idx1]
            .links
            .get(&zid2)
            .filter(|w| w.is_set())
            .map(LinkEdgeWeight::value);
        let w2 = self.graph[idx2]
            .links
            .get(&zid1)
            .filter(|w| w.is_set())
            .map(LinkEdgeWeight::value);
        let w = match (w1, w2) {
            (None, None) => LinkEdgeWeight::DEFAULT,
            (None, Some(b)) => b,
            (Some(a), None) => a,
            (Some(a), Some(b)) => a.max(b),
        };

        let jitter = 1.0 + 0.01 * ((hasher.finish() as u32) as f64 / u32::MAX as f64);
        self.graph.update_edge(idx1, idx2, w as f64 * jitter);
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

    // ── c2b ingest ──────────────────────────────────────────────────

    use sce_forge_runtime::codec::SceBytes;
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;

    /// Build a LinkState entry. `options` is unused by the ingest (it reads
    /// the typed `Option` fields, not the flag byte), so it is left 0.
    fn entry(
        psid: u64,
        sn: u64,
        zid: Option<&[u8]>,
        whatami: Option<u8>,
        links: &[u64],
    ) -> LinkstateOwned {
        LinkstateOwned {
            options: 0,
            psid,
            sn,
            zid_len: zid.map(|z| z.len() as u64),
            zid: zid.map(|z| SceBytes::from_slice(z).unwrap()),
            whatami,
            num_locators: None,
            locators: None,
            links_len: links.len() as u64,
            links: links.iter().map(|&p| LinkstateLink { psid: p }).collect(),
            weights: None,
        }
    }

    fn list(entries: Vec<LinkstateOwned>) -> LinkstateListOwned {
        LinkstateListOwned {
            num_link_states: entries.len() as u64,
            link_states: entries,
        }
    }

    #[test]
    fn ingest_adds_node_and_learns_mapping() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        let changes = net.ingest_linkstate_list(
            link,
            list(vec![entry(10, 5, Some(&zid(0xAA)), Some(2), &[])]),
        );
        assert_eq!(changes.updated, vec![zid(0xAA)]);
        let node = net.get_node(&zid(0xAA)).expect("node added");
        assert_eq!(node.sn, 5);
        assert_eq!(node.whatami, Some(2));
        // the source link learned psid 10 -> 0xAA.
        assert_eq!(net.get_link(link).unwrap().get_zid(10), Some(&zid(0xAA)));
    }

    #[test]
    fn ingest_sn_staleness_gate() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        net.ingest_linkstate_list(link, list(vec![entry(10, 5, Some(&zid(0xAA)), None, &[])]));
        // a duplicate (same sn) is ignored.
        let dup = net.ingest_linkstate_list(link, list(vec![entry(10, 5, None, None, &[])]));
        assert!(dup.updated.is_empty(), "stale/duplicate sn ignored");
        assert_eq!(net.get_node(&zid(0xAA)).unwrap().sn, 5);
        // a strictly-newer sn updates.
        let newer = net.ingest_linkstate_list(link, list(vec![entry(10, 6, None, None, &[])]));
        assert_eq!(newer.updated, vec![zid(0xAA)]);
        assert_eq!(net.get_node(&zid(0xAA)).unwrap().sn, 6);
    }

    #[test]
    fn ingest_drops_entry_with_invalid_whatami() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        // whatami=3 is not a valid single role -> the entry is dropped.
        let changes = net.ingest_linkstate_list(
            link,
            list(vec![entry(10, 5, Some(&zid(0xAA)), Some(3), &[])]),
        );
        assert!(changes.updated.is_empty());
        assert!(net.get_node(&zid(0xAA)).is_none());
    }

    #[test]
    fn ingest_resolves_link_psids_to_zid_edges() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        // A (psid 1 -> 0xAA) appears before B, so B's link psid 1 resolves
        // against the mapping A registered earlier in the same list.
        net.ingest_linkstate_list(
            link,
            list(vec![
                entry(1, 5, Some(&zid(0xAA)), Some(2), &[]),
                entry(2, 5, Some(&zid(0xBB)), Some(2), &[1]),
            ]),
        );
        let b = net.get_node(&zid(0xBB)).expect("node B added");
        assert_eq!(b.links.len(), 1);
        let weight = b.links.get(&zid(0xAA)).expect("edge B->A resolved");
        assert_eq!(weight.value(), 100, "no weights block => default");
        assert!(!weight.is_set());
    }

    #[test]
    fn ingest_from_unknown_link_is_dropped() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        // link id 99 was never registered.
        let changes =
            net.ingest_linkstate_list(99, list(vec![entry(10, 5, Some(&zid(0xAA)), None, &[])]));
        assert!(changes.updated.is_empty());
        assert!(net.get_node(&zid(0xAA)).is_none());
    }

    // ── c2c edge rebuild ────────────────────────────────────────────

    use wz_codecs::linkstate_weight::LinkstateWeight;

    fn entry_weighted(
        psid: u64,
        sn: u64,
        zid: Option<&[u8]>,
        whatami: Option<u8>,
        links: &[u64],
        weights: &[u16],
    ) -> LinkstateOwned {
        let mut e = entry(psid, sn, zid, whatami, links);
        e.weights = Some(
            weights
                .iter()
                .map(|&w| LinkstateWeight { weight: w })
                .collect(),
        );
        e
    }

    #[test]
    fn edge_forms_only_on_mutual_advertisement() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        // learn psid 2 -> 0xBB (B, no links yet)
        net.ingest_linkstate_list(
            link,
            list(vec![entry(2, 1, Some(&zid(0xBB)), Some(2), &[])]),
        );
        // A advertises a link to B, but B has not advertised A back.
        net.ingest_linkstate_list(
            link,
            list(vec![entry(1, 1, Some(&zid(0xAA)), Some(2), &[2])]),
        );
        assert_eq!(net.edge_count(), 0, "one-sided link => no edge");
        // B advertises a link back to A => mutual => the edge forms.
        net.ingest_linkstate_list(link, list(vec![entry(2, 2, None, Some(2), &[1])]));
        assert_eq!(net.edge_count(), 1, "mutual link => edge");
        assert!(net.edge_weight(&zid(0xAA), &zid(0xBB)).is_some());
    }

    #[test]
    fn edge_pruned_when_link_no_longer_advertised() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        net.ingest_linkstate_list(
            link,
            list(vec![entry(2, 1, Some(&zid(0xBB)), Some(2), &[])]),
        );
        net.ingest_linkstate_list(
            link,
            list(vec![entry(1, 1, Some(&zid(0xAA)), Some(2), &[2])]),
        );
        net.ingest_linkstate_list(link, list(vec![entry(2, 2, None, Some(2), &[1])]));
        assert_eq!(net.edge_count(), 1);
        // A re-advertises with no links => the edge is pruned.
        net.ingest_linkstate_list(link, list(vec![entry(1, 2, None, Some(2), &[])]));
        assert_eq!(net.edge_count(), 0, "dropped link => edge pruned");
    }

    #[test]
    fn edge_weight_is_max_of_both_directions() {
        let mut net = LinkstateNetwork::new(zid(0x01), 2);
        let link = net.add_link(zid(0x07));
        net.ingest_linkstate_list(
            link,
            list(vec![entry(2, 1, Some(&zid(0xBB)), Some(2), &[])]),
        );
        // A->B weight 50.
        net.ingest_linkstate_list(
            link,
            list(vec![entry_weighted(
                1,
                1,
                Some(&zid(0xAA)),
                Some(2),
                &[2],
                &[50],
            )]),
        );
        // B->A weight 80 => mutual; the edge takes max(50, 80) = 80 + jitter.
        net.ingest_linkstate_list(
            link,
            list(vec![entry_weighted(2, 2, None, Some(2), &[1], &[80])]),
        );
        let w = net
            .edge_weight(&zid(0xAA), &zid(0xBB))
            .expect("edge present");
        assert!(
            (80.0..=80.8).contains(&w),
            "max(50,80)=80 plus sub-1% jitter, got {w}"
        );
    }
}
