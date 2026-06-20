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
//! with psid<->zid mappings, c2b the
//! [`LinkstateNetwork::ingest_linkstate_list`] node update under the
//! sn-staleness gate, c2c the mutual-link edge rebuild (`update_edge`), d
//! the spanning-tree computation (`compute_trees`), and (c3c-3 D3) the
//! [`remove_detached_nodes`](LinkstateNetwork::remove_detached_nodes) GC
//! that prunes nodes no longer reachable from self once a link drops or an
//! advertisement is withdrawn (zenoh `network.rs:786,948,990`).
//!
//! EXPLICITLY DEFERRED (tracked, not silently dropped):
//! - gossip / autoconnect propagation, locator ingest, and the
//!   `local_mappings` forwarding table. (The receive-side onward re-flood
//!   `propagate_link_states`, `network.rs:804`, is DONE: the graph supplies
//!   the [`build_linkstate_split`] payload builder — `new` nodes full,
//!   `updated` nodes links-only, the D4 `Details` split — and the per-face
//!   re-flood lives in the driver `linkstate_forward::propagate`, R311ra+sl.)
//! - the real handshake `whatami` (the driver currently records every
//!   peer-mesh neighbour as Peer).
//!
//! Drop observability (E2): a dropped ingest entry — an unresolvable psid /
//! link / zid, an invalid whatami — is now surfaced through the `log` facade
//! (wz's logging SSOT; zenoh `tracing::error!`s the same sites). `error!` for
//! an unresolvable reference (a protocol inconsistency), `warn!` for a
//! host-validation drop of malformed input, `debug!` for a GC prune. A no-op
//! without a logger backend; an operator who installs one sees why a peer or
//! edge silently failed to appear.
//!
//! This crate is pulled only by wz-runtime-tokio's `routing-peer` feature
//! (AP/full-node mesh routing; absent from the MCU footprint). Backed by
//! `petgraph` 0.6 (`StableUnGraph`, matching zenoh's own petgraph), so node
//! indices stay stable across removals.

use std::collections::HashMap;
use std::num::NonZeroU16;

use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableUnGraph;
use sce_forge_runtime::codec::{SceBytes, SceString};
use wz_codecs::linkstate::LinkstateOwned;
use wz_codecs::linkstate_link::LinkstateLink;
use wz_codecs::linkstate_list::LinkstateListOwned;
use wz_codecs::linkstate_weight::LinkstateWeight;
use wz_codecs::locator::{LocatorOwned, MAX_LOCATORS_PER_NODE, MAX_LOCATOR_LEN};

/// The node-role type, re-exported from `wz-codecs` (the SSOT). The graph keys
/// a node's role on this typed enum; the former `WHATAMI_*` byte constants and
/// the `is_valid_whatami` predicate are subsumed by [`WhatAmI`] and its
/// `TryFrom<u8>` (the codec carries the raw byte on the wire; the ingest
/// validates it through the type, so an out-of-set role is unrepresentable in
/// the graph rather than guarded by a hand-rolled match).
pub use wz_codecs::whatami::WhatAmI;

/// Maximum zid length in bytes (zenoh `ZenohIdProto::MAX_SIZE`). zenoh
/// rejects an oversized zid at DECODE (the zid codec caps at this); the wz
/// codec carries the raw bytes without that check, so the ingest discharges
/// the host-validation obligation (the same contract as the `whatami` range
/// check) by dropping a longer zid. Keeping every `Node.zid` <= 16 by
/// construction is also what makes the `build_linkstate_list` re-encode
/// infallible.
pub const ZENOHID_MAX_SIZE: usize = 16;

/// LinkState `options` flag bits (zenoh `linkstate.rs:20-23`): which optional
/// fields a built LinkState carries. P=zid, W=whatami, L=locators, H=link
/// weights. L gates a node's advertised reachability locators — the gossip
/// payload a discovering peer dials (zenoh `make_link_state` `locators` field,
/// `network.rs:336-341`).
const OPT_P: u8 = 0x01;
const OPT_W: u8 = 0x02;
const OPT_L: u8 = 0x04;
const OPT_H: u8 = 0x08;

/// The sub-1% tie-break budget the edge jitter rides on (zenoh
/// `network.rs:453`): equal base-weight edges differ by at most this
/// fraction so Bellman-Ford breaks ties deterministically.
const JITTER_FRACTION: f64 = 0.01;

/// The wire `psid` for a local node — its petgraph `NodeIndex` as the
/// compact integer a peer references the node by (zenoh `idx.index()`).
/// Named once so the TX build does not re-spell the `as u64` cast.
fn local_psid(idx: NodeIndex) -> u64 {
    idx.index() as u64
}

/// Assemble a `LinkStateList` from its entries, deriving `num_link_states`
/// from the vec length — the single SSOT for the list tail, so the count can
/// never desync from the entry count. Shared by every list builder
/// ([`build_linkstate_list`](LinkstateNetwork::build_linkstate_list) /
/// [`build_linkstate_split`](LinkstateNetwork::build_linkstate_split)). zenoh
/// `make_msg` writes the list the same way (`network.rs:355-357`).
fn into_list(link_states: Vec<LinkstateOwned>) -> LinkstateListOwned {
    LinkstateListOwned {
        num_link_states: link_states.len() as u64,
        link_states,
    }
}

/// Project a node's host locators (`&[String]`) into the codec's owned
/// `LocatorOwned` list for a TX entry, capping against the codec's own wire
/// bounds. Returns `None` when the node advertises no usable locator — the
/// caller then leaves the `L` option clear, exactly as a node with no locators
/// emits no locator field. The TX inverse of [`locators_from_wire`].
///
/// The two caps are a RUNTIME boundary check, not a by-construction invariant
/// like the zid one ([`make_link_state`] re-encodes `node.zid` with an
/// `expect`, since every graph zid is `<= 16` by construction): a locator is an
/// arbitrary host string (a deploy listen address, or a peer's wire bytes) with
/// no upstream length/count guarantee, so the obligation to keep the wire within
/// what a no-alloc receiver can decode is discharged HERE — the producer-side
/// analog of the ingest's oversized-zid drop. Both bounds are sourced from the
/// codec ([`MAX_LOCATOR_LEN`] = the `SceString<N>` width, [`MAX_LOCATORS_PER_NODE`]
/// = the list `max-count`), so this never hand-copies a literal that could
/// silently drift from the generated type.
fn locators_to_wire(locators: &[String]) -> Option<Vec<LocatorOwned>> {
    let owned: Vec<LocatorOwned> = locators
        .iter()
        .filter_map(|loc| {
            if loc.len() > MAX_LOCATOR_LEN {
                log::warn!(
                    "dropping over-long locator ({} bytes, cap {MAX_LOCATOR_LEN}) \
                     from a link-state entry",
                    loc.len()
                );
                return None;
            }
            // On the alloc (AP) backing this crate targets, `from_view` is
            // infallible (the `> MAX_LOCATOR_LEN` guard above is what enforces
            // the wire bound); on a no-alloc backing it would reject past `N`,
            // so the `?` keeps that path correct too.
            Some(LocatorOwned {
                locator_len: loc.len() as u64,
                locator: SceString::from_view(loc).ok()?,
            })
        })
        .take(MAX_LOCATORS_PER_NODE)
        .collect();
    (!owned.is_empty()).then_some(owned)
}

/// Project a decoded entry's `LocatorOwned` list back into host `String`s for
/// the graph `Node.locators`. Returns `None` for an absent OR empty list, so a
/// node's stored locators are never `Some(empty)` (a degenerate "advertises
/// zero locators" state). The RX inverse of [`locators_to_wire`].
///
/// DIVERGENCE from zenoh on the empty case: zenoh sets `L` whenever
/// `locators.is_some()` INCLUDING `Some([])`, and on update does
/// `if ls.locators.is_some() { node.locators = ls.locators }` — so a `Some([])`
/// CLEARS a node's locators (`network.rs:713-716`). wz collapses `Some([])` to
/// `None` here, which under the apply step's preserve-on-None rule instead KEEPS
/// the prior locators. The divergence is unreachable from a wz producer
/// ([`locators_to_wire`] never emits `Some([])` — an empty list returns `None`,
/// leaving `L` clear), so it only differs for a peer that explicitly wires an
/// empty `L`; wz treats that as "no new locators" rather than "clear", which is
/// the safer reading for discovery data.
fn locators_from_wire(locators: Option<Vec<LocatorOwned>>) -> Option<Vec<String>> {
    let strings: Vec<String> = locators?
        .into_iter()
        .map(|loc| loc.locator.as_str().to_string())
        .collect();
    (!strings.is_empty()).then_some(strings)
}

/// A routing identity — a zenoh zid (1..=16 bytes). Stored as a fixed 16-byte
/// zero-padded buffer plus a length, so it is no-alloc (`Copy`) and the
/// edge-jitter tie-break hashes the buffer directly. The wz mirror of zenoh
/// `ZenohIdProto` (a fixed buffer + size), replacing the prior `Vec<u8>`.
///
/// CANONICAL invariant: `bytes[len..]` is always zero (the constructor
/// guarantees it). This makes the derived `Ord` — compare `bytes`
/// lexicographically, then `len` — byte-for-byte identical to the ordering of
/// the trimmed `Vec<u8>` it replaces: a shorter zid that is a zero-extended
/// prefix of a longer one compares equal on `bytes` and then orders BEFORE it
/// on `len`, exactly as `Vec<u8>` orders a prefix before its extension. So the
/// deterministic cross-implementation jitter tie-break with a zenohd peer
/// (`update_edge`, which orders the pair by `Ord` then hashes [`le16`](Self::le16))
/// is unchanged by the representation switch.
///
/// Cross-impl note: this equivalence is stated against the OLD `Vec<u8>` (the
/// thing being replaced — exact). The load-bearing property is equivalence to
/// ZENOH, whose `ZenohIdProto` Ord is lexicographic over the 16-byte LE array.
/// Both `Zid` and the old `Vec<u8>` agree with zenoh for every CANONICAL wire
/// zid, because zenoh's codec trims trailing zeros (`size()`), so a received
/// zid never has a trailing-zero byte — the only inputs where a zero-extended
/// prefix could order differently. A non-canonical self zid (a handshake
/// `Vec<u8>` with a trailing zero) is the one latent corner; the handshake
/// supplies canonical zids, so it is unreachable today.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Zid {
    bytes: [u8; 16],
    len: u8,
}

impl Zid {
    /// The maximum zid length (zenoh `ZenohIdProto::MAX_SIZE`).
    pub const MAX_SIZE: usize = 16;

    /// From TRUSTED, already-canonical bytes — this node's own zid, or a
    /// handshake neighbour's — infallible, truncated to 16 and canonically
    /// zero-padded. For an UNTRUSTED zid decoded off the wire use the
    /// validating `TryFrom<&[u8]>` / `TryFrom<Vec<u8>>` instead, which reject an
    /// empty / all-zero / oversized one rather than silently admitting or
    /// truncating it. A slice longer than 16 is truncated defensively (the wire
    /// ingest already rejects an oversized zid via `TryFrom` before it reaches
    /// here).
    pub fn from_slice(src: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        let len = src.len().min(Self::MAX_SIZE);
        bytes[..len].copy_from_slice(&src[..len]);
        Zid {
            bytes,
            len: len as u8,
        }
    }

    /// The trimmed zid bytes — the wire form (`to_le_bytes()[..size]`).
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The trimmed length (1..=16 for a real zid).
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the zid carries no bytes (only an empty/placeholder value).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The fixed 16-byte zero-padded form zenoh hashes for the edge-jitter
    /// tie-break (`ZenohIdProto::to_le_bytes()`).
    pub fn le16(&self) -> [u8; 16] {
        self.bytes
    }
}

impl core::fmt::Display for Zid {
    /// Lowercase per-byte hex in WIRE order — the bytes [`as_slice`](Self::as_slice)
    /// yields, e.g. `[0x1a, 0x2b]` renders `"1a2b"`. wz's single zid string form:
    /// [`Debug`](Self) wraps this in `Zid(..)`, and the demo's face logs print it.
    ///
    /// DIVERGES (deliberately) from zenoh `ZenohIdProto::Display`, which prints the
    /// bytes interpreted as a little-endian `u128` in hex with the leading zero
    /// stripped (so `[0x1a, 0x2b]` would render `"2b1a"`). wz does not need that
    /// form: zenoh's only use of it is turning a zid into a key expression
    /// (`From<ZenohIdProto> for OwnedKeyExpr`), a path wz has no analogue of. A wz
    /// zid is a routing identity shown only in diagnostics, where the wire-order
    /// hex an operator also reads in a packet dump is the more useful rendering.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for Zid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Zid({self})")
    }
}

impl AsRef<[u8]> for Zid {
    /// The trimmed wire bytes — the borrow form for an API expecting `&[u8]`
    /// (the session boundary, hashing, a codec). The same bytes as
    /// [`as_slice`](Self::as_slice).
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Why a byte slice is not a valid [`Zid`]. The zid size contract is zenoh's
/// `ZenohIdProto`: 1..=16 SIGNIFICANT bytes. The typed reject the validating
/// [`Zid`] `TryFrom` conversions return for an untrusted wire zid, mirroring the
/// two cases zenoh's `ZenohIdProto::try_from(&[u8])` rejects via `SizeError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZidError {
    /// No significant bytes — an empty slice OR an all-zero buffer. zenoh's
    /// u128-backed `ZenohIdProto` reports an all-zero id as size 0 (a zid is
    /// `NonZero` by construction), so both collapse to one reject; a conformant
    /// peer never sends either.
    Empty,
    /// More than [`Zid::MAX_SIZE`] (16) bytes — carries the offending length,
    /// like zenoh's `SizeError(size)`.
    Oversized(usize),
}

impl core::fmt::Display for ZidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZidError::Empty => write!(f, "zid has no significant (non-zero) bytes"),
            ZidError::Oversized(n) => {
                write!(f, "zid is {n} bytes, over the {} max", Zid::MAX_SIZE)
            }
        }
    }
}

impl std::error::Error for ZidError {}

impl TryFrom<&[u8]> for Zid {
    type Error = ZidError;

    /// The VALIDATING wire-bytes -> zid conversion (the UNTRUSTED path): an
    /// empty / all-zero slice, or one over [`MAX_SIZE`](Self::MAX_SIZE), is
    /// rejected — exactly as zenoh `ZenohIdProto::try_from(&[u8])` rejects via
    /// `SizeError`. Use this for any zid decoded off the wire; for a trusted,
    /// already-canonical zid (self / a handshake neighbour) use the infallible
    /// [`from_slice`](Self::from_slice). Replaces the prior infallible
    /// `From<&[u8]>`, whose silent truncation made an over-length zid a
    /// representable illegal state.
    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        // Size first (matches zenoh's size-checked-first order), then the
        // all-zero / empty check (`all` is vacuously true for an empty slice).
        if src.len() > Self::MAX_SIZE {
            return Err(ZidError::Oversized(src.len()));
        }
        if src.iter().all(|&b| b == 0) {
            return Err(ZidError::Empty);
        }
        Ok(Zid::from_slice(src))
    }
}

impl TryFrom<Vec<u8>> for Zid {
    type Error = ZidError;

    /// The session / handshake layer carries a peer zid as `Vec<u8>`; the
    /// validating boundary conversion into the routing identity (delegates to
    /// the slice form).
    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        Zid::try_from(src.as_slice())
    }
}

/// A local link id (the index the runtime assigns a peer face).
pub type LinkId = usize;

/// A peer-state id — the compact integer a peer uses to reference a node
/// inside its `LinkStateList` (zenoh `psid`). Resolved to a global [`Zid`]
/// through the receiving [`Link`]'s mapping.
pub type Psid = u64;

/// A received link-state entry after pass 1 of
/// `convert_to_local_link_states` (its own zid resolved + mapping
/// registered), still carrying its raw psid-space `links` / `weights` for
/// pass 2 to resolve. A named struct (not a tuple) so the fields cannot be
/// transposed — and to match [`LocalLinkState`], the pass-2 output.
struct ResolvedEntry {
    zid: Zid,
    whatami: WhatAmI,
    sn: u64,
    links: Vec<LinkstateLink>,
    weights: Option<Vec<LinkstateWeight>>,
    locators: Option<Vec<String>>,
}

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

    /// The raw wire value — the explicit value, or 0 (the "no weight"
    /// sentinel) if unset. The TX inverse of [`from_raw`](Self::from_raw),
    /// mirroring zenoh `LinkEdgeWeight::as_raw` (used by `make_link_state`).
    pub fn as_raw(&self) -> u16 {
        self.0.map(NonZeroU16::get).unwrap_or(0)
    }

    /// Whether an explicit weight was advertised.
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

/// A node (vertex) in the topology graph — one peer's advertised state.
/// Mirrors zenoh `Node` (`network.rs:56-62`). `whatami` is the typed
/// [`WhatAmI`] role (`None` until a link-state for the node arrives); the wire
/// codec carries the raw role byte, and the ingest validates it into the type,
/// so an out-of-set role is unrepresentable here. `locators` stays the codec's
/// host type (UTF-8 strings).
#[derive(Debug, Clone)]
pub struct Node {
    pub zid: Zid,
    pub whatami: Option<WhatAmI>,
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

/// Which fields of a node's `LinkState` a TX entry carries — the wz mirror of
/// zenoh `Details` (`network.rs:49`), narrowed to the field combinations wz
/// emits. An ENUM, not a `(zid, links, locators)` bool triple, so the
/// meaningless "neither zid nor links" combo is unrepresentable (the project's
/// make-illegal-states-unrepresentable rule). Each variant is one of zenoh's
/// selective re-advertisements:
/// - [`Full`](Self::Full) (zid + links + locators) — a new node: the receiver
///   learns its psid<->zid mapping, its links, AND its dial locators
///   ([`build_linkstate_list`](LinkstateNetwork::build_linkstate_list), the
///   `new` half of [`build_linkstate_split`](LinkstateNetwork::build_linkstate_split)).
/// - [`LinksOnly`](Self::LinksOnly) (links, no zid, no locators) — an updated
///   node the receiver already mapped: omit the ~16-byte zid, re-advertise just
///   its links/whatami (the D4 propagate optimisation; the receiver resolves the
///   omitted zid from the psid it learned earlier, and KEEPS the locators it
///   learned when the node was new — the ingest's preserve-on-None rule).
/// - [`ZidOnly`](Self::ZidOnly) (zid, no links, no locators) — a newly-linked
///   neighbour announced to EXISTING peers so a sibling entry referencing it by
///   psid resolves, without re-sending the neighbour's own (irrelevant to them)
///   links — the first entry of zenoh `add_link`'s 2-entry delta
///   (`network.rs:873-890`),
///   [`build_link_added_delta`](LinkstateNetwork::build_link_added_delta).
///
/// Locators ride [`Full`](Self::Full) only — a node's locators are advertised
/// when it is first introduced (a new neighbour's bootstrap full flood, and the
/// `new` half of a propagation), and the ingest's preserve-on-None rule keeps
/// them across the links-only updates that follow. A late-joining face is
/// bootstrapped with the FULL topology
/// ([`build_linkstate_list`](LinkstateNetwork::build_linkstate_list), every node
/// [`Full`](Self::Full)), so it learns this peer's and its direct neighbours'
/// locators (the per-source gate below withholds distant ones).
///
/// `Full` REQUESTS a node's locators, but the gossip-policy filter (zenoh's
/// two-part `gossip` gate) narrows which actually ride the wire:
/// - per SOURCE node: [`make_link_state`](LinkstateNetwork::make_link_state)
///   admits a node's locators only when
///   [`propagate_locators`](LinkstateNetwork::propagate_locators) does — self or
///   a direct neighbour — so a distant multihop node's locators are withheld
///   (the A4b port of zenoh `hat/p2p_peer/gossip.rs:281`).
/// - per TARGET face: the driver's link-state fan-out skips a face whose role is
///   outside the `gossip_target` set (a client), zenoh's per-target
///   `send_on_link` (the A4a port, threaded on the handshake whatami — "F1").
///
/// Still pending (zenoh has it, wz does not yet): the `gossip_multihop` flag
/// that relays every node's locators across all hops, and config-sourcing the
/// gossip target per local whatami.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Details {
    Full,
    LinksOnly,
    ZidOnly,
}

impl Details {
    /// `(carry_zid, carry_links, carry_locators)` — the `LinkState` field gates
    /// this variant selects, the form [`make_link_state`](LinkstateNetwork::make_link_state)
    /// consumes (mirroring zenoh's `Details { zid, links, locators }` bool fields).
    fn fields(self) -> (bool, bool, bool) {
        match self {
            Details::Full => (true, true, true),
            Details::LinksOnly => (false, true, false),
            Details::ZidOnly => (true, false, false),
        }
    }
}

/// A LinkState resolved from psid-space into zid-space — the intermediate
/// the ingest produces before applying it to the graph. Mirrors zenoh
/// `LocalLinkState` (`network.rs:96-103`). `locators` is `None` when the entry
/// carried no `L` field — a links-only re-advertisement — and the apply step
/// then KEEPS the node's existing locators (preserve-on-None).
struct LocalLinkState {
    sn: u64,
    zid: Zid,
    whatami: WhatAmI,
    links: HashMap<Zid, LinkEdgeWeight>,
    locators: Option<Vec<String>>,
}

/// What a LinkStateList ingest changed, split the way zenoh's re-flood needs:
/// `new` = nodes seen for the first time with full state (a fresh insert, or a
/// placeholder getting its first real link-state — `oldsn == 0`); `updated` =
/// nodes already mapped that re-advertised (`oldsn > 0`); `removed` = nodes the
/// ensuing reachability prune dropped. The driver (step c3) re-floods `new`
/// FULL and `updated` LINKS-ONLY (the D4 `Details` split — zenoh
/// `network.rs:645-678`), and purges each `removed` node's subscription
/// interest (zenoh `pubsub_remove_node` over `changes.removed_nodes`,
/// `hat/linkstate_peer/mod.rs:418-422`). A NARROWED subset of zenoh `Changes`
/// (`network.rs:110-114`, `(NodeIndex, Node)` pairs): wz carries only the zids
/// (the node payloads land when gossip needs them).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub new: Vec<Zid>,
    pub updated: Vec<Zid>,
    pub removed: Vec<Zid>,
}

/// A spanning tree rooted at one node, computed from THIS peer's vantage
/// (`self.idx`). `parent` is the next hop toward the root; `children` are
/// the nodes for which this peer is the next hop from the root; and
/// `directions[dest]` is the first hop from this peer toward `dest` along
/// the tree. Forwarding a message along its source's tree cannot loop —
/// a tree has no cycles. Mirrors zenoh `Tree` (`network.rs:116-121`).
#[derive(Debug, Clone, Default)]
pub struct Tree {
    pub parent: Option<NodeIndex>,
    pub children: Vec<NodeIndex>,
    pub directions: Vec<Option<NodeIndex>>,
}

/// The linkstate-peer topology graph. Mirrors zenoh `Network` (the
/// petgraph of `Node`s + the per-link state), narrowed to the routing
/// state c2 owns: the self node, the neighbour links, and their
/// psid<->zid mappings. The spanning trees + shortest-path distances
/// (zenoh's `trees` / `distances`) are step d.
pub struct LinkstateNetwork {
    idx: NodeIndex,
    graph: StableUnGraph<Node, f64>,
    /// Secondary index `zid -> NodeIndex` so `get_idx` is O(1) instead of
    /// the O(n) scan zenoh does over its `Copy` 16-byte ids. Maintained as
    /// an invariant by `insert_node` (the single node-insertion path) and
    /// `remove_detached_nodes` (the single node-removal path), which keep it
    /// in lockstep with the petgraph node set — zenoh needs no such index
    /// (its O(n) `get_idx` reads the graph directly), so this is wz's added
    /// bookkeeping obligation.
    idx_by_zid: HashMap<Zid, NodeIndex>,
    links: HashMap<LinkId, Link>,
    next_link_id: LinkId,
    /// Per-root spanning trees from this peer's vantage, indexed by the
    /// root node's `NodeIndex::index()` (sparse; gaps are default Trees).
    /// Rebuilt by `compute_trees`.
    trees: Vec<Tree>,
    /// Shortest-path distance from this peer to each node, indexed by
    /// `NodeIndex::index()`. The self-rooted Bellman-Ford result.
    distances: Vec<f64>,
}

impl LinkstateNetwork {
    /// A graph seeded with the local (self) node — sn starts at 1, as in
    /// zenoh `Network::new` (`network.rs:156-162`).
    pub fn new(self_zid: Zid, self_whatami: WhatAmI) -> Self {
        let mut graph = StableUnGraph::default();
        let idx = graph.add_node(Node {
            zid: self_zid,
            whatami: Some(self_whatami),
            locators: None,
            sn: 1,
            links: HashMap::new(),
        });
        let mut idx_by_zid = HashMap::new();
        idx_by_zid.insert(self_zid, idx);
        LinkstateNetwork {
            idx,
            graph,
            idx_by_zid,
            links: HashMap::new(),
            next_link_id: 0,
            // one (trivial) self-rooted tree + a zero self-distance, as in
            // zenoh `Network::new` (`network.rs:174-179`).
            trees: vec![Tree {
                parent: None,
                children: vec![],
                directions: vec![None],
            }],
            distances: vec![0.0],
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

    /// Set self's advertised dial locators (its listen addresses) on the self
    /// node, so they ride every FULL flood self originates — the wz analog of
    /// zenoh reading `runtime.get_locators()` for the self entry
    /// (`network.rs:337-339`). The driver calls this once at startup (before
    /// the first face registers, so the first flood already carries them). An
    /// empty list clears the advertisement (self emits no `L` field — the
    /// signature-stable default for a node that does not announce locators).
    pub fn set_self_locators(&mut self, locators: Vec<String>) {
        self.graph[self.idx].locators = (!locators.is_empty()).then_some(locators);
    }

    /// The dial locators a node has advertised, or `None` if it is unknown or
    /// has announced none. The discovery read a gossip/autoconnect consumer
    /// dials toward (the data this ingest populates).
    pub fn node_locators(&self, zid: &Zid) -> Option<&[String]> {
        self.get_idx(zid)
            .and_then(|idx| self.graph[idx].locators.as_deref())
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

    /// Find a node index by zid — an O(1) secondary-index lookup (the
    /// `zid -> NodeIndex` map kept by `insert_node`). zenoh does an O(n)
    /// scan (`network.rs:256`); the index avoids the compounding scan cost
    /// across `rebuild_edges` / ingest / the per-query accessors.
    pub fn get_idx(&self, zid: &Zid) -> Option<NodeIndex> {
        self.idx_by_zid.get(zid).copied()
    }

    /// Look up a node by zid.
    pub fn get_node(&self, zid: &Zid) -> Option<&Node> {
        self.get_idx(zid).map(|i| &self.graph[i])
    }

    /// This node's wire `psid` for `zid` (its petgraph `NodeIndex` as the
    /// compact local id, `local_psid`), or `None` if `zid` is unknown. The
    /// routing-context `node_id` a forwarder stamps on a data message it
    /// floods FROM `zid`'s spanning tree: each receiver remaps it back to a
    /// `zid` via its own link's `psid <-> zid` mapping (zenoh
    /// `get_local_context`, `network.rs:273`).
    pub fn local_psid_of(&self, zid: &Zid) -> Option<u64> {
        self.get_idx(zid).map(local_psid)
    }

    /// The single node-insertion path: add the node to the petgraph AND the
    /// `idx_by_zid` secondary index together, so the two never desync.
    fn insert_node(&mut self, node: Node) -> NodeIndex {
        let zid = node.zid;
        let idx = self.graph.add_node(node);
        self.idx_by_zid.insert(zid, idx);
        idx
    }

    /// Insert a node for `zid` if absent, returning its index (the upsert
    /// primitive the LinkStateList ingest in c2b builds on). A freshly
    /// inserted node has sn 0 / unknown whatami until a link-state for it
    /// arrives.
    pub fn ensure_node(&mut self, zid: Zid) -> NodeIndex {
        if let Some(i) = self.get_idx(&zid) {
            return i;
        }
        self.insert_node(Node {
            zid,
            whatami: None,
            locators: None,
            sn: 0,
            links: HashMap::new(),
        })
    }

    /// Register a new link to a neighbour and connect self to it in the
    /// graph, returning the link id. The runtime calls this when a peer
    /// face is established (step c3). Mirrors zenoh `add_link`
    /// (`network.rs:812-859`): introduce the neighbour node, record that
    /// self now links to it (bumping self's link-state sn), and form the
    /// edge if the neighbour already advertises self back.
    pub fn add_link(&mut self, peer_zid: Zid, peer_whatami: WhatAmI) -> LinkId {
        let id = self.next_link_id;
        self.next_link_id += 1;
        self.links.insert(id, Link::new(peer_zid));

        if self.get_idx(&peer_zid).is_none() {
            self.insert_node(Node {
                zid: peer_zid,
                whatami: Some(peer_whatami),
                locators: None,
                sn: 0,
                links: HashMap::new(),
            });
        }
        self.graph[self.idx]
            .links
            .insert(peer_zid, LinkEdgeWeight::default());
        self.graph[self.idx].sn += 1;
        self.rebuild_edges(self.idx);
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

    /// Remove a link (the peer face went down): drop the per-link mapping
    /// state, disconnect self from the neighbour in the graph (self no longer
    /// advertises the link, so the self<->neighbour edge is pruned and self's
    /// link-state sn is bumped), then GC every node the link's loss detached
    /// from the mesh. Returns the zids of those pruned nodes (the departed
    /// neighbour itself when it had no other path, plus anything reachable
    /// only through it). Mirrors zenoh `remove_link` (`network.rs:936-988`):
    /// self-side bookkeeping then `remove_detached_nodes`. An unknown link id
    /// is a no-op returning an empty vec.
    pub fn remove_link(&mut self, id: LinkId) -> Vec<Zid> {
        let link = match self.links.remove(&id) {
            Some(link) => link,
            None => return Vec::new(),
        };
        self.graph[self.idx].links.remove(&link.zid);
        self.graph[self.idx].sn += 1;
        self.rebuild_edges(self.idx);
        self.remove_detached_nodes()
    }

    /// GC every node no longer reachable from self over the ADVERTISEMENT
    /// graph, returning the pruned nodes' zids. Mirrors zenoh
    /// `remove_detached_nodes` (`network.rs:990-1013`): a DFS from `self.idx`
    /// following each visited node's advertised `links` (NOT the petgraph
    /// edges — reachability is over what nodes claim to link to, so a node is
    /// kept as long as a chain of advertisements leads to it), then any
    /// node the DFS never reached is removed. A node that left the mesh (its
    /// last advertiser dropped it, or the only link toward it went down)
    /// would otherwise linger as a ghost vertex — unbounded memory growth and
    /// topology divergence from a zenoh peer that did prune. Run after every
    /// topology mutation that can sever reachability: the ingest tail
    /// (`process_linkstates`) and `remove_link`.
    ///
    /// Unlike zenoh (which returns `(NodeIndex, Node)` pairs for gossip), wz
    /// returns just the zids — the only thing the driver needs to purge the
    /// pruned nodes' subscription interest. Keeps the `idx_by_zid` secondary
    /// index in lockstep: every node dropped from the graph is dropped from
    /// the index too (wz's removal-side invariant — see the field doc).
    fn remove_detached_nodes(&mut self) -> Vec<Zid> {
        use petgraph::visit::{VisitMap, Visitable};

        let mut dfs_stack = vec![self.idx];
        let mut visit_map = self.graph.visit_map();
        while let Some(node) = dfs_stack.pop() {
            if visit_map.visit(node) {
                // Collect first: the `links` borrow of `self.graph` must end
                // before `get_idx` borrows `self` again.
                let succ_zids: Vec<Zid> = self.graph[node].links.keys().cloned().collect();
                for succ_zid in succ_zids {
                    if let Some(succ) = self.get_idx(&succ_zid) {
                        if !visit_map.is_visited(&succ) {
                            dfs_stack.push(succ);
                        }
                    }
                }
            }
        }

        let mut removed = Vec::new();
        let mut removed_idxs: Vec<NodeIndex> = Vec::new();
        for idx in self.graph.node_indices().collect::<Vec<NodeIndex>>() {
            if !visit_map.is_visited(&idx) {
                if let Some(node) = self.graph.remove_node(idx) {
                    // GC event (zenoh debug!s the same, `network.rs:1008`): a
                    // node left the reachable mesh and is pruned.
                    log::debug!("pruning detached node {:?}", node.zid);
                    self.idx_by_zid.remove(&node.zid);
                    removed.push(node.zid);
                    removed_idxs.push(idx);
                }
            }
        }
        if !removed_idxs.is_empty() {
            self.scrub_trees(&removed_idxs);
        }
        removed
    }

    /// Drop every reference to a freed `NodeIndex` from the cached spanning
    /// trees + distances, maintaining the invariant: the trees NEVER reference
    /// an index that has left the graph. This is load-bearing for safety, not
    /// just tidiness — `StableUnGraph` REUSES a freed index on the next
    /// `add_node`, and the tree recompute is COALESCED onto a later tick (D2c),
    /// so a stale `trees` entry holding a freed index would, after a reuse,
    /// resolve via `node_weight` to a DIFFERENT live node and silently misroute
    /// a Push toward the wrong neighbour during the coalescing window. (The
    /// `node_weight` guard in the accessors only catches a still-absent index;
    /// it cannot catch a reused one.) Scrubbing the freed indices here leaves
    /// the trees consistent-but-possibly-incomplete — affected routes resolve
    /// to None (drop) until the tick recompute rebuilds them, exactly the
    /// bounded staleness D2c already accepts, and NEVER an aliased misroute.
    fn scrub_trees(&mut self, freed: &[NodeIndex]) {
        for &f in freed {
            // the tree ROOTED at a freed index is meaningless; a node that
            // reuses the index must not read the departed node's tree.
            if let Some(tree) = self.trees.get_mut(f.index()) {
                *tree = Tree::default();
            }
            if let Some(dist) = self.distances.get_mut(f.index()) {
                *dist = f64::INFINITY;
            }
        }
        for tree in &mut self.trees {
            tree.children.retain(|c| !freed.contains(c));
            if tree.parent.is_some_and(|p| freed.contains(&p)) {
                tree.parent = None;
            }
            // a freed index appearing as a direction VALUE (a first hop), or as
            // a direction SLOT (a destination), is nulled.
            for dir in &mut tree.directions {
                if dir.is_some_and(|d| freed.contains(&d)) {
                    *dir = None;
                }
            }
            for &f in freed {
                if let Some(slot) = tree.directions.get_mut(f.index()) {
                    *slot = None;
                }
            }
        }
    }

    /// Ingest a `LinkStateList` received on link `src_link_id`: learn its
    /// psid<->zid mappings, then apply the (zid-resolved) link-states to
    /// the graph under the sn-staleness gate. Returns the nodes it changed.
    /// Mirrors zenoh's receive path for the linkstate-peer (full-linkstate)
    /// mode — `convert_to_local_link_states` (`network.rs:457`) then the
    /// `link_states` full path (`network.rs:705-808`: node update + edge
    /// rebuild). NOT the `!full_linkstate` `process_linkstates_peer_to_peer`
    /// (that path does no edge rebuild); the linkstate-peer HAT sets
    /// `full_linkstate = true` (`hat/linkstate_peer/mod.rs:203`).
    pub fn ingest_linkstate_list(
        &mut self,
        src_link_id: LinkId,
        list: LinkstateListOwned,
    ) -> Changes {
        let local = self.convert_to_local_link_states(src_link_id, list);
        self.process_linkstates(local)
    }

    /// Build one node's `LinkState` keyed by its local `psid` (the petgraph
    /// `NodeIndex`), carrying exactly the fields [`details`](Details) selects:
    /// its links (each resolved to the neighbour's local psid) with weights when
    /// `details.links`, and its zid (so the receiver learns the psid<->zid
    /// mapping) when `details.zid`. whatami + sn ride every entry. Mirrors zenoh
    /// `make_link_state` (`network.rs:304-348`), whose `Details` likewise gates
    /// the links iteration and the zid field. The links-only / zid-only forms
    /// are the D4 selective-re-advertisement deltas (a node the receiver already
    /// mapped need not re-send its ~16-byte zid; a sibling need not re-send a
    /// new neighbour's links). Locators ride the FULL form only (a node's dial
    /// addresses, advertised when it is first introduced); the ingest's
    /// preserve-on-None rule keeps them across the links-only updates that follow.
    fn make_link_state(&self, idx: NodeIndex, details: Details) -> LinkstateOwned {
        let node = &self.graph[idx];
        let (want_zid, want_links, want_locators) = details.fields();
        // links: resolve each neighbour zid to its local psid, with a weight per
        // link (zenoh make_link_state, `network.rs:308-325`) — ONLY when the
        // variant carries links; an entry that omits links (a zid-only neighbour
        // announcement) leaves the list empty, like zenoh's `if details.links`.
        let mut links = Vec::new();
        let mut weights = Vec::new();
        let mut has_weight = false;
        if want_links {
            for (dest_zid, weight) in &node.links {
                if let Some(dest_idx) = self.get_idx(dest_zid) {
                    links.push(LinkstateLink {
                        psid: local_psid(dest_idx),
                    });
                    weights.push(LinkstateWeight {
                        weight: weight.as_raw(),
                    });
                    has_weight = has_weight || weight.is_set();
                } else {
                    // a link to an unknown node is an internal inconsistency: the
                    // graph holds an edge to a vertex it cannot index. Skip it
                    // rather than emit an unresolvable psid; zenoh error!s the
                    // same (`network.rs:317`).
                    log::error!("building linkstate: link dest {dest_zid:?} is not in the graph");
                }
            }
        }
        // locators: the node's dial addresses, carried only by the FULL form
        // (`want_locators`) and only when the node actually has some — a
        // links-only/zid-only re-advertisement omits them, and the receiver
        // keeps what it learned (the ingest's preserve-on-None rule). zenoh
        // `make_link_state` `network.rs:336-341` (self reads the live
        // `runtime.get_locators()`; wz stores self's locators on the self node,
        // so both self and others read `node.locators` uniformly here).
        // Even on the FULL form, a node's locators ride only when zenoh's
        // per-source `propagate_locators` gate admits it (self or a direct
        // neighbour) — a distant multihop node's reachability addresses are
        // withheld, so locators travel one hop (the A4b TX complement of A4a's
        // per-face gossip-target gate). `want_locators` selects the FULL form;
        // the gate then narrows which sources within it actually advertise.
        let locators = (want_locators && self.propagate_locators(idx))
            .then(|| node.locators.as_deref().and_then(locators_to_wire))
            .flatten();
        // options: P (zid) set iff the variant carries the zid (the codec gates
        // the zid field on P; a zid-omitting entry relies on the receiver's
        // existing psid->zid mapping). W (if whatami known) | L (if locators are
        // carried) | H (if a non-default weight was emitted) apply on top.
        let mut options = if want_zid { OPT_P } else { 0 };
        if node.whatami.is_some() {
            options |= OPT_W;
        }
        if locators.is_some() {
            options |= OPT_L;
        }
        if has_weight {
            options |= OPT_H;
        }
        LinkstateOwned {
            options,
            psid: local_psid(idx),
            sn: node.sn,
            zid_len: want_zid.then_some(node.zid.len() as u64),
            // every graph zid is <= ZENOHID_MAX_SIZE by construction (the
            // ingest drops an oversized wire zid; the handshake supplies a
            // valid self/neighbour zid), so this never exceeds capacity.
            zid: want_zid.then(|| {
                SceBytes::from_slice(node.zid.as_slice()).expect("graph zid is <= ZENOHID_MAX_SIZE")
            }),
            // the wire carries the raw API-form role byte; the node holds the
            // typed role, so project it back to the byte here at the codec edge.
            whatami: node.whatami.map(WhatAmI::to_api),
            num_locators: locators.as_ref().map(|l| l.len() as u64),
            locators,
            links_len: links.len() as u64,
            links,
            weights: has_weight.then_some(weights),
        }
    }

    /// Whether node `idx`'s dial locators may ride a FULL link-state entry this
    /// peer floods — zenoh `propagate_locators` (`hat/p2p_peer/gossip.rs:281`).
    /// True for self (this peer advertises its own listen addresses) and for a
    /// DIRECT neighbour (a node self holds a link to); a distant multihop node's
    /// locators are withheld, so reachability data travels one hop — a receiver
    /// learns a far node's locators from that node's OWN neighbour, not relayed
    /// across every hop.
    ///
    /// zenoh also rides every node's locators when `gossip_multihop` is set; wz
    /// has no such flag yet, so this is the non-multihop self-or-direct-neighbour
    /// form (zenoh's `gossip` enabled flag is implicitly true here — wz only
    /// builds a link-state when it gossips). The multihop flag is a later atom.
    fn propagate_locators(&self, idx: NodeIndex) -> bool {
        idx == self.idx
            || self.graph[self.idx]
                .links
                .contains_key(&self.graph[idx].zid)
    }

    /// Build the `LinkStateList` advertising THIS peer's full known topology,
    /// for flooding to neighbours (the TX counterpart of
    /// [`ingest_linkstate_list`](Self::ingest_linkstate_list)). Every graph
    /// node, full state. Mirrors zenoh `make_msg` over all nodes
    /// (`network.rs:350-365`).
    pub fn build_linkstate_list(&self) -> LinkstateListOwned {
        into_list(
            self.graph
                .node_indices()
                .map(|idx| self.make_link_state(idx, Details::Full))
                .collect(),
        )
    }

    /// Build the re-flood payload `propagate_link_states` (c3d-2) sends onward
    /// when an ingest changed a subset of the graph: `new` nodes carry FULL
    /// state (zid + links, so a receiver can map a psid it has not seen) and
    /// `updated` nodes carry LINKS-ONLY state (the D4 `Details` split — the
    /// receiver already mapped them when they were new, so the zid is omitted).
    /// New nodes are listed first so, within the single list, a links-only
    /// entry that happens to reference a brand-new node still resolves. Unknown
    /// zids are skipped. Mirrors zenoh `make_msg` over the `propagate_link_states`
    /// per-link `out` list (`network.rs:645-678`: new = `Details{zid:true}`,
    /// updated = `Details{zid:false}`).
    pub fn build_linkstate_split(&self, new: &[Zid], updated: &[Zid]) -> LinkstateListOwned {
        into_list(
            new.iter()
                .filter_map(|zid| self.get_idx(zid))
                .map(|idx| self.make_link_state(idx, Details::Full))
                .chain(
                    updated
                        .iter()
                        .filter_map(|zid| self.get_idx(zid))
                        .map(|idx| self.make_link_state(idx, Details::LinksOnly)),
                )
                .collect(),
        )
    }

    /// Build the 1-entry `[self LINKS-ONLY]` delta — self's own node entry with
    /// its links but no zid. This is what zenoh `remove_link` floods to all links
    /// on a link loss (`network.rs:952-962`), and what `add_link` sends existing
    /// links when the new neighbour was already known. Named once here so both
    /// driver flood paths share one construction (the self-links-only delta is one
    /// concept). Equivalent to `build_linkstate_split(&[], &[self_zid])` without
    /// the zid round-trip.
    pub fn build_self_links_delta(&self) -> LinkstateListOwned {
        into_list(vec![self.make_link_state(self.idx, Details::LinksOnly)])
    }

    /// Build the minimal delta zenoh `add_link` sends to its EXISTING links when
    /// self gains a NEW neighbour (`network.rs:873-890`): a 2-entry list —
    /// `[neighbour ZID-ONLY, self LINKS-ONLY]`. The neighbour entry carries only
    /// its zid (no links — the existing peers do not need a freshly-linked
    /// neighbour's links; the neighbour floods its own full state) so that self's
    /// links-only entry, which references the neighbour by psid, resolves against
    /// the just-registered mapping. The neighbour is listed FIRST so the mapping
    /// is registered before self's entry is resolved within the one list (the
    /// two-pass ingest tolerates either order, but this matches zenoh). If the
    /// neighbour is not in the graph the delta degrades to self's links-only
    /// entry alone.
    pub fn build_link_added_delta(&self, neighbour: &Zid) -> LinkstateListOwned {
        let mut entries = Vec::with_capacity(2);
        if let Some(n_idx) = self.get_idx(neighbour) {
            entries.push(self.make_link_state(n_idx, Details::ZidOnly));
        }
        entries.push(self.make_link_state(self.idx, Details::LinksOnly));
        into_list(entries)
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
        // A list from an unknown link is dropped (zenoh logs + returns
        // empty, `network.rs:469-476`).
        if !self.links.contains_key(&src_link_id) {
            log::error!("linkstate list received on unknown link {src_link_id}");
            return Vec::new();
        }

        // Pass 1 — register EVERY entry's psid->zid mapping before resolving
        // any link. zenoh is two-pass (`network.rs:479-517` register, then
        // `:519-556` resolve) precisely so a link referencing a node whose
        // entry appears LATER in the same list still resolves. A single-pass
        // resolve would drop such a link (e.g. self's own flood, where self's
        // entry lists links to neighbours whose entries follow it).
        let resolved: Vec<ResolvedEntry> = {
            let src_link = self
                .links
                .get_mut(&src_link_id)
                .expect("link present (checked above)");
            let mut resolved = Vec::with_capacity(list.link_states.len());
            for entry in list.link_states {
                // The entry's own zid: present (register the psid->zid
                // mapping) or referenced by a previously-learned psid.
                let zid = match entry.zid {
                    Some(bytes) => {
                        // host-validation obligation (like whatami below): zenoh
                        // rejects a non-conformant zid at decode (its
                        // `ZenohIdProto::try_from` enforces 1..=16 significant
                        // bytes); the wz codec carries the raw bytes, so the
                        // validating `Zid::try_from` drops an oversized OR an
                        // empty / all-zero one here, before it reaches the graph
                        // (the length-only guard this replaced admitted an empty
                        // zid as a len-0 identity).
                        let zid = match Zid::try_from(bytes.as_slice()) {
                            Ok(zid) => zid,
                            Err(e) => {
                                log::warn!("dropping linkstate entry (psid {}): {e}", entry.psid);
                                continue;
                            }
                        };
                        src_link.set_zid_mapping(entry.psid, zid);
                        zid
                    }
                    None => match src_link.get_zid(entry.psid) {
                        Some(zid) => *zid,
                        None => {
                            // unknown psid mapping -> drop entry (the node
                            // silently vanishes); zenoh error!s the same
                            // (`network.rs:507`).
                            log::error!(
                                "linkstate entry on link {src_link_id} has an unresolvable \
                                 node psid {} (no zid mapping)",
                                entry.psid
                            );
                            continue;
                        }
                    },
                };
                // whatami: absent defaults to Router; an out-of-set byte is
                // dropped (the c2 host-validation obligation — zenoh rejects it
                // at decode, the wz codec carries the raw byte and the typed
                // `WhatAmI::try_from` is the single validator).
                let whatami = match entry.whatami {
                    None => WhatAmI::Router,
                    Some(w) => match WhatAmI::try_from(w) {
                        Ok(role) => role,
                        Err(()) => {
                            log::warn!(
                                "dropping linkstate entry on link {src_link_id}: invalid whatami {w}"
                            );
                            continue;
                        }
                    },
                };
                resolved.push(ResolvedEntry {
                    zid,
                    whatami,
                    sn: entry.sn,
                    links: entry.links,
                    weights: entry.weights,
                    // a `None`/empty `L` field projects to `None`, which the
                    // apply step reads as "keep the node's existing locators".
                    locators: locators_from_wire(entry.locators),
                });
            }
            resolved
        };

        // Pass 2 — every mapping is now registered; resolve each entry's link
        // psids to zids, attaching the advertised weight (or the default when
        // no weights block). zenoh `network.rs:519-556`.
        let src_link = self
            .links
            .get(&src_link_id)
            .expect("link present (checked above)");
        resolved
            .into_iter()
            .map(
                |ResolvedEntry {
                     zid,
                     whatami,
                     sn,
                     links: entry_links,
                     weights,
                     locators,
                 }| {
                    let mut links = HashMap::with_capacity(entry_links.len());
                    for (i, link) in entry_links.iter().enumerate() {
                        if let Some(dst) = src_link.get_zid(link.psid) {
                            let weight = weights
                                .as_ref()
                                .and_then(|ws| ws.get(i))
                                .map(|w| LinkEdgeWeight::from_raw(w.weight))
                                .unwrap_or_default();
                            links.insert(*dst, weight);
                        } else {
                            // unknown link psid -> drop that edge; zenoh error!s
                            // the same (`network.rs:538`).
                            log::error!(
                                "linkstate entry on link {src_link_id} references an \
                                 unresolvable link psid {}",
                                link.psid
                            );
                        }
                    }
                    LocalLinkState {
                        sn,
                        zid,
                        whatami,
                        links,
                        locators,
                    }
                },
            )
            .collect()
    }

    /// Apply zid-resolved link-states to the graph under the sn-staleness
    /// gate, rebuild the changed nodes' edges, then GC any node the update
    /// detached from the mesh. A new node is added; an existing node is
    /// updated only if the advertised sn is strictly newer (a stale or
    /// duplicate advertisement is ignored). Mirrors the `full_linkstate`
    /// `link_states` node-update + edge-rebuild + trailing
    /// `remove_detached_nodes` (`network.rs:728-808`) minus only the
    /// `propagate_link_states` receive-side re-flood (a tracked deferral —
    /// see the module doc). Returns the changed and the pruned nodes' zids:
    /// a node the prune removed is dropped from `updated` (zenoh
    /// `network.rs:787-788` `new_nodes.retain` / `updated_nodes.retain`).
    fn process_linkstates(&mut self, states: Vec<LocalLinkState>) -> Changes {
        let mut changes = Changes::default();
        for ls in states {
            // `is_new` = the receiver does not yet have this node's full state,
            // so the re-flood must carry its zid: a fresh insert, or an
            // existing node whose `sn` was still 0 (a placeholder that never
            // had a real link-state). zenoh `oldsn == 0` (network.rs:717).
            let (idx, is_new) = match self.get_idx(&ls.zid) {
                None => (
                    self.insert_node(Node {
                        zid: ls.zid,
                        whatami: Some(ls.whatami),
                        // a fresh node takes whatever locators the entry carried
                        // (`None` if it was a links-only introduction — a later
                        // FULL entry for it then supplies them).
                        locators: ls.locators,
                        sn: ls.sn,
                        links: ls.links,
                    }),
                    true,
                ),
                Some(idx) => {
                    let node = &mut self.graph[idx];
                    // sn-staleness gate (zenoh network.rs:580): ignore a
                    // not-newer advertisement.
                    if node.sn >= ls.sn {
                        continue;
                    }
                    let was_placeholder = node.sn == 0;
                    node.sn = ls.sn;
                    node.links = ls.links;
                    // preserve-on-None: a links-only re-advertisement (no `L`
                    // field) keeps the locators learned when the node was new;
                    // only an entry that actually carries locators overwrites
                    // them. zenoh `network.rs:714-715`.
                    if ls.locators.is_some() {
                        node.locators = ls.locators;
                    }
                    (idx, was_placeholder)
                }
            };
            // A node this entry advertises but we did not yet know is introduced
            // as a placeholder and must re-flood FULL so a downstream learns it
            // (zenoh `new_nodes.push`, `network.rs:763`). Deduped — it may also
            // carry its own entry later in the list (processed as `new` then).
            for placeholder in self.rebuild_edges(idx) {
                if !changes.new.contains(&placeholder) {
                    changes.new.push(placeholder);
                }
            }
            let zid = self.graph[idx].zid;
            if is_new {
                if !changes.new.contains(&zid) {
                    changes.new.push(zid);
                }
            } else {
                changes.updated.push(zid);
            }
        }
        // Prune nodes the update made unreachable, then drop any pruned zid
        // from `new` / `updated` (a node cannot be both freshly-advertised and
        // detached in the same ingest, but the retain keeps the sets disjoint
        // by construction — zenoh `network.rs:786-788`).
        let removed = self.remove_detached_nodes();
        if !removed.is_empty() {
            changes.new.retain(|z| !removed.contains(z));
            changes.updated.retain(|z| !removed.contains(z));
        }
        changes.removed = removed;
        changes
    }

    /// Rebuild node `idx1`'s edges from its (just-updated) `links`: add or
    /// update an edge to every advertised destination that ALSO advertises
    /// `idx1` back (a mutual link), introducing a placeholder node for a
    /// not-yet-known destination, and pruning edges `idx1` no longer
    /// advertises. Mirrors zenoh's edge-rebuild loop (`network.rs:742-783`):
    /// an edge exists iff both endpoints advertise the link. Returns the zids
    /// of any placeholders it INTRODUCED — zenoh pushes a reintroduced node
    /// into `new_nodes` so it re-floods onward (`network.rs:755-764`), which
    /// `process_linkstates` mirrors via `changes.new`.
    fn rebuild_edges(&mut self, idx1: NodeIndex) -> Vec<Zid> {
        let zid1 = self.graph[idx1].zid;
        let link_zids: Vec<Zid> = self.graph[idx1].links.keys().cloned().collect();
        let mut introduced = Vec::new();

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
                    self.ensure_node(*dest);
                    introduced.push(*dest);
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
        introduced
    }

    /// Set the petgraph edge weight between two mutually-linked nodes. The
    /// weight is the stronger of the two advertised directions (or the
    /// default when neither is explicit), plus a deterministic sub-1%
    /// jitter derived from the ordered zid pair so equal-cost paths break
    /// ties identically on EVERY peer — including a zenohd peer. Mirrors
    /// zenoh `update_edge` (`network.rs:424-455`); the jitter hashes the
    /// fixed 16-byte zero-padded zid (zenoh's `ZenohIdProto::to_le_bytes()`,
    /// `network.rs:430-434`), NOT the trimmed wire bytes, so a sub-16-byte
    /// zid produces the byte-identical jitter zenohd computes — otherwise
    /// a mixed wz/zenohd mesh could pick different equal-cost next hops and
    /// loop. Cross-process reproducibility relies on `DefaultHasher::new()`
    /// being fixed-seed (std's SipHash with constant keys) — the same
    /// implementation detail zenoh depends on, so wz and zenohd agree.
    fn update_edge(&mut self, idx1: NodeIndex, idx2: NodeIndex) {
        use std::hash::Hasher;

        let zid1 = self.graph[idx1].zid;
        let zid2 = self.graph[idx2].zid;

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        if zid1 > zid2 {
            hasher.write(&zid2.le16());
            hasher.write(&zid1.le16());
        } else {
            hasher.write(&zid1.le16());
            hasher.write(&zid2.le16());
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

        let jitter = 1.0 + JITTER_FRACTION * ((hasher.finish() as u32) as f64 / u32::MAX as f64);
        self.graph.update_edge(idx1, idx2, w as f64 * jitter);
    }

    /// Recompute the per-root spanning trees and this peer's shortest-path
    /// distances from the current graph: for every possible root, a
    /// Bellman-Ford from that root gives the shortest-path predecessors,
    /// from which this peer (`self.idx`) derives its parent / children /
    /// per-destination next hop in that root's tree. Forwarding a message
    /// along its source's tree is loop-free (a tree has no cycles) — the
    /// whole point of linkstate-peer routing. Mirrors zenoh `compute_trees`
    /// (`network.rs:1015-1113`). Call after the topology changes (add_link
    /// / ingest) and before querying the trees.
    ///
    /// Returns the per-tree `new_children` DELTA: each `(root_zid, [child_zid,
    /// ..])` names a tree root whose set of this-peer children GAINED members
    /// vs the previous trees, with only the newly-added children — zenoh's
    /// `compute_trees -> Vec<Vec<NodeIndex>>` (`network.rs:1097-1111`, children
    /// filtered to those not in `old_children`). A tree whose children did not
    /// grow contributes nothing. The subscription re-advertise
    /// (`pubsub_tree_change`) floods a sourced declaration only to a source
    /// tree's NEW children, not all of them — so a recompute that adds one child
    /// re-advertises to that child alone, not the whole subtree. The return is
    /// ignorable by callers that only need the recompute (the topology-query
    /// methods read `self.trees` directly).
    pub fn compute_trees(&mut self) -> Vec<(Zid, Vec<Zid>)> {
        let indexes: Vec<NodeIndex> = self.graph.node_indices().collect();
        let max_idx = match indexes.iter().max() {
            Some(m) => *m,
            None => return Vec::new(),
        };

        // Snapshot each tree's children BEFORE the rebuild so the post-rebuild
        // diff yields the new-children delta (zenoh captures `old_children`
        // ahead of the recompute, `network.rs:1019-1020`). A tree index absent
        // from the old set (a node that did not exist before) has every child
        // counted new — zenoh's `else { children.clone() }` arm.
        let old_children: Vec<Vec<NodeIndex>> =
            self.trees.iter().map(|t| t.children.clone()).collect();

        self.trees.clear();
        self.trees.resize_with(max_idx.index() + 1, Tree::default);

        for tree_root_idx in &indexes {
            // Every edge weight is `base * (1.0 + jitter)` with base >= 1 and
            // jitter > 0, so all weights are strictly positive and
            // Bellman-Ford cannot find a negative cycle. Assert it loudly
            // rather than silently leaving an empty tree, so a future
            // weight-model change that breaks the invariant fails fast.
            let paths = petgraph::algo::bellman_ford(&self.graph, *tree_root_idx)
                .expect("positive edge weights guarantee no negative cycle");
            if tree_root_idx.index() == self.idx.index() {
                self.distances = paths.distances.clone();
            }

            let tree = &mut self.trees[tree_root_idx.index()];
            tree.parent = paths.predecessors[self.idx.index()];
            for idx in &indexes {
                if paths.predecessors[idx.index()] == Some(self.idx) {
                    tree.children.push(*idx);
                }
            }
            tree.directions.resize(max_idx.index() + 1, None);
            let parent = tree.parent;

            let mut dfs = petgraph::algo::DfsSpace::new(&self.graph);
            for destination in &indexes {
                if self.idx == *destination
                    || !petgraph::algo::has_path_connecting(
                        &self.graph,
                        self.idx,
                        *destination,
                        Some(&mut dfs),
                    )
                {
                    continue;
                }
                // walk the predecessor chain back from `destination` until a
                // node whose predecessor is self -> that node is the first
                // hop; if none (destination is toward the root), use parent.
                let mut direction = None;
                let mut current = *destination;
                while let Some(pred) = paths.predecessors[current.index()] {
                    if pred == self.idx {
                        direction = Some(current);
                        break;
                    }
                    current = pred;
                }
                self.trees[tree_root_idx.index()].directions[destination.index()] =
                    direction.or(parent);
            }
        }

        // Per-tree new-children delta: children present now but not in the
        // pre-rebuild snapshot (zenoh `network.rs:1101-1107`). A tree that did
        // not gain a child contributes nothing, so an unchanged topology (a
        // sn-stale re-flood) yields an empty delta and re-advertises nothing.
        let mut new_children = Vec::new();
        for tree_root_idx in &indexes {
            let old = old_children.get(tree_root_idx.index());
            let delta: Vec<Zid> = self.trees[tree_root_idx.index()]
                .children
                .iter()
                .filter(|child| old.map_or(true, |o| !o.contains(child)))
                .map(|child| self.graph[*child].zid)
                .collect();
            if !delta.is_empty() {
                new_children.push((self.graph[*tree_root_idx].zid, delta));
            }
        }
        new_children
    }

    /// This peer's children in the spanning tree rooted at `source` — the
    /// neighbours to forward a message flooded along `source`'s tree to.
    /// Empty if `source` is unknown or [`compute_trees`] has not run for
    /// the current topology.
    pub fn tree_children_of(&self, source: &Zid) -> Vec<Zid> {
        let root = match self.get_idx(source) {
            Some(idx) => idx,
            None => return Vec::new(),
        };
        match self.trees.get(root.index()) {
            Some(tree) => tree
                .children
                .iter()
                // `node_weight` (not the panicking index op): a child pruned
                // by `remove_detached_nodes` since the last `compute_trees` —
                // possible because the recompute is COALESCED onto a later
                // tick — resolves to None and is skipped. The pruned node is
                // unreachable, so it was never a valid forward target anyway;
                // the next recompute drops it from the tree for good.
                .filter_map(|child| self.graph.node_weight(*child).map(|n| n.zid))
                .collect(),
            None => Vec::new(),
        }
    }

    /// The first hop from this peer toward `dest` along `source`'s tree
    /// (the unicast next-hop), if a path exists.
    pub fn next_hop(&self, source: &Zid, dest: &Zid) -> Option<Zid> {
        let root = self.get_idx(source)?;
        let dest_idx = self.get_idx(dest)?;
        let tree = self.trees.get(root.index())?;
        let hop = tree.directions.get(dest_idx.index()).copied().flatten()?;
        // `node_weight` is the non-panicking accessor (the `graph[hop]`
        // indexing op panics on a removed `NodeIndex`). In practice this None
        // arm is UNREACHABLE, for ONE reason: the single node-removal path
        // (`remove_detached_nodes`) always runs `scrub_trees`, whose by-value
        // clause nulls every `directions` slot whose VALUE is a freed hop. So a
        // hop freed since the last `compute_trees` leaves its `directions` slot
        // `None` and is caught at the `.flatten()?` above — it never reaches
        // this line. Note the "live `dest`, freed first-hop" state DOES exist
        // transiently: in a diamond, `dest` can survive via an alternate subtree
        // while its cached first-hop is pruned, so the slot is nulled by VALUE,
        // not because `dest` itself left the graph (an earlier comment wrongly
        // claimed a freed hop always detaches `dest`). Kept as defensive
        // belt-and-suspenders for that scrub invariant.
        Some(self.graph.node_weight(hop)?.zid)
    }

    /// The deduped set of first-hop children of this peer toward ANY of
    /// `dests` along `source`'s tree — the per-`dest` topology successor query
    /// the data-route filter (c3c-3) builds on. For each `dest`,
    /// [`next_hop`](Self::next_hop) gives the child to forward toward (zenoh's
    /// `route_successor`, i.e. `trees[source].directions[dest]`); the children
    /// are DEDUPED, so several destinations sharing one subtree yield that child
    /// once. A Push replicated to this set reaches every `dest`'s subtree
    /// exactly once instead of flooding every tree child
    /// ([`tree_children_of`](Self::tree_children_of) is the unfiltered
    /// broadcast). This is the multicast generalisation of the unicast
    /// `next_hop`.
    ///
    /// Placement: this is a pure TOPOLOGY query — it knows nothing of
    /// subscriptions (the caller passes the interested-peer set). zenoh's
    /// data-route ASSEMBLY `insert_faces_for_subs` (the HAT, `pubsub.rs:909-944`)
    /// is mirrored by the forwarder's `forward_push`, which supplies the
    /// interested set and resolves children to faces; the per-`sub`
    /// `directions[sub]` lookup it performs is exactly this method's body.
    ///
    /// A `dest` unknown or unreachable in `source`'s tree contributes nothing.
    /// A `dest` UPSTREAM of self toward the source (including `dest == source`)
    /// resolves to self's PARENT direction — zenoh's
    /// `directions[dest] = direction.or(parent)` — so it DOES appear in the
    /// output (it is not dropped here); the caller's inbound-face exclusion
    /// (`forward_push`) is what suppresses actually sending upstream. Output
    /// order is first-seen-deterministic over `dests`.
    pub fn directions_toward(&self, source: &Zid, dests: &[Zid]) -> Vec<Zid> {
        let mut out: Vec<Zid> = Vec::new();
        for dest in dests {
            if let Some(hop) = self.next_hop(source, dest) {
                if !out.contains(&hop) {
                    out.push(hop);
                }
            }
        }
        out
    }

    /// Shortest-path distance from this peer to `dest`, if reachable
    /// (`None` for an unreachable node — Bellman-Ford infinity).
    pub fn distance_to(&self, dest: &Zid) -> Option<f64> {
        let dest_idx = self.get_idx(dest)?;
        self.distances
            .get(dest_idx.index())
            .copied()
            .filter(|d| d.is_finite())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b, b, b, b])
    }

    #[test]
    fn zid_ord_matches_vec_u8_ord_including_zero_extended_prefixes() {
        // F2 (session-review): the canonical zero-padding makes the derived Zid
        // Ord byte-for-byte identical to the trimmed Vec<u8> ordering it
        // replaced. This is LOAD-BEARING for the cross-impl edge-jitter
        // tie-break (update_edge orders the pair by Ord, then hashes le16) and
        // was previously asserted only in prose. The decisive cases are
        // zero-extended prefixes — where the [u8;16] bytes compare equal and the
        // `len` field must break the tie the same way Vec<u8> does.
        let cases: &[&[u8]] = &[
            &[1],
            &[1, 0],
            &[1, 5],
            &[2],
            &[1, 9],
            &[1, 9, 3],
            &[0xff; 15],
            &[0xff; 16],
        ];
        for a in cases {
            for b in cases {
                assert_eq!(
                    Zid::from_slice(a).cmp(&Zid::from_slice(b)),
                    a.to_vec().cmp(&b.to_vec()),
                    "Zid Ord must match Vec<u8> Ord for {a:?} vs {b:?}"
                );
            }
        }
        // the specific prefix tie-break the invariant rests on.
        assert!(Zid::from_slice(&[1]) < Zid::from_slice(&[1, 0]));
        assert!(Zid::from_slice(&[1, 0]) < Zid::from_slice(&[1, 5]));
    }

    #[test]
    fn zid_eq_hash_truncation_and_from_are_canonical() {
        use std::collections::HashSet;
        // Eq + Hash consistency — Zid is a HashMap/HashSet key (idx_by_zid,
        // Link mappings, the subs table), so equal trimmed bytes must hash +
        // compare equal regardless of how they were built.
        assert_eq!(Zid::from_slice(&[1, 2, 3]), Zid::from_slice(&[1, 2, 3]));
        let mut set = HashSet::new();
        assert!(set.insert(Zid::from_slice(&[1, 2, 3])));
        assert!(
            !set.insert(Zid::from_slice(&[1, 2, 3])),
            "an equal zid dedups in a HashSet (Eq/Hash agree)"
        );
        assert!(
            set.insert(Zid::from_slice(&[1, 2, 4])),
            "a distinct zid is a new member"
        );
        // a >16-byte slice truncates to the 16-byte canonical form.
        let big = Zid::from_slice(&[0xAB; 17]);
        assert_eq!(big.len(), 16);
        assert_eq!(big.as_slice(), &[0xAB; 16]);
        // The validating TryFrom (the session(Vec<u8>) / wire -> routing
        // boundary) agrees with from_slice for a canonical zid; its rejects are
        // covered in zid_try_from_rejects_empty_and_oversized.
        assert_eq!(
            Zid::try_from(&[1, 2][..]).unwrap(),
            Zid::from_slice(&[1, 2])
        );
        assert_eq!(Zid::try_from(vec![1, 2]).unwrap(), Zid::from_slice(&[1, 2]));
    }

    #[test]
    fn zid_try_from_rejects_empty_and_oversized() {
        // The UNTRUSTED wire path: TryFrom enforces the zenoh ZenohIdProto size
        // contract (1..=16 significant bytes), unlike the trusted infallible
        // from_slice which admits / truncates.
        assert_eq!(Zid::try_from(&[][..]), Err(ZidError::Empty), "empty slice");
        assert_eq!(
            Zid::try_from(&[0u8, 0, 0][..]),
            Err(ZidError::Empty),
            "an all-zero buffer has size 0 (a zid is NonZero in zenoh)"
        );
        assert_eq!(
            Zid::try_from(&[0xAB; 17][..]),
            Err(ZidError::Oversized(17)),
            "17 bytes is over the 16 max"
        );
        // oversized is checked first, so a >16 all-zero slice reports Oversized
        // (matches zenoh's size-checked-first order).
        assert_eq!(Zid::try_from(&[0u8; 20][..]), Err(ZidError::Oversized(20)));
        // a conformant 1- and 16-byte zid round-trips through as_slice.
        assert_eq!(Zid::try_from(&[1][..]).unwrap().as_slice(), &[1]);
        assert_eq!(
            Zid::try_from(&[7u8; 16][..]).unwrap().as_slice(),
            &[7u8; 16]
        );
        // the Vec form delegates to the slice form.
        assert_eq!(
            Zid::try_from(vec![1u8, 2]).unwrap(),
            Zid::from_slice(&[1, 2])
        );
        assert!(Zid::try_from(Vec::<u8>::new()).is_err());
    }

    #[test]
    fn zid_display_is_wire_order_lowercase_hex() {
        // Display (and Debug, which wraps it) render the trimmed bytes as
        // lowercase per-byte hex in WIRE order — the SSOT the demo face logs use.
        let z = Zid::from_slice(&[0x1a, 0x2b, 0x0c]);
        assert_eq!(z.to_string(), "1a2b0c");
        assert_eq!(format!("{z:?}"), "Zid(1a2b0c)");
        // a zero byte within the trimmed length is preserved (no integer-style
        // stripping) and the order is NOT reversed — the deliberate divergence
        // from zenoh's u128 ZenohIdProto::Display, which would render the first
        // zid "c2b1a" and this one "1".
        let lead0 = Zid::from_slice(&[0x01, 0x00]);
        assert_eq!(lead0.to_string(), "0100");
    }

    #[test]
    fn zid_as_ref_is_the_trimmed_bytes() {
        let z = Zid::from_slice(&[9, 8, 7]);
        let r: &[u8] = z.as_ref();
        assert_eq!(r, z.as_slice());
        assert_eq!(r, &[9, 8, 7]);
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
        let net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        assert_eq!(net.node_count(), 1);
        assert_eq!(net.self_zid(), &zid(0x01));
        assert_eq!(net.get_idx(&zid(0x01)), Some(net.self_idx()));
        let self_node = net.get_node(&zid(0x01)).unwrap();
        assert_eq!(self_node.whatami, Some(WhatAmI::Peer));
        assert_eq!(self_node.sn, 1, "self sn starts at 1 (zenoh parity)");
    }

    #[test]
    fn ensure_node_is_idempotent_upsert() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
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
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let id = net.add_link(zid(0x07), WhatAmI::Peer);
        assert_eq!(net.get_link(id).unwrap().zid, zid(0x07));

        let link = net.get_link_mut(id).unwrap();
        link.set_zid_mapping(5, zid(0xAB));
        assert_eq!(net.get_link(id).unwrap().get_zid(5), Some(&zid(0xAB)));
        assert_eq!(net.get_link(id).unwrap().get_zid(6), None);
    }

    #[test]
    fn add_and_remove_link() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let a = net.add_link(zid(0x07), WhatAmI::Peer);
        let b = net.add_link(zid(0x08), WhatAmI::Peer);
        assert_ne!(a, b, "distinct link ids");
        assert!(net.get_link(a).is_some());
        // A is a leaf neighbour (no other advertiser), so dropping its link
        // detaches it: remove_link prunes the node and returns its zid.
        let removed = net.remove_link(a);
        assert_eq!(
            removed,
            vec![zid(0x07)],
            "dropping the only link to A detaches and prunes it"
        );
        assert!(net.get_link(a).is_none());
        assert!(net.get_link(b).is_some(), "removing one link leaves others");
        assert!(
            net.get_idx(&zid(0x07)).is_none(),
            "the pruned node left the graph and the idx_by_zid index"
        );
        assert!(net.get_idx(&zid(0x08)).is_some(), "B remains a graph node");
    }

    // ── c2b ingest ──────────────────────────────────────────────────

    use sce_forge_runtime::codec::{SceBytes, SceCursor};
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_codecs::linkstate_list::LinkstateList;

    /// Build a LinkState entry. `options` is unused by the ingest (it reads
    /// the typed `Option` fields, not the flag byte), so it is left 0.
    fn entry(
        psid: u64,
        sn: u64,
        zid: Option<&Zid>,
        whatami: Option<u8>,
        links: &[u64],
    ) -> LinkstateOwned {
        LinkstateOwned {
            options: 0,
            psid,
            sn,
            zid_len: zid.map(|z| z.len() as u64),
            zid: zid.map(|z| SceBytes::from_slice(z.as_slice()).unwrap()),
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

    /// A link-state entry for the link peer 0x07 (psid 7) advertising links
    /// to `node_psids`. Co-list it with those nodes' entries so the
    /// reachability prune (c3c-3 D3) keeps them: a node only reachable as a
    /// floating A<->B pair (no advertiser leading back to self) is detached
    /// and pruned, so the edge/ingest mechanics below relay their nodes
    /// behind 0x07 (self -> 0x07 -> nodes). 0x07 does NOT advertise self
    /// back, so it adds no self<->0x07 edge — the tests still isolate the
    /// A<->B edge. Sent once; its `links` persist (0x07 is not re-advertised,
    /// so a later node-only ingest cannot sn-gate it away).
    fn relay(sn: u64, node_psids: &[u64]) -> LinkstateOwned {
        entry(7, sn, Some(&zid(0x07)), Some(2), node_psids)
    }

    /// [`entry`] plus an advertised `L` (locators) field — for the locator
    /// ingest tests. `num_locators` rides the count and `OPT_L` is set, exactly
    /// as the TX path emits a node that advertises locators.
    fn entry_with_locators(
        psid: u64,
        sn: u64,
        zid: Option<&Zid>,
        whatami: Option<u8>,
        links: &[u64],
        locators: &[&str],
    ) -> LinkstateOwned {
        let mut e = entry(psid, sn, zid, whatami, links);
        e.options |= OPT_L;
        e.num_locators = Some(locators.len() as u64);
        e.locators = Some(
            locators
                .iter()
                .map(|s| LocatorOwned {
                    locator_len: s.len() as u64,
                    locator: SceString::from_view(s).unwrap(),
                })
                .collect(),
        );
        e
    }

    #[test]
    fn ingest_adds_node_and_learns_mapping() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays node 0xAA (psid 10) behind it, so 0xAA is reachable and
        // the prune keeps it. 0xAA is listed BEFORE the relay so it is
        // inserted from its own entry (whatami Some(2)) rather than as a
        // whatami-None placeholder created by the relay's advertisement —
        // process_linkstates, like zenoh, sets whatami only at node creation
        // (network.rs:711-722 updates sn/links, not whatami).
        let changes = net.ingest_linkstate_list(
            link,
            list(vec![
                entry(10, 5, Some(&zid(0xAA)), Some(2), &[]),
                relay(1, &[10]),
            ]),
        );
        assert!(
            changes.new.contains(&zid(0xAA)),
            "0xAA is freshly added -> the `new` (full-state) set"
        );
        let node = net.get_node(&zid(0xAA)).expect("node added");
        assert_eq!(node.sn, 5);
        assert_eq!(node.whatami, Some(WhatAmI::Peer));
        // the source link learned psid 10 -> 0xAA.
        assert_eq!(net.get_link(link).unwrap().get_zid(10), Some(&zid(0xAA)));
    }

    #[test]
    fn ingest_sn_staleness_gate() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays 0xAA so it stays reachable across the re-ingests below.
        net.ingest_linkstate_list(
            link,
            list(vec![
                relay(1, &[10]),
                entry(10, 5, Some(&zid(0xAA)), None, &[]),
            ]),
        );
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
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
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
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // A (psid 1 -> 0xAA) appears before B, so B's link psid 1 resolves
        // against the mapping A registered earlier in the same list. 0x07
        // relays both so they are reachable and survive the prune.
        net.ingest_linkstate_list(
            link,
            list(vec![
                relay(1, &[1, 2]),
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
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
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
        zid: Option<&Zid>,
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
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays A and B (reachability), plus B (psid 2, no links yet)
        // and A->B one-sided.
        net.ingest_linkstate_list(
            link,
            list(vec![
                relay(1, &[1, 2]),
                entry(2, 1, Some(&zid(0xBB)), Some(2), &[]),
                entry(1, 1, Some(&zid(0xAA)), Some(2), &[2]),
            ]),
        );
        assert_eq!(net.edge_count(), 0, "one-sided link => no edge");
        // B advertises a link back to A => mutual => the edge forms.
        net.ingest_linkstate_list(link, list(vec![entry(2, 2, None, Some(2), &[1])]));
        assert_eq!(net.edge_count(), 1, "mutual link => edge");
        assert!(net.edge_weight(&zid(0xAA), &zid(0xBB)).is_some());
    }

    #[test]
    fn edge_pruned_when_link_no_longer_advertised() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays A and B so they remain reachable even after A drops its
        // link below (the edge prune is the subject; the node prune is not).
        net.ingest_linkstate_list(
            link,
            list(vec![
                relay(1, &[1, 2]),
                entry(2, 1, Some(&zid(0xBB)), Some(2), &[]),
                entry(1, 1, Some(&zid(0xAA)), Some(2), &[2]),
            ]),
        );
        net.ingest_linkstate_list(link, list(vec![entry(2, 2, None, Some(2), &[1])]));
        assert_eq!(net.edge_count(), 1);
        // A re-advertises with no links => the A<->B edge is pruned (A and B
        // both stay in the graph — still reachable via the 0x07 relay).
        net.ingest_linkstate_list(link, list(vec![entry(1, 2, None, Some(2), &[])]));
        assert_eq!(net.edge_count(), 0, "dropped link => edge pruned");
        // explicitly: the edge went, but A and B did NOT (still reachable via the
        // 0x07 relay) — so edge_count==0 is the edge prune, not a node prune.
        assert!(
            net.get_idx(&zid(0xAA)).is_some() && net.get_idx(&zid(0xBB)).is_some(),
            "A and B survive (only the A<->B edge was pruned, not the nodes)"
        );
    }

    #[test]
    fn edge_weight_is_max_of_both_directions() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays A and B (reachability), plus B (psid 2, no links yet)
        // and A->B weight 50, in one consistent snapshot.
        net.ingest_linkstate_list(
            link,
            list(vec![
                relay(1, &[1, 2]),
                entry(2, 1, Some(&zid(0xBB)), Some(2), &[]),
                entry_weighted(1, 1, Some(&zid(0xAA)), Some(2), &[2], &[50]),
            ]),
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

    // ── d spanning-tree forwarding ──────────────────────────────────

    #[test]
    fn add_link_connects_self_and_edge_forms_on_mutual() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        // add_link connects self to A in the graph (node + self link).
        assert_eq!(net.node_count(), 2);
        assert_eq!(net.edge_count(), 0, "A has not advertised self back yet");
        // A advertises a link back to self => the self<->A edge forms.
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]), // teach psid 10 -> self
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]), // A links to self
            ]),
        );
        assert_eq!(net.edge_count(), 1, "self<->A mutual edge");
    }

    #[test]
    fn self_rooted_tree_lists_direct_neighbour_as_child() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        net.compute_trees();
        assert_eq!(net.tree_children_of(&zid(0x01)), vec![zid(0xAA)]);
        assert_eq!(net.distance_to(&zid(0x01)), Some(0.0), "self distance is 0");
        assert!(net.distance_to(&zid(0xAA)).unwrap() > 0.0);
    }

    #[test]
    fn compute_trees_returns_only_the_newly_added_children() {
        // First compute: self gains child A (every child is new vs the empty
        // initial trees). A second neighbour B then joins; the next recompute's
        // delta for self's tree is JUST B — A is an existing child, not re-emitted.
        // This is the new-children delta the subscription re-advertise floods to.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        let first = net.compute_trees();
        assert_eq!(
            first
                .iter()
                .find(|(root, _)| *root == zid(0x01))
                .map(|(_, c)| c.clone()),
            Some(vec![zid(0xAA)]),
            "first compute: A is a new child of self"
        );

        // B joins as a second direct neighbour of self.
        let lb = net.add_link(zid(0xBB), WhatAmI::Peer);
        net.ingest_linkstate_list(
            lb,
            list(vec![
                entry(20, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(21, 5, Some(&zid(0xBB)), Some(2), &[20]),
            ]),
        );
        let second = net.compute_trees();
        assert_eq!(
            second
                .iter()
                .find(|(root, _)| *root == zid(0x01))
                .map(|(_, c)| c.clone()),
            Some(vec![zid(0xBB)]),
            "second compute: only the NEW child B is in self's tree delta, not A"
        );
        // The full tree DOES include both — the delta is only the new ones.
        let mut children = net.tree_children_of(&zid(0x01));
        children.sort();
        assert_eq!(children, vec![zid(0xAA), zid(0xBB)]);
    }

    #[test]
    fn dropping_a_self_link_can_add_a_child_via_re_homing() {
        // R311sg session-review counterexample: a self-link drop does NOT always
        // shrink self's tree children — under non-uniform weights it can RE-HOME a
        // node THROUGH self, ADDING a child to a remote root's tree. This refutes
        // the retracted "deregister delta is provably empty" claim.
        //
        // Topology rooted at R (self = S): R-S(100), S-F(250), S-M(100), M-F(100).
        // F's cheapest path from R is R-S-M-F (300) < R-S-F (350), so F is M's
        // child, NOT S's — S's children in R's tree = [M]. Dropping S-M forces
        // F onto R-S-F, so F RE-HOMES as S's child — a NEW child of S in R's tree.
        let s = zid(0x05); // self
        let r = zid(0x0D); // root (a remote node, e.g. a subscription source)
        let m = zid(0x0B); // the detour relay
        let f = zid(0x0F); // the node that re-homes
        let mut net = LinkstateNetwork::new(s, WhatAmI::Peer);
        let lr = net.add_link(r, WhatAmI::Peer);
        let lf = net.add_link(f, WhatAmI::Peer);
        let lm = net.add_link(m, WhatAmI::Peer);

        // Pass 1 — teach each link's psid -> zid mappings (low sn, no links).
        net.ingest_linkstate_list(lr, list(vec![entry(0, 1, Some(&s), Some(2), &[])]));
        net.ingest_linkstate_list(
            lf,
            list(vec![
                entry(0, 1, Some(&s), Some(2), &[]),
                entry(2, 1, Some(&m), Some(2), &[]),
            ]),
        );
        net.ingest_linkstate_list(
            lm,
            list(vec![
                entry(0, 1, Some(&s), Some(2), &[]),
                entry(2, 1, Some(&f), Some(2), &[]),
            ]),
        );
        // Pass 2 — advertise links (high sn). R->S; F->{S w250, M default};
        // M->{S default, F default}. The S-F edge takes 250, S-M / M-F take 100.
        net.ingest_linkstate_list(lr, list(vec![entry(1, 5, Some(&r), Some(2), &[0])]));
        net.ingest_linkstate_list(
            lf,
            list(vec![entry_weighted(
                1,
                5,
                Some(&f),
                Some(2),
                &[0, 2],
                &[250, 0],
            )]),
        );
        net.ingest_linkstate_list(lm, list(vec![entry(1, 5, Some(&m), Some(2), &[0, 2])]));

        net.compute_trees();
        assert_eq!(
            net.tree_children_of(&r),
            vec![m],
            "before the drop: F routes via the cheaper detour M, so S's only child \
             in R's tree is M (F is M's child, not S's)"
        );

        // Drop the S-M link: F can now only reach R via R-S-F, so it re-homes as
        // S's child. compute_trees must report F as a NEW child of S in R's tree.
        // M itself stays reachable via F (S-F-M), so the reachability prune keeps
        // it — a node with another path is NOT detached (zenoh parity).
        let pruned = net.remove_link(lm);
        assert!(
            pruned.is_empty(),
            "M is still reachable via F, so dropping S-M prunes nothing"
        );
        let delta = net.compute_trees();
        assert_eq!(
            net.tree_children_of(&r),
            vec![f],
            "after the drop: F re-homed as S's child in R's tree"
        );
        let r_delta = delta
            .iter()
            .find(|(root, _)| *root == r)
            .map(|(_, c)| c.clone());
        assert_eq!(
            r_delta,
            Some(vec![f]),
            "the self-link drop ADDED F as a new child of R's tree — a non-empty \
             delta deregister MUST re-advertise to (not discard as 'provably empty')"
        );
    }

    #[test]
    fn next_hop_follows_shortest_path_over_a_line() {
        // Topology: self -- A -- B (a line). next hop self->B is A.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        // One consistent snapshot (a real flood is one list): A (the direct
        // peer) advertises self + B, and B advertises A back. The 2-pass
        // convert resolves a link to an entry appearing later in the same
        // list, so B stays reachable (self -> A -> B) and is not pruned —
        // unlike a split build where B is transiently detached between lists.
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]), // teach self mapping
                entry(12, 5, Some(&zid(0xBB)), Some(2), &[11]), // B -> A
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]), // A -> self, B
            ]),
        );
        assert_eq!(net.edge_count(), 2, "self<->A and A<->B");
        net.compute_trees();

        // self forwards toward B via A; B is not a direct child of self.
        assert_eq!(net.next_hop(&zid(0x01), &zid(0xBB)), Some(zid(0xAA)));
        assert_eq!(net.tree_children_of(&zid(0x01)), vec![zid(0xAA)]);
        // distance to B is roughly two hops (~2x the ~100 default weight).
        let d_b = net.distance_to(&zid(0xBB)).unwrap();
        assert!(
            (199.0..=202.0).contains(&d_b),
            "two-hop distance, got {d_b}"
        );
    }

    #[test]
    fn remove_link_disconnects_self() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        assert_eq!(net.edge_count(), 1);
        net.remove_link(l);
        assert_eq!(net.edge_count(), 0, "self<->A edge pruned on link removal");
    }

    // ── c3c-3 D3 remove_detached_nodes ──────────────────────────────

    #[test]
    fn ingest_prunes_a_node_no_longer_advertised() {
        // self -- A, and A advertises a link to B, so B is reachable THROUGH
        // A's advertisement. When A re-advertises (newer sn) WITHOUT B, B has
        // no remaining path from self and remove_detached_nodes prunes it; the
        // ingest reports it in `changes.removed` (zenoh network.rs:786-808).
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(12, 0, Some(&zid(0xBB)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]), // A -> self, B
            ]),
        );
        assert!(net.get_idx(&zid(0xBB)).is_some(), "B is reachable via A");

        // A re-advertises (sn 6) dropping its link to B.
        let changes = net.ingest_linkstate_list(
            l,
            list(vec![entry(11, 6, Some(&zid(0xAA)), Some(2), &[10])]),
        );
        assert_eq!(
            changes.removed,
            vec![zid(0xBB)],
            "B lost its only advertiser, so the ingest prunes it"
        );
        assert!(
            net.get_idx(&zid(0xBB)).is_none(),
            "B left both the graph and the idx_by_zid index"
        );
        assert!(net.get_idx(&zid(0xAA)).is_some(), "A is still reachable");
    }

    #[test]
    fn remove_link_transitively_prunes_unreachable_nodes() {
        // self -- A -- B (a line): B is reachable ONLY through A. Dropping the
        // self--A link detaches A AND, transitively, B; remove_link prunes both
        // and returns their zids (zenoh remove_link -> remove_detached_nodes,
        // network.rs:948).
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(12, 5, Some(&zid(0xBB)), Some(2), &[11]), // B -> A
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]), // A -> self, B
            ]),
        );
        assert_eq!(net.node_count(), 3, "self, A, B");

        let mut removed = net.remove_link(l);
        removed.sort();
        assert_eq!(
            removed,
            vec![zid(0xAA), zid(0xBB)],
            "dropping self--A detaches A and (transitively) B"
        );
        assert_eq!(net.node_count(), 1, "only self remains");
        assert!(net.get_idx(&zid(0xAA)).is_none());
        assert!(net.get_idx(&zid(0xBB)).is_none());
    }

    #[test]
    fn tree_accessors_tolerate_a_node_pruned_since_the_last_recompute() {
        // D2c coalesces the recompute, so a node can be pruned (remove_link /
        // ingest) AFTER compute_trees built a tree still referencing its
        // NodeIndex, BEFORE the next recompute runs. The accessors must use
        // node_weight (not the panicking index op): a dangling child is
        // skipped, a pruned destination yields no next hop. Never a panic.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0xAA), WhatAmI::Peer);
        let lc = net.add_link(zid(0xCC), WhatAmI::Peer);
        // A and C each advertise self back -> both are self's tree children.
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        net.ingest_linkstate_list(
            lc,
            list(vec![
                entry(20, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(21, 5, Some(&zid(0xCC)), Some(2), &[20]),
            ]),
        );
        net.compute_trees();
        let mut kids = net.tree_children_of(&zid(0x01));
        kids.sort();
        assert_eq!(
            kids,
            vec![zid(0xAA), zid(0xCC)],
            "A and C are both children"
        );

        // Drop A's link WITHOUT recomputing — A is pruned but the trees still
        // hold its now-dangling NodeIndex.
        let removed = net.remove_link(la);
        assert_eq!(removed, vec![zid(0xAA)], "leaf A is pruned");

        assert_eq!(
            net.tree_children_of(&zid(0x01)),
            vec![zid(0xCC)],
            "the pruned child A is skipped (not panicked on); C remains"
        );
        assert_eq!(
            net.directions_toward(&zid(0x01), &[zid(0xAA), zid(0xCC)]),
            vec![zid(0xCC)],
            "a pruned destination yields no direction (no next hop, no panic)"
        );
    }

    #[test]
    fn a_reused_node_index_does_not_alias_a_stale_tree_entry() {
        // F1 (session-review): StableUnGraph REUSES a freed index on the next
        // add_node, and the tree recompute is COALESCED (D2c), so between a
        // prune (which frees an index) and the next compute_trees a NEW node can
        // reuse that index. The `node_weight` accessor guard only catches a
        // still-absent index — it would resolve a REUSED one to the wrong live
        // node and misroute. remove_detached_nodes scrubs the freed indices from
        // the trees so no stale entry can alias the reused node.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0xAA), WhatAmI::Peer);
        // self -- A -- C: C is reachable only via A, so self's tree routes toward
        // C through A (directions[C] = A).
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(12, 5, Some(&zid(0xCC)), Some(2), &[11]), // C -> A
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]), // A -> self, C
            ]),
        );
        net.compute_trees();
        let c_idx = net.get_idx(&zid(0xCC)).expect("C present");
        assert_eq!(
            net.next_hop(&zid(0x01), &zid(0xCC)),
            Some(zid(0xAA)),
            "self routes toward C via A"
        );

        // Prune C (A re-advertises without it) — freeing C's index. NO recompute
        // (the coalesced D2c window).
        let changes = net.ingest_linkstate_list(
            la,
            list(vec![entry(11, 6, Some(&zid(0xAA)), Some(2), &[10])]),
        );
        assert_eq!(changes.removed, vec![zid(0xCC)]);

        // A new node D reuses C's freed StableGraph index.
        let d_idx = net.ensure_node(zid(0xDD));
        assert_eq!(d_idx, c_idx, "D reused C's freed index");

        // Without the scrub these would alias to C's stale entries: next_hop
        // would return C's old hop A, and tree_children_of(D) would return the
        // departed C's stale tree. The scrub makes both resolve to nothing.
        assert_eq!(
            net.next_hop(&zid(0x01), &zid(0xDD)),
            None,
            "no stale next hop toward the reused-index node D (not C's old hop A)"
        );
        assert!(
            net.tree_children_of(&zid(0xDD)).is_empty(),
            "D has no tree rooted at the reused index (not C's stale tree)"
        );
    }

    #[test]
    fn a_reintroduced_placeholder_re_floods_as_new() {
        // F3 (session-review): a node advertised as a link dest but not (or no
        // longer) in the graph is reintroduced as a placeholder; zenoh pushes it
        // into new_nodes so it re-floods onward (network.rs:763). It must appear
        // in changes.new even though it carries no own entry in this list.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        // A advertises self + B; B advertises A. The link learns psid 12 -> B.
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(12, 5, Some(&zid(0xBB)), Some(2), &[11]), // B -> A
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]), // A -> self, B
            ]),
        );
        // A drops B -> B detaches and is pruned (the link keeps the psid 12 -> B
        // mapping).
        net.ingest_linkstate_list(
            l,
            list(vec![entry(11, 6, Some(&zid(0xAA)), Some(2), &[10])]),
        );
        assert!(net.get_idx(&zid(0xBB)).is_none(), "B was pruned");
        // A re-advertises a link to B (psid 12 still mapped) with NO B entry: B
        // is reintroduced as a placeholder and re-floods as new.
        let changes = net.ingest_linkstate_list(
            l,
            list(vec![entry(11, 7, Some(&zid(0xAA)), Some(2), &[10, 12])]),
        );
        assert!(
            changes.new.contains(&zid(0xBB)),
            "the reintroduced placeholder B is reported in changes.new for re-flood"
        );
    }

    // ── c3c-3 D4 Details split (full-for-new / links-only-for-updated) ──

    #[test]
    fn build_linkstate_split_full_carries_the_zid_links_only_omits_it() {
        // D4: a NEW node re-floods full (zid + P flag); an UPDATED node
        // re-floods links-only (no zid, P clear) — the links/psid/sn survive so
        // the receiver applies the update against its existing psid->zid map.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        net.add_link(zid(0xAA), WhatAmI::Peer); // self advertises a link, so it has one
        let full = net.build_linkstate_split(&[zid(0x01)], &[]); // self as NEW
        let links_only = net.build_linkstate_split(&[], &[zid(0x01)]); // self as UPDATED
        let fe = &full.link_states[0];
        let le = &links_only.link_states[0];
        assert!(fe.zid.is_some(), "full carries the zid");
        assert_eq!(
            fe.options & 0x01,
            0x01,
            "full sets the P (zid-present) flag"
        );
        assert!(le.zid.is_none(), "links-only omits the zid");
        assert_eq!(le.options & 0x01, 0, "links-only clears the P flag");
        // identity + the links delta survive in both (the point of links-only).
        assert_eq!(fe.psid, le.psid);
        assert_eq!(fe.sn, le.sn);
        assert_eq!(fe.links_len, le.links_len, "links present in both variants");
    }

    #[test]
    fn build_link_added_delta_is_neighbour_zid_only_then_self_links_only() {
        // zenoh add_link's 2-entry delta to existing links: the NEW neighbour as
        // ZID-ONLY (zid present, NO links) first, then self LINKS-ONLY (no zid,
        // links present incl the neighbour). It is a delta -- NOT the full
        // topology -- so a third (unrelated) node is absent.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        net.add_link(zid(0x0C), WhatAmI::Peer); // an unrelated existing neighbour C
        net.add_link(zid(0x0B), WhatAmI::Peer); // the just-added neighbour B
        let delta = net.build_link_added_delta(&zid(0x0B));
        assert_eq!(
            delta.link_states.len(),
            2,
            "exactly [neighbour, self] -- the unrelated node C is NOT re-sent"
        );
        let nb = &delta.link_states[0];
        let me = &delta.link_states[1];
        // neighbour B: zid-only.
        assert!(nb.zid.is_some(), "the neighbour entry carries its zid");
        assert_eq!(nb.options & 0x01, 0x01, "neighbour sets the P flag");
        assert_eq!(nb.links_len, 0, "the neighbour entry carries NO links");
        // self: links-only, referencing B by psid.
        assert!(me.zid.is_none(), "self omits its zid (links-only)");
        assert_eq!(me.options & 0x01, 0, "self clears the P flag");
        assert_eq!(me.psid, 0, "self is psid 0");
        assert!(
            me.links_len >= 1,
            "self's links-only entry advertises its links (incl the new B)"
        );
    }

    #[test]
    fn build_link_added_delta_resolves_at_the_receiver() {
        // The 2-entry add-delta's LOAD-BEARING claim (session-review coverage
        // gap): the receiver resolves self's links-only entry — which references
        // the NEW neighbour by psid — because the SAME list's zid-only neighbour
        // entry registered that psid->zid mapping. R is an EXISTING neighbour of A
        // (already mapped A via a bootstrap); A then gains C and sends R the delta,
        // so R must learn C AND resolve A's freshly-advertised link to C.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let mut r = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        a.add_link(zid(0x0B), WhatAmI::Peer); // A knows R
        let ra = r.add_link(zid(0x0A), WhatAmI::Peer); // R knows A
        r.ingest_linkstate_list(ra, a.build_linkstate_list()); // bootstrap: R maps A
        assert!(
            r.get_node(&zid(0x0A)).is_some(),
            "R mapped A from the bootstrap"
        );
        assert!(r.get_node(&zid(0x0C)).is_none(), "R does not know C yet");

        // A gains a NEW neighbour C -> the 2-entry delta to its existing link R.
        a.add_link(zid(0x0C), WhatAmI::Peer);
        let delta = a.build_link_added_delta(&zid(0x0C));
        assert_eq!(delta.link_states.len(), 2, "[C zid-only, A links-only]");
        let changes = r.ingest_linkstate_list(ra, delta);

        // The zid-only entry taught R that C exists...
        assert!(
            r.get_node(&zid(0x0C)).is_some(),
            "R resolved C from the same-list zid-only entry"
        );
        assert!(changes.new.contains(&zid(0x0C)), "C is reported new to R");
        // ...and A's links-only entry resolved its link to C against the psid that
        // zid-only entry just registered — the cross-entry resolution that is the
        // whole point of the 2-entry delta.
        assert!(
            r.get_node(&zid(0x0A))
                .unwrap()
                .links
                .contains_key(&zid(0x0C)),
            "A's links-only entry resolved its A->C link via the same-list mapping"
        );
    }

    #[test]
    fn link_added_delta_resolves_regardless_of_entry_order() {
        // The docstring claims the two-pass ingest tolerates either entry order
        // (it lists neighbour-first only to match zenoh). Prove it: feed the SAME
        // delta with its entries REVERSED (self links-only FIRST, then C zid-only)
        // and the receiver must still resolve C and A's A->C link.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let mut r = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        a.add_link(zid(0x0B), WhatAmI::Peer);
        let ra = r.add_link(zid(0x0A), WhatAmI::Peer);
        r.ingest_linkstate_list(ra, a.build_linkstate_list());
        a.add_link(zid(0x0C), WhatAmI::Peer);

        let mut delta = a.build_link_added_delta(&zid(0x0C));
        delta.link_states.reverse(); // self links-only now precedes C zid-only
        r.ingest_linkstate_list(ra, delta);

        assert!(
            r.get_node(&zid(0x0C)).is_some(),
            "C resolved even though its zid-only entry came AFTER self's links entry"
        );
        assert!(
            r.get_node(&zid(0x0A))
                .unwrap()
                .links
                .contains_key(&zid(0x0C)),
            "A->C resolved regardless of entry order (two-pass ingest)"
        );
    }

    #[test]
    fn a_links_only_reflood_resolves_against_the_prior_full_mapping() {
        // The D4 round-trip: B first ingests A's FULL flood (registering A's
        // psid->zid), then ingests A's links-only re-advertise (no zid) and
        // resolves A from that earlier mapping — applying the newer sn, no drop.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let _la = a.add_link(zid(0x0B), WhatAmI::Peer);
        let lb = b.add_link(zid(0x0A), WhatAmI::Peer);

        b.ingest_linkstate_list(lb, a.build_linkstate_list()); // A full -> B maps A
        assert!(
            b.get_idx(&zid(0x0A)).is_some(),
            "B mapped A from the full flood"
        );
        let sn_before = b.get_node(&zid(0x0A)).unwrap().sn;

        a.add_link(zid(0x0C), WhatAmI::Peer); // bumps A's sn so the re-advertise is newer
        let links_only = a.build_linkstate_split(&[], &[zid(0x0A)]);
        assert!(
            links_only.link_states[0].zid.is_none(),
            "A's re-flood omits its zid (links-only)"
        );

        let changes = b.ingest_linkstate_list(lb, links_only);
        assert_eq!(
            changes.updated,
            vec![zid(0x0A)],
            "B resolved the zid-less entry to A and recorded an update"
        );
        assert!(changes.new.is_empty(), "A was already known, so not `new`");
        assert!(
            b.get_node(&zid(0x0A)).unwrap().sn > sn_before,
            "B applied the newer sn from the links-only re-advertise"
        );
    }

    #[test]
    fn a_links_only_entry_for_an_unmapped_psid_is_dropped() {
        // The D4 SAFETY boundary (session-review): a links-only re-flood (zid
        // omitted) is valid ONLY against a prior full mapping. An entry with no
        // zid whose psid the link never learned must be DROPPED — never admitted
        // with a guessed identity. (Also path-covers the E2 unresolvable-psid
        // error log in convert.)
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0x07), WhatAmI::Peer);
        let links_only_unmapped = LinkstateOwned {
            options: 0, // P clear -> no zid (links-only)
            psid: 50,   // never mapped on this link
            sn: 5,
            zid_len: None,
            zid: None,
            whatami: Some(2),
            num_locators: None,
            locators: None,
            links_len: 0,
            links: Vec::new(),
            weights: None,
        };
        let changes = net.ingest_linkstate_list(l, list(vec![links_only_unmapped]));
        assert!(
            changes.new.is_empty() && changes.updated.is_empty(),
            "an unmapped links-only entry is dropped, not admitted"
        );
        assert_eq!(
            net.node_count(),
            2,
            "only self + the link peer 0x07; the zid-less unmapped node never entered the graph"
        );
    }

    /// Independently recompute the default-weight jittered edge weight the
    /// way zenoh does — hashing the 16-byte zero-padded zids. Used to pin
    /// that `update_edge` pads (not trims); a trimmed-bytes hash would
    /// produce a different value and fail the assertion below.
    fn expected_default_edge_weight(a: &Zid, b: &Zid) -> f64 {
        use std::hash::Hasher;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let (lo, hi) = if a > b { (b, a) } else { (a, b) };
        h.write(&lo.le16());
        h.write(&hi.le16());
        let jitter = 1.0 + 0.01 * ((h.finish() as u32) as f64 / u32::MAX as f64);
        LinkEdgeWeight::DEFAULT as f64 * jitter
    }

    #[test]
    fn edge_jitter_hashes_16_byte_padded_zid() {
        // a mutual edge between two SHORT (4-byte) zids; the jitter must hash
        // the 16-byte zero-padded form (zenoh's to_le_bytes), so wz agrees
        // with zenohd on equal-cost tie-breaks.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let l = net.add_link(zid(0xAA), WhatAmI::Peer);
        net.ingest_linkstate_list(
            l,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        let w = net
            .edge_weight(&zid(0x01), &zid(0xAA))
            .expect("edge present");
        let expected = expected_default_edge_weight(&zid(0x01), &zid(0xAA));
        assert!(
            (w - expected).abs() < 1e-9,
            "edge weight {w} must match the 16-byte-padded jitter {expected}"
        );
    }

    #[test]
    fn spanning_tree_is_acyclic_on_a_triangle() {
        // self -- A, self -- B, A -- B (a 3-cycle). self's own tree must be
        // acyclic: A and B are both direct children; the A-B edge is unused.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0xAA), WhatAmI::Peer);
        let lb = net.add_link(zid(0xBB), WhatAmI::Peer);
        // A floods (its link): teach self/A/B zids, A links to self + B.
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(12, 0, Some(&zid(0xBB)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10, 12]),
            ]),
        );
        // B floods (its own link): B links to self + A.
        net.ingest_linkstate_list(
            lb,
            list(vec![
                entry(20, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(21, 0, Some(&zid(0xAA)), Some(2), &[]),
                entry(22, 5, Some(&zid(0xBB)), Some(2), &[20, 21]),
            ]),
        );
        net.compute_trees();
        assert_eq!(net.edge_count(), 3, "triangle has 3 edges (the cycle)");
        let mut children = net.tree_children_of(&zid(0x01));
        children.sort();
        assert_eq!(
            children,
            vec![zid(0xAA), zid(0xBB)],
            "both neighbours are direct children; the tree does not use A-B"
        );
        assert_eq!(net.next_hop(&zid(0x01), &zid(0xAA)), Some(zid(0xAA)));
        assert_eq!(net.next_hop(&zid(0x01), &zid(0xBB)), Some(zid(0xBB)));
    }

    #[test]
    fn directions_toward_splits_and_dedups_by_subtree() {
        // self -- A, self -- B, B -- D (D behind B). In self's own tree A and
        // B are direct children; D is reached via B. The subscription filter:
        //  - [A, D]  -> {A, B}  (two distinct subtrees, no dedup)
        //  - [B, D]  -> {B}     (both via child B -> deduped to one)
        //  - [D]     -> {B}     (forward only down B's subtree, NOT to A)
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0xAA), WhatAmI::Peer);
        let lb = net.add_link(zid(0xBB), WhatAmI::Peer);
        // A floods: teach self/A zids, A links self -> edge self<->A.
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0xAA)), Some(2), &[10]),
            ]),
        );
        // B floods: teach self/B/D zids; B links self + D -> edges self<->B,
        // B<->D (D's own link advertised next pass).
        net.ingest_linkstate_list(
            lb,
            list(vec![
                entry(20, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(22, 0, Some(&zid(0xDD)), Some(2), &[]),
                entry(21, 5, Some(&zid(0xBB)), Some(2), &[20, 22]),
            ]),
        );
        net.ingest_linkstate_list(
            lb,
            list(vec![entry(22, 5, Some(&zid(0xDD)), Some(2), &[21])]),
        );
        net.compute_trees();

        let mut split = net.directions_toward(&zid(0x01), &[zid(0xAA), zid(0xDD)]);
        split.sort();
        assert_eq!(
            split,
            vec![zid(0xAA), zid(0xBB)],
            "A direct + D via B -> two distinct directions"
        );
        assert_eq!(
            net.directions_toward(&zid(0x01), &[zid(0xBB), zid(0xDD)]),
            vec![zid(0xBB)],
            "B and D-behind-B collapse to the single child B"
        );
        assert_eq!(
            net.directions_toward(&zid(0x01), &[zid(0xDD)]),
            vec![zid(0xBB)],
            "interest only behind B -> forward down B's subtree, not to A"
        );
        assert!(
            net.directions_toward(&zid(0x01), &[]).is_empty(),
            "no interested peers -> no outbound children"
        );
        assert!(
            net.directions_toward(&zid(0x01), &[zid(0xFF)]).is_empty(),
            "an unknown / unreachable dest contributes no direction"
        );
    }

    #[test]
    fn directions_toward_follows_a_non_self_source_tree() {
        // Line A -- self -- C -- E. A Push SOURCED at A floods along A's tree,
        // in which self's children are C (toward C and E). The filter on A's
        // tree for interest {C, E} must pick child C once (E is behind C);
        // interest in the source A itself resolves to the UPSTREAM (parent)
        // direction, which forward_push's inbound-face exclusion suppresses.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let la = net.add_link(zid(0x0A), WhatAmI::Peer);
        let lc = net.add_link(zid(0x0C), WhatAmI::Peer);
        // A floods: A links self -> edge A<->self.
        net.ingest_linkstate_list(
            la,
            list(vec![
                entry(10, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(11, 5, Some(&zid(0x0A)), Some(2), &[10]),
            ]),
        );
        // C floods: teach self/C/E zids; C links self + E; E links C.
        net.ingest_linkstate_list(
            lc,
            list(vec![
                entry(20, 0, Some(&zid(0x01)), Some(2), &[]),
                entry(22, 0, Some(&zid(0x0E)), Some(2), &[]),
                entry(21, 5, Some(&zid(0x0C)), Some(2), &[20, 22]),
            ]),
        );
        net.ingest_linkstate_list(
            lc,
            list(vec![entry(22, 5, Some(&zid(0x0E)), Some(2), &[21])]),
        );
        net.compute_trees();

        assert_eq!(
            net.directions_toward(&zid(0x0A), &[zid(0x0C), zid(0x0E)]),
            vec![zid(0x0C)],
            "in A's tree, interest in C and E-behind-C both route via child C"
        );
        assert_eq!(
            net.directions_toward(&zid(0x0A), &[zid(0x0A)]),
            vec![zid(0x0A)],
            "interest in the source resolves to the upstream (parent) direction \
             (zenoh directions[source]=parent); forward_push's inbound-face \
             exclusion is what suppresses sending it back"
        );
    }

    // ── c3b TX: build_linkstate_list + cross-peer convergence ───────

    #[test]
    fn two_peers_converge_via_build_then_ingest() {
        // A and B are directly linked. Each builds its own link-state list
        // (the TX path) and the other ingests it (the RX path); both must
        // learn the A<->B edge from the round-trip — the real mesh property.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let la_b = a.add_link(zid(0x0B), WhatAmI::Peer);
        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);

        // Two flood rounds (linkstate is idempotent under re-flood).
        for _ in 0..2 {
            let a_msg = a.build_linkstate_list();
            b.ingest_linkstate_list(lb_a, a_msg);
            let b_msg = b.build_linkstate_list();
            a.ingest_linkstate_list(la_b, b_msg);
        }
        a.compute_trees();
        b.compute_trees();

        assert!(
            a.edge_weight(&zid(0x0A), &zid(0x0B)).is_some(),
            "A learned the A<->B edge"
        );
        assert!(
            b.edge_weight(&zid(0x0A), &zid(0x0B)).is_some(),
            "B learned the A<->B edge"
        );
        assert_eq!(a.next_hop(&zid(0x0A), &zid(0x0B)), Some(zid(0x0B)));
        assert_eq!(b.next_hop(&zid(0x0B), &zid(0x0A)), Some(zid(0x0A)));
    }

    #[test]
    fn topology_propagates_transitively_over_a_line() {
        // Line A -- B -- C. A has NO direct link to C; it must learn C from
        // B's flood (B advertises its C link + C's node), then route to C
        // through B — multi-hop topology propagation over build/ingest.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let la_b = a.add_link(zid(0x0B), WhatAmI::Peer);
        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);
        let lb_c = b.add_link(zid(0x0C), WhatAmI::Peer);
        let mut c = LinkstateNetwork::new(zid(0x0C), WhatAmI::Peer);
        let lc_b = c.add_link(zid(0x0B), WhatAmI::Peer);

        // Flood until converged: neighbours feed B, then B feeds the far ends.
        for _ in 0..3 {
            let c_msg = c.build_linkstate_list();
            b.ingest_linkstate_list(lb_c, c_msg);
            let a_msg = a.build_linkstate_list();
            b.ingest_linkstate_list(lb_a, a_msg);
            let b_to_a = b.build_linkstate_list();
            a.ingest_linkstate_list(la_b, b_to_a);
            let b_to_c = b.build_linkstate_list();
            c.ingest_linkstate_list(lc_b, b_to_c);
        }
        a.compute_trees();

        assert!(
            a.get_node(&zid(0x0C)).is_some(),
            "A learned C transitively via B's flood"
        );
        assert_eq!(
            a.next_hop(&zid(0x0A), &zid(0x0C)),
            Some(zid(0x0B)),
            "A routes to C through B"
        );
    }

    #[test]
    fn full_flood_carries_self_locators_into_the_neighbour_graph() {
        // The locator data round-trip: A advertises its dial locators on its
        // full flood (the FULL form carries the `L` field), and B ingests them
        // into A's node — the discovery data a gossip/autoconnect consumer
        // reads. Mutation guard: if make_link_state stops emitting locators OR
        // process_linkstates stops ingesting them, node_locators(A) is None and
        // this fails.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        a.set_self_locators(vec!["tcp/10.0.0.10:7447".to_string()]);
        a.add_link(zid(0x0B), WhatAmI::Peer);
        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);

        b.ingest_linkstate_list(lb_a, a.build_linkstate_list());

        assert_eq!(
            b.node_locators(&zid(0x0A)),
            Some(["tcp/10.0.0.10:7447".to_string()].as_slice()),
            "B learned A's advertised locators from the full flood"
        );
        // Control: B announced no self locators, so its own node carries none —
        // the L field is omitted, not emitted empty.
        assert_eq!(b.node_locators(&zid(0x0B)), None);
    }

    #[test]
    fn a_full_flood_rides_a_direct_neighbours_locators_but_withholds_a_distant_nodes() {
        // zenoh's per-source `propagate_locators` gate (gossip.rs:281): when S
        // re-floods its topology it advertises a DIRECT neighbour's locators but
        // WITHHOLDS a distant (multihop) node's — reachability data travels one
        // hop. A receiver therefore learns the neighbour's dial addresses through
        // S, not the distant node's (it learns those from the distant node's own
        // neighbour). The non-multihop gossip default.
        let mut s = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link_n = s.add_link(zid(0x20), WhatAmI::Peer); // S — N (direct)
                                                           // N (psid 10) advertises its locators + a link to D; D (psid 11)
                                                           // advertises its own locators + a link back to N. Ingest is ungated, so
                                                           // S stores both.
        s.ingest_linkstate_list(
            link_n,
            list(vec![
                entry_with_locators(
                    10,
                    5,
                    Some(&zid(0x20)),
                    Some(2),
                    &[11],
                    &["tcp/10.0.0.20:7447"],
                ),
                entry_with_locators(
                    11,
                    5,
                    Some(&zid(0x30)),
                    Some(2),
                    &[10],
                    &["tcp/10.0.0.30:7447"],
                ),
            ]),
        );
        assert!(
            s.node_locators(&zid(0x20)).is_some(),
            "S ingested N's locators"
        );
        assert!(
            s.node_locators(&zid(0x30)).is_some(),
            "S ingested D's locators"
        );

        // A fresh receiver R links to S and ingests S's full re-flood.
        let mut r = LinkstateNetwork::new(zid(0x02), WhatAmI::Peer);
        let link_s = r.add_link(zid(0x01), WhatAmI::Peer);
        r.ingest_linkstate_list(link_s, s.build_linkstate_list());

        assert!(
            r.node_locators(&zid(0x20)).is_some(),
            "S advertised its direct neighbour N's locators",
        );
        assert_eq!(
            r.node_locators(&zid(0x30)),
            None,
            "S withheld the distant node D's locators (the per-source gate)",
        );
    }

    #[test]
    fn a_links_only_update_preserves_previously_learned_locators() {
        // preserve-on-None (zenoh network.rs:714-715): once a node's locators
        // are learned, a later links-only re-advertisement (no `L` field) must
        // KEEP them, not wipe them — otherwise every D4 links-only delta would
        // erase the discovery data.
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // 0x07 relays 0xAA; 0xAA first advertises locators (full entry, L set).
        net.ingest_linkstate_list(
            link,
            list(vec![
                entry_with_locators(
                    10,
                    5,
                    Some(&zid(0xAA)),
                    Some(2),
                    &[],
                    &["tcp/192.0.2.1:7447"],
                ),
                relay(1, &[10]),
            ]),
        );
        assert_eq!(
            net.node_locators(&zid(0xAA)),
            Some(["tcp/192.0.2.1:7447".to_string()].as_slice()),
            "0xAA's locators were ingested"
        );
        // 0xAA re-advertises with a NEWER sn but NO L field (a links-only
        // update): its locators survive.
        net.ingest_linkstate_list(
            link,
            list(vec![entry(10, 6, Some(&zid(0xAA)), Some(2), &[])]),
        );
        assert_eq!(
            net.get_node(&zid(0xAA)).unwrap().sn,
            6,
            "the newer sn was applied (the entry was not stale-gated)"
        );
        assert_eq!(
            net.node_locators(&zid(0xAA)),
            Some(["tcp/192.0.2.1:7447".to_string()].as_slice()),
            "a links-only (no-L) re-advertisement preserves the locators"
        );
    }

    #[test]
    fn an_over_long_locator_is_dropped_at_the_tx_boundary() {
        // A locator past the codec's SceString<128> width cannot round-trip a
        // no-alloc peer's decoder, so the TX projection drops it (the same
        // host-validation obligation as the oversized-zid drop) while the
        // valid sibling still rides.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        let ok = "tcp/10.0.0.10:7447".to_string();
        let too_long = format!("tcp/[{}]:7447", "f".repeat(200));
        assert!(too_long.len() > MAX_LOCATOR_LEN);
        a.set_self_locators(vec![ok.clone(), too_long]);
        a.add_link(zid(0x0B), WhatAmI::Peer);
        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);

        b.ingest_linkstate_list(lb_a, a.build_linkstate_list());

        assert_eq!(
            b.node_locators(&zid(0x0A)),
            Some([ok].as_slice()),
            "the valid locator rode; the over-128 one was dropped at TX"
        );
    }

    #[test]
    fn locators_survive_a_full_wire_encode_decode_round_trip() {
        // The load-bearing claim is "link-states carry the L field ON THE WIRE".
        // The other locator tests build->ingest owned structs in memory and
        // never touch bytes, so they would still pass if make_link_state set
        // `locators: Some(..)` with OPT_L clear or a wrong num_locators — a real
        // peer's decode gates `locators` on OPT_L (codec linkstate.rs). This
        // drives the FULL path: build -> ENCODE to bytes -> DECODE -> ingest, so
        // OPT_L / num_locators / the locator bytes must all be self-consistent
        // for the locators to survive.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        a.set_self_locators(vec!["tcp/10.0.0.10:7447".to_string()]);
        a.add_link(zid(0x0B), WhatAmI::Peer);

        // TX: build A's full link-state list, then ENCODE it to wire bytes.
        let wire = a
            .build_linkstate_list()
            .try_as_borrowed()
            .expect("re-borrow A's list for encode")
            .encode_to_vec();

        // RX: decode the bytes back (the real peer path), then ingest on B.
        let mut cursor = SceCursor::new(&wire);
        let decoded = LinkstateList::decode(&mut cursor)
            .expect("decode A's link-state list")
            .try_into_owned()
            .expect("own the decoded list");

        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);
        b.ingest_linkstate_list(lb_a, decoded);

        assert_eq!(
            b.node_locators(&zid(0x0A)),
            Some(["tcp/10.0.0.10:7447".to_string()].as_slice()),
            "A's locators survived encode->decode->ingest (OPT_L + num_locators consistent)"
        );
    }

    #[test]
    fn ingest_drops_entry_with_oversized_zid() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // a 17-byte WIRE zid exceeds ZENOHID_MAX_SIZE -> the entry is dropped (the
        // host-validation obligation zenoh enforces at decode), so it never
        // reaches the graph and the later build re-encode stays infallible. The
        // entry is built directly with the oversized SceBytes since `Zid` itself
        // truncates to 16 (the `entry` helper can no longer carry the raw form).
        let big = vec![0xAB_u8; ZENOHID_MAX_SIZE + 1];
        let oversized = LinkstateOwned {
            options: 0,
            psid: 11,
            sn: 5,
            zid_len: Some(big.len() as u64),
            zid: Some(SceBytes::from_slice(&big).unwrap()),
            whatami: Some(2),
            num_locators: None,
            locators: None,
            links_len: 0,
            links: Vec::new(),
            weights: None,
        };
        let changes = net.ingest_linkstate_list(link, list(vec![oversized]));
        assert!(changes.updated.is_empty(), "oversized-zid entry dropped");
        assert!(changes.new.is_empty());
        assert!(
            net.get_node(&Zid::from_slice(&big)).is_none(),
            "the oversized zid (even truncated) was not admitted"
        );
    }

    #[test]
    fn ingest_drops_entry_with_all_zero_zid() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer);
        let link = net.add_link(zid(0x07), WhatAmI::Peer);
        // An all-zero (or empty) wire zid has no significant bytes — zenoh's
        // u128-backed ZenohIdProto reports it as size 0 and rejects it at decode;
        // the validating Zid::try_from drops the entry here. This closes the gap
        // the old length-only guard left: an all-zero / empty zid passed the
        // `> MAX` check and reached the graph as a zero identity.
        let zeros = vec![0u8; 4];
        let zero_zid = LinkstateOwned {
            options: 0,
            psid: 11,
            sn: 5,
            zid_len: Some(zeros.len() as u64),
            zid: Some(SceBytes::from_slice(&zeros).unwrap()),
            whatami: Some(2),
            num_locators: None,
            locators: None,
            links_len: 0,
            links: Vec::new(),
            weights: None,
        };
        let changes = net.ingest_linkstate_list(link, list(vec![zero_zid]));
        assert!(changes.updated.is_empty(), "all-zero-zid entry dropped");
        assert!(changes.new.is_empty());
        assert!(
            net.get_node(&Zid::from_slice(&zeros)).is_none(),
            "the all-zero zid was not admitted"
        );
    }

    #[test]
    fn local_psid_of_is_the_node_index() {
        let mut net = LinkstateNetwork::new(zid(0x01), WhatAmI::Peer); // self -> idx 0
        net.add_link(zid(0x0A), WhatAmI::Peer); // first neighbour -> idx 1
        assert_eq!(net.local_psid_of(&zid(0x01)), Some(0), "self is psid 0");
        assert_eq!(
            net.local_psid_of(&zid(0x0A)),
            Some(1),
            "neighbour is psid 1"
        );
        assert_eq!(net.local_psid_of(&zid(0xFF)), None, "unknown zid -> None");
    }

    #[test]
    fn build_encode_decode_ingest_round_trips_through_the_wire() {
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::linkstate_list::LinkstateList;
        // A builds its list and serializes it through the REAL LinkStateList
        // codec; B decodes the wire bytes and ingests — exercising the
        // encode/decode round-trip the in-process convergence tests skip.
        let mut a = LinkstateNetwork::new(zid(0x0A), WhatAmI::Peer);
        a.add_link(zid(0x0B), WhatAmI::Peer);
        let wire = a
            .build_linkstate_list()
            .try_as_borrowed()
            .expect("borrow built list")
            .encode_to_vec();

        let decoded = LinkstateList::decode(&mut SceCursor::new(&wire))
            .expect("decode list wire")
            .try_into_owned()
            .expect("into owned");

        let mut b = LinkstateNetwork::new(zid(0x0B), WhatAmI::Peer);
        let lb_a = b.add_link(zid(0x0A), WhatAmI::Peer);
        b.ingest_linkstate_list(lb_a, decoded);
        b.compute_trees();
        assert!(
            b.get_node(&zid(0x0A)).is_some(),
            "B learned A from the wire-decoded list"
        );
        assert!(
            b.edge_weight(&zid(0x0A), &zid(0x0B)).is_some(),
            "the A<->B edge formed from wire-decoded links"
        );
    }
}
