// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y714 (§1.1f) — the capture read as NODES rather than as 5-tuples.
//!
//! # The unit this plane changes
//!
//! Every other plane in this crate observes a FLOW: a 5-tuple, or a pair of
//! endpoints on a datagram group. That is the unit the wire hands out and it is
//! the wrong unit for the question "which nodes are talking to which" — one
//! node reconnecting from a new source port is two flows, one node reached over
//! two links is two flows, and a NAT between the tap and the peer makes the
//! address a fiction while the zid stays exactly what it was.
//!
//! The zenoh identity is the ZID, and it is on the wire in three places: the
//! INIT of a unicast handshake, the JOIN a multicast peer announces itself
//! with, and the HELLO that answers a SCOUT. This plane keeps those, keyed by
//! zid, and reports what each was seen doing.
//!
//! # What counts as a LINK, and why less than you would think
//!
//! A link is recorded only where BOTH ends named themselves on one flow — an
//! INIT each way. One INIT proves a node sent one; it does not prove a session,
//! and the peer that would have answered may be outside the capture.
//!
//! R311y608's rule is enforced here rather than re-derived: a frame carrying
//! `inadmissible_on_link` is a message the LINK cannot carry, and pico's raweth
//! is exactly that case — it gives every raweth link the multicast transport,
//! whose receive path takes an INIT and does nothing with it. The zid in such a
//! message was genuinely on the wire, so it is recorded as SEEN; it never
//! establishes a link, because no session exists for it to be a link of. An
//! observer that skipped this distinction would report a topology assembled
//! from messages no participant acted on.
//!
//! # Producers
//!
//! Both flow tables, and after the decryption pass. `flows()` is the stream
//! half and a plane built from it alone silently omits every multicast JOIN —
//! which is where a peer census on a real deployment mostly comes from. The
//! decryption ordering is the same rule [`crate::agg`] states: a flow whose
//! plaintext was just opened carries messages, and a plane built before the
//! pass censuses the ciphertext-only view.

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::{Direction, PassiveFrame};

use crate::link::FlowKey;

/// How a node came to be known.
///
/// Kept apart rather than summed because they are different strengths of
/// evidence: an INIT is a node trying to establish a session, a JOIN is a node
/// announcing itself to a group, and a HELLO is a node answering a question.
/// A census that folded them could not tell a peer that is actually talking
/// from one that merely answered a scout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeEvidence {
    /// INITs that named this zid, on links that can carry one.
    pub init: usize,
    /// JOINs — the multicast self-announcement.
    pub join: usize,
    /// HELLOs answering a scout — the responder naming itself.
    pub hello: usize,
    /// SCOUTs that carried a zid — the asker naming itself. Optional on the
    /// wire, so a capture full of anonymous scouts leaves this at zero without
    /// that meaning nobody scouted.
    pub scout: usize,
    /// Messages that named this zid on a link whose transport cannot act on
    /// them (R311y608). Counted, and never used to establish anything.
    pub inadmissible: usize,
}

impl NodeEvidence {
    /// Evidence a participant could have acted on.
    pub fn admissible(&self) -> usize {
        self.init + self.join + self.hello + self.scout
    }
}

/// One zenoh node, as the wire named itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedNode {
    /// The identifier, exactly the bytes the message carried. Zenoh zids are
    /// 1..=16 bytes and shorter ones are common on pico deployments, so this is
    /// a slice and not a `[u8; 16]` — padding one would invent bytes and make
    /// two different nodes compare equal.
    pub zid: Vec<u8>,
    /// The role byte where a message carried one, in the handshake's own 2-bit
    /// packing. `None` when every message that named this node was a kind that
    /// does not state a role.
    pub whatami: Option<u8>,
    /// How it was seen.
    pub evidence: NodeEvidence,
    /// Capture index of the first message that named it.
    pub first_packet: usize,
    /// Flows this zid was named on, in first-appearance order.
    pub flows: Vec<FlowKey>,
    /// R311y714 (§1.1f) — transport-unit bytes this node SENT, over the flows
    /// where the capture could say which end it is.
    ///
    /// Counted once per UNIT and not once per message: `unit_len` rides on
    /// every message of a batch (it is the length the message arrived under),
    /// so summing it per message multiplies a batch by its own message count.
    /// Only the message at `batch_index == 0` contributes.
    pub wire_bytes: u64,
    /// R311y714 — where this node said it can be REACHED, from the HELLO's
    /// locator list, in first-appearance order and without duplicates.
    ///
    /// The half of a node's identity that a deployment's config can be matched
    /// against: a zid answers "who" and this answers "where", and a reader
    /// holding a config file has the second and not the first. Empty for a
    /// node that only ever INITed — a locator list is a HELLO's payload, and
    /// inventing one from the flow's addresses would report the ADDRESS THIS
    /// CAPTURE SAW rather than the address the node advertises, which are
    /// different across a NAT and it is exactly the NAT case this plane exists
    /// for.
    pub locators: Vec<String>,
}

/// Two nodes that named themselves to each other on one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLink {
    /// Index into [`NodeCensus::nodes`] of the node on [`Direction::A`].
    pub a: usize,
    /// Index of the node on [`Direction::B`].
    pub b: usize,
    /// The flow that carried both halves.
    pub flow: FlowKey,
}

/// A capture read as a set of nodes and the links between them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeCensus {
    nodes: Vec<ObservedNode>,
    links: Vec<ObservedLink>,
    /// R311y714 (§1.1f) — unit bytes on a direction whose SENDER this capture
    /// cannot name.
    ///
    /// The honesty valve on every share this type computes. A capture that
    /// joins a session already in progress has no handshake, so no direction
    /// has an owner and every byte lands here — and a share of the attributed
    /// bytes alone would then be a percentage of a fraction, presented as a
    /// percentage of the whole. A reader must be able to see the denominator.
    unattributed_bytes: u64,
}

impl NodeCensus {
    /// An empty census.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every node this capture named, in first-appearance order.
    pub fn nodes(&self) -> &[ObservedNode] {
        &self.nodes
    }

    /// Every link where both ends named themselves.
    pub fn links(&self) -> &[ObservedLink] {
        &self.links
    }

    /// R311y714 — unit bytes this census could not credit to any node.
    ///
    /// Read it BEFORE any share below: a capture with no handshake in it
    /// attributes nothing, and shares over an empty numerator would otherwise
    /// read as a tidy 0% rather than as "this capture cannot say".
    pub fn unattributed_bytes(&self) -> u64 {
        self.unattributed_bytes
    }

    /// Unit bytes credited to a named node.
    pub fn attributed_bytes(&self) -> u64 {
        self.nodes.iter().map(|n| n.wire_bytes).sum()
    }

    /// R311y714 (§1.1f) — one node's share of every unit byte this capture
    /// carried, attributed or not, in parts per ten thousand.
    ///
    /// The DENOMINATOR IS THE WHOLE CAPTURE, not the attributed part. A share
    /// over the attributed bytes alone would rise as attribution got worse,
    /// which is the one direction an occupancy figure must never move.
    ///
    /// Integer basis points rather than a float: this crate is `no_std` and a
    /// percentage rendered from an integer ratio cannot drift between the two
    /// renderings that print it. TRUNCATED, so N nodes' shares sum to between
    /// `10_000 - N` and `10_000` — a consumer that needs them to add up
    /// exactly must carry the remainder itself rather than round here, where
    /// rounding would make one node's share depend on the others'.
    pub fn share_bp(&self, node: usize) -> Option<u32> {
        let total = self.attributed_bytes() + self.unattributed_bytes;
        if total == 0 {
            return None;
        }
        let n = self.nodes.get(node)?;
        Some(((n.wire_bytes.saturating_mul(10_000)) / total) as u32)
    }

    /// The node carrying `zid`, if the capture named it.
    pub fn node(&self, zid: &[u8]) -> Option<&ObservedNode> {
        self.nodes.iter().find(|n| n.zid == zid)
    }

    /// Fold one flow's decoded messages in.
    ///
    /// NO FILTER, unlike every other plane here, and the reason is a category
    /// one rather than an omission: [`crate::filter`] selects DATA-PLANE
    /// records by keyexpr, kind and payload, and a node is named by a handshake
    /// message that has none of those. Under a record selector every node would
    /// be undecidable, which is a worse answer than not offering the knob.
    ///
    /// `flow` is what makes a link answerable: two zids are peers because they
    /// named themselves on THE SAME flow in opposite directions, and a fold
    /// that took only the frames could not say that.
    pub fn observe_flow(&mut self, flow: &FlowKey, frames: &[PassiveFrame]) {
        // Per-direction, the last zid seen naming itself on an admissible
        // message. A flow that re-handshakes names the same pair again, and a
        // flow that is genuinely reused by a different node names the new one —
        // taking the latest is what keeps the link current rather than
        // remembering a node that has gone.
        let mut ends: [Option<usize>; 2] = [None, None];
        for frame in frames {
            let Some((zid, whatami, kind)) = named_zid(frame) else {
                continue;
            };
            if zid.is_empty() {
                // A zid field that decoded to nothing names no node. Skipped
                // rather than recorded as a node with an empty identity, which
                // would alias every such message onto one fictional peer.
                continue;
            }
            let idx = self.intern(&zid, whatami, frame, flow);
            if frame.inadmissible_on_link {
                self.nodes[idx].evidence.inadmissible += 1;
                // NOT an end of any link: see the module docs.
                continue;
            }
            match kind {
                Named::Init => self.nodes[idx].evidence.init += 1,
                Named::Join => self.nodes[idx].evidence.join += 1,
                Named::Hello => self.nodes[idx].evidence.hello += 1,
                Named::Scout => self.nodes[idx].evidence.scout += 1,
            }
            // Only a UNICAST handshake makes a node an end of a link. A JOIN is
            // an announcement to a group and its "other end" is every listener,
            // which is not a pair and must not be reported as one.
            if matches!(kind, Named::Init) {
                ends[dir_index(frame.direction)] = Some(idx);
            }
        }
        if let (Some(a), Some(b)) = (ends[0], ends[1]) {
            if a != b {
                self.record_link(a, b, flow);
            }
        }
        // R311y714 (§1.1f) — SECOND pass, and it has to be second: which node
        // owns a direction is settled by the handshake, and a fold that
        // attributed bytes as it walked would credit everything before the
        // INIT to nobody even on a flow whose INIT arrives one message later.
        for frame in frames {
            // Once per unit. See `ObservedNode::wire_bytes`.
            if frame.batch_index != 0 {
                continue;
            }
            let bytes = frame.unit_len as u64;
            match ends[dir_index(frame.direction)] {
                Some(idx) => self.nodes[idx].wire_bytes += bytes,
                None => self.unattributed_bytes += bytes,
            }
        }
    }

    /// R311y714 — fold one datagram flow's SCOUTING list in.
    ///
    /// A THIRD row producer, and the compiler is what found it: the `Hello`
    /// evidence kind was unconstructible because a HELLO never enters
    /// `frames` — a scouting message advances no session, so
    /// [`crate::DatagramDissection`] keeps it in its own list. A census built
    /// from `frames` alone reports zero nodes on a capture whose whole content
    /// is discovery, which is exactly what a first look at a deployment is.
    ///
    /// No link is recorded here. A HELLO names its sender and a SCOUT names its
    /// asker, and neither states that a session was established — the INIT
    /// that would is on a different flow.
    pub fn observe_scouting(&mut self, flow: &FlowKey, scouting: &[crate::ScoutingDatagram]) {
        for datagram in scouting {
            let Ok(decoded) = &datagram.frame else {
                continue;
            };
            let (zid, whatami, kind) = match decoded {
                wz_session_core::scouting_message::ScoutingFrame::Hello { body, .. } => {
                    (body.zid.to_vec(), Some(body.whatami()), Named::Hello)
                }
                // The zid is OPTIONAL on a scout: a node may ask without saying
                // who it is, and `None` is that node declining to be named
                // rather than an empty identity.
                wz_session_core::scouting_message::ScoutingFrame::Scout { body, .. } => {
                    match &body.zid {
                        Some(z) => (z.to_vec(), None, Named::Scout),
                        None => continue,
                    }
                }
                _ => continue,
            };
            if zid.is_empty() {
                continue;
            }
            let idx = self.intern_scouted(&zid, whatami, datagram.packet_index, flow);
            // R311y714 — the locator list, which only a HELLO carries. Taken
            // from the decoded body rather than from the flow's addresses: see
            // `ObservedNode::locators` for why the two are not the same claim.
            if let wz_session_core::scouting_message::ScoutingFrame::Hello { body, .. } = decoded {
                if let Some(list) = body.locators.as_ref() {
                    for loc in list.iter() {
                        let text = loc.locator.as_str();
                        if !text.is_empty() && !self.nodes[idx].locators.iter().any(|l| l == text) {
                            self.nodes[idx].locators.push(String::from(text));
                        }
                    }
                }
            }
            match kind {
                Named::Hello => self.nodes[idx].evidence.hello += 1,
                Named::Scout => self.nodes[idx].evidence.scout += 1,
                _ => {}
            }
        }
    }

    fn record_link(&mut self, a: usize, b: usize, flow: &FlowKey) {
        let already = self
            .links
            .iter()
            .any(|l| l.a == a && l.b == b && &l.flow == flow);
        if !already {
            self.links.push(ObservedLink { a, b, flow: *flow });
        }
    }

    fn intern(
        &mut self,
        zid: &[u8],
        whatami: Option<u8>,
        frame: &PassiveFrame,
        flow: &FlowKey,
    ) -> usize {
        self.intern_scouted(zid, whatami, frame.stream_offset, flow)
    }

    fn intern_scouted(
        &mut self,
        zid: &[u8],
        whatami: Option<u8>,
        first_packet: usize,
        flow: &FlowKey,
    ) -> usize {
        let idx = match self.nodes.iter().position(|n| n.zid == zid) {
            Some(i) => i,
            None => {
                self.nodes.push(ObservedNode {
                    zid: zid.to_vec(),
                    whatami,
                    evidence: NodeEvidence::default(),
                    first_packet,
                    flows: Vec::new(),
                    wire_bytes: 0,
                    locators: Vec::new(),
                });
                self.nodes.len() - 1
            }
        };
        let node = &mut self.nodes[idx];
        // FIRST role wins. A later message disagreeing about a node's role is a
        // finding, not a correction, and overwriting would hide it; the census
        // keeps what it first saw and the disagreement remains visible as two
        // messages with different roles in the capture.
        if node.whatami.is_none() {
            node.whatami = whatami;
        }
        if !node.flows.contains(flow) {
            node.flows.push(*flow);
        }
        idx
    }
}

/// Which kind of message named a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Named {
    Init,
    Join,
    Hello,
    Scout,
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// The zid a transport message names, if it names one.
///
/// The handshake `cbyte` packs the zid length minus one in its top nibble and
/// the 2-bit role below it; the decoded body already carries the zid as bytes,
/// so the length is not re-derived here — reading it twice is how the two
/// spellings drift.
fn named_zid(frame: &PassiveFrame) -> Option<(Vec<u8>, Option<u8>, Named)> {
    let Ok(decoded) = &frame.frame else {
        return None;
    };
    match decoded {
        InboundFrame::Init { body, .. } => {
            Some((body.zid.to_vec(), Some(whatami_of(body.cbyte)), Named::Init))
        }
        InboundFrame::Join { body, .. } => {
            Some((body.zid.to_vec(), Some(whatami_of(body.cbyte)), Named::Join))
        }
        _ => None,
    }
}

/// The 2-bit role packed in a handshake cbyte.
fn whatami_of(cbyte: u8) -> u8 {
    (cbyte >> 1) & 0x03
}

/// R311y714 — the whole capture, read as nodes.
///
/// BOTH flow tables, for the reason stated in the module docs and measured four
/// times before it was written down: `flows()` is the stream half, and a peer
/// census that skipped `datagram_flows()` would miss every multicast JOIN.
pub fn nodes(dissection: &crate::Dissection) -> NodeCensus {
    let mut census = NodeCensus::new();
    // R311y721 — every list, through the dissection's own enumeration. A
    // `quic/...` peer's Init is inside a QUIC stream and a serial peer's is
    // inside a COBS frame; a census that named the two flow tables would report
    // either deployment as having no participants at all.
    for (flow, frames) in dissection.message_lists() {
        census.observe_flow(&flow, frames);
    }
    for flow in dissection.datagram_flows() {
        // The scouting list, which is where a discovery-only capture's nodes
        // all are. A SECOND producer and not a frame list: a scouting datagram
        // is in the Scout/Hello namespace rather than the transport one, so it
        // cannot be a `PassiveFrame` and `message_lists` cannot carry it.
        census.observe_scouting(&flow.flow, &flow.scouting);
    }
    census
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{
        init_message, raweth_packet, scout_message, tcp_packet, udp_packet, SCOUT_GROUP,
    };
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    /// R311y714 (§1.1f) — a unicast handshake names BOTH nodes, and that pair
    /// is a link.
    ///
    /// The claim the plane exists for: the answer is keyed by zid, not by the
    /// 5-tuple the flow table is keyed by.
    #[test]
    fn a_handshake_names_two_nodes_and_the_link_between_them() {
        let mut d = Dissection::new();
        // INIT each way on ONE tcp flow, with different zids.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::tcp_packet_reverse(2000, &framed_init(&[0xB2; 4])),
        );
        d.finish();

        let census = nodes(&d);
        assert_eq!(census.nodes().len(), 2, "{:?}", census.nodes());
        assert!(
            census.node(&[0xA1; 4]).is_some() && census.node(&[0xB2; 4]).is_some(),
            "both zids must be named: {:?}",
            census.nodes()
        );
        assert_eq!(census.links().len(), 1, "{:?}", census.links());
        let link = &census.links()[0];
        assert_ne!(link.a, link.b, "a link is between two DIFFERENT nodes");
    }

    /// R311y714 — one INIT is not a link.
    ///
    /// A node that sent an INIT nobody answered is a node, and reporting it as
    /// connected would be a topology assembled from an intention.
    #[test]
    fn one_end_naming_itself_is_a_node_and_not_a_link() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.finish();

        let census = nodes(&d);
        assert_eq!(census.nodes().len(), 1);
        assert!(census.links().is_empty(), "{:?}", census.links());
    }

    /// R311y714 — THE DISCRIMINATOR: an INIT the LINK cannot carry names a zid
    /// and establishes nothing.
    ///
    /// R311y608 measured that pico gives a raweth link the multicast transport,
    /// whose receive path takes an INIT and does nothing with it. So no session
    /// exists for such a message, and a census that let it establish a link
    /// would report a topology no participant agrees with. The zid was on the
    /// wire, so it is still SEEN — the two statements are kept apart.
    #[test]
    fn an_inadmissible_init_names_a_node_but_establishes_no_link() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &raweth_packet(&init_message()));
        d.finish();

        let census = nodes(&d);
        assert_eq!(census.nodes().len(), 1, "the zid was on the wire");
        let node = &census.nodes()[0];
        assert_eq!(node.evidence.init, 0, "and it establishes nothing");
        assert_eq!(node.evidence.inadmissible, 1, "counted as what it is");
        assert!(census.links().is_empty(), "{:?}", census.links());
    }

    /// R311y714 — the SCOUTING list is a producer of its own.
    ///
    /// The compiler found this one: `Hello` was an unconstructible evidence
    /// kind because a scouting message never enters `frames`. A capture whose
    /// whole content is discovery — which is what a first look at a deployment
    /// is — reports zero nodes without this walk.
    #[test]
    fn a_discovery_only_capture_still_names_its_nodes() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &scout_message()),
        );
        d.finish();

        let census = nodes(&d);
        assert_eq!(
            census.nodes().len(),
            1,
            "the scout named its asker: {:?}",
            census.nodes()
        );
        assert_eq!(census.nodes()[0].evidence.scout, 1);
        assert!(
            census.nodes()[0].flows.len() == 1,
            "and the flow it was seen on is kept"
        );
    }

    /// R311y714 — the DATAGRAM table's transport messages count too.
    ///
    /// `flows()` is the stream half. A multicast JOIN is how a peer announces
    /// itself on a group, and a census built from the stream table alone misses
    /// every one of them — the omission this workspace has now been told about
    /// four times.
    #[test]
    fn a_multicast_join_names_the_node_that_announced_itself() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(
                [10, 0, 0, 1],
                7447,
                [224, 0, 0, 224],
                7447,
                &join_message(&[0xC3; 4]),
            ),
        );
        d.finish();

        let census = nodes(&d);
        assert_eq!(census.nodes().len(), 1, "{:?}", census.nodes());
        assert_eq!(census.nodes()[0].evidence.join, 1);
        assert!(
            census.links().is_empty(),
            "a JOIN announces to a group; its other end is every listener, \
             which is not a pair"
        );
    }

    /// R311y714 (§1.1f) — traffic is credited to the node that SENT it, and
    /// what cannot be credited is stated rather than divided away.
    ///
    /// [REDACTED-REQ] asks for occupancy against the whole, and the trap is the
    /// denominator: a capture that joins a session already in progress carries
    /// no handshake, so no direction has an owner. Sharing out only the
    /// attributed bytes would make such a capture read as a tidy 100% for
    /// whoever happened to be identified, and the figure would IMPROVE as
    /// attribution got worse.
    #[test]
    fn traffic_is_credited_to_its_sender_and_the_rest_is_said_aloud() {
        let mut d = Dissection::new();
        // A handshake each way, then a keepalive from the A side only.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::tcp_packet_reverse(2000, &framed_init(&[0xB2; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            2,
            &tcp_packet(
                1000 + framed_init(&[0xA1; 4]).len() as u32,
                &framed_keepalive(),
            ),
        );
        d.finish();

        let census = nodes(&d);
        let a = census
            .nodes()
            .iter()
            .position(|n| n.zid == [0xA1; 4])
            .expect("the A-side node");
        let b = census
            .nodes()
            .iter()
            .position(|n| n.zid == [0xB2; 4])
            .expect("the B-side node");
        assert!(
            census.nodes()[a].wire_bytes > census.nodes()[b].wire_bytes,
            "A sent two units and B one: {:?}",
            census.nodes()
        );
        assert_eq!(
            census.unattributed_bytes(),
            0,
            "every direction on this flow has an owner"
        );
        // Truncated basis points: two nodes lose at most two. Asserted as the
        // stated range rather than as equality, because equality would pass
        // only by luck of these byte counts and would break on the next
        // fixture for a reason that is not a defect.
        let sum = census.share_bp(a).unwrap() + census.share_bp(b).unwrap();
        assert!(
            (9_998..=10_000).contains(&sum),
            "the two shares are the whole capture, less truncation: {sum}"
        );
    }

    /// R311y715 (§C G6) — the share a READER sees, in both renderings at once.
    ///
    /// The census's own denominator has been pinned since R311y714; the
    /// CONVERSION that turns its basis points into the percentage a person
    /// reads had nothing on it. Changing the text render's divisor from 100 to
    /// 1000 left all 392 tests green — a figure ten times wrong on the page,
    /// while the JSON beside it stayed right, which is the two-renderings
    /// disagreement R311y664 measured the hard way.
    ///
    /// The existing CLI test could not catch it: its capture is scouting-only,
    /// so every share is `null` and the text prints a zero that is zero under
    /// any divisor. A share must be NON-ZERO for its conversion to be visible.
    #[test]
    fn the_printed_percentage_and_the_exported_basis_points_are_one_figure() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::tcp_packet_reverse(2000, &framed_init(&[0xB2; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            2,
            &tcp_packet(
                1000 + framed_init(&[0xA1; 4]).len() as u32,
                &framed_keepalive(),
            ),
        );
        d.finish();

        let census = nodes(&d);
        let report = crate::report::CaptureReport::of(&d).with_nodes(&census);
        let text = report.to_text();
        let json = report.to_json();

        // ANTI-VACUITY: a share of zero is zero under any divisor, so the
        // fixture must state a real one before anything below means anything.
        for i in 0..census.nodes().len() {
            let bp = census
                .share_bp(i)
                .expect("every direction on this flow has an owner");
            assert!(bp > 0, "node {i} must carry traffic: {text}");
            assert!(
                json.contains(&alloc::format!("\"share_bp\":{bp}")),
                "the export states the basis points as they are: {json}"
            );
            assert!(
                text.contains(&alloc::format!("share {}.{:02}%", bp / 100, bp % 100)),
                "and the page states the SAME figure as a percentage: {text}"
            );
        }

        // Read back what the page actually prints, rather than recomputing it:
        // the percentages a reader sees must add up to the capture.
        let printed: alloc::vec::Vec<u32> = text
            .split("-- share ")
            .skip(1)
            .filter_map(|rest| rest.split('%').next())
            .filter_map(|p| {
                let (whole, frac) = p.split_once('.')?;
                Some(whole.parse::<u32>().ok()? * 100 + frac.parse::<u32>().ok()?)
            })
            .collect();
        assert_eq!(printed.len(), census.nodes().len(), "one line each: {text}");
        let sum: u32 = printed.iter().sum();
        assert!(
            (9_998..=10_000).contains(&sum),
            "the printed percentages are the whole capture, less truncation: \
             {printed:?}"
        );
    }

    /// R311y714 (§1.1f) — THE DENOMINATOR. A share is of the whole capture,
    /// not of the part this reader could attribute.
    ///
    /// Written because the first version of the test above did NOT bind this:
    /// changing the divisor to the attributed bytes alone left every assertion
    /// green. The fixture that catches it needs PARTIAL attribution — one flow
    /// with a handshake and one without — and then the difference is the whole
    /// point: over the attributed part the identified node reads as 100%, and
    /// over the capture it reads as its actual share of the traffic.
    #[test]
    fn a_share_is_of_the_whole_capture_and_not_of_the_attributed_part() {
        let mut d = Dissection::new();
        // Flow 1: a full handshake, so both directions have an owner.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &crate::datagram_tests::tcp_packet_reverse(2000, &framed_init(&[0xB2; 4])),
        );
        // Flow 2: a DIFFERENT 5-tuple carrying traffic with no handshake in the
        // capture — the mid-session flow, whose bytes belong to nobody this
        // reader can name.
        let mut other = tcp_packet(3000, &framed_keepalive());
        other[26] = 99;
        d.push_packet(LINKTYPE_ETHERNET, 2, &other);
        d.finish();

        assert!(
            d.byte_residue().recovered > 0,
            "the fixture must carry bytes at all"
        );
        let census = nodes(&d);
        assert!(
            census.unattributed_bytes() > 0 && census.attributed_bytes() > 0,
            "the fixture must be PARTIALLY attributed, or it cannot see the \
             difference: attributed {}, unattributed {}",
            census.attributed_bytes(),
            census.unattributed_bytes()
        );
        let sum: u32 = (0..census.nodes().len())
            .map(|i| census.share_bp(i).unwrap())
            .sum();
        assert!(
            sum < 10_000,
            "the named nodes cannot be the whole capture while some of it is \
             uncredited: {sum} bp"
        );
    }

    /// R311y714 — the same capture WITHOUT its handshake attributes nothing,
    /// and says so.
    ///
    /// The mid-session capture, which is the ordinary case on a deployment
    /// somebody is debugging. Not a degenerate input: it is the input.
    #[test]
    fn a_capture_with_no_handshake_attributes_nothing_and_says_so() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed_keepalive()));
        d.finish();

        let census = nodes(&d);
        assert!(census.nodes().is_empty(), "no node named itself");
        assert!(
            census.unattributed_bytes() > 0,
            "and the bytes are counted as uncredited rather than dropped"
        );
        assert_eq!(census.attributed_bytes(), 0);
        assert_eq!(
            census.share_bp(0),
            None,
            "a share over an empty numerator must be absent, not zero"
        );
    }

    /// One length-prefixed KeepAlive.
    fn framed_keepalive() -> Vec<u8> {
        alloc::vec![1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// R311y714 (§1.1f, [REDACTED-REQ]) — a node says WHERE it can be reached, and
    /// the census keeps it.
    ///
    /// The other half of an identity: a zid answers "who" and a locator
    /// answers "where", and a reader holding a deployment's config has the
    /// second and not the first. Taken from the HELLO's own list and never
    /// from the flow's addresses — across a NAT those are different claims,
    /// and the NAT case is the reason this plane is keyed by zid at all.
    #[test]
    fn a_hello_tells_the_census_where_its_node_can_be_reached() {
        let mut d = Dissection::new();
        // The SCOUT first, so the HELLO answering it is read as an answer.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &scout_message()),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet(
                [192, 168, 1, 9],
                7447,
                [192, 168, 1, 5],
                43210,
                &crate::datagram_tests::hello_with_locators(),
            ),
        );
        d.finish();

        let census = nodes(&d);
        let responder = census
            .nodes()
            .iter()
            .find(|n| n.evidence.hello > 0)
            .expect("the HELLO named its sender");
        assert_eq!(
            responder.locators,
            alloc::vec![String::from(crate::datagram_tests::PEER_LOCATOR)],
            "the advertised locator is what a config file can be matched \
             against: {responder:?}"
        );
        // The asker advertised nothing, and an empty list is the honest answer
        // rather than the address this capture happened to see it from.
        let asker = census
            .nodes()
            .iter()
            .find(|n| n.evidence.scout > 0)
            .expect("the SCOUT named its asker");
        assert!(asker.locators.is_empty(), "{asker:?}");
    }

    /// R311y714 — the node plane ALONE on a report page.
    ///
    /// Required by the solo-plane-page lint, and the lint's reason is measured
    /// history: R311y618 severed one leg of `is_complete` and 229 tests stayed
    /// green, because every page carrying that plane also carried another one
    /// that produced the verdict. A plane that has never been alone on a page
    /// is a plane whose own contribution nothing checks.
    #[test]
    fn the_node_plane_alone_on_a_page_still_reports() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([192, 168, 1, 5], 43210, SCOUT_GROUP, 7446, &scout_message()),
        );
        d.finish();
        let census = nodes(&d);
        let report = crate::report::CaptureReport::of(&d).with_nodes(&census);
        assert!(
            report.is_complete(),
            "a scouting capture with nothing missing is complete: {}",
            report.to_text()
        );
        assert!(
            report.to_text().contains("nodes: 1"),
            "and the plane reaches the page it is alone on: {}",
            report.to_text()
        );
    }

    /// One length-prefixed INIT naming `zid`.
    fn framed_init(zid: &[u8]) -> Vec<u8> {
        let wire = init_wire(zid);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    fn init_wire(zid: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_INIT,
            0x09,
            (((zid.len() as u8) - 1) << 4) | 0x02,
        ];
        wire.extend_from_slice(zid);
        wire
    }

    fn join_message(zid: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_JOIN,
            0x09,
            (((zid.len() as u8) - 1) << 4) | 0x02,
        ];
        wire.extend_from_slice(zid);
        // lease, next_sn reliable / best-effort: one-byte VLE each.
        wire.extend_from_slice(&[0x0A, 0x00, 0x00]);
        wire
    }
}
