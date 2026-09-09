// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    /// Capture anchor of the first message that named it.
    ///
    /// R311y919 (open-debt item 452) — THE NAME IS WRONG OVER A STREAM AND IS
    /// RENAMED (R2119, open-debt item 455). The value is
    /// `PassiveFrame::stream_offset`, which is a packet index on a datagram
    /// link and a BYTE OFFSET on a stream one, so under the old name
    /// `first_packet` this field reported an offset while saying packet. A
    /// wrong name is charged to every reader, and R311y919 could only put
    /// [`Self::anchors`] beside it because a rename of an emitted key was not
    /// expressible then.
    ///
    /// It is now. Item 509 gave every document its own revision and made a
    /// rename an ordinary two-step edit, so the Rust field carries the right
    /// name from here and the census document emits BOTH keys for one
    /// revision — `first_packet` announced as retiring — before the next
    /// revision drops it. See `crate::doc_revision`.
    pub first_anchor: usize,
    /// R2456 (open-debt item 701) — capture anchor of the LAST message that
    /// named it, which is what says a node STOPPED appearing.
    ///
    /// # The question [`Self::first_anchor`] alone cannot answer
    ///
    /// The consumer report that asked for this named the hole precisely: this
    /// plane is CUMULATIVE, so a node never leaves the list, and diffing two
    /// snapshots cannot report a departure either — the earlier set is always a
    /// subset of the later one. With only a first anchor, "this node is gone"
    /// is not expressible from the document at all, and the cumulative property
    /// that makes it inexpressible is one this workspace wrote down itself, in
    /// `wz_dissect_live_census`'s header.
    ///
    /// The sibling row has carried the pair since R311y918
    /// (`crate::agg::KeyexprRow::last_anchor`), from the same walk and one line
    /// away. Nothing had to be TRACKED to close this: this census's own
    /// `intern_scouted` already receives the anchor of every observation and,
    /// until now, used it to create the node and then dropped it.
    ///
    /// # Why `max` and not assignment
    ///
    /// A node is named on MANY flows ([`Self::flows`]), and the walk visits
    /// flows in the flow table's order rather than in anchor order — so a
    /// packet index from a later flow can be smaller than one already recorded.
    /// Plain assignment would make this the anchor of the most recently WALKED
    /// observation, which is not the same claim as the last one SEEN and would
    /// let the value move backwards. The sibling row assigns because it folds
    /// one list at a time; this plane does not have that luxury.
    pub last_anchor: usize,
    /// R2456 (open-debt item 701) — whether the pair above spans EVERY
    /// observation of this node, or only those in the space that opened it.
    ///
    /// The node edition of [`crate::agg::KeyexprRow::anchors_exact`], here for
    /// the same reason it is there and reached by a different route: a keyexpr
    /// row folds both directions of many flows, and a node is named on many
    /// flows too. An anchor is a coordinate in ONE space, so a node first seen
    /// on a UDP flow (a capture-global packet index) and seen again inside a
    /// TCP stream (a byte offset in that stream's direction) has two
    /// coordinates that cannot bound one interval.
    ///
    /// Reporting the pair anyway would be the failure this field's own
    /// acceptance test refuses: an interval whose ends are in different spaces
    /// spans nothing, and a consumer cannot see that from the numbers. So a
    /// foreign observation makes this `false` instead of extending the pair,
    /// and [`Self::anchors`] keeps naming the space the pair IS in.
    ///
    /// Structural, like the sibling's: always emitted, `true` on the ordinary
    /// single-space node, so a consumer never reads an absent key as "exact".
    pub anchors_exact: bool,
    /// R311y919 (open-debt item 452) — which space [`Self::first_anchor`] is
    /// in. Read this before reading that.
    ///
    /// R2456 — and [`Self::last_anchor`], when [`Self::anchors_exact`].
    pub anchors: crate::AnchorSpace,
    /// R2456 (open-debt item 701) — the space TOKEN the pair is in, which is
    /// finer than [`Self::anchors`] and is why it is not emitted.
    ///
    /// [`crate::AnchorSpace`] says how to READ an anchor; this says which
    /// coordinate system it is a number in. Two directions of two different
    /// stream lists are all `StreamBytes` and are four spaces, so the KIND
    /// cannot decide whether an observation extends the pair. The kind is what
    /// a document reports, because a reader can act on it; the token exists
    /// only to answer that question, and is `pub(crate)` for
    /// `crate::agg::KeyexprRow::space`'s reason.
    pub(crate) space: usize,
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
    /// R2457 (open-debt item 702) — the list's index in
    /// `crate::Dissection::message_lists`, which is what
    /// [`SessionGrouping`] keys by.
    ///
    /// [`Self::flow`] cannot do that job. A TCP flow and a UDP flow may carry
    /// the identical 5-tuple — `Dissection::message_lists_with_origin` says so
    /// where it explains why an origin rides beside the key — so a grouping
    /// keyed by [`FlowKey`] would hand one session's owners to the other
    /// list. The index is the same one `crate::agg` and `crate::interest`
    /// already take, from the same `enumerate()` over the same iterator, which
    /// is what makes the three walks comparable at all.
    pub list: usize,
}

/// R2456 (open-debt item 701) — WHERE one observation sits, as the three facts
/// a node's anchor pair needs and nothing else.
///
/// A struct rather than three parameters because they travel together and are
/// meaningless apart: an anchor without its space is a number in an unstated
/// coordinate system, which is the defect `crate::AnchorSpace` was introduced to
/// end. Threading them separately through
/// [`NodeCensus::intern`] / [`NodeCensus::intern_scouted`] would also put this
/// census's second producer one argument away from passing the wrong one.
#[derive(Debug, Clone, Copy)]
struct At {
    /// The observation's anchor, in [`Self::space`].
    anchor: usize,
    /// How to READ [`Self::anchor`] — what the document reports.
    kind: crate::AnchorSpace,
    /// WHICH coordinate system [`Self::anchor`] is a number in. See
    /// [`ObservedNode::space`].
    space: usize,
}

/// A capture read as a set of nodes and the links between them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeCensus {
    /// R311y919 (open-debt item 452) — the coordinate space of the list being
    /// walked, set once per [`Self::observe_flow`].
    anchors: crate::AnchorSpace,
    /// R2456 (open-debt item 701) — which message list is being walked, set
    /// once per [`Self::observe_flow`]. Half of the space token; see
    /// [`Self::space_of`].
    ///
    /// On the census for [`Self::anchors`]' reason, and taken as an argument
    /// for `crate::interest::InterestCensus::observe_flow`'s: without it, two
    /// directions of two different stream lists are one number, and a node seen
    /// on both would have its anchor pair silently extended across a boundary
    /// the pair cannot cross.
    list: usize,
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

    /// Round 2016 (item 268) — WHO IS ON THIS SIDE OF THIS FLOW.
    ///
    /// The one lookup that lets the interest plane and this one meet. A
    /// declaration knows the flow it went past on and the DIRECTION that made
    /// it (`DeclaredInterest::declarer`, in the interest plane); this answers
    /// which zid that direction belongs to, and "zid a1a1a1a1 subscribes to
    /// `robot/**`" falls out of the two.
    ///
    /// ⚠ That name is NOT a doc link, and deliberately. The interest plane is
    /// behind `network-codecs`; a link to it resolves in an all-features build
    /// of this crate and is unresolved in every lean one, which is a red no
    /// per-crate doc run can show. Round 2016 shipped it as a link and Round
    /// 2017's push found it on `wz-runtime-tokio`.
    ///
    /// # `None` is a real answer and the commoner one
    ///
    /// It comes back only for a flow with a LINK — both ends named themselves,
    /// which needs the handshake to be in the capture. A tap started
    /// mid-session has no Init to read, so it has nodes it cannot place and
    /// directions it cannot own. Answering with a guess there — the flow's
    /// address, say, or the only zid seen nearby — would be this plane's own
    /// stated failure: `unattributed_bytes` exists because a share computed
    /// over an invented denominator reads as a measurement.
    ///
    /// R311y869 saw this join was one lookup away and did not make it, on the
    /// ground that the honest arm needs a fixture of its own. It has one now.
    pub fn zid_on(&self, flow: &FlowKey, dir: Direction) -> Option<&[u8]> {
        let link = self.links.iter().find(|l| &l.flow == flow)?;
        let at = match dir {
            Direction::A => link.a,
            Direction::B => link.b,
        };
        self.nodes.get(at).map(|n| n.zid.as_slice())
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
    pub fn observe_flow(
        &mut self,
        flow: &FlowKey,
        frames: &[PassiveFrame],
        // R2456 (open-debt item 701) — the list's index in
        // `Dissection::message_lists()`, which `crate::agg` and
        // `crate::interest` already take for the same reason: it is half the
        // space token, and without it two directions of two different flows are
        // one number.
        list: usize,
    ) {
        // R2206 (open-debt item 561) — the space is read off the frames rather
        // than handed in. It arrived as an argument decided one layer up by a
        // match over the message lists, and that second opinion was item 561.
        // The first frame answers for the list: every frame of one list comes
        // out of the same producer, and `the_space_a_list_reports_is_the_one_\
        // its_frames_carry` is what holds that.
        if let Some(frame) = frames.first() {
            self.anchors = crate::anchor_space_of(frame);
        }
        self.list = list;
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
    ///
    /// # R2456 (open-debt item 701) — this producer names its own space
    ///
    /// A [`crate::ScoutingDatagram`]'s anchor is a `packet_index`, so this list
    /// is always [`crate::AnchorSpace::PacketIndex`] and there is nothing to
    /// read off a frame, because there are no frames here.
    ///
    /// It used to take the space from this census's own `anchors` field, which
    /// [`Self::observe_flow`] sets and this method never did — so a node first
    /// named by a HELLO inherited the space of whichever message list the walk
    /// happened to finish on, and on a capture whose last list was a stream it
    /// reported a capture-global packet index under `"offset_space":"stream"`.
    /// Harmless while the document emitted one anchor per node and nothing
    /// compared two; not harmless once [`ObservedNode::last_anchor`] joined it,
    /// because a leaked space is exactly what
    /// [`ObservedNode::anchors_exact`] exists to notice, and a token that is
    /// itself a leak would have made the flag agree with anything.
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
            // R2456 — PacketIndex by construction, not by inheritance. See the
            // method doc.
            let at = At {
                anchor: datagram.packet_index,
                kind: crate::AnchorSpace::PacketIndex,
                space: self.space_of(crate::AnchorSpace::PacketIndex, Direction::A),
            };
            let idx = self.intern_scouted(&zid, whatami, at, flow);
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
        // R2457 — the LIST as well, read off `self.list` which
        // `observe_flow` set for this walk. Two lists carrying the same flow
        // key are two links, and deduping without it would drop the second.
        let list = self.list;
        let already = self
            .links
            .iter()
            .any(|l| l.a == a && l.b == b && &l.flow == flow && l.list == list);
        if !already {
            self.links.push(ObservedLink {
                a,
                b,
                flow: *flow,
                list,
            });
        }
    }

    /// R2456 (open-debt item 701) — the space token an observation is in.
    ///
    /// `crate::agg::ThroughputTable::observe_flow_where`'s composition, spelled
    /// the same way for the same reason: every
    /// [`crate::AnchorSpace::PacketIndex`] list shares one token because a
    /// packet index is global to the capture, while a byte offset is absolute
    /// only within its own list and its own direction.
    ///
    /// The KIND is a parameter rather than [`Self::anchors`] because this
    /// census has a second producer. [`Self::observe_scouting`] folds a list
    /// that carries no [`PassiveFrame`], so `self.anchors` is whatever the last
    /// [`Self::observe_flow`] left there — see that method for what reading it
    /// would have claimed.
    fn space_of(&self, anchors: crate::AnchorSpace, dir: Direction) -> usize {
        match anchors {
            crate::AnchorSpace::PacketIndex => 0,
            crate::AnchorSpace::StreamBytes => 1 + self.list * 2 + dir_index(dir),
        }
    }

    fn intern(
        &mut self,
        zid: &[u8],
        whatami: Option<u8>,
        frame: &PassiveFrame,
        flow: &FlowKey,
    ) -> usize {
        let at = At {
            anchor: frame.stream_offset,
            kind: self.anchors,
            space: self.space_of(self.anchors, frame.direction),
        };
        self.intern_scouted(zid, whatami, at, flow)
    }

    fn intern_scouted(&mut self, zid: &[u8], whatami: Option<u8>, at: At, flow: &FlowKey) -> usize {
        let idx = match self.nodes.iter().position(|n| n.zid == zid) {
            Some(i) => i,
            None => {
                self.nodes.push(ObservedNode {
                    zid: zid.to_vec(),
                    whatami,
                    evidence: NodeEvidence::default(),
                    first_anchor: at.anchor,
                    last_anchor: at.anchor,
                    anchors_exact: true,
                    anchors: at.kind,
                    space: at.space,
                    flows: Vec::new(),
                    wire_bytes: 0,
                    locators: Vec::new(),
                });
                self.nodes.len() - 1
            }
        };
        let node = &mut self.nodes[idx];
        // R2456 (open-debt item 701) — the pair belongs to the space that
        // OPENED it, which is `crate::agg::ThroughputTable::observe_flow_where`'s
        // rule and is here for the reason `ObservedNode::anchors_exact` states.
        // An observation from another space cannot extend an interval it is not
        // in; what it does instead is make the interval partial, which the node
        // SAYS rather than absorbing the number and reporting a span that spans
        // nothing.
        if node.space == at.space {
            // `max`, not assignment — see `ObservedNode::last_anchor`.
            node.last_anchor = node.last_anchor.max(at.anchor);
        } else {
            node.anchors_exact = false;
        }
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
    // R2456 (open-debt item 701) — `enumerate()`'s index, not a number of this
    // walk's own: it is half the space token, and two lists handed the same one
    // would make two coordinate systems look like one. See
    // `NodeCensus::space_of`.
    for (list, (flow, frames)) in dissection.message_lists().enumerate() {
        census.observe_flow(&flow, frames, list);
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

/// R2457 (open-debt item 702) — which SESSION each message list belongs to, and
/// which side of it each direction is.
///
/// # What this is for
///
/// A keyexpr id is minted by a session and is a fact about that session.
/// [`crate::agg::KeyexprSpaces`] used to key its tables by the flow's own
/// direction, which is right only while a session has ONE link: under
/// `transport/unicast/max_links: 2` a `DeclKexpr` leaves on the link that was
/// dialled first and the data using the alias may leave on the second, and a
/// per-flow table then holds the declaration in one instance and the reference
/// in another. It never cross-resolved — the conservative direction — it simply
/// could not resolve.
///
/// This is the map that raises the unit. Nothing else about the rule changes:
/// two sessions still get separate tokens and their id `3`s stay unrelated.
///
/// # Why the node pair IS the session, exactly
///
/// Not an approximation, and this was checked upstream rather than assumed.
/// zenoh keeps established unicast transports in
/// `HashMap<ZenohIdProto, Arc<dyn TransportUnicastTrait>>`
/// (`zenoh-transport-1.10.0/src/unicast/manager.rs:108`) and dispatches an
/// arriving link on `guard.get(&config.zid)`
/// (same file, `:800`): a zid it already holds a transport for means the link
/// JOINS that transport, and only an unknown zid makes a new one. So a pair of
/// zids can hold at most one unicast session, and grouping by the pair is the
/// session rather than a band around it.
///
/// ⚠ The version read is the one this machine has provisioned in the registry
/// cache — 1.10.0, where `CLAUDE.md`'s reference paragraph says 1.5.0. The file
/// and lines are cited so the next reader can re-run the check rather than
/// inherit it.
///
/// # What it CANNOT group, and why that is the fallback and not a bug
///
/// [`NodeCensus`] records a link only where BOTH ends named themselves with an
/// INIT on one flow — see the module docs for why less than you would think
/// counts. A capture that starts mid-session has no handshake in it, so its
/// flows appear in no link, [`Self::owners`] answers
/// [`crate::agg::SpaceOwner::Flow`] for them, and resolution reaches exactly as
/// far as it did before R2457. That is the honest answer for such a flow, and
/// it is REPORTED as such: a reference missed under a `Flow` owner is
/// [`crate::agg::UnresolvedCause::NoSession`], which tells a consumer the
/// declaration may be one flow over rather than absent.
#[derive(Debug, Clone, Default)]
pub struct SessionGrouping {
    /// Per list index, the owner of each direction. Absent for a list this
    /// capture could not attribute to a session.
    by_list: alloc::collections::BTreeMap<usize, [crate::agg::SpaceOwner; 2]>,
    /// How many distinct sessions the links named.
    sessions: usize,
}

impl SessionGrouping {
    /// Derive the grouping from a census's links.
    ///
    /// # The unit, spelled
    ///
    /// A SESSION is an unordered pair of node indices — see the type docs for
    /// the upstream reading that makes the pair exact. A SIDE is a
    /// `(session, node)`, and it is that and not the node alone because one
    /// node holds a separate session, and so a separate id space, with each
    /// peer it talks to.
    pub fn of(census: &NodeCensus) -> Self {
        use alloc::collections::BTreeMap;

        // The session a node PAIR stands under, and the side token a
        // `(session, node)` stands under. Both interned in link order, so the
        // tokens a capture hands out do not depend on map internals.
        let mut sessions: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        let mut sides: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        let mut by_list = BTreeMap::new();
        for link in census.links() {
            let pair = (link.a.min(link.b), link.a.max(link.b));
            let next = sessions.len();
            let session = *sessions.entry(pair).or_insert(next);
            let mut token = |node: usize| {
                let next = sides.len();
                crate::agg::SpaceOwner::Session(*sides.entry((session, node)).or_insert(next))
            };
            // Direction A is `link.a` and B is `link.b`: `observe_flow` fills
            // `ends` by `dir_index(frame.direction)` and hands them to
            // `record_link` in that order. Reversing them here would resolve
            // every reference against the peer's table, which is the failure
            // `KeyexprSpaces::resolve` documents as never happening.
            by_list.insert(link.list, [token(link.a), token(link.b)]);
        }
        Self {
            sessions: sessions.len(),
            by_list,
        }
    }

    /// The two owners for one message list.
    ///
    /// [`crate::agg::SpaceOwner::Flow`] on both sides for a list this capture
    /// could not attribute — which is the pre-R2457 behaviour, kept as the
    /// fallback the type docs describe.
    pub fn owners(&self, list: usize) -> [crate::agg::SpaceOwner; 2] {
        self.by_list.get(&list).copied().unwrap_or([
            crate::agg::SpaceOwner::Flow { list, side: 0 },
            crate::agg::SpaceOwner::Flow { list, side: 1 },
        ])
    }

    /// How many distinct sessions the links named.
    ///
    /// A session with two links is ONE here, which is the whole point: read
    /// beside [`Self::grouped_lists`], a session count below the list count is
    /// what a multilink capture looks like.
    pub fn sessions(&self) -> usize {
        self.sessions
    }

    /// How many message lists were attributed to a session.
    ///
    /// The rest fall back to per-flow spaces. A reader comparing this with the
    /// number of lists in the capture learns how much of it began mid-session.
    pub fn grouped_lists(&self) -> usize {
        self.by_list.len()
    }
}

/// The grouping for a whole capture, in one call.
///
/// The ordering this plane imposes, named where a caller meets it: the node
/// census must be complete BEFORE the first keyexpr fold, because the fold
/// resolves as it walks and a session it learns about later cannot retroactively
/// bind an alias an earlier record referenced. See `crate::agg::aggregate_where`
/// for what that costs and why the alternatives were not taken.
pub fn session_grouping(dissection: &crate::Dissection) -> SessionGrouping {
    SessionGrouping::of(&nodes(dissection))
}

/// R2459 (open-debt item 704) — the `Dissection::message_lists` index of each
/// STREAM flow's list, in `Dissection::flows` order.
///
/// # Why a door, and why HERE
///
/// [`SessionGrouping::owners`] is keyed by the position in
/// `Dissection::message_lists`, which the census planes get for free because
/// they ARE that walk. A renderer keyed on the two FLOW TABLES is not, and it
/// cannot compute the position either: a datagram flow contributes one list
/// PLUS one per QUIC stream PLUS one for its RFC 9221 datagrams, so
/// `flows.len() + i` is right only for a capture that holds no QUIC flow. Two
/// such renderers exist — `crate::fields_json` and `wz-analyze`'s field
/// listing — and a second copy of this derivation is exactly the drift
/// `Dissection::message_lists` was made to end.
///
/// It lives beside the grouping rather than on `Dissection` because it answers
/// that type's OWN question, inverted: `owners` maps a list index to a pair of
/// spaces, and this maps a row of a flow table to its list index. One module
/// owns the key space both directions.
///
/// DERIVED by reading the ORIGINS rather than by counting: every list whose
/// origin is `MessageListOrigin::Stream` is one row of `flows()` in order,
/// because that walk is the only producer of that origin.
pub fn stream_list_indices(dissection: &crate::Dissection) -> alloc::vec::Vec<usize> {
    list_indices(dissection, |origin| {
        matches!(origin, crate::MessageListOrigin::Stream)
    })
}

/// R2459 (open-debt item 704) — the `Dissection::message_lists` index of each
/// DATAGRAM flow's CLEARTEXT list, in `Dissection::datagram_flows` order.
///
/// [`stream_list_indices`] carries the argument for both. The cleartext list is
/// `MessageListOrigin::Datagram`, whose only producer is the first entry of
/// `DatagramDissection::frame_lists_with_origin`, so the k-th such list is the
/// k-th row of that table.
///
/// ⚠ This names the flow's FIRST list, not its only one. A caller that wants
/// the flow's whole id space has to fold over
/// `DatagramDissection::frame_lists`: the QUIC sub-lists carry declarations
/// too, and open-debt item 705 is the three production walks that do not.
pub fn datagram_list_indices(dissection: &crate::Dissection) -> alloc::vec::Vec<usize> {
    list_indices(dissection, |origin| {
        matches!(origin, crate::MessageListOrigin::Datagram)
    })
}

/// R2460 (open-debt item 705) — the `Dissection::message_lists` index of EVERY
/// list a datagram flow holds, one row per `Dissection::datagram_flows` entry
/// and in `DatagramDissection::frame_lists_with_origin` order.
///
/// # Why the flow's whole span and not only its first list
///
/// [`datagram_list_indices`] names the CLEARTEXT list, which is the one the two
/// field documents render. The declarations are not all there: a QUIC sub-list
/// carries `DeclKexpr` too, and the three production walks that absorbed
/// `flow.frames` alone left those out of every per-flow table. The census
/// planes never had the defect because they walk
/// `Dissection::message_lists` — every list, one `KeyexprSpaces` — so the two
/// renderings of one capture disagreed about whether an id resolves.
///
/// # Why an index per list rather than the flow's one owner reused
///
/// [`SessionGrouping`] is keyed by LIST — see [`ObservedLink::list`], and
/// `by_list` above — because a link is recorded only where both ends sent an
/// INIT on that list. A QUIC sub-list whose stream carried the handshake gets
/// the SAME `agg::SpaceOwner::Session` token as its flow's cleartext list, and
/// one that did not gets the `agg::SpaceOwner::Flow` fallback. Reusing the
/// cleartext owner for every sub-list would resolve references the census
/// leaves unresolved — more generous than the plane this is supposed to agree
/// with, which is the same class of defect pointing the other way.
///
/// DERIVED, not counted: the enumeration emits a flow's lists contiguously and
/// `MessageListOrigin::Datagram` is the first of each run, so a row opens at
/// that origin and the QUIC origins join the row already open. `flows.len() + i`
/// is what this replaces, and it is right only for a capture holding no QUIC
/// flow.
pub fn datagram_flow_list_indices(
    dissection: &crate::Dissection,
) -> alloc::vec::Vec<alloc::vec::Vec<usize>> {
    let mut rows: alloc::vec::Vec<alloc::vec::Vec<usize>> = alloc::vec::Vec::new();
    for (list, (_, origin, _)) in dissection.message_lists_with_origin().enumerate() {
        match origin {
            crate::MessageListOrigin::Datagram => rows.push(alloc::vec![list]),
            crate::MessageListOrigin::QuicStream(_) | crate::MessageListOrigin::QuicDatagram => {
                // Cannot precede its own `Datagram` — the enumeration emits the
                // cleartext list first for every flow. Skipped rather than
                // panicking if that ever stops holding, because a renderer is
                // the wrong place to learn it: the zip below is what would then
                // be short, and it is checked there.
                if let Some(row) = rows.last_mut() {
                    row.push(list);
                }
            }
            crate::MessageListOrigin::Stream | crate::MessageListOrigin::Serial => {}
        }
    }
    rows
}

/// R2460 (open-debt item 705) — fold a datagram flow's NON-cleartext lists into
/// `spaces`, each under its own owners.
///
/// # The division of labour, and why the cleartext list is not here
///
/// The cleartext list is folded by the caller, one frame at a time, INTERLEAVED
/// with rendering that list's rows: an id has to resolve through the binding
/// that was live when the record travelled, or a replay re-publishes a payload
/// under a name the sender never used. The sub-lists are folded whole, which is
/// the generous form, and `wz-analyze`'s stream half states the reason for the
/// identical decision about its own sink rows: a recovered row does not travel
/// with the frame that produced it, so there is no point in the sequence to
/// fold up to.
///
/// # The order is the census's, which is the whole point
///
/// `DatagramDissection::frame_lists_with_origin` runs Datagram → QuicStream* →
/// QuicDatagram, and `agg::aggregate_grouped` sees those same lists in that
/// same order because both project `Dissection::message_lists`. Folding here,
/// after the caller's cleartext pass and before the next flow, puts this walk
/// on the census's schedule — so the two renderings of one capture answer the
/// same way about whether an id resolves, which is the disagreement item 705
/// names.
///
/// Ends by re-entering the cleartext list's owners, so a caller that renders
/// more of this flow afterwards is in the state it was in. The only effect on
/// such a caller is the absorption.
pub fn absorb_datagram_sublists(
    flow: &crate::DatagramDissection,
    lists: &[usize],
    grouping: &SessionGrouping,
    spaces: &mut crate::agg::KeyexprSpaces,
) {
    let mut pairs = flow.frame_lists_with_origin().zip(lists.iter());
    // The cleartext list, dropped: see the division of labour above.
    let _ = pairs.next();
    for ((_, messages), &list) in pairs {
        spaces.enter_flow(grouping.owners(list));
        for frame in messages.as_slice() {
            spaces.absorb_frame(frame);
        }
    }
    if let Some(&cleartext) = lists.first() {
        spaces.enter_flow(grouping.owners(cleartext));
    }
}

/// The one walk both doors above project, so a producer added to
/// `Dissection::message_lists_with_origin` moves both at once.
fn list_indices(
    dissection: &crate::Dissection,
    want: impl Fn(crate::MessageListOrigin) -> bool,
) -> alloc::vec::Vec<usize> {
    dissection
        .message_lists_with_origin()
        .enumerate()
        .filter(|(_, (_, origin, _))| want(*origin))
        .map(|(list, _)| list)
        .collect()
}

// R311y851 — `pub(crate)`, on the precedent `exchange::tests` set and with the
// same trade named: the census EXPORT's end-to-end test needs a capture in
// which two nodes named themselves, and the INIT builder for one lives here.
// The alternative is a second hand-laid INIT layout in `census_json::tests`,
// which is the copy that drifts — and this one is already pinned against the
// real decoder by the tests below it. The cost is that `cfg(test)` visibility
// widens to the crate -> [[feedback_cfg_test_is_a_widener_not_a_gate]].
#[cfg(test)]
pub(crate) mod tests {
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
    pub(crate) fn framed_init(zid: &[u8]) -> Vec<u8> {
        let wire = init_wire(zid);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// R2457 (open-debt item 702) — the SAME INIT without the length prefix,
    /// which is what a datagram link carries.
    ///
    /// `pub(crate)` on the precedent this module's header states: the session
    /// grouping's acceptance in `crate::agg` needs a capture where two flows
    /// carry the same pair of zids, and a second hand-laid INIT layout there is
    /// the copy that drifts. This one is pinned against the real decoder by the
    /// tests above.
    pub(crate) fn init_wire(zid: &[u8]) -> Vec<u8> {
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

    /// R2456 (open-debt item 701) — THE ACCEPTANCE, and it is the consumer's
    /// own derivation rather than this round's.
    ///
    /// # Why "the key is there" is not the test
    ///
    /// The report that asked for [`ObservedNode::last_anchor`] wrote the
    /// acceptance out and said why, and the why is the part that matters: a
    /// build that pinned EVERY node's last anchor to the newest anchor in the
    /// capture satisfies "the key is present and is a plausible number", and
    /// that build is WORSE than the one with no key at all, because its
    /// document reads "everyone is still here". This workspace has paid for the
    /// cousin of that repeatedly under the name "a population of zero reports
    /// green"; here the population is fine and the ORACLE is what would be
    /// vacuous.
    ///
    /// So the claim under test is a MOVEMENT: while the census goes on growing,
    /// the anchor of a node that stopped being named must STOP.
    ///
    /// # The three numbers, and what each one rules out
    ///
    /// `0xA1` is named at anchors 0 and 1 and then never again; `0xB2` is named
    /// at 2, 3 and 4. So `A.last_anchor` must be 1, and each of the other two
    /// values it could plausibly have is a different defect:
    ///
    /// * `0` — the field is `first_anchor` under a second name, which is the
    ///   "nothing was actually recorded" build;
    /// * `4` — every node is pinned to the newest anchor, which is the build
    ///   the report named as worse than absence.
    ///
    /// A is named TWICE on purpose. With one appearance, `first` and `last`
    /// coincide and the first defect above would pass.
    #[test]
    fn a_node_that_stopped_appearing_keeps_the_anchor_it_stopped_at() {
        let mut d = Dissection::new();
        // One multicast flow, five packets. A announces itself twice and goes
        // quiet; B goes on announcing itself, so the census keeps growing.
        for (packet, zid) in [(0usize, 0xA1u8), (1, 0xA1), (2, 0xB2), (3, 0xB2), (4, 0xB2)] {
            d.push_packet(
                LINKTYPE_ETHERNET,
                packet,
                &udp_packet(
                    [10, 0, 0, 1],
                    7447,
                    [224, 0, 0, 224],
                    7447,
                    &join_message(&[zid; 4]),
                ),
            );
        }
        d.finish();

        let census = nodes(&d);
        let a = census.node(&[0xA1; 4]).expect("A named itself");
        let b = census.node(&[0xB2; 4]).expect("B named itself");
        // The census DID go on growing after A fell silent. Without this the
        // assertion below would hold on a capture where nothing happened after
        // A's last message, and would be testing arithmetic rather than the
        // property.
        assert!(
            b.last_anchor > a.last_anchor,
            "the fixture must keep growing after A stops: {a:?} {b:?}"
        );
        assert_eq!(
            a.first_anchor, 0,
            "A was first named by the capture's first packet: {a:?}"
        );
        assert_eq!(
            a.last_anchor, 1,
            "A's anchor must STOP where A stopped: 0 would mean nothing was \
             recorded, {} would mean every node is pinned to the newest \
             anchor and the document claims everyone is still here: {a:?}",
            b.last_anchor
        );
        assert_eq!(b.last_anchor, 4, "B's anchor must still be moving: {b:?}");
        // And the pair is over ONE space, so it is an interval a consumer may
        // subtract. The mixed case is the next test.
        assert!(a.anchors_exact && b.anchors_exact, "{a:?} {b:?}");
    }

    /// R2456 (open-debt item 701) — the reporter's OPEN QUESTION, answered by
    /// measurement: a node's interval can be inexact, exactly as a keyexpr
    /// row's can, so the node plane needs the flag too.
    ///
    /// The report asked whether an `anchors_exact` node edition was needed and
    /// asked for an answer rather than a guess. It is needed, and this is the
    /// capture that shows why: one zid names itself both on a multicast UDP
    /// flow, where an anchor is a capture-global packet index, and inside a TCP
    /// stream, where it is a byte offset in that stream's direction. Those two
    /// numbers cannot bound one interval, and a pair reported as though they
    /// could would be a span over nothing — the same defect the throughput row
    /// has carried the flag for since R311y918.
    ///
    /// The CONTROL is the test above: an ordinary single-space node reports
    /// `true`, so this flag is not hardwired to the answer that makes this
    /// assertion pass.
    #[test]
    fn a_node_named_in_two_coordinate_spaces_says_its_pair_is_not_an_interval() {
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(
                [10, 0, 0, 1],
                7447,
                [224, 0, 0, 224],
                7447,
                &join_message(&[0xA1; 4]),
            ),
        );
        // The SAME zid, inside a TCP stream. `stream_offset` is a byte offset
        // here and a packet index above.
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1000, &framed_init(&[0xA1; 4])),
        );
        d.finish();

        let a = census_of(&d, &[0xA1; 4]);
        assert!(
            !a.anchors_exact,
            "the two anchors are in different spaces, so the pair spans \
             nothing and the node must say so: {a:?}"
        );
    }

    /// R2456 — and the DOCUMENT carries it, which is the surface a consumer
    /// actually reads.
    ///
    /// Separate from the two above because they judge the census type and this
    /// judges the emitted JSON. The rendering is where item 701 was reported
    /// from, and this workspace has twice had a field that was right in the
    /// struct and wrong on the way out.
    #[test]
    fn a_stopped_nodes_anchor_is_frozen_in_the_document_too() {
        let mut d = Dissection::new();
        for (packet, zid) in [(0usize, 0xA1u8), (1, 0xA1), (2, 0xB2), (3, 0xB2)] {
            d.push_packet(
                LINKTYPE_ETHERNET,
                packet,
                &udp_packet(
                    [10, 0, 0, 1],
                    7447,
                    [224, 0, 0, 224],
                    7447,
                    &join_message(&[zid; 4]),
                ),
            );
        }
        d.finish();

        let json = crate::census_json::nodes_json(&nodes(&d));
        // BY VALUE and by adjacency, so a document that emitted the key with
        // the newest anchor in it fails here rather than passing on the key's
        // presence.
        assert!(
            json.contains("\"first_anchor\":0,\"last_anchor\":1,\"anchors_exact\":true"),
            "A stopped at anchor 1 and the document must say so: {json}"
        );
        assert!(
            json.contains("\"first_anchor\":2,\"last_anchor\":3,\"anchors_exact\":true"),
            "B was still being named at anchor 3: {json}"
        );
    }

    /// The one node this capture named, by zid.
    fn census_of(d: &Dissection, zid: &[u8]) -> ObservedNode {
        let census = nodes(d);
        census
            .node(zid)
            .unwrap_or_else(|| panic!("the capture must name {zid:?}: {:?}", census.nodes()))
            .clone()
    }
}
