// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The capture read as SESSIONS: one row per zenoh session, with the cells a
//! sessions editor shows and nothing a consumer has to join or interpret.
//!
//! # The unit, and why it is not the flow
//!
//! Every other plane here is keyed by a FLOW, the unit the wire hands out. A
//! session is the unit a person asks about: a node reconnecting from a new source
//! port is two flows and one session, a node reached over two links is two flows
//! and one session. The identity of a session is the PAIR of zids its handshake
//! named, as `node::SessionGrouping` argues from upstream (a pair of zids holds at
//! most one unicast session), so a row groups the flows whose pair is the same.
//! A flow whose pair is not known is a row of its own, because grouping by a
//! guess is the failure this plane exists to avoid.
//!
//! # A tap has no local side
//!
//! The ROLE a passive observer can state is the OBSERVED INITIATOR: the zid of the
//! end that sent the InitSyn. The other end is the acceptor, the zid of the end
//! that sent the InitAck. Neither is "local" and neither is "remote": there is no
//! such thing at a tap, and a column that said so would be an invention.
//!
//! # Counters are kept at INGEST
//!
//! The decoded messages a dissection holds are capped by `frames_per_flow`, and a
//! live tap trims them from the front. A row built from them would lose the
//! handshake of a long session (the Init is the oldest message), report a count
//! that stops growing at the ceiling, and date a session from the oldest message
//! it still held. So what a row needs is taken where the data arrives, in a
//! [`LinkIngest`] on each flow, and from two counters the dissection already keeps
//! at ingest and that no trim moves:
//!
//! * `frames` is the count of messages EVER produced for the flow's lists
//!   ([`crate::messages::MessageList::produced`]);
//! * `bytes` is the flow's recovered byte count (`ByteResidue::recovered`), taken
//!   at the point the flow's bytes are recovered, before anything reads them.
//!
//! # What a cell that cannot be stated looks like
//!
//! A value this reader cannot state is an explicit `null`, never an omitted key,
//! and the row's `unstated` list carries one entry for it naming the cell and a
//! REASON WORD: a consumer shows an unknown as "not read" and must not have to
//! test for a key to learn that. The reasons are the closed set [`Unstated`],
//! declared beside the document and held to this walk by a test, and which of
//! them a cell can carry is [`Cell::reasons`], held by a test to every row.
//!
//! # Flows that are not sessions
//!
//! A multicast group has no handshake and no pair: a peer announces itself to the
//! listeners with a Join, and the node plane records that as an END of a flow,
//! never as a link. A row would invent a pair, so such a flow is not a row. It is
//! COUNTED under [`Excluded`], and so is a flow that carried only discovery
//! (Scout, Hello). The test for "no handshake" is the dissector's own, taken
//! where it is made ([`LinkIngest::handshake_absent`]).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use wz_session_core::inbound::InboundFrame;
use wz_session_core::parse_error::InboundParseError;
use wz_session_core::passive::{
    Direction, PassiveFrame, ReadingEvidence, SessionPhase, SnSteps, UnitReading, VersionEvidence,
};
use wz_session_core::scouting_message::ScoutingFrame;

use crate::link::{FlowKey, LinkKind};
use crate::zenoh_evidence::{model, Check, ZenohEvidence};
use crate::{Dissection, Framing};

/// What the ingest path keeps about one flow that no retention bound may take
/// away.
///
/// Three facts, each one a statement about what ARRIVED rather than about what is
/// still held: the capture instants of the first and the last packet, the zids of
/// the two Inits (which is the identity of a session and is on the OLDEST message
/// of a flow, the first one a ceiling discards), and whether the link was seen to
/// have no handshake.
#[derive(Debug, Clone, Default)]
pub struct LinkIngest {
    /// The smallest capture instant of a packet of this flow, nanoseconds.
    first_ns: Option<u64>,
    /// The largest.
    last_ns: Option<u64>,
    /// Per direction (`A` is index 0), the zid in the latest Init that
    /// direction sent and whether that Init was an InitAck.
    named: [Option<(Vec<u8>, bool)>; 2],
    /// Some datagram of this flow arrived on a link that has no handshake.
    handshake_absent: bool,
    /// The flow produced at least one message this reader decoded as a zenoh
    /// transport message of a kind it knows. An `Unknown` MID is a message the
    /// reader produced and did not understand, and is not evidence that the
    /// bytes are zenoh: four junk bytes decode to one.
    understood: bool,
    /// What the flow's version-bearing messages said, counted here for the
    /// reason the module gives: an Init is the oldest message of a flow and the
    /// first a retention ceiling discards. See [`VersionEvidence`].
    versions: VersionEvidence,
    /// How the flow's framing units read, counted at ingest for the same reason
    /// [`Self::versions`] is. See [`ReadingEvidence`].
    readings: ReadingEvidence,
    /// The observations of the zenoh test this ingest path makes: the cookie
    /// echoes, the version headers and the unit readings. The Init roles are
    /// read off [`Self::named`] and the SN steps off the flow's sessions, both
    /// when the evidence is asked for ([`Self::evidence`]).
    observed: ZenohEvidence,
    /// Per direction, the cookie of the latest InitAck that direction sent, for
    /// the OpenSyn of the other direction to be compared with. Only a flow that
    /// carried an InitAck holds one.
    init_ack_cookie: [Option<Vec<u8>>; 2],
}

/// Whether a flow is zenoh, as the sequential test of [`crate::zenoh_evidence`]
/// reads its evidence's two sums. The closed set:
///
/// * `yes` -- the `yes` sum is at or above [`model::YES_AT`] and the `no` sum
///   is above [`model::NO_AT`];
/// * `no` -- the `no` sum is at or below [`model::NO_AT`] and the `yes` sum is
///   below [`model::YES_AT`];
/// * `undecided` -- otherwise: too little evidence either way, which is the
///   word a lone header earns and the word a flow starts with, or both sums
///   past their thresholds at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZenohVerdict {
    /// The evidence crossed the threshold for zenoh.
    Yes,
    /// It crossed the threshold against.
    No,
    /// It crossed neither.
    Undecided,
}

impl ZenohVerdict {
    /// The word `evidence` comes to.
    pub fn of(evidence: &ZenohEvidence) -> ZenohVerdict {
        let yes = evidence.log2_lr_millibits() >= model::YES_AT;
        let no = evidence.log2_lr_no_millibits() <= model::NO_AT;
        match (yes, no) {
            (true, false) => ZenohVerdict::Yes,
            (false, true) => ZenohVerdict::No,
            _ => ZenohVerdict::Undecided,
        }
    }

    /// The word this verdict is written as.
    pub const fn name(self) -> &'static str {
        match self {
            ZenohVerdict::Yes => "yes",
            ZenohVerdict::No => "no",
            ZenohVerdict::Undecided => "undecided",
        }
    }

    /// Every verdict, from an exhaustive match.
    pub fn all() -> [ZenohVerdict; 3] {
        let one = |v: ZenohVerdict| match v {
            ZenohVerdict::Yes => ZenohVerdict::Yes,
            ZenohVerdict::No => ZenohVerdict::No,
            ZenohVerdict::Undecided => ZenohVerdict::Undecided,
        };
        [
            one(ZenohVerdict::Yes),
            one(ZenohVerdict::No),
            one(ZenohVerdict::Undecided),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|v| v.name()).collect();
        words.sort_unstable();
        words
    }
}

/// What a flow's version-bearing messages (Init, Join, Scout, Hello) announced:
/// a different question from [`ZenohVerdict`], which asks whether the bytes are
/// zenoh as this reader reads it. The closed set:
///
/// * `none` -- no version-bearing message was read;
/// * `own` -- every one announced the version this reader reads;
/// * `foreign` -- every one announced another version;
/// * `mixed` -- both were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnouncedVersion {
    /// No version-bearing message.
    None,
    /// This reader's version only.
    Own,
    /// Another version only.
    Foreign,
    /// Both.
    Mixed,
}

impl AnnouncedVersion {
    /// The word `evidence` comes to.
    pub fn of(evidence: VersionEvidence) -> AnnouncedVersion {
        match (evidence.own_version > 0, evidence.foreign_version > 0) {
            (false, false) => AnnouncedVersion::None,
            (true, false) => AnnouncedVersion::Own,
            (false, true) => AnnouncedVersion::Foreign,
            (true, true) => AnnouncedVersion::Mixed,
        }
    }

    /// The word this answer is written as.
    pub const fn name(self) -> &'static str {
        match self {
            AnnouncedVersion::None => "none",
            AnnouncedVersion::Own => "own",
            AnnouncedVersion::Foreign => "foreign",
            AnnouncedVersion::Mixed => "mixed",
        }
    }

    /// Every answer, from an exhaustive match.
    pub fn all() -> [AnnouncedVersion; 4] {
        let one = |v: AnnouncedVersion| match v {
            AnnouncedVersion::None => AnnouncedVersion::None,
            AnnouncedVersion::Own => AnnouncedVersion::Own,
            AnnouncedVersion::Foreign => AnnouncedVersion::Foreign,
            AnnouncedVersion::Mixed => AnnouncedVersion::Mixed,
        };
        [
            one(AnnouncedVersion::None),
            one(AnnouncedVersion::Own),
            one(AnnouncedVersion::Foreign),
            one(AnnouncedVersion::Mixed),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|v| v.name()).collect();
        words.sort_unstable();
        words
    }
}

/// What a flow's Inits say about who initiated it.
///
/// Three answers, because a passive observer can be in three situations: the
/// Inits settle it, they are not there to settle it, or they contradict each
/// other (two InitSyns and no InitAck, which a conforming peer never sends and a
/// hand-built capture can).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Roles {
    /// At most one Init names each role, and the capture holds what it holds:
    /// `initiator` is the zid of the end that sent the InitSyn, `acceptor` the
    /// zid of the end that sent the InitAck, either of them absent.
    Settled {
        /// The InitSyn's sender, where the capture holds the InitSyn.
        initiator: Option<Vec<u8>>,
        /// The InitAck's sender, where the capture holds the InitAck.
        acceptor: Option<Vec<u8>>,
    },
    /// Both directions sent an InitSyn, or both an InitAck: the Inits name two
    /// nodes and do not say which one dialled.
    Contradicted,
}

impl LinkIngest {
    /// A packet of the flow arrived at `ts_ns`.
    ///
    /// The minimum and the maximum rather than the first and the last seen: a
    /// capture written by several interfaces is not in time order, and a session
    /// does not start later because its first packet was written later. A
    /// packet with no clock changes nothing, and a flow whose packets none had one
    /// reports no instant.
    pub(crate) fn observe_packet(&mut self, ts_ns: Option<u64>) {
        let Some(ns) = ts_ns else {
            return;
        };
        self.first_ns = Some(self.first_ns.map_or(ns, |held| held.min(ns)));
        self.last_ns = Some(self.last_ns.map_or(ns, |held| held.max(ns)));
    }

    /// A datagram of the flow arrived on a link with no handshake (a multicast
    /// group, or pico's raweth).
    pub(crate) fn observe_handshake_absent(&mut self) {
        self.handshake_absent = true;
    }

    /// One message the flow's session produced.
    ///
    /// The rule is the node plane's, so a row and a node agree about who named
    /// themselves: a message the link cannot carry (`inadmissible_on_link`)
    /// names nobody, and an Init whose zid decoded to nothing names nobody. The
    /// LATEST Init of a kind wins, as it does for a link there: a flow reused by
    /// another node names the new one, and remembering the node that has gone is
    /// the failure.
    fn observe_frame(&mut self, frame: &PassiveFrame) {
        if matches!(&frame.frame, Ok(decoded) if !matches!(decoded, InboundFrame::Unknown { .. })) {
            self.understood = true;
        }
        // Before the admissibility test: an Init on a link that cannot carry one
        // names nobody, and is still a message of a version.
        let announced = frame.frame.as_ref().map(InboundFrame::announced_version);
        self.versions.observe(announced, frame.unit_read_whole);
        // An Init in a unit not read whole names nobody either: see
        // `PassiveFrame::unit_read_whole`. Neither is evidence of the test: a
        // zenoh peer never sends an Init on a link without a handshake.
        if frame.inadmissible_on_link || !frame.unit_read_whole {
            return;
        }
        if let Ok(Some(version)) = announced {
            self.observe_version(version);
        }
        let seat = usize::from(frame.direction == Direction::B);
        match &frame.frame {
            Ok(InboundFrame::Init { is_ack, body, .. }) => {
                if *is_ack {
                    self.init_ack_cookie[seat] = body.cookie.as_ref().map(|c| c.to_vec());
                }
                if !body.zid.is_empty() {
                    self.named[seat] = Some((body.zid.to_vec(), *is_ack));
                }
            }
            Ok(InboundFrame::Open {
                is_ack: false,
                body,
                ..
            }) => self.observe_cookie_echo(seat, body.cookie.as_ref().map(|c| &c[..])),
            _ => {}
        }
    }

    /// An OpenSyn from `seat`'s direction carried `cookie`: compared with the
    /// cookie the other direction's latest InitAck issued, where the capture
    /// holds one. An empty cookie on both sides matches nothing worth weighing
    /// and is not an observation.
    fn observe_cookie_echo(&mut self, seat: usize, cookie: Option<&[u8]>) {
        let Some(issued) = self.init_ack_cookie[1 - seat].as_deref() else {
            return;
        };
        let echoed = cookie.unwrap_or(&[]);
        if issued.is_empty() && echoed.is_empty() {
            return;
        }
        if issued == echoed {
            self.observed.confirm(
                Check::CookieEcho,
                crate::zenoh_evidence::cookie_echo_weight(issued.len()),
            );
        } else {
            self.observed
                .violate(Check::CookieEcho, model::COOKIE_ECHO_VIOLATED);
        }
    }

    /// The version an admissible version-bearing message announced, out of a
    /// unit read whole: this reader's confirms the check and any other
    /// violates it. Both are weighed, because an observation that could only
    /// confirm would raise the `yes` sum's expectation under the null.
    fn observe_version(&mut self, version: u8) {
        if version == wz_codecs::wire_const::PROTOCOL_VERSION {
            self.observed
                .confirm(Check::VersionHeader, model::VERSION_HEADER);
        } else {
            self.observed
                .violate(Check::VersionHeader, model::VERSION_FOREIGN);
        }
    }

    /// One framing unit's reading, as evidence of the test.
    fn observe_reading(&mut self, reading: UnitReading) {
        let weight = crate::zenoh_evidence::unit_reading_weight(reading);
        if reading == UnitReading::Explained {
            self.observed.confirm(Check::UnitReading, weight);
        } else {
            self.observed.violate(Check::UnitReading, weight);
        }
    }

    /// One framing unit the session produced: every message of it, and the unit
    /// itself counted by how it read.
    ///
    /// `frames` are the records of ONE unit, as
    /// [`wz_session_core::passive::ReadUnit`] hands them out. The messages and
    /// the unit are told together because the unit's class is stamped on its
    /// messages: a caller that told only the messages would lose the count.
    pub(crate) fn observe_unit(&mut self, frames: &[PassiveFrame]) {
        for frame in frames {
            self.observe_frame(frame);
        }
        self.readings.observe_frames(frames);
        // An lz4 batch a build without lz4 cannot open reads `undecoded`
        // whatever its bytes are: counted as a reading, and not weighed as
        // evidence, because it says what the build can do.
        let unopenable = !wz_session_core::passive::OPENS_LZ4_BATCHES
            && frames.iter().any(|f| {
                matches!(
                    f.carried,
                    wz_session_core::passive::Carried::Undecompressible
                )
            });
        if let Some(reading) = UnitReading::of_frames(frames).filter(|_| !unopenable) {
            self.observe_reading(reading);
        }
    }

    /// One scouting datagram's decode, for the evidence alone: a Scout or a
    /// Hello names a node in the census, never a session. `whole` is whether the
    /// message took the whole datagram, which is `datagram_len` bytes. A scouting
    /// datagram is a framing unit of one message.
    pub(crate) fn observe_scouting(
        &mut self,
        frame: &Result<ScoutingFrame, InboundParseError>,
        whole: bool,
        datagram_len: usize,
    ) {
        let announced = frame.as_ref().map(ScoutingFrame::announced_version);
        self.versions.observe(announced, whole);
        if let (true, Ok(Some(version))) = (whole, announced) {
            self.observe_version(version);
        }
        let reading = UnitReading::of_scouting(frame, whole);
        self.readings.observe(reading, datagram_len);
        self.observe_reading(reading);
    }

    /// What the flow's version-bearing messages said.
    pub fn versions(&self) -> VersionEvidence {
        self.versions
    }

    /// The flow's evidence for the zenoh test: what ingest observed, the Init
    /// roles, and what the flow's sessions observed ([`SessionObservations`]:
    /// the SN steps and how each stream direction's framing was first judged).
    pub fn evidence(&self, sessions: SessionObservations) -> ZenohEvidence {
        let mut evidence = self.observed;
        match self.roles() {
            Roles::Settled {
                initiator: Some(_),
                acceptor: Some(_),
            } => evidence.confirm(Check::InitRoles, model::INIT_ROLES_CONFIRMED),
            Roles::Contradicted => evidence.violate(Check::InitRoles, model::INIT_ROLES_VIOLATED),
            Roles::Settled { .. } => {}
        }
        let steps = sessions.steps;
        evidence.add(
            Check::SnFollows,
            steps.follows,
            steps.breaks,
            crate::zenoh_evidence::sn_steps_weight(steps),
        );
        evidence.add(
            Check::StreamFraming,
            sessions.framing_held,
            sessions.framing_lost,
            model::FRAMING_HELD
                .times(sessions.framing_held)
                .plus(model::FRAMING_LOST.times(sessions.framing_lost)),
        );
        evidence
    }

    /// How the flow's framing units read.
    pub fn readings(&self) -> ReadingEvidence {
        self.readings
    }

    /// The instant of the first packet of this flow, if any packet had a clock.
    pub fn first_ns(&self) -> Option<u64> {
        self.first_ns
    }

    /// The instant of the last packet of this flow, if any packet had a clock.
    pub fn last_ns(&self) -> Option<u64> {
        self.last_ns
    }

    /// The zid the Init of `direction` named, where the capture holds one, and
    /// whether that Init was an InitAck.
    pub fn named(&self, direction: Direction) -> Option<(&[u8], bool)> {
        let seat = usize::from(direction == Direction::B);
        self.named[seat]
            .as_ref()
            .map(|(zid, ack)| (zid.as_slice(), *ack))
    }

    /// The two nodes of this flow, where BOTH directions named themselves and
    /// they are two nodes, as `[A, B]`.
    ///
    /// The node plane's own rule for a link (`NodeCensus::links`): one Init
    /// proves a node sent one and does not prove a session, and a flow whose two
    /// Inits name the same node is not two nodes talking.
    pub fn pair(&self) -> Option<[&[u8]; 2]> {
        let a = self.named(Direction::A)?.0;
        let b = self.named(Direction::B)?.0;
        (a != b).then_some([a, b])
    }

    /// Who initiated, from what the Inits say. See [`Roles`].
    pub fn roles(&self) -> Roles {
        let mut initiator: Option<Vec<u8>> = None;
        let mut acceptor: Option<Vec<u8>> = None;
        for direction in [Direction::A, Direction::B] {
            let Some((zid, is_ack)) = self.named(direction) else {
                continue;
            };
            let slot = if is_ack {
                &mut acceptor
            } else {
                &mut initiator
            };
            if slot.is_some() {
                return Roles::Contradicted;
            }
            *slot = Some(zid.to_vec());
        }
        Roles::Settled {
            initiator,
            acceptor,
        }
    }

    /// Whether the flow was seen on a link that has no handshake.
    pub fn handshake_absent(&self) -> bool {
        self.handshake_absent
    }

    /// Whether the flow produced a zenoh transport message of a known kind.
    pub fn understood(&self) -> bool {
        self.understood
    }
}

/// WHY a cell of a row is `null`: the closed set of reasons, one word each.
///
/// Four, and each one is something the code can distinguish rather than a word a
/// consumer might like to read:
///
/// * `not_in_capture` -- the message that would state the value is not among
///   the bytes this reader was given (a capture that began after the handshake);
/// * `encrypted` -- the flow is an encrypted transport this reader holds no keys
///   for, so what would state the value is unreadable;
/// * `no_clock` -- no packet of the flow carried a timestamp;
/// * `mixed` -- the evidence does not agree on one value: the row groups several
///   flows and they disagree, or one flow's own Inits do (both directions sent an
///   InitSyn), so no one value is the session's.
///
/// An `evicted` reason is deliberately absent. A flow the table's ceiling evicts
/// has no row at all, so no cell can say it; the loss is stated once for the
/// document, by `dropped_by_limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unstated {
    /// The handshake that would state it is not in the capture.
    NotInCapture,
    /// The flow is encrypted and unreadable here.
    Encrypted,
    /// No packet of the flow carried a timestamp.
    NoClock,
    /// The flows of the row disagree.
    Mixed,
}

impl Unstated {
    /// The word this reason is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Unstated::NotInCapture => "not_in_capture",
            Unstated::Encrypted => "encrypted",
            Unstated::NoClock => "no_clock",
            Unstated::Mixed => "mixed",
        }
    }

    /// Every reason, from an exhaustive match so the array cannot fall behind
    /// the enum.
    pub fn all() -> [Unstated; 4] {
        let one = |u: Unstated| match u {
            Unstated::NotInCapture => Unstated::NotInCapture,
            Unstated::Encrypted => Unstated::Encrypted,
            Unstated::NoClock => Unstated::NoClock,
            Unstated::Mixed => Unstated::Mixed,
        };
        [
            one(Unstated::NotInCapture),
            one(Unstated::Encrypted),
            one(Unstated::NoClock),
            one(Unstated::Mixed),
        ]
    }

    /// Every word, sorted, which is the form a document declares a family in.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|u| u.name()).collect();
        words.sort_unstable();
        words
    }
}

/// The cells of a row that can be `null`. A cell that is `null` is named, with
/// its reason, in the row's `unstated` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    /// `initiator`, the zid of the InitSyn's sender.
    Initiator,
    /// `acceptor`, the zid of the InitAck's sender.
    Acceptor,
    /// `link`, the kind of link.
    Link,
    /// `phase`, how far the session got.
    Phase,
    /// `first_seen_ts_ns`.
    FirstSeen,
    /// `last_seen_ts_ns`.
    LastSeen,
    /// `frames`.
    Frames,
}

impl Cell {
    /// Every cell, from an exhaustive match so the array cannot fall behind the
    /// enum: a cell added later fails to compile here.
    pub fn all() -> [Cell; 7] {
        let one = |c: Cell| match c {
            Cell::Initiator => Cell::Initiator,
            Cell::Acceptor => Cell::Acceptor,
            Cell::Link => Cell::Link,
            Cell::Phase => Cell::Phase,
            Cell::FirstSeen => Cell::FirstSeen,
            Cell::LastSeen => Cell::LastSeen,
            Cell::Frames => Cell::Frames,
        };
        [
            one(Cell::Initiator),
            one(Cell::Acceptor),
            one(Cell::Link),
            one(Cell::Phase),
            one(Cell::FirstSeen),
            one(Cell::LastSeen),
            one(Cell::Frames),
        ]
    }

    /// The key of the cell itself.
    pub const fn key(self) -> &'static str {
        match self {
            Cell::Initiator => "initiator",
            Cell::Acceptor => "acceptor",
            Cell::Link => "link",
            Cell::Phase => "phase",
            Cell::FirstSeen => "first_seen_ts_ns",
            Cell::LastSeen => "last_seen_ts_ns",
            Cell::Frames => "frames",
        }
    }

    /// Every key, sorted, which is the form a document declares the `cell`
    /// family in.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|c| c.key()).collect();
        words.sort_unstable();
        words
    }

    /// The reasons this cell can carry, and no others.
    ///
    /// The document declares ONE `reason` family for the whole row, because the
    /// declaration machinery holds a family to at least two words and a cell
    /// that can carry exactly one (`link`, `phase`, the two instants, `frames`)
    /// has no family of its own to be held to. What a cell can say is therefore
    /// stated HERE and in the header, and a test holds every row of every
    /// fixture to it: a cell saying a reason that is not in its list fails
    /// there, so a consumer reading the header's table is told the truth.
    pub const fn reasons(self) -> &'static [Unstated] {
        match self {
            Cell::Initiator | Cell::Acceptor => {
                &[Unstated::NotInCapture, Unstated::Encrypted, Unstated::Mixed]
            }
            Cell::Link => &[Unstated::Mixed],
            Cell::Phase | Cell::Frames => &[Unstated::Encrypted],
            Cell::FirstSeen | Cell::LastSeen => &[Unstated::NoClock],
        }
    }
}

/// A value of a row, or the reason it cannot be stated.
pub type Stated<T> = Result<T, Unstated>;

/// Whether the zenoh session is in the clear, and if not what became of it.
///
/// The vocabulary is closed and every word is a finding this reader can make:
///
/// * `clear` -- zenoh transport messages were decoded from the flow's own bytes;
/// * `encrypted_unreadable` -- the flow is TLS or QUIC and nothing was decrypted;
/// * `decrypted_tls`, `decrypted_quic` -- the flow was encrypted and a decryption
///   pass recovered the session. The doors of this library do not decrypt, so a
///   row says these only over a dissection a caller decrypted before asking;
/// * `unknown` -- nothing was decoded and nothing says the flow is encrypted, so
///   the flow may be zenoh this reader could not read or may be something else;
/// * `mixed` -- the row groups flows that differ.
///
/// The detection is the report's (`Framing::Encrypted` for TLS, the QUIC census
/// for QUIC) and nothing here recognises a second way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// Decoded from cleartext.
    Clear,
    /// Decrypted from QUIC.
    DecryptedQuic,
    /// Decrypted from TLS.
    DecryptedTls,
    /// Encrypted, and no key was applied.
    EncryptedUnreadable,
    /// The row's flows differ.
    Mixed,
    /// Not decided.
    Unknown,
}

impl Encryption {
    /// The word this finding is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Encryption::Clear => "clear",
            Encryption::DecryptedQuic => "decrypted_quic",
            Encryption::DecryptedTls => "decrypted_tls",
            Encryption::EncryptedUnreadable => "encrypted_unreadable",
            Encryption::Mixed => "mixed",
            Encryption::Unknown => "unknown",
        }
    }

    /// Every finding, from an exhaustive match.
    pub fn all() -> [Encryption; 6] {
        let one = |e: Encryption| match e {
            Encryption::Clear => Encryption::Clear,
            Encryption::DecryptedQuic => Encryption::DecryptedQuic,
            Encryption::DecryptedTls => Encryption::DecryptedTls,
            Encryption::EncryptedUnreadable => Encryption::EncryptedUnreadable,
            Encryption::Mixed => Encryption::Mixed,
            Encryption::Unknown => Encryption::Unknown,
        };
        [
            one(Encryption::Clear),
            one(Encryption::DecryptedQuic),
            one(Encryption::DecryptedTls),
            one(Encryption::EncryptedUnreadable),
            one(Encryption::Mixed),
            one(Encryption::Unknown),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|e| e.name()).collect();
        words.sort_unstable();
        words
    }
}

/// Why a flow is not a row, the closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The link has no handshake: a multicast group, or raweth.
    MulticastGroup,
    /// Only discovery messages (Scout, Hello) were decoded from the flow.
    ScoutingOnly,
}

impl Why {
    /// The word this reason is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Why::MulticastGroup => "multicast_group",
            Why::ScoutingOnly => "scouting_only",
        }
    }

    /// Every reason, from an exhaustive match.
    pub fn all() -> [Why; 2] {
        let one = |w: Why| match w {
            Why::MulticastGroup => Why::MulticastGroup,
            Why::ScoutingOnly => Why::ScoutingOnly,
        };
        [one(Why::MulticastGroup), one(Why::ScoutingOnly)]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|w| w.name()).collect();
        words.sort_unstable();
        words
    }
}

/// How many flows were left out of the rows, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Excluded {
    /// Flows on a link with no handshake.
    pub multicast_group: u64,
    /// Flows that carried only discovery.
    pub scouting_only: u64,
}

impl Excluded {
    /// The count for one reason.
    pub fn count(&self, why: Why) -> u64 {
        match why {
            Why::MulticastGroup => self.multicast_group,
            Why::ScoutingOnly => self.scouting_only,
        }
    }

    fn note(&mut self, why: Why) {
        match why {
            Why::MulticastGroup => self.multicast_group += 1,
            Why::ScoutingOnly => self.scouting_only += 1,
        }
    }
}

/// One flow that is part of a session, with what the flow alone says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The flow the link was read off.
    pub flow: FlowKey,
    /// The kind of link.
    pub kind: LinkKind,
    /// Whether the session is in the clear.
    pub encryption: Encryption,
    /// The session phase, or why it is not stated.
    pub phase: Stated<SessionPhase>,
    /// Messages ever produced for the flow, or why they are not stated.
    pub frames: Stated<u64>,
    /// Bytes the flow carried.
    pub bytes: u64,
    /// The first packet's instant.
    pub first_ns: Option<u64>,
    /// The last packet's instant.
    pub last_ns: Option<u64>,
    /// The InitSyn's sender, or why the flow does not say.
    pub initiator: Stated<Vec<u8>>,
    /// The InitAck's sender, or why the flow does not say.
    pub acceptor: Stated<Vec<u8>>,
    /// The two nodes both directions named, in zid order, where both did: the
    /// session this flow belongs to. `None` leaves the flow a row of its own.
    pub pair: Option<(Vec<u8>, Vec<u8>)>,
    /// What the flow's version-bearing messages said.
    pub versions: VersionEvidence,
    /// The flow's evidence for the zenoh test.
    pub evidence: ZenohEvidence,
    /// How the flow's framing units read.
    pub readings: ReadingEvidence,
}

/// One row: a session, or a flow whose session is not known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// The zid of the end that sent the InitSyn.
    pub initiator: Stated<Vec<u8>>,
    /// The zid of the end that sent the InitAck.
    pub acceptor: Stated<Vec<u8>>,
    /// The kind of link, when every flow of the row is the same kind.
    pub link: Stated<LinkKind>,
    /// How far the session got.
    pub phase: Stated<SessionPhase>,
    /// Whether the session is in the clear.
    pub encryption: Encryption,
    /// The earliest packet of any flow of the row.
    pub first_seen_ns: Stated<u64>,
    /// The latest packet of any flow of the row.
    pub last_seen_ns: Stated<u64>,
    /// Messages ever produced, summed over the flows.
    pub frames: Stated<u64>,
    /// Bytes carried, summed over the flows.
    pub bytes: u64,
    /// What the flows' version-bearing messages said, together.
    pub versions: VersionEvidence,
    /// The flows' evidence for the zenoh test, together: the observations of
    /// one session's links add, as the observations of one link do.
    pub evidence: ZenohEvidence,
    /// How the flows' framing units read, together.
    pub readings: ReadingEvidence,
    /// The flows, in the order the dissection holds them.
    pub links: Vec<Link>,
}

/// The table: its rows and the flows that are not rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTable {
    /// One per session, in the order the dissection first met each.
    pub rows: Vec<SessionRow>,
    /// What was left out.
    pub excluded: Excluded,
}

/// The phases in the order a session moves through them, for the one rule that
/// compares them. `Closed` is not on this scale: it is where a session ENDS, not
/// a step further than `Established`.
fn progress(phase: SessionPhase) -> u8 {
    match phase {
        SessionPhase::Unseen => 0,
        SessionPhase::HalfInit => 1,
        SessionPhase::InitComplete => 2,
        SessionPhase::Established => 3,
        SessionPhase::Closed => 4,
    }
}

/// The phase of a session that spans several flows.
///
/// A session is over when EVERY flow of it is closed, and until then it is as far
/// as its furthest flow that is still open: one link closing while another
/// carries on is not the session closing. Over the flows of the session whose
/// phase is stated; `None` when none is.
fn combined_phase(phases: impl Iterator<Item = SessionPhase>) -> Option<SessionPhase> {
    let mut best_open: Option<SessionPhase> = None;
    let mut any = false;
    for phase in phases {
        any = true;
        if phase == SessionPhase::Closed {
            continue;
        }
        let further = match best_open {
            Some(held) => progress(phase) > progress(held),
            None => true,
        };
        if further {
            best_open = Some(phase);
        }
    }
    match (best_open, any) {
        (Some(phase), _) => Some(phase),
        (None, true) => Some(SessionPhase::Closed),
        (None, false) => None,
    }
}

/// The one value every item agrees on, or `Mixed`.
fn agreed<T: PartialEq + Clone>(items: impl Iterator<Item = Stated<T>>) -> Stated<T> {
    let mut found: Option<Stated<T>> = None;
    for item in items {
        match &found {
            None => found = Some(item),
            Some(held) if *held == item => {}
            Some(_) => return Err(Unstated::Mixed),
        }
    }
    found.unwrap_or(Err(Unstated::NotInCapture))
}

impl SessionRow {
    /// Fold the flows of one session into its row.
    fn of(links: Vec<Link>) -> Self {
        let initiator = agreed(links.iter().map(|l| l.initiator.clone()));
        let acceptor = agreed(links.iter().map(|l| l.acceptor.clone()));
        let link = agreed(links.iter().map(|l| Ok(l.kind)));
        let phase = combined_phase(links.iter().filter_map(|l| l.phase.ok())).ok_or(
            // No flow of the row stated its phase: every one is unreadable.
            Unstated::Encrypted,
        );
        let encryption = match agreed(links.iter().map(|l| Ok(l.encryption))) {
            Ok(one) => one,
            Err(_) => Encryption::Mixed,
        };
        let first = links.iter().filter_map(|l| l.first_ns).min();
        let last = links.iter().filter_map(|l| l.last_ns).max();
        let frames = links
            .iter()
            .try_fold(0u64, |sum, l| l.frames.map(|n| sum.saturating_add(n)));
        let bytes = links
            .iter()
            .fold(0u64, |sum, l| sum.saturating_add(l.bytes));
        let versions = links
            .iter()
            .fold(VersionEvidence::default(), |sum, l| sum.and(l.versions));
        let evidence = links
            .iter()
            .fold(ZenohEvidence::default(), |sum, l| sum.and(l.evidence));
        let readings = links
            .iter()
            .fold(ReadingEvidence::default(), |sum, l| sum.and(l.readings));
        SessionRow {
            initiator,
            acceptor,
            link,
            phase,
            encryption,
            first_seen_ns: first.ok_or(Unstated::NoClock),
            last_seen_ns: last.ok_or(Unstated::NoClock),
            frames,
            bytes,
            versions,
            evidence,
            readings,
            links,
        }
    }
}

/// The furthest phase over a set of sessions: a QUIC flow's own session and one
/// per stream.
fn furthest(phases: impl Iterator<Item = SessionPhase>) -> SessionPhase {
    combined_phase(phases).unwrap_or(SessionPhase::Unseen)
}

/// Every flow of the dissection that is a candidate for a row, in dissection
/// order: the stream flows, then the datagram flows, then the serial line.
fn links_of(d: &Dissection) -> (Vec<Link>, Excluded) {
    let mut links = Vec::new();
    let mut excluded = Excluded::default();

    for f in d.flows() {
        let frames = f.frames.produced();
        let encryption = match f.framing() {
            Framing::Encrypted(state) => {
                // The report's own finding: a decryption pass ran and left
                // nothing undecrypted. `None` there is `Some(None)` here.
                if matches!(state.outcome, Some(None)) {
                    Encryption::DecryptedTls
                } else {
                    Encryption::EncryptedUnreadable
                }
            }
            _ if f.ingest.understood() => Encryption::Clear,
            _ => Encryption::Unknown,
        };
        links.push(link_of(
            f.flow,
            encryption,
            f.session.context().phase,
            frames,
            f.residue().recovered,
            &f.ingest,
            f.session_observations(),
        ));
    }

    for f in d.datagram_flows() {
        let frames: u64 = f.frame_lists_with_origin().map(|(_, l)| l.produced()).sum();
        if f.ingest.handshake_absent() {
            let why = if frames == 0 && f.scouting.produced() > 0 {
                Why::ScoutingOnly
            } else {
                Why::MulticastGroup
            };
            excluded.note(why);
            continue;
        }
        if frames == 0 && f.scouting.produced() > 0 {
            excluded.note(Why::ScoutingOnly);
            continue;
        }
        let recovered_quic = !f.quic_streams.is_empty() || f.quic_datagrams.produced() > 0;
        let encryption = if f.quic.is_some() {
            if recovered_quic {
                Encryption::DecryptedQuic
            } else {
                Encryption::EncryptedUnreadable
            }
        } else if f.ingest.understood() {
            Encryption::Clear
        } else {
            Encryption::Unknown
        };
        let phase = furthest(
            core::iter::once(f.session.context().phase)
                .chain(f.quic_streams.iter().map(|s| s.session.context().phase)),
        );
        links.push(link_of(
            f.flow,
            encryption,
            phase,
            frames,
            f.residue().recovered,
            &f.ingest,
            f.session_observations(),
        ));
    }

    if let Some(census) = d.serial_census() {
        let frames = d.serial_frames.produced();
        let encryption = if d.serial_ingest.understood() {
            Encryption::Clear
        } else {
            Encryption::Unknown
        };
        links.push(link_of(
            FlowKey::serial_line(),
            encryption,
            d.serial_session.context().phase,
            frames,
            census.bytes as u64,
            &d.serial_ingest,
            SessionObservations::of(&d.serial_session),
        ));
    }
    (links, excluded)
}

/// Both directions' SN steps of one session together.
pub(crate) fn session_sn_steps(session: &wz_session_core::passive::PassiveSession) -> SnSteps {
    session
        .sn_steps(Direction::A)
        .and(session.sn_steps(Direction::B))
}

/// What a flow's sessions observed that the zenoh test weighs, both
/// directions and every session of the flow together: the SN steps
/// ([`wz_session_core::passive::PassiveSession::sn_steps`]) and the stream
/// directions whose framing was first judged held or lost
/// ([`wz_session_core::passive::PassiveSession::first_framing`]; a datagram
/// direction has no framing to judge).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionObservations {
    /// The SN steps.
    pub steps: SnSteps,
    /// Stream directions that framed a unit before they lost their framing.
    pub framing_held: u64,
    /// Stream directions that lost their framing first.
    pub framing_lost: u64,
}

impl SessionObservations {
    /// One session's.
    pub fn of(session: &wz_session_core::passive::PassiveSession) -> Self {
        let mut out = Self {
            steps: session_sn_steps(session),
            ..Self::default()
        };
        for direction in [Direction::A, Direction::B] {
            match session.first_framing(direction) {
                Some(true) => out.framing_held += 1,
                Some(false) => out.framing_lost += 1,
                None => {}
            }
        }
        out
    }

    /// Two sessions' together.
    pub fn and(self, other: Self) -> Self {
        Self {
            steps: self.steps.and(other.steps),
            framing_held: self.framing_held.saturating_add(other.framing_held),
            framing_lost: self.framing_lost.saturating_add(other.framing_lost),
        }
    }
}

/// One flow's link, the cells that depend on whether it could be read decided
/// in ONE place.
fn link_of(
    flow: FlowKey,
    encryption: Encryption,
    phase: SessionPhase,
    frames: u64,
    bytes: u64,
    ingest: &LinkIngest,
    sessions: SessionObservations,
) -> Link {
    let unreadable = encryption == Encryption::EncryptedUnreadable;
    // The role cells. A zid the Inits do not give is absent for the reason that
    // fits: the flow is unreadable, or the Inits contradict each other, or the
    // message that would state it is not in the capture.
    let absent = |contradicted: bool| {
        if contradicted {
            Unstated::Mixed
        } else if unreadable {
            Unstated::Encrypted
        } else {
            Unstated::NotInCapture
        }
    };
    let (initiator, acceptor) = match ingest.roles() {
        Roles::Settled {
            initiator,
            acceptor,
        } => (
            initiator.ok_or(absent(false)),
            acceptor.ok_or(absent(false)),
        ),
        Roles::Contradicted => (Err(absent(true)), Err(absent(true))),
    };
    let pair = ingest.pair().map(|[a, b]| {
        if a <= b {
            (a.to_vec(), b.to_vec())
        } else {
            (b.to_vec(), a.to_vec())
        }
    });
    Link {
        flow,
        kind: flow.link(),
        encryption,
        phase: if unreadable {
            Err(Unstated::Encrypted)
        } else {
            Ok(phase)
        },
        frames: if unreadable {
            Err(Unstated::Encrypted)
        } else {
            Ok(frames)
        },
        bytes,
        first_ns: ingest.first_ns(),
        last_ns: ingest.last_ns(),
        initiator,
        acceptor,
        pair,
        versions: ingest.versions(),
        evidence: ingest.evidence(sessions),
        readings: ingest.readings(),
    }
}

/// The capture read as sessions.
///
/// One row per zid pair for the flows whose handshake named both ends, and one
/// row per flow for the rest, in the order the dissection first met each.
pub fn session_table(d: &Dissection) -> SessionTable {
    let (links, excluded) = links_of(d);
    // The session a pair stands under: the pair is UNORDERED, because the two
    // links of one session need not have been dialled by the same end.
    let mut by_pair: BTreeMap<(Vec<u8>, Vec<u8>), usize> = BTreeMap::new();
    let mut groups: Vec<Vec<Link>> = Vec::new();
    for link in links {
        match link.pair.clone() {
            Some(key) => match by_pair.get(&key) {
                Some(&at) => groups[at].push(link),
                None => {
                    by_pair.insert(key, groups.len());
                    groups.push(alloc::vec![link]);
                }
            },
            None => groups.push(alloc::vec![link]),
        }
    }
    SessionTable {
        rows: groups.into_iter().map(SessionRow::of).collect(),
        excluded,
    }
}
