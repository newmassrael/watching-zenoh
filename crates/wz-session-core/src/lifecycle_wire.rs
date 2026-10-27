// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The words of the session lifecycle that need no allocator: what an open is
//! answered with, why a verb is refused, the shape of the open key, and the
//! capability document.
//!
//! Decision D6 of `docs/session-lifecycle-intent.md` made the lifecycle a set of
//! queries, and `lifecycle_query` answers them for a node with a heap. A node
//! of the fixed-memory profile has no heap to answer from, but it holds peers by their
//! zid (round 3629) and is asked to open one, so it must give the same answer in the
//! same words. The vocabulary is therefore a module of its own that every profile
//! builds, and `lifecycle_query` re-exports it: one list of reasons, one spelling of
//! each verdict, however the node holds its sessions.
//!
//! What stays in `lifecycle_query` is what needs the heap: the close and reset verbs
//! that walk the sessions a host lists, the per-peer reset record, and the status
//! document whose machines are a list.

use crate::credential_identity::{zid_from_key_text, CREDENTIAL_ZID_BYTES};
use crate::text_out::TextOut;

/// The verb the open query carries in its key.
pub const OPEN_VERB: &str = "open";

/// What a node's opener made of a request to hold a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The request reached the node's machines. Accepted, not completed: the dial
    /// is asynchronous, and the status query is how its end is read.
    Accepted,
    /// The node knows no locator for the peer, so there is nothing to dial.
    PeerUnknown,
    /// The node knows the peer but none of the locators it has for it can be
    /// dialled from here.
    NoDialableLocator,
    /// The loop that holds the node's machines is gone.
    OpenerGone,
    /// The node holds as many peers by their zid as it was built for (a build states
    /// how many, and none by default), so it takes no further one.
    NoRoom,
    /// The node's links do not hold a session to the node a dial was made for, so a
    /// peer cannot be held by its zid: a session to whichever node answered a stale
    /// locator would not be one to the zid (decision D4).
    Unverifiable,
}

/// Why a verb was refused, as one of a closed set of reasons.
///
/// The words are the implementation's own and a querier shows them as written, so
/// each is a sentence that stands alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedReason {
    /// The node's authority does not admit closing the session this key names.
    NotPermitted,
    /// The key's last chunk is not a zid in the spelling a key carries.
    PeerNotAZid,
    /// The node's authority does not admit resetting the session this key names.
    ResetNotPermitted,
    /// A reset key's generation chunk is not a decimal number.
    GenerationNotANumber,
    /// The node's authority does not admit reading the status this key names.
    StatusNotPermitted,
    /// The node's authority does not admit opening the session this key names.
    OpenNotPermitted,
    /// The node knows no locator for the peer an open names.
    PeerUnknown,
    /// None of the locators the node knows for the peer can be dialled from it.
    NoDialableLocator,
    /// The loop that would hold the peer is gone, so the open reached nobody.
    OpenerGone,
    /// The node holds as many peers by their zid as it was built for.
    NoRoom,
    /// The node's links do not hold a session to the node a dial was made for, so no
    /// dial by a zid could be told from one to another node.
    Unverifiable,
}

impl RefusedReason {
    /// Every reason, for the declared set to be held to.
    pub const ALL: [Self; 11] = [
        Self::NotPermitted,
        Self::PeerNotAZid,
        Self::ResetNotPermitted,
        Self::GenerationNotANumber,
        Self::StatusNotPermitted,
        Self::OpenNotPermitted,
        Self::PeerUnknown,
        Self::NoDialableLocator,
        Self::OpenerGone,
        Self::NoRoom,
        Self::Unverifiable,
    ];

    /// The sentence a querier is shown. Plain ASCII with no quote or backslash, so
    /// it is written into the JSON as it stands.
    pub const fn words(self) -> &'static str {
        match self {
            Self::NotPermitted => "this node does not permit closing the session with that peer",
            Self::PeerNotAZid => "the last chunk of the key is not a zid",
            Self::ResetNotPermitted => {
                "this node does not permit resetting the session with that peer"
            }
            Self::GenerationNotANumber => "the generation chunk of the key is not a number",
            Self::StatusNotPermitted => {
                "this node does not permit reading the status of the session with that peer"
            }
            Self::OpenNotPermitted => "this node does not permit opening a session with that peer",
            Self::PeerUnknown => "this node knows no locator for that peer",
            Self::NoDialableLocator => "this node cannot dial any locator it knows for that peer",
            Self::OpenerGone => "the loop that would hold that peer is gone",
            Self::NoRoom => "this node holds as many peers by their zid as it was built for",
            Self::Unverifiable => {
                "this node cannot tell which node answers a dial, so it holds no peer by its zid"
            }
        }
    }
}

/// The answer to an open query (decision D6): the peer joins the node's intent and
/// its machine connects. A second open of a held peer changes nothing, and says
/// the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVerdict {
    /// The node's machines were asked to hold the peer. Accepted, not completed:
    /// the status query reads how the dial ended.
    Opening,
    /// The open was not attempted, or reached nothing to dial.
    Refused(RefusedReason),
}

impl OpenVerdict {
    /// The verdict an opener's outcome amounts to.
    pub fn of(outcome: OpenOutcome) -> Self {
        match outcome {
            OpenOutcome::Accepted => Self::Opening,
            OpenOutcome::PeerUnknown => Self::Refused(RefusedReason::PeerUnknown),
            OpenOutcome::NoDialableLocator => Self::Refused(RefusedReason::NoDialableLocator),
            OpenOutcome::OpenerGone => Self::Refused(RefusedReason::OpenerGone),
            OpenOutcome::NoRoom => Self::Refused(RefusedReason::NoRoom),
            OpenOutcome::Unverifiable => Self::Refused(RefusedReason::Unverifiable),
        }
    }

    /// Write the reply document: one JSON object. The words of `verdict` are the
    /// closed set `opening` and `refused`; `reason` appears only on `refused`.
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W) {
        match self {
            Self::Opening => out.push_str("{\"verdict\":\"opening\"}"),
            Self::Refused(reason) => write_refused(out, *reason),
        }
    }

    /// The `verdict` word, for a declared set to be held to.
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 2] = ["opening", "refused"];
}

/// The verb the close query carries in its key.
pub const CLOSE_VERB: &str = "close";

/// The verb the reset query carries in its key.
pub const RESET_VERB: &str = "reset";

/// The verb the status query carries in its key.
pub const STATUS_VERB: &str = "status";

/// Every lifecycle verb a node can have bound, in the order the capability query
/// lists them. `open` is last, and listed only by a node that has an opener.
pub const VERBS: [&str; 4] = [CLOSE_VERB, RESET_VERB, STATUS_VERB, OPEN_VERB];

/// Write the capability document `{"verbs":["close","reset","status"]}`, with
/// `"open"` after them when `open_bound`.
pub fn write_verbs_json<W: TextOut + ?Sized>(out: &mut W, open_bound: bool) {
    let mut bound: [&str; VERBS.len()] = [""; VERBS.len()];
    let mut count = 0;
    for verb in VERBS {
        if verb == OPEN_VERB && !open_bound {
            continue;
        }
        bound[count] = verb;
        count += 1;
    }
    write_verb_list(out, &bound[..count]);
}

/// `{"verdict":"refused","reason":"..."}`: the one spelling of a refusal, which
/// every verb's reply uses.
fn write_refused<W: TextOut + ?Sized>(out: &mut W, reason: RefusedReason) {
    out.push_str("{\"verdict\":\"refused\",\"reason\":\"");
    out.push_str(reason.words());
    out.push_str("\"}");
}

/// What a node's sessions did when told to close: how many links to the peer were
/// ordered closed by this call, and how many had been ordered before it.
///
/// Two counts rather than one verdict because the node that holds the sessions
/// knows them and the verdict is this module's: `newly_ordered` is the number a
/// reply reports as `links`, and the sum says whether the peer was there at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseOrder {
    /// Links to the peer that this call ordered closed.
    pub newly_ordered: u32,
    /// Links to the peer that a close had already been ordered for.
    pub already_ordered: u32,
}

/// The links a node holds to a peer, by whether a close was ordered for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionLinks {
    /// Links no close has been ordered for.
    pub open: u32,
    /// Links a close has been ordered for and that are still held.
    pub closing: u32,
}

/// One machine a node works to hold a peer by, as the status query shows it.
///
/// The state is in words ([`crate::peer_table::StateWords`], read off the machine
/// by the host), because the host that keeps the machines may publish them to the
/// answerer as plain data: the face loop of AP does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineReport<'a> {
    /// The configured endpoint the machine dials, as the host names it, or
    /// `None` for the machine of the node itself (an `open` by its zid).
    pub endpoint: Option<&'a str>,
    /// The state's word.
    pub state: &'a str,
    /// For a refusal, its cause.
    pub cause: Option<&'a str>,
    /// Whether the machine holds the peer in the node's intent
    /// ([`crate::peer_connection::PeerConnectionState::in_intent`]).
    pub in_intent: bool,
}

/// The answer to a close query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseVerdict {
    /// The close was ordered on `links` links; the sessions are on their way out.
    Closing {
        /// Links this call ordered closed.
        links: u32,
    },
    /// Every session with that peer had already been ordered closed.
    AlreadyClosed,
    /// This node holds no session with that peer.
    NotFound,
    /// The close was not attempted.
    Refused(RefusedReason),
}

impl CloseVerdict {
    /// The verdict a [`CloseOrder`] amounts to.
    pub fn of(order: CloseOrder) -> Self {
        if order.newly_ordered > 0 {
            Self::Closing {
                links: order.newly_ordered,
            }
        } else if order.already_ordered > 0 {
            Self::AlreadyClosed
        } else {
            Self::NotFound
        }
    }

    /// Write the reply document: one JSON object. The words of `verdict` are the
    /// closed set `closing`, `already_closed`, `not_found`, `refused`; `links`
    /// appears only on `closing` and `reason` only on `refused`.
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W) {
        match self {
            Self::Closing { links } => {
                let _ = write!(out, "{{\"verdict\":\"closing\",\"links\":{links}}}");
            }
            Self::AlreadyClosed => out.push_str("{\"verdict\":\"already_closed\"}"),
            Self::NotFound => out.push_str("{\"verdict\":\"not_found\"}"),
            Self::Refused(reason) => write_refused(out, *reason),
        }
    }

    /// The `verdict` word, for a declared set to be held to.
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Closing { .. } => "closing",
            Self::AlreadyClosed => "already_closed",
            Self::NotFound => "not_found",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 4] = ["closing", "already_closed", "not_found", "refused"];
}

/// The answer to a reset query (decision D6): the close a generation asks for,
/// once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetVerdict {
    /// The close was ordered on `links` links; a peer the node still holds by
    /// intent is connected again by its machine.
    Resetting {
        /// Links this call ordered closed.
        links: u32,
    },
    /// Every session with that peer had already been ordered closed.
    AlreadyClosed,
    /// This node holds no session with that peer.
    NotFound,
    /// A reset of this generation or a later one was already taken, so this one
    /// is a retransmission and closes nothing.
    Duplicate {
        /// The latest generation taken for the peer.
        last: u64,
    },
    /// The reset was not attempted.
    Refused(RefusedReason),
}

impl ResetVerdict {
    /// The verdict a [`CloseOrder`] amounts to, for a generation not seen before.
    pub fn of(order: CloseOrder) -> Self {
        match CloseVerdict::of(order) {
            CloseVerdict::Closing { links } => Self::Resetting { links },
            CloseVerdict::AlreadyClosed => Self::AlreadyClosed,
            _ => Self::NotFound,
        }
    }

    /// Write the reply document: one JSON object. The words of `verdict` are the
    /// closed set `resetting`, `already_closed`, `not_found`, `duplicate`,
    /// `refused`; `links` appears only on `resetting`, `generation` only on
    /// `duplicate` and `reason` only on `refused`.
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W) {
        match self {
            Self::Resetting { links } => {
                let _ = write!(out, "{{\"verdict\":\"resetting\",\"links\":{links}}}");
            }
            Self::AlreadyClosed => out.push_str("{\"verdict\":\"already_closed\"}"),
            Self::NotFound => out.push_str("{\"verdict\":\"not_found\"}"),
            Self::Duplicate { last } => {
                let _ = write!(out, "{{\"verdict\":\"duplicate\",\"generation\":{last}}}");
            }
            Self::Refused(reason) => write_refused(out, *reason),
        }
    }

    /// The `verdict` word, for a declared set to be held to.
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Resetting { .. } => "resetting",
            Self::AlreadyClosed => "already_closed",
            Self::NotFound => "not_found",
            Self::Duplicate { .. } => "duplicate",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 5] = [
        "resetting",
        "already_closed",
        "not_found",
        "duplicate",
        "refused",
    ];
}

/// The answer to a status query (decision D6), as the reply reports it: the
/// reply itself also lists each machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVerdict {
    /// What the node holds for the peer.
    Status {
        /// The links of the node's sessions with the peer.
        links: SessionLinks,
        /// Whether a machine holds the peer in the node's intent.
        intent: bool,
        /// How many machines work to hold the peer.
        machines: u32,
    },
    /// The status was not read.
    Refused(RefusedReason),
}

impl StatusVerdict {
    /// What the node holds for the peer, read from the machines that hold it: the
    /// peer is in the intent when any of them holds it so.
    pub fn of(links: SessionLinks, machines: &[MachineReport<'_>]) -> Self {
        Self::Status {
            links,
            intent: machines.iter().any(|machine| machine.in_intent),
            machines: u32::try_from(machines.len()).unwrap_or(u32::MAX),
        }
    }

    /// Write the reply document for this verdict over `machines`, the rows it
    /// was read from: the one document `{"verdict":"status","links":{..},
    /// "intent":..,"machines":[..]}`, or the refusal. A machine is
    /// `{"state":..}` with `"cause"` beside a refused state and `"endpoint"` on a
    /// configured endpoint's machine, each text escaped by the workspace's one
    /// escaper. Written over any [`TextOut`], so a node with no allocator writes
    /// it into a fixed buffer and the heap profile into a `String`, byte for
    /// byte the same.
    #[cfg(feature = "storage-profile")]
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W, machines: &[MachineReport<'_>]) {
        let (links, intent) = match self {
            Self::Status { links, intent, .. } => (links, intent),
            Self::Refused(reason) => return write_refused(out, *reason),
        };
        let _ = write!(
            out,
            "{{\"verdict\":\"status\",\"links\":{{\"open\":{},\"closing\":{}}},\"intent\":{intent},\"machines\":[",
            links.open, links.closing
        );
        for (at, machine) in machines.iter().enumerate() {
            if at > 0 {
                out.push(',');
            }
            out.push_str("{\"state\":");
            crate::json::escape_into(machine.state, out);
            if let Some(cause) = machine.cause {
                out.push_str(",\"cause\":");
                crate::json::escape_into(cause, out);
            }
            if let Some(endpoint) = machine.endpoint {
                out.push_str(",\"endpoint\":");
                crate::json::escape_into(endpoint, out);
            }
            out.push('}');
        }
        out.push_str("]}");
    }

    /// The `verdict` word, for a declared set to be held to.
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 2] = ["status", "refused"];
}

/// The key of an open query, `@/<zid>/<whatami>/session/open/<peer-zid>`, read.
///
/// The same six chunks `drive::LifecycleKey` reads, for the one verb a node
/// with no allocator serves, and it needs none of the machinery that type sits in.
/// Borrowing the key, so nothing is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenKey<'a> {
    /// The node the query addresses.
    pub node_zid: &'a str,
    /// That node's role as the querier spelled it.
    pub whatami: &'a str,
    /// The peer the node is asked to hold, as the key spells it.
    pub peer_zid: &'a str,
}

impl<'a> OpenKey<'a> {
    /// The open key `keyexpr` is, or `None` when it is not one.
    ///
    /// Exactly six chunks, `@` first, `session` fourth and `open` fifth, none empty, and no
    /// wildcard in the node, the role or the peer: a wildcard open would be "hold every
    /// peer that matches", and a key that merely intersects this one is not a target the
    /// caller meant (`lifecycle_query`'s module documentation gives the reason for every
    /// verb that acts).
    pub fn parse(keyexpr: &'a str) -> Option<Self> {
        let mut chunks = keyexpr.split('/');
        let (at, node_zid, whatami, session, verb, peer_zid) = (
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
        );
        if chunks.next().is_some()
            || at != "@"
            || session != "session"
            || verb != OPEN_VERB
            || [node_zid, whatami, peer_zid]
                .iter()
                .any(|chunk| chunk.is_empty() || chunk.contains(['*', '$']))
        {
            return None;
        }
        Some(Self {
            node_zid,
            whatami,
            peer_zid,
        })
    }

    /// The peer, read as a zid, or `None` when the chunk spells none (the spelling
    /// zenoh prints; see [`zid_from_key_text`]).
    pub fn peer(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        zid_from_key_text(self.peer_zid)
    }
}

/// The key of any one verb that acts on a peer, read: `@/<zid>/<whatami>/session/<verb>/<peer-zid>`
/// for `open`, `close` and `status`, and `@/<zid>/<whatami>/session/reset/<generation>/<peer-zid>`
/// for `reset`, whose generation is the chunk before the peer.
///
/// The same chunks `drive::LifecycleKey` reads on the heap profile, for a node with no allocator,
/// borrowing the key. A chunk that names the node, its role, the generation or the peer is literal:
/// a pattern is never a target, since a wildcard close is "close everything that matches".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerbKey<'a> {
    /// The node the query addresses.
    pub node_zid: &'a str,
    /// That node's role as the querier spelled it.
    pub whatami: &'a str,
    /// The verb: one of [`VERBS`].
    pub verb: &'a str,
    /// A reset's generation as the key spells it; `None` for every other verb.
    pub generation: Option<&'a str>,
    /// The peer, as the key spells it.
    pub peer_zid: &'a str,
}

impl<'a> VerbKey<'a> {
    /// The key of a verb on a peer `keyexpr` is, or `None` when it is not one: `@` first, `session`
    /// fourth, a verb of [`VERBS`] fifth, the right number of chunks for it, none empty, and no
    /// wildcard in any chunk that names something.
    pub fn parse(keyexpr: &'a str) -> Option<Self> {
        let mut chunks = keyexpr.split('/');
        let (at, node_zid, whatami, session, verb) = (
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
        );
        if at != "@" || session != "session" || !VERBS.contains(&verb) {
            return None;
        }
        let (generation, peer_zid) = if verb == RESET_VERB {
            (Some(chunks.next()?), chunks.next()?)
        } else {
            (None, chunks.next()?)
        };
        if chunks.next().is_some() {
            return None;
        }
        let named = [node_zid, whatami, peer_zid]
            .into_iter()
            .chain(generation)
            .any(|chunk| chunk.is_empty() || chunk.contains(['*', '$']));
        if named {
            return None;
        }
        Some(Self {
            node_zid,
            whatami,
            verb,
            generation,
            peer_zid,
        })
    }
}

/// Write the capability document `{"verbs":[...]}` for exactly the verbs `verbs` names, in
/// that order. A node says what it has bound (`lifecycle_query` writes the heap profile's four,
/// and the fixed profile its one).
pub fn write_verb_list<W: TextOut + ?Sized>(out: &mut W, verbs: &[&str]) {
    out.push_str("{\"verbs\":[");
    for (at, verb) in verbs.iter().enumerate() {
        if at > 0 {
            out.push_str(",");
        }
        out.push_str("\"");
        out.push_str(verb);
        out.push_str("\"");
    }
    out.push_str("]}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_out::FixedText;

    #[test]
    fn an_open_key_is_six_literal_chunks() {
        let key = OpenKey::parse("@/aa/peer/session/open/1f").expect("an open key");
        assert_eq!(
            (key.node_zid, key.whatami, key.peer_zid),
            ("aa", "peer", "1f")
        );
        let mut want = [0u8; CREDENTIAL_ZID_BYTES];
        want[0] = 0x1f;
        assert_eq!(key.peer(), Some(want));
        for refused in [
            "@/aa/peer/session/open/*",
            "@/aa/peer/session/open/$*",
            "@/aa/*/session/open/1f",
            "@/*/peer/session/open/1f",
            "@/aa/peer/session/open",
            "@/aa/peer/session/open/1f/x",
            "@/aa/peer/session/close/1f",
            "@/aa/peer/status/open/1f",
            "x/aa/peer/session/open/1f",
            "@//peer/session/open/1f",
            "@/aa/peer/session/open/",
        ] {
            assert_eq!(OpenKey::parse(refused), None, "{refused}");
        }
        let not_a_zid = OpenKey::parse("@/aa/peer/session/open/01").expect("still an open key");
        assert_eq!(not_a_zid.peer(), None, "a leading zero is no zid");
    }

    #[test]
    fn a_verb_key_is_literal_chunks_and_a_reset_carries_its_generation() {
        let key = VerbKey::parse("@/aa/peer/session/close/1f").expect("a close key");
        assert_eq!(
            (key.verb, key.generation, key.peer_zid),
            ("close", None, "1f")
        );
        let key = VerbKey::parse("@/aa/peer/session/reset/7/1f").expect("a reset key");
        assert_eq!(
            (
                key.node_zid,
                key.whatami,
                key.verb,
                key.generation,
                key.peer_zid
            ),
            ("aa", "peer", "reset", Some("7"), "1f")
        );
        for verb in ["open", "status"] {
            let text = ["@/aa/peer/session/", verb, "/1f"].concat();
            assert_eq!(VerbKey::parse(&text).map(|k| k.verb), Some(verb));
        }
        for refused in [
            "@/aa/peer/session/close/*",
            "@/aa/peer/session/close/$*",
            "@/aa/*/session/status/1f",
            "@/*/peer/session/open/1f",
            "@/aa/peer/session/reset/*/1f",
            "@/aa/peer/session/reset/7/*",
            "@/aa/peer/session/reset/1f",
            "@/aa/peer/session/reset/7/1f/x",
            "@/aa/peer/session/close/7/1f",
            "@/aa/peer/session/close",
            "@/aa/peer/session/close/",
            "@/aa/peer/session/verbs",
            "@/aa/peer/session/hold/1f",
            "@/aa/peer/status/close/1f",
            "x/aa/peer/session/close/1f",
            "@//peer/session/close/1f",
            "@/aa/peer/session/reset//1f",
        ] {
            assert_eq!(VerbKey::parse(refused), None, "{refused}");
        }
    }

    #[test]
    fn the_capability_document_lists_what_it_is_given() {
        for (verbs, want) in [
            (&["open"][..], "{\"verbs\":[\"open\"]}"),
            (&["close", "open"][..], "{\"verbs\":[\"close\",\"open\"]}"),
            (&[][..], "{\"verbs\":[]}"),
        ] {
            let mut text: FixedText<64> = FixedText::new();
            write_verb_list(&mut text, verbs);
            assert_eq!(text.finish().expect("fits"), want);
        }
    }

    #[cfg(feature = "storage-profile")]
    #[test]
    fn the_status_document_is_written_into_a_fixed_buffer_from_the_rows_it_lists() {
        let machines = [
            MachineReport {
                endpoint: None,
                state: "established",
                cause: None,
                in_intent: true,
            },
            MachineReport {
                endpoint: Some("tcp/1.2.3.4:7447"),
                state: "refused",
                cause: Some("a \"quoted\" cause"),
                in_intent: false,
            },
        ];
        let links = SessionLinks {
            open: 2,
            closing: 1,
        };
        let verdict = StatusVerdict::of(links, &machines);
        assert_eq!(
            verdict,
            StatusVerdict::Status {
                links,
                intent: true,
                machines: 2
            }
        );
        let mut text: FixedText<256> = FixedText::new();
        verdict.write_json(&mut text, &machines);
        assert_eq!(
            text.finish().expect("fits"),
            "{\"verdict\":\"status\",\"links\":{\"open\":2,\"closing\":1},\"intent\":true,\
             \"machines\":[{\"state\":\"established\"},{\"state\":\"refused\",\
             \"cause\":\"a \\\"quoted\\\" cause\",\"endpoint\":\"tcp/1.2.3.4:7447\"}]}"
        );

        // No machine holds the peer: no intent, an empty list, and a refusal is the
        // same sentence every verb gives.
        let none = StatusVerdict::of(SessionLinks::default(), &[]);
        let mut text: FixedText<128> = FixedText::new();
        none.write_json(&mut text, &[]);
        assert_eq!(
            text.finish().expect("fits"),
            "{\"verdict\":\"status\",\"links\":{\"open\":0,\"closing\":0},\"intent\":false,\
             \"machines\":[]}"
        );
        let mut text: FixedText<128> = FixedText::new();
        StatusVerdict::Refused(RefusedReason::PeerNotAZid).write_json(&mut text, &[]);
        assert_eq!(
            text.finish().expect("fits"),
            "{\"verdict\":\"refused\",\"reason\":\"the last chunk of the key is not a zid\"}"
        );
    }

    #[test]
    fn every_outcome_has_a_verdict_and_every_reason_a_clean_sentence() {
        for outcome in [
            OpenOutcome::Accepted,
            OpenOutcome::PeerUnknown,
            OpenOutcome::NoDialableLocator,
            OpenOutcome::OpenerGone,
            OpenOutcome::NoRoom,
            OpenOutcome::Unverifiable,
        ] {
            let mut text: FixedText<192> = FixedText::new();
            OpenVerdict::of(outcome).write_json(&mut text);
            let doc = text.finish().expect("fits");
            assert!(doc.starts_with("{\"verdict\":\""), "{doc}");
            assert_eq!(
                doc.contains("\"reason\""),
                outcome != OpenOutcome::Accepted,
                "{doc}"
            );
        }
        for reason in RefusedReason::ALL {
            assert!(!reason.words().contains(['"', '\\']));
        }
    }
}
