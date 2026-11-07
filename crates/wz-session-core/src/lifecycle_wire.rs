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

use core::ffi::CStr;

use crate::credential_identity::{zid_from_key_text, CREDENTIAL_ZID_BYTES};
use crate::text_out::TextOut;

/// The verb the open query carries in its key.
pub const OPEN_VERB: &str = "open";

/// The chunk before the peer that makes an open passive (decision D10):
/// `@/<zid>/<whatami>/session/open/passive/<peer-zid>`. A zid is lower-case hex, so the word
/// cannot be taken for one, and `reset` already carries its generation in the same place.
pub const PASSIVE_CHUNK: &str = "passive";

/// How an open holds the peer (decision D10): BGP's two administrative start events, the same
/// machine started either to dial or to wait for the remote's own session
/// (RFC 4271, section 8.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenMode {
    /// Dial the peer: `ManualStart`.
    #[default]
    Dial,
    /// Wait for the peer's session and dial nothing: `ManualStart_with_PassiveTcpEstablishment`.
    Passive,
}

impl OpenMode {
    /// The mode an open key's argument chunk names, or `None` for a chunk that is no mode.
    pub fn of_argument(argument: Option<&str>) -> Option<Self> {
        match argument {
            None => Some(Self::Dial),
            Some(PASSIVE_CHUNK) => Some(Self::Passive),
            Some(_) => None,
        }
    }
}

/// The chunks after the verb of a lifecycle key: the verb's argument, for the verbs that take one
/// (`reset`'s generation, `open`'s `passive`), and the peer. `None` when the verb has the wrong
/// number of chunks, or `open` carries a chunk that is not `passive`.
pub(crate) fn tail_of<'a>(
    verb: &str,
    mut chunks: core::str::Split<'a, char>,
) -> Option<(Option<&'a str>, &'a str)> {
    let first = chunks.next()?;
    let second = chunks.next();
    if chunks.next().is_some() {
        return None;
    }
    match (verb, second) {
        (RESET_VERB, Some(peer)) => Some((Some(first), peer)),
        (OPEN_VERB, Some(peer)) if first == PASSIVE_CHUNK => Some((Some(first), peer)),
        (RESET_VERB, None) | (_, Some(_)) => None,
        (_, None) => Some((None, first)),
    }
}

/// What a node's opener made of a request to hold a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The request reached the node's machines. Accepted, not completed: the dial
    /// is asynchronous, and the status query is how its end is read.
    Accepted,
    /// The zid the opener was handed does not read as a zid. A request that came by a
    /// key never gets here, since the key's reader refuses it first.
    NotAZid,
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
    pub const ALL: [Self; 9] = [
        Self::NotPermitted,
        Self::PeerNotAZid,
        Self::ResetNotPermitted,
        Self::GenerationNotANumber,
        Self::StatusNotPermitted,
        Self::OpenNotPermitted,
        Self::OpenerGone,
        Self::NoRoom,
        Self::Unverifiable,
    ];

    /// The sentence a querier is shown. Plain ASCII with no quote or backslash, so
    /// it is written into the JSON as it stands.
    pub const fn words(self) -> &'static str {
        utf8(self.c_words())
    }

    /// [`Self::words`] as a C string, the one spelling of each sentence: a C ABI hands it out as
    /// it stands, with no copy made at run time.
    pub const fn c_words(self) -> &'static CStr {
        match self {
            Self::NotPermitted => c"this node does not permit closing the session with that peer",
            Self::PeerNotAZid => c"the last chunk of the key is not a zid",
            Self::ResetNotPermitted => {
                c"this node does not permit resetting the session with that peer"
            }
            Self::GenerationNotANumber => c"the generation chunk of the key is not a number",
            Self::StatusNotPermitted => {
                c"this node does not permit reading the status of the session with that peer"
            }
            Self::OpenNotPermitted => c"this node does not permit opening a session with that peer",
            Self::OpenerGone => c"the loop that would hold that peer is gone",
            Self::NoRoom => c"this node holds as many peers by their zid as it was built for",
            Self::Unverifiable => {
                c"this node cannot tell which node answers a dial, so it holds no peer by its zid"
            }
        }
    }
}

/// The text of a word spelled once as a C string. Every word of this module is ASCII, so the
/// conversion cannot fail; it runs at compile time where the caller is `const`.
const fn utf8(word: &'static CStr) -> &'static str {
    match word.to_str() {
        Ok(text) => text,
        Err(_) => panic!("a lifecycle word is ASCII"),
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
            OpenOutcome::NotAZid => Self::Refused(RefusedReason::PeerNotAZid),
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
    /// How the peer is held (decision D10): dialled, or waited for.
    pub mode: OpenMode,
}

impl<'a> OpenKey<'a> {
    /// The open key `keyexpr` is, or `None` when it is not one.
    ///
    /// Six chunks, `@` first, `session` fourth and `open` fifth, or seven with the literal
    /// `passive` between the verb and the peer (decision D10), none empty, and no wildcard in
    /// the node, the role or the peer: a wildcard open would be "hold every peer that
    /// matches", and a key that merely intersects this one is not a target the caller meant
    /// (`lifecycle_query`'s module documentation gives the reason for every verb that acts).
    pub fn parse(keyexpr: &'a str) -> Option<Self> {
        let mut chunks = keyexpr.split('/');
        let (at, node_zid, whatami, session, verb) = (
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
            chunks.next()?,
        );
        if at != "@" || session != "session" || verb != OPEN_VERB {
            return None;
        }
        let (argument, peer_zid) = tail_of(verb, chunks)?;
        if [node_zid, whatami, peer_zid]
            .iter()
            .any(|chunk| chunk.is_empty() || chunk.contains(['*', '$']))
        {
            return None;
        }
        Some(Self {
            node_zid,
            whatami,
            peer_zid,
            mode: OpenMode::of_argument(argument)?,
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
    /// The verb's argument as the key spells it: a reset's generation, or the `passive` of an
    /// open (decision D10); `None` for every other key.
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
        let (generation, peer_zid) = tail_of(verb, chunks)?;
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

/// Every `verdict` word a reply of any verb carries, each once, in the order the verbs' own lists
/// give them ([`verdict_words_of`]).
pub const VERDICT_WORDS: [&str; 8] = {
    let mut words = [""; 8];
    let mut i = 0;
    while i < words.len() {
        words[i] = utf8(VERDICT_C_WORDS[i]);
        i += 1;
    }
    words
};

/// [`VERDICT_WORDS`] as C strings, in the same order: the one spelling of each verdict word.
pub const VERDICT_C_WORDS: [&CStr; 8] = [
    c"opening",
    c"closing",
    c"resetting",
    c"already_closed",
    c"not_found",
    c"duplicate",
    c"status",
    c"refused",
];

/// The `verdict` words a reply to `verb` can carry, or `None` for a word that is no verb.
pub fn verdict_words_of(verb: &str) -> Option<&'static [&'static str]> {
    match verb {
        OPEN_VERB => Some(&OpenVerdict::WORDS),
        CLOSE_VERB => Some(&CloseVerdict::WORDS),
        RESET_VERB => Some(&ResetVerdict::WORDS),
        STATUS_VERB => Some(&StatusVerdict::WORDS),
        _ => None,
    }
}

/// A reply of a lifecycle verb read back: the `verdict` word and the members the verdict's writer
/// puts beside it.
///
/// The reader of the documents this module writes, in this module, so a node that asked a verb says
/// what the answer was without a second decoder of the reply's spelling. It borrows nothing and needs
/// no allocator. A status reply is read up to its `intent`: the machines after it are a list as long
/// as the node holds them, and a querier may keep fewer bytes than that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRead {
    /// The `verdict` word: one of [`VERDICT_WORDS`].
    pub verdict: &'static str,
    /// The links the call ordered closed, on `closing` and `resetting`.
    pub links: Option<u32>,
    /// The latest generation taken for the peer, on `duplicate`.
    pub generation: Option<u64>,
    /// The links of the node's sessions with the peer, on `status`.
    pub held: Option<SessionLinks>,
    /// Whether a machine holds the peer in the node's intent, on `status`.
    pub intent: Option<bool>,
    /// Why the verb was refused, on `refused`.
    pub reason: Option<RefusedReason>,
}

impl ReplyRead {
    /// The reply `document` is, or `None` when it is no document a verdict here writes: another
    /// spelling, an unknown word or reason, or cut before the members its verdict carries.
    pub fn parse(document: &[u8]) -> Option<Self> {
        let text = core::str::from_utf8(document).ok()?;
        let (word, rest) = text.strip_prefix("{\"verdict\":\"")?.split_once('"')?;
        let verdict = *VERDICT_WORDS.iter().find(|known| **known == word)?;
        let mut read = Self {
            verdict,
            links: None,
            generation: None,
            held: None,
            intent: None,
            reason: None,
        };
        match verdict {
            "opening" | "already_closed" | "not_found" => (rest == "}").then_some(read),
            "closing" | "resetting" => {
                let links = rest.strip_prefix(",\"links\":")?.strip_suffix('}')?;
                read.links = Some(decimal(links)?);
                Some(read)
            }
            "duplicate" => {
                let last = rest.strip_prefix(",\"generation\":")?.strip_suffix('}')?;
                read.generation = Some(decimal(last)?);
                Some(read)
            }
            "refused" => {
                let words = rest.strip_prefix(",\"reason\":\"")?.strip_suffix("\"}")?;
                read.reason = Some(
                    *RefusedReason::ALL
                        .iter()
                        .find(|reason| reason.words() == words)?,
                );
                Some(read)
            }
            "status" => {
                let (open, rest) = rest
                    .strip_prefix(",\"links\":{\"open\":")?
                    .split_once(",\"closing\":")?;
                let (closing, rest) = rest.split_once("},\"intent\":")?;
                let (intent, _machines) = rest.split_once(",\"machines\":[")?;
                read.held = Some(SessionLinks {
                    open: decimal(open)?,
                    closing: decimal(closing)?,
                });
                read.intent = Some(match intent {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                });
                Some(read)
            }
            _ => None,
        }
    }
}

/// Why a line on a node's control channel is no command, as the word the port answers with
/// (`{"error":"<word>"}`): a closed set, like the refusals', since a line that is no command names
/// no peer and so has no verdict.
///
/// Here, beside the verdicts, and not in the port that writes it: an answer of the control channel
/// is read by [`Answer::read`] with the same reader as an answer in band, so the words are the
/// wire's and the port (`wz_session_mcu::control_port`) only uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The first word is not a command the port knows, or there is none.
    UnknownCommand,
    /// `open` with no peer, or with more than one.
    OpenTakesOnePeer,
    /// `close` with no peer, or with more than one.
    CloseTakesOnePeer,
    /// `reset` without exactly a peer and a generation.
    ResetTakesAPeerAndAGeneration,
    /// `status` with no peer, or with more than one.
    StatusTakesOnePeer,
    /// `whoami` followed by anything.
    WhoamiTakesNothing,
    /// The line was longer than the channel's buffer: the channel reads no part of it, since the
    /// part it kept would be a different command from the one sent.
    LineTooLong,
}

impl ControlError {
    /// Every error word, for the declared set to be held to.
    pub const ALL: [Self; 7] = [
        Self::UnknownCommand,
        Self::OpenTakesOnePeer,
        Self::CloseTakesOnePeer,
        Self::ResetTakesAPeerAndAGeneration,
        Self::StatusTakesOnePeer,
        Self::WhoamiTakesNothing,
        Self::LineTooLong,
    ];

    /// The word on the wire.
    pub const fn words(self) -> &'static str {
        utf8(self.c_words())
    }

    /// [`Self::words`] as a C string, the one spelling of each word.
    pub const fn c_words(self) -> &'static CStr {
        match self {
            Self::UnknownCommand => c"unknown-command",
            Self::OpenTakesOnePeer => c"open-takes-one-peer",
            Self::CloseTakesOnePeer => c"close-takes-one-peer",
            Self::ResetTakesAPeerAndAGeneration => c"reset-takes-a-peer-and-a-generation",
            Self::StatusTakesOnePeer => c"status-takes-one-peer",
            Self::WhoamiTakesNothing => c"whoami-takes-nothing",
            Self::LineTooLong => c"line-too-long",
        }
    }

    /// The answer document: one JSON object with the one word.
    pub fn write_json<W: TextOut + ?Sized>(self, out: &mut W) {
        out.push_str("{\"error\":\"");
        out.push_str(self.words());
        out.push_str("\"}");
    }
}

/// Write the control channel's answer to `whoami`, `{"zid":"<zid>"}`, the zid spelled as a key
/// spells it (lower-case hex: nothing in it needs escaping).
pub fn write_zid_json<W: TextOut + ?Sized>(zid: &str, out: &mut W) {
    out.push_str("{\"zid\":\"");
    out.push_str(zid);
    out.push_str("\"}");
}

/// An answer a node gave about its sessions, read back: a verb's reply in band, or a line its
/// control channel answered with.
///
/// The one reader of both, so a consumer that asked a node by a key or by its pipe reads the
/// answer without a second decoder of either spelling, and reads them as the node's own console
/// line (`HOST-WZ-VERDICT`) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<'a> {
    /// A verdict on a peer: the reply of any verb, in band or on the channel.
    Verdict(ReplyRead),
    /// The channel's answer to `whoami`: the node's zid, as a key spells it.
    Whoami(&'a str),
    /// The channel's answer to a line that is no command.
    Error(ControlError),
}

impl<'a> Answer<'a> {
    /// The answer `bytes` are, or `None` when they are none of the documents a node writes: empty,
    /// another spelling, a word or reason outside the closed sets, a zid that is not one, or a
    /// document cut before what its verdict carries.
    pub fn read(bytes: &'a [u8]) -> Option<Self> {
        let text = core::str::from_utf8(bytes).ok()?;
        if text.starts_with("{\"verdict\":\"") {
            return ReplyRead::parse(bytes).map(Self::Verdict);
        }
        if let Some(rest) = text.strip_prefix("{\"zid\":\"") {
            let zid = rest.strip_suffix("\"}")?;
            return zid_from_key_text(zid).map(|_| Self::Whoami(zid));
        }
        let word = text.strip_prefix("{\"error\":\"")?.strip_suffix("\"}")?;
        ControlError::ALL
            .into_iter()
            .find(|error| error.words() == word)
            .map(Self::Error)
    }
}

/// The roles a lifecycle key may name the node it asks as: zenoh's three.
pub const WHATAMI_WORDS: [&str; 3] = ["client", "peer", "router"];

/// The words a lifecycle verb's key is made from: the verb, the node it is asked of (`of`), the peer
/// it is about (`about`), the role the node is asked as, a reset's generation and an open's mode.
///
/// The one maker of such a key, so the generator of a declared node's queriers
/// (`scripts/lib/wz_node.py`, `verb_key`) and a consumer that asks by a C call make the same key;
/// both are held to `scripts/lib/verb_key_vectors.txt`. What it writes, [`VerbKey::parse`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerbWords<'a> {
    /// The verb: one of [`VERBS`].
    pub verb: &'a str,
    /// The zid of the node asked, as a key spells it.
    pub of: &'a str,
    /// The zid of the peer the verb is about, as a key spells it.
    pub about: &'a str,
    /// The role the node is asked as: one of [`WHATAMI_WORDS`].
    pub whatami: &'a str,
    /// A reset's generation; `None` for every other verb.
    pub generation: Option<u64>,
    /// An open's mode, one of [`OPEN_MODE_WORDS`]; `dial` for every other verb.
    pub mode: &'a str,
}

/// The words an open's mode is stated in (decision D10): dial the peer, or wait for its session.
pub const OPEN_MODE_WORDS: [&str; 2] = ["dial", PASSIVE_CHUNK];

/// Why words make no lifecycle key, as a word a consumer branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// The verb is none of [`VERBS`].
    NoSuchVerb,
    /// The role is none of [`WHATAMI_WORDS`].
    NoSuchRole,
    /// The mode is none of [`OPEN_MODE_WORDS`].
    NoSuchMode,
    /// `of` does not spell a zid.
    OfIsNoZid,
    /// `about` does not spell a zid.
    AboutIsNoZid,
    /// A reset with no generation.
    ResetTakesAGeneration,
    /// A generation given to a verb that is not reset.
    OnlyResetTakesAGeneration,
    /// A passive mode given to a verb that is not open.
    OnlyOpenIsPassive,
}

impl KeyRefusal {
    /// Every refusal, for a consumer's set to be held to.
    pub const ALL: [Self; 8] = [
        Self::NoSuchVerb,
        Self::NoSuchRole,
        Self::NoSuchMode,
        Self::OfIsNoZid,
        Self::AboutIsNoZid,
        Self::ResetTakesAGeneration,
        Self::OnlyResetTakesAGeneration,
        Self::OnlyOpenIsPassive,
    ];

    /// The refusal's word.
    pub const fn words(self) -> &'static str {
        utf8(self.c_words())
    }

    /// [`Self::words`] as a C string, the one spelling of each word.
    pub const fn c_words(self) -> &'static CStr {
        match self {
            Self::NoSuchVerb => c"no-such-verb",
            Self::NoSuchRole => c"no-such-role",
            Self::NoSuchMode => c"no-such-mode",
            Self::OfIsNoZid => c"of-is-no-zid",
            Self::AboutIsNoZid => c"about-is-no-zid",
            Self::ResetTakesAGeneration => c"reset-takes-a-generation",
            Self::OnlyResetTakesAGeneration => c"only-reset-takes-a-generation",
            Self::OnlyOpenIsPassive => c"only-open-is-passive",
        }
    }
}

/// The longest key [`VerbWords::write`] writes, in bytes: a reset's, the one verb whose key carries
/// a number. `@/`, a zid of 32 digits, `/`, the longest role, `/session/`, `reset`, `/`, a
/// generation of 20 digits (`u64::MAX`), `/`, and a zid of 32 digits. Every other verb's key is
/// shorter: its longest extra chunk is the `passive/` of an open.
pub const VERB_KEY_MAX_BYTES: usize = 2 + 32 + 1 + 6 + 9 + RESET_VERB.len() + 1 + 20 + 1 + 32;

impl VerbWords<'_> {
    /// Write the key, `@/<of>/<whatami>/session/<verb>/<about>` with `<generation>/` before
    /// `<about>` for a reset and `passive/` for a passive open, or say why the words make none.
    /// Nothing is written on a refusal.
    ///
    /// # Errors
    ///
    /// The first refusal, in the order of [`KeyRefusal::ALL`].
    pub fn write<W: TextOut + ?Sized>(&self, out: &mut W) -> Result<(), KeyRefusal> {
        if !VERBS.contains(&self.verb) {
            return Err(KeyRefusal::NoSuchVerb);
        }
        if !WHATAMI_WORDS.contains(&self.whatami) {
            return Err(KeyRefusal::NoSuchRole);
        }
        if !OPEN_MODE_WORDS.contains(&self.mode) {
            return Err(KeyRefusal::NoSuchMode);
        }
        let passive = self.mode == PASSIVE_CHUNK;
        if zid_from_key_text(self.of).is_none() {
            return Err(KeyRefusal::OfIsNoZid);
        }
        if zid_from_key_text(self.about).is_none() {
            return Err(KeyRefusal::AboutIsNoZid);
        }
        let reset = self.verb == RESET_VERB;
        match (reset, self.generation) {
            (true, None) => return Err(KeyRefusal::ResetTakesAGeneration),
            (false, Some(_)) => return Err(KeyRefusal::OnlyResetTakesAGeneration),
            _ => {}
        }
        if passive && self.verb != OPEN_VERB {
            return Err(KeyRefusal::OnlyOpenIsPassive);
        }
        for part in [
            "@/",
            self.of,
            "/",
            self.whatami,
            "/session/",
            self.verb,
            "/",
        ] {
            out.push_str(part);
        }
        if let Some(generation) = self.generation {
            let mut digits = [0u8; 20];
            out.push_str(decimal_text(generation, &mut digits));
            out.push_str("/");
        }
        if passive {
            out.push_str(PASSIVE_CHUNK);
            out.push_str("/");
        }
        out.push_str(self.about);
        Ok(())
    }
}

/// `n` in decimal, in `buf`.
fn decimal_text(mut n: u64, buf: &mut [u8; 20]) -> &str {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    // Only ASCII digits were written.
    core::str::from_utf8(&buf[at..]).unwrap_or("")
}

/// A number as the writers here spell it: decimal digits and nothing else.
fn decimal<N: core::str::FromStr>(text: &str) -> Option<N> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
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

    /// Decision D10: the chunk `passive` before the peer makes an open passive, and no other
    /// chunk there is a mode; every reader of a lifecycle key reads it the same way.
    #[test]
    fn a_passive_open_key_carries_the_literal_chunk_before_the_peer() {
        let key = OpenKey::parse("@/aa/peer/session/open/passive/1f").expect("a passive open");
        assert_eq!((key.peer_zid, key.mode), ("1f", OpenMode::Passive));
        let key = OpenKey::parse("@/aa/peer/session/open/1f").expect("an open");
        assert_eq!(key.mode, OpenMode::Dial);
        for refused in [
            "@/aa/peer/session/open/active/1f",
            "@/aa/peer/session/open/*/1f",
            "@/aa/peer/session/open/passive/*",
            "@/aa/peer/session/open/passive/1f/x",
            "@/aa/peer/session/open//1f",
            "@/aa/peer/session/close/passive/1f",
            "@/aa/peer/session/status/passive/1f",
        ] {
            assert_eq!(OpenKey::parse(refused), None, "{refused}");
        }
        // The mode word alone is six chunks, an open of a peer named `passive`, which is no zid.
        let named = OpenKey::parse("@/aa/peer/session/open/passive").expect("an open key");
        assert_eq!((named.mode, named.peer()), (OpenMode::Dial, None));
        let verb = VerbKey::parse("@/aa/peer/session/open/passive/1f").expect("a verb key");
        assert_eq!(
            (verb.verb, verb.generation, verb.peer_zid),
            ("open", Some("passive"), "1f")
        );
        assert_eq!(VerbKey::parse("@/aa/peer/session/close/passive/1f"), None);
        assert_eq!(
            OpenMode::of_argument(Some("passive")),
            Some(OpenMode::Passive)
        );
        assert_eq!(OpenMode::of_argument(Some("7")), None);
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

    /// What every writer here writes, the reader reads back as written.
    fn read_back(write: impl FnOnce(&mut FixedText<192>)) -> Option<ReplyRead> {
        let mut text: FixedText<192> = FixedText::new();
        write(&mut text);
        ReplyRead::parse(text.finish().expect("fits").as_bytes())
    }

    #[test]
    fn the_reader_reads_back_every_verdict_the_writers_write() {
        let refused = |reason| ReplyRead {
            verdict: "refused",
            links: None,
            generation: None,
            held: None,
            intent: None,
            reason: Some(reason),
        };
        let plain = |verdict| ReplyRead {
            verdict,
            links: None,
            generation: None,
            held: None,
            intent: None,
            reason: None,
        };
        assert_eq!(
            read_back(|t| OpenVerdict::Opening.write_json(t)),
            Some(plain("opening"))
        );
        assert_eq!(
            read_back(|t| CloseVerdict::Closing { links: 3 }.write_json(t)),
            Some(ReplyRead {
                links: Some(3),
                ..plain("closing")
            })
        );
        assert_eq!(
            read_back(|t| CloseVerdict::AlreadyClosed.write_json(t)),
            Some(plain("already_closed"))
        );
        assert_eq!(
            read_back(|t| CloseVerdict::NotFound.write_json(t)),
            Some(plain("not_found"))
        );
        assert_eq!(
            read_back(|t| ResetVerdict::Resetting { links: 1 }.write_json(t)),
            Some(ReplyRead {
                links: Some(1),
                ..plain("resetting")
            })
        );
        assert_eq!(
            read_back(|t| ResetVerdict::Duplicate { last: u64::MAX }.write_json(t)),
            Some(ReplyRead {
                generation: Some(u64::MAX),
                ..plain("duplicate")
            })
        );
        for reason in RefusedReason::ALL {
            assert_eq!(
                read_back(|t| CloseVerdict::Refused(reason).write_json(t)),
                Some(refused(reason)),
                "{reason:?}"
            );
        }
        let status =
            "{\"verdict\":\"status\",\"links\":{\"open\":2,\"closing\":1},\"intent\":true,\
                      \"machines\":[{\"state\":\"established\"}]}";
        let want = ReplyRead {
            held: Some(SessionLinks {
                open: 2,
                closing: 1,
            }),
            intent: Some(true),
            ..plain("status")
        };
        assert_eq!(ReplyRead::parse(status.as_bytes()), Some(want));
        // A querier that kept fewer bytes than the machines take still reads what comes before them.
        let cut = status.find("machines\":[").expect("the list") + "machines\":[".len();
        assert_eq!(ReplyRead::parse(&status.as_bytes()[..cut]), Some(want));
    }

    #[cfg(feature = "storage-profile")]
    #[test]
    fn the_reader_reads_back_the_status_the_writer_writes() {
        let machines = [MachineReport {
            endpoint: None,
            state: "established",
            cause: None,
            in_intent: false,
        }];
        let links = SessionLinks {
            open: 0,
            closing: 4,
        };
        let read = read_back(|t| StatusVerdict::of(links, &machines).write_json(t, &machines))
            .expect("a status");
        assert_eq!(
            (read.verdict, read.held, read.intent),
            ("status", Some(links), Some(false))
        );
    }

    #[test]
    fn the_reader_refuses_what_no_writer_here_writes() {
        for refused in [
            "",
            "{}",
            "{\"verdict\":\"opening\"",
            "{\"verdict\":\"opening\"} ",
            "{\"verdict\":\"held\"}",
            "{\"verdict\":\"closing\"}",
            "{\"verdict\":\"closing\",\"links\":}",
            "{\"verdict\":\"closing\",\"links\":-1}",
            "{\"verdict\":\"closing\",\"links\":+1}",
            "{\"verdict\":\"closing\",\"links\":99999999999}",
            "{\"verdict\":\"duplicate\",\"links\":1}",
            "{\"verdict\":\"refused\"}",
            "{\"verdict\":\"refused\",\"reason\":\"because\"}",
            "{\"verdict\":\"not_found\",\"links\":1}",
            "{\"verdict\":\"status\",\"links\":{\"open\":2,\"closing\":1},\"intent\":true",
            "{\"verdict\":\"status\",\"links\":{\"open\":2,\"closing\":1},\"intent\":yes,\"machines\":[",
            " {\"verdict\":\"opening\"}",
        ] {
            assert_eq!(ReplyRead::parse(refused.as_bytes()), None, "{refused}");
        }
        assert_eq!(ReplyRead::parse(&[0xff, 0xfe]), None, "not text");
    }

    #[test]
    fn every_verbs_words_are_among_the_verdict_words_and_cover_them() {
        let mut seen: [bool; VERDICT_WORDS.len()] = [false; VERDICT_WORDS.len()];
        for verb in VERBS {
            for word in verdict_words_of(verb).expect("a verb has words") {
                let at = VERDICT_WORDS
                    .iter()
                    .position(|known| known == word)
                    .expect("a verb's word is a verdict word");
                seen[at] = true;
            }
        }
        assert!(seen.iter().all(|s| *s), "a verdict word no verb gives");
        assert_eq!(verdict_words_of("hold"), None);
    }

    /// The vocabulary a consumer reads (`scripts/lib/wz_node.py --vocabulary`, `verdicts`) states the
    /// words each verb's reply carries and the sentences of a refusal; it is held here to the sets
    /// the writers and the reader use, so the two cannot drift.
    #[test]
    fn the_vocabulary_states_the_words_and_the_reasons_this_module_writes() {
        let vocabulary = include_str!("../../../scripts/lib/wz_node.py");
        for verb in VERBS {
            let mut line: FixedText<192> = FixedText::new();
            line.push_str("    \"");
            line.push_str(verb);
            line.push_str("\": (");
            for (at, word) in verdict_words_of(verb)
                .expect("a verb has words")
                .iter()
                .enumerate()
            {
                line.push_str(if at == 0 { "\"" } else { ", \"" });
                line.push_str(word);
                line.push_str("\"");
            }
            line.push_str("),\n");
            let line = line.finish().expect("fits");
            assert!(
                vocabulary.contains(line),
                "wz_node.py does not state {line:?}"
            );
        }
        let means_from = vocabulary
            .find("\nVERDICT_MEANS = {\n")
            .expect("wz_node.py states VERDICT_MEANS");
        let means_block = &vocabulary[means_from..];
        let means_block = &means_block[..means_block.find("\n}\n").expect("its end")];
        for word in VERDICT_WORDS {
            let mut means: FixedText<64> = FixedText::new();
            for part in ["\n    \"", word, "\": \""] {
                means.push_str(part);
            }
            let means = means.finish().expect("fits");
            assert!(
                means_block.contains(means),
                "wz_node.py says nothing of what {word} means"
            );
        }
        for reason in RefusedReason::ALL {
            let mut line: FixedText<192> = FixedText::new();
            for part in ["\n    \"", reason.words(), "\",\n"] {
                line.push_str(part);
            }
            let line = line.finish().expect("fits");
            assert!(
                vocabulary.contains(line),
                "wz_node.py does not state the refusal {line:?}"
            );
        }
        // The words of the control channel's error answer (`control.words.pipe.errors`), in the
        // order of `ControlError::ALL`.
        let errors_from = vocabulary
            .find("\nCONTROL_ERRORS = (\n")
            .expect("wz_node.py states CONTROL_ERRORS");
        let errors_block = &vocabulary[errors_from..];
        let errors_block = &errors_block[..errors_block.find("\n)\n").expect("its end")];
        let mut stated = errors_block.lines().skip(2);
        for error in ControlError::ALL {
            let mut line: FixedText<64> = FixedText::new();
            for part in ["    \"", error.words(), "\","] {
                line.push_str(part);
            }
            assert_eq!(
                stated.next(),
                Some(line.finish().expect("fits")),
                "wz_node.py's CONTROL_ERRORS is ControlError::ALL, in its order"
            );
        }
        assert_eq!(stated.next(), None, "CONTROL_ERRORS states no other word");
    }

    /// The words of every vector of `scripts/lib/verb_key_vectors.txt` make its key, and the key
    /// reads back as those words: the file the declared node's generator is held to as well.
    #[test]
    fn the_key_of_every_vector_is_what_the_generator_makes_and_reads_back() {
        let vectors = include_str!("../../../scripts/lib/verb_key_vectors.txt");
        let mut seen = 0;
        for line in vectors
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let mut fields = line.split(' ');
            let mut next = || fields.next().expect("seven fields");
            let (verb, of, about, whatami, generation, mode, key) =
                (next(), next(), next(), next(), next(), next(), next());
            let generation = (generation != "-").then(|| generation.parse::<u64>().expect("a u64"));
            let words = VerbWords {
                verb,
                of,
                about,
                whatami,
                generation,
                mode,
            };
            let mut out: FixedText<{ VERB_KEY_MAX_BYTES }> = FixedText::new();
            words.write(&mut out).expect("the words make a key");
            let written = out.finish().expect("within VERB_KEY_MAX_BYTES");
            assert_eq!(written, key, "{line}");
            let read = VerbKey::parse(written).expect("the key reads back");
            assert_eq!(
                (read.node_zid, read.whatami, read.verb, read.peer_zid),
                (of, whatami, verb, about)
            );
            seen += 1;
        }
        assert!(seen >= 7, "the vectors were read");
    }

    #[test]
    fn the_longest_key_fits_and_every_refusal_is_its_own() {
        let widest = "ffffffffffffffffffffffffffffffff";
        let words = VerbWords {
            verb: RESET_VERB,
            of: widest,
            about: widest,
            whatami: "router",
            generation: Some(u64::MAX),
            mode: "dial",
        };
        let mut out: FixedText<{ VERB_KEY_MAX_BYTES }> = FixedText::new();
        words.write(&mut out).expect("a key");
        assert_eq!(out.finish().expect("fits").len(), VERB_KEY_MAX_BYTES);

        let base = VerbWords {
            verb: CLOSE_VERB,
            of: "a1",
            about: "b2",
            whatami: "client",
            generation: None,
            mode: "dial",
        };
        let refused = |words: VerbWords<'_>| {
            let mut out: FixedText<{ VERB_KEY_MAX_BYTES }> = FixedText::new();
            let why = words.write(&mut out).expect_err("refused");
            assert_eq!(out.finish().expect("empty"), "", "nothing is written");
            why
        };
        assert_eq!(
            refused(VerbWords {
                verb: "hold",
                ..base
            }),
            KeyRefusal::NoSuchVerb
        );
        assert_eq!(
            refused(VerbWords {
                whatami: "server",
                ..base
            }),
            KeyRefusal::NoSuchRole
        );
        assert_eq!(
            refused(VerbWords {
                mode: "wait",
                ..base
            }),
            KeyRefusal::NoSuchMode
        );
        assert_eq!(
            refused(VerbWords { of: "0a", ..base }),
            KeyRefusal::OfIsNoZid
        );
        assert_eq!(
            refused(VerbWords {
                about: "B2",
                ..base
            }),
            KeyRefusal::AboutIsNoZid
        );
        assert_eq!(
            refused(VerbWords {
                verb: RESET_VERB,
                ..base
            }),
            KeyRefusal::ResetTakesAGeneration
        );
        assert_eq!(
            refused(VerbWords {
                generation: Some(1),
                ..base
            }),
            KeyRefusal::OnlyResetTakesAGeneration
        );
        assert_eq!(
            refused(VerbWords {
                mode: "passive",
                ..base
            }),
            KeyRefusal::OnlyOpenIsPassive
        );
        for (at, a) in KeyRefusal::ALL.iter().enumerate() {
            for b in &KeyRefusal::ALL[at + 1..] {
                assert_ne!(a.words(), b.words());
            }
        }
    }

    /// One reader of an answer in band and on the control channel: every document the writers
    /// here write reads back as what it says, and anything else reads as nothing.
    #[test]
    fn an_answer_reads_as_its_verdict_zid_or_error_and_anything_else_as_none() {
        let mut text: FixedText<192> = FixedText::new();
        CloseVerdict::of(CloseOrder {
            newly_ordered: 2,
            already_ordered: 0,
        })
        .write_json(&mut text);
        let closing = text.finish().expect("fits");
        match Answer::read(closing.as_bytes()) {
            Some(Answer::Verdict(read)) => {
                assert_eq!((read.verdict, read.links), ("closing", Some(2)));
            }
            other => panic!("{other:?}"),
        }
        let mut text: FixedText<64> = FixedText::new();
        write_zid_json("a1b2", &mut text);
        assert_eq!(
            Answer::read(text.finish().expect("fits").as_bytes()),
            Some(Answer::Whoami("a1b2"))
        );
        for error in ControlError::ALL {
            let mut text: FixedText<64> = FixedText::new();
            error.write_json(&mut text);
            assert_eq!(
                Answer::read(text.finish().expect("fits").as_bytes()),
                Some(Answer::Error(error))
            );
        }
        for not_one in [
            &b""[..],
            b"{}",
            b"{\"verdict\":\"closing\"",
            b"{\"verdict\":\"closing\",\"links\":}",
            b"{\"zid\":\"0a\"}",
            b"{\"error\":\"nope\"}",
            b"{\"members\":[]}",
            b"\xff",
        ] {
            assert_eq!(Answer::read(not_one), None, "{not_one:?}");
        }
    }

    #[test]
    fn every_outcome_has_a_verdict_and_every_reason_a_clean_sentence() {
        for outcome in [
            OpenOutcome::Accepted,
            OpenOutcome::NotAZid,
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
