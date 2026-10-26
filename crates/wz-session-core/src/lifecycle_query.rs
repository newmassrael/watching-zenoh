// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session lifecycle as a QUERY: close a session and be told what happened,
//! open one, read what a node holds for a peer, and ask a node which lifecycle
//! verbs it has.
//!
//! The close verb has always been a Push on a switchboard row
//! (`@/<zid>/<whatami>/session/close/<peer-zid>`, [`crate::drive::LifecycleKey`]):
//! a matched sample becomes a close request on the session it is bound to, gated
//! by a [`crate::drive::SessionLifecycleAuthority`], and nothing comes back. A
//! Push has no reply path, so a caller could not tell a close that ran from one
//! that was refused or aimed at nobody. This is the same verb asked as a GET, which has one.
//!
//! # The five queries
//!
//! * `GET @/<zid>/<whatami>/session/close/<peer-zid>` takes the peer out of the
//!   node's intent, orders EVERY session this node holds with that peer closed
//!   and answers one JSON object: `{"verdict":"closing","links":N}`,
//!   `{"verdict":"already_closed"}`, `{"verdict":"not_found"}` or
//!   `{"verdict":"refused","reason":"..."}`.
//! * `GET @/<zid>/<whatami>/session/reset/<generation>/<peer-zid>` orders those
//!   sessions closed once per generation and leaves the intent, so a peer the
//!   node should hold is connected again (decision D6 of
//!   `docs/session-lifecycle-intent.md`). A generation no later than one already
//!   taken answers `{"verdict":"duplicate","generation":G}` and closes nothing;
//!   otherwise `resetting` with `links`, `already_closed`, `not_found` or
//!   `refused`.
//! * `GET @/<zid>/<whatami>/session/status/<peer-zid>` reads what the node holds
//!   for the peer, so the outcome of a verb that has no reply (a Push) is
//!   observable (decision D6): the links of its sessions, whether the peer is in
//!   the intent, and the state of each machine that works to hold it,
//!   `{"verdict":"status","links":{"open":N,"closing":M},"intent":true,"machines":[..]}`.
//!   A machine is `{"state":"established"}`, with `"cause"` beside a `refused`
//!   state and `"endpoint"` on a configured endpoint's machine. A refusal answers
//!   `{"verdict":"refused","reason":"..."}`.
//! * `GET @/<zid>/<whatami>/session/open/<peer-zid>` asks the node to hold the
//!   peer: it joins the intent and its machine connects (decision D6). The reply
//!   says the request was taken, `{"verdict":"opening"}`, not that a session is
//!   up; the status query reads how the dial ends. A second open of a held peer
//!   changes nothing and says the same, which is what makes a retransmission
//!   safe. `{"verdict":"refused","reason":"..."}` names a peer the node has no
//!   locator for, one it cannot dial, or a loop that is gone. A host with no
//!   opener serves no open query.
//! * `GET @/<zid>/<whatami>/session/verbs` answers `{"verbs":["close","reset","status"]}`,
//!   with `"open"` last on a node that serves it: the verbs this node has bound.
//!   It says what the node KNOWS, not whether this caller may use it; permission
//!   is judged by `refused` on each verb's query.
//!
//! A node that binds none of them answers nothing, which a querier reads as "no
//! surface". That is the honest answer for a node that has no lifecycle ingress.
//!
//! # What "closing" promises
//!
//! The reply is sent when the close is ORDERED, not when the session is gone,
//! because the query can arrive over the very session it closes and the reply has
//! to leave before the link does. So `closing` means: the drive loop has been told,
//! and the session is on its way to Closed through the ordinary Closing path. A
//! caller that wants completion watches the transport close, as it would for a
//! close from either side.
//!
//! # Whole session, every link
//!
//! A peer may be joined by several links. A close ends the SESSION with that peer,
//! not one link: every link to the peer's zid is ordered closed, and `links` is how
//! many this call ordered. A close that finds the peer's links all already ordered
//! answers `already_closed`.
//!
//! # Why the close, reset, status and open queries are exact-key only
//!
//! A GET may carry a wildcard, and a wildcard close is "close everything that
//! matches". The close query is answered only for a literal key that names this
//! node, this role, the `close` verb and one peer, and the reset query only for
//! one that also names one generation. A wildcard that merely
//! intersects it gets no reply, so a destructive verb is never reached by a pattern
//! the caller did not mean as a target. The status query reads one peer the same
//! way: its reply is about the peer its key names, and a pattern names none. The
//! capability query has no target, so it answers any key that intersects it.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::drive::RESET_VERB;
// Re-exported: the two types a host binds the queries with, so it names one module.
pub use crate::drive::{LifecycleKey, SessionLifecycleAuthority};
// The vocabulary a node with no allocator answers in too: the words are the same list.
use crate::lifecycle_wire::{write_verb_list, OPEN_VERB};
pub use crate::lifecycle_wire::{OpenOutcome, OpenVerdict, RefusedReason};
use crate::query_sink::{QueryView, ReplyError, ReplyOut};
use crate::text_out::{FixedText, TextOut};
use crate::zid_hex::{canonical_zid, same_zid, zenoh_hex_to_zid};

/// The verb the close query carries in its key.
const CLOSE_VERB: &str = "close";

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

/// The node's table of sessions, as the close query needs it: told a peer's zid,
/// it orders closed every session it holds with that peer.
///
/// A port, for the reason [`SessionLifecycleAuthority`] is one: the sessions live
/// in a host's face table, which this crate cannot name. The host implements it
/// over that table (`request_close` on each face's session bundle), and the same
/// answerer serves every host.
pub trait SessionDirectory {
    /// Order every session with the peer whose zid is `peer_zid` (wire bytes, any
    /// trailing zero bytes) closed, and say how many it ordered and how many had
    /// been ordered already. An unknown peer is the default: both zero.
    fn order_close(&self, peer_zid: &[u8]) -> CloseOrder;

    /// The links of the sessions this node has with the peer whose zid is
    /// `peer_zid`, read without changing them: the status query's account of the
    /// sessions (decision D6's status, apart from the intent).
    fn links(&self, peer_zid: &[u8]) -> SessionLinks;
}

impl<D: SessionDirectory + ?Sized> SessionDirectory for &D {
    fn order_close(&self, peer_zid: &[u8]) -> CloseOrder {
        (**self).order_close(peer_zid)
    }

    fn links(&self, peer_zid: &[u8]) -> SessionLinks {
        (**self).links(peer_zid)
    }
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

/// The machines a node works to hold its peers by (decision D5), as the status
/// query reads them: each one that holds the peer a key names.
///
/// A port for the reason [`SessionDirectory`] is one: the machines live with the
/// host that drives them (the face loop of AP), which this crate cannot name.
pub trait PeerMachines {
    /// Call `each` for every machine that holds the peer whose zid is `peer_zid`
    /// (wire bytes, any trailing zero bytes): the node's own machine, and each
    /// configured endpoint's whose last session reached that peer.
    fn each_machine(&self, peer_zid: &[u8], each: &mut dyn FnMut(&MachineReport<'_>));
}

impl<M: PeerMachines + ?Sized> PeerMachines for &M {
    fn each_machine(&self, peer_zid: &[u8], each: &mut dyn FnMut(&MachineReport<'_>)) {
        (**self).each_machine(peer_zid, each)
    }
}

/// The machines of a host that holds no peer by a machine: the status query then
/// reports the sessions alone, and no peer is in the intent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMachines;

impl PeerMachines for NoMachines {
    fn each_machine(&self, _peer_zid: &[u8], _each: &mut dyn FnMut(&MachineReport<'_>)) {}
}

/// The node's intent, as the close query changes it (decision D6 of
/// `docs/session-lifecycle-intent.md`): the peers the node should be connected
/// to, apart from the sessions it has.
///
/// A port for the reason [`SessionDirectory`] is one, and a SEPARATE one because
/// the two are held apart on purpose: a close takes the peer out of the intent
/// and ends its sessions, a reset ends the sessions and leaves the intent, so a
/// peer the node should still hold is connected again by its machine.
pub trait PeerIntent {
    /// Take the peer whose zid is `peer_zid` (wire bytes, any trailing zero
    /// bytes) out of the intent: it is not dialled again, by any machine that
    /// held it, until an `open` or a connect-list edit names it again.
    fn withdraw(&self, peer_zid: &[u8]);
}

impl<I: PeerIntent + ?Sized> PeerIntent for &I {
    fn withdraw(&self, peer_zid: &[u8]) {
        (**self).withdraw(peer_zid)
    }
}

/// The intent of a host that holds no peer by intent: it dials nobody again, so
/// a close has no intent to withdraw. Said by a type rather than by an
/// `Option`, so the queries of such a host state it where they are built.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoIntent;

impl PeerIntent for NoIntent {
    fn withdraw(&self, _peer_zid: &[u8]) {}
}

/// The node's opener, as the open query asks it (decision D6): told a peer's
/// zid, it asks the node's machines to hold that peer.
///
/// A port for the reason [`SessionDirectory`] is one: the locators the node has
/// for a peer, and the machines that dial them, live with the host. The in-band
/// form of the verb asks the same host through [`crate::drive::SessionOpener`],
/// so one request is one request however it arrives (decision D7).
pub trait PeerOpener {
    /// Whether the host has an opener at all. A host without one answers no open
    /// query and lists no `open` verb, because the capability document says what
    /// the node has bound.
    const BOUND: bool = true;

    /// Ask the node to hold the peer whose zid is `peer_zid` (wire bytes, any
    /// trailing zero bytes). A peer already held is unchanged.
    fn open(&self, peer_zid: &[u8]) -> OpenOutcome;
}

impl<O: PeerOpener + ?Sized> PeerOpener for &O {
    const BOUND: bool = O::BOUND;

    fn open(&self, peer_zid: &[u8]) -> OpenOutcome {
        (**self).open(peer_zid)
    }
}

/// The opener of a host that cannot create a session by a zid (a profile with no
/// session manager to bind): the open query is not served.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpener;

impl PeerOpener for NoOpener {
    const BOUND: bool = false;

    fn open(&self, _peer_zid: &[u8]) -> OpenOutcome {
        OpenOutcome::OpenerGone
    }
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
            Self::Refused(reason) => {
                out.push_str("{\"verdict\":\"refused\",\"reason\":\"");
                out.push_str(reason.words());
                out.push_str("\"}");
            }
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
            Self::Refused(reason) => {
                out.push_str("{\"verdict\":\"refused\",\"reason\":\"");
                out.push_str(reason.words());
                out.push_str("\"}");
            }
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

/// The answer to a status query (decision D6), as [`Answered`] reports it: the
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

/// The verb the status query carries in its key.
const STATUS_VERB: &str = "status";

/// Every lifecycle verb a node can have bound, in the order the capability query
/// lists them. `open` is last, and listed only by a node whose host has an opener
/// ([`PeerOpener::BOUND`]).
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

/// The queryables a node hosts to serve the lifecycle queries, as the key
/// patterns to register them on: the close query for any peer, the reset query
/// for any generation and peer, the status query for any peer, the open query for
/// any peer when `open_bound`, and the capability query.
pub fn query_patterns(zid_hex: &str, whatami: &str, open_bound: bool) -> Vec<String> {
    let root = alloc::format!("@/{zid_hex}/{whatami}/session");
    let mut patterns = Vec::from([
        alloc::format!("{root}/{CLOSE_VERB}/*"),
        alloc::format!("{root}/{RESET_VERB}/*/*"),
        alloc::format!("{root}/{STATUS_VERB}/*"),
    ]);
    if open_bound {
        patterns.push(alloc::format!("{root}/{OPEN_VERB}/*"));
    }
    patterns.push(alloc::format!("{root}/verbs"));
    patterns
}

/// Answers the lifecycle queries of one node.
///
/// Holds nothing it does not borrow from the host but one record: the node's
/// identity, the authority that says who may close, reset or read, the directory
/// that holds the sessions, the intent a close withdraws the peer from, the
/// machines the status query reads and the opener an open asks. The record
/// is the latest reset generation taken per peer, the duplicate suppression of
/// at-most-once calls (decision D6; Birrell and Nelson, 1984), and it lives here
/// because this is where a reset is taken. [`Self::answer`] is the body of the
/// queryable handler the host registers on [`query_patterns`].
pub struct LifecycleQueries<A, D, I = NoIntent, M = NoMachines, O = NoOpener> {
    zid_hex: String,
    whatami: String,
    authority: A,
    directory: D,
    intent: I,
    machines: M,
    opener: O,
    /// The latest reset generation taken, by the peer's zid in its canonical
    /// form. Volatile, as every runtime edit of D6 is.
    resets: RefCell<BTreeMap<Vec<u8>, u64>>,
}

/// What [`LifecycleQueries::answer`] did with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// A reply was staged: the close query's verdict.
    Close(CloseVerdict),
    /// A reply was staged: the reset query's verdict.
    Reset(ResetVerdict),
    /// A reply was staged: the status query's verdict.
    Status(StatusVerdict),
    /// A reply was staged: the open query's verdict.
    Open(OpenVerdict),
    /// A reply was staged: the capability document.
    Verbs,
    /// The query is no lifecycle query this node serves, or is a close, reset,
    /// status or open query that is not an exact key; nothing was replied.
    Unserved,
}

impl<A: SessionLifecycleAuthority, D: SessionDirectory> LifecycleQueries<A, D> {
    /// The queries of the node `zid_hex` (zenoh's spelling) of role `whatami`,
    /// for a host that holds no peer by intent, by a machine or by an opener
    /// ([`Self::with_intent`], [`Self::with_machines`] and [`Self::with_opener`]
    /// say it does).
    pub fn new(zid_hex: &str, whatami: &str, authority: A, directory: D) -> Self {
        Self {
            zid_hex: String::from(zid_hex),
            whatami: String::from(whatami),
            authority,
            directory,
            intent: NoIntent,
            machines: NoMachines,
            opener: NoOpener,
            resets: RefCell::new(BTreeMap::new()),
        }
    }
}

impl<A, D, I, M, O> LifecycleQueries<A, D, I, M, O>
where
    A: SessionLifecycleAuthority,
    D: SessionDirectory,
    I: PeerIntent,
    M: PeerMachines,
    O: PeerOpener,
{
    /// These queries for a host that holds its peers by `intent`: a close also
    /// withdraws the peer from it, so no machine dials the peer again.
    pub fn with_intent<J: PeerIntent>(self, intent: J) -> LifecycleQueries<A, D, J, M, O> {
        LifecycleQueries {
            zid_hex: self.zid_hex,
            whatami: self.whatami,
            authority: self.authority,
            directory: self.directory,
            intent,
            machines: self.machines,
            opener: self.opener,
            resets: self.resets,
        }
    }

    /// These queries for a host that holds its peers by `machines`: the status
    /// query reports each one that holds the peer it names.
    pub fn with_machines<N: PeerMachines>(self, machines: N) -> LifecycleQueries<A, D, I, N, O> {
        LifecycleQueries {
            zid_hex: self.zid_hex,
            whatami: self.whatami,
            authority: self.authority,
            directory: self.directory,
            intent: self.intent,
            machines,
            opener: self.opener,
            resets: self.resets,
        }
    }

    /// These queries for a host that can open a session by a zid: the open query
    /// is served, and the capability query lists `open`.
    pub fn with_opener<P: PeerOpener>(self, opener: P) -> LifecycleQueries<A, D, I, M, P> {
        LifecycleQueries {
            zid_hex: self.zid_hex,
            whatami: self.whatami,
            authority: self.authority,
            directory: self.directory,
            intent: self.intent,
            machines: self.machines,
            opener,
            resets: self.resets,
        }
    }

    /// The patterns to register this on.
    pub fn patterns(&self) -> Vec<String> {
        query_patterns(&self.zid_hex, &self.whatami, O::BOUND)
    }

    fn verbs_key(&self) -> String {
        alloc::format!("@/{}/{}/session/verbs", self.zid_hex, self.whatami)
    }

    /// Answer one query: the close or reset query with its verdict, the status
    /// query with what the node holds for the peer, the capability query with the
    /// verb list, or nothing.
    pub fn answer(&self, view: &dyn QueryView, out: &mut dyn ReplyOut) -> Answered {
        let key = view.keyexpr();

        let verbs_key = self.verbs_key();
        let verbs_chunks: alloc::vec::Vec<&str> = verbs_key.split('/').collect();
        if crate::keyexpr_match::keyexpr_intersects_target(key, &verbs_chunks) {
            let mut body: FixedText<64> = FixedText::new();
            write_verbs_json(&mut body, O::BOUND);
            return match body.finish() {
                Ok(text) if reply_json(out, &verbs_key, text).is_ok() => Answered::Verbs,
                _ => Answered::Unserved,
            };
        }

        // The close, reset and status queries: an exact key naming this node and
        // one peer. A pattern is never a target (module docs), the generation
        // included.
        let Some(parsed) = LifecycleKey::parse(key) else {
            return Answered::Unserved;
        };
        if parsed.node_zid != self.zid_hex
            || parsed.whatami != self.whatami
            || parsed.peer_zid.contains(['*', '$'])
            || parsed.argument.is_some_and(|a| a.contains(['*', '$']))
        {
            return Answered::Unserved;
        }
        if parsed.verb == STATUS_VERB {
            // Its own body: the machines are a list, so the reply has no bound
            // this module could size a fixed buffer to.
            let mut body = String::new();
            let verdict = self.status(&parsed, &mut body);
            // A reply the stage refused was still a read: the verdict says what
            // the node holds, and the host's reply-stage counters say the rest.
            let _ = reply_json(out, key, &body);
            return Answered::Status(verdict);
        }
        let mut body: FixedText<192> = FixedText::new();
        let answered = match parsed.verb {
            CLOSE_VERB => {
                let verdict = self.close(&parsed);
                verdict.write_json(&mut body);
                Answered::Close(verdict)
            }
            RESET_VERB => {
                let verdict = self.reset(&parsed);
                verdict.write_json(&mut body);
                Answered::Reset(verdict)
            }
            // A host with no opener binds no open query, so the verb is no query
            // of this node's and nothing is replied.
            OPEN_VERB if O::BOUND => {
                let verdict = self.open(&parsed);
                verdict.write_json(&mut body);
                Answered::Open(verdict)
            }
            _ => return Answered::Unserved,
        };
        match body.finish() {
            Ok(text) if reply_json(out, key, text).is_ok() => answered,
            // A reply the stage refused still happened as an order: the verdict is
            // what the node did, and the host's reply-stage counters say the rest.
            Ok(_) => answered,
            Err(_) => Answered::Unserved,
        }
    }

    /// Close: the peer leaves the intent, and every session with it is ordered
    /// closed. Withdrawn first, so a session that ends before the withdrawal
    /// reaches the node's machines is not dialled again for long: the machine
    /// that took the loss is stopped where it waits.
    fn close(&self, key: &LifecycleKey<'_>) -> CloseVerdict {
        if !self.authority.admits_close(key) {
            return CloseVerdict::Refused(RefusedReason::NotPermitted);
        }
        let Some(peer) = zenoh_hex_to_zid(key.peer_zid) else {
            return CloseVerdict::Refused(RefusedReason::PeerNotAZid);
        };
        self.intent.withdraw(&peer);
        CloseVerdict::of(self.directory.order_close(&peer))
    }

    /// Open: the node's machines are asked to hold the peer, which joins the
    /// intent. A peer already held is unchanged, so a retransmission is safe.
    fn open(&self, key: &LifecycleKey<'_>) -> OpenVerdict {
        if !self.authority.admits_open(key) {
            return OpenVerdict::Refused(RefusedReason::OpenNotPermitted);
        }
        let Some(peer) = zenoh_hex_to_zid(key.peer_zid) else {
            return OpenVerdict::Refused(RefusedReason::PeerNotAZid);
        };
        OpenVerdict::of(self.opener.open(&peer))
    }

    /// Reset: every session with the peer is ordered closed once for the key's
    /// generation, and the intent is left as it is. A generation no later than
    /// the latest taken for the peer is a retransmission and closes nothing.
    fn reset(&self, key: &LifecycleKey<'_>) -> ResetVerdict {
        if !self.authority.admits_reset(key) {
            return ResetVerdict::Refused(RefusedReason::ResetNotPermitted);
        }
        let Some(peer) = zenoh_hex_to_zid(key.peer_zid) else {
            return ResetVerdict::Refused(RefusedReason::PeerNotAZid);
        };
        let Some(generation) = key.argument.and_then(|g| g.parse::<u64>().ok()) else {
            return ResetVerdict::Refused(RefusedReason::GenerationNotANumber);
        };
        let canonical = Vec::from(canonical_zid(&peer));
        {
            let mut resets = self.resets.borrow_mut();
            if let Some(&last) = resets.get(&canonical) {
                if generation <= last {
                    return ResetVerdict::Duplicate { last };
                }
            }
            // Taken before the close is ordered: a close the node could not carry
            // out (no session) is still this generation's, so a retransmission
            // after the peer is back does not close it.
            resets.insert(canonical, generation);
        }
        ResetVerdict::of(self.directory.order_close(&peer))
    }

    /// Status: the links of the sessions with the peer, and each machine that
    /// works to hold it, written into `body`. Reads only: nothing here changes a
    /// session, a machine or the intent.
    fn status(&self, key: &LifecycleKey<'_>, body: &mut String) -> StatusVerdict {
        use core::fmt::Write as _;
        let refused = |reason: RefusedReason, body: &mut String| {
            body.push_str("{\"verdict\":\"refused\",\"reason\":\"");
            body.push_str(reason.words());
            body.push_str("\"}");
            StatusVerdict::Refused(reason)
        };
        if !self.authority.admits_status(key) {
            return refused(RefusedReason::StatusNotPermitted, body);
        }
        let Some(peer) = zenoh_hex_to_zid(key.peer_zid) else {
            return refused(RefusedReason::PeerNotAZid, body);
        };
        let links = self.directory.links(&peer);
        let mut rows = String::new();
        let mut machines = 0u32;
        let mut intent = false;
        self.machines.each_machine(&peer, &mut |machine| {
            if machines > 0 {
                rows.push(',');
            }
            machines = machines.saturating_add(1);
            intent |= machine.in_intent;
            rows.push_str("{\"state\":");
            crate::json::escape_into(machine.state, &mut rows);
            if let Some(cause) = machine.cause {
                rows.push_str(",\"cause\":");
                crate::json::escape_into(cause, &mut rows);
            }
            if let Some(endpoint) = machine.endpoint {
                rows.push_str(",\"endpoint\":");
                crate::json::escape_into(endpoint, &mut rows);
            }
            rows.push('}');
        });
        let _ = write!(
            body,
            "{{\"verdict\":\"status\",\"links\":{{\"open\":{},\"closing\":{}}},\"intent\":{intent},\"machines\":[{rows}]}}",
            links.open, links.closing
        );
        StatusVerdict::Status {
            links,
            intent,
            machines,
        }
    }
}

/// Stage one JSON reply under `key`.
fn reply_json(out: &mut dyn ReplyOut, key: &str, body: &str) -> Result<(), ReplyError> {
    // The PACKED id (`id << 1`): its low bit says a schema string follows, so the
    // bare id of `application/json` (5) would announce a schema that is not there
    // and the querier would read the reply as malformed and close the session.
    out.reply_keyed_encoded_parts(
        key,
        body.as_bytes(),
        crate::sample::EncodingHint::APPLICATION_JSON.packed_id,
        None,
    )
}

/// One session a host holds, as the close query reads it. Implemented for the
/// session bundle itself, so a host's face table is a list of these and its
/// directory is one call to [`order_close_over`].
pub trait SessionTarget {
    /// The zid of the peer this session is with, once the handshake named it.
    fn peer_zid(&self) -> Option<alloc::vec::Vec<u8>>;
    /// Whether a close has already been ordered for this session.
    fn close_ordered(&self) -> bool;
    /// Order this session closed.
    fn order_close(&self);
}

impl<R: crate::link::SessionRuntime, T: wz_runtime_core::TimeSource> SessionTarget
    for crate::session_actions::SessionLinkActions<R, T>
{
    fn peer_zid(&self) -> Option<alloc::vec::Vec<u8>> {
        crate::session_actions::SessionLinkActions::peer_zid(self)
    }

    fn close_ordered(&self) -> bool {
        crate::session_actions::SessionLinkActions::close_ordered(self)
    }

    fn order_close(&self) {
        self.request_close();
    }
}

/// Order closed every session of `sessions` that is with `peer_zid`, once each.
///
/// The one place "count the links, order the ones not yet ordered, never order one
/// twice" is decided, so that every host's [`SessionDirectory`] is the enumeration
/// of its own face table and nothing more. Zids are compared as values
/// ([`same_zid`]), so a peer that pads its id with trailing zero bytes is the peer
/// its key names.
pub fn order_close_over<'a, S, I>(sessions: I, peer_zid: &[u8]) -> CloseOrder
where
    S: SessionTarget + ?Sized + 'a,
    I: IntoIterator<Item = &'a S>,
{
    let mut order = CloseOrder::default();
    for session in sessions {
        let Some(zid) = session.peer_zid() else {
            continue;
        };
        if !same_zid(&zid, peer_zid) {
            continue;
        }
        if session.close_ordered() {
            order.already_ordered = order.already_ordered.saturating_add(1);
        } else {
            session.order_close();
            order.newly_ordered = order.newly_ordered.saturating_add(1);
        }
    }
    order
}

/// The links of `sessions` that are with `peer_zid`, by whether a close was
/// ordered for each: the read [`order_close_over`] makes before it orders, so a
/// host's [`SessionDirectory::links`] is the same enumeration of its face table.
pub fn count_links_over<'a, S, I>(sessions: I, peer_zid: &[u8]) -> SessionLinks
where
    S: SessionTarget + ?Sized + 'a,
    I: IntoIterator<Item = &'a S>,
{
    let mut links = SessionLinks::default();
    for session in sessions {
        let Some(zid) = session.peer_zid() else {
            continue;
        };
        if !same_zid(&zid, peer_zid) {
            continue;
        }
        if session.close_ordered() {
            links.closing = links.closing.saturating_add(1);
        } else {
            links.open = links.open.saturating_add(1);
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::PeerConnectionState;
    use crate::query_sink::BorrowedQuery;
    use crate::sample::{EncodingHint, QosLevel};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};

    const ME: &str = "a1b2";
    const PEER_A: &str = "c3d4";
    const PEER_B: &str = "e5f6";

    /// A reply sink that keeps what it was given.
    #[derive(Default)]
    struct Recorder {
        /// `(key, body, packed encoding id)` per reply.
        replies: Vec<(String, String, u32)>,
    }

    impl ReplyOut for Recorder {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_keyed_encoded(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&EncodingHint>,
        ) -> Result<(), ReplyError> {
            self.replies.push((
                String::from(keyexpr),
                String::from_utf8(payload.to_vec()).expect("a lifecycle reply is text"),
                encoding.expect("a lifecycle reply is typed").packed_id,
            ));
            Ok(())
        }
        fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn query(keyexpr: &str) -> impl QueryView + '_ {
        BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 1,
            is_local: false,
            qos: QosLevel::DEFAULT,
        }
    }

    /// An authority with one answer for every key, counting how often it is asked.
    struct Authority {
        admits: bool,
        asked: Cell<u32>,
    }

    impl SessionLifecycleAuthority for Authority {
        fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.admits
        }

        fn admits_reset(&self, _key: &LifecycleKey<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.admits
        }

        fn admits_status(&self, _key: &LifecycleKey<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.admits
        }

        fn admits_open(&self, _key: &LifecycleKey<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.admits
        }
    }

    /// Sessions that remember being ordered closed.
    struct Fake {
        zid: Option<Vec<u8>>,
        ordered: Cell<bool>,
    }

    impl SessionTarget for Fake {
        fn peer_zid(&self) -> Option<Vec<u8>> {
            self.zid.clone()
        }
        fn close_ordered(&self) -> bool {
            self.ordered.get()
        }
        fn order_close(&self) {
            self.ordered.set(true);
        }
    }

    struct Table(RefCell<Vec<Fake>>);

    impl SessionDirectory for Table {
        fn order_close(&self, peer_zid: &[u8]) -> CloseOrder {
            order_close_over(self.0.borrow().iter(), peer_zid)
        }

        fn links(&self, peer_zid: &[u8]) -> SessionLinks {
            count_links_over(self.0.borrow().iter(), peer_zid)
        }
    }

    fn fake(zid: &str) -> Fake {
        Fake {
            zid: zenoh_hex_to_zid(zid),
            ordered: Cell::new(false),
        }
    }

    fn node(admits: bool, sessions: Vec<Fake>) -> LifecycleQueries<Authority, Table> {
        LifecycleQueries::new(
            ME,
            "peer",
            Authority {
                admits,
                asked: Cell::new(0),
            },
            Table(RefCell::new(sessions)),
        )
    }

    fn ask<I: PeerIntent, M: PeerMachines, O: PeerOpener>(
        node: &LifecycleQueries<Authority, Table, I, M, O>,
        key: &str,
    ) -> (Answered, Vec<(String, String)>) {
        let mut out = Recorder::default();
        let answered = node.answer(&query(key), &mut out);
        for (_, _, encoding) in &out.replies {
            // The PACKED id of application/json, 5 << 1: the bare 5 has its
            // schema-present bit set, and a querier reads it as a malformed reply.
            assert_eq!(*encoding, 10);
        }
        (
            answered,
            out.replies.into_iter().map(|(k, b, _)| (k, b)).collect(),
        )
    }

    /// The four verdicts are four different documents, each a single JSON object
    /// with only the keys its word carries, under the key that was asked.
    #[test]
    fn each_verdict_is_its_own_document_under_the_asked_key() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let node = node(true, vec![fake(PEER_A), fake(PEER_B)]);

        let (answered, replies) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
        assert_eq!(
            replies,
            vec![(
                key.clone(),
                String::from("{\"verdict\":\"closing\",\"links\":1}")
            )]
        );

        // The same peer again: nothing new to order, and it says so.
        let (answered, replies) = ask(&node, &key);
        assert_eq!(answered, Answered::Close(CloseVerdict::AlreadyClosed));
        assert_eq!(
            replies,
            vec![(
                key.clone(),
                String::from("{\"verdict\":\"already_closed\"}")
            )]
        );

        // A peer this node has no session with.
        let nobody = alloc::format!("@/{ME}/peer/session/close/1f0e");
        let (answered, replies) = ask(&node, &nobody);
        assert_eq!(answered, Answered::Close(CloseVerdict::NotFound));
        assert_eq!(
            replies,
            vec![(nobody, String::from("{\"verdict\":\"not_found\"}"))]
        );

        // The other peer was not touched by any of it.
        assert!(!node.directory.0.borrow()[1].ordered.get());
    }

    /// A close ends the WHOLE session: every link to the peer, counted, each
    /// ordered once. The control is the peer's neighbour, which stays open.
    #[test]
    fn a_close_orders_every_link_to_the_peer_and_counts_them() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let one_already = fake(PEER_A);
        one_already.ordered.set(true);
        let node = node(
            true,
            vec![fake(PEER_A), fake(PEER_A), one_already, fake(PEER_B)],
        );

        let (answered, _) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Closing { links: 2 }),
            "two links were ordered by this call; the third had been ordered before"
        );
        let table = node.directory.0.borrow();
        assert!(table[..3].iter().all(|s| s.ordered.get()));
        assert!(!table[3].ordered.get(), "CONTROL: another peer's session");
    }

    /// A session whose peer zid is padded with trailing zero bytes is the peer its
    /// key names: ids are compared as values.
    #[test]
    fn a_peer_with_a_padded_zid_is_the_peer_its_key_names() {
        let mut padded = fake(PEER_A);
        padded
            .zid
            .as_mut()
            .expect("a zid")
            .extend_from_slice(&[0, 0]);
        let node = node(true, vec![padded]);
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        assert_eq!(
            ask(&node, &key).0,
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
    }

    /// A refusal asks the directory nothing: the sessions are not touched, and the
    /// reply carries the reason in the implementation's own words.
    #[test]
    fn a_refused_close_touches_no_session_and_says_why() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let node = node(false, vec![fake(PEER_A)]);
        let (answered, replies) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Refused(RefusedReason::NotPermitted))
        );
        assert_eq!(
            replies,
            vec![(
                key,
                String::from(
                    "{\"verdict\":\"refused\",\"reason\":\"this node does not permit closing \
                     the session with that peer\"}"
                )
            )]
        );
        assert!(!node.directory.0.borrow()[0].ordered.get());

        // A last chunk that is not a zid is refused, after the authority has spoken.
        let node = node_for_bad_peer();
        let bad = alloc::format!("@/{ME}/peer/session/close/not-a-zid");
        let (answered, replies) = ask(&node, &bad);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Refused(RefusedReason::PeerNotAZid))
        );
        assert!(replies[0]
            .1
            .contains("\"reason\":\"the last chunk of the key is not a zid\""));
    }

    fn node_for_bad_peer() -> LifecycleQueries<Authority, Table> {
        node(true, vec![fake(PEER_A)])
    }

    /// A destructive verb is reached only by a key that names its target. A pattern,
    /// another node's key, another role's key and a key of another verb get no reply,
    /// and the authority is not even asked.
    #[test]
    fn a_close_is_reached_only_by_a_key_that_names_one_peer_of_this_node() {
        let node = node(true, vec![fake(PEER_A)]);
        for key in [
            alloc::format!("@/{ME}/peer/session/close/*"),
            alloc::format!("@/{ME}/peer/session/close/**"),
            alloc::format!("@/{ME}/peer/session/close/$*"),
            alloc::format!("@/{ME}/peer/session/cl$*/{PEER_A}"),
            alloc::format!("@/ffff/peer/session/close/{PEER_A}"),
            alloc::format!("@/{ME}/router/session/close/{PEER_A}"),
            alloc::format!("@/{ME}/peer/session/open/{PEER_A}"),
            alloc::format!("@/{ME}/peer/session/close"),
            String::from("demo/anything"),
        ] {
            let (answered, replies) = ask(&node, &key);
            assert_eq!(answered, Answered::Unserved, "{key}");
            assert!(replies.is_empty(), "{key}");
        }
        assert_eq!(
            node.authority.asked.get(),
            0,
            "no key above reached the authority"
        );
        assert!(!node.directory.0.borrow()[0].ordered.get());

        // A pattern that covers the capability key is answered with the capability
        // and nothing else: it is a question about the verbs, never a target.
        for pattern in [
            alloc::format!("@/{ME}/peer/session/**"),
            alloc::format!("@/{ME}/peer/**"),
        ] {
            let (answered, _) = ask(&node, &pattern);
            assert_eq!(answered, Answered::Verbs, "{pattern}");
        }
        assert_eq!(node.authority.asked.get(), 0);
        assert!(!node.directory.0.borrow()[0].ordered.get());
    }

    /// The capability query names the verbs the node has bound, to a literal key and
    /// to a pattern that covers it; and it does not depend on the authority.
    #[test]
    fn the_capability_query_lists_the_bound_verbs() {
        let verbs = alloc::format!("@/{ME}/peer/session/verbs");
        for admits in [true, false] {
            let node = node(admits, Vec::new());
            for asked in [
                verbs.clone(),
                alloc::format!("@/{ME}/peer/session/*"),
                alloc::format!("@/{ME}/peer/**"),
            ] {
                let (answered, replies) = ask(&node, &asked);
                assert_eq!(answered, Answered::Verbs, "{asked}");
                assert_eq!(
                    replies,
                    vec![(
                        verbs.clone(),
                        String::from("{\"verbs\":[\"close\",\"reset\",\"status\"]}")
                    )],
                    "{asked}"
                );
            }
            assert_eq!(node.authority.asked.get(), 0);
        }
        // Another node's capability is not this node's to answer.
        let node = node(true, Vec::new());
        assert_eq!(
            ask(&node, "@/ffff/peer/session/verbs").0,
            Answered::Unserved
        );
    }

    /// The patterns a host registers are the four keys the queries are asked on.
    #[test]
    fn the_registered_patterns_cover_exactly_the_queries_a_host_serves() {
        assert_eq!(
            query_patterns(ME, "peer", false),
            [
                "@/a1b2/peer/session/close/*",
                "@/a1b2/peer/session/reset/*/*",
                "@/a1b2/peer/session/status/*",
                "@/a1b2/peer/session/verbs",
            ]
        );
        assert_eq!(
            query_patterns(ME, "peer", true),
            [
                "@/a1b2/peer/session/close/*",
                "@/a1b2/peer/session/reset/*/*",
                "@/a1b2/peer/session/status/*",
                "@/a1b2/peer/session/open/*",
                "@/a1b2/peer/session/verbs",
            ]
        );
    }

    /// An opener that records each peer it is asked to hold and answers as told.
    struct Opener {
        asked: RefCell<Vec<Vec<u8>>>,
        outcome: OpenOutcome,
    }

    impl Opener {
        fn answering(outcome: OpenOutcome) -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                outcome,
            }
        }
    }

    impl PeerOpener for Opener {
        fn open(&self, peer_zid: &[u8]) -> OpenOutcome {
            self.asked.borrow_mut().push(peer_zid.to_vec());
            self.outcome
        }
    }

    /// Decision D6 — an open asks the node's machines to hold the peer and says the
    /// request was taken; asked again it asks again and says the same, because the
    /// machines treat a second open as no change. Each outcome of the opener is its
    /// own refusal word.
    #[test]
    fn an_open_asks_the_opener_and_each_outcome_is_its_own_word() {
        let key = alloc::format!("@/{ME}/peer/session/open/{PEER_A}");
        let a = zenoh_hex_to_zid(PEER_A).expect("a zid");

        let taking = node(true, Vec::new()).with_opener(Opener::answering(OpenOutcome::Accepted));
        for _ in 0..2 {
            let (answered, replies) = ask(&taking, &key);
            assert_eq!(answered, Answered::Open(OpenVerdict::Opening));
            assert_eq!(
                replies,
                vec![(key.clone(), String::from("{\"verdict\":\"opening\"}"))]
            );
        }
        assert_eq!(*taking.opener.asked.borrow(), vec![a.clone(), a]);

        for (outcome, reason) in [
            (OpenOutcome::PeerUnknown, RefusedReason::PeerUnknown),
            (
                OpenOutcome::NoDialableLocator,
                RefusedReason::NoDialableLocator,
            ),
            (OpenOutcome::OpenerGone, RefusedReason::OpenerGone),
            (OpenOutcome::NoRoom, RefusedReason::NoRoom),
            (OpenOutcome::Unverifiable, RefusedReason::Unverifiable),
        ] {
            let refusing = node(true, Vec::new()).with_opener(Opener::answering(outcome));
            let (answered, replies) = ask(&refusing, &key);
            assert_eq!(answered, Answered::Open(OpenVerdict::Refused(reason)));
            assert_eq!(
                replies[0].1,
                alloc::format!(
                    "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                    reason.words()
                )
            );
        }
    }

    /// An open the authority does not admit, or aimed at what is not a zid, asks
    /// the opener nothing; a pattern is no target; and a host with no opener serves
    /// no open query and lists no such verb.
    #[test]
    fn an_open_is_refused_unserved_or_not_a_query_of_a_host_with_no_opener() {
        let key = alloc::format!("@/{ME}/peer/session/open/{PEER_A}");

        let denied = node(false, Vec::new()).with_opener(Opener::answering(OpenOutcome::Accepted));
        assert_eq!(
            ask(&denied, &key).0,
            Answered::Open(OpenVerdict::Refused(RefusedReason::OpenNotPermitted))
        );
        let (answered, _) = ask(&denied, &alloc::format!("@/{ME}/peer/session/open/0f1e"));
        assert_eq!(
            answered,
            Answered::Open(OpenVerdict::Refused(RefusedReason::OpenNotPermitted)),
            "the authority speaks before the key's last chunk is read"
        );
        assert!(denied.opener.asked.borrow().is_empty());

        let permitted =
            node(true, Vec::new()).with_opener(Opener::answering(OpenOutcome::Accepted));
        let (answered, _) = ask(&permitted, &alloc::format!("@/{ME}/peer/session/open/0f1e"));
        assert_eq!(
            answered,
            Answered::Open(OpenVerdict::Refused(RefusedReason::PeerNotAZid))
        );
        for pattern in [
            alloc::format!("@/{ME}/peer/session/open/*"),
            alloc::format!("@/{ME}/peer/session/open/**"),
        ] {
            assert_eq!(ask(&permitted, &pattern).0, Answered::Unserved, "{pattern}");
        }
        assert!(permitted.opener.asked.borrow().is_empty());

        // No opener: not served, and the capability document does not list it.
        let bare = node(true, Vec::new());
        assert_eq!(ask(&bare, &key).0, Answered::Unserved);
        let verbs = alloc::format!("@/{ME}/peer/session/verbs");
        assert!(!ask(&bare, &verbs).1[0].1.contains("open"));
        assert_eq!(
            ask(&permitted, &verbs).1[0].1,
            "{\"verbs\":[\"close\",\"reset\",\"status\",\"open\"]}"
        );
    }

    /// The in-band query of the heap profile held to the table every transport of the contract is
    /// held to (`lifecycle_contract`, decision D7): the same cases the fixed-memory profile's query
    /// and the control port answer, asked as a GET on the node's own key. The opener here is told
    /// the zid as wire bytes without their trailing zeros, which is this profile's form; the judge
    /// reads it in the sixteen-byte form the others give.
    #[cfg(feature = "lifecycle-contract")]
    #[test]
    fn the_heap_query_conforms_to_the_contract_every_transport_is_held_to() {
        use crate::credential_identity::zid_from_wire;
        use crate::lifecycle_contract::{judge_answers, judge_asking, Binding, CASES, REPEATS};

        for case in CASES {
            let key = alloc::format!("@/{ME}/peer/session/open/{}", case.peer_text);
            let bound =
                node(case.permitted, Vec::new()).with_opener(Opener::answering(case.outcome));
            let bare = node(case.permitted, Vec::new());
            let answers: Vec<Option<String>> = (0..REPEATS)
                .map(|_| {
                    let replies = match case.binding {
                        Binding::Bound => ask(&bound, &key).1,
                        Binding::Unbound => ask(&bare, &key).1,
                    };
                    replies
                        .into_iter()
                        .find(|(reply_key, _)| *reply_key == key)
                        .map(|(_, body)| body)
                })
                .collect();
            let seen: Vec<Option<&str>> = answers.iter().map(Option::as_deref).collect();
            judge_answers(case, &seen).unwrap_or_else(|v| panic!("{v:?}: {seen:?}"));
            if matches!(case.binding, Binding::Bound) {
                let asked = bound.opener.asked.borrow();
                let last = asked
                    .last()
                    .and_then(|zid| zid_from_wire(zid))
                    .unwrap_or([0; crate::credential_identity::CREDENTIAL_ZID_BYTES]);
                judge_asking(case, asked.len() as u32, last).unwrap_or_else(|v| panic!("{v:?}"));
            }
        }
    }

    /// The machines of a host, each with the zid of the peer it holds.
    struct Machines(Vec<(Vec<u8>, Option<&'static str>, PeerConnectionState)>);

    impl PeerMachines for Machines {
        fn each_machine(&self, peer_zid: &[u8], each: &mut dyn FnMut(&MachineReport<'_>)) {
            for (zid, endpoint, state) in &self.0 {
                if same_zid(zid, peer_zid) {
                    let words = state.words();
                    each(&MachineReport {
                        endpoint: *endpoint,
                        state: words.state,
                        cause: words.cause,
                        in_intent: state.in_intent(),
                    });
                }
            }
        }
    }

    /// Decision D6 — the status of a peer is read, not changed: the links of its
    /// sessions by whether a close was ordered, and each machine that holds it,
    /// a refusal with its cause and an endpoint's machine with its endpoint.
    #[test]
    fn a_status_reads_the_links_and_every_machine_that_holds_the_peer() {
        let a = zenoh_hex_to_zid(PEER_A).expect("a zid");
        let b = zenoh_hex_to_zid(PEER_B).expect("a zid");
        let node = node(true, vec![fake(PEER_A), fake(PEER_A), fake(PEER_B)]).with_machines(
            Machines(vec![
                (a.clone(), None, PeerConnectionState::Established),
                (
                    a.clone(),
                    Some("127.0.0.1:7447"),
                    PeerConnectionState::NoSlot,
                ),
                (b.clone(), None, PeerConnectionState::Idle),
            ]),
        );
        node.directory.0.borrow()[1].ordered.set(true);
        let key = alloc::format!("@/{ME}/peer/session/status/{PEER_A}");

        let (answered, replies) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Status(StatusVerdict::Status {
                links: SessionLinks {
                    open: 1,
                    closing: 1
                },
                intent: true,
                machines: 2,
            })
        );
        assert_eq!(
            replies,
            vec![(
                key,
                String::from(
                    "{\"verdict\":\"status\",\"links\":{\"open\":1,\"closing\":1},\"intent\":true,\
                     \"machines\":[{\"state\":\"established\"},{\"state\":\"refused\",\
                     \"cause\":\"no_slot\",\"endpoint\":\"127.0.0.1:7447\"}]}"
                )
            )]
        );
        assert_eq!(
            node.directory
                .0
                .borrow()
                .iter()
                .filter(|s| s.ordered.get())
                .count(),
            1,
            "a status orders no close"
        );

        // A peer whose only machine was closed is out of the intent.
        let (answered, replies) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/status/{PEER_B}"),
        );
        assert_eq!(
            answered,
            Answered::Status(StatusVerdict::Status {
                links: SessionLinks {
                    open: 1,
                    closing: 0
                },
                intent: false,
                machines: 1,
            })
        );
        assert!(
            replies[0].1.contains("\"intent\":false"),
            "{}",
            replies[0].1
        );
    }

    /// A host with no machines reads the sessions alone; a status the authority
    /// does not admit reads nothing; a pattern is no target.
    #[test]
    fn a_status_is_refused_unserved_or_read_from_the_sessions_alone() {
        let bare = node(true, vec![fake(PEER_A)]);
        let (answered, replies) = ask(
            &bare,
            &alloc::format!("@/{ME}/peer/session/status/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Status(StatusVerdict::Status {
                links: SessionLinks {
                    open: 1,
                    closing: 0
                },
                intent: false,
                machines: 0,
            })
        );
        assert_eq!(
            replies[0].1,
            "{\"verdict\":\"status\",\"links\":{\"open\":1,\"closing\":0},\"intent\":false,\"machines\":[]}"
        );

        let refused = node(false, vec![fake(PEER_A)]);
        let (answered, replies) = ask(
            &refused,
            &alloc::format!("@/{ME}/peer/session/status/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Status(StatusVerdict::Refused(RefusedReason::StatusNotPermitted))
        );
        assert_eq!(
            replies[0].1,
            alloc::format!(
                "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                RefusedReason::StatusNotPermitted.words()
            )
        );

        for key in [
            alloc::format!("@/{ME}/peer/session/status/*"),
            alloc::format!("@/{ME}/peer/session/status/**"),
        ] {
            assert_eq!(ask(&bare, &key).0, Answered::Unserved, "{key}");
        }
    }

    /// The intent of a host that records each peer a close withdraws.
    #[derive(Default)]
    struct Intent(RefCell<Vec<Vec<u8>>>);

    impl PeerIntent for Intent {
        fn withdraw(&self, peer_zid: &[u8]) {
            self.0.borrow_mut().push(peer_zid.to_vec());
        }
    }

    /// Decision D6 — a close takes the peer out of the intent and ends its
    /// sessions; a reset ends them and leaves the intent.
    #[test]
    fn a_close_withdraws_the_peer_and_a_reset_does_not() {
        let node = node(true, vec![fake(PEER_A)]).with_intent(Intent::default());
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/1/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Resetting { links: 1 })
        );
        assert!(
            node.intent.0.borrow().is_empty(),
            "a reset leaves the intent"
        );

        node.directory.0.borrow()[0].ordered.set(false);
        let (answered, _) = ask(&node, &alloc::format!("@/{ME}/peer/session/close/{PEER_A}"));
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
        assert_eq!(
            *node.intent.0.borrow(),
            vec![zenoh_hex_to_zid(PEER_A).expect("a zid")],
            "a close withdraws the peer it names"
        );
    }

    /// Decision D6 — a reset closes once per generation: a retransmission of a
    /// generation already taken, or of an earlier one, closes nothing and says
    /// which generation was taken; a later one closes again.
    #[test]
    fn a_reset_closes_once_per_generation() {
        let node = node(true, vec![fake(PEER_A)]);
        let reset =
            |generation: u64| alloc::format!("@/{ME}/peer/session/reset/{generation}/{PEER_A}");

        let (answered, replies) = ask(&node, &reset(7));
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Resetting { links: 1 })
        );
        assert_eq!(replies[0].1, "{\"verdict\":\"resetting\",\"links\":1}");

        node.directory.0.borrow()[0].ordered.set(false);
        for again in [7, 3] {
            let (answered, replies) = ask(&node, &reset(again));
            assert_eq!(
                answered,
                Answered::Reset(ResetVerdict::Duplicate { last: 7 })
            );
            assert_eq!(replies[0].1, "{\"verdict\":\"duplicate\",\"generation\":7}");
        }
        assert!(
            !node.directory.0.borrow()[0].ordered.get(),
            "a duplicate orders no close"
        );

        let (answered, _) = ask(&node, &reset(8));
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Resetting { links: 1 })
        );

        // A generation taken for a peer the node holds no session with is still
        // taken: its retransmission after the peer is back closes nothing.
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/1/{PEER_B}"),
        );
        assert_eq!(answered, Answered::Reset(ResetVerdict::NotFound));
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/1/{PEER_B}"),
        );
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Duplicate { last: 1 })
        );
    }

    /// A reset is refused when the authority does not admit it, or when its
    /// generation is not a number, and then takes no generation; a pattern in
    /// the generation is no target at all.
    #[test]
    fn a_reset_is_refused_or_unserved_and_then_takes_no_generation() {
        let node = node(false, vec![fake(PEER_A)]);
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/1/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Refused(RefusedReason::ResetNotPermitted))
        );

        let node = node_for_bad_peer();
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/x/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Refused(RefusedReason::GenerationNotANumber))
        );
        for key in [
            alloc::format!("@/{ME}/peer/session/reset/*/{PEER_A}"),
            alloc::format!("@/{ME}/peer/session/reset/{PEER_A}"),
        ] {
            assert_eq!(ask(&node, &key).0, Answered::Unserved, "{key}");
        }
        assert!(!node.directory.0.borrow()[0].ordered.get());
        let (answered, _) = ask(
            &node,
            &alloc::format!("@/{ME}/peer/session/reset/1/{PEER_A}"),
        );
        assert_eq!(
            answered,
            Answered::Reset(ResetVerdict::Resetting { links: 1 }),
            "the refused and unserved keys took no generation"
        );
    }

    /// The words a querier switches on are one closed set, each its own document.
    #[test]
    fn the_verdict_words_are_the_declared_set() {
        let all = [
            CloseVerdict::Closing { links: 3 },
            CloseVerdict::AlreadyClosed,
            CloseVerdict::NotFound,
            CloseVerdict::Refused(RefusedReason::NotPermitted),
        ];
        let words: Vec<&str> = all.iter().map(CloseVerdict::word).collect();
        assert_eq!(words, CloseVerdict::WORDS);
        for verdict in all {
            let mut text: FixedText<192> = FixedText::new();
            verdict.write_json(&mut text);
            let doc = text.finish().expect("fits");
            assert!(
                doc.starts_with(&alloc::format!("{{\"verdict\":\"{}\"", verdict.word())),
                "{doc}"
            );
            assert_eq!(
                doc.contains("\"links\""),
                matches!(verdict, CloseVerdict::Closing { .. })
            );
            assert_eq!(
                doc.contains("\"reason\""),
                matches!(verdict, CloseVerdict::Refused(_))
            );
        }
        for reason in RefusedReason::ALL {
            assert!(
                !reason.words().contains(['"', '\\']),
                "a reason is written into the JSON as it stands"
            );
        }
        let all = [
            ResetVerdict::Resetting { links: 2 },
            ResetVerdict::AlreadyClosed,
            ResetVerdict::NotFound,
            ResetVerdict::Duplicate { last: 4 },
            ResetVerdict::Refused(RefusedReason::ResetNotPermitted),
        ];
        let words: Vec<&str> = all.iter().map(ResetVerdict::word).collect();
        assert_eq!(words, ResetVerdict::WORDS);
        for verdict in all {
            let mut text: FixedText<192> = FixedText::new();
            verdict.write_json(&mut text);
            let doc = text.finish().expect("fits");
            assert!(
                doc.starts_with(&alloc::format!("{{\"verdict\":\"{}\"", verdict.word())),
                "{doc}"
            );
        }
        let all = [
            StatusVerdict::Status {
                links: SessionLinks::default(),
                intent: false,
                machines: 0,
            },
            StatusVerdict::Refused(RefusedReason::StatusNotPermitted),
        ];
        let words: Vec<&str> = all.iter().map(StatusVerdict::word).collect();
        assert_eq!(words, StatusVerdict::WORDS);
        let all = [
            OpenVerdict::Opening,
            OpenVerdict::Refused(RefusedReason::PeerUnknown),
        ];
        let words: Vec<&str> = all.iter().map(OpenVerdict::word).collect();
        assert_eq!(words, OpenVerdict::WORDS);
    }
}
