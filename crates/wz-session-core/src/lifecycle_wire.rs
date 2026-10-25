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
            Self::Opening => "opening",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 2] = ["opening", "refused"];
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
