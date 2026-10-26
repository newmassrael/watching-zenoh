// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The conformance table of decision D7, `docs/session-lifecycle-intent.md`: one list of the
//! cases a request to hold a peer can be, and what the contract says of each, for every
//! transport and every profile to be held to.
//!
//! The contract is the open of a peer by its zid and the one verdict it is answered with
//! ([`crate::lifecycle_wire`]). The transports (the in-band query of the heap profile, the
//! in-band query of the fixed-memory profile, the out-of-band line, the build-time declaration)
//! were each proved by a test of its own, and nothing held those tests to the same cases: a
//! transport could drift from the others and every test would still pass. A conformance suite is
//! the remedy protocol engineering has for exactly this (a table of cases, run through an adapter
//! per implementation), and the table is the one place the contract is written as cases.
//!
//! The table lives in this crate because the verdict's words do, and a profile's adapter can
//! then be written in the crate that has its transport without a second copy of the cases.
//!
//! The expected answers are LITERAL words, not computed by the code under test: a table that asked
//! the verdict function what the verdict should be would agree with it by construction.
//!
//! An adapter does one thing: serve a request the way its transport carries it, [`REPEATS`] times,
//! and hand back each answer it got (`None` for none) and what the node's opener was asked. Then
//! [`judge_answers`] reads what the transport can be seen to have said, and [`judge_asking`] reads
//! what the node was asked, which only an adapter that holds the opener can see.
//!
//! Compiled for tests and for the feature `lifecycle-contract`, which a production build never
//! names.

use crate::credential_identity::CREDENTIAL_ZID_BYTES;
use crate::lifecycle_wire::OpenOutcome;

/// How many times each request is made. Twice, because the contract's idempotency (decision D6)
/// is that asking again gets the same answer, which a transport that cannot tell whether its
/// request arrived relies on.
pub const REPEATS: usize = 2;

/// Whether the node binds an opener at all (decision D7's third value binds none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The node binds an opener that answers `outcome`, and permits per the case.
    Bound,
    /// The node binds none: its peers are the ones it was built with.
    Unbound,
}

/// What a request must be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Exactly this document, every time.
    Is(&'static str),
    /// This document, or no answer at all: a transport with no verb to answer with says nothing,
    /// and one with a verb that is not bound says the refusal.
    SilentOr(&'static str),
}

/// One case of the contract.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    /// The case's name, which a failure quotes.
    pub name: &'static str,
    /// Whether the node binds an opener.
    pub binding: Binding,
    /// Whether the opener permits a request (the node's write permit).
    pub permitted: bool,
    /// What the opener answers when it is asked.
    pub outcome: OpenOutcome,
    /// The peer, spelled as a key carries a zid.
    pub peer_text: &'static str,
    /// What the transport must answer.
    pub answer: Answer,
    /// The zid the opener must be asked for, each time, or `None` when it must not be asked.
    pub asked_for: Option<[u8; CREDENTIAL_ZID_BYTES]>,
}

impl Case {
    /// Whether a node that was built for no peer by their zid, which is what a real node of the
    /// host binary is, can be seen to answer this case: it permits, it is asked, and it has no
    /// room.
    pub const fn reachable_on_a_node_with_no_room(&self) -> bool {
        matches!(self.binding, Binding::Bound)
            && self.permitted
            && matches!(self.outcome, OpenOutcome::NoRoom)
    }
}

const fn zid(first: u8) -> [u8; CREDENTIAL_ZID_BYTES] {
    let mut z = [0u8; CREDENTIAL_ZID_BYTES];
    z[0] = first;
    z
}

const OPENING: &str = "{\"verdict\":\"opening\"}";
const NOT_PERMITTED: &str = "{\"verdict\":\"refused\",\"reason\":\"this node does not permit opening a session with that peer\"}";
const NOT_A_ZID: &str =
    "{\"verdict\":\"refused\",\"reason\":\"the last chunk of the key is not a zid\"}";
const PEER_UNKNOWN: &str =
    "{\"verdict\":\"refused\",\"reason\":\"this node knows no locator for that peer\"}";
const NO_DIALABLE: &str = "{\"verdict\":\"refused\",\"reason\":\"this node cannot dial any locator it knows for that peer\"}";
const OPENER_GONE: &str =
    "{\"verdict\":\"refused\",\"reason\":\"the loop that would hold that peer is gone\"}";
const NO_ROOM: &str = "{\"verdict\":\"refused\",\"reason\":\"this node holds as many peers by their zid as it was built for\"}";
const UNVERIFIABLE: &str = "{\"verdict\":\"refused\",\"reason\":\"this node cannot tell which node answers a dial, so it holds no peer by its zid\"}";

/// A bound, permitting node whose opener answers `outcome` for the peer `text`.
const fn bound(
    name: &'static str,
    outcome: OpenOutcome,
    text: &'static str,
    answer: &'static str,
    asked_for: Option<[u8; CREDENTIAL_ZID_BYTES]>,
) -> Case {
    Case {
        name,
        binding: Binding::Bound,
        permitted: true,
        outcome,
        peer_text: text,
        answer: Answer::Is(answer),
        asked_for,
    }
}

/// A peer text that names no zid, to a node that permits and would accept one. The outcome is
/// `NoRoom` so that a node that cannot be told what to answer, a real one with no room, answers
/// these the same way: the opener is never asked, so the outcome is not read.
const fn not_a_zid(name: &'static str, text: &'static str) -> Case {
    bound(name, OpenOutcome::NoRoom, text, NOT_A_ZID, None)
}

/// The table. Every transport answers every case the same way.
pub const CASES: &[Case] = &[
    bound(
        "a zid is opened",
        OpenOutcome::Accepted,
        "1f",
        OPENING,
        Some(zid(0x1f)),
    ),
    bound(
        "the longest spelling of a zid is opened, and is read little-endian",
        OpenOutcome::Accepted,
        "ffffffffffffffffffffffffffffffff",
        OPENING,
        Some([0xff; CREDENTIAL_ZID_BYTES]),
    ),
    bound(
        "a zid of more than one byte is read little-endian",
        OpenOutcome::Accepted,
        "abc",
        OPENING,
        Some({
            let mut z = [0u8; CREDENTIAL_ZID_BYTES];
            z[0] = 0xbc;
            z[1] = 0x0a;
            z
        }),
    ),
    bound(
        "a peer the node knows no locator for is refused by name",
        OpenOutcome::PeerUnknown,
        "1f",
        PEER_UNKNOWN,
        Some(zid(0x1f)),
    ),
    bound(
        "a peer with no dialable locator is refused by name",
        OpenOutcome::NoDialableLocator,
        "1f",
        NO_DIALABLE,
        Some(zid(0x1f)),
    ),
    bound(
        "a loop that is gone is refused by name",
        OpenOutcome::OpenerGone,
        "1f",
        OPENER_GONE,
        Some(zid(0x1f)),
    ),
    bound(
        "a node with no room is refused by name",
        OpenOutcome::NoRoom,
        "1f",
        NO_ROOM,
        Some(zid(0x1f)),
    ),
    bound(
        "a node that cannot tell which node answers is refused by name",
        OpenOutcome::Unverifiable,
        "1f",
        UNVERIFIABLE,
        Some(zid(0x1f)),
    ),
    Case {
        name: "a node that does not permit is never asked",
        binding: Binding::Bound,
        permitted: false,
        outcome: OpenOutcome::Accepted,
        peer_text: "1f",
        answer: Answer::Is(NOT_PERMITTED),
        asked_for: None,
    },
    Case {
        name: "the permit is judged before the spelling of the peer",
        binding: Binding::Bound,
        permitted: false,
        outcome: OpenOutcome::Accepted,
        peer_text: "0abc",
        answer: Answer::Is(NOT_PERMITTED),
        asked_for: None,
    },
    not_a_zid("a leading zero names no zid", "0abc"),
    not_a_zid("a text that is not hex names no zid", "xyz"),
    not_a_zid("upper case hex names no zid", "ABC"),
    not_a_zid(
        "more than thirty-two digits name no zid",
        "fffffffffffffffffffffffffffffffff",
    ),
    Case {
        name: "a node that binds no opener opens nothing by request",
        binding: Binding::Unbound,
        permitted: false,
        outcome: OpenOutcome::NoRoom,
        peer_text: "1f",
        answer: Answer::SilentOr(NOT_PERMITTED),
        asked_for: None,
    },
];

/// A case a transport failed, by the case's name and what was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Violation {
    /// The case's name.
    pub case: &'static str,
    /// What the transport did instead.
    pub what: &'static str,
}

/// Whether what a transport answered, to each of the [`REPEATS`] requests, is what the contract
/// says of `case`. `None` is no answer.
pub fn judge_answers(case: &Case, answers: &[Option<&str>]) -> Result<(), Violation> {
    let fail = |what| {
        Err(Violation {
            case: case.name,
            what,
        })
    };
    if answers.len() != REPEATS {
        return fail("the adapter did not make every request");
    }
    for answer in answers {
        match (case.answer, answer) {
            (Answer::Is(want), Some(got)) if *got == want => {}
            (Answer::Is(_), Some(_)) => return fail("answered another document"),
            (Answer::Is(_), None) => return fail("did not answer"),
            (Answer::SilentOr(_), None) => {}
            (Answer::SilentOr(want), Some(got)) if *got == want => {}
            (Answer::SilentOr(_), Some(_)) => return fail("answered another document"),
        }
    }
    Ok(())
}

/// Whether what the node's opener was asked is what the contract says of `case`: asked for the
/// peer on every request that reached it, and not at all when the request must not. `asked` is
/// how many times the opener was asked over the [`REPEATS`] requests, and `last` the zid, in its
/// sixteen-byte form, it was last asked for.
pub fn judge_asking(
    case: &Case,
    asked: u32,
    last: [u8; CREDENTIAL_ZID_BYTES],
) -> Result<(), Violation> {
    let fail = |what| {
        Err(Violation {
            case: case.name,
            what,
        })
    };
    match case.asked_for {
        None if asked != 0 => fail("asked the opener when it must not"),
        Some(_) if asked as usize != REPEATS => {
            fail("did not ask the opener once for each request")
        }
        Some(peer) if last != peer => fail("asked the opener for another peer"),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::lifecycle_wire::RefusedReason;

    /// A table that has lost a row has stopped holding the transports to it, so the table is held
    /// to what the wire can say: every refusal a request can get is a case, and a case's name is
    /// its identity.
    #[test]
    fn the_table_has_a_case_for_every_answer_an_open_can_get() {
        let words = |reason: RefusedReason| {
            std::format!(
                "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                reason.words()
            )
        };
        for reason in [
            RefusedReason::OpenNotPermitted,
            RefusedReason::PeerNotAZid,
            RefusedReason::PeerUnknown,
            RefusedReason::NoDialableLocator,
            RefusedReason::OpenerGone,
            RefusedReason::NoRoom,
            RefusedReason::Unverifiable,
        ] {
            let want = words(reason);
            assert!(
                CASES
                    .iter()
                    .any(|c| matches!(c.answer, Answer::Is(w) if w == want)),
                "no case answers {reason:?}"
            );
        }
        assert!(CASES
            .iter()
            .any(|c| matches!(c.answer, Answer::Is(w) if w == OPENING)));
        for (i, a) in CASES.iter().enumerate() {
            assert!(
                CASES[i + 1..].iter().all(|b| b.name != a.name),
                "{}",
                a.name
            );
        }
    }

    /// The judge must be able to fail: a transport that drifts is a red row and not a pass.
    #[test]
    fn the_judge_refuses_a_transport_that_drifts() {
        let case = &CASES[0];
        let want = match case.answer {
            Answer::Is(w) | Answer::SilentOr(w) => w,
        };
        assert!(judge_answers(case, &[Some(want), Some(want)]).is_ok());
        assert!(judge_answers(case, &[Some(want), Some(NO_ROOM)]).is_err());
        assert!(judge_answers(case, &[Some(want), None]).is_err());
        assert!(judge_answers(case, &[Some(want)]).is_err());

        let silent = CASES
            .iter()
            .find(|c| matches!(c.binding, Binding::Unbound))
            .expect("a case for the node that binds none");
        assert!(judge_answers(silent, &[None, None]).is_ok());
        assert!(judge_answers(silent, &[Some(NOT_PERMITTED), None]).is_ok());
        assert!(judge_answers(silent, &[Some(OPENING), None]).is_err());

        assert!(judge_asking(case, 0, zid(0)).is_err(), "never asked");
        assert!(judge_asking(case, 2, zid(0x1f)).is_ok());
        assert!(judge_asking(case, 2, zid(0x2f)).is_err(), "another peer");
        assert!(judge_asking(case, 3, zid(0x1f)).is_err(), "asked too often");
    }
}
