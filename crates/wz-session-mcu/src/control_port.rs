// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The out-of-band transport of decision D7, `docs/session-lifecycle-intent.md`: a node is told
//! which peer to hold, close, reset or report on a channel of its own, not in a query the session
//! carries.
//!
//! The channel belongs to whoever hosts the node (a test agent's pipe, a supervisor's socket); the
//! port is what stands between a line it carries and the node. One line is one command, and one
//! command is answered with one JSON object:
//!
//! ```text
//! open <peer>                ->  {"verdict":"opening"}
//! close <peer>               ->  {"verdict":"closing","links":N}
//! reset <peer> <generation>  ->  {"verdict":"resetting","links":N}
//! status <peer>              ->  {"verdict":"status","links":{..},"intent":..,"machines":[..]}
//! whoami                     ->  {"zid":"<the node's zid>"}
//! anything else              ->  {"error":"unknown-command"} or the command's own error word
//! ```
//!
//! `<peer>` is spelled as the in-band key spells it, and every verdict is the one the same verb
//! answers in band, because both are `lifecycle_node::lifecycle_verdict`: the permit, the order of
//! checks, the spelling of the zid, the outcomes and their words are one thing and this module adds
//! none. What it adds is only the reading of a line, an error word for a line that is not a command
//! (which is not a verdict on any peer), and `whoami`, which has no in-band form because the
//! in-band key already names the node. Repeating a command is safe: `open` is idempotent, a
//! repeated `close` is `already_closed`, and a repeated `reset` carries its generation, so an agent
//! that lost a reply may send it again.

use wz_session_core::lifecycle_node::{lifecycle_verdict, Command as Asked, LifecycleNode};
use wz_session_core::text_out::TextOut;

/// The word that asks the node to hold a peer.
pub const OPEN_COMMAND: &str = "open";
/// The word that asks the node to close the sessions with a peer and drop it from the intent.
pub const CLOSE_COMMAND: &str = "close";
/// The word that asks the node to close the sessions with a peer once for a generation.
pub const RESET_COMMAND: &str = "reset";
/// The word that asks the node what it holds for a peer.
pub const STATUS_COMMAND: &str = "status";
/// The word that asks the node its own zid.
pub const WHOAMI_COMMAND: &str = "whoami";

/// The error words, a closed set like the refusals' (a line that is no command names no peer, so
/// it has no verdict).
const UNKNOWN_COMMAND: &str = "unknown-command";
const OPEN_TAKES_ONE_PEER: &str = "open-takes-one-peer";
const CLOSE_TAKES_ONE_PEER: &str = "close-takes-one-peer";
const RESET_TAKES_A_PEER_AND_A_GENERATION: &str = "reset-takes-a-peer-and-a-generation";
const STATUS_TAKES_ONE_PEER: &str = "status-takes-one-peer";
const WHOAMI_TAKES_NOTHING: &str = "whoami-takes-nothing";
const LINE_TOO_LONG: &str = "line-too-long";

/// What a line asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Hold this peer, spelled as a key spells it.
    Open(&'a str),
    /// Close the sessions with this peer and take it out of the intent.
    Close(&'a str),
    /// Close the sessions with this peer once for this generation, leaving the intent.
    Reset(&'a str, &'a str),
    /// Say what the node holds for this peer.
    Status(&'a str),
    /// Say the node's own zid.
    Whoami,
}

/// Why a line is no command, as the word the port answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
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

impl Malformed {
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
        match self {
            Self::UnknownCommand => UNKNOWN_COMMAND,
            Self::OpenTakesOnePeer => OPEN_TAKES_ONE_PEER,
            Self::CloseTakesOnePeer => CLOSE_TAKES_ONE_PEER,
            Self::ResetTakesAPeerAndAGeneration => RESET_TAKES_A_PEER_AND_A_GENERATION,
            Self::StatusTakesOnePeer => STATUS_TAKES_ONE_PEER,
            Self::WhoamiTakesNothing => WHOAMI_TAKES_NOTHING,
            Self::LineTooLong => LINE_TOO_LONG,
        }
    }

    /// The answer document: one JSON object with the one word.
    pub fn write_json<W: TextOut + ?Sized>(self, out: &mut W) {
        out.push_str("{\"error\":\"");
        out.push_str(self.words());
        out.push_str("\"}");
    }
}

/// Read one line (its line end already cut, or not: surrounding white space is ignored).
pub fn parse(line: &str) -> Result<Command<'_>, Malformed> {
    let mut words = line.split_ascii_whitespace();
    let first = words.next();
    let (one, two, three) = (words.next(), words.next(), words.next());
    match (first, one, two, three) {
        (Some(OPEN_COMMAND), Some(peer), None, _) => Ok(Command::Open(peer)),
        (Some(OPEN_COMMAND), ..) => Err(Malformed::OpenTakesOnePeer),
        (Some(CLOSE_COMMAND), Some(peer), None, _) => Ok(Command::Close(peer)),
        (Some(CLOSE_COMMAND), ..) => Err(Malformed::CloseTakesOnePeer),
        (Some(RESET_COMMAND), Some(peer), Some(generation), None) => {
            Ok(Command::Reset(peer, generation))
        }
        (Some(RESET_COMMAND), ..) => Err(Malformed::ResetTakesAPeerAndAGeneration),
        (Some(STATUS_COMMAND), Some(peer), None, _) => Ok(Command::Status(peer)),
        (Some(STATUS_COMMAND), ..) => Err(Malformed::StatusTakesOnePeer),
        (Some(WHOAMI_COMMAND), None, _, _) => Ok(Command::Whoami),
        (Some(WHOAMI_COMMAND), ..) => Err(Malformed::WhoamiTakesNothing),
        _ => Err(Malformed::UnknownCommand),
    }
}

/// Answer `line` to `out` as one JSON object (no line end: the channel adds its own), asking `node`
/// for what the line asks. `own_zid` is the node's zid as `z_id_to_string` prints it; a host that
/// does not know it answers `whoami` as an unknown command.
pub fn answer<N, W>(node: &N, own_zid: Option<&str>, line: &str, out: &mut W)
where
    N: LifecycleNode + ?Sized,
    W: TextOut + ?Sized,
{
    let command = match parse(line) {
        Ok(Command::Open(peer)) => Asked::Open { peer },
        Ok(Command::Close(peer)) => Asked::Close { peer },
        Ok(Command::Reset(peer, generation)) => Asked::Reset { peer, generation },
        Ok(Command::Status(peer)) => Asked::Status { peer },
        Ok(Command::Whoami) => {
            match own_zid {
                // Lower-case hex: nothing in it needs escaping.
                Some(zid) => {
                    out.push_str("{\"zid\":\"");
                    out.push_str(zid);
                    out.push_str("\"}");
                }
                None => Malformed::UnknownCommand.write_json(out),
            }
            return;
        }
        Err(malformed) => return malformed.write_json(out),
    };
    lifecycle_verdict(node, command, out);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::node_opening::{NodeOpening, OpeningOnly};
    use core::cell::Cell;
    use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
    use wz_session_core::lifecycle_wire::{OpenOutcome, OpenVerdict};
    use wz_session_core::text_out::FixedText;

    struct Node {
        permit: bool,
        outcome: OpenOutcome,
        opened: Cell<u32>,
    }

    impl NodeOpening for Node {
        fn permitted(&self) -> bool {
            self.permit
        }
        fn open(&self, _zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome {
            self.opened.set(self.opened.get() + 1);
            self.outcome
        }
    }

    fn said(node: &Node, line: &str) -> FixedText<192> {
        let mut out = FixedText::new();
        answer(&OpeningOnly(node), None, line, &mut out);
        assert!(!out.overflowed());
        out
    }

    fn node(permit: bool, outcome: OpenOutcome) -> Node {
        Node {
            permit,
            outcome,
            opened: Cell::new(0),
        }
    }

    #[test]
    fn a_line_is_read_as_a_command_and_nothing_else_is() {
        assert_eq!(parse("open abc"), Ok(Command::Open("abc")));
        assert_eq!(parse("  open\tabc \r\n"), Ok(Command::Open("abc")));
        assert_eq!(parse("close abc"), Ok(Command::Close("abc")));
        assert_eq!(parse("reset abc 7"), Ok(Command::Reset("abc", "7")));
        assert_eq!(parse("status abc"), Ok(Command::Status("abc")));
        assert_eq!(parse(" whoami "), Ok(Command::Whoami));
        assert_eq!(parse("open"), Err(Malformed::OpenTakesOnePeer));
        assert_eq!(parse("open a b"), Err(Malformed::OpenTakesOnePeer));
        assert_eq!(parse("close"), Err(Malformed::CloseTakesOnePeer));
        assert_eq!(parse("close a b"), Err(Malformed::CloseTakesOnePeer));
        assert_eq!(
            parse("reset a"),
            Err(Malformed::ResetTakesAPeerAndAGeneration)
        );
        assert_eq!(
            parse("reset a 1 2"),
            Err(Malformed::ResetTakesAPeerAndAGeneration)
        );
        assert_eq!(parse("status"), Err(Malformed::StatusTakesOnePeer));
        assert_eq!(parse("status a b"), Err(Malformed::StatusTakesOnePeer));
        assert_eq!(parse("whoami now"), Err(Malformed::WhoamiTakesNothing));
        for line in [
            "",
            "   ",
            "hold abc",
            "OPEN abc",
            "opened abc",
            "closed abc",
        ] {
            assert_eq!(parse(line), Err(Malformed::UnknownCommand), "{line:?}");
        }
    }

    #[test]
    fn the_port_answers_what_the_in_band_verb_answers_for_the_same_request() {
        // The two transports share the function, so the reply document of every outcome is the
        // one `OpenVerdict` writes, byte for byte.
        for outcome in [
            OpenOutcome::Accepted,
            OpenOutcome::PeerUnknown,
            OpenOutcome::NoDialableLocator,
            OpenOutcome::OpenerGone,
            OpenOutcome::NoRoom,
            OpenOutcome::Unverifiable,
        ] {
            let node = node(true, outcome);
            let mut want = FixedText::<192>::new();
            OpenVerdict::of(outcome).write_json(&mut want);
            assert_eq!(
                said(&node, "open abc").prefix(),
                want.prefix(),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn a_repeated_open_is_answered_again_and_a_line_that_is_no_command_opens_nothing() {
        let node = node(true, OpenOutcome::Accepted);
        let first = said(&node, "open abc");
        let again = said(&node, "open abc");
        assert_eq!(first.prefix(), "{\"verdict\":\"opening\"}");
        assert_eq!(first.prefix(), again.prefix());
        assert_eq!(node.opened.get(), 2);

        assert_eq!(
            said(&node, "hold abc").prefix(),
            "{\"error\":\"unknown-command\"}"
        );
        assert_eq!(
            said(&node, "open").prefix(),
            "{\"error\":\"open-takes-one-peer\"}"
        );
        assert_eq!(node.opened.get(), 2);
    }

    #[test]
    fn every_error_word_is_its_own_clean_sentence() {
        for (at, malformed) in Malformed::ALL.into_iter().enumerate() {
            let mut out = FixedText::<192>::new();
            malformed.write_json(&mut out);
            let doc = out.prefix();
            assert!(doc.starts_with("{\"error\":\""), "{doc}");
            assert!(!malformed.words().contains(['"', '\\', ' ']));
            for other in &Malformed::ALL[at + 1..] {
                assert_ne!(malformed.words(), other.words());
            }
        }
        let mut out = FixedText::<192>::new();
        Malformed::LineTooLong.write_json(&mut out);
        assert_eq!(out.prefix(), "{\"error\":\"line-too-long\"}");
    }

    #[test]
    fn the_permit_and_the_spelling_of_the_peer_are_the_nodes_not_the_ports() {
        let closed = node(false, OpenOutcome::Accepted);
        assert_eq!(
            said(&closed, "open abc").prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"this node does not permit opening a session with that peer\"}"
        );
        assert_eq!(closed.opened.get(), 0);

        let open = node(true, OpenOutcome::Accepted);
        let reply = said(&open, "open 0abc");
        assert!(
            reply.prefix().starts_with("{\"verdict\":\"refused\""),
            "{}",
            reply.prefix()
        );
        assert_eq!(open.opened.get(), 0);
    }

    #[test]
    fn a_node_that_binds_only_open_refuses_the_other_verbs_by_name() {
        let open = node(true, OpenOutcome::Accepted);
        assert_eq!(
            said(&open, "close abc").prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"this node does not permit closing the session with that peer\"}"
        );
        assert_eq!(
            said(&open, "reset abc 1").prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"this node does not permit resetting the session with that peer\"}"
        );
        assert_eq!(
            said(&open, "status abc").prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"this node does not permit reading the status of the session with that peer\"}"
        );
        assert_eq!(open.opened.get(), 0);
    }

    #[test]
    fn whoami_is_the_zid_the_host_gave_and_nothing_when_it_gave_none() {
        let node = node(true, OpenOutcome::Accepted);
        let mut out = FixedText::<192>::new();
        answer(&OpeningOnly(&node), Some("a1b2"), "whoami", &mut out);
        assert_eq!(out.prefix(), "{\"zid\":\"a1b2\"}");
        assert_eq!(
            said(&node, "whoami").prefix(),
            "{\"error\":\"unknown-command\"}"
        );
    }
}
