// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The out-of-band transport of decision D7, `docs/session-lifecycle-intent.md`: a node is told
//! which peer to hold on a channel of its own, not in a query the session carries.
//!
//! The channel belongs to whoever hosts the node (a test agent's pipe, a supervisor's socket); the
//! port is what stands between a line it carries and the node. One line is one command, and one
//! command is answered with one JSON object:
//!
//! ```text
//! open <peer>      ->  {"verdict":"opening"}
//!                      {"verdict":"refused","reason":"..."}
//! anything else    ->  {"error":"unknown-command"}   or   {"error":"open-takes-one-peer"}
//! ```
//!
//! `<peer>` is spelled as the in-band key spells it, and the verdict is the one `session/open`
//! answers, because both are [`open_verdict`]: the permit, the spelling of the zid, the outcomes
//! and their words are one thing and this module adds none. What it adds is only the reading of a
//! line, and an error word for a line that is not a command, which is not a verdict on any peer.
//! Repeating `open` is safe, since the opener is idempotent ([`NodeOpening::open`]); an agent
//! that lost a reply may send it again.

use wz_session_core::text_out::TextOut;

use crate::node_opening::{open_verdict, NodeOpening};

/// The word that asks the node to hold a peer.
pub const OPEN_COMMAND: &str = "open";

/// The error words, a closed set like the refusals' (a line that is no command names no peer, so
/// it has no verdict).
const UNKNOWN_COMMAND: &str = "unknown-command";
const OPEN_TAKES_ONE_PEER: &str = "open-takes-one-peer";
const LINE_TOO_LONG: &str = "line-too-long";

/// What a line asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Hold this peer, spelled as a key spells it.
    Open(&'a str),
}

/// Why a line is no command, as the word the port answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The first word is not a command the port knows, or there is none.
    UnknownCommand,
    /// `open` with no peer, or with more than one.
    OpenTakesOnePeer,
    /// The line was longer than the channel's buffer: the channel reads no part of it, since the
    /// part it kept would be a different command from the one sent.
    LineTooLong,
}

impl Malformed {
    /// The word on the wire.
    pub const fn words(self) -> &'static str {
        match self {
            Self::UnknownCommand => UNKNOWN_COMMAND,
            Self::OpenTakesOnePeer => OPEN_TAKES_ONE_PEER,
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
    match words.next() {
        Some(OPEN_COMMAND) => match (words.next(), words.next()) {
            (Some(peer), None) => Ok(Command::Open(peer)),
            _ => Err(Malformed::OpenTakesOnePeer),
        },
        _ => Err(Malformed::UnknownCommand),
    }
}

/// Answer `line` to `out` as one JSON object (no line end: the channel adds its own), asking
/// `opener` for what the line asks.
pub fn answer<O, W>(opener: &O, line: &str, out: &mut W)
where
    O: NodeOpening + ?Sized,
    W: TextOut + ?Sized,
{
    match parse(line) {
        Ok(Command::Open(peer)) => open_verdict(opener, peer).write_json(out),
        Err(malformed) => malformed.write_json(out),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
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
        answer(node, line, &mut out);
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
        assert_eq!(parse("open"), Err(Malformed::OpenTakesOnePeer));
        assert_eq!(parse("open a b"), Err(Malformed::OpenTakesOnePeer));
        for line in ["", "   ", "close abc", "OPEN abc", "opened abc"] {
            assert_eq!(parse(line), Err(Malformed::UnknownCommand), "{line:?}");
        }
    }

    #[test]
    fn the_port_answers_what_the_in_band_verb_answers_for_the_same_request() {
        // The two transports share `open_verdict`, so the reply document of every outcome is the
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
    fn a_line_the_channel_could_not_hold_is_answered_by_its_word() {
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
}
