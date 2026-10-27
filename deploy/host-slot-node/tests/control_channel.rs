// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The out-of-band transport of decision D7, through a real process: `host-slot-node` started as
//! a test agent starts it, a line written to its standard input, an answer read from its standard
//! output.
//!
//! What this holds is the channel and the semantics it shares: the node reads a line while its
//! loop runs, answers one JSON document per line in the words the in-band verb answers in, repeats
//! the same answer for the same request, and says so when a line is no command. The node is built
//! for no peers by their zid (`MAX_PEER_NODES` is 0 by default), so a well-formed request is
//! refused for room: a hold that succeeds needs a build with room and a secure channel (decision
//! D4) and is not run here.
#![cfg(feature = "control")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

use wz_session_core::lifecycle_wire::RefusedReason;

const WAIT: Duration = Duration::from_secs(20);

struct Agent {
    child: Child,
    stdin: ChildStdin,
    answers: Receiver<String>,
    /// The zid the node said it has, in the spelling the READY line prints.
    zid: String,
}

impl Agent {
    /// Start the node against a router that is not there, and wait until its loop has said it is
    /// ready: a line sent before that waits in the pipe and is read by the first round, so the
    /// wait is for the test's clarity and not for correctness.
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_host-slot-node"))
            .arg("127.0.0.1:1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the node starts");
        let stdin = child.stdin.take().expect("stdin");
        let out = child.stdout.take().expect("stdout");
        let err = child.stderr.take().expect("stderr");

        let (ready_tx, ready) = channel();
        thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if let Some(rest) = line.split("HOST-WZ-CLIENT READY ").nth(1) {
                    let zid = rest.split_whitespace().next().unwrap_or_default();
                    let _ = ready_tx.send(zid.to_string());
                }
            }
        });
        let zid = ready.recv_timeout(WAIT).expect("the node says it is ready");

        let (tx, answers) = channel();
        thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            answers,
            zid,
        }
    }

    /// Send one line and take the one answer it gets.
    fn ask(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").expect("the channel is open");
        self.stdin.flush().expect("flush");
        self.answers
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| panic!("no answer to {line:?}"))
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn refused(reason: RefusedReason) -> String {
    format!(
        "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
        reason.words()
    )
}

#[test]
fn a_node_answers_each_line_it_is_sent_in_the_words_of_the_in_band_verb() {
    let mut agent = Agent::start();

    // A zid the node has no room to hold by request. The same request gets the same answer
    // again, which is what a transport that cannot tell whether its request arrived relies on.
    let want = refused(RefusedReason::NoRoom);
    assert_eq!(agent.ask("open abc"), want);
    assert_eq!(agent.ask("open abc"), want);

    // The spelling of the peer is read as a key spells it: a leading zero names no zid.
    assert_eq!(agent.ask("open 0abc"), refused(RefusedReason::PeerNotAZid));
}

/// The channel held to the table every transport of the contract is held to
/// (`wz_session_mcu::contract`, decision D7). The node of this binary permits, binds its own
/// opener and has no room for a peer by its zid, so the cases it can be seen to answer are the
/// ones whose opener says `NoRoom`, and a peer that names no zid, which no opener is asked
/// about. The cases that need another opener are run through the transports that can hold one.
#[test]
fn the_channel_conforms_to_the_contract_on_the_cases_a_node_with_no_room_can_show() {
    use wz_session_mcu::contract::{judge_answers, CASES, REPEATS};

    let mut agent = Agent::start();
    let mut run = 0;
    for case in CASES
        .iter()
        .filter(|c| c.reachable_on_a_node_with_no_room())
    {
        let line = format!("open {}", case.peer_text);
        let answers: Vec<String> = (0..REPEATS).map(|_| agent.ask(&line)).collect();
        let seen: Vec<Option<&str>> = answers.iter().map(|a| Some(a.as_str())).collect();
        judge_answers(case, &seen).unwrap_or_else(|v| panic!("{v:?}: {seen:?}"));
        run += 1;
    }
    assert!(
        run >= 5,
        "the table has lost the cases this node can show: {run}"
    );
}

/// The other verbs, through the process. The node holds no peer and has no room for one, so what
/// it can be seen to say is what a node with nothing says: a peer it never held is not found, a
/// status of it reads none, and a reset is refused for want of a place to remember its generation
/// (decision of 2026-10-26: the sender learns why, and the record is never grown or evicted).
/// `whoami` is the zid the node printed when it said it was ready.
#[test]
fn a_node_that_holds_nothing_says_so_for_close_status_and_reset_and_names_itself() {
    let mut agent = Agent::start();

    let own = format!("{{\"zid\":\"{}\"}}", agent.zid);
    assert!(
        !agent.zid.is_empty() && agent.zid.len() <= 32,
        "{}",
        agent.zid
    );
    assert_eq!(agent.ask("whoami"), own);
    assert_eq!(agent.ask("whoami"), own, "it names itself again");

    for _ in 0..2 {
        assert_eq!(agent.ask("close 1f"), "{\"verdict\":\"not_found\"}");
        assert_eq!(
            agent.ask("status 1f"),
            "{\"verdict\":\"status\",\"links\":{\"open\":0,\"closing\":0},\"intent\":false,\"machines\":[]}"
        );
        assert_eq!(agent.ask("reset 1f 1"), refused(RefusedReason::NoRoom));
    }

    // The permit is read first, then the peer, then the generation.
    assert_eq!(
        agent.ask("reset 0abc 1"),
        refused(RefusedReason::PeerNotAZid)
    );
    assert_eq!(
        agent.ask("reset 1f x"),
        refused(RefusedReason::GenerationNotANumber)
    );
    assert_eq!(agent.ask("close 0abc"), refused(RefusedReason::PeerNotAZid));
    assert_eq!(
        agent.ask("status 0abc"),
        refused(RefusedReason::PeerNotAZid)
    );
}

#[test]
fn a_line_that_is_no_command_is_answered_with_an_error_word_and_opens_nothing() {
    let mut agent = Agent::start();
    assert_eq!(agent.ask("hold abc"), "{\"error\":\"unknown-command\"}");
    assert_eq!(agent.ask("open"), "{\"error\":\"open-takes-one-peer\"}");
    assert_eq!(agent.ask("open a b"), "{\"error\":\"open-takes-one-peer\"}");
    assert_eq!(agent.ask("close"), "{\"error\":\"close-takes-one-peer\"}");
    assert_eq!(
        agent.ask("reset 1f"),
        "{\"error\":\"reset-takes-a-peer-and-a-generation\"}"
    );
    assert_eq!(agent.ask("status"), "{\"error\":\"status-takes-one-peer\"}");
    assert_eq!(
        agent.ask("whoami now"),
        "{\"error\":\"whoami-takes-nothing\"}"
    );
    let overlong = format!("open {}", "a".repeat(400));
    assert_eq!(agent.ask(&overlong), "{\"error\":\"line-too-long\"}");

    // The channel is still read after a bad line.
    assert_eq!(agent.ask("open abc"), refused(RefusedReason::NoRoom));
}
