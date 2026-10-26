// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The contract of decision D7, `docs/session-lifecycle-intent.md`, for every verb: a node is
//! asked to open, close or reset a session with a peer, or to report what it holds for one, and
//! answers in the words of [`crate::lifecycle_wire`].
//!
//! The transports differ only in what feeds the function here: a query the node serves
//! (in-band), a line an agent writes to the node's control channel (out-of-band), or, for the
//! open verb, nothing at run time because the build declared the peers.
//! [`lifecycle_verdict`](crate::lifecycle_node::lifecycle_verdict) is
//! the one place that turns a [`Command`](crate::lifecycle_node::Command) into a verdict and a
//! document, so no transport owns a
//! copy of the semantics: the order of checks, the spelling of the peer and the words are the
//! same on every one.
//!
//! The order of checks is the same for every verb, and it is written once: the node's permit for
//! the verb, then the spelling of the peer, then (for a reset) the spelling of the generation,
//! then the effect. A refusal therefore never touches the node, and a node that does not permit a
//! verb says so whatever else is wrong with the request.
//!
//! The function writes through any text sink and holds nothing, so a node with no allocator calls
//! it as the heap profile does. What a node holds is behind one port,
//! [`LifecycleNode`](crate::lifecycle_node::LifecycleNode), and
//! what it costs a node to hold it is that node's own.

use crate::credential_identity::{zid_from_key_text, CREDENTIAL_ZID_BYTES};
use crate::lifecycle_wire::{
    CloseOrder, CloseVerdict, MachineReport, OpenOutcome, OpenVerdict, RefusedReason, ResetVerdict,
    SessionLinks, StatusVerdict,
};
use crate::text_out::TextOut;

/// A zid in the sixteen-byte form: the little-endian bytes of the id, as a key spells it.
pub type Zid = [u8; CREDENTIAL_ZID_BYTES];

/// One of the verbs a node may serve, for the node to say which it permits.
///
/// Four permissions rather than one, because "may be asked to hold a peer", "may close every
/// session", "may cycle a session" and "may learn which peers the node holds" are permissions a
/// policy can mean to grant apart (least privilege, and a node refuses by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Hold a peer by its zid.
    Open,
    /// End the sessions with a peer and take it out of the intent.
    Close,
    /// End the sessions with a peer once per generation and leave the intent.
    Reset,
    /// Read what the node holds for a peer.
    Status,
}

/// One request, as a transport reads it: the peer and the generation are the text the transport
/// carried, and [`lifecycle_verdict`] reads them, so that no transport spells a zid its own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Hold the peer.
    Open {
        /// The peer, spelled as a key carries a zid.
        peer: &'a str,
    },
    /// Close every session with the peer and withdraw it from the intent.
    Close {
        /// The peer, spelled as a key carries a zid.
        peer: &'a str,
    },
    /// Close every session with the peer once for `generation`.
    Reset {
        /// The peer, spelled as a key carries a zid.
        peer: &'a str,
        /// The generation, as the text the request carried.
        generation: &'a str,
    },
    /// Read what the node holds for the peer.
    Status {
        /// The peer, spelled as a key carries a zid.
        peer: &'a str,
    },
}

/// What the node did with a generation a reset carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// No generation of this peer as late as this one was taken before; this one is now the
    /// latest, and the reset runs.
    Taken,
    /// A reset of this generation or a later one was already taken, so this is a retransmission.
    Duplicate {
        /// The latest generation taken for the peer.
        last: u64,
    },
    /// The node has no room to remember this peer's generations, so it cannot promise a
    /// retransmission closes nothing and takes no request that carries one. Never a heap node.
    NoRoom,
}

/// What a node holds and does, as the verbs ask it: the port of [`lifecycle_verdict`].
///
/// A port for the reason the heap profile's ports are: the sessions, the machines and the record
/// of generations live with the host, which this crate cannot name. Each method is one effect or
/// one read, and none checks a permit or spells a zid: that is the function's, written once.
pub trait LifecycleNode {
    /// Whether the node permits `verb`. Asked first, so a node that does not permit it is never
    /// asked anything else.
    fn permits(&self, verb: Verb) -> bool;

    /// Ask the node to hold the peer. Accepted, not completed: how the dial ends is read in the
    /// status. Asking again for a peer already held changes nothing and is accepted again.
    fn open(&self, peer: &Zid) -> OpenOutcome;

    /// Take the peer out of the node's intent: no machine dials it again until an open or a
    /// configuration edit names it again.
    fn withdraw(&self, peer: &Zid);

    /// Order every session with the peer closed, and say how many links this ordered and how
    /// many had been ordered already.
    fn order_close(&self, peer: &Zid) -> CloseOrder;

    /// Take `generation` as the latest of the peer, unless one as late was taken (decision D6;
    /// the duplicate suppression of at-most-once calls, Birrell and Nelson, 1984).
    fn take_generation(&self, peer: &Zid, generation: u64) -> Generation;

    /// The links of the sessions with the peer, read without changing them.
    fn links(&self, peer: &Zid) -> SessionLinks;

    /// Call `read` once with every machine that holds the peer. The rows are lent for the call,
    /// so a node that keeps them in a table of fixed size lends a slice of its own stack.
    fn read_machines(&self, peer: &Zid, read: &mut dyn FnMut(&[MachineReport<'_>]));
}

/// What [`lifecycle_verdict`] decided, for a caller that counts or reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The verdict on an open.
    Open(OpenVerdict),
    /// The verdict on a close.
    Close(CloseVerdict),
    /// The verdict on a reset.
    Reset(ResetVerdict),
    /// The verdict on a status read.
    Status(StatusVerdict),
}

/// Decide `command` on `node` and write the reply document into `out`.
///
/// The one place the lifecycle contract is written: the permit, the spelling, then the effect, in
/// that order for every verb. The words are `lifecycle_wire`'s.
pub fn lifecycle_verdict<N, W>(node: &N, command: Command<'_>, out: &mut W) -> Verdict
where
    N: LifecycleNode + ?Sized,
    W: TextOut + ?Sized,
{
    match command {
        Command::Open { peer } => {
            let verdict = open(node, peer);
            verdict.write_json(out);
            Verdict::Open(verdict)
        }
        Command::Close { peer } => {
            let verdict = close(node, peer);
            verdict.write_json(out);
            Verdict::Close(verdict)
        }
        Command::Reset { peer, generation } => {
            let verdict = reset(node, peer, generation);
            verdict.write_json(out);
            Verdict::Reset(verdict)
        }
        Command::Status { peer } => Verdict::Status(status(node, peer, out)),
    }
}

/// Open: the peer joins the intent and the node's machine connects. A peer already held is
/// unchanged, so a retransmission is safe.
fn open<N: LifecycleNode + ?Sized>(node: &N, peer: &str) -> OpenVerdict {
    if !node.permits(Verb::Open) {
        return OpenVerdict::Refused(RefusedReason::OpenNotPermitted);
    }
    match zid_from_key_text(peer) {
        Some(peer) => OpenVerdict::of(node.open(&peer)),
        None => OpenVerdict::Refused(RefusedReason::PeerNotAZid),
    }
}

/// Close: the peer leaves the intent, and every session with it is ordered closed. Withdrawn
/// first, so a session that ends before the withdrawal reaches the node's machines is not dialled
/// again for long: the machine that took the loss is stopped where it waits.
fn close<N: LifecycleNode + ?Sized>(node: &N, peer: &str) -> CloseVerdict {
    if !node.permits(Verb::Close) {
        return CloseVerdict::Refused(RefusedReason::NotPermitted);
    }
    let Some(peer) = zid_from_key_text(peer) else {
        return CloseVerdict::Refused(RefusedReason::PeerNotAZid);
    };
    node.withdraw(&peer);
    CloseVerdict::of(node.order_close(&peer))
}

/// Reset: every session with the peer is ordered closed once for the generation, and the intent
/// is left as it is, so a peer the node should hold is connected again. A generation no later
/// than the latest taken for the peer is a retransmission and closes nothing. The generation is
/// taken before the close is ordered: a close the node could not carry out (no session) is still
/// this generation's, so a retransmission after the peer is back does not close it.
fn reset<N: LifecycleNode + ?Sized>(node: &N, peer: &str, generation: &str) -> ResetVerdict {
    if !node.permits(Verb::Reset) {
        return ResetVerdict::Refused(RefusedReason::ResetNotPermitted);
    }
    let Some(peer) = zid_from_key_text(peer) else {
        return ResetVerdict::Refused(RefusedReason::PeerNotAZid);
    };
    let Ok(generation) = generation.parse::<u64>() else {
        return ResetVerdict::Refused(RefusedReason::GenerationNotANumber);
    };
    match node.take_generation(&peer, generation) {
        Generation::Duplicate { last } => ResetVerdict::Duplicate { last },
        Generation::NoRoom => ResetVerdict::Refused(RefusedReason::NoRoom),
        Generation::Taken => ResetVerdict::of(node.order_close(&peer)),
    }
}

/// Status: the links of the sessions with the peer and each machine that holds it, written into
/// `out`. Reads only: nothing here changes a session, a machine or the intent.
fn status<N, W>(node: &N, peer: &str, out: &mut W) -> StatusVerdict
where
    N: LifecycleNode + ?Sized,
    W: TextOut + ?Sized,
{
    let refused = |reason: RefusedReason, out: &mut W| {
        let verdict = StatusVerdict::Refused(reason);
        verdict.write_json(out, &[]);
        verdict
    };
    if !node.permits(Verb::Status) {
        return refused(RefusedReason::StatusNotPermitted, out);
    }
    let Some(peer) = zid_from_key_text(peer) else {
        return refused(RefusedReason::PeerNotAZid, out);
    };
    let links = node.links(&peer);
    // The document opens with the intent and the count, and both are read from the rows it
    // lists, in the one call that lends them.
    let mut read = None;
    node.read_machines(&peer, &mut |machines| {
        let verdict = StatusVerdict::of(links, machines);
        verdict.write_json(out, machines);
        read = Some(verdict);
    });
    // A node that lent no rows holds no machine for the peer.
    read.unwrap_or_else(|| {
        let verdict = StatusVerdict::of(links, &[]);
        verdict.write_json(out, &[]);
        verdict
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::text_out::FixedText;
    use core::cell::{Cell, RefCell};
    use std::vec::Vec;

    /// A node that records what it was asked, in order.
    struct Recording {
        permit: [bool; 4],
        taken: Cell<Generation>,
        asked: RefCell<Vec<&'static str>>,
    }

    impl Recording {
        fn new(permit: bool) -> Self {
            Self {
                permit: [permit; 4],
                taken: Cell::new(Generation::Taken),
                asked: RefCell::new(Vec::new()),
            }
        }
        fn note(&self, what: &'static str) {
            self.asked.borrow_mut().push(what);
        }
    }

    impl LifecycleNode for Recording {
        fn permits(&self, verb: Verb) -> bool {
            self.permit[verb as usize]
        }
        fn open(&self, _peer: &Zid) -> OpenOutcome {
            self.note("open");
            OpenOutcome::Accepted
        }
        fn withdraw(&self, _peer: &Zid) {
            self.note("withdraw");
        }
        fn order_close(&self, _peer: &Zid) -> CloseOrder {
            self.note("order_close");
            CloseOrder {
                newly_ordered: 1,
                already_ordered: 0,
            }
        }
        fn take_generation(&self, _peer: &Zid, _generation: u64) -> Generation {
            self.note("take_generation");
            self.taken.get()
        }
        fn links(&self, _peer: &Zid) -> SessionLinks {
            self.note("links");
            SessionLinks::default()
        }
        fn read_machines(&self, _peer: &Zid, read: &mut dyn FnMut(&[MachineReport<'_>])) {
            self.note("read_machines");
            read(&[]);
        }
    }

    fn run(node: &Recording, command: Command<'_>) -> (Verdict, std::string::String) {
        let mut text: FixedText<256> = FixedText::new();
        let verdict = lifecycle_verdict(node, command, &mut text);
        (
            verdict,
            std::string::String::from(text.finish().expect("fits")),
        )
    }

    const EVERY: [fn(&str) -> Command<'_>; 4] = [
        |peer| Command::Open { peer },
        |peer| Command::Close { peer },
        |peer| Command::Reset {
            peer,
            generation: "1",
        },
        |peer| Command::Status { peer },
    ];

    #[test]
    fn a_node_that_does_not_permit_a_verb_is_asked_nothing_whatever_else_is_wrong() {
        for command in EVERY {
            let node = Recording::new(false);
            // A peer that spells no zid: the permit is read before the spelling.
            let (_, doc) = run(&node, command("01"));
            assert!(doc.contains("does not permit"), "{doc}");
            assert!(node.asked.borrow().is_empty());
        }
    }

    #[test]
    fn a_peer_that_spells_no_zid_is_refused_before_the_node_is_asked() {
        for command in EVERY {
            let node = Recording::new(true);
            let (_, doc) = run(&node, command("01"));
            assert_eq!(
                doc,
                "{\"verdict\":\"refused\",\"reason\":\"the last chunk of the key is not a zid\"}"
            );
            assert!(node.asked.borrow().is_empty());
        }
    }

    #[test]
    fn each_permit_is_its_own() {
        for (granted, verb) in [Verb::Open, Verb::Close, Verb::Reset, Verb::Status]
            .into_iter()
            .enumerate()
        {
            let mut node = Recording::new(false);
            node.permit[granted] = true;
            for (at, command) in EVERY.into_iter().enumerate() {
                let (_, doc) = run(&node, command("1"));
                assert_eq!(
                    doc.contains("does not permit"),
                    at != granted,
                    "{verb:?} granted, command {at}: {doc}"
                );
            }
        }
    }

    #[test]
    fn a_close_withdraws_before_it_orders_and_a_reset_never_withdraws() {
        let node = Recording::new(true);
        run(&node, Command::Close { peer: "1" });
        assert_eq!(*node.asked.borrow(), ["withdraw", "order_close"]);
        let node = Recording::new(true);
        let (verdict, _) = run(
            &node,
            Command::Reset {
                peer: "1",
                generation: "7",
            },
        );
        assert_eq!(
            verdict,
            Verdict::Reset(ResetVerdict::Resetting { links: 1 })
        );
        assert_eq!(*node.asked.borrow(), ["take_generation", "order_close"]);
    }

    #[test]
    fn a_generation_is_read_after_the_peer_and_a_duplicate_closes_nothing() {
        let node = Recording::new(true);
        let (_, doc) = run(
            &node,
            Command::Reset {
                peer: "1",
                generation: "x",
            },
        );
        assert!(doc.contains("generation chunk"), "{doc}");
        assert!(node.asked.borrow().is_empty());

        node.taken.set(Generation::Duplicate { last: 5 });
        let (_, doc) = run(
            &node,
            Command::Reset {
                peer: "1",
                generation: "3",
            },
        );
        assert_eq!(doc, "{\"verdict\":\"duplicate\",\"generation\":5}");
        assert_eq!(*node.asked.borrow(), ["take_generation"]);

        node.taken.set(Generation::NoRoom);
        let (verdict, _) = run(
            &node,
            Command::Reset {
                peer: "1",
                generation: "3",
            },
        );
        assert_eq!(
            verdict,
            Verdict::Reset(ResetVerdict::Refused(RefusedReason::NoRoom))
        );
    }

    #[test]
    fn a_status_reads_and_changes_nothing() {
        let node = Recording::new(true);
        let (verdict, doc) = run(&node, Command::Status { peer: "1" });
        assert_eq!(
            doc,
            "{\"verdict\":\"status\",\"links\":{\"open\":0,\"closing\":0},\"intent\":false,\
             \"machines\":[]}"
        );
        assert!(matches!(
            verdict,
            Verdict::Status(StatusVerdict::Status { .. })
        ));
        assert_eq!(*node.asked.borrow(), ["links", "read_machines"]);
    }
}
