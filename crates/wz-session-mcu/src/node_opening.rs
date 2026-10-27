// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The contract of decision D7, `docs/session-lifecycle-intent.md`: a node is asked to hold a
//! peer by its zid, and answers with an outcome.
//!
//! The three transports differ only in what feeds this port: a query the node serves
//! (`admin_fixed`, in-band), a line an agent writes to the node's control channel
//! (`control_port`, out-of-band), or nothing at run time because the build declared the peers
//! (`connect_manager::ConnectManager::hold_declared`). [`open_verdict`] is the one place that
//! turns a request into a verdict, so no transport owns a copy of the semantics: the permit, the
//! spelling of the zid, the outcomes, and their words are the same on every one.

use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::lifecycle_node::{self, Generation, LifecycleNode, Verb, Zid};
use wz_session_core::lifecycle_wire::{
    CloseOrder, MachineReport, OpenOutcome, OpenVerdict, SessionLinks,
};

/// What an open request asks of the node: whether it may be asked, and to hold a peer by its zid
/// (decision D6, `docs/session-lifecycle-intent.md`).
///
/// A port, for the reason the heap profile's `PeerOpener` is one: the machines that hold a peer
/// live with the loop that ticks them, and the request is served beside it. The node's own
/// implementation is `crate::connect_manager::ControlledOpener`.
///
/// It is also the strategy of decision D7: whether the node serves the in-band verbs is the type
/// its admin queryable is made with, so a build whose peers are declared when it is built names
/// [`NoOpening`] and its answer holds no code of the open query, which `BOUND` removes where the
/// answer is compiled (`docs/build-configuration.md` C3: a choice that changes the shape of the
/// code is a type parameter, not a feature).
pub trait NodeOpening {
    /// Whether the node binds the in-band verbs at all. `false` only for [`NoOpening`].
    const BOUND: bool = true;

    /// Whether this node lets a request open a session: the node's write permit, which is what
    /// the config write is gated by too. A node that does not permit it answers a refusal that
    /// says so, and opens nothing.
    fn permitted(&self) -> bool;

    /// Ask the node to hold the peer `zid`. Accepted, not completed: how the dial ends is read
    /// in the node's connection status. Asking again for a peer already held changes nothing
    /// and is accepted again, so a transport that cannot tell whether its request arrived may
    /// repeat it.
    fn open(&self, zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome;
}

/// The opener of a node that binds no in-band verb: the third value of decision D7, where the
/// peers a node holds are the ones it was built with and the machines only reconnect them. Its
/// admin answer lists no `open` and serves no `session/open` key.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpening;

impl NodeOpening for NoOpening {
    const BOUND: bool = false;

    fn permitted(&self) -> bool {
        false
    }

    fn open(&self, _zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome {
        // Not reached: the answer never asks an opener that is not `BOUND`. Were it reached, a
        // node that binds no verb takes no peer by request, which is `NoRoom`'s meaning.
        OpenOutcome::NoRoom
    }
}

/// The verdict on a request to hold the peer `peer_text`, spelled as a key carries it (the text
/// zenoh prints; `zid_from_key_text`): refused when the node does not permit it, refused when
/// the text names no zid, else what the node's opener made of it.
///
/// Decided by `lifecycle_node::open_verdict`, the function every verb of every profile is decided
/// by, over [`OpeningOnly`]: a node that binds this verb alone.
pub fn open_verdict<O: NodeOpening + ?Sized>(opener: &O, peer_text: &str) -> OpenVerdict {
    lifecycle_node::open_verdict(&OpeningOnly(opener), peer_text)
}

/// A node that binds the open verb alone, as the fixed in-band query and the first control port
/// served it: the verbs of the other three are not permitted and ask the node nothing.
///
/// The effects of those verbs are not reached, since the function reads the permit first; they
/// answer what a node with nothing to close, nothing to read and no room for a generation would.
#[derive(Debug, Clone, Copy)]
pub struct OpeningOnly<'a, O: ?Sized>(pub &'a O);

impl<O: NodeOpening + ?Sized> LifecycleNode for OpeningOnly<'_, O> {
    fn permits(&self, verb: Verb) -> bool {
        matches!(verb, Verb::Open) && self.0.permitted()
    }

    fn open(&self, zid: &Zid) -> OpenOutcome {
        self.0.open(zid)
    }

    fn withdraw(&self, _zid: &Zid) {}

    fn order_close(&self, _zid: &Zid) -> CloseOrder {
        CloseOrder::default()
    }

    fn take_generation(&self, _zid: &Zid, _generation: u64) -> Generation {
        Generation::NoRoom
    }

    fn links(&self, _zid: &Zid) -> SessionLinks {
        SessionLinks::default()
    }

    fn read_machines(&self, _zid: &Zid, read: &mut dyn FnMut(&[MachineReport<'_>])) {
        read(&[]);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use wz_session_core::lifecycle_wire::RefusedReason;

    struct Counting {
        permit: bool,
        outcome: OpenOutcome,
        asked: Cell<Option<[u8; CREDENTIAL_ZID_BYTES]>>,
        times: Cell<u32>,
    }

    impl Counting {
        fn new(permit: bool, outcome: OpenOutcome) -> Self {
            Self {
                permit,
                outcome,
                asked: Cell::new(None),
                times: Cell::new(0),
            }
        }
    }

    impl NodeOpening for Counting {
        fn permitted(&self) -> bool {
            self.permit
        }
        fn open(&self, zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome {
            self.asked.set(Some(*zid));
            self.times.set(self.times.get() + 1);
            self.outcome
        }
    }

    #[test]
    fn a_node_that_does_not_permit_is_never_asked() {
        let node = Counting::new(false, OpenOutcome::Accepted);
        assert_eq!(
            open_verdict(&node, "abc"),
            OpenVerdict::Refused(RefusedReason::OpenNotPermitted)
        );
        assert_eq!(node.times.get(), 0);
    }

    #[test]
    fn a_peer_that_is_no_zid_is_refused_before_the_node_is_asked() {
        let node = Counting::new(true, OpenOutcome::Accepted);
        for text in ["", "0abc", "xyz", "00000000000000000000000000000000f"] {
            assert_eq!(
                open_verdict(&node, text),
                OpenVerdict::Refused(RefusedReason::PeerNotAZid),
                "{text:?}"
            );
        }
        assert_eq!(node.times.get(), 0);
    }

    #[test]
    fn a_zid_is_read_as_the_key_text_reads_it_and_asked_again_is_accepted_again() {
        let node = Counting::new(true, OpenOutcome::Accepted);
        for _ in 0..2 {
            assert_eq!(open_verdict(&node, "abc"), OpenVerdict::Opening);
        }
        let mut expected = [0u8; CREDENTIAL_ZID_BYTES];
        expected[0] = 0xbc;
        expected[1] = 0x0a;
        assert_eq!(node.asked.get(), Some(expected));
        assert_eq!(node.times.get(), 2);
    }

    #[test]
    fn every_outcome_has_the_verdict_the_wire_gives_it() {
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
            let node = Counting::new(true, outcome);
            assert_eq!(open_verdict(&node, "1"), OpenVerdict::Refused(reason));
        }
    }

    #[test]
    fn a_node_that_binds_no_verb_permits_nothing() {
        const { assert!(!NoOpening::BOUND) };
        assert_eq!(
            open_verdict(&NoOpening, "1"),
            OpenVerdict::Refused(RefusedReason::OpenNotPermitted)
        );
    }
}
