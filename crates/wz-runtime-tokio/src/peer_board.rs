// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a face loop's peer machines are doing, as the loop last published it
//! (decision D6 of `docs/session-lifecycle-intent.md`: each peer's machine state
//! is readable, so the outcome of a verb that has no reply is observable).
//!
//! The machines live in the loop (`loop_peers::LoopPeers`, a module of the
//! builds with the connect reconcile), which owns them and changes them
//! on every dial, loss and timer, and nothing outside the loop can borrow them
//! while it runs. So the loop publishes: after each change it replaces the board
//! with every peer's rows, and a reader (the lifecycle status query) reads the
//! board, never the machines. A reader sees the state as of the loop's last
//! change, whole, and never one half-applied.
//!
//! The host makes the board and hands one clone to the loop
//! (`FaceSources::peer_board`) and one to the reader, as it does the session
//! ceiling. Rows are plain words (wz-session-core's `StateWords`, read off each
//! machine by the loop), so the board is the same type in every build of the loop,
//! the ones with no machine among them.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use wz_session_core::locator_directory::DirectoryZid;

/// One machine that works to hold a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardRow {
    /// The configured endpoint the machine dials, as the loop keys it, or `None`
    /// for the machine of the node itself (a lifecycle `open` by its zid).
    pub endpoint: Option<String>,
    /// The machine's state, in its word.
    pub state: &'static str,
    /// For a refusal, its cause.
    pub cause: Option<&'static str>,
    /// Whether the machine holds the peer in the node's intent.
    pub in_intent: bool,
}

/// The rows of every peer a loop holds, by the zid each is read by: a node's
/// own, and for an endpoint the zid its last session named. An endpoint that has
/// not reached a node yet has no zid to be read by and is not on the board.
pub type BoardRows = BTreeMap<DirectoryZid, Vec<BoardRow>>;

/// The board a loop publishes its peers to and a reader reads them from. Clones
/// share one board.
#[derive(Debug, Clone, Default)]
pub struct PeerBoard(Arc<RwLock<BoardRows>>);

impl PeerBoard {
    /// An empty board: no peer held.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the board with `rows`, every peer the loop holds.
    pub fn publish(&self, rows: BoardRows) {
        // A writer that panicked left rows a later publish replaces whole, so the
        // poison carries nothing a reader must not see.
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = rows;
    }

    /// The rows of the peer `zid`, empty for a peer the loop does not hold.
    pub fn rows(&self, zid: &DirectoryZid) -> Vec<BoardRow> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(zid)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(feature = "session-close-ingress")]
impl wz_session_core::lifecycle_query::PeerMachines for PeerBoard {
    fn each_machine(
        &self,
        peer_zid: &[u8],
        each: &mut dyn FnMut(&wz_session_core::lifecycle_query::MachineReport<'_>),
    ) {
        let Some(zid) = wz_session_core::credential_identity::zid_from_wire(peer_zid) else {
            return;
        };
        for row in self.rows(&zid) {
            each(&wz_session_core::lifecycle_query::MachineReport {
                endpoint: row.endpoint.as_deref(),
                state: row.state,
                cause: row.cause,
                in_intent: row.in_intent,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: DirectoryZid = [0xa1; 16];

    fn row(state: &'static str) -> BoardRow {
        BoardRow {
            endpoint: None,
            state,
            cause: None,
            in_intent: state != "idle",
        }
    }

    /// A clone reads what the other publishes, and a publish replaces the board
    /// whole: a peer it leaves out is no longer read.
    #[test]
    fn a_publish_replaces_the_board_every_clone_reads() {
        let loop_side = PeerBoard::new();
        let reader = loop_side.clone();
        assert!(reader.rows(&A).is_empty(), "nothing published yet");

        loop_side.publish(BoardRows::from([(A, vec![row("connecting")])]));
        assert_eq!(reader.rows(&A), vec![row("connecting")]);

        loop_side.publish(BoardRows::new());
        assert!(
            reader.rows(&A).is_empty(),
            "the peer the publish left out is gone"
        );
    }
}
