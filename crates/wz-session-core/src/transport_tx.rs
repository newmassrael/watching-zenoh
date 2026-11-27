// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one transport transmits with: the conduits its messages are framed in and the sequence
//! numbers its frames carry, which zenoh-pico keeps in the state every transport shares
//! (`_z_transport_common_t`) and sends with by one function whatever the transport
//! (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
//!
//! Held apart from the session around it so that a transport that is not a unicast session holds
//! the same state and is written by the same walk. The link a frame leaves by and the facts of the
//! session its emit reads (its counters, its compression) are not part of it: a session's core is
//! shared by every link of an aggregate, so it cannot own one binding's link.

use crate::link::SessionRuntime;
use crate::session_actions::{FrameTxConduits, TxConduits};

/// The transmit state of one transport.
pub struct TransportTx<R: SessionRuntime> {
    /// One lock per conduit, and the windows over them. A sender holds its conduit's lock from the
    /// mint of a frame's sequence number to the frame's emit, so the order of the numbers is the
    /// order on the wire, and a fragment chain stays whole on it.
    pub(crate) conduits: TxConduits<R>,
    /// The next sequence number of each conduit and reliability channel. Raw and monotonic: the
    /// wire value is masked to the negotiated ring where it is minted, so the counter's own wrap
    /// is the ring's successor too. The first frame takes the initial number the Open announced.
    pub(crate) frame_sn: FrameTxConduits<R::Word>,
}

impl<R: SessionRuntime> TransportTx<R> {
    /// Every conduit empty and its window closed, every channel at `initial_sn`.
    pub fn new(initial_sn: u64) -> Self {
        Self {
            conduits: TxConduits::new(),
            frame_sn: FrameTxConduits::new(initial_sn),
        }
    }

    /// Back to the state [`Self::new`] builds, for a session that opens its transport again. A
    /// frame open in a lent slot is given back to its lender by the caller first: the lender is a
    /// link, which this state does not hold.
    #[cfg(feature = "session-reconnect")]
    pub(crate) fn reset(&self, initial_sn: u64) {
        self.conduits.reset();
        self.frame_sn.reset(initial_sn);
    }
}

impl<R: SessionRuntime> core::fmt::Debug for TransportTx<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportTx")
            .field("conduits", &self.conduits)
            .finish_non_exhaustive()
    }
}
