// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The clock of the transport's shared-memory bookkeeping (`transport-shm`).
//!
//! The watchdog of the segments is `zenoh-shm`'s: a holder of a buffer confirms its slot through
//! that crate's confirmator, and a provider's slots are validated by its validator
//! (`docs/shm-transport.md`, section 6). What the transport keeps beside it runs here, on one
//! thread at the validator's interval: the poll of the handoff counters, which lets a sender
//! release a chunk its receiver has acknowledged, and the release of the providers the process
//! keeps for buffers a receiver still holds (`crate::shm_buffer`).
//!
//! The thread starts the first time something needs it, so a process that never sends shared
//! memory never pays for it.

use std::sync::OnceLock;
use std::time::Duration;

/// How often the bookkeeping runs: upstream's validator period, the interval its handoff reactor
/// sleeps (`commons/zenoh-shm/src/watchdog/validator.rs` @
/// `WatchdogValidator::new(Duration::from_millis(100));`).
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Start the thread, once per process.
pub(crate) fn start() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        // A thread that cannot be spawned leaves the handoffs unpolled: a sender then keeps what
        // it sent until the session ends, which costs memory and loses nothing.
        let _ = std::thread::Builder::new()
            .name("wz-shm-handoff".to_owned())
            .spawn(run);
    });
}

/// One pass of the bookkeeping. The thread calls this every [`POLL_INTERVAL`]; a test calls it
/// to make a window pass.
pub(crate) fn tick() {
    crate::shm_buffer::sweep_orphans();
    #[cfg(feature = "session-extshm")]
    crate::shm_auth_segment::poll_tx_handoffs();
}

fn run() {
    loop {
        std::thread::sleep(POLL_INTERVAL);
        tick();
    }
}
