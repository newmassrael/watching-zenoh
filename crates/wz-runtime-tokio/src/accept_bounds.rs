// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an accepting node gives an inbound link before its handshake is complete.
//!
//! Plain configuration data, so it is a module of its own that every build has: the C interfaces
//! carry it in structures they build for every role, and the accept loop that reads it
//! (`accept_loop`, behind `routing-accept`) re-exports it, so a path through that module still
//! names it.

use crate::config::{ACCEPT_PENDING, ACCEPT_TIMEOUT_MS};
#[cfg(feature = "transport-unicast")]
use crate::session_glue::SessionTimeouts;

/// How much an accepting node gives an inbound link before the handshake is complete, and how
/// many it gives at once: upstream's `transport/unicast/accept_timeout` and `accept_pending`,
/// which its manager keeps side by side (`io/zenoh-transport/src/unicast/manager.rs` @
/// `pub accept_timeout: Duration,` and `pub accept_pending: usize,`).
///
/// The timeout is ONE bound over the whole accept, as upstream wraps its accept in a single
/// `tokio::time::timeout`: the link's own handshake (the ws or tls server side) spends from it,
/// and the session handshake is given what is left. The pending count is the accepts whose
/// handshake has not finished; one past it is closed at once, with nothing said to the peer
/// (`handle_new_link_unicast`: "Closing link for preventing potential DoS").
///
/// `Default` is upstream's, ten seconds and a hundred. zenoh-pico bounds its accept at one second
/// (`Z_TRANSPORT_ACCEPT_TIMEOUT`), which is also the §2.5 baseline of the session machine: an
/// interface standing for it states that ([`Self::with_timeout_ms`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptBounds {
    /// How long an accepted link may take to complete its whole handshake, in milliseconds.
    pub timeout_ms: u64,
    /// How many accepted links may be mid-handshake at once.
    pub pending: usize,
}

impl Default for AcceptBounds {
    fn default() -> Self {
        Self {
            timeout_ms: ACCEPT_TIMEOUT_MS,
            pending: ACCEPT_PENDING,
        }
    }
}

impl AcceptBounds {
    /// These bounds with another accept timeout, in milliseconds.
    pub const fn with_timeout_ms(self, timeout_ms: u64) -> Self {
        Self { timeout_ms, ..self }
    }

    /// The deadlines of the session handshake of an accept that has already spent
    /// `spent_ms` of the bound on the link's own handshake: the §2.5 baseline, with the
    /// `Accepting` window the rest of the bound, and never nothing, so the drive finds the
    /// deadline elapsed rather than waiting for ever on a zero. The deadlines are the session
    /// machine's, so this is there with the unicast session (`transport-unicast`) and not in a
    /// build that holds the bounds as data only.
    #[cfg(feature = "transport-unicast")]
    pub fn timeouts_after(&self, spent_ms: u64) -> SessionTimeouts {
        SessionTimeouts {
            accepting_inactivity_ms: self.timeout_ms.saturating_sub(spent_ms).max(1),
            ..SessionTimeouts::spec_defaults()
        }
    }
}
