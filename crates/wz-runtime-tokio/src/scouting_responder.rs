// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y846 — the socket half of the scouting RESPONDER: recv a datagram on the
//! scouting group, answer a Scout with this node's Hello, UNICAST back to the
//! asker.
//!
//! The decision is [`wz_session_core::scout_responder::answer_scout`] and lives
//! there, with no socket in sight; this owns the IO. That is the same split
//! `crate::scouting_glue` documents for the initiator, and it earns the same two
//! things: the gates are unit-testable without a multicast route, and the reasons
//! for NOT answering are values a caller can count rather than log lines it can
//! only read.
//!
//! (That module is named here without a link, and the omission is the point: it
//! is behind `scouting-active`, which this feature deliberately does not imply,
//! so an intra-doc link would be unresolved in exactly the build this module
//! exists for.)
//!
//! # Why a responder is not the initiator's mirror image
//!
//! `scouting_glue::drive_scouting_until_resolved` RESOLVES: it has a deadline, an
//! outcome, and a caller waiting for a locator to dial. A responder has none of
//! those. It is a service with no terminal state, so [`serve`] runs until the
//! socket dies and returns the cause, and the per-datagram
//! [`ScoutingResponder::answer_next`] exists so a test can assert one exchange
//! without racing a loop it cannot stop.
//!
//! # What it does NOT do
//!
//! It does not connect to whoever scouted it. Upstream keeps those apart too —
//! `Runtime::responder` only answers, while `autoconnect_all` is a separate task
//! that scouts and dials (zenoh `net/runtime/orchestrator.rs:1090` vs `:1112`).
//! Being findable and choosing to dial are different decisions, and folding them
//! would make a node that answers a Scout also dial every node that asked.

use std::io;
use std::net::SocketAddr;

use wz_session_core::link::{LinkEvent, LostCause};
use wz_session_core::scout_responder::{answer_scout, ScoutDecision, ScoutIgnored};
// R311y428's rule, applied to this module's own parameter types: a consumer
// reaches this crate through the wz facade (`wz::runtime_tokio::*`), which
// re-exports no `wz-session-core` path of its own, so without these the
// constructors below cannot be CALLED from there — their argument types are
// unnameable. `scouting_glue` re-exports `ScoutParams` for exactly this reason
// and the in-tree tests never hit it, because they carry a direct
// wz-session-core dev-dep the facade's consumers lack.
pub use wz_session_core::scout_responder::{ResponderIdentity, ResponderIdentityError};

use crate::{LinkDriver, UdpDriver};

/// What one turn of the responder loop did.
///
/// Every arm is REPORTED rather than merely counted, because the operator
/// question behind this subsystem is "why can nothing find me", and the answers
/// are different actions: a `WhatMismatch` means the network is looking for a
/// role this node does not have, a `SendFailed` means the reply could not leave,
/// and silence means no Scout ever arrived.
#[derive(Debug)]
pub enum ResponderStep {
    /// A Hello of `bytes` bytes went to this address.
    Answered {
        /// The asker's address — the datagram source, not the group.
        to: SocketAddr,
        /// The Hello's length on the wire.
        bytes: usize,
    },
    /// The datagram produced no reply.
    Ignored {
        /// Where it came from, when the link attributed it.
        from: Option<SocketAddr>,
        /// Which gate refused it.
        why: ScoutIgnored,
    },
    /// A Scout that should have been answered arrived with no source
    /// attribution, so there is nowhere to send the Hello.
    ///
    /// Unreachable through [`UdpDriver`], which always fills
    /// [`wz_session_core::link::RxFrame::src`] — kept as a named arm rather than
    /// an `unwrap` because the field is an `Option` on the shared trait and a
    /// future link type could leave it empty. A silent drop there would look
    /// exactly like a node nobody scouted.
    SourceUnknown,
    /// The reply could not be written. Upstream logs and continues here
    /// (`orchestrator.rs:1180`), and so does [`serve`]: one unreachable asker
    /// must not stop the node answering everyone else.
    SendFailed {
        /// The asker the reply was for.
        to: SocketAddr,
        /// The OS error.
        error: io::Error,
    },
    /// The socket is gone; the loop is over.
    LinkLost {
        /// Why the link reported itself lost.
        cause: LostCause,
    },
}

/// A node's answering half: one group socket plus the identity it answers with.
pub struct ScoutingResponder {
    driver: UdpDriver,
    identity: ResponderIdentity,
    answered: u64,
    ignored: u64,
}

impl ScoutingResponder {
    /// Take ownership of a socket already bound and joined to the scouting
    /// group — [`UdpDriver::bind_multicast_v4`] is the constructor that does
    /// all four steps consistently.
    ///
    /// The socket is taken rather than built here so the caller keeps the
    /// choice of group, interface and TTL it was configured with
    /// (`scouting/multicast/address` / `interface` / `ttl`). A responder that
    /// bound its own would answer on a group the operator did not name.
    pub fn new(driver: UdpDriver, identity: ResponderIdentity) -> Self {
        Self {
            driver,
            identity,
            answered: 0,
            ignored: 0,
        }
    }

    /// The address the responder is listening on, for reporting.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.driver.local_addr()
    }

    /// The identity every Hello carries.
    pub fn identity(&self) -> &ResponderIdentity {
        &self.identity
    }

    /// How many Hellos this responder has sent.
    pub fn answered(&self) -> u64 {
        self.answered
    }

    /// How many datagrams it declined to answer.
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// Receive exactly one datagram and act on it.
    ///
    /// Awaits the socket, so it does not return until something arrives or the
    /// link is lost. A caller that needs a deadline wraps this in a timeout —
    /// the responder deliberately owns no clock, because unlike the initiator
    /// it has no window to expire.
    pub async fn answer_next(&mut self) -> ResponderStep {
        let rx = match self.driver.poll_event().await {
            LinkEvent::Rx(frame) => frame,
            LinkEvent::Lost { cause } => return ResponderStep::LinkLost { cause },
            // A multicast receiver reports `Ready` only at open; nothing was
            // received, so nothing is answered and the caller loops.
            LinkEvent::Ready => {
                return ResponderStep::Ignored {
                    from: None,
                    why: ScoutIgnored::NotAScout,
                }
            }
        };
        match answer_scout(&self.identity, &rx.bytes) {
            ScoutDecision::Ignored(why) => {
                self.ignored += 1;
                ResponderStep::Ignored { from: rx.src, why }
            }
            ScoutDecision::Answer(hello) => {
                let Some(to) = rx.src else {
                    return ResponderStep::SourceUnknown;
                };
                match self.driver.send_datagram_to(&hello, to).await {
                    Ok(()) => {
                        self.answered += 1;
                        ResponderStep::Answered {
                            to,
                            bytes: hello.len(),
                        }
                    }
                    Err(error) => ResponderStep::SendFailed { to, error },
                }
            }
        }
    }
}

/// Answer Scouts until the socket dies, reporting every turn to `observe`.
///
/// Returns the [`LostCause`] that ended it, so a caller can distinguish a closed
/// socket from an OS error rather than seeing a task end.
///
/// `observe` is a plain `FnMut` rather than a channel or a log call: the demo
/// prints, the tests count, and neither has to agree with the other about a
/// format. It is called for EVERY step including the ignored ones, because "a
/// Scout arrived and was refused" is the diagnosis an unfindable node needs and
/// it is invisible from the outside.
pub async fn serve<F>(mut responder: ScoutingResponder, mut observe: F) -> LostCause
where
    F: FnMut(&ResponderStep),
{
    loop {
        let step = responder.answer_next().await;
        observe(&step);
        if let ResponderStep::LinkLost { cause } = step {
            return cause;
        }
    }
}
