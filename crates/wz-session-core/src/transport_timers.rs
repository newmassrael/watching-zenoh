// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The unicast session's own timers, kept with the session and not with what drives it: the
//! handshake deadline of the state the machine is in, the lease the peer is held to, the keep-alive
//! this end owes, and the application layer's wake.
//!
//! A drive loop asks when the next of them falls due ([`TransportTimers::next_due_ms`]), which is
//! how long it may wait for input, and hands the session the time once that may have come
//! ([`TransportTimers::fire_due`]). The loop holds no deadline and judges none, so every driver of
//! the session (a cooperative pump, a thread of its own, an async task) keeps the same timers, in
//! the same order, and a driver is the wait and nothing else.

use wz_runtime_core::TimeSource;

#[cfg(feature = "transport-keepalive")]
use crate::drive::{check_keepalive_deadline, keepalive_wake_deadline};
use crate::drive::{check_lease_deadline, lease_wake_deadline, SessionEngine};
use crate::driver_loop::{EventSink, IterationEvent};
use crate::link::SessionRuntime;
use crate::session_actions::SessionLinkActions;
use crate::session_fsm_unicast::SessionFsmUnicastEvent;
use crate::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

/// The timers of one unicast session, beside its machine ([`SessionEngine`]) and its actions
/// ([`SessionLinkActions`]), which hold the lease's and the keep-alive's stamps.
pub struct TransportTimers {
    /// The handshake deadline of the state the machine is in, armed when the timers first see the
    /// state.
    handshake: HandshakeDeadlineTracker,
}

impl TransportTimers {
    /// Timers over the session's handshake bounds, with no handshake deadline armed yet.
    pub fn new(timeouts: SessionTimeouts) -> Self {
        Self {
            handshake: HandshakeDeadlineTracker::new(timeouts),
        }
    }

    /// The first instant, in the session's monotonic milliseconds, at which one of its timers
    /// falls due: the handshake deadline of the state the machine is in, the lease's, the
    /// keep-alive's and the application layer's. `None` when none is armed. A state the timers
    /// see for the first time has its handshake deadline armed from `now_ms`.
    pub fn next_due_ms<R: SessionRuntime, T: TimeSource>(
        &mut self,
        engine: &SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
    ) -> Option<u64> {
        let handshake = self
            .handshake
            .poll(engine.get_current_state(), now_ms)
            .map(|(deadline_ms, _event)| deadline_ms);
        #[cfg(feature = "transport-keepalive")]
        let keepalive = keepalive_wake_deadline(actions);
        #[cfg(not(feature = "transport-keepalive"))]
        let keepalive: Option<u64> = None;
        [
            handshake,
            lease_wake_deadline(actions),
            keepalive,
            actions.app_wake_deadline_ms(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Give the session the time `now_ms` and raise what has fallen due by it: the handshake
    /// deadline's timeout event, or, in a state with no handshake deadline, the lease's check
    /// ([`IterationEvent::Lease`]); then the keep-alive's check
    /// ([`IterationEvent::KeepAlive`]), which sends one when it is owed. A check runs only once
    /// its deadline has passed, so a session whose timers are not due raises nothing.
    ///
    /// The application layer's wake is not raised here: a loop raises it before it reads its
    /// input (`SessionLinkActions::take_app_wake_due`), so a stream of input cannot hold it off.
    pub fn fire_due<R: SessionRuntime, T: TimeSource>(
        &mut self,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut dyn EventSink,
    ) {
        // In Established the handshake tracker disarms and the lease's deadline applies: the later
        // of the session's establishment and its last input, plus the adopted window, the same
        // arithmetic the lease's check derives again.
        let deadline: Option<(u64, Option<SessionFsmUnicastEvent>)> =
            match self.handshake.poll(engine.get_current_state(), now_ms) {
                Some((deadline_ms, event)) => Some((deadline_ms, Some(event))),
                None => lease_wake_deadline(actions).map(|deadline_ms| (deadline_ms, None)),
            };
        if let Some((deadline_ms, kind)) = deadline {
            if now_ms >= deadline_ms {
                match kind {
                    None => {
                        let outcome = check_lease_deadline(actions, engine, now_ms);
                        on_event.event(IterationEvent::Lease(outcome));
                    }
                    Some(event) => {
                        engine.process_event(event);
                    }
                }
            }
        }
        // The keep-alive's check runs only once its deadline has passed, so the steady state
        // raises no event, and a session whose keep-alive worker has stopped (in Closing) arms no
        // deadline and sends nothing after its Close.
        #[cfg(feature = "transport-keepalive")]
        if let Some(deadline_ms) = keepalive_wake_deadline(actions) {
            if now_ms >= deadline_ms {
                let outcome = check_keepalive_deadline(actions, now_ms);
                on_event.event(IterationEvent::KeepAlive(outcome));
            }
        }
    }
}
