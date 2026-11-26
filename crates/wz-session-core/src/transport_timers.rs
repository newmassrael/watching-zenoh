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
//!
//! The lease's and the keep-alive's deadlines are read when one of them falls due, not at every
//! step: a step whose input only moves them later (a receipt, a frame sent) reads none. What can
//! bring one earlier (a duty armed, a handshake deadline that stood and no longer does, a stamp
//! changed through its door, a lease adopted) is what the timers compare at every step, and a
//! change there has them read the deadlines again at once. The wait a loop asks for and the
//! check it hands the time to keep one reading: the loop's question answers the first instant
//! as last read, which is never later than the deadline itself.
//!
//! [`TransportTimers::next_due_ms`]: crate::transport_timers::TransportTimers::next_due_ms
//! [`TransportTimers::fire_due`]: crate::transport_timers::TransportTimers::fire_due

use wz_runtime_core::TimeSource;

#[cfg(feature = "transport-keepalive")]
use crate::drive::{judge_keepalive, keepalive_deadlines, KeepaliveDeadlines};
use crate::drive::{judge_lease, lease_deadlines, LeaseDeadlines, SessionEngine};
use crate::driver_loop::{EventSink, IterationEvent};
use crate::link::SessionRuntime;
use crate::session_actions::SessionLinkActions;
use crate::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

/// The timers of one unicast session, beside its machine ([`SessionEngine`]) and its actions
/// ([`SessionLinkActions`]), which hold the lease's and the keep-alive's stamps.
pub struct TransportTimers {
    /// The handshake deadline of the state the machine is in, armed when the timers first see the
    /// state.
    handshake: HandshakeDeadlineTracker,
    /// The first instant at which the lease's or the keep-alive's check can fall due, as the
    /// timers last read the link's deadlines: none runs before it while what they were read under
    /// holds. A deadline that moved later since is found when this instant comes. 0 until the
    /// first read and after a check, so the step after reads them again.
    link_due_ms: u64,
    /// What the link's deadlines were last read under; `None` before the first read.
    read_under: Option<ReadUnder>,
}

/// What the link's lease and keep-alive deadlines were read under: whether a handshake deadline
/// stood, which keeps the lease's check out, whether each duty was armed, and the link's count of
/// writes that may have brought a deadline earlier. Each is a word read with no lock, and a step
/// whose input moves a deadline only later changes none of them.
#[derive(Clone, Copy)]
struct ReadUnder {
    moved: u64,
    handshake: bool,
    lease_armed: bool,
    #[cfg(feature = "transport-keepalive")]
    keepalive_armed: bool,
}

impl ReadUnder {
    /// What `actions`' link stands under now. The count is read first: a deadline read after it
    /// sees every write it counts.
    fn of<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
        handshake: bool,
    ) -> Self {
        use core::sync::atomic::Ordering;
        Self {
            moved: actions.link.deadlines_moved(),
            handshake,
            lease_armed: actions.link.lease_armed.load(Ordering::SeqCst),
            #[cfg(feature = "transport-keepalive")]
            keepalive_armed: actions.link.keepalive_armed.load(Ordering::SeqCst),
        }
    }

    /// Whether deadlines read under `self` still hold under `now`.
    fn holds_under(self, now: Self) -> bool {
        #[cfg(feature = "transport-keepalive")]
        if self.keepalive_armed != now.keepalive_armed {
            return false;
        }
        self.moved == now.moved
            && self.handshake == now.handshake
            && self.lease_armed == now.lease_armed
    }
}

impl TransportTimers {
    /// Timers over the session's handshake bounds, with no handshake deadline armed yet.
    pub fn new(timeouts: SessionTimeouts) -> Self {
        Self {
            handshake: HandshakeDeadlineTracker::new(timeouts),
            link_due_ms: 0,
            read_under: None,
        }
    }

    /// The first instant, in the session's monotonic milliseconds, at which one of its timers
    /// falls due: the handshake deadline of the state the machine is in, the lease's, the
    /// keep-alive's and the application layer's. `None` when none is armed. A state the timers
    /// see for the first time has its handshake deadline armed from the end of the millisecond
    /// `now_ms` names.
    ///
    /// The lease's and the keep-alive's are the first instant the timers hold for them, read again
    /// only under what [`Self::fire_due`] reads them again under: a deadline that moved later
    /// since is answered at the instant held, which wakes a loop early and never late, and the
    /// check at that instant reads the later one.
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
        // What falls due by now is the check's to judge; the wait reads the instant held.
        let _ = self.link_due(actions, handshake.is_some(), now_ms);
        let link = (self.link_due_ms != u64::MAX).then_some(self.link_due_ms);
        [handshake, link, actions.app_wake_deadline_ms()]
            .into_iter()
            .flatten()
            .min()
    }

    /// The link's lease and keep-alive deadlines that have passed by `now_ms`, for a check to
    /// judge, with the first instant either falls due held in `link_due_ms` (`u64::MAX` when
    /// neither duty is armed). They are read again only when the instant held has come or what
    /// they were read under changed; before that nothing has passed and no stamp, clock or lease
    /// is read. The lease's is left out while a handshake deadline stands. One body for the wait
    /// and the check, out of line: it reads the stamps once for both.
    #[inline(never)]
    fn link_due<R: SessionRuntime, T: TimeSource>(
        &mut self,
        actions: &SessionLinkActions<R, T>,
        handshake: bool,
        now_ms: u64,
    ) -> LinkDue {
        let under = ReadUnder::of(actions, handshake);
        if self.read_under.is_some_and(|read| read.holds_under(under)) && now_ms < self.link_due_ms
        {
            return LinkDue::default();
        }
        self.read_under = Some(under);
        let mut due_ms = u64::MAX;
        let mut passed = LinkDue::default();
        if !handshake {
            if let Some(deadlines) = lease_deadlines(actions) {
                let wake_ms = deadlines.wake();
                due_ms = wake_ms;
                if now_ms >= wake_ms {
                    passed.lease = Some(deadlines);
                }
            }
        }
        #[cfg(feature = "transport-keepalive")]
        if let Some(deadlines) = keepalive_deadlines(actions) {
            if let Some(deadline_ms) = deadlines.earliest() {
                due_ms = due_ms.min(deadline_ms);
                if now_ms >= deadline_ms {
                    passed.keepalive = Some(deadlines);
                }
            }
        }
        self.link_due_ms = due_ms;
        passed
    }

    /// Give the session the time `now_ms` and raise what has fallen due by it: the handshake
    /// deadline's timeout event, or, in a state with no handshake deadline, the lease's check
    /// ([`IterationEvent::Lease`]); then the keep-alive's check
    /// ([`IterationEvent::KeepAlive`]), which sends one when it is owed. A check runs only once
    /// its deadline has passed, so a session whose timers are not due raises nothing.
    ///
    /// The lease's and the keep-alive's deadlines are read again only when the first of them, as
    /// last read, has come, or when what they were read under changed (a duty armed or lowered,
    /// a handshake deadline that stood or no longer does, a write that may bring one earlier); a
    /// step before that compares words and reads no stamp, clock or lease.
    ///
    /// The application layer's wake is not raised here: a loop raises it before it reads its
    /// input (`SessionLinkActions::take_app_wake_due`), so a stream of input cannot hold it off.
    pub fn fire_due<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(
        &mut self,
        engine: &mut SessionEngine<R, T>,
        actions: &SessionLinkActions<R, T>,
        now_ms: u64,
        on_event: &mut F,
    ) {
        // In Established the handshake tracker disarms and the lease's deadline applies: the later
        // of the session's establishment and its last input, plus the adopted window.
        let handshake = match self.handshake.poll(engine.get_current_state(), now_ms) {
            Some((deadline_ms, event)) => {
                if now_ms >= deadline_ms {
                    engine.process_event(event);
                }
                true
            }
            None => false,
        };
        // A judge moves what the deadlines are read from (a tick ended, the machine told), so a
        // step that judged one leaves 0 and the next reads them again. A keep-alive due with a
        // lease judged waits for that read: a lease that ended the session stopped its worker,
        // and nothing is sent after its Close.
        let passed = self.link_due(actions, handshake, now_ms);
        if let Some(deadlines) = passed.lease {
            let outcome = judge_lease(actions, engine, now_ms, deadlines);
            on_event.event(IterationEvent::Lease(outcome));
            self.link_due_ms = 0;
            return;
        }
        #[cfg(feature = "transport-keepalive")]
        if let Some(deadlines) = passed.keepalive {
            let outcome = judge_keepalive(actions, now_ms, deadlines);
            on_event.event(IterationEvent::KeepAlive(outcome));
            self.link_due_ms = 0;
        }
    }
}

/// The link's deadlines that have passed by the instant `TransportTimers::link_due` was asked
/// at, each as it was read, so its judge reads the stamps no second time.
#[derive(Default)]
struct LinkDue {
    lease: Option<LeaseDeadlines>,
    #[cfg(feature = "transport-keepalive")]
    keepalive: Option<KeepaliveDeadlines>,
}
