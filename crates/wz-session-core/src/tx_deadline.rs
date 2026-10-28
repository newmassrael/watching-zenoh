// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2928 — one message's congestion outcome and deadline, shared by every
//! transport that pushes onto a bounded link queue.
//!
//! The unicast session (`session_actions`) grew these in R2923 / R2926; the
//! multicast transmission pipeline asks the same questions of its queue, and
//! upstream answers both from one `TransmissionPipeline`
//! (`io/zenoh-transport/src/multicast/link.rs` @ `let tpc = TransmissionPipelineConf {`),
//! so the two transports share one deadline rather than two copies of it.

use crate::link::RoomWait;
use crate::session_init_params::TxQueueConf;

/// R2923 / R2926 — whether a message was pushed onto its conduit's link, or
/// found no room within its deadline (a congestion drop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The message is on the link's queue.
    Pushed,
    /// No room was found within the message's deadline.
    Congested,
}

/// What a BLOCKING message that found no room in its deadline costs: the one decision the
/// `tx-expiry-keeps-session` policy makes, taken where the unicast sender and the router's
/// egress sweep both give up on a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxExpiry {
    /// Upstream's behaviour: the message is dropped and the session closes as unresponsive
    /// (`io/zenoh-transport/src/unicast/universal/tx.rs` @ `if !pushed && !msg.is_droppable() {`),
    /// with the sender told nothing.
    Closing,
    /// The policy: the message is dropped, the sender is told the transport is not available,
    /// and the session stays open.
    Kept,
}

impl TxExpiry {
    /// The outcome the build's queue configuration gives an expired blocking message.
    pub const fn of(conf: &TxQueueConf) -> Self {
        if conf.expiry_keeps_session {
            Self::Kept
        } else {
            Self::Closing
        }
    }
}

/// The run of blocking messages that found no room, one after another, on one session: what a
/// circuit breaker counts. `tx-expiry-keeps-session` keeps the session open for each expiry,
/// and `TX_EXPIRY_CLOSE_AFTER` is how long a link may stay blocked before it is not kept any
/// more. A message that finds room is proof the link moves, so it ends the run.
///
/// It counts messages in a row and not messages in a period, so it needs no clock: a session
/// has none fine enough, and a run of expiries is already spread over `wait_before_close` each.
///
/// A plain count, not an atomic: it lives in the session's out-of-band state, under the lock
/// that state already has, where it takes the room of a field's padding and no new bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryRun {
    run: u16,
}

impl ExpiryRun {
    /// A message was pushed, so the link has room: the run ends.
    pub fn pushed(&mut self) {
        self.run = 0;
    }

    /// A blocking message expired. Whether this is the `close_after`-th in the run, which is
    /// the one that closes the session; every expiry after it is too, so a close asked for twice
    /// is the same close. `0` never closes.
    pub fn expired(&mut self, close_after: u16) -> bool {
        if close_after == 0 {
            return false;
        }
        self.run = self.run.saturating_add(1);
        self.run >= close_after
    }
}

/// R2926 — one message's congestion deadline, held across every ask for room
/// its frame or fragment chain makes: upstream's `Deadline` over a
/// `LazyDeadline` over a `WaitTime`
/// (`io/zenoh-transport/src/common/pipeline.rs` @ `fn advance(&mut self, instant: &mut Instant) {`).
///
/// A droppable message starts with `wait_before_drop`, and each fragment it
/// puts on the wire extends the deadline by an increment that DOUBLES, the
/// extensions together capped by `max_wait_before_drop_fragments`. A blocking
/// message has no cap to spend, so upstream's advance leaves its deadline
/// where it is: the whole chain shares one `wait_before_close`.
///
/// The deadline is held as microseconds LEFT, not as an instant: a session
/// has no clock that fine, and each ask reports how long it waited
/// ([`crate::link::RoomAnswer`]), which is what spends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushDeadline {
    droppable: bool,
    /// Microseconds left before the deadline.
    left_us: u64,
    /// The increment the next fragment adds (droppable only).
    step_us: u64,
    /// What is left of `max_wait_before_drop_fragments` (droppable only).
    extend_left_us: u64,
    /// The `tx-no-progress-deadline` policy: the window a BLOCKING message may wait with no
    /// fragment of it going out, in microseconds. `None` is upstream's behaviour, the total wait
    /// alone. It is a SECOND bound beside `left_us`, never a replacement for it: the message is
    /// given up on at whichever comes first, and a fragment out restarts only this window.
    /// Never set for a droppable message, which drops and does not close.
    window_us: Option<u64>,
    /// What is left of the window since the last fragment went out (blocking with a window only).
    window_left_us: u64,
    /// Whether this is a sender that may not wait at all ([`Self::probe`]). A configured wait of
    /// zero is not the same: it still sends a chain, and abandons it if the lane fills.
    probing: bool,
}

impl PushDeadline {
    /// The deadline a message starts with: `wait_before_drop` when it is
    /// droppable, `wait_before_close` when it blocks.
    pub fn new(droppable: bool, conf: &TxQueueConf) -> Self {
        if droppable {
            Self {
                droppable,
                left_us: conf.wait_before_drop_us,
                step_us: conf.wait_before_drop_us,
                extend_left_us: conf.max_wait_before_drop_fragments_us,
                window_us: None,
                window_left_us: 0,
                probing: false,
            }
        } else {
            Self {
                droppable,
                left_us: conf.wait_before_close_us,
                step_us: 0,
                extend_left_us: 0,
                window_us: conf.no_progress_us,
                window_left_us: conf.no_progress_us.unwrap_or(0),
                probing: false,
            }
        }
    }

    /// Whether this deadline belongs to a sender that may not wait ([`Self::probe`]).
    pub fn is_probe(&self) -> bool {
        self.probing
    }

    /// The deadline of a sender that may not wait at all: every ask for room is made with a
    /// wait of zero, and no fragment extends it. A router forwarding to many faces uses it so
    /// that one face with a full queue costs the loop an answer and not a stall; the message
    /// that found no room is the caller's to keep and send again.
    ///
    /// A message that is a chain of fragments longer than the queue can hold is not sent at all:
    /// a chain cannot be abandoned and begun again without end, which is what a sender that does
    /// not wait would do to it, so the sender is told to send it waiting. A chain the queue can
    /// hold whole is asked for like any frame.
    pub fn probe(droppable: bool) -> Self {
        Self {
            droppable,
            left_us: 0,
            step_us: 0,
            extend_left_us: 0,
            window_us: None,
            window_left_us: 0,
            probing: true,
        }
    }

    /// How long the next ask may wait: what is left of the total wait, and, under the
    /// `tx-no-progress-deadline` policy, no more than what is left of the window.
    fn wait_us(&self) -> u64 {
        match self.window_us {
            Some(_) => self.left_us.min(self.window_left_us),
            None => self.left_us,
        }
    }

    /// The ask for room this deadline makes now.
    pub fn ask(&self) -> RoomWait {
        if self.droppable {
            RoomWait::Drop {
                wait_us: self.wait_us(),
            }
        } else {
            RoomWait::Block {
                wait_us: self.wait_us(),
            }
        }
    }

    /// Spend what an ask waited, against the total wait and against the window.
    pub fn spend(&mut self, waited_us: u64) {
        self.left_us = self.left_us.saturating_sub(waited_us);
        self.window_left_us = self.window_left_us.saturating_sub(waited_us);
    }

    /// A fragment went out: upstream's `on_next_fragment`, which doubles the
    /// increment and adds it, bounded by what is left of the cap.
    ///
    /// A blocking message has no cap to spend, so upstream leaves its deadline where it is. Under
    /// the `tx-no-progress-deadline` policy a fragment out is progress, and starts the window
    /// again; the total wait is not touched, so the message is still bounded by it.
    pub fn next_fragment(&mut self) {
        if !self.droppable {
            if let Some(window_us) = self.window_us {
                self.window_left_us = window_us;
            }
            return;
        }
        self.step_us = self.step_us.saturating_mul(2);
        let add = self.step_us.min(self.extend_left_us);
        self.extend_left_us -= add;
        self.left_us = self.left_us.saturating_add(add);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_init_params::WAIT_BEFORE_CLOSE_US;

    /// With no count stated, a blocked link is kept however long it stays blocked: the
    /// policy as it was before the limit.
    #[test]
    fn a_run_of_expiries_never_closes_when_no_count_is_stated() {
        let mut run = ExpiryRun::default();
        for _ in 0..10_000 {
            assert!(!run.expired(0));
        }
    }

    /// The count-th expiry in a row is the one that closes the session, and the ones before
    /// it are kept.
    #[test]
    fn the_expiry_that_completes_the_run_closes_the_session() {
        let mut run = ExpiryRun::default();
        assert!(!run.expired(3));
        assert!(!run.expired(3));
        assert!(run.expired(3));
        // A close asked for again is the same close.
        assert!(run.expired(3));
    }

    /// A count of one is upstream's own answer, the first expiry closes it.
    #[test]
    fn a_count_of_one_closes_at_the_first_expiry() {
        assert!(ExpiryRun::default().expired(1));
    }

    /// A message that finds room ends the run: the expiries on either side of it are two runs
    /// of two, not one of four, so a link that blocks now and then is never closed.
    #[test]
    fn a_push_between_expiries_starts_the_count_again() {
        let mut run = ExpiryRun::default();
        assert!(!run.expired(3));
        assert!(!run.expired(3));
        run.pushed();
        assert!(!run.expired(3));
        assert!(!run.expired(3));
        assert!(run.expired(3));
    }

    /// A push with no run open changes nothing.
    #[test]
    fn a_push_with_no_run_open_leaves_the_count_at_zero() {
        let mut run = ExpiryRun::default();
        run.pushed();
        assert!(!run.expired(2));
        assert!(run.expired(2));
    }

    /// Under pico's transmit model a droppable message asks for room as long
    /// as a blocking one does, and its fragments add nothing past that: pico
    /// drops only on a contended TX mutex, never for a full socket.
    #[test]
    fn a_pico_droppable_message_waits_as_long_as_a_blocking_one() {
        let pico = TxQueueConf::pico();
        let mut drop = PushDeadline::new(true, &pico);
        let block = PushDeadline::new(false, &pico);
        assert_eq!(
            drop.ask(),
            RoomWait::Drop {
                wait_us: WAIT_BEFORE_CLOSE_US
            }
        );
        assert_eq!(
            block.ask(),
            RoomWait::Block {
                wait_us: WAIT_BEFORE_CLOSE_US
            }
        );
        drop.next_fragment();
        assert_eq!(
            drop.ask(),
            RoomWait::Drop {
                wait_us: WAIT_BEFORE_CLOSE_US
            },
            "a fragment must not stretch a pico drop past the close deadline"
        );
    }

    /// A blocking message's conf: a total wait of 1000 and, optionally, a no-progress window.
    fn blocking_conf(no_progress_us: Option<u64>) -> TxQueueConf {
        TxQueueConf {
            wait_before_close_us: 1_000,
            no_progress_us,
            ..TxQueueConf::default()
        }
    }

    /// Upstream's behaviour, the default of the policy: the total wait alone, which each ask
    /// spends and a fragment out does not give back.
    #[test]
    fn a_blocking_message_has_only_its_total_wait_when_the_policy_is_off() {
        let mut block = PushDeadline::new(false, &blocking_conf(None));
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 1_000 });
        block.spend(750);
        block.next_fragment();
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 250 });
    }

    /// The policy adds a second bound: an ask may wait no longer than the window, though the
    /// total has more left.
    #[test]
    fn with_the_policy_on_an_ask_waits_no_longer_than_the_window() {
        let block = PushDeadline::new(false, &blocking_conf(Some(100)));
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 100 });
    }

    /// With no progress the window runs out first and the message is given up on, with most of
    /// the total wait unspent: the point of the policy.
    #[test]
    fn with_the_policy_on_a_stall_ends_the_message_before_the_total_wait() {
        let mut block = PushDeadline::new(false, &blocking_conf(Some(100)));
        block.spend(100);
        assert_eq!(
            block.ask(),
            RoomWait::Block { wait_us: 0 },
            "the window is spent, and 900 of the total is still left"
        );
    }

    /// A fragment out is progress: it starts the window again. It does NOT make the total wait
    /// longer, which is the difference from a renewal of the deadline.
    #[test]
    fn a_fragment_out_restarts_the_window_and_never_the_total_wait() {
        let mut block = PushDeadline::new(false, &blocking_conf(Some(400)));
        block.spend(300);
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 100 });
        block.next_fragment();
        assert_eq!(
            block.ask(),
            RoomWait::Block { wait_us: 400 },
            "the window is whole again"
        );
        block.spend(400);
        block.next_fragment();
        assert_eq!(
            block.ask(),
            RoomWait::Block { wait_us: 300 },
            "700 of 1000 is spent, so the total, not the window, bounds this ask"
        );
        block.spend(300);
        block.next_fragment();
        assert_eq!(
            block.ask(),
            RoomWait::Block { wait_us: 0 },
            "progress cannot buy a total wait that is spent"
        );
    }

    /// A window as long as the total, or longer, adds no bound: the total is always first.
    #[test]
    fn a_window_past_the_total_wait_changes_nothing() {
        let mut block = PushDeadline::new(false, &blocking_conf(Some(5_000)));
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 1_000 });
        block.spend(1_000);
        assert_eq!(block.ask(), RoomWait::Block { wait_us: 0 });
    }

    /// A droppable message drops and does not close, so the policy has nothing to bound:
    /// its deadline and its fragment extensions are what they were.
    #[test]
    fn the_policy_does_not_touch_a_droppable_message() {
        let steps = |no_progress_us: Option<u64>| {
            let conf = TxQueueConf {
                wait_before_drop_us: 100,
                max_wait_before_drop_fragments_us: 1_000,
                no_progress_us,
                ..TxQueueConf::default()
            };
            let mut drop = PushDeadline::new(true, &conf);
            let mut seen = [drop.ask(); 5];
            for slot in seen.iter_mut().skip(1) {
                drop.spend(60);
                drop.next_fragment();
                *slot = drop.ask();
            }
            seen
        };
        assert_eq!(steps(None), steps(Some(10)));
    }

    /// A sender that may not wait never waits, whatever the policy says.
    #[test]
    fn the_policy_does_not_touch_a_probe() {
        let mut probe = PushDeadline::probe(false);
        probe.next_fragment();
        assert_eq!(probe.ask(), RoomWait::Block { wait_us: 0 });
    }

    /// The default is upstream's: an expired blocking message closes the session.
    #[test]
    fn an_expired_blocking_message_closes_the_session_by_default() {
        assert_eq!(TxExpiry::of(&TxQueueConf::default()), TxExpiry::Closing);
    }

    /// The policy keeps the session; the control above is its pair.
    #[test]
    fn with_the_policy_on_an_expired_blocking_message_keeps_the_session() {
        let conf = TxQueueConf {
            expiry_keeps_session: true,
            ..TxQueueConf::default()
        };
        assert_eq!(TxExpiry::of(&conf), TxExpiry::Kept);
    }

    /// The control: zenoh's default still drops after `wait_before_drop`.
    #[test]
    fn a_zenoh_droppable_message_still_waits_only_wait_before_drop() {
        let zenoh = TxQueueConf::default();
        let drop = PushDeadline::new(true, &zenoh);
        assert_eq!(
            drop.ask(),
            RoomWait::Drop {
                wait_us: crate::session_init_params::WAIT_BEFORE_DROP_US
            }
        );
    }
}
