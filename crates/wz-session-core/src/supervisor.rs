// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The checkpoints a node watches and whether every one is healthy (`docs/observation-plane.md`
//! M3).
//!
//! An application that must keep making progress feeds a checkpoint on every pass. Each checkpoint
//! is a [`supervision`](crate::supervision) machine with a deadline of its own. The supervisor is
//! healthy only while every checkpoint it holds is armed, so a node that feeds a hardware watchdog
//! feeds it from [`Supervisor::is_healthy`] and from nowhere else: a hung checkpoint stops the feed.
//!
//! # What is the host's
//!
//! The supervisor reads no clock, starts no task and calls no hook. The host hands it the time on
//! every call (`now`, a tick count of the monotonic time source, any width up to 32 bits and wrapping
//! at 2^32), calls [`Supervisor::check`] on its own cadence, and runs the hook a checkpoint's
//! expiry asks for. The cooperative engine calls `check` every turn of its loop; a build with tasks
//! gives it one.
//!
//! # The deadline
//!
//! A deadline has passed when `now - last_feed >= timeout`, the difference taken modulo 2^32
//! ([`elapsed`]). Written that way a wrap of the counter between the feed and the check is the
//! ordinary case and not a special one, and a `timeout` of at most `2^31 - 1` ticks is told apart
//! from a counter that went round; a longer one is refused where it is set.
//!
//! # After an expiry
//!
//! A checkpoint whose deadline passed runs its expiry hook once ([`Check::hook`]), and cannot be
//! stopped while the hook runs ([`Stop::Refused`]). Once the host reports the hook done it is
//! `Expired`, where a feed is ignored: a late feed does not hide a missed deadline. With
//! [`AfterExpiry::Rearm`] the next feed after an expiry starts the checkpoint again; with
//! [`AfterExpiry::Latch`], the default and the behaviour of a watchdog, it stays expired until it
//! is stopped and started.

use sce_rust_runtime::Engine;

use crate::constant_session_id::built_under_constant_id;
use crate::duty_outbox::{Duties, DutyOutbox};
use crate::supervision::{
    SupervisionActions, SupervisionEvent, SupervisionPolicy, SupervisionState,
};

/// The id every checkpoint's machine is built under (SCE ADR 0045: the host gives a machine its
/// id). A constant, so the generated constructor never refuses it.
const SUPERVISION_SESSION_ID: &str = "wz-supervision";

/// The longest timeout a deadline can have: the difference of two readings is compared modulo
/// 2^32, so a timeout past half the range cannot be told from a counter that went round.
pub const MAX_TIMEOUT_TICKS: u32 = i32::MAX as u32;

/// Whether `timeout` ticks have passed from `last_feed` to `now`, both readings of a counter that
/// wraps at 2^32.
pub const fn elapsed(now: u32, last_feed: u32, timeout: u32) -> bool {
    now.wrapping_sub(last_feed) >= timeout
}

/// What a checkpoint that expired does when the next feed comes: the `supervision-after-expiry`
/// policy itself. `Latch` leaves it expired until it is stopped and started again, `Rearm` starts
/// it again on the feed.
pub use crate::policy::SupervisionAfterExpiry as AfterExpiry;

/// The supervisor a build has: `SUPERVISION_CHECKPOINTS` checkpoints.
pub type BuildSupervisor = Supervisor<{ crate::caps::SUPERVISION_CHECKPOINTS }>;

impl BuildSupervisor {
    /// A supervisor of the build's size, under the build's `supervision-after-expiry` policy.
    pub fn for_build() -> Self {
        Self::new(crate::policy::SessionPolicy::default().supervision_after_expiry)
    }
}

/// Why a checkpoint could not be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartRefused {
    /// There is no checkpoint of that number.
    NoSuchCheckpoint,
    /// The timeout is `0` or longer than [`MAX_TIMEOUT_TICKS`].
    TimeoutOutOfRange,
}

/// What a request to stop a checkpoint came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The checkpoint is not supervised now.
    Stopped,
    /// Its expiry hook is running; the checkpoint does not stop until the hook is done.
    Refused,
    /// There is no checkpoint of that number.
    NoSuchCheckpoint,
}

/// The expiry hooks a [`Supervisor::check`] asks the host to run, one per checkpoint that expired.
/// The host runs each and calls [`Supervisor::hook_done`] for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Check {
    expired: u64,
}

impl Check {
    /// Whether checkpoint `index` expired and its hook is to run.
    pub const fn hook(self, index: usize) -> bool {
        index < 64 && self.expired & (1 << index) != 0
    }

    /// Whether no checkpoint expired.
    pub const fn is_clear(self) -> bool {
        self.expired == 0
    }
}

struct DeadlineBinding {
    duties: DutyOutbox,
}

impl DeadlineBinding {
    const ARM: u8 = 1 << 0;
    const CANCEL: u8 = 1 << 1;
    const HOOK: u8 = 1 << 2;
}

impl SupervisionActions for DeadlineBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn arm_deadline(&mut self) {
        self.duties.record(Self::ARM);
    }

    fn cancel_deadline(&mut self) {
        self.duties.record(Self::CANCEL);
    }

    fn run_expiry_hook(&mut self) {
        self.duties.record(Self::HOOK);
    }
}

struct Checkpoint {
    engine: Engine<SupervisionPolicy<DeadlineBinding>>,
    last_feed: u32,
    timeout: u32,
}

impl Checkpoint {
    fn new() -> Self {
        let mut engine = Engine::new(built_under_constant_id(
            SupervisionPolicy::new_with_session_id(
                SUPERVISION_SESSION_ID,
                DeadlineBinding {
                    duties: DutyOutbox::default(),
                },
            ),
            "the supervision session id",
        ));
        // W3C SCXML 3.3: enter the initial `Disarmed` leaf. Entering it is the start and asks for
        // nothing, so the duty it recorded is dropped.
        engine.initialize();
        let _ = engine.policy().actions().duties.take();
        Self {
            engine,
            last_feed: 0,
            timeout: 0,
        }
    }

    fn drive(&mut self, event: SupervisionEvent) -> Duties {
        self.engine.process_event(event);
        self.engine.policy().actions().duties.take()
    }

    fn state(&self) -> SupervisionState {
        self.engine.get_current_state()
    }
}

/// `N` checkpoints and the rule that the node is healthy only while all of them are armed.
pub struct Supervisor<const N: usize> {
    checkpoints: [Checkpoint; N],
    after_expiry: AfterExpiry,
}

impl<const N: usize> Supervisor<N> {
    /// `N` checkpoints, none supervised, and what an expired one does on the next feed.
    pub fn new(after_expiry: AfterExpiry) -> Self {
        assert!(N <= 64, "the expiry set of a check is one 64-bit word");
        Self {
            checkpoints: core::array::from_fn(|_| Checkpoint::new()),
            after_expiry,
        }
    }

    /// Begin supervising checkpoint `index`: its deadline is `timeout` ticks after `now`, and
    /// after each feed. A checkpoint that is already supervised is not started again.
    pub fn start(&mut self, index: usize, now: u32, timeout: u32) -> Result<(), StartRefused> {
        if timeout == 0 || timeout > MAX_TIMEOUT_TICKS {
            return Err(StartRefused::TimeoutOutOfRange);
        }
        let checkpoint = self
            .checkpoints
            .get_mut(index)
            .ok_or(StartRefused::NoSuchCheckpoint)?;
        if checkpoint.state() == SupervisionState::Disarmed {
            checkpoint.last_feed = now;
            checkpoint.timeout = timeout;
            checkpoint.drive(SupervisionEvent::SupervisionStart);
        }
        Ok(())
    }

    /// The application made progress at `now`. Ignored by a checkpoint that is not armed, except
    /// that under [`AfterExpiry::Rearm`] a feed to one that expired starts it again.
    pub fn feed(&mut self, index: usize, now: u32) {
        let after_expiry = self.after_expiry;
        let Some(checkpoint) = self.checkpoints.get_mut(index) else {
            return;
        };
        match checkpoint.state() {
            SupervisionState::Armed => {
                checkpoint.last_feed = now;
                checkpoint.drive(SupervisionEvent::SupervisionFeed);
            }
            SupervisionState::Expired if after_expiry == AfterExpiry::Rearm => {
                checkpoint.last_feed = now;
                checkpoint.drive(SupervisionEvent::SupervisionRearm);
            }
            _ => {}
        }
    }

    /// Stop supervising checkpoint `index`.
    pub fn stop(&mut self, index: usize) -> Stop {
        let Some(checkpoint) = self.checkpoints.get_mut(index) else {
            return Stop::NoSuchCheckpoint;
        };
        if checkpoint.state() == SupervisionState::Expiring {
            return Stop::Refused;
        }
        checkpoint.drive(SupervisionEvent::SupervisionStop);
        Stop::Stopped
    }

    /// Look at every armed checkpoint at `now`. Each whose deadline has passed expires, and the
    /// result says which hooks the host is to run.
    pub fn check(&mut self, now: u32) -> Check {
        let mut check = Check::default();
        for (index, checkpoint) in self.checkpoints.iter_mut().enumerate() {
            if checkpoint.state() == SupervisionState::Armed
                && elapsed(now, checkpoint.last_feed, checkpoint.timeout)
            {
                let duties = checkpoint.drive(SupervisionEvent::DeadlineExpired);
                if duties.has(DeadlineBinding::HOOK) {
                    check.expired |= 1 << index;
                }
            }
        }
        check
    }

    /// The expiry hook of checkpoint `index` returned.
    pub fn hook_done(&mut self, index: usize) {
        if let Some(checkpoint) = self.checkpoints.get_mut(index) {
            if checkpoint.state() == SupervisionState::Expiring {
                checkpoint.drive(SupervisionEvent::HookDone);
            }
        }
    }

    /// The state of checkpoint `index`, or `None` if there is none.
    pub fn state(&self, index: usize) -> Option<SupervisionState> {
        self.checkpoints.get(index).map(Checkpoint::state)
    }

    /// Whether the node is healthy: at least one checkpoint is supervised and every checkpoint
    /// that is supervised is armed. A supervisor with nothing under watch is not healthy, so a
    /// node that feeds a hardware watchdog from here does not feed it on the strength of nothing.
    pub fn is_healthy(&self) -> bool {
        let mut any = false;
        for checkpoint in &self.checkpoints {
            match checkpoint.state() {
                SupervisionState::Armed => any = true,
                SupervisionState::Disarmed => {}
                SupervisionState::Expiring | SupervisionState::Expired => return false,
            }
        }
        any
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[test]
    fn a_deadline_is_a_difference_taken_modulo_the_counter() {
        assert!(!elapsed(100, 100, 5));
        assert!(!elapsed(104, 100, 5));
        assert!(elapsed(105, 100, 5));
        // The counter went round between the feed and the check: 10 ticks passed.
        assert!(elapsed(5, u32::MAX - 4, 10));
        assert!(!elapsed(4, u32::MAX - 4, 10));
    }

    #[test]
    fn the_build_supervisor_has_the_builds_checkpoints_and_none_supervised() {
        let supervisor = BuildSupervisor::for_build();
        assert!(supervisor
            .state(crate::caps::SUPERVISION_CHECKPOINTS - 1)
            .is_some());
        assert!(supervisor
            .state(crate::caps::SUPERVISION_CHECKPOINTS)
            .is_none());
        assert!(!supervisor.is_healthy());
    }

    #[test]
    fn a_checkpoint_armed_and_fed_does_not_expire_and_one_not_fed_does() {
        let mut supervisor = Supervisor::<2>::new(AfterExpiry::Latch);
        supervisor.start(0, 0, 10).unwrap();
        supervisor.start(1, 0, 10).unwrap();
        assert!(supervisor.is_healthy());

        supervisor.feed(0, 9);
        supervisor.feed(1, 9);
        assert!(supervisor.check(18).is_clear(), "both were fed at 9");
        supervisor.feed(0, 18);
        let check = supervisor.check(19);
        assert!(
            check.hook(1) && !check.hook(0),
            "only the one not fed expired"
        );
        assert!(!supervisor.is_healthy(), "a hung checkpoint stops the feed");
    }

    #[test]
    fn the_hook_runs_once_per_expiry_and_the_checkpoint_does_not_stop_while_it_runs() {
        let mut supervisor = Supervisor::<1>::new(AfterExpiry::Latch);
        supervisor.start(0, 0, 5).unwrap();
        assert!(supervisor.check(5).hook(0));
        assert_eq!(supervisor.state(0), Some(SupervisionState::Expiring));
        assert!(
            supervisor.check(50).is_clear(),
            "the hook is not asked for twice"
        );
        assert_eq!(supervisor.stop(0), Stop::Refused);
        assert_eq!(supervisor.state(0), Some(SupervisionState::Expiring));

        supervisor.hook_done(0);
        assert_eq!(supervisor.state(0), Some(SupervisionState::Expired));
        assert_eq!(supervisor.stop(0), Stop::Stopped);
        assert_eq!(supervisor.state(0), Some(SupervisionState::Disarmed));
    }

    #[test]
    fn a_latched_checkpoint_ignores_a_late_feed_and_a_rearming_one_takes_it() {
        for (policy, expect) in [
            (AfterExpiry::Latch, SupervisionState::Expired),
            (AfterExpiry::Rearm, SupervisionState::Armed),
        ] {
            let mut supervisor = Supervisor::<1>::new(policy);
            supervisor.start(0, 0, 5).unwrap();
            supervisor.check(5);
            supervisor.hook_done(0);
            supervisor.feed(0, 6);
            assert_eq!(supervisor.state(0), Some(expect), "{policy:?}");
        }
    }

    #[test]
    fn a_latched_checkpoint_is_supervised_again_by_stopping_and_starting_it() {
        let mut supervisor = Supervisor::<1>::new(AfterExpiry::Latch);
        supervisor.start(0, 0, 5).unwrap();
        supervisor.check(5);
        supervisor.hook_done(0);
        supervisor.stop(0);
        supervisor.start(0, 100, 5).unwrap();
        assert!(supervisor.is_healthy());
        assert!(supervisor.check(104).is_clear());
        assert!(supervisor.check(105).hook(0));
    }

    #[test]
    fn nothing_under_watch_is_not_healthy_and_a_stopped_checkpoint_does_not_count() {
        let mut supervisor = Supervisor::<2>::new(AfterExpiry::Latch);
        assert!(!supervisor.is_healthy(), "no checkpoint is supervised");
        supervisor.start(0, 0, 5).unwrap();
        assert!(
            supervisor.is_healthy(),
            "the other is not supervised, and does not count"
        );
        supervisor.stop(0);
        assert!(!supervisor.is_healthy());
    }

    #[test]
    fn a_timeout_out_of_range_and_a_missing_checkpoint_are_refused_where_they_are_set() {
        let mut supervisor = Supervisor::<1>::new(AfterExpiry::Latch);
        assert_eq!(
            supervisor.start(0, 0, 0),
            Err(StartRefused::TimeoutOutOfRange)
        );
        assert_eq!(
            supervisor.start(0, 0, MAX_TIMEOUT_TICKS + 1),
            Err(StartRefused::TimeoutOutOfRange)
        );
        assert_eq!(supervisor.start(0, 0, MAX_TIMEOUT_TICKS), Ok(()));
        assert_eq!(
            supervisor.start(1, 0, 5),
            Err(StartRefused::NoSuchCheckpoint)
        );
        assert_eq!(supervisor.stop(1), Stop::NoSuchCheckpoint);
        assert_eq!(supervisor.state(1), None);
    }

    /// Every order of the five operations, up to length 6, over one checkpoint, under both
    /// policies: a hook is running exactly while one was asked for and not reported done, and
    /// nothing but the hook's end takes a checkpoint out of `Expiring`.
    #[test]
    fn whatever_the_order_of_events_the_rules_of_the_machine_hold() {
        #[derive(Clone, Copy, Debug)]
        enum Op {
            Start,
            Feed,
            Stop,
            Check,
            HookDone,
        }
        const OPS: [Op; 5] = [Op::Start, Op::Feed, Op::Stop, Op::Check, Op::HookDone];
        let mut sequences: Vec<Vec<Op>> = std::vec![Vec::new()];
        for _ in 0..6 {
            let mut next = Vec::new();
            for sequence in &sequences {
                for op in OPS {
                    let mut longer = sequence.clone();
                    longer.push(op);
                    next.push(longer);
                }
            }
            for sequence in &next {
                run(sequence);
            }
            sequences = next;
        }

        fn run(sequence: &[Op]) {
            for policy in [AfterExpiry::Latch, AfterExpiry::Rearm] {
                let mut supervisor = Supervisor::<1>::new(policy);
                let mut now = 0u32;
                let mut hooks_asked = 0u32;
                let mut hooks_done = 0u32;
                for op in sequence {
                    now += 3;
                    let before = supervisor.state(0).unwrap();
                    match op {
                        Op::Start => {
                            let _ = supervisor.start(0, now, 4);
                        }
                        Op::Feed => supervisor.feed(0, now),
                        Op::Stop => {
                            let stopped = supervisor.stop(0);
                            assert_eq!(
                                stopped == Stop::Refused,
                                before == SupervisionState::Expiring,
                                "{sequence:?}"
                            );
                        }
                        Op::Check => {
                            if supervisor.check(now).hook(0) {
                                hooks_asked += 1;
                            }
                        }
                        Op::HookDone => {
                            if before == SupervisionState::Expiring {
                                hooks_done += 1;
                            }
                            supervisor.hook_done(0);
                        }
                    }
                    let after = supervisor.state(0).unwrap();
                    assert_eq!(
                        after == SupervisionState::Expiring,
                        hooks_asked > hooks_done,
                        "a hook is running exactly while one was asked and not done: {sequence:?}"
                    );
                    if before == SupervisionState::Expiring && !matches!(op, Op::HookDone) {
                        assert_eq!(after, SupervisionState::Expiring, "{sequence:?}");
                    }
                }
            }
        }
    }
}
