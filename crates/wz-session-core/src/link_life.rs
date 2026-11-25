// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one link of a session that dials its endpoints and takes no face beside the one it dials,
//! as a value with no I/O ([`UnicastLink`]): where the link stands, what an input at a time comes
//! to, and what the link's owner does about it ([`Effects`]).
//!
//! The life itself is the [`unicast_link`](crate::unicast_link) machine; this value holds the
//! numbers the machine does not read (the endpoint dialled, the deadlines, the end of a wait) and
//! raises the one event each input comes to. The owner holds the I/O: it dials the endpoint an
//! effect names, begins the handshake, pumps the established link, and reports what came of each
//! as the next input, with the time it read after doing it.
//!
//! | where | input | what follows |
//! |---|---|---|
//! | `Idle` | `Open` | dial the first endpoint; none: the session ends |
//! | `Dialing` | `DialPending` | the dial is given up `open_timeout_ms` from now |
//! | `Dialing` | `DialMade` | begin the handshake, given up at the dial's deadline (`open_timeout_ms` from now for a dial answered at once) |
//! | `Dialing` | `HandshakeBegun` | `Handshaking` |
//! | `Dialing` | `DialRefused`, `HandshakeRefused(Endpoint)`, or the deadline | dial the next endpoint; none left: back off or end |
//! | `Dialing` | `HandshakeRefused(Task)` | no endpoint is dialled further: back off or end |
//! | `Dialing` | `HandshakeRefused(Fatal)` | the session ends |
//! | `Handshaking` | `Established` | `Up` |
//! | `Handshaking` | `Ended`, or the deadline | end the handshake; dial the next endpoint; none left: back off or end |
//! | `Up` | `Ended` | lose the link; dial the first endpoint at once, or end |
//! | `Backoff` | its end | dial the first endpoint |
//! | `Idle` | `Taken` | a link accepted on a port: its handshake runs, given up `accept_timeout_ms` from now |
//! | `Handshaking` | `HeldElsewhere` | end the handshake; stand by (`Held`) |
//! | `Held` | `NodeFree` | dial the first endpoint |
//! | any but `Closed` | `Close` | let go of the dial or the link; `Closed` |
//!
//! "Back off or end": the session dials every endpoint again `redial_ms` after the dials ended,
//! counted from the time of the input that ended them, once its link has been up and when it has
//! a `redial_ms`; before that, or without one, it ends. An established link that ends is dialled
//! again at once, from the first endpoint. The cooperative engine keeps one such link for each
//! face it holds, and carries out its effects with the face's I/O.
//!
//! A face taken beside the dial role's ([`LinkRole::Taken`]) is dialled once at most and goes
//! with its link: where the dial role's face would dial on, back off, stand by or end the
//! session, a taken face's link is closed and the owner takes the face out ([`Effects::removes`]).
//!
//! A handshake that completed is established even when its link ended after: the owner reports
//! `Established` before `Ended` when it reads both at one look.

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

#[cfg(feature = "storage-profile")]
use crate::driver_loop::DriverOutcome;
use crate::duty_outbox::{Duties, DutyOutbox};
use crate::unicast_link::{
    UnicastLinkActions, UnicastLinkEvent, UnicastLinkPolicy, UnicastLinkState,
};

/// The id the link's machine is built under (SCE ADR 0045: the host gives a machine its id). A
/// constant, so the generated constructor never refuses it.
const UNICAST_LINK_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-unicast-link");

/// The host binding of the machine: each action body records its duty.
#[derive(Default)]
struct LinkBinding {
    duties: DutyOutbox,
}

impl LinkBinding {
    const DIAL: u8 = 1 << 0;
    const BEGIN_HANDSHAKE: u8 = 1 << 1;
    const BRING_UP: u8 = 1 << 2;
    const END_HANDSHAKE: u8 = 1 << 3;
    const LOSE: u8 = 1 << 4;
    const BACKOFF: u8 = 1 << 5;
    const END_SESSION: u8 = 1 << 6;
    const LET_GO: u8 = 1 << 7;
}

impl UnicastLinkActions for LinkBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn arm_backoff(&mut self) {
        self.duties.record(Self::BACKOFF);
    }

    fn begin_handshake(&mut self) {
        self.duties.record(Self::BEGIN_HANDSHAKE);
    }

    fn bring_up(&mut self) {
        self.duties.record(Self::BRING_UP);
    }

    fn dial_endpoint(&mut self) {
        self.duties.record(Self::DIAL);
    }

    fn end_handshake(&mut self) {
        self.duties.record(Self::END_HANDSHAKE);
    }

    fn end_session(&mut self) {
        self.duties.record(Self::END_SESSION);
    }

    fn let_go(&mut self) {
        self.duties.record(Self::LET_GO);
    }

    fn lose_link(&mut self) {
        self.duties.record(Self::LOSE);
    }
}

/// The times a link's life is counted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTimes {
    /// How long a dial, and the handshake that follows it, may take, in milliseconds.
    pub open_timeout_ms: u64,
    /// How long the session waits to dial its endpoints again once none answered, in
    /// milliseconds; `None` for a session that dials none again.
    pub redial_ms: Option<u64>,
    /// How often a dial under way is asked whether it was answered, in milliseconds.
    pub dial_look_ms: u64,
    /// How long the handshake of a link accepted on a port may take, in milliseconds.
    pub accept_timeout_ms: u64,
}

/// Which face of the session the link is: the one that dials the session's endpoints, kept for
/// as long as the session is, or one taken beside it, which goes with its link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    /// The dial role's face.
    Dial,
    /// A face taken beside the dial role's: a link accepted on a port, or an endpoint attached.
    Taken,
}

/// Why the handshake a made dial asked for could not begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// For the endpoint's own reason: the next endpoint is dialled.
    Endpoint,
    /// For a reason the next endpoint would meet the same (no task for the link): no endpoint is
    /// dialled further.
    Task,
    /// For a reason the session cannot go on past (no entropy for the handshake's cookie key).
    Fatal,
}

/// What the link's owner reports to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkInput {
    /// The session opens, or a taken face's endpoint is attached.
    Open,
    /// A taken face holds a link accepted on a port, whose handshake runs.
    Taken,
    /// The dial the link asked for is under way.
    DialPending,
    /// The dial made a link.
    DialMade,
    /// The dial was refused.
    DialRefused,
    /// The handshake the link asked for is under way.
    HandshakeBegun,
    /// The handshake the link asked for could not begin.
    HandshakeRefused(Refused),
    /// The handshake completed.
    Established,
    /// The link's pump ended: a lease that ran out, a Close from the peer, a read that failed.
    Ended,
    /// The handshake ended because the node it reached is held by another face.
    HeldElsewhere,
    /// No other face holds the node the dial role stands by for.
    NodeFree,
    /// The session closes.
    Close,
    /// Only the time moved.
    Tick,
}

/// Where the link stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPhase {
    /// Not opened yet.
    Idle,
    /// Endpoint `row` is being dialled.
    Dialing {
        /// The endpoint's row.
        row: usize,
    },
    /// The handshake of the link endpoint `row` made runs, given up at `deadline_us`.
    Handshaking {
        /// The endpoint's row.
        row: usize,
        /// When the handshake is given up.
        deadline_us: u64,
    },
    /// Established.
    Up,
    /// Waiting to dial every endpoint again at `until_us`.
    Backoff {
        /// When the endpoints are dialled again.
        until_us: u64,
    },
    /// The dial role standing by while another face holds the node its link reached.
    Held,
    /// Closed, ended, or, for a taken face, gone.
    Closed,
}

/// What the owner does after an input, in this order: let go of what a close leaves
/// ([`Self::let_go`]), end the handshake ([`Self::end_handshake`]), lose the established link
/// ([`Self::lose`]), bring the link up ([`Self::bring_up`]), begin the handshake
/// ([`Self::begin_handshake`]), dial ([`Self::dial`]); and it ends the session
/// ([`Self::ends_session`]) or waits ([`Self::backs_off`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effects {
    duties: Duties,
    row: usize,
    gone: bool,
}

impl Effects {
    /// Let go of the dial under way or of the link: the session closes.
    pub fn let_go(self) -> bool {
        self.duties.has(LinkBinding::LET_GO)
    }

    /// End the task of a handshake that is over.
    pub fn end_handshake(self) -> bool {
        self.duties.has(LinkBinding::END_HANDSHAKE)
    }

    /// The established link ended: what its peer declared goes with it.
    pub fn lose(self) -> bool {
        self.duties.has(LinkBinding::LOSE)
    }

    /// The handshake completed: the link carries the session.
    pub fn bring_up(self) -> bool {
        self.duties.has(LinkBinding::BRING_UP)
    }

    /// The dial made a link: begin its handshake, and report [`LinkInput::HandshakeBegun`] or
    /// [`LinkInput::HandshakeRefused`].
    pub fn begin_handshake(self) -> bool {
        self.duties.has(LinkBinding::BEGIN_HANDSHAKE)
    }

    /// Dial the endpoint of this row, and report what the dial came to.
    pub fn dial(self) -> Option<usize> {
        self.duties.has(LinkBinding::DIAL).then_some(self.row)
    }

    /// No endpoint answered: wait to dial them all again ([`UnicastLink::wake_at`]).
    pub fn backs_off(self) -> bool {
        self.duties.has(LinkBinding::BACKOFF)
    }

    /// The link is gone and none is dialled again: the session ends.
    pub fn ends_session(self) -> bool {
        self.duties.has(LinkBinding::END_SESSION)
    }

    /// A taken face's link is gone: the face goes, with its tables.
    pub fn removes(self) -> bool {
        self.gone
    }

    /// Nothing to do.
    pub fn is_empty(self) -> bool {
        self.duties.is_empty() && !self.gone
    }
}

/// Where a dial of `Dialing` stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialStage {
    /// Asked for, not reported yet.
    Owed,
    /// Under way, given up at the link's deadline.
    Pending,
    /// Made a link whose handshake was asked for, not reported yet.
    Made,
}

/// The numbers the machine does not read.
#[derive(Debug, Clone, Copy)]
struct LinkData {
    times: LinkTimes,
    role: LinkRole,
    /// The endpoints the session dials, rows `0..endpoints`.
    endpoints: usize,
    /// The endpoint dialled, or whose link's handshake runs.
    row: usize,
    stage: DialStage,
    /// When the dial under way, and the handshake after it, are given up.
    deadline_us: u64,
    /// When a wait to dial again is over.
    until_us: u64,
    /// Whether the link has been up: only then does the session dial again after its dials all
    /// failed, as an open that no endpoint answers fails.
    has_been_up: bool,
}

impl LinkData {
    /// Whether the session dials its endpoints again once they all failed.
    fn redials(&self) -> bool {
        self.has_been_up && self.times.redial_ms.is_some()
    }

    /// When a deadline set at `now_us` passes.
    fn deadline_from(&self, now_us: u64) -> u64 {
        now_us.saturating_add(self.times.open_timeout_ms.saturating_mul(1000))
    }
}

/// How a walk over the endpoints goes on, by where the link stands: the events that dial the next
/// endpoint, back off and end the session from there.
struct WalkEvents {
    next: UnicastLinkEvent,
    exhausted: UnicastLinkEvent,
    ended: UnicastLinkEvent,
    gone: UnicastLinkEvent,
}

const FROM_DIALING: WalkEvents = WalkEvents {
    next: UnicastLinkEvent::DialNext,
    exhausted: UnicastLinkEvent::DialExhausted,
    ended: UnicastLinkEvent::DialEnded,
    gone: UnicastLinkEvent::DialGone,
};

const FROM_HANDSHAKING: WalkEvents = WalkEvents {
    next: UnicastLinkEvent::HandshakeNext,
    exhausted: UnicastLinkEvent::HandshakeExhausted,
    ended: UnicastLinkEvent::HandshakeEnded,
    gone: UnicastLinkEvent::HandshakeGone,
};

/// The one link of a session that holds one face, with its life's machine.
pub struct UnicastLink {
    engine: Engine<UnicastLinkPolicy<LinkBinding>>,
    data: LinkData,
}

impl UnicastLink {
    /// Build the link of a face of `role` of a session that dials `endpoints` endpoints under
    /// `times` in `slot`, where its owner keeps it, `Idle`, and lend it. Built in place: the machine's engine is
    /// the largest part, and a value moved into its place would be a slot of each frame it passed
    /// through. Nothing of it needs dropping: the machine holds no resource.
    pub fn init_in(
        slot: &mut MaybeUninit<Self>,
        times: LinkTimes,
        role: LinkRole,
        endpoints: usize,
    ) -> &mut Self {
        let at = slot.as_mut_ptr();
        // SAFETY: `at` points at storage for one link that holds no value. The numbers are
        // written to their field, and the machine is built in its field by `new_in_place`, which
        // writes every field of the engine; with both of its two fields written the link is
        // whole, and it is lent as such for as long as `slot` is.
        let link = unsafe {
            addr_of_mut!((*at).data).write(LinkData {
                times,
                role,
                endpoints,
                row: 0,
                stage: DialStage::Owed,
                deadline_us: 0,
                until_us: 0,
                has_been_up: false,
            });
            let engine = &mut *addr_of_mut!((*at).engine)
                .cast::<MaybeUninit<Engine<UnicastLinkPolicy<LinkBinding>>>>();
            Engine::new_in_place(
                engine,
                UnicastLinkPolicy::new_with_checked_session_id(
                    UNICAST_LINK_SESSION_ID,
                    LinkBinding::default(),
                ),
            );
            &mut *at
        };
        // W3C SCXML 3.3: enter the initial `Idle` leaf, which asks for nothing.
        link.engine
            .initialize()
            .unwrap_or_else(|never| match never {});
        link
    }

    /// [`Self::init_in`] for an owner that keeps the link as a field of a value it moves into
    /// its place (a face's record), built in a slot of this frame and moved out whole.
    pub fn new(times: LinkTimes, role: LinkRole, endpoints: usize) -> Self {
        let mut slot = MaybeUninit::uninit();
        Self::init_in(&mut slot, times, role, endpoints);
        // SAFETY: `init_in` wrote both fields of the link in `slot`. The machine holds no
        // address of itself (its engine is built in place for the stack alone), so the link it
        // makes is whole wherever it is moved.
        unsafe { slot.assume_init() }
    }

    /// Which face of the session the link is.
    pub fn role(&self) -> LinkRole {
        self.data.role
    }

    /// Where the link stands.
    pub fn phase(&self) -> LinkPhase {
        let data = &self.data;
        match self.engine.get_current_state() {
            UnicastLinkState::Idle => LinkPhase::Idle,
            UnicastLinkState::Dialing => LinkPhase::Dialing { row: data.row },
            UnicastLinkState::Handshaking => LinkPhase::Handshaking {
                row: data.row,
                deadline_us: data.deadline_us,
            },
            UnicastLinkState::Up => LinkPhase::Up,
            UnicastLinkState::Backoff => LinkPhase::Backoff {
                until_us: data.until_us,
            },
            UnicastLinkState::Held => LinkPhase::Held,
            UnicastLinkState::Closed => LinkPhase::Closed,
        }
    }

    /// When the owner is next to look at the link though it brings no input, `now_us` being
    /// the time now: at once while a dial or a handshake it asked for is owed a report, at the
    /// next look of a dial under way or its deadline when that is sooner, at a handshake's
    /// deadline, and at the end of a wait. `None` for a link that is up, idle, standing by or
    /// closed, which only an input moves on.
    pub fn wake_at(&self, now_us: u64) -> Option<u64> {
        let data = &self.data;
        match self.engine.get_current_state() {
            UnicastLinkState::Dialing => match data.stage {
                DialStage::Owed | DialStage::Made => Some(now_us),
                DialStage::Pending => Some(
                    now_us
                        .saturating_add(data.times.dial_look_ms.saturating_mul(1000))
                        .min(data.deadline_us),
                ),
            },
            UnicastLinkState::Handshaking => Some(data.deadline_us),
            UnicastLinkState::Backoff => Some(data.until_us),
            UnicastLinkState::Idle
            | UnicastLinkState::Up
            | UnicastLinkState::Held
            | UnicastLinkState::Closed => None,
        }
    }

    /// What `input`, reported at `now_us`, comes to: the link moves on, and the owner is told
    /// what to do. An input the link has no use for where it stands moves nothing.
    pub fn input(&mut self, input: LinkInput, now_us: u64) -> Effects {
        if input == LinkInput::Close {
            return self.drive(UnicastLinkEvent::LinkClose);
        }
        let event = match self.engine.get_current_state() {
            UnicastLinkState::Idle => match input {
                LinkInput::Open => self.walk_from_idle(),
                LinkInput::Taken => {
                    self.data.row = 0;
                    self.data.deadline_us = now_us
                        .saturating_add(self.data.times.accept_timeout_ms.saturating_mul(1000));
                    Some(UnicastLinkEvent::LinkTaken)
                }
                _ => None,
            },
            UnicastLinkState::Dialing => self.dialing(input, now_us),
            UnicastLinkState::Handshaking => match input {
                LinkInput::Established => {
                    self.data.has_been_up = true;
                    Some(UnicastLinkEvent::HandshakeDone)
                }
                LinkInput::Ended => Some(self.walk_on(now_us, &FROM_HANDSHAKING)),
                LinkInput::HeldElsewhere => Some(match self.data.role {
                    LinkRole::Dial => UnicastLinkEvent::HandshakeHeld,
                    LinkRole::Taken => UnicastLinkEvent::HandshakeGone,
                }),
                _ if now_us >= self.data.deadline_us => {
                    Some(self.walk_on(now_us, &FROM_HANDSHAKING))
                }
                _ => None,
            },
            UnicastLinkState::Up => match input {
                LinkInput::Ended => Some(self.lost()),
                _ => None,
            },
            UnicastLinkState::Backoff if now_us >= self.data.until_us => {
                self.dial_row(0);
                Some(UnicastLinkEvent::BackoffOver)
            }
            UnicastLinkState::Held => match input {
                LinkInput::NodeFree => {
                    self.dial_row(0);
                    Some(UnicastLinkEvent::HeldOver)
                }
                _ => None,
            },
            UnicastLinkState::Backoff | UnicastLinkState::Closed => None,
        };
        match event {
            Some(event) => self.drive(event),
            None => Effects::default(),
        }
    }

    /// [`Self::input`] for what a pump of the established link came to: one that terminated
    /// ended the link, and one stopped at its iteration cap goes on.
    #[cfg(feature = "storage-profile")]
    pub fn pumped(&mut self, outcome: DriverOutcome, now_us: u64) -> Effects {
        match outcome {
            DriverOutcome::Terminated => self.input(LinkInput::Ended, now_us),
            DriverOutcome::IterationLimit => Effects::default(),
        }
    }

    /// What `input` comes to while an endpoint is being dialled.
    fn dialing(&mut self, input: LinkInput, now_us: u64) -> Option<UnicastLinkEvent> {
        let stage = self.data.stage;
        match input {
            LinkInput::DialPending if stage == DialStage::Owed => {
                self.data.deadline_us = self.data.deadline_from(now_us);
                self.data.stage = DialStage::Pending;
                None
            }
            LinkInput::DialMade if stage != DialStage::Made => {
                // A dial answered at once has its deadline from now; one answered later keeps
                // the deadline it was given when it was begun.
                if stage == DialStage::Owed {
                    self.data.deadline_us = self.data.deadline_from(now_us);
                }
                self.data.stage = DialStage::Made;
                Some(UnicastLinkEvent::DialMade)
            }
            LinkInput::HandshakeBegun if stage == DialStage::Made => {
                Some(UnicastLinkEvent::HandshakeBegun)
            }
            LinkInput::DialRefused if stage != DialStage::Made => {
                Some(self.walk_on(now_us, &FROM_DIALING))
            }
            LinkInput::HandshakeRefused(why) if stage == DialStage::Made => Some(match why {
                Refused::Endpoint => self.walk_on(now_us, &FROM_DIALING),
                Refused::Task => self.walk(self.data.endpoints, now_us, &FROM_DIALING),
                Refused::Fatal => UnicastLinkEvent::DialEnded,
            }),
            _ if stage == DialStage::Pending && now_us >= self.data.deadline_us => {
                Some(self.walk_on(now_us, &FROM_DIALING))
            }
            _ => None,
        }
    }

    /// The event the session's open comes to: the first endpoint dialled, or the session ended
    /// when it has none.
    fn walk_from_idle(&mut self) -> Option<UnicastLinkEvent> {
        if self.data.endpoints == 0 {
            return Some(UnicastLinkEvent::DialEnded);
        }
        self.dial_row(0);
        Some(UnicastLinkEvent::LinkOpen)
    }

    /// The event that takes the walk over the endpoints on to `row` at `now_us`, by `from`:
    /// that endpoint dialled while there is one; past the last, a wait counted from `now_us` when
    /// the session dials again, and its end otherwise. A taken face walks nowhere: it goes.
    fn walk(&mut self, row: usize, now_us: u64, from: &WalkEvents) -> UnicastLinkEvent {
        if self.data.role == LinkRole::Taken {
            return from.gone;
        }
        if row < self.data.endpoints {
            self.dial_row(row);
            return from.next;
        }
        match self.data.times.redial_ms {
            Some(ms) if self.data.redials() => {
                self.data.until_us = now_us.saturating_add(ms.saturating_mul(1000));
                from.exhausted
            }
            _ => from.ended,
        }
    }

    /// The event that takes the walk on past the endpoint dialled now ([`Self::walk`]).
    fn walk_on(&mut self, now_us: u64, from: &WalkEvents) -> UnicastLinkEvent {
        // Only a row below `endpoints`, itself a `usize`, is dialled, so the next one never
        // saturates; a saturated row would still lie past the last endpoint.
        self.walk(self.data.row.saturating_add(1), now_us, from)
    }

    /// The event an established link that ended comes to: dialled again at once from the first
    /// endpoint, or the session's end; for a taken face, the face gone.
    fn lost(&mut self) -> UnicastLinkEvent {
        if self.data.role == LinkRole::Taken {
            return UnicastLinkEvent::LinkGone;
        }
        if self.data.redials() && self.data.endpoints > 0 {
            self.dial_row(0);
            UnicastLinkEvent::LinkLost
        } else {
            UnicastLinkEvent::LinkEnded
        }
    }

    /// Ready the dial of `row`, which the event raised next asks for.
    fn dial_row(&mut self, row: usize) {
        self.data.row = row;
        self.data.stage = DialStage::Owed;
    }

    /// Raise `event` and take the duties it ran.
    fn drive(&mut self, event: UnicastLinkEvent) -> Effects {
        self.engine.process_event(event);
        Effects {
            duties: self.engine.policy().actions().duties.take(),
            row: self.data.row,
            gone: matches!(
                event,
                UnicastLinkEvent::DialGone
                    | UnicastLinkEvent::HandshakeGone
                    | UnicastLinkEvent::LinkGone
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clock is the test's: every input carries the time it is reported at, in microseconds.
    const MS: u64 = 1000;
    const TIMES: LinkTimes = LinkTimes {
        open_timeout_ms: 1000,
        redial_ms: Some(5000),
        dial_look_ms: 1,
        accept_timeout_ms: 2000,
    };

    fn made(
        slot: &mut MaybeUninit<UnicastLink>,
        times: LinkTimes,
        endpoints: usize,
    ) -> &mut UnicastLink {
        UnicastLink::init_in(slot, times, LinkRole::Dial, endpoints)
    }

    /// Open, the first endpoint answered at once, its handshake completed: the link is up at
    /// `now_us`, through endpoint 0.
    fn bring_up(link: &mut UnicastLink, now_us: u64) {
        assert_eq!(link.input(LinkInput::Open, now_us).dial(), Some(0));
        assert!(link.input(LinkInput::DialMade, now_us).begin_handshake());
        assert!(link.input(LinkInput::HandshakeBegun, now_us).is_empty());
        assert!(link.input(LinkInput::Established, now_us).bring_up());
        assert_eq!(link.phase(), LinkPhase::Up);
    }

    /// An open dials the first endpoint; a dial under way is looked at each `dial_look_ms` and
    /// given up `open_timeout_ms` after it began; the handshake of the link it made keeps that
    /// deadline, and a completed handshake brings the link up. Turned red by a handshake whose
    /// deadline is counted again from the answer (`LinkInput::DialMade` in `dialing`).
    #[test]
    fn an_open_dials_the_first_endpoint_and_its_handshake_keeps_the_dials_deadline() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 2);
        assert_eq!(link.phase(), LinkPhase::Idle);
        assert_eq!(link.wake_at(0), None);
        let open = link.input(LinkInput::Open, 0);
        assert_eq!(open.dial(), Some(0));
        assert!(!open.begin_handshake());
        assert!(!open.ends_session());
        assert!(!open.backs_off());
        assert_eq!(link.phase(), LinkPhase::Dialing { row: 0 });
        assert_eq!(
            link.wake_at(0),
            Some(0),
            "a dial asked for is owed a report at once"
        );
        assert!(link.input(LinkInput::DialPending, 10).is_empty());
        assert_eq!(link.wake_at(10), Some(10 + MS), "the next look");
        assert_eq!(
            link.wake_at(999_500),
            Some(10 + 1000 * MS),
            "the deadline when it is sooner than the next look"
        );
        assert!(link.input(LinkInput::DialMade, 500 * MS).begin_handshake());
        assert_eq!(
            link.wake_at(500 * MS),
            Some(500 * MS),
            "owed a report at once"
        );
        assert!(link.input(LinkInput::HandshakeBegun, 500 * MS).is_empty());
        assert_eq!(
            link.phase(),
            LinkPhase::Handshaking {
                row: 0,
                deadline_us: 10 + 1000 * MS,
            }
        );
        assert_eq!(link.wake_at(600 * MS), Some(10 + 1000 * MS));
        assert!(link.input(LinkInput::Established, 600 * MS).bring_up());
        assert_eq!(link.phase(), LinkPhase::Up);
        assert_eq!(
            link.wake_at(600 * MS),
            None,
            "a link that is up moves on input alone"
        );
    }

    /// A dial answered at once gives its handshake `open_timeout_ms` from the time the answer
    /// was read, as the engine reads the deadline after the dial.
    #[test]
    fn a_dial_answered_at_once_counts_its_handshake_from_the_answer() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 1);
        link.input(LinkInput::Open, 0);
        link.input(LinkInput::DialMade, 200);
        link.input(LinkInput::HandshakeBegun, 300);
        assert_eq!(
            link.phase(),
            LinkPhase::Handshaking {
                row: 0,
                deadline_us: 200 + 1000 * MS,
            }
        );
    }

    /// A handshake is given up at its deadline and not before, or when its link ends first: its
    /// task is ended and the next endpoint dialled. Turned red by a deadline compared with `>`.
    #[test]
    fn a_handshake_is_given_up_at_its_deadline_or_its_end_for_the_next_endpoint() {
        for ended in [false, true] {
            let mut slot = MaybeUninit::uninit();
            let link = made(&mut slot, TIMES, 2);
            link.input(LinkInput::Open, 0);
            link.input(LinkInput::DialMade, 0);
            link.input(LinkInput::HandshakeBegun, 0);
            let deadline = 1000 * MS;
            if ended {
                let over = link.input(LinkInput::Ended, 5);
                assert!(over.end_handshake());
                assert_eq!(over.dial(), Some(1));
            } else {
                assert!(link.input(LinkInput::Tick, deadline - 1).is_empty());
                let over = link.input(LinkInput::Tick, deadline);
                assert!(over.end_handshake());
                assert_eq!(over.dial(), Some(1));
                assert!(!over.lose());
                assert!(!over.ends_session());
            }
            assert_eq!(link.phase(), LinkPhase::Dialing { row: 1 });
        }
    }

    /// A dial under way that is not answered by its deadline is given up for the next endpoint;
    /// one refused is given up at once.
    #[test]
    fn an_unanswered_dial_is_given_up_at_its_deadline_and_a_refused_one_at_once() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 3);
        link.input(LinkInput::Open, 0);
        link.input(LinkInput::DialPending, 0);
        assert!(link.input(LinkInput::Tick, 1000 * MS - 1).is_empty());
        assert_eq!(link.input(LinkInput::Tick, 1000 * MS).dial(), Some(1));
        assert_eq!(
            link.input(LinkInput::DialRefused, 1000 * MS).dial(),
            Some(2)
        );
        assert_eq!(link.phase(), LinkPhase::Dialing { row: 2 });
    }

    /// An open that no endpoint answers ends the session, whatever its `redial_ms`: a session
    /// dials again only a link it had. Turned red by a backoff before the link was ever up
    /// (`LinkData::redials` without `has_been_up`).
    #[test]
    fn an_open_no_endpoint_answers_ends_the_session() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 2);
        link.input(LinkInput::Open, 0);
        assert_eq!(link.input(LinkInput::DialRefused, 1).dial(), Some(1));
        let last = link.input(LinkInput::DialRefused, 2);
        assert!(last.ends_session());
        assert!(!last.backs_off());
        assert_eq!(last.dial(), None);
        assert_eq!(link.phase(), LinkPhase::Closed);
        assert!(
            link.input(LinkInput::Open, 3).is_empty(),
            "a closed link stays so"
        );
    }

    /// A session with no endpoint to dial is ended at its open.
    #[test]
    fn a_session_with_no_endpoint_ends_at_its_open() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 0);
        let open = link.input(LinkInput::Open, 0);
        assert!(open.ends_session());
        assert_eq!(open.dial(), None);
        assert_eq!(link.phase(), LinkPhase::Closed);
    }

    /// The order a lease that ran out sets off: the lost link is lost first and the first
    /// endpoint dialled again at once, in the same input; once every endpoint is refused the
    /// session waits `redial_ms` counted from the input that ended the dials, not from the loss,
    /// and dials the first endpoint again at the end of the wait and not before. Turned red by a
    /// wait counted from the loss (`walk`'s `now_us`), or a loss that waits before it dials.
    #[test]
    fn a_lease_that_runs_out_loses_the_link_dials_at_once_then_backs_off_from_the_last_dial() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 2);
        bring_up(link, 0);
        let lease_out = 50_000 * MS;
        let lost = link.input(LinkInput::Ended, lease_out);
        assert!(lost.lose());
        assert_eq!(lost.dial(), Some(0));
        assert!(!lost.ends_session());
        assert!(!lost.backs_off());
        // A refused dial may block for seconds before it answers.
        let first = lease_out + 3000 * MS;
        assert_eq!(link.input(LinkInput::DialRefused, first).dial(), Some(1));
        let last = first + 500 * MS;
        let off = link.input(LinkInput::DialRefused, last);
        assert!(off.backs_off());
        assert!(!off.ends_session());
        let until = last + 5000 * MS;
        assert_eq!(link.phase(), LinkPhase::Backoff { until_us: until });
        assert_eq!(link.wake_at(last), Some(until));
        assert!(link.input(LinkInput::Tick, until - 1).is_empty());
        let again = link.input(LinkInput::Tick, until);
        assert_eq!(again.dial(), Some(0));
        assert_eq!(link.phase(), LinkPhase::Dialing { row: 0 });
    }

    /// A session that dials none again ends when its established link ends, after the link is
    /// lost.
    #[test]
    fn a_lost_link_ends_a_session_that_dials_none_again() {
        let mut slot = MaybeUninit::uninit();
        let times = LinkTimes {
            redial_ms: None,
            ..TIMES
        };
        let link = made(&mut slot, times, 2);
        bring_up(link, 0);
        let lost = link.input(LinkInput::Ended, 9);
        assert!(lost.lose());
        assert!(lost.ends_session());
        assert_eq!(lost.dial(), None);
        assert_eq!(link.phase(), LinkPhase::Closed);
    }

    /// A handshake over at the last endpoint ends its task and backs off once the link has been
    /// up, or ends the session when the session dials none again.
    #[test]
    fn a_handshake_over_at_the_last_endpoint_backs_off_or_ends() {
        for redial_ms in [Some(5000), None] {
            let mut slot = MaybeUninit::uninit();
            let link = made(&mut slot, LinkTimes { redial_ms, ..TIMES }, 1);
            bring_up(link, 0);
            let lost = link.input(LinkInput::Ended, 10);
            if redial_ms.is_none() {
                assert!(lost.ends_session());
                continue;
            }
            assert_eq!(lost.dial(), Some(0));
            link.input(LinkInput::DialMade, 20);
            link.input(LinkInput::HandshakeBegun, 20);
            let over = link.input(LinkInput::Ended, 30);
            assert!(over.end_handshake());
            assert!(over.backs_off());
            assert_eq!(
                link.phase(),
                LinkPhase::Backoff {
                    until_us: 30 + 5000 * MS,
                }
            );
        }
    }

    /// A handshake that cannot begin for its endpoint's reason goes on to the next endpoint; one
    /// that cannot for a reason every endpoint would meet dials none further; one that cannot for
    /// want of entropy ends the session even where it would dial again.
    #[test]
    fn a_handshake_that_cannot_begin_goes_on_stops_the_walk_or_ends() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 3);
        link.input(LinkInput::Open, 0);
        link.input(LinkInput::DialMade, 0);
        let next = link.input(LinkInput::HandshakeRefused(Refused::Endpoint), 1);
        assert_eq!(next.dial(), Some(1));
        assert!(
            !next.end_handshake(),
            "no handshake began, so none is ended"
        );
        link.input(LinkInput::DialMade, 2);
        let task = link.input(LinkInput::HandshakeRefused(Refused::Task), 3);
        assert!(
            task.ends_session(),
            "before the link was up, no wait follows"
        );
        assert_eq!(task.dial(), None);

        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 3);
        bring_up(link, 0);
        link.input(LinkInput::Ended, 1);
        link.input(LinkInput::DialMade, 2);
        assert!(link
            .input(LinkInput::HandshakeRefused(Refused::Task), 3)
            .backs_off());

        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 3);
        bring_up(link, 0);
        link.input(LinkInput::Ended, 1);
        link.input(LinkInput::DialMade, 2);
        let fatal = link.input(LinkInput::HandshakeRefused(Refused::Fatal), 3);
        assert!(fatal.ends_session());
        assert_eq!(link.phase(), LinkPhase::Closed);
    }

    /// A handshake read completed and ended at one look is established first, and lost at the
    /// next input.
    #[test]
    fn an_established_handshake_whose_link_ended_comes_up_then_is_lost() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 1);
        link.input(LinkInput::Open, 0);
        link.input(LinkInput::DialMade, 0);
        link.input(LinkInput::HandshakeBegun, 0);
        assert!(link.input(LinkInput::Established, 5).bring_up());
        let lost = link.input(LinkInput::Ended, 5);
        assert!(lost.lose());
        assert_eq!(lost.dial(), Some(0));
    }

    /// A close lets go of the dial under way or of the link, and of nothing in a wait; a closed
    /// link moves no more.
    #[test]
    fn a_close_lets_go_of_a_dial_or_a_link_and_closes() {
        let mut slot = MaybeUninit::uninit();
        let dialing = made(&mut slot, TIMES, 1);
        dialing.input(LinkInput::Open, 0);
        assert!(dialing.input(LinkInput::Close, 1).let_go());
        assert_eq!(dialing.phase(), LinkPhase::Closed);
        assert!(dialing.input(LinkInput::Close, 2).is_empty());

        let mut slot = MaybeUninit::uninit();
        let up = made(&mut slot, TIMES, 1);
        bring_up(up, 0);
        let close = up.input(LinkInput::Close, 1);
        assert!(close.let_go());
        assert!(!close.lose());
        assert!(!close.ends_session());
        assert_eq!(up.phase(), LinkPhase::Closed);
        assert!(up.input(LinkInput::Ended, 2).is_empty());

        let mut slot = MaybeUninit::uninit();
        let waiting = made(&mut slot, TIMES, 1);
        bring_up(waiting, 0);
        waiting.input(LinkInput::Ended, 1);
        waiting.input(LinkInput::DialRefused, 2);
        assert!(matches!(waiting.phase(), LinkPhase::Backoff { .. }));
        assert!(waiting.input(LinkInput::Close, 3).is_empty());
        assert_eq!(waiting.phase(), LinkPhase::Closed);
    }

    /// The pump of an established link that terminated ended the link; one stopped at its
    /// iteration cap goes on.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn a_terminated_pump_ends_the_link_and_a_capped_one_goes_on() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 1);
        bring_up(link, 0);
        assert!(link.pumped(DriverOutcome::IterationLimit, 1).is_empty());
        assert_eq!(link.phase(), LinkPhase::Up);
        let lost = link.pumped(DriverOutcome::Terminated, 2);
        assert!(lost.lose());
        assert_eq!(lost.dial(), Some(0));
    }

    /// A face taken beside the dial role's, from a link accepted on a port.
    fn taken(slot: &mut MaybeUninit<UnicastLink>, endpoints: usize) -> &mut UnicastLink {
        UnicastLink::init_in(slot, TIMES, LinkRole::Taken, endpoints)
    }

    /// An accepted link runs its handshake for `accept_timeout_ms` from when it was taken, and a
    /// handshake over takes the face out, ending no session and dialling nothing. Turned red by a
    /// taken face that walks the endpoints (`walk` without its role).
    #[test]
    fn an_accepted_link_runs_until_its_accept_timeout_then_its_face_goes() {
        let mut slot = MaybeUninit::uninit();
        let link = taken(&mut slot, 2);
        assert!(link.input(LinkInput::Taken, 100).is_empty());
        let deadline = 100 + 2000 * MS;
        assert_eq!(
            link.phase(),
            LinkPhase::Handshaking {
                row: 0,
                deadline_us: deadline,
            }
        );
        assert!(link.input(LinkInput::Tick, deadline - 1).is_empty());
        let over = link.input(LinkInput::Tick, deadline);
        assert!(over.end_handshake());
        assert!(over.removes());
        assert!(!over.ends_session());
        assert_eq!(over.dial(), None);
        assert_eq!(link.phase(), LinkPhase::Closed);
    }

    /// A taken face's established link that ends takes the face with it, whatever the session's
    /// `redial_ms`; the dial role's lost link is never `removes`.
    #[test]
    fn a_taken_faces_lost_link_takes_the_face_and_dials_nothing() {
        let mut slot = MaybeUninit::uninit();
        let link = taken(&mut slot, 2);
        link.input(LinkInput::Taken, 0);
        assert!(link.input(LinkInput::Established, 1).bring_up());
        let lost = link.input(LinkInput::Ended, 2);
        assert!(lost.lose());
        assert!(lost.removes());
        assert!(!lost.ends_session());
        assert_eq!(lost.dial(), None);

        let mut slot = MaybeUninit::uninit();
        let dial = made(&mut slot, TIMES, 2);
        bring_up(dial, 0);
        assert!(!dial.input(LinkInput::Ended, 1).removes());
    }

    /// An attached endpoint is dialled once: a refusal takes its face out and ends no session.
    #[test]
    fn an_attached_face_is_dialled_once() {
        let mut slot = MaybeUninit::uninit();
        let link = taken(&mut slot, 1);
        assert_eq!(link.input(LinkInput::Open, 0).dial(), Some(0));
        let refused = link.input(LinkInput::DialRefused, 1);
        assert!(refused.removes());
        assert!(!refused.ends_session());
        assert_eq!(refused.dial(), None);
        assert_eq!(link.phase(), LinkPhase::Closed);
    }

    /// The dial role's handshake that reached a node another face holds ends and stands by; the
    /// time moves nothing then, and the first endpoint is dialled once the node is free. A taken
    /// face in the same place goes instead.
    #[test]
    fn a_dial_role_stands_by_for_a_held_node_and_dials_once_it_is_free() {
        let mut slot = MaybeUninit::uninit();
        let link = made(&mut slot, TIMES, 2);
        link.input(LinkInput::Open, 0);
        link.input(LinkInput::DialMade, 0);
        link.input(LinkInput::HandshakeBegun, 0);
        let held = link.input(LinkInput::HeldElsewhere, 5);
        assert!(held.end_handshake());
        assert_eq!(held.dial(), None);
        assert!(!held.removes());
        assert_eq!(link.phase(), LinkPhase::Held);
        assert_eq!(link.wake_at(5), None);
        assert!(link.input(LinkInput::Tick, 1_000_000 * MS).is_empty());
        assert_eq!(link.input(LinkInput::NodeFree, 6).dial(), Some(0));
        assert_eq!(link.phase(), LinkPhase::Dialing { row: 0 });

        let mut slot = MaybeUninit::uninit();
        let other = taken(&mut slot, 1);
        other.input(LinkInput::Taken, 0);
        let gone = other.input(LinkInput::HeldElsewhere, 1);
        assert!(gone.end_handshake());
        assert!(gone.removes());
    }
}
