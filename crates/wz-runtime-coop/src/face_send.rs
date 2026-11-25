// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sending side of a session's faces as a value: whether a publish may be dropped, what one
//! that finds the session held does, whether a publish dropped on some faces is kept for the
//! others, the order of a publish's sends and where its fan-out goes on after a wait for a slot,
//! and what each face of a fan-out is sent, with no I/O in any of it.
//!
//! The executor holds the session's lock, the rooms of its faces and the mark of who holds the
//! session, the publishes kept for other faces, the clock and the sends. It asks here what each of
//! them comes to, does it, and reports back what the sends found; the decisions are here once,
//! testable without a link, as a face's link life is (`wz_session_core::link_life`).
//!
//! What a droppable publish that finds the session held does, by what the rooms answered:
//!
//! | [`Room`] | [`Behind`] |
//! |---|---|
//! | `Free` | `TryAgain`: the holder waits on no face |
//! | `Stepping`, `Unasked` | `WaitForSession` |
//! | `Congested(set)` | `Dropped` on the set, the caller not told |
//! | `Held(face)` | `Dropped` on that face, the caller told |
//!
//! A publish that holds the session runs as [`PublishRun`] says: what was handed to the session
//! before it is sent first, then the publish to each face from the first on ([`Pass`]), then what
//! was handed meanwhile. When a face's link found no outbound slot, the session is let go and a
//! slot waited for, within the publish's `wait_before_close`, and the fan-out goes on from that
//! face, each time with what was handed meanwhile sent after it.

use wz_session_core::qos::{CongestionControl, Priority};

use crate::faces::FaceId;

/// Whether a publish may be dropped: a best-effort one, or one whose congestion control is
/// `Drop`, as zenoh's `is_droppable` reads a message
/// (`commons/zenoh-protocol/src/network/mod.rs` @
/// `!self.is_reliable() || self.congestion_control() == CongestionControl::Drop`).
pub const fn droppable(reliable: bool, congestion: CongestionControl) -> bool {
    !reliable || matches!(congestion, CongestionControl::Drop)
}

/// What a droppable publish that found the session held is told of the faces it would be sent
/// to, `S` naming a set of them. Each face is a transport of its own, as each of zenoh's is: the
/// publish is dropped on the faces its holder waits on and still sent to the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Room<S> {
    /// Every face asked takes bytes, or the holder is a publish between its sends or a read
    /// working out its wait: whoever holds the session is not waiting on a face.
    Free,
    /// Nothing was asked: what holds the session is not a publish, and lets go of it once its step
    /// is done.
    Stepping,
    /// These faces took no bytes within the wait.
    Congested(S),
    /// No face that is up gives a wait to ask.
    Unasked,
    /// Nothing was asked: this face is held by another publish sending on it.
    Held(FaceId),
}

/// The faces a publish is dropped on: a set the rooms answered, or the one face another publish
/// holds, whose set the executor reads off the rooms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropSet<S> {
    /// These faces.
    Faces(S),
    /// The face another publish's send holds.
    Face(FaceId),
}

/// What a droppable publish that found the session held does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behind<S> {
    /// Try the session again: its holder waits on no face.
    TryAgain,
    /// Wait for the session, blocked: its holder holds no send and lets go once its step is done,
    /// or there is no face to ask.
    WaitForSession,
    /// The publish is dropped on `on`, and owed to the session's other faces; the caller is told
    /// of the drop when `told` (the queue profile that drops at once, as zenoh-pico's put fails
    /// when the transmit lock it tries is held), and answered with success otherwise, as zenoh
    /// answers a congestion drop.
    Dropped {
        /// The faces it is dropped on.
        on: DropSet<S>,
        /// Whether the caller is told.
        told: bool,
    },
}

impl<S> Room<S> {
    /// What a droppable publish does behind a holder that answered this.
    pub fn behind(self) -> Behind<S> {
        match self {
            Room::Free => Behind::TryAgain,
            Room::Stepping | Room::Unasked => Behind::WaitForSession,
            Room::Congested(faces) => Behind::Dropped {
                on: DropSet::Faces(faces),
                told: false,
            },
            Room::Held(face) => Behind::Dropped {
                on: DropSet::Face(face),
                told: true,
            },
        }
    }
}

/// How many dropped publishes of each priority a session keeps for the faces they are still owed
/// to: the sizes of its transmission queues, as a message that finds its queue full is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandedLimits {
    at_most: [usize; Priority::NUM],
}

impl HandedLimits {
    /// At most `at_most[p]` publishes of priority `p` kept at once.
    pub const fn new(at_most: [usize; Priority::NUM]) -> Self {
        Self { at_most }
    }

    /// Whether a publish of `priority` is kept beside the `held` of its priority kept already;
    /// one that is not is dropped on every face, the drop it already is.
    pub fn keeps(&self, priority: Priority, held: usize) -> bool {
        self.at_most
            .get(usize::from(priority.wire_byte()))
            .is_some_and(|most| held < *most)
    }
}

/// Where a fan-out stands a face: the dial role's face first, then the others by number, as each
/// takes the next number when it comes. A fan-out that stopped at a face goes on from it by this,
/// whatever faces went meanwhile.
pub fn order_key(face: FaceId, dial_face: FaceId) -> u64 {
    if face == dial_face {
        FIRST_FACE
    } else {
        face
    }
}

/// The order of the first of a session's faces ([`order_key`]): a fan-out from it reaches every
/// face.
pub const FIRST_FACE: u64 = 0;

/// Where a fan-out begins, and whether its sends wait for no slot: a session whose links share
/// fewer outbound slots than they are may find every slot held by another link's frame, and a
/// publish that may not be dropped then waits for one with nothing of the session held and goes on
/// where it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pass {
    /// The order of the first face sent to ([`order_key`]).
    pub from: u64,
    /// Whether a send that finds no slot is left unsent and the fan-out stops there.
    pub probe: bool,
}

/// How one face of a fan-out is sent the publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceSend {
    /// Not at all: the publish was dropped on it, or the pass begins after it.
    Skip,
    /// By a send that does not wait for a slot ([`after_probe`]).
    Probe,
    /// By the caller's own send.
    Send,
}

/// What a send that does not wait for a slot found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAnswer {
    /// The face's link has no outbound slot.
    NoRoom,
    /// Sent.
    Sent,
    /// Refused, which the fan-out reports.
    Failed,
    /// The publish would leave as a chain of fragments, which such a send does not begin; or the
    /// send has no way not to wait.
    Chain,
}

/// What follows a send that does not wait for a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterProbe {
    /// The fan-out stops at this face, which is sent nothing, nor are the faces after it.
    StopHere,
    /// On to the next face.
    Next,
    /// Send the face the publish as the caller's own send.
    SendAsOwn,
}

impl Pass {
    /// A pass from the first face on.
    pub const fn first(probe: bool) -> Self {
        Self {
            from: FIRST_FACE,
            probe,
        }
    }

    /// A pass to every face, each send as the caller's own: what a publish handed to the session is
    /// sent by.
    pub const EVERY_FACE: Self = Self::first(false);

    /// How the face at `order` ([`order_key`]) is sent the publish, `dropped_on` when the
    /// publish was dropped on it.
    pub const fn face_send(&self, order: u64, dropped_on: bool) -> FaceSend {
        if dropped_on || order < self.from {
            FaceSend::Skip
        } else if self.probe {
            FaceSend::Probe
        } else {
            FaceSend::Send
        }
    }
}

/// What follows a send that did not wait for a slot and found `answer`.
pub const fn after_probe(answer: ProbeAnswer) -> AfterProbe {
    match answer {
        ProbeAnswer::NoRoom => AfterProbe::StopHere,
        ProbeAnswer::Sent | ProbeAnswer::Failed => AfterProbe::Next,
        ProbeAnswer::Chain => AfterProbe::SendAsOwn,
    }
}

/// How a publish that holds the session begins: what was handed to the session before it is sent
/// first when `hand_before`, then the fan-out by `pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Begin {
    /// Send what was handed before this publish, ahead of it.
    pub hand_before: bool,
    /// The fan-out.
    pub pass: Pass,
}

/// What follows a fan-out of a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Then {
    /// The publish is done.
    Done,
    /// Let go of the session and wait for an outbound slot, `left_us` at most, then go on from
    /// `stuck` ([`PublishRun::waited`]).
    WaitForSlots {
        /// The face whose link found no slot.
        stuck: FaceId,
        /// What is left of the publish's wait.
        left_us: u64,
    },
}

/// What follows a fan-out: what was handed meanwhile is sent after it when `hand_after`, then
/// `then`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fanned {
    /// Send what was handed while the publish held the session, after it.
    pub hand_after: bool,
    /// What follows.
    pub then: Then,
}

/// One publish that holds the session, from its first fan-out to its last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishRun {
    /// Whether the session keeps publishes for other faces, whose sends go around the fan-out.
    hands: bool,
    /// Whether the first fan-out's sends wait for no slot.
    probe: bool,
    /// The publish's `wait_before_close`.
    wait_us: u64,
    /// The dial role's face ([`order_key`]).
    dial_face: FaceId,
    /// When the wait for a slot ends, from the first face that found none.
    deadline_us: Option<u64>,
    /// The face the last fan-out stopped at.
    stuck: Option<FaceId>,
}

impl PublishRun {
    /// A publish on a session that keeps publishes for other faces when `hands`, whose first
    /// fan-out's sends wait for no slot when `probe` (a publish that may not be dropped, on a
    /// session whose links share fewer outbound slots than they are), waiting `wait_us` in all for
    /// a slot; `dial_face` is the dial role's face, which a fan-out reaches first.
    pub const fn new(hands: bool, probe: bool, wait_us: u64, dial_face: FaceId) -> Self {
        Self {
            hands,
            probe,
            wait_us,
            dial_face,
            deadline_us: None,
            stuck: None,
        }
    }

    /// How the publish begins.
    pub const fn begin(&self) -> Begin {
        Begin {
            hand_before: self.hands,
            pass: Pass::first(self.probe),
        }
    }

    /// What follows a fan-out that stopped at `stuck` (`None` when it reached every face).
    /// `now_us` reads the clock, which only a fan-out that stopped asks. The wait for a slot is
    /// the publish's `wait_before_close` from the first face that found none, as a blocking
    /// send's is.
    pub fn fanned(&mut self, stuck: Option<FaceId>, now_us: impl FnOnce() -> u64) -> Fanned {
        self.stuck = stuck;
        let then = match stuck {
            None => Then::Done,
            Some(stuck) => {
                let now_us = now_us();
                let wait_us = self.wait_us;
                let deadline_us = *self
                    .deadline_us
                    .get_or_insert_with(|| now_us.saturating_add(wait_us));
                Then::WaitForSlots {
                    stuck,
                    left_us: deadline_us.saturating_sub(now_us),
                }
            }
        };
        Fanned {
            hand_after: self.hands,
            then,
        }
    }

    /// The fan-out that goes on after a wait for a slot, the clock reading `now_us` as the session
    /// is taken again: from the face it stopped at, the faces before it being sent the publish
    /// already. Its sends wait for no slot while a link was waited on (`waited`) and the wait has
    /// time left; otherwise each is the caller's own, as any blocking send past its wait is. The
    /// executor has every link write what it owes before it.
    pub fn waited(&self, waited: bool, now_us: u64) -> Pass {
        let in_time = self
            .deadline_us
            .is_some_and(|deadline_us| now_us < deadline_us);
        Pass {
            from: self
                .stuck
                .map_or(FIRST_FACE, |stuck| order_key(stuck, self.dial_face)),
            probe: waited && in_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIAL: FaceId = 1 << 62;

    /// A best-effort publish and one whose congestion control is `Drop` may be dropped; a reliable
    /// one that blocks, or blocks for its first, may not.
    #[test]
    fn a_publish_is_droppable_when_best_effort_or_drop() {
        assert!(droppable(false, CongestionControl::Block));
        assert!(droppable(false, CongestionControl::Drop));
        assert!(droppable(true, CongestionControl::Drop));
        assert!(!droppable(true, CongestionControl::Block));
        assert!(!droppable(true, CongestionControl::BlockFirst));
    }

    /// Each answer of the rooms comes to its own step: tried again, waited for, or dropped on the
    /// faces named, the caller told only of a drop behind another publish's send.
    #[test]
    fn each_room_answer_comes_to_its_step() {
        assert_eq!(Room::<u8>::Free.behind(), Behind::TryAgain);
        assert_eq!(Room::<u8>::Stepping.behind(), Behind::WaitForSession);
        assert_eq!(Room::<u8>::Unasked.behind(), Behind::WaitForSession);
        assert_eq!(
            Room::Congested(0b101u8).behind(),
            Behind::Dropped {
                on: DropSet::Faces(0b101),
                told: false
            }
        );
        assert_eq!(
            Room::<u8>::Held(7).behind(),
            Behind::Dropped {
                on: DropSet::Face(7),
                told: true
            }
        );
    }

    /// A publish is kept below its priority's limit and not at it; a priority with no room keeps
    /// none, and the limits of the priorities are apart.
    #[test]
    fn a_publish_is_kept_below_its_prioritys_limit() {
        let mut at_most = [2; Priority::NUM];
        at_most[usize::from(Priority::Background.wire_byte())] = 0;
        let limits = HandedLimits::new(at_most);
        assert!(limits.keeps(Priority::Data, 0));
        assert!(limits.keeps(Priority::Data, 1));
        assert!(!limits.keeps(Priority::Data, 2));
        assert!(!limits.keeps(Priority::Data, 3));
        assert!(!limits.keeps(Priority::Background, 0));
        assert!(limits.keeps(Priority::RealTime, 1));
    }

    /// The dial role's face comes first, the others by number.
    #[test]
    fn the_dial_face_is_first_in_a_fan_out() {
        assert_eq!(order_key(DIAL, DIAL), FIRST_FACE);
        assert_eq!(order_key(3, DIAL), 3);
        assert!(order_key(DIAL, DIAL) < order_key(1, DIAL));
    }

    /// A face the publish was dropped on is skipped, as is one before the pass's first; the others
    /// are probed on a probing pass and sent otherwise.
    #[test]
    fn each_face_of_a_pass_is_skipped_probed_or_sent() {
        let every = Pass::EVERY_FACE;
        assert_eq!(every.face_send(FIRST_FACE, false), FaceSend::Send);
        assert_eq!(every.face_send(5, false), FaceSend::Send);
        assert_eq!(every.face_send(5, true), FaceSend::Skip);
        let probing = Pass {
            from: 4,
            probe: true,
        };
        assert_eq!(probing.face_send(3, false), FaceSend::Skip);
        assert_eq!(probing.face_send(4, false), FaceSend::Probe);
        assert_eq!(probing.face_send(9, true), FaceSend::Skip);
        assert_eq!(
            Pass::first(true).face_send(FIRST_FACE, false),
            FaceSend::Probe
        );
    }

    /// No slot stops the fan-out at the face; a send that went or was refused goes on; a chain is
    /// sent as the caller's own.
    #[test]
    fn a_probe_stops_goes_on_or_sends_as_own() {
        assert_eq!(after_probe(ProbeAnswer::NoRoom), AfterProbe::StopHere);
        assert_eq!(after_probe(ProbeAnswer::Sent), AfterProbe::Next);
        assert_eq!(after_probe(ProbeAnswer::Failed), AfterProbe::Next);
        assert_eq!(after_probe(ProbeAnswer::Chain), AfterProbe::SendAsOwn);
    }

    /// A publish that reaches every face is done after one fan-out, with what was handed sent
    /// before and after it on a session that keeps publishes, and around nothing on one that does
    /// not.
    #[test]
    fn a_publish_that_reaches_every_face_is_done() {
        let mut run = PublishRun::new(true, false, 5_000, DIAL);
        assert_eq!(
            run.begin(),
            Begin {
                hand_before: true,
                pass: Pass::first(false)
            }
        );
        assert_eq!(
            run.fanned(None, || 100),
            Fanned {
                hand_after: true,
                then: Then::Done
            }
        );
        let mut bare = PublishRun::new(false, false, 5_000, DIAL);
        assert!(!bare.begin().hand_before);
        assert_eq!(
            bare.fanned(None, || 100),
            Fanned {
                hand_after: false,
                then: Then::Done
            }
        );
    }

    /// A fan-out that reached every face does not read the clock.
    #[test]
    fn a_fan_out_that_reached_every_face_reads_no_clock() {
        let mut run = PublishRun::new(true, true, 5_000, DIAL);
        let fanned = run.fanned(None, || {
            panic!("the clock is read only when a face found no slot")
        });
        assert_eq!(fanned.then, Then::Done);
    }

    /// A fan-out that stops at a face waits out the publish's whole wait from then, and goes on
    /// from that face: probing while a link was waited on and the wait has time left, as the
    /// caller's own sends once it has none or there was no link to wait on. The deadline is the
    /// first stop's, whatever stops follow.
    #[test]
    fn a_stopped_fan_out_waits_then_goes_on_from_its_face() {
        let mut run = PublishRun::new(true, true, 5_000, DIAL);
        assert_eq!(run.begin().pass, Pass::first(true));
        assert_eq!(
            run.fanned(Some(7), || 1_000).then,
            Then::WaitForSlots {
                stuck: 7,
                left_us: 5_000
            }
        );
        assert_eq!(
            run.waited(true, 2_000),
            Pass {
                from: 7,
                probe: true
            }
        );
        assert_eq!(
            run.waited(false, 2_000),
            Pass {
                from: 7,
                probe: false
            },
            "no link was waited on"
        );
        assert_eq!(
            run.fanned(Some(9), || 2_000).then,
            Then::WaitForSlots {
                stuck: 9,
                left_us: 4_000
            },
            "the deadline is the first stop's"
        );
        assert_eq!(
            run.waited(true, 6_000),
            Pass {
                from: 9,
                probe: false
            },
            "past the deadline every send is the caller's own"
        );
        assert_eq!(
            run.fanned(Some(9), || 6_500).then,
            Then::WaitForSlots {
                stuck: 9,
                left_us: 0
            }
        );
        assert_eq!(run.fanned(None, || 6_500).then, Then::Done);
    }

    /// A fan-out that stopped at the dial role's face goes on from the first face, which it is.
    #[test]
    fn a_fan_out_stopped_at_the_dial_face_goes_on_from_the_first() {
        let mut run = PublishRun::new(false, true, 1_000, DIAL);
        let _ = run.fanned(Some(DIAL), || 0);
        assert_eq!(
            run.waited(true, 10),
            Pass {
                from: FIRST_FACE,
                probe: true
            }
        );
    }
}
