// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The life of one face of a session as a value: where its link stands, what became of the link
//! at a step, and what the session does about it, with no I/O in any of it.
//!
//! The link itself (its task, its dial under way, its wire) is the executor's, which reads what
//! the link did into [`Signals`], asks [`FaceLife::turn`] what that comes to, asks
//! [`FaceLife::effect`] what to do, does it on the stack, the rooms and the task table, and
//! records where the link then stands ([`FaceLife::set`]). The decisions are here once, testable
//! without a network, and the executor holds the I/O once.
//!
//! What each step of a face comes to, by where its link stands and what the executor read of it:
//!
//! | phase | signal | [`Turn`] | [`FaceEffect`] |
//! |---|---|---|---|
//! | any | none of the below | `Stays` | `Stay` |
//! | `Up` | `ended` | `Lost` | `Lose`: `Remove`, `EndSession` or `DialFrom(0)` |
//! | `Opening` | `established` | `Established` | `BringUp` |
//! | `Opening` | `ended`, or the deadline | `HandshakeOver` | `Fail`: `Remove`, `StandBy` or `DialFrom(next)` |
//! | `Dialing` | `dial` answered, or the deadline | `DialOver` | `Handshake`, or `DialFailed`: `Remove` or `DialFrom(next)` |
//! | `Waiting` past its time, `Held` with `!node_held` | | `Due` | `Dial(0)` |
//!
//! A face of the dial role ([`FaceRole::Dial`]) is kept through every loss and dialled again; any
//! other face goes with its link (`Next::Remove`). Only a session that takes faces besides its
//! dial (`listen`) has such faces, or a dial role that stands by for a node another face holds
//! (`Held`, `Next::StandBy`): a build without it has neither, nor the decisions about them.

use wz_session_core::session_zid::SessionZid;

use crate::faces::{FaceId, DIAL_LOOK_MS};

/// Which face of the session it is: the one that dials the session's endpoints, kept for as long
/// as the session is, or one taken besides (attached, or accepted on a port), which goes with its
/// link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceRole {
    /// The dial role's face.
    Dial,
    /// A face taken besides the dial role's.
    #[cfg(feature = "listen")]
    Taken,
}

/// Where a face's link stands, without the link: what [`Link`](crate::faces::Link) is, less the
/// wire and the dial the executor holds. The endpoint a dial reaches is not here: no decision
/// reads it, and it stays with the dial, which hands it over when it is let go of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Established.
    Up,
    /// In its handshake, given up at `deadline_us`; the dial role goes on from endpoint `next`.
    Opening {
        /// The endpoint the dial role dials next when this one fails.
        next: usize,
        /// When the handshake is given up.
        deadline_us: u64,
    },
    /// A dial under way, given up at `deadline_us` as the handshake after it is.
    Dialing {
        /// The endpoint the dial role dials next when this one fails.
        next: usize,
        /// When the dial is given up.
        deadline_us: u64,
    },
    /// Waiting to dial again at `at_us`.
    Waiting {
        /// When the endpoints are dialled again.
        at_us: u64,
    },
    /// Standing by while another face holds the node `node` its link reached.
    #[cfg(feature = "listen")]
    Held {
        /// The node the link reached.
        node: SessionZid,
    },
}

impl Phase {
    /// When a face whose link stands here is next to be looked at though its link brings no
    /// input: a face waiting to dial again at its time, a dial under way at the next look
    /// (`DIAL_LOOK_MS` from now) or at its deadline when that is sooner, and a handshake at its
    /// deadline, which ends it. `None` for a link that is up and a face standing by, which only
    /// input or another face moves on. `now_us` reads the clock, which only a dial asks.
    pub fn wake_at(&self, now_us: impl FnOnce() -> u64) -> Option<u64> {
        match self {
            Phase::Waiting { at_us } => Some(*at_us),
            Phase::Dialing { deadline_us, .. } => Some(
                now_us()
                    .saturating_add(DIAL_LOOK_MS.saturating_mul(1000))
                    .min(*deadline_us),
            ),
            Phase::Opening { deadline_us, .. } => Some(*deadline_us),
            Phase::Up => None,
            #[cfg(feature = "listen")]
            Phase::Held { .. } => None,
        }
    }
}

/// What the executor read of a face's link at a step.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signals {
    /// The link's task ended (a link up or in its handshake).
    pub ended: bool,
    /// The link's handshake completed.
    pub established: bool,
    /// The dial under way was answered: `Some(true)` with a link, `Some(false)` refused, `None`
    /// while it is still being made.
    pub dial: Option<bool>,
    /// Another face holds the node this face stands by for, or brings a link to it up.
    #[cfg(feature = "listen")]
    pub node_held: bool,
}

/// What became of a face's link at a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// Nothing for the session to do.
    Stays,
    /// The link was up and its task ended.
    Lost,
    /// The link's handshake completed.
    Established,
    /// The handshake ended, or its deadline passed, before it completed.
    HandshakeOver {
        /// The endpoint the dial role dials next.
        next: usize,
    },
    /// The dial was answered, or its deadline passed unanswered (`made` `None`).
    DialOver {
        /// Whether the dial made a link: `None` when it was not answered in time.
        made: Option<bool>,
        /// The endpoint the dial role dials next.
        next: usize,
        /// When the dial, and the handshake after it, are given up.
        deadline_us: u64,
    },
    /// The face is to be dialled again now.
    Due,
}

/// What follows a link that failed or was lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// The face goes, with its tables.
    #[cfg(feature = "listen")]
    Remove,
    /// The session ends: the dial role's link is gone and the session dials none again.
    EndSession,
    /// Dial the session's endpoints from `from` on, and wait to dial them all again when none
    /// answers (the executor's, which holds the dials and the redial time).
    DialFrom {
        /// The first endpoint dialled.
        from: usize,
    },
    /// Stand by while another face holds `node`.
    #[cfg(feature = "listen")]
    StandBy {
        /// The node another face holds.
        node: SessionZid,
    },
}

/// What the session does for a face at a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaceEffect {
    /// Nothing.
    Stay,
    /// The link was lost: end the chains of its peer, forget the face's room, lose what the peer
    /// declared, tell the face's watchers it went down; then `then`.
    Lose {
        /// What follows.
        then: Next,
    },
    /// The handshake completed: bring the link up.
    BringUp,
    /// The handshake failed: end the link's task; then `then`.
    Fail {
        /// What follows.
        then: Next,
    },
    /// The dial made a link: begin its handshake, given up at `deadline_us`; a dial role that
    /// fails it goes on from `next`.
    Handshake {
        /// The endpoint the dial role dials next.
        next: usize,
        /// When the handshake is given up.
        deadline_us: u64,
    },
    /// The dial was refused or not answered in time; then `then`.
    DialFailed {
        /// What follows.
        then: Next,
    },
    /// Dial the session's endpoints again from `from` on.
    Dial {
        /// The first endpoint dialled.
        from: usize,
    },
}

/// One face's life: its number, its role and where its link stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaceLife {
    id: FaceId,
    role: FaceRole,
    phase: Phase,
}

impl FaceLife {
    /// The face `id` of `role`, its link standing at `phase`.
    pub const fn new(id: FaceId, role: FaceRole, phase: Phase) -> Self {
        Self { id, role, phase }
    }

    /// The face's number.
    pub const fn id(&self) -> FaceId {
        self.id
    }

    /// The face's role.
    pub const fn role(&self) -> FaceRole {
        self.role
    }

    /// Where the face's link stands.
    pub const fn phase(&self) -> &Phase {
        &self.phase
    }

    /// Record where the face's link stands once the executor acted on it.
    pub fn set(&mut self, phase: Phase) {
        self.phase = phase;
    }

    /// What became of the face's link at `now_us`, given what the executor read of it. A handshake
    /// that completed is established even when its task ended after.
    pub fn turn(&self, now_us: u64, signals: Signals) -> Turn {
        match &self.phase {
            Phase::Up if signals.ended => Turn::Lost,
            Phase::Opening { .. } if signals.established => Turn::Established,
            Phase::Opening { next, deadline_us } if signals.ended || now_us >= *deadline_us => {
                Turn::HandshakeOver { next: *next }
            }
            Phase::Dialing { next, deadline_us }
                if signals.dial.is_some() || now_us >= *deadline_us =>
            {
                Turn::DialOver {
                    made: signals.dial,
                    next: *next,
                    deadline_us: *deadline_us,
                }
            }
            Phase::Waiting { at_us } if now_us >= *at_us => Turn::Due,
            #[cfg(feature = "listen")]
            Phase::Held { .. } if !signals.node_held => Turn::Due,
            _ => Turn::Stays,
        }
    }

    /// What the session does about `turn`: `redials` when the session dials its endpoints again
    /// after they all failed, and `stood_by` the node a failed handshake reached when another face
    /// holds it (which only a session that takes faces besides its dial can say).
    pub fn effect(&self, turn: Turn, redials: bool, stood_by: Option<SessionZid>) -> FaceEffect {
        match turn {
            Turn::Stays => FaceEffect::Stay,
            Turn::Lost => FaceEffect::Lose {
                then: self.after_loss(redials),
            },
            Turn::Established => FaceEffect::BringUp,
            Turn::HandshakeOver { next } => FaceEffect::Fail {
                then: self.after_handshake(next, stood_by),
            },
            Turn::DialOver {
                made: Some(true),
                next,
                deadline_us,
            } => FaceEffect::Handshake { next, deadline_us },
            Turn::DialOver { next, .. } => FaceEffect::DialFailed {
                then: self.after_failure(next),
            },
            Turn::Due => FaceEffect::Dial { from: 0 },
        }
    }

    /// When the face is next to be looked at though its link brings no input
    /// ([`Phase::wake_at`]).
    pub fn wake_at(&self, now_us: u64) -> Option<u64> {
        self.phase.wake_at(|| now_us)
    }

    /// What follows a link of this face that failed before it was up, the dial role going on
    /// from endpoint `next`: also the executor's answer when the handshake a [`FaceEffect::Handshake`]
    /// asked for could not begin.
    pub fn after_failure(&self, next: usize) -> Next {
        #[cfg(feature = "listen")]
        if self.role == FaceRole::Taken {
            return Next::Remove;
        }
        Next::DialFrom { from: next }
    }

    /// What follows a link of this face that was lost: `redials` when the session dials its
    /// endpoints again.
    fn after_loss(&self, redials: bool) -> Next {
        #[cfg(feature = "listen")]
        if self.role == FaceRole::Taken {
            return Next::Remove;
        }
        if redials {
            Next::DialFrom { from: 0 }
        } else {
            Next::EndSession
        }
    }

    /// What follows a handshake of this face that is over before it completed, the dial role
    /// going on from endpoint `next` unless another face holds the node it reached (`stood_by`),
    /// which only a session that takes faces besides its dial can say.
    fn after_handshake(&self, next: usize, stood_by: Option<SessionZid>) -> Next {
        #[cfg(feature = "listen")]
        {
            if self.role == FaceRole::Taken {
                return Next::Remove;
            }
            if let Some(node) = stood_by {
                return Next::StandBy { node };
            }
        }
        #[cfg(not(feature = "listen"))]
        let _ = stood_by;
        Next::DialFrom { from: next }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    #[cfg(feature = "listen")]
    fn node() -> SessionZid {
        SessionZid::new(&[0x51, 0x52]).expect("a zid")
    }

    fn dial(phase: Phase) -> FaceLife {
        FaceLife::new(0, FaceRole::Dial, phase)
    }

    #[cfg(feature = "listen")]
    fn taken(phase: Phase) -> FaceLife {
        FaceLife::new(3, FaceRole::Taken, phase)
    }

    fn ended() -> Signals {
        Signals {
            ended: true,
            ..Signals::default()
        }
    }

    fn opening() -> Phase {
        Phase::Opening {
            next: 2,
            deadline_us: NOW + 10,
        }
    }

    fn dialing() -> Phase {
        Phase::Dialing {
            next: 2,
            deadline_us: NOW + 10,
        }
    }

    /// A link that is up is lost when its task ends, and stays otherwise.
    #[test]
    fn an_up_link_is_lost_when_its_task_ends() {
        assert_eq!(dial(Phase::Up).turn(NOW, ended()), Turn::Lost);
        assert_eq!(dial(Phase::Up).turn(NOW, Signals::default()), Turn::Stays);
    }

    /// A handshake that completed is established even when its task ended after; one that ended
    /// first, or ran out of time, is over; one still running in time stays.
    #[test]
    fn a_handshake_is_established_over_or_running() {
        let both = Signals {
            ended: true,
            established: true,
            ..Signals::default()
        };
        assert_eq!(dial(opening()).turn(NOW, both), Turn::Established);
        assert_eq!(
            dial(opening()).turn(NOW, ended()),
            Turn::HandshakeOver { next: 2 }
        );
        assert_eq!(
            dial(opening()).turn(NOW + 10, Signals::default()),
            Turn::HandshakeOver { next: 2 },
            "the deadline ends it"
        );
        assert_eq!(dial(opening()).turn(NOW, Signals::default()), Turn::Stays);
    }

    /// A dial is over once it is answered, made or refused, or its deadline passed unanswered;
    /// it stays while it is being made in time.
    #[test]
    fn a_dial_is_over_when_answered_or_out_of_time() {
        for made in [Some(true), Some(false)] {
            let signals = Signals {
                dial: made,
                ..Signals::default()
            };
            assert_eq!(
                dial(dialing()).turn(NOW, signals),
                Turn::DialOver {
                    made,
                    next: 2,
                    deadline_us: NOW + 10,
                }
            );
        }
        assert_eq!(
            dial(dialing()).turn(NOW + 10, Signals::default()),
            Turn::DialOver {
                made: None,
                next: 2,
                deadline_us: NOW + 10,
            }
        );
        assert_eq!(dial(dialing()).turn(NOW, Signals::default()), Turn::Stays);
    }

    /// A face waiting is due at its time; one standing by is due once no other face holds its
    /// node.
    #[test]
    fn a_waiting_or_held_face_is_due_when_its_reason_is_gone() {
        let waiting = dial(Phase::Waiting { at_us: NOW });
        assert_eq!(waiting.turn(NOW, Signals::default()), Turn::Due);
        assert_eq!(waiting.turn(NOW - 1, Signals::default()), Turn::Stays);
        #[cfg(feature = "listen")]
        {
            let held = dial(Phase::Held { node: node() });
            let still = Signals {
                node_held: true,
                ..Signals::default()
            };
            assert_eq!(held.turn(NOW, still), Turn::Stays);
            assert_eq!(held.turn(NOW, Signals::default()), Turn::Due);
        }
    }

    /// A lost link takes a face taken besides with it; the dial role's face dials again from the
    /// first endpoint, or ends the session when it dials none again.
    #[test]
    fn a_lost_link_removes_a_taken_face_and_redials_or_ends_the_dial_role() {
        #[cfg(feature = "listen")]
        assert_eq!(
            taken(Phase::Up).effect(Turn::Lost, true, None),
            FaceEffect::Lose { then: Next::Remove }
        );
        assert_eq!(
            dial(Phase::Up).effect(Turn::Lost, true, None),
            FaceEffect::Lose {
                then: Next::DialFrom { from: 0 }
            }
        );
        assert_eq!(
            dial(Phase::Up).effect(Turn::Lost, false, None),
            FaceEffect::Lose {
                then: Next::EndSession
            }
        );
    }

    /// A failed handshake takes a face taken besides with it, even when its node is held; the
    /// dial role's face stands by for a node another face holds, and goes on to the next
    /// endpoint otherwise.
    #[test]
    fn a_failed_handshake_removes_stands_by_or_goes_on() {
        let over = Turn::HandshakeOver { next: 2 };
        #[cfg(feature = "listen")]
        {
            assert_eq!(
                taken(opening()).effect(over.clone(), true, Some(node())),
                FaceEffect::Fail { then: Next::Remove }
            );
            assert_eq!(
                dial(opening()).effect(over.clone(), true, Some(node())),
                FaceEffect::Fail {
                    then: Next::StandBy { node: node() }
                }
            );
        }
        assert_eq!(
            dial(opening()).effect(over, false, None),
            FaceEffect::Fail {
                then: Next::DialFrom { from: 2 }
            },
            "the next endpoint is dialled whether or not the session redials"
        );
    }

    /// A session that takes no face besides its dial never stands by: no other face can hold the
    /// node a failed handshake reached, so the dial role goes on to the next endpoint whatever it
    /// is told of one. Turned red by a build without `listen` that reads the node it is handed.
    #[cfg(not(feature = "listen"))]
    #[test]
    fn a_dial_role_with_no_other_face_goes_on_after_a_failed_handshake() {
        let node = SessionZid::new(&[0x51, 0x52]).expect("a zid");
        assert_eq!(
            dial(opening()).effect(Turn::HandshakeOver { next: 2 }, true, Some(node)),
            FaceEffect::Fail {
                then: Next::DialFrom { from: 2 }
            }
        );
        assert_eq!(dial(opening()).after_failure(3), Next::DialFrom { from: 3 });
    }

    /// A dial that made a link begins its handshake; one refused or unanswered takes a face
    /// taken besides with it, and the dial role goes on to the next endpoint.
    #[test]
    fn a_dial_over_begins_a_handshake_or_fails() {
        let over = |made| Turn::DialOver {
            made,
            next: 2,
            deadline_us: NOW + 10,
        };
        assert_eq!(
            dial(dialing()).effect(over(Some(true)), true, None),
            FaceEffect::Handshake {
                next: 2,
                deadline_us: NOW + 10,
            }
        );
        for made in [Some(false), None] {
            assert_eq!(
                dial(dialing()).effect(over(made), true, None),
                FaceEffect::DialFailed {
                    then: Next::DialFrom { from: 2 },
                }
            );
            #[cfg(feature = "listen")]
            assert_eq!(
                taken(dialing()).effect(over(made), true, None),
                FaceEffect::DialFailed { then: Next::Remove }
            );
        }
    }

    /// A due face dials from the first endpoint; one that stays has nothing to do; a completed
    /// handshake brings the link up.
    #[test]
    fn a_due_face_dials_a_stay_does_nothing_and_an_established_link_comes_up() {
        assert_eq!(
            dial(Phase::Waiting { at_us: NOW }).effect(Turn::Due, true, None),
            FaceEffect::Dial { from: 0 }
        );
        assert_eq!(
            dial(Phase::Up).effect(Turn::Stays, true, None),
            FaceEffect::Stay
        );
        assert_eq!(
            dial(opening()).effect(Turn::Established, true, None),
            FaceEffect::BringUp
        );
    }

    /// A face is looked at again at its wait's end, a dial at the next look or its deadline, a
    /// handshake at its deadline; a link that is up, or a face standing by, only on input.
    #[test]
    fn a_face_wakes_at_its_wait_its_dial_look_or_its_handshake_deadline() {
        let look = DIAL_LOOK_MS * 1000;
        assert_eq!(dial(Phase::Waiting { at_us: NOW }).wake_at(0), Some(NOW));
        assert_eq!(
            dial(dialing()).wake_at(0),
            Some(look.min(NOW + 10)),
            "the next look"
        );
        assert_eq!(
            dial(dialing()).wake_at(NOW),
            Some(NOW + 10),
            "the deadline when it comes before the next look"
        );
        assert_eq!(dial(opening()).wake_at(0), Some(NOW + 10));
        assert_eq!(dial(Phase::Up).wake_at(0), None);
        #[cfg(feature = "listen")]
        assert_eq!(dial(Phase::Held { node: node() }).wake_at(0), None);
    }

    /// The executor records where the link stands after it acted.
    #[test]
    fn the_phase_is_what_the_executor_records() {
        let mut life = dial(Phase::Up);
        life.set(Phase::Waiting { at_us: NOW });
        assert_eq!(life.phase(), &Phase::Waiting { at_us: NOW });
        assert_eq!((life.id(), life.role()), (0, FaceRole::Dial));
    }

    /// A phase reads the clock only for a dial, whose next look is counted from now: a waiting
    /// face and a handshake have times of their own, and a link that is up or a face standing by
    /// none. Turned red by a clock read for a phase that has no use for it, which a read's wait
    /// over faces that are all up would pay at every step.
    #[test]
    fn a_phase_reads_the_clock_only_for_a_dial() {
        let mut reads = 0;
        let mut read = |now: u64| {
            reads += 1;
            now
        };
        assert_eq!(Phase::Up.wake_at(|| read(0)), None);
        #[cfg(feature = "listen")]
        assert_eq!(Phase::Held { node: node() }.wake_at(|| read(0)), None);
        assert_eq!(Phase::Waiting { at_us: 7 }.wake_at(|| read(0)), Some(7));
        assert_eq!(opening().wake_at(|| read(0)), Some(NOW + 10));
        let dialing = Phase::Dialing {
            next: 1,
            deadline_us: 100_000,
        };
        assert_eq!(
            dialing.wake_at(|| read(50)),
            Some(50 + DIAL_LOOK_MS * 1000),
            "the next look"
        );
        assert_eq!(
            dialing.wake_at(|| read(99_999)),
            Some(100_000),
            "the deadline when it is sooner"
        );
        assert_eq!(reads, 2, "only the dial read the clock");
    }
}
