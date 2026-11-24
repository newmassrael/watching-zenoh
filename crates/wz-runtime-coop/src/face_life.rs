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
//! Each answer of [`LinkSupervisor::advance`](crate::faces::LinkSupervisor::advance) is one
//! [`Turn`], and the engine's poll of a face is [`FaceLife::effect`] over it:
//!
//! | `Moved` | phase | signal | [`Turn`] | [`FaceEffect`] |
//! |---|---|---|---|---|
//! | `Stays` | any | none of the below | `Stays` | `Stay` |
//! | `Lost` | `Up` | `ended` | `Lost` | `Lose`: `Remove`, `EndSession` or `DialFrom(0)` |
//! | `Established` | `Opening` | `established` | `Established` | `BringUp` |
//! | `HandshakeOver` | `Opening` | `ended`, or the deadline | `HandshakeOver` | `Fail`: `Remove`, `StandBy` or `DialFrom(next)` |
//! | `DialOver` | `Dialing` | `dial` answered, or the deadline | `DialOver` | `Handshake`, or `DialFailed`: `Remove` or `DialFrom(next)` |
//! | `Due` | `Waiting` past its time, `Held` with `!node_held` | | `Due` | `Dial(0)` |
//!
//! A face of the dial role ([`FaceRole::Dial`]) is kept through every loss and dialled again; any
//! other face goes with its link ([`Next::Remove`]).

use wz_session_core::session_zid::SessionZid;

use crate::faces::{DialEndpoint, FaceId};

/// Which face of the session it is: the one that dials the session's endpoints, kept for as long
/// as the session is, or one taken besides (attached, or accepted on a port), which goes with its
/// link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceRole {
    /// The dial role's face.
    Dial,
    /// A face taken besides the dial role's.
    Taken,
}

/// Where a face's link stands, without the link: what [`Link`](crate::faces::Link) is, less the
/// wire and the dial the executor holds.
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
    /// A dial of `endpoint` under way, given up at `deadline_us` as the handshake after it is.
    Dialing {
        /// The endpoint dialled.
        endpoint: DialEndpoint,
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
    Held {
        /// The node the link reached.
        node: SessionZid,
    },
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
    pub node_held: bool,
}

/// What became of a face's link at a step: [`Moved`](crate::faces::Moved) without the link.
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
        /// The endpoint dialled.
        endpoint: DialEndpoint,
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
        /// The endpoint the link reaches.
        endpoint: DialEndpoint,
        /// The endpoint the dial role dials next.
        next: usize,
        /// When the handshake is given up.
        deadline_us: u64,
    },
    /// The dial was refused or not answered in time; then `then`.
    DialFailed {
        /// The endpoint dialled, which the refusal names.
        endpoint: DialEndpoint,
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

    /// What became of the face's link at `now_us`, given what the executor read of it: the answer
    /// [`LinkSupervisor::advance`](crate::faces::LinkSupervisor::advance) gives, in its order (a
    /// handshake that completed is established even when its task ended after).
    pub fn turn(&self, now_us: u64, signals: Signals) -> Turn {
        match &self.phase {
            Phase::Up if signals.ended => Turn::Lost,
            Phase::Opening { .. } if signals.established => Turn::Established,
            Phase::Opening { next, deadline_us } if signals.ended || now_us >= *deadline_us => {
                Turn::HandshakeOver { next: *next }
            }
            Phase::Dialing {
                endpoint,
                next,
                deadline_us,
            } if signals.dial.is_some() || now_us >= *deadline_us => Turn::DialOver {
                made: signals.dial,
                endpoint: endpoint.clone(),
                next: *next,
                deadline_us: *deadline_us,
            },
            Phase::Waiting { at_us } if now_us >= *at_us => Turn::Due,
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
                then: match self.role {
                    FaceRole::Taken => Next::Remove,
                    FaceRole::Dial if !redials => Next::EndSession,
                    FaceRole::Dial => Next::DialFrom { from: 0 },
                },
            },
            Turn::Established => FaceEffect::BringUp,
            Turn::HandshakeOver { next } => FaceEffect::Fail {
                then: match (self.role, stood_by) {
                    (FaceRole::Taken, _) => Next::Remove,
                    (FaceRole::Dial, Some(node)) => Next::StandBy { node },
                    (FaceRole::Dial, None) => Next::DialFrom { from: next },
                },
            },
            Turn::DialOver {
                made: Some(true),
                endpoint,
                next,
                deadline_us,
            } => FaceEffect::Handshake {
                endpoint,
                next,
                deadline_us,
            },
            Turn::DialOver { endpoint, next, .. } => FaceEffect::DialFailed {
                endpoint,
                then: self.after_failure(next),
            },
            Turn::Due => FaceEffect::Dial { from: 0 },
        }
    }

    /// What follows a link of this face that failed before it was up, the dial role going on
    /// from endpoint `next`: also the executor's answer when the handshake a [`FaceEffect::Handshake`]
    /// asked for could not begin.
    pub fn after_failure(&self, next: usize) -> Next {
        match self.role {
            FaceRole::Taken => Next::Remove,
            FaceRole::Dial => Next::DialFrom { from: next },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    fn node() -> SessionZid {
        SessionZid::new(&[0x51, 0x52]).expect("a zid")
    }

    fn dial(phase: Phase) -> FaceLife {
        FaceLife::new(0, FaceRole::Dial, phase)
    }

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
            endpoint: DialEndpoint::Listed(1),
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
                    endpoint: DialEndpoint::Listed(1),
                    next: 2,
                    deadline_us: NOW + 10,
                }
            );
        }
        assert_eq!(
            dial(dialing()).turn(NOW + 10, Signals::default()),
            Turn::DialOver {
                made: None,
                endpoint: DialEndpoint::Listed(1),
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
        let held = dial(Phase::Held { node: node() });
        let still = Signals {
            node_held: true,
            ..Signals::default()
        };
        assert_eq!(held.turn(NOW, still), Turn::Stays);
        assert_eq!(held.turn(NOW, Signals::default()), Turn::Due);
    }

    /// A lost link takes a face taken besides with it; the dial role's face dials again from the
    /// first endpoint, or ends the session when it dials none again.
    #[test]
    fn a_lost_link_removes_a_taken_face_and_redials_or_ends_the_dial_role() {
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
        assert_eq!(
            dial(opening()).effect(over, false, None),
            FaceEffect::Fail {
                then: Next::DialFrom { from: 2 }
            },
            "the next endpoint is dialled whether or not the session redials"
        );
    }

    /// A dial that made a link begins its handshake; one refused or unanswered takes a face
    /// taken besides with it, and the dial role goes on to the next endpoint.
    #[test]
    fn a_dial_over_begins_a_handshake_or_fails() {
        let over = |made| Turn::DialOver {
            made,
            endpoint: DialEndpoint::Listed(1),
            next: 2,
            deadline_us: NOW + 10,
        };
        assert_eq!(
            dial(dialing()).effect(over(Some(true)), true, None),
            FaceEffect::Handshake {
                endpoint: DialEndpoint::Listed(1),
                next: 2,
                deadline_us: NOW + 10,
            }
        );
        for made in [Some(false), None] {
            assert_eq!(
                dial(dialing()).effect(over(made), true, None),
                FaceEffect::DialFailed {
                    endpoint: DialEndpoint::Listed(1),
                    then: Next::DialFrom { from: 2 },
                }
            );
            assert_eq!(
                taken(dialing()).effect(over(made), true, None),
                FaceEffect::DialFailed {
                    endpoint: DialEndpoint::Listed(1),
                    then: Next::Remove,
                }
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

    /// The executor records where the link stands after it acted.
    #[test]
    fn the_phase_is_what_the_executor_records() {
        let mut life = dial(Phase::Up);
        life.set(Phase::Waiting { at_us: NOW });
        assert_eq!(life.phase(), &Phase::Waiting { at_us: NOW });
        assert_eq!((life.id(), life.role()), (0, FaceRole::Dial));
    }
}
