// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2830 (§5.23 `adminspace-write`) — the MCU node holds a session with every
//! endpoint its connection control names, and re-dials the ones that drop.
//!
//! [`crate::admin_host::ConnectControl`] is what a host writes; this module is
//! what makes the write mean something. [`crate::connect_manager::ConnectManager`]
//! is ticked by the firmware's main loop. On every tick it
//!
//! 1. notices a new generation on the control and reconciles: an endpoint no
//!    longer named is hung up, a new one is dialled at once;
//! 2. notices a session that has ended and schedules its re-dial; and
//! 3. dials whatever is due.
//!
//! The waits are upstream's `connect.retry` schedule, from the one
//! transcription the AP uses too (`wz_session_core::retry_period`): 1 s, 2 s,
//! 4 s, then 4 s, growing while a dial keeps failing. A session that had been
//! ESTABLISHED and then dropped starts the schedule again from its first wait,
//! because upstream builds a fresh period per outage.
//!
//! The dialling itself is behind [`crate::connect_manager::Dialer`], so the
//! bookkeeping above is decided (and tested) without a network. The lwIP
//! dialer, and the node status it reports, are the next slice.
//!
//! An endpoint this build cannot dial at all (a scheme it has no link for, an
//! address it cannot parse) is REFUSED rather than retried: retrying cannot
//! change the answer, and a hot loop of doomed dials is the one thing the
//! schedule exists to prevent. It is tried again only when the list is
//! written again, since that is the only event that can change it.

use alloc::vec::Vec;

use wz_session_core::admin_connect::{ConnectEndpoints, EndpointText};
use wz_session_core::retry_period::{RetryPeriod, RetryPolicy};

use crate::admin_host::ConnectControl;

/// Why a dial could not even be attempted. Permanent for this endpoint text
/// in this build, so it is not retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefused {
    /// The endpoint's scheme names a link this build does not carry.
    Unsupported,
    /// The address could not be read as one this link can reach.
    BadAddress,
}

/// Why a dial did not start a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailed {
    /// This endpoint can never be dialled by this build; not retried.
    Refused(DialRefused),
    /// The node could not afford a session right now (no socket, no
    /// buffer). Counted as a failed attempt of the same outage, so the
    /// endpoint waits its next period, as a dial that never answered would.
    Exhausted,
}

/// How a session that was dialled has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// It never reached an established session.
    BeforeEstablished,
    /// It was established and then closed or lost.
    AfterEstablished,
}

/// Starts, watches and ends the sessions a [`ConnectManager`] asks for.
pub trait Dialer {
    /// Whatever the dialer needs to keep per live session.
    type Session;

    /// Start a session towards `endpoint`.
    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed>;

    /// `Some` once the session has ended, saying how.
    fn ended(&mut self, session: &mut Self::Session) -> Option<Ended>;

    /// End a session the list no longer names.
    fn hang_up(&mut self, session: Self::Session);
}

/// Where one endpoint stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// A session is live (or being opened).
    Live,
    /// Waiting to (re-)dial at this time.
    Waiting {
        /// When the next dial is due, in the manager's clock.
        at_ms: u64,
    },
    /// This build cannot dial it.
    Refused(DialRefused),
}

enum State<S> {
    /// The period rides along so a session that ends before establishing
    /// continues the SAME outage's schedule.
    Live {
        session: S,
        period: RetryPeriod,
    },
    Waiting {
        at_ms: u64,
        period: RetryPeriod,
    },
    Refused(DialRefused),
}

struct Slot<S> {
    endpoint: EndpointText,
    state: State<S>,
}

/// Keeps a node's sessions in step with its [`ConnectControl`].
pub struct ConnectManager<D: Dialer> {
    control: &'static ConnectControl,
    dialer: D,
    policy: RetryPolicy,
    generation: Option<u32>,
    slots: Vec<Slot<D::Session>>,
}

impl<D: Dialer> ConnectManager<D> {
    /// A manager over `control`, dialling with `dialer`, on upstream's
    /// default retry schedule.
    pub fn new(control: &'static ConnectControl, dialer: D) -> Self {
        Self::with_policy(control, dialer, RetryPolicy::ZENOH_DEFAULT)
    }

    /// The same, on an explicit retry schedule.
    pub fn with_policy(control: &'static ConnectControl, dialer: D, policy: RetryPolicy) -> Self {
        Self {
            control,
            dialer,
            policy,
            generation: None,
            slots: Vec::new(),
        }
    }

    /// The dialer, for a caller that needs to reach the sessions it holds.
    pub fn dialer(&mut self) -> &mut D {
        &mut self.dialer
    }

    /// Where every endpoint stands, in the order the list named them.
    pub fn states(&self) -> impl Iterator<Item = (&str, SlotState)> + '_ {
        self.slots.iter().map(|slot| {
            let state = match slot.state {
                State::Live { .. } => SlotState::Live,
                State::Waiting { at_ms, .. } => SlotState::Waiting { at_ms },
                State::Refused(why) => SlotState::Refused(why),
            };
            (slot.endpoint.as_str(), state)
        })
    }

    /// Advance to `now_ms`: reconcile a new list, notice ended sessions, and
    /// dial what is due.
    pub fn tick(&mut self, now_ms: u64) {
        let (generation, list) = self.control.endpoints();
        if self.generation != Some(generation) {
            self.reconcile(&list, now_ms);
            self.generation = Some(generation);
        }
        for slot in &mut self.slots {
            let next = match &mut slot.state {
                State::Live { session, period } => match self.dialer.ended(session) {
                    None => None,
                    Some(how) => {
                        // Before establishing, a failure is part of the same
                        // outage and grows its period; after, the outage is a
                        // new one and starts from the first wait, as upstream
                        // builds a fresh period per outage.
                        let mut period = match how {
                            Ended::BeforeEstablished => *period,
                            Ended::AfterEstablished => self.policy.period(),
                        };
                        let wait = period.next_ms();
                        Some(State::Waiting {
                            at_ms: now_ms.saturating_add(wait),
                            period,
                        })
                    }
                },
                State::Waiting { at_ms, period } if now_ms >= *at_ms => {
                    Some(match self.dialer.dial(&slot.endpoint) {
                        Ok(session) => State::Live {
                            session,
                            period: *period,
                        },
                        Err(DialFailed::Refused(why)) => State::Refused(why),
                        Err(DialFailed::Exhausted) => {
                            let mut period = *period;
                            let wait = period.next_ms();
                            State::Waiting {
                                at_ms: now_ms.saturating_add(wait),
                                period,
                            }
                        }
                    })
                }
                _ => None,
            };
            if let Some(state) = next {
                slot.state = state;
            }
        }
    }

    fn reconcile(&mut self, list: &ConnectEndpoints, now_ms: u64) {
        // Hang up what the list no longer names.
        let mut kept = Vec::with_capacity(self.slots.len());
        for slot in self.slots.drain(..) {
            if list.contains(&slot.endpoint) {
                kept.push(slot);
            } else if let State::Live { session, .. } = slot.state {
                self.dialer.hang_up(session);
            }
        }
        // Keep the list's order; a new endpoint is due now, and a refused one
        // is given another chance, since a rewrite is what could change it.
        let mut slots = Vec::with_capacity(list.len());
        for endpoint in list.iter() {
            match kept.iter().position(|s| s.endpoint == *endpoint) {
                Some(i) => {
                    let mut slot = kept.swap_remove(i);
                    if let State::Refused(_) = slot.state {
                        slot.state = self.due_now(now_ms);
                    }
                    slots.push(slot);
                }
                None => slots.push(Slot {
                    endpoint: endpoint.clone(),
                    state: self.due_now(now_ms),
                }),
            }
        }
        self.slots = slots;
    }

    fn due_now(&self, now_ms: u64) -> State<D::Session> {
        State::Waiting {
            at_ms: now_ms,
            period: self.policy.period(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use core::cell::RefCell;

    /// A dialer that records what it was asked and ends sessions on demand.
    #[derive(Default)]
    struct FakeDialer {
        dials: RefCell<Vec<String>>,
        hang_ups: Vec<String>,
        /// Sessions to end on the next `ended` call, and how.
        endings: Vec<(String, Ended)>,
        /// Answer every dial with `Exhausted`.
        exhausted: bool,
    }

    impl Dialer for FakeDialer {
        type Session = String;

        fn dial(&mut self, endpoint: &str) -> Result<String, DialFailed> {
            if endpoint.starts_with("serial/") {
                return Err(DialFailed::Refused(DialRefused::Unsupported));
            }
            if self.exhausted {
                return Err(DialFailed::Exhausted);
            }
            self.dials.borrow_mut().push(String::from(endpoint));
            Ok(String::from(endpoint))
        }

        fn ended(&mut self, session: &mut String) -> Option<Ended> {
            let i = self.endings.iter().position(|(e, _)| e == session)?;
            Some(self.endings.remove(i).1)
        }

        fn hang_up(&mut self, session: String) {
            self.hang_ups.push(session);
        }
    }

    fn write(control: &'static ConnectControl, list: &[&str]) {
        let mut body = String::from("[");
        for (i, e) in list.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push('"');
            body.push_str(e);
            body.push('"');
        }
        body.push(']');
        control.apply_for_test(body.as_bytes());
    }

    fn dials(m: &mut ConnectManager<FakeDialer>) -> Vec<String> {
        m.dialer().dials.borrow_mut().drain(..).collect()
    }

    #[test]
    fn a_written_list_is_dialled_at_once_and_an_empty_one_dials_nothing() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        let mut m = ConnectManager::new(&CONTROL, FakeDialer::default());
        m.tick(0);
        std::assert!(dials(&mut m).is_empty(), "no list, no dial");

        write(&CONTROL, &["udp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        m.tick(5);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        std::assert!(m.states().all(|(_, s)| s == SlotState::Live));
    }

    /// Failures before establishing are ONE outage and the wait grows on
    /// upstream's default, 1 s then 2 s; a session that had been up and then
    /// drops starts again from 1 s.
    #[test]
    fn re_dials_follow_upstreams_schedule_per_outage() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        let mut m = ConnectManager::new(&CONTROL, FakeDialer::default());
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m).len(), 1);

        let fail = |m: &mut ConnectManager<FakeDialer>, how| {
            m.dialer()
                .endings
                .push((String::from("udp/10.0.0.1:7447"), how));
        };

        fail(&mut m, Ended::BeforeEstablished);
        m.tick(100);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 1100 }
        );
        m.tick(1099);
        std::assert!(dials(&mut m).is_empty(), "not before the wait is up");
        m.tick(1100);
        std::assert_eq!(dials(&mut m).len(), 1, "re-dialled when due");

        fail(&mut m, Ended::BeforeEstablished);
        m.tick(1200);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 3200 },
            "the same outage: the wait grew to 2 s"
        );
        m.tick(3200);
        std::assert_eq!(dials(&mut m).len(), 1);

        fail(&mut m, Ended::AfterEstablished);
        m.tick(9000);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 10000 },
            "a new outage starts from 1 s again"
        );
    }

    /// A node that cannot afford a session right now is not refused: the
    /// endpoint waits its period like a dial nobody answered, and is dialled
    /// once the node can.
    #[test]
    fn an_exhausted_dial_waits_its_period_and_is_not_refused() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        let mut m = ConnectManager::new(
            &CONTROL,
            FakeDialer {
                exhausted: true,
                ..FakeDialer::default()
            },
        );
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 1000 }
        );
        m.tick(1000);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 3000 },
            "still the same outage: the wait grew"
        );
        m.dialer().exhausted = false;
        m.tick(3000);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);
    }

    #[test]
    fn an_endpoint_the_list_drops_is_hung_up_and_one_it_cannot_dial_waits_for_a_rewrite() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        let mut m = ConnectManager::new(&CONTROL, FakeDialer::default());
        write(&CONTROL, &["udp/10.0.0.1:7447", "serial//dev/ttyS0"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);
        std::assert_eq!(
            m.states().nth(1).unwrap().1,
            SlotState::Refused(DialRefused::Unsupported)
        );
        m.tick(60_000);
        std::assert!(
            dials(&mut m).is_empty(),
            "a refused endpoint is not retried"
        );

        write(&CONTROL, &["serial//dev/ttyS0"]);
        m.tick(60_001);
        std::assert_eq!(m.dialer().hang_ups, vec![String::from("udp/10.0.0.1:7447")]);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Refused(DialRefused::Unsupported),
            "a rewrite tries the refused endpoint again, and it is refused again"
        );
    }
}
