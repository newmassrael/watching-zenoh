// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
            }
        } else {
            Self {
                droppable,
                left_us: conf.wait_before_close_us,
                step_us: 0,
                extend_left_us: 0,
            }
        }
    }

    /// The ask for room this deadline makes now.
    pub fn ask(&self) -> RoomWait {
        if self.droppable {
            RoomWait::Drop {
                wait_us: self.left_us,
            }
        } else {
            RoomWait::Block {
                wait_us: self.left_us,
            }
        }
    }

    /// Spend what an ask waited.
    pub fn spend(&mut self, waited_us: u64) {
        self.left_us = self.left_us.saturating_sub(waited_us);
    }

    /// A fragment went out: upstream's `on_next_fragment`, which doubles the
    /// increment and adds it, bounded by what is left of the cap.
    pub fn next_fragment(&mut self) {
        if !self.droppable {
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
