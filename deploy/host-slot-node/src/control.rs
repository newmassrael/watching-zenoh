// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The agent of the out-of-band transport (decision D7, `docs/session-lifecycle-intent.md`): a
//! host node that takes its peers from lines on standard input and answers each on standard
//! output, the control channel of a test agent that starts the process.
//!
//! The semantics are not here. A line is read and answered by `wz_session_mcu::control_port`,
//! which asks the node's opener (`wz_session_mcu::node_opening`), so what `open <peer>` means is
//! what the admin query `session/open/<peer>` means. This module is the two things only a host
//! has: the descriptor the lines come from (`wz_runtime_posix::control`) and the place in the
//! loop where they are looked at ([`WithControl`], a round's `after_tick`).
//!
//! The authority is the channel's: whoever holds the pipe is the agent that started the node, so
//! [`HostOpener`] permits what the pipe asks. A node that must not take a peer by request is built
//! without this feature, and one that takes none out of band is built with [`NoOpening`]'s kind
//! of opener in the same place.
//!
//! [`NoOpening`]: wz_session_mcu::node_opening::NoOpening

use core::ops::ControlFlow;

use wz_runtime_posix::control::{reply, Lines};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::lifecycle_wire::OpenOutcome;
use wz_session_core::text_out::FixedText;
use wz_session_mcu::connect_manager::NodeOpener;
use wz_session_mcu::control_port::{self, Malformed};
use wz_session_mcu::node_opening::NodeOpening;
use wz_session_mcu::slot_node::{NodeApp, NodeHandle};

/// How many lines one round answers at most, so a flood on the channel cannot starve the loop.
const LINES_PER_ROUND: usize = 4;
/// The bytes of one answer: the longest refusal's words and the verdict around them.
const ANSWER_BYTES: usize = 192;

/// The node's opener for its control channel: every request the channel carries is permitted,
/// since the channel is the agent's own.
pub struct HostOpener {
    opener: NodeOpener,
}

impl HostOpener {
    /// The opener of the nodes held in the node's own store.
    pub const fn new(opener: NodeOpener) -> Self {
        Self { opener }
    }
}

impl NodeOpening for HostOpener {
    fn permitted(&self) -> bool {
        true
    }

    fn open(&self, zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome {
        match self.opener.open(zid) {
            Ok(()) => OpenOutcome::Accepted,
            Err(refusal) => refusal.into(),
        }
    }
}

/// An application with the control channel read beside it, once a round, after the application's
/// own.
pub struct WithControl<A, O> {
    inner: A,
    opener: O,
    lines: Lines,
}

impl<A, O> WithControl<A, O> {
    /// `inner` run as it was, and the lines of standard input answered with `opener`.
    pub const fn new(inner: A, opener: O) -> Self {
        Self {
            inner,
            opener,
            lines: Lines::stdin(),
        }
    }
}

impl<A: NodeApp, O: NodeOpening> NodeApp for WithControl<A, O> {
    fn after_tick(&mut self, now_ms: u64, node: &dyn NodeHandle) -> ControlFlow<i32> {
        self.inner.after_tick(now_ms, node)?;
        for _ in 0..LINES_PER_ROUND {
            let Some(line) = self.lines.take_line() else {
                break;
            };
            let mut answer = FixedText::<ANSWER_BYTES>::new();
            if line.overlong {
                Malformed::LineTooLong.write_json(&mut answer);
            } else {
                control_port::answer(&self.opener, line.text, &mut answer);
            }
            reply(answer.prefix());
        }
        ControlFlow::Continue(())
    }
}
