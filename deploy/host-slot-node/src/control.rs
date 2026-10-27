// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The agent of the out-of-band transport (decision D7, `docs/session-lifecycle-intent.md`): a
//! host node that takes its commands from lines on standard input and answers each on standard
//! output, the control channel of a test agent that starts the process.
//!
//! The semantics are not here. A line is read and answered by `wz_session_mcu::control_port`,
//! which asks the node (`wz_session_mcu::connect_manager::StoreNode`, the verbs over the node's
//! own store), so what `open <peer>` or `close <peer>` means is what the admin query
//! `session/open/<peer>` or `session/close/<peer>` means. This module is the two things only a
//! host has: the descriptor the lines come from (`wz_runtime_posix::control`) and the place in
//! the loop where they are looked at ([`WithControl`], a round's `after_tick`).
//!
//! The authority is the channel's: whoever holds the pipe is the agent that started the node, so
//! [`HostPermits`] permits every verb the pipe asks. A node that must not act on a request is
//! built without this feature, and one that binds only the open verb out of band is built with
//! [`OpeningOnly`]'s kind of node in the same place.
//!
//! [`OpeningOnly`]: wz_session_mcu::node_opening::OpeningOnly

use core::ops::ControlFlow;

use wz_runtime_posix::control::{reply, Lines};
use wz_session_core::lifecycle_node::{LifecycleNode, Verb};
use wz_session_core::text_out::FixedText;
use wz_session_mcu::connect_manager::{LifecyclePermits, PeerStore, StoreNode};
use wz_session_mcu::control_port::{self, Malformed};
use wz_session_mcu::slot_node::{NodeApp, NodeHandle};

/// How many lines one round answers at most, so a flood on the channel cannot starve the loop.
const LINES_PER_ROUND: usize = 4;
/// The bytes of one answer: the longest refusal's words and the verdict around them, or a
/// status with its machine's row.
const ANSWER_BYTES: usize = 256;

/// The permit of the control channel: every verb its pipe asks is permitted, since the channel is
/// the agent's own.
pub struct HostPermits;

impl LifecyclePermits for HostPermits {
    fn permits(&self, _verb: Verb) -> bool {
        true
    }
}

/// The verbs of the node's own store, under the channel's permit.
pub type HostNode = StoreNode<HostPermits>;

/// The node of the nodes held in `store`, for the control channel.
pub const fn host_node(store: &'static PeerStore) -> HostNode {
    StoreNode::new(store, HostPermits)
}

/// An application with the control channel read beside it, once a round, after the application's
/// own.
pub struct WithControl<A, N> {
    inner: A,
    node: N,
    /// The node's own zid, which `whoami` answers.
    own_zid: FixedText<33>,
    lines: Lines,
}

impl<A, N> WithControl<A, N> {
    /// `inner` run as it was, and the lines of standard input answered by `node`, which is the node
    /// whose zid is `own_zid` in the spelling zenoh prints.
    pub const fn new(inner: A, node: N, own_zid: FixedText<33>) -> Self {
        Self {
            inner,
            node,
            own_zid,
            lines: Lines::stdin(),
        }
    }
}

impl<A: NodeApp, N: LifecycleNode> NodeApp for WithControl<A, N> {
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
                control_port::answer(
                    &self.node,
                    Some(self.own_zid.prefix()),
                    line.text,
                    &mut answer,
                );
            }
            reply(answer.prefix());
        }
        ControlFlow::Continue(())
    }
}
