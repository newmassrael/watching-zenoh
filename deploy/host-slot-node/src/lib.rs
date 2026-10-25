// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What every front end of the host's fixed-memory node shares.
//!
//! The node has two front ends over one mechanism (`wz_session_mcu::slot_node`): `host-slot-node`
//! reads its router and its documents from the command line, and `declared-node` has them from a
//! declaration (`deploy/nodes/*.toml`, turned into constants by `scripts/lib/wz_node.py`). Each
//! front end owns what only it can state: the `static` tables, whose sizes are const generics it
//! chooses, and the way its input becomes a [`wz_session_mcu::slot_node::ClientNode`]. This crate
//! is the rest, written once for both: the numbers a link is tuned with ([`tuning`]), the host's
//! console and sleep as the node's port ([`HostPort`]), the identity a node starts with
//! ([`fresh_identity`]), and the secure channel (`tls`).
//!
//! It is `#![no_std]` and links no allocator, as the nodes do.
#![no_std]

use core::fmt;
use core::marker::PhantomData;

use wz_runtime_posix::glue::{log_args, yield_us};
use wz_runtime_posix::PosixEntropy;
use wz_session_core::entropy::EntropySource;
use wz_session_mcu::slot_node::{NodePort, SIGNING_KEY_BYTES, ZID_MAX};

#[cfg(feature = "tls")]
pub mod tls;

/// The numbers a node's link and session are tuned with. They are the same for every front end: a
/// declaration states what a node answers and dials, not how its link is tuned.
pub mod tuning {
    /// Sessions the node holds at most: the one it dials.
    pub const SESSIONS: usize = 1;
    /// The runtime's task table: a pump task per session, and nothing else runs as a task.
    pub const TASKS: usize = SESSIONS;
    /// Bytes of one task cell of a node that only ANSWERS: the pump's handle and the application
    /// layer's state. A task the cell cannot hold is refused and counted, and the loop says so on
    /// the console rather than run a node that never starts a session.
    ///
    /// Measured on 2026-10-23 by building the node with each size and running it against a port
    /// nobody listens on, which spawns the session's task and says whether the cell held it: the
    /// answering node is refused at 2,112 bytes and held at 2,176. The cell is the next step up with
    /// about a fifth to spare. The 1,024 bytes the answering node had before refused its task, and
    /// so did the revision before `slot_node` (so it is not that change's doing). The kit's cell is
    /// 384 bytes (`fixed_client.rs`) and holds the session there.
    pub const TASK_BYTES_ANSWERING: usize = 2560;
    /// Bytes of one task cell of a node that also ASKS (`get`): it keeps the session's pending
    /// queries in that state, nine rows of the key text and the sink each, which is what the larger
    /// cell is for. Measured the same day: the asking node is refused at 2,304 bytes and held at
    /// 2,560; the cell is the next step up with about a fifth to spare.
    pub const TASK_BYTES_ASKING: usize = 3072;
    /// Bytes of one task cell of a node that PUBLISHES and ASKS on its own (a declared node): what the
    /// answering node keeps, a handle to its own session, the schedules and the publications of at
    /// most four publishers and four queriers (a declaration holds no more, `wz_node.py`), and the
    /// pending queries of the queriers (a row each, with a two-word sink). Not found by the search
    /// the numbers above were: it is a step above the asking node's cell, which holds the pending
    /// rows alone, and a task a cell cannot hold is refused and said on the console, so the node
    /// that does not start says why. The interop runs of the declared nodes start a session in it.
    /// It is `.bss`, so the cell a node that only publishes does not need costs no flash.
    pub const TASK_BYTES_ACTIVE: usize = 4096;
    /// Timers the runtime holds: the handshake and lease deadlines of the session.
    pub const TIMERS: usize = 4;
    /// The batch the node advertises: an Ethernet frame less the IPv4 and UDP headers, as the kit's.
    pub const BATCH_SIZE: u16 = (1500 - 20 - 8) as u16;
    /// Extra bytes a link's receive buffer holds beyond one batch, so a datagram that carries a
    /// batch and a transport header is not truncated.
    pub const RX_SLACK: usize = 64;
    /// The receive buffer of the session's driver.
    pub const RX: usize = BATCH_SIZE as usize + RX_SLACK;
    /// The storage the session's frames are encoded into: the largest frame it sends is one batch.
    pub const TX: usize = BATCH_SIZE as usize;
    /// How long the loop sleeps between two dials of a router that is not up: it holds no socket
    /// then, and would otherwise spin.
    pub const IDLE_SLEEP_US: u32 = 1_000;
    /// The most the node's link waits for a datagram when its session has nothing due sooner. The
    /// node has ONE session ([`SESSIONS`]) and its loop waits on nothing else, so the link may
    /// sleep until the session's next deadline (the lease, the keep-alive) instead of waking every
    /// millisecond; with more sessions this would leave the others' sockets unread. The link wakes
    /// for a datagram at once, and arms its timeout at a power of two not above the deadline, so no
    /// deadline is late.
    pub const IDLE_WAIT_MS: u32 = 1_000;
    /// The longest document a queryable may answer with: the pool every document is a prefix of.
    pub const DOC_MAX: usize = 4096;
    /// The longest zenoh id: 16 bytes.
    pub const ZID_LEN: usize = super::ZID_MAX;
}

/// The name a node's console lines carry ("host-slot-node: session established").
pub trait ConsoleName {
    /// The name.
    const NAME: &'static str;
}

/// The host's console and its sleep: what the node's loop cannot know
/// (`wz_session_mcu::slot_node::NodePort`), under the name `N` gives.
pub struct HostPort<N: ConsoleName>(PhantomData<N>);

impl<N: ConsoleName> HostPort<N> {
    /// The port.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<N: ConsoleName> Default for HostPort<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: ConsoleName> NodePort for HostPort<N> {
    const NAME: &'static str = N::NAME;

    fn log(&mut self, line: fmt::Arguments<'_>) {
        log_args(line);
    }

    fn idle(&mut self, us: u32) {
        yield_us(us);
    }
}

/// The reason a host that cannot supply entropy stops the node, as the console line.
const NO_ENTROPY: &str = "wz: FAIL - getrandom could not fill the signing key";

/// The cookie-signing secret a node starts with.
///
/// The secret is a secret, so it comes from the kernel's entropy and a host that cannot supply it
/// stops the node: a predictable key is worse than no node. The reason is the console line.
pub fn fresh_signing_key() -> Result<[u8; SIGNING_KEY_BYTES], &'static str> {
    let mut key = [0u8; SIGNING_KEY_BYTES];
    PosixEntropy
        .try_fill_bytes(&mut key)
        .map_err(|_| NO_ENTROPY)?;
    Ok(key)
}

/// How a node joins its multicast group on the host.
#[cfg(feature = "multicast")]
pub mod group {
    use wz_runtime_coop::session_drive::LinkOpenError;
    pub use wz_runtime_posix::group::PosixGroupTransport;
    use wz_runtime_posix::net::PosixNetError;
    use wz_session_mcu::slot_group::{GroupBind, GROUP_BATCH_BYTES};

    use super::tuning::RX_SLACK;

    /// The receive buffer of the group's receiver: a batch the group's members agree on, and the
    /// slack a datagram carries beyond it.
    pub const GROUP_RX: usize = GROUP_BATCH_BYTES as usize + RX_SLACK;

    /// The transport of the group, as the host opens it.
    pub type HostGroupTransport = PosixGroupTransport<GROUP_RX>;

    /// Joins `group` on `port` through the interface the kernel's routing picks, sending with `ttl`.
    #[derive(Debug, Clone, Copy)]
    pub struct PosixGroupBind {
        /// The group's address.
        pub group: [u8; 4],
        /// The group's port.
        pub port: u16,
        /// The hop limit of what the node sends.
        pub ttl: u8,
    }

    impl GroupBind<HostGroupTransport> for PosixGroupBind {
        fn bind(&mut self) -> Result<HostGroupTransport, LinkOpenError> {
            PosixGroupTransport::join(self.group, self.port, [0; 4], self.ttl).map_err(
                |e| match e {
                    // The process has no descriptor left: worth a later try.
                    PosixNetError::Socket(_) => LinkOpenError::Exhausted,
                    // The kernel would not bind the port or join the group.
                    _ => LinkOpenError::Refused,
                },
            )
        }
    }
}

/// A random zenoh id. Over the secure channel the node's id is the one its key names and this is not
/// asked for (`tls::identity`), so a build with `tls` does not call it.
pub fn fresh_zid() -> Result<[u8; ZID_MAX], &'static str> {
    let mut zid = [0u8; ZID_MAX];
    PosixEntropy
        .try_fill_bytes(&mut zid)
        .map_err(|_| NO_ENTROPY)?;
    Ok(zid)
}
