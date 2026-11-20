// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins, each a face of the session beside its links.
//!
//! A group's session is the session shell's (`wz_session_mcu::group_drive`), the one an MCU image
//! runs, hosted as a task of the session's local set as each link's session is: its JOIN beacon,
//! the members it admits, its lease sweep, the per-member order of what they send and the framing
//! of what it sends are that session's, and every rule they follow is the session core's
//! (`multicast_dispatch`, `multicast_rx`, `multicast_tx`). The dispatcher keeps each member's
//! declarations apart from the moment it is built (`MulticastConfig::scoping_members`), as the
//! tokio engine's group face does, since two members number their entities alike.
//!
//! What this module adds is the hosting: the group's tables in the session's registry, where what
//! a member sends is dispatched as a peer's frames are; the queue the session puts its own
//! messages on, which the group's task drains with the replies its dispatch stages; the members
//! the group's JOINs admitted; and the stop the session's close asks for, after which the task
//! tells the group it leaves.

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use core::net::SocketAddr;

use wz_capi_port::group::GroupDeclarations;
use wz_capi_port::FanoutError;
use wz_runtime_coop::group_transport::GroupTransport;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::multicast_dispatch::MulticastConfig;
use wz_session_core::multicast_params::{MulticastOutcome, MulticastParams};
use wz_session_core::multicast_peer_lost::MulticastPeerId;
use wz_session_core::multicast_reply_sink::{MulticastReplyEnqueue, MulticastReplySink};
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::push_build;
use wz_session_core::qos::Priority;
use wz_session_core::sample::SampleKind;
use wz_session_core::WhatAmI;
use wz_session_mcu::group_drive::{
    spawn_multicast_session_seeded, MulticastReplyQueue, MulticastSessionSeed,
};

#[allow(unused_imports)]
use crate::prelude::*;

use super::registry::{FaceId, Registry};

/// The rows of each group's member table: a member whose JOIN finds them all held is turned
/// away, as a group whose `max_sessions` is reached turns one away. A table that does not grow,
/// so that what a group holds is what it was given when it was joined; the tokio engine's group
/// face starts from the same count of rows and grows past it, and zenoh-pico states no cap.
pub(super) const GROUP_MEMBERS: usize = 32;

/// How often a group's task looks at its beacon, its lease sweep and its stop when nothing
/// arrives, in milliseconds, and so the longest a read waits while the session holds a group: the
/// tick of the tokio engine's group face, shorter than any beacon interval an ABI advertises.
pub(super) const GROUP_TICK_MS: u32 = 50;

/// What a group's dispatch hands what it staged to: the group's queue, which its task drains.
pub(super) type GroupReplies = MulticastReplySink<MulticastReplyQueue>;

/// A member the group's JOINs admitted: who it is and the role it announced.
struct Member {
    peer: MulticastPeerId,
    whatami: Option<WhatAmI>,
}

/// The stack's group transport as the group's task holds it, marked each time it hands the task
/// a datagram: the task takes one datagram a step, as the group's loop always has, so a group
/// that took one may hold more, and the session's read steps it again at once rather than after
/// a tick.
struct Watched {
    inner: alloc::boxed::Box<dyn GroupTransport>,
    took: Rc<Cell<bool>>,
}

impl GroupTransport for Watched {
    fn open(&mut self) -> bool {
        self.inner.open()
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn service(&self) {
        self.inner.service();
    }

    fn carrier_up(&self) -> bool {
        self.inner.carrier_up()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        self.inner.send_to_group(datagram);
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let took = self.inner.recv_with(f);
        if took {
            self.took.set(true);
        }
        took
    }
}

/// What a group is joined with: the face its tables are in, what the session tells it of its
/// declarations, the stack's transport and the parameters its session runs with.
pub(super) struct GroupJoining {
    pub(super) id: FaceId,
    pub(super) declarations: GroupDeclarations,
    pub(super) transport: alloc::boxed::Box<dyn GroupTransport>,
    pub(super) params: MulticastParams,
    pub(super) policy: SessionPolicy,
}

/// One group of the session: its face, its task, its queue, its members and its stop.
pub(super) struct GroupFace {
    id: FaceId,
    declarations: GroupDeclarations,
    task: CoopLocalJoinHandle<MulticastOutcome>,
    tx: MulticastReplyQueue,
    members: Rc<RefCell<Vec<Member>>>,
    took: Rc<Cell<bool>>,
    stop: Rc<Cell<bool>>,
}

impl GroupFace {
    /// Join the group `joining` names, whose tables the registry holds already, its session
    /// spawned on `local`: each event of it goes through `dispatch`, with the sink the group's
    /// replies are queued on, after the members it admits and loses are noted. The task opens the
    /// transport as the session's link at its first step, which the caller runs.
    pub(super) fn join<C, D>(local: &CoopLocalSet<C>, joining: GroupJoining, dispatch: D) -> Self
    where
        C: ClockSource + 'static,
        D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
    {
        let GroupJoining {
            id,
            declarations,
            transport,
            params,
            policy,
        } = joining;
        let tx = MulticastReplyQueue::new();
        let members: Rc<RefCell<Vec<Member>>> = Rc::new(RefCell::new(Vec::new()));
        let took = Rc::new(Cell::new(false));
        let stop = Rc::new(Cell::new(false));
        let config = MulticastConfig::new(params.lease_ms)
            .with_max_sessions(params.max_sessions)
            .scoping_members();
        let seed: MulticastSessionSeed<Watched, GROUP_MEMBERS> = MulticastSessionSeed::new(
            config,
            Watched {
                inner: transport,
                took: Rc::clone(&took),
            },
            params,
            policy,
            u64::from(GROUP_TICK_MS),
        );
        let on_event = noting_members(
            Rc::clone(&members),
            MulticastReplySink::new(tx.clone()),
            dispatch,
        );
        let next_tx = {
            let tx = tx.clone();
            move || tx.pop()
        };
        let should_stop = {
            let stop = Rc::clone(&stop);
            move || stop.get()
        };
        let task = spawn_multicast_session_seeded(local, seed, on_event, next_tx, should_stop);
        Self {
            id,
            declarations,
            task,
            tx,
            members,
            took,
            stop,
        }
    }

    /// The face the group's tables are in.
    pub(super) fn id(&self) -> FaceId {
        self.id
    }

    /// What the session tells the group of its declarations.
    pub(super) fn declarations(&self) -> GroupDeclarations {
        self.declarations
    }

    /// Whether the group's session has ended: it left the group, lost its link, or could not
    /// open it.
    pub(super) fn has_ended(&self) -> bool {
        self.task.is_finished()
    }

    /// Whether the group's task took a datagram since this was last asked.
    pub(super) fn took_input(&self) -> bool {
        self.took.replace(false)
    }

    /// Ask the group's session to stop: at its next step it tells the group it leaves and lets
    /// the group's link go.
    pub(super) fn stop(&self) {
        self.stop.set(true);
    }

    /// The members the group holds, each by its zid and the wire code of the role it announced;
    /// a member whose role this node does not know is not one a caller can name, and a group whose
    /// session ended holds none.
    pub(super) fn member_identities(&self) -> Vec<(Vec<u8>, u8)> {
        if self.has_ended() {
            return Vec::new();
        }
        self.members
            .borrow()
            .iter()
            .filter_map(|member| {
                let role = member.whatami?;
                Some((member.peer.as_slice().to_vec(), role.to_wire()))
            })
            .collect()
    }

    /// Put a publication on the group, naming its key in full: the group is told no keyexpr the
    /// session declares unless its declarations say so (`GroupDeclarations::declares_keyexprs`),
    /// which a group whose session tells it its entities, or less, does not. Built by the session
    /// core's Push builders, as a link's is, and framed by the group's task with the sequence
    /// number of its channel. A group whose session ended is sent nothing.
    pub(super) fn publish(&self, put: GroupPut<'_>) -> Result<usize, FanoutError> {
        if self.has_ended() {
            return Ok(0);
        }
        let push = match put.kind {
            SampleKind::Put => {
                push_build::build_push_literal_with_meta(put.keyexpr, put.payload, put.meta)
            }
            SampleKind::Del => push_build::build_push_del_literal_with_meta(put.keyexpr, put.meta),
        }
        .map_err(|_| FanoutError::ExceedsCapacity)?;
        self.tx.enqueue(MulticastTxItem::Push {
            push: alloc::boxed::Box::new(push),
            reliable: put.reliable,
            priority: put.priority,
        });
        Ok(0)
    }
}

/// The `on_event` of a group's session: the members its JOINs admit and the ones it loses are
/// noted, and then the event goes through `dispatch` with the sink the group's replies are queued
/// on.
fn noting_members<D>(
    members: Rc<RefCell<Vec<Member>>>,
    replies: GroupReplies,
    mut dispatch: D,
) -> impl FnMut(IterationEvent<'_, '_>) + 'static
where
    D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
{
    move |event| {
        match &event {
            IterationEvent::MulticastPeerArrived(arrived) => {
                members.borrow_mut().push(Member {
                    peer: arrived.peer,
                    whatami: arrived.whatami,
                });
            }
            IterationEvent::MulticastPeerLost(lost) => {
                members
                    .borrow_mut()
                    .retain(|member| member.peer != lost.peer);
            }
            _ => {}
        }
        dispatch(event, &replies);
    }
}

/// One publication the session puts on its groups.
pub(super) struct GroupPut<'a> {
    pub(super) keyexpr: &'a str,
    pub(super) payload: &'a [u8],
    pub(super) kind: SampleKind,
    pub(super) meta: &'a PushMetadata,
    pub(super) reliable: bool,
    pub(super) priority: Priority,
}

/// The dispatch of a group whose session answers queries outside its lock: the registry's, with
/// the `ResponseFinal`s it owes held for the queries a callback is still to answer, as a link's
/// is, and what it staged queued on the group. A member's query is held under the group's own
/// `generation`, so the answer it is owed is the group's and no link's.
#[cfg(feature = "queryable")]
pub(super) fn dispatch(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    policy: SessionPolicy,
    plane: alloc::sync::Arc<super::query::QueryPlane>,
    generation: u64,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    use core::sync::atomic::Ordering;
    use wz_session_core::response_sink::ResponseSink;
    move |event, replies| {
        let mut registry = registry.borrow_mut();
        plane.arriving.store(generation, Ordering::Release);
        registry
            .app
            .set_unanswerable_final(policy.query_unanswerable_final());
        registry.dispatch_event(face, event);
        registry.flush_pending_replies(face, replies);
        for (rid, qos) in registry.take_pending_final_rids(face) {
            if super::lock(&plane.holds).owe(generation, rid, qos) {
                replies.send_response_final(rid, qos);
            }
        }
    }
}

/// The dispatch of a group whose session has no queryable: the registry's, with everything it
/// staged queued on the group at once.
#[cfg(not(feature = "queryable"))]
pub(super) fn dispatch(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    move |event, replies| registry.borrow_mut().dispatch(face, event, replies)
}
