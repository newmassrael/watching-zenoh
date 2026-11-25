// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The in-memory group the tests of a group over a transport the program supplies share, in both
//! forms of the engine's calls: each member's datagram is handed to every other member with the
//! address the sender is known by, as a group socket hands it in.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{
    AppPort, AppTransport, LockedCall, SessionTransport, TableLock,
};
use wz_session_core::multicast_params::GroupJoinRule;
use wz_session_core::wire_const::T_MID_JOIN;
use wz_session_core::WhatAmI;

use super::{client_config, config_zid};
use crate::app_link::AppLinks;
use crate::{CoopConfig, CoopEngine, OpenError};

pub(super) type Engine = CoopEngine<AppLinks, PosixClock>;

/// The group every member joins. Synthetic: no socket is opened for it.
pub(super) const GROUP: &str = "udp/239.7.7.7:7447#iface=lan7";

/// The address a member's datagrams come from.
pub(super) fn source(member: u8) -> String {
    format!("udp/192.0.2.{member}:7447")
}

/// The group as the members' stacks share it.
#[derive(Default)]
pub(super) struct Network {
    /// Each member's group link and its transport.
    pub(super) joined: Mutex<Vec<Joined>>,
    /// How many times a member's stack was told to leave the group.
    pub(super) leaves: AtomicUsize,
    /// Each member whose stack was asked to join the group, once per join.
    pub(super) joins: Mutex<Vec<u8>>,
    /// Each member that sent a JOIN beacon on the group, once per beacon.
    pub(super) beacons: Mutex<Vec<u8>>,
    /// Each datagram a member sent on the group, with the member (read by the tests of a get).
    #[cfg(feature = "query")]
    pub(super) datagrams: Mutex<Vec<(u8, Vec<u8>)>>,
}

impl Network {
    /// How many JOIN beacons `member` sent on the group.
    pub(super) fn beacons_of(&self, member: u8) -> usize {
        self.beacons
            .lock()
            .unwrap()
            .iter()
            .filter(|sent| **sent == member)
            .count()
    }

    /// How many times `member`'s stack was asked to join the group.
    pub(super) fn joins_of(&self, member: u8) -> usize {
        self.joins
            .lock()
            .unwrap()
            .iter()
            .filter(|joined| **joined == member)
            .count()
    }

    /// `member`'s stack loses its group link, as an interface that goes down loses it: the stack
    /// tells the session the link is closed.
    #[cfg(feature = "threads")]
    pub(super) fn cut(&self, member: u8) {
        let lost: Vec<Joined> = {
            let mut joined = self.joined.lock().unwrap();
            let (lost, kept) = joined.drain(..).partition(|j| j.member == member);
            *joined = kept;
            lost
        };
        for joined in lost {
            if let Some(transport) = joined.transport.upgrade() {
                let _ = transport.event(
                    joined.link,
                    wz_session_core::app_link_table::ProgramEvent::Closed,
                );
            }
        }
    }
}

pub(super) struct Joined {
    member: u8,
    link: LinkHandle,
    transport: Weak<AppTransport>,
}

/// One member's stack: it joins [`GROUP`], with whatever keys follow it, and refuses anything
/// else, and hands what its session sends on the group to every other member, from [`source`].
pub(super) struct MemberStack {
    pub(super) network: Arc<Network>,
    pub(super) member: u8,
    /// Its own transport, given once the transport is made over this stack.
    pub(super) transport: Arc<Mutex<Weak<AppTransport>>>,
}

impl AppPort for MemberStack {
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
        if kind != AppLinkKind::Group || !locator.starts_with(GROUP) {
            return ProgramOpen::Refused;
        }
        let transport = self.transport.lock().unwrap().clone();
        self.network.joins.lock().unwrap().push(self.member);
        self.network.joined.lock().unwrap().push(Joined {
            member: self.member,
            link,
            transport,
        });
        ProgramOpen::Up
    }

    fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        // A beacon is sent alone in its datagram; the low five bits of a header are its id.
        if bytes
            .first()
            .is_some_and(|header| header & 0x1f == T_MID_JOIN)
        {
            self.network.beacons.lock().unwrap().push(self.member);
        }
        #[cfg(feature = "query")]
        self.network
            .datagrams
            .lock()
            .unwrap()
            .push((self.member, bytes.to_vec()));
        let others: Vec<(LinkHandle, Arc<AppTransport>)> = self
            .network
            .joined
            .lock()
            .unwrap()
            .iter()
            .filter(|joined| joined.member != self.member)
            .filter_map(|joined| Some((joined.link, joined.transport.upgrade()?)))
            .collect();
        let from = source(self.member);
        for (link, transport) in others {
            // A member that cannot take it now drops it, as a group socket does.
            let _ = transport.received(link, bytes, Some(from.as_str()));
        }
        ProgramSend::Wrote(bytes.len())
    }

    fn close(&self, link: LinkHandle) {
        self.network
            .joined
            .lock()
            .unwrap()
            .retain(|joined| !(joined.member == self.member && joined.link == link));
        self.network.leaves.fetch_add(1, Ordering::SeqCst);
    }
}

/// The table of a member's transport, under the host's lock.
pub(super) struct Table(pub(super) Mutex<AppLinkTable>);

impl TableLock for Table {
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable) -> LockedCall) -> LockedCall {
        f(&mut self.0.lock().unwrap())
    }
}

/// What every member's beacon advertises: zenoh-pico's terms, beaconed often so the members
/// learn each other within the test.
pub(super) fn profile() -> GroupProfile {
    GroupProfile {
        lease_ms: 10_000,
        join_interval_ms: 100,
        max_sessions: None,
        seq_num_res: wz_session_core::policy::SnResolution::Bits32,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        compression: false,
        join_rule: GroupJoinRule::Pico,
    }
}

/// A peer's config that dials nothing and joins `endpoint`.
pub(super) fn member_config(member: u8, endpoint: &str) -> CoopConfig {
    CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(member),
        groups: vec![GroupJoin {
            endpoint: endpoint.to_owned(),
            profile: profile(),
            is_shm: false,
            declarations: GroupDeclarations::Entities,
        }],
        ..client_config()
    }
}

/// Open a session for `member` over a stack of `network`.
pub(super) fn open_member(
    network: &Arc<Network>,
    member: u8,
    config: CoopConfig,
) -> Result<Arc<Engine>, OpenError> {
    let own = Arc::new(Mutex::new(Weak::new()));
    let transport = Arc::new(AppTransport::new(
        Box::new(Table(Mutex::new(AppLinkTable::new()))),
        Box::new(MemberStack {
            network: Arc::clone(network),
            member,
            transport: Arc::clone(&own),
        }),
    ));
    *own.lock().unwrap() = Arc::downgrade(&transport);
    let links = AppLinks::new(SessionTransport::new(transport, &config.limits));
    Engine::open(links, PosixClock, PosixEntropy, config)
}
