// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The other direction of a session's own scouting (R3071): a node that is FOUND answers a Scout
//! that asks for its role with a Hello ([`bind_responder`]), naming where its listener is
//! reached ([`Advertised`]).
//!
//! The decision to answer is the runtime's responder's and is pure; this module resolves whether
//! the node answers (`scouting/multicast/listen`), builds what it says about itself, and binds
//! the sockets. Its own module, and the `peer` feature's, because only a node with a listener has
//! anything to be found at: the half that LOOKS for nodes ([`crate::scouting_node`]) is the
//! `scout` feature's, which a client that scouts for its router keeps.

use std::io;
use std::net::IpAddr;

pub use wz_runtime_tokio::scouting_responder::LateLocators;
use wz_runtime_tokio::scouting_responder::{
    bind_reply_sockets, serve, ResponderIdentity, ScoutingResponder,
};
use wz_runtime_tokio::session_open::BoundListener;
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};

use crate::scouting_node::{
    group_join_interface, join_beyond_the_first, named_interface_addresses, ScoutingPlan,
};

/// How a node is reached, as a Hello says it: the locator list for a scouter on this host and the
/// one for a scouter beside it, which differ only by the loopback addresses an unspecified bind
/// expands to. See [`ResponderIdentity::with_noloopback_locators`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Advertised {
    /// What a process on this host is told.
    pub local: Vec<String>,
    /// What a node on another host is told.
    pub remote: Vec<String>,
}

impl Advertised {
    /// What a node with no listener tells a scouter: nothing it could dial. Upstream answers a
    /// Hello with an empty locator list for a node bound to nothing (`listen/endpoints: []`).
    pub fn none() -> Self {
        Self::default()
    }

    /// The locators `bound` is reached at, once bound.
    ///
    /// The address is the one the listener ACTUALLY got, as upstream's is: it rebuilds the
    /// endpoint from the bound socket address after the bind, so a port of `0` is advertised as
    /// the port the kernel gave and a name as the address it resolved to
    /// (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @
    /// `// Update the endpoint locator address`). An unspecified bind stands for the addresses of
    /// the host, listed with and without the loopback ones
    /// ([`wz_runtime_tokio::link_interfaces::expand_unspecified`]); when the host's addresses
    /// cannot be read it stands for none, and the node is findable and not dialable, which is
    /// what the Hello then says. The scheme and its metadata (`?rel=0`) are the listener kind's.
    pub fn of(bound: &BoundListener) -> Self {
        use wz_runtime_tokio::link_interfaces::{expand_unspecified, local_addresses};

        let Ok(socket) = bound.local_addr() else {
            // A listener with no IP address (a unix socket, a serial line) is reached at the
            // address it renders.
            return match bound.local_addr_display() {
                Ok(address) => {
                    let locator = bound.advertised_locator(&address);
                    Self {
                        local: vec![locator.clone()],
                        remote: vec![locator],
                    }
                }
                Err(_) => Self::none(),
            };
        };
        let locators = |exclude_loopback: bool| -> Vec<String> {
            let local = if socket.ip().is_unspecified() {
                local_addresses().unwrap_or_default()
            } else {
                Vec::new()
            };
            expand_unspecified(socket, &local, exclude_loopback)
                .iter()
                .map(|address| bound.advertised_locator(&address.to_string()))
                .collect()
        };
        Self {
            local: locators(false),
            remote: locators(true),
        }
    }

    /// The locators of every listener of a session, in the order the listeners were bound.
    ///
    /// R3076 -- a node that listens on several endpoints is reached at all of them, and its Hello
    /// and its gossip entry name them all. MEASURED on the real library with two tcp endpoints:
    /// the Hello lists both, in an order that is not the config's (upstream keeps a protocol's
    /// listeners in a hash map, and the real library names the same two in either order from one
    /// run to the next), so a reader compares the locators as a set. A locator two listeners both
    /// expand to is listed once, as a set of locators would hold it.
    pub fn of_all(bound: &[&BoundListener]) -> Self {
        let mut all = Self::none();
        for listener in bound {
            let one = Self::of(listener);
            for (into, from) in [(&mut all.local, one.local), (&mut all.remote, one.remote)] {
                for locator in from {
                    if !into.contains(&locator) {
                        into.push(locator);
                    }
                }
            }
        }
        all
    }
}

/// A session's scouting responder, answering until it is dropped.
///
/// Dropping it ends the answering: it runs on a task of the session's own runtime, and a session
/// that is closing has no node left to be found at.
pub struct Findable {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Findable {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A responder whose sockets are bound and joined and which answers nobody yet.
///
/// Binding and answering are two steps because upstream's are: a client binds its scouting socket
/// BEFORE it searches for a node to connect to, and starts answering only AFTER it has connected
/// (`zenoh/src/net/runtime/orchestrator.rs` @ `async fn start_client(&self) -> ZResult<()> {`,
/// where `this.responder(&mcast_socket, &sockets)` is spawned after `connect_first`). MEASURED on
/// the real library: a client with a listener and nothing to dial answers no Scout while it
/// searches. A bind that fails fails the open at the first step, and the search is then never
/// started.
pub struct Responder {
    inner: ScoutingResponder,
}

impl Responder {
    /// Begin answering, until the returned [`Findable`] is dropped.
    pub fn start(self) -> Findable {
        let responder = self.inner;
        // Network-tier upkeep, on the subsystem upstream puts its scouting on
        // (`commons/zenoh-runtime/src/lib.rs` @ `pub enum ZRuntime`: `Net`), so `WZ_RUNTIME`
        // paces it. Aborted when the [`Findable`] drops, which is before the session's own
        // runtime is, so the socket it reads is never polled after its reactor is gone.
        let task = wz_runtime_tokio::runtime_pool::WzRuntime::Net.spawn(async move {
            let _ = serve(responder, |_step| {}).await;
        });
        Findable { task }
    }
}

/// Bind the responder of a node: join the plan's group and be ready to answer a Scout that asks
/// for this node's role with a Hello naming its zid, its role and where it is reached.
///
/// `None` when the plan says the node does not answer (`scouting/multicast/listen: false`).
/// Bound before the open returns, so a node that cannot join its group fails its OPEN, as
/// upstream's `start_scout` does with the `?` on its multicast bind (the responder shares that
/// socket there), and a node that was told to be findable is never silently not.
///
/// The Hello leaves from the unicast socket nearest the asker, as upstream's does
/// (`orchestrator.rs` @ `fn get_best_match<'a>(`): one per interface that can carry multicast
/// when the config names none, and the named interface's own addresses when it does.
///
/// R3089 -- `late` is where the listeners that bind after the responder started are told to it:
/// the next Hello names each, as it names the ones bound before.
pub async fn bind_responder(
    plan: &ScoutingPlan,
    whatami: wz_runtime_tokio::session_glue::WhatAmI,
    zid: &[u8],
    advertised: Advertised,
    late: LateLocators,
) -> io::Result<Option<Responder>> {
    if !plan.answers {
        return Ok(None);
    }
    let identity = ResponderIdentity::try_new(whatami, zid.to_vec(), advertised.local)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        .with_noloopback_locators(advertised.remote);
    let named = plan
        .interface
        .as_deref()
        .map(named_interface_addresses)
        .unwrap_or_default();
    let join = group_join_interface(plan, &named);
    let config = McastSocketConfig {
        iface: join.as_deref(),
        ttl: plan.ttl,
        ..McastSocketConfig::default()
    };
    let group_socket = UdpDriver::bind_scouting_group(plan.group, plan.port, config).await?;
    join_beyond_the_first(&group_socket, plan.group, &named);
    let replies = match plan.interface {
        Some(_) => named,
        None => {
            wz_runtime_tokio::link_interfaces::multicast_interface_addresses().unwrap_or_default()
        }
    };
    // An address that cannot be held a moment after it was listed leaves the node answering from
    // the interfaces that bound; the election runs on those.
    // Heard on every interface the config scouts on, as upstream's one socket is joined on each
    // (`bind_mcast_port`). The bind above joined the group on the interface the kernel chose; a
    // config that names an interface is joined on that one alone, which is that bind. An
    // interface already joined or gone is skipped, as upstream warns and goes on.
    if plan.interface.is_none() {
        for iface in &replies {
            // Upstream joins an IPv4 group on each interface address and an IPv6 group once, on
            // interface 0 (`bind_mcast_port`), which the bind above already did.
            if let (IpAddr::V4(group), IpAddr::V4(iface)) = (plan.group, iface) {
                let _ = group_socket.join_multicast_v4_on(group, *iface);
            }
        }
    }
    // The addresses that could not be held are not reported: this crate has no logger, and the
    // election runs on the sockets that bound.
    let reply_sockets = bind_reply_sockets(&replies).await.0;
    Ok(Some(Responder {
        inner: ScoutingResponder::with_reply_sockets(group_socket, identity, reply_sockets)
            .with_late_locators(late),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener bound to the unspecified address is advertised at the addresses of THIS host,
    /// read from its own interface table: the loopback address for a scouter on the host, and
    /// no unspecified address for anyone. The table is the host's (`getifaddrs` on a unix host,
    /// `GetAdaptersAddresses` on Windows), so this is the end-to-end answer of the reading
    /// that the unit tests of `link_interfaces` tell only on tables made for them. A host whose
    /// table could not be read advertises nothing, and that is what this refuses.
    #[test]
    fn a_wildcard_listener_is_advertised_at_the_hosts_own_addresses() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let bound = runtime
            .block_on(wz_runtime_tokio::session_open::bind_endpoint(
                "tcp/0.0.0.0:0",
            ))
            .expect("a wildcard tcp listener binds");
        let port = bound.local_addr().expect("a bound address").port();

        let advertised = Advertised::of(&bound);

        let loopback = format!("127.0.0.1:{port}");
        assert!(
            advertised
                .local
                .iter()
                .any(|locator| locator.contains(&loopback)),
            "a scouter on the host is told no loopback locator: {:?}",
            advertised.local
        );
        assert!(
            advertised
                .remote
                .iter()
                .all(|locator| !locator.contains("127.0.0.1")),
            "a node beside is told a loopback locator: {:?}",
            advertised.remote
        );
        for locator in advertised.local.iter().chain(advertised.remote.iter()) {
            assert!(
                !locator.contains("0.0.0.0"),
                "the unspecified address was advertised: {locator}"
            );
        }
    }
}
