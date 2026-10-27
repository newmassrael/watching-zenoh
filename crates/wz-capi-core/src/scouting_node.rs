// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session's OWN scouting: finding, over multicast, the nodes it should connect to.
//!
//! [`crate::scouting`] is `z_scout`: a one-shot survey a program asks for and reads. This is
//! the other thing zenoh does with the same group. A node that is not told where to connect
//! looks for peers and routers itself, and zenoh opens a session to each it is willing to
//! (`zenoh/src/net/runtime/orchestrator.rs` @ `async fn autoconnect_all(`), and a client with
//! nothing to dial scouts for the first one it can open (`connect_first`). Before this the C
//! ABI refused a config that stated no endpoint while scouting was on, so a program that calls
//! `z_open` on a default config, which is what every shipped example does without `-e`, could
//! not open at all.
//!
//! ## What is here and what is not
//!
//! This module resolves WHAT to look for and binds the sockets; the decision about each answer
//! is [`wz_runtime_tokio::scouting_autoconnect::autoconnect_verdict`] and the dial is the
//! drive's (`crate::drive`), face by face on its own task.
//!
//! The other direction, a node that is FOUND answering a Scout with a Hello (R3071), is
//! [`crate::scouting_responder`]'s: a node that looks for others is not one that is looked for, and
//! only the second has a listener.
//!
//! ## Re-scouting is the recovery path
//!
//! The runtime's `serve_autoconnect` posts an intent once per peer for the life of the loop,
//! which is right for the mesh loop that owns a retry schedule of its own. Upstream's
//! `autoconnect_all` has none: it calls `connect_peer` for every Hello of every window, and a
//! peer whose link was lost is dialled again the next time it answers. So this loop posts the
//! intents of every window, and the drive drops one for a peer it already holds a face to or is
//! dialling.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};
use wz_routing_graph::{AutoConnect, AutoConnectStrategies, Zid};
use wz_runtime_tokio::accept_loop::DialIntentSender;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_autoconnect::{autoconnect_verdict, AutoconnectVerdict};
use wz_runtime_tokio::scouting_fanout::{
    bind_scout_sockets, scout_interface_addresses, ScoutFanOut,
};
use wz_runtime_tokio::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutParams, ScoutedHello,
    ScoutingActions,
};
use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};

use crate::scouting::SCOUT_TICK_MS;

/// The first scouting window and the longest one, in milliseconds: a Scout goes out at the start
/// of each, and the next window is twice the last (`zenoh/src/net/runtime/orchestrator.rs` @
/// `const SCOUT_PERIOD_INCREASE_FACTOR: u32 = 2;`).
const SCOUT_INITIAL_PERIOD_MS: u64 = 1_000;
const SCOUT_MAX_PERIOD_MS: u64 = 8_000;
/// How often the answers of a running window are read.
const HARVEST_PERIOD: Duration = Duration::from_millis(20);

/// `scouting/multicast/address`'s default group and port.
const GROUP_DEFAULT: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224));
const PORT_DEFAULT: u16 = 7446;
/// `scouting/delay` and `scouting/timeout` defaults, in milliseconds.
const DELAY_DEFAULT_MS: u64 = 500;
const TIMEOUT_DEFAULT_MS: u64 = 3000;

/// `scouting/multicast/autoconnect`'s default for a node of role `whatami`: a router connects
/// to nobody a scout finds, a peer or a client to a router, a peer or a client
/// (`commons/zenoh-config/src/defaults.rs` @ `pub mod autoconnect {`).
fn default_autoconnect(whatami: wz_runtime_tokio::session_glue::WhatAmI) -> WhatAmIMatcher {
    match whatami {
        WhatAmI::Router => WhatAmIMatcher::empty(),
        WhatAmI::Peer | WhatAmI::Client => WhatAmIMatcher::empty().router().peer().client(),
    }
}

/// What a session does with multicast scouting, resolved from its config.
///
/// Every field is a value the config states or zenoh's shipped default for it
/// (`commons/zenoh-config/src/defaults.rs` @ `pub mod multicast {`); the host that reads the
/// config resolves them, so this crate holds no reading of its own.
#[derive(Clone, Debug)]
pub struct ScoutingPlan {
    /// The group scouts go to: `scouting/multicast/address`, of either family.
    pub group: IpAddr,
    /// Its port.
    pub port: u16,
    /// `scouting/multicast/interface`, `None` for upstream's `"auto"`.
    pub interface: Option<String>,
    /// `scouting/multicast/ttl`, `None` for the OS default (one subnet).
    pub ttl: Option<u32>,
    /// `scouting/delay`: how long a peer's open waits for its first scouted connection.
    pub delay: Duration,
    /// `scouting/timeout`: how long a client with nothing to dial scouts before it fails.
    pub timeout: Duration,
    /// `scouting/multicast/autoconnect` for this node's role: which roles it opens a session to
    /// when they answer. EMPTY is a real instruction (a router's default) and means it scouts
    /// for nobody.
    pub matcher: WhatAmIMatcher,
    /// `scouting/multicast/autoconnect_strategy`: the tie-break per discovered role.
    pub strategies: AutoConnectStrategies,
    /// `scouting/multicast/listen` for this node's role: whether it ANSWERS a Scout, so that
    /// another node can find it. Upstream's default is on for all three roles
    /// (`commons/zenoh-config/src/defaults.rs` @ `pub mod listen {`).
    pub answers: bool,
}

/// The group and port `scouting/multicast/address` names, zenoh's default for an unstated one, or
/// the refusal of one that is not a socket address.
fn group_of(node: &ZenohNodeConfig) -> Result<(IpAddr, u16), ScoutingConfigError> {
    match node.scout_multicast_address.as_deref() {
        None => Ok((GROUP_DEFAULT, PORT_DEFAULT)),
        Some(text) => match text.parse::<std::net::SocketAddr>() {
            Ok(addr) => Ok((addr.ip(), addr.port())),
            Err(_) => Err(ScoutingConfigError::Address(text.to_owned())),
        },
    }
}

/// The group a config named is not one this node can scout on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScoutingConfigError {
    /// `scouting/multicast/address` is not a socket address (`<ipv4>:<port>` or
    /// `[<ipv6>]:<port>`), so it is refused by name and not scouted on as a different group.
    Address(String),
}

impl ScoutingPlan {
    /// Whether this node looks for anyone at all.
    pub fn scouts(&self) -> bool {
        !self.matcher.is_empty()
    }

    /// The plan a node of role `whatami` with this config follows, or `None` when it scouts not
    /// at all because `scouting/multicast/enabled` is off.
    ///
    /// Every key left unstated takes zenoh's shipped default, which at the pinned version is:
    /// `224.0.0.224:7446`, interface `auto`, `scouting/delay` 500 ms, `scouting/timeout`
    /// 3000 ms, and autoconnect to routers, peers AND clients for a peer or a client and to
    /// nobody for a router, each under the `always` tie-break
    /// (`commons/zenoh-config/src/defaults.rs` @ `pub mod scouting {`).
    pub fn resolve(
        node: &ZenohNodeConfig,
        whatami: wz_runtime_tokio::session_glue::WhatAmI,
    ) -> Result<Option<Self>, ScoutingConfigError> {
        if !node.multicast_scouting {
            return Ok(None);
        }
        let (group, port) = group_of(node)?;
        let matcher = node
            .scout_multicast_autoconnect
            .unwrap_or_else(|| default_autoconnect(whatami));
        Ok(Some(Self {
            group,
            port,
            interface: node
                .scout_multicast_interface
                .clone()
                .filter(|iface| iface != "auto"),
            ttl: node.scout_multicast_ttl,
            delay: Duration::from_millis(node.scouting_delay_ms.unwrap_or(DELAY_DEFAULT_MS)),
            timeout: Duration::from_millis(node.scouting_timeout_ms.unwrap_or(TIMEOUT_DEFAULT_MS)),
            matcher,
            strategies: node
                .scout_multicast_autoconnect_strategy
                .unwrap_or_default(),
            answers: node.scout_multicast_listen.unwrap_or(true),
        }))
    }

    /// The plan of a scout a program asks for, as upstream's `scout(what, config)` reads its
    /// config (`zenoh/src/api/scouting.rs` @ `.multicast.address()`): the group, the interface and
    /// the hop limit the config states or zenoh's default for each, and NOTHING ELSE of it.
    /// Whether the config enables multicast scouting is a session's question, which `scout` does
    /// not ask; and a scout has no delay, no timeout, no tie-break and no role to answer for.
    /// `what` is the roles it asks for, in the API form.
    pub fn for_scout(node: &ZenohNodeConfig, what: u8) -> Result<Self, ScoutingConfigError> {
        let (group, port) = group_of(node)?;
        let mut matcher = WhatAmIMatcher::empty();
        for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            if what & role.to_api() != 0 {
                matcher = match role {
                    WhatAmI::Router => matcher.router(),
                    WhatAmI::Peer => matcher.peer(),
                    WhatAmI::Client => matcher.client(),
                };
            }
        }
        Ok(Self {
            group,
            port,
            interface: node
                .scout_multicast_interface
                .clone()
                .filter(|iface| iface != "auto"),
            ttl: node.scout_multicast_ttl,
            delay: Duration::from_millis(DELAY_DEFAULT_MS),
            timeout: Duration::from_millis(TIMEOUT_DEFAULT_MS),
            matcher,
            strategies: AutoConnectStrategies::default(),
            answers: false,
        })
    }

    /// The Scout's `what` byte: the roles asked for, in the API form
    /// (`Router=1 | Peer=2 | Client=4`).
    fn what(&self) -> u8 {
        [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .filter(|role| self.matcher.matches(*role))
            .fold(0u8, |bits, role| bits | role.to_api())
    }
}

/// The interface the GROUP socket is joined on. An IPv4 group is joined on the interface the
/// config names, and an IPv6 group is joined ONCE, on interface 0 -- the kernel's choice -- whatever
/// the config names, as upstream's `bind_mcast_port` does
/// (`zenoh/src/net/runtime/orchestrator.rs` @ `socket.join_multicast_v6(&addr, 0)`). That is why an
/// IPv6 Scout that leaves by a named interface is heard only when the kernel's choice and that
/// interface are the same one: it is a property of the host, and wz keeps it.
///
/// An IPv4 group named an interface list is joined on EACH IPv4 address the list holds, as
/// `bind_mcast_port` joins on each of the addresses `get_interfaces` returned. The bind takes the
/// first, as the address literal its config reads, and [`join_beyond_the_first`] joins the rest.
/// A list that holds no IPv4 address joins nothing upstream; here the bind joins on the kernel's
/// choice, which differs only for a node that hears a Scout it was never going to send one beside.
pub(crate) fn group_join_interface(plan: &ScoutingPlan, named: &[IpAddr]) -> Option<String> {
    if plan.group.is_ipv6() || plan.interface.is_none() {
        return None;
    }
    named
        .iter()
        .find(|address| address.is_ipv4())
        .map(IpAddr::to_string)
}

/// Join an IPv4 `group` on every named IPv4 address beyond the first, which the bind already
/// joined it on. An interface already joined or gone is skipped, as upstream warns and goes on.
pub(crate) fn join_beyond_the_first(group_socket: &UdpDriver, group: IpAddr, named: &[IpAddr]) {
    let IpAddr::V4(group) = group else { return };
    for address in named.iter().filter(|address| address.is_ipv4()).skip(1) {
        if let IpAddr::V4(iface) = address {
            let _ = group_socket.join_multicast_v4_on(group, *iface);
        }
    }
}

/// The addresses a Scout leaves by when the config names `interface`, read as upstream's
/// `get_interfaces` reads it: a comma-separated list, each part trimmed, an ADDRESS LITERAL being
/// that address of either family whether or not this host holds it
/// (`zenoh/src/net/runtime/orchestrator.rs` @ `name.trim().parse::<IpAddr>()`), and a NAME being
/// the FIRST IPv4 address of the interface it names, up or not. A part that finds nothing is left
/// out, so the list can be empty and the node then scouts by nothing. See
/// [`wz_runtime_tokio::link_interfaces::scouting_interface_addresses`], which decides it.
pub(crate) fn named_interface_addresses(interface: &str) -> Vec<IpAddr> {
    wz_runtime_tokio::link_interfaces::scouting_interface_addresses(
        interface,
        wz_runtime_tokio::link_interfaces::first_ipv4_of_interface_named,
    )
}

/// The scouting sockets of one node, bound: the group joined and a Scout sent from every
/// interface that can carry one.
///
/// Bound apart from [`Self::autoconnect`] so that a node which cannot bind fails its OPEN, as
/// upstream's `start_scout` does with the `?` on its multicast bind, rather than finding out on a
/// task nobody is watching.
pub struct ScoutLink {
    driver: ScoutFanOut,
}

impl ScoutLink {
    /// Join `plan`'s group and bind its ask sockets.
    pub async fn bind(plan: &ScoutingPlan) -> io::Result<Self> {
        let (group_socket, ask, refused) = Self::sockets(plan).await;
        let (driver, _shape) = ScoutFanOut::over(group_socket?, ask, refused);
        Ok(Self { driver })
    }

    /// The same sockets for a scout a program asks for, which does not need the group socket:
    /// upstream's `scout` receives on its per-interface sockets alone
    /// (`zenoh/src/api/scouting.rs` @ `Runtime::bind_ucast_port(iface, multicast_ttl).ok()`), so a
    /// group that cannot be joined costs it nothing, and a scout with no socket at all is a scout
    /// that finds nobody and is not an error (`ScoutInner { scout_task: None }`). `None` is that.
    pub async fn bind_for_scout(plan: &ScoutingPlan) -> Option<Self> {
        let (group_socket, ask, refused) = Self::sockets(plan).await;
        ScoutFanOut::over_optional(group_socket.ok(), ask, refused)
            .map(|(driver, _shape)| Self { driver })
    }

    /// The group socket (bound and joined, or the error that kept it from being) and the ask
    /// sockets of `plan`, with the addresses that refused.
    async fn sockets(
        plan: &ScoutingPlan,
    ) -> (
        io::Result<UdpDriver>,
        Vec<UdpDriver>,
        Vec<(IpAddr, io::Error)>,
    ) {
        let group = plan.group;
        // The addresses the config's interface text names, resolved before any socket exists.
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
        let group_socket = UdpDriver::bind_scouting_group(group, plan.port, config).await;
        if let Ok(socket) = &group_socket {
            join_beyond_the_first(socket, group, &named);
        }
        // Where the Scout leaves from: every interface that can carry multicast when the
        // config names none, and the addresses its text names when it does, as upstream's
        // `get_interfaces` resolves them.
        let locals = match plan.interface {
            Some(_) => named,
            None => scout_interface_addresses().unwrap_or_default(),
        };
        let (ask, refused) = bind_scout_sockets(group, plan.port, &locals, plan.ttl).await;
        (group_socket, ask, refused)
    }

    /// Scout until `intents` has no receiver, posting a `DialIntent` for every responder the
    /// plan's policy admits, AS EACH ANSWERS. `zid` is this node's own wire zid: it is what the
    /// Scout announces and what the policy's tie-break compares against.
    ///
    /// The cadence is upstream's: one Scout, then the answers to it for a window of one second,
    /// the next window twice as long, and so on up to eight (`orchestrator.rs` @
    /// `const SCOUT_INITIAL_PERIOD: Duration`). An answer is acted on when it arrives and not
    /// when its window ends: the scouting machine hands its answers over only at the window's
    /// end, so they are read from it every `HARVEST_PERIOD` while it runs, and a node that
    /// answers at once is dialled at once, which is what keeps a scouted open as quick as one
    /// that was told where to connect.
    ///
    /// Returns when the receiver is gone (the session is closing) or the scouting link is lost.
    pub async fn autoconnect(self, plan: &ScoutingPlan, zid: &[u8], intents: &DialIntentSender) {
        let policy =
            AutoConnect::with_strategies(Zid::from_slice(zid), plan.matcher, plan.strategies);
        // One intent for a responder in a window, and a window later another: a peer that went
        // away is dialled again the next time it answers.
        let mut posted = BTreeSet::new();
        let mut current = 0;
        self.scout_each(plan.what(), zid, |Delivery { hello, window }| {
            if window != current {
                current = window;
                posted.clear();
            }
            // A node does not dial itself: its own Scout may come back through the group.
            if hello.zid == zid || !posted.insert(hello.zid.clone()) {
                return true;
            }
            match autoconnect_verdict(&policy, &hello) {
                AutoconnectVerdict::Dial(intent) => intents.send(intent).is_ok(),
                _ => true,
            }
        })
        .await;
    }

    /// Scout for the roles `what` names until `each` declines, handing it every Hello as the
    /// window it answers gathers it, in the order they arrive.
    ///
    /// The cadence is the one [`Self::autoconnect`] describes, and it is upstream's for a scout a
    /// program asks for as well as for a node that looks for its peers
    /// (`zenoh/src/net/runtime/orchestrator.rs` @ `pub(crate) async fn scout<Fut, F>(`): one Scout
    /// and then the answers to it, windows of one second doubling to eight, for as long as it is
    /// asked to. A responder that answers in every window is handed over in every window, and
    /// nothing here dedupes: that is the caller's to decide. A Hello whose role `what` did not ask
    /// for is dropped, as upstream's receive loop drops it (`matcher.matches(hello.whatami)`).
    ///
    /// Returns when `each` declines or the scouting link is lost; the caller stops a scout that
    /// has no end of its own by dropping the future.
    pub async fn scout_each(
        mut self,
        what: u8,
        zid: &[u8],
        mut each: impl FnMut(Delivery) -> bool,
    ) {
        let clock = TokioTime::new();
        let mut window_ms = SCOUT_INITIAL_PERIOD_MS;
        let mut window = 0u64;
        loop {
            let actions = ScoutingActions::new(ScoutParams {
                what,
                zid: zid.to_vec(),
                timeout_ms: window_ms,
                // The survey arm: every responder of the window, not the first (upstream's
                // callback returns `Loop::Continue` always).
                exit_on_first: false,
            });
            let mut engine = new_scouting_engine(&actions);
            let drive = drive_scouting_until_resolved(
                &mut self.driver,
                &actions,
                &mut engine,
                &clock,
                None,
                SCOUT_TICK_MS,
            );
            tokio::pin!(drive);
            let mut handed = 0;
            let mut harvest = tokio::time::interval(HARVEST_PERIOD);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut drive => break outcome,
                    _ = harvest.tick() => {
                        if !hand_over(&actions, what, window, &mut handed, &mut each) {
                            return;
                        }
                    }
                }
            };
            // What arrived in the last tick before the window closed.
            if !hand_over(&actions, what, window, &mut handed, &mut each)
                || matches!(outcome, ScoutOutcome::LinkLost(_))
            {
                return;
            }
            window_ms = (window_ms * 2).min(SCOUT_MAX_PERIOD_MS);
            window += 1;
        }
    }
}

/// A Hello a scout hands over, and the window it answered: windows are numbered from 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// What the responder said of itself.
    pub hello: ScoutedHello,
    /// The window it answered.
    pub window: u64,
}

/// Hand `each` the Hellos of this window that it has not been handed, in arrival order, and drop
/// those of a role `what` did not ask for. `false` when `each` declined.
fn hand_over(
    actions: &ScoutingActions,
    what: u8,
    window: u64,
    handed: &mut usize,
    each: &mut impl FnMut(Delivery) -> bool,
) -> bool {
    for hello in actions.scouted_hellos().into_iter().skip(*handed) {
        *handed += 1;
        if !hello.whatami.is_some_and(|role| what & role.to_api() != 0) {
            continue;
        }
        if !each(Delivery { hello, window }) {
            return false;
        }
    }
    true
}

/// A running scout a program asked for: a thread that scouts until this is dropped.
///
/// Dropping it stops the scout and waits for the thread, so no callback runs once the drop has
/// returned; upstream waits for its task for up to ten seconds in the same place
/// (`zenoh/src/api/scouting.rs` @ `terminate(Duration::from_secs(10))`).
pub struct ScoutStream {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScoutStream {
    /// Scout on `plan` for the roles `what` names, announcing `zid`, handing every Hello to
    /// `each` on the scout's own thread. A plan that no socket can carry is a scout that finds
    /// nobody, and not an error.
    pub fn start(
        plan: ScoutingPlan,
        what: u8,
        zid: Vec<u8>,
        mut each: impl FnMut(ScoutedHello) + Send + 'static,
    ) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("wz-scout".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let Some(link) = ScoutLink::bind_for_scout(&plan).await else {
                        return;
                    };
                    tokio::select! {
                        _ = link.scout_each(what, &zid, |delivery| {
                            each(delivery.hello);
                            true
                        }) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for ScoutStream {
    fn drop(&mut self) {
        // The receiver of the stop completes when its sender goes.
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_runtime_tokio::session_glue::WhatAmI as Role;

    fn resolved(node: &ZenohNodeConfig, role: Role) -> ScoutingPlan {
        ScoutingPlan::resolve(node, role)
            .expect("the config resolves")
            .expect("scouting is on")
    }

    /// A config that states nothing about scouting resolves to zenoh's shipped defaults, per role:
    /// the group `224.0.0.224:7446`, interface `auto`, a 500 ms delay and a 3 s timeout, and
    /// autoconnect to routers, peers AND clients for a peer or a client and to nobody for a
    /// router. The expected values are read off the pinned upstream's `scouting` defaults
    /// (`commons/zenoh-config/src/defaults.rs` @ `pub const delay: u64 = 500;`) and not off this
    /// crate.
    #[test]
    fn an_unstated_config_takes_zenohs_shipped_defaults_per_role() {
        let node = ZenohNodeConfig::default();
        for role in [Role::Peer, Role::Client] {
            let plan = resolved(&node, role);
            assert_eq!(
                (plan.group, plan.port),
                (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224)), 7446)
            );
            assert_eq!(plan.interface, None);
            assert_eq!(plan.ttl, None);
            assert_eq!(plan.delay, Duration::from_millis(500));
            assert_eq!(plan.timeout, Duration::from_millis(3000));
            assert!(plan.scouts());
            // router (1) | peer (2) | client (4)
            assert_eq!(plan.what(), 7, "a {role:?} asks for every role");
            assert!(
                plan.answers,
                "a {role:?} answers a Scout unless told not to"
            );
        }
        let router = resolved(&node, Role::Router);
        assert!(!router.scouts(), "a router connects to nobody it finds");
        assert_eq!(router.what(), 0);
        assert!(
            router.answers,
            "a router connects to nobody and is still found: `listen` is on for all three roles"
        );
    }

    /// Each stated key replaces its default, and `"auto"` is no interface.
    #[test]
    fn a_stated_config_replaces_each_default() {
        let mut node = ZenohNodeConfig::default();
        node.scout_multicast_address = Some(String::from("224.0.0.231:7511"));
        node.scout_multicast_interface = Some(String::from("lo"));
        node.scout_multicast_ttl = Some(3);
        node.scouting_delay_ms = Some(40);
        node.scouting_timeout_ms = Some(70);
        node.scout_multicast_autoconnect = Some(WhatAmIMatcher::empty().router());
        node.scout_multicast_listen = Some(false);
        let plan = resolved(&node, Role::Peer);
        assert!(
            !plan.answers,
            "`scouting/multicast/listen: false` is honoured"
        );
        assert_eq!(
            (plan.group, plan.port),
            (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 231)), 7511)
        );
        assert_eq!(plan.interface.as_deref(), Some("lo"));
        assert_eq!(plan.ttl, Some(3));
        assert_eq!(plan.delay, Duration::from_millis(40));
        assert_eq!(plan.timeout, Duration::from_millis(70));
        assert_eq!(plan.what(), 1, "routers alone");

        node.scout_multicast_interface = Some(String::from("auto"));
        assert_eq!(resolved(&node, Role::Peer).interface, None);
    }

    /// An EMPTY autoconnect is an instruction and not an absence: it is what a router's config
    /// resolves to, and it means the node looks for nobody, whatever its role.
    #[test]
    fn an_empty_autoconnect_scouts_for_nobody() {
        let mut node = ZenohNodeConfig::default();
        node.scout_multicast_autoconnect = Some(WhatAmIMatcher::empty());
        assert!(!resolved(&node, Role::Client).scouts());
    }

    /// An address literal named as the interface is that address, of either family and whether or
    /// not this host holds it, and an IPv6 group is joined on interface 0 whatever interface is
    /// named while an IPv4 group is joined on the IPv4 addresses the text names, and on none when
    /// it names only an IPv6 one (upstream warns that it cannot join an IPv4 group there).
    #[test]
    fn an_address_literal_is_the_interface_and_an_ipv6_group_is_joined_on_interface_zero() {
        for text in ["192.0.2.7", "fd7a:115c:a1e0::1", " ::1 "] {
            let expected: IpAddr = text.trim().parse().expect("a literal");
            assert_eq!(
                named_interface_addresses(text),
                vec![expected],
                "`{text}` is the address it spells"
            );
        }
        let mut node = ZenohNodeConfig::default();
        node.scout_multicast_interface = Some(String::from("fd7a:115c:a1e0::1"));
        node.scout_multicast_address = Some(String::from("[ff05::232]:7511"));
        let v6 = resolved(&node, Role::Peer);
        let named = named_interface_addresses("fd7a:115c:a1e0::1");
        assert_eq!(
            group_join_interface(&v6, &named),
            None,
            "an IPv6 group joins on interface 0"
        );
        node.scout_multicast_address = Some(String::from("224.0.0.231:7511"));
        let v4 = resolved(&node, Role::Peer);
        assert_eq!(
            group_join_interface(&v4, &named),
            None,
            "an IPv4 group has nothing to join on when the text names only an IPv6 address"
        );
    }

    /// A list names several addresses, and an IPv4 group is joined on the IPv4 ones: the bind
    /// takes the first, which the config reads as an address literal, and the rest are joined
    /// after it.
    #[test]
    fn an_ipv4_group_is_joined_on_the_first_ipv4_address_of_a_list() {
        let mut node = ZenohNodeConfig::default();
        node.scout_multicast_interface = Some(String::from("fd7a::1, 192.0.2.7, 198.51.100.9"));
        node.scout_multicast_address = Some(String::from("224.0.0.231:7511"));
        let plan = resolved(&node, Role::Peer);
        let named = named_interface_addresses(plan.interface.as_deref().expect("named"));
        assert_eq!(
            named,
            vec![
                "fd7a::1".parse::<IpAddr>().unwrap(),
                "192.0.2.7".parse().unwrap(),
                "198.51.100.9".parse().unwrap()
            ]
        );
        assert_eq!(
            group_join_interface(&plan, &named).as_deref(),
            Some("192.0.2.7"),
            "the first IPv4 address of the list is the bind's"
        );
    }

    /// An IPv6 group is a plan like any other: the family is the group's, and the port follows it.
    #[test]
    fn an_ipv6_group_resolves_to_a_plan() {
        let mut node = ZenohNodeConfig::default();
        node.scout_multicast_address = Some(String::from("[ff05::231]:7511"));
        let plan = resolved(&node, Role::Peer);
        assert_eq!(
            (plan.group, plan.port),
            (IpAddr::from([0xff05, 0, 0, 0, 0, 0, 0, 0x231]), 7511)
        );
    }

    /// A scout a program asks for reads the group, the interface and the hop limit of a config
    /// and nothing else of it: not whether multicast scouting is on (a session's question), and
    /// the roles are the ones it asks for. A group that is not a socket address is refused by name.
    #[test]
    fn a_scout_a_program_asks_for_reads_the_group_and_not_whether_scouting_is_on() {
        let mut node = ZenohNodeConfig::default();
        node.multicast_scouting = false;
        node.scout_multicast_address = Some(String::from("224.0.0.231:7511"));
        node.scout_multicast_interface = Some(String::from("auto"));
        node.scout_multicast_ttl = Some(3);
        let plan = ScoutingPlan::for_scout(&node, 1 | 2).expect("a plan");
        assert_eq!(
            (plan.group, plan.port),
            (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 231)), 7511)
        );
        assert_eq!((plan.interface.as_deref(), plan.ttl), (None, Some(3)));
        assert_eq!(plan.what(), 1 | 2, "routers and peers, not clients");
        assert_eq!(ScoutingPlan::for_scout(&node, 4).unwrap().what(), 4);
        assert_eq!(
            ScoutingPlan::for_scout(&ZenohNodeConfig::default(), 2)
                .unwrap()
                .port,
            7446,
            "an unstated group is zenoh's"
        );
        node.scout_multicast_address = Some(String::from("not-an-address"));
        assert_eq!(
            ScoutingPlan::for_scout(&node, 2).err(),
            Some(ScoutingConfigError::Address(String::from("not-an-address")))
        );
    }

    /// A window hands each Hello over once, as it arrives, in arrival order, and leaves out one
    /// whose role was not asked for or that names no role; a caller that declines is told so.
    #[test]
    fn a_window_hands_each_hello_over_once_and_only_of_the_roles_asked_for() {
        let actions: std::sync::Arc<ScoutingActions> = ScoutingActions::new(ScoutParams {
            what: 2,
            zid: vec![9],
            timeout_ms: 1000,
            exit_on_first: false,
        });
        let hello = |zid: u8, role: Option<WhatAmI>| ScoutedHello {
            version: 9,
            whatami: role,
            zid: vec![zid],
            locators: vec![],
        };
        let mut handed = 0;
        let mut got = Vec::new();
        let mut each = |delivery: Delivery| {
            got.push((delivery.hello.zid[0], delivery.window));
            true
        };
        actions.hellos.lock().unwrap().extend([
            hello(1, Some(WhatAmI::Peer)),
            hello(2, Some(WhatAmI::Router)),
            hello(3, None),
        ]);
        assert!(hand_over(&actions, 2, 7, &mut handed, &mut each));
        actions
            .hellos
            .lock()
            .unwrap()
            .push(hello(4, Some(WhatAmI::Peer)));
        assert!(hand_over(&actions, 2, 7, &mut handed, &mut each));
        assert_eq!(got, vec![(1, 7), (4, 7)], "once each, and the peers only");
        actions
            .hellos
            .lock()
            .unwrap()
            .push(hello(5, Some(WhatAmI::Peer)));
        assert!(
            !hand_over(&actions, 2, 7, &mut handed, &mut |_: Delivery| false),
            "a caller that declines ends the window"
        );
    }

    /// With multicast scouting off there is no plan, and a group that is not a socket address is
    /// refused by name and not replaced by another.
    #[test]
    fn scouting_off_is_no_plan_and_an_unusable_group_is_refused() {
        let mut node = ZenohNodeConfig::default();
        node.multicast_scouting = false;
        assert!(ScoutingPlan::resolve(&node, Role::Peer)
            .expect("resolves")
            .is_none());

        node.multicast_scouting = true;
        for text in ["not-an-address", "224.0.0.224", "ff02::1:7446"] {
            node.scout_multicast_address = Some(text.to_owned());
            assert_eq!(
                ScoutingPlan::resolve(&node, Role::Peer).err(),
                Some(ScoutingConfigError::Address(text.to_owned())),
                "`{text}` is not a group and port"
            );
        }
    }
}
