// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! drive's (`crate::drive`), face by face on its own task. A node that scouts is not yet a node
//! that is FOUND: answering a Scout is the responder's half, which this module does not carry.
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
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutParams, ScoutingActions,
};
use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};

use crate::scouting::{SCOUT_PROTO_VERSION, SCOUT_TICK_MS};

/// The first scouting window and the longest one, in milliseconds: a Scout goes out at the start
/// of each, and the next window is twice the last (`zenoh/src/net/runtime/orchestrator.rs` @
/// `const SCOUT_PERIOD_INCREASE_FACTOR: u32 = 2;`).
const SCOUT_INITIAL_PERIOD_MS: u64 = 1_000;
const SCOUT_MAX_PERIOD_MS: u64 = 8_000;
/// How often the answers of a running window are read.
const HARVEST_PERIOD: Duration = Duration::from_millis(20);

/// `scouting/multicast/address`'s default group and port.
const GROUP_DEFAULT: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
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
    /// The group scouts go to: `scouting/multicast/address`.
    pub group: Ipv4Addr,
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
}

/// The group a config named is not one this node can scout on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScoutingConfigError {
    /// `scouting/multicast/address` is not `<ipv4>:<port>`. An IPv6 group is a real zenoh value
    /// and is not one this host joins yet, so it is refused by name and not scouted on as a
    /// different group.
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
        let (group, port) = match node.scout_multicast_address.as_deref() {
            None => (GROUP_DEFAULT, PORT_DEFAULT),
            Some(text) => match text.parse::<std::net::SocketAddr>() {
                Ok(std::net::SocketAddr::V4(addr)) => (*addr.ip(), addr.port()),
                _ => return Err(ScoutingConfigError::Address(text.to_owned())),
            },
        };
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
        }))
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
        let group = IpAddr::V4(plan.group);
        let config = McastSocketConfig {
            iface: plan.interface.as_deref(),
            ttl: plan.ttl,
            ..McastSocketConfig::default()
        };
        let group_socket = UdpDriver::bind_multicast(group, plan.port, config).await?;
        // Where the Scout leaves from: every interface that can carry multicast when the
        // config names none, and the named one's own addresses when it does, as upstream's
        // `get_interfaces` resolves them.
        let locals = match plan.interface.as_deref() {
            Some(iface) => wz_runtime_tokio::link_interfaces::unicast_addresses_of_interface(iface)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?
                .into_iter()
                .filter(IpAddr::is_ipv4)
                .collect(),
            None => scout_interface_addresses().unwrap_or_default(),
        };
        let (ask, refused) = bind_scout_sockets(group, plan.port, &locals, plan.ttl).await;
        let (driver, _shape) = ScoutFanOut::over(group_socket, ask, refused);
        Ok(Self { driver })
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
    pub async fn autoconnect(
        mut self,
        plan: &ScoutingPlan,
        zid: &[u8],
        intents: &DialIntentSender,
    ) {
        let policy =
            AutoConnect::with_strategies(Zid::from_slice(zid), plan.matcher, plan.strategies);
        let clock = TokioTime::new();
        let mut window_ms = SCOUT_INITIAL_PERIOD_MS;
        loop {
            let actions = ScoutingActions::new(ScoutParams {
                version: SCOUT_PROTO_VERSION,
                what: plan.what(),
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
            let mut posted = BTreeSet::new();
            let mut harvest = tokio::time::interval(HARVEST_PERIOD);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut drive => break outcome,
                    _ = harvest.tick() => {
                        if !post_admitted(&actions, &policy, zid, intents, &mut posted) {
                            return;
                        }
                    }
                }
            };
            // What arrived in the last tick before the window closed.
            if !post_admitted(&actions, &policy, zid, intents, &mut posted)
                || matches!(outcome, ScoutOutcome::LinkLost(_))
            {
                return;
            }
            window_ms = (window_ms * 2).min(SCOUT_MAX_PERIOD_MS);
        }
    }
}

/// Post the intent of every responder of this window that has not been posted yet and whom the
/// policy admits. `false` when the receiver is gone.
fn post_admitted(
    actions: &ScoutingActions,
    policy: &AutoConnect,
    own_zid: &[u8],
    intents: &DialIntentSender,
    posted: &mut BTreeSet<Vec<u8>>,
) -> bool {
    for hello in actions.scouted_hellos() {
        // A node does not dial itself: its own Scout may come back through the group.
        if hello.zid == own_zid || !posted.insert(hello.zid.clone()) {
            continue;
        }
        if let AutoconnectVerdict::Dial(intent) = autoconnect_verdict(policy, &hello) {
            if intents.send(intent).is_err() {
                return false;
            }
        }
    }
    true
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
                (Ipv4Addr::new(224, 0, 0, 224), 7446)
            );
            assert_eq!(plan.interface, None);
            assert_eq!(plan.ttl, None);
            assert_eq!(plan.delay, Duration::from_millis(500));
            assert_eq!(plan.timeout, Duration::from_millis(3000));
            assert!(plan.scouts());
            // router (1) | peer (2) | client (4)
            assert_eq!(plan.what(), 7, "a {role:?} asks for every role");
        }
        let router = resolved(&node, Role::Router);
        assert!(!router.scouts(), "a router connects to nobody it finds");
        assert_eq!(router.what(), 0);
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
        let plan = resolved(&node, Role::Peer);
        assert_eq!(
            (plan.group, plan.port),
            (Ipv4Addr::new(224, 0, 0, 231), 7511)
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

    /// With multicast scouting off there is no plan, and a group this host cannot scout on is
    /// refused by name and not replaced by another.
    #[test]
    fn scouting_off_is_no_plan_and_an_unusable_group_is_refused() {
        let mut node = ZenohNodeConfig::default();
        node.multicast_scouting = false;
        assert!(ScoutingPlan::resolve(&node, Role::Peer)
            .expect("resolves")
            .is_none());

        node.multicast_scouting = true;
        for text in ["not-an-address", "224.0.0.224", "[ff02::1]:7446"] {
            node.scout_multicast_address = Some(text.to_owned());
            assert_eq!(
                ScoutingPlan::resolve(&node, Role::Peer).err(),
                Some(ScoutingConfigError::Address(text.to_owned())),
                "`{text}` is not an IPv4 group and port"
            );
        }
    }
}
