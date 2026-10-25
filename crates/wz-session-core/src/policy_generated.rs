// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-policies.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], whose
//! `Default` is the value the build's environment states as `WZ_POLICY_<NAME>`, or upstream's
//! behaviour when it states none. A test names the other value by setting the field.

use super::{policy_bool, policy_choice};

/// `multicast-loopback`: Whether a datagram a node sends to a multicast group is also
/// delivered to members of that group on the same host. `os-default` leaves the operating
/// system's setting alone. `on` and `off` set it on every multicast socket the node opens:
/// `on` is for nodes that share a host and must hear one another, `off` for a node that
/// must not hear its own host's traffic.
/// Upstream: Never sets IP_MULTICAST_LOOP on a multicast socket, so each sending socket
/// keeps the operating system's setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastLoopback {
    /// `os-default`.
    OsDefault,
    /// `on`.
    On,
    /// `off`.
    Off,
}

impl MulticastLoopback {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::OsDefault => "os-default",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    const CHOICES: [&str; 3] = ["os-default", "on", "off"];
    const ALL: [Self; 3] = [Self::OsDefault, Self::On, Self::Off];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_MULTICAST_LOOPBACK");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for MulticastLoopback {
    fn default() -> Self {
        Self::stated()
    }
}

/// What this build decided beyond upstream's behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionPolicy {
    /// `multicast-loopback`. Upstream: Never sets IP_MULTICAST_LOOP on a multicast socket,
    /// so each sending socket keeps the operating system's setting.
    pub multicast_loopback: MulticastLoopback,
    /// `tx-no-progress-deadline`. Upstream: Gives a blocking message one wait_before_close
    /// for the whole of it, however many fragments go out: its deadline has no cap to
    /// extend by, so a fragment out leaves the deadline where it is.
    pub tx_no_progress_deadline: bool,
    /// `tx-expiry-keeps-session`. Upstream: Closes the session as unresponsive when a
    /// blocking message found no room in its deadline, and tells the sender nothing.
    pub tx_expiry_keeps_session: bool,
}

impl SessionPolicy {
    /// The policy this build states: its environment's values, else upstream's.
    pub const fn from_build() -> Self {
        let multicast_loopback = MulticastLoopback::stated();
        let tx_no_progress_deadline = policy_bool(option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE"));
        let tx_expiry_keeps_session = policy_bool(option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION"));
        Self {
            multicast_loopback,
            tx_no_progress_deadline,
            tx_expiry_keeps_session,
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}
