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

/// `subscriber-overload`: What a subscriber whose callback runs off the receive path does
/// when its delivery lane is full and its declaration says nothing. `block` makes the
/// session wait for room, outside the lock the receive path holds, so the transport's own
/// backpressure is the flow control and no sample is lost. `reject` refuses the sample at
/// once: the receive path is never held, the sample is lost, and it is counted by reason
/// and by whether it was sent reliably. A sample longer than the whole lane can never wait
/// for room, so it is refused either way. Each declaration can still state its own choice;
/// this sets the default for the ones that do not.
/// Upstream: Hands a sample to a channel handler that blocks its sender when the handler is
/// full, so a slow consumer applies backpressure into the session and no sample is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriberOverload {
    /// `block`.
    Block,
    /// `reject`.
    Reject,
}

impl SubscriberOverload {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Reject => "reject",
        }
    }

    const CHOICES: [&str; 2] = ["block", "reject"];
    const ALL: [Self; 2] = [Self::Block, Self::Reject];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for SubscriberOverload {
    fn default() -> Self {
        Self::stated()
    }
}

/// `key-set`: Which keys the receive path takes a message on (docs/closed-key-set.md).
/// `open` takes any key a peer sends. `closed` takes only the keys the image declares as
/// its key set, which the build generates into a read-only table: a message on any other
/// key is dropped before a subscriber is looked up, and counted by reason. A closed build
/// that is given no table takes no key at all. The selectors a peer asks with, a query or
/// an interest, are patterns and not data keys, and are answered as in an open build.
/// Upstream: Takes a message on any key a peer sends, and finds the subscribers it reaches
/// by matching that key against each subscription's pattern as text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySet {
    /// `open`.
    Open,
    /// `closed`.
    Closed,
}

impl KeySet {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }

    const CHOICES: [&str; 2] = ["open", "closed"];
    const ALL: [Self; 2] = [Self::Open, Self::Closed];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_KEY_SET");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for KeySet {
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
    /// `declaration-sync-pacing`. Upstream: Replays every declaration it holds to a new
    /// peer in one call, as soon as the session is open again.
    pub declaration_sync_pacing: bool,
    /// `entity-timestamp-opt-in`. Upstream: Hands every received sample's timestamp to the
    /// subscriber and every reply's to the querier, and lets any publisher attach the
    /// timestamp it is given.
    pub entity_timestamp_opt_in: bool,
    /// `subscriber-overload`. Upstream: Hands a sample to a channel handler that blocks its
    /// sender when the handler is full, so a slow consumer applies backpressure into the
    /// session and no sample is lost.
    pub subscriber_overload: SubscriberOverload,
    /// `key-set`. Upstream: Takes a message on any key a peer sends, and finds the
    /// subscribers it reaches by matching that key against each subscription's pattern as
    /// text.
    pub key_set: KeySet,
}

impl SessionPolicy {
    /// The policy this build states: its environment's values, else upstream's.
    pub const fn from_build() -> Self {
        let multicast_loopback = MulticastLoopback::stated();
        let tx_no_progress_deadline = policy_bool(option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE"));
        let tx_expiry_keeps_session = policy_bool(option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION"));
        let declaration_sync_pacing = policy_bool(option_env!("WZ_POLICY_DECLARATION_SYNC_PACING"));
        let entity_timestamp_opt_in = policy_bool(option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN"));
        let subscriber_overload = SubscriberOverload::stated();
        let key_set = KeySet::stated();
        Self {
            multicast_loopback,
            tx_no_progress_deadline,
            tx_expiry_keeps_session,
            declaration_sync_pacing,
            entity_timestamp_opt_in,
            subscriber_overload,
            key_set,
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}
