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
/// and by whether it was sent reliably. `keep-latest` admits the new sample and takes out
/// the newest ones already queued behind the one being delivered until it fits: the receive
/// path is never held, the newest sample is never the one lost, and each one taken out is
/// counted by how it was sent. It is for a stream whose last value is the one that matters.
/// A sample longer than the whole lane can never wait for room, so it is refused under
/// every choice. Each declaration can still state its own choice; this sets the default for
/// the ones that do not.
/// Upstream: Hands a sample to a channel handler that blocks its sender when the handler is
/// full, so a slow consumer applies backpressure into the session and no sample is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriberOverload {
    /// `block`.
    Block,
    /// `reject`.
    Reject,
    /// `keep-latest`.
    KeepLatest,
}

impl SubscriberOverload {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Reject => "reject",
            Self::KeepLatest => "keep-latest",
        }
    }

    const CHOICES: [&str; 3] = ["block", "reject", "keep-latest"];
    const ALL: [Self; 3] = [Self::Block, Self::Reject, Self::KeepLatest];

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
/// `closed` needs the cargo feature `key-set-closed` of wz-session-core, which compiles the
/// mode in; a build that states it without the feature does not compile, and an open build
/// has neither the code nor its bytes.
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

/// `sn-resolution`: The width of the sequence numbers the sessions of the C interfaces
/// advertise: in the InitSyn of a unicast session, where the two sides take the smaller of
/// the two advertised widths, and in the Join of a multicast group, where a member refuses
/// a Join that states another width than its own, so every member of a group states the
/// same. `bits-32` is what zenoh and zenoh-pico advertise. `bits-8`, `bits-16` and
/// `bits-64` state that width instead, for a peer built with a sequence-number width of its
/// own. A session that negotiates a width below its peer's runs the narrower ring of the
/// two; a ring of 8 bits wraps after 128 frames in flight, so a narrow width asks a
/// deployment to know its traffic. The request-id resolution is not part of this policy.
/// Upstream: Advertises the 32-bit sequence-number resolution in its InitSyn and in the
/// Join of a group, and has no setting for another: zenoh's `Resolution` default and zenoh-
/// pico's `Z_SN_RESOLUTION 0x02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnResolution {
    /// `bits-32`.
    Bits32,
    /// `bits-8`.
    Bits8,
    /// `bits-16`.
    Bits16,
    /// `bits-64`.
    Bits64,
}

impl SnResolution {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Bits32 => "bits-32",
            Self::Bits8 => "bits-8",
            Self::Bits16 => "bits-16",
            Self::Bits64 => "bits-64",
        }
    }

    const CHOICES: [&str; 4] = ["bits-32", "bits-8", "bits-16", "bits-64"];
    const ALL: [Self; 4] = [Self::Bits32, Self::Bits8, Self::Bits16, Self::Bits64];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_SN_RESOLUTION");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for SnResolution {
    fn default() -> Self {
        Self::stated()
    }
}

/// `clock-quality-stamping`: Whether a node stamps data with a time it does not trust.
/// `always` stamps with the clock's reading whatever its standing. `trusted-only` stamps
/// only while the clock is synchronised to a reference, or held over from one within the
/// bound the host keeps: before the host first reports a reference, and once that bound has
/// passed, the node stamps no data it forwards, takes no timestamp into its clock and
/// counts the data it passed on as it came. A storage that needs a time to order what it
/// keeps still takes one from the system clock. The host reports the clock's standing,
/// because only the host knows it: a time daemon, a satellite receiver, a fieldbus master.
/// Upstream: Stamps with whatever time the system clock reads, and has no notion of whether
/// that clock is set or follows a reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockQualityStamping {
    /// `always`.
    Always,
    /// `trusted-only`.
    TrustedOnly,
}

impl ClockQualityStamping {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::TrustedOnly => "trusted-only",
        }
    }

    const CHOICES: [&str; 2] = ["always", "trusted-only"];
    const ALL: [Self; 2] = [Self::Always, Self::TrustedOnly];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_CLOCK_QUALITY_STAMPING");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for ClockQualityStamping {
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
    /// `sn-resolution`. Upstream: Advertises the 32-bit sequence-number resolution in its
    /// InitSyn and in the Join of a group, and has no setting for another: zenoh's
    /// `Resolution` default and zenoh-pico's `Z_SN_RESOLUTION 0x02`.
    pub sn_resolution: SnResolution,
    /// `clock-quality-stamping`. Upstream: Stamps with whatever time the system clock
    /// reads, and has no notion of whether that clock is set or follows a reference.
    pub clock_quality_stamping: ClockQualityStamping,
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
        let sn_resolution = SnResolution::stated();
        let clock_quality_stamping = ClockQualityStamping::stated();
        Self {
            multicast_loopback,
            tx_no_progress_deadline,
            tx_expiry_keeps_session,
            declaration_sync_pacing,
            entity_timestamp_opt_in,
            subscriber_overload,
            key_set,
            sn_resolution,
            clock_quality_stamping,
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}
