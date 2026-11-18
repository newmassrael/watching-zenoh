// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-policies.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], whose
//! `Default` is the value the build's environment states as `WZ_POLICY_<NAME>`, or upstream's
//! behaviour when it states none. A test names the other value by setting the field.
//!
//! Each policy's value type, an `Off` and `On` enum of its own for a bool policy, implements
//! [`PolicyValue`]: the domain the build allows (`WZ_POLICY_<NAME>_ALLOWS_<VALUE>`, an unset name
//! allowing the value), the build's default, which the domain must hold, and where the policy is
//! bound.

use super::{policy_allows, policy_bool, policy_choice};

use crate::policy_binding::{
    default_is_allowed, Binding, Domain, Mutability, PolicyValue, Scope, Wire,
};

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

/// `reliable-gap-reconnect`: What a node does when a frame on the reliable channel arrives
/// with a sequence number that jumped forward, which means frames were lost on the way.
/// `off` accepts the jump, which is upstream's behaviour. `until-declarations-synced`
/// treats the jump as a lost link only while the peer has not yet sent the end of its
/// initial declarations, so a session whose declaration sync was cut short is reopened and
/// the sync is redone, and a jump after that is accepted. `always` treats every forward
/// jump on the reliable channel as a lost link. The frame that showed the jump is dropped,
/// and the supervisor of a reconnecting session opens the session again and redoes the
/// declaration sync. A frame that does not advance the number is dropped as before, and the
/// best-effort channels are not affected. Only the tokio engine reconnects, so another
/// engine ends the link and leaves it to the application, and only the tokio engine reports
/// the end of the peer's declarations, so for another engine `until-declarations-synced` is
/// `always`.
/// Upstream: Accepts a forward jump of the reliable channel's sequence number without a
/// word: the frames in between are lost, the session stays open and nothing is repaired, so
/// a peer's declaration lost that way is never noticed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReliableGapReconnect {
    /// `off`.
    Off,
    /// `until-declarations-synced`.
    UntilDeclarationsSynced,
    /// `always`.
    Always,
}

impl ReliableGapReconnect {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::UntilDeclarationsSynced => "until-declarations-synced",
            Self::Always => "always",
        }
    }

    const CHOICES: [&str; 3] = ["off", "until-declarations-synced", "always"];
    const ALL: [Self; 3] = [Self::Off, Self::UntilDeclarationsSynced, Self::Always];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_RELIABLE_GAP_RECONNECT");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for ReliableGapReconnect {
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

/// `key-set`: Which keys the receive path takes a message on (the closed key set). `open`
/// takes any key a peer sends. `closed` takes only the keys the image declares as its key
/// set, which the build generates into a read-only table: a message on any other key is
/// dropped before a subscriber is looked up, and counted by reason. A closed build that is
/// given no table takes no key at all. The selectors a peer asks with, a query or an
/// interest, are patterns and not data keys, and are answered as in an open build. `closed`
/// needs the cargo feature `key-set-closed` of wz-session-core, which compiles the mode in;
/// a build that states it without the feature does not compile, and an open build has
/// neither the code nor its bytes.
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
/// advertise when their configuration states none: in the InitSyn of a unicast session,
/// where the two sides take the smaller of the two advertised widths, and in the Join of a
/// multicast group, where a member refuses a Join that states another width than its own,
/// so every member of a group states the same. `bits-32` is what zenoh advertises by
/// default and what zenoh-pico always advertises. `bits-8`, `bits-16` and `bits-64` state
/// that width instead, for a peer built with a sequence-number width of its own. A
/// configuration that states `transport/link/tx/sequence_number_resolution` with a width
/// other than 32 bits is followed instead of this policy, as zenoh follows the key. A
/// session that negotiates a width below its peer's runs the narrower ring of the two; a
/// ring of 8 bits wraps after 128 frames in flight, so a narrow width asks a deployment to
/// know its traffic. The request-id resolution is not part of this policy.
/// Upstream: Advertises the 32-bit sequence-number resolution in its InitSyn and in the
/// Join of a group unless its configuration states another: zenoh reads
/// `transport/link/tx/sequence_number_resolution`, whose default is 32 bits, and zenoh-pico
/// builds in `Z_SN_RESOLUTION 0x02` with no setting for another.
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

/// `supervision-after-expiry`: What a checkpoint does when it is fed after its deadline was
/// missed. `latch` leaves it expired: the missed deadline stays visible, the node stays
/// unhealthy, and the checkpoint is supervised again only when it is stopped and started,
/// which is what a watchdog does. `rearm` supervises it again on that feed, so a checkpoint
/// that recovers makes the node healthy again. The expiry hook runs once per expiry either
/// way.
/// Upstream: Supervises nothing: an application that stops making progress is not noticed
/// by the library, so there is no expiry and nothing for a later feed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisionAfterExpiry {
    /// `latch`.
    Latch,
    /// `rearm`.
    Rearm,
}

impl SupervisionAfterExpiry {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Latch => "latch",
            Self::Rearm => "rearm",
        }
    }

    const CHOICES: [&str; 2] = ["latch", "rearm"];
    const ALL: [Self; 2] = [Self::Latch, Self::Rearm];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_SUPERVISION_AFTER_EXPIRY");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for SupervisionAfterExpiry {
    fn default() -> Self {
        Self::stated()
    }
}

/// `event-ring-full`: Which event a full event ring gives up. `overwrite-oldest` writes the
/// new event over the oldest, so the ring always holds the latest: it is what a post-mortem
/// wants, and needs no reader at all. `drop-newest` refuses the new event and counts the
/// refusals, so the ring holds the beginning until a reader frees it: it is what a boot
/// trace wants, and the events are lost whenever no reader is reading.
/// Upstream: Keeps no record of the events a node has: a log call with no logger installed
/// is dropped, so neither the oldest nor the newest of them survives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventRingFull {
    /// `overwrite-oldest`.
    OverwriteOldest,
    /// `drop-newest`.
    DropNewest,
}

impl EventRingFull {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::OverwriteOldest => "overwrite-oldest",
            Self::DropNewest => "drop-newest",
        }
    }

    const CHOICES: [&str; 2] = ["overwrite-oldest", "drop-newest"];
    const ALL: [Self; 2] = [Self::OverwriteOldest, Self::DropNewest];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_EVENT_RING_FULL");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for EventRingFull {
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

/// `routing-face-drive`: How a node that routes for others serves its links. `task-per-
/// face` gives each link a task of its own on the node's worker threads: a node with many
/// peers uses more than one core, and a link that is slow to serve holds up only itself.
/// `one-task` serves every link from the node's one task, one message at a time, on one
/// core: the order in which the node handles what its links bring is then the order the
/// task polled them, which a run replayed for a test needs, and a host with one core loses
/// nothing by it. Neither changes what a peer is sent or in what order one link's messages
/// are routed.
/// Upstream: Reads each link of a node on a task of its own, spawned on the node's receive
/// runtime (two worker threads unless the runtime is configured otherwise), and routes what
/// that link brings on the same task under a read lock of the routing tables, so the links
/// of a node are served by several threads at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingFaceDrive {
    /// `task-per-face`.
    TaskPerFace,
    /// `one-task`.
    OneTask,
}

impl RoutingFaceDrive {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TaskPerFace => "task-per-face",
            Self::OneTask => "one-task",
        }
    }

    const CHOICES: [&str; 2] = ["task-per-face", "one-task"];
    const ALL: [Self; 2] = [Self::TaskPerFace, Self::OneTask];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_ROUTING_FACE_DRIVE");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for RoutingFaceDrive {
    fn default() -> Self {
        Self::stated()
    }
}

/// `routing-table-sharing`: How a node that routes for others shares its routing tables
/// between the links that route by them and the changes made to them. `rwlock` is
/// upstream's: one reader-writer lock, so a declaration, a link coming up or one leaving
/// waits for the messages being routed, and they wait for it. `snapshot` publishes each
/// change of the tables as a new version that the links route by without waiting: a change
/// copies only the part of the tables it touches, and a link that leaves is sent nothing
/// after its leaving has returned. What `snapshot` does not keep of `rwlock`: a message
/// being routed by the version before a change may reach a link after a declaration that
/// change sends to the same link, an order no rule of the protocol sets. `snapshot` is the
/// value to choose for a router whose sessions come and go while it routes: a change waits
/// for no message being routed, and a message costs what it costs under `rwlock`.
/// Upstream: Keeps a router's routing tables behind one reader-writer lock
/// (`RwLock<Tables>` in its `TablesLock`), so a declaration, a face coming up or one
/// leaving waits for the messages being routed, and they wait for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingTableSharing {
    /// `rwlock`.
    Rwlock,
    /// `snapshot`.
    Snapshot,
}

impl RoutingTableSharing {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Rwlock => "rwlock",
            Self::Snapshot => "snapshot",
        }
    }

    const CHOICES: [&str; 2] = ["rwlock", "snapshot"];
    const ALL: [Self; 2] = [Self::Rwlock, Self::Snapshot];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_ROUTING_TABLE_SHARING");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for RoutingTableSharing {
    fn default() -> Self {
        Self::stated()
    }
}

/// `reassembly-pool-overflow`: What a node does with the first fragment of a new fragmented
/// message when every slot of its reassembly pool holds a message still arriving. The pool
/// is shared by all the node's peers and bounded, where upstream gives each peer and
/// channel a buffer of its own; sizing the pool at twice the peer table keeps the moment
/// from arising. `reject` drops the new message's fragments and keeps the messages already
/// arriving, which is what wz did before this policy. `diagnostic-event` does the same and
/// logs a warning, reassembly/slot-pool-full, at each such drop. `oldest-wins` ends the
/// message whose first fragment came earliest, of whichever peer, and gives its slot to the
/// new one: the ended message is reported as evicted and its later fragments are not joined
/// to it, so the newest traffic is kept and a peer that stalls mid-message loses that
/// message before its deadline. A peer already holding its quota of messages is refused
/// before the pool is looked at, whatever the value.
/// Upstream: Keeps one defragmentation buffer for each peer and channel, so a new
/// fragmented message never waits on another peer's and there is no shared pool to fill.
/// None of the three values is upstream's, since upstream has no such moment; `reject` is
/// what wz did before the policy existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyPoolOverflow {
    /// `reject`.
    Reject,
    /// `diagnostic-event`.
    DiagnosticEvent,
    /// `oldest-wins`.
    OldestWins,
}

impl ReassemblyPoolOverflow {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::DiagnosticEvent => "diagnostic-event",
            Self::OldestWins => "oldest-wins",
        }
    }

    const CHOICES: [&str; 3] = ["reject", "diagnostic-event", "oldest-wins"];
    const ALL: [Self; 3] = [Self::Reject, Self::DiagnosticEvent, Self::OldestWins];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_REASSEMBLY_POOL_OVERFLOW");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for ReassemblyPoolOverflow {
    fn default() -> Self {
        Self::stated()
    }
}

/// `link-tie-order`: How a node orders two zids when it and a peer dialled each other at
/// the same moment and both ends must keep the same one of the two links: the link the node
/// with the lower zid dialled is kept, and this says which zid is lower. `zid-number` reads
/// each zid as the 128-bit number zenoh reads, its first wire byte the least significant.
/// `zid-bytes` compares the two ids byte by byte from the first wire byte, as zenoh-pico
/// compares ids. The two orders disagree on most pairs of zids, so both ends of a link must
/// state the same value: a peer that keeps one link by the other order closes the link this
/// node kept, and neither link survives.
/// Upstream: Two nodes that dial each other at once keep one transport; zenoh orders the
/// two zids as the 128-bit numbers they are, the wire carrying a zid's little-endian bytes.
/// zenoh-pico keeps no such rule, and compares two ids byte by byte from the first wire
/// byte (`_z_id_cmp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkTieOrder {
    /// `zid-number`.
    ZidNumber,
    /// `zid-bytes`.
    ZidBytes,
}

impl LinkTieOrder {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ZidNumber => "zid-number",
            Self::ZidBytes => "zid-bytes",
        }
    }

    const CHOICES: [&str; 2] = ["zid-number", "zid-bytes"];
    const ALL: [Self; 2] = [Self::ZidNumber, Self::ZidBytes];

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_LINK_TIE_ORDER");
        let index = policy_choice(stated, &Self::CHOICES, 0);
        Self::ALL[index]
    }
}

impl Default for LinkTieOrder {
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
    /// `datagram-fragment-pacing`. Upstream: Writes the fragments of a large message to a
    /// datagram socket back to back, as fast as the socket takes them, however small the
    /// receiver's buffer.
    pub datagram_fragment_pacing: bool,
    /// `multicast-link-requires-iface`. Upstream: Opens a multicast link whose locator
    /// names no interface on the first interface that can carry multicast, or on the
    /// kernel's choice when the host has none, so the link may sit on an interface nobody
    /// chose.
    pub multicast_link_requires_iface: bool,
    /// `reliable-gap-reconnect`. Upstream: Accepts a forward jump of the reliable channel's
    /// sequence number without a word: the frames in between are lost, the session stays
    /// open and nothing is repaired, so a peer's declaration lost that way is never
    /// noticed.
    pub reliable_gap_reconnect: ReliableGapReconnect,
    /// `entity-link-restriction`. Upstream: Lets every entity use every link of the
    /// session: a put reaches every link that wants it, a declaration is made to every
    /// link, a query goes to every link.
    pub entity_link_restriction: bool,
    /// `targeted-query`. Upstream: Sends a query to every link whose peers declared a
    /// queryable it matches, and a caller cannot name the peer a query is for.
    pub targeted_query: bool,
    /// `publisher-admission-retry`. Upstream: Sends a put to every link at once and waits
    /// on each link for room in its queue; a put that finds none on a link is dropped there
    /// (or closes the session) and still reports success, and a caller cannot ask for it to
    /// be tried again.
    pub publisher_admission_retry: bool,
    /// `multi-route-atomic-tx`. Upstream: Sends a put to each link on its own terms: a link
    /// whose queue is full drops the frame or waits for room while the other links take it,
    /// so one put can reach some links and not others.
    pub multi_route_atomic_tx: bool,
    /// `entity-timestamp-opt-in`. Upstream: Hands every received sample's timestamp to the
    /// subscriber and every reply's to the querier, and lets any publisher attach the
    /// timestamp it is given.
    pub entity_timestamp_opt_in: bool,
    /// `reply-auto-timestamp`. Upstream: Sends a reply with the timestamp its handler gave
    /// it and with none when the handler gave none.
    pub reply_auto_timestamp: bool,
    /// `subscriber-overload`. Upstream: Hands a sample to a channel handler that blocks its
    /// sender when the handler is full, so a slow consumer applies backpressure into the
    /// session and no sample is lost.
    pub subscriber_overload: SubscriberOverload,
    /// `key-set`. Upstream: Takes a message on any key a peer sends, and finds the
    /// subscribers it reaches by matching that key against each subscription's pattern as
    /// text.
    pub key_set: KeySet,
    /// `sn-resolution`. Upstream: Advertises the 32-bit sequence-number resolution in its
    /// InitSyn and in the Join of a group unless its configuration states another: zenoh
    /// reads `transport/link/tx/sequence_number_resolution`, whose default is 32 bits, and
    /// zenoh-pico builds in `Z_SN_RESOLUTION 0x02` with no setting for another.
    pub sn_resolution: SnResolution,
    /// `supervision-after-expiry`. Upstream: Supervises nothing: an application that stops
    /// making progress is not noticed by the library, so there is no expiry and nothing for
    /// a later feed to do.
    pub supervision_after_expiry: SupervisionAfterExpiry,
    /// `event-ring-full`. Upstream: Keeps no record of the events a node has: a log call
    /// with no logger installed is dropped, so neither the oldest nor the newest of them
    /// survives.
    pub event_ring_full: EventRingFull,
    /// `clock-quality-stamping`. Upstream: Stamps with whatever time the system clock
    /// reads, and has no notion of whether that clock is set or follows a reference.
    pub clock_quality_stamping: ClockQualityStamping,
    /// `routing-face-drive`. Upstream: Reads each link of a node on a task of its own,
    /// spawned on the node's receive runtime (two worker threads unless the runtime is
    /// configured otherwise), and routes what that link brings on the same task under a
    /// read lock of the routing tables, so the links of a node are served by several
    /// threads at once.
    pub routing_face_drive: RoutingFaceDrive,
    /// `routing-table-sharing`. Upstream: Keeps a router's routing tables behind one
    /// reader-writer lock (`RwLock<Tables>` in its `TablesLock`), so a declaration, a face
    /// coming up or one leaving waits for the messages being routed, and they wait for it.
    pub routing_table_sharing: RoutingTableSharing,
    /// `reassembly-pool-overflow`. Upstream: Keeps one defragmentation buffer for each peer
    /// and channel, so a new fragmented message never waits on another peer's and there is
    /// no shared pool to fill. None of the three values is upstream's, since upstream has
    /// no such moment; `reject` is what wz did before the policy existed.
    pub reassembly_pool_overflow: ReassemblyPoolOverflow,
    /// `link-tie-order`. Upstream: Two nodes that dial each other at once keep one
    /// transport; zenoh orders the two zids as the 128-bit numbers they are, the wire
    /// carrying a zid's little-endian bytes. zenoh-pico keeps no such rule, and compares
    /// two ids byte by byte from the first wire byte (`_z_id_cmp`).
    pub link_tie_order: LinkTieOrder,
}

impl SessionPolicy {
    /// The policy this build states: its environment's values, else upstream's.
    pub const fn from_build() -> Self {
        let multicast_loopback = MulticastLoopback::stated();
        let tx_no_progress_deadline = policy_bool(option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE"));
        let tx_expiry_keeps_session = policy_bool(option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION"));
        let declaration_sync_pacing = policy_bool(option_env!("WZ_POLICY_DECLARATION_SYNC_PACING"));
        let datagram_fragment_pacing =
            policy_bool(option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING"));
        let multicast_link_requires_iface =
            policy_bool(option_env!("WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE"));
        let reliable_gap_reconnect = ReliableGapReconnect::stated();
        let entity_link_restriction = policy_bool(option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION"));
        let targeted_query = policy_bool(option_env!("WZ_POLICY_TARGETED_QUERY"));
        let publisher_admission_retry =
            policy_bool(option_env!("WZ_POLICY_PUBLISHER_ADMISSION_RETRY"));
        let multi_route_atomic_tx = policy_bool(option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX"));
        let entity_timestamp_opt_in = policy_bool(option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN"));
        let reply_auto_timestamp = policy_bool(option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP"));
        let subscriber_overload = SubscriberOverload::stated();
        let key_set = KeySet::stated();
        let sn_resolution = SnResolution::stated();
        let supervision_after_expiry = SupervisionAfterExpiry::stated();
        let event_ring_full = EventRingFull::stated();
        let clock_quality_stamping = ClockQualityStamping::stated();
        let routing_face_drive = RoutingFaceDrive::stated();
        let routing_table_sharing = RoutingTableSharing::stated();
        let reassembly_pool_overflow = ReassemblyPoolOverflow::stated();
        let link_tie_order = LinkTieOrder::stated();
        Self {
            multicast_loopback,
            tx_no_progress_deadline,
            tx_expiry_keeps_session,
            declaration_sync_pacing,
            datagram_fragment_pacing,
            multicast_link_requires_iface,
            reliable_gap_reconnect,
            entity_link_restriction,
            targeted_query,
            publisher_admission_retry,
            multi_route_atomic_tx,
            entity_timestamp_opt_in,
            reply_auto_timestamp,
            subscriber_overload,
            key_set,
            sn_resolution,
            supervision_after_expiry,
            event_ring_full,
            clock_quality_stamping,
            routing_face_drive,
            routing_table_sharing,
            reassembly_pool_overflow,
            link_tie_order,
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}

impl PolicyValue for MulticastLoopback {
    const POLICY: &'static str = "multicast-loopback";
    const ALL: &'static [Self] = &[Self::OsDefault, Self::On, Self::Off];
    const IDS: &'static [&'static str] = &["os-default", "on", "off"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_OS_DEFAULT"
        )),
        policy_allows(option_env!("WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_ON")),
        policy_allows(option_env!("WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_OFF")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Link;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<MulticastLoopback>(MulticastLoopback::DEFAULT as usize),
    "the default of multicast-loopback is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `tx-no-progress-deadline` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxNoProgressDeadline {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl TxNoProgressDeadline {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for TxNoProgressDeadline {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<TxNoProgressDeadline> for bool {
    fn from(value: TxNoProgressDeadline) -> Self {
        value.is_on()
    }
}

impl Default for TxNoProgressDeadline {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for TxNoProgressDeadline {
    const POLICY: &'static str = "tx-no-progress-deadline";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<TxNoProgressDeadline>(TxNoProgressDeadline::DEFAULT as usize),
    "the default of tx-no-progress-deadline is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `tx-expiry-keeps-session` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxExpiryKeepsSession {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl TxExpiryKeepsSession {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for TxExpiryKeepsSession {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<TxExpiryKeepsSession> for bool {
    fn from(value: TxExpiryKeepsSession) -> Self {
        value.is_on()
    }
}

impl Default for TxExpiryKeepsSession {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for TxExpiryKeepsSession {
    const POLICY: &'static str = "tx-expiry-keeps-session";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<TxExpiryKeepsSession>(TxExpiryKeepsSession::DEFAULT as usize),
    "the default of tx-expiry-keeps-session is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `declaration-sync-pacing` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationSyncPacing {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl DeclarationSyncPacing {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_DECLARATION_SYNC_PACING");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for DeclarationSyncPacing {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<DeclarationSyncPacing> for bool {
    fn from(value: DeclarationSyncPacing) -> Self {
        value.is_on()
    }
}

impl Default for DeclarationSyncPacing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for DeclarationSyncPacing {
    const POLICY: &'static str = "declaration-sync-pacing";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_DECLARATION_SYNC_PACING_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_DECLARATION_SYNC_PACING_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Link;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Quiescent;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = Some("the start of the next replay of declarations");

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<DeclarationSyncPacing>(DeclarationSyncPacing::DEFAULT as usize),
    "the default of declaration-sync-pacing is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `datagram-fragment-pacing` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramFragmentPacing {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl DatagramFragmentPacing {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for DatagramFragmentPacing {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<DatagramFragmentPacing> for bool {
    fn from(value: DatagramFragmentPacing) -> Self {
        value.is_on()
    }
}

impl Default for DatagramFragmentPacing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for DatagramFragmentPacing {
    const POLICY: &'static str = "datagram-fragment-pacing";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Link;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<DatagramFragmentPacing>(DatagramFragmentPacing::DEFAULT as usize),
    "the default of datagram-fragment-pacing is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `multicast-link-requires-iface` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastLinkRequiresIface {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl MulticastLinkRequiresIface {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for MulticastLinkRequiresIface {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<MulticastLinkRequiresIface> for bool {
    fn from(value: MulticastLinkRequiresIface) -> Self {
        value.is_on()
    }
}

impl Default for MulticastLinkRequiresIface {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for MulticastLinkRequiresIface {
    const POLICY: &'static str = "multicast-link-requires-iface";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE_ALLOWS_OFF"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE_ALLOWS_ON"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Link;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<MulticastLinkRequiresIface>(MulticastLinkRequiresIface::DEFAULT as usize),
    "the default of multicast-link-requires-iface is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for ReliableGapReconnect {
    const POLICY: &'static str = "reliable-gap-reconnect";
    const ALL: &'static [Self] = &[Self::Off, Self::UntilDeclarationsSynced, Self::Always];
    const IDS: &'static [&'static str] = &["off", "until-declarations-synced", "always"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_OFF")),
        policy_allows(option_env!(
            "WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_UNTIL_DECLARATIONS_SYNCED"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_ALWAYS"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<ReliableGapReconnect>(ReliableGapReconnect::DEFAULT as usize),
    "the default of reliable-gap-reconnect is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `entity-link-restriction` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityLinkRestriction {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl EntityLinkRestriction {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for EntityLinkRestriction {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<EntityLinkRestriction> for bool {
    fn from(value: EntityLinkRestriction) -> Self {
        value.is_on()
    }
}

impl Default for EntityLinkRestriction {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for EntityLinkRestriction {
    const POLICY: &'static str = "entity-link-restriction";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Entity;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<EntityLinkRestriction>(EntityLinkRestriction::DEFAULT as usize),
    "the default of entity-link-restriction is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `targeted-query` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetedQuery {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl TargetedQuery {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_TARGETED_QUERY");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for TargetedQuery {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<TargetedQuery> for bool {
    fn from(value: TargetedQuery) -> Self {
        value.is_on()
    }
}

impl Default for TargetedQuery {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for TargetedQuery {
    const POLICY: &'static str = "targeted-query";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_TARGETED_QUERY_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_TARGETED_QUERY_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Message;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<TargetedQuery>(TargetedQuery::DEFAULT as usize),
    "the default of targeted-query is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `publisher-admission-retry` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublisherAdmissionRetry {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl PublisherAdmissionRetry {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_PUBLISHER_ADMISSION_RETRY");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for PublisherAdmissionRetry {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<PublisherAdmissionRetry> for bool {
    fn from(value: PublisherAdmissionRetry) -> Self {
        value.is_on()
    }
}

impl Default for PublisherAdmissionRetry {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for PublisherAdmissionRetry {
    const POLICY: &'static str = "publisher-admission-retry";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_PUBLISHER_ADMISSION_RETRY_ALLOWS_OFF"
        )),
        policy_allows(option_env!("WZ_POLICY_PUBLISHER_ADMISSION_RETRY_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Message;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<PublisherAdmissionRetry>(PublisherAdmissionRetry::DEFAULT as usize),
    "the default of publisher-admission-retry is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `multi-route-atomic-tx` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiRouteAtomicTx {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl MultiRouteAtomicTx {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for MultiRouteAtomicTx {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<MultiRouteAtomicTx> for bool {
    fn from(value: MultiRouteAtomicTx) -> Self {
        value.is_on()
    }
}

impl Default for MultiRouteAtomicTx {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for MultiRouteAtomicTx {
    const POLICY: &'static str = "multi-route-atomic-tx";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Message;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<MultiRouteAtomicTx>(MultiRouteAtomicTx::DEFAULT as usize),
    "the default of multi-route-atomic-tx is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `entity-timestamp-opt-in` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityTimestampOptIn {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl EntityTimestampOptIn {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for EntityTimestampOptIn {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<EntityTimestampOptIn> for bool {
    fn from(value: EntityTimestampOptIn) -> Self {
        value.is_on()
    }
}

impl Default for EntityTimestampOptIn {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for EntityTimestampOptIn {
    const POLICY: &'static str = "entity-timestamp-opt-in";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Entity;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<EntityTimestampOptIn>(EntityTimestampOptIn::DEFAULT as usize),
    "the default of entity-timestamp-opt-in is outside its WZ_POLICY_*_ALLOWS_*"
);

/// `reply-auto-timestamp` as a value; [`SessionPolicy`] holds it as a `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyAutoTimestamp {
    /// `off`, upstream's behaviour.
    Off,
    /// `on`.
    On,
}

impl ReplyAutoTimestamp {
    /// The value as the declaration, the Kconfig and the environment spell it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The value as the `bool` field of [`SessionPolicy`] holds it.
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }

    const fn from_bool(on: bool) -> Self {
        if on {
            Self::On
        } else {
            Self::Off
        }
    }

    const fn stated() -> Self {
        let stated = option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP");
        Self::from_bool(policy_bool(stated))
    }
}

impl From<bool> for ReplyAutoTimestamp {
    fn from(on: bool) -> Self {
        Self::from_bool(on)
    }
}

impl From<ReplyAutoTimestamp> for bool {
    fn from(value: ReplyAutoTimestamp) -> Self {
        value.is_on()
    }
}

impl Default for ReplyAutoTimestamp {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl PolicyValue for ReplyAutoTimestamp {
    const POLICY: &'static str = "reply-auto-timestamp";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP_ALLOWS_OFF")),
        policy_allows(option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP_ALLOWS_ON")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Entity;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<ReplyAutoTimestamp>(ReplyAutoTimestamp::DEFAULT as usize),
    "the default of reply-auto-timestamp is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for SubscriberOverload {
    const POLICY: &'static str = "subscriber-overload";
    const ALL: &'static [Self] = &[Self::Block, Self::Reject, Self::KeepLatest];
    const IDS: &'static [&'static str] = &["block", "reject", "keep-latest"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_BLOCK")),
        policy_allows(option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_REJECT")),
        policy_allows(option_env!(
            "WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_KEEP_LATEST"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Entity;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<SubscriberOverload>(SubscriberOverload::DEFAULT as usize),
    "the default of subscriber-overload is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for KeySet {
    const POLICY: &'static str = "key-set";
    const ALL: &'static [Self] = &[Self::Open, Self::Closed];
    const IDS: &'static [&'static str] = &["open", "closed"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_KEY_SET_ALLOWS_OPEN")),
        policy_allows(option_env!("WZ_POLICY_KEY_SET_ALLOWS_CLOSED")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<KeySet>(KeySet::DEFAULT as usize),
    "the default of key-set is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for SnResolution {
    const POLICY: &'static str = "sn-resolution";
    const ALL: &'static [Self] = &[Self::Bits32, Self::Bits8, Self::Bits16, Self::Bits64];
    const IDS: &'static [&'static str] = &["bits-32", "bits-8", "bits-16", "bits-64"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_32")),
        policy_allows(option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_8")),
        policy_allows(option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_16")),
        policy_allows(option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_64")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Negotiated;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<SnResolution>(SnResolution::DEFAULT as usize),
    "the default of sn-resolution is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for SupervisionAfterExpiry {
    const POLICY: &'static str = "supervision-after-expiry";
    const ALL: &'static [Self] = &[Self::Latch, Self::Rearm];
    const IDS: &'static [&'static str] = &["latch", "rearm"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_SUPERVISION_AFTER_EXPIRY_ALLOWS_LATCH"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_SUPERVISION_AFTER_EXPIRY_ALLOWS_REARM"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Runtime;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<SupervisionAfterExpiry>(SupervisionAfterExpiry::DEFAULT as usize),
    "the default of supervision-after-expiry is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for EventRingFull {
    const POLICY: &'static str = "event-ring-full";
    const ALL: &'static [Self] = &[Self::OverwriteOldest, Self::DropNewest];
    const IDS: &'static [&'static str] = &["overwrite-oldest", "drop-newest"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_EVENT_RING_FULL_ALLOWS_OVERWRITE_OLDEST"
        )),
        policy_allows(option_env!("WZ_POLICY_EVENT_RING_FULL_ALLOWS_DROP_NEWEST")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Runtime;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Quiescent;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = Some("after the consumer has read every record");

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<EventRingFull>(EventRingFull::DEFAULT as usize),
    "the default of event-ring-full is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for ClockQualityStamping {
    const POLICY: &'static str = "clock-quality-stamping";
    const ALL: &'static [Self] = &[Self::Always, Self::TrustedOnly];
    const IDS: &'static [&'static str] = &["always", "trusted-only"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_CLOCK_QUALITY_STAMPING_ALLOWS_ALWAYS"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_CLOCK_QUALITY_STAMPING_ALLOWS_TRUSTED_ONLY"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Runtime;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<ClockQualityStamping>(ClockQualityStamping::DEFAULT as usize),
    "the default of clock-quality-stamping is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for RoutingFaceDrive {
    const POLICY: &'static str = "routing-face-drive";
    const ALL: &'static [Self] = &[Self::TaskPerFace, Self::OneTask];
    const IDS: &'static [&'static str] = &["task-per-face", "one-task"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_ROUTING_FACE_DRIVE_ALLOWS_TASK_PER_FACE"
        )),
        policy_allows(option_env!("WZ_POLICY_ROUTING_FACE_DRIVE_ALLOWS_ONE_TASK")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Runtime;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<RoutingFaceDrive>(RoutingFaceDrive::DEFAULT as usize),
    "the default of routing-face-drive is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for RoutingTableSharing {
    const POLICY: &'static str = "routing-table-sharing";
    const ALL: &'static [Self] = &[Self::Rwlock, Self::Snapshot];
    const IDS: &'static [&'static str] = &["rwlock", "snapshot"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_ROUTING_TABLE_SHARING_ALLOWS_RWLOCK")),
        policy_allows(option_env!(
            "WZ_POLICY_ROUTING_TABLE_SHARING_ALLOWS_SNAPSHOT"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Runtime;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Timing;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<RoutingTableSharing>(RoutingTableSharing::DEFAULT as usize),
    "the default of routing-table-sharing is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for ReassemblyPoolOverflow {
    const POLICY: &'static str = "reassembly-pool-overflow";
    const ALL: &'static [Self] = &[Self::Reject, Self::DiagnosticEvent, Self::OldestWins];
    const IDS: &'static [&'static str] = &["reject", "diagnostic-event", "oldest-wins"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!(
            "WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_REJECT"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_DIAGNOSTIC_EVENT"
        )),
        policy_allows(option_env!(
            "WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_OLDEST_WINS"
        )),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Session;
    const BINDING: Binding = Binding::Live;
    const MUTABILITY: Mutability = Mutability::Hot;
    const WIRE: Wire = Wire::None;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<ReassemblyPoolOverflow>(ReassemblyPoolOverflow::DEFAULT as usize),
    "the default of reassembly-pool-overflow is outside its WZ_POLICY_*_ALLOWS_*"
);

impl PolicyValue for LinkTieOrder {
    const POLICY: &'static str = "link-tie-order";
    const ALL: &'static [Self] = &[Self::ZidNumber, Self::ZidBytes];
    const IDS: &'static [&'static str] = &["zid-number", "zid-bytes"];
    const DOMAIN: Domain<Self> = Domain::from_allowed(&[
        policy_allows(option_env!("WZ_POLICY_LINK_TIE_ORDER_ALLOWS_ZID_NUMBER")),
        policy_allows(option_env!("WZ_POLICY_LINK_TIE_ORDER_ALLOWS_ZID_BYTES")),
    ]);
    const DEFAULT: Self = Self::stated();
    const SCOPE: Scope = Scope::Link;
    const BINDING: Binding = Binding::Open;
    const MUTABILITY: Mutability = Mutability::Fixed;
    const WIRE: Wire = Wire::Visible;
    const BOUNDARY: Option<&'static str> = None;

    fn index(self) -> usize {
        self as usize
    }
}

const _: () = assert!(
    default_is_allowed::<LinkTieOrder>(LinkTieOrder::DEFAULT as usize),
    "the default of link-tie-order is outside its WZ_POLICY_*_ALLOWS_*"
);
