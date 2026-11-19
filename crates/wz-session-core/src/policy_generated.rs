// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-policies.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], the
//! snapshot a creator hands each machine. Its build defaults ([`SessionPolicy::defaults`]) are
//! the values the build's environment states as `WZ_POLICY_<NAME>`, or upstream's behaviour where
//! it states none, and a test names another value with the field's `select_*`.
//!
//! A reader that names a policy by its id, as the open-stage document does, dispatches on the
//! policy's row of [`POLICIES`]; [`PROFILES`] holds the named sets of policy values the
//! declaration states (`[[profile]]`), which a document starts from.
//!
//! Each policy's value type, an `Off` and `On` enum of its own for a bool policy, implements
//! [`PolicyValue`]: the domain the build allows (`WZ_POLICY_<NAME>_ALLOWS_<VALUE>`, an unset name
//! taking the rule of `DEFAULTS_ONLY`), the build's default, which the domain must hold, and
//! where the policy is bound. A field of [`SessionPolicy`] holds no byte for a policy whose domain
//! is one value.

use super::{policy_bool, policy_choice, policy_defaults_only};

use crate::policy_binding::{
    default_is_allowed, Binding, Bound, Domain, Mutability, OutsideDomain, PolicyEntry,
    PolicyField, PolicyValue, Scope, Wire,
};
use crate::policy_document::{Profile, Statement};

/// Whether an allowance the build does not state keeps only the build default: what
/// `WZ_POLICY_DOMAINS` states, else whether the target has no operating system.
const DEFAULTS_ONLY: bool = policy_defaults_only(option_env!("WZ_POLICY_DOMAINS"));

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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::stated()
    }
}

/// The value of every policy, as one snapshot: what a creator resolved and handed the machines of
/// its scope. A machine reads a policy only through the accessor of its field, never from the
/// build. Each value lies inside the build's domain of its policy ([`PolicyValue::DOMAIN`]), and a
/// policy whose domain is one value reads as that value whatever was selected ([`Bound::get`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionPolicy {
    /// `multicast-loopback`. Upstream: Never sets IP_MULTICAST_LOOP on a multicast socket,
    /// so each sending socket keeps the operating system's setting.
    multicast_loopback: MulticastLoopbackBound,
    /// `tx-no-progress-deadline`. Upstream: Gives a blocking message one wait_before_close
    /// for the whole of it, however many fragments go out: its deadline has no cap to
    /// extend by, so a fragment out leaves the deadline where it is.
    tx_no_progress_deadline: TxNoProgressDeadlineBound,
    /// `tx-expiry-keeps-session`. Upstream: Closes the session as unresponsive when a
    /// blocking message found no room in its deadline, and tells the sender nothing.
    tx_expiry_keeps_session: TxExpiryKeepsSessionBound,
    /// `declaration-sync-pacing`. Upstream: Replays every declaration it holds to a new
    /// peer in one call, as soon as the session is open again.
    declaration_sync_pacing: DeclarationSyncPacingBound,
    /// `datagram-fragment-pacing`. Upstream: Writes the fragments of a large message to a
    /// datagram socket back to back, as fast as the socket takes them, however small the
    /// receiver's buffer.
    datagram_fragment_pacing: DatagramFragmentPacingBound,
    /// `multicast-link-requires-iface`. Upstream: Opens a multicast link whose locator
    /// names no interface on the first interface that can carry multicast, or on the
    /// kernel's choice when the host has none, so the link may sit on an interface nobody
    /// chose.
    multicast_link_requires_iface: MulticastLinkRequiresIfaceBound,
    /// `reliable-gap-reconnect`. Upstream: Accepts a forward jump of the reliable channel's
    /// sequence number without a word: the frames in between are lost, the session stays
    /// open and nothing is repaired, so a peer's declaration lost that way is never
    /// noticed.
    reliable_gap_reconnect: ReliableGapReconnectBound,
    /// `entity-link-restriction`. Upstream: Lets every entity use every link of the
    /// session: a put reaches every link that wants it, a declaration is made to every
    /// link, a query goes to every link.
    entity_link_restriction: EntityLinkRestrictionBound,
    /// `targeted-query`. Upstream: Sends a query to every link whose peers declared a
    /// queryable it matches, and a caller cannot name the peer a query is for.
    targeted_query: TargetedQueryBound,
    /// `publisher-admission-retry`. Upstream: Sends a put to every link at once and waits
    /// on each link for room in its queue; a put that finds none on a link is dropped there
    /// (or closes the session) and still reports success, and a caller cannot ask for it to
    /// be tried again.
    publisher_admission_retry: PublisherAdmissionRetryBound,
    /// `multi-route-atomic-tx`. Upstream: Sends a put to each link on its own terms: a link
    /// whose queue is full drops the frame or waits for room while the other links take it,
    /// so one put can reach some links and not others.
    multi_route_atomic_tx: MultiRouteAtomicTxBound,
    /// `entity-timestamp-opt-in`. Upstream: Hands every received sample's timestamp to the
    /// subscriber and every reply's to the querier, and lets any publisher attach the
    /// timestamp it is given.
    entity_timestamp_opt_in: EntityTimestampOptInBound,
    /// `reply-auto-timestamp`. Upstream: Sends a reply with the timestamp its handler gave
    /// it and with none when the handler gave none.
    reply_auto_timestamp: ReplyAutoTimestampBound,
    /// `subscriber-overload`. Upstream: Hands a sample to a channel handler that blocks its
    /// sender when the handler is full, so a slow consumer applies backpressure into the
    /// session and no sample is lost.
    subscriber_overload: SubscriberOverloadBound,
    /// `key-set`. Upstream: Takes a message on any key a peer sends, and finds the
    /// subscribers it reaches by matching that key against each subscription's pattern as
    /// text.
    key_set: KeySetBound,
    /// `sn-resolution`. Upstream: Advertises the 32-bit sequence-number resolution in its
    /// InitSyn and in the Join of a group unless its configuration states another: zenoh
    /// reads `transport/link/tx/sequence_number_resolution`, whose default is 32 bits, and
    /// zenoh-pico builds in `Z_SN_RESOLUTION 0x02` with no setting for another.
    sn_resolution: SnResolutionBound,
    /// `supervision-after-expiry`. Upstream: Supervises nothing: an application that stops
    /// making progress is not noticed by the library, so there is no expiry and nothing for
    /// a later feed to do.
    supervision_after_expiry: SupervisionAfterExpiryBound,
    /// `event-ring-full`. Upstream: Keeps no record of the events a node has: a log call
    /// with no logger installed is dropped, so neither the oldest nor the newest of them
    /// survives.
    event_ring_full: EventRingFullBound,
    /// `clock-quality-stamping`. Upstream: Stamps with whatever time the system clock
    /// reads, and has no notion of whether that clock is set or follows a reference.
    clock_quality_stamping: ClockQualityStampingBound,
    /// `routing-face-drive`. Upstream: Reads each link of a node on a task of its own,
    /// spawned on the node's receive runtime (two worker threads unless the runtime is
    /// configured otherwise), and routes what that link brings on the same task under a
    /// read lock of the routing tables, so the links of a node are served by several
    /// threads at once.
    routing_face_drive: RoutingFaceDriveBound,
    /// `routing-table-sharing`. Upstream: Keeps a router's routing tables behind one
    /// reader-writer lock (`RwLock<Tables>` in its `TablesLock`), so a declaration, a face
    /// coming up or one leaving waits for the messages being routed, and they wait for it.
    routing_table_sharing: RoutingTableSharingBound,
    /// `reassembly-pool-overflow`. Upstream: Keeps one defragmentation buffer for each peer
    /// and channel, so a new fragmented message never waits on another peer's and there is
    /// no shared pool to fill. None of the three values is upstream's, since upstream has
    /// no such moment; `reject` is what wz did before the policy existed.
    reassembly_pool_overflow: ReassemblyPoolOverflowBound,
    /// `link-tie-order`. Upstream: Two nodes that dial each other at once keep one
    /// transport; zenoh orders the two zids as the 128-bit numbers they are, the wire
    /// carrying a zid's little-endian bytes. zenoh-pico keeps no such rule, and compares
    /// two ids byte by byte from the first wire byte (`_z_id_cmp`).
    link_tie_order: LinkTieOrderBound,
}

impl SessionPolicy {
    /// The build defaults: each policy's value as the build's environment states it
    /// (`WZ_POLICY_<NAME>`), else upstream's behaviour.
    pub const fn from_build() -> Self {
        Self {
            multicast_loopback: Bound::build_default(),
            tx_no_progress_deadline: Bound::build_default(),
            tx_expiry_keeps_session: Bound::build_default(),
            declaration_sync_pacing: Bound::build_default(),
            datagram_fragment_pacing: Bound::build_default(),
            multicast_link_requires_iface: Bound::build_default(),
            reliable_gap_reconnect: Bound::build_default(),
            entity_link_restriction: Bound::build_default(),
            targeted_query: Bound::build_default(),
            publisher_admission_retry: Bound::build_default(),
            multi_route_atomic_tx: Bound::build_default(),
            entity_timestamp_opt_in: Bound::build_default(),
            reply_auto_timestamp: Bound::build_default(),
            subscriber_overload: Bound::build_default(),
            key_set: Bound::build_default(),
            sn_resolution: Bound::build_default(),
            supervision_after_expiry: Bound::build_default(),
            event_ring_full: Bound::build_default(),
            clock_quality_stamping: Bound::build_default(),
            routing_face_drive: Bound::build_default(),
            routing_table_sharing: Bound::build_default(),
            reassembly_pool_overflow: Bound::build_default(),
            link_tie_order: Bound::build_default(),
        }
    }

    /// The build defaults ([`Self::from_build`]): the snapshot a creator starts from. A machine
    /// does not call it; it reads the snapshot its creator handed it.
    pub const fn defaults() -> Self {
        Self::from_build()
    }

    /// `multicast-loopback` as this snapshot holds it.
    pub const fn multicast_loopback(&self) -> MulticastLoopback {
        self.multicast_loopback.get()
    }

    /// Selects `multicast-loopback`, when the build's domain holds `value`.
    pub fn select_multicast_loopback(
        &mut self,
        value: MulticastLoopback,
    ) -> Result<(), OutsideDomain<MulticastLoopback>> {
        self.multicast_loopback = Bound::select(value)?;
        Ok(())
    }

    /// `tx-no-progress-deadline` as this snapshot holds it: `true` for `on`.
    pub const fn tx_no_progress_deadline(&self) -> bool {
        self.tx_no_progress_deadline.get().is_on()
    }

    /// Selects `tx-no-progress-deadline`, when the build's domain holds `value`.
    pub fn select_tx_no_progress_deadline(
        &mut self,
        value: TxNoProgressDeadline,
    ) -> Result<(), OutsideDomain<TxNoProgressDeadline>> {
        self.tx_no_progress_deadline = Bound::select(value)?;
        Ok(())
    }

    /// `tx-expiry-keeps-session` as this snapshot holds it: `true` for `on`.
    pub const fn tx_expiry_keeps_session(&self) -> bool {
        self.tx_expiry_keeps_session.get().is_on()
    }

    /// Selects `tx-expiry-keeps-session`, when the build's domain holds `value`.
    pub fn select_tx_expiry_keeps_session(
        &mut self,
        value: TxExpiryKeepsSession,
    ) -> Result<(), OutsideDomain<TxExpiryKeepsSession>> {
        self.tx_expiry_keeps_session = Bound::select(value)?;
        Ok(())
    }

    /// `declaration-sync-pacing` as this snapshot holds it: `true` for `on`.
    pub const fn declaration_sync_pacing(&self) -> bool {
        self.declaration_sync_pacing.get().is_on()
    }

    /// Selects `declaration-sync-pacing`, when the build's domain holds `value`.
    pub fn select_declaration_sync_pacing(
        &mut self,
        value: DeclarationSyncPacing,
    ) -> Result<(), OutsideDomain<DeclarationSyncPacing>> {
        self.declaration_sync_pacing = Bound::select(value)?;
        Ok(())
    }

    /// `datagram-fragment-pacing` as this snapshot holds it: `true` for `on`.
    pub const fn datagram_fragment_pacing(&self) -> bool {
        self.datagram_fragment_pacing.get().is_on()
    }

    /// Selects `datagram-fragment-pacing`, when the build's domain holds `value`.
    pub fn select_datagram_fragment_pacing(
        &mut self,
        value: DatagramFragmentPacing,
    ) -> Result<(), OutsideDomain<DatagramFragmentPacing>> {
        self.datagram_fragment_pacing = Bound::select(value)?;
        Ok(())
    }

    /// `multicast-link-requires-iface` as this snapshot holds it: `true` for `on`.
    pub const fn multicast_link_requires_iface(&self) -> bool {
        self.multicast_link_requires_iface.get().is_on()
    }

    /// Selects `multicast-link-requires-iface`, when the build's domain holds `value`.
    pub fn select_multicast_link_requires_iface(
        &mut self,
        value: MulticastLinkRequiresIface,
    ) -> Result<(), OutsideDomain<MulticastLinkRequiresIface>> {
        self.multicast_link_requires_iface = Bound::select(value)?;
        Ok(())
    }

    /// `reliable-gap-reconnect` as this snapshot holds it.
    pub const fn reliable_gap_reconnect(&self) -> ReliableGapReconnect {
        self.reliable_gap_reconnect.get()
    }

    /// Selects `reliable-gap-reconnect`, when the build's domain holds `value`.
    pub fn select_reliable_gap_reconnect(
        &mut self,
        value: ReliableGapReconnect,
    ) -> Result<(), OutsideDomain<ReliableGapReconnect>> {
        self.reliable_gap_reconnect = Bound::select(value)?;
        Ok(())
    }

    /// `entity-link-restriction` as this snapshot holds it: `true` for `on`.
    pub const fn entity_link_restriction(&self) -> bool {
        self.entity_link_restriction.get().is_on()
    }

    /// Selects `entity-link-restriction`, when the build's domain holds `value`.
    pub fn select_entity_link_restriction(
        &mut self,
        value: EntityLinkRestriction,
    ) -> Result<(), OutsideDomain<EntityLinkRestriction>> {
        self.entity_link_restriction = Bound::select(value)?;
        Ok(())
    }

    /// `targeted-query` as this snapshot holds it: `true` for `on`.
    pub const fn targeted_query(&self) -> bool {
        self.targeted_query.get().is_on()
    }

    /// Selects `targeted-query`, when the build's domain holds `value`.
    pub fn select_targeted_query(
        &mut self,
        value: TargetedQuery,
    ) -> Result<(), OutsideDomain<TargetedQuery>> {
        self.targeted_query = Bound::select(value)?;
        Ok(())
    }

    /// `publisher-admission-retry` as this snapshot holds it: `true` for `on`.
    pub const fn publisher_admission_retry(&self) -> bool {
        self.publisher_admission_retry.get().is_on()
    }

    /// Selects `publisher-admission-retry`, when the build's domain holds `value`.
    pub fn select_publisher_admission_retry(
        &mut self,
        value: PublisherAdmissionRetry,
    ) -> Result<(), OutsideDomain<PublisherAdmissionRetry>> {
        self.publisher_admission_retry = Bound::select(value)?;
        Ok(())
    }

    /// `multi-route-atomic-tx` as this snapshot holds it: `true` for `on`.
    pub const fn multi_route_atomic_tx(&self) -> bool {
        self.multi_route_atomic_tx.get().is_on()
    }

    /// Selects `multi-route-atomic-tx`, when the build's domain holds `value`.
    pub fn select_multi_route_atomic_tx(
        &mut self,
        value: MultiRouteAtomicTx,
    ) -> Result<(), OutsideDomain<MultiRouteAtomicTx>> {
        self.multi_route_atomic_tx = Bound::select(value)?;
        Ok(())
    }

    /// `entity-timestamp-opt-in` as this snapshot holds it: `true` for `on`.
    pub const fn entity_timestamp_opt_in(&self) -> bool {
        self.entity_timestamp_opt_in.get().is_on()
    }

    /// Selects `entity-timestamp-opt-in`, when the build's domain holds `value`.
    pub fn select_entity_timestamp_opt_in(
        &mut self,
        value: EntityTimestampOptIn,
    ) -> Result<(), OutsideDomain<EntityTimestampOptIn>> {
        self.entity_timestamp_opt_in = Bound::select(value)?;
        Ok(())
    }

    /// `reply-auto-timestamp` as this snapshot holds it: `true` for `on`.
    pub const fn reply_auto_timestamp(&self) -> bool {
        self.reply_auto_timestamp.get().is_on()
    }

    /// Selects `reply-auto-timestamp`, when the build's domain holds `value`.
    pub fn select_reply_auto_timestamp(
        &mut self,
        value: ReplyAutoTimestamp,
    ) -> Result<(), OutsideDomain<ReplyAutoTimestamp>> {
        self.reply_auto_timestamp = Bound::select(value)?;
        Ok(())
    }

    /// `subscriber-overload` as this snapshot holds it.
    pub const fn subscriber_overload(&self) -> SubscriberOverload {
        self.subscriber_overload.get()
    }

    /// Selects `subscriber-overload`, when the build's domain holds `value`.
    pub fn select_subscriber_overload(
        &mut self,
        value: SubscriberOverload,
    ) -> Result<(), OutsideDomain<SubscriberOverload>> {
        self.subscriber_overload = Bound::select(value)?;
        Ok(())
    }

    /// `key-set` as this snapshot holds it.
    pub const fn key_set(&self) -> KeySet {
        self.key_set.get()
    }

    /// Selects `key-set`, when the build's domain holds `value`.
    pub fn select_key_set(&mut self, value: KeySet) -> Result<(), OutsideDomain<KeySet>> {
        self.key_set = Bound::select(value)?;
        Ok(())
    }

    /// `sn-resolution` as this snapshot holds it.
    pub const fn sn_resolution(&self) -> SnResolution {
        self.sn_resolution.get()
    }

    /// Selects `sn-resolution`, when the build's domain holds `value`.
    pub fn select_sn_resolution(
        &mut self,
        value: SnResolution,
    ) -> Result<(), OutsideDomain<SnResolution>> {
        self.sn_resolution = Bound::select(value)?;
        Ok(())
    }

    /// `supervision-after-expiry` as this snapshot holds it.
    pub const fn supervision_after_expiry(&self) -> SupervisionAfterExpiry {
        self.supervision_after_expiry.get()
    }

    /// Selects `supervision-after-expiry`, when the build's domain holds `value`.
    pub fn select_supervision_after_expiry(
        &mut self,
        value: SupervisionAfterExpiry,
    ) -> Result<(), OutsideDomain<SupervisionAfterExpiry>> {
        self.supervision_after_expiry = Bound::select(value)?;
        Ok(())
    }

    /// `event-ring-full` as this snapshot holds it.
    pub const fn event_ring_full(&self) -> EventRingFull {
        self.event_ring_full.get()
    }

    /// Selects `event-ring-full`, when the build's domain holds `value`.
    pub fn select_event_ring_full(
        &mut self,
        value: EventRingFull,
    ) -> Result<(), OutsideDomain<EventRingFull>> {
        self.event_ring_full = Bound::select(value)?;
        Ok(())
    }

    /// `clock-quality-stamping` as this snapshot holds it.
    pub const fn clock_quality_stamping(&self) -> ClockQualityStamping {
        self.clock_quality_stamping.get()
    }

    /// Selects `clock-quality-stamping`, when the build's domain holds `value`.
    pub fn select_clock_quality_stamping(
        &mut self,
        value: ClockQualityStamping,
    ) -> Result<(), OutsideDomain<ClockQualityStamping>> {
        self.clock_quality_stamping = Bound::select(value)?;
        Ok(())
    }

    /// `routing-face-drive` as this snapshot holds it.
    pub const fn routing_face_drive(&self) -> RoutingFaceDrive {
        self.routing_face_drive.get()
    }

    /// Selects `routing-face-drive`, when the build's domain holds `value`.
    pub fn select_routing_face_drive(
        &mut self,
        value: RoutingFaceDrive,
    ) -> Result<(), OutsideDomain<RoutingFaceDrive>> {
        self.routing_face_drive = Bound::select(value)?;
        Ok(())
    }

    /// `routing-table-sharing` as this snapshot holds it.
    pub const fn routing_table_sharing(&self) -> RoutingTableSharing {
        self.routing_table_sharing.get()
    }

    /// Selects `routing-table-sharing`, when the build's domain holds `value`.
    pub fn select_routing_table_sharing(
        &mut self,
        value: RoutingTableSharing,
    ) -> Result<(), OutsideDomain<RoutingTableSharing>> {
        self.routing_table_sharing = Bound::select(value)?;
        Ok(())
    }

    /// `reassembly-pool-overflow` as this snapshot holds it.
    pub const fn reassembly_pool_overflow(&self) -> ReassemblyPoolOverflow {
        self.reassembly_pool_overflow.get()
    }

    /// Selects `reassembly-pool-overflow`, when the build's domain holds `value`.
    pub fn select_reassembly_pool_overflow(
        &mut self,
        value: ReassemblyPoolOverflow,
    ) -> Result<(), OutsideDomain<ReassemblyPoolOverflow>> {
        self.reassembly_pool_overflow = Bound::select(value)?;
        Ok(())
    }

    /// `link-tie-order` as this snapshot holds it.
    pub const fn link_tie_order(&self) -> LinkTieOrder {
        self.link_tie_order.get()
    }

    /// Selects `link-tie-order`, when the build's domain holds `value`.
    pub fn select_link_tie_order(
        &mut self,
        value: LinkTieOrder,
    ) -> Result<(), OutsideDomain<LinkTieOrder>> {
        self.link_tie_order = Bound::select(value)?;
        Ok(())
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_build()
    }
}

/// How `multicast-loopback` is held: in no byte when its domain is one value.
type MulticastLoopbackBound = Bound<MulticastLoopback, { MulticastLoopback::HELD }>;

impl PolicyValue for MulticastLoopback {
    const POLICY: &'static str = "multicast-loopback";
    const ALL: &'static [Self] = &[Self::OsDefault, Self::On, Self::Off];
    const IDS: &'static [&'static str] = &["os-default", "on", "off"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_OS_DEFAULT"),
            option_env!("WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_ON"),
            option_env!("WZ_POLICY_MULTICAST_LOOPBACK_ALLOWS_OFF"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for MulticastLoopback {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_multicast_loopback(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.multicast_loopback.get()
    }
}

/// `tx-no-progress-deadline` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `tx-no-progress-deadline` is held: in no byte when its domain is one value.
type TxNoProgressDeadlineBound = Bound<TxNoProgressDeadline, { TxNoProgressDeadline::HELD }>;

impl PolicyValue for TxNoProgressDeadline {
    const POLICY: &'static str = "tx-no-progress-deadline";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE_ALLOWS_OFF"),
            option_env!("WZ_POLICY_TX_NO_PROGRESS_DEADLINE_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for TxNoProgressDeadline {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_tx_no_progress_deadline(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.tx_no_progress_deadline.get()
    }
}

/// `tx-expiry-keeps-session` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `tx-expiry-keeps-session` is held: in no byte when its domain is one value.
type TxExpiryKeepsSessionBound = Bound<TxExpiryKeepsSession, { TxExpiryKeepsSession::HELD }>;

impl PolicyValue for TxExpiryKeepsSession {
    const POLICY: &'static str = "tx-expiry-keeps-session";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION_ALLOWS_OFF"),
            option_env!("WZ_POLICY_TX_EXPIRY_KEEPS_SESSION_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for TxExpiryKeepsSession {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_tx_expiry_keeps_session(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.tx_expiry_keeps_session.get()
    }
}

/// `declaration-sync-pacing` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `declaration-sync-pacing` is held: in no byte when its domain is one value.
type DeclarationSyncPacingBound = Bound<DeclarationSyncPacing, { DeclarationSyncPacing::HELD }>;

impl PolicyValue for DeclarationSyncPacing {
    const POLICY: &'static str = "declaration-sync-pacing";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_DECLARATION_SYNC_PACING_ALLOWS_OFF"),
            option_env!("WZ_POLICY_DECLARATION_SYNC_PACING_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for DeclarationSyncPacing {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_declaration_sync_pacing(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.declaration_sync_pacing.get()
    }
}

/// `datagram-fragment-pacing` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `datagram-fragment-pacing` is held: in no byte when its domain is one value.
type DatagramFragmentPacingBound = Bound<DatagramFragmentPacing, { DatagramFragmentPacing::HELD }>;

impl PolicyValue for DatagramFragmentPacing {
    const POLICY: &'static str = "datagram-fragment-pacing";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING_ALLOWS_OFF"),
            option_env!("WZ_POLICY_DATAGRAM_FRAGMENT_PACING_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for DatagramFragmentPacing {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_datagram_fragment_pacing(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.datagram_fragment_pacing.get()
    }
}

/// `multicast-link-requires-iface` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `multicast-link-requires-iface` is held: in no byte when its domain is one value.
type MulticastLinkRequiresIfaceBound =
    Bound<MulticastLinkRequiresIface, { MulticastLinkRequiresIface::HELD }>;

impl PolicyValue for MulticastLinkRequiresIface {
    const POLICY: &'static str = "multicast-link-requires-iface";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE_ALLOWS_OFF"),
            option_env!("WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for MulticastLinkRequiresIface {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_multicast_link_requires_iface(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.multicast_link_requires_iface.get()
    }
}

/// How `reliable-gap-reconnect` is held: in no byte when its domain is one value.
type ReliableGapReconnectBound = Bound<ReliableGapReconnect, { ReliableGapReconnect::HELD }>;

impl PolicyValue for ReliableGapReconnect {
    const POLICY: &'static str = "reliable-gap-reconnect";
    const ALL: &'static [Self] = &[Self::Off, Self::UntilDeclarationsSynced, Self::Always];
    const IDS: &'static [&'static str] = &["off", "until-declarations-synced", "always"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_OFF"),
            option_env!("WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_UNTIL_DECLARATIONS_SYNCED"),
            option_env!("WZ_POLICY_RELIABLE_GAP_RECONNECT_ALLOWS_ALWAYS"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for ReliableGapReconnect {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_reliable_gap_reconnect(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.reliable_gap_reconnect.get()
    }
}

/// `entity-link-restriction` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `entity-link-restriction` is held: in no byte when its domain is one value.
type EntityLinkRestrictionBound = Bound<EntityLinkRestriction, { EntityLinkRestriction::HELD }>;

impl PolicyValue for EntityLinkRestriction {
    const POLICY: &'static str = "entity-link-restriction";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION_ALLOWS_OFF"),
            option_env!("WZ_POLICY_ENTITY_LINK_RESTRICTION_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for EntityLinkRestriction {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_entity_link_restriction(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.entity_link_restriction.get()
    }
}

/// `targeted-query` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `targeted-query` is held: in no byte when its domain is one value.
type TargetedQueryBound = Bound<TargetedQuery, { TargetedQuery::HELD }>;

impl PolicyValue for TargetedQuery {
    const POLICY: &'static str = "targeted-query";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_TARGETED_QUERY_ALLOWS_OFF"),
            option_env!("WZ_POLICY_TARGETED_QUERY_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for TargetedQuery {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_targeted_query(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.targeted_query.get()
    }
}

/// `publisher-admission-retry` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `publisher-admission-retry` is held: in no byte when its domain is one value.
type PublisherAdmissionRetryBound =
    Bound<PublisherAdmissionRetry, { PublisherAdmissionRetry::HELD }>;

impl PolicyValue for PublisherAdmissionRetry {
    const POLICY: &'static str = "publisher-admission-retry";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_PUBLISHER_ADMISSION_RETRY_ALLOWS_OFF"),
            option_env!("WZ_POLICY_PUBLISHER_ADMISSION_RETRY_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for PublisherAdmissionRetry {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_publisher_admission_retry(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.publisher_admission_retry.get()
    }
}

/// `multi-route-atomic-tx` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `multi-route-atomic-tx` is held: in no byte when its domain is one value.
type MultiRouteAtomicTxBound = Bound<MultiRouteAtomicTx, { MultiRouteAtomicTx::HELD }>;

impl PolicyValue for MultiRouteAtomicTx {
    const POLICY: &'static str = "multi-route-atomic-tx";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX_ALLOWS_OFF"),
            option_env!("WZ_POLICY_MULTI_ROUTE_ATOMIC_TX_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for MultiRouteAtomicTx {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_multi_route_atomic_tx(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.multi_route_atomic_tx.get()
    }
}

/// `entity-timestamp-opt-in` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `entity-timestamp-opt-in` is held: in no byte when its domain is one value.
type EntityTimestampOptInBound = Bound<EntityTimestampOptIn, { EntityTimestampOptIn::HELD }>;

impl PolicyValue for EntityTimestampOptIn {
    const POLICY: &'static str = "entity-timestamp-opt-in";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN_ALLOWS_OFF"),
            option_env!("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for EntityTimestampOptIn {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_entity_timestamp_opt_in(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.entity_timestamp_opt_in.get()
    }
}

/// `reply-auto-timestamp` as a value; [`SessionPolicy`] reads it as a `bool`.
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

    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.
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
    /// The build default; a machine reads the value of the snapshot it is handed instead.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How `reply-auto-timestamp` is held: in no byte when its domain is one value.
type ReplyAutoTimestampBound = Bound<ReplyAutoTimestamp, { ReplyAutoTimestamp::HELD }>;

impl PolicyValue for ReplyAutoTimestamp {
    const POLICY: &'static str = "reply-auto-timestamp";
    const ALL: &'static [Self] = &[Self::Off, Self::On];
    const IDS: &'static [&'static str] = &["off", "on"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP_ALLOWS_OFF"),
            option_env!("WZ_POLICY_REPLY_AUTO_TIMESTAMP_ALLOWS_ON"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for ReplyAutoTimestamp {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_reply_auto_timestamp(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.reply_auto_timestamp.get()
    }
}

/// How `subscriber-overload` is held: in no byte when its domain is one value.
type SubscriberOverloadBound = Bound<SubscriberOverload, { SubscriberOverload::HELD }>;

impl PolicyValue for SubscriberOverload {
    const POLICY: &'static str = "subscriber-overload";
    const ALL: &'static [Self] = &[Self::Block, Self::Reject, Self::KeepLatest];
    const IDS: &'static [&'static str] = &["block", "reject", "keep-latest"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_BLOCK"),
            option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_REJECT"),
            option_env!("WZ_POLICY_SUBSCRIBER_OVERLOAD_ALLOWS_KEEP_LATEST"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for SubscriberOverload {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_subscriber_overload(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.subscriber_overload.get()
    }
}

/// How `key-set` is held: in no byte when its domain is one value.
type KeySetBound = Bound<KeySet, { KeySet::HELD }>;

impl PolicyValue for KeySet {
    const POLICY: &'static str = "key-set";
    const ALL: &'static [Self] = &[Self::Open, Self::Closed];
    const IDS: &'static [&'static str] = &["open", "closed"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_KEY_SET_ALLOWS_OPEN"),
            option_env!("WZ_POLICY_KEY_SET_ALLOWS_CLOSED"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for KeySet {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_key_set(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.key_set.get()
    }
}

/// How `sn-resolution` is held: in no byte when its domain is one value.
type SnResolutionBound = Bound<SnResolution, { SnResolution::HELD }>;

impl PolicyValue for SnResolution {
    const POLICY: &'static str = "sn-resolution";
    const ALL: &'static [Self] = &[Self::Bits32, Self::Bits8, Self::Bits16, Self::Bits64];
    const IDS: &'static [&'static str] = &["bits-32", "bits-8", "bits-16", "bits-64"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_32"),
            option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_8"),
            option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_16"),
            option_env!("WZ_POLICY_SN_RESOLUTION_ALLOWS_BITS_64"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for SnResolution {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_sn_resolution(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.sn_resolution.get()
    }
}

/// How `supervision-after-expiry` is held: in no byte when its domain is one value.
type SupervisionAfterExpiryBound = Bound<SupervisionAfterExpiry, { SupervisionAfterExpiry::HELD }>;

impl PolicyValue for SupervisionAfterExpiry {
    const POLICY: &'static str = "supervision-after-expiry";
    const ALL: &'static [Self] = &[Self::Latch, Self::Rearm];
    const IDS: &'static [&'static str] = &["latch", "rearm"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_SUPERVISION_AFTER_EXPIRY_ALLOWS_LATCH"),
            option_env!("WZ_POLICY_SUPERVISION_AFTER_EXPIRY_ALLOWS_REARM"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for SupervisionAfterExpiry {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_supervision_after_expiry(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.supervision_after_expiry.get()
    }
}

/// How `event-ring-full` is held: in no byte when its domain is one value.
type EventRingFullBound = Bound<EventRingFull, { EventRingFull::HELD }>;

impl PolicyValue for EventRingFull {
    const POLICY: &'static str = "event-ring-full";
    const ALL: &'static [Self] = &[Self::OverwriteOldest, Self::DropNewest];
    const IDS: &'static [&'static str] = &["overwrite-oldest", "drop-newest"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_EVENT_RING_FULL_ALLOWS_OVERWRITE_OLDEST"),
            option_env!("WZ_POLICY_EVENT_RING_FULL_ALLOWS_DROP_NEWEST"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for EventRingFull {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_event_ring_full(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.event_ring_full.get()
    }
}

/// How `clock-quality-stamping` is held: in no byte when its domain is one value.
type ClockQualityStampingBound = Bound<ClockQualityStamping, { ClockQualityStamping::HELD }>;

impl PolicyValue for ClockQualityStamping {
    const POLICY: &'static str = "clock-quality-stamping";
    const ALL: &'static [Self] = &[Self::Always, Self::TrustedOnly];
    const IDS: &'static [&'static str] = &["always", "trusted-only"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_CLOCK_QUALITY_STAMPING_ALLOWS_ALWAYS"),
            option_env!("WZ_POLICY_CLOCK_QUALITY_STAMPING_ALLOWS_TRUSTED_ONLY"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for ClockQualityStamping {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_clock_quality_stamping(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.clock_quality_stamping.get()
    }
}

/// How `routing-face-drive` is held: in no byte when its domain is one value.
type RoutingFaceDriveBound = Bound<RoutingFaceDrive, { RoutingFaceDrive::HELD }>;

impl PolicyValue for RoutingFaceDrive {
    const POLICY: &'static str = "routing-face-drive";
    const ALL: &'static [Self] = &[Self::TaskPerFace, Self::OneTask];
    const IDS: &'static [&'static str] = &["task-per-face", "one-task"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_ROUTING_FACE_DRIVE_ALLOWS_TASK_PER_FACE"),
            option_env!("WZ_POLICY_ROUTING_FACE_DRIVE_ALLOWS_ONE_TASK"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for RoutingFaceDrive {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_routing_face_drive(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.routing_face_drive.get()
    }
}

/// How `routing-table-sharing` is held: in no byte when its domain is one value.
type RoutingTableSharingBound = Bound<RoutingTableSharing, { RoutingTableSharing::HELD }>;

impl PolicyValue for RoutingTableSharing {
    const POLICY: &'static str = "routing-table-sharing";
    const ALL: &'static [Self] = &[Self::Rwlock, Self::Snapshot];
    const IDS: &'static [&'static str] = &["rwlock", "snapshot"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_ROUTING_TABLE_SHARING_ALLOWS_RWLOCK"),
            option_env!("WZ_POLICY_ROUTING_TABLE_SHARING_ALLOWS_SNAPSHOT"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for RoutingTableSharing {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_routing_table_sharing(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.routing_table_sharing.get()
    }
}

/// How `reassembly-pool-overflow` is held: in no byte when its domain is one value.
type ReassemblyPoolOverflowBound = Bound<ReassemblyPoolOverflow, { ReassemblyPoolOverflow::HELD }>;

impl PolicyValue for ReassemblyPoolOverflow {
    const POLICY: &'static str = "reassembly-pool-overflow";
    const ALL: &'static [Self] = &[Self::Reject, Self::DiagnosticEvent, Self::OldestWins];
    const IDS: &'static [&'static str] = &["reject", "diagnostic-event", "oldest-wins"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_REJECT"),
            option_env!("WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_DIAGNOSTIC_EVENT"),
            option_env!("WZ_POLICY_REASSEMBLY_POOL_OVERFLOW_ALLOWS_OLDEST_WINS"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for ReassemblyPoolOverflow {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_reassembly_pool_overflow(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.reassembly_pool_overflow.get()
    }
}

/// How `link-tie-order` is held: in no byte when its domain is one value.
type LinkTieOrderBound = Bound<LinkTieOrder, { LinkTieOrder::HELD }>;

impl PolicyValue for LinkTieOrder {
    const POLICY: &'static str = "link-tie-order";
    const ALL: &'static [Self] = &[Self::ZidNumber, Self::ZidBytes];
    const IDS: &'static [&'static str] = &["zid-number", "zid-bytes"];
    const DOMAIN: Domain<Self> = Domain::from_stated(
        &[
            option_env!("WZ_POLICY_LINK_TIE_ORDER_ALLOWS_ZID_NUMBER"),
            option_env!("WZ_POLICY_LINK_TIE_ORDER_ALLOWS_ZID_BYTES"),
        ],
        Self::DEFAULT as usize,
        DEFAULTS_ONLY,
    );
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

impl PolicyField for LinkTieOrder {
    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {
        policy.select_link_tie_order(value)
    }

    fn held_in(policy: &SessionPolicy) -> Self {
        policy.link_tie_order.get()
    }
}

/// How many policies the declaration states: the length of [`POLICIES`] and of every table kept
/// per policy.
pub const POLICY_COUNT: usize = 23;

/// Every policy as a reader that names it by its id sees it, in the order of the fields of
/// [`SessionPolicy`].
pub static POLICIES: [PolicyEntry; POLICY_COUNT] = [
    PolicyEntry::of::<MulticastLoopback>(),
    PolicyEntry::of::<TxNoProgressDeadline>(),
    PolicyEntry::of::<TxExpiryKeepsSession>(),
    PolicyEntry::of::<DeclarationSyncPacing>(),
    PolicyEntry::of::<DatagramFragmentPacing>(),
    PolicyEntry::of::<MulticastLinkRequiresIface>(),
    PolicyEntry::of::<ReliableGapReconnect>(),
    PolicyEntry::of::<EntityLinkRestriction>(),
    PolicyEntry::of::<TargetedQuery>(),
    PolicyEntry::of::<PublisherAdmissionRetry>(),
    PolicyEntry::of::<MultiRouteAtomicTx>(),
    PolicyEntry::of::<EntityTimestampOptIn>(),
    PolicyEntry::of::<ReplyAutoTimestamp>(),
    PolicyEntry::of::<SubscriberOverload>(),
    PolicyEntry::of::<KeySet>(),
    PolicyEntry::of::<SnResolution>(),
    PolicyEntry::of::<SupervisionAfterExpiry>(),
    PolicyEntry::of::<EventRingFull>(),
    PolicyEntry::of::<ClockQualityStamping>(),
    PolicyEntry::of::<RoutingFaceDrive>(),
    PolicyEntry::of::<RoutingTableSharing>(),
    PolicyEntry::of::<ReassemblyPoolOverflow>(),
    PolicyEntry::of::<LinkTieOrder>(),
];

/// The profile `upstream`: Every policy at upstream's behaviour, stated explicitly, so a
/// document that names it behaves as the original whatever the build states as its
/// defaults. Where upstream has no such behaviour, the value is the one wz had before the
/// policy existed.
const PROFILE_UPSTREAM: Profile = Profile {
    id: "upstream",
    statements: &[
        Statement::new("multicast-loopback", "os-default"),
        Statement::new("tx-no-progress-deadline", "off"),
        Statement::new("tx-expiry-keeps-session", "off"),
        Statement::new("declaration-sync-pacing", "off"),
        Statement::new("datagram-fragment-pacing", "off"),
        Statement::new("multicast-link-requires-iface", "off"),
        Statement::new("reliable-gap-reconnect", "off"),
        Statement::new("entity-link-restriction", "off"),
        Statement::new("targeted-query", "off"),
        Statement::new("publisher-admission-retry", "off"),
        Statement::new("multi-route-atomic-tx", "off"),
        Statement::new("entity-timestamp-opt-in", "off"),
        Statement::new("reply-auto-timestamp", "off"),
        Statement::new("subscriber-overload", "block"),
        Statement::new("key-set", "open"),
        Statement::new("sn-resolution", "bits-32"),
        Statement::new("supervision-after-expiry", "latch"),
        Statement::new("event-ring-full", "overwrite-oldest"),
        Statement::new("clock-quality-stamping", "always"),
        Statement::new("routing-face-drive", "task-per-face"),
        Statement::new("routing-table-sharing", "rwlock"),
        Statement::new("reassembly-pool-overflow", "reject"),
        Statement::new("link-tie-order", "zid-number"),
    ],
};

/// Every profile the declaration states, which a document names by its id (`wz/profile`).
pub static PROFILES: [Profile; 1] = [PROFILE_UPSTREAM];
