// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2830 (§5.23 `adminspace-write`) — the MCU node holds a session with every
//! endpoint its connection control names, and re-dials the ones that drop.
//!
//! The control is an [`EndpointSource`]: `ConnectControl` (`adminspace-write`) is what a host
//! writes, `StaticEndpoints` is what an image was built with; this module is
//! what makes either mean something. [`crate::connect_manager::ConnectManager`]
//! is ticked by the firmware's main loop. On every tick it
//!
//! 1. notices a new generation on the control and reconciles: an endpoint no
//!    longer named is hung up, a new one is dialled at once;
//! 2. notices a session that has come up or has ended, and tells its endpoint's
//!    machine; and
//! 3. dials whatever is due.
//!
//! Each endpoint is a peer of the connection machine of decision D5 of
//! `docs/session-lifecycle-intent.md`, and the manager is that machine's host on this
//! profile, as the face loop of an AP node is on its own. What both do for a
//! machine (which face a dial opened, which timer is still its peer's, when to
//! start a schedule over) is written once, in `wz_session_core::peer_planner`;
//! what is this profile's is here: the rows in the order the list named them, the
//! session each holds, the moment its next dial is due, and the endpoints the build
//! cannot dial, which the machine knows as a peer with no candidate (`NoLocator`).
//!
//! The waits are upstream's `connect.retry` schedule, from the one
//! transcription the AP uses too (`wz_session_core::retry_period`): 1 s, 2 s,
//! 4 s, then 4 s, growing while a dial keeps failing. A session that had been
//! ESTABLISHED and then dropped starts the schedule again from its first wait,
//! because upstream builds a fresh period per outage.
//!
//! The dialling itself is behind [`crate::connect_manager::Dialer`], so the
//! bookkeeping above is decided (and tested) without a network. The dialer that
//! opens a session over a network stack is `crate::dial::UdpDialer`.
//!
//! An endpoint this build cannot dial at all (a scheme it has no link for, an
//! address it cannot parse) is REFUSED rather than retried: retrying cannot
//! change the answer, and a hot loop of doomed dials is the one thing the
//! schedule exists to prevent. It is tried again only when the list is
//! written again, since that is the only event that can change it.

use heapless::Vec as FixedVec;
use wz_session_core::bounded::BoundedVec;
use wz_session_core::caps::{MAX_LOCATOR_LEN, MAX_PEER_NODES, MAX_STATIC_CONNECT};
use wz_session_core::connect_endpoints::{group_len, ConnectEndpoints, ConnectEntry, EndpointText};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::lifecycle_wire::OpenOutcome;
use wz_session_core::locator_directory::{
    DirectoryRefusal, DirectoryZid, Lifetime, LocatorDirectory, LocatorSource,
};
use wz_session_core::peer_connection::PeerConnectionState;
use wz_session_core::peer_planner::{DialEnd, PeerAction, PeerPlanner, PeerPorts};
use wz_session_core::retry_period::{RetryPeriod, RetryPolicy};

/// Where a [`ConnectManager`] reads the endpoints it should hold sessions with.
///
/// The manager used to read `admin_host::ConnectControl` only, the list a host writes at
/// runtime, which made every node that dials an admin node. A firmware that dials a router it was
/// built to know has no list to write: it names the endpoints once. Both are sources.
pub trait EndpointSource {
    /// The generation of the list, which moves whenever the list does. The manager asks this
    /// every tick and takes the list only when it has moved, so an idle node copies nothing.
    fn generation(&self) -> u32;

    /// The list and the generation it was read at.
    fn endpoints(&self) -> (u32, ConnectEndpoints);
}

/// Endpoints fixed when the image is built: `udp/192.168.100.1:7447`, once, for the life of the
/// node. A `static` of this type is checked at compile time (an endpoint over `MAX_LOCATOR_LEN`
/// bytes, or more than `MAX_STATIC_CONNECT` of them, does not build), so the list the manager
/// reads can never be the truncation of the one the image was written with.
pub struct StaticEndpoints {
    list: &'static [&'static str],
}

impl StaticEndpoints {
    /// The endpoints the node holds sessions with, in the order it dials them.
    pub const fn new(list: &'static [&'static str]) -> Self {
        assert!(
            list.len() <= MAX_STATIC_CONNECT,
            "more endpoints than the node holds rows for"
        );
        let mut i = 0;
        while i < list.len() {
            assert!(
                list[i].len() <= MAX_LOCATOR_LEN,
                "an endpoint longer than a locator row"
            );
            i += 1;
        }
        Self { list }
    }
}

impl EndpointSource for StaticEndpoints {
    fn generation(&self) -> u32 {
        0
    }

    fn endpoints(&self) -> (u32, ConnectEndpoints) {
        let mut out = ConnectEndpoints::new();
        for text in self.list {
            let mut endpoint = EndpointText::new();
            // `new` checked the length, so neither push can refuse.
            let _ = endpoint.push_str(text);
            let _ = out.push(ConnectEntry::single(endpoint));
        }
        (0, out)
    }
}

/// Why a dial could not even be attempted. Permanent for this endpoint text
/// in this build, so it is not retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefused {
    /// The endpoint's scheme names a link this build does not carry.
    Unsupported,
    /// The address could not be read as one this link can reach.
    BadAddress,
    /// R2841 — one locator of a `{ strategy, locators }` group of several:
    /// one session over several links, which this node's session cannot
    /// hold. Decided by the manager from the list, before any dial.
    MultiLinkGroup,
}

impl DialRefused {
    /// R2846 — the reason in the word the node reports it with, at
    /// `status/connect`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DialRefused::Unsupported => "unsupported",
            DialRefused::BadAddress => "bad_address",
            DialRefused::MultiLinkGroup => "multi_link_group",
        }
    }
}

/// Why a dial did not start a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailed {
    /// This endpoint can never be dialled by this build; not retried.
    Refused(DialRefused),
    /// The node could not afford a session right now (no socket, no
    /// buffer). Counted as a failed attempt of the same outage, so the
    /// endpoint waits its next period, as a dial that never answered would.
    Exhausted,
    /// The other end did not take the link (a TCP connection refused or
    /// unreachable). A failed attempt of the same outage, as `Exhausted` is:
    /// the endpoint waits its next period.
    Unreachable,
}

/// How a session that was dialled has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// It never reached an established session.
    BeforeEstablished,
    /// It was established and then closed or lost.
    AfterEstablished,
}

/// Starts, watches and ends the sessions a [`ConnectManager`] asks for.
pub trait Dialer {
    /// Whatever the dialer needs to keep per live session.
    type Session;

    /// Whether this build can dial `endpoint` at all, asked before any dial is made. An
    /// endpoint it cannot (a scheme it has no link for, an address it cannot read) is a peer
    /// with no candidate: refused, and not retried. The default can dial anything, and a dial
    /// that finds otherwise says [`DialFailed::Refused`].
    ///
    /// Asked of the type and not of a value: what a build can dial is a fact of the build, and
    /// the node's opener answers it without holding the dialer, which the manager owns.
    fn classify(_endpoint: &str) -> Result<(), DialRefused> {
        Ok(())
    }

    /// Whether [`Self::dial_for`] makes a dial the session's handshake holds to the node it was
    /// made for (decision D4): the dial is refused at the InitAck when another node answers. A
    /// dialer that cannot say so is not asked to dial a node, because a session to whichever node
    /// answers a stale hint is not a session to the zid.
    const VERIFIES_NODES: bool = false;

    /// Start a session towards `endpoint`.
    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed>;

    /// Start a session towards `endpoint` FOR the node `node`: the locator is a hint for reaching
    /// the zid, and the session closes at the InitAck if another node answers. The default
    /// refuses, so a dialer opens no unverified session for a zid by leaving this out
    /// ([`Self::VERIFIES_NODES`] says it does).
    fn dial_for(
        &mut self,
        _endpoint: &str,
        _node: &DirectoryZid,
    ) -> Result<Self::Session, DialFailed> {
        Err(DialFailed::Refused(DialRefused::Unsupported))
    }

    /// Whether the session is established now. The manager tells the endpoint's machine
    /// the first time it is, so the machine reads `Established` while the session is up. The
    /// default never says so, and the manager learns it from [`Self::ended`] instead, as it
    /// did before the machine: an end after establishing is reported as established and then
    /// lost.
    fn established(&mut self, _session: &mut Self::Session) -> bool {
        false
    }

    /// The zid the session's remote named, once it has, in the sixteen-byte form of a derived
    /// zid. Remembered by the machine, so that a `close` can name the node an endpoint reached.
    fn remote(&self, _session: &Self::Session) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        None
    }

    /// `Some` once the session has ended, saying how.
    fn ended(&mut self, session: &mut Self::Session) -> Option<Ended>;

    /// End a session the list no longer names.
    fn hang_up(&mut self, session: Self::Session);
}

/// Where one endpoint stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// A session is live (or being opened).
    Live,
    /// Waiting to (re-)dial at this time.
    Waiting {
        /// When the next dial is due, in the manager's clock.
        at_ms: u64,
    },
    /// This build cannot dial it.
    Refused(DialRefused),
}

/// Where one node held by its zid stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// A session is live (or being opened).
    Live,
    /// Waiting to (re-)dial at this time.
    Waiting {
        /// When the next dial is due, in the manager's clock.
        at_ms: u64,
    },
    /// The directory has no live hint of it that this build can dial: it is dialled again when a
    /// source confirms one.
    NoHint,
    /// Another node answered at the hint it was dialled at (decision D4): the session was hung
    /// up, and the node is dialled no more until it is opened again.
    Mismatched,
}

/// Where one peer stands, before it is said as an endpoint's or a node's.
enum Standing {
    Live,
    Waiting { at_ms: u64 },
    NoLocator,
    Mismatched,
}

/// Why a node could not be held by its zid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRefusal {
    /// The dialer does not hold a session to the node it was made for, so no dial of it could
    /// be told from one to another node ([`Dialer::VERIFIES_NODES`]).
    Unverifiable,
    /// The node holds as many nodes as it was built for ([`MAX_PEER_NODES`]), which is none
    /// unless the image states more.
    NoRoom,
    /// The directory holds no live hint for the node, so there is nothing to dial. The node is
    /// not taken into a table that a flood of opens for zids nobody advertised would fill.
    NoLocator,
    /// The directory holds hints for the node, none of which this build can dial.
    NoDialableLocator,
}

/// The request to hold a node by its zid (a lifecycle `open`, decision D6), made where the
/// manager is not: a query a node answers is served beside its loop and not inside it.
///
/// It answers at once with everything the node knows without the loop: whether this dialer can
/// hold a session to the node it dials for, whether the node has room for one more, whether the
/// directory has a live hint for it and whether this build can dial one. A request that passes is
/// kept for the manager's next tick, which holds the node. Accepted and not completed, as the
/// port's contract says: how the dial ends is read in [`ConnectManager::node_states`].
///
/// It holds no dialer, which the manager owns, and is not typed by one: what the dialer can do
/// (whether it holds a session to the node it dials for, which locators it can dial) is written
/// into the store by the manager when it is made, so an image can declare its opener beside its
/// store, in a `static`, before there is a manager. Until there is one the opener says
/// `Unverifiable`, which is what a node that dials nothing is. It is a reference to the store, so
/// it is `Copy`.
#[derive(Clone, Copy)]
pub struct NodeOpener {
    store: &'static PeerStore,
}

impl NodeOpener {
    /// The opener of the nodes held in `store`. `const`, so a `static` can be one.
    pub const fn in_store(store: &'static PeerStore) -> Self {
        Self { store }
    }

    /// Ask the manager to hold the node `zid`. A node already held, or already asked for, is
    /// unchanged, and says the same.
    pub fn open(&self, zid: &DirectoryZid) -> Result<(), NodeRefusal> {
        self.store.with(|t| {
            if !t.verifies_nodes {
                return Err(NodeRefusal::Unverifiable);
            }
            if t.held.contains(zid) || t.requests.contains(zid) {
                return Ok(());
            }
            // Written so that it holds for any value of the limit, none included.
            if MAX_PEER_NODES.saturating_sub(t.held.len() + t.requests.len()) == 0 {
                return Err(NodeRefusal::NoRoom);
            }
            if t.directory.candidates(zid, t.now_ms).next().is_none() {
                return Err(NodeRefusal::NoLocator);
            }
            let classify = t.classify.unwrap_or(|_| Ok(()));
            if first_dialable(&t.directory, zid, t.now_ms, classify).is_none() {
                return Err(NodeRefusal::NoDialableLocator);
            }
            t.requests.push(*zid).map_err(|_| NodeRefusal::NoRoom)
        })
    }
}

/// The word a lifecycle open is answered with for a refusal: the same list the heap profile's
/// opener answers in (`wz_session_core::lifecycle_wire`). A node that knows no hint for the peer
/// is one that knows no locator for it.
impl From<NodeRefusal> for OpenOutcome {
    fn from(refusal: NodeRefusal) -> Self {
        match refusal {
            NodeRefusal::Unverifiable => Self::Unverifiable,
            NodeRefusal::NoRoom => Self::NoRoom,
            NodeRefusal::NoLocator => Self::PeerUnknown,
            NodeRefusal::NoDialableLocator => Self::NoDialableLocator,
        }
    }
}

/// A [`NodeOpener`] under a permit: what a node binds to answer `session/open/<peer>`, as the
/// node's write permit says (which gates the config write too).
#[cfg(all(feature = "adminspace-fixed", feature = "session-slot"))]
pub struct ControlledOpener {
    opener: NodeOpener,
    permit: &'static (dyn crate::admin_status::ConnectStatusSource + Sync),
}

#[cfg(all(feature = "adminspace-fixed", feature = "session-slot"))]
impl ControlledOpener {
    /// The opener of the nodes held in `store`, permitted as `permit` says. `const`, so the
    /// image declares it in a `static` beside the store and the control it is made of.
    pub const fn new(
        store: &'static PeerStore,
        permit: &'static (dyn crate::admin_status::ConnectStatusSource + Sync),
    ) -> Self {
        Self {
            opener: NodeOpener::in_store(store),
            permit,
        }
    }
}

#[cfg(all(feature = "adminspace-fixed", feature = "session-slot"))]
impl crate::admin_fixed::NodeOpening for ControlledOpener {
    fn permitted(&self) -> bool {
        self.permit.write_permit()
    }

    fn open(&self, zid: &DirectoryZid) -> OpenOutcome {
        match self.opener.open(zid) {
            Ok(()) => OpenOutcome::Accepted,
            Err(refusal) => refusal.into(),
        }
    }
}

/// What names a peer to the machines: a configured endpoint by the slot of its row, or a node by
/// its zid.
///
/// A name is an identity and not a copy of what it names, so it is small: seventeen bytes, where
/// the text of an endpoint is sixty-four and more. The planner holds a name in each of its tables,
/// in every action it asks for and in the sort of a `withdraw`, and the manager's frames hold a
/// few of those actions at a time, on the stack of the thread that ticks it. The endpoint's text
/// stays in its row, and a dial reads it there when it is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// The row of a configured endpoint, by its slot: the lowest not taken by another endpoint,
    /// so a slot freed by a rewrite of the list is the next endpoint's. The planner forgets a
    /// peer before its slot is reused (`reconcile`).
    Endpoint(u8),
    Node(DirectoryZid),
}

/// How many peers the machines hold: the endpoints the control names and the nodes asked for.
const PEERS: usize = MAX_STATIC_CONNECT + MAX_PEER_NODES;

/// How many dials can be in flight for the peers, with the ones a peer stopped wanting while
/// they ran: each of the peers dials once at a time.
const DIALS: usize = 2 * PEERS;

/// How many hints the directory holds: two for each node, since a node advertises a few
/// locators and the soft ones displace each other when it is full.
const DIRECTORY_ROWS: usize = 2 * MAX_PEER_NODES;

type Planner = PeerPlanner<Key, u64, PEERS, DIALS>;

/// A manager's tables: the machines of its peers and the locators it knows for its nodes.
struct Tables {
    planner: Planner,
    directory: LocatorDirectory<DIRECTORY_ROWS>,
    /// The moment the manager last ticked, which an opener reads the directory's live hints at:
    /// it is asked outside the loop and has no clock of its own.
    now_ms: u64,
    /// The nodes the manager holds a row for, mirrored here so that an opener can tell a node
    /// that is held (an open of it changes nothing) from one that needs room.
    held: FixedVec<DirectoryZid, MAX_PEER_NODES>,
    /// The nodes an opener accepted and the manager has not taken yet, in the order they were
    /// asked for. The manager takes them at its next tick, in the loop that owns its rows.
    requests: FixedVec<DirectoryZid, MAX_PEER_NODES>,
    /// Whether the manager's dialer holds a session to the node it dials for
    /// ([`Dialer::VERIFIES_NODES`]), written when the manager is made. `false` before: a store
    /// nobody dials from holds no node.
    verifies_nodes: bool,
    /// What the manager's dialer can dial ([`Dialer::classify`]), written when the manager is
    /// made, so an opener answers it without the dialer's type. `None` before: nothing is
    /// dialled from the store, so anything is dialable. An `Option` and not a function pointer
    /// from the start because a store whose initial value is all zero bytes lives in `.bss`, and
    /// one non-zero byte (a function's address is one) moves the whole of the image's tables
    /// into `.data`, and a copy of them into flash.
    classify: Option<Classify>,
}

/// What a build can dial, as a dialer answers it ([`Dialer::classify`]).
type Classify = fn(&str) -> Result<(), DialRefused>;

/// The machines of a manager's peers and the locators of its nodes, in a table of their own.
///
/// One connection machine per peer is some 930 bytes on the target (`size_of` of its engine, read
/// off a `thumbv7m-none-eabi` build: two event queues, the delayed-send ring and the rest of the
/// runtime's engine, none of which this machine uses), so the table of `MAX_STATIC_CONNECT`
/// of them (and `MAX_PEER_NODES` more, none by default), with the planner's tables beside it, is
/// some 10 KB. That does not belong in the
/// manager, which is a local of the node's loop and sits on the stack of the thread that runs it.
/// It is a type of its own so that it can be declared where the node's other big tables are, in a
/// `static` whose initial value is all zero bytes (`slot_node::NodeStorage`), and so that a
/// manager holds only a reference to it.
///
/// A critical section guards it, as the crate's other shared state is (`ConnectControl`): the
/// node is driven by one cooperative loop, which is the only thing that reaches it, and the guard
/// makes that a property the type has and not a rule a caller keeps.
pub struct PeerStore {
    tables: critical_section::Mutex<core::cell::RefCell<Tables>>,
}

impl PeerStore {
    /// An empty store: no peer held. `const`, so a `static` can be one.
    pub const fn new() -> Self {
        Self {
            tables: critical_section::Mutex::new(core::cell::RefCell::new(Tables {
                planner: Planner::new(),
                directory: LocatorDirectory::new(),
                now_ms: 0,
                held: FixedVec::new(),
                requests: FixedVec::new(),
                verifies_nodes: false,
                classify: None,
            })),
        }
    }

    /// Run `f` on the tables.
    fn with<R>(&self, f: impl FnOnce(&mut Tables) -> R) -> R {
        critical_section::with(|cs| f(&mut self.tables.borrow_ref_mut(cs)))
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a manager's [`PeerStore`] is: in a `static` the image declared, or, on a profile with a
/// heap, in a box the manager owns.
enum StoreRef {
    Static(&'static PeerStore),
    #[cfg(not(feature = "session-slot"))]
    Boxed(alloc::boxed::Box<PeerStore>),
}

impl StoreRef {
    fn get(&self) -> &PeerStore {
        match self {
            Self::Static(store) => store,
            #[cfg(not(feature = "session-slot"))]
            Self::Boxed(store) => store,
        }
    }
}

/// What one call of the planner asked, at most: a session closed, a wait armed and a dial, of
/// one peer. Room for one more of each, so that a count is never the reason an action is
/// lost.
type Actions = FixedVec<PeerAction<Key, u64, ()>, 6>;

/// A session a peer holds, with the face the planner knows it as.
struct Held<S> {
    face: u64,
    session: S,
    /// Whether the peer's machine has been told the session is up.
    up: bool,
}

/// The moment a peer's next dial is due, and which arming of its timer that is.
#[derive(Clone, Copy)]
struct Due {
    generation: u64,
    at_ms: u64,
}

/// One peer: an endpoint of the list, in the order the list named it, or a node asked for by its
/// zid, after them.
struct Row<S> {
    key: Key,
    /// The text of the endpoint the row is of: where the endpoint is dialled, and what the list
    /// names it by. `None` for a node.
    endpoint: Option<EndpointText>,
    /// One locator of a group of several: one session over several links, which this node's
    /// session cannot hold, so it has no candidate. Only an endpoint can be one.
    multi_link: bool,
    held: Option<Held<S>>,
    due: Option<Due>,
}

impl<S> Row<S> {
    /// A row of `key`, with no session and no timer.
    fn new(key: Key, endpoint: Option<EndpointText>, multi_link: bool) -> Self {
        Self {
            key,
            endpoint,
            multi_link,
            held: None,
            due: None,
        }
    }

    /// The endpoint the row is of, `None` for a node.
    fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_ref().map(|text| text.as_str())
    }
}

/// The peers a manager holds, one row each. The list a host writes is itself
/// held in `MAX_STATIC_CONNECT` rows (`ConnectEndpoints`), so no list can name more
/// endpoints than that, and a node is taken only while fewer than `MAX_PEER_NODES` are held
/// (`open_node`): the table is bounded by the numbers that bound what feeds it, and a manager
/// holds no row it was not told of. The backing
/// is the profile's (`BoundedVec`): the growable one where there is a heap, a fixed
/// table of that many rows under `bounded-heapless`, where a row past the bound could
/// only be a defect and is hung up and refused rather than grown (`reconcile`).
type Rows<S> = BoundedVec<Row<S>, PEERS>;

/// The retry schedule of each peer that is in an outage.
type Periods = BoundedVec<(Key, RetryPeriod), PEERS>;

/// What this profile answers for the planner.
struct Ports<'a, D: Dialer> {
    /// What the dialer type can dial is its own and is asked of the type.
    dialer: core::marker::PhantomData<fn() -> D>,
    rows: &'a Rows<D::Session>,
    periods: &'a mut Periods,
    directory: &'a LocatorDirectory<DIRECTORY_ROWS>,
    policy: RetryPolicy,
    now_ms: u64,
}

impl<D: Dialer> Ports<'_, D> {
    /// The row of `key`.
    fn row(&self, key: &Key) -> Option<&Row<D::Session>> {
        self.rows.iter().find(|row| row.key == *key)
    }
}

impl<D: Dialer> PeerPorts<Key> for Ports<'_, D> {
    /// What a dial is made at is not carried by the action: it is read where it lives when the
    /// dial is made (`ConnectManager::dial_peer`), so the actions hold names and not copies.
    type Target = ();

    /// An endpoint is dialled at itself, unless this build cannot dial it: a peer with no
    /// candidate. A node is dialled at the first of its live hints that this build can dial,
    /// FOR the node: the hint is where the zid may be, and the session closes at the InitAck
    /// if another node answers (decision D4). A dialer that cannot hold a session to the node
    /// it was made for dials none, since a session to whichever node answered would not be one
    /// to the zid.
    fn dialable(&self, key: &Key) -> Option<()> {
        let row = self.row(key)?;
        match (key, row.endpoint.as_ref()) {
            (Key::Endpoint(_), Some(endpoint)) => {
                if row.multi_link || D::classify(endpoint).is_err() {
                    return None;
                }
                Some(())
            }
            (Key::Node(zid), _) => {
                if !D::VERIFIES_NODES {
                    return None;
                }
                first_dialable(self.directory, zid, self.now_ms, D::classify).map(|_| ())
            }
            // An endpoint's row always holds its text.
            (Key::Endpoint(_), None) => None,
        }
    }

    fn retry_wait_ms(&mut self, key: &Key) -> u64 {
        if let Some((_, period)) = self.periods.iter_mut().find(|(k, _)| k == key) {
            return period.next_ms();
        }
        let mut period = self.policy.period();
        let wait = period.next_ms();
        // A table of as many rows as there are endpoints holds every endpoint in an outage; an
        // endpoint it could not hold would start from the first wait again.
        let _ = self.periods.push((*key, period));
        wait
    }

    fn retry_restart(&mut self, key: &Key) {
        self.periods.retain(|(k, _)| k != key);
    }
}

/// The first live hint of `zid` that `classify` says can be dialled, in the order the directory
/// gives them.
fn first_dialable<'a>(
    directory: &'a LocatorDirectory<DIRECTORY_ROWS>,
    zid: &'a DirectoryZid,
    now_ms: u64,
    classify: Classify,
) -> Option<&'a str> {
    directory
        .candidates(zid, now_ms)
        .map(|row| row.locator())
        .find(|locator| classify(locator).is_ok())
}

/// Keeps a node's sessions in step with its [`EndpointSource`], and holds the nodes it is asked
/// to open by their zid.
pub struct ConnectManager<D: Dialer> {
    control: &'static dyn EndpointSource,
    dialer: D,
    policy: RetryPolicy,
    generation: Option<u32>,
    rows: Rows<D::Session>,
    periods: Periods,
    store: StoreRef,
    /// The counter the planner mints the face of a dial from.
    next_id: u64,
}

impl<D: Dialer> ConnectManager<D> {
    /// A manager over `control`, dialling with `dialer`, on upstream's default retry schedule,
    /// holding its machines in a box. Only a profile with a heap has one; the slot profile hands
    /// the manager a store the image declared ([`Self::in_store`]).
    #[cfg(not(feature = "session-slot"))]
    pub fn new(control: &'static dyn EndpointSource, dialer: D) -> Self {
        Self::in_store(
            control,
            dialer,
            StoreRef::Boxed(alloc::boxed::Box::default()),
            RetryPolicy::ZENOH_DEFAULT,
        )
    }

    /// A manager over `control`, dialling with `dialer`, holding its machines in `store`, on
    /// upstream's default retry schedule. One store serves one manager: a second manager over the
    /// same store would share its machines.
    pub fn in_static_store(
        control: &'static dyn EndpointSource,
        dialer: D,
        store: &'static PeerStore,
    ) -> Self {
        Self::in_store(
            control,
            dialer,
            StoreRef::Static(store),
            RetryPolicy::ZENOH_DEFAULT,
        )
    }

    fn in_store(
        control: &'static dyn EndpointSource,
        dialer: D,
        store: StoreRef,
        policy: RetryPolicy,
    ) -> Self {
        // What this dialer can do is the store's to say to an opener, which has no dialer.
        store.get().with(|t| {
            t.verifies_nodes = D::VERIFIES_NODES;
            t.classify = Some(D::classify);
        });
        Self {
            control,
            dialer,
            policy,
            generation: None,
            rows: BoundedVec::new(),
            periods: BoundedVec::new(),
            store,
            next_id: 0,
        }
    }

    /// The dialer, for a caller that needs to reach the sessions it holds.
    pub fn dialer(&mut self) -> &mut D {
        &mut self.dialer
    }

    /// Where every endpoint stands, in the order the list named them.
    pub fn states(&self) -> impl Iterator<Item = (&str, SlotState)> + '_ {
        self.rows.iter().filter_map(|row| {
            let endpoint = row.endpoint()?;
            let state = match self.standing(row) {
                Standing::Waiting { at_ms } => SlotState::Waiting { at_ms },
                Standing::NoLocator => SlotState::Refused(self.refusal(row, endpoint)),
                // An endpoint names no node, so no dial of it can find another one answering.
                Standing::Live | Standing::Mismatched => SlotState::Live,
            };
            Some((endpoint, state))
        })
    }

    /// Where every node asked for by its zid stands, in the order they were asked for.
    pub fn node_states(&self) -> impl Iterator<Item = (&DirectoryZid, NodeState)> + '_ {
        self.rows.iter().filter_map(|row| {
            let Key::Node(zid) = &row.key else {
                return None;
            };
            let state = match self.standing(row) {
                Standing::Live => NodeState::Live,
                Standing::Waiting { at_ms } => NodeState::Waiting { at_ms },
                Standing::NoLocator => NodeState::NoHint,
                Standing::Mismatched => NodeState::Mismatched,
            };
            Some((zid, state))
        })
    }

    /// Where one peer stands.
    fn standing(&self, row: &Row<D::Session>) -> Standing {
        match self.store.get().with(|t| t.planner.state(&row.key)) {
            Some(PeerConnectionState::NoLocator) => Standing::NoLocator,
            Some(PeerConnectionState::Backoff) => Standing::Waiting {
                at_ms: row.due.map_or(0, |due| due.at_ms),
            },
            Some(PeerConnectionState::IdentityMismatch) => Standing::Mismatched,
            // The manager tells a machine that a session came up, that a dial failed, or that
            // another node answered, so no other refusal is a state a peer is in.
            _ => Standing::Live,
        }
    }

    /// R2834 — the sessions this manager holds right now, with the endpoint
    /// each was dialled for, in the list's order. A session is here from its
    /// dial until the manager sees it end, so it may still be handshaking; a
    /// caller that reports sessions asks each one whether it is established.
    /// The sessions of nodes are not here: they have no endpoint.
    pub fn sessions(&self) -> impl Iterator<Item = (&str, &D::Session)> + '_ {
        self.rows.iter().filter_map(|row| {
            let held = row.held.as_ref()?;
            Some((row.endpoint()?, &held.session))
        })
    }

    /// Why this build has no candidate for `row`'s endpoint.
    fn refusal(&self, row: &Row<D::Session>, endpoint: &str) -> DialRefused {
        if row.multi_link {
            return DialRefused::MultiLinkGroup;
        }
        // The endpoint is refused by the dialer when it is refused at all; a refusal the
        // dialer no longer gives (it was a group the list has since split) falls back to the
        // one an unreadable endpoint is.
        D::classify(endpoint)
            .err()
            .unwrap_or(DialRefused::Unsupported)
    }

    /// `source` confirms that the node `zid` may be reached at `locator`, for `lifetime`: the
    /// hint a node asked for by its zid is dialled at (decision D3). A build states a node's
    /// hints this way (`Declared`), and a scouting Hello of the node gives them (`Hello`).
    pub fn confirm_locator(
        &mut self,
        zid: DirectoryZid,
        locator: &str,
        source: LocatorSource,
        now_ms: u64,
        lifetime: Lifetime,
    ) -> Result<(), DirectoryRefusal> {
        self.store.get().with(|t| {
            t.now_ms = t.now_ms.max(now_ms);
            t.directory.confirm(zid, locator, source, now_ms, lifetime)
        })
    }

    /// The opener of this manager's nodes, for the code that serves a request to hold a peer by
    /// its zid (a lifecycle `open`), which runs where the manager does not. `None` when the
    /// manager's store is not a `static`: an opener outlives any one borrow of the manager, and
    /// only the slot profile's store is declared where one can be held.
    pub fn node_opener(&self) -> Option<NodeOpener> {
        match &self.store {
            StoreRef::Static(store) => Some(NodeOpener::in_store(store)),
            #[cfg(not(feature = "session-slot"))]
            StoreRef::Boxed(_) => None,
        }
    }

    /// Take the nodes an opener accepted since the last tick, and hold each as if
    /// [`Self::open_node`] had been asked here. An open the tables refuse by now (the hint
    /// lapsed between the request and this tick) leaves no row, and is asked again.
    #[inline(never)]
    fn serve_requests(&mut self, now_ms: u64) {
        loop {
            let next = self.store.get().with(|t| {
                if t.requests.is_empty() {
                    None
                } else {
                    Some(t.requests.remove(0))
                }
            });
            let Some(zid) = next else {
                return;
            };
            let _ = self.open_node(zid, now_ms);
        }
    }

    /// Say which nodes this manager holds a row for, where an opener reads it.
    fn mirror_held(&self) {
        self.store.get().with(|t| {
            t.held.clear();
            for row in self.rows.iter() {
                if let Key::Node(zid) = &row.key {
                    // As many rows for nodes as the limit, which the mirror is sized by.
                    let _ = t.held.push(*zid);
                }
            }
        });
    }

    /// `source` no longer confirms any hint of the node `zid`.
    pub fn withdraw_locators(&mut self, zid: &DirectoryZid, source: LocatorSource) {
        self.store.get().with(|t| t.directory.withdraw(zid, source));
    }

    /// Hold a session with the node `zid`, dialled at what the directory knows of it (decision D6:
    /// a lifecycle `open`). A node already held is unchanged, and one that had no hint to dial
    /// resolves again. The node is refused, and takes no row, when its dial could not be told from
    /// one to another node, when the node holds as many as it was built for, or when the directory
    /// has nothing it can dial.
    pub fn open_node(&mut self, zid: DirectoryZid, now_ms: u64) -> Result<(), NodeRefusal> {
        if !D::VERIFIES_NODES {
            return Err(NodeRefusal::Unverifiable);
        }
        let key = Key::Node(zid);
        if !self.rows.iter().any(|row| row.key == key) {
            let held = self
                .rows
                .iter()
                .filter(|row| matches!(row.key, Key::Node(_)))
                .count();
            // Written so that it holds for any value of the limit, none included.
            if MAX_PEER_NODES.saturating_sub(held) == 0 {
                return Err(NodeRefusal::NoRoom);
            }
            let known = self
                .store
                .get()
                .with(|t| t.directory.candidates(&zid, now_ms).next().is_some());
            if !known {
                return Err(NodeRefusal::NoLocator);
            }
            let dialable = self
                .store
                .get()
                .with(|t| first_dialable(&t.directory, &zid, now_ms, D::classify).is_some());
            if !dialable {
                return Err(NodeRefusal::NoDialableLocator);
            }
            // Fewer than `MAX_PEER_NODES` nodes are held and the endpoints fit their rows, so
            // the row fits; one that did not could only be a defect.
            if self.rows.push(Row::new(key, None, false)).is_err() {
                return Err(NodeRefusal::NoRoom);
            }
        }
        self.mirror_held();
        self.drive(now_ms, |planner, ports, next_id, emit| {
            // The table holds as many peers as the rows do.
            let _ = planner.open(key, ports, next_id, emit);
        });
        Ok(())
    }

    /// Stop holding the node `zid`: the session it holds, and the session of any endpoint that
    /// reached the same node, is hung up (decision D6: a lifecycle `close`), and the node is
    /// dialled no more. The hints stay: they are the directory's, and a later `open` uses them.
    pub fn close_node(&mut self, zid: &DirectoryZid, now_ms: u64) {
        let key = Key::Node(*zid);
        self.drive(now_ms, |planner, ports, next_id, emit| {
            planner.withdraw(zid, key, ports, next_id, emit);
        });
        if let Some(held) = self.row_mut(&key).and_then(|row| row.held.take()) {
            let face = held.face;
            self.dialer.hang_up(held.session);
            self.drive(now_ms, |planner, ports, next_id, emit| {
                planner.dial_ended(face, DialEnd::Failed, ports, next_id, emit);
            });
        }
        self.store.get().with(|t| t.planner.forget(&key));
        self.periods.retain(|(k, _)| *k != key);
        self.rows.retain(|row| row.key != key);
        self.mirror_held();
    }

    /// Advance to `now_ms`: reconcile a new list, take the nodes an opener asked for, notice
    /// sessions that came up or ended, and dial what is due.
    pub fn tick(&mut self, now_ms: u64) {
        self.store.get().with(|t| t.now_ms = now_ms);
        if self.generation != Some(self.control.generation()) {
            let (generation, list) = self.control.endpoints();
            self.reconcile(&list, now_ms);
            self.generation = Some(generation);
        }
        self.store.get().with(|t| t.directory.expire(now_ms));
        self.serve_requests(now_ms);
        self.observe(now_ms);
        self.fire_due(now_ms);
    }

    /// Run one call of the planner against this profile's ports, and take what it asked for.
    ///
    /// A dial that does not start is a failed attempt of the endpoint's outage, which the
    /// planner is told of in the next turn of this loop and answers with a wait and no further
    /// dial. It is a loop and not a call back into this function, so that no call of the
    /// manager is its own callee and the worst chain of calls under a tick is a bound.
    fn drive(
        &mut self,
        now_ms: u64,
        call: impl FnOnce(&mut Planner, &mut Ports<'_, D>, &mut u64, &mut dyn FnMut(Action)),
    ) {
        let mut actions = self.ask(now_ms, call);
        let mut failed: FixedVec<u64, 6> = FixedVec::new();
        loop {
            self.take(actions, now_ms, &mut failed);
            let Some(id) = failed.pop() else {
                return;
            };
            // The turn after a failed dial asks for no dial, so the list only shrinks.
            actions = self.ask(now_ms, |planner, ports, next_id, emit| {
                planner.dial_ended(id, DialEnd::Failed, ports, next_id, emit);
            });
        }
    }

    /// One call of the planner against this profile's ports, and what it asked for.
    fn ask(
        &mut self,
        now_ms: u64,
        call: impl FnOnce(&mut Planner, &mut Ports<'_, D>, &mut u64, &mut dyn FnMut(Action)),
    ) -> Actions {
        let mut actions = Actions::new();
        let next_id = &mut self.next_id;
        self.store.get().with(|tables| {
            let mut ports = Ports {
                dialer: core::marker::PhantomData,
                rows: &self.rows,
                periods: &mut self.periods,
                directory: &tables.directory,
                policy: self.policy,
                now_ms,
            };
            call(&mut tables.planner, &mut ports, next_id, &mut |action| {
                // At most one of each kind per call and `Actions` holds six.
                let _ = actions.push(action);
            })
        });
        actions
    }

    /// Take the actions of one call: start the dials, arm the waits, hang up the sessions.
    /// The faces of the dials that did not start go to `failed`.
    fn take(&mut self, actions: Actions, now_ms: u64, failed: &mut FixedVec<u64, 6>) {
        for action in actions {
            match action {
                PeerAction::Dial { id, key, .. } => match self.dial_peer(&key, now_ms) {
                    Ok(session) => {
                        if let Some(row) = self.row_mut(&key) {
                            row.held = Some(Held {
                                face: id,
                                session,
                                up: false,
                            });
                        }
                    }
                    // `Refused` is the answer `classify` already gave, so a dial that finds it
                    // is the dialer disagreeing with itself; it is a failed attempt and the
                    // endpoint waits, which cannot do harm.
                    Err(_) => {
                        // At most six actions, so at most six dials.
                        let _ = failed.push(id);
                    }
                },
                PeerAction::Retry {
                    key,
                    generation,
                    after_ms,
                    ..
                } => {
                    if let Some(row) = self.row_mut(&key) {
                        row.due = Some(Due {
                            generation,
                            at_ms: now_ms.saturating_add(after_ms),
                        });
                    }
                }
                PeerAction::Close { id } => self.hang_up_face(id),
            }
        }
    }

    /// Dial `key`: an endpoint at its own text, a node at the first live hint of the directory
    /// that this build can dial, FOR the node. The planner asked for the dial having found there
    /// was something to dial, and nothing moves the rows or the directory between that and here,
    /// so a peer with nothing to dial now is the dialer disagreeing with itself, a failed attempt.
    ///
    /// Out of line, so that the locator it holds (sixty-four bytes of a node's hint) is a frame of
    /// the dial and not of the loop that ticks the manager.
    #[inline(never)]
    fn dial_peer(&mut self, key: &Key, now_ms: u64) -> Result<D::Session, DialFailed> {
        match key {
            Key::Endpoint(_) => {
                let endpoint = self
                    .rows
                    .iter()
                    .find(|row| row.key == *key)
                    .and_then(|row| row.endpoint.as_ref())
                    .ok_or(DialFailed::Unreachable)?;
                self.dialer.dial(endpoint)
            }
            Key::Node(zid) => {
                // Read out of the critical section: a dial is not made inside one.
                let locator: Option<EndpointText> = self.store.get().with(|t| {
                    first_dialable(&t.directory, zid, now_ms, D::classify)
                        .and_then(|locator| EndpointText::try_from(locator).ok())
                });
                let locator = locator.ok_or(DialFailed::Unreachable)?;
                self.dialer.dial_for(&locator, zid)
            }
        }
    }

    fn row_mut(&mut self, key: &Key) -> Option<&mut Row<D::Session>> {
        self.rows.iter_mut().find(|row| row.key == *key)
    }

    /// The lowest slot no endpoint's row holds. A freed slot is the next endpoint's, which is why
    /// `reconcile` forgets a peer in the planner before it drops its row.
    fn free_slot(&self) -> Option<u8> {
        (0..=u8::MAX).find(|slot| !self.rows.iter().any(|row| row.key == Key::Endpoint(*slot)))
    }

    /// Hang up the session held as face `id`, if a row holds it.
    fn hang_up_face(&mut self, id: u64) {
        let held = self
            .rows
            .iter_mut()
            .find(|row| row.held.as_ref().is_some_and(|held| held.face == id))
            .and_then(|row| row.held.take());
        if let Some(held) = held {
            self.dialer.hang_up(held.session);
        }
    }

    /// Tell each machine whose session came up or ended.
    fn observe(&mut self, now_ms: u64) {
        for at in 0..self.rows.len() {
            let node = match &self.rows[at].key {
                Key::Node(zid) => Some(*zid),
                Key::Endpoint(_) => None,
            };
            let Some(held) = self.rows[at].held.as_mut() else {
                continue;
            };
            let face = held.face;
            let was_up = held.up;
            let came_up = !was_up && self.dialer.established(&mut held.session);
            let remote = if came_up {
                self.dialer.remote(&held.session)
            } else {
                None
            };
            if came_up {
                held.up = true;
            }
            // A session to a node that names another node is not one to the node, whatever
            // the dialer's handshake let through (decision D4): it is hung up, and the dial
            // is the mismatch of a stale hint.
            if matches!((node, remote), (Some(expected), Some(named)) if expected != named) {
                if let Some(held) = self.rows[at].held.take() {
                    self.dialer.hang_up(held.session);
                }
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.dial_ended(face, DialEnd::Mismatch, ports, next_id, emit);
                });
                continue;
            }
            let ended = self.dialer.ended(&mut held.session);
            let mut up = was_up || came_up;
            if came_up {
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.dial_ended(face, DialEnd::Established { remote }, ports, next_id, emit);
                });
            }
            let Some(how) = ended else {
                continue;
            };
            if !up && how == Ended::AfterEstablished {
                // A dialer that does not say when a session comes up says only that it did, at
                // its end: the machine is told it was up, and then that it was lost.
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.dial_ended(
                        face,
                        DialEnd::Established { remote: None },
                        ports,
                        next_id,
                        emit,
                    );
                });
                up = true;
            }
            // The session is over: nothing is left to hang up, and its handle goes.
            self.rows[at].held = None;
            if up {
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.face_down(face, ports, next_id, emit);
                });
            } else {
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.dial_ended(face, DialEnd::Failed, ports, next_id, emit);
                });
            }
        }
    }

    /// Dial the endpoints whose wait is up.
    fn fire_due(&mut self, now_ms: u64) {
        let mut due: FixedVec<(Key, u64), PEERS> = FixedVec::new();
        for row in self.rows.iter_mut() {
            if let Some(timer) = row.due {
                if now_ms >= timer.at_ms {
                    row.due = None;
                    // At most one timer per row, and the table has a row each.
                    let _ = due.push((row.key, timer.generation));
                }
            }
        }
        for (key, generation) in due {
            self.drive(now_ms, |planner, ports, next_id, emit| {
                planner.retry_due(key, generation, ports, next_id, emit);
            });
        }
    }

    // Out of line: it runs when the list moves, which for an image-built list is once, and it holds
    // the list, the rows that stay and the rows it builds, a few KB. Inlined into `tick` those sit
    // under the loop of the node for its whole life, beneath every receive.
    #[inline(never)]
    fn reconcile(&mut self, list: &ConnectEndpoints, now_ms: u64) {
        // An empty group names nothing to dial.
        let dialable = |e: &ConnectEntry| !e.endpoint.is_empty();
        // Whether the entry is one locator of a group of several, which this node cannot
        // open as one transport.
        let in_group = |e: &ConnectEntry| e.group.is_some_and(|g| group_len(list, g.index) > 1);
        // A node is not the list's to name: it stays until it is closed. An endpoint is
        // named as it was held: one the list now writes as a member of a group of several
        // (or no longer does) is another entry, so its session is hung up and the row is
        // made again, as the rows were compared whole before they were keyed by peer.
        let named = |row: &Row<D::Session>| match row.endpoint() {
            Some(endpoint) => list.iter().any(|entry| {
                dialable(entry)
                    && entry.endpoint.as_str() == endpoint
                    && in_group(entry) == row.multi_link
            }),
            None => true,
        };

        // Hang up what the list no longer names: stop the machine (a session it holds is
        // hung up by the close that asks for), then hang up what is still held (a session
        // still handshaking has no face the machine holds), and forget the endpoint.
        let mut gone: FixedVec<Key, MAX_STATIC_CONNECT> = FixedVec::new();
        for row in self.rows.iter() {
            if !named(row) {
                // One row per endpoint, and the table has as many rows as this holds.
                let _ = gone.push(row.key);
            }
        }
        for key in gone {
            self.drive(now_ms, |planner, ports, next_id, emit| {
                planner.stop(&key, ports, next_id, emit);
            });
            if let Some(held) = self.row_mut(&key).and_then(|row| row.held.take()) {
                let face = held.face;
                self.dialer.hang_up(held.session);
                // A dial the machine stopped is abandoned, and its end is the planner's to
                // clear.
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    planner.dial_ended(face, DialEnd::Failed, ports, next_id, emit);
                });
            }
            self.store.get().with(|t| t.planner.forget(&key));
            self.periods.retain(|(k, _)| *k != key);
            self.rows.retain(|row| row.key != key);
        }

        // A new endpoint is due now, and a refused one is given another chance, since a
        // rewrite is what could change it. R2841 — upstream opens a group of several
        // locators as ONE transport over all its locators (`allOf`, the only strategy its
        // runtime implements); an MCU session holds one link, so each is refused by name
        // rather than dialled as separate sessions to what is one peer.
        for entry in list.iter().filter(|e| dialable(e)) {
            let multi_link = in_group(entry);
            let held = self
                .rows
                .iter_mut()
                .find(|row| row.endpoint() == Some(entry.endpoint.as_str()));
            let key = match held {
                // A row that stayed was named as it is (`named`), group or not.
                Some(row) => row.key,
                None => {
                    // The list holds as many entries as this table has rows for endpoints, so a
                    // slot is always free and a row always fits; one that did not could only
                    // be a defect.
                    let Some(slot) = self.free_slot() else {
                        continue;
                    };
                    let key = Key::Endpoint(slot);
                    let row = Row::new(key, Some(entry.endpoint.clone()), multi_link);
                    if self.rows.push(row).is_err() {
                        continue;
                    }
                    key
                }
            };
            // `open` of an endpoint already held or being reached changes nothing; one its
            // machine refused resolves again.
            let state = self.store.get().with(|t| t.planner.state(&key));
            if state == Some(PeerConnectionState::NoLocator) || state.is_none() {
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    let _ = planner.open(key, ports, next_id, emit);
                });
            }
        }

        // Keep the list's order, and the nodes after it in the order they were asked for.
        let mut kept: BoundedVec<Option<Row<D::Session>>, PEERS> = BoundedVec::new();
        for row in core::mem::take(&mut self.rows) {
            let _ = kept.push(Some(row));
        }
        for entry in list.iter().filter(|e| dialable(e)) {
            let held = kept
                .iter()
                .position(|row| {
                    row.as_ref()
                        .is_some_and(|row| row.endpoint() == Some(entry.endpoint.as_str()))
                })
                .and_then(|at| kept[at].take());
            if let Some(row) = held {
                let _ = self.rows.push(row);
            }
        }
        for row in kept.into_iter().flatten() {
            let _ = self.rows.push(row);
        }
    }
}

type Action = PeerAction<Key, u64, ()>;

#[cfg(all(test, feature = "adminspace-write"))]
mod tests {
    use super::*;
    use crate::admin_host::ConnectControl;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// A dialer that records what it was asked and ends sessions on demand.
    #[derive(Default)]
    struct FakeDialer {
        dials: RefCell<Vec<String>>,
        hang_ups: Vec<String>,
        /// Sessions to end on the next `ended` call, and how.
        endings: Vec<(String, Ended)>,
        /// Sessions that are established now, and the zid each names.
        up: Vec<(String, Option<[u8; CREDENTIAL_ZID_BYTES]>)>,
        /// Answer every dial with `Exhausted`.
        exhausted: bool,
        /// The dials made for a node: the locator and the zid it was made for.
        dials_for: RefCell<Vec<(String, DirectoryZid)>>,
    }

    impl Dialer for FakeDialer {
        type Session = String;

        const VERIFIES_NODES: bool = true;

        /// The session of a dial made for a node is the locator and `@`, so that a test can
        /// tell it from an endpoint's and have the dialer say it is up or has ended.
        fn dial_for(&mut self, endpoint: &str, node: &DirectoryZid) -> Result<String, DialFailed> {
            self.dials_for
                .borrow_mut()
                .push((String::from(endpoint), *node));
            Ok(alloc::format!("{endpoint}@"))
        }

        fn classify(endpoint: &str) -> Result<(), DialRefused> {
            if endpoint.starts_with("serial/") {
                return Err(DialRefused::Unsupported);
            }
            Ok(())
        }

        fn dial(&mut self, endpoint: &str) -> Result<String, DialFailed> {
            if self.exhausted {
                return Err(DialFailed::Exhausted);
            }
            self.dials.borrow_mut().push(String::from(endpoint));
            Ok(String::from(endpoint))
        }

        fn established(&mut self, session: &mut String) -> bool {
            self.up.iter().any(|(s, _)| s == session)
        }

        fn remote(&self, session: &String) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
            self.up
                .iter()
                .find(|(s, _)| s == session)
                .and_then(|(_, zid)| *zid)
        }

        fn ended(&mut self, session: &mut String) -> Option<Ended> {
            let i = self.endings.iter().position(|(e, _)| e == session)?;
            Some(self.endings.remove(i).1)
        }

        fn hang_up(&mut self, session: String) {
            self.hang_ups.push(session);
        }
    }

    fn write(control: &'static ConnectControl, list: &[&str]) {
        let mut body = String::from("[");
        for (i, e) in list.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push('"');
            body.push_str(e);
            body.push('"');
        }
        body.push(']');
        control.apply_for_test(body.as_bytes());
    }

    fn dials(m: &mut ConnectManager<FakeDialer>) -> Vec<String> {
        m.dialer().dials.borrow_mut().drain(..).collect()
    }

    #[test]
    fn a_written_list_is_dialled_at_once_and_an_empty_one_dials_nothing() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        m.tick(0);
        std::assert!(dials(&mut m).is_empty(), "no list, no dial");

        write(&CONTROL, &["udp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        m.tick(5);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        std::assert!(m.states().all(|(_, s)| s == SlotState::Live));
        // R2834 — every live slot's session is reachable, with its endpoint.
        let held: Vec<(&str, &String)> = m.sessions().collect();
        std::assert_eq!(
            held,
            [
                ("udp/10.0.0.1:7447", &String::from("udp/10.0.0.1:7447")),
                ("udp/10.0.0.2:7447", &String::from("udp/10.0.0.2:7447")),
            ]
        );
    }

    /// Failures before establishing are ONE outage and the wait grows on
    /// upstream's default, 1 s then 2 s; a session that had been up and then
    /// drops starts again from 1 s.
    #[test]
    fn re_dials_follow_upstreams_schedule_per_outage() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m).len(), 1);

        let fail = |m: &mut ConnectManager<FakeDialer>, how| {
            m.dialer()
                .endings
                .push((String::from("udp/10.0.0.1:7447"), how));
        };

        fail(&mut m, Ended::BeforeEstablished);
        m.tick(100);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 1100 }
        );
        m.tick(1099);
        std::assert!(dials(&mut m).is_empty(), "not before the wait is up");
        m.tick(1100);
        std::assert_eq!(dials(&mut m).len(), 1, "re-dialled when due");

        fail(&mut m, Ended::BeforeEstablished);
        m.tick(1200);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 3200 },
            "the same outage: the wait grew to 2 s"
        );
        m.tick(3200);
        std::assert_eq!(dials(&mut m).len(), 1);

        fail(&mut m, Ended::AfterEstablished);
        m.tick(9000);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 10000 },
            "a new outage starts from 1 s again"
        );
    }

    /// A dialer that says when a session comes up gives the same schedule: a session
    /// that was seen up and then dropped starts again from the first wait, and one that
    /// is up is Live, not waiting.
    #[test]
    fn a_session_seen_up_and_then_lost_starts_the_schedule_over() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m).len(), 1);

        // Two failed attempts first, so the wait has grown.
        m.dialer()
            .endings
            .push((String::from("udp/10.0.0.1:7447"), Ended::BeforeEstablished));
        m.tick(100);
        m.tick(1100);
        std::assert_eq!(dials(&mut m).len(), 1);

        m.dialer()
            .up
            .push((String::from("udp/10.0.0.1:7447"), Some([0xab; 16])));
        m.tick(1500);
        std::assert_eq!(m.states().next().unwrap().1, SlotState::Live);

        m.dialer().up.clear();
        m.dialer()
            .endings
            .push((String::from("udp/10.0.0.1:7447"), Ended::AfterEstablished));
        m.tick(9000);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 10000 },
            "the first wait again, not the grown one"
        );
    }

    /// A node that cannot afford a session right now is not refused: the
    /// endpoint waits its period like a dial nobody answered, and is dialled
    /// once the node can.
    #[test]
    fn an_exhausted_dial_waits_its_period_and_is_not_refused() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(
            &CONTROL,
            FakeDialer {
                exhausted: true,
                ..FakeDialer::default()
            },
            &STORE,
        );
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 1000 }
        );
        m.tick(1000);
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Waiting { at_ms: 3000 },
            "still the same outage: the wait grew"
        );
        m.dialer().exhausted = false;
        m.tick(3000);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);
    }

    /// R2841 — upstream's group element: a group of one locator is dialled
    /// like a bare endpoint; a group of several is one session over several
    /// links, refused by name and never dialled; an empty group names nothing.
    #[test]
    fn a_group_of_one_is_dialled_and_a_group_of_several_is_refused() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        CONTROL.apply_for_test(
            br#"[{ strategy: "allOf", locators: ["udp/10.0.0.1:1", "udp/10.0.0.2:1"] },
                 { strategy: "allOf", locators: ["udp/10.0.0.3:1"] },
                 { strategy: "oneOf", locators: [] }]"#,
        );
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.3:1"]);
        let states: Vec<(String, SlotState)> =
            m.states().map(|(e, s)| (String::from(e), s)).collect();
        std::assert_eq!(
            states,
            [
                (
                    String::from("udp/10.0.0.1:1"),
                    SlotState::Refused(DialRefused::MultiLinkGroup)
                ),
                (
                    String::from("udp/10.0.0.2:1"),
                    SlotState::Refused(DialRefused::MultiLinkGroup)
                ),
                (String::from("udp/10.0.0.3:1"), SlotState::Live),
            ]
        );
    }

    /// An endpoint that is up when a rewrite makes it a member of a group of several is
    /// hung up and refused with the others (the lane's step 6: a group of two is refused
    /// whole, the live member included), and a group split again is dialled again.
    #[test]
    fn a_live_endpoint_made_a_group_member_is_hung_up_and_refused() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:1"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:1"]);
        std::assert_eq!(m.states().next().unwrap().1, SlotState::Live);

        CONTROL.apply_for_test(
            br#"[{ strategy: "allOf", locators: ["udp/10.0.0.1:1", "udp/10.0.0.2:9"] }]"#,
        );
        m.tick(1);
        std::assert_eq!(m.dialer().hang_ups, vec![String::from("udp/10.0.0.1:1")]);
        std::assert_eq!(m.sessions().count(), 0, "a refused member holds no session");
        let states: Vec<SlotState> = m.states().map(|(_, s)| s).collect();
        std::assert_eq!(
            states,
            [
                SlotState::Refused(DialRefused::MultiLinkGroup),
                SlotState::Refused(DialRefused::MultiLinkGroup),
            ]
        );
        std::assert!(dials(&mut m).is_empty(), "a group is never dialled");

        write(&CONTROL, &["udp/10.0.0.1:1"]);
        m.tick(2);
        std::assert_eq!(
            dials(&mut m),
            ["udp/10.0.0.1:1"],
            "a group split is dialled again"
        );
        std::assert_eq!(m.states().next().unwrap().1, SlotState::Live);
    }

    #[test]
    fn an_endpoint_the_list_drops_is_hung_up_and_one_it_cannot_dial_waits_for_a_rewrite() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:7447", "serial//dev/ttyS0"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);
        std::assert_eq!(
            m.states().nth(1).unwrap().1,
            SlotState::Refused(DialRefused::Unsupported)
        );
        m.tick(60_000);
        std::assert!(
            dials(&mut m).is_empty(),
            "a refused endpoint is not retried"
        );

        write(&CONTROL, &["serial//dev/ttyS0"]);
        m.tick(60_001);
        std::assert_eq!(m.dialer().hang_ups, vec![String::from("udp/10.0.0.1:7447")]);
        std::assert_eq!(m.sessions().count(), 0, "a refused slot holds no session");
        std::assert_eq!(
            m.states().next().unwrap().1,
            SlotState::Refused(DialRefused::Unsupported),
            "a rewrite tries the refused endpoint again, and it is refused again"
        );
    }

    /// An endpoint the list drops while its session is up is hung up too, and the machine
    /// it leaves behind holds nothing: the list written again with it is a new endpoint,
    /// dialled at once.
    #[test]
    fn a_dropped_endpoint_with_a_session_up_is_hung_up_and_a_rewrite_dials_it_afresh() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        m.tick(0);
        m.dialer()
            .up
            .push((String::from("udp/10.0.0.1:7447"), None));
        m.tick(10);
        std::assert_eq!(dials(&mut m).len(), 1);

        write(&CONTROL, &["udp/10.0.0.2:7447"]);
        m.tick(20);
        std::assert_eq!(m.dialer().hang_ups, vec![String::from("udp/10.0.0.1:7447")]);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.2:7447"]);
        std::assert_eq!(m.states().count(), 1, "the dropped endpoint is gone");

        write(&CONTROL, &["udp/10.0.0.1:7447", "udp/10.0.0.2:7447"]);
        m.dialer().up.clear();
        m.tick(30);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"], "dialled afresh");
    }

    /// The manager is a local of the node's loop, which runs on a stack of a few KB on the
    /// smallest image, so it does not carry the machines of its peers (each some 930 bytes on
    /// the target, a table of them some 10 KB): they are in a [`PeerStore`] it only refers to.
    /// A manager that held them would pass every other test here and overflow that stack, which
    /// round 3613 did and this bound exists to refuse. The bound is loose on purpose: it says
    /// "a few rows and some references", not an exact figure a field would move.
    #[test]
    fn the_manager_does_not_carry_the_machines_of_its_peers() {
        let manager = core::mem::size_of::<ConnectManager<FakeDialer>>();
        let store = core::mem::size_of::<PeerStore>();
        std::assert!(
            store > 8 * 1024,
            "the store is where the machines are ({store} bytes), or this test guards nothing"
        );
        std::assert!(
            manager < 4 * 1024,
            "the manager is {manager} bytes: it is carrying the machines it should refer to"
        );
    }

    /// The list is a set: an endpoint written twice is one endpoint, one session.
    #[test]
    fn an_endpoint_written_twice_is_one_endpoint() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        write(&CONTROL, &["udp/10.0.0.1:7447", "udp/10.0.0.1:7447"]);
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);
        std::assert_eq!(m.states().count(), 1);
    }

    /// The nodes a build is asked to hold by their zid are `MAX_PEER_NODES`, and the default is
    /// none, so a node-holding test has a build that states some (`WZ_LIMIT_MAX_PEER_NODES`, as
    /// the leg that counts these tests does). A build that states none refuses every open for
    /// want of room, which is what is asserted of it.
    fn nodes_asked_for() -> bool {
        MAX_PEER_NODES != 0
    }

    const NODE_A: DirectoryZid = [0xa1; CREDENTIAL_ZID_BYTES];
    const NODE_B: DirectoryZid = [0xb2; CREDENTIAL_ZID_BYTES];

    fn declare(m: &mut ConnectManager<FakeDialer>, zid: DirectoryZid, locator: &str) {
        m.confirm_locator(
            zid,
            locator,
            LocatorSource::Declared,
            0,
            Lifetime::Permanent,
        )
        .expect("the directory has a row for the hint");
    }

    /// A node whose zid the build was told a locator of is dialled at that locator, FOR the zid,
    /// and held beside the endpoints the list names, which a rewrite of the list leaves alone.
    #[test]
    fn a_node_with_a_hint_is_dialled_for_its_zid_beside_the_endpoints() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            std::assert_eq!(m.open_node(NODE_A, 0), Err(NodeRefusal::NoRoom));
            return;
        }
        write(&CONTROL, &["udp/10.0.0.1:7447"]);
        declare(&mut m, NODE_A, "udp/10.0.0.9:7447");
        m.tick(0);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.1:7447"]);

        std::assert_eq!(m.open_node(NODE_A, 1), Ok(()));
        let made: Vec<(String, DirectoryZid)> =
            m.dialer().dials_for.borrow_mut().drain(..).collect();
        std::assert_eq!(made, [(String::from("udp/10.0.0.9:7447"), NODE_A)]);
        std::assert_eq!(m.node_states().count(), 1);
        std::assert_eq!(m.node_states().next().unwrap().1, NodeState::Live);
        std::assert_eq!(m.states().count(), 1, "the endpoints are the list's alone");

        write(&CONTROL, &["udp/10.0.0.2:7447"]);
        m.tick(2);
        std::assert_eq!(dials(&mut m), ["udp/10.0.0.2:7447"]);
        std::assert_eq!(
            m.node_states().count(),
            1,
            "a rewrite of the list leaves the node"
        );
        std::assert!(m.dialer().hang_ups.iter().all(|s| !s.ends_with('@')));
    }

    /// An open for a node that is not held takes no row until there is something to dial: a zid
    /// nobody advertised, and a node whose hints this build cannot dial, are each refused by name,
    /// and a flood of opens does not fill the table.
    #[test]
    fn a_node_nothing_can_be_dialled_for_is_refused_and_takes_no_row() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            return;
        }
        std::assert_eq!(m.open_node(NODE_A, 0), Err(NodeRefusal::NoLocator));
        declare(&mut m, NODE_B, "serial//dev/ttyS0");
        std::assert_eq!(m.open_node(NODE_B, 0), Err(NodeRefusal::NoDialableLocator));
        std::assert_eq!(m.node_states().count(), 0);
        std::assert!(m.dialer().dials_for.borrow().is_empty());
    }

    /// A dialer that does not hold a session to the node it was made for is not asked to dial one:
    /// the session would be to whichever node answered the hint.
    #[test]
    fn a_dialer_that_cannot_verify_a_node_opens_none() {
        struct Plain;
        impl Dialer for Plain {
            type Session = ();
            fn dial(&mut self, _endpoint: &str) -> Result<(), DialFailed> {
                Ok(())
            }
            fn ended(&mut self, _session: &mut ()) -> Option<Ended> {
                None
            }
            fn hang_up(&mut self, _session: ()) {}
        }
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, Plain, &STORE);
        std::assert_eq!(m.open_node(NODE_A, 0), Err(NodeRefusal::Unverifiable));
    }

    /// The node holds as many nodes as it was built for, and a further open is refused.
    #[test]
    fn a_node_past_the_built_capacity_is_refused() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            return;
        }
        for at in (1u8..).take(MAX_PEER_NODES) {
            let zid = [at; CREDENTIAL_ZID_BYTES];
            declare(&mut m, zid, "udp/10.0.0.9:7447");
            std::assert_eq!(m.open_node(zid, 0), Ok(()));
        }
        let over = [0xee; CREDENTIAL_ZID_BYTES];
        declare(&mut m, over, "udp/10.0.0.9:7447");
        std::assert_eq!(m.open_node(over, 0), Err(NodeRefusal::NoRoom));
        std::assert_eq!(m.node_states().count(), MAX_PEER_NODES);
        // One already held is not another: asking again changes nothing.
        std::assert_eq!(m.open_node([1; CREDENTIAL_ZID_BYTES], 0), Ok(()));
        std::assert_eq!(m.node_states().count(), MAX_PEER_NODES);
    }

    /// The opener answers outside the loop with what the node knows without it, and the
    /// manager holds the node it accepted at its next tick.
    #[test]
    fn the_opener_accepts_a_node_and_the_next_tick_holds_it() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        let opener = m.node_opener().expect("a static store has an opener");
        if !nodes_asked_for() {
            std::assert_eq!(opener.open(&NODE_A), Err(NodeRefusal::NoRoom));
            return;
        }
        m.tick(0);
        std::assert_eq!(opener.open(&NODE_A), Err(NodeRefusal::NoLocator));
        declare(&mut m, NODE_A, "udp/10.0.0.9:7447");
        std::assert_eq!(opener.open(&NODE_A), Ok(()));
        std::assert_eq!(
            opener.open(&NODE_A),
            Ok(()),
            "a second open of it is the same open"
        );
        std::assert_eq!(
            m.node_states().count(),
            0,
            "nothing is held until the loop ticks"
        );
        m.tick(1);
        let made: Vec<(String, DirectoryZid)> =
            m.dialer().dials_for.borrow_mut().drain(..).collect();
        std::assert_eq!(made, [(String::from("udp/10.0.0.9:7447"), NODE_A)]);
        std::assert_eq!(m.node_states().next().unwrap().1, NodeState::Live);
        std::assert_eq!(
            opener.open(&NODE_A),
            Ok(()),
            "a node that is held is not another"
        );

        m.close_node(&NODE_A, 2);
        std::assert_eq!(m.node_states().count(), 0);
        std::assert_eq!(
            opener.open(&NODE_A),
            Ok(()),
            "a closed node can be opened again"
        );
        m.tick(3);
        std::assert_eq!(m.node_states().count(), 1);
    }

    /// Each refusal the opener gives is the one `open_node` gives, and a refused open leaves
    /// nothing to take.
    #[test]
    fn the_opener_refuses_what_the_node_cannot_hold() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        let opener = m.node_opener().expect("a static store has an opener");
        if !nodes_asked_for() {
            return;
        }
        declare(&mut m, NODE_B, "serial//dev/ttyS0");
        std::assert_eq!(opener.open(&NODE_B), Err(NodeRefusal::NoDialableLocator));
        for at in (1u8..).take(MAX_PEER_NODES) {
            let zid = [at; CREDENTIAL_ZID_BYTES];
            declare(&mut m, zid, "udp/10.0.0.9:7447");
            std::assert_eq!(opener.open(&zid), Ok(()));
        }
        let over = [0xee; CREDENTIAL_ZID_BYTES];
        declare(&mut m, over, "udp/10.0.0.9:7447");
        std::assert_eq!(
            opener.open(&over),
            Err(NodeRefusal::NoRoom),
            "the nodes asked for and not yet taken count against the room"
        );
        m.tick(1);
        std::assert_eq!(m.node_states().count(), MAX_PEER_NODES);
        std::assert_eq!(opener.open(&over), Err(NodeRefusal::NoRoom));
    }

    /// Each refusal of a node is one word of the lifecycle's open vocabulary, and no two share
    /// one: a node with no hint is a node the opener knows no locator for.
    #[test]
    fn a_refusal_of_a_node_is_one_word_of_the_open_vocabulary() {
        let words = [
            (NodeRefusal::Unverifiable, OpenOutcome::Unverifiable),
            (NodeRefusal::NoRoom, OpenOutcome::NoRoom),
            (NodeRefusal::NoLocator, OpenOutcome::PeerUnknown),
            (
                NodeRefusal::NoDialableLocator,
                OpenOutcome::NoDialableLocator,
            ),
        ];
        for (refusal, outcome) in words {
            std::assert_eq!(OpenOutcome::from(refusal), outcome);
        }
    }

    /// An opener is made from the store alone, so an image declares it in a `static` beside the
    /// store before any manager exists. Until a manager is made over the store it says
    /// `Unverifiable`, and once there is one it answers for that manager's dialer.
    #[test]
    fn an_opener_made_from_the_store_alone_answers_for_the_manager_made_after_it() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        static OPENER: NodeOpener = NodeOpener::in_store(&STORE);
        std::assert_eq!(OPENER.open(&NODE_A), Err(NodeRefusal::Unverifiable));
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            std::assert_eq!(OPENER.open(&NODE_A), Err(NodeRefusal::NoRoom));
            return;
        }
        std::assert_eq!(OPENER.open(&NODE_A), Err(NodeRefusal::NoLocator));
        declare(&mut m, NODE_A, "udp/10.0.0.9:7447");
        std::assert_eq!(OPENER.open(&NODE_A), Ok(()));
        m.tick(1);
        std::assert_eq!(m.node_states().count(), 1);
    }

    /// A dialer that cannot hold a session to the node it dials for has an opener that says so,
    /// whatever the directory knows.
    #[test]
    fn the_opener_of_a_dialer_that_cannot_verify_says_so() {
        struct Plain;
        impl Dialer for Plain {
            type Session = ();
            fn dial(&mut self, _endpoint: &str) -> Result<(), DialFailed> {
                Ok(())
            }
            fn ended(&mut self, _session: &mut ()) -> Option<Ended> {
                None
            }
            fn hang_up(&mut self, _session: ()) {}
        }
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let m = ConnectManager::in_static_store(&CONTROL, Plain, &STORE);
        let opener = m.node_opener().expect("a static store has an opener");
        std::assert_eq!(opener.open(&NODE_A), Err(NodeRefusal::Unverifiable));
    }

    /// A session that comes up naming another node than the one asked for is no session to it,
    /// whatever the dialer let through: it is hung up, and the machine refuses the node as one
    /// another answered for (decision D4), so it is not dialled again until it is opened.
    #[test]
    fn a_session_that_names_another_node_is_hung_up() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            return;
        }
        declare(&mut m, NODE_A, "udp/10.0.0.9:7447");
        std::assert_eq!(m.open_node(NODE_A, 0), Ok(()));
        m.dialer()
            .up
            .push((String::from("udp/10.0.0.9:7447@"), Some(NODE_B)));
        m.tick(10);
        std::assert_eq!(
            m.dialer().hang_ups,
            vec![String::from("udp/10.0.0.9:7447@")],
            "the session of another node is not kept"
        );
        std::assert_eq!(m.node_states().next().unwrap().1, NodeState::Mismatched);
        m.dialer().up.clear();
        m.tick(60_000);
        std::assert_eq!(
            m.dialer().dials_for.borrow().len(),
            1,
            "a node another answered for is not dialled again by waiting"
        );
    }

    /// A `close` of a node hangs up its session and takes its row, and leaves the hints: they are
    /// the directory's, and a later `open` dials them again.
    #[test]
    fn closing_a_node_hangs_it_up_and_keeps_its_hints() {
        static CONTROL: ConnectControl = ConnectControl::new(true);
        static STORE: PeerStore = PeerStore::new();
        let mut m = ConnectManager::in_static_store(&CONTROL, FakeDialer::default(), &STORE);
        if !nodes_asked_for() {
            return;
        }
        declare(&mut m, NODE_A, "udp/10.0.0.9:7447");
        std::assert_eq!(m.open_node(NODE_A, 0), Ok(()));
        m.dialer()
            .up
            .push((String::from("udp/10.0.0.9:7447@"), Some(NODE_A)));
        m.tick(10);
        std::assert_eq!(m.node_states().next().unwrap().1, NodeState::Live);

        m.close_node(&NODE_A, 20);
        std::assert_eq!(
            m.dialer().hang_ups,
            vec![String::from("udp/10.0.0.9:7447@")]
        );
        std::assert_eq!(m.node_states().count(), 0);

        m.dialer().up.clear();
        std::assert_eq!(
            m.open_node(NODE_A, 30),
            Ok(()),
            "the hint outlived the node"
        );
        std::assert_eq!(m.dialer().dials_for.borrow().len(), 2);
    }
}
