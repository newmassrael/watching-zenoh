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
use wz_session_core::caps::{MAX_LOCATOR_LEN, MAX_STATIC_CONNECT};
use wz_session_core::connect_endpoints::{group_len, ConnectEndpoints, ConnectEntry, EndpointText};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
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
    fn classify(&self, _endpoint: &str) -> Result<(), DialRefused> {
        Ok(())
    }

    /// Start a session towards `endpoint`.
    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed>;

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

/// What names an endpoint to the machines: its text.
type Key = EndpointText;

/// How many dials can be in flight for the endpoints, with the ones an endpoint stopped
/// wanting while they ran: each of the endpoints dials once at a time.
const DIALS: usize = 2 * MAX_STATIC_CONNECT;

type Planner = PeerPlanner<Key, u64, MAX_STATIC_CONNECT, DIALS>;

/// The machines of a manager's peers, in a table of their own.
///
/// One connection machine per peer is some 930 bytes on the target (`size_of` of its engine, read
/// off a `thumbv7m-none-eabi` build: two event queues, the delayed-send ring and the rest of the
/// runtime's engine, none of which this machine uses), so the table of `MAX_STATIC_CONNECT`
/// of them, with the planner's tables beside it, is some 10 KB. That does not belong in the
/// manager, which is a local of the node's loop and sits on the stack of the thread that runs it.
/// It is a type of its own so that it can be declared where the node's other big tables are, in a
/// `static` whose initial value is all zero bytes (`slot_node::NodeStorage`), and so that a
/// manager holds only a reference to it.
///
/// A critical section guards it, as the crate's other shared state is (`ConnectControl`): the
/// node is driven by one cooperative loop, which is the only thing that reaches it, and the guard
/// makes that a property the type has and not a rule a caller keeps.
pub struct PeerStore {
    planner: critical_section::Mutex<core::cell::RefCell<Planner>>,
}

impl PeerStore {
    /// An empty store: no peer held. `const`, so a `static` can be one.
    pub const fn new() -> Self {
        Self {
            planner: critical_section::Mutex::new(core::cell::RefCell::new(Planner::new())),
        }
    }

    /// Run `f` on the planner.
    fn with<R>(&self, f: impl FnOnce(&mut Planner) -> R) -> R {
        critical_section::with(|cs| f(&mut self.planner.borrow_ref_mut(cs)))
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
/// one endpoint. Room for one more of each, so that a count is never the reason an action is
/// lost.
type Actions = FixedVec<PeerAction<Key, u64, Key>, 6>;

/// A session an endpoint holds, with the face the planner knows it as.
struct Held<S> {
    face: u64,
    session: S,
    /// Whether the endpoint's machine has been told the session is up.
    up: bool,
}

/// The moment an endpoint's next dial is due, and which arming of its timer that is.
#[derive(Clone, Copy)]
struct Due {
    generation: u64,
    at_ms: u64,
}

/// One endpoint of the list, in the order the list named it.
struct Row<S> {
    entry: ConnectEntry,
    /// One locator of a group of several: one session over several links, which this node's
    /// session cannot hold, so it has no candidate.
    multi_link: bool,
    held: Option<Held<S>>,
    due: Option<Due>,
}

/// The endpoints a manager holds, one row each. The list a host writes is itself
/// held in `MAX_STATIC_CONNECT` rows (`ConnectEndpoints`), so no list can name more
/// endpoints than this table has rows: the table is bounded by the same number that
/// bounds what feeds it, and a manager holds no row it was not told of. The backing
/// is the profile's (`BoundedVec`): the growable one where there is a heap, a fixed
/// table of that many rows under `bounded-heapless`, where a row past the bound could
/// only be a defect and is hung up and refused rather than grown (`reconcile`).
type Rows<S> = BoundedVec<Row<S>, MAX_STATIC_CONNECT>;

/// The retry schedule of each endpoint that is in an outage.
type Periods = BoundedVec<(Key, RetryPeriod), MAX_STATIC_CONNECT>;

/// What this profile answers for the planner.
struct Ports<'a, D: Dialer> {
    dialer: &'a D,
    rows: &'a Rows<D::Session>,
    periods: &'a mut Periods,
    policy: RetryPolicy,
}

impl<D: Dialer> Ports<'_, D> {
    /// The row of `key`.
    fn row(&self, key: &Key) -> Option<&Row<D::Session>> {
        self.rows.iter().find(|row| row.entry.endpoint == *key)
    }
}

impl<D: Dialer> PeerPorts<Key> for Ports<'_, D> {
    type Target = Key;

    /// The endpoint itself, unless this build cannot dial it: a peer with no candidate.
    fn dialable(&self, key: &Key) -> Option<Key> {
        let row = self.row(key)?;
        if row.multi_link || self.dialer.classify(key).is_err() {
            return None;
        }
        Some(key.clone())
    }

    fn retry_wait_ms(&mut self, key: &Key) -> u64 {
        if let Some((_, period)) = self.periods.iter_mut().find(|(k, _)| k == key) {
            return period.next_ms();
        }
        let mut period = self.policy.period();
        let wait = period.next_ms();
        // A table of as many rows as there are endpoints holds every endpoint in an outage; an
        // endpoint it could not hold would start from the first wait again.
        let _ = self.periods.push((key.clone(), period));
        wait
    }

    fn retry_restart(&mut self, key: &Key) {
        self.periods.retain(|(k, _)| k != key);
    }
}

/// Keeps a node's sessions in step with its [`EndpointSource`].
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
        self.rows.iter().map(|row| {
            let state = match self.store.get().with(|p| p.state(&row.entry.endpoint)) {
                Some(PeerConnectionState::NoLocator) => SlotState::Refused(self.refusal(row)),
                Some(PeerConnectionState::Backoff) => SlotState::Waiting {
                    at_ms: row.due.map_or(0, |due| due.at_ms),
                },
                // The manager tells a machine only that a session came up or that a dial
                // failed, so no other refusal is a state an endpoint is in.
                _ => SlotState::Live,
            };
            (row.entry.as_str(), state)
        })
    }

    /// R2834 — the sessions this manager holds right now, with the endpoint
    /// each was dialled for, in the list's order. A session is here from its
    /// dial until the manager sees it end, so it may still be handshaking; a
    /// caller that reports sessions asks each one whether it is established.
    pub fn sessions(&self) -> impl Iterator<Item = (&str, &D::Session)> + '_ {
        self.rows.iter().filter_map(|row| {
            row.held
                .as_ref()
                .map(|held| (row.entry.as_str(), &held.session))
        })
    }

    /// Why this build has no candidate for `row`'s endpoint.
    fn refusal(&self, row: &Row<D::Session>) -> DialRefused {
        if row.multi_link {
            return DialRefused::MultiLinkGroup;
        }
        // The endpoint is refused by the dialer when it is refused at all; a refusal the
        // dialer no longer gives (it was a group the list has since split) falls back to the
        // one an unreadable endpoint is.
        self.dialer
            .classify(&row.entry.endpoint)
            .err()
            .unwrap_or(DialRefused::Unsupported)
    }

    /// Advance to `now_ms`: reconcile a new list, notice sessions that came up or ended, and
    /// dial what is due.
    pub fn tick(&mut self, now_ms: u64) {
        if self.generation != Some(self.control.generation()) {
            let (generation, list) = self.control.endpoints();
            self.reconcile(&list, now_ms);
            self.generation = Some(generation);
        }
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
        let mut actions = self.ask(call);
        let mut failed: FixedVec<u64, 6> = FixedVec::new();
        loop {
            self.take(actions, now_ms, &mut failed);
            let Some(id) = failed.pop() else {
                return;
            };
            // The turn after a failed dial asks for no dial, so the list only shrinks.
            actions = self.ask(|planner, ports, next_id, emit| {
                planner.dial_ended(id, DialEnd::Failed, ports, next_id, emit);
            });
        }
    }

    /// One call of the planner against this profile's ports, and what it asked for.
    fn ask(
        &mut self,
        call: impl FnOnce(&mut Planner, &mut Ports<'_, D>, &mut u64, &mut dyn FnMut(Action)),
    ) -> Actions {
        let mut actions = Actions::new();
        let mut ports = Ports {
            dialer: &self.dialer,
            rows: &self.rows,
            periods: &mut self.periods,
            policy: self.policy,
        };
        let next_id = &mut self.next_id;
        self.store.get().with(|planner| {
            call(planner, &mut ports, next_id, &mut |action| {
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
                PeerAction::Dial { id, key, target } => match self.dialer.dial(&target) {
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

    fn row_mut(&mut self, key: &Key) -> Option<&mut Row<D::Session>> {
        self.rows.iter_mut().find(|row| row.entry.endpoint == *key)
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
        let mut due: FixedVec<(Key, u64), MAX_STATIC_CONNECT> = FixedVec::new();
        for row in self.rows.iter_mut() {
            if let Some(timer) = row.due {
                if now_ms >= timer.at_ms {
                    row.due = None;
                    // At most one timer per row, and the table has a row each.
                    let _ = due.push((row.entry.endpoint.clone(), timer.generation));
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
        let named = |key: &Key| {
            list.iter()
                .any(|entry| dialable(entry) && entry.endpoint == *key)
        };

        // Hang up what the list no longer names: stop the machine (a session it holds is
        // hung up by the close that asks for), then hang up what is still held (a session
        // still handshaking has no face the machine holds), and forget the endpoint.
        let mut gone: FixedVec<Key, MAX_STATIC_CONNECT> = FixedVec::new();
        for row in self.rows.iter() {
            if !named(&row.entry.endpoint) {
                // One row per endpoint, and the table has as many rows as this holds.
                let _ = gone.push(row.entry.endpoint.clone());
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
            self.store.get().with(|planner| planner.forget(&key));
            self.periods.retain(|(k, _)| *k != key);
            self.rows.retain(|row| row.entry.endpoint != key);
        }

        // A new endpoint is due now, and a refused one is given another chance, since a
        // rewrite is what could change it. R2841 — upstream opens a group of several
        // locators as ONE transport over all its locators (`allOf`, the only strategy its
        // runtime implements); an MCU session holds one link, so each is refused by name
        // rather than dialled as separate sessions to what is one peer.
        for entry in list.iter().filter(|e| dialable(e)) {
            let multi_link = entry.group.is_some_and(|g| group_len(list, g.index) > 1);
            let key = entry.endpoint.clone();
            let retry = match self.row_mut(&key) {
                Some(row) => {
                    row.multi_link = multi_link;
                    true
                }
                None => {
                    let row = Row {
                        entry: entry.clone(),
                        multi_link,
                        held: None,
                        due: None,
                    };
                    // The list holds as many entries as this table has rows, so a row always
                    // fits; a row that did not could only be a defect.
                    self.rows.push(row).is_ok()
                }
            };
            if !retry {
                continue;
            }
            // `open` of an endpoint already held or being reached changes nothing; one its
            // machine refused resolves again.
            let state = self.store.get().with(|planner| planner.state(&key));
            if state == Some(PeerConnectionState::NoLocator) || state.is_none() {
                self.drive(now_ms, |planner, ports, next_id, emit| {
                    let _ = planner.open(key, ports, next_id, emit);
                });
            }
        }

        // Keep the list's order.
        let mut kept: BoundedVec<Option<Row<D::Session>>, MAX_STATIC_CONNECT> = BoundedVec::new();
        for row in core::mem::take(&mut self.rows) {
            let _ = kept.push(Some(row));
        }
        for entry in list.iter().filter(|e| dialable(e)) {
            let held = kept
                .iter()
                .position(|row| {
                    row.as_ref()
                        .is_some_and(|row| row.entry.endpoint == entry.endpoint)
                })
                .and_then(|at| kept[at].take());
            if let Some(row) = held {
                let _ = self.rows.push(row);
            }
        }
    }
}

type Action = PeerAction<Key, u64, Key>;

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
    }

    impl Dialer for FakeDialer {
        type Session = String;

        fn classify(&self, endpoint: &str) -> Result<(), DialRefused> {
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
}
