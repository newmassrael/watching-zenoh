// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node's state and its admin GET with no allocator (fixed-memory step
//! S9b, `session-slot` profile).
//!
//! [`crate::admin_status`] answers upstream's admin GET from `String`s and `Vec`s: a
//! node holds its peers as owned rows, clones them out of a lock on every GET,
//! builds a `String` per leg and a `String` identity, and stages each reply as an
//! owned record. This module is the same answer with every one of those in fixed
//! storage, so that a node on the slot profile answers a GET and allocates nothing:
//!
//! - [`FixedNodeIdentity`]: who the node is, built once from `&str`s into rows of
//!   fixed width (`IdentityRefused` names what did not fit, at startup, where it
//!   can be fixed, not at the first GET);
//! - [`FixedNodeStatus`]: the sessions and the endpoint statuses the node reports,
//!   [`FixedAdminSession`] rows in a table of the pool's session count. A row that
//!   does not fit is refused and COUNTED ([`StatusRefusals`]), never cut or
//!   silently left out;
//! - [`AdminHost`]: the node's reply scratch ([`AdminReplyArena`], sized by the
//!   deploy file's `admin_reply_bytes`) behind the node's lock;
//! - [`host_admin_queryable_fixed`]: registers the admin queryable. A GET renders
//!   each leg straight from the rows, with no clone of them, into the arena, and
//!   the reply is staged in the asking session's stage: a leg that does not fit is
//!   refused, counted and answered to the querier as a typed error.
//!
//! What writes [`FixedNodeStatus`] on a slot image is the admin node shell (step
//! S9c, `crate::admin_status::NodeStatus`'s writer today); it gives the rows as
//! [`wz_admin::adminspace::AdminSessionRef`] views of whatever it keeps.
//!
//! # The lock
//!
//! The status, the arena and the busy count live behind one critical section of the
//! runtime's (`wz_runtime_coop::cs`), as `crate::admin_status::NodeStatus` does, and a
//! GET holds it for the whole answer: the legs are rendered from the rows where they
//! lie, which is what removes the clone. On a single-core cooperative runtime nothing
//! else contends for it except the shell's own `set_sessions`, which runs between
//! GETs; the interrupt-off time of one answer has NOT been measured on a board.

use core::cell::{Cell, RefCell};

use wz_admin::admin_reply::{AdminReplyArena, AdminReplyRefusals};
use wz_admin::adminspace::{
    write_admin_queryable_key, AdminLegEncoding, AdminLinkList, AdminLinkWeight, AdminNodeFacts,
    AdminSessionRef,
};
use wz_runtime_coop::cs::Mutex;
use wz_session_core::bounded::{BoundedVec, Storage};
use wz_session_core::caps;
#[cfg(feature = "lifecycle-verbs")]
use wz_session_core::lifecycle_wire::VerbKey;
use wz_session_core::lifecycle_wire::{write_verb_list, OpenKey, OPEN_VERB};
use wz_session_core::locality::Locality;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{FnQuerySink, QueryView, ReplyOut};
use wz_session_core::registry_error::RegisterError;
use wz_session_core::slot_observer::{NoSink, ObserverSinks, RegistryTables};
use wz_session_core::text_out::{FixedText, TextOut};

use crate::node_opening::open_verdict;
use wz_session_core::lifecycle_monitor::Asker;
use wz_session_core::sealed_command::SealRefused;
#[cfg(feature = "lifecycle-verbs")]
use wz_session_core::sealed_command::{claim, Claimed, SealVerifier, SealedNode};

use crate::admin_status::{
    write_connect_status, ConfigView, ConnectStatusSource, DialStatus, CONNECT_STATUS_TAIL,
};

/// Bytes of a zid in zenoh hex form: up to 16 bytes, so 32 digits.
const ZID_TEXT_BYTES: usize = 32;
/// Bytes of a role string: the longest is `router`.
const ROLE_TEXT_BYTES: usize = 8;
/// Bytes of a region name an admin row carries.
const REGION_TEXT_BYTES: usize = 16;
/// Bytes of the version string a node reports.
const VERSION_TEXT_BYTES: usize = 32;

/// A locator or endpoint text, as wide as every other locator in the stack.
type LocatorText = FixedText<{ caps::MAX_LOCATOR_LEN }>;

pub use crate::node_opening::{NoOpening, NodeOpening};

/// The one [`NoOpening`] a node without verbs hands its queryable.
static NO_OPENING: NoOpening = NoOpening;

/// What a node binds of the in-band lifecycle verbs, as its admin queryable is typed by it
/// (decision D7: whether and which verbs a node serves in band is a type, so a node that binds
/// none holds none of their code).
///
/// A node that binds only the open verb is any [`NodeOpening`] (`NoOpening` binds none), and a
/// node that binds all four is a `Verbs` around a `StoreNode` over the store of its connect manager
/// (`lifecycle-verbs`). Either answers the capability query in the verbs it has and each verb it
/// has in the documents the heap profile's queries use.
pub trait InBand: Sync + 'static {
    /// Whether the node binds any in-band verb. `false` only for [`NoOpening`].
    const BOUND: bool = true;

    /// Serve the lifecycle legs of `query`: the capability document, which any key that reaches
    /// it is answered, and the verb the key names when it is a literal key of this node.
    ///
    /// Out of line in each implementation: it runs inside the admin answer, which is under every
    /// receive of the node, and a node that binds no verb should not carry its frame there.
    fn serve<const BODY: usize>(
        &self,
        arena: &mut AdminReplyArena<BODY>,
        query: &dyn QueryView,
        out: &mut dyn ReplyOut,
        zid_hex: &str,
        whatami: &str,
    );
}

impl<O: NodeOpening + Sync + 'static> InBand for O {
    const BOUND: bool = <O as NodeOpening>::BOUND;

    fn serve<const BODY: usize>(
        &self,
        arena: &mut AdminReplyArena<BODY>,
        query: &dyn QueryView,
        out: &mut dyn ReplyOut,
        zid_hex: &str,
        whatami: &str,
    ) {
        serve_open(arena, query, out, zid_hex, whatami, self);
    }
}

/// A node that binds all four verbs in band: the legs of `open`, `close`, `reset` and `status`,
/// each decided by `lifecycle_node::lifecycle_verdict` over the node it wraps. The node of a
/// fixed-memory image is `Verbs(StoreNode::new(&STORE, permits))`; the wrapper is what says that
/// the node binds the verbs in band and not only out of band (decision D7).
#[cfg(feature = "lifecycle-verbs")]
pub struct Verbs<N>(pub N);

#[cfg(feature = "lifecycle-verbs")]
impl<N: wz_session_core::lifecycle_node::LifecycleNode + Sync + 'static> InBand for Verbs<N> {
    fn serve<const BODY: usize>(
        &self,
        arena: &mut AdminReplyArena<BODY>,
        query: &dyn QueryView,
        out: &mut dyn ReplyOut,
        zid_hex: &str,
        whatami: &str,
    ) {
        // An admin node verifies no sealed command (decision D17): one it is sent is refused.
        serve_verbs(arena, query, out, zid_hex, whatami, &self.0, None);
    }
}

/// `s` in a fixed text of `N` bytes, or `None` if it does not fit.
fn fixed<const N: usize>(s: &str) -> Option<FixedText<N>> {
    let mut text = FixedText::new();
    text.push_str(s);
    (!text.overflowed()).then_some(text)
}

/// One link of a [`FixedAdminSession`].
pub struct FixedAdminLink {
    src: LocatorText,
    dst: LocatorText,
}

/// The links of a [`FixedAdminSession`], read by the `local_data` writer as the
/// AP's `Vec<AdminLink>` is.
pub struct FixedLinks(BoundedVec<FixedAdminLink, { caps::MAX_ADMIN_SESSION_LINKS }>);

impl AdminLinkList for FixedLinks {
    fn link_count(&self) -> usize {
        self.0.len()
    }

    fn link(&self, index: usize) -> Option<(&str, &str)> {
        self.0
            .get(index)
            .map(|link| (link.src.prefix(), link.dst.prefix()))
    }
}

/// Why a session row was not taken into [`FixedNodeStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowRefused {
    /// A text of the row (zid, role, region, a link's locator) is wider than its
    /// fixed field.
    TextTooLong,
    /// The row lists more links than [`caps::MAX_ADMIN_SESSION_LINKS`].
    TooManyLinks,
}

/// One `sessions[]` row in fixed storage: [`wz_admin::adminspace::AdminSession`]
/// with every text a fixed field.
pub struct FixedAdminSession {
    peer_zid_hex: FixedText<ZID_TEXT_BYTES>,
    whatami: Option<FixedText<ROLE_TEXT_BYTES>>,
    links: FixedLinks,
    shm: bool,
    weight: Option<AdminLinkWeight>,
    region: Option<FixedText<REGION_TEXT_BYTES>>,
}

impl FixedAdminSession {
    /// Copy a borrowed row into fixed storage, or say why it does not fit.
    pub fn from_view(view: &AdminSessionRef<'_>) -> Result<Self, RowRefused> {
        let too_long = RowRefused::TextTooLong;
        let mut links = BoundedVec::new();
        for index in 0..view.links.link_count() {
            let Some((src, dst)) = view.links.link(index) else {
                break;
            };
            let link = FixedAdminLink {
                src: fixed(src).ok_or(too_long)?,
                dst: fixed(dst).ok_or(too_long)?,
            };
            links.push(link).map_err(|_| RowRefused::TooManyLinks)?;
        }
        Ok(Self {
            peer_zid_hex: fixed(view.peer_zid_hex).ok_or(too_long)?,
            whatami: match view.whatami {
                Some(role) => Some(fixed(role).ok_or(too_long)?),
                None => None,
            },
            links: FixedLinks(links),
            shm: view.shm,
            weight: view.weight,
            region: match view.region {
                Some(region) => Some(fixed(region).ok_or(too_long)?),
                None => None,
            },
        })
    }

    /// This row as the `local_data` writer reads it.
    pub fn view(&self) -> AdminSessionRef<'_> {
        AdminSessionRef {
            peer_zid_hex: self.peer_zid_hex.prefix(),
            whatami: self.whatami.as_ref().map(FixedText::prefix),
            links: &self.links,
            shm: self.shm,
            weight: self.weight,
            region: self.region.as_ref().map(FixedText::prefix),
        }
    }
}

/// One endpoint status row: the endpoint text and where it stands.
pub struct FixedEndpointStatus {
    endpoint: LocatorText,
    status: DialStatus,
}

/// What a [`FixedNodeStatus`] refused since it was made, by why.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StatusRefusals {
    /// Session rows past the table's capacity.
    pub sessions_full: u32,
    /// Session rows refused by the row itself ([`RowRefused`]).
    pub session_rows_refused: u32,
    /// Endpoint rows past [`wz_session_core::caps::MAX_STATIC_CONNECT`].
    pub endpoints_full: u32,
    /// Endpoint rows wider than a locator.
    pub endpoint_text_too_long: u32,
}

struct State<const SESSIONS: usize> {
    sessions: BoundedVec<FixedAdminSession, SESSIONS>,
    endpoints: BoundedVec<FixedEndpointStatus, { caps::MAX_STATIC_CONNECT }>,
    permit_read: bool,
    refusals: StatusRefusals,
}

/// The state a node reports in its admin GET, in fixed storage, kept where both the
/// shell that updates it and the queryable that reads it reach it.
///
/// `SESSIONS` is the number of session rows: the pool's session count
/// (`wz_session_core::session_slot_pool_mcu::SLOT_COUNT`), since a node holds no
/// more sessions than its pool has slots.
pub struct FixedNodeStatus<const SESSIONS: usize> {
    state: Mutex<RefCell<State<SESSIONS>>>,
}

impl<const SESSIONS: usize> FixedNodeStatus<SESSIONS> {
    /// No sessions yet. `permit_read` is the node's `adminspace.permissions.read`;
    /// upstream's default is `true`. `const`, so firmware can place it in a `static`.
    pub const fn new(permit_read: bool) -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                sessions: BoundedVec::new(),
                endpoints: BoundedVec::new(),
                permit_read,
                refusals: StatusRefusals {
                    sessions_full: 0,
                    session_rows_refused: 0,
                    endpoints_full: 0,
                    endpoint_text_too_long: 0,
                },
            })),
        }
    }

    /// Replace the sessions the node reports with `rows`. A row that does not fit
    /// the table, or whose text does not fit its fields, is left out and COUNTED.
    pub fn set_sessions<'a>(&self, rows: impl IntoIterator<Item = AdminSessionRef<'a>>) {
        self.set_session_rows(
            rows.into_iter()
                .map(|row| FixedAdminSession::from_view(&row)),
        );
    }

    /// [`Self::set_sessions`] for rows already copied into fixed storage, each as the
    /// result of copying it (a row that did not fit arrives as its refusal and is
    /// COUNTED, not left out silently). What a node that reads each session's row
    /// through a lend (`SessionAdminRow::with_admin_session`) gives it: the borrowed
    /// row cannot leave the call that lends it, so the copy is made there and the
    /// copies are given here, outside any lock.
    pub fn set_session_rows(
        &self,
        rows: impl IntoIterator<Item = Result<FixedAdminSession, RowRefused>>,
    ) {
        wz_runtime_coop::cs::with(|cs| {
            let mut state = self.state.borrow(cs).borrow_mut();
            state.sessions.clear();
            for row in rows {
                match row {
                    Ok(row) => {
                        if state.sessions.push(row).is_err() {
                            state.refusals.sessions_full =
                                state.refusals.sessions_full.saturating_add(1);
                        }
                    }
                    Err(_) => {
                        state.refusals.session_rows_refused =
                            state.refusals.session_rows_refused.saturating_add(1);
                    }
                }
            }
        });
    }

    /// Replace the endpoint statuses the `status/connect` leg reports, each as
    /// `(endpoint, status)`; refusals are counted as for sessions.
    pub fn set_endpoints<'a>(&self, rows: impl IntoIterator<Item = (&'a str, DialStatus)>) {
        wz_runtime_coop::cs::with(|cs| {
            let mut state = self.state.borrow(cs).borrow_mut();
            state.endpoints.clear();
            for (endpoint, status) in rows {
                let Some(endpoint) = fixed(endpoint) else {
                    state.refusals.endpoint_text_too_long =
                        state.refusals.endpoint_text_too_long.saturating_add(1);
                    continue;
                };
                if state
                    .endpoints
                    .push(FixedEndpointStatus { endpoint, status })
                    .is_err()
                {
                    state.refusals.endpoints_full = state.refusals.endpoints_full.saturating_add(1);
                }
            }
        });
    }

    /// Change the read permit at runtime, as upstream's
    /// `adminspace/permissions/read` does.
    pub fn set_read_permit(&self, permit: bool) {
        wz_runtime_coop::cs::with(|cs| self.state.borrow(cs).borrow_mut().permit_read = permit);
    }

    /// How many session rows the node reports now.
    pub fn session_count(&self) -> usize {
        wz_runtime_coop::cs::with(|cs| self.state.borrow(cs).borrow().sessions.len())
    }

    /// What this status refused since it was made, by why.
    pub fn refusals(&self) -> StatusRefusals {
        wz_runtime_coop::cs::with(|cs| self.state.borrow(cs).borrow().refusals)
    }
}

/// Which input [`FixedNodeIdentity::new`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRefused {
    /// The zid is wider than a zenoh id (32 hex digits).
    Zid,
    /// The version string is wider than its field (32 bytes).
    Version,
    /// A locator is wider than [`caps::MAX_LOCATOR_LEN`].
    Locator,
    /// More locators than [`caps::MAX_ADMIN_LOCATORS`].
    TooManyLocators,
}

/// Who the node is, as its `local_data` reports it, in fixed storage.
pub struct FixedNodeIdentity {
    zid_hex: FixedText<ZID_TEXT_BYTES>,
    whatami: &'static str,
    version: FixedText<VERSION_TEXT_BYTES>,
    locators: BoundedVec<LocatorText, { caps::MAX_ADMIN_LOCATORS }>,
}

impl FixedNodeIdentity {
    /// The identity of a node with this zid (zenoh hex form), role, version and
    /// listening locators, or what does not fit.
    pub fn new(
        zid_hex: &str,
        whatami: &'static str,
        version: &str,
        locators: &[&str],
    ) -> Result<Self, IdentityRefused> {
        let mut rows = BoundedVec::new();
        for locator in locators {
            let text = fixed(locator).ok_or(IdentityRefused::Locator)?;
            rows.push(text)
                .map_err(|_| IdentityRefused::TooManyLocators)?;
        }
        Ok(Self {
            zid_hex: fixed(zid_hex).ok_or(IdentityRefused::Zid)?,
            whatami,
            version: fixed(version).ok_or(IdentityRefused::Version)?,
            locators: rows,
        })
    }
}

/// The reply scratch of a node's admin queryable, and how often it found the
/// scratch taken. One per node; see [`AdminReplyArena`] for why that is enough.
///
/// `BODY` is the deploy file's `admin_reply_bytes`.
pub struct AdminHost<const BODY: usize = { caps::MAX_ADMIN_REPLY_BYTES }> {
    arena: Mutex<RefCell<AdminReplyArena<BODY>>>,
    busy: Mutex<Cell<u32>>,
}

impl<const BODY: usize> AdminHost<BODY> {
    /// A host with an empty arena. `const`, so firmware can place it in a `static`.
    pub const fn new() -> Self {
        Self {
            arena: Mutex::new(RefCell::new(AdminReplyArena::new())),
            busy: Mutex::new(Cell::new(0)),
        }
    }

    /// What the arena refused since it was made, by why: legs too large for the
    /// buffer, keys too long, replies the session's stage refused.
    pub fn refusals(&self) -> AdminReplyRefusals {
        wz_runtime_coop::cs::with(|cs| self.arena.borrow(cs).borrow().refusals())
    }

    /// How many GETs found the arena in use and were not answered. A handler cannot
    /// re-enter the arena on a cooperative runtime, so a count above zero is a
    /// defect, and is reported rather than papered over.
    pub fn busy_refusals(&self) -> u32 {
        wz_runtime_coop::cs::with(|cs| self.busy.borrow(cs).get())
    }
}

impl<const BODY: usize> Default for AdminHost<BODY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Register the node's admin queryable on `queryables`, answering from `status` in
/// `host`'s arena with nothing allocated per GET.
///
/// The legs and their gates are those of
/// `crate::admin_status::host_admin_queryable`: every upstream leg through
/// [`AdminReplyArena::answer`], the `config` leg from `config` (`{}` when `None`),
/// and, with `connect`, the connection status leg `@/<zid>/<whatami>/status/connect`.
/// A denied read answers nothing and the query is still terminated. The registration
/// allocates nothing: the sink is a closed [`AdminQuerySink`] the registry holds inline.
///
/// `Err` when the registry's queryable table refuses the registration: full, or the
/// pattern past `caps::MAX_KEYEXPR_BYTES`; the node must then say it answers no
/// admin GET, not run as if it did.
pub fn host_admin_queryable_fixed<const BODY: usize, const SESSIONS: usize>(
    queryables: &mut QueryableRegistry<AdminQuerySink<BODY, SESSIONS>>,
    identity: FixedNodeIdentity,
    status: &'static FixedNodeStatus<SESSIONS>,
    host: &'static AdminHost<BODY>,
    config: Option<&'static (dyn ConfigView + Sync)>,
    connect: Option<&'static (dyn ConnectStatusSource + Sync)>,
) -> Result<(), RegisterError> {
    host_admin_queryable_fixed_with_open(
        queryables,
        identity,
        status,
        host,
        config,
        connect,
        &NO_OPENING,
    )
}

/// [`host_admin_queryable_fixed`], and with an `open` the node's lifecycle open query too:
/// `GET @/<zid>/<whatami>/session/open/<peer-zid>` asks the node to hold the peer, and
/// `GET @/<zid>/<whatami>/session/verbs` says the node has bound it, in the words and the
/// documents the heap profile's lifecycle queries use (`wz_session_core::lifecycle_wire`).
///
/// The open query is answered only for a literal key that names this node, its role and one
/// peer: a pattern is never a target. Nothing else of the lifecycle is bound on this profile,
/// so the capability document lists `open` and no other verb. The opener's type is the node's
/// transport (decision D7): [`NoOpening`] binds none, any other binds the in-band verbs.
#[allow(clippy::too_many_arguments)]
pub fn host_admin_queryable_fixed_with_open<const BODY: usize, const SESSIONS: usize, O: InBand>(
    queryables: &mut QueryableRegistry<AdminQuerySink<BODY, SESSIONS, O>>,
    identity: FixedNodeIdentity,
    status: &'static FixedNodeStatus<SESSIONS>,
    host: &'static AdminHost<BODY>,
    config: Option<&'static (dyn ConfigView + Sync)>,
    connect: Option<&'static (dyn ConnectStatusSource + Sync)>,
    open: &'static O,
) -> Result<(), RegisterError> {
    let mut pattern: FixedText<{ caps::MAX_KEYEXPR_BYTES }> = FixedText::new();
    write_admin_queryable_key(&mut pattern, identity.zid_hex.prefix(), identity.whatami);
    let pattern = pattern
        .finish()
        .map_err(|_| RegisterError::KeyexprTooLong)?;
    let answer = FnQuerySink::new(
        AdminQueryState {
            identity,
            status,
            host,
            config,
            connect,
            open,
        },
        answer_admin_query::<BODY, SESSIONS, O>,
    );
    queryables
        .register_sink(pattern, Locality::Any, false, answer)
        .map(|_id| ())
}

/// What the node's admin queryable holds: its identity and the statics it answers from.
pub struct AdminQueryState<const BODY: usize, const SESSIONS: usize, O: InBand = NoOpening> {
    identity: FixedNodeIdentity,
    status: &'static FixedNodeStatus<SESSIONS>,
    host: &'static AdminHost<BODY>,
    config: Option<&'static (dyn ConfigView + Sync)>,
    connect: Option<&'static (dyn ConnectStatusSource + Sync)>,
    open: &'static O,
}

/// The sink of the node's admin queryable ([`host_admin_queryable_fixed`]): a closed
/// type, so the registry is typed by it and the registration allocates nothing. The opener
/// it is typed with defaults to [`NoOpening`], the node with no in-band verb.
pub type AdminQuerySink<const BODY: usize, const SESSIONS: usize, O = NoOpening> =
    FnQuerySink<AdminQueryState<BODY, SESSIONS, O>>;

/// The registrations of the admin node, as the sinks its observer is typed with
/// ([`wz_session_core::slot_observer::SlotObserverOf`]): the config-write subscriber
/// and the admin queryable, both closed, and no listener on a peer's declarations.
///
/// A node built without `adminspace-write` answers admin GETs and takes no config
/// write, as upstream's admin space does with its write permission off, so its
/// subscriber slot is [`NoSink`].
pub struct AdminSinks<const BODY: usize, const SESSIONS: usize, O: InBand = NoOpening>(
    core::marker::PhantomData<O>,
);

impl<const BODY: usize, const SESSIONS: usize, O: InBand> ObserverSinks
    for AdminSinks<BODY, SESSIONS, O>
{
    #[cfg(feature = "adminspace-write")]
    type Subscriber = crate::admin_host::ConnectWriteSink;
    #[cfg(not(feature = "adminspace-write"))]
    type Subscriber = NoSink;
    type SubscriberId = wz_session_core::pubsub::SubscriptionId;
    type QueryableId = wz_session_core::query::QueryableId;
    type LivelinessSubscriberId = u64;
    type Delivery = ();
    type Tables<P: Storage> =
        RegistryTables<Self::Subscriber, Self::Queryable, Self::LivelinessSubscriber, P>;
    type Queryable = AdminQuerySink<BODY, SESSIONS, O>;
    type LivelinessSubscriber = NoSink;
    type Declared = NoSink;
    type Undeclared = NoSink;
}

/// The lifecycle legs of a node that binds the open verb: the capability document, which any
/// key that reaches it is answered, and the open query, which only a literal key that names
/// this node, its role and one peer is.
///
/// Out of line: it runs inside the admin answer, which is under every receive of the node, and a
/// node that binds no opener should not carry its frame there.
#[inline(never)]
fn serve_open<const BODY: usize, O: NodeOpening>(
    arena: &mut AdminReplyArena<BODY>,
    query: &dyn QueryView,
    out: &mut dyn ReplyOut,
    zid_hex: &str,
    whatami: &str,
    opener: &O,
) {
    // The capability document says what the node KNOWS, not whether this caller may use it.
    let _ = arena.serve_leg(
        query,
        out,
        zid_hex,
        whatami,
        VERBS_TAIL,
        AdminLegEncoding::Json,
        |body| write_verb_list(body, &[OPEN_VERB]),
    );
    let key = query.keyexpr();
    let Some(parsed) = OpenKey::parse(key) else {
        return;
    };
    if parsed.node_zid != zid_hex || parsed.whatami != whatami {
        return;
    }
    // A node that binds only the open verb verifies no sealed command: a query that carries one is
    // refused by name and never judged as the link's commander (decision D17).
    if query.attachment().is_some() {
        if let Some(tail) = node_key_tail(key, zid_hex, whatami) {
            let _ = arena.serve_leg(
                query,
                out,
                zid_hex,
                whatami,
                tail,
                AdminLegEncoding::Json,
                |body| SealRefused::NotVerified.write_json(body),
            );
        }
        return;
    }
    // The commander is whom the link's key proved asks, or nobody shown (decision D12).
    let requester = query.requester();
    let verdict = open_verdict(
        opener,
        parsed.peer_zid,
        parsed.mode,
        Asker::query(requester.as_ref(), key),
    );
    // The key's own tail, `session/open/<peer>`: it follows `@/<zid>/<whatami>/`, which the
    // parse has just held to name this node. A reply the arena refuses is counted there; the
    // open has happened either way, as the heap profile's reply says.
    let Some(tail) = node_key_tail(key, zid_hex, whatami) else {
        return;
    };
    let _ = arena.serve_leg(
        query,
        out,
        zid_hex,
        whatami,
        tail,
        AdminLegEncoding::Json,
        |body| verdict.write_json(body),
    );
}

/// The lifecycle legs of a node that binds all four verbs: the capability document, and the verb a
/// literal key of this node names, decided by the one function every transport is decided by.
/// The key past `@/<zid>/<whatami>/`: the tail a reply names. `None` for a key that does not
/// name this node, which the caller's parse has already refused.
fn node_key_tail<'k>(key: &'k str, zid_hex: &str, whatami: &str) -> Option<&'k str> {
    key.strip_prefix("@/")?
        .strip_prefix(zid_hex)?
        .strip_prefix('/')?
        .strip_prefix(whatami)?
        .strip_prefix('/')
}

#[cfg(feature = "lifecycle-verbs")]
#[inline(never)]
fn serve_verbs<const BODY: usize, N: wz_session_core::lifecycle_node::LifecycleNode + ?Sized>(
    arena: &mut AdminReplyArena<BODY>,
    query: &dyn QueryView,
    out: &mut dyn ReplyOut,
    zid_hex: &str,
    whatami: &str,
    node: &N,
    seal: Option<&dyn SealVerifier>,
) {
    use wz_session_core::lifecycle_node::{lifecycle_verdict, Command, Verb};
    use wz_session_core::lifecycle_wire::{CLOSE_VERB, RESET_VERB, STATUS_VERB};
    // The capability document says what the node KNOWS, not whether this caller may use it: the
    // verbs the build compiled in, in the order the heap profile lists them.
    let _ = arena.serve_leg(
        query,
        out,
        zid_hex,
        whatami,
        VERBS_TAIL,
        AdminLegEncoding::Json,
        |body| {
            let words = [
                (Verb::Close, CLOSE_VERB),
                (Verb::Reset, RESET_VERB),
                (Verb::Status, STATUS_VERB),
                (Verb::Open, OPEN_VERB),
            ]
            .into_iter()
            .filter(|&(verb, _)| node.binds(verb))
            .map(|(_, word)| word);
            let mut bound: [&str; 4] = [""; 4];
            let mut count = 0;
            for (filled, (slot, word)) in (1..).zip(bound.iter_mut().zip(words)) {
                *slot = word;
                count = filled;
            }
            write_verb_list(body, bound.get(..count).unwrap_or_default());
        },
    );
    let key = query.keyexpr();
    let Some(parsed) = VerbKey::parse(key) else {
        return;
    };
    if parsed.node_zid != zid_hex || parsed.whatami != whatami {
        return;
    }
    let peer = parsed.peer_zid;
    // The commander is whom the link's key proved asks, or nobody shown (decision D12).
    let requester = query.requester();
    // A verb the build did not compile in is no query of this node's: nothing is replied, as for a
    // node that binds no opener.
    let (verb, command) = match parsed.verb {
        OPEN_VERB => {
            // The grammar admits no argument of an open but `passive` (VerbKey has read it).
            let Some(mode) =
                wz_session_core::lifecycle_wire::OpenMode::of_argument(parsed.generation)
            else {
                return;
            };
            (Verb::Open, Command::Open { peer, mode })
        }
        CLOSE_VERB => (Verb::Close, Command::Close { peer }),
        RESET_VERB => (
            Verb::Reset,
            Command::Reset {
                peer,
                generation: parsed.generation.unwrap_or(""),
            },
        ),
        STATUS_VERB => (Verb::Status, Command::Status { peer }),
        _ => return,
    };
    if !node.binds(verb) {
        return;
    }
    // The key's own tail, `session/<verb>/..`: it follows `@/<zid>/<whatami>/`, which the parse has
    // just held to name this node. A reply the arena refuses is counted there; the verb has
    // happened either way, as the heap profile's reply says.
    let Some(tail) = node_key_tail(key, zid_hex, whatami) else {
        return;
    };
    // A query that carries a sealed command is the commander's whose key signed it, verified,
    // held to this key and fresh before the monitor judges it, and its counter taken only on a
    // permit (decision D17); one that fails is refused by name and never judged as the link's.
    let claimed = claim(query.attachment(), &command, seal);
    let _ = arena.serve_leg(
        query,
        out,
        zid_hex,
        whatami,
        tail,
        AdminLegEncoding::Json,
        |body| match &claimed {
            Claimed::Channel => {
                lifecycle_verdict(node, command, Asker::query(requester.as_ref(), key), body);
            }
            Claimed::Sealed(sealed) => {
                lifecycle_verdict(
                    &SealedNode::new(node, sealed.admission()),
                    command,
                    Asker::sealed(sealed.commander(), key),
                    body,
                );
            }
            Claimed::Refused(refused) => refused.write_json(body),
        },
    );
}

/// The tail of the capability query, `@/<zid>/<whatami>/session/verbs`.
const VERBS_TAIL: &str = "session/verbs";

/// Bytes of the document one lifecycle verb is answered with on a client node: a status of a
/// peer with its machines is the longest, and the admin node of the kit answers the same
/// documents from an arena of this size (`deploy/zephyr-admin-node`, `AdminHost<1024>`). A
/// document past it is refused, counted ([`VerbLegs::refusals`]) and answered as a typed error.
#[cfg(feature = "client-verbs")]
pub const VERB_REPLY_BYTES: usize = 1024;

/// The in-band lifecycle verbs of a node that is not an admin node: a client of the slot
/// profile (`crate::slot_node`), whose queryables answer documents and cells, binds the four
/// verbs on one queryable more, `@/<zid>/<whatami>/session/**`, decided by the same function and
/// in the same documents as the admin node's ([`Verbs`]).
///
/// The commander of every verb is whom the key of the link the query arrived on proved
/// ([`QueryView::requester`], decision D12): the router's when the query came through one, the
/// asking node's own only on a secure session it holds with this node. A grant names a zid, so it
/// takes effect for the link that proves that zid, and for no node behind it.
///
/// `const`, so the image declares it in a `static` beside the node it wraps; the name is set once,
/// when the node knows its zid ([`Self::name`]), before the queryable is registered.
#[cfg(feature = "client-verbs")]
pub struct VerbLegs {
    node: &'static (dyn wz_session_core::lifecycle_node::LifecycleNode + Sync),
    host: AdminHost<VERB_REPLY_BYTES>,
    name: core::cell::UnsafeCell<VerbName>,
    named: Cell<bool>,
    seal: Cell<Option<&'static (dyn SealVerifier + Sync)>>,
}

/// Who the node is, as the verbs' keys name it, and the key the queryable is registered under.
#[cfg(feature = "client-verbs")]
struct VerbName {
    zid_hex: FixedText<ZID_TEXT_BYTES>,
    whatami: &'static str,
    pattern: FixedText<{ caps::MAX_KEYEXPR_BYTES }>,
}

// SAFETY: the profile's rule: one thread runs the program. The name is written once, by `name`,
// before the queryable that reads it is registered, and never after; the arena is behind its own
// lock.
#[cfg(feature = "client-verbs")]
unsafe impl Sync for VerbLegs {}

/// Why the verbs could not be named.
#[cfg(feature = "client-verbs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbNameRefused {
    /// The zid, or the key made of it, is longer than its fixed field.
    TooLong,
    /// The verbs were named before: a node names them once.
    Twice,
}

#[cfg(feature = "client-verbs")]
impl VerbLegs {
    /// The verbs `node` binds, unnamed.
    pub const fn new(
        node: &'static (dyn wz_session_core::lifecycle_node::LifecycleNode + Sync),
    ) -> Self {
        Self {
            node,
            host: AdminHost::new(),
            name: core::cell::UnsafeCell::new(VerbName {
                zid_hex: FixedText::new(),
                whatami: "",
                pattern: FixedText::new(),
            }),
            named: Cell::new(false),
            seal: Cell::new(None),
        }
    }

    /// Verify the sealed commands a query may carry with `verifier` (decision D17): such a query
    /// is judged for the commander whose key signed it, whatever link it came over. Once, before
    /// the queryable is registered; `false` when a verifier was given before, which stays. Until
    /// then every query that carries an attachment is refused by name.
    pub fn verify_sealed_with(&self, verifier: &'static (dyn SealVerifier + Sync)) -> bool {
        if self.seal.get().is_some() {
            return false;
        }
        self.seal.set(Some(verifier));
        true
    }

    /// Name the node the verbs are of, `@/<zid_hex>/<whatami>`, and hand back the key the
    /// queryable is registered and declared under, `@/<zid_hex>/<whatami>/session/**`. Once: the
    /// key is lent for the life of the program.
    pub fn name(
        &'static self,
        zid_hex: &str,
        whatami: &'static str,
    ) -> Result<&'static str, VerbNameRefused> {
        if self.named.get() {
            return Err(VerbNameRefused::Twice);
        }
        let mut zid: FixedText<ZID_TEXT_BYTES> = FixedText::new();
        zid.push_str(zid_hex);
        let mut pattern: FixedText<{ caps::MAX_KEYEXPR_BYTES }> = FixedText::new();
        wz_admin::adminspace::write_admin_leg_key(&mut pattern, zid_hex, whatami, "session/**");
        if zid.overflowed() || pattern.overflowed() {
            return Err(VerbNameRefused::TooLong);
        }
        // SAFETY: `named` is false, so nothing has read the name or been lent the key; one thread
        // runs the program.
        let name = unsafe { &mut *self.name.get() };
        *name = VerbName {
            zid_hex: zid,
            whatami,
            pattern,
        };
        self.named.set(true);
        // SAFETY: the name is never written again (`named` is now true), so the key lives, unmoved
        // and unchanged, for as long as the `static` does.
        Ok(unsafe { &*self.name.get() }.pattern.prefix())
    }

    /// The key the queryable is registered and declared under, once named.
    pub fn key(&'static self) -> Option<&'static str> {
        // SAFETY: named, so never written again.
        self.named
            .get()
            .then(|| unsafe { &*self.name.get() }.pattern.prefix())
    }

    /// The node's zid and role, once named.
    fn named(&self) -> Option<(&str, &'static str)> {
        if !self.named.get() {
            return None;
        }
        // SAFETY: named, so never written again.
        let name = unsafe { &*self.name.get() };
        Some((name.zid_hex.prefix(), name.whatami))
    }

    /// What the arena refused since it was made: documents past [`VERB_REPLY_BYTES`], keys too
    /// long, replies the session's stage refused.
    pub fn refusals(&self) -> AdminReplyRefusals {
        self.host.refusals()
    }

    /// Answer one query that reached the verbs' queryable: the capability document and the verb
    /// the key names, for the commander the link proved.
    pub fn answer(&self, query: &dyn QueryView, out: &mut dyn ReplyOut) {
        let Some((zid_hex, whatami)) = self.named() else {
            return;
        };
        wz_runtime_coop::cs::with(|cs| {
            let Ok(mut arena) = self.host.arena.borrow(cs).try_borrow_mut() else {
                let busy = self.host.busy.borrow(cs);
                busy.set(busy.get().saturating_add(1));
                return;
            };
            let seal = self.seal.get().map(|seal| seal as &dyn SealVerifier);
            serve_verbs(&mut arena, query, out, zid_hex, whatami, self.node, seal);
        });
    }
}

/// The verifier of the sealed commands a fixed-memory node is sent (decision D17): its ES256 (the
/// TLS library's, `wz_tls_mbedtls::es256::PsaEs256`), the `N` commanders its declaration grants
/// a verb to, and once the node has started, its zid and the freshness of their commands, in a
/// static behind the runtime's critical section. The commanders are the build's, so the window
/// has a slot for each of them and for no other key (decision D19).
#[cfg(feature = "sealed-commands")]
pub struct FixedSeal<E, const N: usize> {
    es256: E,
    commanders: [wz_session_core::lifecycle_node::Zid; N],
    state: Mutex<RefCell<Option<SealState<N>>>>,
}

/// What a started [`FixedSeal`] holds: the node's zid and the freshness of its commanders.
#[cfg(feature = "sealed-commands")]
struct SealState<const N: usize> {
    node: wz_session_core::lifecycle_node::Zid,
    fresh: wz_session_core::sealed_command::seal::Freshness<
        [wz_session_core::sealed_command::seal::Slot; N],
    >,
}

#[cfg(feature = "sealed-commands")]
impl<E, const N: usize> FixedSeal<E, N> {
    /// A verifier that verifies with `es256` the commands of `commanders`, the distinct zids the
    /// declaration grants a verb to, and verifies nothing until it is started. `const`, so the
    /// image declares it in a `static`.
    pub const fn new(es256: E, commanders: [wz_session_core::lifecycle_node::Zid; N]) -> Self {
        Self {
            es256,
            commanders,
            state: Mutex::new(RefCell::new(None)),
        }
    }

    /// Start verifying for the node `node` after a start of the node that remembers no counter:
    /// a commander's first command carries `echo`, drawn from the node's entropy at this start
    /// (RFC 8613, appendix B.1.2). Once: `false` if it was started before, which stays.
    pub fn start(&self, node: wz_session_core::lifecycle_node::Zid, echo: [u8; 16]) -> bool {
        use wz_session_core::sealed_command::seal::{Freshness, ReplayWindow, Slot};
        let fresh = Freshness::started(
            ReplayWindow::granting(self.commanders.map(Slot::granted)),
            echo,
        );
        wz_runtime_coop::cs::with(|cs| {
            let Ok(mut state) = self.state.borrow(cs).try_borrow_mut() else {
                return false;
            };
            if state.is_some() {
                return false;
            }
            *state = Some(SealState { node, fresh });
            true
        })
    }

    /// The last counter taken from `commander` since the start; `None` before the start, for a
    /// commander none was taken from, and for a key no grant names.
    pub fn last(&self, commander: &wz_session_core::lifecycle_node::Zid) -> Option<u64> {
        wz_runtime_coop::cs::with(|cs| {
            let state = self.state.borrow(cs).try_borrow().ok()?;
            state.as_ref()?.fresh.window().last(commander)
        })
    }
}

#[cfg(feature = "sealed-commands")]
impl<E: wz_session_core::sealed_command::seal::Es256, const N: usize> SealVerifier
    for FixedSeal<E, N>
{
    fn verify(
        &self,
        bytes: &[u8],
    ) -> Result<wz_session_core::sealed_command::seal::Verified, SealRefused> {
        let node = wz_runtime_coop::cs::with(|cs| {
            let state = self.state.borrow(cs).try_borrow().ok()?;
            state.as_ref().map(|state| state.node)
        })
        .ok_or(SealRefused::NotVerified)?;
        wz_session_core::sealed_command::seal::verify_sealed(bytes, &node, &self.es256)
            .map_err(SealRefused::from)
    }

    fn check(
        &self,
        sealed: &wz_session_core::sealed_command::seal::Sealed,
    ) -> Result<(), SealRefused> {
        wz_runtime_coop::cs::with(|cs| {
            let state = self
                .state
                .borrow(cs)
                .try_borrow()
                .map_err(|_| SealRefused::NotVerified)?;
            let state = state.as_ref().ok_or(SealRefused::NotVerified)?;
            state.fresh.check(sealed).map_err(SealRefused::from)
        })
    }

    fn take(
        &self,
        verified: wz_session_core::sealed_command::seal::Verified,
    ) -> Result<wz_session_core::sealed_command::seal::Sealed, SealRefused> {
        wz_runtime_coop::cs::with(|cs| {
            let mut state = self
                .state
                .borrow(cs)
                .try_borrow_mut()
                .map_err(|_| SealRefused::NotVerified)?;
            let state = state.as_mut().ok_or(SealRefused::NotVerified)?;
            state.fresh.take(verified).map_err(SealRefused::from)
        })
    }
}

/// One admin GET, answered from the node's status in the host's arena.
fn answer_admin_query<const BODY: usize, const SESSIONS: usize, O: InBand>(
    held: &mut AdminQueryState<BODY, SESSIONS, O>,
    query: &dyn QueryView,
    out: &mut dyn ReplyOut,
) {
    let identity = &held.identity;
    let (status, host, config, connect, open) =
        (held.status, held.host, held.config, held.connect, held.open);
    wz_runtime_coop::cs::with(|cs| {
        let state = status.state.borrow(cs).borrow();
        let Ok(mut arena) = host.arena.borrow(cs).try_borrow_mut() else {
            let busy = host.busy.borrow(cs);
            busy.set(busy.get().saturating_add(1));
            return;
        };
        let zid_hex = identity.zid_hex.prefix();
        if state.permit_read {
            if let Some(source) = connect {
                // A refusal is counted by the arena and answered to the querier;
                // the answer below still runs.
                let _ = arena.serve_leg(
                    query,
                    out,
                    zid_hex,
                    identity.whatami,
                    CONNECT_STATUS_TAIL,
                    AdminLegEncoding::Json,
                    |body| {
                        write_connect_status(
                            source,
                            state
                                .endpoints
                                .iter()
                                .map(|row| (row.endpoint.prefix(), &row.status)),
                            body,
                        )
                    },
                );
            }
        }
        // A constant of the type: for `NoOpening` the branch and the call are not compiled.
        if <O as InBand>::BOUND {
            open.serve(&mut arena, query, out, zid_hex, identity.whatami);
        }
        let facts = AdminNodeFacts {
            zid_hex,
            whatami: identity.whatami,
            version: identity.version.prefix(),
            // This node's config is its connection control, which holds
            // `connect/endpoints` and nothing else, so no document ever set
            // `metadata`: `null`, upstream's value for a config that sets none.
            metadata_json: "null",
            read: state.permit_read,
            stats: None,
            locators: identity.locators.iter().map(FixedText::prefix),
            sessions: state.sessions.iter().map(FixedAdminSession::view),
            // This node holds unicast sessions only, so there is no group member
            // to list: upstream's answer for a node without one.
            multicast_peers: core::iter::empty(),
        };
        // The answer's refusals are counted in the arena.
        let _ = arena.answer(query, out, facts, &[], &[], |buffer| match config {
            Some(view) => view.write_config_json(buffer),
            None => buffer.push_str("{}"),
        });
    });
}

#[cfg(test)]
mod node_key_tail_tests {
    use super::node_key_tail;

    /// The tail of a key that names this node is what follows its zid and role; a key that names
    /// another node or another role, or stops at the role, has none.
    #[test]
    fn the_tail_follows_this_nodes_zid_and_role() {
        assert_eq!(
            node_key_tail("@/aa/peer/session/open/1f", "aa", "peer"),
            Some("session/open/1f")
        );
        assert_eq!(
            node_key_tail("@/ab/peer/session/open/1f", "aa", "peer"),
            None
        );
        assert_eq!(
            node_key_tail("@/aa/client/session/open/1f", "aa", "peer"),
            None
        );
        assert_eq!(node_key_tail("@/aa/peer", "aa", "peer"), None);
    }
}

/// Decision D17 at the fixed profile's in-band entry point: the verbs answered for the commander a
/// sealed command proves, through a link that proved only a router no grant names.
#[cfg(all(test, feature = "sealed-commands", feature = "alloc"))]
mod sealed_tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::vec::Vec;
    use wz_session_core::lifecycle_monitor::{Grant, Monitor, NoRecord, Policy};
    use wz_session_core::lifecycle_node::{Generation, LifecycleNode, Verb, Zid};
    use wz_session_core::lifecycle_wire::{
        CloseOrder, MachineReport, OpenMode, OpenOutcome, SessionLinks,
    };
    use wz_session_core::query_sink::{BorrowedQuery, ProvenQuery, ReplyError};
    use wz_session_core::sample::{EncodingHint, QosLevel};
    use wz_session_core::sealed_command::seal::{self, Echo};
    use wz_session_core::sealed_command::witness::{DigestEs256, DigestSigner};

    const ME: &str = "a1b2";
    const PEER: &str = "c3d4";
    const BOOT: Echo = [0x5e; 16];
    const LISTED: DigestSigner = DigestSigner(0x41);
    /// The zid the link proved: a router no grant names.
    const ROUTER: Zid = [0x1f; 16];

    fn zid(text: &str) -> Zid {
        wz_session_core::credential_identity::zid_from_key_text(text).expect("a zid")
    }

    /// Grants `close` to [`LISTED`] alone, and counts the closes it orders.
    struct Node {
        listed: Zid,
        closes: Cell<u32>,
    }

    impl Policy for Node {
        fn each_grant(&self, verb: Verb, visit: &mut dyn FnMut(Grant<'_>) -> bool) {
            if verb == Verb::Close {
                visit(Grant {
                    commander: &self.listed,
                    key: None,
                });
            }
        }
    }

    impl LifecycleNode for Node {
        fn monitor(&self) -> Monitor<'_> {
            Monitor::new(self, &NoRecord)
        }
        fn open(&self, _peer: &Zid, _mode: OpenMode) -> OpenOutcome {
            OpenOutcome::OpenerGone
        }
        fn withdraw(&self, _peer: &Zid) {}
        fn order_close(&self, _peer: &Zid) -> CloseOrder {
            self.closes.set(self.closes.get() + 1);
            CloseOrder {
                newly_ordered: 1,
                already_ordered: 0,
            }
        }
        fn take_generation(&self, _peer: &Zid, _generation: u64) -> Generation {
            Generation::Taken
        }
        fn links(&self, _peer: &Zid) -> SessionLinks {
            SessionLinks::default()
        }
        fn read_machines(&self, _peer: &Zid, read: &mut dyn FnMut(&[MachineReport<'_>])) {
            read(&[]);
        }
    }

    /// The bodies of the replies staged.
    #[derive(Default)]
    struct Bodies(Vec<String>);

    impl ReplyOut for Bodies {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_keyed_encoded(
            &mut self,
            _keyexpr: &str,
            payload: &[u8],
            _encoding: Option<&EncodingHint>,
        ) -> Result<(), ReplyError> {
            self.0
                .push(String::from_utf8(payload.to_vec()).expect("a document is text"));
            Ok(())
        }
        fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&[u8]>, _payload: &[u8]) {}
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn close(counter: u64, echo: Option<Echo>) -> Vec<u8> {
        let command = seal::Command {
            verb: seal::Verb::Close,
            node: zid(ME),
            object: seal::Object {
                peer: zid(PEER),
                generation: None,
            },
            counter,
            echo,
        };
        let (bytes, len) = LISTED.sealed(&command).expect("seals");
        bytes[..len].to_vec()
    }

    /// Ask the close of [`PEER`] over a link that proved [`ROUTER`], carrying `attachment`: the
    /// document answered.
    fn ask(node: &Node, verifier: Option<&dyn SealVerifier>, attachment: Option<&[u8]>) -> String {
        let key = std::format!("@/{ME}/peer/session/close/{PEER}");
        let view = BorrowedQuery {
            keyexpr: &key,
            parameters: None,
            attachment,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 1,
            is_local: false,
            qos: QosLevel::DEFAULT,
        };
        let proven = ProvenQuery {
            inner: &view,
            peer: Some(ROUTER),
            encoding: None,
        };
        let mut arena: AdminReplyArena<1024> = AdminReplyArena::new();
        let mut out = Bodies::default();
        serve_verbs(&mut arena, &proven, &mut out, ME, "peer", node, verifier);
        out.0.into_iter().next().unwrap_or_default()
    }

    /// The router's own close is refused; the listed commander's sealed close is challenged for
    /// the echo after the start, permitted when it carries it, and a replay when sent again; a
    /// tampered one is refused by name. Red if the entry point judged a sealed query as the link's
    /// commander or took a counter before the echo.
    #[test]
    fn a_listed_commanders_sealed_close_is_permitted_through_an_unlisted_router() {
        let node = Node {
            listed: LISTED.commander(),
            closes: Cell::new(0),
        };
        let verifier: FixedSeal<DigestEs256, 1> = FixedSeal::new(DigestEs256, [LISTED.commander()]);
        assert_eq!(
            ask(&node, Some(&verifier), Some(&close(1, Some(BOOT)))),
            SealRefused::NotVerified.document(),
            "a verifier that has not started verifies nothing"
        );
        assert!(verifier.start(zid(ME), BOOT));
        assert!(!verifier.start(zid(ME), [0; 16]), "started once");

        assert!(ask(&node, Some(&verifier), None).contains("does not permit"));
        let challenged = ask(&node, Some(&verifier), Some(&close(1, None)));
        assert_eq!(
            challenged,
            SealRefused::EchoRequired { echo: BOOT }.document()
        );
        assert_eq!(node.closes.get(), 0);

        let repeat = close(2, Some(BOOT));
        assert_eq!(
            ask(&node, Some(&verifier), Some(&repeat)),
            "{\"verdict\":\"closing\",\"links\":1}"
        );
        assert_eq!(node.closes.get(), 1);
        assert_eq!(
            ask(&node, Some(&verifier), Some(&repeat)),
            SealRefused::Replay { last: 2 }.document()
        );

        let mut tampered = close(3, None);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            ask(&node, Some(&verifier), Some(&tampered)),
            SealRefused::BadSignature.document()
        );
        assert_eq!(node.closes.get(), 1);
        assert_eq!(verifier.last(&LISTED.commander()), Some(2));
    }

    /// A node given no verifier refuses a query that carries an attachment, even from a link its
    /// grant names, and answers the same link without it.
    #[test]
    fn a_node_with_no_verifier_refuses_an_attachment_even_from_a_listed_link() {
        let node = Node {
            listed: ROUTER,
            closes: Cell::new(0),
        };
        assert_eq!(
            ask(&node, None, Some(&close(1, Some(BOOT)))),
            SealRefused::NotVerified.document()
        );
        assert_eq!(node.closes.get(), 0);
        assert_eq!(
            ask(&node, None, None),
            "{\"verdict\":\"closing\",\"links\":1}",
            "CONTROL: the same link without the attachment is its grant"
        );
    }

    trait Document {
        fn document(self) -> String;
    }

    impl Document for SealRefused {
        fn document(self) -> String {
            let mut text: FixedText<256> = FixedText::new();
            self.write_json(&mut text);
            String::from(text.prefix())
        }
    }
}
