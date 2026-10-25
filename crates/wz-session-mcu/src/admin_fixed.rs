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
//! [`wz_session_core::adminspace::AdminSessionRef`] views of whatever it keeps.
//!
//! # The lock
//!
//! The status, the arena and the busy count live behind one `critical_section` lock,
//! as `crate::admin_status::NodeStatus` does, and a GET holds it for the whole
//! answer: the legs are rendered from the rows where they lie, which is what removes
//! the clone. On a single-core cooperative runtime nothing else contends for it
//! except the shell's own `set_sessions`, which runs between GETs; the interrupt-off
//! time of one answer has NOT been measured on a board.

use core::cell::{Cell, RefCell};

use critical_section::Mutex;
use wz_session_core::admin_reply::{AdminReplyArena, AdminReplyRefusals};
use wz_session_core::adminspace::{
    write_admin_queryable_key, AdminLegEncoding, AdminLinkList, AdminLinkWeight, AdminNodeFacts,
    AdminSessionRef,
};
use wz_session_core::bounded::BoundedVec;
use wz_session_core::caps;
use wz_session_core::lifecycle_wire::{
    write_verb_list, OpenKey, OpenOutcome, OpenVerdict, RefusedReason, OPEN_VERB,
};
use wz_session_core::locality::Locality;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{FnQuerySink, QueryView, ReplyOut};
use wz_session_core::registry_error::RegisterError;
use wz_session_core::slot_observer::{NoSink, ObserverSinks};
use wz_session_core::text_out::{FixedText, TextOut};

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

/// What the open query asks of the node: whether it may be asked, and to hold a peer by its zid
/// (decision D6, `docs/session-lifecycle-intent.md`).
///
/// A port, for the reason the heap profile's `PeerOpener` is one: the machines that hold a peer
/// live with the loop that ticks them, and the query is served beside it. The node's own
/// implementation is `crate::connect_manager::ControlledOpener`.
///
/// It is also the strategy of decision D7: whether the node serves the in-band verbs is the type
/// its admin queryable is made with, so a build whose peers are declared when it is built names
/// [`NoOpening`] and its answer holds no code of the open query, which `BOUND` removes where the
/// answer is compiled (`docs/build-configuration.md` C3: a choice that changes the shape of the
/// code is a type parameter, not a feature).
pub trait NodeOpening {
    /// Whether the node binds the in-band verbs at all. `false` only for [`NoOpening`].
    const BOUND: bool = true;

    /// Whether this node lets a query open a session: the node's write permit, which is what
    /// the config write is gated by too. A node that does not permit it answers a refusal that
    /// says so, and opens nothing.
    fn permitted(&self) -> bool;

    /// Ask the node to hold the peer `zid`. Accepted, not completed: how the dial ends is read
    /// in the node's connection status.
    fn open(
        &self,
        zid: &[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES],
    ) -> OpenOutcome;
}

/// The opener of a node that binds no in-band verb: the third value of decision D7, where the
/// peers a node holds are the ones it was built with and the machines only reconnect them. Its
/// admin answer lists no `open` and serves no `session/open` key.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpening;

impl NodeOpening for NoOpening {
    const BOUND: bool = false;

    fn permitted(&self) -> bool {
        false
    }

    fn open(
        &self,
        _zid: &[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES],
    ) -> OpenOutcome {
        // Not reached: the answer never asks an opener that is not `BOUND`. Were it reached, a
        // node that binds no verb takes no peer by request, which is `NoRoom`'s meaning.
        OpenOutcome::NoRoom
    }
}

/// The one [`NoOpening`] a node without verbs hands its queryable.
static NO_OPENING: NoOpening = NoOpening;

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

/// One `sessions[]` row in fixed storage: [`wz_session_core::adminspace::AdminSession`]
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
    /// through a lend (`SessionLinkActions::with_admin_session`) gives it: the borrowed
    /// row cannot leave the call that lends it, so the copy is made there and the
    /// copies are given here, outside any lock.
    pub fn set_session_rows(
        &self,
        rows: impl IntoIterator<Item = Result<FixedAdminSession, RowRefused>>,
    ) {
        critical_section::with(|cs| {
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
        critical_section::with(|cs| {
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
        critical_section::with(|cs| self.state.borrow(cs).borrow_mut().permit_read = permit);
    }

    /// How many session rows the node reports now.
    pub fn session_count(&self) -> usize {
        critical_section::with(|cs| self.state.borrow(cs).borrow().sessions.len())
    }

    /// What this status refused since it was made, by why.
    pub fn refusals(&self) -> StatusRefusals {
        critical_section::with(|cs| self.state.borrow(cs).borrow().refusals)
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
        critical_section::with(|cs| self.arena.borrow(cs).borrow().refusals())
    }

    /// How many GETs found the arena in use and were not answered. A handler cannot
    /// re-enter the arena on a cooperative runtime, so a count above zero is a
    /// defect, and is reported rather than papered over.
    pub fn busy_refusals(&self) -> u32 {
        critical_section::with(|cs| self.busy.borrow(cs).get())
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
pub fn host_admin_queryable_fixed_with_open<
    const BODY: usize,
    const SESSIONS: usize,
    O: NodeOpening + Sync + 'static,
>(
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
pub struct AdminQueryState<
    const BODY: usize,
    const SESSIONS: usize,
    O: NodeOpening + Sync + 'static = NoOpening,
> {
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
pub struct AdminSinks<
    const BODY: usize,
    const SESSIONS: usize,
    O: NodeOpening + Sync + 'static = NoOpening,
>(core::marker::PhantomData<O>);

impl<const BODY: usize, const SESSIONS: usize, O: NodeOpening + Sync + 'static> ObserverSinks
    for AdminSinks<BODY, SESSIONS, O>
{
    #[cfg(feature = "adminspace-write")]
    type Subscriber = crate::admin_host::ConnectWriteSink;
    #[cfg(not(feature = "adminspace-write"))]
    type Subscriber = NoSink;
    type Queryable = AdminQuerySink<BODY, SESSIONS, O>;
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
    let verdict = if !opener.permitted() {
        OpenVerdict::Refused(RefusedReason::OpenNotPermitted)
    } else {
        match parsed.peer() {
            Some(peer) => OpenVerdict::of(opener.open(&peer)),
            None => OpenVerdict::Refused(RefusedReason::PeerNotAZid),
        }
    };
    // The key's own tail, `session/open/<peer>`: it follows `@/<zid>/<whatami>/`, which the
    // parse has just held to name this node. A reply the arena refuses is counted there; the
    // open has happened either way, as the heap profile's reply says.
    let tail = &key[2 + zid_hex.len() + 1 + whatami.len() + 1..];
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

/// The tail of the capability query, `@/<zid>/<whatami>/session/verbs`.
const VERBS_TAIL: &str = "session/verbs";

/// One admin GET, answered from the node's status in the host's arena.
fn answer_admin_query<const BODY: usize, const SESSIONS: usize, O: NodeOpening + Sync + 'static>(
    held: &mut AdminQueryState<BODY, SESSIONS, O>,
    query: &dyn QueryView,
    out: &mut dyn ReplyOut,
) {
    let identity = &held.identity;
    let (status, host, config, connect, open) =
        (held.status, held.host, held.config, held.connect, held.open);
    critical_section::with(|cs| {
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
        if O::BOUND {
            serve_open(&mut arena, query, out, zid_hex, identity.whatami, open);
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
