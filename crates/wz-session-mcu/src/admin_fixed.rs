// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! S9c, [`crate::admin_status::NodeStatus`]'s writer today); it gives the rows as
//! [`wz_session_core::adminspace::AdminSessionRef`] views of whatever it keeps.
//!
//! # The lock
//!
//! The status, the arena and the busy count live behind one `critical_section` lock,
//! as [`crate::admin_status::NodeStatus`] does, and a GET holds it for the whole
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
use wz_session_core::locality::Locality;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::BoxedQuerySink;
use wz_session_core::registry_error::RegisterError;
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
        critical_section::with(|cs| {
            let mut state = self.state.borrow(cs).borrow_mut();
            state.sessions.clear();
            for row in rows {
                match FixedAdminSession::from_view(&row) {
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

/// Why a [`FixedNodeIdentity`] was not built.
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
/// [`crate::admin_status::host_admin_queryable`]: every upstream leg through
/// [`AdminReplyArena::answer`], the `config` leg from `config` (`{}` when `None`),
/// and, with `connect`, the connection status leg `@/<zid>/<whatami>/status/connect`.
/// A denied read answers nothing and the query is still terminated. The registration
/// itself allocates once (the boxed sink), at startup.
///
/// `Err` when the registry's queryable table refuses the registration: full, or the
/// pattern past `caps::MAX_KEYEXPR_BYTES`; the node must then say it answers no
/// admin GET, not run as if it did.
pub fn host_admin_queryable_fixed<const BODY: usize, const SESSIONS: usize>(
    queryables: &mut QueryableRegistry<BoxedQuerySink>,
    identity: FixedNodeIdentity,
    status: &'static FixedNodeStatus<SESSIONS>,
    host: &'static AdminHost<BODY>,
    config: Option<&'static (dyn ConfigView + Sync)>,
    connect: Option<&'static (dyn ConnectStatusSource + Sync)>,
) -> Result<(), RegisterError> {
    let mut pattern: FixedText<{ caps::MAX_KEYEXPR_BYTES }> = FixedText::new();
    write_admin_queryable_key(&mut pattern, identity.zid_hex.prefix(), identity.whatami);
    let pattern = pattern
        .finish()
        .map_err(|_| RegisterError::KeyexprTooLong)?;
    let answer = BoxedQuerySink::new(move |query, out| {
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
    });
    queryables
        .register_sink(pattern, Locality::Any, false, answer)
        .map(|_id| ())
}
