// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A4 (session-reconnect) — re-dial + re-handshake support types.
//!
//! zenoh-pico `Z_FEATURE_AUTO_RECONNECT` parity. pico restores a session by
//! (a) keeping the `_z_session_t` alive while the transport is torn down and
//! re-opened (`_z_client_reopen_task_fn`, `src/net/session.c`), and (b)
//! replaying `_z_session_t._declaration_cache` — the list of declaration
//! network messages recorded at `_z_send_declare` time and pruned at
//! `_z_send_undeclare` time (`src/net/primitives.c:52-76`) — onto the fresh
//! transport so the peer's declaration tables are rebuilt.
//!
//! The wz mirror keeps the same two halves:
//!
//! - [`CachedDeclaration`] is the cache entry: the typed argument tuple of
//!   the `SessionLinkActions::send_declare_*` / `send_interest_*` emit that
//!   recorded it. pico caches the encoded `_z_network_message_t`; wz caches
//!   the *pre-encode* arguments and re-runs the same builder at replay time
//!   because the transport envelope (Frame SN) is minted per send by the
//!   `dispatch_network_message` chokepoint (R311jq) — replaying stored wire
//!   bytes would replay a stale SN.
//! - [`SwappableLink`] is the transport-replacement seam: the
//!   [`SessionLinkActions::driver`](crate::session_actions::SessionLinkActions::driver)
//!   slot is a plain per-profile `R::LinkSink` captured at construction, so
//!   a reconnect supervisor that re-dials cannot re-point an existing
//!   actions bundle (and every `Session` / handle clone holding it) at the
//!   new link. Wiring the actions' sink to a `SwappableLink` up front gives
//!   the supervisor one [`swap`](SwappableLink::swap) point — the wz mirror
//!   of pico replacing `_z_transport_t` under the session transport mutex
//!   while `_z_session_t` survives.

use alloc::string::String;

use crate::link::{BoxedLinkDriver, SessionRuntime};
use crate::reliability::Reliability;
use crate::send_declare_error::SendDeclareError;
use crate::send_wire_error::SendWireError;

/// One recorded declaration emit, replayable onto a fresh transport.
///
/// pico `_z_session_t._declaration_cache` entry mirror. Variants cover
/// exactly the emit paths pico routes through its caching `_z_send_declare`
/// helper: the four `Declare(Decl*)` kinds, plus the two liveliness
/// `Interest` forms (`net/liveliness.c:209` subscriber, `:355` get — both
/// cached; the get entry is never pruned in pico either, its post-reconnect
/// replay is a harmless re-snapshot whose replies find no pending query).
///
/// Interest-response declarations (`Declare(DeclToken)` answers to a peer
/// interest, routed through `send_declare(DeclareOwned)`) are NOT cached —
/// pico's responder side rebuilds them from its live token registry per
/// inbound interest, and so does wz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedDeclaration {
    /// `send_declare_keyexpr(mapping_id, suffix)` — pruned by
    /// `send_undeclare_kexpr(mapping_id)`.
    Keyexpr { mapping_id: u64, suffix: String },
    /// `send_declare_subscriber(..)` — pruned by
    /// `send_undeclare_subscriber(subscriber_id)`.
    Subscriber {
        subscriber_id: u64,
        mapping_id: u64,
        suffix: Option<String>,
    },
    /// `send_declare_queryable(..)` — pruned by
    /// `send_undeclare_queryable(queryable_id)`.
    Queryable {
        queryable_id: u64,
        mapping_id: u64,
        suffix: Option<String>,
    },
    /// `send_declare_token(..)` — pruned by
    /// `send_undeclare_token(token_id)`.
    Token {
        token_id: u64,
        mapping_id: u64,
        suffix: Option<String>,
    },
    /// `send_interest_liveliness_subscriber(..)` — pruned by
    /// `send_interest_final(interest_id)` (pico's interest prune filter
    /// matches any `_Z_N_INTEREST` cache entry by id).
    LivelinessSubscriberInterest {
        interest_id: u64,
        history: bool,
        mapping_id: u64,
        suffix: Option<String>,
    },
    /// `send_interest_liveliness_get(..)` — one-shot CURRENT snapshot
    /// interest. Cached for pico parity (`net/liveliness.c:355` routes it
    /// through the caching `_z_send_declare`); prunable by
    /// `send_interest_final(interest_id)` like the subscriber form.
    LivelinessGetInterest {
        interest_id: u64,
        mapping_id: u64,
        suffix: Option<String>,
    },
}

impl CachedDeclaration {
    /// The interest id of an `Interest`-plane entry, `None` for the
    /// `Declare`-plane kinds. The `send_interest_final` prune filter —
    /// pico matches any cached `_Z_N_INTEREST` by `_id` regardless of
    /// which emit recorded it.
    pub fn interest_id(&self) -> Option<u64> {
        match self {
            Self::LivelinessSubscriberInterest { interest_id, .. }
            | Self::LivelinessGetInterest { interest_id, .. } => Some(*interest_id),
            _ => None,
        }
    }
}

/// Typed reject from
/// [`SessionLinkActions::replay_declarations`](crate::session_actions::SessionLinkActions::replay_declarations).
///
/// A replay re-runs builders whose arguments already passed the outbound
/// gates at original declare time, so the wrapped variants are
/// invariant-breach signals (a builder that accepted the arguments once
/// rejecting them on identical re-input), surfaced typed instead of
/// panicking per the fail-fast contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDeclarationsError {
    /// A `Declare`-plane builder (`build_declare_*`) rejected a cached
    /// entry's arguments at replay time.
    Declare(SendDeclareError),
    /// An `Interest`-plane builder (`build_interest_*`) rejected a cached
    /// entry's arguments at replay time.
    Interest(SendWireError),
    /// R311g1 signature-stability — the `session-reconnect` Cargo feature
    /// is OFF in this build, so no declaration cache exists to replay.
    FeatureDisabled,
}

impl core::fmt::Display for ReplayDeclarationsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Declare(e) => write!(f, "replay_declarations: declare builder reject: {e}"),
            Self::Interest(e) => write!(f, "replay_declarations: interest builder reject: {e}"),
            Self::FeatureDisabled => f.write_str(
                "replay_declarations: session-reconnect Cargo feature is OFF \
                 in this build; no declaration cache exists (signature-stability \
                 contract — caller observes build-time choice as runtime reject)",
            ),
        }
    }
}

impl core::error::Error for ReplayDeclarationsError {}

/// Link-sink indirection for transport replacement — the wz mirror of pico
/// swapping `_z_session_t._tp` under the session transport mutex while the
/// session (and every handle into it) survives.
///
/// Implements [`BoxedLinkDriver`] by delegating every call to the inner
/// `R::LinkSink` under the per-profile mutex, so an actions bundle whose
/// `driver` slot wraps a `SwappableLink` keeps emitting through whatever
/// link [`swap`](Self::swap) installed last. A reconnect supervisor dials
/// the replacement link first and swaps only on success, so the window
/// where sends still target the dead link is the pre-swap window that
/// already existed (the link-loss race is inherent, not introduced here).
///
/// `R::LinkSink: Send` bound: the per-profile mutex projection
/// (`Runtime::Mutex<T>` requires `T: Send`) — satisfied by the AP profile
/// (`Arc<dyn BoxedLinkDriver + Send + Sync>`). The lwIP MCU profile's
/// `Rc<dyn BoxedLinkDriver>` sink is `!Send` and cannot satisfy this
/// bound; its single-task swap seam is [`LocalSwappableLink`] (R311ki).
pub struct SwappableLink<R: SessionRuntime>
where
    R::LinkSink: Send + 'static,
{
    inner: R::Mutex<R::LinkSink>,
}

impl<R: SessionRuntime> SwappableLink<R>
where
    R::LinkSink: Send + 'static,
{
    /// Wrap the initial link sink. The caller hands the resulting
    /// `SwappableLink` (behind the per-profile refcount wrapper) to
    /// `SessionLinkActions` as its `driver`, retaining a second handle for
    /// later [`swap`](Self::swap) calls.
    pub fn new(initial: R::LinkSink) -> Self {
        Self {
            inner: R::new_mutex(initial),
        }
    }

    /// Install `next` as the delegation target, returning the previous
    /// sink so the supervisor can drop it (releasing the dead transport)
    /// outside the lock.
    pub fn swap(&self, next: R::LinkSink) -> R::LinkSink {
        R::with_mutex_mut(&self.inner, |slot| core::mem::replace(slot, next))
    }
}

impl<R: SessionRuntime> BoxedLinkDriver for SwappableLink<R>
where
    R::LinkSink: Send + 'static,
{
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        R::with_mutex_mut(&self.inner, |sink| {
            R::link_driver(sink).send_blocking(bytes, reliability);
        });
    }

    fn open_blocking(&self) {
        R::with_mutex_mut(&self.inner, |sink| {
            R::link_driver(sink).open_blocking();
        });
    }

    fn close_blocking(&self) {
        R::with_mutex_mut(&self.inner, |sink| {
            R::link_driver(sink).close_blocking();
        });
    }
}

/// R311ki — single-task transport-replacement seam, the MCU twin of
/// [`SwappableLink`] (the MCU-reconnect carry: the lwIP profile's
/// `Rc<dyn BoxedLinkDriver>` sink is `!Send`, and `Runtime::Mutex<T>`
/// requires `T: Send`, so the mutex-backed seam cannot exist there).
///
/// A `RefCell` replaces the per-profile mutex: the single-task
/// cooperative drive model (the same invariant behind the lwIP `Rc`
/// sink itself) means delegation and [`swap`](Self::swap) always run on
/// the one task, so interior mutability without `Sync` is exactly
/// sufficient. `!Sync` by construction — the type CANNOT be shared
/// across threads, which is the honest encoding of the profile
/// invariant (the AP profile keeps the `Send`-bounded [`SwappableLink`]
/// because its supervisor and senders live on different tasks).
///
/// NOT re-entrant: a [`BoxedLinkDriver`] implementation reached through
/// the delegation must not call back into this seam (the `RefCell`
/// borrow would panic loudly) — the same non-reentrancy discipline the
/// MCU critical_section mutex already imposes on the actions bundle.
///
/// No live consumer yet: the MCU reconnect SUPERVISOR (re-dial +
/// re-handshake loop) needs the larger MCU session-open runtime —
/// bottom-up framework staging, same as `scout_static` (R311ih) shipped
/// exposed + tested + cross-compiled awaiting its consumer.
pub struct LocalSwappableLink<R: SessionRuntime> {
    inner: core::cell::RefCell<R::LinkSink>,
}

impl<R: SessionRuntime> LocalSwappableLink<R> {
    /// Wrap the initial link sink (see [`SwappableLink::new`]; the
    /// caller keeps a second `Rc` handle for later swaps).
    pub fn new(initial: R::LinkSink) -> Self {
        Self {
            inner: core::cell::RefCell::new(initial),
        }
    }

    /// Install `next` as the delegation target, returning the previous
    /// sink so the supervisor can drop the dead transport outside any
    /// borrow.
    pub fn swap(&self, next: R::LinkSink) -> R::LinkSink {
        core::mem::replace(&mut self.inner.borrow_mut(), next)
    }
}

impl<R: SessionRuntime> BoxedLinkDriver for LocalSwappableLink<R> {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        R::link_driver(&self.inner.borrow()).send_blocking(bytes, reliability);
    }

    fn open_blocking(&self) {
        R::link_driver(&self.inner.borrow()).open_blocking();
    }

    fn close_blocking(&self) {
        R::link_driver(&self.inner.borrow()).close_blocking();
    }
}
