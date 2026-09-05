// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y97 — `ext-pubsub-group-membership` (§5.25): the live group + its
//! membership tasks. The AP-only tokio half over the no_std data + wire
//! codec in [`wz_session_core::group_membership`].
//!
//! The wz mirror of zenoh-ext `group.rs`. A [`Group`] lets a set of peers
//! form a named group on a shared key namespace and track its live
//! membership (the "view"):
//!
//! - On [`Group::join`] a member announces itself with a
//!   [`GroupNetEvent::Join`] (carrying its full [`Member`] record) on the
//!   group **event key** `zenoh/ext/net/group/<gid>/evt`, then declares a
//!   subscriber on that key to learn about peers.
//! - An `Auto`-liveliness member refreshes its lease with periodic
//!   [`GroupNetEvent::KeepAlive`] beacons (every `lease * refresh_ratio`);
//!   a watchdog evicts a member whose lease elapses without a refresh and
//!   emits a [`GroupEvent::LeaseExpired`].
//! - Each member serves its own [`Member`] record from a per-member
//!   **query key** `zenoh/ext/net/group/<gid>/<mid>`, so a peer that hears a
//!   beacon from a member it does not yet know `get`s that key to learn the
//!   member's details (the late-joiner recovery path).
//!
//! ## wz mirror notes (callback-driven session)
//!
//! zenoh-ext runs four background `recv_async` loop tasks (keep-alive,
//! watchdog, net-event handler, query handler). wz's session is
//! callback-driven, so the net-event handler and the query handler become
//! callback registrations (a [`Subscriber`] and a [`Queryable`]) rather than
//! spawned loops — the dispatch fires them inline. Only the two genuinely
//! time-driven loops are spawned tokio tasks: the keep-alive beacon and the
//! watchdog. The unknown-member `get` issued from the net-event subscriber
//! callback re-enters `Session::query` (with the member-state lock released),
//! and its reply callback inserts the recovered member — the same
//! deferred-fire re-entrancy the advanced-recovery atom relies on.
//!
//! ## Faithful divergences / omissions
//!
//! - zenoh-ext sets the group event publisher's QoS to `Priority::DataHigh`;
//!   wz `PublishOptions` exposes no priority setter, so the group events are
//!   published at the default priority (a documented QoS omission, not a
//!   protocol divergence — the membership wire is byte-identical).
//! - [`GroupOptions::get_locality`] (a wz addition, default
//!   [`Locality::Any`]) controls the unknown-member `get` destination, the
//!   same locality knob the advanced subscriber carries; it lets a
//!   same-session loopback deployment/test exercise the recovery path.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;

use wz_runtime_core::TimeSource;
use wz_session_core::group_membership::{
    decode_member, decode_net_event, encode_member, encode_net_event, GroupNetEvent,
};
use wz_session_core::link::SessionRuntime;
use wz_session_core::locality::Locality;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sink::SampleView;

use crate::session::{
    PublishError, PublishOptions, QueryOptions, Queryable, QueryableError, QueryableOptions,
    Session, SubscribeError, SubscribeOptions, Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;

pub use wz_session_core::group_membership::{Member, MemberLiveliness};

/// The group key-expression namespace (zenoh-ext `GROUP_PREFIX`,
/// group.rs:37). The single source of truth for both KE shapes below.
const GROUP_PREFIX: &str = "zenoh/ext/net/group";
/// The event-key trailing chunk (zenoh-ext `EVENT_POSTFIX`, group.rs:38).
const EVENT_POSTFIX: &str = "evt";
/// The watchdog sweep period — once per second (zenoh-ext
/// `Duration::from_secs(1)`, group.rs:402).
const WATCHDOG_PERIOD_MS: u64 = 1_000;
/// The unknown-member `get` timeout. The recovered member is only relevant
/// for the duration of its lease, so an unanswered `get` (the member left
/// between its beacon and our query) is bounded tighter than the platform
/// default. R311y326 — a `0` would no longer wedge (it resolves to the 10s
/// `DEFAULT_QUERY_TIMEOUT_MS`); this explicit 5s is chosen because a stale
/// member is lease-scoped and the next beacon re-issues if it was a transient
/// miss, so a shorter bound than the default is wanted here.
const MEMBER_QUERY_TIMEOUT_MS: u32 = 5_000;

/// The group event key `zenoh/ext/net/group/<gid>/evt` — the pub/sub channel
/// the join / leave / keep-alive events travel on.
fn event_keyexpr(gid: &str) -> String {
    format!("{GROUP_PREFIX}/{gid}/{EVENT_POSTFIX}")
}

/// The per-member query key `zenoh/ext/net/group/<gid>/<mid>` — the queryable
/// each member declares to serve its own record (zenoh-ext group.rs:231-234).
fn member_keyexpr(gid: &str, mid: &str) -> String {
    format!("{GROUP_PREFIX}/{gid}/{mid}")
}

/// Whether a group or member id contains a key-expression wildcard. zenoh-ext
/// rejects a wild group id / member id (group.rs:118-120, 369-371); a
/// non-wild keyexpr contains none of the wildcard chunks, all of which carry
/// a `*`.
fn is_wild(ke: &str) -> bool {
    ke.contains('*')
}

/// The keep-alive beacon period: `lease * refresh_ratio`, so a refresh always
/// precedes the lease elapsing (zenoh-ext group.rs:190-193). Clamped to
/// `>= 1ms` BY CONSTRUCTION so a degenerate zero period cannot spin the beacon
/// task (the advanced-publisher C4 lesson) — the floor lives here, not at the
/// call site, so any future caller is spin-safe too (R311y102 review).
fn keepalive_period_ms(lease: Duration, refresh_ratio: f32) -> u64 {
    (((lease.as_millis() as f64) * (refresh_ratio as f64)) as u64).max(1)
}

/// Construction options for a [`Group`]. `#[non_exhaustive]` for additive
/// stability (mirrors the advanced pub/sub option structs).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct GroupOptions {
    /// Where the unknown-member recovery `get` is sent. Default
    /// [`Locality::Any`] (members are normally remote); set
    /// [`Locality::SessionLocal`] for a same-session loopback deployment.
    pub get_locality: Locality,
}

impl Default for GroupOptions {
    fn default() -> Self {
        Self {
            get_locality: Locality::Any,
        }
    }
}

impl GroupOptions {
    /// Default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the unknown-member `get` locality (builder).
    pub fn with_get_locality(mut self, locality: Locality) -> Self {
        self.get_locality = locality;
        self
    }
}

/// A change in the group the user is informed of via [`Group::subscribe`].
/// Mirror of zenoh-ext `GroupEvent` (group.rs:83-90).
#[derive(Clone, Debug)]
pub enum GroupEvent {
    /// A member joined (or was recovered via the unknown-member query).
    Join(Member),
    /// A member announced it is leaving.
    Leave(String),
    /// A member's lease elapsed without a refreshing keep-alive.
    LeaseExpired(String),
    /// The group leader changed. RESERVED + never emitted — a faithful mirror
    /// of zenoh-ext, which likewise DECLARES `GroupEvent::NewLeader`
    /// (group.rs:89) but never sends it (no construction site upstream); the
    /// leader is a pull query ([`Group::leader`]), not a push event. Kept for
    /// wire/API parity, not a wz-specific dead stub (R311y102 review arbitration).
    NewLeader(String),
}

/// Why [`Group::join`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum GroupError {
    /// `join` spawns the watchdog (and, for `Auto` liveliness, the keep-alive
    /// beacon) as tokio tasks, so it must be called from within a tokio
    /// runtime context. Fail-clear instead of a `tokio::spawn` panic.
    NoRuntime,
    /// The group id contained a key-expression wildcard.
    WildcardGroupId(String),
    /// The member id contained a key-expression wildcard.
    WildcardMemberId(String),
    /// Publishing the initial join announcement failed.
    Publish(PublishError),
    /// Declaring the group event subscriber failed.
    Subscribe(SubscribeError),
    /// Declaring the per-member queryable failed.
    Queryable(QueryableError),
}

/// The shared, runtime-agnostic group state the handlers + tasks mutate. Holds
/// no session (the callbacks/tasks capture their own session clone), so it is
/// a plain `Send + Sync` record behind an `Arc`.
struct GroupState {
    gid: String,
    local_member: Member,
    /// Known peers: `mid -> (record, alive_till_ms)` keyed by member id. The
    /// local member is NOT here (it is the always-present `+1`); the value's
    /// `alive_till_ms` is a monotonic-clock deadline.
    members: Mutex<HashMap<String, (Member, u64)>>,
    /// The user event channel sender, present once [`Group::subscribe`] was
    /// called (a single subscription, last-wins — zenoh-ext group.rs:412-415).
    event_tx: Mutex<Option<UnboundedSender<GroupEvent>>>,
    /// Wakes [`Group::wait_for_view_size`] waiters on every membership growth.
    notify: Notify,
    /// The unknown-member `get` destination.
    get_locality: Locality,
}

impl GroupState {
    /// Forward a user event to the subscription, if any (a dropped receiver is
    /// non-fatal — the send is silently discarded).
    fn send_event(&self, evt: GroupEvent) {
        if let Some(tx) = self
            .event_tx
            .lock()
            .expect("group event_tx mutex poisoned")
            .as_ref()
        {
            let _ = tx.send(evt);
        }
    }

    /// Insert (or replace) a known member with a fresh lease deadline, wake
    /// view-size waiters, and emit a [`GroupEvent::Join`]. Used by both the
    /// inbound `Join` event and the unknown-member query recovery.
    fn insert_member(&self, mid: String, member: Member, now_ms: u64) {
        let alive_till = now_ms.saturating_add(member.lease.as_millis() as u64);
        {
            let mut ms = self.members.lock().expect("group members mutex poisoned");
            ms.insert(mid, (member.clone(), alive_till));
        }
        self.notify.notify_waiters();
        self.send_event(GroupEvent::Join(member));
    }

    /// Refresh a known member's lease deadline. Returns `false` (without
    /// touching state) when the member is unknown — the caller then recovers
    /// it via the per-member query. The lock is released on return, so the
    /// caller may safely re-enter `Session::query`.
    fn refresh_member(&self, mid: &str, now_ms: u64) -> bool {
        let mut ms = self.members.lock().expect("group members mutex poisoned");
        match ms.get_mut(mid) {
            Some((member, alive_till)) => {
                *alive_till = now_ms.saturating_add(member.lease.as_millis() as u64);
                true
            }
            None => false,
        }
    }
}

/// RAII handle for a spawned group task (keep-alive / watchdog): dropping it
/// aborts the loop so a torn-down [`Group`] stops beaconing / sweeping.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A live group membership handle bound to a [`Session`]. Owns the event
/// subscriber, the per-member queryable, and the background tasks; dropping it
/// tears all of them down (RAII).
pub struct Group<R: SessionRuntime, T: TimeSource> {
    state: Arc<GroupState>,
    session: Session<R, T, Unicast>,
    event_keyexpr: String,
    _subscriber: Subscriber<R>,
    _queryable: Queryable<R, T>,
    _keep_alive: Option<AbortOnDrop>,
    _watchdog: AbortOnDrop,
}

impl<R, T> Group<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + 'static,
{
    /// Join the group `group` as `member`. Announces the member on the event
    /// key, declares the event subscriber + the per-member queryable, and
    /// spawns the watchdog (plus the keep-alive beacon for `Auto`
    /// liveliness). Must be called from within a tokio runtime.
    pub fn join(
        session: &Session<R, T, Unicast>,
        group: impl Into<String>,
        member: Member,
        options: GroupOptions,
    ) -> Result<Self, GroupError> {
        let gid = group.into();
        if is_wild(&gid) {
            return Err(GroupError::WildcardGroupId(gid));
        }
        if is_wild(&member.mid) {
            return Err(GroupError::WildcardMemberId(member.mid.clone()));
        }
        // Fail fast & clear if off-runtime: the watchdog (+ keep-alive) below
        // are tokio::spawn tasks that PANIC without a runtime. Checked BEFORE
        // any declare / publish so a failure leaves nothing half-built.
        tokio::runtime::Handle::try_current().map_err(|_| GroupError::NoRuntime)?;

        let event_keyexpr = event_keyexpr(&gid);
        let member_keyexpr = member_keyexpr(&gid, &member.mid);
        let is_auto = matches!(member.liveliness, MemberLiveliness::Auto);

        let state = Arc::new(GroupState {
            gid,
            local_member: member.clone(),
            members: Mutex::new(HashMap::new()),
            event_tx: Mutex::new(None),
            notify: Notify::new(),
            get_locality: options.get_locality,
        });

        // 1) Announce the member BEFORE declaring the subscriber, so we never
        //    receive our own Join (a peer that already joined sees it; we do
        //    not). Mirrors zenoh-ext's "publish join, then spawn handlers".
        let join_buf = encode_net_event(&GroupNetEvent::Join(member.clone()));
        session
            .publish(&event_keyexpr, &join_buf, PublishOptions::put())
            .map_err(GroupError::Publish)?;

        // 2) The net-event subscriber: decode + dispatch each inbound event.
        let sub_state = Arc::clone(&state);
        let sub_session = session.clone();
        let sub_clock = Arc::clone(session.clock());
        let subscriber = session
            .declare_subscriber(
                &event_keyexpr,
                SubscribeOptions::default(),
                move |v: &dyn SampleView| {
                    if let Ok(evt) = decode_net_event(v.payload()) {
                        handle_net_event(&sub_state, &sub_session, &sub_clock, evt);
                    }
                },
            )
            .map_err(GroupError::Subscribe)?;

        // 3) The per-member queryable: answer every get with the local record.
        let reply_buf = encode_member(&member);
        let reply_keyexpr = member_keyexpr.clone();
        let queryable = session
            .declare_queryable(
                &member_keyexpr,
                QueryableOptions::default().with_complete(true),
                move |_view: &dyn QueryView, out: &mut dyn ReplyOut| {
                    out.reply_keyed(&reply_keyexpr, &reply_buf);
                },
            )
            .map_err(GroupError::Queryable)?;

        // 4) The keep-alive beacon task (auto liveliness only): re-announce the
        //    lease every `lease * refresh_ratio`.
        let keep_alive = is_auto.then(|| {
            let ka_session = session.clone();
            let ka_clock = Arc::clone(session.clock());
            let ka_keyexpr = event_keyexpr.clone();
            let ka_buf = encode_net_event(&GroupNetEvent::KeepAlive(member.mid.clone()));
            let period_ms = keepalive_period_ms(member.lease, member.refresh_ratio);
            // The APPLICATION subsystem. zenoh-ext's group runs its four tasks
            // through `TaskController::spawn_abortable`
            // (`zenoh-ext/src/group.rs`
            // @ `task_controller.spawn_abortable(keep_alive_task(`), the arm
            // WITHOUT a `ZRuntime` argument
            // (`commons/zenoh-task/src/lib.rs`
            // @ `pub fn spawn_abortable<F, T>(&self, future: F)`, versus
            // `spawn_abortable_with_rt`), so they inherit the caller's
            // runtime — and a group is joined from application code. Naming the
            // subsystem it already lands on is what makes it schedulable.
            AbortOnDrop(
                crate::runtime_pool::WzRuntime::Application.spawn(async move {
                    loop {
                        ka_clock.sleep(period_ms).await;
                        // Fire-and-forget: a beacon publish error (e.g. a torn-down
                        // link) is transient — the next tick re-beacons, and the
                        // peer's lease has not yet elapsed. Dropping it is the
                        // zenoh-ext behavior (group.rs:197 `let _ = ...put()`).
                        let _ = ka_session.publish(&ka_keyexpr, &ka_buf, PublishOptions::put());
                    }
                }),
            )
        });

        // 5) The watchdog: evict expired members once per second.
        let wd_state = Arc::clone(&state);
        let wd_clock = Arc::clone(session.clock());
        // APPLICATION for the same reason as the keep-alive beacon above —
        // upstream's watchdog is the fourth of those inheriting tasks
        // (`zenoh-ext/src/group.rs`
        // @ `task_controller.spawn_abortable(watchdog_task(`).
        let watchdog = AbortOnDrop(
            crate::runtime_pool::WzRuntime::Application.spawn(async move {
                loop {
                    wd_clock.sleep(WATCHDOG_PERIOD_MS).await;
                    sweep_expired(&wd_state, wd_clock.now_monotonic_ms());
                }
            }),
        );

        Ok(Self {
            state,
            session: session.clone(),
            event_keyexpr,
            _subscriber: subscriber,
            _queryable: queryable,
            _keep_alive: keep_alive,
            _watchdog: watchdog,
        })
    }

    /// The group identifier.
    pub fn group_id(&self) -> &str {
        &self.state.gid
    }

    /// This member's identifier.
    pub fn local_member_id(&self) -> &str {
        self.state.local_member.id()
    }

    /// The current group view: every known peer plus the local member
    /// (zenoh-ext group.rs:430-441).
    pub fn view(&self) -> Vec<Member> {
        let ms = self
            .state
            .members
            .lock()
            .expect("group members mutex poisoned");
        let mut v: Vec<Member> = ms.values().map(|(m, _)| m.clone()).collect();
        v.push(self.state.local_member.clone());
        v
    }

    /// The current group size (known peers + the local member; zenoh-ext
    /// group.rs:469-472).
    pub fn size(&self) -> usize {
        self.state
            .members
            .lock()
            .expect("group members mutex poisoned")
            .len()
            + 1
    }

    /// The current leader: the member with the lexicographically greatest id
    /// (zenoh-ext group.rs:476-486). A view change may change the leader.
    pub fn leader(&self) -> Member {
        let mut leader = self.state.local_member.clone();
        for m in self.view() {
            if leader.id() < m.id() {
                leader = m;
            }
        }
        leader
    }

    /// Subscribe to [`GroupEvent`]s. A single subscription at a time — a new
    /// call replaces the previous receiver (zenoh-ext group.rs:412-415).
    pub fn subscribe(&self) -> UnboundedReceiver<GroupEvent> {
        let (tx, rx) = unbounded_channel();
        *self
            .state
            .event_tx
            .lock()
            .expect("group event_tx mutex poisoned") = Some(tx);
        rx
    }

    /// Manually emit one keep-alive beacon now (the deterministic core the
    /// `Auto` keep-alive task loops). For a `Manual`-liveliness member this is
    /// how the user asserts liveliness; it is also the test seam over the same
    /// publish the timer drives.
    pub fn assert_liveliness(&self) -> Result<(), PublishError> {
        let buf = encode_net_event(&GroupNetEvent::KeepAlive(
            self.state.local_member.mid.clone(),
        ));
        self.session
            .publish(&self.event_keyexpr, &buf, PublishOptions::put())?;
        Ok(())
    }

    /// Wait until the group view reaches `size` members or `timeout` elapses.
    /// Returns whether the desired size was reached (zenoh-ext
    /// group.rs:445-466).
    pub async fn wait_for_view_size(&self, size: usize, timeout: Duration) -> bool {
        if self.size() >= size {
            return true;
        }
        let wait = async {
            loop {
                // Register interest BEFORE re-checking so a growth between the
                // check and the await is not a lost wake-up.
                let notified = self.state.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.size() >= size {
                    return true;
                }
                notified.await;
            }
        };
        tokio::time::timeout(timeout, wait).await.unwrap_or(false)
    }
}

/// Dispatch one decoded inbound group event into the shared state. The wz
/// equivalent of zenoh-ext's `net_event_handler` match (group.rs:254-354),
/// invoked inline from the event subscriber callback. All arms ignore an
/// event whose member id is the local member (defensive: the join-before-
/// subscribe ordering already prevents a self-event, and zenoh-ext's
/// KeepAlive arm self-filters too).
fn handle_net_event<R, T>(
    state: &Arc<GroupState>,
    session: &Session<R, T, Unicast>,
    clock: &Arc<T>,
    evt: GroupNetEvent,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let local_mid = state.local_member.id();
    match evt {
        GroupNetEvent::Join(member) => {
            if member.mid != local_mid {
                state.insert_member(member.mid.clone(), member, clock.now_monotonic_ms());
            }
        }
        GroupNetEvent::Leave(mid) => {
            if mid != local_mid {
                let removed = state
                    .members
                    .lock()
                    .expect("group members mutex poisoned")
                    .remove(&mid)
                    .is_some();
                if removed {
                    state.send_event(GroupEvent::Leave(mid));
                }
            }
        }
        GroupNetEvent::KeepAlive(mid) => {
            if mid != local_mid {
                // refresh_member releases the members lock before we return, so
                // re-entering Session::query for the unknown case is safe.
                if !state.refresh_member(&mid, clock.now_monotonic_ms()) {
                    issue_member_query(state, session, clock, mid);
                }
            }
        }
    }
}

/// Recover an unknown member's record: `get` its per-member queryable and feed
/// the decoded [`Member`] back into the view. The wz equivalent of zenoh-ext's
/// unknown-KeepAlive query (group.rs:298-348). MUST be called with the members
/// lock released — `Session::query` re-enters the session (its reply callback
/// locks the state again). The returned [`crate::reply::ReplyHandle`] is
/// dropped: wz replies fire via the reply registry, not the handle (the same
/// fire-and-forget the advanced-recovery GET uses).
fn issue_member_query<R, T>(
    state: &Arc<GroupState>,
    session: &Session<R, T, Unicast>,
    clock: &Arc<T>,
    mid: String,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let keyexpr = member_keyexpr(&state.gid, &mid);
    let opts = QueryOptions::get()
        .with_allowed_destination(state.get_locality)
        .with_timeout_ms(MEMBER_QUERY_TIMEOUT_MS);
    // R311y836 — pin the mode rather than ride the default, which now resolves
    // to LATEST. zenoh-ext's group does the same thing at a STRUCTURALLY
    // IDENTICAL site: it builds the same per-member keyexpr
    // (`format!("{}/{}/{}", GROUP_PREFIX, &state.gid, kae.mid)`) and names the
    // mode right before the get — `let qc = zenoh::query::ConsolidationMode::None;`
    // (`zenoh-ext/src/group.rs` @ `Received Keep Alive from unknown member`).
    //
    // HONEST ABOUT ITS OWN WEIGHT: no test in this tree discriminates this pin,
    // and that was MEASURED — a probe that dropped every caller's explicit mode
    // reddened 16 cases and not one of them was a group case. Collapsing needs
    // TWO answers on ONE member key, which needs a `Locality::Any` member
    // answered by both a loopback queryable and a wire peer; no fixture stages
    // that. It is kept because the upstream site is the same call with the same
    // decision, not because a local red proves it. Do not read it as
    // load-bearing.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
    let reply_state = Arc::clone(state);
    let reply_clock = Arc::clone(clock);
    let _ = session.query(
        &keyexpr,
        opts,
        move |reply: &dyn ReplyView| {
            if let Ok(member) = decode_member(reply.payload()) {
                reply_state.insert_member(
                    member.mid.clone(),
                    member,
                    reply_clock.now_monotonic_ms(),
                );
            }
        },
        move |_rid| {},
    );
}

/// Evict every member whose lease deadline has passed and emit a
/// [`GroupEvent::LeaseExpired`] for each. The wz equivalent of zenoh-ext's
/// `watchdog_task` body (group.rs:201-227).
fn sweep_expired(state: &Arc<GroupState>, now_ms: u64) {
    let mut expired: Vec<String> = Vec::new();
    {
        let mut ms = state.members.lock().expect("group members mutex poisoned");
        ms.retain(|mid, (_, alive_till)| {
            if *alive_till < now_ms {
                expired.push(mid.clone());
                false
            } else {
                true
            }
        });
    }
    for mid in expired {
        state.send_event(GroupEvent::LeaseExpired(mid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    fn loopback_session() -> TokioSession {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        // The `_driver` half is bound for the test scope; the loopback
        // dispatch runs over `actions` (the same fixture the advanced pub/sub
        // tests use).
        TokioSession::new(actions, observer, clock)
    }

    fn member_ids(members: &[Member]) -> Vec<String> {
        let mut ids: Vec<String> = members.iter().map(|m| m.mid.clone()).collect();
        ids.sort();
        ids
    }

    /// keepalive_period_ms = lease * refresh_ratio (the beacon must precede the
    /// lease elapsing), clamped to >= 1ms BY CONSTRUCTION (the spin guard lives
    /// in the function, not the call site).
    #[test]
    fn keepalive_period_is_lease_times_ratio() {
        assert_eq!(
            keepalive_period_ms(Duration::from_secs(18), 0.75),
            13_500,
            "18s * 0.75 = 13.5s"
        );
        // A degenerate zero period would spin the beacon; the function floors it.
        assert_eq!(
            keepalive_period_ms(Duration::from_millis(0), 0.75),
            1,
            "clamped to >= 1ms by construction, not at the call site"
        );
    }

    #[test]
    fn wildcard_ids_are_rejected_by_is_wild() {
        assert!(is_wild("a/*/b"));
        assert!(is_wild("a/**"));
        assert!(!is_wild("a/b/c"));
    }

    /// A member that joins while a peer's subscriber is already declared shows
    /// up in that peer's view (the loopback publish drains synchronously). The
    /// later joiner has not yet seen the earlier member (its Join was published
    /// before the later subscriber existed) — the late-joiner gap the
    /// keep-alive recovery below closes.
    #[cfg(feature = "pubsub-allow-loop")]
    #[tokio::test]
    async fn join_propagates_to_an_existing_member() {
        let session = loopback_session();
        let opts = GroupOptions::new().with_get_locality(Locality::SessionLocal);

        let group_a = Group::join(&session, "grp", Member::new("a"), opts).expect("a joins");
        let group_b = Group::join(&session, "grp", Member::new("b"), opts).expect("b joins");

        // B's Join reached A's already-declared subscriber.
        assert_eq!(group_a.size(), 2, "A sees itself + B");
        assert_eq!(
            member_ids(&group_a.view()),
            vec!["a".to_string(), "b".to_string()]
        );
        // B joined after A's Join was published, so B has not learned A yet.
        assert_eq!(group_b.size(), 1, "B sees only itself until a beacon");
        // Leader = the lexicographically greatest id.
        assert_eq!(group_a.leader().mid, "b");
        // A already has 2 members -> the fast path returns immediately.
        assert!(
            group_a
                .wait_for_view_size(2, Duration::from_millis(0))
                .await
        );
    }

    /// The late-joiner recovery path: B does not know A until A beacons. A's
    /// keep-alive reaches B's subscriber, B sees an unknown member, queries A's
    /// per-member queryable, and learns A — all synchronously over the
    /// loopback (publish -> subscriber callback -> nested GET -> queryable
    /// reply -> insert).
    #[cfg(feature = "pubsub-allow-loop")]
    #[tokio::test]
    async fn keepalive_recovers_unknown_member_via_query() {
        let session = loopback_session();
        let opts = GroupOptions::new().with_get_locality(Locality::SessionLocal);

        let group_a = Group::join(&session, "grp", Member::new("a"), opts).expect("a joins");
        let group_b = Group::join(&session, "grp", Member::new("b"), opts).expect("b joins");
        assert_eq!(group_b.size(), 1, "B has not learned A yet");

        // A beacons -> B's subscriber sees an unknown member id -> B GETs A's
        // queryable -> B learns A.
        group_a.assert_liveliness().expect("a beacons");

        assert_eq!(
            group_b.size(),
            2,
            "B recovered A via the unknown-member GET"
        );
        assert_eq!(
            member_ids(&group_b.view()),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    /// `join` off a tokio runtime fails clear with `NoRuntime` (the watchdog
    /// spawn would otherwise panic), not a panic. Runs outside any runtime.
    #[test]
    fn join_off_runtime_fails_clear_not_panic() {
        let session = loopback_session();
        let result = Group::join(&session, "grp", Member::new("a"), GroupOptions::new());
        assert!(matches!(result, Err(GroupError::NoRuntime)));
    }

    #[test]
    fn wildcard_member_id_is_rejected() {
        let session = loopback_session();
        let result = Group::join(&session, "grp", Member::new("a/*"), GroupOptions::new());
        assert!(matches!(result, Err(GroupError::WildcardMemberId(_))));
    }
}
