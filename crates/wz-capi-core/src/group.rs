// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R2932 — the group membership plane of a C session: ONE zenoh-ext `Group`
//! as the C program sees it, over the N wz groups the face registry holds.
//!
//! ## Why there is an aggregate at all
//!
//! A zenoh-c session is one session with many peers; a wz unicast session is
//! one peer. [`crate::faces::SharedSession`] therefore joins a C group once
//! per face (the wire half, [`Locality::Remote`]) and once on the local plane
//! (the in-process half, [`Locality::SessionLocal`]), exactly as it replays
//! every other declaration. Each of those wz groups sees only the members its
//! own session can reach. The C program asked for ONE group, so the answer it
//! gets — the view, the size, the leader and the event stream — is the UNION,
//! and the union is what this module keeps.
//!
//! ## Why the view is read from the events, not from the per-face groups
//!
//! One source for both, so the two cannot disagree: a C callback told
//! `Join(x)` that then asks for the view finds `x` in it, and a member is
//! reported gone exactly when the last face that could see it stops seeing it.
//! Reading the per-face views instead would answer the view from one
//! instant and the events from another. What makes the events a complete
//! source is [`Group::join_with_events`]: the channel exists before the group
//! can hear anything, so no membership change reaches a per-face view without
//! also reaching this aggregate.
//!
//! ## Event semantics across faces
//!
//! - `Join(m)` is delivered when `m` enters the union — the FIRST face to see
//!   it. The same member heard through a second face updates the stored record
//!   and is not announced twice.
//! - `Leave(mid)` / `LeaseExpired(mid)` are delivered when `mid` leaves the
//!   union — the LAST face that saw it — with the kind of that last removal.
//! - A face going DOWN removes its contribution; a member only that face could
//!   see leaves the union and is delivered as `LeaseExpired`. This is the one
//!   departure from upstream's timing, which would report the same member as
//!   expired one lease later: the lease can no longer be refreshed over a link
//!   that is gone, and a view that shrank without an event would break the
//!   one-source property above.
//! - `NewLeader` is passed through. Upstream declares it and never sends it,
//!   and so does the wz group, so it does not occur.
//!
//! ## Locking
//!
//! Two mutexes, and the split is what makes re-entry from a C callback safe.
//! `members` is never held across a C call, so a callback may read the view.
//! `sink` IS held across the C call, which is what serialises delivery and
//! lets a retirement free the C context synchronously (the matching plane's
//! R311y535 argument). A callback that tries to take `sink` for its OWN
//! aggregate would wait on its own frame; [`GroupAggregate::delivering_here`]
//! is how the callers that need `sink` recognise that case and refuse it
//! rather than deadlock.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Condvar, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use wz_runtime_tokio::group::{Group, GroupEvent, Member};
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};

// Re-exported for the ABI shims, which name these in their signatures.
pub use wz_runtime_tokio::group::{GroupError, MemberLiveliness};
pub use wz_runtime_tokio::locality::Locality;

/// A C-level group id, keying the per-face wz groups one C join spawned.
pub type GroupId = u64;

/// What a C group's events are delivered to. Owned by the aggregate, so
/// retiring it is what runs the C `drop(context)`.
pub type GroupEventSink = Box<dyn FnMut(&GroupEvent) + Send + 'static>;

/// Which per-session copy of a C group a membership was heard through.
///
/// Minted fresh for every copy rather than taken from the face id, because a
/// face id is REUSED: the dial role brings every reconnect up under the same
/// `DIAL_FACE_ID`. A token that outlived its copy could then be revived by a
/// late event from the forwarder of the copy that is gone, and the union would
/// hold a member through a session that no longer exists. With a fresh token
/// per copy, [`GroupAggregate::forget`] can retire it for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Via(u64);

impl Via {
    fn fresh() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// One remote member in the union: its latest record and the sessions that
/// currently see it. Never empty while stored.
struct Seen {
    member: Member,
    via: BTreeSet<Via>,
}

/// The union, and the copies that may no longer contribute to it.
#[derive(Default)]
struct Union {
    seen: BTreeMap<String, Seen>,
    /// Copies [`GroupAggregate::forget`] retired. An event their forwarder
    /// was already carrying when the copy dropped is ignored instead of
    /// re-adding a member through a session that is gone. Grows by one per
    /// face that went down while this group was joined.
    retired: BTreeSet<Via>,
}

/// The cross-face state behind ONE C group. See the module doc.
pub struct GroupAggregate {
    local_member: Member,
    gid: String,
    members: StdMutex<Union>,
    /// Signalled on every change of `members`; paired with that mutex.
    changed: Condvar,
    sink: StdMutex<Option<GroupEventSink>>,
}

thread_local! {
    /// The aggregates whose sink THIS thread is currently inside, innermost
    /// last. A stack rather than a flag because a C callback may re-enter the
    /// session and reach another group's delivery.
    static DELIVERING: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Marks `agg` as delivering on this thread for the guard's lifetime.
struct DeliveryMark(usize);

impl DeliveryMark {
    fn enter(agg: &GroupAggregate) -> Self {
        let key = agg as *const GroupAggregate as usize;
        DELIVERING.with(|d| d.borrow_mut().push(key));
        Self(key)
    }
}

impl Drop for DeliveryMark {
    fn drop(&mut self) {
        DELIVERING.with(|d| {
            let mut d = d.borrow_mut();
            if let Some(pos) = d.iter().rposition(|k| *k == self.0) {
                d.remove(pos);
            }
        });
    }
}

/// Why [`GroupAggregate::subscribe`] refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SubscribeRefused {
    /// Called from inside this group's own event callback, where the sink is
    /// held by the calling frame.
    InsideOwnCallback,
}

impl GroupAggregate {
    pub(crate) fn new(gid: String, local_member: Member) -> Self {
        Self {
            local_member,
            gid,
            members: StdMutex::new(Union::default()),
            changed: Condvar::new(),
            sink: StdMutex::new(None),
        }
    }

    fn members(&self) -> MutexGuard<'_, Union> {
        // Poison-tolerant for the reason `SharedSession::lock` gives: a map
        // cannot be left torn by a panic, and refusing to serve is worse.
        self.members
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sink(&self) -> MutexGuard<'_, Option<GroupEventSink>> {
        self.sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether this thread is inside THIS aggregate's C callback.
    pub fn delivering_here(&self) -> bool {
        let key = self as *const GroupAggregate as usize;
        DELIVERING.with(|d| d.borrow().contains(&key))
    }

    /// The group id this C group joined.
    pub fn group_id(&self) -> &str {
        &self.gid
    }

    /// The local member.
    pub fn local_member(&self) -> &Member {
        &self.local_member
    }

    /// The union view: every member some session of this C session sees,
    /// plus the local member, ordered by member id.
    pub fn view(&self) -> Vec<Member> {
        let members = self.members();
        let mut view: Vec<Member> = members.seen.values().map(|s| s.member.clone()).collect();
        view.push(self.local_member.clone());
        view.sort_by(|a, b| a.id().cmp(b.id()));
        view
    }

    /// The union size, the local member included.
    pub fn size(&self) -> usize {
        self.members().seen.len() + 1
    }

    /// The member with the lexicographically greatest id — upstream's rule
    /// (`zenoh-ext/src/group.rs` @ `pub async fn leader(&self) -> Member {`),
    /// applied to the union.
    pub fn leader(&self) -> Member {
        let members = self.members();
        let mut leader = &self.local_member;
        for seen in members.seen.values() {
            if leader.id() < seen.member.id() {
                leader = &seen.member;
            }
        }
        leader.clone()
    }

    /// Block until the union holds at least `size` members or `timeout`
    /// elapses; whether it got there.
    ///
    /// From inside this group's own callback it answers at once: every change
    /// is delivered through the sink the calling frame holds, so waiting there
    /// would wait for a delivery that cannot start until it returns.
    pub fn wait_for_view_size(&self, size: usize, timeout: Duration) -> bool {
        let mut members = self.members();
        if members.seen.len() + 1 >= size || self.delivering_here() {
            return members.seen.len() + 1 >= size;
        }
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            members = self
                .changed
                .wait_timeout(members, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
            if members.seen.len() + 1 >= size {
                return true;
            }
        }
    }

    /// Install (or replace) the C sink, returning the one it displaced so the
    /// CALLER drops it outside every lock. Upstream's `subscribe` is
    /// last-wins as well (`zenoh-ext/src/group.rs` @ `pub fn subscribe`).
    pub fn subscribe(
        &self,
        sink: GroupEventSink,
    ) -> Result<Option<GroupEventSink>, SubscribeRefused> {
        if self.delivering_here() {
            return Err(SubscribeRefused::InsideOwnCallback);
        }
        Ok(self.sink().replace(sink))
    }

    /// Take the C sink out so the caller can drop it — the synchronous release
    /// behind a C group drop. `None` from inside this group's own callback,
    /// where the sink stays and falls with the aggregate's last `Arc`.
    pub(crate) fn retire(&self) -> Option<GroupEventSink> {
        if self.delivering_here() {
            return None;
        }
        self.sink().take()
    }

    /// Fold one event heard through `via` into the union and deliver it to C
    /// if it moved the union.
    pub(crate) fn apply(&self, via: Via, event: GroupEvent) {
        let mut sink = self.sink();
        let deliver = {
            let mut members = self.members();
            if members.retired.contains(&via) {
                return;
            }
            let deliver = match &event {
                GroupEvent::Join(member) => {
                    let seen = members
                        .seen
                        .entry(member.mid.clone())
                        .or_insert_with(|| Seen {
                            member: member.clone(),
                            via: BTreeSet::new(),
                        });
                    let first = seen.via.is_empty();
                    seen.member = member.clone();
                    seen.via.insert(via);
                    first
                }
                GroupEvent::Leave(mid) | GroupEvent::LeaseExpired(mid) => {
                    remove_via(&mut members.seen, mid, via)
                }
                GroupEvent::NewLeader(_) => true,
            };
            self.changed.notify_all();
            deliver
        };
        if deliver {
            Self::deliver(self, &mut sink, &event);
        }
    }

    /// Retire `via` for good (its session is gone), remove its whole
    /// contribution, and deliver a `LeaseExpired` for each member that left
    /// the union with it.
    pub(crate) fn forget(&self, via: Via) {
        let mut sink = self.sink();
        let gone: Vec<String> = {
            let mut members = self.members();
            members.retired.insert(via);
            let mids: Vec<String> = members
                .seen
                .iter()
                .filter(|(_, seen)| seen.via.contains(&via))
                .map(|(mid, _)| mid.clone())
                .collect();
            let gone = mids
                .into_iter()
                .filter(|mid| remove_via(&mut members.seen, mid, via))
                .collect();
            self.changed.notify_all();
            gone
        };
        for mid in gone {
            Self::deliver(self, &mut sink, &GroupEvent::LeaseExpired(mid));
        }
    }

    fn deliver(agg: &Self, sink: &mut MutexGuard<'_, Option<GroupEventSink>>, event: &GroupEvent) {
        if let Some(sink) = sink.as_mut() {
            let _mark = DeliveryMark::enter(agg);
            sink(event);
        }
    }
}

/// Drop `via` from `mid`'s set; `true` when that emptied it (the member left
/// the union). A `mid` not stored, or not seen through `via`, changes nothing.
fn remove_via(members: &mut BTreeMap<String, Seen>, mid: &str, via: Via) -> bool {
    let Some(seen) = members.get_mut(mid) else {
        return false;
    };
    if !seen.via.remove(&via) {
        return false;
    }
    if seen.via.is_empty() {
        members.remove(mid);
        return true;
    }
    false
}

/// One session's copy of a C group: the wz group and the task that forwards
/// its events into the aggregate. Dropping it leaves the group on that session
/// (RAII inside [`Group`]) and stops the forwarder.
pub(crate) struct FaceGroup {
    _group: Group<TokioRuntime, TokioTime>,
    forward: tokio::task::JoinHandle<()>,
    via: Via,
    agg: std::sync::Arc<GroupAggregate>,
}

impl Drop for FaceGroup {
    fn drop(&mut self) {
        self.forward.abort();
    }
}

/// Leave the group on a session that is GOING AWAY: drop the copy, then take
/// its contribution out of the union.
///
/// In that order, and the order is the point: the copy's forwarder may still
/// be carrying an event when the copy drops, and [`GroupAggregate::forget`]
/// retiring the token is what stops that event re-adding a member afterwards.
/// Runs C callbacks (the `LeaseExpired`s), so call it with no registry lock
/// held.
pub(crate) fn retire_copies(copies: impl IntoIterator<Item = FaceGroup>) {
    for copy in copies {
        let (agg, via) = (std::sync::Arc::clone(&copy.agg), copy.via);
        drop(copy);
        agg.forget(via);
    }
}

impl FaceGroup {
    /// Join `agg`'s group as its local member on `session`, forwarding every
    /// event heard there into `agg` under a freshly minted [`Via`].
    ///
    /// `locality` is the half this session serves — see
    /// [`wz_runtime_tokio::group::GroupOptions::event_locality`]. The unknown
    /// member recovery `get` is pinned to the same half, for the same reason.
    pub(crate) fn join(
        session: &wz_runtime_tokio::session::TokioSession,
        agg: &std::sync::Arc<GroupAggregate>,
        locality: Locality,
        priority: wz_runtime_tokio::qos::Priority,
    ) -> Result<Self, GroupError> {
        use wz_runtime_tokio::runtime_pool::WzRuntime;
        let options = wz_runtime_tokio::group::GroupOptions::new()
            .with_event_locality(locality)
            .with_get_locality(locality)
            .with_event_priority(priority);
        // `Group::join` refuses to run outside a runtime context, because its
        // keep-alive and watchdog once were bare `tokio::spawn`s. They now name
        // the APPLICATION subsystem, so that is the context entered here: it is
        // where they land whichever thread joins, and the C application thread
        // — where a C program joins — has no runtime of its own to offer.
        let _rt = WzRuntime::Application.handle().enter();
        let (group, mut events) =
            Group::join_with_events(session, agg.gid.clone(), agg.local_member.clone(), options)?;
        let keep = std::sync::Arc::clone(agg);
        let agg = std::sync::Arc::clone(agg);
        let via = Via::fresh();
        // The APPLICATION subsystem too: the forwarder consumes what the
        // keep-alive and watchdog produce, and it must not run on the C
        // application thread, which the `unsafe impl Sync` premise of every C
        // closure on these ABIs forbids.
        let forward = WzRuntime::Application.spawn(async move {
            while let Some(event) = events.recv().await {
                agg.apply(via, event);
            }
        });
        Ok(Self {
            _group: group,
            forward,
            via,
            agg: keep,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // Fixed tokens: these tests never mint one, so they cannot collide.
    const FACE_A: Via = Via(1);
    const FACE_B: Via = Via(2);
    const PLANE: Via = Via(3);

    fn agg_with_log() -> (Arc<GroupAggregate>, Arc<Mutex<Vec<String>>>) {
        let agg = Arc::new(GroupAggregate::new("g".into(), Member::new("me")));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        agg.subscribe(Box::new(move |e: &GroupEvent| {
            let line = match e {
                GroupEvent::Join(m) => format!("join {}", m.id()),
                GroupEvent::Leave(mid) => format!("leave {mid}"),
                GroupEvent::LeaseExpired(mid) => format!("expired {mid}"),
                GroupEvent::NewLeader(mid) => format!("leader {mid}"),
            };
            sink_log.lock().unwrap().push(line);
        }))
        .unwrap();
        (agg, log)
    }

    /// The union announces a member once however many faces see it, and
    /// reports it gone only when the LAST of them stops.
    #[test]
    fn a_member_seen_through_two_faces_joins_and_leaves_once() {
        let (agg, log) = agg_with_log();
        agg.apply(FACE_A, GroupEvent::Join(Member::new("x")));
        agg.apply(FACE_B, GroupEvent::Join(Member::new("x")));
        assert_eq!(agg.size(), 2);
        agg.apply(FACE_A, GroupEvent::Leave("x".into()));
        assert_eq!(agg.size(), 2, "face 2 still sees x");
        agg.apply(FACE_B, GroupEvent::LeaseExpired("x".into()));
        assert_eq!(agg.size(), 1);
        assert_eq!(*log.lock().unwrap(), ["join x", "expired x"]);
    }

    /// A face going down takes its members with it, and each one that leaves
    /// the union is reported, so the view never shrinks silently.
    #[test]
    fn a_face_down_expires_only_the_members_no_other_session_sees() {
        let (agg, log) = agg_with_log();
        agg.apply(FACE_A, GroupEvent::Join(Member::new("a")));
        agg.apply(FACE_A, GroupEvent::Join(Member::new("b")));
        agg.apply(PLANE, GroupEvent::Join(Member::new("b")));
        agg.forget(FACE_A);
        let ids: Vec<String> = agg.view().iter().map(|m| m.id().to_owned()).collect();
        assert_eq!(ids, ["b", "me"]);
        assert_eq!(*log.lock().unwrap(), ["join a", "join b", "expired a"]);
    }

    /// A copy that was forgotten cannot add to the union again: an event its
    /// forwarder was still carrying when the copy dropped is ignored.
    #[test]
    fn a_retired_copy_cannot_revive_a_member() {
        let (agg, log) = agg_with_log();
        agg.forget(FACE_A);
        agg.apply(FACE_A, GroupEvent::Join(Member::new("late")));
        assert_eq!(agg.size(), 1);
        assert!(log.lock().unwrap().is_empty());
    }

    /// A removal for a member the union never held is not delivered: C was
    /// never told it joined.
    #[test]
    fn an_unknown_member_leaving_is_silent() {
        let (agg, log) = agg_with_log();
        agg.apply(FACE_A, GroupEvent::Leave("ghost".into()));
        assert!(log.lock().unwrap().is_empty());
    }

    /// The leader is upstream's rule over the union, the local member included.
    #[test]
    fn the_leader_is_the_greatest_id_in_the_union() {
        let (agg, _log) = agg_with_log();
        assert_eq!(agg.leader().id(), "me");
        agg.apply(FACE_B, GroupEvent::Join(Member::new("zz")));
        assert_eq!(agg.leader().id(), "zz");
    }

    /// A callback may read the view, and a subscribe from inside its own
    /// callback is refused instead of deadlocking on the sink it runs under.
    #[test]
    fn a_callback_can_read_the_view_and_cannot_resubscribe_itself() {
        let agg = Arc::new(GroupAggregate::new("g".into(), Member::new("me")));
        let seen_size = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let (inner, size, refusals) = (
            Arc::clone(&agg),
            Arc::clone(&seen_size),
            Arc::clone(&refused),
        );
        agg.subscribe(Box::new(move |_e: &GroupEvent| {
            size.store(inner.size(), Ordering::SeqCst);
            if inner.subscribe(Box::new(|_e: &GroupEvent| {})).is_err() {
                refusals.fetch_add(1, Ordering::SeqCst);
            }
            assert!(inner.wait_for_view_size(2, Duration::from_secs(5)));
        }))
        .unwrap();
        agg.apply(PLANE, GroupEvent::Join(Member::new("x")));
        assert_eq!(seen_size.load(Ordering::SeqCst), 2);
        assert_eq!(refused.load(Ordering::SeqCst), 1);
    }

    /// A waiter is woken by a join on another thread rather than by its
    /// timeout.
    #[test]
    fn a_waiter_wakes_on_growth() {
        let (agg, _log) = agg_with_log();
        let joiner = Arc::clone(&agg);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            joiner.apply(FACE_A, GroupEvent::Join(Member::new("x")));
        });
        let start = Instant::now();
        assert!(agg.wait_for_view_size(2, Duration::from_secs(10)));
        assert!(start.elapsed() < Duration::from_secs(5));
        t.join().unwrap();
    }
}
