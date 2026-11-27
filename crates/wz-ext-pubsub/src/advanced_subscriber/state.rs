// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The per-source ordering machine of an advanced subscriber, and the sample-miss listeners it
//! reports holes to.
//!
//! The machine takes a sample or an event, calls the sample callback and the miss listeners it
//! holds, and hands back the one thing its host must do: a [`RecoveryRequest`] (or whether to
//! issue a history get), so that the get is issued with the machine's lock released. It reads no
//! clock: every method that reaches a source's state takes the host's reading in milliseconds,
//! which is what a source's retention is measured in.

use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use core::ffi::c_void;
#[cfg(feature = "advanced-retention")]
use core::time::Duration;

#[cfg(feature = "advanced-recovery")]
use wz_session_core::caps;
#[cfg(feature = "advanced-history")]
use wz_session_core::sample::{timestamp_strictly_newer, TimestampHint};
use wz_session_core::sample::{EntityGlobalId, Sample, TimestampZid};
use wz_session_core::sink::SampleView;

#[cfg(feature = "advanced-recovery")]
use crate::advanced_cache::ring::{Order, RecordRing};
use crate::prelude::*;
use crate::sync::{lock_or_panic, Mutex, MutexGuard};

mod sources;

use sources::Sources;

/// What the state's lock panics with when a panic of its holder poisoned it.
pub(crate) const STATE_POISONED: &str = "advanced subscriber state mutex poisoned";

/// A detected gap in a sequenced source's stream: `nb` samples between the
/// last in-order delivery and the just-received `sn` were missed. Mirror of
/// `zenoh-ext/src/advanced_subscriber.rs` @ `pub struct Miss {`, field for
/// field and accessor for accessor.
///
/// R2814 — the source is ONE [`EntityGlobalId`], as upstream's is. It used to
/// be two public fields, `source_zid: Vec<u8>` and `source_eid: u32`: the same
/// information, split, so a caller that wanted to key on "which publisher"
/// had to rebuild the pair itself, and the zid cost an allocation per miss.
/// The fields are private because upstream's are; a `Miss` is something this
/// module reports, not something a caller constructs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Miss {
    source: EntityGlobalId,
    nb: u32,
}

impl Miss {
    /// The source whose samples were missed.
    pub fn source(&self) -> EntityGlobalId {
        self.source
    }

    /// How many samples were skipped (`sn - last_delivered - 1`).
    pub fn nb(&self) -> u32 {
        self.nb
    }

    /// A miss of `nb` samples of `source`. For a test of a host that reports misses
    /// to its own listeners; the machine builds its own.
    #[doc(hidden)]
    pub fn for_test(source: EntityGlobalId, nb: u32) -> Self {
        Self { source, nb }
    }
}

/// R2814 — THE MISS-LISTENER REGISTRY, upstream's
/// `zenoh-ext/src/advanced_subscriber.rs` @ `miss_handlers: HashMap<usize, Callback<Miss>>,`
/// with its `register_miss_callback` / `unregister_miss_callback` pair.
///
/// # Why a registry and not the one `on_miss` closure this module took before
///
/// Upstream declares a subscriber with NO miss callback at all; listeners are
/// declared afterwards, any number of them, each retractable on its own
/// (`sample_miss_listener()`). wz fixed exactly one closure at declare time, and
/// that one fact generated a defect in each C ABI that mirrors the upstream
/// call order: both kept a single slot that a listener "installs into", so a
/// second listener REPLACED the first, and dropping the first then cleared the
/// slot out from under the second. Nothing in either ABI was wrong locally —
/// the shape they were adapting to could not say "two listeners".
///
/// # Order
///
/// A `BTreeMap` keyed by registration id rather than upstream's `HashMap`, so
/// listeners fire in the order they were declared. Upstream promises no order;
/// registration order is one of the orders it permits, and a deterministic one
/// is what a test (or a C program) can reason about.
///
/// # The listener lent at declaration
///
/// A host that declares its subscriber with one listener from the start, in the raw form an
/// engine's own callbacks take ([`Self::lent`]), keeps it beside the map rather than in it, so
/// the declaration takes no memory for it. It is the first registered, so it fires first, which
/// is the order the map would give it.
///
/// # The map is reached through its own operations
///
/// The listeners registered after the declaration lie in a map made by the first
/// [`Self::register`] and reached through a table of its own operations: a host whose listeners
/// are its own, as the pico C ABI's are (one lent listener that fires its own set), never
/// registers one, so its build links no code of the map, and a miss is one call to that host's
/// set.
#[derive(Default)]
pub struct MissHandlers {
    next_id: usize,
    first: Option<FirstListener>,
    listeners: Option<Box<dyn Listeners>>,
}

/// What a registry does with the listeners registered after the declaration, in the order of
/// their ids.
trait Listeners: Send {
    /// Hold `handler` under `id`.
    fn hold(&mut self, id: usize, handler: Box<dyn FnMut(Miss) + Send>);
    /// Let go of the handler held under `id`, if one is.
    fn let_go(&mut self, id: usize);
    /// Report `miss` to every handler held.
    fn report(&mut self, miss: Miss);
}

impl Listeners for BTreeMap<usize, Box<dyn FnMut(Miss) + Send>> {
    fn hold(&mut self, id: usize, handler: Box<dyn FnMut(Miss) + Send>) {
        BTreeMap::insert(self, id, handler);
    }

    fn let_go(&mut self, id: usize) {
        BTreeMap::remove(self, &id);
    }

    fn report(&mut self, miss: Miss) {
        for handler in self.values_mut() {
            handler(miss);
        }
    }
}

impl MissHandlers {
    /// A registry holding one listener from the start, `call(context, miss)`, with
    /// `drop(context)` run once after its last call, when it is retracted or the registry is
    /// dropped.
    ///
    /// # Safety
    /// `call` may be made with `context` from any thread until `drop` runs, and `drop` with it
    /// once, after the last call, from any thread.
    pub unsafe fn lent(
        call: unsafe fn(*mut c_void, Miss),
        context: *mut c_void,
        drop: Option<unsafe fn(*mut c_void)>,
    ) -> Self {
        Self {
            next_id: 1,
            first: Some(FirstListener {
                id: 0,
                lent: Lent {
                    call,
                    context,
                    drop,
                },
            }),
            listeners: None,
        }
    }

    /// Hold `handler` and name it, so it can be retracted.
    pub fn register(&mut self, handler: Box<dyn FnMut(Miss) + Send>) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.listeners
            .get_or_insert_with(|| Box::new(BTreeMap::<usize, Box<dyn FnMut(Miss) + Send>>::new()))
            .hold(id, handler);
        id
    }

    /// Let go of the handler registered as `id`; one already gone is left alone.
    pub fn unregister(&mut self, id: usize) {
        if self.first.as_ref().is_some_and(|first| first.id == id) {
            self.first = None;
            return;
        }
        if let Some(listeners) = self.listeners.as_mut() {
            listeners.let_go(id);
        }
    }

    /// Report one miss to every registered listener. A miss with no listener
    /// is dropped, which is upstream's behaviour: the sample stream never
    /// depends on anyone listening for its holes.
    fn fire(&mut self, miss: Miss) {
        if let Some(FirstListener { lent, .. }) = self.first.as_ref() {
            // SAFETY: the maker of the listener lets it be called from any thread until its drop,
            // which runs only when this registry lets it go.
            unsafe { (lent.call)(lent.context, miss) };
        }
        if let Some(listeners) = self.listeners.as_mut() {
            listeners.report(miss);
        }
    }

    /// Whether the registry made its map of listeners, which only a registration does.
    #[cfg(test)]
    fn holds_a_map(&self) -> bool {
        self.listeners.is_some()
    }
}

// SAFETY: the boxed listeners are `Send`, and a lent one's maker lets it be called and let go
// of from any thread (`MissHandlers::lent`).
unsafe impl Send for MissHandlers {}

/// The listener a registry holds from the start ([`MissHandlers::lent`]), under the id it was
/// registered with.
struct FirstListener {
    id: usize,
    lent: Lent<unsafe fn(*mut c_void, Miss)>,
}

/// A callback in the raw form an engine's own callbacks take: a function, the context it reads,
/// and what lets the context go after the last call, run when this is dropped. It holds no memory
/// of its own.
struct Lent<F> {
    call: F,
    context: *mut c_void,
    drop: Option<unsafe fn(*mut c_void)>,
}

impl<F> Drop for Lent<F> {
    fn drop(&mut self) {
        if let Some(drop) = self.drop {
            // SAFETY: the maker's (`OnSample::lent`, `MissHandlers::lent`): run once, after the
            // last call.
            unsafe { drop(self.context) };
        }
    }
}

/// The sample callback of a machine: a function over a context, in the raw form an engine's own
/// callbacks take, with the context's drop run once after the last call. A host lends one, which
/// takes no memory ([`Self::lent`]), or hands the program's closure, boxed behind one
/// ([`Self::boxed`]). One form, so a sample is handed on by one call, and a host that lends its
/// callback links no code of a boxed one.
pub struct OnSample(Lent<unsafe fn(*mut c_void, Delivery<'_>)>);

/// A program's sample closure, as [`OnSample::boxed`] takes it.
type BoxedSample = Box<dyn FnMut(Delivery<'_>) + Send>;

impl OnSample {
    /// The program's closure.
    pub fn boxed(on_sample: BoxedSample) -> Self {
        // Boxed once more, so the context is one word.
        let context = Box::into_raw(Box::new(on_sample)).cast::<c_void>();
        // SAFETY: the context is the box made just above, read by `call_boxed` through the one
        // caller `Self::call`'s `&mut self` admits and dropped once by `drop_boxed`; the closure
        // is `Send`.
        unsafe { Self::lent(call_boxed, context, Some(drop_boxed)) }
    }

    /// `call(context, sample)`, with `drop(context)` run once after the last call, when this
    /// is dropped.
    ///
    /// # Safety
    /// As [`MissHandlers::lent`]'s.
    pub unsafe fn lent(
        call: unsafe fn(*mut c_void, Delivery<'_>),
        context: *mut c_void,
        drop: Option<unsafe fn(*mut c_void)>,
    ) -> Self {
        Self(Lent {
            call,
            context,
            drop,
        })
    }

    fn call(&mut self, sample: Delivery<'_>) {
        // SAFETY: the maker lets it be called from any thread until its drop (`Self::lent`).
        unsafe { (self.0.call)(self.0.context, sample) }
    }
}

/// Call the program's closure [`OnSample::boxed`] made `context` of.
///
/// # Safety
/// `context` is that box, not dropped yet, and no other call of it runs.
unsafe fn call_boxed(context: *mut c_void, sample: Delivery<'_>) {
    // SAFETY: the caller's.
    let on_sample = unsafe { &mut *context.cast::<BoxedSample>() };
    on_sample(sample);
}

/// Let go of the program's closure [`OnSample::boxed`] made `context` of.
///
/// # Safety
/// `context` is that box, dropped once, here, after its last call.
unsafe fn drop_boxed(context: *mut c_void) {
    // SAFETY: the caller's.
    drop(unsafe { Box::from_raw(context.cast::<BoxedSample>()) });
}

// SAFETY: a boxed callback is `Send`, and a lent one's maker lets it be called and let go of from
// any thread (`OnSample::lent`).
unsafe impl Send for OnSample {}

/// The lock a subscriber's state is under. A host that holds the state behind it hands a miss
/// listener that lock itself ([`StateCell`]), so it is the one type every host makes.
pub type StateLock = Mutex<State>;

/// The state under `lock`, locked. A lock a panic of its holder poisoned panics with the state's
/// own message: what it guards may be half changed.
pub fn lock_state(lock: &StateLock) -> MutexGuard<'_, State> {
    lock_or_panic(lock, STATE_POISONED)
}

/// What a miss listener reaches its subscriber's state through: the state's own lock, or what
/// holds the lock with the rest of the subscriber.
pub trait StateCell: Send + Sync {
    /// The subscriber's state, under its lock.
    fn state_cell(&self) -> &StateLock;
}

impl StateCell for StateLock {
    fn state_cell(&self) -> &StateLock {
        self
    }
}

/// R2814 — a declared sample-miss listener: upstream's
/// `zenoh-ext/src/advanced_subscriber.rs` @ `pub struct SampleMissListener<Handler> {`.
///
/// Dropping it retracts the listener, as upstream's `Drop` does; [`Self::undeclare`]
/// says when explicitly, and [`Self::background`] keeps it registered for the
/// life of the subscriber (upstream's `.background()` builder form).
///
/// It holds the subscriber's state WEAKLY. A listener that outlives its
/// subscriber has nothing left to hear from, and must not keep the
/// subscriber's callbacks alive by existing; retracting it afterwards is then
/// a no-op rather than an error.
///
/// ⚠ Listeners run while the subscriber's state is locked, exactly as
/// upstream's run under its `zlock!` — so a listener must not declare or
/// undeclare a listener on the same subscriber from inside its own callback.
pub struct SampleMissListener {
    id: usize,
    statesref: StatesRef,
    undeclare_on_drop: bool,
}

/// What a listener reaches its subscriber's state through.
enum StatesRef {
    /// The state's lock, held weakly.
    Weak(Weak<dyn StateCell>),
    /// A host's own weak count of its subscriber ([`SampleMissListener::lent`]).
    Lent {
        context: *mut c_void,
        unregister: unsafe fn(context: *mut c_void, id: usize),
        let_go: unsafe fn(context: *mut c_void),
    },
}

// SAFETY: a `Weak` of a `Send + Sync` cell is both; a lent context is admitted from any thread by
// `SampleMissListener::lent`'s contract, and is only read through its two functions.
unsafe impl Send for SampleMissListener {}
// SAFETY: as `Send`; a shared listener calls nothing.
unsafe impl Sync for SampleMissListener {}

impl SampleMissListener {
    /// The listener registered as `id` in the state `statesref` names.
    pub fn new(id: usize, statesref: Weak<impl StateCell + 'static>) -> Self {
        Self {
            id,
            statesref: StatesRef::Weak(statesref),
            undeclare_on_drop: true,
        }
    }

    /// The listener registered as `id` in the state a host reaches through `context`, a weak
    /// count of its own: `unregister(context, id)` retracts the listener, if the subscriber still
    /// stands, and `let_go(context)` lets go of the count, once, last. Nothing is allocated for
    /// it.
    ///
    /// # Safety
    /// `context` stands until `let_go(context)` runs, and both functions may be called with it
    /// from any thread.
    pub unsafe fn lent(
        id: usize,
        context: *mut c_void,
        unregister: unsafe fn(context: *mut c_void, id: usize),
        let_go: unsafe fn(context: *mut c_void),
    ) -> Self {
        Self {
            id,
            statesref: StatesRef::Lent {
                context,
                unregister,
                let_go,
            },
            undeclare_on_drop: true,
        }
    }

    /// Retract this listener now. Upstream's `undeclare`; consuming, so a
    /// retracted listener cannot be retracted twice.
    pub fn undeclare(mut self) {
        self.undeclare_impl();
    }

    /// Keep this listener registered until the subscriber itself goes away,
    /// without holding a handle — upstream's `.background()`, which declares
    /// a listener nobody can retract.
    pub fn background(mut self) {
        self.undeclare_on_drop = false;
    }

    fn undeclare_impl(&mut self) {
        // Cleared first, as upstream does, so a panic in here cannot make the
        // `Drop` below try again.
        self.undeclare_on_drop = false;
        match &self.statesref {
            StatesRef::Weak(statesref) => {
                if let Some(cell) = statesref.upgrade() {
                    lock_state(cell.state_cell())
                        .miss_handlers
                        .unregister(self.id);
                }
            }
            // SAFETY: `Self::lent`'s: the context stands until it is let go of, in the drop.
            StatesRef::Lent {
                context,
                unregister,
                ..
            } => unsafe { (*unregister)(*context, self.id) },
        }
    }
}

impl Drop for SampleMissListener {
    fn drop(&mut self) {
        if self.undeclare_on_drop {
            self.undeclare_impl();
        }
        if let StatesRef::Lent {
            context, let_go, ..
        } = self.statesref
        {
            // SAFETY: `Self::lent`'s: the count is let go of once, here, after its last use.
            unsafe { let_go(context) };
        }
    }
}

impl core::fmt::Debug for SampleMissListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SampleMissListener")
            .field("id", &self.id)
            .field("undeclare_on_drop", &self.undeclare_on_drop)
            .finish()
    }
}

/// Per-source ordering state. Tracks the last in-order delivered sequence
/// number; the recovery build adds the in-flight recovery-GET count
/// ([`Self::pending_queries`]), and the samples a source holds back lie in the
/// subscriber's ring as records of the source's row (`State::pending`)
/// — the wz mirror of zenoh-ext `SourceState<u32>` (advanced_subscriber.rs:
/// 444-448).
/// R2621 — THE RETENTION BOOKKEEPING EVERY PER-SOURCE STATE CARRIES, and the
/// reason it is one type rather than two fields copied into three structs.
///
/// wz's source maps were never reclaimed: `sequenced` and `timestamped` grew one
/// entry per distinct source ever seen, for the life of the subscriber, where
/// upstream bounds them by a retention period
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `async fn gc_task(statesref: Weak<Mutex<State>>, retention_period: Duration) {`).
/// That sweep needs exactly two things from a state — WHEN it was last touched,
/// and whether its publisher is still ALIVE — so they live together in the type
/// that exists because the sweep does.
///
/// ⚠ THE PAIR IS INDIVISIBLE AND THIS MODULE ALREADY SAID SO. Upstream's sweep
/// spares a live publisher rather than popping it
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `} else if state.alive {`), so a
/// sweep shipped without `alive` reclaims LIVE sources and destroys their
/// `last_delivered`, turning the next sample from that publisher into a false
/// gap. And `alive` shipped without the sweep is the write-only flag
/// [`TimestampedState`]'s own doc refuses — "a condition that can never be false
/// reads as coverage while grading nothing". Neither half is shippable alone,
/// which is why they arrive in one type in one round.
///
/// A state is created through `entry(..).or_insert_with(..)` at the moment its
/// source is first seen, so creation IS the first access: it starts at the
/// reading the host gave the call that created it, and not alive.
///
/// ⚠ SCOPED TO THE RETENTION FEATURE (`advanced-retention`, which implies
/// recovery), and the limit is stated rather than hidden: the retention PERIOD is
/// configured through `RecoveryConfig`, because that is where upstream puts it,
/// and upstream spawns its `gc_task` from the recovery path. A build without the
/// feature (the zenoh-pico preset's, whose subscriber keeps each source until it
/// goes) has no flag and no sweep: a source keeps its row until a new source takes
/// the one met longest ago among those that hold nothing back. Compiling the
/// bookkeeping into a build that can never sweep would be the dead surface this
/// module refuses elsewhere.
#[cfg(feature = "advanced-retention")]
struct Retention {
    /// When this source was last touched, in the host's milliseconds. Upstream's
    /// `latest_access`, which its sweep compares against `now` and its heartbeat
    /// arm refreshes.
    latest_access_ms: u64,
    /// Whether a LIVENESS TOKEN says this publisher is live — upstream's own
    /// wording, "Alive as per liveliness subscriber". Set true by the token's
    /// Put arm and false by its Delete arm; read only by the sweep.
    ///
    /// ⚠ DEFAULTS FALSE, and that is upstream's default rather than a guess:
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `alive: false,` in its
    /// `SourceState`'s `Default`. Defaulting TRUE was this round's first
    /// attempt and it is a silent no-op bug — nothing would ever clear the flag
    /// on a source that has no liveliness token, so the sweep would refresh
    /// every entry forever and reclaim nothing while appearing to run. False is
    /// also the right MEANING: the flag records a positive statement by a token,
    /// so its absence is "no token says so", not "assume live".
    alive: bool,
}

#[cfg(feature = "advanced-retention")]
impl Retention {
    /// A source seen for the first time at `now_ms`.
    fn new(now_ms: u64) -> Self {
        Self {
            latest_access_ms: now_ms,
            alive: false,
        }
    }

    /// Mark this source touched. Called wherever a state is reached for a
    /// sample, a beacon or a reply, so the sweep's age means "unheard from"
    /// rather than "declared long ago".
    fn touch(&mut self, now_ms: u64) {
        self.latest_access_ms = now_ms;
    }
}

struct SourceState {
    /// R2621 — see [`Retention`]. Carried by both shapes, because the gap this
    /// closes is the SUBSCRIBER surface's and not either shape's.
    #[cfg(feature = "advanced-retention")]
    retention: Retention,
    /// Last in-order delivered sequence number (`None` before the first
    /// sample from this source).
    last_delivered: Option<u32>,
    /// In-flight recovery GETs for this source (zenoh `pending_queries`): a
    /// new GET is only issued when this is 0, and the buffer is flushed when
    /// it returns to 0. Upstream counts in a `u64`; every increment here is
    /// behind that zero test, so the count is 0 or 1 and a `u32` holds it.
    #[cfg(feature = "advanced-recovery")]
    pending_queries: u32,
}

impl SourceState {
    /// A source first seen at `now_ms`. The reading is the retention clock's, so a build
    /// without the sweep, which has none, ignores it.
    fn new(now_ms: u64) -> Self {
        #[cfg(not(feature = "advanced-retention"))]
        let _ = now_ms;
        Self {
            #[cfg(feature = "advanced-retention")]
            retention: Retention::new(now_ms),
            last_delivered: None,
            #[cfg(feature = "advanced-recovery")]
            pending_queries: 0,
        }
    }

    /// Whether this source, in `slot`, may give its row to a new one: it holds no sample back
    /// and waits on no get.
    #[cfg(feature = "advanced-recovery")]
    fn idle(&self, slot: usize, out: &Outlet<'_>) -> bool {
        self.pending_queries == 0 && out.held(sequenced_owner(slot)) == 0
    }
}

/// R2553 — per-TIMESTAMPED-source state: the sibling of [`SourceState`] for a
/// publisher that orders by its timestamp's own id rather than by a sequence
/// number (the `uhlc` discriminator `AdvPublisherSource::Timestamped` names).
///
/// # Why a separate struct rather than the same one
///
/// Upstream shares it. At
/// `zenoh-ext/src/advanced_subscriber.rs` @ `timestamped_states: LruCache<ID, SourceState<Timestamp>>,`
/// it is the SAME
/// `SourceState<T>` the sequenced map holds, parameterised on `Timestamp`
/// instead of a sequence number. wz's [`SourceState`] is NOT generic (its
/// `last_delivered` is a `u32` and its held samples are found by sequence number), so
/// sharing it here would mean making the sequenced side generic over a
/// parameter only one arm ever varies. The fields that survive the change of
/// parameter are exactly the two below; the ones that do not — the miss
/// arithmetic — are the ones upstream never runs for a timestamped source
/// either. So the split follows the arithmetic rather than the type.
///
/// # What upstream carries here that this does not, and why it is not dropped quietly
///
/// * `pending_samples` — the reorder buffer. Absent by the deferral
///   `State::timestamped` documents; it is the NEXT part of this build.
/// * `alive` — upstream sets it from the liveliness Put/Delete pair and reads
///   it in ONE place:
///   `zenoh-ext/src/advanced_subscriber.rs` @ `} else if state.alive {`,
///   which is its LRU retention sweep. wz has no
///   retention sweep and no LRU: neither this map nor `sequenced` is ever
///   reclaimed, so an `alive` flag here would be written by the Delete arm and
///   read by nobody. That is the shape this module's own `timestamped` doc
///   calls out — "a condition that can never be false reads as coverage while
///   grading nothing" — so the flag waits for the sweep that would read it, and
///   the absence is recorded as a residual of the SUBSCRIBER surface (it is
///   missing for the sequenced shape in exactly the same way) rather than of
///   the `uhlc` shape this round builds.
#[cfg(feature = "advanced-history")]
struct TimestampedState {
    /// R2621 — see [`Retention`]. The `alive` flag this doc used to say was
    /// waiting for a sweep now HAS that sweep, so it lands here.
    #[cfg(feature = "advanced-retention")]
    retention: Retention,
    /// Newest instant delivered for this timestamp-id (`None` before the
    /// first). Upstream's `last_delivered: Option<T>` at `T = Timestamp`.
    last_delivered: Option<wz_session_core::sample::TimestampHint>,
    /// In-flight history GETs for this source, the timestamped twin of
    /// [`SourceState::pending_queries`]: the `uhlc` late-publisher trigger
    /// opens a slot and the GET's terminal Final closes it, so a second token
    /// Put for the same publisher while its cache GET is still outstanding does
    /// not fan a duplicate. 0 or 1, as [`SourceState::pending_queries`] is.
    pending_queries: u32,
}

#[cfg(feature = "advanced-history")]
impl TimestampedState {
    /// A timestamp-id first seen at `now_ms`.
    fn new(now_ms: u64) -> Self {
        #[cfg(not(feature = "advanced-retention"))]
        let _ = now_ms;
        Self {
            #[cfg(feature = "advanced-retention")]
            retention: Retention::new(now_ms),
            last_delivered: None,
            pending_queries: 0,
        }
    }
}

/// The timestamped ordering state when the history feature is OFF: the `uhlc`
/// late-publisher GET does not exist in that build, so there is no query to
/// count. Kept as a distinct definition rather than a `#[cfg]`-d-away field so
/// the history-off build carries no `pending_queries` it could never move —
/// the same reason [`SourceState`] gates its own two recovery fields.
#[cfg(not(feature = "advanced-history"))]
struct TimestampedState {
    /// R2621 — see [`Retention`]. Present in the history-off build too: an
    /// unreclaimed map grows the same either way, so the retention surface is
    /// not a history feature — though it IS a recovery one, because that is
    /// where its period is configured.
    #[cfg(feature = "advanced-retention")]
    retention: Retention,
    /// Newest instant delivered for this timestamp-id (`None` before the first).
    last_delivered: Option<wz_session_core::sample::TimestampHint>,
}

#[cfg(not(feature = "advanced-history"))]
impl TimestampedState {
    /// A timestamp-id first seen at `now_ms`.
    fn new(now_ms: u64) -> Self {
        #[cfg(not(feature = "advanced-retention"))]
        let _ = now_ms;
        Self {
            #[cfg(feature = "advanced-retention")]
            retention: Retention::new(now_ms),
            last_delivered: None,
        }
    }
}

/// Whether the timestamped source in `slot` may give its row to a new one: it holds no sample
/// back and waits on no get.
#[cfg(feature = "advanced-history")]
fn timestamped_idle(slot: usize, state: &TimestampedState, out: &Outlet<'_>) -> bool {
    state.pending_queries == 0 && out.held(timestamped_owner(slot)) == 0
}

/// The owner the records of the sequenced source in `slot` carry in the ring. No record carries
/// owner zero, which the ring keeps for a record let go.
#[cfg(feature = "advanced-recovery")]
fn sequenced_owner(slot: usize) -> u32 {
    u32::try_from(slot).map_or(u32::MAX, |slot| slot.saturating_add(1))
}

/// The owner the records of the timestamped source in `slot` carry: past every sequenced one.
#[cfg(feature = "advanced-recovery")]
fn timestamped_owner(slot: usize) -> u32 {
    sequenced_owner(caps::MAX_ADVANCED_SOURCES.saturating_add(slot))
}

/// The bytes the samples a subscriber's sources hold back lie in, as the records of one ring
/// (`advanced_cache::ring`), sized at build (`ADVANCED_SUBSCRIBER_PENDING_BYTES`) and kept with the
/// subscriber, so holding a sample takes no memory. Zeroed, it is an empty ring.
#[cfg(feature = "advanced-recovery")]
#[repr(C, align(8))]
struct PendingSpan([u8; caps::ADVANCED_SUBSCRIBER_PENDING_BYTES]);

#[cfg(feature = "advanced-recovery")]
impl PendingSpan {
    const fn empty() -> Self {
        Self([0; caps::ADVANCED_SUBSCRIBER_PENDING_BYTES])
    }

    /// The ring the span holds; none for a span too short for one record.
    fn ring(&mut self) -> Option<RecordRing<'_>> {
        RecordRing::over(&mut self.0)
    }
}

/// What a source's samples go on through: the ring that holds them back, the sample callback and
/// the miss listeners.
struct Outlet<'a> {
    #[cfg(feature = "advanced-recovery")]
    ring: Option<RecordRing<'a>>,
    on_sample: &'a mut OnSample,
    miss_handlers: &'a mut MissHandlers,
}

impl Outlet<'_> {
    /// Hand `sample` to the sample callback.
    fn deliver(&mut self, sample: Delivery<'_>) {
        self.on_sample.call(sample);
    }

    /// How many samples `owner` holds back.
    #[cfg(feature = "advanced-recovery")]
    fn held(&self, owner: u32) -> usize {
        self.ring.as_ref().map_or(0, |ring| ring.live(owner))
    }

    /// The record of `owner` held under `key`.
    #[cfg(feature = "advanced-recovery")]
    fn find(&self, owner: u32, order: Order, key: u64) -> Option<usize> {
        self.ring.as_ref()?.find(owner, order, key)
    }

    /// The record of `owner` held under the least key, with its key.
    #[cfg(feature = "advanced-recovery")]
    fn first(&self, owner: u32, order: Order) -> Option<(u64, usize)> {
        self.ring.as_ref()?.first(owner, order)
    }

    /// Hold `sample` back as a record of `owner`; `false` when the ring has no room for it.
    #[cfg(feature = "advanced-recovery")]
    fn hold(&mut self, owner: u32, sample: &Delivery<'_>) -> bool {
        self.ring
            .as_mut()
            .is_some_and(|ring| ring.place(owner, sample.view()))
    }

    /// Let the record at `at` go unseen.
    #[cfg(feature = "advanced-recovery")]
    fn let_go(&mut self, at: usize) {
        if let Some(ring) = self.ring.as_mut() {
            ring.let_go(at);
        }
    }

    /// Hand the record at `at` to the sample callback, lent where it lies, and let it go.
    #[cfg(feature = "advanced-recovery")]
    fn hand_on(&mut self, at: usize) {
        if let Some(ring) = self.ring.as_mut() {
            if let Some(view) = ring.view_at(at) {
                self.on_sample.call(Delivery::Lent(&view));
            }
            ring.let_go(at);
        }
    }

    /// Hand the record at `at` to the sample callback when `admit` says so of its timestamp,
    /// and let it go either way.
    #[cfg(feature = "advanced-history")]
    fn hand_on_if(&mut self, at: usize, admit: impl FnOnce(Option<&TimestampHint>) -> bool) {
        if let Some(ring) = self.ring.as_mut() {
            if let Some(view) = ring.view_at(at) {
                if admit(view.timestamp()) {
                    self.on_sample.call(Delivery::Lent(&view));
                }
            }
            ring.let_go(at);
        }
    }
}

/// What a recovery trigger asks the caller to do AFTER releasing the state
/// lock: issue a recovery GET against `(zid, eid)`'s `@adv` cache. Returned
/// (not issued inline) so the re-entrant `Session::query` runs without the
/// state mutex held. `to_sn = None` is the OPEN `_sn={from_sn}..` selector
/// (sample-driven + periodic); `Some(hb)` is the BOUNDED `_sn={from_sn}..{hb}`
/// the heartbeat trigger uses (it knows the publisher's last sn).
#[cfg(feature = "advanced-recovery")]
pub struct RecoveryRequest {
    /// The publisher's zid.
    pub zid: Vec<u8>,
    /// The publisher's entity id.
    pub eid: u32,
    /// The first sequence number to ask for.
    pub from_sn: u32,
    /// The last one, when the request is bounded.
    pub to_sn: Option<u32>,
}

/// A sample the machine is handed or hands on: a live one read where the session lent it, or
/// one the machine owns, because it held it in a reorder buffer or recovered it from a reply. A
/// sample is copied out of the session's memory only when the machine must keep it past the call
/// that lent it, so a sample delivered as it arrives takes no memory of its own. Both are borrowed,
/// so a delivery is as small as a reference whatever a sample holds.
pub enum Delivery<'a> {
    /// Read where it lies, for the length of the call.
    Lent(&'a dyn SampleView),
    /// One the machine owns, which the callback may take ([`Self::into_sample`]).
    Held(&'a mut Sample),
}

impl Delivery<'_> {
    /// The sample, read where it lies.
    pub fn view(&self) -> &dyn SampleView {
        match self {
            Self::Lent(view) => *view,
            Self::Held(sample) => &**sample,
        }
    }

    /// The sample as a value of its own: a lent one is copied out once, a held one moved out,
    /// leaving the machine an empty one to drop, which holds no memory.
    pub fn into_sample(self) -> Sample {
        match self {
            Self::Lent(view) => Sample::from_view(view),
            Self::Held(sample) => core::mem::replace(sample, Sample::new_del(String::new())),
        }
    }
}

/// The machine's callback for a consumer that keeps every sample it is handed.
pub fn owned_samples(
    mut on_sample: impl FnMut(Sample) + Send + 'static,
) -> Box<dyn FnMut(Delivery<'_>) + Send> {
    Box::new(move |delivery: Delivery<'_>| on_sample(delivery.into_sample()))
}

/// Per-source last-in-order-delivered tracking + the user callbacks.
/// Behind an `Arc<Mutex>` because the session may fire the subscriber
/// callback from different worker threads (the storage-service idiom).
///
/// R311y95 (review L1) — the `on_sample` / miss-listener callbacks are invoked
/// WHILE this `State` mutex is held (`deliver_and_flush` / `flush_sequenced` /
/// the ingest path all call them under the guard). This matches zenoh holding
/// the `zlock` across `callback.call` (advanced_subscriber.rs): a callback that
/// re-enters this same subscriber's `State` (e.g. by inspecting it) would
/// deadlock, so callbacks must stay self-contained. Issuing a recovery / history
/// GET is deliberately deferred OUTSIDE the lock (the `RecoveryRequest` return +
/// the host's `issue_recovery_get`) for exactly this reason.
pub struct State {
    /// `(zid, eid)` -> per-source ordering state.
    sequenced: Sources<EntityGlobalId, SourceState>,
    /// R2522 — TIMESTAMP-mode ordering: the newest instant delivered per
    /// timestamp-id, which is the second of upstream's three `handle_sample`
    /// arms (`zenoh-ext/src/advanced_subscriber.rs` @ `} else if let Some(timestamp) = sample.timestamp() {`).
    ///
    /// # Why the key is the TIMESTAMP's id and not a source_info zid
    ///
    /// These samples carry no source_info at all — that is what makes them the
    /// timestamped case. Upstream keys on `*timestamp.get_id()`, so the identity
    /// is the clock's, and two publishers sharing a zid share a state exactly as
    /// they do upstream.
    ///
    /// # Why a bare instant and not a `SourceState`, and what that gives up
    ///
    /// Read at the pin rather than assumed, because the assumption was wrong:
    /// upstream does NOT keep a bare instant. `zenoh-ext/src/advanced_subscriber.rs`
    /// @ `timestamped_states: LruCache<ID, SourceState<Timestamp>>,` reuses the
    /// SAME struct as the sequenced side, so the timestamped state carries
    /// `pending_samples` and `pending_queries` too.
    ///
    /// Two of those fields genuinely do not apply here and one does:
    ///
    /// * `Miss` / `nb` — never computed for a timestamped source in either
    ///   implementation. "The sample after this one" is not a thing a clock
    ///   defines, and upstream's timestamped arm calls no miss handler.
    /// * `pending_queries` — R2553 BUILT it ([`TimestampedState`]), because the
    ///   `uhlc` late-publisher GET needs the same one-in-flight gate the
    ///   sequenced side has.
    /// * `pending_samples` — still absent, and still the named residual: upstream
    ///   buffers a timestamped sample while a history GET is in flight
    ///   (`if (states.global_pending_queries == 0 && state.pending_queries == 0)
    ///   || states.max_history_depth == 1`) so the older recovered samples
    ///   deliver before the live ones, spilling through
    ///   `flush_timestamped_source` at the depth bound. wz's map holds the
    ///   ordering core plus the query gate, so a timestamped source seen DURING
    ///   the startup history query still delivers live-first.
    ///
    /// That remaining gap is a named residual of `ext-pubsub-advanced-history`,
    /// not an oversight of this field: it is the same buffering the sequenced
    /// side gets from `history_pending` + `max_history_depth` above, and the
    /// order this doc prescribed — the `uhlc` shape first, so the buffering has
    /// a subject — is the order R2552 + R2553 took.
    ///
    /// The comparison is `wz_session_core::sample::timestamp_strictly_newer`,
    /// which already implements uhlc's `(time, 16-byte LE id)` `Ord` — the
    /// primitive the storage plane's newer-wins gate keys off. STRICTLY newer,
    /// so a retransmission at an equal instant is dropped; upstream's
    /// `last_delivered.map(|t| t < *timestamp)` says the same.
    ///
    /// Ungated on purpose: `ext-pubsub-advanced-subscriber` (this module's own
    /// gate) now pulls `pubsub-timestamp`, so a `#[cfg]` here would be
    /// vacuously true — a condition that can never be false reads as coverage
    /// while grading nothing.
    timestamped: Sources<TimestampZid, TimestampedState>,
    /// The samples the sources hold back until they may go on: records of one ring in the
    /// subscriber's own bytes, each carrying its source's row as its owner. A sequenced source's
    /// are found by their sequence number and a timestamped source's by their time alone, since
    /// every sample of one timestamped row carries that row's timestamp id.
    #[cfg(feature = "advanced-recovery")]
    pending: PendingSpan,
    on_sample: OnSample,
    /// R2814 — every declared sample-miss listener; see [`MissHandlers`].
    miss_handlers: MissHandlers,
    /// R311y82 — whether forward gaps BUFFER + trigger a recovery GET (true)
    /// or report a [`Miss`] and deliver past the gap (false, the plain
    /// declare).
    #[cfg(feature = "advanced-recovery")]
    retransmission: bool,
    /// R311y86 — how many GLOBAL history GETs are in flight. While it is
    /// non-zero a live sample from an as-yet-undelivered source BUFFERS instead
    /// of delivering, so the (older) history delivers first; the buffers flush
    /// when the last one's terminal Final fires ([`State::finish_history`]).
    ///
    /// # Why a COUNT and not the `bool` this was until R2555
    ///
    /// Upstream's is a count — `zenoh-ext/src/advanced_subscriber.rs` @ `global_pending_queries: u64,`
    /// — and wz's `bool` was adequate only because wz issued exactly ONE global
    /// GET, at declare. A `bool` cannot tell "one outstanding" from "two", so
    /// the FIRST completion would clear it and release every buffered sample
    /// while a second GET was still returning older ones — which the
    /// strictly-newer and dup-drop tests would then discard. The ordering this
    /// module exists to provide would be silently lost, with no failing test,
    /// because nothing today issues a second one.
    ///
    /// R2555 WIDENS IT BEFORE THE FEATURE THAT NEEDS IT, and the widening is
    /// provably inert at the old population: this value was written exactly
    /// twice — once at construction (0 or 1) and once to `false` in
    /// `finish_history` — and nothing ever set it back, so it was monotonic 1
    /// to 0 and never exceeded 1. The whole suite passing unchanged across the
    /// change is therefore not merely reassuring, it is the proof.
    #[cfg(feature = "advanced-history")]
    global_pending_queries: usize,
    /// R2503 — the pending buffer's CEILING, from the same config the history
    /// GET's `_max` selector uses. `usize::MAX` when the user set no bound,
    /// which is upstream's own answer rather than a wz choice:
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `let max_history_depth = conf`
    /// reads `.history.as_ref().and_then(|h| h.max_samples).unwrap_or(usize::MAX)`,
    /// with the comment that an unbounded query "can receive unbounded number
    /// of responses". So the buffer bound exists BECAUSE the selector bound
    /// does, and one field carrying both roles is upstream's coupling, not a
    /// second meaning invented here.
    #[cfg(feature = "advanced-history")]
    max_history_depth: usize,
}

impl State {
    /// A machine that delivers to `on_sample` and reports holes to `miss_handlers`, with
    /// forward gaps reported and delivered past (the plain subscriber) and no history get in
    /// flight. [`Self::with_retransmission`] and [`Self::with_history`] configure the rest.
    pub fn new(
        on_sample: Box<dyn FnMut(Delivery<'_>) + Send>,
        miss_handlers: MissHandlers,
    ) -> Self {
        Self::delivering_to(OnSample::boxed(on_sample), miss_handlers)
    }

    /// [`Self::new`] over a sample callback in either of its forms.
    pub fn delivering_to(on_sample: OnSample, miss_handlers: MissHandlers) -> Self {
        Self {
            sequenced: Sources::new(),
            timestamped: Sources::new(),
            #[cfg(feature = "advanced-recovery")]
            pending: PendingSpan::empty(),
            on_sample,
            miss_handlers,
            #[cfg(feature = "advanced-recovery")]
            retransmission: false,
            #[cfg(feature = "advanced-history")]
            global_pending_queries: 0,
            #[cfg(feature = "advanced-history")]
            max_history_depth: usize::MAX,
        }
    }

    /// Buffer forward gaps and ask for a retransmission (the recovering subscriber), where the
    /// plain one reports a [`Miss`] and delivers past the hole.
    #[cfg(feature = "advanced-recovery")]
    pub fn with_retransmission(mut self, retransmission: bool) -> Self {
        self.retransmission = retransmission;
        self
    }

    /// Start with `global_pending_queries` history gets in flight (the startup get is one), the
    /// pending buffer bounded at `max_history_depth` samples.
    #[cfg(feature = "advanced-history")]
    pub fn with_history(mut self, global_pending_queries: usize, max_history_depth: usize) -> Self {
        self.global_pending_queries = global_pending_queries;
        self.max_history_depth = max_history_depth;
        self
    }

    /// The state [`Self::delivering_to`] makes, its retransmission and history set as
    /// [`Self::with_retransmission`] and [`Self::with_history`] set them, made in `place`: a state
    /// holds the bytes its sources hold samples back in (`ADVANCED_SUBSCRIBER_PENDING_BYTES`), so a
    /// host that keeps it in a place of its own writes it there rather than moving it there.
    #[cfg(feature = "engine-host")]
    pub(crate) fn write_in(
        place: &mut core::mem::MaybeUninit<Self>,
        on_sample: OnSample,
        miss_handlers: MissHandlers,
        retransmission: bool,
        global_pending_queries: usize,
        max_history_depth: usize,
    ) -> &mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: each field is written once through a pointer to it, inside the place; the span
        // the sources hold samples back in is written as zeroes, the empty ring
        // `PendingSpan::empty` is.
        unsafe {
            core::ptr::addr_of_mut!((*at).sequenced).write(Sources::new());
            core::ptr::addr_of_mut!((*at).timestamped).write(Sources::new());
            core::ptr::addr_of_mut!((*at).pending).write_bytes(0, 1);
            core::ptr::addr_of_mut!((*at).on_sample).write(on_sample);
            core::ptr::addr_of_mut!((*at).miss_handlers).write(miss_handlers);
            core::ptr::addr_of_mut!((*at).retransmission).write(retransmission);
            core::ptr::addr_of_mut!((*at).global_pending_queries).write(global_pending_queries);
            core::ptr::addr_of_mut!((*at).max_history_depth).write(max_history_depth);
        }
        // Every field is named here, so a field added to the state and not written above fails
        // to compile rather than leaving its place unwritten.
        let _every_field_written = |state: &Self| {
            let Self {
                sequenced: _,
                timestamped: _,
                pending: _,
                on_sample: _,
                miss_handlers: _,
                retransmission: _,
                global_pending_queries: _,
                max_history_depth: _,
            } = state;
        };
        // SAFETY: every field was written above.
        unsafe { place.assume_init_mut() }
    }

    /// The listener registry, for declaring and retracting a listener.
    pub fn miss_handlers(&mut self) -> &mut MissHandlers {
        &mut self.miss_handlers
    }

    /// The two tables of the sources, and what their samples go on through.
    fn parts(
        &mut self,
    ) -> (
        &mut Sources<EntityGlobalId, SourceState>,
        &mut Sources<TimestampZid, TimestampedState>,
        Outlet<'_>,
    ) {
        (
            &mut self.sequenced,
            &mut self.timestamped,
            Outlet {
                #[cfg(feature = "advanced-recovery")]
                ring: self.pending.ring(),
                on_sample: &mut self.on_sample,
                miss_handlers: &mut self.miss_handlers,
            },
        )
    }

    /// R2522 — upstream's SECOND and THIRD `handle_sample` arms: what to do
    /// with a sample that carries no `source_info`, and therefore no sequence
    /// number to order on.
    ///
    /// Upstream splits that case in two — `zenoh-ext/src/advanced_subscriber.rs` @ `} else if let Some(timestamp) = sample.timestamp() {`
    /// is the first half and its trailing `else` the second — and so does this:
    ///
    /// * WITH a timestamp — order by the clock. The sample is admitted only
    ///   when its instant is STRICTLY newer than the newest already delivered
    ///   for the same timestamp-id, so a retransmission at an equal instant and
    ///   a late arrival at an older one are both dropped. Upstream's
    ///   `state.last_delivered.map(|t| t < *timestamp).unwrap_or(true)` is the
    ///   same predicate; [`wz_session_core::sample::timestamp_strictly_newer`]
    ///   is the uhlc `(time, 16-byte LE id)` comparison it resolves to.
    /// * WITHOUT one — there is nothing to order by and nothing to
    ///   de-duplicate against, so deliver unconditionally. This is the arm wz
    ///   already had, and the reason it must stay LAST: it is the fallback, not
    ///   the rule.
    ///
    /// R2554 — ONE arm table, reached by every ingest path in every build. It
    /// used to be two (a `&dyn SampleView` copy for the live paths and an owned
    /// `Sample` copy for the recovered one), which is the duplication
    /// [`State::route_sample`] documents the cost of.
    /// R2555 — and it now BUFFERS as well as orders, which is the arm's second
    /// half and this atom's last residual. Upstream holds a timestamped sample
    /// while a history GET is in flight so the older recovered samples deliver
    /// ahead of it: `zenoh-ext/src/advanced_subscriber.rs` @ `if (states.global_pending_queries == 0 && state.pending_queries == 0)`
    /// selects between delivering now and buffering, and the buffer drains
    /// through `flush_timestamped_source`. wz's `history_pending` is that
    /// `global_pending_queries == 0` test and [`TimestampedState::pending_queries`]
    /// the per-source one.
    ///
    /// THE `max_history_depth == 1` ESCAPE IS UPSTREAM'S AND IS KEPT: a buffer
    /// of one can hold nothing that reordering would help, so that build
    /// delivers live rather than storing a single sample to hand straight back.
    fn deliver_unsequenced(&mut self, sample: Delivery<'_>, now_ms: u64) {
        let Some(ts) = sample.view().timestamp().cloned() else {
            self.on_sample.call(sample);
            return;
        };
        #[cfg(feature = "advanced-history")]
        let history_pending = self.global_pending_queries != 0;
        #[cfg(feature = "advanced-history")]
        let max_history_depth = self.max_history_depth;
        let (_, timestamped, mut out) = self.parts();
        #[cfg(feature = "advanced-history")]
        let may_go = |slot: usize, state: &TimestampedState| timestamped_idle(slot, state, &out);
        #[cfg(not(feature = "advanced-history"))]
        let may_go = |_: usize, _: &TimestampedState| true;
        let Some((slot, state)) =
            timestamped.entry(&ts.zid, || TimestampedState::new(now_ms), may_go)
        else {
            // A source the table has no row for goes on as it came, ordered by nothing.
            out.deliver(sample);
            return;
        };
        #[cfg(not(feature = "advanced-history"))]
        let _ = slot;
        // R2621 — a sample IS being heard from, so the retention clock restarts.
        #[cfg(feature = "advanced-retention")]
        state.retention.touch(now_ms);

        // STRICTLY newer, so a retransmission at an equal instant and a late
        // arrival at an older one are both dropped before anything else.
        if let Some(last) = &state.last_delivered {
            if !wz_session_core::sample::timestamp_strictly_newer(&ts, last) {
                return;
            }
        }

        #[cfg(feature = "advanced-history")]
        if (history_pending || state.pending_queries != 0) && max_history_depth != 1 {
            hold_timestamped(
                state,
                timestamped_owner(slot),
                &ts,
                sample,
                max_history_depth,
                &mut out,
            );
            return;
        }

        state.last_delivered = Some(ts);
        out.deliver(sample);
    }

    /// R2554 — THE SHAPE FORK, and there is exactly one of it.
    ///
    /// Upstream's `handle_sample` is a single function with three arms, called
    /// from nine sites; wz had the arms spread over THREE independent forks on
    /// `source_info` — the recovery-off live path, the recovery-on live path,
    /// and the reply path — and that is not a tidiness observation, it is the
    /// measured generator of a shipped defect. R2522 built the timestamped arm
    /// into TWO of the three; its commit message names the two it knew about
    /// ("shared by handle and handle_live") and its diff never touches the
    /// third, which sat 700 lines away over a different input type. A
    /// timestamped publisher's whole cache was therefore unreachable through
    /// every GET this module issues, for thirty rounds, and nothing could say
    /// so because no single place listed the arms.
    ///
    /// So the fork lives here, once, and the terminal arms are taken here:
    ///
    /// * WITH a timestamp and no `source_info` — order by the clock
    ///   ([`Self::deliver_unsequenced`]), STRICTLY newer per timestamp-id.
    /// * WITH neither — nothing to order by and nothing to de-duplicate
    ///   against, so deliver unconditionally. It must stay LAST: it is the
    ///   fallback, not the rule.
    /// * WITH `source_info` — the SEQUENCED arm, which is the one case this
    ///   cannot finish itself, because what a forward gap may do differs by
    ///   build (a recovery-off build reports a [`Miss`] and advances; a
    ///   recovery-on build buffers and asks for a retransmission). That case is
    ///   handed back to the caller with the source identity already read off
    ///   the sample, so no caller re-derives it.
    ///
    /// Returning the identity rather than taking a `key` argument also removes
    /// a state that could previously be constructed: the old
    /// `ingest_sequenced(key, sn, sample, ..)` let a caller pass a key that
    /// DISAGREED with the sample's own `source_info`. Every test did pass them
    /// redundantly; production could not, but nothing said so.
    ///
    /// R2814 — the identity comes back as an [`EntityGlobalId`] plus the
    /// sequence number, and a record whose zid is outside `1..=16` bytes takes
    /// the unsequenced arm. That is [`wz_session_core::sample::SourceInfo`]'s
    /// own contract ("any value outside `1..=16` should be treated by consumers
    /// as an absence-of-source"), and it is now decided here, once, instead of
    /// every sequenced arm keying on an empty zid.
    fn route_sample<'a>(
        &mut self,
        sample: Delivery<'a>,
        now_ms: u64,
    ) -> Option<(EntityGlobalId, u32, Delivery<'a>)> {
        let sequenced = sample
            .view()
            .source_info()
            .and_then(|info| info.source_id().map(|id| (id, info.sn)));
        match sequenced {
            Some((source, sn)) => Some((source, sn, sample)),
            None => {
                self.deliver_unsequenced(sample, now_ms);
                None
            }
        }
    }
}

/// R2555 — flush ONE timestamped source's reorder buffer, oldest instant
/// first. The wz mirror of `zenoh-ext/src/advanced_subscriber.rs` @ `fn flush_timestamped_source(`,
/// including both of its guards and its whole-buffer drain.
///
/// ⚠ THE `pending_queries != 0` GUARD IS UPSTREAM'S AND IS NOT A MISTAKE TO
/// CORRECT HERE, though it reads like one: it means the depth-bound spill
/// does NOTHING while this source's own GET is outstanding, so the buffer
/// can exceed the bound until that GET completes. Upstream carries exactly
/// that, and the guard is what makes the flush safe to call from all three
/// of its sites without each re-testing it. The bound is honoured the
/// moment the GET's terminal Final runs
/// ([`State::finish_timestamped_recovery`]).
///
/// ⚠⚠ It drains the WHOLE buffer where the sequenced spill (R2503) pops
/// only the oldest. That difference is upstream's too, and it follows from
/// the ordering: the sequenced buffer is waiting for a specific missing
/// sequence number to arrive and must keep the rest, while a clock defines
/// no hole to wait for — everything held is simply older than now.
///
/// The held samples are `owner`'s records in the ring, each compared by its
/// own timestamp through [`wz_session_core::sample::timestamp_strictly_newer`]
/// rather than an open-coded `u64` test.
#[cfg(feature = "advanced-history")]
fn flush_timestamped(state: &mut TimestampedState, owner: u32, out: &mut Outlet<'_>) {
    if state.pending_queries != 0 {
        return;
    }
    drain_timestamped(state, owner, out);
}

/// Hand on every sample `owner` holds back, oldest instant first, each only when it is newer
/// than the last handed on; the others are let go.
#[cfg(feature = "advanced-history")]
fn drain_timestamped(state: &mut TimestampedState, owner: u32, out: &mut Outlet<'_>) {
    while let Some((_, at)) = out.first(owner, Order::Time) {
        out.hand_on_if(at, |ts| match ts {
            Some(ts)
                if state
                    .last_delivered
                    .as_ref()
                    .is_none_or(|last| timestamp_strictly_newer(ts, last)) =>
            {
                state.last_delivered = Some(ts.clone());
                true
            }
            _ => false,
        });
    }
}

/// Hold the timestamped `sample`, stamped `ts`, back as a record of `owner` while the history it
/// would overtake is on its way. R2555 — upstream's `entry(..).or_insert(sample)`: the FIRST
/// sample at an instant wins, so a duplicate arriving while one is held does not displace it.
/// Past `depth` held samples the source is flushed, as upstream's bound flushes it.
///
/// A sample the ring has no room for is not held: what the source holds goes on first, oldest
/// first, and then it, so the ring's bound gives up the wait but never a sample or its order.
#[cfg(feature = "advanced-history")]
fn hold_timestamped(
    state: &mut TimestampedState,
    owner: u32,
    ts: &TimestampHint,
    sample: Delivery<'_>,
    depth: usize,
    out: &mut Outlet<'_>,
) {
    let held = out.find(owner, Order::Time, ts.time).is_some() || out.hold(owner, &sample);
    if !held {
        drain_timestamped(state, owner, out);
        let newer = state
            .last_delivered
            .as_ref()
            .is_none_or(|last| timestamp_strictly_newer(ts, last));
        if newer {
            state.last_delivered = Some(ts.clone());
            out.deliver(sample);
        }
        return;
    }
    if out.held(owner) >= depth {
        flush_timestamped(state, owner, out);
    }
}

#[cfg(not(feature = "advanced-recovery"))]
impl State {
    /// The zenoh `handle_sample` state machine (retransmission-off subset).
    ///
    /// R2554 — the shape decision is NOT made here any more; it is made once,
    /// in [`State::route_sample`], which also takes the two terminal arms. What
    /// is left here is the part that genuinely differs by build: a forward gap
    /// in a build with no retransmission reports a [`Miss`] and advances past
    /// it, where the recovery build buffers and asks.
    pub fn handle(&mut self, view: &dyn SampleView, now_ms: u64) {
        let Some((source, sn, sample)) = self.route_sample(Delivery::Lent(view), now_ms) else {
            return;
        };
        let (sequenced, _, mut out) = self.parts();
        // With nothing held back and no get, every row may go to a new source.
        let Some((_, state)) = sequenced.entry(&source, || SourceState::new(now_ms), |_, _| true)
        else {
            // A table of no rows orders nothing.
            out.deliver(sample);
            return;
        };
        match state.last_delivered {
            // First sample from this source: deliver, record.
            None => {
                out.deliver(sample);
                state.last_delivered = Some(sn);
            }
            // In order: deliver, advance.
            Some(last) if sn == last.wrapping_add(1) => {
                out.deliver(sample);
                state.last_delivered = Some(sn);
            }
            // Forward gap (no retransmission): report the miss, deliver,
            // advance past it (zenoh advanced_subscriber.rs:521-535).
            Some(last) if sn > last => {
                out.miss_handlers.fire(Miss {
                    source,
                    nb: sn - last - 1,
                });
                out.deliver(sample);
                state.last_delivered = Some(sn);
            }
            // `sn <= last`: duplicate / out-of-order-late — drop.
            Some(_) => {}
        }
    }
}

#[cfg(feature = "advanced-recovery")]
impl State {
    /// Ingest a LIVE sample (the subscriber callback path). Returns a
    /// [`RecoveryRequest`] when a forward gap on a retransmission-enabled
    /// source needs a `_sn`-range recovery GET; the caller issues it OUTSIDE
    /// the state lock. `now_ms` is the host's clock reading.
    pub fn handle_live(&mut self, view: &dyn SampleView, now_ms: u64) -> Option<RecoveryRequest> {
        self.admit(Delivery::Lent(view), true, now_ms)
    }

    /// R2554 — THE ONE INGEST ENTRY of a recovery-enabled build, and upstream's
    /// own shape: `zenoh-ext/src/advanced_subscriber.rs` @ `fn handle_sample(states: &mut State, sample: Sample) -> bool {`
    /// is one function that every one of its nine call sites passes an owned
    /// sample to — the live subscription and eight GET callbacks alike.
    ///
    /// `live` is the ONLY thing those callers differ by, and it means exactly
    /// one thing: whether a forward gap may trigger a NEW recovery GET. A
    /// recovered sample must not, because the GET that produced it is the one
    /// already in flight.
    pub fn ingest(
        &mut self,
        mut sample: Sample,
        live: bool,
        now_ms: u64,
    ) -> Option<RecoveryRequest> {
        self.admit(Delivery::Held(&mut sample), live, now_ms)
    }

    /// Ingest a RECOVERED sample read where its reply lies (a recovery or history get's reply),
    /// as [`Self::ingest`] does an owned one: `live = false`, as the get that produced it is the
    /// one in flight. A sample handed on at once is not copied.
    pub fn handle_recovered(
        &mut self,
        view: &dyn SampleView,
        now_ms: u64,
    ) -> Option<RecoveryRequest> {
        self.admit(Delivery::Lent(view), false, now_ms)
    }

    /// [`Self::ingest`] of a sample lent or held.
    fn admit(&mut self, sample: Delivery<'_>, live: bool, now_ms: u64) -> Option<RecoveryRequest> {
        let (source, sn, sample) = self.route_sample(sample, now_ms)?;
        self.ingest_sequenced(source, sn, sample, live, now_ms)
    }

    /// The sequenced-ordering arm (zenoh `handle_sample`
    /// advanced_subscriber.rs:497-540), reached only through [`Self::ingest`].
    ///
    /// R2554 — the `key` / `sn` parameters are gone: they were always the
    /// sample's own `source_info` read back out, and passing them separately
    /// let a caller state an identity the sample contradicted.
    fn ingest_sequenced(
        &mut self,
        source: EntityGlobalId,
        sn: u32,
        sample: Delivery<'_>,
        live: bool,
        now_ms: u64,
    ) -> Option<RecoveryRequest> {
        let retransmission = self.retransmission;
        #[cfg(feature = "advanced-history")]
        let history_pending = self.global_pending_queries != 0;
        #[cfg(feature = "advanced-history")]
        let max_history_depth = self.max_history_depth;
        // With no history config there is no bound, which is upstream's answer (below).
        #[cfg(not(feature = "advanced-history"))]
        let max_history_depth = usize::MAX;
        let (sequenced, _, mut out) = self.parts();
        let Some((slot, state)) = sequenced.entry(
            &source,
            || SourceState::new(now_ms),
            |slot, state| state.idle(slot, &out),
        ) else {
            // Every row holds samples back or waits on a get: a source with none goes on as it
            // came, ordered by nothing.
            out.deliver(sample);
            return None;
        };
        let owner = sequenced_owner(slot);
        // R2621 — delivery is activity, as on the two paths above.
        #[cfg(feature = "advanced-retention")]
        state.retention.touch(now_ms);

        match state.last_delivered {
            // First sample / in order: deliver, advance, drain contiguous buffer.
            None => {
                // R311y86 — while the startup history GET is in flight, BUFFER a
                // first sample (live or recovered) so the whole history delivers
                // in order on completion (zenoh advanced_subscriber.rs:504-516).
                // Skip the recovery trigger — the history GET is recovering it.
                #[cfg(feature = "advanced-history")]
                if history_pending {
                    // R2503 — SPILL, and note the order: upstream inserts FIRST
                    // and then checks, so the buffer transiently holds
                    // depth + 1. Copying the order matters because the
                    // alternative (check, then insert) drops the sample that
                    // just arrived instead of the oldest one.
                    // ⚠ The spill DELIVERS the oldest rather than dropping it
                    // (`deliver_and_flush`, which also drains the contiguous
                    // successors) — a "bounded" buffer that dropped would pass
                    // a length assertion and silently lose a sample.
                    // ⚠⚠ BEFORE the `return None` below, or it never runs.
                    hold_sequenced(
                        state,
                        source,
                        owner,
                        sn,
                        sample,
                        max_history_depth,
                        &mut out,
                    );
                    return None;
                }
                deliver_and_flush(state, owner, sn, sample, &mut out);
            }
            Some(last) if sn == last.wrapping_add(1) => {
                deliver_and_flush(state, owner, sn, sample, &mut out)
            }
            // Forward gap.
            Some(last) if sn > last => {
                if retransmission {
                    // BUFFER; the recovery GET (below) back-fills the hole.
                    // R2503 — the SAME ceiling as the history arm above. The
                    // residual clause named only that arm, and a build that
                    // trusted it would leave this one unbounded: upstream
                    // guards BOTH inserts and spills after each --
                    // `zenoh-ext/src/advanced_subscriber.rs` @ `if state.pending_samples.len() >= states.max_history_depth {`,
                    // which occurs TWICE there, once per insert. (R2509 — the
                    // needle is on the citation's own line: a path with none is
                    // a BARE mention, and the bare budget is a ratchet that
                    // reds the whole of Layers C0 and Z rather than this file.)
                    // ⚠ GATED, and that is upstream's answer rather than an
                    // omission: `max_history_depth` is `usize::MAX` when there
                    // is no history config, i.e. NO spill. With the history
                    // feature off there is no `HistoryConfig` to read, and
                    // unbounded is exactly what upstream does in that case.
                    hold_sequenced(
                        state,
                        source,
                        owner,
                        sn,
                        sample,
                        max_history_depth,
                        &mut out,
                    );
                } else {
                    // No retransmission: report the miss, deliver, advance.
                    out.miss_handlers.fire(Miss {
                        source,
                        nb: sn - last - 1,
                    });
                    out.deliver(sample);
                    state.last_delivered = Some(sn);
                }
            }
            // `sn <= last`: duplicate / out-of-order-late — drop.
            Some(_) => {}
        }

        // Sample-driven trigger (zenoh sub_callback advanced_subscriber.rs:
        // 704-712): a live sample that left the buffer non-empty with no GET
        // in flight issues one for `_sn=last_delivered+1..`.
        if live && retransmission && state.pending_queries == 0 && out.held(owner) != 0 {
            state.pending_queries += 1;
            Some(RecoveryRequest {
                zid: source.zid().to_vec(),
                eid: source.eid(),
                from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                to_sn: None,
            })
        } else {
            None
        }
    }

    /// A recovery GET completed (its terminal Final fired): decrement the
    /// in-flight count and, when it reaches 0, flush the reorder buffer —
    /// delivering recovered + buffered samples in order and reporting a
    /// [`Miss`] for any hole the recovery did not fill (zenoh
    /// `SequencedRepliesHandler::drop` -> `flush_sequenced_source`,
    /// advanced_subscriber.rs:1362-1382 / 1266-1306).
    pub fn finish_recovery(&mut self, key: &(Vec<u8>, u32)) {
        // R311y87 (review C2) — do NOT flush while the startup history GET is
        // still in flight: a per-source recovery GET (heartbeat/periodic) can
        // complete mid-history; flushing then advances `last_delivered`, so a
        // later (older-sn) history reply for this source hits the dup-drop arm
        // and is silently LOST. Defer the flush to `finish_history` (zenoh gates
        // SequencedRepliesHandler::drop on `global_pending_queries == 0`,
        // advanced_subscriber.rs:1368).
        #[cfg(feature = "advanced-history")]
        let history_pending = self.global_pending_queries != 0;
        let (sequenced, _, mut out) = self.parts();
        let Some(source) = EntityGlobalId::new(&key.0, key.1) else {
            return;
        };
        if let Some((slot, state)) = sequenced.get_mut(&source) {
            state.pending_queries = state.pending_queries.saturating_sub(1);
            let may_flush = state.pending_queries == 0;
            #[cfg(feature = "advanced-history")]
            let may_flush = may_flush && !history_pending;
            if may_flush {
                flush_sequenced(state, source, sequenced_owner(slot), &mut out);
            }
        }
    }

    /// R311y86 — a GLOBAL history GET completed (its terminal Final fired):
    /// close its slot and, when it was the LAST one, flush every source's
    /// buffer in order, so the history accumulated during the query delivers
    /// oldest-first (zenoh `InitialRepliesHandler::drop` -> per-source
    /// `flush_sequenced_source`, advanced_subscriber.rs:1334-1352). A source
    /// with a per-source recovery GET still in flight is left for
    /// [`Self::finish_recovery`] to flush.
    ///
    /// R2555 — "when it was the LAST one" is the new half, and it is upstream's
    /// own gate: `zenoh-ext/src/advanced_subscriber.rs` @ `if states.global_pending_queries == 0 {`
    /// guards both of that handler's flush loops. Flushing on any completion
    /// rather than the last would release buffered samples while another global
    /// GET is still returning OLDER ones, which the strictly-newer and dup-drop
    /// arms would then discard — losing history the subscriber had already
    /// recovered. `saturating_sub` because the failed-to-issue rollback in
    /// the host's `issue_recovery_get` runs this too.
    ///
    /// R2555 — and the TIMESTAMPED sources too, which is the half that was
    /// missing. Upstream's same handler drains both maps under the one
    /// `global_pending_queries == 0` test: `zenoh-ext/src/advanced_subscriber.rs` @ `flush_timestamped_source(state, states.callback.as_ref());`
    /// sits directly under the sequenced loop in `InitialRepliesHandler::drop`.
    /// Without it a timestamped sample buffered during the startup GET would
    /// never be handed back — the buffer would fill and stay full, which is
    /// strictly worse than not buffering at all.
    #[cfg(feature = "advanced-history")]
    pub fn finish_history(&mut self) {
        self.global_pending_queries = self.global_pending_queries.saturating_sub(1);
        if self.global_pending_queries != 0 {
            return;
        }
        let (sequenced, timestamped, mut out) = self.parts();
        for (slot, source, state) in sequenced.iter_mut() {
            if state.pending_queries == 0 {
                flush_sequenced(state, *source, sequenced_owner(slot), &mut out);
            }
        }
        for (slot, _, state) in timestamped.iter_mut() {
            flush_timestamped(state, timestamped_owner(slot), &mut out);
        }
    }

    /// R2621 — RECLAIM SOURCE STATES NOBODY HAS HEARD FROM, the sweep wz had
    /// none of. Returns how many entries were dropped, across BOTH maps.
    ///
    /// This is the deterministic core; the background task is thin timer glue
    /// over it, the same split the periodic job uses over
    /// [`Self::periodic_requests`]. Written that way so the policy is unit
    /// tested at an instant the test chooses rather than through a sleep.
    ///
    /// THE RULE IS UPSTREAM'S, CLAUSE FOR CLAUSE
    /// (`zenoh-ext/src/advanced_subscriber.rs` @ `async fn gc_task(statesref: Weak<Mutex<State>>, retention_period: Duration) {`):
    /// a state younger than the retention period stays; an older one whose
    /// publisher is still ALIVE has its access refreshed instead of being
    /// dropped; an older one that is not alive is reclaimed. The middle arm is
    /// the one that matters — without it a live but quiet publisher loses its
    /// `last_delivered` and its next sample reads as a gap.
    ///
    /// ⚠ A FULL SCAN WHERE UPSTREAM POPS AN LRU, and the cost is stated rather
    /// than hidden: upstream holds an `LruCache` and walks from the
    /// least-recently-accessed end, stopping at the first entry young enough,
    /// so it touches only what it reclaims. wz holds plain hash maps, so this
    /// is O(sources) per tick. That is a deliberate trade — an LRU here would
    /// be a second index to keep coherent with two maps that are otherwise
    /// keyed lookups — and it is bounded by the same retention period, which is
    /// hours by default rather than milliseconds.
    #[cfg(feature = "advanced-retention")]
    pub fn reclaim_expired_sources(&mut self, now_ms: u64, retention_period: Duration) -> usize {
        /// Whether the source whose retention is `retention` stays.
        fn stays(retention: &mut Retention, now_ms: u64, retention_period_ms: u64) -> bool {
            if now_ms.saturating_sub(retention.latest_access_ms) <= retention_period_ms {
                return true;
            }
            if retention.alive {
                // Spare it AND refresh, so a live-but-quiet publisher is not
                // re-examined every tick for the rest of the session.
                retention.latest_access_ms = now_ms;
                return true;
            }
            false
        }

        let retention_period_ms = u64::try_from(retention_period.as_millis()).unwrap_or(u64::MAX);
        let (sequenced, timestamped, mut out) = self.parts();
        // A source that goes lets go of what it holds back with it, as upstream's state takes its
        // buffer when it is popped.
        let mut sweep = |owner: u32, retention: &mut Retention| {
            let keep = stays(retention, now_ms, retention_period_ms);
            if !keep {
                if let Some(ring) = out.ring.as_mut() {
                    ring.let_go_all(owner);
                }
            }
            keep
        };
        let gone = sequenced.retain(|slot, s| sweep(sequenced_owner(slot), &mut s.retention));
        gone + timestamped.retain(|slot, s| sweep(timestamped_owner(slot), &mut s.retention))
    }

    /// R2621 — the liveliness token's writer for the retention's `alive` flag, both
    /// arms through one function: a Put says the publisher is live and a Delete
    /// says it is gone, which is upstream's pair
    /// (`zenoh-ext/src/advanced_subscriber.rs` @ `state.alive = true;` and its
    /// Delete twin).
    ///
    /// Both SHAPES, because a `uhlc` publisher and a sequenced one are equally
    /// live or gone when their token says so. The sequenced map is keyed by
    /// `(zid, eid)` and the timestamped one by `zid` alone, which is why a token
    /// naming only a zid reaches every sequenced entry sharing it.
    ///
    /// Gated with its callers and its reader: the liveliness subscriber that drives
    /// it exists only under the history feature and the sweep that reads the flag
    /// only under the retention one, and a writer compiled where nothing can call it
    /// is the dead code this module already refuses.
    #[cfg(all(feature = "advanced-history", feature = "advanced-retention"))]
    pub fn set_source_alive(&mut self, zid: &[u8], eid: Option<u32>, alive: bool) {
        for (_, source, state) in self.sequenced.iter_mut() {
            if source.zid() == zid && eid.is_none_or(|e| e == source.eid()) {
                state.retention.alive = alive;
            }
        }
        let timestamped = &mut self.timestamped;
        if let Some((_, state)) = TimestampZid::new(zid).and_then(|id| timestamped.get_mut(&id)) {
            state.retention.alive = alive;
        }
    }

    /// R311y83 — the periodic trigger: collect a `_sn=last+1..` recovery
    /// request for every sequenced source with no GET in flight. Re-asking past
    /// `last_delivered` catches a lost LAST sample that no later live sample
    /// would trigger sample-driven recovery for (zenoh `PeriodicQuery::run`,
    /// advanced_subscriber.rs:587-643). wz drives ONE shared task that iterates
    /// all sources here (vs zenoh's per-source `TimedEvent`); the GET shape is
    /// identical. No-op when retransmission is off.
    ///
    /// R311y447-review — TWO reviewers independently flagged that the previous
    /// "observable-equivalent" claim glossed a real divergence, so it is named
    /// here rather than asserted away. The `pending_queries == 0` gate below has
    /// NO upstream counterpart: zenoh's `PeriodicQuery::run` increments
    /// unconditionally (`:592`), and that is deliberate — it gates its other two
    /// triggers (sample-driven `:706`, heartbeat `:1104`) and leaves only periodic
    /// ungated. Observable difference: when a GET round trip exceeds the period,
    /// upstream issues overlapping GETs while wz issues at most one. wz is the
    /// more conservative of the two and no leg in the cross-impl corpus witnesses
    /// the difference; removing this gate reds nothing today.
    pub fn periodic_requests(&mut self) -> Vec<RecoveryRequest> {
        if !self.retransmission {
            return Vec::new();
        }
        let mut requests = Vec::new();
        for (_, source, state) in self.sequenced.iter_mut() {
            if state.pending_queries == 0 {
                state.pending_queries += 1;
                requests.push(RecoveryRequest {
                    zid: source.zid().to_vec(),
                    eid: source.eid(),
                    from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                    to_sn: None,
                });
            }
        }
        requests
    }

    /// R311y84 — the heartbeat trigger: a beacon reporting the publisher's last
    /// sn `hb_sn` for source `(zid, eid)`. When the beacon is ahead of
    /// `last_delivered` and no GET is in flight, request a BOUNDED
    /// `_sn=last+1..hb_sn` recovery GET (zenoh heartbeat callback,
    /// advanced_subscriber.rs:1095-1118). No-op when retransmission is off.
    pub fn handle_heartbeat(
        &mut self,
        zid: Vec<u8>,
        eid: u32,
        hb_sn: u32,
        now_ms: u64,
    ) -> Option<RecoveryRequest> {
        if !self.retransmission {
            return None;
        }
        // A beacon's zid is one a token decoded, 1..=16 bytes: no other names a source.
        let source = EntityGlobalId::new(&zid, eid)?;
        // R2617 — SKIP THE HEARTBEAT FOR A SOURCE THIS SUBSCRIBER HAS JUST MET
        // WHILE A GLOBAL PULL IS STILL RUNNING. Upstream's guard, on the arm it
        // takes only for a newly-inserted source:
        // `zenoh-ext/src/advanced_subscriber.rs` @ `if states.global_pending_queries > 0 {`,
        // whose trace calls it "publisher that is currently being pulled by
        // global query". Without it the beacon fires a per-source
        // `_sn=last+1..hb` GET for a publisher the startup history GET is
        // already fetching in full, so the same samples are asked for twice and
        // the per-source slot is occupied by a query the global one makes
        // redundant.
        //
        // THE STATE IS STILL INSERTED BEFORE THE RETURN, exactly as upstream
        // inserts through `get_or_insert_mut` and only then decides: the source
        // has been SEEN, and forgetting it here would make the next beacon look
        // new all over again.
        //
        // The `history` cfg is the honest scope: `global_pending_queries` only
        // exists where a global pull can exist, and with history compiled out
        // there is nothing for this guard to be about.
        #[cfg(feature = "advanced-history")]
        let global_pull_in_flight = self.global_pending_queries != 0;
        #[cfg(not(feature = "advanced-history"))]
        let global_pull_in_flight = false;
        let newly_seen = !self.sequenced.contains_key(&source);
        let (sequenced, _, out) = self.parts();
        // A beacon from a source the table has no row for asks nothing: every row is busy.
        let (_, state) = sequenced.entry(
            &source,
            || SourceState::new(now_ms),
            |slot, state| state.idle(slot, &out),
        )?;
        // R2621 — a beacon is the publisher saying it is still there, which is
        // exactly what upstream's heartbeat arm refreshes `latest_access` for.
        #[cfg(feature = "advanced-retention")]
        state.retention.touch(now_ms);
        if newly_seen && global_pull_in_flight {
            return None;
        }
        let caught_up = state
            .last_delivered
            .map(|last| hb_sn <= last)
            .unwrap_or(false);
        if !caught_up && state.pending_queries == 0 {
            state.pending_queries += 1;
            Some(RecoveryRequest {
                zid,
                eid,
                from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                to_sn: Some(hb_sn),
            })
        } else {
            None
        }
    }

    /// R311y100 — the late-publisher trigger: a publisher `(zid, eid)` appeared
    /// (its `@adv` liveliness token Put was detected). Open a recovery slot
    /// (`pending_queries += 1`) so the per-publisher history GET's replies flush
    /// in order, UNLESS a GET for this source is already in flight (the
    /// `pending_queries == 0` gate avoids piling up concurrent GETs — zenoh's
    /// own TODO at advanced_subscriber.rs:824 notes the un-deduped re-query;
    /// gating on no-in-flight is the wz refinement). Returns whether to issue
    /// the GET. NOT gated on `retransmission`: late-publisher detection is a
    /// HISTORY trigger, independent of the sample-driven recovery flag (zenoh
    /// gates it on `historyconf.liveliness`, not retransmission).
    #[cfg(feature = "advanced-history")]
    pub fn handle_late_publisher(&mut self, zid: Vec<u8>, eid: u32, now_ms: u64) -> bool {
        // A token's zid is 1..=16 bytes; no other names a source to recover.
        let Some(source) = EntityGlobalId::new(&zid, eid) else {
            return false;
        };
        let (sequenced, _, out) = self.parts();
        let Some((_, state)) = sequenced.entry(
            &source,
            || SourceState::new(now_ms),
            |slot, state| state.idle(slot, &out),
        ) else {
            // Every row is busy: the history of a source with none is not asked for.
            return false;
        };
        if state.pending_queries == 0 {
            state.pending_queries += 1;
            true
        } else {
            false
        }
    }

    /// R2553 — the same trigger for a TIMESTAMPED publisher, keyed by zid
    /// alone. Upstream's is the `uhlc` half of the one liveliness callback:
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `.timestamped_states` reached
    /// through `get_or_insert_mut(ID::from(zid), Default::default)` followed by
    /// `state.pending_queries += 1`.
    ///
    /// THE KEY IS THE ZID AND NOT A `(zid, eid)` PAIR, which is the whole
    /// reason this is a second method rather than the one above taking an
    /// `Option<u32>`: a `uhlc` token names no entity, and the samples it will
    /// recover are keyed by the TIMESTAMP's id — so the identity the GET opens
    /// a slot for has to be the identity the replies land under, or the slot
    /// belongs to a source no reply will ever close.
    ///
    /// wz's one-in-flight gate is kept here for the reason
    /// [`Self::handle_late_publisher`] gives (upstream's own TODO notes the
    /// un-deduped re-query); the RETURN is what says whether to issue.
    #[cfg(feature = "advanced-history")]
    pub fn handle_late_timestamped_publisher(&mut self, zid: Vec<u8>, now_ms: u64) -> bool {
        let Some(id) = TimestampZid::new(&zid) else {
            return false;
        };
        let (_, timestamped, out) = self.parts();
        let Some((_, state)) = timestamped.entry(
            &id,
            || TimestampedState::new(now_ms),
            |slot, state| timestamped_idle(slot, state, &out),
        ) else {
            // Every row is busy: the history of a source with none is not asked for.
            return false;
        };
        if state.pending_queries == 0 {
            state.pending_queries += 1;
            true
        } else {
            false
        }
    }

    /// R2555 — open a GLOBAL history slot for a publisher with no readable
    /// identity. Upstream's `states.global_pending_queries += 1` in the third
    /// liveliness arm.
    ///
    /// UNCONDITIONAL, where the two keyed triggers return whether to issue:
    /// their one-in-flight gate exists because a per-source slot can be
    /// observed to be occupied, and here there is no source to observe. That is
    /// upstream's behaviour too — its third arm increments without testing —
    /// and the honest consequence is that repeated tokens from unidentifiable
    /// publishers each cost a GET. The alternative would be de-duplicating on
    /// the token key expression, which is a wz invention rather than a mirror,
    /// so it is not taken here.
    #[cfg(feature = "advanced-history")]
    pub fn open_global_history_slot(&mut self) {
        self.global_pending_queries += 1;
    }

    /// R2553 — a timestamped publisher's history GET completed: close the slot
    /// its trigger opened. The twin of [`Self::finish_recovery`], and upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `impl Drop for TimestampedRepliesHandler`.
    /// `saturating_sub` for the same reason the sequenced side uses it: the
    /// failed-to-issue rollback runs this too.
    ///
    /// R2555 — and it now FLUSHES, which R2553 recorded as the missing half:
    /// the buffer this closes the last query on is the buffer
    /// `flush_timestamped` drains, and upstream's handler does both in that
    /// order. The `!history_pending` test is upstream's
    /// `global_pending_queries == 0` guard — a per-source GET can complete
    /// while the startup history GET is still running, and flushing then would
    /// advance `last_delivered` past instants the startup GET is about to
    /// return, dropping them on the strictly-newer test. That is the same trap
    /// [`Self::finish_recovery`] documents on the sequenced side.
    #[cfg(feature = "advanced-history")]
    pub fn finish_timestamped_recovery(&mut self, zid: &[u8]) {
        let history_pending = self.global_pending_queries != 0;
        let (_, timestamped, mut out) = self.parts();
        let Some(id) = TimestampZid::new(zid) else {
            return;
        };
        if let Some((slot, state)) = timestamped.get_mut(&id) {
            state.pending_queries = state.pending_queries.saturating_sub(1);
            if !history_pending {
                flush_timestamped(state, timestamped_owner(slot), &mut out);
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Deliver `sample` (sn = `sn`), advance `last_delivered`, then drain every
/// contiguous buffered sample (`last+1`, `last+2`, ...) in order. The wz
/// mirror of zenoh's `deliver_and_flush` (advanced_subscriber.rs:482-495).
#[cfg(feature = "advanced-recovery")]
fn deliver_and_flush(
    state: &mut SourceState,
    owner: u32,
    sn: u32,
    sample: Delivery<'_>,
    out: &mut Outlet<'_>,
) {
    out.deliver(sample);
    state.last_delivered = Some(sn);
    drain_contiguous(state, owner, out);
}

/// Hand on what `owner` holds back from the sequence number after the last delivered on, for as
/// long as the run has no hole.
#[cfg(feature = "advanced-recovery")]
fn drain_contiguous(state: &mut SourceState, owner: u32, out: &mut Outlet<'_>) {
    while let Some(next) = state.last_delivered.map(|sn| sn.wrapping_add(1)) {
        let Some(at) = out.find(owner, Order::Sn, u64::from(next)) else {
            return;
        };
        out.hand_on(at);
        state.last_delivered = Some(next);
    }
}

/// Hold `sample`, the `sn` of `source`, back as a record of `owner` until what comes before it
/// is in. A sample already held under `sn` gives way to it, as an insert into upstream's map
/// does. R2503 — past `depth` held samples the oldest goes on at once and drains its successors,
/// as the bound of a history get says (`deliver_and_flush`); a "bounded" buffer that dropped it
/// would pass a length assertion and silently lose a sample.
///
/// A sample the ring has no room for is not held: what the source holds goes on first, in order,
/// with a [`Miss`] for each hole it gives up, and then it. The ring's bound gives up the wait,
/// never a sample or its order.
#[cfg(feature = "advanced-recovery")]
fn hold_sequenced(
    state: &mut SourceState,
    source: EntityGlobalId,
    owner: u32,
    sn: u32,
    sample: Delivery<'_>,
    depth: usize,
    out: &mut Outlet<'_>,
) {
    if let Some(at) = out.find(owner, Order::Sn, u64::from(sn)) {
        out.let_go(at);
    }
    if !out.hold(owner, &sample) {
        flush_sequenced(state, source, owner, out);
        if admit_in_order(state, source, sn, out.miss_handlers) {
            out.deliver(sample);
        }
        return;
    }
    if out.held(owner) >= depth {
        if let Some((first, at)) = out.first(owner, Order::Sn) {
            out.hand_on(at);
            state.last_delivered = u32::try_from(first).ok();
            drain_contiguous(state, owner, out);
        }
    }
}

/// Whether the `sn` of `source` goes on now, past what `state` delivered last: the first, the
/// next, or one past a hole, which is reported to the listeners as a [`Miss`]. One at or before
/// the last delivered is a duplicate or late, and does not. Moves the last delivered to `sn`
/// when it goes.
#[cfg(feature = "advanced-recovery")]
fn admit_in_order(
    state: &mut SourceState,
    source: EntityGlobalId,
    sn: u32,
    miss_handlers: &mut MissHandlers,
) -> bool {
    match state.last_delivered {
        None => {}
        Some(last) if sn == last.wrapping_add(1) => {}
        Some(last) if sn > last => miss_handlers.fire(Miss {
            source,
            nb: sn - last - 1,
        }),
        Some(_) => return false,
    }
    state.last_delivered = Some(sn);
    true
}

/// Flush the reorder buffer after a recovery GET completed: drain it
/// sn-ordered, delivering each contiguous sample and reporting a [`Miss`] for
/// any hole the recovery did not fill (zenoh `flush_sequenced_source`,
/// advanced_subscriber.rs:1266-1306). Caller guarantees `pending_queries == 0`.
#[cfg(feature = "advanced-recovery")]
fn flush_sequenced(
    state: &mut SourceState,
    source: EntityGlobalId,
    owner: u32,
    out: &mut Outlet<'_>,
) {
    while let Some((key, at)) = out.first(owner, Order::Sn) {
        let goes =
            u32::try_from(key).is_ok_and(|sn| admit_in_order(state, source, sn, out.miss_handlers));
        if goes {
            out.hand_on(at);
        } else {
            out.let_go(at);
        }
    }
}
