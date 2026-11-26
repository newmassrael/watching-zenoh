// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An advanced subscriber hosted on an engine's port: what declares its entities, asks its gets,
//! runs its two periodic jobs and takes it down, written over [`SessionEngine`] and nothing else.
//!
//! The host is generic over what holds the engine, `E` ([`EngineHolder`]): the port's object by
//! count by default, or a holder of an engine's own type, which an ABI built with one engine names
//! so that every call is resolved when the build is made and no table of all the session's
//! operations is made for the subscriber; an engine placed in its session's own memory is held by
//! its own holder, not by an `Arc`.
//!
//! The ordering machine ([`super::state`]) and the plans ([`super::plans`]) decide; this module
//! does what they ask. It names no runtime: the subscription, the liveliness subscriptions and the
//! detection token are the port's declarations, a get is the port's `get_on_wire` with one
//! callback per leg, and a periodic job is the port's ticker. So the same host runs on the
//! cooperative engine, where a tick is as late as the program is slow to step the session, and on
//! the tokio engine, where it is a task.
//!
//! # How a get ends
//!
//! The port ends a leg by dropping its callback. A get is over when the LAST leg's callback is, so
//! every callback of one get holds the same slot of the subscriber's table of gets in flight, and
//! what the machine does when a get ends (close its slot, flush what it buffered) runs when the
//! last holder of the slot lets it go. The host holds the slot once more while it issues the get,
//! which is what makes a get that no leg was issued for, or that every leg ended while it was
//! still being issued, end exactly once and after the call returned, with no lock of the engine
//! held. The table has a slot for each get the session holds pending at once, and a callback is
//! the engine's raw form over a count of the subscriber, so asking a get takes no memory.
//!
//! # How a subscriber is taken down
//!
//! Dropping the handle retracts the entities in the order the tokio runtime's does, and in the
//! middle of them cancels the gets in flight, so that nothing arriving afterwards reaches the
//! application's callback, which the application may free the moment the handle is dropped. A
//! cancelled get's callbacks are dropped by the engine, and a dropped callback is a leg's end for
//! any reason, so the host sets `closing` first: a get that ends because it was cancelled does not
//! flush into a callback that is going away.
//!
//! This is the widest form (history, which implies recovery), the one a C ABI's option struct
//! asks for. A build that wants less links the machine and the plans alone.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt::Write as _;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use wz_capi_port::cancellation::{CancellableFan, CancellationToken, TokenRef};
use wz_capi_port::{
    EngineHolder, LivelinessSink, Refusal, ReplyCallback, SessionEngine, SubId, SubscriberSink,
    Ticker, TokenId, WireKey,
};
use wz_session_core::caps;
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::locality::Locality;
use wz_session_core::query_mode::{ConsolidationMode, QueryTarget};
use wz_session_core::query_options::QueryOptionsOf;
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sample::EntityGlobalId;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::serde_codec::z_deserialize;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::sink::SampleRef;
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use super::options::{AdvancedSubscriberOptions, DeclarationForms, EntityForm, FormsHandle, Kept};
use super::plans::{
    parse_heartbeat_source, recovery_query_timeout_ms, AdvPublisherSource, GetParameters,
    RecoveredView,
};
use super::state::{
    Delivery, Miss, MissHandlers, OnSample, RecoveryRequest, SampleMissListener, State,
};
use crate::prelude::*;
use crate::sync::{lock_or_panic, Mutex, MutexGuard};

use wz_capi_port::lodge::{Lodging, NoPlace, Strong, WeakRef};

/// Why declaring an advanced subscriber on an engine failed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// The engine is closed, or does not carry what the subscriber needs in this build (a
    /// liveliness plane, a requesting end, periodic jobs); the text says which. A refusal and not
    /// a degradation: the caller asked for it, and a subscriber that quietly lacks it is the
    /// failure nobody can see from outside.
    Refused(&'static str),
    /// The session has handed out every declaration id it can put on the wire, so the
    /// subscription was not declared.
    IdsExhausted,
    /// A history bound was zero, which upstream refuses at construction.
    HistoryBoundZero {
        /// Which knob: `"max_samples"` or `"max_age"`.
        knob: &'static str,
    },
    /// The engine refused a declaration the subscriber is made of, for this cause.
    Declined(Refusal),
    /// The heap had no room for what the subscriber's callbacks and jobs share, so nothing was
    /// declared.
    NoRoom,
}

impl HostError {
    /// The engine's refusal of `what`, one of the declarations a subscriber is made of: a spent
    /// id space and a plane this build does not hold keep the names they had, and any other
    /// cause is carried as the engine gave it.
    fn of(what: &'static str) -> impl FnOnce(Refusal) -> Self {
        move |refused| match refused {
            Refusal::NoEntityId => Self::IdsExhausted,
            Refusal::NotBuilt => Self::Refused(what),
            other => Self::Declined(other),
        }
    }
}

impl core::fmt::Display for HostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused(what) => write!(f, "the engine refused an advanced subscriber: {what}"),
            Self::IdsExhausted => {
                f.write_str("the session has handed out every 32-bit declaration id")
            }
            Self::HistoryBoundZero { knob } => write!(f, "history {knob} must not be zero"),
            Self::NoRoom => f.write_str("the heap has no room for an advanced subscriber"),
            Self::Declined(refused) => {
                write!(f, "the engine refused an advanced subscriber: {refused}")
            }
        }
    }
}

impl core::error::Error for HostError {}

/// What every callback and job of one subscriber shares.
struct Shared<E: EngineHolder> {
    /// Held weakly: the engine holds the callbacks that hold this.
    engine: E::Handle,
    /// The gets in flight, a row for each get the build's sessions hold pending at most, since a
    /// session refuses a get past them anyway. Before the token, so a fan is never dropped after
    /// the token it is registered on.
    gets: [GetSlot<E>; caps::MAX_PENDING_QUERIES],
    state: Mutex<State>,
    /// The cancellation of the gets in flight, and what teardown cancels through.
    token: CancellationToken,
    /// Set before the gets are cancelled, and never cleared: from then on nothing reaches the
    /// application's callback.
    closing: AtomicBool,
    /// The key expression this subscriber subscribes to, kept inline.
    base_keyexpr: FixedKey,
    /// The destination of every get.
    dest: Locality,
    /// The timeout of every get, in milliseconds.
    timeout_ms: u32,
    /// The bounds of a detected late publisher's history get: its depth and its age.
    late: (Option<usize>, Option<core::time::Duration>),
}

impl<E: EngineHolder> Shared<E> {
    /// A subscriber of `engine` on `base_keyexpr` with no get in flight, made in `place`, where
    /// it stays: its token holds a lock made in its place ([`CancellationToken::init_in`]).
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self`, aligned for it and holds none; what is made there
    /// is not moved until it is dropped there.
    unsafe fn write_in(
        place: NonNull<Self>,
        engine: E::Handle,
        state: State,
        base_keyexpr: FixedKey,
        dest: Locality,
        timeout_ms: u32,
    ) {
        let at = place.as_ptr();
        // SAFETY: the caller's: each field is written once through a pointer to it, not null as
        // it is inside the place, the token made there.
        unsafe {
            addr_of_mut!((*at).engine).write(engine);
            addr_of_mut!((*at).gets).write(core::array::from_fn(|_| GetSlot::new()));
            addr_of_mut!((*at).state).write(Mutex::new(state));
            CancellationToken::init_in(NonNull::new_unchecked(addr_of_mut!((*at).token)));
            addr_of_mut!((*at).closing).write(AtomicBool::new(false));
            addr_of_mut!((*at).base_keyexpr).write(base_keyexpr);
            addr_of_mut!((*at).dest).write(dest);
            addr_of_mut!((*at).timeout_ms).write(timeout_ms);
            addr_of_mut!((*at).late).write((None, None));
        }
    }

    /// The key expression this subscriber subscribes to.
    fn base(&self) -> &str {
        self.base_keyexpr.prefix()
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// The engine's clock, or zero when the engine is gone (and then nothing is asked of it).
    fn now_ms(&self) -> u64 {
        E::upgrade(&self.engine).map_or(0, |engine| engine.now_ms())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock_or_panic(&self.state, super::state::STATE_POISONED)
    }

    /// A free slot of the table of gets, taken; none when every one holds a get.
    fn claim(&self) -> Option<&GetSlot<E>> {
        self.gets.iter().find(|slot| {
            slot.taken
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        })
    }
}

/// What the machine does when a get is over.
enum Finish {
    /// The startup get, or a late publisher's whose source is not identified.
    History,
    /// A sequenced source's recovery or late-publisher get.
    Recovery((Vec<u8>, u32)),
    /// A timestamped late publisher's get, by its zid.
    Timestamped(Vec<u8>),
}

impl Finish {
    fn run(self, state: &mut State) {
        match self {
            Self::History => state.finish_history(),
            Self::Recovery(key) => state.finish_recovery(&key),
            Self::Timestamped(zid) => state.finish_timestamped_recovery(&zid),
        }
    }
}

/// One get in flight, in its subscriber's table. Taken by the issuer of a get, held by the issuer
/// while it issues and by each leg's callback, and given back by the last of them, which ends the
/// get. See the module doc.
struct GetSlot<E: EngineHolder> {
    /// The slot holds a get.
    taken: AtomicBool,
    /// The holders of the get: its issuer while it issues, and each leg not yet ended.
    holders: AtomicUsize,
    /// The subscriber whose table the slot is in, as a leg reaches it: its lodging, which a leg
    /// holds a count of.
    owner: UnsafeCell<*const Lodging<Shared<E>>>,
    /// What ends the get; taken by its end.
    finish: UnsafeCell<Option<Finish>>,
    /// The get's legs as one thing to cancel, and its registration on the teardown's token: held
    /// to the end of the get, after its finish has run, so a teardown waits for it. Dropped where
    /// it lies, since the token's list names it by its address.
    fan: UnsafeCell<Option<CancellableFan>>,
}

// SAFETY: `owner`, `finish` and `fan` are written only by the one that took the slot, before it
// hands out a leg, and by the last holder as it ends the get; in between they are read through
// shared borrows only, and the fan is `Sync`. The subscriber `owner` names is `Sync`.
unsafe impl<E: EngineHolder> Send for GetSlot<E> {}
// SAFETY: as `Send`.
unsafe impl<E: EngineHolder> Sync for GetSlot<E> {}

impl<E: EngineHolder> GetSlot<E> {
    fn new() -> Self {
        Self {
            taken: AtomicBool::new(false),
            holders: AtomicUsize::new(0),
            owner: UnsafeCell::new(core::ptr::null()),
            finish: UnsafeCell::new(None),
            fan: UnsafeCell::new(None),
        }
    }

    /// Fill the slot with a get of `owner` that `finish` ends, held by its issuer, and answer the
    /// get's fan, registered on no token yet.
    ///
    /// # Safety
    /// The caller took the slot ([`Shared::claim`]) for `owner`, whose table it is in, and has
    /// handed out no leg of it.
    unsafe fn open(&self, owner: &Strong<Shared<E>>, finish: Finish) -> &CancellableFan {
        // SAFETY: the caller's: nothing else reaches the slot yet.
        unsafe {
            *self.owner.get() = Strong::as_raw(owner).cast::<Lodging<Shared<E>>>();
            *self.finish.get() = Some(finish);
            self.holders.store(1, Ordering::Release);
            (*self.fan.get()).insert(CancellableFan::new())
        }
    }

    /// The subscriber the slot is in.
    ///
    /// # Safety
    /// The caller holds the slot's get, which holds the subscriber.
    unsafe fn owner(&self) -> &Shared<E> {
        // SAFETY: the caller's: `owner` was written before the get had a holder but its issuer,
        // and the subscriber stands while the get does.
        unsafe { Strong::<Shared<E>>::value_of((*self.owner.get()).cast::<c_void>()) }
    }

    /// One leg's callback, holding the get and the subscriber until the engine lets it go
    /// ([`end_leg`]).
    ///
    /// # Safety
    /// The caller is the issuer of the slot's get and still holds it; `owner` is the subscriber
    /// the slot is in.
    unsafe fn leg(&self, owner: &Strong<Shared<E>>) -> ReplyCallback {
        self.holders.fetch_add(1, Ordering::AcqRel);
        // The count of the subscriber the leg holds, let go of by `end_leg`.
        let _ = Strong::into_raw(owner.clone());
        let context = core::ptr::from_ref(self).cast_mut().cast::<c_void>();
        // SAFETY: the context is this slot, which the leg holds until `end_leg` runs, once, after
        // its last call; a call reads the subscriber through a shared borrow, which it admits from
        // any thread.
        unsafe { ReplyCallback::raw(on_reply::<E>, context, Some(end_leg::<E>)) }
    }

    /// Let go of one hold of the get. The last ends it: its finish runs unless the subscriber is
    /// closing, its fan is dropped where it lies, and the slot is free for the next get.
    ///
    /// # Safety
    /// The caller holds the get (its issuer, or a leg) and lets go of it once; the subscriber the
    /// slot is in stands for the call.
    unsafe fn release(&self) {
        if self.holders.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // SAFETY: the last holder has the slot to itself, and the caller keeps the subscriber.
        unsafe {
            let shared = self.owner();
            if let Some(finish) = (*self.finish.get()).take() {
                if !shared.is_closing() {
                    finish.run(&mut shared.lock());
                }
            }
            *self.fan.get() = None;
        }
        self.taken.store(false, Ordering::Release);
    }
}

/// A reply of one leg of a get: fed to the machine as a recovered sample.
///
/// # Safety
/// `context` is a slot whose get the leg holds ([`GetSlot::leg`]).
unsafe fn on_reply<E: EngineHolder>(context: *mut c_void, reply: &dyn ReplyView) {
    // SAFETY: the caller's: the leg holds the get, which holds the subscriber.
    let shared = unsafe { (*context.cast_const().cast::<GetSlot<E>>()).owner() };
    if shared.is_closing() {
        return;
    }
    // `_anyke` opts out of the responder's reply-keyexpr guard, and this is the local half upstream
    // pairs it with.
    if !wz_session_core::keyexpr_match::keyexpr_intersects(shared.base(), reply.keyexpr()) {
        return;
    }
    // Recovered, not live: the get that produced this reply is the one in flight, so a gap here
    // must not fan another.
    if let Some(view) = RecoveredView::of(reply) {
        let now = shared.now_ms();
        let _ = shared.lock().handle_recovered(&view, now);
    }
}

/// A leg's end: it lets go of the get, which the last holder ends, and then of the subscriber.
///
/// # Safety
/// `context` is a slot whose get the leg holds ([`GetSlot::leg`]), let go of once, here.
unsafe fn end_leg<E: EngineHolder>(context: *mut c_void) {
    // SAFETY: the caller's. The subscriber is read before the get is let go of, since the slot may
    // hold the next get right after, and the leg's count of it is let go of last, so it stands
    // while the get ends.
    unsafe {
        let slot = &*context.cast_const().cast::<GetSlot<E>>();
        let owner = *slot.owner.get();
        slot.release();
        drop(Strong::<Shared<E>>::from_raw(
            owner.cast_mut().cast::<c_void>(),
        ));
    }
}

/// A subscription callback of the subscriber's own, in the engine's raw form over a count of the
/// subscriber, which the engine lets go of with the callback: no memory is taken for it.
fn own_sink<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    call: unsafe fn(context: *mut c_void, sample: &SampleRef<'_>),
) -> SubscriberSink {
    let context = Strong::into_raw(shared.clone());
    // SAFETY: the context is a count of the subscriber, let go of once by `let_go` after the last
    // call; a call reads the subscriber through a shared borrow, which it admits from any thread.
    unsafe { SubscriberSink::raw(call, context, Some(let_go::<E>)) }
}

/// The subscriber a callback's context holds a count of, as the count it is, left held.
///
/// # Safety
/// `context` is a count of a subscriber ([`own_sink`]) not yet let go of.
unsafe fn held<E: EngineHolder>(context: *mut c_void) -> ManuallyDrop<Strong<Shared<E>>> {
    // SAFETY: the caller's; the count is not let go of here, as the value is never dropped.
    ManuallyDrop::new(unsafe { Strong::from_raw(context) })
}

/// Let go of the count of the subscriber a callback held.
///
/// # Safety
/// As [`held`]'s, called once, after the callback's last call.
unsafe fn let_go<E: EngineHolder>(context: *mut c_void) {
    // SAFETY: the caller's.
    drop(ManuallyDrop::into_inner(unsafe { held::<E>(context) }));
}

/// The live subscription's callback: a sample in order goes to the application, and a gap asks
/// for recovery.
///
/// # Safety
/// As [`held`]'s.
unsafe fn on_live<E: EngineHolder>(context: *mut c_void, view: &SampleRef<'_>) {
    // SAFETY: the caller's.
    let shared = unsafe { held::<E>(context) };
    if shared.is_closing() {
        return;
    }
    let now = shared.now_ms();
    let request = shared.lock().handle_live(view, now);
    // Issued OUTSIDE the state lock: the get re-enters the engine, and a loopback answer re-enters
    // the state.
    if let Some(request) = request {
        issue_recovery_query(&shared, request);
    }
}

/// The heartbeat subscription's callback: a publisher's last sequence number, which asks for what
/// the subscriber has not seen of it.
///
/// # Safety
/// As [`held`]'s.
unsafe fn on_heartbeat<E: EngineHolder>(context: *mut c_void, view: &SampleRef<'_>) {
    // SAFETY: the caller's.
    let shared = unsafe { held::<E>(context) };
    if shared.is_closing() || view.kind != SampleKind::Put {
        return;
    }
    // Sequenced only: a heartbeat's payload IS a sequence number.
    let Some(AdvPublisherSource::Sequenced { zid, eid }) = parse_heartbeat_source(view.keyexpr)
    else {
        return;
    };
    let Ok(last_sn) = z_deserialize::<u32>(view.payload) else {
        return;
    };
    let now = shared.now_ms();
    let request = shared.lock().handle_heartbeat(zid, eid, last_sn, now);
    if let Some(request) = request {
        issue_recovery_query(&shared, request);
    }
}

/// The late-publisher liveliness subscription's callback, in the engine's raw form over a count of
/// the subscriber ([`own_sink`]'s, let go of by [`let_go`]).
///
/// # Safety
/// As [`held`]'s.
unsafe fn on_late_publisher<E: EngineHolder>(context: *mut c_void, sample: LivelinessSample<'_>) {
    // SAFETY: the caller's.
    let shared = unsafe { held::<E>(context) };
    if shared.is_closing() {
        return;
    }
    let (depth, age) = shared.late;
    on_late_publisher_detected(&shared, sample.kind, sample.keyexpr, depth, age);
}

/// A sample-miss listener's retraction, over a weak count of the subscriber: a subscriber already
/// gone has nothing to retract.
///
/// # Safety
/// `context` is a weak count of a subscriber ([`WeakRef::into_raw`]) not yet let go of.
unsafe fn unregister_miss<E: EngineHolder>(context: *mut c_void, id: usize) {
    // SAFETY: the caller's; the count is not let go of here.
    let weak = ManuallyDrop::new(unsafe { WeakRef::<Shared<E>>::from_raw(context) });
    if let Some(shared) = weak.upgrade() {
        shared.lock().miss_handlers().unregister(id);
    }
}

/// Let go of a sample-miss listener's weak count of its subscriber.
///
/// # Safety
/// As [`unregister_miss`]'s, called once, last.
unsafe fn let_go_weak<E: EngineHolder>(context: *mut c_void) {
    // SAFETY: the caller's.
    drop(unsafe { WeakRef::<Shared<E>>::from_raw(context) });
}

/// A subscription (or liveliness subscription) the engine holds, retracted when this is dropped.
struct Subscription<E: EngineHolder> {
    engine: E,
    id: SubId,
    retract: bool,
}

impl<E: EngineHolder> Drop for Subscription<E> {
    fn drop(&mut self) {
        if self.retract {
            self.engine.undeclare_subscriber(self.id);
        }
    }
}

/// A liveliness token the engine holds, retracted when this is dropped.
struct Token<E: EngineHolder> {
    engine: E,
    id: TokenId,
    retract: bool,
}

impl<E: EngineHolder> Drop for Token<E> {
    fn drop(&mut self) {
        if self.retract {
            self.engine.undeclare_liveliness_token(self.id);
        }
    }
}

/// An entity and what keeps its wire name valid. The entity is the FIRST field, so it is
/// retracted first and the name goes right after it, which is the order a host that declares keys
/// shows a peer.
struct Held<T> {
    entity: T,
    keeps: Option<Kept>,
}

/// The teardown of the gets in flight. Armed until the subscriber goes to the background, which
/// leaves them running to their Final.
struct GetCancel<E: EngineHolder> {
    shared: Strong<Shared<E>>,
    armed: bool,
}

impl<E: EngineHolder> Drop for GetCancel<E> {
    fn drop(&mut self) {
        if self.armed {
            self.shared.closing.store(true, Ordering::Release);
            self.shared.token.cancel();
        }
    }
}

/// The place of what an advanced subscriber's callbacks and jobs share, which a host that keeps
/// its objects in places of its own lends [`EngineSubscriber::declare_in`]: sized for it, and
/// holding nothing until a declaration lodges the part there.
#[repr(transparent)]
pub struct SubscriberCore<E: EngineHolder>(MaybeUninit<Lodging<Shared<E>>>);

impl<E: EngineHolder> SubscriberCore<E> {
    /// A place holding no subscriber's part.
    pub const fn vacant() -> Self {
        Self(Lodging::vacant())
    }
}

/// A [`SubscriberCore`] its host lends one declaration, and how the host takes it back.
pub struct LentCore<E: EngineHolder> {
    core: NonNull<SubscriberCore<E>>,
    give_back: unsafe fn(*mut c_void),
    context: *mut c_void,
}

impl<E: EngineHolder> LentCore<E> {
    /// `core`, given back by `give_back(context)`.
    ///
    /// # Safety
    /// `core` is valid for writes, holds no subscriber's part, and stands until
    /// `give_back(context)` runs, which a declaration made with it does once. That may be on any
    /// thread that lets go of the part last, the engine's among them as it lets a callback go with
    /// no lock of its own held, so `give_back` takes no lock the engine holds then.
    pub unsafe fn new(
        core: NonNull<SubscriberCore<E>>,
        give_back: unsafe fn(*mut c_void),
        context: *mut c_void,
    ) -> Self {
        Self {
            core,
            give_back,
            context,
        }
    }
}

/// A live advanced subscriber on an engine's port, named by the engine's type `E` (the port's
/// object unless the holder names its engine's own).
pub struct EngineSubscriber<E: EngineHolder = Arc<dyn SessionEngine>> {
    // THE FIELD ORDER IS THE RETRACTION ORDER, the tokio runtime's: the subscription, the two
    // jobs, the gets in flight, the late-publisher subscription, the heartbeat subscription and
    // the detection token.
    subscriber: Held<Subscription<E>>,
    periodic: Option<Ticker<E>>,
    retention: Option<Ticker<E>>,
    cancel: GetCancel<E>,
    late_publishers: Option<Held<Subscription<E>>>,
    heartbeat: Option<Held<Subscription<E>>>,
    detection_token: Option<Held<Token<E>>>,
    shared: Strong<Shared<E>>,
    id: EntityGlobalId,
    /// Kept for [`Self::background`], which hands the names back to the host that made them.
    forms: Option<FormsHandle>,
}

/// The wire form of an entity as the host named it.
fn wire_of(form: &EntityForm) -> WireKey {
    if let (true, Some(kept)) = (form.suffix_is_kept(), form.kept()) {
        // SAFETY: the form's suffix lies in what it keeps (`EntityForm::aliased_in`), which the
        // key keeps a count of, so it stays there, unchanged, while the key does.
        return unsafe {
            WireKey::aliased_in(
                form.mapping_id(),
                form.suffix().unwrap_or_default(),
                kept.clone(),
            )
        };
    }
    let wire = if form.is_literal() {
        WireKey::literal()
    } else {
        WireKey::aliased(form.mapping_id(), form.suffix().map(str::to_owned))
    };
    match form.kept() {
        Some(anchor) => wire.keeping(anchor.clone()),
        None => wire,
    }
}

/// What forms says about one entity, the literal form when it says nothing.
fn form_of(
    forms: Option<&FormsHandle>,
    ask: impl FnOnce(&dyn DeclarationForms) -> EntityForm,
) -> EntityForm {
    forms.map(|f| ask(f.forms())).unwrap_or_default()
}

impl<E: EngineHolder> EngineSubscriber<E> {
    /// Declare an advanced subscriber on `keyexpr` over `engine`, delivering to `on_sample`.
    ///
    /// What `options` asks for is declared and refused if the engine cannot carry it: a
    /// subscription always; a heartbeat subscription and a periodic job when recovery asks for
    /// them; the startup get and the late-publisher subscription when history asks for them; the
    /// detection token when detection does. The order is the tokio runtime's.
    pub fn declare(
        engine: &E,
        keyexpr: impl AsRef<str>,
        options: AdvancedSubscriberOptions,
        on_sample: impl FnMut(Delivery<'_>) + Send + 'static,
    ) -> Result<Self, HostError> {
        Self::declare_with(
            engine,
            keyexpr,
            options,
            OnSample::boxed(Box::new(on_sample)),
            MissHandlers::default(),
        )
    }

    /// [`Self::declare`] with one miss listener registered from the start, which never leaves.
    pub fn declare_with_miss_listener(
        engine: &E,
        keyexpr: impl AsRef<str>,
        options: AdvancedSubscriberOptions,
        on_sample: impl FnMut(Delivery<'_>) + Send + 'static,
        on_miss: impl FnMut(Miss) + Send + 'static,
    ) -> Result<Self, HostError> {
        let mut misses = MissHandlers::default();
        misses.register(Box::new(on_miss));
        Self::declare_with(
            engine,
            keyexpr,
            options,
            OnSample::boxed(Box::new(on_sample)),
            misses,
        )
    }

    /// [`Self::declare`] delivering to `on_sample` and reporting holes to the listeners
    /// `misses` holds from the start, in whichever form each was made: a host whose callbacks are
    /// lent ([`OnSample::lent`], [`MissHandlers::lent`]) declares with no memory taken for them.
    pub fn declare_with(
        engine: &E,
        keyexpr: impl AsRef<str>,
        options: AdvancedSubscriberOptions,
        on_sample: OnSample,
        misses: MissHandlers,
    ) -> Result<Self, HostError> {
        let base_keyexpr = admitted(engine, keyexpr.as_ref(), &options)?;
        let make = |place: NonNull<Shared<E>>| {
            // SAFETY: the place is the box's, valid for one `Shared`, holding none, never moved.
            unsafe { write_shared_part(place, engine, base_keyexpr, &options, on_sample, misses) }
        };
        // SAFETY: `make` makes the whole shared part in the place it is handed. Refused, `make` is
        // dropped uncalled, and the callbacks with it.
        let shared = unsafe { Strong::try_boxed_in(make) }.map_err(|NoPlace| HostError::NoRoom)?;
        Self::declare_over(engine, shared, options)
    }

    /// [`Self::declare_with`] with what the subscriber's callbacks and jobs share lodged in `core`,
    /// a place its host lends, and not in memory of its own: a host that keeps its objects in
    /// places of its own declares with no memory taken for it.
    ///
    /// The place is given back once ([`LentCore::new`]): at once when the declaration is refused
    /// before the part is made, and otherwise with the last of what holds the part.
    pub fn declare_in(
        engine: &E,
        keyexpr: impl AsRef<str>,
        options: AdvancedSubscriberOptions,
        on_sample: OnSample,
        misses: MissHandlers,
        core: LentCore<E>,
    ) -> Result<Self, HostError> {
        let base_keyexpr = match admitted(engine, keyexpr.as_ref(), &options) {
            Ok(base_keyexpr) => base_keyexpr,
            Err(refused) => {
                drop((on_sample, misses));
                // SAFETY: `LentCore::new`'s: nothing was lodged, so the place goes back now, once.
                unsafe { (core.give_back)(core.context) };
                return Err(refused);
            }
        };
        let make = |place: NonNull<Shared<E>>| {
            // SAFETY: the place is the lent core's, valid for one `Shared`, holding none, never
            // moved while it is counted.
            unsafe { write_shared_part(place, engine, base_keyexpr, &options, on_sample, misses) }
        };
        // SAFETY: `LentCore::new`'s; a `SubscriberCore` is the place of its lodging
        // (`repr(transparent)`); `make` makes the whole shared part in the place it is handed.
        let shared = unsafe {
            Strong::lodge_in(
                core.core.cast::<MaybeUninit<Lodging<Shared<E>>>>(),
                make,
                core.give_back,
                core.context,
            )
        };
        Self::declare_over(engine, shared, options)
    }

    /// Declare what `options` asks for over `shared`, the subscriber's shared part, made.
    fn declare_over(
        engine: &E,
        shared: Strong<Shared<E>>,
        options: AdvancedSubscriberOptions,
    ) -> Result<Self, HostError> {
        let zid = engine.session_zid();
        let recovery = options.recovery;
        let history = options.history;
        let forms = options.forms.clone();
        let base = shared.base();

        // The live subscription.
        let subscriber_form = form_of(forms.as_ref(), |f| f.subscriber(base));
        let subscriber = declare_subscription(
            engine,
            base,
            &subscriber_form,
            options.allowed_origin,
            own_sink(&shared, on_live::<E>),
        )?;
        let id = identity_of(zid, subscriber.entity.id, forms.as_ref());

        // The retention sweep and the periodic re-ask: jobs the engine runs.
        let retention = match recovery.map(|c| c.retention_period()) {
            Some(period) => {
                let weak = Strong::downgrade(&shared);
                let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
                Some(
                    Ticker::start_on(
                        E::clone(engine),
                        period_ms,
                        Arc::new(move || {
                            let Some(shared) = weak.upgrade() else {
                                return false;
                            };
                            if shared.is_closing() {
                                return false;
                            }
                            let now = shared.now_ms();
                            shared.lock().reclaim_expired_sources(now, period);
                            true
                        }),
                    )
                    .map_err(HostError::of("the engine runs no periodic jobs"))?,
                )
            }
            None => None,
        };
        let periodic = match recovery.and_then(|c| c.periodic_queries()) {
            Some(period) => {
                let weak = Strong::downgrade(&shared);
                let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
                Some(
                    Ticker::start_on(
                        E::clone(engine),
                        period_ms,
                        Arc::new(move || {
                            let Some(shared) = weak.upgrade() else {
                                return false;
                            };
                            if shared.is_closing() {
                                return false;
                            }
                            run_periodic_tick(&shared);
                            true
                        }),
                    )
                    .map_err(HostError::of("the engine runs no periodic jobs"))?,
                )
            }
            None => None,
        };

        // The startup get, after the live subscription, so a live sample that arrives during it
        // is held until the history is in.
        if let Some(history) = history {
            issue_history_query(&shared, history.sample_depth, history.max_age);
        }

        // The late-publisher subscription, declared to replay the tokens already alive: the
        // startup get is a snapshot, and a publisher whose cache filled after it is met here.
        let late_publishers = if history.is_some_and(|h| h.detect_late_publishers) {
            let keyexpr = crate::advanced_ke::publisher_detection_ke(base);
            let form = form_of(forms.as_ref(), |f| f.late_publishers(&keyexpr));
            // SAFETY: the context is a count of the subscriber, let go of once by `let_go` after
            // the last call; a call reads the subscriber through a shared borrow, which it admits
            // from any thread.
            let sink = unsafe {
                LivelinessSink::raw(
                    on_late_publisher::<E>,
                    Strong::into_raw(shared.clone()),
                    Some(let_go::<E>),
                )
            };
            Some(declare_liveliness_subscription(
                engine, &keyexpr, &form, true, sink,
            )?)
        } else {
            None
        };

        // The heartbeat subscription, in the place pico declares it, and degraded rather than
        // failing when its derived key is one the outbound gate refuses.
        let heartbeat = if recovery.is_some_and(|c| c.heartbeat()) {
            let keyexpr = crate::advanced_ke::publisher_detection_ke(base);
            if crate::advanced_ke::adv_ke_is_outbound_safe(&keyexpr) {
                let form = form_of(forms.as_ref(), |f| f.heartbeat(&keyexpr));
                Some(declare_subscription(
                    engine,
                    &keyexpr,
                    &form,
                    options.allowed_origin,
                    own_sink(&shared, on_heartbeat::<E>),
                )?)
            } else {
                wz_session_core::diag_warn!(
                    "advanced subscriber on '{base}': heartbeat recovery was REQUESTED \
                     but its derived keyexpr '{keyexpr}' is refused by the outbound pico-safety \
                     gate, so the channel is DEGRADED; the live subscription is unaffected"
                );
                None
            }
        } else {
            None
        };

        // The detection token, last: a subscriber advertises itself once it can receive.
        let detection_token = declare_detection_token(engine, base, &options, id)?;

        Ok(Self {
            subscriber,
            periodic,
            retention,
            cancel: GetCancel {
                shared: shared.clone(),
                armed: true,
            },
            late_publishers,
            heartbeat,
            detection_token,
            shared,
            id,
            forms,
        })
    }

    /// This subscriber's global identity: the session's zid and the id its subscription carries.
    pub fn id(&self) -> EntityGlobalId {
        self.id
    }

    /// The key expression this subscriber subscribes to.
    pub fn keyexpr(&self) -> &str {
        self.shared.base()
    }

    /// Whether the heartbeat channel is actually live: a request that the derived key made
    /// impossible degrades, and this is the outcome.
    pub fn heartbeat_channel_is_live(&self) -> bool {
        self.heartbeat.is_some()
    }

    /// Declare a sample-miss listener. Any number may be declared and each is retracted on its
    /// own, by dropping the handle or [`SampleMissListener::undeclare`].
    pub fn sample_miss_listener(
        &self,
        callback: impl FnMut(Miss) + Send + 'static,
    ) -> SampleMissListener {
        let id = self
            .shared
            .lock()
            .miss_handlers()
            .register(Box::new(callback));
        let weak = WeakRef::into_raw(Strong::downgrade(&self.shared));
        // SAFETY: the context is a weak count of the subscriber, let go of once by `let_go_weak`;
        // a retraction upgrades it, which it admits from any thread.
        unsafe { SampleMissListener::lent(id, weak, unregister_miss::<E>, let_go_weak::<E>) }
    }

    /// Undeclare this subscriber. Consuming and infallible: everything it holds retracts on drop.
    pub fn undeclare(self) {
        drop(self);
    }

    /// Run this subscriber in the background until the engine is dropped, with no handle left to
    /// retract it. The entities stay declared, the gets in flight run to their Final, and the
    /// jobs run on until their weak references stop upgrading. What names an entity is handed to
    /// the host that made it, since nothing is left to let it go after the entity.
    pub fn background(self) {
        let Self {
            subscriber,
            periodic,
            retention,
            mut cancel,
            late_publishers,
            heartbeat,
            detection_token,
            shared: _,
            id: _,
            forms,
        } = self;
        cancel.armed = false;
        let retain = |keeps: Option<Kept>| {
            if let (Some(forms), Some(keeps)) = (forms.as_ref(), keeps) {
                forms.forms().retain(keeps);
            }
        };
        let Held { mut entity, keeps } = subscriber;
        entity.retract = false;
        retain(keeps);
        for ticker in [periodic, retention].into_iter().flatten() {
            ticker.detach();
        }
        for held in [late_publishers, heartbeat].into_iter().flatten() {
            let Held { mut entity, keeps } = held;
            entity.retract = false;
            retain(keeps);
        }
        if let Some(Held { mut entity, keeps }) = detection_token {
            entity.retract = false;
            retain(keeps);
        }
    }
}

/// The checks a declaration makes before anything is made for it: the history bounds, as
/// upstream's builder checks them, a session still open, and a key a session stores, which it
/// answers kept inline.
fn admitted<E: EngineHolder>(
    engine: &E,
    keyexpr: &str,
    options: &AdvancedSubscriberOptions,
) -> Result<FixedKey, HostError> {
    if let Some(history) = options.history.as_ref() {
        if history.sample_depth == Some(0) {
            return Err(HostError::HistoryBoundZero {
                knob: "max_samples",
            });
        }
        if history.max_age == Some(core::time::Duration::ZERO) {
            return Err(HostError::HistoryBoundZero { knob: "max_age" });
        }
    }
    if engine.is_closed() {
        return Err(HostError::Refused("the session is closed"));
    }
    fixed_key(keyexpr).ok_or(HostError::Refused(
        "the key expression is longer than a session stores",
    ))
}

/// What a subscriber of `engine` on `base_keyexpr` shares among its callbacks and jobs, with the
/// machine `options` asks for delivering to `on_sample` and `misses`, made in `place`.
///
/// # Safety
/// As [`Shared::write_in`].
unsafe fn write_shared_part<E: EngineHolder>(
    place: NonNull<Shared<E>>,
    engine: &E,
    base_keyexpr: FixedKey,
    options: &AdvancedSubscriberOptions,
    on_sample: OnSample,
    misses: MissHandlers,
) {
    let history = options.history;
    let state = State::delivering_to(on_sample, misses)
        .with_retransmission(options.recovery.is_some())
        .with_history(
            usize::from(history.is_some()),
            history
                .as_ref()
                .and_then(|h| h.sample_depth)
                .unwrap_or(usize::MAX),
        );
    // SAFETY: the caller's, which is `write_in`'s; the part is whole before its bounds are set.
    unsafe {
        Shared::write_in(
            place,
            E::downgrade(engine),
            state,
            base_keyexpr,
            options.get_locality,
            recovery_query_timeout_ms(options.query_timeout),
        );
        (*place.as_ptr()).late = history
            .map(|h| (h.sample_depth, h.max_age))
            .unwrap_or((None, None));
    }
}

/// The identity a subscriber reports: its host's, when the host has one, else its subscription's
/// own id, which is the entity id its declaration carries.
fn identity_of(
    zid: SessionZid,
    subscription: SubId,
    forms: Option<&FormsHandle>,
) -> EntityGlobalId {
    let eid = forms
        .and_then(|f| f.forms().entity_id())
        .unwrap_or(subscription);
    EntityGlobalId::of_session(zid, eid)
}

/// Declare a plain subscription on `keyexpr` in `form`.
fn declare_subscription<E: EngineHolder>(
    engine: &E,
    keyexpr: &str,
    form: &EntityForm,
    origin: Locality,
    sink: SubscriberSink,
) -> Result<Held<Subscription<E>>, HostError> {
    let id = engine
        .declare_subscriber_on_wire(
            keyexpr,
            wire_of(form),
            origin,
            form.retraction().cloned(),
            sink,
        )
        .map_err(HostError::of("the engine has no subscribers"))?
        .id;
    Ok(Held {
        entity: Subscription {
            engine: E::clone(engine),
            id,
            retract: true,
        },
        keeps: form.kept().cloned(),
    })
}

/// Declare a liveliness subscription on `keyexpr` in `form`.
fn declare_liveliness_subscription<E: EngineHolder>(
    engine: &E,
    keyexpr: &str,
    form: &EntityForm,
    history: bool,
    sink: LivelinessSink,
) -> Result<Held<Subscription<E>>, HostError> {
    let id = engine
        .declare_liveliness_subscriber_on_wire(keyexpr, wire_of(form), history, sink)
        .map_err(HostError::of("the engine has no liveliness plane"))?
        .id;
    Ok(Held {
        entity: Subscription {
            engine: E::clone(engine),
            id,
            retract: true,
        },
        keeps: form.kept().cloned(),
    })
}

/// Declare the `@adv/sub` detection token when the caller asked for it, else `None`.
fn declare_detection_token<E: EngineHolder>(
    engine: &E,
    keyexpr: &str,
    options: &AdvancedSubscriberOptions,
    id: EntityGlobalId,
) -> Result<Option<Held<Token<E>>>, HostError> {
    let Some(detection) = options.subscriber_detection.as_ref() else {
        return Ok(None);
    };
    // Named with the subscriber's OWN identity, the pair its `id()` reports.
    let ke = crate::advanced_ke::subscriber_adv_ke(
        keyexpr,
        &zid_to_zenoh_hex(id.zid()),
        id.eid(),
        detection.metadata.as_deref(),
    );
    let form = form_of(options.forms.as_ref(), |f| f.token(&ke));
    let retraction = form.names_key_on_retraction().then(|| {
        if form.is_literal() {
            RetractionKey::literal()
        } else {
            RetractionKey::declared(form.mapping_id(), form.suffix().unwrap_or_default())
        }
    });
    let token = engine
        .declare_liveliness_token_on_wire(&ke, wire_of(&form), retraction)
        .map_err(HostError::of("the engine has no liveliness plane"))?;
    Ok(Some(Held {
        entity: Token {
            engine: E::clone(engine),
            id: token,
            retract: true,
        },
        keeps: form.kept().cloned(),
    }))
}

/// The options every get of this subscriber carries: it reads each reply's timestamp (it is the
/// runtime's own query, not an entity of the application), goes where the subscriber was told to,
/// is bounded by the timeout so a get nobody answers ends, asks every queryable and not the best
/// match, and takes every sample of a range and not the latest of each key.
fn get_options<'a, E: EngineHolder>(
    shared: &Shared<E>,
    parameters: &'a GetParameters,
) -> QueryOptionsOf<'a> {
    // `_anyke`: a cached sample comes back on its own key, which a get on the `@adv` namespace
    // does not intersect; the responder accepts it only with the flag.
    QueryOptionsOf::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(shared.dest)
        .with_timeout_ms(shared.timeout_ms)
        .with_parameters_lent_anyke(parameters.as_bytes(), true)
        .with_target(QueryTarget::All)
        .with_consolidation(ConsolidationMode::None)
}

/// Issue one get on `keyexpr` with `opts`, feeding each reply to the machine and running `finish`
/// when the get is over. MUST be called with the state lock released.
///
/// The get takes a slot of the subscriber's table of gets in flight; with every slot taken the
/// session holds as many gets pending as it can, and the get is over before it starts, as one no
/// leg was issued for.
fn issue_get<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    keyexpr: &str,
    opts: &QueryOptionsOf<'_>,
    finish: Finish,
) {
    let Some(engine) = E::upgrade(&shared.engine) else {
        return;
    };
    let Some(slot) = shared.claim() else {
        end_unasked(shared, finish);
        return;
    };
    // SAFETY: the slot was taken just above, in `shared`'s table, and no leg of it is out.
    let fan = unsafe { slot.open(shared, finish) };
    // Registered before the first leg is issued, as upstream orders it, so a teardown that starts
    // now stops the issuing. A refusal is a teardown already under way, which marks the subscriber
    // closing first, so the end below runs no finish.
    // SAFETY: the token lies in the subscriber, which every get holds, so it stands until the last
    // fan is dropped; the fan lies in its slot, where it is dropped, and no engine has it yet.
    let registered = unsafe { fan.register(TokenRef::placed(&shared.token)) };
    if registered {
        let mut leg = || -> ReplyCallback {
            // SAFETY: this issuer holds the get until the release below.
            unsafe { slot.leg(shared) }
        };
        let _ = engine.get_on_wire(keyexpr, &WireKey::literal(), opts, Some(fan), &mut leg);
    }
    // The hold of the issuer goes last: a get with no leg ends here, and one whose legs all ended
    // during the call ends here too, after the call returned.
    // SAFETY: the issuer lets go of its hold once, here, and holds the subscriber.
    unsafe { slot.release() };
}

/// A get that is not asked is over at once: its end runs as a get's end does, unless the
/// subscriber is closing.
fn end_unasked<E: EngineHolder>(shared: &Shared<E>, finish: Finish) {
    if !shared.is_closing() {
        finish.run(&mut shared.lock());
    }
}

/// A key written where its holder keeps it (a subscriber's own, or one get's): as long as the
/// longest key a session stores, so a key past it is one no session would send.
type FixedKey = FixedText<{ caps::MAX_KEYEXPR_BYTES }>;

/// `text` as a key kept inline, or `None` when it is longer than a session stores.
fn fixed_key(text: &str) -> Option<FixedKey> {
    let mut key = FixedKey::new();
    key.write_str(text).is_ok().then_some(key)
}

/// The key of the startup get, `<base>/@adv/**`.
fn history_key(base: &str) -> FixedKey {
    let mut key = FixedKey::new();
    crate::advanced_ke::write_history_get_ke(&mut key, base);
    key
}

/// The key of a get of one source's cache, `<base>/@adv/*/<zid>/<eid>/**`.
fn recovery_key(base: &str, zid: &[u8], eid: u32) -> FixedKey {
    let mut key = FixedKey::new();
    crate::advanced_ke::write_recovery_get_ke(&mut key, base, zid, eid);
    key
}

/// Issue one get on the key written in `key`, as [`issue_get`] does; a key too long to write is
/// a get no session sends, and it is over before it starts.
fn issue_get_on<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    key: &FixedKey,
    opts: &QueryOptionsOf<'_>,
    finish: Finish,
) {
    match key.finish() {
        Ok(keyexpr) => issue_get(shared, keyexpr, opts, finish),
        Err(_) => end_unasked(shared, finish),
    }
}

/// Issue a `_sn` recovery get against the gapped source's `@adv` cache: the open range from the
/// next sequence number, or the bounded one a heartbeat asks for.
fn issue_recovery_query<E: EngineHolder>(shared: &Strong<Shared<E>>, request: RecoveryRequest) {
    let key = recovery_key(shared.base(), &request.zid, request.eid);
    let parameters = GetParameters::recovery(request.from_sn, request.to_sn);
    let opts = get_options(shared, &parameters);
    issue_get_on(
        shared,
        &key,
        &opts,
        Finish::Recovery((request.zid, request.eid)),
    );
}

/// Issue the startup get over `<base>/@adv/**`, capped and bounded as the history config says.
fn issue_history_query<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    depth: Option<usize>,
    age: Option<core::time::Duration>,
) {
    let key = history_key(shared.base());
    let parameters = GetParameters::history(depth, age);
    issue_get_on(
        shared,
        &key,
        &get_options(shared, &parameters),
        Finish::History,
    );
}

/// Issue the history get of one detected late publisher `(zid, eid)`.
fn issue_late_publisher_query<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    zid: Vec<u8>,
    eid: u32,
    depth: Option<usize>,
    age: Option<core::time::Duration>,
) {
    let key = recovery_key(shared.base(), &zid, eid);
    let parameters = GetParameters::history(depth, age);
    let opts = get_options(shared, &parameters);
    issue_get_on(shared, &key, &opts, Finish::Recovery((zid, eid)));
}

/// The timestamped twin: the target is the token's own key expression, which is the one the
/// publisher declared its cache queryable on.
fn issue_timestamped_late_publisher_query<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    token_keyexpr: &str,
    zid: Vec<u8>,
    depth: Option<usize>,
    age: Option<core::time::Duration>,
) {
    let parameters = GetParameters::history(depth, age);
    let opts = get_options(shared, &parameters);
    issue_get(shared, token_keyexpr, &opts, Finish::Timestamped(zid));
}

/// The get for a publisher whose token's zid does not decode: counted globally, since there is no
/// source to count it against.
fn issue_unidentified_late_publisher_query<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    token_keyexpr: &str,
    depth: Option<usize>,
    age: Option<core::time::Duration>,
) {
    let parameters = GetParameters::history(depth, age);
    let opts = get_options(shared, &parameters);
    issue_get(shared, token_keyexpr, &opts, Finish::History);
}

/// The late-publisher liveliness callback: on a `Put`, open a slot for the detected publisher and
/// issue its history get (outside the lock); on a `Delete`, only mark it gone.
fn on_late_publisher_detected<E: EngineHolder>(
    shared: &Strong<Shared<E>>,
    kind: LivelinessSampleKind,
    token_keyexpr: &str,
    depth: Option<usize>,
    age: Option<core::time::Duration>,
) {
    if kind != LivelinessSampleKind::Put {
        // A departed publisher has nothing to recover, but its retention flag is how the sweep
        // learns it is not alive any more.
        if let Some(source) = parse_heartbeat_source(token_keyexpr) {
            if let Some((zid, eid)) = match source {
                AdvPublisherSource::Sequenced { zid, eid } => Some((zid, Some(eid))),
                AdvPublisherSource::Timestamped { zid } => Some((zid, None)),
                AdvPublisherSource::Unidentified => None,
            } {
                shared.lock().set_source_alive(&zid, eid, false);
            }
        }
        return;
    }
    let now = shared.now_ms();
    match parse_heartbeat_source(token_keyexpr) {
        Some(AdvPublisherSource::Sequenced { zid, eid }) => {
            let issue = {
                let mut state = shared.lock();
                let issue = state.handle_late_publisher(zid.clone(), eid, now);
                state.set_source_alive(&zid, Some(eid), true);
                issue
            };
            if issue {
                issue_late_publisher_query(shared, zid, eid, depth, age);
            }
        }
        Some(AdvPublisherSource::Timestamped { zid }) => {
            let issue = {
                let mut state = shared.lock();
                let issue = state.handle_late_timestamped_publisher(zid.clone(), now);
                state.set_source_alive(&zid, None, true);
                issue
            };
            if issue {
                issue_timestamped_late_publisher_query(shared, token_keyexpr, zid, depth, age);
            }
        }
        Some(AdvPublisherSource::Unidentified) => {
            shared.lock().open_global_history_slot();
            issue_unidentified_late_publisher_query(shared, token_keyexpr, depth, age);
        }
        None => {}
    }
}

/// One periodic recovery tick: collect each source's `_sn=last+1..` request under the state lock,
/// then issue the gets with it released.
fn run_periodic_tick<E: EngineHolder>(shared: &Strong<Shared<E>>) {
    let requests = shared.lock().periodic_requests();
    for request in requests {
        issue_recovery_query(shared, request);
    }
}

#[cfg(test)]
mod tests;
