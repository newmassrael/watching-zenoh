// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_replay_subscriber_*`: the replay cache of a subscriber, from C. It subscribes to a
//! message's key, watches the session's peers for the message's replay queryable (the key plus
//! the suffix the program states), asks each publisher as it appears for what it last sent, and
//! hands the program every sample, replies and live samples alike, judged by one receiving judge,
//! with a flag that says which it is.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `replay-cache` capability implies `unstable-api`. The round, the
//! table of publishers and the held live samples are [`wz_session_core::replay_subscriber`]'s,
//! the admission of a reply to the judge is [`wz_app_frame::replay_admission`]'s, and the judge
//! is the program's own receiver ([`wz_app_frame::e2e_receiver`]), which the subscriber takes.
//! This file is the pico ABI's names, result codes, callbacks and ownership around them.
//!
//! # Asking
//!
//! A publisher appears when the declaration watch tells a queryable declared on exactly the
//! suffixed key, by a node it names. It is asked once, by a get on the suffixed key: addressed to
//! that node when the session's `targeted-query` policy admits it, otherwise asked of every node
//! that answers the key, whose replies the judge has passed are dropped as duplicates or stale. A
//! get asks for every reply, unconsolidated, and ends at the latest after the round deadline. A
//! publisher that declared its queryable before the watch was declared is not told again (the
//! declaration watch's rule), so a subscriber is made before the links to its publishers come up.
//!
//! # Order
//!
//! Under the session's `replay-live-before-answer = hold-back` the live samples that arrive before
//! the first round is over are held in the program's store and handed on after its last reply;
//! under `deliver` they are handed on as they arrive. A reply of an abandoned round is dropped.
//! Under `replay-reply-shape = segmented` a reply is one piece of a frame, which this library does
//! not join yet, so such a subscriber is refused by name.
//!
//! # Time
//!
//! Milliseconds in 32 bits that wrap: the program's clock, given in the options, or the library's
//! monotonic clock from the creation when it gives none. The deadlines are judged by
//! `wz_ext_replay_subscriber_poll`, which the program calls on its own cadence; the judge is
//! handed the same reading as the time a sample arrived.
//!
//! # Threads
//!
//! The callbacks the session hands samples, replies and declarations to take the subscriber's
//! lock, and the program's callback runs inside it, on that thread or on the one that polls, so it
//! is called for one sample at a time in the order the judge saw them, and must not call a door of
//! its own subscriber. The sample and the frame it points to are valid only for the call.

use core::ffi::{c_char, c_void};
use core::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use wz_app_frame::e2e_receiver::Receiver;
use wz_app_frame::replay_admission::{admit, Admission};
use wz_session_core::policy::ReplayReplyShape;
use wz_session_core::replay_subscriber::{
    CreateRefused, Deadlines, LiveFate, Phase, PublisherSlot, ReplaySubscriber, ReplyFate,
};
use wz_session_core::session_zid::ZID_MAX;

use crate::abi::{z_loaned_keyexpr_t, z_view_keyexpr_t};
use crate::bytes::bytes_ref;
use crate::decl_watch::{
    wz_ext_decl_event_t, wz_ext_decl_watch_declare, wz_ext_decl_watch_drop,
    wz_ext_owned_decl_watch_t, WZ_EXT_DECL_DECLARED, WZ_EXT_DECL_QUERYABLE, WZ_EXT_DECL_UNDECLARED,
};
use crate::e2e::{locked, utf8_arg};
use crate::e2e_receiver::{to_c, wz_ext_e2e_verdict_t, wz_ext_moved_e2e_receiver_t};
use crate::ffi::{catch, guard_val, guarded, InCallback, SendPtr};
use crate::get::{
    z_get, z_get_options_default, z_get_options_t, z_loaned_reply_t, z_moved_closure_reply_t,
    z_owned_closure_reply_t, z_reply_is_ok, z_reply_ok, Z_CONSOLIDATION_MODE_NONE,
    Z_QUERY_TARGET_ALL,
};
use crate::get_to_peer::{wz_ext_get_to_peer, TARGETED_IN_DOMAIN};
use crate::keyexpr::{keyexpr_str, z_view_keyexpr_from_substr, z_view_keyexpr_loan};
use crate::pubsub::{
    z_declare_subscriber, z_loaned_sample_t, z_moved_closure_sample_t, z_owned_closure_sample_t,
    z_owned_subscriber_t, z_sample_payload, z_subscriber_move, z_undeclare_subscriber,
};
use crate::result::{
    ZResult, WZ_EXT_ERR_UNSUPPORTED, Z_EINVAL, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SESSION_CLOSED,
    Z_OK,
};
use crate::session::{session_handle, z_loaned_session_t};
use crate::zid::{z_id_t, Z_ID_SIZE};

// The peer a get is addressed to is the zenoh id the watch named, in the layout of `z_id_t`.
const _: () = assert!(Z_ID_SIZE == ZID_MAX);

/// No publisher has appeared yet.
pub const WZ_EXT_REPLAY_ROUND_IDLE: u8 = 0;
/// A round's queries are out and no reply has come yet.
pub const WZ_EXT_REPLAY_ROUND_ASKING: u8 = 1;
/// At least one reply of the round came.
pub const WZ_EXT_REPLAY_ROUND_ANSWERING: u8 = 2;
/// A deadline passed, or the held samples filled their store, before the round was over.
pub const WZ_EXT_REPLAY_ROUND_ABANDONED: u8 = 3;
/// The round is over, or no publisher appeared before the round deadline.
pub const WZ_EXT_REPLAY_ROUND_LIVE: u8 = 4;
/// What `wz_ext_replay_subscriber_phase` answers for a null subscriber or the gravestone.
pub const WZ_EXT_REPLAY_NO_SUBSCRIBER: u8 = 255;

/// One row of the program's table of publishers: four 64-bit words the subscriber owns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct wz_ext_replay_publisher_slot_t {
    _opaque: [u64; 4],
}

// The C header sizes the table by this type, and the subscriber writes `PublisherSlot` into it.
const _: () = assert!(
    core::mem::size_of::<wz_ext_replay_publisher_slot_t>() == core::mem::size_of::<PublisherSlot>()
        && core::mem::align_of::<wz_ext_replay_publisher_slot_t>()
            == core::mem::align_of::<PublisherSlot>()
);

/// The program's clock: writes the milliseconds of a monotonic source, in 32 bits that wrap, and
/// returns 0, or returns anything else when it cannot say what time it is.
pub type wz_ext_replay_clock_fn =
    unsafe extern "C" fn(context: *mut c_void, now_ms: *mut u32) -> i8;

/// One sample handed to the program. 120 bytes on a 64-bit target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_replay_sample_t {
    /// The frame as it arrived, valid only for the call.
    pub frame: *const u8,
    /// Its length.
    pub len: usize,
    /// The judge's verdict; zero when `judged` is 0.
    pub verdict: wz_ext_e2e_verdict_t,
    /// 1 for a reply of a replay, 0 for a live sample.
    pub from_replay: u8,
    /// 1 when the judge judged it; 0 when the stream the subscriber was made with is not one the
    /// receiver judges in.
    pub judged: u8,
    /// How many bytes of `zid` name the publisher a reply came from; 0 for a live sample.
    pub zid_len: u8,
    pub reserved: u8,
    /// That publisher's zenoh id, zero past `zid_len`.
    pub zid: [u8; ZID_MAX],
}

/// What the subscriber hands each sample to, with the program's context.
pub type wz_ext_replay_deliver_fn =
    unsafe extern "C" fn(context: *mut c_void, sample: *const wz_ext_replay_sample_t);

/// What runs once when the subscriber lets go of the program's context.
pub type wz_ext_replay_drop_fn = unsafe extern "C" fn(context: *mut c_void);

/// How a subscriber is made.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_replay_subscriber_options_t {
    /// The program's table of publishers, `slot_count` rows, owned by the subscriber while it
    /// lives; at least one row.
    pub slots: *mut wz_ext_replay_publisher_slot_t,
    pub slot_count: usize,
    /// Under `hold-back`, the program's store of held live samples, `held_len` bytes cut into
    /// cells of 4 + `held_cell` bytes, owned by the subscriber while it lives; not read under
    /// `deliver`, and may be null with 0.
    pub held: *mut u8,
    pub held_len: usize,
    /// The longest live sample a held cell keeps.
    pub held_cell: usize,
    /// The depth of the publishers' rings: a reply behind the judge's baseline by less is stale.
    pub depth: usize,
    /// The most queries in flight at once; 0 for the querier's own bound,
    /// `QUERIER_MAX_PENDING_QUERIES`, and never above it.
    pub max_in_flight: usize,
    /// The receiver's stream every sample is judged in (0 under sender keying).
    pub stream: usize,
    /// How long a round waits for its next reply, and how long it lasts at most, in
    /// milliseconds; each 1 to 2147483647. No default: they are the deployment's.
    pub progress_ms: u32,
    pub round_ms: u32,
    /// The program's clock, or null for the library's monotonic clock.
    pub clock: Option<wz_ext_replay_clock_fn>,
    pub clock_context: *mut c_void,
}

impl Default for wz_ext_replay_subscriber_options_t {
    fn default() -> Self {
        Self {
            slots: core::ptr::null_mut(),
            slot_count: 0,
            held: core::ptr::null_mut(),
            held_len: 0,
            held_cell: 0,
            depth: 1,
            max_in_flight: 0,
            stream: 0,
            progress_ms: 0,
            round_ms: 0,
            clock: None,
            clock_context: core::ptr::null_mut(),
        }
    }
}

/// What a subscriber counted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_replay_subscriber_counts_t {
    /// Replies of an abandoned round's query, dropped.
    pub late_replies: u64,
    /// Replies of no query in flight, dropped.
    pub unknown_replies: u64,
    /// Replies of the frame the judge holds as its baseline, dropped.
    pub duplicates: u64,
    /// Replies behind the judge's baseline by less than the depth, dropped.
    pub stale: u64,
    /// Live samples held back.
    pub held: u64,
    /// Publishers not taken because every row was in use.
    pub table_full: u64,
    /// Rounds abandoned.
    pub abandoned: u64,
}

/// An owned subscriber: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_replay_subscriber_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned subscriber: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_replay_subscriber_t {
    pub(crate) handle: *mut c_void,
}

/// A moved subscriber (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_replay_subscriber_t {
    pub(crate) _this: wz_ext_owned_replay_subscriber_t,
}

impl wz_ext_owned_replay_subscriber_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }
}

struct Clock {
    read: Option<wz_ext_replay_clock_fn>,
    context: SendPtr,
    origin: Instant,
}

impl Clock {
    fn now(&self) -> Option<u32> {
        match self.read {
            // Milliseconds since the creation, in the 32 bits the round compares: the truncation
            // is the wrap it is written to survive.
            None => Some(self.origin.elapsed().as_millis() as u32),
            Some(read) => {
                let mut now = 0u32;
                // SAFETY: the program gave this clock and its context for the subscriber's life.
                (unsafe { read(self.context.0, &mut now) } == 0).then_some(now)
            }
        }
    }
}

/// The counts the door keeps beside the round's.
#[derive(Default)]
struct Dropped {
    duplicates: u64,
    stale: u64,
}

struct State {
    /// The round over the program's storage; `None` once the program dropped the subscriber, so
    /// a callback that comes after reads nothing of the storage and hands nothing on.
    round: Option<ReplaySubscriber<'static>>,
    receiver: Receiver,
    stream: usize,
    depth: usize,
    clock: Clock,
    deliver: wz_ext_replay_deliver_fn,
    context: SendPtr,
    /// Room for one held sample, as it is released.
    released: Vec<u8>,
    dropped: Dropped,
}

/// A publisher to ask: its row and its zenoh id, padded as `z_id_t` lays it out.
struct Ask {
    slot: usize,
    zid: [u8; ZID_MAX],
    zid_len: usize,
}

impl Ask {
    fn zid(&self) -> &[u8] {
        &self.zid[..self.zid_len]
    }
}

/// What the session's callbacks and the doors share.
struct Shared {
    state: Mutex<State>,
    /// The session the subscriber was made on, as its loan reads.
    session: z_loaned_session_t,
    /// The key the publishers' replay queryables are declared on: the key and the suffix.
    replay_key: String,
    /// How long a get lives at most: the round deadline.
    get_timeout_ms: u64,
}

// SAFETY: the session's words are the handle of a session the program keeps open while the
// subscriber lives, and the doors called through them are pico's, which any thread may call; the
// rest is behind the lock, and the program's context and clock are handed over for exactly that.
unsafe impl Send for Shared {}
// SAFETY: as for `Send`: nothing but the session's words, the key and the timeout, which no door
// writes, is read without the lock.
unsafe impl Sync for Shared {}

/// Behind a handle: the shared state, the subscriber and the watch, and the program's drop.
struct Handle {
    shared: Arc<Shared>,
    subscriber: z_owned_subscriber_t,
    watch: wz_ext_owned_decl_watch_t,
    drop: Option<wz_ext_replay_drop_fn>,
    context: SendPtr,
}

/// The context of one get's reply closure.
struct ReplyContext {
    shared: Arc<Shared>,
    slot: usize,
}

impl State {
    /// Judge `frame` and hand it to the program: a reply when `from` names its publisher.
    fn hand_on(&mut self, frame: &[u8], from: Option<&[u8]>, now: Option<u32>) {
        let now_ms = u64::from(now.unwrap_or(0));
        let (verdict, judged) = match self.receiver.receive(self.stream, frame, now_ms) {
            Ok(verdict) => (to_c(&verdict), 1),
            Err(_) => (wz_ext_e2e_verdict_t::default(), 0),
        };
        let mut sample = wz_ext_replay_sample_t {
            frame: frame.as_ptr(),
            len: frame.len(),
            verdict,
            from_replay: u8::from(from.is_some()),
            judged,
            zid_len: 0,
            reserved: 0,
            zid: [0; ZID_MAX],
        };
        if let Some(zid) = from {
            sample.zid[..zid.len()].copy_from_slice(zid);
            // A row's zenoh id is at most `ZID_MAX` bytes.
            sample.zid_len = zid.len() as u8;
        }
        let call = self.deliver;
        let context = self.context.0;
        let _in_callback = InCallback::enter();
        // SAFETY: the program's callback, called as its declaration says, with a sample that
        // outlives the call.
        let _ = catch(|| unsafe { call(context, &sample) });
    }

    /// Hand on, in arrival order, every held sample the round has released.
    fn release(&mut self, now: Option<u32>) {
        loop {
            let Some(round) = self.round.as_mut() else {
                return;
            };
            let Some(len) = round.pop_released(&mut self.released) else {
                return;
            };
            let frame = self.released[..len].to_vec();
            self.hand_on(&frame, None, now);
        }
    }

    /// The publisher a row holds, as a get addresses it; `None` for a free row.
    fn ask_of(&self, slot: usize) -> Option<Ask> {
        let zid = self.round.as_ref()?.zid(slot);
        if zid.is_empty() {
            return None;
        }
        let mut padded = [0u8; ZID_MAX];
        padded[..zid.len()].copy_from_slice(zid);
        Some(Ask {
            slot,
            zid: padded,
            zid_len: zid.len(),
        })
    }
}

impl Shared {
    /// A live sample arrived.
    fn live(&self, frame: &[u8]) {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        let Some(round) = state.round.as_mut() else {
            return;
        };
        if round.live(frame) == LiveFate::Deliver {
            state.release(now);
            state.hand_on(frame, None, now);
        }
    }

    /// A reply of the query of row `slot` arrived.
    fn reply(&self, slot: usize, frame: &[u8]) {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        let Some(round) = state.round.as_mut() else {
            return;
        };
        if round.reply(slot, now) == ReplyFate::Late {
            return;
        }
        let Some(from) = state.ask_of(slot) else {
            return;
        };
        match admit(&state.receiver, state.stream, frame, state.depth) {
            Admission::Duplicate => {
                state.dropped.duplicates = state.dropped.duplicates.saturating_add(1);
            }
            Admission::Stale => state.dropped.stale = state.dropped.stale.saturating_add(1),
            Admission::Judge => state.hand_on(frame, Some(from.zid()), now),
        }
    }

    /// The query of row `slot` ended; the next publisher to ask, if one waits.
    fn query_ended(&self, slot: usize) -> Option<Ask> {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        let next = state.round.as_mut()?.query_ended(slot, now);
        state.release(now);
        next.and_then(|slot| state.ask_of(slot))
    }

    /// A queryable was declared on the replay key by `zid` under `declaration`; the publisher to
    /// ask, if it is to be asked now.
    fn appeared(&self, zid: &[u8], declaration: u64) -> Option<Ask> {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        let slot = state
            .round
            .as_mut()?
            .appeared(zid, declaration, now)
            .ok()
            .flatten()?;
        state.ask_of(slot)
    }

    /// The queryable `zid` declared under `declaration` was undeclared.
    fn gone(&self, zid: &[u8], declaration: u64) {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        if let Some(round) = state.round.as_mut() {
            round.gone(zid, declaration, now);
            state.release(now);
        }
    }

    /// Look at the deadlines now, and hand on what a round that ended released.
    fn poll(&self) {
        let mut guard = locked(&self.state);
        let state = &mut *guard;
        let now = state.clock.now();
        if let Some(round) = state.round.as_mut() {
            round.poll(now);
            state.release(now);
        }
    }
}

/// Ask the publisher `ask` names, by a get on the replay key; its reply closure tells the
/// subscriber of each reply and of the end. Called with no lock of the subscriber held: a get the
/// session cannot send ends inside this call.
///
/// # Safety
/// `shared.session` is a session the program keeps open while the subscriber lives.
unsafe fn ask(shared: &Arc<Shared>, ask: Ask) {
    let context = Box::into_raw(Box::new(ReplyContext {
        shared: Arc::clone(shared),
        slot: ask.slot,
    }))
    .cast::<c_void>();
    let mut view: z_view_keyexpr_t = core::mem::zeroed();
    let key = &shared.replay_key;
    if z_view_keyexpr_from_substr(&mut view, key.as_ptr().cast::<c_char>(), key.len()) != Z_OK {
        // The key was checked when the subscriber was made; a query that cannot be asked is over.
        on_reply_drop(context);
        return;
    }
    let mut callback = z_moved_closure_reply_t {
        _this: z_owned_closure_reply_t {
            context,
            call: Some(on_reply),
            drop: Some(on_reply_drop),
        },
    };
    let mut options: z_get_options_t = core::mem::zeroed();
    z_get_options_default(&mut options);
    options.target = Z_QUERY_TARGET_ALL;
    options.consolidation.mode = Z_CONSOLIDATION_MODE_NONE;
    options.timeout_ms = shared.get_timeout_ms;
    let targeted = TARGETED_IN_DOMAIN
        && session_handle(&shared.session).is_some_and(|handle| handle.ext.policy.targeted_query());
    // The callback is consumed on every path: a get refused or never sent runs its drop, which
    // ends the query.
    let _ = if targeted {
        let peer = z_id_t { id: ask.zid };
        wz_ext_get_to_peer(
            &shared.session,
            z_view_keyexpr_loan(&view),
            core::ptr::null(),
            &mut callback,
            &mut options,
            &peer,
        )
    } else {
        z_get(
            &shared.session,
            z_view_keyexpr_loan(&view),
            core::ptr::null(),
            &mut callback,
            &mut options,
        )
    };
}

/// A get's reply: a sample of the publisher's ring.
unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    let reply_context = &*context.cast_const().cast::<ReplyContext>();
    let _ = catch(|| {
        if !z_reply_is_ok(reply) {
            return;
        }
        let Some(payload) = bytes_ref(z_sample_payload(z_reply_ok(reply))) else {
            return;
        };
        reply_context
            .shared
            .reply(reply_context.slot, payload.as_slice());
    });
}

/// A get is over: tell the round, and ask the publisher that waited for its room.
unsafe extern "C" fn on_reply_drop(context: *mut c_void) {
    let reply_context = Box::from_raw(context.cast::<ReplyContext>());
    let _ = catch(|| {
        if let Some(next) = reply_context.shared.query_ended(reply_context.slot) {
            ask(&reply_context.shared, next);
        }
    });
}

/// A live sample of the message.
unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    let shared = &*context.cast_const().cast::<Shared>();
    let _ = catch(|| {
        if let Some(payload) = bytes_ref(z_sample_payload(sample)) {
            shared.live(payload.as_slice());
        }
    });
}

/// The subscriber's or the watch's drop: release its share of the state.
unsafe extern "C" fn on_share_drop(context: *mut c_void) {
    drop(Arc::from_raw(context.cast_const().cast::<Shared>()));
}

/// A declaration the watch was told: a replay queryable appearing or leaving.
unsafe extern "C" fn on_declaration(context: *mut c_void, event: *const wz_ext_decl_event_t) {
    // The watch holds the share; this borrows it, to hand a clone to a get.
    let shared = ManuallyDrop::new(Arc::from_raw(context.cast_const().cast::<Shared>()));
    let _ = catch(|| {
        let event = &*event;
        let zid = &event.zid[..usize::from(event.zid_len).min(ZID_MAX)];
        match event.kind {
            WZ_EXT_DECL_DECLARED => {
                if event.keyexpr.is_null() {
                    return;
                }
                let key =
                    core::slice::from_raw_parts(event.keyexpr.cast::<u8>(), event.keyexpr_len);
                if key != shared.replay_key.as_bytes() {
                    return;
                }
                if let Some(next) = shared.appeared(zid, event.id) {
                    ask(&shared, next);
                }
            }
            WZ_EXT_DECL_UNDECLARED => shared.gone(zid, event.id),
            _ => {}
        }
    });
}

/// The C form of a phase.
fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::Idle => WZ_EXT_REPLAY_ROUND_IDLE,
        Phase::Asking => WZ_EXT_REPLAY_ROUND_ASKING,
        Phase::Answering => WZ_EXT_REPLAY_ROUND_ANSWERING,
        Phase::Abandoned => WZ_EXT_REPLAY_ROUND_ABANDONED,
        Phase::Live => WZ_EXT_REPLAY_ROUND_LIVE,
    }
}

/// The code of a refusal to make the round.
fn create_code(refusal: CreateRefused) -> ZResult {
    match refusal {
        CreateRefused::NoSlots
        | CreateRefused::NoQuota
        | CreateRefused::DeadlineOutOfRange
        | CreateRefused::NoHoldStore
        | CreateRefused::HoldCellTooLarge => Z_EINVAL,
    }
}

/// The handle behind a loaned subscriber; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned subscriber of this library.
unsafe fn handle_of<'a>(this_: *const wz_ext_loaned_replay_subscriber_t) -> Option<&'a Handle> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Handle>())
}

/// Take the receiver a moved handle holds, and leave its gravestone.
///
/// # Safety
/// `receiver` is null or a moved receiver of this library.
unsafe fn take_receiver(receiver: *mut wz_ext_moved_e2e_receiver_t) -> Option<Receiver> {
    if receiver.is_null() {
        return None;
    }
    let raw = core::mem::replace(&mut (*receiver)._this.handle, core::ptr::null_mut());
    if raw.is_null() {
        return None;
    }
    let held: Mutex<Receiver> = *Box::from_raw(raw.cast::<Mutex<Receiver>>());
    Some(
        held.into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Fill in the default subscriber options: no storage, a depth of 1, the querier's bound, stream
/// 0, the library's clock, and no deadlines (the program states them).
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_options_default(
    this_: *mut wz_ext_replay_subscriber_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_replay_subscriber_options_t::default();
    }
}

/// A replay subscriber of `keyexpr` on `session`: it subscribes to the key, watches for the
/// publishers' queryables on the key followed by `suffix` (the program's data, NUL-terminated,
/// appended as it is), asks each as it appears, and hands every sample to `deliver` with
/// `context`, judged by `receiver`, which it takes. The session's policies are read once, here.
///
/// The library takes `receiver` and `context` on every path: on a refusal the receiver is dropped
/// and `drop(context)` runs (when `drop` is not null) before this returns, and `this_` holds the
/// gravestone. Returns `Z_ERR_NULL` for a null `this_`, session, keyexpr, suffix, receiver
/// (or its gravestone), options, slot table or `deliver`, or a null store under `hold-back`;
/// `Z_ERR_SESSION_CLOSED` for a closed session; `Z_EINVAL` for a suffix that is not UTF-8, no
/// slot, a deadline of 0 or past 2147483647, a depth of 0, a hold-back store with no room for one
/// cell, or a cell past 2^32 - 1; `Z_ERR_INVALID` for a suffixed key that is not a key expression;
/// `WZ_EXT_ERR_UNSUPPORTED` under `replay-reply-shape = segmented`; otherwise what declaring the
/// subscriber or the watch answers.
///
/// # Safety
/// `this_` is writable; `session` and `keyexpr` are null or loans of this library, the session
/// kept open until the subscriber is dropped; `suffix` is null or a NUL-terminated C string;
/// `receiver` is null or a moved receiver; `options` is null or valid, its storage writable for
/// the lengths it states and left to the subscriber until it is dropped, its clock safe to call
/// with its context from any thread; `deliver` and `drop` are safe to call with `context` as the
/// module doc says.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_replay_subscriber_new(
    this_: *mut wz_ext_owned_replay_subscriber_t,
    session: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    suffix: *const c_char,
    receiver: *mut wz_ext_moved_e2e_receiver_t,
    options: *const wz_ext_replay_subscriber_options_t,
    deliver: Option<wz_ext_replay_deliver_fn>,
    drop: Option<wz_ext_replay_drop_fn>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let receiver = take_receiver(receiver);
        let refuse = |code: ZResult| {
            if let Some(drop) = drop {
                drop(context);
            }
            code
        };
        if this_.is_null() {
            return refuse(Z_ERR_NULL);
        }
        *this_ = wz_ext_owned_replay_subscriber_t::null_value();
        let Some(receiver) = receiver else {
            return refuse(Z_ERR_NULL);
        };
        let Some(deliver) = deliver else {
            return refuse(Z_ERR_NULL);
        };
        if keyexpr.is_null() || suffix.is_null() || options.is_null() {
            return refuse(Z_ERR_NULL);
        }
        let Some(handle) = session_handle(session) else {
            return refuse(Z_ERR_NULL);
        };
        if handle.is_closed() {
            return refuse(Z_ERR_SESSION_CLOSED);
        }
        let policy = &handle.ext.policy;
        if policy.replay_reply_shape() == ReplayReplyShape::Segmented {
            return refuse(WZ_EXT_ERR_UNSUPPORTED);
        }
        let (Some(key), Some(suffix)) = (keyexpr_str(keyexpr), utf8_arg(suffix)) else {
            return refuse(Z_EINVAL);
        };
        let replay_key = format!("{key}{suffix}");
        if wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(&replay_key).is_err() {
            return refuse(Z_ERR_INVALID);
        }
        let options = *options;
        if options.slots.is_null() {
            return refuse(Z_ERR_NULL);
        }
        if options.slot_count == 0 || options.depth == 0 {
            return refuse(Z_EINVAL);
        }
        let live = policy.replay_live_before_answer();
        let held: &'static mut [u8] = match live {
            wz_session_core::policy::ReplayLiveBeforeAnswer::Deliver => &mut [],
            wz_session_core::policy::ReplayLiveBeforeAnswer::HoldBack => {
                if options.held.is_null() {
                    return refuse(Z_ERR_NULL);
                }
                core::slice::from_raw_parts_mut(options.held, options.held_len)
            }
        };
        let quota = match options.max_in_flight {
            0 => wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES,
            asked => asked.min(wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES),
        };
        let clock = Clock {
            read: options.clock,
            context: SendPtr(options.clock_context),
            origin: Instant::now(),
        };
        let rows = options.slots.cast::<PublisherSlot>();
        for row in 0..options.slot_count {
            rows.add(row).write(PublisherSlot::EMPTY);
        }
        let table: &'static mut [PublisherSlot] =
            core::slice::from_raw_parts_mut(rows, options.slot_count);
        let deadlines = Deadlines {
            progress: options.progress_ms,
            round: options.round_ms,
        };
        let round = match ReplaySubscriber::new(
            table,
            held,
            options.held_cell,
            deadlines,
            quota,
            live,
            clock.now(),
        ) {
            Ok(round) => round,
            Err(why) => return refuse(create_code(why)),
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                round: Some(round),
                receiver,
                stream: options.stream,
                depth: options.depth,
                clock,
                deliver,
                context: SendPtr(context),
                released: vec![0u8; options.held_cell],
                dropped: Dropped::default(),
            }),
            session: z_loaned_session_t {
                _val: (*session)._val,
                _cnt: (*session)._cnt,
            },
            replay_key,
            get_timeout_ms: u64::from(options.round_ms),
        });

        let mut view: z_view_keyexpr_t = core::mem::zeroed();
        let made = z_view_keyexpr_from_substr(&mut view, key.as_ptr().cast::<c_char>(), key.len());
        if made != Z_OK {
            return refuse(made);
        }
        let mut sample_closure = z_moved_closure_sample_t {
            _this: z_owned_closure_sample_t {
                context: Arc::into_raw(Arc::clone(&shared))
                    .cast_mut()
                    .cast::<c_void>(),
                call: Some(on_sample),
                drop: Some(on_share_drop),
            },
        };
        let mut subscriber: z_owned_subscriber_t = core::mem::zeroed();
        let declared = z_declare_subscriber(
            &shared.session,
            &mut subscriber,
            z_view_keyexpr_loan(&view),
            &mut sample_closure,
            core::ptr::null(),
        );
        if declared != Z_OK {
            close(&mut locked(&shared.state));
            return refuse(declared);
        }
        let mut watch = wz_ext_owned_decl_watch_t {
            _val: core::ptr::null_mut(),
        };
        let watched = wz_ext_decl_watch_declare(
            &shared.session,
            &mut watch,
            WZ_EXT_DECL_QUERYABLE,
            Some(on_declaration),
            Some(on_share_drop),
            Arc::into_raw(Arc::clone(&shared))
                .cast_mut()
                .cast::<c_void>(),
        );
        if watched != Z_OK {
            close(&mut locked(&shared.state));
            z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
            return refuse(watched);
        }
        let handle = Box::new(Handle {
            shared,
            subscriber,
            watch,
            drop,
            context: SendPtr(context),
        });
        (*this_).handle = Box::into_raw(handle).cast::<c_void>();
        Z_OK
    })
}

/// Let go of the program's storage: the round is gone, and a callback that comes after hands
/// nothing on. Called under the state's lock, so no callback is running.
fn close(state: &mut State) {
    state.round = None;
}

/// Look at the deadlines now: a round whose progress or round deadline passed is abandoned, and
/// held samples it releases are handed on, on this thread, before this returns. `Z_ERR_NULL` for
/// a null subscriber or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_poll(
    this_: *const wz_ext_loaned_replay_subscriber_t,
) -> ZResult {
    guarded(|| {
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        handle.shared.poll();
        Z_OK
    })
}

/// Where the round stands: `WZ_EXT_REPLAY_ROUND_IDLE`, `_ASKING`, `_ANSWERING`, `_ABANDONED` or
/// `_LIVE`, or `WZ_EXT_REPLAY_NO_SUBSCRIBER` for a null subscriber or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_phase(
    this_: *const wz_ext_loaned_replay_subscriber_t,
) -> u8 {
    guard_val(WZ_EXT_REPLAY_NO_SUBSCRIBER, || {
        let Some(handle) = handle_of(this_) else {
            return WZ_EXT_REPLAY_NO_SUBSCRIBER;
        };
        match locked(&handle.shared.state).round.as_ref() {
            Some(round) => phase_code(round.phase()),
            None => WZ_EXT_REPLAY_NO_SUBSCRIBER,
        }
    })
}

/// What the subscriber counted, written to `out`. `Z_ERR_NULL` for a null subscriber, the
/// gravestone or a null `out`.
///
/// # Safety
/// `this_` is null or a loaned subscriber; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_counts(
    this_: *const wz_ext_loaned_replay_subscriber_t,
    out: *mut wz_ext_replay_subscriber_counts_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        let Some(handle) = handle_of(this_) else {
            return Z_ERR_NULL;
        };
        let state = locked(&handle.shared.state);
        let Some(round) = state.round.as_ref() else {
            return Z_ERR_NULL;
        };
        let counts = round.counts();
        *out = wz_ext_replay_subscriber_counts_t {
            late_replies: counts.late_replies,
            unknown_replies: counts.unknown_replies,
            duplicates: state.dropped.duplicates,
            stale: state.dropped.stale,
            held: counts.held,
            table_full: counts.table_full,
            abandoned: counts.abandoned,
        };
        Z_OK
    })
}

/// Borrow a subscriber. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_loan(
    this_: *const wz_ext_owned_replay_subscriber_t,
) -> *const wz_ext_loaned_replay_subscriber_t {
    this_.cast::<wz_ext_loaned_replay_subscriber_t>()
}

/// The moved form of a subscriber, for `wz_ext_replay_subscriber_drop`: a cast, which nulls
/// nothing.
///
/// # Safety
/// `this_` is null or an owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_move(
    this_: *mut wz_ext_owned_replay_subscriber_t,
) -> *mut wz_ext_moved_replay_subscriber_t {
    this_.cast::<wz_ext_moved_replay_subscriber_t>()
}

/// Stop the subscriber and leave the gravestone: nothing is handed on once this returns, the
/// watch and the subscription are undeclared, the program's storage is its own again, and
/// `drop(context)` has run. A get still in flight ends on its own and hands nothing on. A second
/// drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_replay_subscriber_drop(
    this_: *mut wz_ext_moved_replay_subscriber_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let raw = core::mem::replace(&mut (*this_)._this.handle, core::ptr::null_mut());
        if raw.is_null() {
            return Z_OK;
        }
        let mut handle = Box::from_raw(raw.cast::<Handle>());
        close(&mut locked(&handle.shared.state));
        wz_ext_decl_watch_drop(&mut handle.watch);
        z_undeclare_subscriber(z_subscriber_move(&mut handle.subscriber));
        if let Some(drop) = handle.drop {
            drop(handle.context.0);
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_replay_subscriber_null(
    this_: *mut wz_ext_owned_replay_subscriber_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_replay_subscriber_t::null_value();
    }
}

/// Whether the slot holds a subscriber.
///
/// # Safety
/// `this_` is null or an owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_replay_subscriber_check(
    this_: *const wz_ext_owned_replay_subscriber_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_sample_has_the_layout_the_header_declares() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<wz_ext_e2e_verdict_t>(), 80);
        assert_eq!(size_of::<wz_ext_replay_sample_t>(), 120);
        assert_eq!(offset_of!(wz_ext_replay_sample_t, verdict), 16);
        assert_eq!(offset_of!(wz_ext_replay_sample_t, from_replay), 96);
        assert_eq!(offset_of!(wz_ext_replay_sample_t, zid), 100);
        assert_eq!(size_of::<wz_ext_replay_publisher_slot_t>(), 32);
    }

    #[test]
    fn every_phase_has_a_code_of_its_own() {
        let codes = [
            phase_code(Phase::Idle),
            phase_code(Phase::Asking),
            phase_code(Phase::Answering),
            phase_code(Phase::Abandoned),
            phase_code(Phase::Live),
        ];
        assert_eq!(codes, [0, 1, 2, 3, 4]);
        assert!(!codes.contains(&WZ_EXT_REPLAY_NO_SUBSCRIBER));
    }

    /// The doors take the program's context and receiver on every path: each refusal runs its
    /// drop once, before it returns, and leaves the subscriber null.
    #[test]
    fn every_refusal_runs_the_programs_drop_once_and_leaves_the_gravestone() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn on_sample(_: *mut c_void, _: *const wz_ext_replay_sample_t) {}
        unsafe extern "C" fn on_drop(_: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
        let mut stale = 0u8;
        // SAFETY: every pointer is null or a local the call may write; no session is named.
        unsafe {
            let mut this = wz_ext_owned_replay_subscriber_t {
                handle: core::ptr::addr_of_mut!(stale).cast::<c_void>(),
            };
            let options = wz_ext_replay_subscriber_options_t::default();
            assert_eq!(
                wz_ext_replay_subscriber_new(
                    &mut this,
                    core::ptr::null(),
                    core::ptr::null(),
                    c"/@sidecar".as_ptr(),
                    core::ptr::null_mut(),
                    &options,
                    Some(on_sample),
                    Some(on_drop),
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL,
                "no receiver"
            );
            assert!(!wz_ext_internal_replay_subscriber_check(&this));
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);
            assert_eq!(
                wz_ext_replay_subscriber_new(
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                    None,
                    Some(on_drop),
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL,
                "nothing to write"
            );
            assert_eq!(DROPS.load(Ordering::SeqCst), 2);
            assert_eq!(
                wz_ext_replay_subscriber_phase(wz_ext_replay_subscriber_loan(&this)),
                WZ_EXT_REPLAY_NO_SUBSCRIBER
            );
            assert_eq!(
                wz_ext_replay_subscriber_poll(wz_ext_replay_subscriber_loan(&this)),
                Z_ERR_NULL
            );
            wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&mut this));
            wz_ext_replay_subscriber_drop(core::ptr::null_mut());
            assert_eq!(
                DROPS.load(Ordering::SeqCst),
                2,
                "a gravestone drops nothing"
            );
        }
    }
}
