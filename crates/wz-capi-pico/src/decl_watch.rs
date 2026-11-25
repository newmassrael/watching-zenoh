// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_decl_watch_declare` and `wz_ext_decl_watch_drop`: what the peers of a session declare
//! and retract, told to a C program (the declaration watch).
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers). It is in a build with either of the
//! capabilities `remote-declaration-watch` and `declarations-synced-event`, both off by default:
//!
//! * every build with the door tells a watch each subscriber, queryable or liveliness token a
//!   peer declares (`WZ_EXT_DECL_DECLARED`, with the id the peer declared it under and its key
//!   expression) and each one it retracts (`WZ_EXT_DECL_UNDECLARED`, with the id; the wire names
//!   no key);
//! * with `remote-declaration-watch` each event names the peer, as the zenoh id its link's
//!   handshake gave (`zid` and `zid_len`); without it `zid_len` is 0, the peer unknown;
//! * with `declarations-synced-event` a watch is told once per establishment of a link that the
//!   peer has sent everything it held when the link came up (`WZ_EXT_DECL_SYNCED`); without it
//!   that event is never told;
//! * a watch whose events the library had no room to hold is told how many it lost
//!   (`WZ_EXT_DECL_LOST`, the count in `id`) ahead of its next event.
//!
//! What a watch hears, and what it does not, is the port's ([`wz_capi_port::decl_watch`]): of
//! subscribers and queryables, what each peer holds when the watch is declared, told first as
//! declarations, then the peers' declarations from then on, on every link the session holds and
//! every link that comes up later; of tokens, what comes after; and no undeclaration for what a
//! peer held on a link that was lost.
//! Both engines watch: the tokio engine on each of its faces, the cooperative engine from the
//! dispatch of what each link of the session receives.
//!
//! The callback runs where the session hands out its callbacks, the drive of its links, never
//! under a lock of the library, so it may call into the session; the event and the key it points
//! to are valid only for the call. `drop(context)` runs once, after the last call: when the watch
//! is dropped, or when the session is closed if that comes first. A program may free what the
//! callback reads once `wz_ext_decl_watch_drop` returns, as after an undeclare of pico's own
//! entities; dropped from inside the callback, the drop runs when the callback returns.

use core::ffi::{c_char, c_void};

use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchSink};
use wz_session_core::session_zid::ZID_MAX;

use crate::ffi::{catch, guarded, CClosure, InCallback};
use crate::object_slot::{
    closures_of, count_in_entity, kept_at, retire_entity, Answering, Kind, Slot,
};
use crate::refusal::{refusal_code, Door};
use crate::result::{
    ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};
use crate::session::{engine_held, session_handle, z_loaned_session_t, EngineHold};

/// The peer declared an entity.
pub const WZ_EXT_DECL_DECLARED: u8 = 0;
/// The peer retracted an entity it had declared.
pub const WZ_EXT_DECL_UNDECLARED: u8 = 1;
/// The peer has sent every declaration it held when its link came up.
pub const WZ_EXT_DECL_SYNCED: u8 = 2;
/// The library had no room to hold events the watch was owed: `id` counts those lost.
pub const WZ_EXT_DECL_LOST: u8 = 3;

/// A watch of the peers' subscribers.
pub const WZ_EXT_DECL_SUBSCRIBER: u8 = 0;
/// A watch of the peers' queryables.
pub const WZ_EXT_DECL_QUERYABLE: u8 = 1;
/// A watch of the peers' liveliness tokens.
pub const WZ_EXT_DECL_TOKEN: u8 = 2;

/// One event of a declaration watch, as the callback reads it. 48 bytes on a 64-bit target, 40 on
/// a 32-bit one; the reserved bytes are zero.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct wz_ext_decl_event_t {
    /// `WZ_EXT_DECL_DECLARED`, `_UNDECLARED`, `_SYNCED` or `_LOST`.
    pub kind: u8,
    /// The kind of entity the watch was declared for: `WZ_EXT_DECL_SUBSCRIBER`, `_QUERYABLE` or
    /// `_TOKEN`.
    pub entity: u8,
    /// How many bytes of `zid` name the peer; 0 when the peer is not known (a build without
    /// `remote-declaration-watch`, or a link that no longer held its identity).
    pub zid_len: u8,
    /// Zero.
    pub reserved: u8,
    /// Zero.
    pub reserved2: u32,
    /// The id the peer declared the entity under, which its undeclaration names again; 0 for
    /// `WZ_EXT_DECL_SYNCED`; how many events were lost for `WZ_EXT_DECL_LOST`.
    pub id: u64,
    /// The key expression of a `WZ_EXT_DECL_DECLARED`, not NUL-terminated and valid only for the
    /// call; null for the other kinds.
    pub keyexpr: *const c_char,
    /// The length of `keyexpr` in bytes; 0 when it is null.
    pub keyexpr_len: usize,
    /// The peer's zenoh id in the layout of `z_id_t`, zero past `zid_len`.
    pub zid: [u8; ZID_MAX],
}

/// What a watch tells: called with the program's `context` and the event.
pub type wz_ext_decl_watch_fn =
    unsafe extern "C" fn(context: *mut c_void, event: *const wz_ext_decl_event_t);

/// What runs once when a watch lets go of the program's `context`.
pub type wz_ext_decl_watch_drop_fn = unsafe extern "C" fn(context: *mut c_void);

/// An owned declaration watch: `_val` is null when it holds none. Dropping it with
/// `wz_ext_decl_watch_drop` stops the watch. The field is the program's to read, as the header
/// declares it, and the library's alone to write.
#[repr(C)]
pub struct wz_ext_owned_decl_watch_t {
    pub _val: *mut c_void,
}

/// The program's callback, its context and its drop, kept in the watch's place ([`WatchPlace`])
/// and called there by the raw callback the engine holds ([`watch_sink_at`]). The engine calls it
/// where the session dispatches what its links receive, and lets it go after its last call, which
/// runs the program's `drop(context)` once.
type WatchClosure = CClosure<Option<wz_ext_decl_watch_fn>>;

/// Behind a [`wz_ext_owned_decl_watch_t`]: the engine the watch is declared on and its id there,
/// which the watch's drop retracts. It lies in the watch's place, a place of the session's own for
/// the kind (`crate::object_slot::Kind::DeclWatch`).
pub(crate) struct WatchState {
    engine: EngineHold,
    id: DeclWatchId,
}

/// What a watch's place keeps past its handle, for the callback the engine holds: the program's
/// closure, which the engine's release takes out, and the entity code each event is told with.
pub(crate) struct WatchKept {
    closure: WatchClosure,
    entity: u8,
}

/// A declaration watch's place: its handle's state, and what the engine's callback reads past it;
/// the last of the handle and the closure gives the place back (`crate::object_slot::Answering`).
pub(crate) type WatchPlace = Answering<WatchState, WatchKept>;

/// The plane an entity code names, or `None` for a code that is none of the three.
fn plane_of(entity: u8) -> Option<DeclPlane> {
    match entity {
        WZ_EXT_DECL_SUBSCRIBER => Some(DeclPlane::Subscribers),
        WZ_EXT_DECL_QUERYABLE => Some(DeclPlane::Queryables),
        WZ_EXT_DECL_TOKEN => Some(DeclPlane::Tokens),
        _ => None,
    }
}

/// The record the callback is handed for `event`, on a watch of `entity`. Its key points into
/// `event`, so it is valid for as long as the event is borrowed.
fn record_of(entity: u8, event: &DeclWatchEvent<'_>) -> wz_ext_decl_event_t {
    let kind = match event {
        DeclWatchEvent::Declared { .. } => WZ_EXT_DECL_DECLARED,
        DeclWatchEvent::Undeclared { .. } => WZ_EXT_DECL_UNDECLARED,
        DeclWatchEvent::Synced { .. } => WZ_EXT_DECL_SYNCED,
        DeclWatchEvent::Lost { .. } => WZ_EXT_DECL_LOST,
    };
    let (keyexpr, keyexpr_len) = match event.keyexpr() {
        Some(key) => (key.as_ptr().cast::<c_char>(), key.len()),
        None => (core::ptr::null(), 0),
    };
    let (zid, zid_len) = match event.peer_zid() {
        Some(zid) => (zid.to_padded(), zid.as_slice().len() as u8),
        None => ([0u8; ZID_MAX], 0),
    };
    wz_ext_decl_event_t {
        kind,
        entity,
        zid_len,
        reserved: 0,
        reserved2: 0,
        id: event.declaration_id().or(event.lost()).unwrap_or(0),
        keyexpr,
        keyexpr_len,
        zid,
    }
}

/// Hand `event` to the program's callback.
fn tell(closure: &WatchClosure, entity: u8, event: &DeclWatchEvent<'_>) {
    let Some(call) = closure.call else {
        return;
    };
    let record = record_of(entity, event);
    let context = closure.context.0;
    let Some(_in_callback) = InCallback::enter() else {
        return;
    };
    // SAFETY: the program's callback, called as its declaration says, with a record that outlives
    // the call.
    let _ = catch(|| unsafe { call(context, &record) });
}

/// Watch what the peers of `session` declare and retract of the kind `entity` names
/// (`WZ_EXT_DECL_SUBSCRIBER`, `_QUERYABLE` or `_TOKEN`), telling each event to `call` with
/// `context`, and write the watch to `watch`.
///
/// The library takes `context` on every path: on a refusal `drop(context)` runs (when `drop` is
/// not null) before this returns, and `watch` is left null. `Z_ERR_NULL` for a null `watch`,
/// `call` or session; `Z_ERR_INVALID` for an `entity` that is none of the three;
/// `Z_ERR_SESSION_CLOSED` for a closed session; `WZ_EXT_ERR_UNSUPPORTED` when the session's engine
/// does not watch, or this build hears no declaration of that kind; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
/// when the session holds as many watches as its `MAX_DECL_WATCHES` admits, or as many observers
/// of what a peer declares as its bound allows.
///
/// # Safety
/// `session` is a loaned session of this library or null; `watch` is writable or null; `call` and
/// `drop` are safe to call as the module doc says, with `context`, for as long as the watch holds
/// it.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_decl_watch_declare(
    session: *const z_loaned_session_t,
    watch: *mut wz_ext_owned_decl_watch_t,
    entity: u8,
    call: Option<wz_ext_decl_watch_fn>,
    drop: Option<wz_ext_decl_watch_drop_fn>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        // From here the closure owns `drop(context)`: every return below that does not hand it to
        // the engine releases it, which runs the program's drop.
        let closure = WatchClosure::uncounted(context, call, drop);
        if watch.is_null() {
            return Z_ERR_NULL;
        }
        (*watch)._val = core::ptr::null_mut();
        if call.is_none() {
            return Z_ERR_NULL;
        }
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        let Some(plane) = plane_of(entity) else {
            return Z_ERR_INVALID;
        };
        if handle.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let engine = engine_held(handle);
        let Some(place) = Slot::<WatchPlace>::take_entity(engine, Kind::DeclWatch) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        let object = place
            .fill(Answering::keeping(
                WatchState {
                    engine: crate::session::EngineHold::clone(engine),
                    id: 0,
                },
                WatchKept { closure, entity },
            ))
            .cast::<WatchState>();
        // The closure lies in the place now, counted there before the engine can call it or let
        // it go.
        let kept = kept_at::<WatchState, WatchKept>(object);
        count_in_entity::<WatchState, WatchKept, _>(object, &mut (*kept).closure);
        match wz_capi_port::SessionEngine::declare_decl_watch(
            crate::session::EngineHold::as_ref(engine),
            plane,
            watch_sink_at(object),
        ) {
            Ok(id) => {
                (*object).id = id;
                (*watch)._val = object.cast::<c_void>();
                Z_OK
            }
            Err(refusal) => {
                // The refusal let go of the callback, and so of the closure; the place goes back
                // with the state.
                retire_entity::<WatchState, WatchKept>(object);
                refusal_code(refusal, Door::DeclWatch)
            }
        }
    })
}

/// Stop the watch `watch` holds and leave it null: no event is told after this returns, and the
/// program's `drop(context)` has run by then, unless this is called from inside the watch's own
/// callback, when it runs as the callback returns. A null `watch`, or one that holds none, is left
/// as it is; a watch whose session was closed has been released by the close already.
///
/// # Safety
/// `watch` is null or a watch this library wrote.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_decl_watch_drop(watch: *mut wz_ext_owned_decl_watch_t) {
    let _ = guarded(|| {
        if watch.is_null() {
            return Z_OK;
        }
        let val = core::mem::replace(&mut (*watch)._val, core::ptr::null_mut());
        if val.is_null() {
            return Z_OK;
        }
        // A non-null `_val` is the object `wz_ext_decl_watch_declare` placed, let go of once: the
        // slot is null from the line above.
        let object = val.cast::<WatchState>();
        wz_capi_port::SessionEngine::undeclare_decl_watch(
            crate::session::EngineHold::as_ref(&(*object).engine),
            (*object).id,
        );
        closures_of::<WatchState, WatchKept>(object).wait_none();
        retire_entity::<WatchState, WatchKept>(object);
        Z_OK
    });
}

/// The callback the engine holds for the watch whose state is at `object`: a raw one whose
/// context is the place, telling each event to the closure kept there through a shared borrow, and
/// whose release takes the closure out and drops it once, after the last call: its C
/// `drop(context)` runs, and the place goes back if the handle let go of it first. Nothing is
/// allocated.
///
/// # Safety
/// `object` is the object of a live place filled for an `Answering<T, WatchKept>` whose closure
/// is counted in it and taken out by nothing but the callback made here.
unsafe fn watch_sink_at<T>(object: *mut T) -> DeclWatchSink {
    /// # Safety
    /// `context` is the object of a place whose closure the release has not taken out.
    unsafe fn call<T>(context: *mut c_void, event: &DeclWatchEvent<'_>) {
        // SAFETY: the caller's: what is kept stands in the place and is only read here.
        let kept = unsafe { &*kept_at::<T, WatchKept>(context.cast::<T>()) };
        tell(&kept.closure, kept.entity, event);
    }
    /// # Safety
    /// As `call`'s, and nothing calls either again.
    unsafe fn release<T>(context: *mut c_void) {
        // SAFETY: the caller's: the closure is taken out once, here, and dropped out of the place,
        // as its drop may give the place back.
        let closure = unsafe {
            core::ptr::read(core::ptr::addr_of!(
                (*kept_at::<T, WatchKept>(context.cast::<T>())).closure
            ))
        };
        drop(closure);
    }
    // SAFETY: `call` borrows what the place keeps, which stands until `release` takes the closure
    // out once, after the last call, as the closure is counted in the place.
    unsafe { DeclWatchSink::raw(call::<T>, object.cast::<c_void>(), Some(release::<T>)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 5] = [0x10, 0x20, 0x00, 0x30, 0x40];

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_event_has_the_layout_the_header_declares() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<wz_ext_decl_event_t>(), 48);
        assert_eq!(offset_of!(wz_ext_decl_event_t, kind), 0);
        assert_eq!(offset_of!(wz_ext_decl_event_t, entity), 1);
        assert_eq!(offset_of!(wz_ext_decl_event_t, zid_len), 2);
        assert_eq!(offset_of!(wz_ext_decl_event_t, reserved2), 4);
        assert_eq!(offset_of!(wz_ext_decl_event_t, id), 8);
        assert_eq!(offset_of!(wz_ext_decl_event_t, keyexpr), 16);
        assert_eq!(offset_of!(wz_ext_decl_event_t, keyexpr_len), 24);
        assert_eq!(offset_of!(wz_ext_decl_event_t, zid), 32);
        assert_eq!(size_of::<wz_ext_owned_decl_watch_t>(), 8);
    }

    #[test]
    fn each_entity_code_names_its_plane_and_no_other_code_names_one() {
        assert_eq!(
            plane_of(WZ_EXT_DECL_SUBSCRIBER),
            Some(DeclPlane::Subscribers)
        );
        assert_eq!(plane_of(WZ_EXT_DECL_QUERYABLE), Some(DeclPlane::Queryables));
        assert_eq!(plane_of(WZ_EXT_DECL_TOKEN), Some(DeclPlane::Tokens));
        assert_eq!(plane_of(3), None);
        assert_eq!(plane_of(u8::MAX), None);
    }

    #[test]
    fn a_declaration_is_told_with_its_key_and_its_peer() {
        let key = "demo/watch/sub";
        let record = record_of(
            WZ_EXT_DECL_QUERYABLE,
            &DeclWatchEvent::Declared {
                id: 41,
                keyexpr: key,
                peer: Some(&PEER),
            },
        );
        assert_eq!(record.kind, WZ_EXT_DECL_DECLARED);
        assert_eq!(record.entity, WZ_EXT_DECL_QUERYABLE);
        assert_eq!(record.id, 41);
        assert_eq!(record.keyexpr, key.as_ptr().cast::<c_char>());
        assert_eq!(record.keyexpr_len, key.len());
        assert_eq!(usize::from(record.zid_len), PEER.len());
        assert_eq!(&record.zid[..PEER.len()], &PEER[..]);
        assert!(record.zid[PEER.len()..].iter().all(|b| *b == 0));
        assert_eq!((record.reserved, record.reserved2), (0, 0));
    }

    #[test]
    fn an_undeclaration_and_a_sync_name_no_key_and_an_unknown_peer_has_no_bytes() {
        let undeclared = record_of(
            WZ_EXT_DECL_SUBSCRIBER,
            &DeclWatchEvent::Undeclared { id: 7, peer: None },
        );
        assert_eq!(undeclared.kind, WZ_EXT_DECL_UNDECLARED);
        assert_eq!(undeclared.id, 7);
        assert!(undeclared.keyexpr.is_null());
        assert_eq!(undeclared.keyexpr_len, 0);
        assert_eq!(undeclared.zid_len, 0, "no peer is named");
        assert_eq!(undeclared.zid, [0u8; ZID_MAX]);

        let synced = record_of(
            WZ_EXT_DECL_TOKEN,
            &DeclWatchEvent::Synced { peer: Some(&PEER) },
        );
        assert_eq!(synced.kind, WZ_EXT_DECL_SYNCED);
        assert_eq!(synced.entity, WZ_EXT_DECL_TOKEN);
        assert_eq!(synced.id, 0, "a sync is about no one declaration");
        assert!(synced.keyexpr.is_null());
        assert_eq!(usize::from(synced.zid_len), PEER.len());

        let not_a_zid = record_of(
            WZ_EXT_DECL_TOKEN,
            &DeclWatchEvent::Synced {
                peer: Some(&[0, 0, 0]),
            },
        );
        assert_eq!(
            not_a_zid.zid_len, 0,
            "bytes that are no zenoh id name no peer"
        );
    }

    #[test]
    fn a_loss_is_told_with_its_count_and_no_key_or_peer() {
        let lost = record_of(WZ_EXT_DECL_QUERYABLE, &DeclWatchEvent::Lost { count: 5 });
        assert_eq!(lost.kind, WZ_EXT_DECL_LOST);
        assert_eq!(lost.entity, WZ_EXT_DECL_QUERYABLE);
        assert_eq!(lost.id, 5, "the count of events lost");
        assert!(lost.keyexpr.is_null());
        assert_eq!(lost.keyexpr_len, 0);
        assert_eq!(lost.zid_len, 0, "a loss names no peer");
        assert_eq!(lost.zid, [0u8; ZID_MAX]);
    }

    /// The engine's callback tells each event to the C closure kept in the watch's place, with the
    /// program's context and the watch's entity code, and letting it go takes the closure out and
    /// runs the C drop once. Turned red by a callback that tells nothing, one that tells the wrong
    /// entity, or one whose release is not the closure's drop.
    #[test]
    fn a_watchs_callback_tells_the_c_closure_and_drops_it_once() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn on_event(ctx: *mut c_void, event: *const wz_ext_decl_event_t) {
            if ctx as usize == 0x5a
                && (*event).entity == WZ_EXT_DECL_QUERYABLE
                && (*event).kind == WZ_EXT_DECL_UNDECLARED
                && (*event).id == 3
            {
                SEEN.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe extern "C" fn on_drop(ctx: *mut c_void) {
            if ctx as usize == 0x5a {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut place = Answering::keeping(
            0_u8,
            WatchKept {
                closure: WatchClosure::uncounted(
                    0x5a as *mut c_void,
                    Some(on_event),
                    Some(on_drop),
                ),
                entity: WZ_EXT_DECL_QUERYABLE,
            },
        );
        // SAFETY: `place` holds an `Answering<u8, WatchKept>` that outlives the callback, whose
        // closure only the callback takes out.
        let sink = unsafe { watch_sink_at(core::ptr::from_mut(&mut place).cast::<u8>()) };
        sink.call(DeclWatchEvent::Undeclared { id: 3, peer: None });
        sink.call(DeclWatchEvent::Undeclared { id: 3, peer: None });
        assert_eq!(SEEN.load(Ordering::SeqCst), 2);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
        drop(sink);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1, "the C drop ran once");
    }

    /// A watch holds a place of its session's for the kind from its declare to its drop, and a
    /// declare that finds every place held is refused with nothing declared and the program's
    /// drop run once. Turned red by a watch that takes no place (one past the session's limit
    /// admitted), or one whose drop does not give it back.
    #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
    #[test]
    fn a_watch_holds_a_place_of_its_session_until_it_is_dropped() {
        use crate::session::{
            engine_held, listening_on_loopback, z_session_drop, z_session_loan, z_session_move,
        };
        use core::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn on_event(_: *mut c_void, _: *const wz_ext_decl_event_t) {}
        unsafe extern "C" fn on_drop(_: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }

        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let loaned = unsafe { z_session_loan(&session) };
        // SAFETY: as above.
        let handle = unsafe { session_handle(loaned) }.expect("an open session has its handle");
        let engine = engine_held(handle).clone();
        // How many watch places `engine` has free: each claimed, then all given back.
        let free = |engine: &EngineHold| {
            let claimed: alloc::vec::Vec<Slot<u64>> =
                core::iter::from_fn(|| Slot::<u64>::take_entity(engine, Kind::DeclWatch)).collect();
            claimed.len()
        };
        let places = free(&engine);
        assert!(places >= 1, "the session's limit admits a watch");
        let declare = |watch: &mut wz_ext_owned_decl_watch_t| {
            // SAFETY: a live session, a local watch and functions that touch no context.
            unsafe {
                wz_ext_decl_watch_declare(
                    loaned,
                    watch,
                    WZ_EXT_DECL_SUBSCRIBER,
                    Some(on_event),
                    Some(on_drop),
                    core::ptr::null_mut(),
                )
            }
        };

        let mut watch = wz_ext_owned_decl_watch_t {
            _val: core::ptr::null_mut(),
        };
        assert_eq!(declare(&mut watch), Z_OK);
        assert_eq!(free(&engine), places - 1, "the watch holds one place");

        // Every place held, the next declare is refused and lets go of the program's context.
        let held: alloc::vec::Vec<Slot<u64>> =
            core::iter::from_fn(|| Slot::<u64>::take_entity(&engine, Kind::DeclWatch)).collect();
        let mut refused = wz_ext_owned_decl_watch_t {
            _val: core::ptr::null_mut(),
        };
        assert_eq!(declare(&mut refused), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(refused._val.is_null());
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the refused watch's drop ran"
        );
        drop(held);

        // SAFETY: `watch` holds the watch declared above.
        unsafe { wz_ext_decl_watch_drop(&mut watch) };
        assert!(watch._val.is_null());
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "the dropped watch's drop ran"
        );
        assert_eq!(free(&engine), places, "its place went back");

        drop(engine);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// The doors take the program's context on every path: each refusal runs its drop once,
    /// before it returns, and leaves the watch null.
    #[test]
    fn every_refusal_runs_the_programs_drop_once_and_leaves_the_watch_null() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn on_event(_: *mut c_void, _: *const wz_ext_decl_event_t) {}
        unsafe extern "C" fn on_drop(_: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }

        // A watch that holds something stale, which a refusal must not leave behind.
        let mut stale = 0u8;
        // SAFETY: every pointer is null or a local the call may write; no session is named.
        unsafe {
            let mut watch = wz_ext_owned_decl_watch_t {
                _val: core::ptr::addr_of_mut!(stale).cast::<c_void>(),
            };
            assert_eq!(
                wz_ext_decl_watch_declare(
                    core::ptr::null(),
                    &mut watch,
                    WZ_EXT_DECL_SUBSCRIBER,
                    Some(on_event),
                    Some(on_drop),
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL,
                "no session"
            );
            assert!(watch._val.is_null(), "a refused watch is null");
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);

            assert_eq!(
                wz_ext_decl_watch_declare(
                    core::ptr::null(),
                    &mut watch,
                    WZ_EXT_DECL_SUBSCRIBER,
                    None,
                    Some(on_drop),
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL,
                "no callback"
            );
            assert_eq!(DROPS.load(Ordering::SeqCst), 2);

            assert_eq!(
                wz_ext_decl_watch_declare(
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    WZ_EXT_DECL_SUBSCRIBER,
                    Some(on_event),
                    Some(on_drop),
                    core::ptr::null_mut(),
                ),
                Z_ERR_NULL,
                "no watch to write"
            );
            assert_eq!(DROPS.load(Ordering::SeqCst), 3);

            // A null watch and an empty one are left as they are.
            wz_ext_decl_watch_drop(core::ptr::null_mut());
            wz_ext_decl_watch_drop(&mut watch);
            assert!(watch._val.is_null());
            assert_eq!(DROPS.load(Ordering::SeqCst), 3);
        }
    }
}
