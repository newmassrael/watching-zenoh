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
//!   that event is never told.
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

use std::ffi::{c_char, c_void};
use std::sync::Arc;

use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchRefused, DeclWatchSink};
use wz_session_core::session_zid::ZID_MAX;

use crate::ffi::{catch, guarded, CClosure, InCallback, ReleaseLatch};
use crate::result::{
    ZResult, WZ_EXT_ERR_UNSUPPORTED, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_SESSION_CLOSED,
    Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};
use crate::session::{engine_of, session_handle, z_loaned_session_t, Engine};

/// The peer declared an entity.
pub const WZ_EXT_DECL_DECLARED: u8 = 0;
/// The peer retracted an entity it had declared.
pub const WZ_EXT_DECL_UNDECLARED: u8 = 1;
/// The peer has sent every declaration it held when its link came up.
pub const WZ_EXT_DECL_SYNCED: u8 = 2;

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
    /// `WZ_EXT_DECL_DECLARED`, `_UNDECLARED` or `_SYNCED`.
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
    /// `WZ_EXT_DECL_SYNCED`.
    pub id: u64,
    /// The key expression of a `WZ_EXT_DECL_DECLARED`, not NUL-terminated and valid only for the
    /// call; null for the other two kinds.
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

/// The program's callback, its context and its drop, shared by every link's listener of one watch.
type WatchClosure = CClosure<Option<wz_ext_decl_watch_fn>>;

// SAFETY: the callback is reached only through the watch's sink, which the engine calls from where
// the session dispatches what its links receive, the same place a subscriber's samples are handed
// over (`crate::pubsub`'s `CClosure` states it), and `drop` runs only when the last reference goes,
// which a running call holds. The context is the program's, which it hands over for exactly that.
unsafe impl Sync for WatchClosure {}

/// Behind a [`wz_ext_owned_decl_watch_t`]: the engine the watch is declared on, its id there, and
/// the latch that opens once the program's `drop(context)` has run.
struct WatchState {
    engine: Arc<Engine>,
    id: DeclWatchId,
    released: Arc<ReleaseLatch>,
}

/// The plane an entity code names, or `None` for a code that is none of the three.
fn plane_of(entity: u8) -> Option<DeclPlane> {
    match entity {
        WZ_EXT_DECL_SUBSCRIBER => Some(DeclPlane::Subscribers),
        WZ_EXT_DECL_QUERYABLE => Some(DeclPlane::Queryables),
        WZ_EXT_DECL_TOKEN => Some(DeclPlane::Tokens),
        _ => None,
    }
}

/// The pico code of a refused watch.
fn code(refusal: DeclWatchRefused) -> ZResult {
    match refusal {
        DeclWatchRefused::NotProvided | DeclWatchRefused::PlaneNotBuilt => WZ_EXT_ERR_UNSUPPORTED,
        DeclWatchRefused::SessionClosed => Z_ERR_SESSION_CLOSED,
        DeclWatchRefused::Full => Z_ERR_SYSTEM_OUT_OF_MEMORY,
    }
}

/// The record the callback is handed for `event`, on a watch of `entity`. Its key points into
/// `event`, so it is valid for as long as the event is borrowed.
fn record_of(entity: u8, event: &DeclWatchEvent<'_>) -> wz_ext_decl_event_t {
    let kind = match event {
        DeclWatchEvent::Declared { .. } => WZ_EXT_DECL_DECLARED,
        DeclWatchEvent::Undeclared { .. } => WZ_EXT_DECL_UNDECLARED,
        DeclWatchEvent::Synced { .. } => WZ_EXT_DECL_SYNCED,
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
        id: event.declaration_id().unwrap_or(0),
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
    let _in_callback = InCallback::enter();
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
/// when the session holds as many observers of what a peer declares as its bound allows.
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
        let closure = Arc::new(WatchClosure::new(context, call, drop));
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
        let engine = engine_of(handle);
        let released = closure.release_latch();
        let sink: DeclWatchSink =
            Arc::new(move |event: DeclWatchEvent<'_>| tell(&closure, entity, &event));
        match engine.declare_decl_watch(plane, sink) {
            Ok(id) => {
                let state = Box::new(WatchState {
                    engine,
                    id,
                    released,
                });
                (*watch)._val = Box::into_raw(state).cast::<c_void>();
                Z_OK
            }
            Err(refusal) => code(refusal),
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
        // SAFETY: a non-null `_val` is the box `wz_ext_decl_watch_declare` wrote, taken once: the
        // slot is null from the line above.
        let state = Box::from_raw(val.cast::<WatchState>());
        state.engine.undeclare_decl_watch(state.id);
        let released = Arc::clone(&state.released);
        core::mem::drop(state);
        released.wait();
        Z_OK
    });
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
    fn a_refusal_of_the_engine_and_of_the_build_is_unsupported_and_a_closed_session_is_closed() {
        assert_eq!(code(DeclWatchRefused::NotProvided), WZ_EXT_ERR_UNSUPPORTED);
        assert_eq!(
            code(DeclWatchRefused::PlaneNotBuilt),
            WZ_EXT_ERR_UNSUPPORTED
        );
        assert_eq!(code(DeclWatchRefused::SessionClosed), Z_ERR_SESSION_CLOSED);
        assert_eq!(code(DeclWatchRefused::Full), Z_ERR_SYSTEM_OUT_OF_MEMORY);
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
