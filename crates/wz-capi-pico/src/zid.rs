// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The IDENTITY plane — `z_id_t`, the zid closure family, and the three
//! `z_info_*` exports upstream's `z_info.c` is built on.
//!
//! ## Why this closes a program rather than a symbol
//!
//! Measured against wz's cdylib, `z_info.c` was missing exactly five exports:
//! `z_info_zid`, `z_info_routers_zid`, `z_info_peers_zid`, `z_id_to_string` and
//! `z_closure_zid_move`. Everything else it calls already linked. Note what is
//! NOT in that list: `z_closure_zid` itself, because pico's `z_closure(...)` is a
//! pure preprocessor macro that assigns straight into `(closure)->_val`
//! (`api/macros.h:602-620`) — so the STRUCT LAYOUT is the ABI here, and a
//! field-order slip would be a silent memory corruption rather than a link
//! error. `closure_zid_abi_matches_pico` pins it.
//!
//! `Z_FEATURE_CONNECTIVITY` is 0 in the CMake-generated config these programs
//! compile against, so `z_info.c`'s whole transport/link-introspection half is
//! preprocessed out. That is why the program costs five symbols and not thirty,
//! and it is read off the GENERATED header rather than off a cmake flag — the
//! R311y466 trap.
//!
//! ## The peers / routers split is made HERE, at the ABI boundary
//!
//! `SharedSession::peer_identities` reports every established face's
//! `(zid, whatami)` with `whatami` in its raw 2-bit INIT wire form, and this
//! module splits it: role 0 is a Router, roles 1 and 2 (Peer, Client) are
//! reported by `z_info_peers_zid`. That is where pico makes the same split —
//! it walks its transport's peer list and tests the stored whatami — and
//! keeping it here leaves `wz-capi-core` free of pico's role encoding.
//!
//! ## Rendering: LITTLE-ENDIAN hex, which is not the obvious choice
//!
//! `z_id_to_string` emits 32 lowercase hex characters with the BYTE ORDER
//! REVERSED: `_z_string_convert_bytes_le` fills the output back-to-front
//! (`src/collections/string.c:103-119`). A big-endian rendering would look
//! entirely plausible and would disagree with every id a pico program prints, so
//! this is pinned against the real `libzenohpico.so` rather than against a
//! table this crate wrote for itself — see `tests/zid_against_pico_oracle.rs`.

use std::ffi::c_void;

use wz_capi_core::faces::SharedSession;

use crate::abi::z_owned_string_t;
use crate::bytes::store_owned_string;
use crate::pubsub::z_closure_drop_callback_t;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};

/// pico's `ZENOH_ID_SIZE` (`protocol/core.h:59-62`).
pub const Z_ID_SIZE: usize = 16;

/// pico `z_id_t` = `_z_id_t` = `{ uint8_t id[16] }`, 16 B measured.
///
/// Crosses the boundary BY VALUE (`z_info_zid` returns one, `_z_id_len` takes
/// one), so its size and its lack of padding are both load-bearing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_id_t {
    pub id: [u8; Z_ID_SIZE],
}

impl z_id_t {
    /// The all-zero id pico treats as "unset" (`_z_id_check` compares against
    /// `empty_id`).
    pub(crate) fn empty() -> Self {
        Self {
            id: [0u8; Z_ID_SIZE],
        }
    }

    /// Build from a wire zid, which may be SHORTER than 16 bytes: zenoh
    /// transmits a zid with its trailing zeros stripped, so a peer's recorded id
    /// is left-aligned and zero-padded back out here. Longer input is truncated
    /// rather than rejected — a 17-byte zid cannot reach a `z_id_t` at all, and
    /// dropping the peer from the enumeration would hide a real face.
    pub(crate) fn from_wire(bytes: &[u8]) -> Self {
        let mut id = [0u8; Z_ID_SIZE];
        let n = bytes.len().min(Z_ID_SIZE);
        id[..n].copy_from_slice(&bytes[..n]);
        Self { id }
    }
}

/// pico `z_closure_zid_callback_t`: `void call(const z_id_t*, void*)`.
pub type z_closure_zid_callback_t = Option<unsafe extern "C" fn(*const z_id_t, *mut c_void)>;

/// Owned zid closure (pico `z_owned_closure_zid_t`, 24 B measured).
///
/// The field ORDER is `{ context, call, drop }`
/// (`api/types.h:771-775`) and is written DIRECTLY by pico's `z_closure` macro,
/// which never calls into this library. So unlike every other closure here, a
/// wrong order is not caught by a signature mismatch — only by the size/offset
/// pin in this module's tests.
#[repr(C)]
pub struct z_owned_closure_zid_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_zid_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned zid closure, same layout.
#[repr(C)]
pub struct z_loaned_closure_zid_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_zid_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved zid closure (pico `z_moved_closure_zid_t`).
#[repr(C)]
pub struct z_moved_closure_zid_t {
    pub(crate) _this: z_owned_closure_zid_t,
}

impl z_owned_closure_zid_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

// --- closure ownership family ----------------------------------------------

/// Null an owned zid closure (pico `z_internal_closure_zid_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_zid_null(closure: *mut z_owned_closure_zid_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_zid_t::null_value();
    }
}

/// Whether an owned zid closure carries a callback (pico
/// `z_internal_closure_zid_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_zid_check(
    closure: *const z_owned_closure_zid_t,
) -> bool {
    !closure.is_null() && (*closure).call.is_some()
}

/// Borrow an owned zid closure (pico `z_closure_zid_loan`) — offset-0 identity.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_loan(
    closure: *const z_owned_closure_zid_t,
) -> *const z_loaned_closure_zid_t {
    closure as *const z_loaned_closure_zid_t
}

/// Move an owned zid closure (pico `z_closure_zid_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_move(
    closure: *mut z_owned_closure_zid_t,
) -> *mut z_moved_closure_zid_t {
    closure as *mut z_moved_closure_zid_t
}

/// Take a moved zid closure (pico `z_closure_zid_take`), nulling the source so
/// its `drop` runs exactly once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_take(
    closure: *mut z_owned_closure_zid_t,
    src: *mut z_moved_closure_zid_t,
) -> ZResult {
    guarded_null2(closure, src, || {
        *closure = std::mem::replace(&mut (*src)._this, z_owned_closure_zid_t::null_value());
        Z_OK
    })
}

/// Release a zid closure (pico `z_closure_zid_drop`), running its
/// `drop(context)` once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_drop(closure: *mut z_moved_closure_zid_t) -> ZResult {
    crate::ffi::guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let taken = std::mem::replace(&mut (*closure)._this, z_owned_closure_zid_t::null_value());
        if let Some(dropfn) = taken.drop {
            dropfn(taken.context);
        }
        Z_OK
    })
}

/// Invoke a zid closure (pico `z_closure_zid_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_call(
    closure: *const z_loaned_closure_zid_t,
    id: *const z_id_t,
) {
    if closure.is_null() {
        return;
    }
    if let Some(call) = (*closure).call {
        call(id, (*closure).context);
    }
}

/// Shared shape for the two-pointer null guard, so the take exports read the
/// same way across this crate.
#[inline]
unsafe fn guarded_null2<A, B>(a: *mut A, b: *mut B, body: impl FnOnce() -> ZResult) -> ZResult {
    crate::ffi::guarded(|| {
        if a.is_null() || b.is_null() {
            return Z_ERR_NULL;
        }
        body()
    })
}

// --- z_info_* --------------------------------------------------------------

/// This session's own zid (pico `z_info_zid`).
///
/// Returns the 16 bytes the session put on the wire in its INIT — the same id a
/// peer records for it, by construction: `SessionState` holds the single
/// `fresh_zid()` the open minted, and the INIT was built from it.
///
/// pico returns an id BY VALUE and has no error channel here, so an invalid
/// handle yields the empty id (which is exactly what `_z_id_check` reports as
/// unset) rather than a crash.
#[no_mangle]
pub unsafe extern "C" fn z_info_zid(zs: *const z_loaned_session_t) -> z_id_t {
    match session_state(zs) {
        Some(state) => z_id_t { id: state.zid() },
        None => z_id_t::empty(),
    }
}

/// Invoke `callback` once per connected ROUTER (pico `z_info_routers_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_info_routers_zid(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
) -> ZResult {
    enumerate_peers(zs, callback, WHATAMI_ROUTER_ONLY)
}

/// Invoke `callback` once per connected PEER or CLIENT (pico
/// `z_info_peers_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_info_peers_zid(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
) -> ZResult {
    enumerate_peers(zs, callback, WHATAMI_NON_ROUTER)
}

/// The 2-bit INIT `whatami` wire encoding: 0 Router, 1 Peer, 2 Client.
const WHATAMI_WIRE_ROUTER: u8 = 0;
/// Select routers only — `z_info_routers_zid`.
const WHATAMI_ROUTER_ONLY: bool = true;
/// Select everything that is not a router — `z_info_peers_zid`.
const WHATAMI_NON_ROUTER: bool = false;

/// The shared body of the two enumerations, so the closure-consumption contract
/// cannot drift between them.
///
/// The moved closure is consumed on EVERY path including the failure ones —
/// pico's ownership transfer is unconditional once the call is made, so an early
/// return that skipped the release would leak the caller's context. `z_info.c`
/// depends on exactly this: it builds a closure, moves it into
/// `z_info_routers_zid`, and then reuses the variable.
unsafe fn enumerate_peers(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
    routers: bool,
) -> ZResult {
    crate::ffi::guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let taken = std::mem::replace(&mut (*callback)._this, z_owned_closure_zid_t::null_value());
        // From here every return path must release `taken`, so the body runs
        // inside a closure and the release is unconditional below.
        let rc = (|| {
            let state = match session_state(zs) {
                Some(s) => s,
                None => return Z_ERR_NULL,
            };
            let call = match taken.call {
                Some(call) => call,
                // A closure with no callback is not an error in pico; there is
                // simply nothing to invoke.
                None => return Z_OK,
            };
            for (zid, whatami) in shared_of(state).peer_identities() {
                if (whatami == WHATAMI_WIRE_ROUTER) != routers {
                    continue;
                }
                let id = z_id_t::from_wire(&zid);
                call(&id, taken.context);
            }
            Z_OK
        })();
        if let Some(dropfn) = taken.drop {
            dropfn(taken.context);
        }
        rc
    })
}

/// The registry behind a C session handle.
fn shared_of(state: &wz_capi_core::drive::SessionState) -> &SharedSession {
    &state.shared
}

// --- z_id_to_string --------------------------------------------------------

/// Render a zid as pico does (pico `z_id_to_string`): 32 lowercase hex
/// characters, BYTE ORDER REVERSED.
///
/// The reversal is `_z_string_convert_bytes_le` filling its buffer back-to-front
/// (`src/collections/string.c:103-119`), and it is the whole reason this has a
/// foreign-oracle test: a big-endian rendering is equally plausible to read and
/// would disagree with every id a pico program prints.
#[no_mangle]
pub unsafe extern "C" fn z_id_to_string(id: *const z_id_t, out: *mut z_owned_string_t) -> ZResult {
    crate::ffi::guarded(|| {
        if id.is_null() || out.is_null() {
            return Z_ERR_NULL;
        }
        let mut buf = [0u8; Z_ID_SIZE * 2];
        let bytes = &(*id).id;
        let mut pos = buf.len();
        for byte in bytes.iter() {
            pos -= 1;
            buf[pos] = HEX[(byte & 0x0F) as usize];
            pos -= 1;
            buf[pos] = HEX[((byte & 0xF0) >> 4) as usize];
        }
        store_owned_string(out, &buf);
        Z_OK
    })
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// pico's internal `_z_id_len`: the id's length with trailing zero bytes
/// stripped (`src/protocol/core.c:35-45`). Taken BY VALUE, as pico declares it.
///
/// Exported because `z_scout.c` links it directly — an internal symbol that a
/// public example depends on, which is exactly the class of thing a
/// "public API only" export policy would miss.
#[no_mangle]
pub unsafe extern "C" fn _z_id_len(id: z_id_t) -> u8 {
    let mut len = Z_ID_SIZE as u8;
    while len > 0 {
        len -= 1;
        if id.id[len as usize] != 0 {
            len += 1;
            break;
        }
    }
    len
}

/// Build an owned zid closure from a callback + drop + context (pico
/// `z_closure_zid`).
///
/// R311y559 — the constructor of a family whose `_call` half already existed,
/// exactly as [`crate::scout::z_closure_hello`] was.
///
/// # Safety
/// `closure` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid(
    closure: *mut z_owned_closure_zid_t,
    call: z_closure_zid_callback_t,
    drop: crate::pubsub::z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    crate::ffi::guarded(|| {
        if closure.is_null() {
            return crate::result::Z_ERR_NULL;
        }
        *closure = z_owned_closure_zid_t {
            context,
            call,
            drop,
        };
        crate::result::Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI a C program stack-allocates through pico's own header. The
    /// closure OFFSETS matter more here than anywhere else in this crate: pico's
    /// `z_closure` is a macro that writes the fields directly, so a wrong order
    /// corrupts memory instead of failing to link.
    #[test]
    fn closure_zid_abi_matches_pico() {
        assert_eq!(std::mem::size_of::<z_id_t>(), 16);
        assert_eq!(std::mem::size_of::<z_owned_closure_zid_t>(), 24);
        assert_eq!(std::mem::size_of::<z_moved_closure_zid_t>(), 24);
        let closure = z_owned_closure_zid_t::null_value();
        let base = &closure as *const _ as usize;
        assert_eq!(&closure.context as *const _ as usize - base, 0);
        assert_eq!(&closure.call as *const _ as usize - base, 8);
        assert_eq!(&closure.drop as *const _ as usize - base, 16);
    }

    /// `_z_id_len` strips TRAILING zeros only, and reports 0 for the empty id.
    #[test]
    fn id_len_strips_trailing_zeros() {
        unsafe {
            assert_eq!(_z_id_len(z_id_t::empty()), 0);
            let mut id = z_id_t::empty();
            id.id[0] = 1;
            assert_eq!(_z_id_len(id), 1);
            id.id[4] = 9;
            assert_eq!(_z_id_len(id), 5, "a zero INSIDE the id is not stripped");
            id.id[15] = 7;
            assert_eq!(_z_id_len(id), 16);
        }
    }

    /// A short wire zid is zero-padded to 16, LEFT-aligned — zenoh strips
    /// trailing zeros on the wire, so re-padding must put them back at the end.
    #[test]
    fn a_short_wire_zid_pads_on_the_right() {
        let id = z_id_t::from_wire(&[0xAA, 0xBB]);
        assert_eq!(id.id[0], 0xAA);
        assert_eq!(id.id[1], 0xBB);
        assert!(id.id[2..].iter().all(|b| *b == 0));
    }
}
