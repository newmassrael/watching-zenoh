// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_id_t`, the zid closure, and the three `z_info_*` enumerations.
//!
//! ## Two things cross BY VALUE, and both are load-bearing
//!
//! `z_info_zid` RETURNS a `z_id_t` and `z_closure_zid`'s callback takes a
//! `const z_id_t*`. The struct is `ALIGN(1) { uint8_t id[16]; }`
//! (`zenoh_opaque.h:145-147`) — sixteen bytes at alignment ONE, not eight, which
//! is what a `[u8; 16]` in a `#[repr(C)]` struct gives and what a hand-rolled
//! `u128` would not. The const assertions below pin both.
//!
//! ## The RENDERING is where a drop-in can be silently wrong
//!
//! `z_id_to_string` prints the id the way zenoh PRINTS it: lowercase hex of the
//! sixteen bytes read as a little-endian `u128`, so the byte order is REVERSED,
//! and with the leading zeros TRIMMED, so a short id is a short string. The id
//! `1` is the text `1`, the all-zero id is `0`, and an id whose top nibble is
//! zero is 31 characters.
//!
//! The header's one-line doc comment says "16-digit hex string (LSB-first
//! order)", and only the second half of it is true. This function used to follow
//! the whole sentence, and printed the id `123456789` as
//! `00000000000000000000000123456789` where zenohd logs `Using ZID: 123456789`.
//! MEASURED against the real library, which is what settled it
//! (`zenoh_c_open_zid_twice_and_diff`, compiled once and linked against both):
//! the real `z_id_to_string` trims.
//!
//! That is no accident of the build. zenoh-c's function is one line over zenoh's
//! own `Display` for the id (`z_id_to_string` in `src/info.rs` is
//! `zid.to_string()`), and that is `uhlc::ID`'s `{:x}` over a `u128`
//! (`uhlc-0.8.2/src/id.rs:281`) — the SAME spelling the config's `id` key, the
//! keyexpr a zid is rendered into, and zenohd's log use. There is one recipe in
//! this workspace, `zid_hex::zid_to_zenoh_hex`, and this function calls it.
//!
//! Two mistakes are individually plausible and each produces a string that looks
//! like a zid: a big-endian rendering, which disagrees with every id a zenoh-c
//! program prints, and a fixed-width one, which agrees with the reference on a
//! full sixteen-byte id and on nothing shorter.
//!
//! The sibling `wz-capi-pico` renders differently and rightly so: pico's own
//! `_z_id_to_string` converts all sixteen bytes unconditionally, so its text is
//! always 32 characters, and `pico_pure_function_oracle` holds that against the
//! real `libzenohpico`. The two ABIs share an id type and a byte order, not a
//! width.
//!
//! ## The peers/routers SPLIT is made here, at the ABI boundary
//!
//! [`peer_identities`](wz_capi_core::faces::SharedSession::peer_identities)
//! reports each face's `(zid, whatami)` with `whatami` in its raw 2-bit wire form
//! (0 Router, 1 Peer, 2 Client). Upstream exports the split as two functions, so
//! the partition is applied here rather than in the shared core — the core serves
//! both ABIs and neither gets to impose its own bucketing on the other.

use std::ffi::c_void;

use crate::abi::{z_closure_drop_callback_t, z_loaned_session_t, z_owned_string_t};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::string::owned_string_from;

/// The zid width zenoh puts on the wire.
pub const Z_ID_SIZE: usize = 16;

/// zenoh-c `z_id_t` (`zenoh_opaque.h:145-147`) — 16 bytes at ALIGNMENT 1.
#[repr(C, align(1))]
#[derive(Clone, Copy)]
pub struct z_id_t {
    /// The id bytes, LSB-first, as the wire carries them.
    pub id: [u8; Z_ID_SIZE],
}

const _: () = {
    assert!(std::mem::size_of::<z_id_t>() == 16);
    assert!(std::mem::align_of::<z_id_t>() == 1);
};

impl z_id_t {
    /// The all-zero id. Upstream documents this as what an INVALID session
    /// yields: "this function returning an array of 16 zeros means you failed to
    /// pass it a valid session" (`zenoh_commons.h:3095-3098`), which is why the
    /// by-value return needs no error channel.
    pub(crate) fn empty() -> Self {
        Self {
            id: [0u8; Z_ID_SIZE],
        }
    }

    /// Build from a wire zid, which may be SHORTER than 16 bytes: zenoh transmits
    /// a zid with its trailing zeros stripped, so a peer's recorded id is
    /// left-aligned and zero-padded back out here.
    ///
    /// Longer input is truncated rather than rejected — a 17-byte zid cannot
    /// reach a `z_id_t` at all, and dropping the peer from the enumeration would
    /// hide a real face, which is the worse failure of the two.
    pub(crate) fn from_wire(bytes: &[u8]) -> Self {
        let mut id = [0u8; Z_ID_SIZE];
        let n = bytes.len().min(Z_ID_SIZE);
        id[..n].copy_from_slice(&bytes[..n]);
        Self { id }
    }
}

/// zenoh-c `z_closure_zid_callback_t`: `void call(const z_id_t*, void*)`.
pub type z_closure_zid_callback_t = Option<unsafe extern "C" fn(*const z_id_t, *mut c_void)>;

/// Owned zid closure (zenoh-c `z_owned_closure_zid_t`, `zenoh_commons.h:597-601`).
///
/// TRANSPARENT like the sample closure, and for the same reason: the C side's
/// `z_closure` macro writes the three fields DIRECTLY and never calls into this
/// library, so a wrong field ORDER compiles on both sides and then calls the
/// context as a function.
#[repr(C)]
pub struct z_owned_closure_zid_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_zid_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned zid closure — the same layout, so the loan is a pointer cast.
#[repr(C)]
pub struct z_loaned_closure_zid_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_zid_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved zid closure (zenoh-c `z_moved_closure_zid_t`).
#[repr(C)]
pub struct z_moved_closure_zid_t {
    pub(crate) _this: z_owned_closure_zid_t,
}

impl z_owned_closure_zid_t {
    /// The gravestone: no context, no callbacks.
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_closure_zid_t>() == 24);
    assert!(std::mem::align_of::<z_owned_closure_zid_t>() == 8);
    assert!(std::mem::size_of::<z_moved_closure_zid_t>() == 24);
};

/// Construct a zid closure from its parts (zenoh-c `z_closure_zid`).
///
/// Note the argument ORDER — `(this_, call, drop, context)` — which is not the
/// struct's field order, exactly as for the sample closure.
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers; `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid(
    this_: *mut z_owned_closure_zid_t,
    call: z_closure_zid_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_zid_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Borrow a zid closure (zenoh-c `z_closure_zid_loan`) — offset-0 identity.
///
/// # Safety
/// `closure` must be null or a valid owned zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_loan(
    closure: *const z_owned_closure_zid_t,
) -> *const z_loaned_closure_zid_t {
    closure as *const z_loaned_closure_zid_t
}

/// The `_mut` spelling of the loan (zenoh-c `z_closure_zid_loan_mut`).
///
/// R311y568. Note the SIGNATURE: upstream's takes a `const z_owned_closure_zid_t
/// *` and returns a `const z_loaned_closure_zid_t *` — both const, despite the
/// name. That is upstream's declaration and not a transcription slip here, so
/// the mirror keeps it; a C program's call site would not compile against the
/// mutable spelling.
///
/// # Safety
/// As [`z_closure_zid_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_loan_mut(
    closure: *const z_owned_closure_zid_t,
) -> *const z_loaned_closure_zid_t {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_closure_zid_loan(closure) }
}

/// Invoke a zid closure (zenoh-c `z_closure_zid_call`). Calling an uninitialized
/// closure is a no-op, which is upstream's stated contract.
///
/// # Safety
/// `closure` must be null or a valid loaned zid closure; `z_id` is passed through
/// to the C callback unchanged.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_call(
    closure: *const z_loaned_closure_zid_t,
    z_id: *const z_id_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        if let Some(call) = unsafe { (*closure).call } {
            let ctx = unsafe { (*closure).context };
            // SAFETY: an unwind out of the C callback across `extern "C"` is UB.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                call(z_id, ctx);
            }));
        }
    });
}

/// Drop a zid closure that was never moved (zenoh-c `z_closure_zid_drop`): run
/// the C `drop(context)` once and null the struct.
///
/// # Safety
/// `closure_` must be null or a valid moved zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_zid_drop(closure_: *mut z_moved_closure_zid_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        release_zid_closure(std::mem::replace(
            owned,
            z_owned_closure_zid_t::null_value(),
        ));
        Z_OK
    });
}

/// `true` iff the owned zid closure carries a callback (zenoh-c
/// `z_internal_closure_zid_check`).
///
/// # Safety
/// `this_` must be null or a valid owned zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_zid_check(this_: *const z_owned_closure_zid_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).call }.is_some()
    })
}

/// Zero an owned zid closure (zenoh-c `z_internal_closure_zid_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_zid_null(this_: *mut z_owned_closure_zid_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_closure_zid_t::null_value() };
    }
}

/// Run a taken closure's `drop(context)` exactly once.
fn release_zid_closure(taken: z_owned_closure_zid_t) {
    if let Some(dropfn) = taken.drop {
        let ctx = taken.context;
        // SAFETY: upstream's contract — drop runs once, and an unwind across the
        // C boundary is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            dropfn(ctx);
        }));
    }
}

/// Render a zid the way zenoh prints it: lowercase hex of the bytes read as a
/// little-endian `u128`, leading zeros trimmed (zenoh-c `z_id_to_string`).
///
/// Returns `void` upstream — unlike zenoh-pico's, which returns a status. The
/// zero id is the text `0`, never an empty string: it is a legal value (upstream's
/// "invalid session" answer), not an absence. See the module note for what was
/// measured and why the header's "16-digit" is not what the library does.
///
/// # Safety
/// `zid` must be null or a valid `z_id_t`; `dst` must be null or valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_id_to_string(zid: *const z_id_t, dst: *mut z_owned_string_t) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        if zid.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = owned_string_from(b"") };
            return;
        }
        // SAFETY: the caller's contract.
        let bytes = unsafe { &(*zid).id };
        let text = wz_runtime_tokio::zid_hex::zid_to_zenoh_hex(bytes);
        // SAFETY: the caller's contract.
        unsafe { *dst = owned_string_from(text.as_bytes()) };
    });
}

/// This session's own zid (zenoh-c `z_info_zid`).
///
/// Returns the 16 bytes the session put on the wire in its INIT — the same id a
/// peer records for it, by construction: `SessionState` holds the single zid the
/// open minted and the INIT was built from it.
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_info_zid(session: *const z_loaned_session_t) -> z_id_t {
    guard_val(z_id_t::empty(), || {
        // SAFETY: the caller's contract.
        match unsafe { session_state(session) } {
            Some(state) => z_id_t { id: state.zid() },
            None => z_id_t::empty(),
        }
    })
}

/// This session's GLOBAL ENTITY ID (zenoh-c `z_session_id`).
///
/// R2258 (open-debt item 593) — one of the twelve strays the census counts on
/// both unstable arms, and the one that needed no new machinery: the zid half
/// is what [`z_info_zid`] already answers, and the eid half is ZERO because the
/// session is not an entity WITHIN itself. That is the same convention the five
/// entity accessors state — a publisher is not a separate node, so its zid is
/// the session's — read from the other end: the session has no per-entity
/// handle to narrow, so its eid is the empty one.
///
/// ⚠ The item recorded these strays as "accessors, each needing a value wz's
/// marshals do not carry yet". MEASURED when this was built, that is not true
/// of this one: `SessionState::zid()` has carried the value since the open
/// minted it, and `z_entity_global_id_t` has existed since R311y568.
///
/// UNSTABLE-gated as upstream gates it (`#if defined(Z_FEATURE_UNSTABLE_API)`),
/// and it has to be for the same reason [`crate::publisher::z_publisher_id`]
/// is: the return type lives in [`crate::advanced`], which the other arm does
/// not compile.
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_session_id(
    session: *const z_loaned_session_t,
) -> crate::advanced::z_entity_global_id_t {
    guard_val(crate::advanced::z_entity_global_id_t::empty(), || {
        // SAFETY: the caller's contract.
        match unsafe { session_state(session) } {
            Some(state) => crate::advanced::z_entity_global_id_t {
                zid: z_id_t { id: state.zid() },
                eid: 0,
            },
            None => crate::advanced::z_entity_global_id_t::empty(),
        }
    })
}

/// The 2-bit INIT `whatami` wire encoding: 0 Router, 1 Peer, 2 Client.
const WHATAMI_WIRE_ROUTER: u8 = 0;
/// Select routers only — `z_info_routers_zid`.
const WHATAMI_ROUTER_ONLY: bool = true;
/// Select everything that is not a router — `z_info_peers_zid`.
const WHATAMI_NON_ROUTER: bool = false;

/// Invoke `callback` once per connected ROUTER (zenoh-c `z_info_routers_zid`).
///
/// # Safety
/// `session` must be null or a valid loaned session; `callback` must be null or a
/// valid moved zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_info_routers_zid(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { enumerate_peers(session, callback, WHATAMI_ROUTER_ONLY) }
}

/// Invoke `callback` once per connected PEER or CLIENT (zenoh-c
/// `z_info_peers_zid`).
///
/// # Safety
/// `session` must be null or a valid loaned session; `callback` must be null or a
/// valid moved zid closure.
#[no_mangle]
pub unsafe extern "C" fn z_info_peers_zid(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { enumerate_peers(session, callback, WHATAMI_NON_ROUTER) }
}

/// The shared body of the two enumerations, so the closure-consumption contract
/// cannot drift between them.
///
/// The moved closure is consumed on EVERY path including the failure ones.
/// Upstream states the guarantee outright — the callback "is guaranteed to be
/// dropped before this function exits" (`zenoh_commons.h:3073-3075`) — and
/// `z_info.c` depends on it: it builds a closure, moves it into
/// `z_info_routers_zid`, and then builds a second one for the peers call.
///
/// # Safety
/// As the two callers document.
unsafe fn enumerate_peers(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_zid_t,
    routers: bool,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let taken = std::mem::replace(owned, z_owned_closure_zid_t::null_value());
        // From here every return path must release `taken`, so the body runs in a
        // closure and the release below is unconditional.
        let rc = (|| {
            // SAFETY: the caller's contract.
            let Some(state) = (unsafe { session_state(session) }) else {
                return Z_ENULL;
            };
            let Some(call) = taken.call else {
                // A closure with no callback is not an error; there is simply
                // nothing to invoke.
                return Z_OK;
            };
            for (zid, whatami) in state.shared.peer_identities() {
                if (whatami == WHATAMI_WIRE_ROUTER) != routers {
                    continue;
                }
                let id = z_id_t::from_wire(&zid);
                let ctx = taken.context;
                // SAFETY: an unwind out of the C callback across `extern "C"` is
                // UB, so it is caught; the id outlives the call.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    call(&id, ctx);
                }));
            }
            Z_OK
        })();
        release_zid_closure(taken);
        rc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::{z_string_data, z_string_drop, z_string_len, z_view_string_loan};

    /// Read an owned string back out as bytes.
    unsafe fn rendered(id: &z_id_t) -> Vec<u8> {
        let mut out = owned_string_from(b"");
        z_id_to_string(id, &mut out);
        let loaned = z_view_string_loan(&out);
        let bytes =
            std::slice::from_raw_parts(z_string_data(loaned) as *const u8, z_string_len(loaned))
                .to_vec();
        z_string_drop(&mut out as *mut _ as *mut crate::abi::z_moved_string_t);
        bytes
    }

    /// The rendering is REVERSED and TRIMMED, asserted against texts the REAL
    /// libzenohc printed for these bytes.
    ///
    /// The literals were read off that library, not off this function, and the
    /// differential test `zenoh_c_open_zid_twice_and_diff` re-asks the library the
    /// same questions on every run, so a literal that drifted from upstream fails
    /// there. They are here as well because this test runs where the oracle does
    /// not. This test used to assert the opposite — `2301` rendered as 32 padded
    /// characters — against nothing but the model that wrote it.
    ///
    /// A big-endian rendering would start `01` for the first vector and a
    /// fixed-width one would be 32 characters for all but the full-width id.
    #[test]
    fn a_zid_renders_as_the_real_library_prints_it() {
        let prefixed = |prefix: &[u8]| {
            let mut id = z_id_t::empty();
            id.id[..prefix.len()].copy_from_slice(prefix);
            id
        };
        let mut full = z_id_t::empty();
        let mut top_nibble_zero = z_id_t::empty();
        for (i, (low, high)) in full
            .id
            .iter_mut()
            .zip(top_nibble_zero.id.iter_mut())
            .enumerate()
        {
            *low = 0x10 + i as u8;
            *high = 0xa0 + i as u8;
        }
        // The most significant byte is 0x05, so a full-width rendering would
        // begin with a zero digit.
        top_nibble_zero.id[Z_ID_SIZE - 1] = 0x05;
        let cases: [(z_id_t, &str); 7] = [
            (z_id_t::empty(), "0"),
            (prefixed(&[0x01]), "1"),
            (prefixed(&[0x01, 0x23]), "2301"),
            (
                prefixed(&[0x49, 0x1e, 0xc1, 0x47, 0x1e, 0xc1]),
                "c11e47c11e49",
            ),
            (prefixed(&[0x89, 0x67, 0x45, 0x23, 0x01]), "123456789"),
            (full, "1f1e1d1c1b1a19181716151413121110"),
            (top_nibble_zero, "5aeadacabaaa9a8a7a6a5a4a3a2a1a0"),
        ];
        for (id, want) in &cases {
            // SAFETY: local values, valid for the call.
            let text = unsafe { rendered(id) };
            assert_eq!(
                std::str::from_utf8(&text).unwrap(),
                *want,
                "the text of {:02x?}",
                id.id
            );
        }
        // Said again in the one place the two halves of the claim meet: the id
        // whose most significant nibble is zero is 31 characters, not 32.
        assert_eq!(cases[6].1.len(), 31);
    }

    /// Every byte position and every nibble boundary, against the standard
    /// library's own `{:x}` over a `u128`.
    ///
    /// The vectors above are chosen; this one is swept, so a trim that is right
    /// for the ids somebody thought of and off by one nibble for another cannot
    /// pass. The expectation is `format!("{:x}", ..)` and so is derived from
    /// nothing in this crate.
    #[test]
    fn a_zid_with_one_byte_set_renders_as_the_u128_in_hex() {
        for position in 0..Z_ID_SIZE {
            for value in [0x01u8, 0x0f, 0x10, 0x7f, 0x80, 0xf0, 0xff] {
                let mut id = z_id_t::empty();
                id.id[position] = value;
                let want = format!("{:x}", u128::from_le_bytes(id.id));
                // SAFETY: local values, valid for the call.
                let text = unsafe { rendered(&id) };
                assert_eq!(
                    std::str::from_utf8(&text).unwrap(),
                    want,
                    "byte {position} = {value:#04x}"
                );
            }
        }
    }

    /// A wire zid shorter than 16 bytes is zero-padded on the RIGHT, because
    /// zenoh strips TRAILING zeros for transmission.
    #[test]
    fn a_short_wire_zid_is_padded_on_the_right() {
        let id = z_id_t::from_wire(&[0xaa, 0xbb]);
        assert_eq!(id.id[0], 0xaa);
        assert_eq!(id.id[1], 0xbb);
        assert!(id.id[2..].iter().all(|b| *b == 0));
    }

    /// A wire zid LONGER than the type is truncated rather than dropped: hiding a
    /// real face is the worse of the two failures.
    #[test]
    fn an_overlong_wire_zid_is_truncated_not_dropped() {
        let id = z_id_t::from_wire(&[0xff; 20]);
        assert!(id.id.iter().all(|b| *b == 0xff));
    }
}
