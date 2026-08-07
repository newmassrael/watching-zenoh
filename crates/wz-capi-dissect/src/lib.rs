// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y586 (A7) — the C ABI over wz's dissection surface.
//!
//! ## The design choice, and why it is this one
//!
//! A [REDACTED]/C++ consumer can drive wz as a zenoh NODE today ([`wz_capi_c`]) and
//! could not call the decode core at all. Closing that had two candidate
//! shapes, and they are not equally durable:
//!
//! **A wide ABI mirroring the Rust tree** — C structs for `Field`, `Span`,
//! `FieldValue`, an enum tag per variant, accessors per arm. It gives C a
//! typed tree, and it makes every walker wz adds an ABI change: a new
//! `FieldValue` variant is a new tag the C side must learn, and a consumer
//! built against the old header reads a discriminant it has no case for.
//! `dissect` gains walkers as a matter of routine — this round alone added
//! two — so that ABI would break as a matter of routine.
//!
//! **A narrow ABI over a self-describing format** — a handful of functions
//! that hand back JSON. Adding a walker adds NODES, not symbols; a consumer
//! built against today's header keeps working and simply sees fields it does
//! not recognise, which is the same forward-compatibility contract zenoh's
//! own unknown-extension policy takes. [REDACTED] parses it with `QJsonDocument`,
//! which is in the framework already.
//!
//! This crate is the second shape. The deciding fact is that
//! [`wz_session_core::dissect::to_json`] already exists and takes NO serde
//! dependency — it was built for R311y579's G6, whose measured failure was a
//! consumer that could not get a decode out of the library at all. The JSON
//! emit was the answer then for the same reason it is the answer here.
//!
//! ## What the ABI promises
//!
//! Five functions, and the memory rule is the whole of the contract: every
//! string this library returns is owned by this library and must be released
//! with [`wz_dissect_string_free`]. Nothing else is allocated across the
//! boundary, no callbacks run, and no handle outlives the call that made it.
//!
//! ## What it does NOT promise
//!
//! The JSON SHAPE is not frozen. Field names are wz's walker names and may
//! gain siblings; a consumer must read by name and tolerate unknown keys.
//! Freezing the shape would reintroduce exactly the coupling this design
//! exists to avoid.

use core::ffi::{c_char, c_int};
use std::ffi::CString;

use wz_capture::Dissection;
use wz_session_core::dissect::{dissect_transport_message, to_json};

/// Success.
pub const WZ_DISSECT_OK: c_int = 0;
/// A null pointer, or a length that cannot be a buffer.
pub const WZ_DISSECT_ERR_INVALID_ARG: c_int = -1;
/// The capture file could not be read (bad magic, truncated, pcapng).
pub const WZ_DISSECT_ERR_BAD_CAPTURE: c_int = -2;
/// The bytes were not a decodable transport message.
pub const WZ_DISSECT_ERR_DECODE: c_int = -3;

/// The ABI revision. Bumped when a SYMBOL's signature or the memory contract
/// changes — NOT when the JSON gains fields, which is the whole point of
/// handing back JSON.
///
/// # Safety
/// None; takes no arguments and touches no memory.
#[no_mangle]
pub extern "C" fn wz_dissect_abi_version() -> c_int {
    1
}

/// Release a string this library returned. Passing null is a no-op, so a
/// consumer's cleanup path needs no null check of its own.
///
/// # Safety
/// `s` must be a pointer this library returned and not yet freed, or null.
/// Passing anything else, or freeing twice, is undefined.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: the caller contract is that `s` came from `into_raw` on a
        // `CString` this library made.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Dissect ONE transport message from `bytes`, returning its field tree as
/// JSON.
///
/// `base` is the coordinate every span is reported in — pass the message's
/// offset within a capture and the spans read as capture offsets directly,
/// pass 0 and they are message-relative. The walker never mixes the two.
///
/// On success writes an owned C string to `out` and returns
/// [`WZ_DISSECT_OK`]. The caller owns it and must release it with
/// [`wz_dissect_string_free`].
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_transport_message(
    bytes: *const u8,
    len: usize,
    base: usize,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    match dissect_transport_message(input, base) {
        Ok(field) => {
            let json = to_json(&field);
            write_string(json, out)
        }
        Err(_) => WZ_DISSECT_ERR_DECODE,
    }
}

/// Dissect a whole classic pcap FILE held in memory, returning a JSON
/// summary of every flow it found.
///
/// The summary is deliberately a summary and not the full field tree: a
/// capture holds an unbounded number of messages, and a single string
/// carrying all of them is a shape that works for a test and fails for a
/// session. A consumer walks the flows here, then calls
/// [`wz_dissect_transport_message`] per message it wants expanded.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_summary(
    bytes: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection = match Dissection::from_pcap(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    write_string(summary_json(&dissection), out)
}

/// The summary shape. Hand-rolled rather than via serde for the same reason
/// [`to_json`] is: this crate must not force a serde dependency on a
/// consumer that only wants a decode out of the library.
fn summary_json(d: &Dissection) -> String {
    let mut s = String::from("{\"tcp_flows\":[");
    for (i, f) in d.flows().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{{\"frames\":{}}}", f.frames.len()));
    }
    s.push_str("],\"datagram_flows\":[");
    for (i, f) in d.datagram_flows().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{{\"frames\":{}}}", f.frames.len()));
    }
    // The skipped packets are part of the summary on purpose: a consumer that
    // cannot see them reads a dissection with holes as a dissection that was
    // complete.
    s.push_str(&format!("],\"skipped\":{}}}", d.skipped().len()));
    s
}

/// Hand an owned string across the boundary.
///
/// A NUL byte inside the JSON would truncate it silently at the C side, so
/// the conversion's failure is reported rather than unwrapped. `to_json`
/// escapes control characters, so this is a belt-and-braces path — but an
/// unwrap here would turn a walker bug into a panic across an FFI boundary,
/// which is undefined behaviour rather than an error code.
fn write_string(s: String, out: *mut *mut c_char) -> c_int {
    match CString::new(s) {
        Ok(c) => {
            // SAFETY: `out` was null-checked by the caller of this helper.
            unsafe { *out = c.into_raw() };
            WZ_DISSECT_OK
        }
        Err(_) => WZ_DISSECT_ERR_DECODE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the ABI the way C does — raw pointers in, owned string out,
    /// freed through the library's own free. Calling the Rust functions
    /// directly would prove the walkers work and say nothing about the
    /// boundary, which is the only thing this crate adds.
    fn call_transport(bytes: &[u8]) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_transport_message(bytes.as_ptr(), bytes.len(), 0, &mut out) };
        if rc != WZ_DISSECT_OK {
            return Err(rc);
        }
        assert!(!out.is_null(), "OK must come with a string");
        let s = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("utf8")
            .to_string();
        unsafe { wz_dissect_string_free(out) };
        Ok(s)
    }

    #[test]
    fn a_transport_message_crosses_the_boundary_as_json() {
        // A KeepAlive: one header byte, the smallest complete transport
        // message, so the assertion is about the boundary and not a codec.
        let json = call_transport(&[wz_session_core::wire_const::T_MID_KEEP_ALIVE])
            .expect("keepalive dissects");
        assert!(json.starts_with('{'), "not JSON: {json}");
        assert!(json.contains("\"name\""), "no field names: {json}");
        assert!(json.contains("header"), "no header field: {json}");
    }

    /// A decode failure is an ERROR CODE, not a panic. A panic unwinding
    /// across an `extern "C"` boundary is undefined behaviour, so this is the
    /// leg that matters most for an ABI.
    #[test]
    fn undecodable_bytes_return_an_error_rather_than_unwinding() {
        assert_eq!(call_transport(&[]), Err(WZ_DISSECT_ERR_DECODE));
    }

    /// Null arguments are rejected before anything is dereferenced.
    #[test]
    fn null_arguments_are_refused() {
        let mut out: *mut c_char = core::ptr::null_mut();
        assert_eq!(
            unsafe { wz_dissect_transport_message(core::ptr::null(), 0, 0, &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_transport_message([0u8].as_ptr(), 1, 0, core::ptr::null_mut()) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_pcap_summary(core::ptr::null(), 0, &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
    }

    /// Freeing null is a no-op, so a consumer's cleanup path needs no null
    /// check of its own — the commonest source of a double-free at an FFI
    /// boundary is a caller guarding a free the library already guards.
    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe { wz_dissect_string_free(core::ptr::null_mut()) };
    }

    /// A capture this reader does not parse is a NAMED error, not a crash and
    /// not an empty success. pcapng is the case that matters: it is the
    /// commonest modern format and `wz-capture` diagnoses it by name.
    #[test]
    fn a_capture_that_cannot_be_read_is_an_error_code() {
        let mut out: *mut c_char = core::ptr::null_mut();
        let pcapng = [0x0Au8, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0];
        assert_eq!(
            unsafe { wz_dissect_pcap_summary(pcapng.as_ptr(), pcapng.len(), &mut out) },
            WZ_DISSECT_ERR_BAD_CAPTURE
        );
        assert!(out.is_null(), "an error must not hand back a string");
    }

    /// The version is a SYMBOL contract, not a JSON one: it exists so a
    /// consumer can refuse a library whose memory rules changed, and it must
    /// NOT move when a walker adds fields.
    #[test]
    fn the_abi_version_is_readable() {
        assert_eq!(wz_dissect_abi_version(), 1);
    }
}
