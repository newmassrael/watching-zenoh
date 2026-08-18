// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y586 (A7) — the C ABI over wz's dissection surface.
//!
//! ## The design choice, and why it is this one
//!
//! A C/C++ consumer can drive wz as a zenoh NODE today (`wz-capi-c`) and
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
//! own unknown-extension policy takes. A consumer parses it with whatever JSON
//! reader its own framework already ships, so the dependency is theirs and not
//! this crate's.
//!
//! This crate is the second shape. The deciding fact is that
//! [`wz_session_core::dissect::to_json`] already exists and takes NO serde
//! dependency — it was built for R311y579's G6, whose measured failure was a
//! consumer that could not get a decode out of the library at all. The JSON
//! emit was the answer then for the same reason it is the answer here.
//!
//! ## What the ABI promises
//!
//! Eleven functions since R311y856 added `wz_dissect_pcap_fields_with_payloads`
//! and `wz_dissect_declarations_diagnose`, and the memory
//! rule is the whole of the contract: every
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
/// The capture file could not be read: bad magic, or a truncated / malformed
/// file in either format. R311y608 — pcapng was in this list and is not any
/// more; [`wz_dissect_pcap_summary`] dispatches on the magic and reads both.
pub const WZ_DISSECT_ERR_BAD_CAPTURE: c_int = -2;
/// The bytes were not a decodable transport message.
pub const WZ_DISSECT_ERR_DECODE: c_int = -3;
/// R311y854 — the selector did not compile. Its own code and not
/// [`WZ_DISSECT_ERR_INVALID_ARG`], because the two are answered by different
/// people: an invalid argument is the CALLER's bug, and a selector is text an
/// operator typed into a box. Call [`wz_dissect_selector_diagnose`] to learn
/// where.
pub const WZ_DISSECT_ERR_SELECTOR: c_int = -4;
/// R311y856 — a payload declaration did not install. Its own code and not
/// [`WZ_DISSECT_ERR_SELECTOR`] for the reason that code is not
/// [`WZ_DISSECT_ERR_INVALID_ARG`]: a selector and a format declaration are two
/// different texts a person writes, and a UI that could not tell which one it
/// must send them back to would be answering neither. Call
/// [`wz_dissect_declarations_diagnose`] to learn which line and why.
pub const WZ_DISSECT_ERR_DECLARATION: c_int = -5;

/// The ABI revision. Bumped when the SYMBOL SET or the memory contract changes
/// — NOT when the JSON gains fields, which is the whole point of handing back
/// JSON.
///
/// R311y748 — 1 → 2, ADDING `wz_dissect_pcap_summary_bounded`. And the wording
/// above moved with it, because the two statements of this one contract had
/// drifted apart: `wz_dissect.h` says the version moves "when a SYMBOL or the
/// memory rule changes", and this doc had narrowed that to a symbol's
/// SIGNATURE. Under the narrow reading a new symbol is free; under the
/// committed one it is not, and the committed one is right for the reason the
/// narrow one cannot answer — adding a symbol raises exactly one question for a
/// consumer ("does this library have it?"), and a version that does not move is
/// unable to answer it. An existing consumer is unaffected either way, which is
/// what makes this a widening rather than a break.
///
/// R311y851 — 2 → 3, ADDING [`wz_dissect_pcap_census`]. Same rule, third
/// application: a new symbol raises exactly one question for a consumer ("does
/// this library have it?"), and a version that does not move cannot answer it.
///
/// R311y854 — 3 → 4, ADDING [`wz_dissect_pcap_census_where`] and
/// [`wz_dissect_selector_diagnose`].
///
/// R311y855 — 4 → 5, ADDING [`wz_dissect_pcap_fields`].
///
/// R311y856 — 5 → 6, ADDING [`wz_dissect_pcap_fields_with_payloads`] and
/// [`wz_dissect_declarations_diagnose`].
///
/// # Safety
/// None; takes no arguments and touches no memory.
#[no_mangle]
pub extern "C" fn wz_dissect_abi_version() -> c_int {
    6
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

/// Dissect a whole capture FILE held in memory, returning a JSON summary of
/// every flow it found.
///
/// The summary is deliberately a summary and not the full field tree: a
/// capture holds an unbounded number of messages, and a single string
/// carrying all of them is a shape that works for a test and fails for a
/// session. A consumer walks the flows here, then calls
/// [`wz_dissect_transport_message`] per message it wants expanded.
///
/// # R311y608 — EITHER format, and that is not a convenience
///
/// This used to call `Dissection::from_pcap`, so a pcapng file — what every
/// current `dumpcap` / `tshark -w` writes by default — came back
/// [`WZ_DISSECT_ERR_BAD_CAPTURE`], indistinguishable from a corrupt one. It now
/// dispatches on the magic through `Dissection::from_capture`.
///
/// The widening is load-bearing for the health report below rather than
/// cosmetic: `capture_reported_drops` reads the Interface Statistics Block,
/// which the classic format HAS NOWHERE TO PUT. Over `from_pcap` alone that
/// figure is `null` for every file that could ever reach it, and a counter that
/// is structurally always absent is not a counter.
///
/// It is a widening only — every input that used to succeed still does, with
/// the same shape plus siblings — which is the compatibility the module doc
/// promises and the reason [`wz_dissect_abi_version`] does not move.
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
    let dissection = match Dissection::from_capture(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    write_string(summary_json(&dissection), out)
}

/// R311y748 — the same summary, read under the BOUNDED preset, so a C caller
/// can state that its memory is finite.
///
/// # The gap this closes
///
/// [`wz_dissect_pcap_summary`] reads through `Dissection::from_capture`, whose
/// limits are `DissectionLimits::default()` — every field `None`. No cap can
/// bite behind that door, so the `dropped_by_limits` group it reports is five
/// structural zeros for every input that will ever reach it, which R311y746
/// measured and pinned. A counter that is structurally always zero is not a
/// counter, which is the same judgement R311y608 made about
/// `capture_reported_drops` over `from_pcap` alone.
///
/// # Why a NAMED PRESET rather than a limits struct
///
/// This ABI's stated design is a self-describing document instead of a struct
/// tree, and a limits struct passed across the boundary would freeze nine
/// fields' layout into it — so the next axis `DissectionLimits` grows becomes
/// an ABI break rather than a preset edit. The preset is
/// `DissectionLimits::for_live_tap`, this tree's one bounded configuration,
/// and what it cost is reported through the same `dropped_by_limits` group:
/// bounded is never silent here either.
///
/// # The ABI version MOVES for this, 1 → 2
///
/// `wz_dissect.h` says the version moves "when a SYMBOL or the memory rule
/// changes", and this is a new symbol. See [`wz_dissect_abi_version`] for why
/// the narrower reading its own doc had drifted to was the wrong one. Existing
/// consumers are unaffected — every input that reached
/// [`wz_dissect_pcap_summary`] still reaches it with the same shape, and
/// nothing about memory ownership changed.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_summary_bounded(
    bytes: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection =
        match Dissection::from_capture_bounded(input, wz_capture::DissectionLimits::for_live_tap())
        {
            Ok(d) => d,
            Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
        };
    write_string(summary_json(&dissection), out)
}

/// R311y851 — the four ANALYSIS PLANES, which this ABI could not reach at all.
///
/// # The gap, and it was a gap between SURFACES
///
/// wz exports its dissection through two consumption surfaces and they carried
/// different halves of it. The keyexpr plane, the node plane, the query plane
/// and the payload plane — which keys carry the traffic, who the participants
/// are by zid, which queries were answered and how fast, and what the samples
/// declare — were reachable ONLY from `wz-analyze`, the command line. Through
/// this ABI, the surface a framework LINKS, a consumer got a per-flow frame
/// count and the health counters, and nothing above the transport.
///
/// They were not missing. `wz-capture` is this crate's dependency, so all four
/// were compiled into every build of this library and had no symbol — the same
/// class as a capability compiled into a preset with no flag to reach it. What
/// let it stand is that nothing compares the two surfaces to each other.
///
/// # Why one call and not four
///
/// A consumer that wanted three planes would otherwise read the capture three
/// times, and the three answers would be about three walks rather than one. The
/// planes are independent folds over the SAME frames and a reader compares
/// them — "which node published the key that carries the traffic" is a question
/// that spans two of them — so they cross together.
///
/// # What it costs, said plainly
///
/// Four walks of every frame, which is what the command line's `--census` pays
/// and why that flag exists rather than the planes always being built. Call
/// [`wz_dissect_pcap_summary`] when the transport-level answer is what is
/// wanted; this is the analysis one.
///
/// UNBOUNDED, like [`wz_dissect_pcap_summary`]: a file ends, so keeping all of
/// it is bounded. A bounded census door is a separate decision and is not
/// improvised here — see the crate's own registered residual.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_census(
    bytes: *const u8,
    len: usize,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection = match Dissection::from_capture(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    write_string(wz_capture::census_json::census_json(&dissection), out)
}

/// R311y855 — THE FIELD LAYER: every message in a capture, dissected into the
/// byte ranges it was decoded from.
///
/// # The walk this header described and could not perform
///
/// [`wz_dissect_pcap_summary`]'s doc has said since R311y586: "A consumer walks
/// the flows here, then calls [`wz_dissect_transport_message`] per message it
/// wants expanded." That walk was impossible. The summary reports per-flow
/// frame COUNTS, so there is nothing to enumerate by — and a coordinate would
/// not have been enough either: a stream message's bytes live in the
/// REASSEMBLED per-direction stream, which exists only inside this library, so
/// a caller holding the capture file cannot slice one out. The instruction
/// named a two-step walk whose first step this ABI never provided.
///
/// So the walk happens here, where the reassembly is, and the trees cross whole.
///
/// # One coordinate space, and every row says which
///
/// Spans inside a tree are MESSAGE-RELATIVE. Where the message sits is on the
/// row, because the two row producers put different kinds of number there: a
/// stream row carries `message_at`, a byte offset into the direction's retained
/// stream, so a span added to it is a capture coordinate; a datagram row
/// carries `packet`, an INDEX, which must not be added to anything.
/// `offset_space` names which — they are small numbers all round and cannot be
/// told apart by inspection.
///
/// # A row is a tree OR a named refusal, never a silent omission
///
/// The walk is checked against the passive session that framed the message. A
/// disagreement means the coordinate does not name the message the session
/// framed, and the row comes back with `declined` and the reason instead of a
/// confident tree about bytes nobody asked for. Bytes trimmed by a bounded read
/// decline the same way.
///
/// # `max_messages_per_flow`
///
/// 0 means UNBOUNDED, matching the command line's default. That is the shape
/// that works for a test and fails for a session — a capture holds an unbounded
/// number of messages — so a caller with a screen to fill should pass a bound.
/// Each flow reports `shown` and `omitted`, so a held-back listing is never
/// mistaken for a capture that ended.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_fields(
    bytes: *const u8,
    len: usize,
    max_messages_per_flow: usize,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection = match Dissection::from_capture(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    let cap = (max_messages_per_flow > 0).then_some(max_messages_per_flow);
    write_string(
        wz_capture::fields_json::fields_json(&dissection, input, cap, None),
        out,
    )
}

/// R311y856 — the field layer WITH the application payloads decoded, by a
/// mapping the caller declares.
///
/// # The half of the analysis surface a linked consumer could not reach
///
/// `wz-analyze --payload-format demo/**=protobuf` has decoded payloads since
/// R311y699 and this ABI could not, which `analysis_surface_parity.py` reported
/// as an OPEN DEBT: [`wz_capture::payload::formats::FormatMap`] was public, the
/// C surface had it in its dependency graph, and the decoders lived in the
/// COMMAND LINE — a binary this library must not depend on (it carries
/// `wz-tls-record`, and through it `ring`). The decoders moved beside the map
/// (`wz_capture::payload::formats::builtin`); this is the door.
///
/// # `declarations`
///
/// One declaration per line, in the spelling
/// [`wz_capture::payload::formats::parse_declaration`] defines and the command
/// line's two flags already write:
///
/// ```text
/// demo/**=protobuf            a format rule: which decoder reads this topic
/// demo/**:1=temperature       a field name: protobuf carries none, so a
///                             deployment that has a schema declares it
/// ```
///
/// ONE dialect for both surfaces, deliberately: a rule that a person tried in a
/// terminal and then moved into a config file must not have to be re-spelled,
/// and two parsers for one syntax disagree exactly there. An EMPTY text
/// declares nothing, which makes this call equivalent to
/// [`wz_dissect_pcap_fields`] rather than a way to get an error.
///
/// # A declaration this library cannot install is REFUSED
///
/// Not skipped. An unknown format name, a wildcard this build's matcher has no
/// arm for, a line that is not a declaration — each returns
/// [`WZ_DISSECT_ERR_DECLARATION`] and no document. The alternative is a map
/// quietly smaller than the text that built it, and a reader who then sees
/// undecoded bytes concludes the traffic is wrong rather than their rule. Call
/// [`wz_dissect_declarations_diagnose`] for WHICH line and why — a separate
/// call so the memory rule stays "OK means a string, an error means none".
///
/// # Reading the result
///
/// Every walked row gains `payload_decode`, an object whose `state` is one of
/// `decoded`, `refused`, `no_rule`, `keyexpr_unresolved` or `no_payload`. The
/// last three are ANSWERS and not omissions: a rule that never fired and a rule
/// that fired and found nothing send a reader to opposite places, and
/// `keyexpr_unresolved` is the ordinary shape of a capture that began after the
/// declarations went past. A `decoded` field's `start` / `end` are in the
/// MESSAGE's coordinate space, like every other span on the row.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes, `declarations` must be
/// a NUL-terminated C string, and `out` must be a writable pointer to a
/// `*mut c_char`. None may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_fields_with_payloads(
    bytes: *const u8,
    len: usize,
    max_messages_per_flow: usize,
    declarations: *const c_char,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || declarations.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let text = match unsafe { std::ffi::CStr::from_ptr(declarations) }.to_str() {
        Ok(s) => s,
        // Not a declaration error: the bytes are not text at all, so there is
        // no line for the diagnostic call to point at either.
        Err(_) => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    let mut map = wz_capture::payload::formats::FormatMap::new();
    if map.declare_all(text).is_err() {
        return WZ_DISSECT_ERR_DECLARATION;
    }
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection = match Dissection::from_capture(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    let cap = (max_messages_per_flow > 0).then_some(max_messages_per_flow);
    let declared = wz_capture::payload_decode::Declarations::new(&map);
    write_string(
        wz_capture::fields_json::fields_json(&dissection, input, cap, Some(&declared)),
        out,
    )
}

/// R311y856 — read a declaration text and say what is wrong with it, WITHOUT a
/// capture.
///
/// Always returns [`WZ_DISSECT_OK`] for readable text and writes a JSON
/// verdict: `{"ok":true,"installed":N}`, or
/// `{"ok":false,"line":N,"text":"…","message":"…"}` where `line` counts every
/// line of the text from 0 — blank ones included, so the number indexes what
/// the caller sent.
///
/// # Why this is a symbol rather than a richer error code
///
/// The argument [`wz_dissect_selector_diagnose`] makes, arriving for the second
/// text a person types. A declaration is written into a settings box, and a
/// consumer told only "one of these is bad" makes the operator bisect their own
/// configuration — the failure R311y854 named. Paying four walks of a capture
/// file to find out is worse still, and this needs none.
///
/// A verdict is not an error, which is why the OK/no-string rule is untouched:
/// a refused declaration is a successful DIAGNOSIS, and the string it hands
/// back is owned and freed like every other.
///
/// # Safety
/// `declarations` must be a NUL-terminated C string and `out` a writable
/// pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_declarations_diagnose(
    declarations: *const c_char,
    out: *mut *mut c_char,
) -> c_int {
    if declarations.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let text = match unsafe { std::ffi::CStr::from_ptr(declarations) }.to_str() {
        Ok(s) => s,
        Err(_) => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    let mut map = wz_capture::payload::formats::FormatMap::new();
    let verdict = match map.declare_all(text) {
        Ok(installed) => format!("{{\"ok\":true,\"installed\":{installed}}}"),
        Err(bad) => {
            let mut s = String::from("{\"ok\":false,\"line\":");
            s.push_str(&bad.line.to_string());
            s.push_str(",\"text\":");
            // The SAME escaper the rest of this ABI's documents use: the line
            // is the operator's own text, quoted back so a UI can point at it
            // without holding the input a second time.
            wz_session_core::json::escape_into(&bad.text, &mut s);
            s.push_str(",\"message\":");
            wz_session_core::json::escape_into(&bad.error.to_string(), &mut s);
            s.push('}');
            s
        }
    };
    write_string(verdict, out)
}

/// R311y854 — the census NARROWED by a selector, wz's own filter language.
///
/// `selector` is a NUL-terminated expression in the dialect
/// `wz-analyze --select` takes: terms are `field op value` (`key == demo/**`,
/// `kind == query`, `bytes > 100`, `delay >= 10`, …) joined with
/// `and` / `or` / `not` and parentheses. An EMPTY selector selects everything,
/// which makes this call equivalent to [`wz_dissect_pcap_census`] rather than
/// a way to get nothing.
///
/// # Three planes narrow and one does not
///
/// The keyexpr, query and payload planes take the selector. The NODE plane is
/// built whole, because a node is not a record the selector's terms describe —
/// the same choice the command line makes. Every plane carries
/// `narrowed_by_selector` so a consumer reads that off the document instead of
/// inferring it from surviving rows, which is the one way to get this wrong.
///
/// Each narrowed plane also carries `selection`: matched, rejected, and
/// UNDECIDED. The third is why this returns counts rather than only rows — a
/// keyexpr whose declaration went past before the tap started cannot be judged,
/// and a consumer that could not see it would read a short total as a whole
/// one.
///
/// # A bad selector is its OWN error code
///
/// [`WZ_DISSECT_ERR_SELECTOR`], not [`WZ_DISSECT_ERR_INVALID_ARG`]: a caller
/// passing a null pointer has a bug, and a selector is text a person typed. The
/// two want different treatment in a UI, and a single code cannot ask for it.
/// No string is handed back on any error, so the position comes from
/// [`wz_dissect_selector_diagnose`] — a separate call precisely so the memory
/// rule stays "OK means a string, an error means none" without an exception a
/// consumer has to remember.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes, `selector` must be a
/// NUL-terminated C string, and `out` must be a writable pointer to a
/// `*mut c_char`. None may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_census_where(
    bytes: *const u8,
    len: usize,
    selector: *const c_char,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || selector.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let expr = match unsafe { std::ffi::CStr::from_ptr(selector) }.to_str() {
        Ok(s) => s,
        // Not a selector error: the bytes are not text at all, so there is
        // nothing for the diagnostic call to point at either.
        Err(_) => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    let filter = match wz_capture::filter::Filter::parse(expr) {
        Ok(f) => f,
        Err(_) => return WZ_DISSECT_ERR_SELECTOR,
    };
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    let dissection = match Dissection::from_capture(input) {
        Ok(d) => d,
        Err(_) => return WZ_DISSECT_ERR_BAD_CAPTURE,
    };
    write_string(
        wz_capture::census_json::census_json_where(&dissection, &filter),
        out,
    )
}

/// R311y854 — compile a selector and say what is wrong with it, WITHOUT a
/// capture.
///
/// Always returns [`WZ_DISSECT_OK`] for readable text and writes a JSON verdict:
/// `{"ok":true}`, or `{"ok":false,"at":N,"message":"…"}` where `at` is a BYTE
/// offset into the selector.
///
/// # Why this is a symbol rather than a richer error code
///
/// A selector is typed, character by character, into a box. The useful moment
/// to answer "is this valid, and if not where" is while it is being typed —
/// before there is a capture to run it against, and certainly before a
/// consumer would want to pay four walks of a file to find out. A UI that can
/// only say "invalid" is one that makes the operator bisect their own
/// expression by hand.
///
/// A verdict is not an error, which is why the OK/no-string rule is untouched:
/// a refused selector is a successful DIAGNOSIS, and the string it hands back
/// is owned and freed like every other.
///
/// # Safety
/// `selector` must be a NUL-terminated C string and `out` a writable pointer to
/// a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_selector_diagnose(
    selector: *const c_char,
    out: *mut *mut c_char,
) -> c_int {
    if selector.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    // SAFETY: caller contract above.
    let expr = match unsafe { std::ffi::CStr::from_ptr(selector) }.to_str() {
        Ok(s) => s,
        Err(_) => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    let verdict = match wz_capture::filter::Filter::parse(expr) {
        Ok(_) => String::from("{\"ok\":true}"),
        Err(e) => {
            let mut s = String::from("{\"ok\":false,\"at\":");
            s.push_str(&e.at.to_string());
            s.push_str(",\"message\":");
            // The SAME escaper the census document uses: a message quotes the
            // operator's own text back (an unknown field name, a bad value), so
            // it carries whatever they typed.
            wz_session_core::json::escape_into(&e.to_string(), &mut s);
            s.push('}');
            s
        }
    };
    write_string(verdict, out)
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
        // R311y608 — the scouting count too. A datagram flow reported by its
        // frame count alone shows a scout group as an EMPTY flow, which reads
        // as "nothing was on it" for the one exchange that is always there.
        s.push_str(&format!(
            "{{\"frames\":{},\"scouting\":{}}}",
            f.frames.len(),
            f.scouting.len()
        ));
    }
    // The skipped packets are part of the summary on purpose: a consumer that
    // cannot see them reads a dissection with holes as a dissection that was
    // complete.
    s.push_str(&format!("],\"skipped\":{},", d.skipped().len()));
    s.push_str("\"health\":");
    s.push_str(&wz_capture::report::health_json(d));
    s.push('}');
    s
}

// R311y608's `health_json` MOVED to `wz_capture::report::health_json` in
// R311y857, beside the counters, and the whole of its reasoning went with it --
// including the one honest limitation this entry point still owns:
// `dropped_by_limits` is all zeros through `wz_dissect_pcap_summary` and
// STRUCTURALLY so, because that door builds an UNBOUNDED dissection
// (`Dissection::from_capture` takes no `DissectionLimits`), so no cap exists to
// bite. The zeros are true and are not evidence that a bounded dissection would
// report none.
//
// It moved for the reason R311y856 moved the payload decoder: the command line
// carried a strictly SMALLER selection of these figures (`packets_skipped`, the
// three stream-health counts and the two INVALID checksum counts) and could not
// reach the rest at all -- the last `debt-analysis-surface-parity` row, and the
// one direction where this ABI was the richer surface. Giving the CLI its flag
// before moving the emit would have shipped a second rendering of one value.

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

    /// A capture this reader cannot parse is a NAMED error, not a crash and
    /// not an empty success.
    ///
    /// R311y608 — the fixture is a TRUNCATED pcapng: the right magic and then
    /// nothing. Before this round the same assertion held for a perfectly good
    /// pcapng too, and the test doc said so; the reader now dispatches on the
    /// magic, so what is left here is the honest claim — a DAMAGED file still
    /// fails, and fails by code rather than by unwinding across the boundary.
    #[test]
    fn a_capture_that_cannot_be_read_is_an_error_code() {
        let mut out: *mut c_char = core::ptr::null_mut();
        let truncated = [0x0Au8, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0];
        assert_eq!(
            unsafe { wz_dissect_pcap_summary(truncated.as_ptr(), truncated.len(), &mut out) },
            WZ_DISSECT_ERR_BAD_CAPTURE
        );
        assert!(out.is_null(), "an error must not hand back a string");
    }

    /// Drive the summary the way C does.
    fn call_summary(bytes: &[u8]) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_pcap_summary(bytes.as_ptr(), bytes.len(), &mut out) };
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

    /// One Interface Statistics Block, per pcapng §4.6: block type, total
    /// length, interface id, ts_high, ts_low, options, trailing length.
    ///
    /// Hand-laid HERE rather than shared with `wz-capture`'s own fixture on
    /// purpose — a fixture the reader and the writer share proves only that
    /// they hold one belief between them, and this file's claim is that the
    /// figure survives the C boundary, which needs the figure to be real.
    fn isb_with_drops(interface_id: u32, dropped: u64) -> Vec<u8> {
        let mut opts = Vec::new();
        opts.extend_from_slice(&5u16.to_le_bytes()); // opt_isb_ifdrop
        opts.extend_from_slice(&8u16.to_le_bytes());
        opts.extend_from_slice(&dropped.to_le_bytes());
        opts.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
        opts.extend_from_slice(&0u16.to_le_bytes());

        let total = (24 + opts.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0000_0005u32.to_le_bytes()); // BT_ISB
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_low
        out.extend_from_slice(&opts);
        out.extend_from_slice(&total.to_le_bytes());
        out
    }

    /// R311y608 — THE ONE THAT MATTERS: a pcapng REACHES this ABI at all, and
    /// what the capture tool admitted losing crosses it as a number.
    ///
    /// Two defects in one assertion. The reader used to call `from_pcap`, so
    /// every pcapng — what `dumpcap` and `tshark -w` write by DEFAULT — came
    /// back `WZ_DISSECT_ERR_BAD_CAPTURE`, indistinguishable from corruption.
    /// And `capture_reported_drops` reads the ISB, which only pcapng has, so
    /// over the old entry point that counter could never be anything but
    /// absent: a C consumer had no way to learn its capture had a hole in it.
    #[test]
    fn a_pcapng_reaches_the_boundary_and_carries_its_own_drop_count() {
        let mut file = wz_capture::pcapng::write(&[(1, 6)], &[(0, 1_000_000, &[0u8; 4])]);
        file.extend_from_slice(&isb_with_drops(0, 17));

        let json = call_summary(&file).expect("a pcapng must now be readable");
        assert!(
            json.contains("\"capture_reported_drops\":17"),
            "the capture tool's own admission must cross the boundary: {json}"
        );
    }

    /// `null` and `0` are DIFFERENT answers, and the difference is the point.
    ///
    /// A classic pcap has nowhere in the format to record a drop count, so the
    /// honest report is "the file said nothing" — not "the file said none".
    /// Emitting `0` here would tell a consumer its capture was complete on the
    /// evidence of a field that cannot exist.
    #[test]
    fn a_classic_pcap_reports_no_statement_rather_than_zero_drops() {
        let file = wz_capture::pcap::write(1, &[(0, 0, &[0u8; 4])]);
        let json = call_summary(&file).expect("a classic pcap still reads");
        assert!(
            json.contains("\"capture_reported_drops\":null"),
            "silence must not be reported as a clean bill of health: {json}"
        );
        assert!(
            !json.contains("\"capture_reported_drops\":0"),
            "0 is a claim the format cannot support: {json}"
        );
    }

    /// The other two counters cross too, and a scouting datagram is COUNTED
    /// rather than leaving its flow looking empty.
    ///
    /// R311y605's `health()`, R311y606's `fragment_stats()` and R311y607's
    /// `capture_reported_drops()` had zero readers between them outside
    /// `wz-capture`'s own tests. This is the reader, and this is the assertion
    /// that it stays one — the three are named together because a measurement
    /// nobody reads cannot be told from one that is wrong.
    #[test]
    fn the_health_counters_all_cross_the_boundary() {
        let file = wz_capture::pcap::write(1, &[(0, 0, &[0u8; 4])]);
        let json = call_summary(&file).expect("reads");
        for key in [
            "\"health\"",
            "\"dropped_by_limits\"",
            "\"scout_askers\"",
            "\"fragments\"",
            "\"completed\"",
            "\"streams\"",
            "\"retransmits\"",
            "\"transport_checksum_absent\"",
        ] {
            assert!(json.contains(key), "{key} missing from the summary: {json}");
        }
    }

    /// R311y746 — the `dropped_by_limits` group this boundary emits is a group
    /// of STRUCTURAL zeros, and that is a fact about the entry point rather
    /// than about the capture.
    ///
    /// [`Dissection::from_capture`] takes `DissectionLimits::default()`, whose
    /// every field is `None` (a file ends, so keeping all of it is bounded), so
    /// no cap can bite behind this door however large the capture is. The test
    /// above satisfies itself with the KEYS being present; this one pins the
    /// reason the values under them are always zero, so a later reader does not
    /// mistake the zeros for a measurement of a healthy capture.
    ///
    /// A capture LARGER than the live-tap preset's own flow cap is what makes
    /// the point: 1 025 distinct 5-tuples would evict once under
    /// `DissectionLimits::for_live_tap`, and here they all survive.
    #[test]
    fn the_drop_group_at_this_boundary_is_structurally_zero() {
        // A framed KeepAlive: a 2-byte length prefix and the message, which is
        // what makes each packet a flow with a decodable message on it.
        let payload = [1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        // One flow past `DissectionLimits::for_live_tap().max_flows_per_table`.
        let over_tap_cap = 1_025usize;
        let packets: Vec<Vec<u8>> = (0..over_tap_cap)
            .map(|i| {
                let mut p = tcp_packet(1000, &payload);
                // The SOURCE PORT is what makes each a distinct 5-tuple, and it
                // sits at the start of the TCP header: 14 bytes of Ethernet, 20
                // of IPv4.
                let port = 20_000u16 + i as u16;
                p[34..36].copy_from_slice(&port.to_be_bytes());
                p
            })
            .collect();
        let frames: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = wz_capture::pcap::write(1, &frames);

        let json = call_summary(&file).expect("the capture reads");
        assert!(
            json.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":0,\"scout_askers\":0}"
            ),
            "an entry point that states no caps must report no bite: {json}"
        );
        // And the capture really was over the live tap's cap, or the zero above
        // would be a zero about nothing.
        assert_eq!(
            json.matches("{\"frames\":1}").count(),
            over_tap_cap,
            "every 5-tuple must have survived, or this proves nothing"
        );
    }

    /// Drive the bounded summary the way C does.
    fn call_summary_bounded(bytes: &[u8]) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_pcap_summary_bounded(bytes.as_ptr(), bytes.len(), &mut out) };
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

    /// R311y748 — AND THE BOUNDED DOOR MAKES THAT GROUP A MEASUREMENT.
    ///
    /// The pair with the test above is the point, and they are driven off ONE
    /// capture for that reason: the same bytes through the unbounded entry
    /// report five zeros and 1 025 living flows, and through the bounded one
    /// report an eviction. A single-sided assertion here would be satisfied by
    /// a library that had simply started counting something.
    #[test]
    fn the_bounded_door_reports_a_bound_that_bit() {
        let payload = [1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let over_tap_cap = 1_025usize;
        let packets: Vec<Vec<u8>> = (0..over_tap_cap)
            .map(|i| {
                let mut p = tcp_packet(1000, &payload);
                let port = 20_000u16 + i as u16;
                p[34..36].copy_from_slice(&port.to_be_bytes());
                p
            })
            .collect();
        let frames: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = wz_capture::pcap::write(1, &frames);

        let bounded = call_summary_bounded(&file).expect("the capture reads");
        assert!(
            bounded.contains("\"flows\":1"),
            "the live-tap flow cap must bite and be reported: {bounded}"
        );
        // The SAME bytes through the unbounded door, so the difference is the
        // caps and not the capture.
        let unbounded = call_summary(&file).expect("the capture reads");
        assert!(
            unbounded.contains("\"flows\":0"),
            "the unbounded door must still report no bite: {unbounded}"
        );
        assert_ne!(
            bounded, unbounded,
            "two doors that answer identically would mean the caps never reached the reader"
        );
    }

    /// A scouting exchange must not read as an empty flow.
    ///
    /// R311y607 gave a datagram flow a second list and the summary reported
    /// only the first, so a capture of a scout group — the one exchange every
    /// zenoh network has — crossed this boundary as a flow with zero messages
    /// on it.
    #[test]
    fn a_scouting_datagram_is_counted_rather_than_invisible() {
        // A SCOUT toward zenoh's group: the destination is what routes it into
        // the scouting namespace, so the packet has to be built whole.
        let mut scout = vec![wz_session_core::wire_const::S_MID_SCOUT, 0x09, 0x38];
        scout.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let pkt = udp_packet([192, 168, 1, 5], 43210, [224, 0, 0, 224], 7446, &scout);
        let file = wz_capture::pcap::write(1, &[(0, 0, pkt.as_slice())]);

        let json = call_summary(&file).expect("reads");
        assert!(
            json.contains("\"scouting\":1"),
            "the scout must be counted: {json}"
        );
    }

    /// R311y609 — a capture with a HOLE crosses this boundary as a hole.
    ///
    /// The three numbers this adds are three different witnesses to "missing",
    /// and none of them existed at this boundary before: the TCP sequence
    /// space proving bytes were sent and are absent, the observer's own
    /// admission that it lost and regained the framing, and what the sender
    /// NUMBERED. A C consumer previously saw a capture with a dropped segment
    /// as a flow that simply stopped — a dissector that looks broken instead
    /// of a capture that is incomplete.
    ///
    /// Built here rather than shared with `wz-capture`'s fixture, for the
    /// reason `isb_with_drops` is: a fixture the reader and writer share
    /// proves they hold one belief between them.
    #[test]
    fn a_capture_with_a_hole_crosses_the_boundary_as_a_hole() {
        // Small frames, chopped at a size that is not a multiple of the frame
        // size, so the missing segment splices the stream MID-FRAME.
        let mut stream = Vec::new();
        for i in 0..400u16 {
            let body = [
                wz_session_core::wire_const::T_MID_FRAME
                    | wz_session_core::wire_const::FLAG_T_FRAME_R,
                (i % 0x80) as u8,
                0x1F,
                0x00,
                0x00,
                0x00,
            ];
            stream.extend_from_slice(&(body.len() as u16).to_le_bytes());
            stream.extend_from_slice(&body);
        }
        const SEG: usize = 37;
        let packets: Vec<Vec<u8>> = stream
            .chunks(SEG)
            .enumerate()
            .filter(|(i, _)| *i != 7) // the segment the capture never recorded
            .map(|(i, seg)| tcp_packet(1000 + (i * SEG) as u32, seg))
            .collect();
        let records: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = wz_capture::pcap::write(1, &records);

        let json = call_summary(&file).expect("reads");
        assert!(
            json.contains("\"gaps_forced\":1"),
            "the sequence space proves a byte range is absent: {json}"
        );
        assert!(
            json.contains(&format!("\"gap_bytes_missing\":{SEG}")),
            "and says how many: {json}"
        );
        assert!(
            json.contains("\"desyncs\":1") && json.contains("\"recoveries\":1"),
            "the observer lost the framing on the splice and found it again: {json}"
        );
        for key in ["\"framing\"", "\"sequence\"", "\"without_resolution\""] {
            assert!(json.contains(key), "{key} missing: {json}");
        }
    }

    /// R311y611 (§1.4b) — a peer whose wire-spec vintage is not this reader's
    /// crosses the boundary as a NUMBER, not as silence.
    ///
    /// A reserved flag bit decodes without complaint — zenoh's own decoder
    /// ignores those bits and so does `parse_inbound` — so before R311y611 the
    /// only trace of it anywhere was that the stream path desynchronised, which
    /// a datagram capture never does. A differential oracle that swallows the
    /// one signal saying "this peer is not speaking your version" is worse than
    /// one that cannot read the message at all.
    #[test]
    fn a_reserved_header_bit_crosses_the_boundary_as_a_count() {
        // KEEP_ALIVE defines no flag but Z, so 0x40 is reserved. Sent on a
        // DATAGRAM, which is the path with no gate to refuse it.
        let clean = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let odd = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE | 0x40],
        );

        let control =
            call_summary(&wz_capture::pcap::write(1, &[(0, 0, clean.as_slice())])).expect("reads");
        assert!(
            control.contains("\"reserved_headers\":0"),
            "the control arm must be zero or the other arm proves nothing: {control}"
        );

        let json =
            call_summary(&wz_capture::pcap::write(1, &[(0, 0, odd.as_slice())])).expect("reads");
        assert!(
            json.contains("\"reserved_headers\":1"),
            "the bit the decoder ignored must still be counted: {json}"
        );
    }

    /// R311y612 (§4.2) — a WEBSOCKET direction that loses its frame boundary
    /// and finds it again crosses the boundary as its OWN pair of numbers.
    ///
    /// Its own, and not folded into `desyncs` / `recoveries`, because the two
    /// are losses of different framings: a zenoh-framing desync is inside a
    /// stream this reader still holds, while a ws-framing one means the message
    /// boundary itself is gone. A consumer that saw one number could not tell
    /// which had happened.
    ///
    /// The control arm is the same capture with no hole in it. Without it a
    /// `ws_desyncs` key that were hard-wired to 1 would pass.
    #[test]
    fn a_websocket_resynchronisation_crosses_the_boundary_as_a_count() {
        let upgrade = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";
        // One RFC6455 BINARY frame per bare KeepAlive — a ws message boundary
        // IS the framing, so there is no length prefix inside it.
        let ws_msg = [0x82u8, 0x01, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut stream = upgrade.to_vec();
        for _ in 0..24 {
            stream.extend_from_slice(&ws_msg);
        }

        // Segment it so a whole segment can be dropped MID-flow. The dropped
        // index must have segments after it: dropping the last one is a
        // truncated capture, not a hole, and the first version of this fixture
        // did exactly that — `gaps_forced` came back 0 and nothing was proven.
        const SEG: usize = 12;
        const DROP: usize = 5;
        let segs: Vec<&[u8]> = stream.chunks(SEG).collect();
        assert!(
            DROP + 1 < segs.len(),
            "the hole needs bytes on its far side; {} segments",
            segs.len()
        );
        let build = |drop_at: Option<usize>| -> Vec<u8> {
            let mut pkts: Vec<Vec<u8>> = Vec::new();
            for (i, seg) in segs.iter().enumerate() {
                if Some(i) == drop_at {
                    continue;
                }
                pkts.push(tcp_packet(1000 + (i * SEG) as u32, seg));
            }
            let refs: Vec<(u32, u32, &[u8])> =
                pkts.iter().map(|p| (0u32, 0u32, p.as_slice())).collect();
            wz_capture::pcap::write(1, &refs)
        };

        let control = call_summary(&build(None)).expect("reads");
        assert!(
            control.contains("\"ws_desyncs\":0") && control.contains("\"ws_recoveries\":0"),
            "the intact arm must be zero or the other proves nothing: {control}"
        );

        let json = call_summary(&build(Some(DROP))).expect("reads");
        assert!(
            json.contains("\"ws_desyncs\":1"),
            "the ws direction lost its frame boundary and must say so: {json}"
        );
        assert!(
            json.contains("\"ws_recoveries\":1"),
            "and found it again — before R311y612 the flow simply ended here \
             and every later message was reported as absent: {json}"
        );
        assert!(
            !json.contains("\"ws_resync_skipped_bytes\":0"),
            "a recovery that stepped over nothing would mean the hole was not \
             where the fixture put it: {json}"
        );
    }

    /// R311y610 (§4.2) — a capture that STOPS with the hole still open.
    ///
    /// The test above loses a segment early and has 90-odd later ones to spend
    /// the patience on. A file that ends within the patience of its hole spends
    /// nothing, and before R311y610 every byte behind that hole stayed held
    /// forever — a C consumer saw a flow that simply stopped short, with
    /// `gaps_forced` at zero saying nothing was wrong.
    ///
    /// Four segments, one lost, so the default patience is never remotely
    /// reached; only "the file ended" can release the tail.
    #[test]
    fn a_capture_that_ends_on_its_hole_still_reports_one() {
        let mut stream = Vec::new();
        for i in 0..64u16 {
            let body = [
                wz_session_core::wire_const::T_MID_FRAME
                    | wz_session_core::wire_const::FLAG_T_FRAME_R,
                (i % 0x80) as u8,
                0x1F,
                0x00,
                0x00,
                0x00,
            ];
            stream.extend_from_slice(&(body.len() as u16).to_le_bytes());
            stream.extend_from_slice(&body);
        }
        const SEG: usize = 129;
        let packets: Vec<Vec<u8>> = stream
            .chunks(SEG)
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(i, seg)| tcp_packet(1000 + (i * SEG) as u32, seg))
            .collect();
        assert!(
            packets.len() < wz_capture::tcp::DEFAULT_GAP_PATIENCE,
            "the whole point is a capture SHORTER than the patience: {} \
             segments",
            packets.len()
        );
        let records: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = wz_capture::pcap::write(1, &records);

        let json = call_summary(&file).expect("reads");
        assert!(
            json.contains("\"gaps_forced\":1")
                && json.contains(&format!("\"gap_bytes_missing\":{SEG}")),
            "the end of the file is what gives up on the gap: {json}"
        );
        assert!(
            json.contains("\"desyncs\":1") && json.contains("\"recoveries\":1"),
            "and the bytes behind it are decoded, as a discontinuity: {json}"
        );
    }

    /// Drive the census the way C does.
    fn call_census(bytes: &[u8]) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_pcap_census(bytes.as_ptr(), bytes.len(), &mut out) };
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

    const ZID_A: [u8; 4] = [0xA1; 4];
    const ZID_B: [u8; 4] = [0xB2; 4];

    /// `[T_MID_INIT, flags, cbyte, zid…]`, length-prefixed for a stream link.
    ///
    /// Hand-laid HERE rather than shared with `wz-capture`'s fixture, for the
    /// reason `isb_with_drops` above is: a fixture the reader and the writer
    /// share proves only that they hold one belief between them, and this
    /// file's claim is that a node the WIRE named crosses the C boundary.
    fn framed_init(zid: &[u8]) -> Vec<u8> {
        let mut wire = vec![
            wz_session_core::wire_const::T_MID_INIT,
            0x09,
            (((zid.len() as u8) - 1) << 4) | 0x02,
        ];
        wire.extend_from_slice(zid);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// A literal keyexpr: `id 0` in the SENDER's space plus the suffix, which
    /// resolves without a Declare having gone past before the tap started.
    fn literal(keyexpr: &'static str) -> wz_codecs::wireexpr::Wireexpr<'static> {
        wz_codecs::wireexpr::Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
                wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                },
            ),
        }
    }

    /// One `T_MID_FRAME` at `sn` carrying `records`, length-prefixed.
    fn framed_frame(sn: u8, records: &[u8]) -> Vec<u8> {
        let mut wire = vec![
            wz_session_core::wire_const::T_MID_FRAME | wz_session_core::wire_const::FLAG_T_FRAME_R,
            sn,
        ];
        wire.extend_from_slice(records);
        let mut out = (wire.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&wire);
        out
    }

    /// A capture in which every analysis plane has something to say: two nodes
    /// that named themselves, a Put on a literal key, and a query answered and
    /// closed.
    ///
    /// One packet per direction so the whole of each stream is contiguous: a
    /// reassembly gap here would look exactly like a decode that failed.
    fn census_capture() -> Vec<u8> {
        let put = framed_frame(
            0,
            &wz_codecs::push::Push {
                header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
                keyexpr: literal("demo/temp"),
                body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                    payload_len: 5,
                    payload: b"hello",
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let query = framed_frame(
            1,
            &wz_codecs::request::Request {
                header: wz_codecs::request::Request::default().header
                    | wz_codecs::wire_const::FLAG_N_N,
                rid: 7,
                keyexpr: literal("demo/q"),
                body: wz_codecs::request::RequestVariant::CodecZenohQuery(
                    wz_codecs::query::Query::default(),
                ),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut answer_records = wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header
                | wz_codecs::wire_const::FLAG_N_N,
            request_id: 7,
            keyexpr: literal("demo/q"),
            body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
                body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(
                    wz_codecs::msg_put::MsgPut {
                        payload_len: 6,
                        payload: b"answer",
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        answer_records.extend_from_slice(
            &wz_codecs::response_final::ResponseFinal {
                request_id: 7,
                ..Default::default()
            }
            .encode_to_vec(),
        );

        let mut low_to_high = framed_init(&ZID_A);
        low_to_high.extend_from_slice(&put);
        low_to_high.extend_from_slice(&query);
        let mut high_to_low = framed_init(&ZID_B);
        high_to_low.extend_from_slice(&framed_frame(0, &answer_records));

        let a = tcp_packet(1000, &low_to_high);
        let b = tcp_packet_reverse(2000, &high_to_low);
        // Distinct capture timestamps, or the exchange correlates and reports
        // `unstamped` — a row that exists and measures nothing.
        wz_capture::pcap::write(1, &[(0, 0, a.as_slice()), (0, 9_000, b.as_slice())])
    }

    /// R311y851 — THE FOUR ANALYSIS PLANES CROSS THIS BOUNDARY, AND THE SUMMARY
    /// DOOR DOES NOT CARRY THEM.
    ///
    /// The pair is the point, and both arms are driven off ONE capture for that
    /// reason. Before this round every plane `wz-capture` computes was
    /// compiled into this library and reachable only by writing Rust: a C
    /// consumer could learn how many frames a flow held and could not learn
    /// which key they carried, who sent them, or whether a query was answered.
    /// A single-sided assertion here would be satisfied by a library that had
    /// merely started emitting a bigger document.
    #[test]
    fn the_census_planes_cross_the_boundary_and_the_summary_does_not_carry_them() {
        let file = census_capture();

        let census = call_census(&file).expect("the capture reads");
        assert!(
            census.contains("\"keyexpr\":\"demo/temp\""),
            "the key the Put travelled under must cross: {census}"
        );
        assert!(
            census.contains("\"zid\":\"a1a1a1a1\"") && census.contains("\"zid\":\"b2b2b2b2\""),
            "both zids the handshake named must cross: {census}"
        );
        assert!(
            census.contains("\"requests\":1,\"completed\":1"),
            "the query and the reply that closed it must cross: {census}"
        );
        assert!(
            census.contains("\"contradictions\":[]"),
            "the payload plane must have judged rather than been skipped: {census}"
        );

        // THE CONTROL: the same bytes through the door that already existed.
        let summary = call_summary(&file).expect("the capture reads");
        for absent in [
            "demo/temp",
            "a1a1a1a1",
            "\"requests\"",
            "\"contradictions\"",
        ] {
            assert!(
                !summary.contains(absent),
                "{absent} is in the SUMMARY, so the census door is not what \
                 carried it: {summary}"
            );
        }
        // And the summary is not empty — it answers its own question, which is
        // what makes its silence about these four a scope and not a failure.
        assert!(
            summary.contains("\"health\""),
            "the summary must still be the summary: {summary}"
        );
    }

    /// Drive the narrowed census the way C does.
    fn call_census_where(bytes: &[u8], selector: &str) -> Result<String, c_int> {
        let sel = std::ffi::CString::new(selector).expect("no interior NUL");
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe {
            wz_dissect_pcap_census_where(bytes.as_ptr(), bytes.len(), sel.as_ptr(), &mut out)
        };
        if rc != WZ_DISSECT_OK {
            assert!(out.is_null(), "an error must not hand back a string");
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

    /// Drive the field layer the way C does.
    fn call_fields(bytes: &[u8], cap: usize) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_pcap_fields(bytes.as_ptr(), bytes.len(), cap, &mut out) };
        if rc != WZ_DISSECT_OK {
            assert!(out.is_null(), "an error must not hand back a string");
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

    /// R311y855 — THE FIELD LAYER CROSSES, AND THE WALK THIS HEADER DESCRIBED
    /// BECOMES POSSIBLE.
    ///
    /// `wz_dissect_pcap_summary`'s doc has told a C consumer since R311y586 to
    /// walk the flows and expand the messages it wants. It could not: the
    /// summary reports frame COUNTS, and a stream message's bytes live in the
    /// reassembled stream, which the caller does not have. The control arm here
    /// is that same summary over the same bytes — it carries neither a span nor
    /// a coordinate, so the trees are evidence about the new door.
    #[test]
    fn the_field_layer_crosses_the_boundary_and_the_summary_cannot_locate_a_message() {
        let file = census_capture();

        let fields = call_fields(&file, 0).expect("the capture reads");
        assert!(
            fields.contains("\"offset_space\":\"stream_byte\""),
            "a row must say WHICH space its number is in: {fields}"
        );
        assert!(
            fields.contains("\"message_at\":"),
            "and carry the coordinate the message begins at: {fields}"
        );
        assert!(
            fields.contains("\"fields\":{\"name\":"),
            "the TREE crosses, which is what a byte range comes from: {fields}"
        );
        // A span is a range of the message, and the tree carries them: without
        // `start`/`end` a consumer has a name and no bytes to highlight.
        assert!(
            fields.contains("\"start\":") && fields.contains("\"end\":"),
            "the spans are the point of this door: {fields}"
        );

        // THE CONTROL: the door that already existed, over the same bytes.
        let summary = call_summary(&file).expect("the capture reads");
        for absent in ["\"message_at\"", "\"offset_space\"", "\"start\""] {
            assert!(
                !summary.contains(absent),
                "{absent} is in the SUMMARY, so the field door is not what \
                 carried it: {summary}"
            );
        }
    }

    /// R311y855 — the bound is reachable from C and reports what it held back.
    #[test]
    fn the_field_bound_crosses_and_says_how_many_it_held_back() {
        let file = census_capture();
        let all = call_fields(&file, 0).expect("reads");
        assert!(
            all.contains("\"omitted\":0"),
            "0 means unbounded, matching the command line's default: {all}"
        );
        let bounded = call_fields(&file, 1).expect("reads");
        assert!(
            bounded.contains("\"shown\":1,\"omitted\":"),
            "a bounded listing shows its bound: {bounded}"
        );
        assert!(
            !bounded.contains("\"shown\":1,\"omitted\":0"),
            "and the capture really was over the bound, or this proves \
             nothing: {bounded}"
        );
    }

    /// The field door keeps the ABI's memory contract like every other.
    #[test]
    fn the_field_door_refuses_what_every_other_door_refuses() {
        let mut out: *mut c_char = core::ptr::null_mut();
        let truncated = [0x0Au8, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0];
        assert_eq!(
            unsafe { wz_dissect_pcap_fields(truncated.as_ptr(), truncated.len(), 0, &mut out) },
            WZ_DISSECT_ERR_BAD_CAPTURE
        );
        assert!(out.is_null(), "an error must not hand back a string");
        assert_eq!(
            unsafe { wz_dissect_pcap_fields(core::ptr::null(), 0, 0, &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_pcap_fields([0u8].as_ptr(), 1, 0, core::ptr::null_mut()) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
    }

    /// R311y854 — A SELECTOR CROSSES THE BOUNDARY AND NARROWS THE CENSUS, and
    /// the unfiltered door over the same bytes is the control.
    ///
    /// Before this round the only census a C consumer could ask for was the
    /// whole capture. `wz-analyze --select` has narrowed these planes since
    /// R311y616 and the linked surface had no way to say so, which is the
    /// surface delta this round is paying down.
    #[test]
    fn a_selector_crosses_the_boundary_and_narrows_what_the_census_reports() {
        let file = census_capture();

        let whole = call_census(&file).expect("the capture reads");
        assert!(
            whole.contains("\"keyexpr\":\"demo/q\""),
            "the CONTROL must carry the key the selector will reject: {whole}"
        );

        let narrowed = call_census_where(&file, "key == demo/temp").expect("the capture reads");
        assert!(
            narrowed.contains("\"keyexpr\":\"demo/temp\""),
            "the matching key must survive: {narrowed}"
        );
        assert!(
            !narrowed.contains("\"keyexpr\":\"demo/q\""),
            "the rejected key must be gone: {narrowed}"
        );
        assert!(
            narrowed.contains("\"narrowed_by_selector\":true")
                && narrowed.contains("\"narrowed_by_selector\":false"),
            "both answers must appear -- three planes narrow and the node plane \
             does not, and a consumer reads that off the document: {narrowed}"
        );
        // The node plane really is whole, which is what the `false` above is
        // about. Asserted rather than inferred from the flag.
        assert!(
            narrowed.contains("\"zid\":\"a1a1a1a1\"") && narrowed.contains("\"zid\":\"b2b2b2b2\""),
            "the node plane takes no selector: {narrowed}"
        );

        // An EMPTY selector selects everything rather than nothing.
        let empty = call_census_where(&file, "").expect("the capture reads");
        assert_eq!(
            empty, whole,
            "an empty selector must be the identity, or a caller with no filter \
             typed gets a different census from the unfiltered door"
        );
    }

    /// R311y854 — A BAD SELECTOR IS ITS OWN CODE, AND THE DIAGNOSIS SAYS WHERE.
    ///
    /// The pair is the point. The census door refuses and hands back nothing,
    /// which keeps the memory rule uniform; the diagnostic door SUCCEEDS and
    /// hands back a position, which is what a box an operator types into needs.
    /// One code with no position would make them bisect their own expression.
    #[test]
    fn a_selector_that_does_not_compile_is_refused_and_then_explained() {
        let file = census_capture();
        assert_eq!(
            call_census_where(&file, "key === demo/**"),
            Err(WZ_DISSECT_ERR_SELECTOR),
            "a malformed selector is not INVALID_ARG: the caller is fine and \
             the operator's text is not"
        );

        let mut out: *mut c_char = core::ptr::null_mut();
        let good = std::ffi::CString::new("key == demo/**").expect("no NUL");
        assert_eq!(
            unsafe { wz_dissect_selector_diagnose(good.as_ptr(), &mut out) },
            WZ_DISSECT_OK
        );
        let verdict = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("utf8")
            .to_string();
        unsafe { wz_dissect_string_free(out) };
        assert_eq!(verdict, "{\"ok\":true}");

        out = core::ptr::null_mut();
        let bad = std::ffi::CString::new("kind == frobnicate").expect("no NUL");
        assert_eq!(
            unsafe { wz_dissect_selector_diagnose(bad.as_ptr(), &mut out) },
            WZ_DISSECT_OK,
            "a refused selector is a successful DIAGNOSIS, not an error"
        );
        let verdict = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("utf8")
            .to_string();
        unsafe { wz_dissect_string_free(out) };
        assert!(
            verdict.starts_with("{\"ok\":false,\"at\":"),
            "the verdict must carry a position: {verdict}"
        );
        assert!(
            verdict.contains("frobnicate"),
            "and quote back what the operator typed: {verdict}"
        );
        // The position is a real offset into THEIR text, not a constant.
        assert!(
            !verdict.contains("\"at\":0"),
            "`kind ==` parses, so the fault is not at byte 0 -- an `at` that is \
             always 0 would point every UI at the first character: {verdict}"
        );
    }

    /// The census door keeps the ABI's memory contract: a bad capture is a
    /// CODE, nulls are refused, and neither hands back a string.
    #[test]
    fn the_census_door_refuses_what_every_other_door_refuses() {
        let mut out: *mut c_char = core::ptr::null_mut();
        let truncated = [0x0Au8, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0];
        assert_eq!(
            unsafe { wz_dissect_pcap_census(truncated.as_ptr(), truncated.len(), &mut out) },
            WZ_DISSECT_ERR_BAD_CAPTURE
        );
        assert!(out.is_null(), "an error must not hand back a string");
        assert_eq!(
            unsafe { wz_dissect_pcap_census(core::ptr::null(), 0, &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_pcap_census([0u8].as_ptr(), 1, core::ptr::null_mut()) },
            WZ_DISSECT_ERR_INVALID_ARG
        );

        // R311y854 — and so do the two doors this round added, including the
        // null SELECTOR, which is the argument neither of the others has.
        let sel = std::ffi::CString::new("").expect("no NUL");
        assert_eq!(
            unsafe { wz_dissect_pcap_census_where([0u8].as_ptr(), 1, core::ptr::null(), &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe {
                wz_dissect_pcap_census_where(
                    core::ptr::null(),
                    0,
                    sel.as_ptr(),
                    core::ptr::null_mut(),
                )
            },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_selector_diagnose(core::ptr::null(), &mut out) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            unsafe { wz_dissect_selector_diagnose(sel.as_ptr(), core::ptr::null_mut()) },
            WZ_DISSECT_ERR_INVALID_ARG
        );
    }

    /// Ethernet + IPv4 + TCP carrying `payload` at `seq`.
    fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1111u16.to_be_bytes());
        tcp.extend_from_slice(&7447u16.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(0x10); // ACK
        tcp.extend_from_slice(&64u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// The same packet the other way: addresses swapped as well as ports,
    /// which is what keeps it the SAME 5-tuple travelling in the other
    /// direction rather than a second flow.
    fn tcp_packet_reverse(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&7447u16.to_be_bytes());
        tcp.extend_from_slice(&1111u16.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(0x10); // ACK
        tcp.extend_from_slice(&64u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// Ethernet + IPv4 + UDP carrying `payload`.
    fn udp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// The version is a SYMBOL contract, not a JSON one: it exists so a
    /// consumer can refuse a library whose memory rules changed, and it must
    /// NOT move when a walker adds fields.
    #[test]
    fn the_abi_version_is_readable() {
        // R311y856 — 6 since `wz_dissect_pcap_fields_with_payloads` and
        // `wz_dissect_declarations_diagnose` joined the symbol set. The
        // header's contract is the symbol SET, not a symbol's signature; see
        // `wz_dissect_abi_version`.
        assert_eq!(wz_dissect_abi_version(), 6);
    }

    /// R311y856 — a capture carrying ONE `Put` on `demo/sensor` whose payload
    /// is the protobuf message `{ 1: 150 }`.
    ///
    /// Its own fixture rather than a widening of [`census_capture`]: that one's
    /// payloads are `b"hello"` and `b"answer"`, which are text and not any
    /// format's bytes, and a decoder run over them would be measuring the
    /// fixture rather than the door.
    fn protobuf_capture() -> Vec<u8> {
        let put = framed_frame(
            0,
            &wz_codecs::push::Push {
                header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
                keyexpr: literal("demo/sensor"),
                body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                    payload_len: 3,
                    payload: &[0x08, 0x96, 0x01],
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut low_to_high = framed_init(&ZID_A);
        low_to_high.extend_from_slice(&put);
        let packet = tcp_packet(1000, &low_to_high);
        wz_capture::pcap::write(1, &[(0, 0, packet.as_slice())])
    }

    /// Drive the field layer WITH declarations, the way C does.
    fn call_fields_with_payloads(
        bytes: &[u8],
        cap: usize,
        declarations: &str,
    ) -> Result<String, c_int> {
        let text = CString::new(declarations).expect("no interior NUL");
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe {
            wz_dissect_pcap_fields_with_payloads(
                bytes.as_ptr(),
                bytes.len(),
                cap,
                text.as_ptr(),
                &mut out,
            )
        };
        if rc != WZ_DISSECT_OK {
            assert!(out.is_null(), "an error must not hand back a string");
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

    /// Drive the declaration diagnostic the way C does.
    fn call_declarations_diagnose(declarations: &str) -> String {
        let text = CString::new(declarations).expect("no interior NUL");
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_declarations_diagnose(text.as_ptr(), &mut out) };
        assert_eq!(
            rc, WZ_DISSECT_OK,
            "a refused declaration is a successful DIAGNOSIS, not an error"
        );
        let s = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("utf8")
            .to_string();
        unsafe { wz_dissect_string_free(out) };
        s
    }

    /// R311y856 — THE PAYLOAD DECODES THROUGH THE ABI, under the declaration
    /// text a person types at the command line.
    ///
    /// # The discriminator
    ///
    /// One capture, two doors. [`wz_dissect_pcap_fields`] must carry no payload
    /// block at all and [`wz_dissect_pcap_fields_with_payloads`] must carry a
    /// decoded one, so the evidence is the DIFFERENCE: a build that decoded
    /// unconditionally passes the second half alone, and a build whose new
    /// symbol quietly ignored its declarations passes the first.
    ///
    /// The third arm is the one that matters most for a schemaless decoder. Run
    /// over a topic its rule does not cover, `Protobuf` does not fail — it
    /// produces fields. So a rule naming another topic must come back
    /// `no_rule`, carrying the keyexpr that WAS tested.
    #[test]
    fn a_declaration_reaches_the_abi_and_decodes_the_payload() {
        let file = protobuf_capture();

        let plain = call_fields(&file, 0).expect("the capture reads");
        assert!(
            !plain.contains("payload_decode"),
            "the door that declares nothing must report nothing about payloads: \
             {plain}"
        );

        let missed =
            call_fields_with_payloads(&file, 0, "other/topic=protobuf").expect("the capture reads");
        assert!(
            missed
                .contains("\"payload_decode\":{\"state\":\"no_rule\",\"keyexpr\":\"demo/sensor\"}"),
            "a rule covering no topic here must say so AND name the keyexpr it \
             was tested against: {missed}"
        );

        let decoded =
            call_fields_with_payloads(&file, 0, "demo/sensor=protobuf\ndemo/sensor:1=temperature")
                .expect("the capture reads");
        assert!(
            decoded.contains(
                "\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/sensor\",\
                 \"format\":\"protobuf\""
            ),
            "the covering rule must fire: {decoded}"
        );
        assert!(
            decoded.contains("\"path\":\"1\",\"name\":\"temperature\",\"value\":\"varint 150\""),
            "and the DECLARED name must ride the decoded field -- protobuf's \
             wire format carries none, so this is the only place one can come \
             from: {decoded}"
        );
    }

    /// R311y856 — A DECLARATION THIS BUILD CANNOT INSTALL IS REFUSED, with a
    /// code of its own and no document.
    ///
    /// The silent drop this refuses is the expensive one: a reader whose rule
    /// was discarded sees undecoded bytes and concludes the TRAFFIC is wrong.
    /// The code is separate from [`WZ_DISSECT_ERR_SELECTOR`] because a UI has
    /// two different boxes to send the operator back to.
    #[test]
    fn an_uninstallable_declaration_is_refused_rather_than_dropped() {
        let file = protobuf_capture();
        assert_eq!(
            call_fields_with_payloads(&file, 0, "demo/sensor=protobufff"),
            Err(WZ_DISSECT_ERR_DECLARATION),
            "an unknown format name is its own refusal, not an invalid argument"
        );
        assert_eq!(
            call_fields_with_payloads(&file, 0, "not a declaration"),
            Err(WZ_DISSECT_ERR_DECLARATION),
            "and so is a line that is not a declaration at all"
        );
        // An EMPTY text declares nothing and is not an error -- it is the same
        // question `wz_dissect_pcap_fields` answers, which is what makes the
        // new door a widening rather than a second mode.
        let empty =
            call_fields_with_payloads(&file, 0, "").expect("an empty text declares nothing");
        assert!(
            !empty.contains("payload_decode"),
            "an empty declaration text must behave as no declarations: {empty}"
        );
    }

    /// R311y856 — THE DIAGNOSTIC ANSWERS WITHOUT A CAPTURE, and names the LINE.
    ///
    /// The half a UI needs while the text is being typed. A consumer told only
    /// "one of these is bad" makes the operator bisect their own configuration,
    /// which is the failure R311y854 named for the selector.
    #[test]
    fn the_declaration_diagnostic_names_the_line_and_needs_no_capture() {
        assert_eq!(
            call_declarations_diagnose("demo/**=protobuf\ndemo/**:1=temperature"),
            "{\"ok\":true,\"installed\":2}"
        );

        // The SECOND line is the bad one, and the verdict must say so: an index
        // that always reported 0 would look right on every single-line text,
        // which is the shape a count in this workspace has been caught by
        // before.
        let verdict = call_declarations_diagnose("demo/**=protobuf\nnot a declaration");
        assert!(
            verdict.starts_with("{\"ok\":false,\"line\":1,\"text\":\"not a declaration\""),
            "the verdict must point at the offending line and quote it: {verdict}"
        );
        assert!(
            verdict.contains("is not a declaration -- expected"),
            "and say what a declaration looks like: {verdict}"
        );

        // The other refusal a reader meets, and it is a DIFFERENT message: the
        // line parsed and named a decoder this build does not carry.
        let unknown = call_declarations_diagnose("demo/**=protobufff");
        assert!(
            unknown.contains("this build has no decoder named `protobufff`")
                && unknown.contains("protobuf"),
            "an unknown format must be told apart from a malformed line, and \
             say what IS available: {unknown}"
        );
    }
}
