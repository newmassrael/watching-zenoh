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

/// R311y887 — read with no ceilings at all, which is what a FILE deserves: it
/// ends, so keeping every byte of it is already bounded.
///
/// Zero on purpose. A caller that zero-initialises its argument struct gets the
/// behaviour every door here had before presets existed, which is the only
/// default that cannot surprise one.
pub const WZ_DISSECT_LIMITS_NONE: c_int = 0;
/// R311y887 — `DissectionLimits::for_live_tap`, this tree's one bounded
/// configuration, for a caller reading a LINK rather than a file.
///
/// A named preset and not a struct, for the reason
/// [`wz_dissect_pcap_summary_bounded`]'s doc gives: a struct across this
/// boundary freezes nine fields' layout into the ABI, so the next axis
/// `DissectionLimits` grows becomes a break rather than an edit. An integer
/// grows by gaining VALUES, which no consumer has to be recompiled for.
pub const WZ_DISSECT_LIMITS_LIVE_TAP: c_int = 1;

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
/// R311y885 — 6 → 7, ADDING [`wz_dissect_pcap_census_bounded`]. The census
/// DOCUMENT also gained a `dropped_by_limits` group in the same round, and that
/// half moves nothing here on purpose: `wz_dissect.h` says a consumer reads the
/// document BY NAME and tolerates unknown keys, so a new key is the widening
/// that contract exists to permit. The symbol is what a consumer cannot
/// discover by reading, and the symbol is why this number moves.
///
/// R311y887 — 7 → 8, ADDING [`wz_dissect_pcap_census_where_limited`]. The
/// [`WZ_DISSECT_LIMITS_NONE`] / [`WZ_DISSECT_LIMITS_LIVE_TAP`] constants arrive
/// with it and move nothing further: a constant is a value a consumer compiles
/// in, not a symbol it links, and this revision answers "does this library have
/// it?" about the door that reads them.
///
/// R311y913 (unregistered item 435) — 8 → 9, ADDING
/// [`wz_dissect_readable_surfaces`]. A new symbol, so the revision moves under
/// the rule this doc already states.
///
/// # Safety
/// None; takes no arguments and touches no memory.
#[no_mangle]
pub extern "C" fn wz_dissect_abi_version() -> c_int {
    9
}

/// R311y913 (unregistered item 435) — WHAT THIS BUILD CAN READ, as a document.
///
/// # The asymmetry this ends
///
/// `wz-analyze --help` has answered two questions for a while: which pcap link
/// types this build decodes (`LINK TYPES READ`) and which extension bodies it
/// OPENS rather than rendering as `value` (`EXT BODIES READ`). The surface a
/// product LINKS could answer neither, and `analysis_surface_parity.py` was
/// blind to the gap because a help SECTION is neither a flag nor a symbol —
/// R311y912 gave that gate the axis that made this countable, and this is the
/// half it counted as missing.
///
/// Both questions matter to a consumer for the same reason: an unread capture
/// reports `messages decoded: 0`, and so does a capture with no zenoh traffic
/// in it. A UI that cannot tell those apart cannot tell its operator to
/// re-capture, and an extension body this build does not open goes out as
/// `value` — raw bytes — which reads exactly like "there was no structure
/// here".
///
/// # DERIVED, not restated
///
/// The lists come from `wz_capture::link::readable_link_types_line` and
/// `wz_session_core::dissect::readable_ext_bodies_line`, which are driven by
/// the link-type match and the two body dispatches themselves. So this door,
/// the help text and the dispatch are ONE fact: a body that gains a walker
/// appears in all three on the commit that adds it. A hand-written list here
/// would have been the third copy of something that already has two, which is
/// the failure this whole family of self-reports keeps being caught by.
///
/// # The document
///
/// ```json
/// {"link_types":"0 NULL, 1 ETHERNET, …",
///  "ext_bodies":{"zbuf":"Auth/pubkey, …","z64":"Declare/node_id, …"}}
/// ```
///
/// Strings rather than arrays, and deliberately: they are the SAME strings the
/// command line prints, so a consumer rendering them beside a capture shows
/// what a person reading `--help` would see. A consumer wanting them split has
/// one separator to apply and cannot be shown a different answer than the
/// terminal gives.
///
/// Takes no capture: this is a property of the LIBRARY, not of a file, which is
/// why it is worth asking before a capture is opened.
///
/// # Safety
/// `out` must be a writable pointer to a `*mut c_char` and must not be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_readable_surfaces(out: *mut *mut c_char) -> c_int {
    if out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    let mut s = String::from("{\"link_types\":");
    wz_session_core::json::escape_into(&wz_capture::link::readable_link_types_line(), &mut s);
    s.push_str(",\"ext_bodies\":{\"zbuf\":");
    wz_session_core::json::escape_into(
        &wz_session_core::dissect::readable_ext_bodies_line(
            wz_session_core::ext_header::EXT_ENC_ZBUF,
        ),
        &mut s,
    );
    s.push_str(",\"z64\":");
    wz_session_core::json::escape_into(
        &wz_session_core::dissect::readable_ext_bodies_line(
            wz_session_core::ext_header::EXT_ENC_Z64,
        ),
        &mut s,
    );
    s.push_str("}}");
    write_string(s, out)
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

/// R311y885 — the ANALYSIS PLANES under the live-tap ceilings, which is the
/// combination a tap actually needs and the one no door reached.
///
/// # The gap this closes, and why it was invisible
///
/// R311y748 gave the ABI a bounded SUMMARY, and the round after it the parity
/// table recorded "reading under the live-tap bounds" as a capability both
/// surfaces reach. Both statements are true and neither covers this: the
/// summary is the TRANSPORT answer, and a consumer that wants to know which
/// keys carry the traffic calls [`wz_dissect_pcap_census`], whose doc says
/// UNBOUNDED in as many words. So a framework tapping a live link could bound
/// the one document it did not need and had no way to bound the one it did —
/// the census walk builds five planes over a `Dissection` whose every limit is
/// `None`, on a stream that does not end.
///
/// That is the same shape as the gap R311y851 closed (a capability compiled
/// into the library with no symbol to reach it), one layer in: the BOUND was
/// compiled in, `Dissection::from_capture_bounded` is the same constructor the
/// summary door already calls, and only this entry point was missing.
///
/// # It is never silent about what the bound cost
///
/// The census document carries `dropped_by_limits` as of this round — the same
/// group `wz_dissect_pcap_summary` renders, from the same emitter — so a plane
/// short by an evicted flow is read as short-and-why rather than as a quiet
/// network. A bounded door whose output could not say what it dropped would be
/// the structural-zero defect R311y746 pinned, inverted.
///
/// # A NAMED PRESET, on the argument [`wz_dissect_pcap_summary_bounded`] makes
///
/// `DissectionLimits::for_live_tap`, not a limits struct: this ABI hands back
/// documents rather than taking struct trees, and freezing nine fields' layout
/// into the boundary would make the next axis `DissectionLimits` grows an ABI
/// break instead of a preset edit.
///
/// The RESIDUE, stated rather than hidden: the preset is the only bound on
/// offer here, and [`wz_dissect_pcap_census_where`] — the selector door — is
/// still unbounded. Both are carried, not fixed by improvisation.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes and `out` must be a
/// writable pointer to a `*mut c_char`. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_census_bounded(
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
/// `decoded`, `refused`, `encoding_mismatch`, `no_rule`, `keyexpr_unresolved`
/// or `no_payload`. The last three are ANSWERS and not omissions: a rule that
/// never fired and a rule that fired and found nothing send a reader to
/// opposite places, and `keyexpr_unresolved` is the ordinary shape of a capture
/// that began after the declarations went past. A `decoded` field's `start` /
/// `end` are in the MESSAGE's coordinate space, like every other span on the
/// row.
///
/// R311y873 — `encoding_mismatch` is the sample's OWN declared encoding
/// disagreeing with the rule, and it carries `declared` rather than `why`. Told
/// apart from `refused` because the two send a reader to opposite places: that
/// one says the bytes are not this format, this one says the bytes are exactly
/// what their publisher said and the MAPPING is wrong. A consumer that folded
/// the two would send an operator to a wire with nothing to answer for.
///
/// R311y874 — a `decoded` block additionally carries `despite_encoding`: the
/// name the publisher declared when the rule was applied OVER that declaration,
/// and `null` on an ordinary decode. It is non-null exactly where the
/// publisher's own bytes refute its own label — the operator's rule was right
/// and the topic is mislabelled — because a declaration this reader can prove
/// false must not veto the rule. Always present, never omitted: a consumer that
/// had to test for the key would read its absence as "nothing was overridden",
/// which is the assumption the field exists to stop.
///
/// R311y875 — the document additionally carries `payload_mapping`, a top-level
/// array summarising what the rules MET. Both findings above are per message,
/// and a capture where one mapping is wrong for every sample on a topic reports
/// it once per row — in the listing a caller bounds because it is that long.
/// Each entry is one (`keyexpr`, `format`, `declared`) triple with `samples`,
/// and `wrong` names the side to fix: `rule` where the publisher's declaration
/// contradicts the decoder AND its bytes bear that out, `publisher` where its
/// own bytes refute the declaration and the rule was applied over it. `note`
/// carries the same sentence the command line prints. Always present, empty
/// when nothing is misbound. The tally counts the messages this listing WALKED,
/// so `max_messages_per_flow` bounds it too and each flow's `omitted` is what
/// makes that legible; see `wz_capture::payload_decode::Declarations`.
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

/// R311y887 — the CENSUS with both axes as ARGUMENTS, which is the answer to
/// the shape question R311y885 left open rather than one more twin.
///
/// # The doubling this stops
///
/// Boundedness is orthogonal to every other thing a read door varies. R311y748
/// gave the summary a `_bounded` twin and R311y885 gave the census one, and the
/// residue that round recorded was that the next document needing a bound would
/// take the door count to eight, then sixteen: a twin per document times a twin
/// per selector. The combination this call adds — a NARROWED census under a
/// ceiling — was the pair that would have been added next, and adding it as a
/// twin would have settled the pattern by repeating it.
///
/// So the preset is a PARAMETER. Not the limits struct the sibling doors'
/// docs refuse — [`WZ_DISSECT_LIMITS_NONE`] and [`WZ_DISSECT_LIMITS_LIVE_TAP`]
/// are small integers, so a preset added later is a new VALUE and not a new
/// field, and nothing about the boundary's layout moves. An unknown value is
/// [`WZ_DISSECT_ERR_INVALID_ARG`] and never a silent fallback to unbounded,
/// which is the one way a caller could believe it had asked for a ceiling and
/// not have one.
///
/// # It subsumes the three census doors and replaces none of them
///
/// An EMPTY selector selects everything, so `("", NONE)` is
/// [`wz_dissect_pcap_census`], `("", LIVE_TAP)` is
/// [`wz_dissect_pcap_census_bounded`] and `(expr, NONE)` is
/// [`wz_dissect_pcap_census_where`]. Those three stay exported: a symbol this
/// ABI has published is a symbol a consumer links, and the memory rule says
/// nothing about symbols going away because they never do. What changes is
/// that the FOURTH combination did not need a fourth name, and the fifth will
/// not need a fifth.
///
/// # Never silent about what the ceiling cost
///
/// The census document carries `dropped_by_limits` (R311y885), from the same
/// emitter the summary's health group uses, so a plane made short by an evicted
/// flow is read as short-and-why rather than as a quiet network. That property
/// is a RULE across the bounded doors now, not three separate habits, and
/// `scripts/lib/bounded_output_parity.py` is what holds it.
///
/// # Safety
/// `bytes` must point to at least `len` readable bytes, `selector` must be a
/// NUL-terminated C string, and `out` must be a writable pointer to a
/// `*mut c_char`. None may be null.
#[no_mangle]
pub unsafe extern "C" fn wz_dissect_pcap_census_where_limited(
    bytes: *const u8,
    len: usize,
    selector: *const c_char,
    limits: c_int,
    out: *mut *mut c_char,
) -> c_int {
    if bytes.is_null() || selector.is_null() || out.is_null() {
        return WZ_DISSECT_ERR_INVALID_ARG;
    }
    let preset = match limits {
        WZ_DISSECT_LIMITS_NONE => wz_capture::DissectionLimits::default(),
        WZ_DISSECT_LIMITS_LIVE_TAP => wz_capture::DissectionLimits::for_live_tap(),
        // Refused rather than defaulted. A caller that asked for a preset this
        // build does not have wants to know, and the failure mode of the other
        // choice is a consumer that believes its memory is bounded.
        _ => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    // SAFETY: caller contract above.
    let expr = match unsafe { std::ffi::CStr::from_ptr(selector) }.to_str() {
        Ok(s) => s,
        Err(_) => return WZ_DISSECT_ERR_INVALID_ARG,
    };
    let filter = match wz_capture::filter::Filter::parse(expr) {
        Ok(f) => f,
        Err(_) => return WZ_DISSECT_ERR_SELECTOR,
    };
    // SAFETY: caller contract above.
    let input = unsafe { core::slice::from_raw_parts(bytes, len) };
    // ONE constructor for both presets: `DissectionLimits::default()` is every
    // field `None`, so the unbounded arm is the bounded call with no ceilings
    // rather than a second code path that could drift from it.
    let dissection = match Dissection::from_capture_bounded(input, preset) {
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

    /// R311y873 — THE HEADER NAMES EVERY `payload_decode` STATE THE LIBRARY
    /// CAN EMIT.
    ///
    /// # Why a test and not a review
    ///
    /// The vocabulary is written out in prose twice — this crate's rustdoc and
    /// `wz_dissect.h` — and both lists said "one of five" for the whole round
    /// in which a sixth was added. Nothing failed: a `state` word is a string
    /// in a JSON document, so a header that names five of six compiles, links,
    /// passes every ABI test, and tells a C consumer that a state they will
    /// receive does not exist. This is the header half of what
    /// `PayloadDecoding::STATES` made holdable at all.
    ///
    /// The HEADER and not the rustdoc, and the asymmetry is deliberate: the
    /// header is what a linking product reads and the only one of the two that
    /// ships. `include_str!` rather than a path opened at runtime, so the file
    /// this asserts about is the one compiled into this build.
    ///
    /// # The one exclusion, and why it is not a skip
    ///
    /// `no_rules` is a state of the TYPE that no document carries, because
    /// `fields_json` folds an empty map to `None` before any row is rendered.
    /// The gate found that on its first run and this round settled it by
    /// running the boundary, not by reading the fold. The exclusion is held by
    /// `no_rules_never_reaches_a_document_so_the_header_need_not_name_it` —
    /// remove that fold and the pair reds, which is what a bare skip here would
    /// have cost.
    #[test]
    fn the_header_names_every_payload_decode_state() {
        const HEADER: &str = include_str!("../include/wz_dissect.h");
        const NEVER_EMITTED: &str = "no_rules";
        let emitted: Vec<&str> = wz_capture::payload_decode::PayloadDecoding::STATES
            .iter()
            .copied()
            .filter(|s| *s != NEVER_EMITTED)
            .collect();
        assert!(
            emitted.len() + 1 == wz_capture::payload_decode::PayloadDecoding::STATES.len(),
            "the exclusion must name a state that EXISTS, or this gate is \
             quietly running over the whole set minus nothing"
        );
        for state in emitted {
            assert!(
                HEADER.contains(state),
                "wz_dissect.h never names the `{state}` state, which this \
                 library emits -- a C consumer branching on the header's list \
                 would fall through on traffic that produces it"
            );
        }
    }

    /// R311y875 — THE HEADER NAMES EVERY `payload_mapping` VERDICT TOO, and it
    /// gets the gate in the round the vocabulary is introduced.
    ///
    /// The sibling above exists because a vocabulary written out in prose twice
    /// drifted for a whole round without anything failing. That lesson costs
    /// nothing to apply forwards, so this word set arrives already held: a third
    /// verdict added later cannot reach a C consumer without appearing in the
    /// header a linking product reads.
    ///
    /// No exclusion here, and that is a claim rather than an omission — both
    /// verdicts are emitted by `push_misbinding` unconditionally, so any word
    /// this set holds is a word a document can carry.
    #[test]
    fn the_header_names_every_misbound_verdict() {
        const HEADER: &str = include_str!("../include/wz_dissect.h");
        for verdict in wz_capture::payload_decode::Misbound::NAMES {
            assert!(
                HEADER.contains(&format!("`{verdict}`")),
                "wz_dissect.h never names the `{verdict}` verdict, which this \
                 library emits in payload_mapping -- a C consumer branching on \
                 the header's list would fall through on a real finding"
            );
        }
    }

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
        let file = capture_one_flow_past_the_tap_cap();

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
            OVER_TAP_CAP,
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
    ///
    /// R311y885 — the bounded arm now pins the WHOLE group rather than one key
    /// from it, on this repo's own verdict-assertion rule: a `contains` of
    /// `"flows":1` is satisfied by a group that also started reporting drops on
    /// four other axes, and it cannot see a rule that WIDENED. Pinning the set
    /// also settles a claim written about this door and never measured — that
    /// the drop counters reach only the UNBOUNDED summary — which the exact
    /// string below refutes.
    #[test]
    fn the_bounded_door_reports_a_bound_that_bit() {
        let file = capture_one_flow_past_the_tap_cap();

        let bounded = call_summary_bounded(&file).expect("the capture reads");
        assert!(
            bounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":1,\"scout_askers\":0}"
            ),
            "the live-tap flow cap must bite and be reported, on that axis \
             ALONE: {bounded}"
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

    /// Drive the BOUNDED census the way C does.
    fn call_census_bounded(bytes: &[u8]) -> Result<String, c_int> {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_pcap_census_bounded(bytes.as_ptr(), bytes.len(), &mut out) };
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

    /// One flow past `DissectionLimits::for_live_tap().max_flows_per_table`,
    /// which is the count that makes a bound observable at all.
    ///
    /// R311y885 — named ONCE. Three tests here need "a capture the live-tap cap
    /// bites", and the number had been retyped beside each fixture; a preset
    /// whose ceiling moves would have left the copies asserting about a capture
    /// that no longer crosses it, each one still green.
    const OVER_TAP_CAP: usize = 1_025;

    /// A capture with [`OVER_TAP_CAP`] distinct 5-tuples on it.
    ///
    /// R311y885 — ONE fixture for the summary pair and the census pair, so the
    /// two documents are compared over the same bytes rather than over two
    /// hand-laid captures that are equal until one of them is edited. A framed
    /// KeepAlive per packet, distinguished by SOURCE PORT, which sits 14 bytes
    /// of Ethernet and 20 of IPv4 in.
    fn capture_one_flow_past_the_tap_cap() -> Vec<u8> {
        // A framed KeepAlive: a 2-byte length prefix and the message, which is
        // what makes each packet a flow with a decodable message on it.
        let payload = [1u8, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let packets: Vec<Vec<u8>> = (0..OVER_TAP_CAP)
            .map(|i| {
                let mut p = tcp_packet(1000, &payload);
                // R311y886 — the byte overwritten is inside what the TCP sum
                // covers, so the edit and the refill are ONE call. This is the
                // second shape of open-debt item 357 and the sharper one: the
                // builder was fixed, every packet still read as corrupt, and
                // the reason was here. R311y888 measured three more sites of
                // the same shape in `wz-capture` and moved the offset
                // arithmetic behind `set_tcp_source_port`, which reads the
                // addresses and the datagram length out of the frame itself.
                wz_packet_fixtures::set_tcp_source_port(&mut p, 20_000u16 + i as u16);
                p
            })
            .collect();
        let frames: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        wz_capture::pcap::write(1, &frames)
    }

    /// R311y885 — THE CENSUS DOCUMENT SAYS WHAT THE WALK UNDER IT LOST, and
    /// through the bounded door that statement is a measurement.
    ///
    /// # What this is a discriminator for
    ///
    /// Two defects at once, and they are separable, so both arms are pinned off
    /// ONE capture:
    ///
    /// * the census document carried no `dropped_by_limits` group at all, so a
    ///   plane short by an evicted flow read exactly like a quiet network;
    /// * there was no door to bound a census with, so the group would have been
    ///   a structural zero even once it existed — the defect R311y746 pinned
    ///   for the summary, arriving one document later.
    ///
    /// A single-sided assertion would be satisfied by a library that had merely
    /// started printing a group of zeros, which is why the unbounded arm asserts
    /// the WHOLE group rather than a key from it.
    #[test]
    fn the_census_reports_what_its_caps_cost() {
        let file = capture_one_flow_past_the_tap_cap();

        let unbounded = call_census(&file).expect("the capture reads");
        assert!(
            unbounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":0,\"scout_askers\":0}"
            ),
            "the unbounded census must carry the group and report no bite: {unbounded}"
        );

        let bounded = call_census_bounded(&file).expect("the capture reads");
        assert!(
            bounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":1,\"scout_askers\":0}"
            ),
            "the live-tap flow cap must bite and the census must say so: {bounded}"
        );
        assert_ne!(
            bounded, unbounded,
            "two doors that answer identically would mean the caps never reached the walk"
        );
    }

    /// Drive the LIMITED census the way C does.
    fn call_census_where_limited(
        bytes: &[u8],
        selector: &str,
        limits: c_int,
    ) -> Result<String, c_int> {
        let sel = std::ffi::CString::new(selector).expect("no interior NUL");
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe {
            wz_dissect_pcap_census_where_limited(
                bytes.as_ptr(),
                bytes.len(),
                sel.as_ptr(),
                limits,
                &mut out,
            )
        };
        if rc != WZ_DISSECT_OK {
            assert!(out.is_null(), "an error must hand back no string");
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

    /// R311y887 (open-debt item 360) — THE PARAMETERISED DOOR ANSWERS EXACTLY
    /// WHAT THE THREE NAMED ONES DO, which is the claim that stops the doubling.
    ///
    /// # Why equality and not "it works"
    ///
    /// The argument for a preset ARGUMENT over a `_bounded` twin per document
    /// is that the twins are special cases of it. If that is true, the fourth
    /// combination needs no fourth name and the fifth needs no fifth; if it is
    /// merely nearly true, this ABI has grown a second answer to a question it
    /// already answered, which is worse than the doubling it was meant to
    /// avoid. So the arms are compared BYTE FOR BYTE against the doors they
    /// claim to subsume, off one capture the live-tap ceiling actually bites.
    #[test]
    fn the_limited_door_subsumes_the_three_named_census_doors() {
        let file = capture_one_flow_past_the_tap_cap();

        assert_eq!(
            call_census_where_limited(&file, "", WZ_DISSECT_LIMITS_NONE).expect("reads"),
            call_census(&file).expect("reads"),
            "an empty selector with no ceiling IS the plain census door"
        );
        assert_eq!(
            call_census_where_limited(&file, "", WZ_DISSECT_LIMITS_LIVE_TAP).expect("reads"),
            call_census_bounded(&file).expect("reads"),
            "an empty selector under the live tap IS the bounded census door"
        );
        assert_eq!(
            call_census_where_limited(&file, "kind == put", WZ_DISSECT_LIMITS_NONE).expect("reads"),
            call_census_where(&file, "kind == put").expect("reads"),
            "a selector with no ceiling IS the narrowed census door"
        );
    }

    /// R311y887 (open-debt item 360) — and the FOURTH combination, which is the
    /// one no door reached: a narrowed census under a ceiling.
    ///
    /// Both arms off one capture, because a door that ignored its preset would
    /// pass a single-sided assertion. The selector is held constant across
    /// them, so the difference is the ceiling and not the narrowing.
    #[test]
    fn a_narrowed_census_can_be_bounded_and_says_what_the_bound_cost() {
        let file = capture_one_flow_past_the_tap_cap();
        let sel = "kind == put";

        let bounded = call_census_where_limited(&file, sel, WZ_DISSECT_LIMITS_LIVE_TAP)
            .expect("the capture reads");
        assert!(
            bounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":1,\"scout_askers\":0}"
            ),
            "the ceiling must bite and the narrowed document must say so: {bounded}"
        );
        let unbounded =
            call_census_where_limited(&file, sel, WZ_DISSECT_LIMITS_NONE).expect("reads");
        assert!(
            unbounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":0,\"scout_askers\":0}"
            ),
            "and the same selector with no ceiling must report no bite: {unbounded}"
        );
    }

    /// R311y887 — an UNKNOWN preset is refused, and refused with the code that
    /// means "the caller has a bug".
    ///
    /// The alternative a door like this usually ships with is a silent fall
    /// back to the zero value, and that failure mode is the reason this arm
    /// exists: a consumer that passed a preset a newer build understands would
    /// be handed an UNBOUNDED read while believing its memory was capped, and
    /// nothing in the document it got back would say otherwise.
    #[test]
    fn an_unknown_limit_preset_is_refused_rather_than_defaulted() {
        let file = capture_one_flow_past_the_tap_cap();
        for bad in [2, -1, i32::MAX] {
            assert_eq!(
                call_census_where_limited(&file, "", bad),
                Err(WZ_DISSECT_ERR_INVALID_ARG),
                "preset {bad} must be refused, not read as unbounded"
            );
        }
        // And the two it DOES know are not refused, or the arm above would pass
        // for a door that refuses everything.
        assert!(call_census_where_limited(&file, "", WZ_DISSECT_LIMITS_NONE).is_ok());
        assert!(call_census_where_limited(&file, "", WZ_DISSECT_LIMITS_LIVE_TAP).is_ok());
    }

    /// R311y887 — a bad selector keeps its OWN code through this door too.
    ///
    /// The preset argument sits between the selector and the output, and an
    /// implementation that validated it first would answer INVALID_ARG for text
    /// a person typed — sending a UI to the wrong box.
    #[test]
    fn a_bad_selector_through_the_limited_door_is_still_a_selector_error() {
        let file = capture_one_flow_past_the_tap_cap();
        assert_eq!(
            call_census_where_limited(&file, "key ==", WZ_DISSECT_LIMITS_LIVE_TAP),
            Err(WZ_DISSECT_ERR_SELECTOR),
            "a selector that does not compile is not an invalid argument"
        );
    }

    /// R311y886 (open-debt item 357) — THIS FILE'S OWN FIXTURES BUILD A HEALTHY
    /// CAPTURE, on both checksum axes.
    ///
    /// # Why a test about the fixtures and not about the library
    ///
    /// `tcp_packet` here wrote a ZERO into the IPv4 and TCP checksum fields.
    /// Over IPv4 that is not absence — neither protocol has a declining form —
    /// so `wz-capture` counted every packet this file has ever built as
    /// present-and-wrong, and every capture assembled from them sat whole in
    /// the corruption bucket. Nothing went red because nothing in this file
    /// asserted on those counters; the cost lands on the NEXT test that does,
    /// which fails for a reason that has nothing to do with what it is testing.
    /// R311y884 paid exactly that cost in `wz-capture` and could not close its
    /// item until the corpus could express a healthy capture at all.
    ///
    /// # It is a control, so it is asserted where the corpus is
    ///
    /// A fixture is not "correct" in the abstract; it is correct against the
    /// reader that will read it. Both counts come from the same summary
    /// document every other test in this file drives, so a change to the
    /// builder or to the verifier moves this arm.
    #[test]
    fn the_fixtures_this_file_builds_are_checksum_clean() {
        let file = capture_one_flow_past_the_tap_cap();
        let json = call_summary(&file).expect("the capture reads");
        assert!(
            json.contains("\"ip_checksum_invalid\":0")
                && json.contains("\"transport_checksum_invalid\":0"),
            "a fixture that ships a wrong checksum makes every capture it \
             builds read as corrupt: {json}"
        );
        // And the reader really looked, or the zeros above are about nothing.
        assert!(
            !json.contains("\"ip_checksum_valid\":0")
                && !json.contains("\"transport_checksum_valid\":0"),
            "both axes must have VERIFIED something, or this proves only that \
             nothing was checked: {json}"
        );
    }

    /// R311y885 — and the bounded census is still a CENSUS: every plane key is
    /// there.
    ///
    /// Separate from the pair above because the two failures are different. A
    /// door that bounded correctly and returned the summary document would pass
    /// that test — `dropped_by_limits` is in both — and would have silently
    /// swapped what a consumer asked for.
    #[test]
    fn the_bounded_census_is_a_census() {
        let bounded =
            call_census_bounded(&capture_one_flow_past_the_tap_cap()).expect("the capture reads");
        for key in [
            "\"keyexprs\":",
            "\"nodes\":",
            "\"exchanges\":",
            "\"payloads\":",
            "\"interests\":",
        ] {
            assert!(
                bounded.contains(key),
                "{key} missing from the bounded census: {bounded}"
            );
        }
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
        // R311y869 — the CONTROL plane, so the interest plane has something to
        // read. Built by the production declare builder, and placed ahead of
        // the traffic as it is on a real session.
        let declare = framed_frame(
            0,
            &wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("demo/**"))
                .expect("the production subscriber builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec(),
        );
        let put = framed_frame(
            1,
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
            2,
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

        // R311y870 — the QUESTION, and one NOBODY ANSWERS: A asks B for its
        // subscribers and B declares nothing at all. That is the finding this
        // door could not carry before, and it needs to cross as such.
        let interest = framed_frame(
            3,
            &wz_session_core::interest_build::build_interest_subscribers(
                9,
                true,
                false,
                0,
                Some("demo/**"),
            )
            .expect("the production interest builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec(),
        );

        let mut low_to_high = framed_init(&ZID_A);
        low_to_high.extend_from_slice(&declare);
        low_to_high.extend_from_slice(&put);
        low_to_high.extend_from_slice(&query);
        low_to_high.extend_from_slice(&interest);
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
        // R311y869 — the FIFTH plane, and the one this door was claimed to
        // reach the moment `analysis_surface_parity.py` gained its row. The
        // claim is checked here rather than trusted: a table saying a
        // capability is on both surfaces is worth exactly what the surface's
        // own test proves.
        assert!(
            census.contains(
                "\"kind\":\"subscriber\",\"declarer\":\"a\",\"id\":1,\
                             \"keyexpr\":\"demo/**\""
            ),
            "the declaration the capture carried must cross: {census}"
        );
        assert!(
            census.contains("\"unclaimed\":[]") && census.contains("\"unclaimed_exact\":true"),
            "and so must the coverage joining it to the keys above: {census}"
        );
        // R311y870 — and the QUESTION half of that plane, which is a different
        // fold rather than one more field: the request, and the finding that
        // nothing answered it.
        assert!(
            census.contains("\"asker\":\"a\",\"id\":9,\"mode\":\"current\",\"answers\":0"),
            "the interest must cross: {census}"
        );
        assert!(
            census.contains("\"unanswered\":[0]"),
            "and so must the finding: {census}"
        );

        // THE CONTROL: the same bytes through the door that already existed.
        let summary = call_summary(&file).expect("the capture reads");
        for absent in [
            "demo/temp",
            "a1a1a1a1",
            "\"requests\"",
            "\"contradictions\"",
            "\"declarer\"",
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
    ///
    /// R311y886 (open-debt item 357) — WITH REAL CHECKSUMS. They used to be
    /// left zero, and over IPv4 a zero is not absence: neither IPv4 nor TCP has
    /// a declining form, so `wz-capture` counted every packet this built as
    /// present-and-wrong. Measured before the fix, a 1 025-packet capture from
    /// here reported `ip_checksum_invalid: 1025` and
    /// `transport_checksum_invalid: 1025` with zero valid on either axis.
    /// `the_fixtures_this_file_builds_are_checksum_clean` is what keeps it.
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
        wz_packet_fixtures::fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut tcp);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        wz_packet_fixtures::fill_ipv4_checksum(&mut ip);
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
        wz_packet_fixtures::fill_tcp_checksum([10, 0, 0, 2], [10, 0, 0, 1], &mut tcp);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        wz_packet_fixtures::fill_ipv4_checksum(&mut ip);
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
    ///
    /// R311y886 — the IPv4 checksum is REAL and the UDP one is deliberately
    /// left zero, and the difference is the point. RFC 768 lets an IPv4 sender
    /// decline the UDP checksum by writing zero, so this fixture is a sender
    /// that declined and `wz-capture` reads it as ABSENT; IPv4 has no such
    /// form, so a zero there was simply wrong. Keeping one of each is what lets
    /// `the_fixtures_this_file_builds_are_checksum_clean` mean "no INVALID"
    /// rather than "nothing was ever checked".
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
        wz_packet_fixtures::fill_ipv4_checksum(&mut ip);
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
        // R311y887 — 8 since `wz_dissect_pcap_census_where_limited` joined the
        // symbol set. The two `WZ_DISSECT_LIMITS_*` constants arrived with it
        // and move nothing further: a constant is compiled in, not linked. The
        // header's contract is the symbol SET, not a symbol's signature and not
        // the JSON shape, which is exactly the distinction this test holds. See
        // `wz_dissect_abi_version`.
        //
        // R311y913 — 9 since `wz_dissect_readable_surfaces` joined it.
        assert_eq!(wz_dissect_abi_version(), 9);
    }

    /// R311y913 (unregistered item 435) — THE LINKED SURFACE CAN SAY WHAT IT
    /// READS, and it says the SAME thing the terminal does.
    ///
    /// # The discriminator is the identity, not the shape
    ///
    /// Asserting that the document has the two keys would pass over a door that
    /// hand-wrote its own list — which is the failure this family of
    /// self-reports keeps being caught by, and the reason `readable_*_line` are
    /// public functions rather than prose. So the test compares against those
    /// functions' output directly: if the door ever grows its own copy, the two
    /// drift and this reds.
    ///
    /// The anti-vacuity leg matters as much: a build whose dispatch read
    /// nothing would produce two empty strings and satisfy any "contains the
    /// key" assertion.
    #[test]
    fn the_readable_surfaces_door_reports_the_dispatch_and_not_a_second_copy() {
        let mut out: *mut c_char = core::ptr::null_mut();
        // SAFETY: `out` is a writable pointer to a null pointer.
        let rc = unsafe { wz_dissect_readable_surfaces(&mut out) };
        assert_eq!(rc, WZ_DISSECT_OK);
        assert!(!out.is_null());
        // SAFETY: OK means a NUL-terminated string this library owns.
        let doc = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("the document is UTF-8")
            .to_string();
        // SAFETY: the pointer this library just handed back, freed once.
        unsafe { wz_dissect_string_free(out) };

        let links = wz_capture::link::readable_link_types_line();
        let zbuf = wz_session_core::dissect::readable_ext_bodies_line(
            wz_session_core::ext_header::EXT_ENC_ZBUF,
        );
        let z64 = wz_session_core::dissect::readable_ext_bodies_line(
            wz_session_core::ext_header::EXT_ENC_Z64,
        );
        // ANTI-VACUITY: a build that read nothing would make every `contains`
        // below true of an empty string.
        assert!(
            !links.is_empty() && !zbuf.is_empty() && !z64.is_empty(),
            "the dispatch reads nothing, so this test asserts nothing: \
             {links:?} {zbuf:?} {z64:?}"
        );
        assert!(
            doc.contains(&links),
            "the door must carry the link-type line the renderer produces: {doc}"
        );
        assert!(
            doc.contains(&zbuf) && doc.contains(&z64),
            "and both ext-body lines: {doc}"
        );
        assert!(
            doc.starts_with("{\"link_types\":\"") && doc.ends_with("}}"),
            "the document is one JSON object: {doc}"
        );
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

    /// R311y874 — the same capture, but the `Put` DECLARES an encoding.
    ///
    /// # Why a real capture and not the field tree the unit tests build
    ///
    /// `payload_decode`'s own tests hand-build the walked tree, so they prove
    /// the DECISION and assume the SHAPE. What reads the encoding is
    /// `declared_encoding`, and what writes it is `walk_msg_put` — two files
    /// that have never met in a test. If the group's field names or the packing
    /// of `packed_id` were anything other than what those tests assume, every
    /// one of them would still pass and no capture would ever be judged.
    ///
    /// So this drives the E flag through the encoder, the pcap, the session,
    /// the walker and the C boundary, and the assertion is that the answer
    /// changed — which it can only do if the read found something.
    fn capture_declaring(encoding_id: u32, payload: &[u8]) -> Vec<u8> {
        capture_declaring_many(&[(encoding_id, payload)])
    }

    /// R311y875 — SEVERAL declaring `Put`s in one capture, on one keyexpr.
    ///
    /// The plural is the whole point of the misbinding plane: the finding it
    /// produces is per (topic, rule, label) and carries a COUNT, and a fixture
    /// with one sample in it cannot tell a working tally from a hard-coded 1.
    ///
    /// Every `Put` goes into the SAME framed batch on the same flow, which is
    /// also what a real publisher does; separate frames would additionally be
    /// testing the flow assembler, which has its own tests.
    fn capture_declaring_many(samples: &[(u32, &[u8])]) -> Vec<u8> {
        let mut low_to_high = framed_init(&ZID_A);
        for (encoding_id, payload) in samples {
            low_to_high.extend_from_slice(&declaring_put(*encoding_id, payload));
        }
        let packet = tcp_packet(1000, &low_to_high);
        wz_capture::pcap::write(1, &[(0, 0, packet.as_slice())])
    }

    /// One framed `Put` on `demo/sensor` that DECLARES `encoding_id`.
    fn declaring_put(encoding_id: u32, payload: &[u8]) -> Vec<u8> {
        framed_frame(
            0,
            &wz_codecs::push::Push {
                header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
                keyexpr: literal("demo/sensor"),
                body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                    // 0x40 is the E flag: `walk_msg_put` reads an `encoding`
                    // group only when it is set, so a struct field alone would
                    // encode nothing and the test would pass on a build that
                    // never looked.
                    header: wz_codecs::msg_put::MsgPut::default().header | 0x40,
                    encoding: Some(wz_codecs::encoding::Encoding {
                        // The WIRE WORD is `(id << 1) | has_schema`.
                        packed_id: encoding_id << 1,
                        schema_len: None,
                        schema: None,
                    }),
                    payload_len: payload.len() as u64,
                    payload,
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }

    /// R311y874 — THE PUBLISHER'S DECLARATION REACHES THE DECISION THROUGH A
    /// REAL CAPTURE, and it decides both ways.
    ///
    /// Both arms under ONE rule (`demo/sensor=protobuf`) and one declaration
    /// (`application/json`, id 5), differing only in the BYTES. That is what
    /// makes the pair evidence: the rule did not change, the label did not
    /// change, and the answer changed — so the thing being consulted is the
    /// payload, which is precisely the credibility question R311y874 added.
    ///
    /// A build that never reads the walked encoding answers `decoded` twice; a
    /// build that reads it but believes it answers `encoding_mismatch` twice.
    /// Neither passes.
    #[test]
    fn a_declared_encoding_decides_both_ways_through_a_real_capture() {
        const JSON: u32 = 5;
        // Valid protobuf (field 1, varint 150) and NOT JSON: the publisher's
        // own bytes refute its own label, so the operator's rule wins.
        let mislabelled = capture_declaring(JSON, &[0x08, 0x96, 0x01]);
        let over = call_fields_with_payloads(&mislabelled, 0, "demo/sensor=protobuf")
            .expect("the capture reads");
        assert!(
            over.contains(
                "\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/sensor\",\
                 \"despite_encoding\":\"application/json\""
            ),
            "a label the bytes refute must not hide the data, and the override \
             must be named: {over}"
        );

        // The same label over bytes that BEAR IT OUT: here the rule is the
        // thing that is wrong and the veto is correct.
        let honest = capture_declaring(JSON, br#"{"a":1}"#);
        let vetoed = call_fields_with_payloads(&honest, 0, "demo/sensor=protobuf")
            .expect("the capture reads");
        assert!(
            vetoed.contains(
                "\"payload_decode\":{\"state\":\"encoding_mismatch\",\"keyexpr\":\"demo/sensor\",\
                 \"format\":\"protobuf\",\"declared\":\"application/json\"}"
            ),
            "a publisher whose bytes match its own label is believed, and the \
             rule is named as the thing to fix: {vetoed}"
        );
    }

    /// R311y875 — THE RUN COUNTS ITS MISBOUND RULES, and tells the two apart.
    ///
    /// # What was missing
    ///
    /// R311y873 and R311y874 taught the field layer to decide whose claim wins,
    /// and both findings went out one message at a time. A capture in which a
    /// rule is wrong for every sample on a topic said so once per row, in the
    /// listing a reader bounds precisely because it is that long, and no plane
    /// anywhere said "this mapping is wrong" or "this publisher is
    /// mislabelling". This is that plane.
    ///
    /// # Why this fixture is the discriminator
    ///
    /// Five samples on ONE keyexpr under ONE rule with ONE declaration, and the
    /// only thing that varies is the BYTES: three refute the label and two bear
    /// it out. So the two rows differ in `wrong` alone, which is what proves the
    /// tally is keyed on the verdict rather than on the triple that produced it —
    /// a build that keyed on the triple would report one row of 5.
    ///
    /// The counts are 3 and 2 rather than 1 and 1 because a hard-coded 1 is
    /// indistinguishable from a working tally on a one-sample fixture.
    #[test]
    fn the_run_counts_which_rules_bound_the_wrong_thing() {
        const JSON: u32 = 5;
        // Valid protobuf (field 1, varint 150), labelled `application/json`:
        // the label is refuted by its own bytes, so the PUBLISHER is wrong.
        const REFUTES: &[u8] = &[0x08, 0x96, 0x01];
        // Actual JSON under the same label: the label holds, so the RULE is.
        const BEARS_OUT: &[u8] = br#"{"a":1}"#;
        let capture = capture_declaring_many(&[
            (JSON, REFUTES),
            (JSON, BEARS_OUT),
            (JSON, REFUTES),
            (JSON, BEARS_OUT),
            (JSON, REFUTES),
        ]);
        let doc = call_fields_with_payloads(&capture, 0, "demo/sensor=protobuf")
            .expect("the capture reads");

        assert!(
            doc.contains(
                "\"payload_mapping\":[{\"keyexpr\":\"demo/sensor\",\"format\":\"protobuf\",\
                 \"declared\":\"application/json\",\"wrong\":\"publisher\",\"samples\":3,"
            ),
            "three samples whose bytes refute their own label must be counted \
             once, against the PUBLISHER, and reported first because they are \
             the larger finding: {doc}"
        );
        assert!(
            doc.contains(
                "{\"keyexpr\":\"demo/sensor\",\"format\":\"protobuf\",\
                 \"declared\":\"application/json\",\"wrong\":\"rule\",\"samples\":2,"
            ),
            "two samples whose bytes bear their label out must be counted \
             separately, against the RULE: {doc}"
        );
    }

    /// R311y875 — the key is STRUCTURAL: present and empty when nothing is
    /// misbound, on R311y720's standing rule.
    ///
    /// A consumer that had to test for the key would read its absence as "no
    /// rule is misbound", which is the assumption this plane exists to stop
    /// being made for free — and the two captures below are the two ways a
    /// document can legitimately carry no finding.
    #[test]
    fn the_misbinding_key_is_present_when_there_is_nothing_to_report() {
        // A rule that fires and agrees with every sample.
        let honest = call_fields_with_payloads(&protobuf_capture(), 0, "demo/sensor=protobuf")
            .expect("the capture reads");
        assert!(
            honest.contains("\"payload_mapping\":[]"),
            "a capture whose rule is right must SAY so with an empty array: {honest}"
        );
        // And a caller that declared nothing at all, which is the arm that
        // reaches `push_misbindings` with no ledger to ask.
        let undeclared =
            call_fields_with_payloads(&protobuf_capture(), 0, "").expect("the capture reads");
        assert!(
            undeclared.contains("\"payload_mapping\":[]"),
            "a caller that declared no rule must get the key too: {undeclared}"
        );
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

    /// R311y873 — `no_rules` NEVER REACHES A DOCUMENT, which is why the header
    /// is right not to name it.
    ///
    /// # Why this test exists, and what it is holding
    ///
    /// `the_header_names_every_payload_decode_state` reds on `no_rules` unless
    /// that state is excluded, and a gate's first finding has to be adjudicated
    /// before it is either obeyed or narrowed. This round asserted the opposite
    /// of what is written above and RAN it: the answer came back from the
    /// boundary rather than from reading the code that feeds it, and the answer
    /// was that an empty declaration text produces no `payload_decode` key at
    /// all. `fields_json` folds an empty map to `None` at its door
    /// (`crates/wz-capture/src/fields_json.rs:86`), so the state exists on the
    /// type and on no wire.
    ///
    /// So this is not a test of a silence for its own sake — it is what makes
    /// the gate's exclusion honest. The moment that fold changes and `no_rules`
    /// starts reaching a consumer, this reds and sends the next author to the
    /// header, which is exactly the coupling a bare skip in the gate would have
    /// thrown away.
    #[test]
    fn no_rules_never_reaches_a_document_so_the_header_need_not_name_it() {
        let file = protobuf_capture();
        let none = call_fields_with_payloads(&file, 0, "").expect("the capture reads");
        assert!(
            !none.contains("payload_decode"),
            "a caller who declared nothing is told nothing about payloads, and \
             the state word for it must stay off the wire: {none}"
        );
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
                 \"despite_encoding\":null,\"format\":\"protobuf\""
            ),
            "the covering rule must fire: {decoded}"
        );
        // R311y874 — and `despite_encoding` is PRESENT with a null on the
        // ordinary decode, asserted here rather than left to the state word.
        // The field answers "was this decoded over the publisher's own label",
        // and a consumer that had to test for the key would read its absence as
        // "no" — which is the assumption the field exists to stop.
        assert!(
            !decoded.contains("\"despite_encoding\":\""),
            "this publisher declared nothing, so nothing was overridden: \
             {decoded}"
        );
        assert!(
            decoded.contains("\"path\":\"1\",\"name\":\"temperature\",\"value\":\"varint 150\""),
            "and the DECLARED name must ride the decoded field -- protobuf's \
             wire format carries none, so this is the only place one can come \
             from: {decoded}"
        );
    }

    /// R311y914 (open-debt item 433) — A CBOR TOPIC CAN BE DECODED THROUGH THE
    /// ABI, and a cbor LABEL no longer silences the rule.
    ///
    /// # What the two arms are for
    ///
    /// The first is the ordinary case and the second is item 433's actual
    /// symptom, which was never "no cbor decoder": `crate::payload::shape_of`
    /// called `application/cbor` binary, so `inspect` answered `Opaque`, so
    /// `judge_claim` could not REFUTE the label — and an unrefutable label is a
    /// VETO over the operator's rule. A publisher labelling JSON bodies
    /// `application/cbor` therefore made every rule on that topic come back
    /// `encoding_mismatch` with nothing decoded, and the reader was told their
    /// mapping was wrong when the publisher's label was.
    ///
    /// So the second arm sends JSON under a cbor label and asks for `json`. It
    /// must now DECODE, carrying `despite_encoding` — the answer that was
    /// unreachable before, in a shape a build that merely added a decoder would
    /// still fail.
    #[test]
    fn a_cbor_topic_decodes_through_the_abi_and_its_label_can_be_refuted() {
        const CBOR: u32 = 8;
        // {"t": 21, 5: "a"} -- a text key and the integer key item 434 is about.
        let honest = capture_declaring(CBOR, &[0xa2, 0x61, 0x74, 0x15, 0x05, 0x61, 0x61]);
        let decoded =
            call_fields_with_payloads(&honest, 0, "demo/sensor=cbor").expect("the capture reads");
        assert!(
            decoded.contains(
                "\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/sensor\",\
                 \"despite_encoding\":null,\"format\":\"cbor\""
            ),
            "the publisher said cbor and the rule says cbor, so it decodes with \
             nothing overridden: {decoded}"
        );
        assert!(
            decoded.contains("\"value\":\"unsigned 21\""),
            "a text-keyed member must reach the linked surface: {decoded}"
        );
        assert!(
            decoded.contains("\"path\":\"$.\\\\i5\""),
            "and so must the integer key, in the namespace item 434 reserved \
             for the keys a text key cannot spell: {decoded}"
        );

        // ITEM 433'S SYMPTOM. JSON bytes under a `application/cbor` label: the
        // label is refuted by its own bytes, so the operator's `json` rule wins
        // and the override is REPORTED rather than the rule being silenced.
        let mislabelled = capture_declaring(CBOR, br#"{"a":1}"#);
        let over = call_fields_with_payloads(&mislabelled, 0, "demo/sensor=json")
            .expect("the capture reads");
        assert!(
            over.contains("\"state\":\"decoded\"")
                && over.contains("\"despite_encoding\":\"application/cbor\""),
            "a cbor label its own bytes refute must not veto the rule: {over}"
        );
        assert!(
            !over.contains("\"state\":\"encoding_mismatch\""),
            "`encoding_mismatch` here is the pre-R311y914 answer, and it was \
             wrong about which side was at fault: {over}"
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
