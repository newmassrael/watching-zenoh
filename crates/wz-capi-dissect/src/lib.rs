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
/// The capture file could not be read: bad magic, or a truncated / malformed
/// file in either format. R311y608 — pcapng was in this list and is not any
/// more; [`wz_dissect_pcap_summary`] dispatches on the magic and reads both.
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
    s.push_str(&health_json(d));
    s.push('}');
    s
}

/// R311y608 — what the dissection LOST, and who lost it.
///
/// The three counters this reports had, between them, ZERO consumers outside
/// `wz-capture`'s own tests: `health()` (R311y605), `fragment_stats()`
/// (R311y606) and `capture_reported_drops()` (R311y607) were each built, each
/// tested, and each read by nothing that ships. A measurement nobody reads is
/// indistinguishable from one that is wrong, so they are closed together here
/// rather than each growing a fourth test.
///
/// They are grouped by WHO lost the packet, because that is the only thing a
/// consumer can act on, and the three answers are genuinely different:
///
/// - `capture_reported_drops` — the CAPTURE TOOL's own admission. Its ring
///   overflowed and the file has a hole. Nothing wz does can recover it, and
///   the correct response is to re-capture with a bigger buffer.
/// - `dropped_by_limits` — THIS DISSECTION's caps biting. The data was
///   present; raise [`wz_capture::DissectionLimits`] and it comes back.
/// - `fragments` / `streams` — what the WIRE did: reordering, retransmission,
///   fragment chains that never completed.
///
/// `capture_reported_drops` is `null` and not `0` when the file made no
/// statement, and the difference is the whole value of the field: a classic
/// pcap has nowhere to record the figure, so "no ISB" is silence and not a
/// clean bill of health.
///
/// # One honest limitation, stated rather than left to be discovered
///
/// `dropped_by_limits` is all zeros through [`wz_dissect_pcap_summary`], and
/// STRUCTURALLY so: that entry point builds an UNBOUNDED dissection
/// (`Dissection::from_capture` takes no [`wz_capture::DissectionLimits`]), so
/// no cap exists to bite. The zeros are true, and they are not evidence that a
/// bounded dissection would report none. Making them reachable means letting a
/// C caller state its caps, which is a second entry point and an ABI decision
/// of its own — registered rather than improvised here. The group is reported
/// anyway because the alternative is a consumer that cannot tell "no caps" from
/// "caps that did not bite" at all.
fn health_json(d: &Dissection) -> String {
    let h = d.health();
    let f = d.fragment_stats();
    let fr = d.framing_health();
    let drops = h.drops;
    let reported = match d.capture_reported_drops() {
        Some(n) => n.to_string(),
        None => String::from("null"),
    };
    format!(
        "\"health\":{{\
         \"capture_reported_drops\":{reported},\
         \"dropped_by_limits\":{{\"frames\":{},\"stream_bytes\":{},\"skipped\":{},\
         \"flows\":{},\"scout_askers\":{}}},\
         \"fragments\":{{\"pieces\":{},\"completed\":{},\"expired\":{},\"evicted\":{},\
         \"malformed\":{},\"overlapping\":{}}},\
         \"streams\":{{\"retransmits\":{},\"out_of_order\":{},\"partial_overlaps\":{},\
         \"ip_checksum_valid\":{},\"ip_checksum_invalid\":{},\"ip_checksum_absent\":{},\
         \"transport_checksum_valid\":{},\"transport_checksum_invalid\":{},\
         \"transport_checksum_absent\":{}}},\
         \"framing\":{{\"gaps_forced\":{},\"gap_bytes_missing\":{},\
         \"desyncs\":{},\"recoveries\":{},\"resync_skipped_bytes\":{},\
         \"reserved_headers\":{}}},\
         \"sequence\":{{\"frames\":{},\"missing\":{},\"gaps\":{},\
         \"duplicates\":{},\"out_of_window\":{},\"without_resolution\":{}}}}}",
        drops.frames,
        drops.stream_bytes,
        drops.skipped,
        drops.flows,
        drops.scout_askers,
        f.pieces,
        f.completed,
        f.expired,
        f.evicted,
        f.malformed,
        f.overlapping,
        h.retransmits,
        h.out_of_order,
        h.partial_overlaps,
        h.ip_checksum_valid,
        h.ip_checksum_invalid,
        h.ip_checksum_absent,
        h.transport_checksum_valid,
        h.transport_checksum_invalid,
        h.transport_checksum_absent,
        fr.gaps_forced,
        fr.gap_bytes_missing,
        fr.desyncs,
        fr.recoveries,
        fr.resync_skipped_bytes,
        fr.reserved_headers,
        fr.sn_frames,
        fr.sn_missing,
        fr.sn_gaps,
        fr.sn_duplicates,
        fr.sn_out_of_window,
        fr.sn_without_resolution,
    )
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
        assert_eq!(wz_dissect_abi_version(), 1);
    }
}
