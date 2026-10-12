// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `e2e` block of a field-document entry: what the end-to-end judge made of
//! one `Push` whose key a profile rule covers.
//!
//! # Where it hangs
//!
//! On the `carried` entry of the `Push`, beside `payload`, and on the entries of
//! `above_transport.carried` for a message that arrived as fragments. The entry
//! and not the row, for the reason the entry's `keyexpr` is there: a `Frame`
//! batches several messages, and a counter is a fact about ONE of them. The key
//! is ABSENT on every entry no profile rule covers, and present, in whatever
//! state, on every entry one does: a reader who registered a profile is told
//! what became of each frame, even the ones that were not frames.
//!
//! # The block
//!
//! ```text
//! "e2e":{"profile":"demo-a","matched_rule":{"index":0,"pattern":"demo/**"},
//!        "body_schema":"pkg.Pose",                    (only when the rule names one)
//!        "opened":true,"payload_offset":16,"payload_bytes":4,
//!        "header":[{"name":"crc","offset":0,"bytes":4,"raw":N,"value":N},
//!                  {"name":"ident","offset":8,"bytes":4,"raw":N,"value":N,
//!                   "parts":[{"name":"domain","value":3},...]}, ...],
//!        "crc_computed":N,"crc_error":false,
//!        "length_field":20,"length_expected":20,"length_matches_frame":true,
//!        "counter":7,
//!        "counter_error":false,"timeout_error":false,"counter_reason":"none",
//!        "silence_ms":12,
//!        "previous_counter":6,"first":false,"counter_step":1,
//!        "max_gap":3,"timeout_ms":100,
//!        "slot":{"keyexpr":"demo/a","zid":"...","identity":[{"name":"ident","value":N}]}}
//! ```
//!
//! * `crc_error`, `counter_error` and `timeout_error` are the three booleans of
//!   the protocol's receiver, in its order. `counter_reason` tells a repetition
//!   from a step past the allowed gap, for analysis; `silence_ms` is the silence
//!   the timeout was judged against. The three length keys are INFORMATION and
//!   not part of the CRC verdict ([`crate::e2e_frame`]): the CRC is taken over
//!   the length as it stands on the wire, so "the sender counts the length
//!   differently" shows as `length_matches_frame: false` beside a clean CRC, and
//!   damage as `crc_error: true`.
//! * `slot` names the counter this frame was judged against
//!   ([`crate::e2e_slots`]). `zid` is the sender as a string when the capture
//!   named it, `null` when the profile separates senders and the capture never
//!   saw this one, and ABSENT when the profile does not separate senders;
//!   `identity` is absent when the profile names no message field.
//! * **`counter_error`, `timeout_error`, `counter_reason` and `silence_ms` are
//!   `null`** when there was no slot to judge against (`slot.zid` is `null`);
//!   `timeout_error` and `silence_ms` are also `null` for a frame whose packet
//!   carried no timestamp, and `silence_ms` for the first frame a slot ever
//!   received, which has no earlier frame to be silent since. `null` is "not
//!   judged" and `false` is "judged and fine": a reader must not read an
//!   unjudged frame as a good one.
//! * **What a frame was judged AGAINST** (field document 35):
//!   `previous_counter` is the counter the slot had last ACCEPTED before this
//!   frame (a CRC error and a repetition accept nothing, so after either it is
//!   unchanged; a step past the allowed gap is accepted, so it becomes the next
//!   frame's), `first` is `true` exactly while the slot has accepted none, and
//!   `counter_step` is the step from `previous_counter` to `counter` in the
//!   counter's own width, the number [`crate::e2e_judge::Judge`] reaches its
//!   verdict from. `max_gap` and `timeout_ms` are the limits of the profile the
//!   slot's judge applied. `first` is how a reader tells a first frame from
//!   one whose packet carried no timestamp, which `silence_ms` alone cannot.
//!   All five are `null` when there is no slot to judge against; `counter_step`
//!   is also `null` while `first` is `true` and for a frame whose CRC did not
//!   match (its counter is not read), and `timeout_ms` for a frame whose packet
//!   carried no timestamp (no timeout was judged).
//! * `opened: false` is a payload that is not a frame: shorter than the header,
//!   or not one run of bytes in the capture. Its block carries `why`, the
//!   sentence, and `unopened_reason`, the word (`payload_shorter_than_header`
//!   or `payload_not_contiguous`; the first alone also carries `payload_bytes`),
//!   and the keys above that need a frame are absent. A history reply is not
//!   either of these: only a `Push` carrying a `put` is read as a frame, so a
//!   reply entry carries no `e2e` block at all.
//!
//! 64-bit values that can pass 2^53 (a CRC, a wide header field) are decimal
//! strings beyond it, by the integer rule every document here keeps.

use alloc::string::String;
use core::fmt::Write as _;

use wz_session_core::json::{escape_into, u64_into};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use crate::e2e_json::push_fields;
use crate::e2e_slots::{Opened, Outcome, SlotSender};
use crate::payload_decode::{push_matched_rule, E2eJudged};

/// Write `null` or the number.
fn push_optional(value: Option<u64>, out: &mut String) {
    match value {
        Some(value) => u64_into(value, out),
        None => out.push_str("null"),
    }
}

/// Write `null` or the number, for the facts a frame was judged under
/// (`previous_counter`, `counter_step`, `max_gap`, `timeout_ms`). A function of
/// its own, and not [`push_optional`], because the cells the integer-door gate
/// names are one per call and these four were born at revision 35, while
/// `silence_ms` was born at 34.
fn push_counter_fact(value: Option<u64>, out: &mut String) {
    match value {
        Some(value) => u64_into(value, out),
        None => out.push_str("null"),
    }
}

/// Write `null` or the boolean.
fn push_optional_bool(value: Option<bool>, out: &mut String) {
    out.push_str(match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    });
}

/// The object that follows `"e2e":`.
pub(crate) fn push_block(judged: &E2eJudged<'_>, out: &mut String) {
    let profile = judged.format.profile();
    out.push_str("{\"profile\":");
    escape_into(profile.name(), out);
    out.push_str(",\"matched_rule\":");
    push_matched_rule(&judged.rule, out);
    if let Some(schema) = judged.format.schema() {
        out.push_str(",\"body_schema\":");
        escape_into(schema, out);
    }
    match &judged.outcome {
        Outcome::Unreadable { why } => {
            out.push_str(",\"opened\":false,\"why\":");
            escape_into(why, out);
        }
        Outcome::TooShort {
            payload_bytes,
            header_bytes,
        } => {
            let _ = write!(
                out,
                ",\"opened\":false,\"payload_bytes\":{payload_bytes},\"why\":"
            );
            escape_into(
                &alloc::format!(
                    "the payload is {payload_bytes} bytes and the profile's header is \
                     {header_bytes}"
                ),
                out,
            );
        }
        Outcome::Opened(opened) => push_opened(judged, opened, out),
    }
    // The machine word beside the sentence, on exactly the blocks that have a
    // sentence: `why` and `unopened_reason` arrive together or not at all.
    if let Some(reason) = judged.outcome.unopened() {
        out.push_str(",\"unopened_reason\":\"");
        out.push_str(reason.word());
        out.push('"');
    }
    out.push('}');
}

fn push_opened(judged: &E2eJudged<'_>, opened: &Opened, out: &mut String) {
    let profile = judged.format.profile();
    let frame = &opened.frame;
    let _ = write!(
        out,
        ",\"opened\":true,\"payload_offset\":{},\"payload_bytes\":{},",
        frame.payload_offset, frame.payload_bytes
    );
    push_fields(profile, &frame.fields, "header", out);
    out.push_str(",\"crc_computed\":");
    u64_into(frame.crc_computed, out);
    let _ = write!(out, ",\"crc_error\":{}", !frame.crc_ok);
    out.push_str(",\"length_field\":");
    u64_into(frame.length_found, out);
    out.push_str(",\"length_expected\":");
    u64_into(frame.length_expected, out);
    let _ = write!(
        out,
        ",\"length_matches_frame\":{}",
        frame.length_matches_frame
    );
    out.push_str(",\"counter\":");
    u64_into(frame.counter(profile), out);

    let judgment = opened.judgment.as_ref();
    out.push_str(",\"counter_error\":");
    push_optional_bool(judgment.map(|j| j.counter_error), out);
    out.push_str(",\"timeout_error\":");
    push_optional_bool(
        judgment.filter(|_| opened.timed).map(|j| j.timeout_error),
        out,
    );
    out.push_str(",\"counter_reason\":");
    match judgment {
        Some(j) => {
            out.push('"');
            out.push_str(j.counter_reason.word());
            out.push('"');
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"silence_ms\":");
    push_optional(
        judgment.filter(|_| opened.timed).and_then(|j| j.silence_ms),
        out,
    );

    // What the frame was judged AGAINST, so a reader does not have to guess it
    // from `silence_ms` (which is `null` for a first frame and for a frame with
    // no timestamp alike). All five are `null` when there is no slot to judge
    // against, and the counter step and the timeout limit are `null` where that
    // part of the judgement was not made.
    out.push_str(",\"previous_counter\":");
    push_counter_fact(judgment.and(opened.previous), out);
    out.push_str(",\"first\":");
    push_optional_bool(judgment.map(|_| opened.previous.is_none()), out);
    out.push_str(",\"counter_step\":");
    push_counter_fact(judgment.and(opened.step), out);
    out.push_str(",\"max_gap\":");
    push_counter_fact(judgment.map(|_| profile.counter().max_gap), out);
    out.push_str(",\"timeout_ms\":");
    push_counter_fact(
        judgment
            .filter(|_| opened.timed)
            .map(|_| profile.counter().timeout_ms),
        out,
    );

    out.push_str(",\"slot\":{\"keyexpr\":");
    escape_into(&opened.slot.keyexpr, out);
    match &opened.slot.sender {
        SlotSender::Pooled => {}
        SlotSender::Zid(zid) => {
            out.push_str(",\"zid\":");
            escape_into(&zid_to_zenoh_hex(zid), out);
        }
        SlotSender::Unknown => out.push_str(",\"zid\":null"),
    }
    if !opened.slot.identity.is_empty() {
        out.push_str(",\"identity\":[");
        for (i, (name, value)) in opened.slot.identity.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            escape_into(name, out);
            out.push_str(",\"value\":");
            u64_into(*value, out);
            out.push('}');
        }
        out.push(']');
    }
    out.push('}');
}
