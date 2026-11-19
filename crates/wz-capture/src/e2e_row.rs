// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `e2e` block of a field-document entry: what the end-to-end judge made of
//! one `Push`, or one `Reply` carrying a `put`, whose key a profile rule covers.
//!
//! # Where it hangs
//!
//! On the `carried` entry of the `Push` or the `Response`, beside `payload`, on
//! the `joined` message of the piece that completed a split one, and on the entries of
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
//!        "max_gap":3,"timeout_ms":100,"unjudged_reason":null,
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
//!   and the keys above that need a frame are absent.
//! * **`unjudged_reason`** (field document 66) says why a frame that was read
//!   was not judged for its counter and its timeout, on every opened block:
//!   `sender_unknown` where there is no slot (`slot.zid` is `null`), `reply`
//!   for a frame that came in a reply to a query, and `null` where the counter
//!   was judged. A reply is read by the rule its own key falls to and its CRC
//!   and length are judged, being properties of its bytes; its counter is not,
//!   because a responder answering from what it holds sends frames of the
//!   past, which are not the live stream. Its `slot` names the slot its key,
//!   sender and identity select, and that slot does not move. Every cell the
//!   `slot.zid == null` case nulls is `null` for a reply too.
//!
//! 64-bit values that can pass 2^53 (a CRC, a wide header field) are decimal
//! strings beyond it, by the integer rule every document here keeps.

#[cfg(test)]
use alloc::string::String;

use wz_session_core::doc_out::DocOut;
#[cfg(test)]
use wz_session_core::doc_out::JsonOut;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use crate::e2e_json::write_fields;
use crate::e2e_slots::{Opened, Outcome, SlotSender};
use crate::payload_decode::{write_matched_rule, E2eJudged};

/// Write `null` or the number.
fn write_optional<W: DocOut>(value: Option<u64>, out: &mut W) {
    match value {
        Some(value) => out.uint_exact(value),
        None => out.null(),
    }
}

/// Write `null` or the number, for the facts a frame was judged under
/// (`previous_counter`, `counter_step`, `max_gap`, `timeout_ms`). A function of
/// its own, and not [`write_optional`], because the cells the integer-door gate
/// names are one per call and these four were born at revision 35, while
/// `silence_ms` was born at 34.
fn write_counter_fact<W: DocOut>(value: Option<u64>, out: &mut W) {
    match value {
        Some(value) => out.uint_exact(value),
        None => out.null(),
    }
}

/// [`write_block`] as JSON text onto `out`, which ends where a value goes: the
/// form the tests read a block in. The field document writes the block through
/// its own writer.
#[cfg(test)]
pub(crate) fn push_block(judged: &E2eJudged<'_>, out: &mut String) {
    JsonOut::value_onto(out, |w| write_block(judged, w));
}

/// The object that follows `"e2e":`.
pub(crate) fn write_block<W: DocOut>(judged: &E2eJudged<'_>, out: &mut W) {
    let profile = judged.format.profile();
    out.open_map();
    out.key("profile");
    out.text(profile.name());
    out.key("matched_rule");
    write_matched_rule(&judged.rule, out);
    if let Some(schema) = judged.format.schema() {
        out.key("body_schema");
        out.text(schema);
    }
    match &judged.outcome {
        Outcome::Unreadable { why } => {
            out.key("opened");
            out.bool(false);
            out.key("why");
            out.text(why);
        }
        Outcome::TooShort {
            payload_bytes,
            header_bytes,
        } => {
            out.key("opened");
            out.bool(false);
            out.key("payload_bytes");
            out.uint(*payload_bytes as u64);
            out.key("why");
            out.text_fmt(format_args!(
                "the payload is {payload_bytes} bytes and the profile's header is \
                 {header_bytes}"
            ));
        }
        Outcome::Opened(opened) => write_opened(judged, opened, out),
    }
    // The machine word beside the sentence, on exactly the blocks that have a
    // sentence: `why` and `unopened_reason` arrive together or not at all.
    if let Some(reason) = judged.outcome.unopened() {
        out.key("unopened_reason");
        out.text(reason.word());
    }
    out.close_map();
}

fn write_opened<W: DocOut>(judged: &E2eJudged<'_>, opened: &Opened, out: &mut W) {
    let profile = judged.format.profile();
    let frame = &opened.frame;
    out.key("opened");
    out.bool(true);
    out.key("payload_offset");
    out.uint(frame.payload_offset as u64);
    out.key("payload_bytes");
    out.uint(frame.payload_bytes as u64);
    write_fields(profile, &frame.fields, "header", out);
    out.key("crc_computed");
    out.uint_exact(frame.crc_computed);
    out.key("crc_error");
    out.bool(!frame.crc_ok);
    out.key("length_field");
    out.uint_exact(frame.length_found);
    out.key("length_expected");
    out.uint_exact(frame.length_expected);
    out.key("length_matches_frame");
    out.bool(frame.length_matches_frame);
    out.key("counter");
    out.uint_exact(frame.counter(profile));

    let judgment = opened.judgment.as_ref();
    out.key("counter_error");
    out.opt_bool(judgment.map(|j| j.counter_error));
    out.key("timeout_error");
    out.opt_bool(judgment.filter(|_| opened.timed).map(|j| j.timeout_error));
    out.key("counter_reason");
    out.opt_text(judgment.map(|j| j.counter_reason.word()));
    out.key("silence_ms");
    write_optional(
        judgment.filter(|_| opened.timed).and_then(|j| j.silence_ms),
        out,
    );

    // What the frame was judged AGAINST, so a reader does not have to guess it
    // from `silence_ms` (which is `null` for a first frame and for a frame with
    // no timestamp alike). All five are `null` when there is no slot to judge
    // against, and the counter step and the timeout limit are `null` where that
    // part of the judgement was not made.
    out.key("previous_counter");
    write_counter_fact(judgment.and(opened.previous), out);
    out.key("first");
    out.opt_bool(judgment.map(|_| opened.previous.is_none()));
    out.key("counter_step");
    write_counter_fact(judgment.and(opened.step), out);
    out.key("max_gap");
    write_counter_fact(judgment.map(|_| profile.counter().max_gap), out);
    out.key("timeout_ms");
    write_counter_fact(
        judgment
            .filter(|_| opened.timed)
            .map(|_| profile.counter().timeout_ms),
        out,
    );
    out.key("unjudged_reason");
    out.opt_text(opened.unjudged.map(|why| why.word()));

    out.key("slot");
    out.open_map();
    out.key("keyexpr");
    out.text(&opened.slot.keyexpr);
    match &opened.slot.sender {
        SlotSender::Pooled => {}
        SlotSender::Zid(zid) => {
            out.key("zid");
            out.text(&zid_to_zenoh_hex(zid));
        }
        SlotSender::Unknown => {
            out.key("zid");
            out.null();
        }
    }
    if !opened.slot.identity.is_empty() {
        out.key("identity");
        out.open_array();
        for (name, value) in &opened.slot.identity {
            out.open_map();
            out.key("name");
            out.text(name);
            out.key("value");
            out.uint_exact(*value);
            out.close_map();
        }
        out.close_array();
    }
    out.close_map();
}
