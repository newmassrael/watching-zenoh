// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The plain functions and values a subscriber reads around its gets, against no session.

#[cfg(feature = "advanced-recovery")]
use super::*;
#[cfg(feature = "advanced-recovery")]
use wz_session_core::zid_hex::zid_to_zenoh_hex;

/// The key expression of an `@adv` publisher token parses to the shape it names.
///
/// R2552 — the `uhlc` case is the new one, and the assertion that matters
/// is that it is a VALUE and not `None`: it used to fall into the same
/// answer as a broken key expression, and the two want opposite responses.
/// A malformed discriminator (`xx`) must still be `None`, or "timestamped"
/// would become the catch-all that swallows real parse failures.
#[cfg(feature = "advanced-recovery")]
#[test]
fn parse_heartbeat_source_round_trips_and_rejects_malformed() {
    let zid = vec![0x09u8, 0xAB];
    let ke = format!("demo/data/@adv/pub/{}/7/_", zid_to_zenoh_hex(&zid));
    assert_eq!(
        parse_heartbeat_source(&ke),
        Some(AdvPublisherSource::Sequenced {
            zid: zid.clone(),
            eid: 7
        })
    );
    // The shape wz's own publisher emits for `Sequencing::{Timestamp,None}`.
    let uhlc_ke = format!("demo/data/@adv/pub/{}/uhlc/_", zid_to_zenoh_hex(&zid));
    assert_eq!(
        parse_heartbeat_source(&uhlc_ke),
        Some(AdvPublisherSource::Timestamped { zid })
    );
    // R2555 — an `@adv/pub` token whose ZID does not decode is the THIRD
    // shape, not a rejection: upstream still queries such a publisher's
    // cache. `zz` is not hex, so `zenoh_hex_to_zid` refuses it exactly
    // where upstream's `ZenohId::from_str` refuses.
    assert_eq!(
        parse_heartbeat_source("demo/@adv/pub/zz/7/_"),
        Some(AdvPublisherSource::Unidentified),
        "an unreadable zid must be DISTINGUISHABLE from a non-token: one is \
         a publisher whose history is still recoverable, the other is not"
    );
    // ... and the discriminator is not even reached in that case, so a
    // `uhlc` token with an unreadable zid is the same shape.
    assert_eq!(
        parse_heartbeat_source("demo/@adv/pub/zz/uhlc/_"),
        Some(AdvPublisherSource::Unidentified)
    );
    // Malformed: no @adv, wrong marker, discriminator neither uhlc nor u32.
    // These are the ONLY cases left that mean "nothing to query".
    assert_eq!(parse_heartbeat_source("demo/data"), None);
    assert_eq!(parse_heartbeat_source("demo/@adv/sub/ff/7/_"), None);
    assert_eq!(parse_heartbeat_source("demo/@adv/pub/ff/xx/_"), None);
}

/// R311y92 (review S1) — the `@adv` namespace SSOT round-trip: a KE built by the
/// publisher's `publisher_adv_ke` parses back through the subscriber's
/// `parse_heartbeat_source` to the same `(zid, eid)`. This couples the two sides through
/// the shared `advanced_ke` module, so a drift on either the construct or the parse side
/// fails here (previously the publisher consts + the subscriber inline literals could
/// diverge silently).
#[cfg(feature = "advanced-recovery")]
#[test]
fn publisher_adv_ke_round_trips_through_parse() {
    let zid = vec![0x09u8, 0xAB];
    let zid_hex = zid_to_zenoh_hex(&zid);
    let ke = crate::advanced_ke::publisher_adv_ke("demo/data", &zid_hex, "7", None);
    assert!(
        ke.starts_with("demo/data/@adv/pub/") && ke.ends_with("/7/_"),
        "the publisher @adv KE has the @adv/pub/.../_ shape, got {ke}"
    );
    assert_eq!(
        parse_heartbeat_source(&ke),
        Some(AdvPublisherSource::Sequenced {
            zid: zid.clone(),
            eid: 7
        }),
        "the publisher-built KE parses back to its source via the shared @adv SSOT"
    );
    // R2552 — the SAME round trip for the shape the publisher emits under
    // `Sequencing::{Timestamp, None}`. Built through `publisher_adv_ke`
    // with the SSOT constant, so this fails if either side ever spells the
    // discriminator itself again.
    let uhlc_ke = crate::advanced_ke::publisher_adv_ke(
        "demo/data",
        &zid_hex,
        crate::advanced_ke::KE_ADV_UHLC,
        None,
    );
    assert_eq!(
        parse_heartbeat_source(&uhlc_ke),
        Some(AdvPublisherSource::Timestamped { zid }),
        "a timestamped publisher's own KE parses back to the timestamped shape"
    );
}

/// R311y89 (review C3) — the pure timeout-ms conversion. The lower clamp keeps
/// a recovery GET on its own configured timeout. R311y326 — pre-y326 the clamp's
/// bite was that a `0`/sub-ms `Duration` would pass through as the never-expire
/// sentinel and wedge a no-answerer GET; now `effective_timeout_ms` resolves a
/// `0` to the platform default, so the clamp pins intent (a live 1 ms deadline)
/// rather than the platform fallback, not never-expire-avoidance.
#[cfg(feature = "advanced-recovery")]
#[test]
fn recovery_query_timeout_ms_clamps_to_a_live_deadline() {
    // The zenoh default (10s) maps to 10000 ms.
    assert_eq!(recovery_query_timeout_ms(Duration::from_secs(10)), 10_000);
    // A zero / sub-ms timeout clamps UP to 1 ms — a live deadline, not the
    // platform default it would otherwise resolve to.
    assert_eq!(recovery_query_timeout_ms(Duration::ZERO), 1);
    assert_eq!(recovery_query_timeout_ms(Duration::from_micros(500)), 1);
    // A timeout past u32::MAX ms caps at u32::MAX (the with_timeout_ms field is u32).
    assert_eq!(
        recovery_query_timeout_ms(Duration::from_millis(u64::from(u32::MAX) + 1)),
        u32::MAX
    );
}

/// R311y442 — what the selector says is the thing a foreign peer logs: the
/// parts are `;`-joined, the bare `_anyke` flag is ALWAYS there, and the `_time` bound is
/// zenoh's `[now(-<age>s)..]` Display.
///
/// R311y442 REWROTE the expectations, and what they used to say is the
/// point. This test PINNED `_max=2&_time=[now(-30s)..]` and a `None` for the
/// no-knobs case — that is, it certified the two defects as the contract. A
/// wz cache reads the `&` form back (it split on `&` too), so the assertion
/// held on both sides of a wz<->wz round trip while being unreadable to
/// every real zenoh and zenoh-pico peer, and the absent `_anyke` meant a
/// conformant responder would refuse every reply. Neither is observable
/// without a foreign counterparty, which is why the leg in
/// `wz_advanced_pubsub_zenoh_ext_interop.rs` is what closes this, not a
/// stricter unit test.
#[cfg(feature = "advanced-history")]
#[test]
fn history_selector_emits_max_and_time() {
    // No knobs is no longer "no parameters": `_anyke` is not optional, it is
    // what makes an `@adv` reply legal at all.
    assert_eq!(history_selector(None, None), "_anyke".to_string());
    assert_eq!(history_selector(Some(2), None), "_max=2;_anyke".to_string());
    assert_eq!(
        history_selector(None, Some(Duration::from_secs(30))),
        "_time=[now(-30s)..];_anyke".to_string()
    );
    assert_eq!(
        history_selector(Some(2), Some(Duration::from_secs(30))),
        "_max=2;_time=[now(-30s)..];_anyke".to_string()
    );
}

/// An age of whole milliseconds, which is every age the C doors hand over, is written as the
/// seconds `f64`'s `Display` prints for it, so the selector reads as zenoh's does; an age finer
/// than a millisecond is written to the nanosecond. Turned red by a fraction written with its
/// trailing zeros, without its leading zeros, or rounded.
#[cfg(feature = "advanced-history")]
#[test]
fn an_age_is_written_as_the_seconds_it_is() {
    for ms in [
        1u64,
        10,
        100,
        999,
        1_000,
        1_500,
        60_000,
        86_400_123,
        1_000_000_000_000_000,
    ] {
        let age = Duration::from_millis(ms);
        assert_eq!(
            GetParameters::history(None, Some(age)).as_str(),
            format!("_time=[now(-{}s)..]", ms as f64 / 1000.0),
            "{ms} ms"
        );
    }
    for (age, seconds) in [
        (Duration::from_nanos(1), "0.000000001"),
        (Duration::from_micros(1_500), "0.0015"),
        (Duration::new(3, 120_000_000), "3.12"),
        (Duration::new(7, 999_999_999), "7.999999999"),
    ] {
        assert_eq!(
            GetParameters::history(None, Some(age)).as_str(),
            format!("_time=[now(-{seconds}s)..]"),
        );
    }
}

/// A cache reading the selector picks the samples it picked when the age was written as `f64`
/// seconds: the two texts resolve to one range. Turned red by an age written in another unit or
/// value than the one asked for.
#[cfg(feature = "advanced-history")]
#[test]
fn a_cache_reads_the_age_as_the_range_the_seconds_named() {
    use crate::time_range::{ntp64_to_system_time, of_parameters};

    let now = ntp64_to_system_time(1_000_000u64 << 32);
    for age in [
        Duration::from_millis(1),
        Duration::from_millis(1_500),
        Duration::from_secs(30),
        Duration::from_millis(86_400_123),
        Duration::from_micros(2_500),
        Duration::from_nanos(1_234_567_891),
    ] {
        let written = GetParameters::history(None, Some(age));
        let range = of_parameters(written.as_str(), now);
        assert!(range.is_some(), "{} is a range", written.as_str());
        assert_eq!(
            range,
            of_parameters(&format!("_time=[now(-{}s)..]", age.as_secs_f64()), now),
            "{}",
            written.as_str()
        );
    }
}

/// The parameters a history or recovery get lends are the selector's text without the flag,
/// which the get writes after them; the longest `usize` and age fit the bound, so no part is
/// ever left out. Turned red by a bound under the longest age text.
#[cfg(feature = "advanced-history")]
#[test]
fn get_parameters_write_the_selector_and_the_longest_values_fit() {
    assert_eq!(GetParameters::history(None, None).as_bytes(), b"");
    assert_eq!(
        GetParameters::history(Some(2), Some(Duration::from_secs(30))).as_str(),
        "_max=2;_time=[now(-30s)..]"
    );
    assert_eq!(
        GetParameters::history(None, Some(Duration::ZERO)).as_str(),
        "_time=[now()..]"
    );
    assert_eq!(GetParameters::recovery(7, None).as_str(), "_sn=7..");
    assert_eq!(GetParameters::recovery(7, Some(9)).as_str(), "_sn=7..9");
    assert_eq!(
        GetParameters::history(Some(usize::MAX), Some(Duration::MAX)).as_str(),
        format!(
            "_max={};_time=[now(-{}.999999999s)..]",
            usize::MAX,
            u64::MAX
        ),
        "the longest values are written whole"
    );
    assert_eq!(
        GetParameters::recovery(u32::MAX, Some(u32::MAX)).as_str(),
        format!("_sn={}..{}", u32::MAX, u32::MAX)
    );
}

/// A sample recovered from a reply is built from the reply's bytes as they
/// are held: a reply off the wire holds ranges of the frame it arrived in, so
/// the recovered sample holds the very same bytes (payload and attachment),
/// not copies, as a live sample does. The reply here is a Put over one lent
/// buffer, and the pointers say whether the sample took ranges of it.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_recovered_sample_holds_the_storage_its_reply_holds() {
    use wz_session_core::link::RxBytes;
    use wz_session_core::reply::{InboundReply, InboundReplyBody};

    let frame = RxBytes::lend(b"PAYLOADATTACH".to_vec());
    let payload = frame.subslice(0..7).expect("a range of the frame");
    let attachment = frame.subslice(7..13).expect("a range of the frame");
    let reply = InboundReply {
        rid: 1,
        keyexpr_literal: "demo/recovered".into(),
        body: InboundReplyBody::Put {
            payload: payload.clone(),
            attachment: Some(attachment.clone()),
            encoding: None,
            source_info: None,
            timestamp: None,
        },
        responder: None,
        qos: None,
        stamp: Default::default(),
    };

    let sample = recovered_sample_from_reply(&reply).expect("a Put reply recovers");

    assert_eq!(sample.payload.as_slice(), b"PAYLOAD");
    assert_eq!(
        sample.payload.as_ptr(),
        payload.as_ptr(),
        "the recovered payload is the reply's own bytes, not a copy of them"
    );
    let kept = sample.attachment.as_ref().expect("the attachment recovers");
    assert_eq!(kept.as_slice(), b"ATTACH");
    assert_eq!(
        kept.as_ptr(),
        attachment.as_ptr(),
        "and so is the attachment"
    );
}

/// A recovered reply read as a view hands on the reply's own bytes and its encoding, and a sample
/// copied out of that view keeps the encoding, which the view gives only as its parts.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_recovered_view_reads_the_reply_where_it_lies() {
    use wz_session_core::link::RxBytes;
    use wz_session_core::reply::{InboundReply, InboundReplyBody};
    use wz_session_core::sample::EncodingHint;
    use wz_session_core::sample_kind::SampleKind;
    use wz_session_core::sink::SampleView;

    let reply = InboundReply {
        rid: 1,
        keyexpr_literal: "demo/recovered".into(),
        body: InboundReplyBody::Put {
            payload: RxBytes::from(b"PAYLOAD".to_vec()),
            attachment: None,
            encoding: Some((0x0B, Some(b"text".to_vec()))),
            source_info: None,
            timestamp: None,
        },
        responder: None,
        qos: None,
        stamp: Default::default(),
    };

    let view = RecoveredView::of(&reply).expect("a Put reply recovers");
    assert_eq!(view.kind(), SampleKind::Put);
    assert_eq!(view.keyexpr(), "demo/recovered");
    assert_eq!(
        view.payload().as_ptr(),
        ReplyView::payload(&reply).as_ptr(),
        "the view reads the reply's bytes where they lie"
    );
    assert_eq!(view.encoding_parts(), Some((0x0B, Some(&b"text"[..]))));

    let sample = recovered_sample_from_reply(&reply).expect("a Put reply recovers");
    assert_eq!(
        sample.encoding,
        Some(EncodingHint {
            packed_id: 0x0B,
            schema: Some(b"text".to_vec()),
        }),
        "a sample copied out of the view keeps the encoding the view gives as parts"
    );
}
