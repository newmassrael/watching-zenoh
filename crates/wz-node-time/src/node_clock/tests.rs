use super::*;

/// The clock is shared by every face's task once the router drives one task per face
/// (`docs/router-task-per-face.md`, phase 1), so it must be `Send + Sync`. The proof is the
/// compile: this function is only instantiated for types that are.
#[test]
fn the_node_clock_can_be_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<NodeHlc>();
}

#[test]
fn zenoh_default_map_stamps_only_on_a_router() {
    // DEFAULT_CONFIG.json5:206 verbatim. A peer or client node must NOT
    // stamp: doing so would make wz add timestamps where zenoh does not,
    // which a foreign subscriber can see.
    let enabled = TimestampingEnabled::default();
    assert!(enabled.get(WhatAmI::Router));
    assert!(!enabled.get(WhatAmI::Peer));
    assert!(!enabled.get(WhatAmI::Client));
}

#[test]
fn the_single_boolean_spelling_applies_to_every_role() {
    // zenoh accepts `enabled: true` as well as the per-role table.
    for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
        assert!(TimestampingEnabled::all(true).get(role));
        assert!(!TimestampingEnabled::all(false).get(role));
    }
}

#[test]
fn a_role_gated_off_node_holds_no_clock() {
    // True in BOTH feature configs (a build without `time-hlc` never
    // stamps), so this test is not gated.
    let off = NodeHlc::for_node(&[0x01], WhatAmI::Peer, TimestampingEnabled::default());
    assert!(!off.is_stamping());
    assert!(off.stamp().is_none());
    assert!(!NodeHlc::disabled().is_stamping());
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_stamping_node_mints_strictly_increasing_stamps_carrying_its_zid() {
    let zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let node = NodeHlc::for_node(&zid, WhatAmI::Router, TimestampingEnabled::default());
    assert!(node.is_stamping());
    let mut prev = 0u64;
    for _ in 0..1000 {
        let stamp = node.stamp().expect("a router-role node stamps");
        assert_eq!(stamp.zid, zid, "the stamp carries the NODE identity");
        assert!(
            stamp.time > prev,
            "HLC stamps must strictly increase: {} !> {prev}",
            stamp.time
        );
        prev = stamp.time;
    }
}

/// A physical clock that never moves, so the only remaining source of
/// increase is the HLC's logical counter. See `build_clock` for why the
/// discriminating tests below cannot use the real one.
#[cfg(feature = "time-hlc")]
struct FrozenEpoch;

#[cfg(feature = "time-hlc")]
impl wz_session_core::epoch::EpochSource for FrozenEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        Ok(wz_session_core::epoch::SinceEpoch {
            secs: 1_700_000_000,
            nanos: 0,
        })
    }
}

/// A source that cannot say what time it is: a clock never set.
#[cfg(feature = "time-hlc")]
struct UnsetEpoch;

#[cfg(feature = "time-hlc")]
impl wz_session_core::epoch::EpochSource for UnsetEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        Err(wz_session_core::epoch::EpochUnavailable)
    }
}

/// A stamping node whose physical clock is frozen.
#[cfg(feature = "time-hlc")]
fn frozen_node(zid: &[u8]) -> NodeHlc {
    NodeHlc {
        clock: Some(build_clock(zid, FrozenEpoch)),
        drop_future_timestamp: false,
    }
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_node_whose_source_cannot_say_the_time_stamps_nothing() {
    let node = NodeHlc {
        clock: Some(build_clock(&[0x01], UnsetEpoch)),
        drop_future_timestamp: false,
    };
    assert!(
        node.is_stamping(),
        "the node has a clock; the clock has no date"
    );
    assert!(node.stamp().is_none());
}

#[cfg(feature = "time-hlc")]
#[test]
fn the_bound_is_zenohs_unless_the_variable_says_a_whole_number_of_milliseconds() {
    use wz_session_core::ntp64::Ntp64;
    let ms = |n: u64| Ntp64::from_duration(core::time::Duration::from_millis(n));
    assert_eq!(max_delta_from(None), ms(500));
    assert_eq!(max_delta_from(Some("20")), ms(20));
    assert_eq!(max_delta_from(Some(" 3000 ")), ms(3000));
    assert_eq!(max_delta_from(Some("soon")), ms(500));
    assert_eq!(max_delta_from(Some("-5")), ms(500));
}

#[cfg(feature = "time-hlc")]
#[test]
fn clones_share_one_clock_rather_than_forking_it() {
    // THE DEFECT THIS MODULE EXISTS TO REMOVE, as a RED-reproducing test.
    // Before R311y450 each consumer built its own HLC from the same node
    // zid, so two clocks derived the SAME `uhlc::ID` while keeping separate
    // `last_time`; two stamps minted "simultaneously" through different
    // consumers could then collide on `(time, zid)`.
    //
    // The physical clock MUST be frozen for this to discriminate. Measured:
    // with the real wall clock this same assertion PASSES against two
    // independently built clocks — the physical advance between reads hides
    // the fork — so a wall-clock version of this test would have gone green
    // on the broken code. Frozen, a forked pair repeats time words (each
    // counts up from the same frozen instant on its own `last_time`) and the
    // strict-increase assertion fails; one shared clock cannot repeat.
    let node = frozen_node(&[0x07]);
    let other = node.clone();
    let mut prev = 0u64;
    for _ in 0..500 {
        for stamp in [
            node.stamp().expect("stamping"),
            other.stamp().expect("stamping"),
        ] {
            assert!(
                stamp.time > prev,
                "interleaved stamps from two handles must share one counter: {} !> {prev}",
                stamp.time
            );
            prev = stamp.time;
        }
    }
}

#[cfg(feature = "time-hlc")]
#[test]
fn the_logical_counter_advances_under_a_frozen_physical_clock() {
    // Isolate the counter: with the physical clock frozen the only way
    // successive timestamps can increase is the low-CSIZE-bit counter (the
    // `else { last_time += 1 }` branch inside uhlc). The real-clock
    // monotonicity test above cannot prove this — its clock may always
    // advance on its own.
    let node = frozen_node(&[0x01]);
    let mut prev = node.stamp().expect("stamping").time;
    for _ in 0..16 {
        let next = node.stamp().expect("stamping").time;
        assert!(
            next > prev,
            "frozen clock: counter must advance: {next} !> {prev}"
        );
        prev = next;
    }
}

// ── The forward-path stamp (`treat_timestamp`), the zenoh macro mirror.
//
// These need `codec-push` (the Push codec) and `pubsub-timestamp` (the
// send-side gate `set_push_timestamp` routes through — with it off a forward
// stamp is a deliberate no-op, so asserting a timestamp appeared would be
// asserting against the gate).
#[cfg(all(feature = "codec-push", feature = "pubsub-timestamp"))]
mod forward_stamp {
    use super::*;
    use wz_session_core::push_build::build_push_literal;
    // The stamping-path fixtures and their builders exist only where a clock
    // can exist — without `time-hlc` the only reachable branch is the
    // non-stamping one below, and an unconditional import would be dead
    // (this crate denies warnings).
    #[cfg(feature = "time-hlc")]
    use wz_session_core::push_build::{
        build_push_del_literal, build_push_literal_with_meta, read_push_timestamp,
    };

    /// A Put whose inline timestamp slot is empty — what a client that does
    /// not set one puts on the wire.
    fn bare_put() -> wz_session_core::wire::PushOwned {
        build_push_literal("demo/hlc", b"v").expect("build put")
    }

    /// A Put carrying `time` paired with `zid`.
    #[cfg(feature = "time-hlc")]
    fn stamped_put(time: u64, zid: &[u8]) -> wz_session_core::wire::PushOwned {
        let meta = wz_session_core::metadata::PushMetadata {
            timestamp: Some(wz_session_core::sample::TimestampHint {
                time,
                zid: zid.to_vec(),
            }),
            ..Default::default()
        };
        build_push_literal_with_meta("demo/hlc", b"v", &meta).expect("build stamped put")
    }

    #[test]
    fn a_non_stamping_node_leaves_the_push_byte_identical() {
        // The default path off a router, and the ONLY path on a build without
        // `time-hlc`: the forward wire is unchanged by this seam existing.
        let node = NodeHlc::for_node(&[0x01], WhatAmI::Peer, TimestampingEnabled::default());
        let before = bare_put();
        let mut after = before.clone();
        node.treat_timestamp(&mut after);
        assert_eq!(before, after, "a non-stamping node must not touch the Push");
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_untimestamped_put_gets_one_and_the_header_bit_agrees() {
        // zenoh `pubsub.rs:203-205` — "Timestamp not present; add one". THE
        // foreign-observable branch: a pico subscriber prints
        // `with timestamp:` only when the field is present.
        let node_zid = [0xA1, 0xB2];
        let node = NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default());
        let mut push = bare_put();
        assert!(
            read_push_timestamp(&push).is_none(),
            "the fixture must start bare or this proves nothing"
        );
        node.treat_timestamp(&mut push);
        let ts = read_push_timestamp(&push).expect("a router stamps an un-timestamped Put");
        assert_eq!(ts.zid, node_zid, "the stamp carries the ROUTER's zid");
        assert!(
            ts.time >= (1u64 << 32),
            "a real post-epoch NTP64, not a bare counter: {}",
            ts.time
        );
        // The field and its header flag must move together — a set field with
        // `_Z_FLAG_Z_P_T` clear shifts the peer's decode of the rest of the
        // body. Checked on the wire header, not via the accessor that reads
        // the field, so this cannot pass on a field-only edit.
        let wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("fixture is a Put");
        };
        assert_eq!(put.header & 0x20, 0x20, "_Z_FLAG_Z_P_T must be set");
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_del_is_neither_stamped_nor_allowed_to_advance_the_clock() {
        // zenoh guards the whole macro on `if let PushBody::Put(data)`
        // (`pubsub.rs:181`). TWO properties here, and the second is the one
        // that makes the `push_is_put` guard load-bearing:
        //
        // 1. the Del passes through unchanged — which `set_push_timestamp`'s
        //    own variant match would deliver even with the guard deleted, so
        //    this assertion ALONE does not test the guard; and
        // 2. treating a Del must not MINT a timestamp, because a mint advances
        //    the node's logical counter for a message that can never carry the
        //    result.
        //
        // Only a frozen physical clock can see (2): under it each mint adds
        // exactly 1, so the delta across the treat is the witness. Measured
        // both ways — with the guard the delta is 1, with the guard deleted it
        // is 2 and this reds.
        let node = frozen_node(&[0x01]);
        assert!(node.is_stamping(), "the fixture only bites on a live clock");
        let before = build_push_del_literal("demo/hlc").expect("build del");
        let mut after = before.clone();
        let t0 = node.stamp().expect("stamping").time;
        node.treat_timestamp(&mut after);
        let t1 = node.stamp().expect("stamping").time;
        assert_eq!(before, after, "a Del must not be stamped");
        assert_eq!(
            t1 - t0,
            1,
            "treating a Del must not mint a timestamp (frozen clock: 1 per mint)"
        );
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_inbound_timestamp_within_the_drift_bound_is_absorbed_not_replaced() {
        // zenoh `pubsub.rs:184-185` — `update_with_timestamp` Ok arm does
        // NOTHING to the message. The relayed Put must keep the PUBLISHER's
        // timestamp; rewriting it would destroy the ordering the publisher
        // established. Absorption is still observable locally: the node's
        // next own stamp must sort after the timestamp it just absorbed.
        let node = NodeHlc::for_node(&[0x01], WhatAmI::Router, TimestampingEnabled::default());
        let publisher_zid = [0x0B, 0x0C];
        let inbound_time = crate::timestamp_source::wall_clock_ntp64();
        let mut push = stamped_put(inbound_time, &publisher_zid);
        node.treat_timestamp(&mut push);
        let ts = read_push_timestamp(&push).expect("still stamped");
        assert_eq!(
            (ts.time, ts.zid.as_slice()),
            (inbound_time, publisher_zid.as_slice()),
            "an absorbed timestamp must survive the relay untouched"
        );
        assert!(
            node.stamp().expect("stamping").time > inbound_time,
            "the absorbed timestamp must have advanced this node's clock"
        );
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_inbound_timestamp_beyond_the_drift_bound_is_replaced() {
        // The error arm: uhlc rejects a timestamp further ahead than its
        // 500ms drift bound, and zenoh's shipped `drop_future_timestamp:
        // false` (`DEFAULT_CONFIG.json5:207-209`) RETIMESTAMPS rather than
        // dropping. 10s ahead is two orders of magnitude past the bound, so
        // this does not sit near a threshold.
        let node_zid = [0x01];
        let node = NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default());
        let ten_seconds = 10u64 << 32;
        let future_time = crate::timestamp_source::wall_clock_ntp64() + ten_seconds;
        let mut push = stamped_put(future_time, &[0x0B, 0x0C]);
        node.treat_timestamp(&mut push);
        let ts = read_push_timestamp(&push).expect("still stamped");
        assert_ne!(
            ts.time, future_time,
            "a future timestamp past the drift bound must be replaced"
        );
        assert_eq!(ts.zid, node_zid, "the replacement carries THIS node's zid");
        assert!(
            ts.time < future_time,
            "the replacement is this node's own now, behind the rejected future"
        );
    }

    /// R2626 — `drop_future_timestamp: true` DROPS the same message the
    /// default arm re-stamps.
    ///
    /// THE TWO ARMS ARE ONE TEST ON PURPOSE. The knob's whole meaning is
    /// which of two things happens to an IDENTICAL input, so asserting the
    /// drop alone would not separate "the knob works" from "this input is
    /// rejected either way" — the default arm here is the control, and it is
    /// the same `future_time` through the same node.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn the_drop_knob_drops_the_future_timestamp_the_default_arm_replaces() {
        let node_zid = [0x01];
        let ten_seconds = 10u64 << 32;
        let future_time = crate::timestamp_source::wall_clock_ntp64() + ten_seconds;

        // CONTROL: shipped default — relay, with the timestamp replaced.
        let keeps = NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default());
        let mut relayed = stamped_put(future_time, &[0x0B, 0x0C]);
        assert_eq!(
            keeps.treat_timestamp(&mut relayed),
            TimestampVerdict::Relay,
            "the shipped default must RELAY a future-stamped Put"
        );
        assert_ne!(
            read_push_timestamp(&relayed).expect("still stamped").time,
            future_time,
            "and re-stamp it, which is the arm the drop knob replaces"
        );

        // The knob ON: the same input through the same role, dropped.
        let drops = NodeHlc::for_node(&node_zid, WhatAmI::Router, TimestampingEnabled::default())
            .with_drop_future_timestamp(true);
        let mut dropped = stamped_put(future_time, &[0x0B, 0x0C]);
        assert_eq!(
            drops.treat_timestamp(&mut dropped),
            TimestampVerdict::Drop,
            "`drop_future_timestamp: true` must report Drop for a timestamp \
             uhlc rejects"
        );
    }

    /// R2626 — the knob does NOT reach the arms that never fail.
    ///
    /// zenoh's drop lives on the `update_with_timestamp` Err branch ONLY, so
    /// a bare Put is still stamped and an in-bound timestamp is still
    /// absorbed even with the knob on. Without this, `drop_future_timestamp`
    /// could be implemented as "drop anything timestamped" and both
    /// assertions above would still pass.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn the_drop_knob_leaves_the_mint_and_absorb_arms_alone() {
        let node = NodeHlc::for_node(&[0x01], WhatAmI::Router, TimestampingEnabled::default())
            .with_drop_future_timestamp(true);

        let mut bare = bare_put();
        assert_eq!(
            node.treat_timestamp(&mut bare),
            TimestampVerdict::Relay,
            "a Put with NO timestamp cannot reach the Err arm, so the knob \
             must not touch it"
        );
        assert!(
            read_push_timestamp(&bare).is_some(),
            "and it must still be minted"
        );

        let inbound_time = crate::timestamp_source::wall_clock_ntp64();
        let mut inside = stamped_put(inbound_time, &[0x0B, 0x0C]);
        assert_eq!(
            node.treat_timestamp(&mut inside),
            TimestampVerdict::Relay,
            "a timestamp INSIDE the drift bound is absorbed, not rejected, so \
             the knob must not drop it"
        );
        assert_eq!(
            read_push_timestamp(&inside).expect("still stamped").time,
            inbound_time,
            "and it must survive the relay untouched"
        );
    }
}

#[cfg(feature = "time-hlc")]
#[test]
fn an_oversized_or_empty_zid_still_yields_a_usable_clock() {
    // `uhlc::ID` is 1..=16 non-zero bytes. A 32-byte zid clamps and an
    // empty one falls back to the guard id, so neither panics during
    // construction — the absorb path derives an id from an INBOUND zid, so
    // this guard is reachable from the wire, not only from a test.
    let long = NodeHlc::for_node(&[0xAB; 32], WhatAmI::Router, TimestampingEnabled::all(true));
    assert!(long.stamp().is_some());
    let empty = NodeHlc::for_node(&[], WhatAmI::Router, TimestampingEnabled::all(true));
    assert!(empty.stamp().is_some());
}
