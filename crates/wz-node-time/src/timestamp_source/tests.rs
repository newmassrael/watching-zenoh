use super::*;

use crate::node_clock::{NodeHlc, TimestampingEnabled};
use wz_codecs::whatami::WhatAmI;

/// A node clock that DOES stamp, whatever the feature set — the fixture for
/// the HLC-path tests. On a build without `time-hlc` this is still a
/// non-stamping ZST, which is why every test that asserts HLC behaviour
/// carries the feature gate.
fn stamping_node(zid: &[u8]) -> NodeHlc {
    NodeHlc::for_node(zid, WhatAmI::Router, TimestampingEnabled::default())
}

#[test]
fn fallback_stamp_carries_zid_and_real_wall_clock_magnitude() {
    let zid = vec![0xAB, 0xCD];
    let stamper = FallbackStamp::new(zid.clone(), stamping_node(&zid));
    let ts = stamper.stamp();
    assert_eq!(ts.zid, zid, "the fallback stamp keeps the storage identity");
    // A real NTP64 wall clock has its seconds in the high 32 bits, so the
    // word is >= 2^32 (post-1970 epoch seconds). Guards against a stub
    // source returning a tiny counter value that every real timestamp
    // would dominate under newer-wins.
    assert!(
        ts.time >= Ntp64::FRAC_PER_SEC,
        "the fallback NTP64 carries real wall-clock seconds in the high 32 bits"
    );
}

#[test]
fn wall_clock_ntp64_is_a_real_post_epoch_ntp64() {
    // The moved SSOT still produces a post-epoch NTP64 (seconds in the
    // high 32 bits), in BOTH feature configs (this test is not gated).
    assert!(wall_clock_ntp64() >= (1u64 << 32));
}

#[cfg(feature = "time-hlc")]
#[test]
fn hlc_stamps_are_strictly_increasing() {
    // The observable FallbackStamp contract under `time-hlc`: successive
    // stamps strictly increase. Guaranteed by the HLC algorithm, so this
    // is zero-flake regardless of host timing. (This tests the contract,
    // not which branch provides it — `node_clock`'s frozen-clock test
    // isolates the logical counter, which a real clock cannot.)
    let stamper = FallbackStamp::new(vec![0x01], stamping_node(&[0x01]));
    let mut prev = stamper.stamp().time;
    for _ in 0..1000 {
        let next = stamper.stamp().time;
        assert!(
            next > prev,
            "HLC stamp must strictly increase: {next} !> {prev}"
        );
        prev = next;
    }
}

#[cfg(feature = "time-hlc")]
#[test]
fn the_stamp_zid_is_the_consumers_not_the_node_clocks() {
    // R311y450 — this now DISCRIMINATES rather than restating the obvious.
    // Before the node clock the stamper derived its HLC id from the very
    // zid it stamped with, so the two could not disagree and the assertion
    // held for free. The clock's identity is now a SEPARATE input, so
    // handing it a DIFFERENT zid makes the test fail if the stamp ever
    // starts carrying the clock's id instead of the consumer's — which
    // would silently move the newer-wins tie-breaker.
    let consumer_zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let node_zid = [0x11, 0x22];
    assert_ne!(
        consumer_zid.as_slice(),
        node_zid.as_slice(),
        "the fixture only discriminates while the two identities differ"
    );
    let stamper = FallbackStamp::new(consumer_zid.clone(), stamping_node(&node_zid));
    assert_eq!(stamper.stamp().zid, consumer_zid);
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_non_stamping_node_falls_the_stamper_back_to_the_wall_clock() {
    // The role gate reaching this stamper: with `time-hlc` COMPILED but the
    // node's role not timestamping (zenoh's peer/client default), the stamp
    // must still be a real post-epoch NTP64 — zenoh's
    // `Session::new_timestamp()` `None` arm, not a zero or a bare counter
    // that every real timestamp would dominate under newer-wins.
    let zid = vec![0x0F];
    let off = NodeHlc::for_node(&zid, WhatAmI::Peer, TimestampingEnabled::default());
    assert!(!off.is_stamping(), "the zenoh default gates a peer off");
    let stamper = FallbackStamp::new(zid.clone(), off);
    let ts = stamper.stamp();
    assert_eq!(ts.zid, zid);
    assert!(ts.time >= Ntp64::FRAC_PER_SEC);
}
