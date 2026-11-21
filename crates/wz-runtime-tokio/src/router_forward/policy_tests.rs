// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A forwarder's machines read the snapshot its creator handed [`RouterForwarder::for_node`], not
//! the build: each test selects every value the build's domain allows and observes it.

use super::*;
use wz_session_core::link_admission::judge_second_link_by;
use wz_session_core::policy::{LinkTieOrder, SessionPolicy};

/// Two zids the two tie orders rank differently: read as a number the first is the higher, read
/// byte by byte from the first wire byte it is the lower.
const LOCAL: &[u8] = &[0x01, 0x02];
const REMOTE: &[u8] = &[0x02];

fn router(self_zid: &[u8], policy: &SessionPolicy) -> RouterForwarder {
    RouterForwarder::for_node(
        WhatAmI::Router,
        Zid::from_slice(self_zid),
        crate::node_clock::TimestampingEnabled::default(),
        policy,
        &wz_session_core::limits::RuntimeLimits::BUILD,
    )
}

#[test]
fn a_forwarder_shares_its_tables_as_its_snapshot_says() {
    for value in [RoutingTableSharing::Rwlock, RoutingTableSharing::Snapshot] {
        let mut policy = SessionPolicy::defaults();
        if policy.select_routing_table_sharing(value).is_err() {
            continue;
        }
        let fwd = router(&[0x05], &policy);
        assert_eq!(fwd.table_sharing(), value);
        assert_eq!(fwd.policy().routing_table_sharing(), value);
    }
}

#[test]
fn a_second_link_is_judged_by_the_tie_order_of_the_snapshot() {
    // The two orders disagree on these zids, so a forwarder that read the build's order would
    // answer one of the two arms below wrongly.
    assert_ne!(
        judge_second_link_by(LinkTieOrder::ZidNumber, true, false, LOCAL, REMOTE),
        judge_second_link_by(LinkTieOrder::ZidBytes, true, false, LOCAL, REMOTE)
    );
    for order in [LinkTieOrder::ZidNumber, LinkTieOrder::ZidBytes] {
        let mut policy = SessionPolicy::defaults();
        if policy.select_link_tie_order(order).is_err() {
            continue;
        }
        let fwd = router(LOCAL, &policy);
        assert_eq!(
            FaceForwarder::judge_second_link(&fwd, true, false, REMOTE),
            Some(judge_second_link_by(order, true, false, LOCAL, REMOTE)),
            "{order:?}"
        );
    }
}

/// The node's clock stamps by the `clock-quality-stamping` value of the snapshot: no reference is
/// reported for its clock, so it withholds the stamp of the data it relays exactly when the value
/// is `trusted-only`.
#[cfg(feature = "time-hlc")]
#[test]
fn a_forwarder_stamps_by_the_clock_quality_of_the_snapshot() {
    use crate::node_clock::DataStamp;
    use wz_session_core::policy::ClockQualityStamping;
    let mut built = 0;
    for value in [
        ClockQualityStamping::Always,
        ClockQualityStamping::TrustedOnly,
    ] {
        let mut policy = SessionPolicy::defaults();
        if policy.select_clock_quality_stamping(value).is_err() {
            continue;
        }
        let fwd = router(&[0x05], &policy);
        assert_eq!(
            fwd.node_hlc().data_stamp() == DataStamp::Withheld,
            value == ClockQualityStamping::TrustedOnly,
            "{}",
            value.id()
        );
        built += 1;
    }
    assert!(built >= 1, "the build's domain holds at least its default");
}

/// The forwarder's clock runs with the `CLOCK_MAX_FORWARD_STEP_MS` of the runtime limits its
/// creator handed it: the build's bound with nothing stated, and the stated one otherwise.
#[cfg(feature = "time-hlc")]
#[test]
fn a_forwarders_clock_is_bounded_by_the_runtime_limits_it_is_handed() {
    use wz_session_core::limits::RuntimeLimits;
    if std::env::var_os("UHLC_MAX_DELTA_MS").is_some() {
        // The variable is selected over the snapshot, which the node clock's own tests hold.
        return;
    }
    let bound = |limits: &RuntimeLimits| {
        RouterForwarder::for_node(
            WhatAmI::Router,
            Zid::from_slice(LOCAL),
            crate::node_clock::TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            limits,
        )
        .node_hlc()
        .max_delta_word()
    };
    let word = |ms: usize| {
        wz_session_core::ntp64::Ntp64::from_duration(core::time::Duration::from_millis(ms as u64))
            .as_word()
    };
    let build = wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS;
    assert_eq!(bound(&RuntimeLimits::defaults()), Some(word(build)));
    let value = if build == 20 { 30 } else { 20 };
    let mut limits = RuntimeLimits::defaults();
    if limits.select_clock_max_forward_step_ms(value).is_err() {
        // A build that keeps the build's value alone refuses the statement itself.
        return;
    }
    assert_eq!(bound(&limits), Some(word(value)));
}
