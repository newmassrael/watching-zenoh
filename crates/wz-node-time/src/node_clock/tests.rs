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
    let off = NodeHlc::for_node_by(
        &[0x01],
        WhatAmI::Peer,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(!off.is_stamping());
    assert!(off.stamp().is_none());
    assert!(!NodeHlc::disabled().is_stamping());
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_stamping_node_mints_strictly_increasing_stamps_carrying_its_zid() {
    let zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let node = NodeHlc::for_node_by(
        &zid,
        WhatAmI::Router,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
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

#[test]
fn a_node_that_does_not_stamp_gives_a_reply_no_stamp() {
    use wz_session_core::reply_stage::ReplyClock;
    let off = NodeHlc::for_node_by(
        &[0x01],
        WhatAmI::Peer,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(off.next_stamp().is_none());
    assert!(NodeHlc::disabled().next_stamp().is_none());
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_stamping_node_stamps_a_reply_with_its_own_identity_and_a_later_time_each_time() {
    use wz_session_core::reply_stage::ReplyClock;
    let zid = [0xDE, 0xAD, 0xBE, 0xEF];
    let node = NodeHlc::for_node_by(
        &zid,
        WhatAmI::Router,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    let first = node.next_stamp().expect("a router-role node stamps");
    let second = node.next_stamp().expect("and again");
    assert_eq!(first.zid.as_slice(), &zid);
    assert!(
        second.time > first.time,
        "one clock, so a later reply is a later time"
    );
    assert_eq!(
        first.parts().zid,
        &zid,
        "the borrowed parts a staged reply carries are the stamp's"
    );
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_node_whose_identity_is_longer_than_a_timestamp_carries_stamps_no_reply() {
    use wz_session_core::reply_stage::ReplyClock;
    let node = NodeHlc::for_node_by(
        &[7; 17],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(
        node.stamp().is_some(),
        "its data is still stamped as it was"
    );
    assert!(node.next_stamp().is_none());
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

/// A standing of a node's own, as a node over the system clock keeps.
#[cfg(feature = "time-hlc")]
fn own_standing() -> StandingHome {
    StandingHome::Own(Box::default())
}

/// The bound a node runs with when the environment states none: the build's.
#[cfg(feature = "time-hlc")]
fn build_bound() -> wz_session_core::ntp64::Ntp64 {
    max_delta_from(Err(std::env::VarError::NotPresent), &RuntimeLimits::BUILD)
        .expect("the build's own bound is honoured")
}

/// A stamping node whose physical clock is frozen.
#[cfg(feature = "time-hlc")]
fn frozen_node(zid: &[u8]) -> NodeHlc {
    let clock = build_clock(zid, FrozenEpoch, own_standing(), build_bound());
    NodeHlc {
        #[cfg(feature = "pubsub-ts-stack")]
        interception_clock: Some(clock.clone()),
        clock: Some(clock),
        drop_future_timestamp: false,
        trusted_only: false,
        clock_refused: None,
    }
}

/// A stamping node whose clock is frozen and whose `clock-quality-stamping` policy is the one
/// named, so a test says which value it is about whatever the build states.
#[cfg(feature = "time-hlc")]
fn frozen_node_with_policy(zid: &[u8], trusted_only: bool) -> NodeHlc {
    frozen_node(zid).with_trusted_only_stamping(trusted_only)
}

#[cfg(feature = "time-hlc")]
#[test]
fn the_policy_always_stamps_with_a_clock_no_reference_was_reported_for() {
    let node = frozen_node_with_policy(&[0x01], false);
    assert!(node.stamp().is_some(), "`always` ignores the standing");
    assert_eq!(node.unstamped(), 0);
}

/// The policy is the stamper's and not the clock's: a node whose untrusted clock stamps none of the
/// data it passes on still gives a time to a caller that reads the clock, as upstream's clock
/// always does, and that time is the same clock's, so the next stamp the policy lets through is
/// above it.
#[cfg(feature = "time-hlc")]
#[test]
fn trusted_only_holds_back_the_stamps_of_data_and_not_the_clock() {
    let node = frozen_node_with_policy(&[0x01], true);
    assert!(
        node.stamp().is_none(),
        "no reference yet: the node stamps no data"
    );
    let read = node.clock_stamp().expect("a reading of the clock").time;
    let word = node.next_word().expect("the clock lent as uhlc's");
    assert!(
        word > read,
        "one clock: the lent read follows the plain read"
    );
    assert!(node.report_sync_acquired());
    let stamped = node.stamp().expect("a reference is followed").time;
    assert!(stamped > word, "the stamp of data is the same clock's next");
}

/// The reason comes with the absence: the policy's refusal is `Withheld`, a node without a clock
/// is `NoClock`, and once the clock is trusted the stamp is the clock's, as `stamp` gives it.
#[cfg(feature = "time-hlc")]
#[test]
fn the_data_stamp_names_why_there_is_none() {
    let node = frozen_node_with_policy(&[0x01], true);
    assert_eq!(node.data_stamp(), DataStamp::Withheld);
    assert!(node.report_sync_acquired());
    assert!(matches!(node.data_stamp(), DataStamp::Stamped(_)));
    assert_eq!(NodeHlc::disabled().data_stamp(), DataStamp::NoClock);
    assert!(matches!(
        frozen_node_with_policy(&[0x01], false).data_stamp(),
        DataStamp::Stamped(_)
    ));
}

/// A node stamps by the `clock-quality-stamping` policy of the snapshot its creator handed it,
/// whatever the build states: each value the build's domain holds gives a node whose untrusted
/// clock withholds the stamp of data exactly when that value is `trusted-only`.
#[cfg(feature = "time-hlc")]
#[test]
fn a_node_stamps_by_the_snapshot_it_is_handed() {
    use wz_session_core::policy::ClockQualityStamping;
    let mut built = 0;
    for value in [
        ClockQualityStamping::Always,
        ClockQualityStamping::TrustedOnly,
    ] {
        let mut policy = SessionPolicy::defaults();
        if policy.select_clock_quality_stamping(value).is_err() {
            // The build's domain leaves this value out: no creator can hand it.
            continue;
        }
        let node = NodeHlc::for_node_over_source_by(
            &[0x01],
            WhatAmI::Router,
            TimestampingEnabled::default(),
            FrozenEpoch,
            &policy,
            &RuntimeLimits::BUILD,
        );
        assert_eq!(
            node.data_stamp() == DataStamp::Withheld,
            value == ClockQualityStamping::TrustedOnly,
            "{}",
            value.id()
        );
        built += 1;
    }
    assert!(built >= 1, "the build's domain holds at least its default");
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_node_that_holds_no_clock_gives_no_reading_either() {
    let node = NodeHlc::disabled();
    assert!(node.clock_stamp().is_none());
    assert!(node.stamp().is_none());
    assert!(node.next_word().is_none());
}

#[cfg(feature = "time-hlc")]
#[test]
fn the_policy_trusted_only_stamps_nothing_until_a_reference_is_reported_and_after_it_is_lost() {
    let node = frozen_node_with_policy(&[0x01], true);
    assert!(node.stamp().is_none(), "no reference yet");

    assert!(node.report_sync_acquired());
    assert!(node.stamp().is_some(), "a reference is followed");

    assert!(node.report_sync_lost());
    #[cfg(not(feature = "clock-source"))]
    assert!(
        node.stamp().is_none(),
        "without a registered clock a loss is untrusted"
    );
    #[cfg(feature = "clock-source")]
    {
        assert!(node.stamp().is_some(), "held over, within the host's bound");
        assert!(node.report_holdover_expired());
        assert!(node.stamp().is_none(), "free running is not trusted");
    }

    assert!(node.report_sync_acquired());
    assert!(node.stamp().is_some(), "a reference back is followed again");
}

#[cfg(feature = "clock-source")]
#[test]
fn a_node_reads_a_source_registered_after_it_was_built_and_none_it_stamps_nothing() {
    use crate::clock_registry::ClockRegistry;
    let registry: &'static ClockRegistry = Box::leak(Box::new(ClockRegistry::new(2)));
    let node = NodeHlc::for_node_with_registry_by(
        &[0x05],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        registry,
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(
        node.stamp().is_some(),
        "nothing registered: the system clock"
    );

    // The application's own clock, registered after the node exists: its date is the node's. It
    // is set ahead of the system clock because a hybrid logical clock never goes back: a source
    // that read earlier than the stamp already made would be stamped over, not followed.
    struct AheadEpoch;
    impl wz_session_core::epoch::EpochSource for AheadEpoch {
        fn try_since_epoch(
            &self,
        ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable>
        {
            Ok(wz_session_core::epoch::SinceEpoch {
                secs: 4_000_000_000,
                nanos: 0,
            })
        }
    }
    let id = registry
        .register(Box::new(AheadEpoch))
        .expect("room for one source");
    let stamp = node.stamp().expect("the registered source answers");
    assert_eq!(
        stamp.time >> 32,
        4_000_000_000,
        "the stamp carries the registered clock's seconds, not the system's"
    );

    // A registered clock that does not know the date leaves the node without one.
    registry.unregister(id);
    registry.register(Box::new(UnsetEpoch)).expect("room");
    assert!(
        node.stamp().is_none(),
        "the system clock is not the fallback of a clock the application chose"
    );
}

#[cfg(feature = "clock-source")]
#[test]
fn nodes_over_one_registry_share_its_standing_and_the_host_reports_through_either() {
    use crate::clock_registry::ClockRegistry;
    let registry: &'static ClockRegistry = Box::leak(Box::new(ClockRegistry::new(1)));
    let build = |zid: u8| {
        NodeHlc::for_node_with_registry_by(
            &[zid],
            WhatAmI::Router,
            TimestampingEnabled::default(),
            registry,
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        )
        .with_trusted_only_stamping(true)
    };
    let (one, two) = (build(1), build(2));
    assert!(
        one.stamp().is_none() && two.stamp().is_none(),
        "nothing reported yet"
    );

    // The host reports to the registry, which it holds, and not to either node.
    assert!(registry.standing().report_sync_acquired());
    assert!(one.stamp().is_some() && two.stamp().is_some());

    // A report through a node is the same report.
    assert!(one.report_sync_lost());
    assert_eq!(registry.standing().changes(), 2);
}

#[cfg(feature = "time-hlc")]
#[test]
fn clones_share_one_standing() {
    let node = frozen_node_with_policy(&[0x01], true);
    let other = node.clone();
    node.report_sync_acquired();
    assert!(
        other.stamp().is_some(),
        "a report through one handle is seen by the other"
    );
}

#[test]
fn a_node_with_no_clock_has_no_standing_to_report() {
    let node = NodeHlc::disabled();
    assert!(!node.report_sync_acquired());
    assert!(!node.report_sync_lost());
    assert_eq!(node.unstamped(), 0);
}

#[cfg(feature = "time-hlc")]
#[test]
fn a_node_whose_source_cannot_say_the_time_stamps_nothing() {
    let clock = build_clock(&[0x01], UnsetEpoch, own_standing(), build_bound());
    let node = NodeHlc {
        #[cfg(feature = "pubsub-ts-stack")]
        interception_clock: Some(clock.clone()),
        clock: Some(clock),
        drop_future_timestamp: false,
        trusted_only: false,
        clock_refused: None,
    };
    #[cfg(feature = "pubsub-ts-stack")]
    assert!(
        node.interception_timestamp().is_none(),
        "nor does it record an interception with a date it does not have"
    );
    assert!(
        node.is_stamping(),
        "the node has a clock; the clock has no date"
    );
    assert!(node.stamp().is_none());
}

/// Absent, the bound is the build's; stated, it is the number stated when the build allows it for
/// `CLOCK_MAX_FORWARD_STEP_MS`, and otherwise refused by that limit's own reason.
#[cfg(feature = "time-hlc")]
#[test]
fn the_bound_is_the_builds_unless_the_variable_states_one_the_build_allows() {
    use wz_session_core::limit_binding::{LimitSpec, LimitValue};
    use wz_session_core::limits::ClockMaxForwardStepMs;
    use wz_session_core::ntp64::Ntp64;
    let ms = |n: u64| Ntp64::from_duration(core::time::Duration::from_millis(n));
    let stated = |text: &str| max_delta_from(Ok(String::from(text)), &RuntimeLimits::BUILD);
    let build = wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS as u64;
    assert_eq!(
        max_delta_from(Err(std::env::VarError::NotPresent), &RuntimeLimits::BUILD),
        Ok(ms(build))
    );
    assert_eq!(
        stated(&build.to_string()),
        Ok(ms(build)),
        "the build's own value is allowed by every build"
    );
    let allows = |n: usize| ClockMaxForwardStepMs::DOMAIN.contains(LimitValue::Integer(n));
    for n in [0usize, 20, 3000, u32::MAX as usize] {
        match stated(&n.to_string()) {
            Ok(bound) => {
                assert!(allows(n), "{n} is taken although the build refuses it");
                assert_eq!(bound, ms(n as u64));
            }
            Err(MaxDeltaRefused::OutsideDomain(outside)) => {
                assert!(!allows(n), "{n} is refused although the build allows it");
                assert_eq!(outside.limit, "CLOCK_MAX_FORWARD_STEP_MS");
            }
            Err(other) => panic!("{n} is refused as {other:?}"),
        }
    }
    assert!(
        matches!(
            stated("4294967296"),
            Err(MaxDeltaRefused::OutsideDomain(_) | MaxDeltaRefused::TooLarge { .. })
        ),
        "past the limit's domain on every build"
    );
}

/// A stated value that is not a whole number of milliseconds is refused by name, never replaced
/// by the build's: the values `uhlc`'s `s.parse()` into a `u64` panics on, including one with
/// spaces around it, and one that is not Unicode.
#[cfg(feature = "time-hlc")]
#[test]
fn a_bound_that_is_not_a_whole_number_of_milliseconds_is_refused_and_not_defaulted() {
    for text in ["soon", "-5", " 3000 ", "", "1.5", "18446744073709551616"] {
        assert_eq!(
            max_delta_from(Ok(String::from(text)), &RuntimeLimits::BUILD),
            Err(MaxDeltaRefused::NotMilliseconds {
                stated: String::from(text)
            }),
            "`{text}`"
        );
    }
    let not_unicode = max_delta_from(
        Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "x",
        ))),
        &RuntimeLimits::BUILD,
    );
    assert_eq!(not_unicode, Err(MaxDeltaRefused::NotUnicode));
    let refusal = max_delta_from(Ok(String::from("soon")), &RuntimeLimits::BUILD).unwrap_err();
    assert!(
        refusal.to_string().contains("UHLC_MAX_DELTA_MS") && refusal.to_string().contains("soon"),
        "the refusal names the variable and the value: {refusal}"
    );
}

/// A build without `std` reads no environment: its node opens with nothing stated, which is the
/// bound of the runtime limits its creator handed it, the one a `std` build opens with when the
/// variable is unset.
#[cfg(feature = "time-hlc")]
#[test]
fn nothing_stated_is_the_bound_a_build_without_std_opens_with() {
    use wz_session_core::ntp64::Ntp64;
    let build = wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS as u64;
    assert_eq!(
        max_delta_of(Stated::Absent, &RuntimeLimits::BUILD),
        Ok(Ntp64::from_duration(core::time::Duration::from_millis(
            build
        )))
    );
    assert_eq!(
        max_delta_of(Stated::Absent, &RuntimeLimits::BUILD),
        max_delta_from(Err(std::env::VarError::NotPresent), &RuntimeLimits::BUILD)
    );
}

/// A node whose stated bound is refused is built without the clock it was to have, and says why;
/// a node that builds no clock is not refused for a bound it would not use.
#[cfg(feature = "time-hlc")]
#[test]
fn a_node_whose_stated_bound_is_refused_holds_no_clock_and_says_why() {
    let refused = max_delta_from(Ok(String::from("soon")), &RuntimeLimits::BUILD).unwrap_err();
    let stamping = SessionPolicy::defaults().clock_quality_stamping();
    let node = |whatami: WhatAmI, bound| {
        NodeHlc::over_source_bounded(
            &[0x01],
            whatami,
            TimestampingEnabled::default(),
            FrozenEpoch,
            own_standing(),
            stamping,
            bound,
        )
    };

    let router = node(WhatAmI::Router, Err(refused.clone()));
    assert_eq!(router.clock_refused(), Some(&refused));
    assert!(!router.is_stamping());
    assert_eq!(router.data_stamp(), DataStamp::NoClock);
    assert_eq!(router.max_delta_word(), None);
    #[cfg(feature = "pubsub-ts-stack")]
    assert!(router.interception_timestamp().is_none());

    let peer = node(WhatAmI::Peer, Err(refused.clone()));
    assert!(!peer.is_stamping());
    assert_eq!(
        peer.clock_refused().is_some(),
        cfg!(feature = "pubsub-ts-stack"),
        "a peer builds a clock only to record interceptions"
    );

    let honoured = node(WhatAmI::Router, Ok(build_bound()));
    assert_eq!(honoured.clock_refused(), None);
    assert!(honoured.is_stamping());
    assert_eq!(honoured.max_delta_word(), Some(build_bound().as_word()));
}

/// `CLOCK_MAX_FORWARD_STEP_MS` with nothing stated: a node whose creator hands it the build's
/// runtime limits runs its clock with the build's bound.
#[cfg(feature = "time-hlc")]
#[test]
fn clock_max_forward_step_ms_with_nothing_stated_holds_the_builds_bound() {
    let build = wz_session_core::ntp64::Ntp64::from_duration(core::time::Duration::from_millis(
        wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS as u64,
    ));
    let limits = RuntimeLimits::defaults();
    assert_eq!(
        max_delta_from(Err(std::env::VarError::NotPresent), &limits),
        Ok(build)
    );
    let node = NodeHlc::for_node_over_source_by(
        &[0x01],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        FrozenEpoch,
        &SessionPolicy::defaults(),
        &limits,
    );
    // The creator's door reads the environment too, so the node holds what the two resolve to.
    let resolved = max_delta_from(std::env::var(MAX_DELTA_VARIABLE), &limits);
    assert_eq!(
        node.max_delta_word(),
        resolved.ok().map(|bound| bound.as_word())
    );
}

/// `CLOCK_MAX_FORWARD_STEP_MS` stated in the runtime limits the creator hands: the clock runs with
/// the stated bound, and `UHLC_MAX_DELTA_MS`, where the environment states it, is selected over
/// it. A build that keeps the build's value alone refuses the statement itself.
#[cfg(feature = "time-hlc")]
#[test]
fn clock_max_forward_step_ms_stated_is_the_bound_the_clock_runs_with() {
    use wz_session_core::limit_binding::LimitSpec;
    use wz_session_core::limits::ClockMaxForwardStepMs;
    use wz_session_core::ntp64::Ntp64;
    let ms = |n: usize| Ntp64::from_duration(core::time::Duration::from_millis(n as u64));
    let build = wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS;
    let value = if build == 20 { 30 } else { 20 };
    let mut limits = RuntimeLimits::defaults();
    let selected = limits.select_clock_max_forward_step_ms(value);
    if ClockMaxForwardStepMs::DOMAIN.is_singleton() {
        assert!(selected.is_err(), "a build of one value refuses another");
        return;
    }
    selected.expect("the value is inside the domain");
    let stated = max_delta_from(Err(std::env::VarError::NotPresent), &limits);
    assert_eq!(stated, Ok(ms(value)));
    let node = NodeHlc::over_source_bounded(
        &[0x01],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        FrozenEpoch,
        own_standing(),
        SessionPolicy::defaults().clock_quality_stamping(),
        stated,
    );
    assert_eq!(node.max_delta_word(), Some(ms(value).as_word()));
    let through_creator = NodeHlc::for_node_over_source_by(
        &[0x01],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        FrozenEpoch,
        &SessionPolicy::defaults(),
        &limits,
    );
    let resolved = max_delta_from(std::env::var(MAX_DELTA_VARIABLE), &limits);
    assert_eq!(
        through_creator.max_delta_word(),
        resolved.ok().map(|bound| bound.as_word())
    );
    assert_eq!(
        max_delta_from(Ok(build.to_string()), &limits),
        Ok(ms(build)),
        "the variable moves the bound over what the creator stated"
    );
}

/// A node of a build without the clock reads no bound, so it never refuses one.
#[test]
fn a_node_built_by_its_creator_reports_no_refusal_when_the_variable_is_unset_or_unread() {
    let node = NodeHlc::for_node_by(
        &[0x01],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    if std::env::var_os(MAX_DELTA_VARIABLE).is_none() || cfg!(not(feature = "time-hlc")) {
        assert_eq!(node.clock_refused(), None);
    }
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
        build_push_del_literal, build_push_literal_with_meta, read_publication_timestamp,
        read_push_timestamp, set_publication_timestamp,
    };

    /// A Put whose inline timestamp slot is empty — what a client that does
    /// not set one puts on the wire.
    fn bare_put() -> wz_session_core::wire::PushOwned {
        build_push_literal("demo/hlc", b"v").expect("build put")
    }

    /// A Put carrying `time` paired with `zid`.
    #[cfg(feature = "time-hlc")]
    fn stamped_put(time: u64, zid: &[u8]) -> wz_session_core::wire::PushOwned {
        let stamp = wz_session_core::sample::TimestampHint {
            time,
            zid: zid.to_vec(),
        };
        let meta = wz_session_core::metadata::PushMetadata {
            timestamp: Some(&stamp),
            ..Default::default()
        };
        build_push_literal_with_meta("demo/hlc", b"v", &meta).expect("build stamped put")
    }

    #[test]
    fn a_non_stamping_node_leaves_the_push_byte_identical() {
        // The default path off a router, and the ONLY path on a build without
        // `time-hlc`: the forward wire is unchanged by this seam existing.
        let node = NodeHlc::for_node_by(
            &[0x01],
            WhatAmI::Peer,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
        let before = bare_put();
        let mut after = before.clone();
        node.treat_timestamp(&mut after);
        assert_eq!(before, after, "a non-stamping node must not touch the Push");
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_trusted_only_node_relays_a_bare_put_unstamped_until_its_clock_is_followed() {
        let node = frozen_node_with_policy(&[0xA1], true);
        let before = bare_put();

        let mut untrusted = before.clone();
        assert_eq!(
            node.treat_timestamp(&mut untrusted),
            TimestampVerdict::Relay
        );
        assert_eq!(
            before, untrusted,
            "an untrusted clock leaves the Put as it came"
        );
        assert_eq!(node.unstamped(), 1, "and the Put is counted");

        node.report_sync_acquired();
        let mut trusted = before.clone();
        node.treat_timestamp(&mut trusted);
        assert!(
            read_push_timestamp(&trusted).is_some(),
            "a followed clock stamps"
        );
        assert_eq!(node.unstamped(), 1, "a stamped Put is not counted");
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_untrusted_clock_does_not_judge_a_future_timestamp_nor_drop_it() {
        // Dropping needs a judgement, and a clock that is not to be trusted has none to give.
        let node = frozen_node_with_policy(&[0xA1], true).with_drop_future_timestamp(true);
        let far = stamped_put(u64::MAX - 1, &[0xB2]);
        let mut push = far.clone();
        assert_eq!(node.treat_timestamp(&mut push), TimestampVerdict::Relay);
        assert_eq!(far, push);
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn an_untimestamped_put_gets_one_and_the_header_bit_agrees() {
        // zenoh `pubsub.rs:203-205` — "Timestamp not present; add one". THE
        // foreign-observable branch: a pico subscriber prints
        // `with timestamp:` only when the field is present.
        let node_zid = [0xA1, 0xB2];
        let node = NodeHlc::for_node_by(
            &node_zid,
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
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

    /// The publication of the node's OWN session is stamped on a delete as on a put: the session
    /// that publishes gives a time from its clock whatever the kind, where a router relaying a
    /// delete does not ([`a_del_is_neither_stamped_nor_allowed_to_advance_the_clock`]).
    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_delete_of_the_nodes_own_session_is_stamped_and_the_header_bit_agrees() {
        let node = frozen_node(&[0x01]);
        let before = build_push_del_literal("demo/hlc").expect("build del");
        assert!(
            read_publication_timestamp(&before).is_none(),
            "the fixture must start bare or this proves nothing"
        );
        let mut after = before.clone();
        assert_eq!(
            node.treat_own_timestamp(&mut after),
            TimestampVerdict::Relay
        );
        let ts = read_publication_timestamp(&after).expect("the session stamps its delete");
        assert_eq!(ts.zid, vec![0x01], "the stamp carries the node's zid");
        let wz_codecs::push::PushOwnedVariant::CodecZenohMsgDel(del) = &after.body else {
            panic!("fixture is a Del");
        };
        assert_eq!(
            del.header & 0x20,
            0x20,
            "the T flag moves with the field, read off the wire header"
        );
        // And the relay of a delete is as it was: not stamped.
        let mut relayed = before.clone();
        node.treat_timestamp(&mut relayed);
        assert_eq!(before, relayed);
    }

    /// A delete that already carries its time keeps it: the session stamps what has none.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_delete_that_carries_a_time_keeps_it_when_the_session_publishes_it() {
        let node = NodeHlc::for_node_by(
            &[0x01],
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
        let mut push = build_push_del_literal("demo/hlc").expect("build del");
        let given = wz_session_core::sample::TimestampHint {
            time: 1u64 << 40,
            zid: vec![0xB2],
        };
        set_publication_timestamp(&mut push, &given).expect("sets");
        let before = push.clone();
        node.treat_own_timestamp(&mut push);
        assert_eq!(
            before, push,
            "a time within the drift bound is absorbed, not replaced"
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
        let node = NodeHlc::for_node_by(
            &[0x01],
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
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
        let node = NodeHlc::for_node_by(
            &node_zid,
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
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
        let keeps = NodeHlc::for_node_by(
            &node_zid,
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        );
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
        let drops = NodeHlc::for_node_by(
            &node_zid,
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        )
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
        let node = NodeHlc::for_node_by(
            &[0x01],
            WhatAmI::Router,
            TimestampingEnabled::default(),
            &SessionPolicy::defaults(),
            &RuntimeLimits::BUILD,
        )
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

    /// A Put no route asks the stamp for leaves the clock where it was, because upstream treats
    /// the timestamp only once the route has a destination; the first route that asks absorbs
    /// it. Both arms take the same Put through the same node, so the unasked arm cannot pass on
    /// a timestamp the clock refuses either way.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_stamp_no_route_asks_for_leaves_the_clock_alone_and_the_first_ask_absorbs() {
        let node = frozen_node(&[0x01]);
        let t0 = node.stamp().expect("stamping").time;
        // A quarter of a second ahead of the frozen physical clock: inside the drift bound, so
        // absorbing it is the only thing that can carry the clock past it.
        let ahead = t0 + (1u64 << 30);
        let put = stamped_put(ahead, &[0xB2]);
        {
            let unasked = ForwardStamp::relayed(&node, &put);
            assert!(!unasked.is_taken(), "making the stamp takes nothing");
            assert_eq!(unasked.routed(), &put, "and names the Put as it arrived");
        }
        let t1 = node.stamp().expect("stamping").time;
        assert!(
            t1 < ahead,
            "a Put routed nowhere must not move the clock to its timestamp"
        );
        assert_eq!(t1 - t0, 1, "nor mint for it (frozen clock: one per mint)");

        let asked = ForwardStamp::relayed(&node, &put);
        let routed = asked
            .for_egress()
            .expect("a Put inside the bound is relayed");
        assert_eq!(
            read_push_timestamp(routed).expect("still stamped").time,
            ahead,
            "a timestamp inside the bound is absorbed, not replaced"
        );
        assert!(
            node.stamp().expect("stamping").time > ahead,
            "the first route that asks absorbs the timestamp into the clock"
        );
    }

    /// Every route after the first is given the Put the first one stamped, and the clock mints
    /// once for all of them: one Put carries one timestamp to every destination.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn every_route_after_the_first_is_given_the_put_the_first_stamped() {
        let node = frozen_node(&[0x01]);
        let put = bare_put();
        let stamp = ForwardStamp::relayed(&node, &put);
        assert!(
            read_push_timestamp(stamp.routed()).is_none(),
            "nothing is stamped before a route asks"
        );
        let t0 = node.stamp().expect("stamping").time;
        let first = stamp.for_egress().expect("relayed").clone();
        let second = stamp.for_egress().expect("relayed").clone();
        let t1 = node.stamp().expect("stamping").time;
        assert_eq!(first, second, "the second route is given the same Put");
        assert_eq!(
            read_push_timestamp(&first)
                .expect("a bare Put is minted a stamp")
                .time,
            t0 + 1,
            "minted by the first ask"
        );
        assert_eq!(
            t1 - t0,
            2,
            "the clock minted once for both asks (frozen clock: one per mint)"
        );
        assert_eq!(
            stamp.routed(),
            &first,
            "the routing log names the Put as it was stamped"
        );
    }

    /// The drop verdict is given to every route that asks, so a dropped Put reaches no
    /// destination, as upstream's `return` out of the route reaches none.
    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_dropped_put_is_refused_to_every_route_that_asks() {
        let node = frozen_node(&[0x01]).with_drop_future_timestamp(true);
        let t0 = node.stamp().expect("stamping").time;
        let far = stamped_put(t0 + (10u64 << 32), &[0xB2]);
        let stamp = ForwardStamp::relayed(&node, &far);
        assert!(
            stamp.for_egress().is_none(),
            "ten seconds past the drift bound with the knob on is dropped"
        );
        assert!(
            stamp.for_egress().is_none(),
            "and refused to the next route as well"
        );
        assert!(stamp.is_taken());
        assert_eq!(stamp.routed(), &far, "a dropped Put is named as it arrived");
    }
}

/// A Push whose stamp is settled is routed as it is: nothing is stamped on its way out.
#[cfg(feature = "codec-push")]
#[test]
fn a_settled_push_is_routed_as_it_is() {
    let put = wz_session_core::push_build::build_push_literal("demo/hlc", b"v").expect("build put");
    let stamp = ForwardStamp::settled(&put);
    assert!(stamp.is_taken(), "a settled stamp has nothing left to take");
    assert_eq!(stamp.for_egress(), Some(&put));
    assert_eq!(stamp.routed(), &put);
}

#[cfg(feature = "time-hlc")]
#[test]
fn an_oversized_or_empty_zid_still_yields_a_usable_clock() {
    // `uhlc::ID` is 1..=16 non-zero bytes. A 32-byte zid clamps and an
    // empty one falls back to the guard id, so neither panics during
    // construction — the absorb path derives an id from an INBOUND zid, so
    // this guard is reachable from the wire, not only from a test.
    let long = NodeHlc::for_node_by(
        &[0xAB; 32],
        WhatAmI::Router,
        TimestampingEnabled::all(true),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(long.stamp().is_some());
    let empty = NodeHlc::for_node_by(
        &[],
        WhatAmI::Router,
        TimestampingEnabled::all(true),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(empty.stamp().is_some());
}

/// The time word and the identity of a timestamp as an interception holds it.
#[cfg(feature = "pubsub-ts-stack")]
fn read_interception(bytes: &[u8]) -> (u64, Vec<u8>) {
    let (time, used) = wz_codecs::vle::decode_zint(bytes).expect("a time word");
    let rest = &bytes[used..];
    let (len, used) = wz_codecs::vle::decode_zint(rest).expect("a length");
    (time, rest[used..used + len as usize].to_vec())
}

#[cfg(feature = "pubsub-ts-stack")]
#[test]
fn an_interception_is_stamped_with_the_zid_of_the_node_and_strictly_increases() {
    let node = NodeHlc::for_node_by(
        &[0x0A, 0x0B],
        WhatAmI::Router,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    let mut prev = 0;
    for _ in 0..100 {
        let (time, id) = read_interception(&node.interception_timestamp().expect("a stamp"));
        assert_eq!(id, [0x0A, 0x0B]);
        assert!(time > prev);
        prev = time;
    }
}

/// Upstream falls back to a lazy HLC seeded with the zid when the node has none, so a peer that
/// stamps no data still records its interceptions.
#[cfg(feature = "pubsub-ts-stack")]
#[test]
fn a_node_whose_role_stamps_no_data_still_stamps_its_interceptions() {
    let peer = NodeHlc::for_node_by(
        &[0x01],
        WhatAmI::Peer,
        TimestampingEnabled::default(),
        &SessionPolicy::defaults(),
        &RuntimeLimits::BUILD,
    );
    assert!(peer.stamp().is_none(), "no data is stamped on a peer");
    let (_, id) = read_interception(&peer.interception_timestamp().expect("a stamp"));
    assert_eq!(id, [0x01]);
}

#[cfg(feature = "pubsub-ts-stack")]
#[test]
fn the_policy_trusted_only_does_not_refuse_an_interception() {
    let node = frozen_node_with_policy(&[0x01], true);
    assert!(
        node.stamp().is_none(),
        "no reference yet: no data is stamped"
    );
    assert!(
        node.interception_timestamp().is_some(),
        "the policy is about data passed on as the node's own"
    );
}

#[cfg(feature = "pubsub-ts-stack")]
#[test]
fn a_node_built_with_no_identity_records_no_interception() {
    assert!(NodeHlc::disabled().interception_timestamp().is_none());
}
