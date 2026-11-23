// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `entity-timestamp-opt-in` on this engine: the policy the session was opened under decides
//! whether a subscriber that states no choice, and a get that states none, see the timestamp the
//! router stamped, and a get's own choice wins over it, as the tokio engine resolves them. Each
//! value the build's domain excludes is passed over, as the tokio engine's tests pass it over.

use std::sync::{Arc, Mutex};

use wz_capi_port::{SessionEngine, WireKey};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::locality::Locality;
use wz_session_core::policy::{EntityTimestampOptIn, SessionPolicy};
use wz_session_core::sink::SampleView;

use super::{config, until, CatchAll, Command, Engine, Router, LOOPBACK};

/// What the session is opened under, and whether an entity that states nothing sees a timestamp
/// under it: hidden when taking part is opt-in, shown when it is not.
const CASES: [(EntityTimestampOptIn, bool); 2] = [
    (EntityTimestampOptIn::On, false),
    (EntityTimestampOptIn::Off, true),
];

/// A session to `router` opened under the build's policies with `entity-timestamp-opt-in` set
/// to `opt_in`; `None` when the build's domain excludes that value.
fn opened_under(router: &Router, opt_in: EntityTimestampOptIn) -> Option<Arc<Engine>> {
    let mut policy = SessionPolicy::defaults();
    policy.select_entity_timestamp_opt_in(opt_in).ok()?;
    Some(
        Engine::open_with_policy(
            PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            config(router),
            policy,
        )
        .expect("the session opens"),
    )
}

/// A subscriber declared through the port states no choice, so it sees the stamped sample's
/// timestamp exactly when the session's policy leaves taking part on.
#[test]
fn a_subscriber_sees_the_timestamp_as_the_sessions_policy_says() {
    for (opt_in, shown) in CASES {
        let router = Router::start(CatchAll::None);
        let Some(engine) = opened_under(&router, opt_in) else {
            continue;
        };
        let seen = Arc::new(Mutex::new(Vec::<bool>::new()));
        let into = seen.clone();
        engine.declare_subscriber_on_wire(
            "demo/ts/**",
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(move || {
                let into = into.clone();
                Box::new(move |sample: &dyn SampleView| {
                    // Read as the pico ABI reads it (`wz-capi-pico`'s `with_metadata`): where the
                    // view holds it first, since a sample of the delivery lane carries its
                    // timestamp as parts and no hint.
                    let stamped =
                        sample.timestamp_parts().is_some() || sample.timestamp().is_some();
                    into.lock().unwrap().push(stamped);
                })
            }),
        );
        until(&engine, "the router to see the subscriber", || {
            router.seen(|s| s.declares) >= 1
        });
        router.send(Command::PushStamped("demo/ts/a", b"v"));
        until(&engine, "the stamped sample", || {
            !seen.lock().unwrap().is_empty()
        });
        assert_eq!(
            *seen.lock().unwrap(),
            [shown],
            "opened under {opt_in:?}, the subscriber sees the timestamp when it is {shown}"
        );
    }
}

/// A get that states no choice sees the stamped reply's timestamp as the session's policy says,
/// and one that states a choice has it whatever the policy.
#[cfg(feature = "query")]
#[test]
fn a_get_sees_the_reply_timestamp_as_the_policy_says_unless_it_chooses() {
    use wz_capi_port::ReplyCallback;
    use wz_session_core::reply_sink::ReplyView;

    use super::get::{remote_get, settle};

    for (opt_in, shown) in CASES {
        let router = Router::start(CatchAll::None);
        let Some(engine) = opened_under(&router, opt_in) else {
            continue;
        };
        settle(&router, &engine, Command::AnswerStamped("demo/ts/**", b"r"));
        for (opts, want) in [
            (remote_get(), shown),
            (remote_get().with_expose_timestamp(!shown), !shown),
        ] {
            let seen = Arc::new(Mutex::new(Vec::<bool>::new()));
            let into = seen.clone();
            let issued =
                engine.get_on_wire("demo/ts/a", &WireKey::literal(), &opts, None, &mut || {
                    let into = into.clone();
                    Box::new(move |reply: &dyn ReplyView| {
                        // Read as the pico ABI reads it (`wz-capi-pico`'s `get.rs`): where the
                        // view holds it first, since a reply of the delivery lane carries its
                        // timestamp as parts and no hint.
                        let stamped =
                            reply.timestamp_parts().is_some() || reply.timestamp().is_some();
                        into.lock().unwrap().push(stamped);
                    }) as ReplyCallback
                });
            assert_eq!(issued, Ok(1), "one leg, to the router");
            until(&engine, "the stamped reply", || {
                !seen.lock().unwrap().is_empty()
            });
            assert_eq!(
                *seen.lock().unwrap(),
                [want],
                "opened under {opt_in:?}, the get sees the reply's timestamp when it is {want}"
            );
        }
    }
}
