// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the shared memory provider of a session in the shared-memory arm (slice Z7 of the top
//! crate): upstream's crate (`up_zenoh`) and wz's (`wz_zenoh`) opened with the same configurations,
//! asked for the provider the same way, results equal as text.
//!
//! * the state the session reports on the first ask, after waiting for it, and on a later ask: a
//!   session with the default configuration has a provider that is not there yet, then is; one
//!   whose shared memory, or whose transport optimisation, is disabled has none;
//! * the provider that comes out: how much it holds and what it hands out;
//! * the state as a future, and `into_option`, which never waits;
//! * a pool no operating system can give, which is an error that stays;
//! * a session opened with the clients of shared memory segments of the application.
//!
//! The crates share the machine's segments, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::{
    future::Future,
    pin::pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// What runs a future to its end on the calling thread: the ones compared here need no reactor.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Thread(std::thread::Thread);
    impl Wake for Thread {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Thread(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::park();
    }
}

macro_rules! session_cases {
    ($name:ident, $z:ident, $core:ident) => {
        mod $name {
            use std::{future::IntoFuture, sync::Arc, time::Duration};

            use $core::Wait;
            use $z::{
                shm::{ShmClientStorage, ShmProviderState},
                Config,
            };

            fn config(shared_memory: &str) -> Config {
                Config::from_json5(&format!(
                    r#"{{ mode: "peer",
                          listen: {{ endpoints: [] }}, connect: {{ endpoints: [] }},
                          scouting: {{ multicast: {{ enabled: false }} }},
                          transport: {{ shared_memory: {{ {shared_memory} }} }} }}"#
                ))
                .expect("a configuration zenoh reads")
            }

            fn kind(state: &ShmProviderState) -> &'static str {
                match state {
                    ShmProviderState::Disabled => "Disabled",
                    ShmProviderState::Initializing(_) => "Initializing",
                    ShmProviderState::Ready(_) => "Ready",
                    ShmProviderState::Error => "Error",
                }
            }

            /// A session opened with `shared_memory` as its section of the configuration, asked
            /// for its provider three ways.
            fn case(label: &str, shared_memory: &str, out: &mut Vec<String>) {
                let session = match $z::open(config(shared_memory)).wait() {
                    Ok(session) => session,
                    Err(error) => {
                        out.push(format!("{label}: does not open: {error}"));
                        return;
                    }
                };
                let first = session.get_shm_provider();
                out.push(format!("{label}: first ask is {}", kind(&first)));
                let provider = first.wait();
                out.push(format!(
                    "{label}: waited, {}",
                    match &provider {
                        Some(provider) => format!(
                            "a provider holding {} of {}",
                            provider.available(),
                            shared_memory
                        ),
                        None => "none".to_owned(),
                    }
                ));
                let later = session.get_shm_provider();
                out.push(format!(
                    "{label}: later ask is {} and into_option is some: {}",
                    kind(&later),
                    session.get_shm_provider().into_option().is_some()
                ));
                if let Some(provider) = provider {
                    out.push(format!(
                        "{label}: the provider hands out {:?}",
                        provider
                            .alloc(1024usize)
                            .wait()
                            .map(|buffer| buffer.len())
                            .map_err(|e| format!("{e:?}"))
                    ));
                }
                out.push(format!(
                    "{label}: as a future, {}",
                    super::block_on(session.get_shm_provider().into_future()).is_some()
                ));
            }

            pub fn scenario() -> Vec<String> {
                let mut out = vec![];
                case("default", "", &mut out);
                case("a small pool", "transport_optimization: { pool_size: 1048576 }", &mut out);
                case("shared memory off", "enabled: false", &mut out);
                case(
                    "transport optimisation off",
                    "transport_optimization: { enabled: false }",
                    &mut out,
                );
                case("init mode", "mode: \"init\"", &mut out);
                case(
                    "a pool no system gives",
                    "transport_optimization: { pool_size: 4611686018427387904 }",
                    &mut out,
                );

                // Into_option never waits: right after the first ask it holds nothing, and the
                // provider is there a moment later.
                let session = $z::open(config("")).wait().expect("opens");
                out.push(format!(
                    "into_option at once: {}",
                    session.get_shm_provider().into_option().is_some()
                ));
                std::thread::sleep(Duration::from_millis(300));
                out.push(format!(
                    "into_option later: {}",
                    session.get_shm_provider().into_option().is_some()
                ));

                // The clients of the application.
                let clients = Arc::new(ShmClientStorage::builder().with_default_client_set().build());
                match $z::open(config("")).with_shm_clients(clients).wait() {
                    Ok(session) => out.push(format!(
                        "with clients: opens, first ask is {}",
                        kind(&session.get_shm_provider())
                    )),
                    Err(error) => out.push(format!("with clients: does not open: {error}")),
                }
                out
            }
        }
    };
}

session_cases!(up, up_zenoh, up_core);
session_cases!(wz, wz_zenoh, wz_core);

#[test]
fn the_provider_of_a_session_is_what_upstream_gives() {
    let _g = serial();
    let (u, w) = (up::scenario(), wz::scenario());
    assert!(u.iter().any(|l| l == "default: first ask is Initializing"), "{u:#?}");
    assert!(u.iter().any(|l| l == "shared memory off: first ask is Disabled"), "{u:#?}");
    assert!(u.iter().any(|l| l == "into_option at once: false"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("with clients: opens")), "{u:#?}");
    assert_eq!(u, w);
}

#[test]
fn the_comparison_sees_a_scenario_that_differs() {
    let _g = serial();
    let u = up::scenario();
    let mut w = wz::scenario();
    w[0] = format!("{} changed", w[0]);
    assert_ne!(u, w);
}
