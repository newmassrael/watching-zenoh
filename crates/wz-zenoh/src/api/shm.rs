// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session does with the `transport/shared_memory` section of its configuration.
//!
//! * [`init_if_asked`]: initialise the shared memory subsystem as the session opens
//!   (`mode` = `init`), which upstream does whether or not the session has a provider;
//! * with `unstable`, the provider of the session, made when it is first asked for. Upstream
//!   builds one in the transport manager (`ShmContext::new`, `LazyShmProvider`): the section says
//!   whether the session has one at all (`enabled`, and `transport_optimization/enabled`) and how
//!   big its pool is (`transport_optimization/pool_size`). It is made on a thread of its own the
//!   first time it is asked for, and the asker is given the receiver of the result, which a later
//!   ask turns into the provider (or into an error that stays).
//!
//! What the provider is not: the provider of the engine. The engine keeps shared memory of its own
//! and this provider does not feed it, so the implicit promotion of a large payload into shared
//! memory that upstream does with this provider is not done (`docs/zenoh-api-on-the-engine.md`,
//! Z7).

/// Initialise the shared memory subsystem as the session opens when the configuration asks for it
/// (`transport/shared_memory/mode` = `init`); in the default `lazy` mode the first use does.
pub(crate) fn init_if_asked(config: &zenoh_config::ExpandedConfig) {
    if matches!(
        config.transport().shared_memory().mode(),
        zenoh_config::ShmInitMode::Init
    ) {
        zenoh_shm::init::init();
    }
}

#[cfg(feature = "unstable")]
pub(crate) use lazy::{provider_of, LazyShmProvider};

#[cfg(feature = "unstable")]
mod lazy {
    use std::{
        num::NonZeroUsize,
        sync::{Arc, Mutex},
    };

    use zenoh_core::Wait;
    use zenoh_shm::api::{
        protocol_implementations::posix::posix_shm_provider_backend::PosixShmProviderBackend,
        provider::shm_provider::{ShmProvider, ShmProviderBuilder},
    };

    use crate::net::runtime::ShmProviderState;

    type Made = Option<Arc<ShmProvider<PosixShmProviderBackend>>>;

    enum Stage {
        /// Not asked for yet: the size of the pool to make.
        Enabled(NonZeroUsize),
        /// Being made.
        Initializing(flume::Receiver<Made>),
        Ready(Arc<ShmProvider<PosixShmProviderBackend>>),
        /// Could not be made; it stays so.
        Error,
    }

    /// The provider of a session, lazily made.
    pub(crate) struct LazyShmProvider {
        stage: Mutex<Stage>,
    }

    impl std::fmt::Debug for LazyShmProvider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LazyShmProvider").finish_non_exhaustive()
        }
    }

    impl LazyShmProvider {
        pub(crate) fn new(pool_size: NonZeroUsize) -> Self {
            Self {
                stage: Mutex::new(Stage::Enabled(pool_size)),
            }
        }

        /// The provider as it is now: the first ask starts it, and a later one finds it made.
        pub(crate) fn state(&self) -> ShmProviderState {
            let mut stage = self
                .stage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match &*stage {
                Stage::Enabled(size) => {
                    let size = size.get();
                    let (sender, receiver) = flume::bounded(1);
                    let spawned = std::thread::Builder::new()
                        .name("wz-zenoh-shm-provider".to_owned())
                        .spawn(move || {
                            let _ = sender.send(
                                match ShmProviderBuilder::default_backend(size).wait() {
                                    Ok(provider) => Some(Arc::new(provider)),
                                    Err(error) => {
                                        tracing::error!("Error creating lazy ShmProvider: {error}");
                                        None
                                    }
                                },
                            );
                        });
                    if let Err(error) = spawned {
                        tracing::error!("Error creating lazy ShmProvider: {error}");
                        *stage = Stage::Error;
                        return ShmProviderState::Error;
                    }
                    *stage = Stage::Initializing(receiver.clone());
                    ShmProviderState::Initializing(receiver)
                }
                Stage::Initializing(receiver) => match receiver.try_recv() {
                    Ok(Some(provider)) => {
                        *stage = Stage::Ready(provider.clone());
                        ShmProviderState::Ready(provider)
                    }
                    Ok(None) => {
                        *stage = Stage::Error;
                        ShmProviderState::Error
                    }
                    Err(_) => ShmProviderState::Initializing(receiver.clone()),
                },
                Stage::Ready(provider) => ShmProviderState::Ready(provider.clone()),
                Stage::Error => ShmProviderState::Error,
            }
        }
    }

    /// The provider a session would make, from the shared memory section of its configuration.
    ///
    /// `None` is a session with no provider: shared memory disabled, or its transport
    /// optimisation.
    pub(crate) fn provider_of(
        config: &zenoh_config::ExpandedConfig,
    ) -> Option<Arc<LazyShmProvider>> {
        let shm = config.transport().shared_memory();
        if !*shm.enabled() {
            return None;
        }
        let optimisation = &shm.transport_optimization;
        (*optimisation.enabled()).then(|| Arc::new(LazyShmProvider::new(*optimisation.pool_size())))
    }

    #[cfg(test)]
    mod tests {
        use std::time::{Duration, Instant};

        use super::*;

        fn expanded(shared_memory: &str) -> zenoh_config::ExpandedConfig {
            crate::config::Config::from_json5(&format!(
                r#"{{ transport: {{ shared_memory: {{ {shared_memory} }} }} }}"#
            ))
            .expect("a configuration zenoh reads")
            .0
            .expanded()
        }

        /// Ask `provider` until its state is one `done` accepts, for five seconds at most.
        fn until(
            provider: &LazyShmProvider,
            done: impl Fn(&ShmProviderState) -> bool,
        ) -> ShmProviderState {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let state = provider.state();
                if done(&state) || Instant::now() > deadline {
                    return state;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn the_configuration_decides_whether_a_session_has_a_provider() {
            assert!(provider_of(&expanded("")).is_some(), "the default has one");
            assert!(
                provider_of(&expanded("enabled: false")).is_none(),
                "shared memory off"
            );
            assert!(
                provider_of(&expanded("transport_optimization: { enabled: false }")).is_none(),
                "the transport optimisation off"
            );
            assert!(
                provider_of(&expanded(
                    "enabled: false, transport_optimization: { enabled: true }"
                ))
                .is_none(),
                "the optimisation is no reason to have one when shared memory is off"
            );
        }

        #[test]
        fn the_first_ask_starts_the_provider_and_it_is_there_a_moment_later() {
            let provider = LazyShmProvider::new(NonZeroUsize::new(1 << 20).unwrap());
            let first = provider.state();
            assert!(
                matches!(first, ShmProviderState::Initializing(_)),
                "{first:?}"
            );
            assert!(first.into_option().is_none(), "into_option never waits");
            let ready = until(&provider, |state| {
                matches!(state, ShmProviderState::Ready(_))
            });
            assert!(matches!(ready, ShmProviderState::Ready(_)), "{ready:?}");
            assert!(
                matches!(provider.state(), ShmProviderState::Ready(_)),
                "it stays ready"
            );
        }

        #[test]
        fn waiting_for_the_first_ask_gives_the_provider() {
            let provider = LazyShmProvider::new(NonZeroUsize::new(1 << 20).unwrap());
            assert!(provider.state().wait().is_some());
        }

        #[test]
        fn a_pool_no_system_gives_is_an_error_that_stays() {
            let provider = LazyShmProvider::new(NonZeroUsize::new(1 << 62).unwrap());
            assert!(matches!(
                provider.state(),
                ShmProviderState::Initializing(_)
            ));
            let failed = until(&provider, |state| matches!(state, ShmProviderState::Error));
            assert!(matches!(failed, ShmProviderState::Error), "{failed:?}");
            assert!(
                matches!(provider.state(), ShmProviderState::Error),
                "it does not try again"
            );
        }
    }
}
