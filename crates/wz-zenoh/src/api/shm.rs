//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/net/runtime/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The provider of the
// session is made here, from the `transport/shared_memory` section, where upstream asks the
// transport manager for it through the runtime's `get_shm_provider`
// (docs/zenoh-api-on-the-engine.md, slice Z7a).

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

/// What carries a buffer of shared memory across the engine, in both directions.
///
/// The process holds two shared-memory systems that share no type: this crate's (`zenoh::shm`,
/// the family crate `zenoh-shm`), whose buffer an application holds as a `ZShm`, and the engine's
/// own. They agree on the protocol (POSIX segments, a metadata slot that counts references, the
/// descriptor on the wire), so the buffer is carried and not converted: the engine is given a
/// [`ShmSendBuffer`] that wraps the slice of the application's `ZBytes` to send, and a
/// [`ShmResolver`] that reads a received descriptor with this crate's reader into a slice the
/// application receives as it is. The reference a sender takes for its receiver is the one the
/// receiver's slice gives back when it drops, exactly as in upstream's codec.
#[cfg(all(feature = "shared-memory", feature = "engine-tokio"))]
pub(crate) mod transport {
    use std::{any::Any, num::NonZeroUsize, sync::Arc};

    use wz_session_core::{
        extshm::{ShmDescriptor, ShmReservation, ShmResolver, ShmSendBuffer, ShmSendHandle},
        link::{RxBytes, RxStorage, ShmChunkView},
    };
    use zenoh_buffers::ZSlice;
    use zenoh_shm::{
        api::client_storage::{ShmClientStorage, GLOBAL_CLIENT_STORAGE},
        metadata::descriptor::MetadataDescriptor,
        reader::ShmReader,
        ShmBufInfo, ShmBufInner,
    };

    use crate::api::bytes::ZBytes;

    fn buffer_of(slice: &ZSlice) -> Option<&ShmBufInner> {
        slice.downcast_ref::<ShmBufInner>()
    }

    /// A slice of shared memory as the engine hands it up: the bytes are the page, and the slice
    /// itself can be got back out of the view ([`RxStorage::as_any`]).
    struct SliceStorage {
        slice: ZSlice,
    }

    impl RxStorage for SliceStorage {
        fn as_slice(&self) -> &[u8] {
            self.slice.as_slice()
        }

        fn shm_chunk(&self) -> Option<&dyn ShmChunkView> {
            Some(self)
        }

        fn as_any(&self) -> Option<&dyn Any> {
            Some(self)
        }
    }

    impl ShmChunkView for SliceStorage {
        fn is_unique(&self) -> bool {
            buffer_of(&self.slice).is_some_and(|buffer| buffer.ref_count() == 1)
        }

        fn writable_ptr(&self) -> Option<*mut u8> {
            None
        }
    }

    /// The view of `slice` the engine hands a receiver.
    fn view_of(slice: ZSlice) -> Option<RxBytes> {
        let len = slice.as_slice().len();
        RxBytes::shared(Arc::new(SliceStorage { slice }), 0..len)
    }

    /// The payload a received view carries, when it is a slice of shared memory this reader
    /// made; `None` for any other bytes, which the caller copies as it always did.
    pub(crate) fn payload_of(view: &RxBytes) -> Option<ZBytes> {
        let (any, range) = view.host_storage()?;
        let storage = any.downcast_ref::<SliceStorage>()?;
        // A payload that is a part of the buffer is not the buffer.
        (range == (0..storage.slice.as_slice().len()))
            .then(|| ZBytes::from_shm_slice(storage.slice.clone()))
    }

    /// The buffer a put of `payload` is sent from, when it is one slice of shared memory.
    pub(crate) fn send_handle_of(payload: &ZBytes) -> Option<ShmSendHandle> {
        let slice = payload.single_shm_slice()?;
        buffer_of(slice)?;
        Some(ShmSendHandle::new(Arc::new(SendBuffer {
            slice: slice.clone(),
        })))
    }

    /// A buffer some provider of this process owns, as the engine sends it.
    struct SendBuffer {
        slice: ZSlice,
    }

    impl SendBuffer {
        fn buffer(&self) -> &ShmBufInner {
            // Checked where the handle is made: the slice is a `ShmBufInner`.
            buffer_of(&self.slice).expect("a send buffer wraps a shared-memory slice")
        }
    }

    impl ShmSendBuffer for SendBuffer {
        fn bytes(&self) -> &[u8] {
            self.slice.as_slice()
        }

        fn protocol(&self) -> u32 {
            self.buffer().protocol()
        }

        fn receiver_view(&self) -> Option<RxBytes> {
            view_of(self.slice.clone())
        }

        fn reserve_for_receiver(self: Arc<Self>) -> Box<dyn ShmReservation> {
            // SAFETY: the reference taken here is the receiver's, given back by `commit`'s
            // receiver when it lets go, or by this reservation when the frame is not sent.
            unsafe { self.buffer().inc_ref_count() };
            Box::new(Reservation {
                buffer: self,
                committed: false,
            })
        }
    }

    /// The reference taken for one receiver, and the descriptor naming it.
    struct Reservation {
        buffer: Arc<SendBuffer>,
        committed: bool,
    }

    impl ShmReservation for Reservation {
        fn descriptor(&self) -> ShmDescriptor {
            let info = &self.buffer.buffer().info;
            ShmDescriptor {
                data_len: u32::try_from(info.data_len.get()).unwrap_or(u32::MAX),
                metadata_id: info.metadata.id,
                metadata_index: info.metadata.index,
                generation: info.generation,
            }
        }

        fn commit(mut self: Box<Self>) {
            self.committed = true;
        }
    }

    impl Drop for Reservation {
        fn drop(&mut self) {
            if !self.committed {
                // SAFETY: the reference this reservation took and nobody was sent.
                unsafe { self.buffer.buffer().release_reference() };
            }
        }
    }

    /// Reads a received descriptor with this crate's reader.
    pub(crate) struct ReaderResolver {
        reader: ShmReader,
    }

    impl ReaderResolver {
        pub(crate) fn new(storage: Arc<ShmClientStorage>) -> Self {
            Self {
                reader: ShmReader::new(storage),
            }
        }

        /// The buffer `descriptor` names. It owns the reference the sender took for this
        /// receiver, and gives it back when it drops.
        fn read(&self, descriptor: &ShmDescriptor) -> Option<Arc<ShmBufInner>> {
            let info = ShmBufInfo::new(
                NonZeroUsize::new(descriptor.data_len as usize)?,
                MetadataDescriptor {
                    id: descriptor.metadata_id,
                    index: descriptor.metadata_index,
                },
                descriptor.generation,
            );
            self.reader.read_shmbuf(info).ok()
        }
    }

    impl ShmResolver for ReaderResolver {
        fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
            let buffer = self.read(descriptor)?;
            Some(AsRef::<[u8]>::as_ref(&*buffer).to_vec())
        }

        fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<RxBytes> {
            view_of(ZSlice::from(self.read(descriptor)?))
        }
    }

    /// The implicit optimisation of large messages: a payload that is a plain buffer as large as
    /// `transport/shared_memory/transport_optimization/message_size_threshold` is copied into the
    /// session's provider, so that it is sent to a peer that negotiated shared memory as a
    /// descriptor and not as bytes (upstream does the same at the link, per peer, in
    /// `io/zenoh-transport/src/common/shm/interop.rs` @ `fn wrap_in_place<const ID: u8>(`).
    ///
    /// Done for a message the configuration lists (`messages`) and only when some peer could read
    /// it, so a session none of whose peers shares memory copies nothing. The provider is made on
    /// the first large message, in the background, and a message that finds it not yet made is
    /// sent as bytes, as upstream's is.
    #[cfg(feature = "unstable")]
    pub(crate) struct Promoter {
        provider: Arc<super::LazyShmProvider>,
        threshold: usize,
        put: bool,
    }

    #[cfg(feature = "unstable")]
    impl Promoter {
        /// The promoter the configuration asks for, or `None` when it asks for none (shared memory
        /// off, or its transport optimisation off).
        pub(crate) fn new(
            config: &zenoh_config::ExpandedConfig,
            provider: Option<&Arc<super::LazyShmProvider>>,
        ) -> Option<Self> {
            let provider = Arc::clone(provider?);
            let optimisation = &config.transport().shared_memory().transport_optimization;
            Some(Self {
                provider,
                threshold: *optimisation.message_size_threshold(),
                put: optimisation
                    .messages()
                    .contains(&zenoh_config::DataMessage::Put),
            })
        }

        /// `payload` as a buffer of shared memory, when a put of it is to be promoted and some
        /// peer could read the promoted buffer; `None` when it is to be sent as it is.
        pub(crate) fn promote(
            &self,
            payload: &ZBytes,
            peer_shares_memory: impl FnOnce() -> bool,
        ) -> Option<ShmSendHandle> {
            use zenoh_core::Wait;
            use zenoh_shm::api::provider::shm_provider::{
                ConstBool, Defragment, GarbageCollect, JustAlloc,
            };

            if !self.put || payload.is_empty() || payload.len() < self.threshold {
                return None;
            }
            if payload.single_shm_slice().is_some() || !peer_shares_memory() {
                return None;
            }
            let crate::net::runtime::ShmProviderState::Ready(provider) = self.provider.state()
            else {
                return None;
            };
            let bytes = payload.to_bytes();
            // SAFETY: the policy is upstream's for this copy: it may defragment and collect, and
            // the buffer it returns is ours alone until it is sent.
            let mut buffer = unsafe {
                provider
                    .alloc(bytes.len())
                    .with_unsafe_policy::<Defragment<GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>>>()
                    .wait()
            }
            .ok()?;
            buffer.as_mut().copy_from_slice(&bytes);
            send_handle_of(&ZBytes::from_shm_slice(buffer.into()))
        }
    }

    /// The reader every session of an engine is given: over the storage of clients the
    /// application opened the session with, or over the process's global one.
    pub(crate) fn resolver_factory(
        storage: Option<Arc<ShmClientStorage>>,
    ) -> Arc<dyn Fn() -> Box<dyn ShmResolver + Send + Sync> + Send + Sync> {
        Arc::new(move || {
            let storage = storage
                .clone()
                .unwrap_or_else(|| Arc::clone(&GLOBAL_CLIENT_STORAGE.read()));
            Box::new(ReaderResolver::new(storage))
        })
    }

    /// The reference a sender takes for its receiver, counted in the buffer's own header: given
    /// back when the frame is not sent, and kept for the receiver when it is.
    #[cfg(test)]
    mod reservation_tests {
        use zenoh_core::Wait;
        use zenoh_shm::api::provider::shm_provider::{
            ConstBool, Defragment, GarbageCollect, JustAlloc, ShmProviderBuilder,
        };

        use super::*;

        /// A payload that is one buffer of a provider of its own, and the provider, which must
        /// outlive it.
        fn a_shared_payload() -> (impl Sized, ZBytes) {
            let provider = ShmProviderBuilder::default_backend(65536usize)
                .wait()
                .expect("a provider");
            // SAFETY: the policy is upstream's for a copy into a fresh buffer; the buffer is ours
            // alone until it is put in the payload.
            let mut buffer = unsafe {
                provider
                    .alloc(64)
                    .with_unsafe_policy::<Defragment<GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>>>()
                    .wait()
            }
            .expect("a buffer");
            buffer.as_mut().copy_from_slice(&[7u8; 64]);
            let payload = ZBytes::from_shm_slice(buffer.into());
            (provider, payload)
        }

        fn references(payload: &ZBytes) -> u32 {
            let slice = payload
                .single_shm_slice()
                .expect("one slice of shared memory");
            buffer_of(slice)
                .expect("a buffer of shared memory")
                .ref_count()
        }

        #[test]
        fn a_reservation_that_is_dropped_gives_its_reference_back() {
            let (_provider, payload) = a_shared_payload();
            let base = references(&payload);
            let handle = send_handle_of(&payload).expect("a handle of the buffer");

            let reservation = handle.reserve_for_receiver();
            assert_eq!(
                references(&payload),
                base + 1,
                "the receiver's reference is taken"
            );
            drop(reservation);
            assert_eq!(
                references(&payload),
                base,
                "the frame was not sent: it is given back"
            );
        }

        #[test]
        fn a_committed_reservation_leaves_the_receivers_reference_and_the_receiver_returns_it() {
            let (_provider, payload) = a_shared_payload();
            let base = references(&payload);
            let handle = send_handle_of(&payload).expect("a handle of the buffer");

            let reservation = handle.reserve_for_receiver();
            let descriptor = reservation.descriptor();
            reservation.commit();
            assert_eq!(
                references(&payload),
                base + 1,
                "the frame left: exactly one reference stands for the receiver"
            );

            let resolver = ReaderResolver::new(Arc::clone(&GLOBAL_CLIENT_STORAGE.read()));
            let received = resolver
                .read(&descriptor)
                .expect("the receiver reads the descriptor");
            assert_eq!(
                references(&payload),
                base + 1,
                "reading takes no reference of its own"
            );
            drop(received);
            assert_eq!(
                references(&payload),
                base,
                "the receiver's drop returns the reference"
            );
        }
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
