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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.2, file
// src/api/client_storage/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{collections::BTreeMap, sync::Arc};

use static_init::dynamic;
use zenoh_result::{bail, ZResult};

use crate::{
    api::{
        client::{shm_client::ShmClient, shm_segment::ShmSegment},
        common::{types::ProtocolID, with_id::WithProtocolID},
        protocol_implementations::posix::posix_shm_client::PosixShmClient,
    },
    reader::{ClientStorage, GlobalDataSegmentId},
    segment_cache::{SegmentCache, RETAINED_SEGMENTS},
};

#[dynamic(lazy, drop)]
/// A global lazily-initialized SHM client storage.
///
/// When initialized, contains default client set, see [with_default_client_set](ShmClientSetBuilder::with_default_client_set)
#[zenoh_macros::unstable_doc]
pub static mut GLOBAL_CLIENT_STORAGE: Arc<ShmClientStorage> = Arc::new(
    ShmClientStorage::builder()
        .with_default_client_set()
        .build(),
);

/// Builder to create new client storages
#[zenoh_macros::unstable_doc]
#[derive(Debug)]
pub struct ShmClientSetBuilder;

impl ShmClientSetBuilder {
    /// Add client to the storage (without including the default client set)
    #[zenoh_macros::unstable_doc]
    pub fn with_client(self, client: Arc<dyn ShmClient>) -> ShmClientStorageBuilder {
        let clients = BTreeMap::from([(client.id(), client)]);
        ShmClientStorageBuilder::new(clients)
    }

    /// Add list of clients to the storage (without including the default client set)
    #[zenoh_macros::unstable_doc]
    pub fn with_clients(self, clients: &[Arc<dyn ShmClient>]) -> ShmClientStorageBuilder {
        let clients = clients
            .iter()
            .cloned()
            .map(|client| (client.id(), client))
            .collect();
        ShmClientStorageBuilder::new(clients)
    }

    /// Include default clients
    #[zenoh_macros::unstable_doc]
    pub fn with_default_client_set(self) -> ShmClientStorageBuilder {
        let client = PosixShmClient {};
        let clients = BTreeMap::from([(client.id(), Arc::new(client) as Arc<dyn ShmClient>)]);
        ShmClientStorageBuilder::new(clients)
    }
}

#[zenoh_macros::unstable_doc]
pub struct ShmClientStorageBuilder {
    clients: BTreeMap<ProtocolID, Arc<dyn ShmClient>>,
}

impl std::fmt::Debug for ShmClientStorageBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShmClientStorageBuilder")
            .field("clients_len", &self.clients.len())
            .finish()
    }
}

impl ShmClientStorageBuilder {
    fn new(clients: BTreeMap<ProtocolID, Arc<dyn ShmClient>>) -> Self {
        Self { clients }
    }

    /// Add client to the storage
    #[zenoh_macros::unstable_doc]
    pub fn with_client(mut self, client: Arc<dyn ShmClient>) -> ZResult<Self> {
        let id = client.id();
        match self.clients.entry(id) {
            std::collections::btree_map::Entry::Occupied(occupied) => {
                bail!("Client already exists for id {id}: {:?}!", occupied)
            }
            std::collections::btree_map::Entry::Vacant(vacant) => {
                vacant.insert(client as Arc<dyn ShmClient>);
                Ok(self)
            }
        }
    }

    /// Add list of clients to the storage
    #[zenoh_macros::unstable_doc]
    pub fn with_clients(mut self, clients: &[Arc<dyn ShmClient>]) -> Self {
        self.clients
            .extend(clients.iter().cloned().map(|client| (client.id(), client)));
        self
    }

    /// Build the storage with parameters specified on previous step
    #[zenoh_macros::unstable_doc]
    pub fn build(self) -> ShmClientStorage {
        ShmClientStorage::new(self.clients)
    }

    /// [`Self::build`], keeping at most `retained` data segments mapped that no buffer points
    /// into (16 by default; 0 maps a segment exactly while a buffer of it is held). Hidden: upstream
    /// has no such knob, and the tests of the bound are what name it.
    #[doc(hidden)]
    pub fn build_retaining(self, retained: usize) -> ShmClientStorage {
        ShmClientStorage::with_retained(self.clients, retained)
    }
}

/// A storage for SHM clients.
///
/// Runtime or Session constructed with instance of this type gets capabilities to read
/// SHM buffers for Protocols added to this instance.
#[zenoh_macros::unstable_doc]
#[derive(Debug)]
pub struct ShmClientStorage {
    pub(crate) clients: ClientStorage<Arc<dyn ShmClient>>,
    /// The data segments this storage's readers mapped: each held by the buffers that point into
    /// it, and the last ones used by the table itself (`SegmentCache`). Upstream's map holds every
    /// segment it mapped for the life of the storage.
    pub(crate) segments: SegmentCache<GlobalDataSegmentId, dyn ShmSegment>,
}

impl Eq for ShmClientStorage {}

impl PartialEq for ShmClientStorage {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl ShmClientStorage {
    /// Get the builder to construct a new storage
    #[zenoh_macros::unstable_doc]
    pub fn builder() -> ShmClientSetBuilder {
        ShmClientSetBuilder
    }

    /// Get the list of supported SHM protocols.
    #[zenoh_macros::unstable_doc]
    pub fn supported_protocols(&self) -> Vec<ProtocolID> {
        self.clients.get_clients().keys().copied().collect()
    }

    /// The client this storage reads `protocol` through, if it holds one. Upstream keeps the
    /// clients to itself; the C ABI of this repository reads a storage it built back through
    /// this, so it is hidden from the documentation for the reason
    /// `ShmBufInner::release_reference` is.
    #[doc(hidden)]
    pub fn client(&self, protocol: ProtocolID) -> Option<&Arc<dyn ShmClient>> {
        self.clients.get_clients().get(&protocol)
    }

    /// How many data segments the storage holds mapped now: those a buffer of a reader points
    /// into, and the last ones used. A diagnostic, hidden for the reason [`Self::client`] is.
    #[doc(hidden)]
    pub fn mapped_segments(&self) -> usize {
        self.segments.mapped()
    }

    fn new(clients: BTreeMap<ProtocolID, Arc<dyn ShmClient>>) -> Self {
        Self::with_retained(clients, RETAINED_SEGMENTS)
    }

    fn with_retained(clients: BTreeMap<ProtocolID, Arc<dyn ShmClient>>, retained: usize) -> Self {
        Self {
            clients: ClientStorage::new(clients),
            segments: SegmentCache::new(retained),
        }
    }
}
