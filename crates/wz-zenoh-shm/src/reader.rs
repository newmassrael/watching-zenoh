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
// src/reader.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{atomic::Ordering, Arc},
};

use zenoh_core::{bail, zerror};
use zenoh_result::ZResult;

use crate::{
    api::{
        client::shm_segment::ShmSegment,
        client_storage::ShmClientStorage,
        common::types::{ProtocolID, PtrInSegment, SegmentID},
        provider::chunk::ChunkDescriptor,
    },
    metadata::subscription::GLOBAL_METADATA_SUBSCRIPTION,
    release_one_reference,
    watchdog::confirmator::{ConfirmedDescriptor, GLOBAL_CONFIRMATOR},
    ShmBufInfo, ShmBufInner,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ShmReader {
    client_storage: Arc<ShmClientStorage>,
}

impl Deref for ShmReader {
    type Target = ShmClientStorage;

    fn deref(&self) -> &Self::Target {
        &self.client_storage
    }
}

impl ShmReader {
    pub fn new(client_storage: Arc<ShmClientStorage>) -> Self {
        Self { client_storage }
    }

    pub fn read_shmbuf(&self, info: ShmBufInfo) -> ZResult<Arc<ShmBufInner>> {
        // Read does not increment the reference count as it is assumed
        // that the sender of this buffer has incremented it for us.

        let metadata = GLOBAL_METADATA_SUBSCRIPTION.read().link(&info.metadata)?;

        // A header of another generation belongs to another buffer, whose reference count and
        // watchdog are not this reader's to touch, so the generation is checked before anything
        // else is done with the header. The original checks it only once the buffer is built,
        // and the drop of that buffer then gives back a reference of the other one.
        if metadata.header().generation.load(Ordering::SeqCst) != info.generation {
            bail!("Buffer is invalidated");
        }

        // attach to the watchdog before doing other things
        let confirmed_metadata = GLOBAL_CONFIRMATOR.read().add(metadata);

        // From here the reference the sender took is this reader's, and every way out gives it
        // back once: a failure before the buffer is built gives it back here, and the drop of the
        // buffer does after. The original keeps it on the failures before the buffer is built, so
        // the sender's chunk never goes back to its pool.
        let buf = match self.map_chunk(&confirmed_metadata, &info) {
            Ok(buf) => buf,
            Err(e) => {
                release_one_reference(&confirmed_metadata.owned.header().refcount);
                return Err(e);
            }
        };
        let shmb = Arc::new(ShmBufInner {
            metadata: confirmed_metadata,
            buf,
            info,
        });

        // Validate buffer
        match shmb.is_valid() {
            true => Ok(shmb),
            false => bail!("Buffer is invalidated"),
        }
    }

    /// The chunk the header of `confirmed` names, mapped through the client of its protocol.
    fn map_chunk(
        &self,
        confirmed: &ConfirmedDescriptor,
        info: &ShmBufInfo,
    ) -> ZResult<PtrInSegment> {
        let header = confirmed.owned.header();
        let data_descriptor = header.data_descriptor();

        // The length of the buffer comes with the info, from the sender, and is held to the length
        // of the chunk its descriptor says: the original builds a slice of whatever length the
        // info holds.
        if info.data_len > data_descriptor.len {
            bail!(
                "Buffer length {} exceeds the chunk capacity {}",
                info.data_len,
                data_descriptor.len
            );
        }

        let segment =
            self.ensure_data_segment(header.protocol.load(Ordering::Relaxed), &data_descriptor)?;
        let buf = segment.map(data_descriptor.chunk)?;
        Ok(PtrInSegment::new(buf, Arc::new(segment)))
    }

    fn ensure_data_segment(
        &self,
        protocol_id: ProtocolID,
        descriptor: &ChunkDescriptor,
    ) -> ZResult<Arc<dyn ShmSegment>> {
        let id = get_global_id(protocol_id, descriptor.segment);
        // A segment mapped now is found; one that is not is attached through the client of its
        // protocol, and the table holds it only as long as a buffer of it or its recent use does
        // (`SegmentCache`), where upstream's map keeps it for the life of the storage.
        self.segments.get_or_map(id, || {
            let client = self
                .clients
                .get_clients()
                .get(&protocol_id)
                .ok_or_else(|| zerror!("Unsupported SHM protocol: {}", protocol_id))?;
            client.attach(descriptor.segment)
        })
    }
}

#[derive(Debug)]
pub(crate) struct ClientStorage<Inner>
where
    Inner: Sized,
{
    clients: BTreeMap<ProtocolID, Inner>,
}

impl<Inner: Sized> ClientStorage<Inner> {
    pub(crate) fn new(clients: BTreeMap<ProtocolID, Inner>) -> Self {
        Self { clients }
    }

    pub(crate) fn get_clients(&self) -> &BTreeMap<ProtocolID, Inner> {
        &self.clients
    }
}

/// # Safety
/// Only immutable access to internal container is allowed,
/// so we are Send if the contained type is Send
unsafe impl<Inner: Send> Send for ClientStorage<Inner> {}

/// # Safety
/// Only immutable access to internal container is allowed,
/// so we are Sync if the contained type is Sync
unsafe impl<Inner: Sync> Sync for ClientStorage<Inner> {}

pub(crate) type GlobalDataSegmentId = u64;
fn get_global_id(protocol: ProtocolID, segment: SegmentID) -> GlobalDataSegmentId {
    static_assertions::assert_eq_size!(GlobalDataSegmentId, (ProtocolID, SegmentID));
    ((protocol as GlobalDataSegmentId) << 32) | (segment as GlobalDataSegmentId)
}
