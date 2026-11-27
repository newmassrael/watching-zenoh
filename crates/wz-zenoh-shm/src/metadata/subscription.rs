//
// Copyright (c) 2025 ZettaScale Technology
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
// src/metadata/subscription.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::sync::Arc;

use static_init::dynamic;
use zenoh_result::{bail, ZResult};

use super::{
    descriptor::{MetadataDescriptor, MetadataSegmentID, OwnedMetadataDescriptor},
    segment::MetadataSegment,
};
use crate::segment_cache::{SegmentCache, RETAINED_SEGMENTS};

#[dynamic(lazy, drop)]
pub static mut GLOBAL_METADATA_SUBSCRIPTION: Subscription = Subscription::new();

pub struct Subscription {
    /// The metadata segments linked: each held by the descriptors that point into it, and the last
    /// ones used by the table itself (`SegmentCache`). Upstream's table keeps every segment it
    /// linked for the life of the process.
    linked_table: SegmentCache<MetadataSegmentID, MetadataSegment>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("linked_table", &self.linked_table)
            .finish()
    }
}

impl Subscription {
    fn new() -> Self {
        Self {
            linked_table: SegmentCache::new(RETAINED_SEGMENTS),
        }
    }

    fn ensure_segment(&self, id: MetadataSegmentID) -> ZResult<Arc<MetadataSegment>> {
        self.linked_table
            .get_or_map(id, || Ok(Arc::new(MetadataSegment::open(id)?)))
    }
    pub fn link(&self, descriptor: &MetadataDescriptor) -> ZResult<OwnedMetadataDescriptor> {
        let segment = self.ensure_segment(descriptor.id)?;

        // The descriptor comes from another process, usually over the network, so its index is
        // checked against the segment before a header is taken at it: the original takes the
        // header at any index of sixteen bits, which is past the end of the segment from the
        // index that is the count of its headers on.
        if usize::from(descriptor.index) >= segment.data.count() {
            bail!(
                "Metadata index {} is out of range for the segment {} of {} headers",
                descriptor.index,
                descriptor.id,
                segment.data.count()
            );
        }

        // construct owned descriptor
        // SAFETY: the index is in bounds of the segment, as checked above
        let (header, watchdog) = unsafe { segment.data.fast_elem_compute(descriptor.index) };

        let owned_descriptor = OwnedMetadataDescriptor::new(segment, header, watchdog);
        Ok(owned_descriptor)
    }
}
