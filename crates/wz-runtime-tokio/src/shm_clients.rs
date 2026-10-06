// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3065 -- the shared-memory READER's clients: how a received descriptor's chunk is mapped, by the
//! protocol its header names.
//!
//! A descriptor names a metadata slot, and the slot's header names the chunk: the protocol it
//! belongs to, the data segment and the offset in it. Reading the chunk is the job of the CLIENT
//! the reader holds for that protocol, which attaches the segment by id and maps the chunk in it.
//! Upstream's default reader holds one client, for POSIX; a program that provides memory some
//! other way supplies a client for its own protocol id, and a reader built from a storage
//! holding it resolves what that provider sends.
//!
//! This module is the seam. [`ShmDataClient`] and [`ShmDataSegment`] are what a client implements,
//! [`ShmClientSet`] is the reader's table of them (with POSIX as the built-in one it has always
//! had, which keeps its own mapping because that mapping also serves writes), and
//! [`ShmClientResolver`] is the [`ShmResolver`] that reads a descriptor through a set.
//!
//! ## What upstream does, mirrored
//!
//! Upstream's reader caches an attached segment under the pair `(protocol, segment id)` and
//! attaches at most once per pair (`commons/zenoh-shm/src/reader.rs` @
//! `fn ensure_data_segment(`), refuses a protocol it holds no client for, and maps the chunk
//! through the segment it holds. A chunk read keeps its segment alive for as long as the buffer
//! lives. All four are here.
//!
//! ## The list a reader advertises is its set's
//!
//! A peer's sender sends this node a descriptor only for a protocol the node's auth segment lists,
//! so the list must be exactly what the set resolves: [`ShmClientSet::protocols`] is the one
//! source of both, and a set that listed a protocol it cannot resolve would have its descriptors
//! dropped on arrival.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use wz_session_core::extshm::{ShmDescriptor, ShmResolver};
use wz_session_core::link::RxBytes;

use crate::shm_provider::{ChunkHold, POSIX_PROTOCOL_ID};

/// One data segment a client attached: all a reader does with it is map a chunk.
pub trait ShmDataSegment: Send + Sync {
    /// The address of `chunk` in this segment, or null when the client cannot map it.
    ///
    /// The address stays valid for as long as the segment is alive, and the reader keeps a segment
    /// alive for as long as any range of a chunk read through it is.
    fn map(&self, chunk: u32) -> *mut u8;
}

/// The reader's client for one protocol: it attaches a data segment by id.
pub trait ShmDataClient: Send + Sync {
    /// The protocol id this client resolves. A buffer's header names it.
    fn protocol(&self) -> u32;

    /// Attach the data segment `segment`, or `None` when it cannot be attached (a peer's segment
    /// that is gone, or one this client does not know). A refusal is not remembered: the next
    /// buffer of that segment asks again.
    fn attach(&self, segment: u32) -> Option<Arc<dyn ShmDataSegment>>;
}

/// Why a [`ShmClientSet`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmClientSetError {
    /// Two clients answer for one protocol, or one answers for POSIX in a set that already has
    /// the built-in POSIX client. Silently keeping one would decide for the caller which.
    DuplicateProtocol(u32),
}

/// The reader's table of clients, by protocol.
pub struct ShmClientSet {
    /// Whether the built-in POSIX client is in the set. A reader built without it cannot resolve
    /// a buffer of POSIX memory, as upstream's storage built without its default client set cannot.
    posix: bool,
    foreign: BTreeMap<u32, Arc<dyn ShmDataClient>>,
    /// The segments attached so far, by `(protocol, segment id)`: upstream's `segments` map.
    mounted: RwLock<BTreeMap<(u32, u32), Arc<dyn ShmDataSegment>>>,
}

impl ShmClientSet {
    /// Upstream's default client set: POSIX alone, which is what every reader had before this
    /// type existed.
    pub fn posix_only() -> Self {
        Self {
            posix: true,
            foreign: BTreeMap::new(),
            mounted: RwLock::new(BTreeMap::new()),
        }
    }

    /// A set of `clients`, with the built-in POSIX client when `posix`. `Err` on two clients for
    /// one protocol, or one for POSIX beside the built-in.
    pub fn new(
        posix: bool,
        clients: impl IntoIterator<Item = Arc<dyn ShmDataClient>>,
    ) -> Result<Self, ShmClientSetError> {
        let mut foreign = BTreeMap::new();
        for client in clients {
            let protocol = client.protocol();
            if (posix && protocol == POSIX_PROTOCOL_ID) || foreign.contains_key(&protocol) {
                return Err(ShmClientSetError::DuplicateProtocol(protocol));
            }
            foreign.insert(protocol, client);
        }
        Ok(Self {
            posix,
            foreign,
            mounted: RwLock::new(BTreeMap::new()),
        })
    }

    /// Whether the built-in POSIX client is in the set.
    pub fn resolves_posix(&self) -> bool {
        self.posix
    }

    /// The protocols this set resolves, which is the list its node's auth segment advertises:
    /// POSIX first when it is in the set, then the clients' ids in ascending order.
    pub fn protocols(&self) -> Vec<u32> {
        let mut protocols = Vec::with_capacity(self.foreign.len() + usize::from(self.posix));
        if self.posix {
            protocols.push(POSIX_PROTOCOL_ID);
        }
        protocols.extend(self.foreign.keys().copied());
        protocols
    }

    /// The attached segment `(protocol, segment)`, attached now if it is the first buffer of it.
    /// `None` when no client is held for `protocol` or the client cannot attach the segment.
    ///
    /// Only the clients that are not the built-in POSIX one: POSIX keeps its own mapping.
    pub(crate) fn mount(&self, protocol: u32, segment: u32) -> Option<Arc<dyn ShmDataSegment>> {
        let id = (protocol, segment);
        // The common path takes the read lock alone, so concurrent readers do not queue.
        if let Some(found) = self.mounted.read().ok()?.get(&id) {
            return Some(found.clone());
        }
        let client = self.foreign.get(&protocol)?;
        let mut mounted = self.mounted.write().ok()?;
        // Many readers may have raced for this segment: the first to take the write lock attaches
        // it and the rest find it.
        if let Some(found) = mounted.get(&id) {
            return Some(found.clone());
        }
        let attached = client.attach(segment)?;
        mounted.insert(id, attached.clone());
        Some(attached)
    }
}

/// The type an offer carries its list in, and the refusal when a set names more protocols than a
/// segment has slots for: re-exported so a host that builds an offer from a set names them here.
#[cfg(feature = "session-extshm")]
pub use wz_session_core::extshm::{ShmProtocolList, TooManyShmProtocols};

#[cfg(feature = "session-extshm")]
impl ShmClientSet {
    /// [`Self::protocols`] as the list a session's offer carries, which is what its auth segment
    /// advertises. Taking BOTH from the one set is what keeps a node from listing a protocol its
    /// reader cannot resolve.
    pub fn advertised(&self) -> Result<ShmProtocolList, TooManyShmProtocols> {
        ShmProtocolList::new(&self.protocols())
    }
}

impl std::fmt::Debug for ShmClientSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShmClientSet")
            .field("protocols", &self.protocols())
            .finish()
    }
}

/// The [`ShmResolver`] that reads a descriptor through a [`ShmClientSet`]: the reader a session is
/// given when it is opened over a client storage, where the default is [`crate::shm_provider::PosixShmResolver`].
#[derive(Debug, Clone)]
pub struct ShmClientResolver {
    clients: Arc<ShmClientSet>,
}

impl ShmClientResolver {
    /// A resolver over `clients`.
    pub fn new(clients: Arc<ShmClientSet>) -> Self {
        Self { clients }
    }
}

impl ShmResolver for ShmClientResolver {
    /// As [`crate::shm_provider::PosixShmResolver::resolve`], with the chunk mapped through
    /// whichever client the header's protocol names, and the reference given back on every way out.
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        ChunkHold::link_through(descriptor, &self.clients)?.read()
    }

    fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<RxBytes> {
        ChunkHold::link_through(descriptor, &self.clients)?.into_shared()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A client that attaches a heap block per segment id and counts its attaches.
    struct Counting {
        protocol: u32,
        attaches: AtomicUsize,
        refuse: bool,
    }

    struct Block(Vec<u8>);

    impl ShmDataSegment for Block {
        fn map(&self, chunk: u32) -> *mut u8 {
            self.0.as_ptr().wrapping_add(chunk as usize) as *mut u8
        }
    }

    impl ShmDataClient for Counting {
        fn protocol(&self) -> u32 {
            self.protocol
        }
        fn attach(&self, _segment: u32) -> Option<Arc<dyn ShmDataSegment>> {
            self.attaches.fetch_add(1, Ordering::SeqCst);
            (!self.refuse).then(|| Arc::new(Block(vec![0; 16])) as Arc<dyn ShmDataSegment>)
        }
    }

    fn client(protocol: u32, refuse: bool) -> Arc<Counting> {
        Arc::new(Counting {
            protocol,
            attaches: AtomicUsize::new(0),
            refuse,
        })
    }

    /// THE LIST A READER ADVERTISES IS ITS SET'S: POSIX first when it is in, then the clients'
    /// ids ascending, and nothing a set cannot resolve.
    #[test]
    fn a_set_lists_exactly_the_protocols_it_resolves() {
        assert_eq!(ShmClientSet::posix_only().protocols(), [POSIX_PROTOCOL_ID]);
        let both = ShmClientSet::new(
            true,
            [
                client(100500, false) as Arc<dyn ShmDataClient>,
                client(7, false),
            ],
        )
        .expect("distinct protocols");
        assert_eq!(both.protocols(), [POSIX_PROTOCOL_ID, 7, 100500]);
        let custom_only =
            ShmClientSet::new(false, [client(100500, false) as Arc<dyn ShmDataClient>])
                .expect("a set without POSIX");
        assert_eq!(custom_only.protocols(), [100500]);
        assert!(!custom_only.resolves_posix());
    }

    /// Two clients for one protocol, or one for POSIX beside the built-in, are refused and not
    /// resolved by keeping one of them.
    #[test]
    fn a_set_refuses_two_clients_for_one_protocol() {
        let twice = ShmClientSet::new(
            false,
            [client(5, false) as Arc<dyn ShmDataClient>, client(5, false)],
        );
        assert_eq!(twice.err(), Some(ShmClientSetError::DuplicateProtocol(5)));
        let over_posix = ShmClientSet::new(
            true,
            [client(POSIX_PROTOCOL_ID, false) as Arc<dyn ShmDataClient>],
        );
        assert_eq!(
            over_posix.err(),
            Some(ShmClientSetError::DuplicateProtocol(POSIX_PROTOCOL_ID))
        );
        // Without the built-in, a client for protocol 0 is the set's own POSIX replacement.
        assert!(ShmClientSet::new(
            false,
            [client(POSIX_PROTOCOL_ID, false) as Arc<dyn ShmDataClient>]
        )
        .is_ok());
    }

    /// A segment is attached ONCE per `(protocol, segment)` however many buffers are read from it,
    /// and a refused attach is asked again by the next buffer.
    #[test]
    fn a_segment_is_attached_once_and_a_refusal_is_asked_again() {
        let c = client(100500, false);
        let set = ShmClientSet::new(true, [c.clone() as Arc<dyn ShmDataClient>]).unwrap();
        let first = set.mount(100500, 42).expect("attached");
        let second = set.mount(100500, 42).expect("found");
        assert!(Arc::ptr_eq(&first, &second), "the same attached segment");
        assert_eq!(
            c.attaches.load(Ordering::SeqCst),
            1,
            "attached once for the pair"
        );
        let _ = set
            .mount(100500, 43)
            .expect("a second segment of the protocol");
        assert_eq!(
            c.attaches.load(Ordering::SeqCst),
            2,
            "each segment attaches once"
        );

        let refusing = client(9, true);
        let set = ShmClientSet::new(true, [refusing.clone() as Arc<dyn ShmDataClient>]).unwrap();
        assert!(set.mount(9, 1).is_none());
        assert!(set.mount(9, 1).is_none());
        assert_eq!(
            refusing.attaches.load(Ordering::SeqCst),
            2,
            "a refusal is not remembered"
        );
    }

    /// A protocol the set holds no client for is not attached at all, and POSIX is not one a
    /// foreign mount answers for: it keeps its own mapping.
    #[test]
    fn a_protocol_with_no_client_is_not_mounted() {
        let set =
            ShmClientSet::new(true, [client(100500, false) as Arc<dyn ShmDataClient>]).unwrap();
        assert!(set.mount(8, 1).is_none(), "no client for the protocol");
        assert!(
            set.mount(POSIX_PROTOCOL_ID, 1).is_none(),
            "POSIX is the built-in's, not a mount"
        );
    }
}
