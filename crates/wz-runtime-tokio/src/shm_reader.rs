// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The shared-memory reader of the process: `zenoh-shm`'s `ShmReader` over a `ShmClientStorage`,
//! as the engine's [`ShmResolver`].
//!
//! A descriptor names a metadata slot, and the slot's header names the chunk: the protocol it
//! belongs to, the data segment and the offset in it. Upstream's reader follows it
//! (`commons/zenoh-shm/src/reader.rs` @ `pub fn read_shmbuf(`): it links the metadata segment,
//! attaches the slot to the watchdog, mounts the data segment through the client its storage
//! holds for the protocol (once per protocol and segment), and builds the buffer, which gives the
//! reference the sender took for this receiver back when it drops. That reader is the one in the
//! process: the engine's sessions, the C ABI's client storages and the top crate's sessions read
//! through [`ShmReaderResolver`], and a repair of the protocol is made once, in `zenoh-shm`
//! (`docs/shm-transport.md`, section 6).
//!
//! What a received buffer becomes is the buffer `zenoh-shm` hands up, whichever way the engine uses
//! it: the bytes handed up to a receiver are a [`ReceivedBuffer`] ([`ShmResolver::resolve_shared`]),
//! and the chunk a forwarding node sends on is the engine's one send buffer over it
//! ([`ShmResolver::hold`], [`ShmBuffer`]). A host whose application holds the buffer itself (the
//! top crate's `ZShm`) gets it back out of the bytes it was handed through
//! [`ReceivedBuffer::buffer`].
//!
//! ## The list a reader advertises is its storage's
//!
//! A peer's sender sends this node a descriptor only for a protocol the node's auth segment lists,
//! so the list is exactly what the storage resolves: `ShmClientStorage::supported_protocols`,
//! which [`ShmReaderResolver::protocols`] reads and from which the offer is built.

use std::any::Any;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::sync::Arc;

use wz_session_core::extshm::{ShmDescriptor, ShmResolver, ShmSendHandle};
use wz_session_core::link::{RxBytes, RxStorage, ShmChunkView};
use zenoh_shm::metadata::descriptor::MetadataDescriptor;
use zenoh_shm::reader::ShmReader;
use zenoh_shm::ShmBufInfo;

use crate::shm_buffer::{ReceiverView, ShmBufHolder, ShmBuffer};

pub use zenoh_result::ZResult;
pub use zenoh_shm::api::client::shm_client::ShmClient;
pub use zenoh_shm::api::client::shm_segment::ShmSegment;
pub use zenoh_shm::api::client_storage::ShmClientStorage;
pub use zenoh_shm::api::common::types::{ChunkID, ProtocolID, SegmentID};
pub use zenoh_shm::api::common::with_id::WithProtocolID;
pub use zenoh_shm::api::protocol_implementations::posix::posix_shm_client::PosixShmClient;
pub use zenoh_shm::ShmBufInner;

/// The type an offer carries its list in, and the refusal when a storage names more protocols
/// than a segment has slots for: re-exported so a host that builds an offer from a storage names
/// them here.
#[cfg(feature = "session-extshm")]
pub use wz_session_core::extshm::{ShmProtocolList, TooManyShmProtocols};

/// The process's client storage: upstream's global one, which holds the default client set (the
/// POSIX client) and which every session that was not given a storage of its own reads through
/// (`commons/zenoh-shm/src/api/client_storage/mod.rs` @
/// `pub static mut GLOBAL_CLIENT_STORAGE: Arc<ShmClientStorage> = Arc::new(`).
pub fn global_client_storage() -> Arc<ShmClientStorage> {
    Arc::clone(&zenoh_shm::api::client_storage::GLOBAL_CLIENT_STORAGE.read())
}

/// The protocols `storage` resolves as the list a session's offer carries, which is what its
/// auth segment advertises. Taking both from the one storage is what keeps a node from listing a
/// protocol its reader cannot resolve.
#[cfg(feature = "session-extshm")]
pub fn advertised(storage: &ShmClientStorage) -> Result<ShmProtocolList, TooManyShmProtocols> {
    ShmProtocolList::new(&storage.supported_protocols())
}

/// The engine's [`ShmResolver`]: upstream's reader over a client storage.
#[derive(Debug, Clone)]
pub struct ShmReaderResolver {
    reader: ShmReader,
}

impl ShmReaderResolver {
    /// A reader over `storage`.
    pub fn new(storage: Arc<ShmClientStorage>) -> Self {
        Self {
            reader: ShmReader::new(storage),
        }
    }

    /// A reader over the process's storage ([`global_client_storage`]): the one a session is
    /// built with.
    pub fn global() -> Self {
        Self::new(global_client_storage())
    }

    /// A reader over a storage of its own that holds the default client set: what the process's
    /// reader resolves, with no mapping kept past the buffers it hands out.
    pub fn of_default_set() -> Self {
        Self::new(Arc::new(
            ShmClientStorage::builder()
                .with_default_client_set()
                .build(),
        ))
    }

    /// The protocols this reader resolves: its storage's, in ascending order.
    pub fn protocols(&self) -> Vec<ProtocolID> {
        self.reader.supported_protocols()
    }

    /// The buffer `descriptor` names. It owns the reference the sender took for this receiver and
    /// gives it back when it drops; a read that fails once the header is of the descriptor's
    /// generation has given it back already, and one of another generation touched nothing.
    /// `None` for a descriptor of no bytes, which no sender builds.
    pub fn read(&self, descriptor: &ShmDescriptor) -> Option<Arc<ShmBufInner>> {
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

impl Default for ShmReaderResolver {
    fn default() -> Self {
        Self::global()
    }
}

impl ShmResolver for ShmReaderResolver {
    /// The bytes copied off the page, and the reference given back when the buffer drops here.
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let buffer = self.read(descriptor)?;
        Some(AsRef::<[u8]>::as_ref(&*buffer).to_vec())
    }

    /// The bytes where they lie on the page, and the reference given back when the last range of
    /// them drops.
    fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<RxBytes> {
        ReceivedBuffer::new(self.read(descriptor)?).view()
    }

    /// The chunk held to be sent on: the reference the descriptor carried is the handle's and goes
    /// back when the last clone of the handle drops; a reservation taken from it is one more. A
    /// forwarder does not deliver the chunk to a subscriber of its own, so a receiver of the
    /// handle is handed its bytes.
    fn hold(&self, descriptor: &ShmDescriptor) -> Option<ShmSendHandle> {
        let buffer: Arc<dyn ShmBufHolder> = self.read(descriptor)?;
        Some(ShmBuffer::new(buffer, ReceiverView::Bytes).into_handle())
    }
}

/// A buffer this process holds as a receiver: the storage a received payload is a range of, and
/// the view a receiver of the session that sent a buffer holds of its own.
pub struct ReceivedBuffer {
    /// Let go of by hand in `Drop`, before the providers the process keeps are looked at: one kept
    /// for this buffer can go only once this reference is given back.
    buffer: ManuallyDrop<Arc<ShmBufInner>>,
}

impl ReceivedBuffer {
    pub(crate) fn new(buffer: Arc<ShmBufInner>) -> Self {
        Self {
            buffer: ManuallyDrop::new(buffer),
        }
    }

    /// The buffer itself, for a host whose application holds it as its own type.
    pub fn buffer(&self) -> &Arc<ShmBufInner> {
        &self.buffer
    }

    /// The whole buffer as the bytes a receiver is handed.
    pub(crate) fn view(self) -> Option<RxBytes> {
        let len = self.as_slice().len();
        let storage: Arc<dyn RxStorage> = Arc::new(self);
        RxBytes::shared(storage, 0..len)
    }
}

impl Drop for ReceivedBuffer {
    fn drop(&mut self) {
        // SAFETY: dropped here, once, and not used after: `self` is being dropped.
        unsafe { ManuallyDrop::drop(&mut self.buffer) };
        crate::shm_buffer::sweep_orphans();
    }
}

impl RxStorage for ReceivedBuffer {
    fn as_slice(&self) -> &[u8] {
        AsRef::<[u8]>::as_ref(&**self.buffer)
    }

    fn shm_chunk(&self) -> Option<&dyn ShmChunkView> {
        Some(self)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl ShmChunkView for ReceivedBuffer {
    /// Upstream's condition for converting a received buffer to a mutable one: this receiver is
    /// its only holder and its provider has not invalidated it.
    fn is_unique(&self) -> bool {
        self.buffer.is_writable()
    }

    fn writable_ptr(&self) -> Option<*mut u8> {
        Some(self.buffer.data_ptr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client of a protocol of its own that attaches nothing: what a storage lists is what this
    /// test reads, not what it maps.
    #[derive(Debug)]
    struct Unattached(ProtocolID);

    impl WithProtocolID for Unattached {
        fn id(&self) -> ProtocolID {
            self.0
        }
    }

    impl ShmClient for Unattached {
        fn attach(&self, _segment: SegmentID) -> ZResult<Arc<dyn ShmSegment>> {
            Err("this client attaches nothing".into())
        }
    }

    fn storage_of(default_set: bool, clients: &[Arc<dyn ShmClient>]) -> Arc<ShmClientStorage> {
        let builder = ShmClientStorage::builder();
        Arc::new(if default_set {
            builder
                .with_default_client_set()
                .with_clients(clients)
                .build()
        } else {
            builder.with_clients(clients).build()
        })
    }

    /// THE LIST A READER ADVERTISES IS ITS STORAGE'S: the default set's POSIX first when it is
    /// in, then the clients' ids ascending, and nothing the storage cannot resolve.
    ///
    /// Turned red by a reader whose list is not read off its own storage (a fixed POSIX list, or
    /// one that leaves the default set out).
    #[test]
    fn a_reader_lists_exactly_the_protocols_its_storage_resolves() {
        assert_eq!(ShmReaderResolver::global().protocols(), [0]);
        let custom: Arc<dyn ShmClient> = Arc::new(Unattached(100500));
        let both = storage_of(
            true,
            &[
                custom.clone(),
                Arc::new(Unattached(7)) as Arc<dyn ShmClient>,
            ],
        );
        assert_eq!(ShmReaderResolver::new(both).protocols(), [0, 7, 100500]);
        let custom_only = storage_of(false, &[custom]);
        assert_eq!(ShmReaderResolver::new(custom_only).protocols(), [100500]);
    }

    /// The offer of a session opened over a storage lists the storage's protocols, the ones its
    /// reader resolves.
    ///
    /// Turned red by an offer built from anything but the storage.
    #[cfg(feature = "session-extshm")]
    #[test]
    fn the_offer_of_a_storage_is_its_protocols() {
        let storage = storage_of(true, &[Arc::new(Unattached(9)) as Arc<dyn ShmClient>]);
        assert_eq!(
            advertised(&storage).expect("two protocols fit").as_slice(),
            [0, 9]
        );
    }

    /// A buffer of its own pool holding `bytes`, sent: its descriptor, with the sender's
    /// reference taken for the receiver.
    fn sent(bytes: &[u8]) -> (crate::shm_buffer::IssuedBuffer, ShmDescriptor) {
        let mut buffer =
            crate::shm_buffer::IssuedBuffer::alloc(bytes.len()).expect("a buffer of its own pool");
        buffer.write(bytes);
        let wire = buffer.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        (buffer, descriptor)
    }

    /// A storage of the default client set that keeps at most `retained` segments no buffer
    /// holds.
    fn storage_retaining(retained: usize) -> Arc<ShmClientStorage> {
        Arc::new(
            ShmClientStorage::builder()
                .with_default_client_set()
                .build_retaining(retained),
        )
    }

    /// A reader maps a provider's segment while a buffer of it is held, and the provider gone
    /// changes nothing for that buffer: it reads what was sent. Once no buffer holds the segment, a
    /// storage that keeps none has unmapped it. The CONTROL is the default storage, which keeps
    /// the segment it used last, so a subscriber that drops each sample before the next does not
    /// map its provider again for every message.
    ///
    /// Turned red by a storage that keeps every segment it ever mapped (upstream's table, the
    /// debt this closes), or by one that unmaps a segment a buffer still points into.
    #[test]
    fn a_reader_maps_a_segment_while_a_buffer_of_it_is_held() {
        let storage = storage_retaining(0);
        let reader = ShmReaderResolver::new(Arc::clone(&storage));
        let (owner, descriptor) = sent(b"held");
        let read = reader
            .read(&descriptor)
            .expect("the receiver reads what was sent");
        assert_eq!(storage.mapped_segments(), 1);
        drop(owner);
        assert_eq!(
            AsRef::<[u8]>::as_ref(&*read),
            b"held",
            "the provider gone, the buffer reads"
        );
        assert_eq!(
            storage.mapped_segments(),
            1,
            "the held buffer keeps its segment"
        );
        drop(read);
        assert_eq!(storage.mapped_segments(), 0, "no buffer holds it: unmapped");

        let kept = storage_retaining(DEFAULT_RETAINED);
        let reader = ShmReaderResolver::new(Arc::clone(&kept));
        let (owner, descriptor) = sent(b"kept");
        drop(reader.read(&descriptor).expect("read"));
        drop(owner);
        assert_eq!(
            kept.mapped_segments(),
            1,
            "CONTROL: the last one used is kept"
        );
    }

    /// The segments kept with no buffer of theirs held are bounded: a reader of more providers
    /// than the bound, each read dropped, holds the bound's worth mapped and no more.
    ///
    /// Turned red by a kept set that grows with every provider read.
    #[test]
    fn the_segments_kept_past_their_buffers_are_bounded() {
        let storage = storage_retaining(2);
        let reader = ShmReaderResolver::new(Arc::clone(&storage));
        let mut owners = Vec::new();
        for n in 0..5u8 {
            let (owner, descriptor) = sent(&[n; 8]);
            drop(reader.read(&descriptor).expect("read"));
            owners.push(owner);
        }
        assert_eq!(storage.mapped_segments(), 2);
    }

    /// The bound a storage built with no word of its own keeps.
    const DEFAULT_RETAINED: usize = 16;

    /// A descriptor of no bytes is no buffer: it is refused before anything is read.
    #[test]
    fn a_descriptor_of_no_bytes_is_refused() {
        let descriptor = ShmDescriptor {
            data_len: 0,
            metadata_id: 0,
            metadata_index: 0,
            generation: 0,
        };
        assert!(ShmReaderResolver::global().read(&descriptor).is_none());
    }
}
