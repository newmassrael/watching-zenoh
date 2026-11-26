// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine's buffers of shared memory: the one implementation of the seams a message is sent
//! from ([`ShmSendBuffer`], [`ShmReservation`]) over `zenoh-shm`'s buffer, `ShmBufInner`,
//! whoever holds it (`docs/shm-transport.md`, section 6).
//!
//! * [`ShmBufHolder`] is what holds a buffer: the buffer itself (one the reader of the process
//!   handed up), a buffer and the provider that issued it ([`IssuedBuffer`]), or a host's own
//!   value that owns one (the top crate's slice of a `ZBytes`).
//! * [`ShmBuffer`] is a holder as the engine sends it, and says what a receiver of the sending
//!   session is handed ([`ReceiverView`]).
//! * [`IssuedBuffer`] is the owner of a buffer a provider of this process issued, which the C ABI
//!   and the engine's own callers allocate.
//!
//! The reference a sender takes for a remote receiver is counted in the buffer's own header and
//! given back when the frame is not sent, exactly as upstream's codec does
//! (`commons/zenoh-codec/src/core/zbuf.rs` @ `unsafe { shmb.inc_ref_count() };`).
//!
//! ## A provider outlives the last owner of its buffers while a receiver holds one
//!
//! Upstream's provider reclaims every metadata slot it issued when it drops, so a buffer whose
//! descriptor is still on its way, or still held by a receiver, turns stale under it
//! (`commons/zenoh-shm/src/metadata/allocated_descriptor.rs` @
//! `impl Drop for AllocatedMetadataDescriptor {`). A publisher that lets go of its buffer and
//! of the provider the moment the put returns would then lose the message. An [`IssuedBuffer`]
//! holds its provider, and one that drops while some receiver still holds a reference of its
//! buffer leaves the provider with the process, which lets go of it once the header says every
//! receiver has let go, or that the watchdog gave up on them.

use std::any::Any;
use std::io;
use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex, OnceLock};

use wz_session_core::extshm::{ShmDescriptor, ShmReservation, ShmSendBuffer, ShmSendHandle};
use wz_session_core::link::{RxBytes, RxStorage, ShmChunkView};
use zenoh_core::Wait;
use zenoh_shm::api::protocol_implementations::posix::posix_shm_provider_backend::PosixShmProviderBackend;
use zenoh_shm::api::provider::memory_layout::MemoryLayout;
use zenoh_shm::api::provider::shm_provider::{
    ConstBool, Defragment, GarbageCollect, JustAlloc, ShmProvider, ShmProviderBuilder,
};
use zenoh_shm::api::provider::shm_provider_backend::ShmProviderBackend;
use zenoh_shm::api::provider::types::AllocAlignment;
use zenoh_shm::metadata::descriptor::MetadataDescriptor;
use zenoh_shm::{HeaderState, ShmBufInfo, ShmBufInner};

use crate::shm_reader::ReceivedBuffer;

/// The room a pool of one buffer needs beside the buffer: the allocator of the default backend
/// (talc) claims part of its arena for its own bins and spends a header on each chunk, so a pool
/// of exactly the buffer's size could not serve it.
const SINGLE_BUFFER_POOL_HEADROOM: usize = 4096;

/// Make the shared-memory subsystem of the process now, as upstream's `init` mode does when a
/// session opens (`commons/zenoh-shm/src/init.rs` @ `pub fn init() {`); otherwise the first buffer
/// the process allocates or reads makes it.
pub fn init() {
    zenoh_shm::init::init();
}

/// What holds a buffer of shared memory the engine sends.
pub trait ShmBufHolder: Send + Sync + 'static {
    /// The buffer.
    fn buffer(&self) -> &ShmBufInner;

    /// The holder itself, for a host that gets its own value back out of a view.
    fn as_any(&self) -> &dyn Any;
}

impl ShmBufHolder for ShmBufInner {
    fn buffer(&self) -> &ShmBufInner {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The bytes `buffer` holds.
fn bytes_of(buffer: &ShmBufInner) -> &[u8] {
    AsRef::<[u8]>::as_ref(buffer)
}

/// The descriptor that names `buffer` on the wire. It takes no reference: one that goes on the
/// wire is built through a reservation, which takes the reference the receiver gives back.
pub fn descriptor_of(buffer: &ShmBufInner) -> ShmDescriptor {
    let info = &buffer.info;
    ShmDescriptor {
        data_len: u32::try_from(info.data_len.get()).unwrap_or(u32::MAX),
        metadata_id: info.metadata.id,
        metadata_index: info.metadata.index,
        generation: info.generation,
    }
}

/// What a receiver of the session that sends a buffer is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverView {
    /// The holder itself, without a reference of its own: the top crate hands its application the
    /// buffer it gave, as upstream hands a subscriber of the same session the same `ZBytes`.
    Shared,
    /// A holder of its own, with a reference and a confirmation of its own, as a remote receiver
    /// holds one: the owner is no longer the only holder while the view lives (the zenoh-c ABI's
    /// local delivery, measured against the real library).
    Held,
    /// The bytes: the buffer is the transport's (a copy made only to cross the links) or one a
    /// forwarder holds to send on.
    Bytes,
}

/// The view of `buffer` a receiver holds as its own: a clone, which takes a reference and a
/// confirmation of its own and gives both back when the last range of the view drops.
fn held_view(buffer: &ShmBufInner) -> Option<RxBytes> {
    ReceivedBuffer::new(Arc::new(buffer.clone())).view()
}

/// A buffer of shared memory as the engine sends it.
pub struct ShmBuffer {
    holder: Arc<dyn ShmBufHolder>,
    view: ReceiverView,
}

impl ShmBuffer {
    /// `holder`'s buffer, whose receivers in the sending session are handed `view`.
    pub fn new(holder: Arc<dyn ShmBufHolder>, view: ReceiverView) -> Self {
        Self { holder, view }
    }

    /// What holds the buffer.
    pub fn holder(&self) -> &Arc<dyn ShmBufHolder> {
        &self.holder
    }

    /// The handle a staged message carries.
    pub fn into_handle(self) -> ShmSendHandle {
        ShmSendHandle::new(Arc::new(self))
    }
}

impl ShmSendBuffer for ShmBuffer {
    fn bytes(&self) -> &[u8] {
        bytes_of(self.holder.buffer())
    }

    fn protocol(&self) -> u32 {
        self.holder.buffer().protocol()
    }

    fn receiver_view(&self) -> Option<RxBytes> {
        match self.view {
            ReceiverView::Shared => SharedView::view(Arc::clone(&self.holder)),
            ReceiverView::Held => held_view(self.holder.buffer()),
            // `None` is what the engine hands the bytes for.
            ReceiverView::Bytes => None,
        }
    }

    fn reserve_for_receiver(self: Arc<Self>) -> Box<dyn ShmReservation> {
        // SAFETY: the reference taken here is the receiver's, given back by that receiver when it
        // lets go, or by the reservation when the frame is not sent.
        unsafe { self.holder.buffer().inc_ref_count() };
        Box::new(HeldReference {
            holder: Arc::clone(&self.holder),
            committed: false,
        })
    }
}

/// A holder handed to a receiver of the session that sent it, without a reference of its own.
pub struct SharedView {
    holder: Arc<dyn ShmBufHolder>,
}

impl SharedView {
    fn view(holder: Arc<dyn ShmBufHolder>) -> Option<RxBytes> {
        let len = bytes_of(holder.buffer()).len();
        RxBytes::shared(Arc::new(Self { holder }), 0..len)
    }

    /// What holds the buffer: a host gets its own value back out of it.
    pub fn holder(&self) -> &Arc<dyn ShmBufHolder> {
        &self.holder
    }
}

impl RxStorage for SharedView {
    fn as_slice(&self) -> &[u8] {
        bytes_of(self.holder.buffer())
    }

    fn shm_chunk(&self) -> Option<&dyn ShmChunkView> {
        Some(self)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl ShmChunkView for SharedView {
    /// The buffer is the sender's as much as this receiver's, so it is the only holder exactly
    /// when its header counts one.
    fn is_unique(&self) -> bool {
        self.holder.buffer().ref_count() == 1
    }

    /// Never written through: the sender holds the same buffer.
    fn writable_ptr(&self) -> Option<*mut u8> {
        None
    }
}

/// Give back the reference a reservation took for a receiver that was never sent it.
fn give_back(buffer: &ShmBufInner) {
    // SAFETY: the reference the reservation took, and nobody was sent it.
    unsafe { buffer.release_reference() };
}

/// The reference [`ShmSendBuffer::reserve_for_receiver`] took, owning its buffer so that it may
/// outlive the handle it was taken from.
struct HeldReference {
    holder: Arc<dyn ShmBufHolder>,
    committed: bool,
}

impl ShmReservation for HeldReference {
    fn descriptor(&self) -> ShmDescriptor {
        descriptor_of(self.holder.buffer())
    }

    fn commit(mut self: Box<Self>) {
        self.committed = true;
    }
}

impl Drop for HeldReference {
    fn drop(&mut self) {
        if !self.committed {
            give_back(self.holder.buffer());
        }
    }
}

/// One reference taken for a receiver of a buffer the caller holds, and the descriptor that
/// carries it: build the frame from [`Self::descriptor`], send it, and [`Self::commit`] once the
/// frame is on its way; dropped any other way, it gives the reference back.
pub struct WireReference<'a> {
    buffer: &'a ShmBufInner,
    committed: bool,
}

impl<'a> WireReference<'a> {
    /// Take one reference of `buffer` for a receiver.
    pub fn take(buffer: &'a ShmBufInner) -> Self {
        // SAFETY: the reference is the receiver's, or given back when this drops uncommitted.
        unsafe { buffer.inc_ref_count() };
        Self {
            buffer,
            committed: false,
        }
    }

    /// The descriptor this reference is for.
    pub fn descriptor(&self) -> ShmDescriptor {
        descriptor_of(self.buffer)
    }

    /// The frame carrying the descriptor has been handed to the link, so the receiver owns the
    /// reference and gives it back when it lets go.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl ShmReservation for WireReference<'_> {
    fn descriptor(&self) -> ShmDescriptor {
        WireReference::descriptor(self)
    }

    fn commit(self: Box<Self>) {
        WireReference::commit(*self);
    }
}

impl Drop for WireReference<'_> {
    fn drop(&mut self) {
        if !self.committed {
            give_back(self.buffer);
        }
    }
}

/// What the publish legs of a session ask of a buffer a message is sent from: the bytes it holds
/// (for a peer that cannot map the segment), the protocol its provider reads it through, the
/// reference one remote receiver gives back, and the view a receiver of the same session is
/// handed. A buffer the caller borrows ([`IssuedBuffer`]) and one a staged message owns
/// ([`ShmSendHandle`]) are sent by the same legs.
pub trait ShmPublishable {
    /// The shared-memory protocol the buffer belongs to; see [`ShmSendBuffer::protocol`].
    fn protocol(&self) -> u32;

    /// The bytes the buffer holds.
    fn bytes(&self) -> &[u8];

    /// Take the reference one remote receiver will give back, and the descriptor naming it. The
    /// reference goes back unless the reservation is committed.
    fn reserve(&self) -> Box<dyn ShmReservation + '_>;

    /// The buffer as a receiver of this session holds it; see [`ShmSendBuffer::receiver_view`].
    fn receiver_view(&self) -> Option<RxBytes>;
}

impl<T: ShmPublishable + ?Sized> ShmPublishable for Arc<T> {
    fn protocol(&self) -> u32 {
        (**self).protocol()
    }

    fn bytes(&self) -> &[u8] {
        (**self).bytes()
    }

    fn reserve(&self) -> Box<dyn ShmReservation + '_> {
        (**self).reserve()
    }

    fn receiver_view(&self) -> Option<RxBytes> {
        (**self).receiver_view()
    }
}

impl ShmPublishable for ShmSendHandle {
    fn protocol(&self) -> u32 {
        ShmSendHandle::protocol(self)
    }

    fn bytes(&self) -> &[u8] {
        ShmSendHandle::bytes(self)
    }

    fn reserve(&self) -> Box<dyn ShmReservation + '_> {
        self.reserve_for_receiver()
    }

    fn receiver_view(&self) -> Option<RxBytes> {
        ShmSendHandle::receiver_view(self)
    }
}

/// The owner of a buffer a provider of this process issued, and of a hold on that provider: what
/// a program writes its payload into and publishes by descriptor.
///
/// Dropping it gives the owner's reference back. The provider goes with the last holder of it,
/// unless some receiver still holds a reference of this buffer, in which case the process keeps
/// the provider until the header says every receiver has let go (see the module docs).
pub struct IssuedBuffer {
    /// Given back by hand in `Drop`, before the provider can go: a provider that drops reclaims
    /// the slot, and a reference given back after that would be counted against whatever buffer
    /// the slot holds by then.
    buffer: ManuallyDrop<ShmBufInner>,
    provider: Option<Arc<dyn Any + Send + Sync>>,
}

impl IssuedBuffer {
    /// `buffer`, which `provider` issued.
    pub fn new(buffer: ShmBufInner, provider: Arc<dyn Any + Send + Sync>) -> Self {
        sweep_orphans();
        Self {
            buffer: ManuallyDrop::new(buffer),
            provider: Some(provider),
        }
    }

    /// A `len`-byte buffer in a pool of its own: a provider over the default POSIX backend, big
    /// enough for that one buffer. What a publisher that sends one buffer wants; a program that
    /// allocates many makes a provider and allocates from it. `len` must not be zero: upstream's
    /// `data_len` is a `NonZeroUsize`, and the descriptor carries it as a `u32`.
    pub fn alloc(len: usize) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a buffer of shared memory is at least one byte (upstream's data_len is NonZero)",
            ));
        }
        u32::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a buffer of shared memory is at most u32::MAX bytes",
            )
        })?;
        let pool = len
            .checked_add(SINGLE_BUFFER_POOL_HEADROOM)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a buffer of shared memory too large",
                )
            })?;
        Self::alloc_from(&posix_pool(pool, 0)?, len, 0)
    }

    /// A `len`-byte buffer of `provider` at an alignment of `2^alignment_pow` bytes, allocated
    /// without collecting, as upstream's plain `alloc` is, and held with the provider.
    pub fn alloc_from<B>(
        provider: &Arc<ShmProvider<B>>,
        len: usize,
        alignment_pow: u8,
    ) -> io::Result<Self>
    where
        B: ShmProviderBackend + Send + Sync + 'static,
    {
        let buffer = provider
            .alloc(layout_of(len, alignment_pow)?)
            .wait()
            .map_err(|e| io::Error::other(e.to_string()))?
            .into_inner();
        Ok(Self::new(buffer, Arc::clone(provider)))
    }

    /// The buffer.
    pub fn buffer(&self) -> &ShmBufInner {
        &self.buffer
    }

    /// The bytes the buffer holds.
    pub fn bytes(&self) -> &[u8] {
        bytes_of(&self.buffer)
    }

    /// The buffer's length: what was asked for, which may be less than the chunk under it.
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether the buffer is empty. It never is, and the method exists beside [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address of the first byte, through which the buffer may be written while
    /// [`Self::is_unique`] holds. Valid for [`Self::len`] bytes for as long as `self` lives.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.buffer.data_ptr()
    }

    /// Copy `bytes` into the buffer, truncated to its length.
    pub fn write(&mut self, bytes: &[u8]) {
        let target = AsMut::<[u8]>::as_mut(&mut *self.buffer);
        let n = bytes.len().min(target.len());
        target[..n].copy_from_slice(&bytes[..n]);
    }

    /// Whether this owner is the buffer's only holder, no descriptor of it in flight and no
    /// receiver holding it, and its provider has not given up on it: upstream's condition for a
    /// shared buffer to become writable again
    /// (`commons/zenoh-shm/src/api/buffer/zshmmut.rs` @ `impl TryFrom<&mut zshm> for &mut zshmmut {`).
    pub fn is_unique(&self) -> bool {
        self.buffer.is_writable()
    }

    /// The descriptor of this buffer, as a value; see [`descriptor_of`].
    pub fn descriptor(&self) -> ShmDescriptor {
        descriptor_of(&self.buffer)
    }

    /// The shared-memory protocol of the buffer: the id its provider's backend reports and its
    /// header carries, the one a receiver reads it through.
    pub fn protocol(&self) -> u32 {
        self.buffer.protocol()
    }

    /// Take one reference for a receiver and the guard that carries it.
    pub fn wire_reference(&self) -> WireReference<'_> {
        WireReference::take(&self.buffer)
    }

    /// The buffer as a receiver in this process holds it: a reference of its own.
    pub fn receiver_view(&self) -> Option<RxBytes> {
        held_view(&self.buffer)
    }

    /// This buffer as a staged message carries it. Cheap: a clone of the `Arc`.
    pub fn send_handle(self: &Arc<Self>) -> ShmSendHandle {
        ShmBuffer::new(
            Arc::clone(self) as Arc<dyn ShmBufHolder>,
            ReceiverView::Held,
        )
        .into_handle()
    }
}

impl ShmBufHolder for IssuedBuffer {
    fn buffer(&self) -> &ShmBufInner {
        &self.buffer
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ShmPublishable for IssuedBuffer {
    fn protocol(&self) -> u32 {
        IssuedBuffer::protocol(self)
    }

    fn bytes(&self) -> &[u8] {
        IssuedBuffer::bytes(self)
    }

    fn reserve(&self) -> Box<dyn ShmReservation + '_> {
        Box::new(self.wire_reference())
    }

    fn receiver_view(&self) -> Option<RxBytes> {
        IssuedBuffer::receiver_view(self)
    }
}

impl Drop for IssuedBuffer {
    fn drop(&mut self) {
        let mut provider = self.provider.take();
        // The owner's own reference is still counted here; any other is a receiver's.
        if self.buffer.ref_count() > 1 {
            if let Some(provider) = provider.take() {
                orphans()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(Orphan {
                        info: self.buffer.info.clone(),
                        _provider: provider,
                    });
                crate::shm_watchdog::start();
            }
        }
        // SAFETY: the buffer is dropped here, once, and not used after: `self` is being dropped.
        unsafe { ManuallyDrop::drop(&mut self.buffer) };
        drop(provider);
        sweep_orphans();
    }
}

/// The layout of `size` bytes at an alignment of `2^alignment_pow` bytes, or `InvalidInput` when
/// there is none: no bytes, an alignment too large to name, or a size that is not a multiple of
/// it.
fn layout_of(size: usize, alignment_pow: u8) -> io::Result<MemoryLayout> {
    AllocAlignment::new(alignment_pow)
        .and_then(|alignment| MemoryLayout::new(size, alignment))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// A provider over the default POSIX backend: one segment of `size` bytes whose every chunk is
/// aligned to `2^alignment_pow` bytes, carved by upstream's default allocator
/// (`commons/zenoh-shm/src/api/provider/shm_provider.rs` @
/// `pub fn default_backend<Layout>(layout: Layout)`).
pub fn posix_pool(
    size: usize,
    alignment_pow: u8,
) -> io::Result<Arc<ShmProvider<PosixShmProviderBackend>>> {
    let provider = ShmProviderBuilder::default_backend(layout_of(size, alignment_pow)?)
        .wait()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Arc::new(provider))
}

/// A provider kept for a buffer whose owner has let go while some receiver still held it.
struct Orphan {
    info: ShmBufInfo,
    _provider: Arc<dyn Any + Send + Sync>,
}

impl Orphan {
    /// Whether no receiver can need the provider any more: every one has let go, the slot holds
    /// another buffer, the watchdog gave up on the holders, or the header cannot be read.
    fn is_finished(&self) -> bool {
        match zenoh_shm::header_state(&self.info.metadata) {
            Ok(state) => {
                state.generation != self.info.generation || state.refcount == 0 || state.invalidated
            }
            Err(_) => true,
        }
    }
}

fn orphans() -> &'static Mutex<Vec<Orphan>> {
    static ORPHANS: OnceLock<Mutex<Vec<Orphan>>> = OnceLock::new();
    ORPHANS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Let go of every kept provider no receiver needs any more. Run when a buffer is issued and when
/// one drops, and on the handoff's clock, for a receiver that lets go after its sender has.
pub(crate) fn sweep_orphans() {
    // A provider that drops reclaims its slots, which takes the storage's locks, so the finished
    // ones are taken out under this lock and dropped after it.
    let finished: Vec<Orphan> = {
        let mut kept = orphans().lock().unwrap_or_else(|e| e.into_inner());
        let (finished, live) = std::mem::take(&mut *kept)
            .into_iter()
            .partition(Orphan::is_finished);
        *kept = live;
        finished
    };
    drop(finished);
}

/// How many providers the process keeps for buffers a receiver still holds. A diagnostic: the
/// witness that a provider is kept while it is needed and let go of after.
pub fn orphans_held() -> usize {
    orphans().lock().map(|kept| kept.len()).unwrap_or(0)
}

/// A copy of `bytes` in a buffer of `provider`, as the transport's and not the application's: a
/// link that negotiated shared memory is sent its descriptor and any other its bytes, and a
/// receiver of the sending session itself is handed the bytes, as upstream's, which copies at the
/// link, hands them. `None` when the provider has no room for it after the collection and the
/// defragmentation upstream's copy allows itself (`io/zenoh-transport/src/common/shm/interop.rs` @
/// `.with_unsafe_policy::<Defragment<GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>>>()`),
/// and for no bytes; the message is then sent as it is. The C ABI's session and the top crate's
/// copy through this one function.
pub fn transport_copy<B>(provider: &Arc<ShmProvider<B>>, bytes: &[u8]) -> Option<ShmSendHandle>
where
    B: ShmProviderBackend + Send + Sync + 'static,
{
    // SAFETY: the policy is upstream's for this copy: it may collect a chunk the watchdog
    // invalidated, which no holder in this process reads, and the buffer it returns is this
    // function's alone until it is sent.
    let allocated = unsafe {
        provider
            .alloc(bytes.len())
            .with_unsafe_policy::<Defragment<GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>>>()
            .wait()
    };
    let mut buffer = allocated.ok()?.into_inner();
    AsMut::<[u8]>::as_mut(&mut buffer).copy_from_slice(bytes);
    let issued = IssuedBuffer::new(buffer, Arc::clone(provider) as Arc<dyn Any + Send + Sync>);
    Some(ShmBuffer::new(Arc::new(issued), ReceiverView::Bytes).into_handle())
}

/// What a descriptor's chunk is doing, as its own metadata slot says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceState {
    /// The slot still holds the buffer the descriptor names, with this many references
    /// outstanding (the owner's, and one per descriptor sent and not yet given back). Zero means
    /// every holder has let go and the provider has not yet collected it.
    Held(u32),
    /// The slot's generation has moved on: the provider collected this chunk, so every holder had
    /// let go and any descriptor naming it is stale.
    Reclaimed,
}

/// The header the descriptor names, or `None` when its metadata segment cannot be opened.
fn header_of(descriptor: &ShmDescriptor) -> Option<HeaderState> {
    zenoh_shm::header_state(&MetadataDescriptor {
        id: descriptor.metadata_id,
        index: descriptor.metadata_index,
    })
    .ok()
}

/// Read a descriptor's chunk state from its metadata segment, or `None` when that segment cannot
/// be opened. A diagnostic, and the instrument the cross-implementation witnesses read the OTHER
/// side's bookkeeping with: whether a zenoh publisher's chunk was released by a wz receiver is a
/// fact in a segment zenoh owns.
pub fn reference_state(descriptor: &ShmDescriptor) -> Option<ReferenceState> {
    let state = header_of(descriptor)?;
    Some(if state.generation != descriptor.generation {
        ReferenceState::Reclaimed
    } else {
        ReferenceState::Held(state.refcount)
    })
}

/// Where a descriptor's chunk lies, as its own header names it: the data segment's id and the
/// chunk's offset in that segment, or `None` when the metadata segment cannot be opened or the
/// slot holds another generation. A diagnostic, like [`reference_state`].
pub fn chunk_position(descriptor: &ShmDescriptor) -> Option<(u32, u32)> {
    let state = header_of(descriptor)?;
    (state.generation == descriptor.generation).then_some((state.segment, state.chunk))
}

/// Whether a descriptor's chunk has been invalidated by its provider's watchdog: `Some(true)` once
/// no holder confirmed it for a whole validation window, `None` when the metadata segment cannot
/// be opened or the slot holds another generation. A diagnostic, like [`reference_state`].
pub fn is_invalidated(descriptor: &ShmDescriptor) -> Option<bool> {
    let state = header_of(descriptor)?;
    (state.generation == descriptor.generation).then_some(state.invalidated)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::shm_reader::ShmReaderResolver;
    use wz_session_core::extshm::ShmResolver;

    fn issued(bytes: &[u8]) -> IssuedBuffer {
        let mut buffer = IssuedBuffer::alloc(bytes.len()).expect("a buffer of its own pool");
        buffer.write(bytes);
        buffer
    }

    /// A reservation dropped before its frame left gives its reference back; a committed one
    /// leaves it with the receiver.
    ///
    /// Turned red by a reservation that does not count in the buffer's own header, or that gives
    /// back a committed reference.
    #[test]
    fn a_reservation_gives_its_reference_back_unless_committed() {
        let buffer = issued(b"reserved");
        let descriptor = buffer.descriptor();
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(1)));

        let wire = buffer.wire_reference();
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(2)));
        drop(wire);
        assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(1)));

        let handle = Arc::new(buffer).send_handle();
        let reservation = handle.reserve_for_receiver();
        assert_eq!(reservation.descriptor(), descriptor);
        reservation.commit();
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(2)),
            "the committed reference is the receiver's"
        );
    }

    /// The reader of the process reads a buffer this process issued, and the reference the sender
    /// took for it is given back when the read buffer drops.
    #[test]
    fn the_reader_of_the_process_reads_a_buffer_this_process_issued() {
        let buffer = issued(b"one reader");
        let wire = buffer.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        let read = ShmReaderResolver::of_default_set()
            .resolve(&descriptor)
            .expect("the descriptor resolves");
        assert_eq!(read, b"one reader");
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "the receiver gave its reference back"
        );
        assert_eq!(
            buffer.protocol(),
            0,
            "the default backend is the POSIX protocol"
        );
    }

    /// A held view is a holder of its own: the owner is not the only holder while it lives, and
    /// the view is once the owner has let go, whose provider the process keeps until then.
    ///
    /// Turned red by a view that shares the owner's reference, or by a provider dropped with its
    /// owner while a view still held its buffer (the slot would read reclaimed).
    #[test]
    fn a_held_view_is_a_holder_of_its_own_and_keeps_the_provider() {
        let buffer = issued(b"held");
        let descriptor = buffer.descriptor();
        assert!(buffer.is_unique());
        let view = buffer.receiver_view().expect("a view");
        assert!(!buffer.is_unique(), "the view holds a reference");
        let chunk = view.shm_chunk().expect("a chunk of shared memory");
        assert!(!chunk.is_unique(), "and so does the owner");

        drop(buffer);
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "the provider is kept for the view"
        );
        assert!(view.shm_chunk().expect("a chunk").is_unique());
        assert_eq!(view.as_slice(), b"held");

        drop(view);
        sweep_orphans();
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed),
            "the provider goes once nobody holds its buffer"
        );
    }

    /// A buffer whose owner let go while a remote receiver held it keeps its provider until the
    /// receiver gives its reference back.
    #[test]
    fn a_provider_outlives_its_owner_while_a_receiver_holds_its_buffer() {
        let buffer = issued(b"in flight");
        let wire = buffer.wire_reference();
        let descriptor = wire.descriptor();
        wire.commit();
        drop(buffer);
        sweep_orphans();
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Held(1)),
            "the descriptor in flight is not made stale"
        );
        let read = ShmReaderResolver::of_default_set()
            .resolve(&descriptor)
            .expect("the receiver reads what was sent");
        assert_eq!(read, b"in flight");
        sweep_orphans();
        assert_eq!(
            reference_state(&descriptor),
            Some(ReferenceState::Reclaimed)
        );
    }

    /// What a receiver of the sending session is handed, by the kind of view.
    ///
    /// Turned red by a shared view that takes a reference of its own, or by a bytes view that hands
    /// a chunk.
    #[test]
    fn the_view_a_session_is_handed_follows_its_kind() {
        let owner = Arc::new(issued(b"view"));
        let holder: Arc<dyn ShmBufHolder> = owner.clone();

        let shared = ShmBuffer::new(Arc::clone(&holder), ReceiverView::Shared);
        let view = shared.receiver_view().expect("the holder itself");
        assert_eq!(owner.buffer().ref_count(), 1, "no reference of its own");
        let (any, range) = view.host_storage().expect("a storage of its own kind");
        let storage = any.downcast_ref::<SharedView>().expect("the shared view");
        assert!(Arc::ptr_eq(storage.holder(), &holder));
        assert_eq!(range, 0..4);
        assert!(view.shm_writable_ptr().is_none(), "the sender holds it too");

        let held = ShmBuffer::new(Arc::clone(&holder), ReceiverView::Held);
        let view = held.receiver_view().expect("a holder of its own");
        assert_eq!(owner.buffer().ref_count(), 2);
        drop(view);

        let bytes = ShmBuffer::new(holder, ReceiverView::Bytes);
        assert!(
            bytes.receiver_view().is_none(),
            "the session is handed the bytes"
        );
        assert_eq!(bytes.bytes(), b"view");
    }

    /// The transport's copy holds the bytes and offers a receiver of the session no view; no bytes
    /// are no copy.
    #[test]
    fn a_transport_copy_holds_the_bytes_and_offers_the_session_no_view() {
        let provider = Arc::new(
            ShmProviderBuilder::default_backend(1usize << 16)
                .wait()
                .expect("a provider"),
        );
        let bytes = [7u8; 4096];
        let copy = transport_copy(&provider, &bytes).expect("room for the copy");
        assert_eq!(copy.bytes(), &bytes[..]);
        assert!(copy.receiver_view().is_none());
        assert!(
            transport_copy(&provider, &[]).is_none(),
            "no bytes, no copy"
        );
        assert!(
            transport_copy(&provider, &[1u8; 1 << 20]).is_none(),
            "a copy the pool cannot hold is sent as it is"
        );
    }

    /// A blocking allocation against a provider that has nothing outstanding fails, where the
    /// original waits for a release that can never come.
    ///
    /// Turned red (by the test's own deadline) when the blocking policy waits with nothing
    /// outstanding.
    #[test]
    fn a_blocking_allocation_with_nothing_outstanding_fails_rather_than_waits() {
        use zenoh_shm::api::provider::shm_provider::BlockOn;

        let (done, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let provider = ShmProviderBuilder::default_backend(1usize << 16)
                .wait()
                .expect("a provider");
            // SAFETY: the buffer, if any, is this thread's alone.
            let allocated = unsafe {
                provider
                    .alloc(1usize << 20)
                    .with_unsafe_policy::<BlockOn<GarbageCollect>>()
                    .wait()
            };
            let _ = done.send(allocated.is_err());
        });
        assert_eq!(
            outcome.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "the allocation failed instead of waiting"
        );
    }

    /// A pool does not map a chunk it did not issue: freeing it later would corrupt the allocator.
    #[test]
    fn a_pool_does_not_map_a_chunk_it_did_not_issue() {
        use std::num::NonZeroUsize;
        use zenoh_shm::api::common::types::PtrInSegment;
        use zenoh_shm::api::provider::chunk::{AllocatedChunk, ChunkDescriptor};

        let provider = ShmProviderBuilder::default_backend(1usize << 16)
            .wait()
            .expect("a provider");
        let mut foreign = vec![0u8; 64];
        let chunk = AllocatedChunk::new(
            ChunkDescriptor::new(1, 0, NonZeroUsize::new(64).expect("non-zero")),
            PtrInSegment::new(foreign.as_mut_ptr(), Arc::new(())),
        );
        assert!(provider.map(chunk, 64).is_err());
    }
}
