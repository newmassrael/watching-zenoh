// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The links a heap profile's IP stack opens ([`crate::ip_stack::IpLinks`]) as one closed type,
//! [`IpLink`]: a sum over the stack's protocols, each link placed in its cell as one of its
//! variants. Where nothing adds a link to the stack's set, the session reads the link as this type
//! and calls a link's methods with a tag test and the variant's body, not through a table
//! ([`ClosedSet`]), and its actions send through it so too; where a stack wrapping this one adds
//! links of its own, the session reads and sends through each link behind its variant's tables, as
//! one of an open set ([`OpenSet`]). Either way what a face keeps to wait on the link reads it
//! behind a table.

use core::mem::MaybeUninit;
use core::ptr::NonNull;

use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::link::{
    BoxedLinkDriver, LinkEnds, LinkSendOutcome, LinkSubject, LostCause, RoomAnswer, RoomWait,
    RxFrame, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

use crate::link_cells::{CellRc, CountKind};
use crate::link_storage::{RxBuffer, TxBuffer};
use crate::session_drive::{
    InputWaiter, LinkOpenError, OpenedLink, SessionDatagramLink, SharedPump, WaitOn,
};
use crate::stream_link::StreamSocket;
#[cfg(feature = "udp-listen")]
use crate::udp_link::PortPeer;
use crate::udp_link::{DatagramSocket, UdpDriver};

/// The discriminant of [`IpLink::Udp`].
const UDP: u8 = 0;
/// The discriminant of `IpLink::Peer` (`udp-listen`).
#[cfg(feature = "udp-listen")]
const PEER: u8 = 1;
/// The discriminant of [`IpLink::Tcp`].
const TCP: u8 = 2;
/// The discriminant of [`IpLink::Tls`].
const TLS: u8 = 3;

/// A `udp/` link of [`IpLink`].
pub type UdpOf<U, N, W> =
    UdpDriver<U, RxBuffer<<N as CountKind>::Flag>, TxBuffer<<N as CountKind>::Flag>, W>;

/// The link of a `udp/` port's peer of [`IpLink`] (`udp-listen`).
#[cfg(feature = "udp-listen")]
pub type PeerOf<U, N, W> = UdpDriver<
    PortPeer<U, <N as CountKind>::Shared>,
    RxBuffer<<N as CountKind>::Flag>,
    TxBuffer<<N as CountKind>::Flag>,
    W,
>;

/// A stream link over `S` of [`IpLink`]: a `tcp/` link over the plain streams, a `tls/` one over
/// the secure channels.
pub type StreamOf<S, N, W> = <S as StreamSocket>::Link<
    RxBuffer<<N as CountKind>::Flag>,
    TxBuffer<<N as CountKind>::Flag>,
    W,
>;

/// A link of an IP stack over the datagram sockets `U`, the plain streams `S` and the secure
/// channels `T`, counted as `N` counts a session's handles and waited for by `W`: the variant is
/// the protocol its dial or its port named. One value in one cell, so a stack's links are one type
/// and one table of each trait where they are read behind one.
///
/// Laid out by its primitive representation (`repr(u8)`): each variant is a C struct of the tag
/// and the variant's field, so the field of a variant of type `V` lies `align_of::<V>()` bytes
/// past the start, which is what lets a link be written where its cell holds it rather than built
/// in a frame and moved there.
// The variants differ in size as their drivers do, and a stack that carries no secure channel has
// a `tls/` variant of no size; clippy weighs that as a large difference. Boxing the larger variant
// would put each link on the heap a second time, beside the cell the session lent it.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
pub enum IpLink<U, S, T, N, W>
where
    U: DatagramSocket + 'static,
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
    N: CountKind,
    W: InputWaiter,
{
    /// A `udp/` link a dial or a port's acceptor opened.
    Udp(UdpOf<U, N, W>) = UDP,
    /// The link of a peer a `udp/` port told apart from the others.
    #[cfg(feature = "udp-listen")]
    Peer(PeerOf<U, N, W>) = PEER,
    /// A `tcp/` link.
    Tcp(StreamOf<S, N, W>) = TCP,
    /// A `tls/` link: the stream link over a secure channel.
    Tls(StreamOf<T, N, W>) = TLS,
}

/// Every method of the link, answered by the variant it is.
macro_rules! on_variant {
    ($self:ident, $link:ident => $body:expr) => {
        match $self {
            IpLink::Udp($link) => $body,
            #[cfg(feature = "udp-listen")]
            IpLink::Peer($link) => $body,
            IpLink::Tcp($link) => $body,
            IpLink::Tls($link) => $body,
        }
    };
}

impl<U, S, T, N, W> IpLink<U, S, T, N, W>
where
    U: DatagramSocket + 'static,
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
    N: CountKind,
    W: InputWaiter,
{
    /// The `udp/` link `make` writes in a cell of `cells` (the heap's when none is lent), as the
    /// set `F` hands it to the session: refused [`LinkOpenError::Unsupported`] when `fits` says the
    /// rows of the build do not name both its ends, [`LinkOpenError::Exhausted`] past the cells.
    #[inline]
    pub(crate) fn open_udp<F: LinkSet<Self, N>>(
        cells: Option<&LentByteCells<N::Flag>>,
        fits: bool,
        make: impl FnOnce(&mut MaybeUninit<UdpOf<U, N, W>>) -> &mut UdpOf<U, N, W>,
    ) -> Result<OpenedLink<F::Pump, N>, LinkOpenError> {
        // SAFETY: `UDP` is the discriminant of the variant whose field is a `UdpOf`.
        unsafe { Self::open_as::<_, F>(cells, fits, UDP, make) }
    }

    /// [`Self::open_udp`] for the link of a `udp/` port's peer.
    #[cfg(feature = "udp-listen")]
    #[inline]
    pub(crate) fn open_peer<F: LinkSet<Self, N>>(
        cells: Option<&LentByteCells<N::Flag>>,
        fits: bool,
        make: impl FnOnce(&mut MaybeUninit<PeerOf<U, N, W>>) -> &mut PeerOf<U, N, W>,
    ) -> Result<OpenedLink<F::Pump, N>, LinkOpenError> {
        // SAFETY: `PEER` is the discriminant of the variant whose field is a `PeerOf`.
        unsafe { Self::open_as::<_, F>(cells, fits, PEER, make) }
    }

    /// [`Self::open_udp`] for a `tcp/` link.
    #[inline]
    pub(crate) fn open_tcp<F: LinkSet<Self, N>>(
        cells: Option<&LentByteCells<N::Flag>>,
        fits: bool,
        make: impl FnOnce(&mut MaybeUninit<StreamOf<S, N, W>>) -> &mut StreamOf<S, N, W>,
    ) -> Result<OpenedLink<F::Pump, N>, LinkOpenError> {
        // SAFETY: `TCP` is the discriminant of the variant whose field is a `StreamOf<S>`.
        unsafe { Self::open_as::<_, F>(cells, fits, TCP, make) }
    }

    /// [`Self::open_udp`] for a `tls/` link.
    #[inline]
    pub(crate) fn open_tls<F: LinkSet<Self, N>>(
        cells: Option<&LentByteCells<N::Flag>>,
        fits: bool,
        make: impl FnOnce(&mut MaybeUninit<StreamOf<T, N, W>>) -> &mut StreamOf<T, N, W>,
    ) -> Result<OpenedLink<F::Pump, N>, LinkOpenError> {
        // SAFETY: `TLS` is the discriminant of the variant whose field is a `StreamOf<T>`.
        unsafe { Self::open_as::<_, F>(cells, fits, TLS, make) }
    }

    /// The link `make` writes as the variant `tag` in a claimed cell, and the two handles the
    /// session holds it by, the sink its actions send through and the pump, as the set `F` hands
    /// the link on. A link refused is never made, and what `make` would have made it of is let go
    /// of where it lies.
    ///
    /// # Safety
    /// `tag` is the discriminant of the variant whose field is a `V`, and `make` leaves a whole `V`
    /// at the place it is handed, which is what the makers of a driver in place do.
    #[inline]
    unsafe fn open_as<V, F>(
        cells: Option<&LentByteCells<N::Flag>>,
        fits: bool,
        tag: u8,
        make: impl FnOnce(&mut MaybeUninit<V>) -> &mut V,
    ) -> Result<OpenedLink<F::Pump, N>, LinkOpenError>
    where
        V: BoxedLinkDriver + SessionDatagramLink + 'static,
        F: LinkSet<Self, N>,
    {
        if !fits {
            return Err(LinkOpenError::Unsupported);
        }
        let claim = CellRc::<Self, N>::claim_of(cells).ok_or(LinkOpenError::Exhausted)?;
        let whole = claim
            // SAFETY: the caller's contract, which is this call's.
            .made(|place| unsafe { Self::write_variant(place, tag, make) })
            .ok_or(LinkOpenError::Exhausted)?;
        Ok(F::opened(whole, |whole| {
            // SAFETY: the cell holds the variant `tag`, whose field is a `V` at that place.
            let variant = unsafe { Self::variant::<V>(whole) };
            OpenedLink {
                sink: variant.clone().into_sink(),
                pump: variant.into_link(),
            }
        }))
    }

    /// The variant `tag` written in `place`: its field by `make`, where the field lies, then its tag.
    ///
    /// # Safety
    /// As [`Self::open_as`].
    unsafe fn write_variant<V>(
        place: &mut MaybeUninit<Self>,
        tag: u8,
        make: impl FnOnce(&mut MaybeUninit<V>) -> &mut V,
    ) -> &mut Self {
        let base = place.as_mut_ptr().cast::<u8>();
        // SAFETY: a variant of a `repr(u8)` enum is a C struct of its tag and its field, so a field
        // of `V` lies `align_of::<V>()` bytes in, inside the place and aligned for `V`; `make`
        // leaves a whole `V` there and `tag` names that variant (the caller's contract), so the
        // place holds a whole value once the tag is written.
        unsafe {
            let field = &mut *base
                .add(core::mem::align_of::<V>())
                .cast::<MaybeUninit<V>>();
            let _made: &mut V = make(field);
            base.write(tag);
            place.assume_init_mut()
        }
    }

    /// `whole` as a handle on the field of its variant, a `V`: the cell is still given back by
    /// the last handle on either, which drops the link whole.
    ///
    /// # Safety
    /// The variant the cell holds has a field of type `V`.
    unsafe fn variant<V>(whole: CellRc<Self, N>) -> CellRc<V, N> {
        // SAFETY: the caller's contract: the field lies `align_of::<V>()` bytes into the link
        // (`Self::write_variant`), as long as the link does.
        unsafe {
            whole.part(|link| {
                NonNull::new_unchecked(
                    link.as_ptr()
                        .cast::<u8>()
                        .add(core::mem::align_of::<V>())
                        .cast::<V>(),
                )
            })
        }
    }
}

impl<U, S, T, N, W> SessionDatagramLink for IpLink<U, S, T, N, W>
where
    U: DatagramSocket + 'static,
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
    N: CountKind,
    W: InputWaiter,
{
    fn service(&self) {
        on_variant!(self, link => link.service())
    }

    fn service_within(&self, max_wait_ms: u64) {
        on_variant!(self, link => link.service_within(max_wait_ms))
    }

    fn uses_wake_budget(&self) -> bool {
        on_variant!(self, link => link.uses_wake_budget())
    }

    fn try_recv(&self) -> Option<RxFrame> {
        on_variant!(self, link => link.try_recv())
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        on_variant!(self, link => link.recv_with(f))
    }

    fn lost(&self) -> Option<LostCause> {
        on_variant!(self, link => link.lost())
    }

    fn take_rx_dropped(&self) -> usize {
        on_variant!(self, link => link.take_rx_dropped())
    }

    fn holds_input(&self) -> bool {
        on_variant!(self, link => link.holds_input())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        on_variant!(self, link => link.waits_for_buffer())
    }

    fn owes_write(&self) -> bool {
        on_variant!(self, link => link.owes_write())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        on_variant!(self, link => link.write_owed_now())
    }

    fn takes_input(&self) -> bool {
        on_variant!(self, link => link.takes_input())
    }

    fn keeps_input(&self) -> bool {
        on_variant!(self, link => link.keeps_input())
    }

    fn keep(&self) {
        on_variant!(self, link => link.keep())
    }

    fn lends_until_next_receive(&self) -> bool {
        on_variant!(self, link => link.lends_until_next_receive())
    }

    fn input_wait(&self) -> Option<WaitOn> {
        on_variant!(self, link => link.input_wait())
    }

    fn room_wait(&self) -> Option<WaitOn> {
        on_variant!(self, link => link.room_wait())
    }
}

/// The sends of the link, answered by the variant it is: the methods any variant states for
/// itself, as [`crate::ip_stack::IpDriver`] answers them, the rest the trait's own.
impl<U, S, T, N, W> BoxedLinkDriver for IpLink<U, S, T, N, W>
where
    U: DatagramSocket + 'static,
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
    N: CountKind,
    W: InputWaiter,
{
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        on_variant!(self, link => link.send_blocking(bytes, reliability))
    }

    // Forwarded, or every session over this link would find room on a stream that has none.
    fn wait_for_room(&self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        on_variant!(self, link => link.wait_for_room(priority, wait))
    }

    fn tx_slot_acquire(&self, want: usize, priority: Priority) -> Option<TxSlotGrant> {
        on_variant!(self, link => link.tx_slot_acquire(want, priority))
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        on_variant!(self, link => link.tx_slot_storage(slot))
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        reliability: Reliability,
        priority: Priority,
    ) -> LinkSendOutcome {
        on_variant!(self, link => link.tx_slot_send(slot, start, len, reliability, priority))
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        on_variant!(self, link => link.tx_slot_abort(slot))
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_spare(&self) -> bool {
        on_variant!(self, link => link.tx_slot_spare())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_claimable(&self) -> bool {
        on_variant!(self, link => link.tx_slot_claimable())
    }

    fn open_blocking(&self) {
        on_variant!(self, link => link.open_blocking())
    }

    fn close_blocking(&self) {
        on_variant!(self, link => link.close_blocking())
    }

    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        on_variant!(self, link => link.link_ends())
    }

    fn link_subject(&self) -> Option<&LinkSubject> {
        on_variant!(self, link => link.link_subject())
    }

    fn peer_credential_zid(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        on_variant!(self, link => link.peer_credential_zid())
    }

    fn batch_length_prefixed(&self) -> bool {
        on_variant!(self, link => link.batch_length_prefixed())
    }

    fn link_mtu(&self) -> usize {
        on_variant!(self, link => link.link_mtu())
    }

    fn link_rx_capacity(&self) -> usize {
        on_variant!(self, link => link.link_rx_capacity())
    }
}

/// How the links of a stack whose links are `E` reach the session that reads and sends through
/// them (`SessionLinks::Pump`, `SharedPump::Sink`): the set the build closes or leaves open.
pub trait LinkSet<E: SessionDatagramLink + BoxedLinkDriver + 'static, N: CountKind>:
    'static
{
    /// The handle a link of the stack is pumped through, which names the type its sink is.
    type Pump: SharedPump<N>;

    /// The two handles the session holds `whole`, a link of the stack in its cell, by, as the set
    /// hands it on; `variant` hands the same link on behind its variant's tables.
    fn opened(
        whole: CellRc<E, N>,
        variant: impl FnOnce(CellRc<E, N>) -> OpenedLink<CellRc<dyn SessionDatagramLink, N>, N>,
    ) -> OpenedLink<Self::Pump, N>;
}

/// The links of a stack that another stack wraps and adds links of its own to: read and sent
/// through behind the tables of their variant, one of an open set, as every link of the wrapping
/// stack is.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenSet;

impl<E: SessionDatagramLink + BoxedLinkDriver + 'static, N: CountKind> LinkSet<E, N> for OpenSet {
    type Pump = CellRc<dyn SessionDatagramLink, N>;

    fn opened(
        whole: CellRc<E, N>,
        variant: impl FnOnce(CellRc<E, N>) -> OpenedLink<CellRc<dyn SessionDatagramLink, N>, N>,
    ) -> OpenedLink<Self::Pump, N> {
        variant(whole)
    }
}

/// The links of a stack nothing adds to: read and sent through as the stack's own type, so each
/// call on a link is the tag test and its variant's body, inlined where it is made, and no table
/// is reached.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClosedSet;

impl<E: SessionDatagramLink + BoxedLinkDriver + 'static, N: CountKind> LinkSet<E, N> for ClosedSet {
    type Pump = ClosedLink<E, N>;

    fn opened(
        whole: CellRc<E, N>,
        _variant: impl FnOnce(CellRc<E, N>) -> OpenedLink<CellRc<dyn SessionDatagramLink, N>, N>,
    ) -> OpenedLink<Self::Pump, N> {
        OpenedLink {
            sink: whole.clone(),
            pump: ClosedLink(whole),
        }
    }
}

/// A link of a closed set in its cell, as the stack hands it to the session's pump ([`ClosedSet`]):
/// the handle on the cell, which names the stack's own type both as the type the link is read as
/// and as the type its sink sends through. A handle on a cell of any other type names the driver's
/// trait for its sink (`SharedPump` for `CellRc`), which is what a stack keeps whose links a
/// session sends through behind a table.
pub struct ClosedLink<E: 'static, N: CountKind>(CellRc<E, N>);

impl<E: 'static, N: CountKind> ClosedLink<E, N> {
    /// The handle on the link's cell.
    pub fn cell(&self) -> &CellRc<E, N> {
        &self.0
    }
}

impl<E: SessionDatagramLink + BoxedLinkDriver + 'static, N: CountKind> SharedPump<N>
    for ClosedLink<E, N>
{
    type Link = E;
    type Sink = E;

    fn share(self) -> Option<CellRc<E, N>> {
        Some(self.0)
    }
}

impl<E: SessionDatagramLink + 'static, N: CountKind> SessionDatagramLink for ClosedLink<E, N> {
    fn service(&self) {
        self.0.service();
    }

    fn service_within(&self, max_wait_ms: u64) {
        self.0.service_within(max_wait_ms);
    }

    fn uses_wake_budget(&self) -> bool {
        self.0.uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        self.0.try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.0.recv_with(f)
    }

    fn lost(&self) -> Option<LostCause> {
        self.0.lost()
    }

    fn take_rx_dropped(&self) -> usize {
        self.0.take_rx_dropped()
    }

    fn holds_input(&self) -> bool {
        self.0.holds_input()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        self.0.waits_for_buffer()
    }

    fn owes_write(&self) -> bool {
        self.0.owes_write()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        self.0.write_owed_now();
    }

    fn takes_input(&self) -> bool {
        self.0.takes_input()
    }

    fn keeps_input(&self) -> bool {
        self.0.keeps_input()
    }

    fn keep(&self) {
        self.0.keep();
    }

    fn lends_until_next_receive(&self) -> bool {
        self.0.lends_until_next_receive()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.0.input_wait()
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.0.room_wait()
    }
}
