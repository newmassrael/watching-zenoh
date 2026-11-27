// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`GroupTransport`] — what a multicast group session needs of the network
//! stack under it.
//!
//! The group drive loop was written against lwIP and named lwIP's types for what
//! it needs of a stack, which is four things: pump the stack's input path, say
//! whether the carrier is up, multicast one datagram to the group, and take one
//! inbound datagram with its source address. This trait is those four. The loop
//! (`wz-session-mcu`'s `group_drive`) is generic over it, as the unicast loop is
//! generic over [`SessionDatagramLink`](crate::session_drive::SessionDatagramLink);
//! lwIP supplies one implementation (`wz-session-lwip`) and Zephyr's sockets
//! another, so a board is not asked to carry the lwIP crate to run a group
//! session over some other stack.
//!
//! It is the multicast twin of that trait and not an extension of it because the
//! two differ where it counts: a unicast link retargets its replies to whoever
//! spoke last and a group never does, and the group's receive carries the source
//! address the §3.2 peer table is keyed by.
//!
//! Two more are the session machine's: `open` and `close` are how the loop
//! performs its `open_multicast_link` and `release_multicast_link` duties, so a
//! transport is the session's link only between the two.

use core::net::{Ipv4Addr, SocketAddr};

// A buffer a session lends exists only where the crate carries sessions.
#[cfg(feature = "session-unicast")]
use wz_session_core::byte_cells::ByteBuf;
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
use wz_session_core::byte_cells::LentByteCells;

/// The interface a group is joined on and sent out of, in the form the group's family names one:
/// IPv4 by an address the interface holds (`IP_ADD_MEMBERSHIP`'s `imr_interface`,
/// `IP_MULTICAST_IF`), IPv6 by its index (`IPV6_JOIN_GROUP`'s `ipv6mr_interface`,
/// `IPV6_MULTICAST_IF`), as upstream zenoh joins an IPv6 group
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.join_multicast_v6(&dst_ip6, 0)`) and
/// sends out of an interface it names by index (`.set_multicast_if_v6(idx)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupInterface {
    /// The interface the stack's routing picks for the group, of either family.
    Routing,
    /// The IPv4 interface that holds this address.
    V4(Ipv4Addr),
    /// The interface of this index, for an IPv6 group. Zero is the stack's choice, as
    /// [`Self::Routing`] is.
    Index(u32),
}

impl GroupInterface {
    /// Whether the interface can be named to a group of `group`'s family: an IPv4 address names
    /// an interface to an IPv4 group only, an index to an IPv6 group only, and the routing's
    /// choice to either.
    pub const fn names_for(self, group: &SocketAddr) -> bool {
        matches!(
            (self, group),
            (GroupInterface::Routing, _)
                | (GroupInterface::V4(_), SocketAddr::V4(_))
                | (GroupInterface::Index(_), SocketAddr::V6(_))
        )
    }
}

/// One group session's whole I/O seam: the socket joined to the group, the group
/// address the loop multicasts to, and whatever the stack needs pumped.
///
/// The loop owns it exclusively for the life of the session (single task, one
/// consumer), which is why the sending and receiving halves take `&mut self`.
pub trait GroupTransport {
    /// Take this transport as the session's group link: the session machine's
    /// `open_multicast_link` duty. `false` when it cannot carry the group (its
    /// socket was released); the session then ends as a lost link before
    /// anything is sent.
    ///
    /// The socket is bound and joined to the group by whoever built the
    /// transport, out of the image's own socket pool, so opening does not bind:
    /// it is what makes that socket the session's link from here on.
    fn open(&mut self) -> bool;

    /// Release the group link: the session machine's `release_multicast_link`
    /// duty. A transport that owns its socket gives it back; one that borrows
    /// it lets the borrow go. Either way it sends and receives nothing after,
    /// and a later `open` fails.
    fn close(&mut self);

    /// Advance the stack's input path and timers by one pass. A stack the loop
    /// must pump (lwIP `NO_SYS`, polled from this thread) does its work here;
    /// one whose input runs on its own thread or ISR does nothing.
    fn service(&self);

    /// Whether the interface the group is joined on has a carrier. Read once per
    /// iteration; `false` ends the session as a lost link. A stack that has no
    /// carrier to report answers `true`.
    fn carrier_up(&self) -> bool;

    /// Multicast one datagram to the group. Best-effort like the AP loop's JOIN
    /// and data emit: multicast UDP has no acknowledgement, a failed send is
    /// non-fatal (the next cadence retries), and the error is dropped.
    fn send_to_group(&mut self, datagram: &[u8]);

    /// Multicast one datagram to the group if the socket takes it now, and say whether it did:
    /// [`GroupSend::Full`] is a socket with no room for it, which nothing was sent to and which
    /// the caller may offer the same datagram again; [`GroupSend::Failed`] is a send the stack
    /// refused for any other reason, after which the datagram is lost. The loop's data emit sends
    /// this way, so a datagram a full socket would have lost waits for room as the tokio group's
    /// writer waits for it.
    ///
    /// A stack that cannot tell a full socket from a sent datagram answers [`GroupSend::Sent`]
    /// after [`Self::send_to_group`], which is what the provided form does.
    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        self.send_to_group(datagram);
        GroupSend::Sent
    }

    /// Wait up to `timeout_us` microseconds for the socket to take another datagram: `true` once
    /// it will (or once it has failed, which the send that follows reports), `false` when it still
    /// would not when the time is up. A sender whose message found the group's queue full waits
    /// here, as a unicast link's sender waits on its stream. A stack that cannot tell answers
    /// `true` at once, which is what the provided form does.
    fn wait_for_room(&self, timeout_us: u64) -> bool {
        let _ = timeout_us;
        true
    }

    /// What a sender with nothing of the session held waits on, from outside the loop that owns
    /// the transport, for the room [`Self::wait_for_room`] waits for: the group's half of
    /// [`SessionDatagramLink::room_wait`](crate::session_drive::SessionDatagramLink::room_wait).
    /// `None` for a stack that gives none; the heap profile's, as that one is.
    #[cfg(all(
        feature = "session-unicast",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    fn room_wait(&self) -> Option<crate::session_drive::WaitOn> {
        None
    }

    /// What a host with nothing of the session held waits on, from outside the loop that owns the
    /// transport, for the group's next inbound datagram: the group's half of
    /// [`SessionDatagramLink::input_wait`](crate::session_drive::SessionDatagramLink::input_wait).
    /// A host that steps the group waits on it, and on the group's deadlines, instead of looking
    /// at the group on a tick. `None` for a stack that gives none; the heap profile's, as that one
    /// is.
    #[cfg(all(
        feature = "session-unicast",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    fn input_wait(&self) -> Option<crate::session_drive::WaitOn> {
        None
    }

    /// Lend the next inbound datagram and its source address to `f` WHERE THE
    /// TRANSPORT HOLDS IT, and let it go once `f` returns, or, on a transport that
    /// lends until its next receive ([`Self::lends_until_next_receive`]), once it
    /// is next asked to receive; `false` when nothing is queued. The source is the §3.2 peer key: an opaque equality key, so the
    /// only requirement is that one peer's datagrams always carry the same one.
    /// `f` must not call back into the transport.
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool;

    /// Whether the transport can keep the datagram it last lent ([`Self::keep`]) and lend the same
    /// bytes again: one that holds what it read until it reads the next datagram. A session whose
    /// host has no room for all of a datagram then stops part-way and goes on from there on a later
    /// step, as a unicast link that keeps its datagram lets it, and nothing is copied to wait. The
    /// provided form answers `false`, and the session reads every datagram whole.
    fn keeps_input(&self) -> bool {
        false
    }

    /// Keep the datagram the last [`Self::recv_with`] lent: the next `recv_with` lends the same
    /// bytes, from the same source, before any other datagram. Called after the lend returned.
    /// Does nothing on a transport that does not keep ([`Self::keeps_input`]).
    fn keep(&mut self) {}

    /// Whether the bytes [`Self::recv_with`] lent stay where they lie until the transport is next
    /// asked to receive: nothing it does meanwhile, its service included, writes them. A session
    /// that holds what it was lent past the call then reads it there and asks for no other
    /// datagram until it no longer does. The provided form answers `false`: the bytes are let go
    /// of as the lend returns, and a session copies what it holds of them.
    fn lends_until_next_receive(&self) -> bool {
        false
    }

    /// The buffer the transport receives into, given back as the group is left, when it is one
    /// its session lent it (`LinkTables`): the session keeps the buffer while it still reads a
    /// datagram there, and its table has the buffer again once that ends. Asked after
    /// [`Self::close`], or as the transport is let go of without one; either way the transport
    /// receives nothing after it. `None`, the provided answer, from a transport whose buffer is its
    /// own. Present where the crate carries sessions (`session-unicast`), which lend buffers.
    #[cfg(feature = "session-unicast")]
    fn give_back_rx(&mut self) -> Option<ByteBuf> {
        None
    }

    /// The bytes of a datagram one send of this transport carries, when it carries less than a
    /// group's batch may be (a raw Ethernet frame): the group frames its batches to it while its
    /// JOIN still states the group's batch, as the tokio engine's group pipeline frames to its
    /// link's budget. `None`, the provided answer, for a transport that carries whatever batch
    /// its group runs.
    fn frame_budget(&self) -> Option<u16> {
        None
    }

    /// The half of the transport that receives, taken out of it: from here on this transport
    /// sends, and receives nothing, and what [`GroupTransport::recv_with`] and the reads beside it
    /// answered is the half's to answer. A reader that holds the half apart from the transport's
    /// senders reads the group without reaching anything a send reaches. `None`, the provided
    /// answer, from a transport whose two halves are one, which goes on receiving as it did.
    #[cfg(all(
        feature = "session-unicast",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    fn split_receive(&mut self) -> Option<alloc::boxed::Box<dyn GroupReceive>> {
        None
    }
}

/// The half of a group's transport that receives: the socket joined to the group and the buffer
/// it reads into, apart from the half the group's senders share
/// ([`GroupTransport::split_receive`]). Each read answers as the transport's own read of the same
/// name answers.
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
pub trait GroupReceive {
    /// As [`GroupTransport::recv_with`].
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool;

    /// As [`GroupTransport::keeps_input`].
    fn keeps_input(&self) -> bool {
        false
    }

    /// As [`GroupTransport::keep`].
    fn keep(&mut self) {}

    /// As [`GroupTransport::lends_until_next_receive`].
    fn lends_until_next_receive(&self) -> bool {
        false
    }

    /// As [`GroupTransport::input_wait`].
    fn input_wait(&self) -> Option<crate::session_drive::WaitOn> {
        None
    }

    /// Whether a receive failed: what a host reports of an interface that went away, which ends
    /// the group's link as [`GroupTransport::carrier_up`] answering `false` does.
    fn failed(&self) -> bool {
        false
    }

    /// Whether [`Self::await_input`] waits: a half whose socket's receive itself waits, for at
    /// most a time it is given. The provided answer is no, and a reader of such a half waits on
    /// [`Self::input_wait`] instead.
    fn awaits_input(&self) -> bool {
        false
    }

    /// Wait in the receive itself, for at most `timeout_us` microseconds past `since_us`, the
    /// caller's last reading of the clock `now_us` reads, for a member's datagram, and keep it
    /// ([`Self::keep`]) for the next [`Self::recv_with`] to lend: `true` once one is kept, `false`
    /// when the time ran out or the receive failed. What the group's own sender sent is dropped
    /// inside the wait, which goes on for what is left of the time, as zenoh-pico's receive loops
    /// past its own datagrams; the clock is read only then. The provided form waits for nothing.
    fn await_input(
        &mut self,
        timeout_us: u64,
        since_us: u64,
        now_us: &mut dyn FnMut() -> u64,
    ) -> bool {
        let _ = (timeout_us, since_us, now_us);
        false
    }

    /// Receive nothing more: this half's part of [`GroupTransport::close`].
    fn close(&mut self);
}

/// What a group's socket did with a datagram it was offered ([`GroupTransport::try_send_to_group`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSend {
    /// The socket took it.
    Sent,
    /// The socket has no room for it now; nothing was sent.
    Full,
    /// The send failed otherwise; the datagram is lost.
    Failed,
}

/// The buffer a group transport receives into: one of its own, or one its session lent from the
/// memory it reserved when it opened (`SessionLinks::lend_groups`), which goes back to the
/// session as the group is left ([`GroupTransport::give_back_rx`]). The transport reads and writes it whole,
/// whichever it is, and says what a datagram longer than it comes to: a host's socket cuts it, as
/// it cut one past a buffer of the transport's own.
///
/// `O` is the transport's own buffer, made by the transport's crate: this one takes no memory of
/// the heap, so a build that links no allocator here (`session-slot`) has the type too.
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
pub enum GroupRx<O> {
    /// The transport's own, made when the group was joined.
    Own(O),
    /// A buffer the session lent.
    Lent(ByteBuf),
    /// The lent buffer, given back: the group was left and receives nothing more.
    GivenBack,
}

#[cfg(all(feature = "alloc", feature = "session-unicast"))]
impl<O: AsRef<[u8]> + AsMut<[u8]>> GroupRx<O> {
    /// The buffer `lent` names, when the session lent one, or one of the transport's own that
    /// `own` makes.
    pub fn lent_or_own(lent: Option<ByteBuf>, own: impl FnOnce() -> O) -> Self {
        match lent {
            Some(buf) => Self::Lent(buf),
            None => Self::Own(own()),
        }
    }

    /// The buffer's bytes; none once given back.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Own(bytes) => bytes.as_ref(),
            Self::Lent(buf) => buf.as_slice(),
            Self::GivenBack => &[],
        }
    }

    /// The buffer's bytes, to receive into; none once given back.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Own(bytes) => bytes.as_mut(),
            Self::Lent(buf) => buf.as_mut_slice(),
            Self::GivenBack => &mut [],
        }
    }

    /// Whether the buffer is one the session lent and has not been given back.
    pub fn is_lent(&self) -> bool {
        matches!(self, Self::Lent(_))
    }

    /// The lent buffer, once: what [`GroupTransport::give_back_rx`] answers. `None` for a buffer
    /// of the transport's own, which stays where it is.
    pub fn give_back(&mut self) -> Option<ByteBuf> {
        match core::mem::replace(self, Self::GivenBack) {
            Self::Lent(buf) => Some(buf),
            other => {
                *self = other;
                None
            }
        }
    }
}

/// The receive buffer a session gives a group its links join ([`GroupJoiner::join`]).
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
pub enum GroupBuffer {
    /// A buffer of the table the session lent, which the group gives back as it is left.
    Lent(ByteBuf),
    /// One of the transport's own, this many bytes long: the session's group batch, the length a
    /// buffer of its table would have, as a session that takes its links' memory on use gives it.
    Sized(usize),
    /// None: the transport's own, of the largest datagram it reads whole, as links no session
    /// gave group buffers hold it.
    Unsized,
}

#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl<O: AsRef<[u8]> + AsMut<[u8]>> GroupRx<O> {
    /// The buffer `given` names: the session's, or one of the transport's own that `own` makes
    /// of the bytes the session sized, or of `widest`, the largest datagram the transport reads
    /// whole, where it sized none. `None`, nothing held, when `own` has no memory for it.
    pub fn given(
        given: GroupBuffer,
        widest: usize,
        own: impl FnOnce(usize) -> Option<O>,
    ) -> Option<Self> {
        match given {
            GroupBuffer::Lent(buf) => Some(Self::Lent(buf)),
            GroupBuffer::Sized(bytes) => own(bytes).map(Self::Own),
            GroupBuffer::Unsized => own(widest).map(Self::Own),
        }
    }
}

#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl GroupRx<alloc::vec::Vec<u8>> {
    /// [`Self::given`], a buffer of the transport's own taken from the heap, which may refuse it.
    pub fn of_heap(given: GroupBuffer, widest: usize) -> Option<Self> {
        Self::given(given, widest, crate::link_storage::zeroed_bytes)
    }
}

/// Where the receive buffers of the groups a stack's links join come from, for links of the kind
/// that names it ([`CountKind::Groups`](crate::link_cells::CountKind::Groups)), which a session
/// hands the stack once (`SessionLinks::lend_groups`): a table the session lent, for a kind whose
/// sessions lend their links tables, or the length of the buffer each group takes of its own, for
/// [`OnHeap`](crate::link_cells::OnHeap)'s. What a stack holds before a session hands it one gives
/// each group the transport's own buffer, of the largest datagram it reads whole.
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
pub trait GroupSource: Copy + Default {
    /// The buffer of a group joined now: a claim of the table, where a table with none left
    /// refuses the join as [`LinkOpenError::Exhausted`](crate::session_drive::LinkOpenError)
    /// before the joiner is asked.
    fn buffer(&self) -> Result<GroupBuffer, crate::session_drive::LinkOpenError>;

    /// The table a group's buffer is claimed of: `None` for a source that lends none.
    fn table(&self) -> Option<&LentByteCells>;
}

/// A table a session lent, while it lent one: each group claims a buffer of it, a group past it
/// is refused as exhausted, and the buffer goes back as the group is left.
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl GroupSource for Option<LentByteCells> {
    fn buffer(&self) -> Result<GroupBuffer, crate::session_drive::LinkOpenError> {
        match self {
            Some(table) => table
                .claim()
                .map(GroupBuffer::Lent)
                .ok_or(crate::session_drive::LinkOpenError::Exhausted),
            None => Ok(GroupBuffer::Unsized),
        }
    }

    fn table(&self) -> Option<&LentByteCells> {
        self.as_ref()
    }
}

/// Each group a buffer of its own taken from the heap as it is joined, as long as the session's
/// group batch (`Self::sized`): the source of a kind whose sessions take their links' memory on
/// use, so a group holds what the session's table would have lent it and nothing is laid out for
/// it before it is joined. The groups a session joins at once are its config's, which bounds them.
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapGroups {
    /// The bytes of a group's buffer, the session's group batch.
    bytes: Option<usize>,
}

#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl HeapGroups {
    /// Every group a buffer of `bytes`, the session's group batch.
    pub const fn sized(bytes: usize) -> Self {
        Self { bytes: Some(bytes) }
    }
}

#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl GroupSource for HeapGroups {
    fn buffer(&self) -> Result<GroupBuffer, crate::session_drive::LinkOpenError> {
        Ok(self.bytes.map_or(GroupBuffer::Unsized, GroupBuffer::Sized))
    }

    fn table(&self) -> Option<&LentByteCells> {
        None
    }
}

/// A transport a stack handed out boxed (`SessionLinks::open_group` on the heap profile) is the
/// transport it boxes, so the group loop runs over it as over the stack's own type.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<T: GroupTransport + ?Sized> GroupTransport for alloc::boxed::Box<T> {
    fn open(&mut self) -> bool {
        (**self).open()
    }

    fn close(&mut self) {
        (**self).close()
    }

    fn service(&self) {
        (**self).service()
    }

    fn carrier_up(&self) -> bool {
        (**self).carrier_up()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        (**self).send_to_group(datagram)
    }

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        (**self).try_send_to_group(datagram)
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        (**self).wait_for_room(timeout_us)
    }

    #[cfg(feature = "session-unicast")]
    fn room_wait(&self) -> Option<crate::session_drive::WaitOn> {
        (**self).room_wait()
    }

    #[cfg(feature = "session-unicast")]
    fn input_wait(&self) -> Option<crate::session_drive::WaitOn> {
        (**self).input_wait()
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        (**self).recv_with(f)
    }

    fn keeps_input(&self) -> bool {
        (**self).keeps_input()
    }

    fn keep(&mut self) {
        (**self).keep()
    }

    fn lends_until_next_receive(&self) -> bool {
        (**self).lends_until_next_receive()
    }

    #[cfg(feature = "session-unicast")]
    fn give_back_rx(&mut self) -> Option<ByteBuf> {
        (**self).give_back_rx()
    }

    fn frame_budget(&self) -> Option<u16> {
        (**self).frame_budget()
    }

    #[cfg(feature = "session-unicast")]
    fn split_receive(&mut self) -> Option<alloc::boxed::Box<dyn GroupReceive>> {
        (**self).split_receive()
    }
}

/// What joins the multicast groups a stack's links are asked for
/// ([`SessionLinks::open_group`](crate::session_drive::SessionLinks::open_group)) when the stack
/// itself is a host's sockets: the joining is the host's (its interface table, its membership
/// and egress options), so the links that dial and listen on the host are given it as a value,
/// as they are given the dial of their streams. A joiner that joins no group, or not the one
/// named, is [`LinkOpenError::Unsupported`](crate::session_drive::LinkOpenError::Unsupported).
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
pub trait GroupJoiner {
    /// The group `group` names, joined: the transport a group session runs over. `rx` is the
    /// buffer the transport receives into, as its session gave it ([`GroupSource::buffer`]): the
    /// session's, or the length of one of the transport's own ([`GroupRx::given`]). A buffer of
    /// its own the heap refuses is [`LinkOpenError::Exhausted`](crate::session_drive::LinkOpenError).
    fn join(
        &self,
        group: &wz_session_core::group_locator::GroupLocator,
        rx: GroupBuffer,
    ) -> Result<alloc::boxed::Box<dyn GroupTransport>, crate::session_drive::LinkOpenError>;
}

/// The joiner of links that join no group: every group endpoint is
/// [`LinkOpenError::Unsupported`](crate::session_drive::LinkOpenError::Unsupported), what the
/// seam answers by default.
#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGroups;

#[cfg(all(
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl GroupJoiner for NoGroups {
    fn join(
        &self,
        group: &wz_session_core::group_locator::GroupLocator,
        rx: GroupBuffer,
    ) -> Result<alloc::boxed::Box<dyn GroupTransport>, crate::session_drive::LinkOpenError> {
        let _ = (group, rx);
        Err(crate::session_drive::LinkOpenError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    /// A buffer of the transport's own stays with it; a lent one is the session's, read and
    /// written as the transport's own is, and given back once, after which it reads as empty.
    #[cfg(all(feature = "alloc", feature = "session-unicast"))]
    #[test]
    fn a_lent_group_buffer_is_given_back_once_and_an_own_one_never() {
        use wz_session_core::byte_cells::{ByteCells, ByteSource};

        static CELLS: ByteCells<4, 1> = ByteCells::new();
        let mut own = GroupRx::lent_or_own(None, || [0u8; 6]);
        assert!(!own.is_lent());
        assert_eq!(own.as_mut_slice().len(), 6, "its own, as long as asked");
        assert!(own.give_back().is_none(), "its own is not given back");
        assert_eq!(own.as_slice().len(), 6, "and stays");

        let mut lent = GroupRx::lent_or_own(CELLS.claim(), || [0u8; 6]);
        assert!(lent.is_lent());
        lent.as_mut_slice().copy_from_slice(b"abcd");
        assert_eq!(lent.as_slice(), b"abcd", "the lent cell, as long as it is");
        let back = lent.give_back().expect("the lent cell");
        assert!(!lent.is_lent());
        assert!(lent.give_back().is_none(), "given back once");
        assert!(lent.as_slice().is_empty() && lent.as_mut_slice().is_empty());
        assert_eq!(CELLS.in_use(), 1, "held by whoever it was given back to");
        drop(back);
        assert_eq!(CELLS.in_use(), 0);
    }

    /// A group's buffer is what its session gave it: the lent one; one of the transport's own of
    /// the length the session sized; or, where it sized none, of the widest datagram. An own
    /// buffer the maker has no memory for gives no buffer. Turned red by a sized buffer made at
    /// the widest length, which each group would hold where its session takes memory on use.
    #[cfg(all(
        feature = "session-unicast",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    #[test]
    fn a_group_buffer_is_the_one_its_session_gave() {
        use wz_session_core::byte_cells::{ByteCells, ByteSource};

        static CELLS: ByteCells<4, 1> = ByteCells::new();
        let own = |len: usize| Some(alloc::vec![0u8; len]);
        let sized = GroupRx::given(GroupBuffer::Sized(48), 1_500, own).expect("made");
        assert_eq!(sized.as_slice().len(), 48, "the session's batch");
        assert!(!sized.is_lent());
        let widest = GroupRx::given(GroupBuffer::Unsized, 1_500, own).expect("made");
        assert_eq!(widest.as_slice().len(), 1_500, "the widest datagram");
        let lent = GroupRx::given(
            GroupBuffer::Lent(CELLS.claim().expect("the cell")),
            1_500,
            own,
        )
        .expect("the lent cell");
        assert!(lent.is_lent());
        assert_eq!(lent.as_slice().len(), 4, "the lent cell, as long as it is");
        assert!(
            GroupRx::<alloc::vec::Vec<u8>>::given(GroupBuffer::Sized(48), 1_500, |_| None)
                .is_none(),
            "no memory, no buffer"
        );
        drop(lent);
        assert_eq!(CELLS.in_use(), 0);
    }

    /// A source of the heap hands each group the length it was sized to, and none given, or a
    /// session that lent no table, the widest. Turned red by a heap source that hands no length,
    /// which leaves each group the widest datagram's buffer.
    #[cfg(all(
        feature = "session-unicast",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    #[test]
    fn a_heap_source_hands_each_group_its_sized_length() {
        assert!(matches!(
            HeapGroups::sized(48).buffer(),
            Ok(GroupBuffer::Sized(48))
        ));
        assert!(HeapGroups::sized(48).table().is_none());
        assert!(matches!(
            HeapGroups::default().buffer(),
            Ok(GroupBuffer::Unsized)
        ));
        assert!(matches!(
            None::<LentByteCells>.buffer(),
            Ok(GroupBuffer::Unsized)
        ));
    }

    /// An interface is named to a group in the group's own family, and the routing's choice to
    /// either: an address to an IPv6 group, or an index to an IPv4 one, names nothing.
    #[test]
    fn an_interface_is_named_to_a_group_of_its_own_family() {
        let v4 = SocketAddr::from(([224, 0, 0, 224], 7446));
        let v6 = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 7446));
        let address = GroupInterface::V4(Ipv4Addr::new(10, 0, 0, 2));
        let index = GroupInterface::Index(2);
        assert!(GroupInterface::Routing.names_for(&v4));
        assert!(GroupInterface::Routing.names_for(&v6));
        assert!(address.names_for(&v4));
        assert!(!address.names_for(&v6));
        assert!(index.names_for(&v6));
        assert!(!index.names_for(&v4));
    }

    /// A transport that states only what it must, and counts the datagrams it was sent.
    #[derive(Default)]
    struct Socket {
        sent: usize,
    }

    impl GroupTransport for Socket {
        fn open(&mut self) -> bool {
            true
        }

        fn close(&mut self) {}

        fn service(&self) {}

        fn carrier_up(&self) -> bool {
            true
        }

        fn send_to_group(&mut self, _datagram: &[u8]) {
            self.sent += 1;
        }

        fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            false
        }
    }

    /// A transport whose two halves are one splits nothing; one that splits hands its receive half
    /// out once, through the box a session holds it in, and the half reads what the transport
    /// would have read. Turned red by a box that does not pass the split on (`Box`'s
    /// `split_receive` left to the provided answer).
    #[cfg(all(
        feature = "alloc",
        feature = "session-unicast",
        not(feature = "session-slot")
    ))]
    #[test]
    fn a_split_receive_half_is_handed_on_through_the_box() {
        struct Half;

        impl GroupReceive for Half {
            fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
                f(b"member", SocketAddr::from(([192, 0, 2, 7], 7447)));
                true
            }

            fn close(&mut self) {}
        }

        struct Splits(Option<alloc::boxed::Box<dyn GroupReceive>>);

        impl GroupTransport for Splits {
            fn open(&mut self) -> bool {
                true
            }

            fn close(&mut self) {}

            fn service(&self) {}

            fn carrier_up(&self) -> bool {
                true
            }

            fn send_to_group(&mut self, _datagram: &[u8]) {}

            fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
                false
            }

            fn split_receive(&mut self) -> Option<alloc::boxed::Box<dyn GroupReceive>> {
                self.0.take()
            }
        }

        let mut one = Socket::default();
        assert!(one.split_receive().is_none(), "CONTROL: its halves are one");
        let mut boxed: alloc::boxed::Box<dyn GroupTransport> =
            alloc::boxed::Box::new(Splits(Some(alloc::boxed::Box::new(Half))));
        let mut half = boxed
            .split_receive()
            .expect("the receive half, through the box");
        assert!(boxed.split_receive().is_none(), "handed out once");
        let mut member = false;
        assert!(half.recv_with(&mut |bytes, _| member = bytes == b"member"));
        assert!(member, "the half reads what the transport would have");
        assert!(!half.failed() && !half.keeps_input() && half.input_wait().is_none());
        assert!(
            !half.awaits_input() && !half.await_input(1_000, 0, &mut || 0),
            "the provided half waits for nothing"
        );
    }

    /// A stack that cannot tell a full socket from a sent datagram sends the datagram and answers
    /// that it was sent, and has room whenever it is asked.
    #[test]
    fn a_stack_that_cannot_tell_sends_and_answers_sent() {
        let mut socket = Socket::default();
        assert_eq!(socket.try_send_to_group(b"d"), GroupSend::Sent);
        assert_eq!(socket.sent, 1, "the datagram went to the plain send");
        assert!(socket.wait_for_room(1_000));
    }

    /// A stack the session holds boxed answers through the box as it answers itself: a socket
    /// with no room is full through it, and has none to wait for.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_boxed_stack_answers_as_the_stack_does() {
        struct Full;

        impl GroupTransport for Full {
            fn open(&mut self) -> bool {
                true
            }

            fn close(&mut self) {}

            fn service(&self) {}

            fn carrier_up(&self) -> bool {
                true
            }

            fn send_to_group(&mut self, _datagram: &[u8]) {}

            fn try_send_to_group(&mut self, _datagram: &[u8]) -> GroupSend {
                GroupSend::Full
            }

            fn wait_for_room(&self, _timeout_us: u64) -> bool {
                false
            }

            fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
                false
            }
        }

        let mut boxed: alloc::boxed::Box<dyn GroupTransport> = alloc::boxed::Box::new(Full);
        assert_eq!(boxed.try_send_to_group(b"d"), GroupSend::Full);
        assert!(!boxed.wait_for_room(1_000));
        let mut plain: alloc::boxed::Box<dyn GroupTransport> =
            alloc::boxed::Box::new(Socket::default());
        assert_eq!(
            plain.try_send_to_group(b"d"),
            GroupSend::Sent,
            "CONTROL: a stack that cannot tell"
        );
    }

    /// A transport that says nothing of its buffer lends a datagram for the call only and gives
    /// no buffer back; one that receives into a buffer its session lent says both through the box
    /// a session holds it in, and gives the buffer back once. Turned red by a box that does not
    /// pass either answer on, which would leave the session copying or the buffer with the
    /// transport.
    #[cfg(all(
        feature = "alloc",
        feature = "session-unicast",
        not(feature = "session-slot")
    ))]
    #[test]
    fn a_lent_buffer_is_told_and_given_back_through_the_box() {
        use wz_session_core::byte_cells::{ByteCells, ByteSource};

        static CELLS: ByteCells<8, 1> = ByteCells::new();

        struct Lent(Option<ByteBuf>);

        impl GroupTransport for Lent {
            fn open(&mut self) -> bool {
                true
            }

            fn close(&mut self) {}

            fn service(&self) {}

            fn carrier_up(&self) -> bool {
                true
            }

            fn send_to_group(&mut self, _datagram: &[u8]) {}

            fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
                false
            }

            fn lends_until_next_receive(&self) -> bool {
                true
            }

            fn give_back_rx(&mut self) -> Option<ByteBuf> {
                self.0.take()
            }
        }

        let mut own = Socket::default();
        assert!(!own.lends_until_next_receive(), "lent for the call only");
        assert!(own.give_back_rx().is_none(), "its buffer is its own");
        let mut boxed: alloc::boxed::Box<dyn GroupTransport> =
            alloc::boxed::Box::new(Lent(CELLS.claim()));
        assert!(boxed.lends_until_next_receive());
        let buf = boxed.give_back_rx().expect("the lent buffer");
        assert!(boxed.give_back_rx().is_none(), "given back once");
        assert_eq!(
            CELLS.in_use(),
            1,
            "the buffer is the session's to let go of"
        );
        drop(buf);
        assert_eq!(CELLS.in_use(), 0);
    }
}
