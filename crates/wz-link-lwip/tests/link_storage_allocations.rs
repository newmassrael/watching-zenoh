// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What opening, using and closing the link costs the heap, counted (Round 3277,
//! fixed-memory step S7).
//!
//! The link is the two things lwIP keeps a pointer into: a socket's state, which
//! the `udp_pcb` holds as its receive callback's argument, and an interface's MAC,
//! which the netif holds as its transmit callback's context. Both used to live on
//! a heap (`Pin<Box<Inner>>`, a leaked `Box`). Each test here runs its subject on
//! its own under a counting `#[global_allocator]`:
//!
//! - two sockets bound, a datagram sent from one to the other through lwIP's
//!   loopback netif and read both ways a reader reads (an owned `try_recv`, a
//!   borrowed `peek_recv` and `consume_recv`), both sockets dropped;
//! - the same with the session socket the MCU opens, a 16 x 1536 receive queue,
//!   24.7 KB of state, bound by the helper the session shell calls;
//! - an Ethernet interface added over a MAC double, an ARP exchange through it
//!   (the transmit trampoline and the receive poll), a datagram in, a datagram
//!   out, with the interface's frame buffer receiving what the MAC does not lend.
//!
//! With `static-link-storage` (the MCU profile's: the state is a cell of a
//! `static` pool the image declares) every one of them must cost the heap
//! NOTHING, bytes included. Without it (the profile every shipped image and the AP
//! run today) each must cost it something, and that half is the instrument's own
//! control: a count that read zero on the shape that is known to box would prove
//! nothing about the shape that is meant not to.
//!
//! With `static-link-storage` the refusals are witnessed too. A pool filled to its
//! capacity refuses the next bind (socket) or addition (interface) as an explicit
//! error, counted by the pool, allocating nothing; a socket that drops gives its
//! cell back and the next bind finds it, allocating nothing; a bind that lwIP
//! refuses (a port in use) gives its cell back too. An interface is never removed,
//! so its cell is never returned, which the last test pins.
//!
//! The count is ATTRIBUTED to the measurement's own thread, as the AP datagram
//! suites attribute theirs (`datagram_rx_pool_allocations`): a measurement owns a
//! tally, its thread works for it, and an allocation counts only when the thread
//! that makes it works for a measurement whose window is open. libtest starts,
//! reports and fails tests on threads of its own, and none of those works for a
//! measurement, so none can move a number. lwIP is process-global, so every test
//! holds the harness's lock for its whole body (`lwip_test_link`'s guard). The two
//! controls at the end pin both halves of the attribution.
//!
//! Host-test level: no board runs it, and no stack depth is measured here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(feature = "static-link-storage")]
use wz_link_lwip::ethernet::EthernetPool;
use wz_link_lwip::ethernet::{EthernetIf, EthernetMac, Ipv4Config};
#[cfg(not(feature = "static-link-storage"))]
use wz_link_lwip::rx_sockets::bind_session_rx;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::rx_sockets::{bind_session_rx_in, SessionRxPool};
use wz_link_lwip::rx_sockets::{SessionRxSocket, SESSION_RX_SLOTS, SESSION_RX_SLOT_SIZE};
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::UdpSocketPool;
use wz_link_lwip::{ipv4_addr_from_octets, ipv4_addr_loopback, LinkError, LwipLink, LwipUdpSocket};

/// Whether this build is the profile the link must not allocate on.
const FIXED: bool = cfg!(feature = "static-link-storage");

/// Counts the allocations of the measurement the allocating thread works for.
struct CountingAllocator;

/// One measurement's count: whether its window is open, and what its threads
/// allocated while it was.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
    bytes: AtomicUsize,
}

thread_local! {
    /// The measurement this thread works for, if any. `const` initialisation of a
    /// destructor-free type, so reading it from inside `alloc` cannot itself
    /// allocate.
    static OWNER: Cell<Option<&'static Tally>> = const { Cell::new(None) };
}

/// One allocation of `size` bytes, counted against the allocating thread's
/// measurement when that measurement's window is open.
fn count_one(size: usize) {
    if let Some(tally) = OWNER.with(Cell::get) {
        if tally.open.load(Ordering::SeqCst) {
            tally.allocations.fetch_add(1, Ordering::SeqCst);
            tally.bytes.fetch_add(size, Ordering::SeqCst);
        }
    }
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a read of
// a thread-local without a destructor and two atomic bumps, none of which allocates
// or unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one(layout.size());
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one(layout.size());
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one(new_size);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// What a window cost the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cost {
    allocations: usize,
    bytes: usize,
}

/// A measurement owned by the test thread that made it, with a tally of its own.
struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The tally
    /// is leaked, a few bytes per test, so a thread that outlives the measurement
    /// and still reads it never reads freed memory.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// Run `f` and return its result with what this measurement's threads
    /// allocated while it ran.
    fn count<R>(&self, f: impl FnOnce() -> R) -> (R, Cost) {
        let allocations = self.tally.allocations.load(Ordering::SeqCst);
        let bytes = self.tally.bytes.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        let out = f();
        self.tally.open.store(false, Ordering::SeqCst);
        let cost = Cost {
            allocations: self.tally.allocations.load(Ordering::SeqCst) - allocations,
            bytes: self.tally.bytes.load(Ordering::SeqCst) - bytes,
        };
        (out, cost)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
}

/// Judge a window against the profile it ran in: nothing at all on the fixed one,
/// and, on the default one, something (the control: the shape that boxes is seen
/// to box).
#[track_caller]
fn judge(what: &str, cost: Cost) {
    if FIXED {
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "{what}: the link must not touch the heap"
        );
    } else {
        assert!(
            cost.allocations > 0 && cost.bytes > 0,
            "{what}: CONTROL: the heap shape allocates, and the instrument must see it"
        );
    }
}

// ---- sockets ---------------------------------------------------------------

/// The narrow socket the loopback tests bind: 4 datagrams of 256 bytes.
type Small = LwipUdpSocket<256, 4>;

#[cfg(feature = "static-link-storage")]
static SMALL: UdpSocketPool<256, 4, 4> = UdpSocketPool::new();

/// A socket of the shape under test: out of a cell of `SMALL` on the fixed
/// profile, a heap box on the default one.
fn open_small(link: &LwipLink, port: u16) -> Result<Small, LinkError> {
    #[cfg(feature = "static-link-storage")]
    {
        Small::bind_in(link, port, &SMALL)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        Small::bind(link, port)
    }
}

/// The session socket the MCU opens, at the full size of its pool.
#[cfg(feature = "static-link-storage")]
static SESSIONS: SessionRxPool<2> = SessionRxPool::new();

fn open_session(link: &LwipLink, port: u16) -> Result<SessionRxSocket, LinkError> {
    #[cfg(feature = "static-link-storage")]
    {
        bind_session_rx_in(link, port, &SESSIONS)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        bind_session_rx(link, port)
    }
}

/// Send one datagram from `from` to port `to` on the loopback and pump lwIP until
/// it has arrived.
fn loop_back<const N: usize, const Q: usize>(
    link: &LwipLink,
    from: &LwipUdpSocket<N, Q>,
    to: u16,
    payload: &[u8],
) {
    from.send_to(ipv4_addr_loopback(), to, payload)
        .expect("send_to the loopback");
    link.poll_loopback();
    link.check_timeouts();
}

#[test]
fn two_sockets_are_bound_used_both_ways_and_dropped_without_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let m = Measurement::new();
    let payload: &[u8] = b"a datagram between two link sockets";

    let (seen, cost) = m.count(|| {
        let mut a = open_small(&link, 7701).expect("bind a");
        let mut b = open_small(&link, 7702).expect("bind b");

        // Owned receive: the datagram moves out of the queue.
        loop_back(&link, &a, 7702, payload);
        let owned = b.try_recv().expect("an owned receive");
        let owned_ok = owned.data.as_slice() == payload && owned.src_port == 7701;

        // Borrowed receive: read where the queue holds it, then give it back.
        loop_back(&link, &b, 7701, payload);
        let borrowed_ok = {
            let view = a.peek_recv().expect("a borrowed receive");
            view.data == payload && view.src_port == 7702
        };
        let consumed = a.consume_recv();
        let drops = a.rx_drop_count() + b.rx_drop_count();
        drop(a);
        drop(b);
        (owned_ok, borrowed_ok, consumed, drops)
    });
    assert_eq!(seen, (true, true, true, 0), "the datagrams arrived intact");
    judge("two sockets, bound, used both ways and dropped", cost);
}

#[test]
fn the_session_socket_is_bound_used_and_dropped_without_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let m = Measurement::new();
    let payload: &[u8] = b"a datagram through the session socket";

    let (seen, cost) = m.count(|| {
        let mut sock = open_session(&link, 7703).expect("bind the session socket");
        let port = sock.local_port();
        loop_back(&link, &sock, port, payload);
        let got = sock.try_recv().expect("the datagram");
        let ok = got.data.as_slice() == payload && sock.rx_drop_count() == 0;
        drop(sock);
        ok
    });
    assert!(seen, "the datagram arrived intact");
    judge("the session socket, bound, used and dropped", cost);
    // The state the measurement is about: one socket is its whole receive queue,
    // which is what a heap box held and a static cell now holds.
    assert!(
        std::mem::size_of::<SessionRxSocket>() <= 64,
        "the socket handle is a pointer, the state is behind it"
    );
    if !FIXED {
        assert!(
            cost.bytes >= SESSION_RX_SLOTS * SESSION_RX_SLOT_SIZE,
            "CONTROL: the box held at least the queue's {} bytes, saw {}",
            SESSION_RX_SLOTS * SESSION_RX_SLOT_SIZE,
            cost.bytes
        );
    }
}

// ---- the interface ---------------------------------------------------------

const NODE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
const NODE_IP: [u8; 4] = [10, 9, 0, 1];
const FAR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
const FAR_IP: [u8; 4] = [10, 9, 0, 2];

/// One Ethernet frame in a fixed buffer.
#[derive(Clone, Copy)]
struct Frame {
    bytes: [u8; 160],
    len: usize,
}

impl Frame {
    fn empty() -> Self {
        Self {
            bytes: [0; 160],
            len: 0,
        }
    }

    fn push(&mut self, more: &[u8]) {
        self.bytes[self.len..self.len + more.len()].copy_from_slice(more);
        self.len += more.len();
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The far host's ARP reply: `FAR_IP` is at `FAR_MAC`.
fn arp_reply() -> Frame {
    let mut f = Frame::empty();
    f.push(&NODE_MAC);
    f.push(&FAR_MAC);
    f.push(&[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]);
    f.push(&FAR_MAC);
    f.push(&FAR_IP);
    f.push(&NODE_MAC);
    f.push(&NODE_IP);
    f
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A UDP datagram from the far host, `FAR_IP:src` to `NODE_IP:dst`, with no UDP
/// checksum (zero, which IPv4 allows).
fn udp_frame(src: u16, dst: u16, payload: &[u8]) -> Frame {
    let udp_len = 8 + payload.len() as u16;
    let total = 20 + udp_len;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&FAR_IP);
    ip[16..20].copy_from_slice(&NODE_IP);
    let sum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut f = Frame::empty();
    f.push(&NODE_MAC);
    f.push(&FAR_MAC);
    f.push(&[0x08, 0x00]);
    f.push(&ip);
    f.push(&src.to_be_bytes());
    f.push(&dst.to_be_bytes());
    f.push(&udp_len.to_be_bytes());
    f.push(&[0, 0]);
    f.push(payload);
    f
}

/// The destination port and payload of an IPv4/UDP frame, if it is one.
fn udp_of(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.get(12..14)? != [0x08, 0x00] || *frame.get(23)? != 17 {
        return None;
    }
    let udp = 14 + usize::from(frame[14] & 0x0f) * 4;
    let dst = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    let len = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    Some((dst, frame.get(udp + 8..udp + len)?))
}

/// A MAC double made of arrays: it keeps the last frame it was asked to send and
/// holds one frame to hand in, so that nothing it does touches the heap and the
/// counts below are the link's alone.
struct ArrayMac {
    address: [u8; 6],
    arp_requests: usize,
    last_udp: Option<Frame>,
    inbox: Option<Frame>,
}

impl ArrayMac {
    fn new(address: [u8; 6]) -> Self {
        Self {
            address,
            arp_requests: 0,
            last_udp: None,
            inbox: None,
        }
    }
}

impl EthernetMac for ArrayMac {
    fn mac_address(&self) -> [u8; 6] {
        self.address
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        if frame.get(12..14) == Some(&[0x08, 0x06]) {
            // lwIP also announces the interface's own address when it comes up;
            // only the request that asks for the far host is the send's.
            if frame.get(38..42) == Some(&FAR_IP) {
                self.arp_requests += 1;
            }
        } else if udp_of(frame).is_some() && frame.len() <= 160 {
            let mut copy = Frame::empty();
            copy.push(frame);
            self.last_udp = Some(copy);
        }
        true
    }
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        let frame = self.inbox.take()?;
        buf[..frame.len].copy_from_slice(frame.as_slice());
        Some(frame.len)
    }
}

/// The interface under test: out of a cell of `ETHERNET` on the fixed profile, a
/// leaked box on the default one.
#[cfg(feature = "static-link-storage")]
static ETHERNET: EthernetPool<ArrayMac, 1> = EthernetPool::new();

fn node_config() -> Ipv4Config {
    Ipv4Config {
        address: NODE_IP,
        netmask: [255, 255, 255, 0],
        gateway: [0, 0, 0, 0],
    }
}

fn add_interface(
    link: &LwipLink,
) -> Result<EthernetIf<ArrayMac>, wz_link_lwip::ethernet::EthernetIfError> {
    #[cfg(feature = "static-link-storage")]
    {
        EthernetIf::add_in(link, ArrayMac::new(NODE_MAC), node_config(), &ETHERNET)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        EthernetIf::add(link, ArrayMac::new(NODE_MAC), node_config())
    }
}

#[test]
fn an_interface_is_added_and_carries_a_datagram_each_way_without_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let m = Measurement::new();
    let reply = arp_reply();
    let inbound = udp_frame(7601, 7704, b"in");
    let out_to = ipv4_addr_from_octets(FAR_IP);

    let (seen, cost) = m.count(|| {
        let mut node = add_interface(&link).expect("the interface");
        let mut socket = open_small(&link, 7704).expect("bind");

        // Out: the send asks who has FAR_IP, which the interface's MAC transmits.
        socket.send_to(out_to, 7601, b"out").expect("send");
        let arp_asked = node.with_mac(|mac| mac.arp_requests);

        // The reply is received into the interface's own frame buffer, and the
        // datagram that was waiting for it leaves.
        node.with_mac(|mac| mac.inbox = Some(reply));
        let taken_reply = node.poll();
        let left = node.with_mac(|mac| mac.last_udp);

        // In: a datagram from the far host reaches the bound socket.
        node.with_mac(|mac| mac.inbox = Some(inbound));
        let taken_in = node.poll();
        let got = socket.try_recv().expect("the datagram came in");
        let in_ok = got.data.as_slice() == b"in";
        drop(socket);
        (arp_asked, taken_reply, left, taken_in, in_ok)
    });
    let (arp_asked, taken_reply, left, taken_in, in_ok) = seen;
    assert_eq!(
        arp_asked, 1,
        "the send asked for the far host's address first"
    );
    assert_eq!(taken_reply, 1, "the reply was taken");
    let left = left.expect("the queued datagram left through the MAC");
    assert_eq!(udp_of(left.as_slice()), Some((7601, &b"out"[..])));
    assert_eq!(
        &left.as_slice()[0..6],
        &FAR_MAC,
        "to the MAC the reply named"
    );
    assert_eq!((taken_in, in_ok), (1, true), "and a datagram came in");
    judge(
        "an interface added, an ARP exchange, a datagram each way",
        cost,
    );
}

// ---- refusals (the fixed profile) ------------------------------------------

#[cfg(feature = "static-link-storage")]
mod refusals {
    use super::*;

    /// A socket pool filled to its capacity refuses the next bind, counted, and
    /// costs the heap nothing doing so; the cell of a dropped socket is found by the
    /// bind after it; and a bind lwIP itself refuses gives its cell back.
    #[test]
    fn a_full_socket_pool_refuses_counts_and_reuses_a_released_cell_without_the_heap() {
        static POOL: UdpSocketPool<64, 2, 3> = UdpSocketPool::new();
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let m = Measurement::new();
        type Tiny = LwipUdpSocket<64, 2>;

        let (held, cost) = m.count(|| {
            let a = Tiny::bind_in(&link, 7711, &POOL).expect("first cell");
            let b = Tiny::bind_in(&link, 7712, &POOL).expect("second cell");
            let c = Tiny::bind_in(&link, 7713, &POOL).expect("third cell");
            (a, b, c)
        });
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "filling the pool"
        );
        let (a, b, c) = held;
        assert_eq!((POOL.capacity(), POOL.in_use(), POOL.refusals()), (3, 3, 0));

        let (refused, cost) = m.count(|| Tiny::bind_in(&link, 7714, &POOL).err());
        assert_eq!(
            refused,
            Some(LinkError::SlotsExhausted),
            "the fourth bind finds no cell"
        );
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "and the refusal costs nothing"
        );
        assert_eq!(POOL.refusals(), 1, "it is counted");
        assert_eq!(POOL.in_use(), 3, "and it took nothing from the pool");

        // The refusal did not bind the port: nothing holds 7714.
        drop(b);
        assert_eq!(POOL.in_use(), 2, "a dropped socket frees its cell");
        let (again, cost) = m.count(|| Tiny::bind_in(&link, 7714, &POOL));
        let again = again.expect("the freed cell is found");
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "reusing it costs nothing"
        );
        assert_eq!(POOL.refusals(), 1, "a bind that succeeds is not a refusal");

        // lwIP refuses a port that is in use; the claimed cell goes back.
        let (taken, cost) = m.count(|| Tiny::bind_in(&link, 7711, &POOL).err());
        assert_eq!(
            taken,
            Some(LinkError::SlotsExhausted),
            "every cell is held, so this is the pool's refusal and not lwIP's"
        );
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            }
        );
        drop(c);
        let (in_use, cost) = m.count(|| Tiny::bind_in(&link, 7711, &POOL).err());
        assert!(
            matches!(in_use, Some(LinkError::BindFailed(_))),
            "with a cell free, a port in use is lwIP's refusal"
        );
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            }
        );
        assert_eq!(
            POOL.in_use(),
            2,
            "and the cell that bind claimed went back: only a and the reused one are held"
        );
        assert_eq!(POOL.refusals(), 2, "the second pool refusal is counted too");
        drop((a, again));
        assert_eq!(POOL.in_use(), 0);
    }

    /// The session socket's own pool: two cells of 24.7 KB, the third bind refused.
    #[test]
    fn the_session_pool_refuses_its_third_socket_and_counts_it() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let m = Measurement::new();
        let before = SESSIONS.refusals();
        let (held, cost) = m.count(|| {
            let a = bind_session_rx_in(&link, 7721, &SESSIONS).expect("first");
            let b = bind_session_rx_in(&link, 7722, &SESSIONS).expect("second");
            (a, b)
        });
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            }
        );
        let (refused, cost) = m.count(|| bind_session_rx_in(&link, 7723, &SESSIONS).err());
        assert_eq!(refused, Some(LinkError::SlotsExhausted));
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            }
        );
        assert_eq!(SESSIONS.refusals(), before + 1);
        drop(held);
        assert_eq!(SESSIONS.in_use(), 0);
    }

    /// An interface pool filled to its capacity refuses the next addition, counted,
    /// without the heap; and an interface is never removed, so dropping its handle
    /// does not give its cell back.
    #[test]
    fn a_full_interface_pool_refuses_counts_and_never_gets_a_cell_back() {
        static POOL: EthernetPool<ArrayMac, 1> = EthernetPool::new();
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let m = Measurement::new();

        let (first, cost) =
            m.count(|| EthernetIf::add_in(&link, ArrayMac::new(NODE_MAC), node_config(), &POOL));
        let first = first.expect("the one cell");
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "adding it"
        );
        assert_eq!((POOL.capacity(), POOL.in_use(), POOL.refusals()), (1, 1, 0));

        let (refused, cost) = m.count(|| {
            EthernetIf::add_in(&link, ArrayMac::new(FAR_MAC), node_config(), &POOL).err()
        });
        assert_eq!(
            refused,
            Some(wz_link_lwip::ethernet::EthernetIfError::NoStorage),
            "the second interface finds no cell"
        );
        assert_eq!(
            cost,
            Cost {
                allocations: 0,
                bytes: 0
            },
            "and the refusal costs nothing"
        );
        assert_eq!(POOL.refusals(), 1, "it is counted");

        {
            // The handle goes out of scope here; lwIP keeps the interface regardless.
            let _gone = first;
        }
        assert_eq!(
            POOL.in_use(),
            1,
            "lwIP keeps the interface for the life of the program, so its cell stays taken"
        );
    }
}

// ---- the instrument's own controls ------------------------------------------

/// A window counts what its own thread allocates, so a zero above is a statement
/// about the link and not about a window that cannot see.
#[test]
fn control_a_box_inside_the_window_is_counted() {
    let m = Measurement::new();
    let (_, cost) = m.count(|| std::hint::black_box(Box::new([0u8; 100])));
    assert_eq!(cost.allocations, 1);
    assert!(cost.bytes >= 100);
}

/// And it counts nothing another thread allocates, which is what lets libtest run
/// its own threads beside a measurement.
#[test]
fn control_another_threads_allocation_is_not_counted() {
    static GO: AtomicBool = AtomicBool::new(false);
    let m = Measurement::new();
    // The thread is started before the window, so spawning it (which allocates on
    // THIS thread) is not what is measured; it allocates once the window is open.
    let other = std::thread::spawn(|| {
        while !GO.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::hint::black_box(Box::new([0u8; 100]));
    });
    let (_, cost) = m.count(|| {
        GO.store(true, Ordering::SeqCst);
        other.join().expect("the other thread")
    });
    assert_eq!(
        cost,
        Cost {
            allocations: 0,
            bytes: 0
        }
    );
}
