// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE MEMORY MATRIX of the two-pass dissection (open-debt item 924, step 5,
//! `docs/dissect-row-index.md`, D7): what a dissection holds per row, for every
//! kind of message list it has.
//!
//! The C ABI's gate (`wz-capi-dissect`'s `handle_memory_gate`) reads one shape of
//! capture, a session of pushes over TCP and over UDP. A dissection keeps its
//! rows in six different places (a stream's assembled bytes, a datagram log, a
//! serial line's frames, a WebSocket flow's unmasked payloads, a TLS flow's
//! plaintext, a scouting list, the plaintext a layer below recovered), and a
//! gate that reads two of them vouches for two. This reads all of them, against
//! the structure that owns each, and says so when it does not.
//!
//! # What each case claims
//!
//! A capture of `N` rows and one of `2N` are read, and for each:
//!
//! * the bytes the allocator counted per row, between the two, are held to a
//!   ceiling that is the measured value plus 10%;
//! * the bytes `Dissection::memory` reports adding, between the two, are the bytes
//!   the allocator counted adding, to the byte. Nothing in the report is a model
//!   (a buffer is its capacity times its element, and an ordered map is a
//!   [`wz_session_core::sorted_chunks::SortedChunks`], whose chunks are buffers),
//!   so a difference of one byte is a structure that grows with the rows and that
//!   the report leaves out, and this is where it shows for the kind that has it.
//!   The failure says which allocation sizes grew, and which shrank, so the
//!   structure is named and not hunted for;
//! * the dissection gives back every byte when it is dropped;
//! * the capture produced rows of the kind the case is for, so a builder that
//!   stopped producing them cannot pass with nothing measured.
//!
//! The slope between two sizes is what is read, and not the total, so what is
//! fixed (the flow table, the first chunk of a log) is not charged to a row.
//!
//! # The size of a unit
//!
//! The cases hold a row's unit at four bytes, where the row's own entry is most of
//! its cost and a copy of the unit hardly shows. [`what_a_row_costs_does_not_follow_the_size_of_its_unit`]
//! reads UDP, TCP and WebSocket at units of 16, 256 and 4096 bytes: the report
//! still equals the allocator, a row on the lent door of a kind that reads its
//! units where they are costs the same at every size, and the handed door holds
//! one copy of the unit and no more than the kind's structure is built to hold (a
//! log of chunks, a chunk's tail over). A TCP stream's kept bytes were one
//! growable buffer, which held 1.4 times its bytes at 4096-byte units and up to
//! twice in general; they are a log of chunks now. A WebSocket message that is one
//! frame is the stream's own bytes (under the four-byte key before them, for a
//! masked frame, which is every one a client sends) and costs nothing beyond it;
//! one joined out of fragments stands nowhere in the stream and is logged, which
//! the capture the redecode gate reads carries and this sweep does not.
//!
//! # The population is derived
//!
//! [`kinds_of`] is an exhaustive `match` over `MessageListOrigin`, with no wildcard,
//! so a kind of list added to the type does not compile until a case names it. The
//! scouting list is the one kind that is not a `MessageListOrigin` (it is a field of
//! a datagram flow), so it is named here by hand, and the test that lists the
//! cases fails if either side names a case the table does not have.
//!
//! # Where it runs
//!
//! `cargo test -p wz-capture --features dissect,fixtures`. The fragment-chain cases
//! need the `fixtures` feature for their captures and are absent without it, which
//! is said in the case list and not left to be noticed.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::passive::Direction;

use crate::datagram_tests::{
    frame_carrying, framed_frame, framed_frame_with_payload, hello_with_locators, init_datagram,
    open_datagram, push, scout_message, sender_space, tcp_packet_on, tcp_packet_reverse,
    udp_packet, SCOUT_GROUP,
};
use crate::redecode_gate::PlainOpener;
use crate::{Dissection, MessageListOrigin};

std::thread_local! {
    /// Bytes this thread has allocated and not yet freed. `const`-initialised, so
    /// reading it never allocates.
    static OUTSTANDING: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the counter
// only observes the sizes.
/// Allocation sizes told apart by the count of live allocations of each. Sizes
/// below [`EXACT`] are told apart exactly, and each size from there up stands for
/// the sixteenth of a power of two it is in, so a buffer that doubled shows as a
/// size of its own and a buffer of a few tens of thousands of bytes is told from
/// one a few percent longer.
const EXACT: usize = 4096;
/// The slots of one power of two from [`EXACT`] up.
const PER_OCTAVE: usize = 16;
const SIZES: usize = EXACT + PER_OCTAVE * 40;

/// The slot a size is counted in.
fn slot_of(size: usize) -> usize {
    if size < EXACT {
        size
    } else {
        let octave = size.ilog2() as usize;
        let sub = (size >> (octave - PER_OCTAVE.ilog2() as usize)) - PER_OCTAVE;
        EXACT + (octave - EXACT.ilog2() as usize) * PER_OCTAVE + sub
    }
}

/// The smallest size a slot counts.
fn slot_low(slot: usize) -> usize {
    if slot < EXACT {
        slot
    } else {
        let octave = (slot - EXACT) / PER_OCTAVE + EXACT.ilog2() as usize;
        let sub = (slot - EXACT) % PER_OCTAVE;
        (PER_OCTAVE + sub) << (octave - PER_OCTAVE.ilog2() as usize)
    }
}

/// What a slot stands for, for a message: a size, or the range of a sixteenth of
/// a power of two.
fn slot_name(slot: usize) -> alloc::string::String {
    if slot < EXACT {
        alloc::format!("{slot} B")
    } else {
        alloc::format!("{}..{} B", slot_low(slot), slot_low(slot + 1))
    }
}

std::thread_local! {
    /// Live allocations by exact size. The matrix reads it to say WHICH sizes grew
    /// when a case fails: an unreported structure shows up as a size that has
    /// thousands more live allocations in the larger capture, and the size names the
    /// structure (a B-tree leaf of this map, a record's ciphertext of this length).
    /// `const`-initialised, so reading it never allocates.
    static LIVE: [Cell<i64>; SIZES] = const { [const { Cell::new(0) }; SIZES] };
}

fn live_add(size: usize, by: i64) {
    let _ = LIVE.try_with(|live| {
        let at = slot_of(size).min(SIZES - 1);
        live[at].set(live[at].get() + by);
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() + layout.size() as isize));
        live_add(layout.size(), 1);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() - layout.size() as isize));
        live_add(layout.size(), -1);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ =
            OUTSTANDING.try_with(|c| c.set(c.get() + new_size as isize - layout.size() as isize));
        live_add(layout.size(), -1);
        live_add(new_size, 1);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// The live allocations by size now, copied to the stack: a copy on the heap would
/// be counted as what a dissection holds.
fn live_now() -> [i64; SIZES] {
    LIVE.with(|live| core::array::from_fn(|at| live[at].get()))
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn outstanding() -> isize {
    OUTSTANDING.with(Cell::get)
}

/// A way to make a dissection, whose inputs were made before it is called, so that
/// what the allocator counts across the call is the dissection and not its input.
type Run = Box<dyn Fn() -> Dissection>;

const LINKTYPE_ETHERNET: u32 = 1;
const SERIAL_LINKTYPE: u32 = 250;

/// How much of a capture is a case at its smaller size; the larger is twice it.
const UNITS: usize = 3_000;

fn pcap_of(packets: &[Vec<u8>]) -> Vec<u8> {
    let rows: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (i as u32, 0, p.as_slice()))
        .collect();
    crate::pcap::write(LINKTYPE_ETHERNET, &rows)
}

/// A capture file read through the door a consumer opens it by: handed to the
/// dissection, which copies what it keeps, or lent, which keeps where it is.
fn file_run(file: Vec<u8>, lent: bool, serial: &'static [u32]) -> Run {
    if lent {
        let container: Arc<dyn crate::LentCapture> = Arc::new(file);
        Box::new(move || {
            let mut d = Dissection::new();
            d.declared_serial_linktypes = serial.to_vec();
            d.follow_lent(&mut crate::CaptureCursor::new(), container.clone())
                .expect("the lent capture reads");
            d.finish();
            d
        })
    } else {
        Box::new(move || {
            Dissection::from_capture_declaring(&file, &[], serial).expect("the capture reads")
        })
    }
}

/// A transport message behind the two-byte length a stream link puts before it.
fn prefixed(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(wire);
    out
}

fn sn(k: usize) -> u8 {
    (k % 0x80) as u8
}

/// The row's unit, length-prefixed as a stream link frames it: the fixture's Frame,
/// or, when `payload` is given, a Frame carrying that many bytes after its header.
fn unit_of(k: usize, payload: Option<usize>) -> Vec<u8> {
    match payload {
        None => framed_frame(sn(k)),
        Some(len) => framed_frame_with_payload(sn(k), len, k as u32 + 1),
    }
}

fn udp(n: usize, lent: bool) -> Run {
    udp_of(n, lent, None)
}

fn udp_of(n: usize, lent: bool, payload: Option<usize>) -> Run {
    let datagram = |wire: &[u8], from_low: bool| {
        if from_low {
            udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire)
        } else {
            udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, wire)
        }
    };
    let mut packets = alloc::vec![
        datagram(&init_datagram(false, &[]), true),
        datagram(&init_datagram(true, &[]), false),
        datagram(&open_datagram(false), true),
        datagram(&open_datagram(true), false),
    ];
    for k in 0..n {
        packets.push(datagram(&unit_of(k, payload)[2..], true));
    }
    file_run(pcap_of(&packets), lent, &[])
}

fn tcp(n: usize, lent: bool) -> Run {
    tcp_of(n, lent, None)
}

fn tcp_of(n: usize, lent: bool, payload: Option<usize>) -> Run {
    let (mut low, mut high) = (1_000u32, 9_000u32);
    let mut packets = Vec::new();
    for wire in [init_datagram(false, &[]), open_datagram(false)] {
        let unit = prefixed(&wire);
        packets.push(tcp_packet_on(1111, low, &unit));
        low += unit.len() as u32;
    }
    for wire in [init_datagram(true, &[]), open_datagram(true)] {
        let unit = prefixed(&wire);
        packets.push(tcp_packet_reverse(high, &unit));
        high += unit.len() as u32;
    }
    for k in 0..n {
        let unit = unit_of(k, payload);
        packets.push(tcp_packet_on(1111, low, &unit));
        low += unit.len() as u32;
    }
    file_run(pcap_of(&packets), lent, &[])
}

fn serial(n: usize, lent: bool) -> Run {
    use wz_session_core::serial_link::{encode_frame, SERIAL_FLAG_ACK, SERIAL_FLAG_INIT};
    let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    let init_a = crate::node::tests::init_wire(&[0x11, 0x22, 0x33, 0x44]);
    let init_b = crate::node::tests::init_wire(&[0x55, 0x66, 0x77, 0x88]);
    let mut frames: Vec<(u32, Vec<u8>)> = alloc::vec![
        (0, encode_frame(SERIAL_FLAG_INIT, &[]).expect("encodes")),
        (
            1,
            encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes")
        ),
        (0, encode_frame(0, &init_a).expect("encodes")),
        (1, encode_frame(0, &init_b).expect("encodes")),
    ];
    for k in 0..n {
        let mut payload: Vec<u8> = keepalive.repeat(k % 3);
        payload.extend_from_slice(&frame_carrying(&push(
            sender_space(0, Some("home/temp")),
            &[k as u8; 9],
        )));
        frames.push(((k % 2) as u32, encode_frame(0, &payload).expect("encodes")));
    }
    let packets: Vec<(u32, u64, &[u8])> = frames
        .iter()
        .enumerate()
        .map(|(i, (iface, bytes))| (*iface, 1_000_000 + i as u64 * 100, bytes.as_slice()))
        .collect();
    let file = crate::pcapng::write(&[(SERIAL_LINKTYPE, 6), (SERIAL_LINKTYPE, 6)], &packets);
    file_run(file, lent, &[SERIAL_LINKTYPE])
}

fn websocket(n: usize, lent: bool) -> Run {
    websocket_of(n, lent, None)
}

fn websocket_of(n: usize, lent: bool, payload: Option<usize>) -> Run {
    websocket_with(n, lent, payload, None)
}

/// The same flow with every message's frame masked, as a client sends it: the
/// payload on the wire is XORed, so it stands nowhere in the stream.
fn websocket_masked_of(n: usize, lent: bool, payload: Option<usize>) -> Run {
    websocket_with(n, lent, payload, Some([0x37, 0xFA, 0x21, 0x3D]))
}

fn websocket_with(n: usize, lent: bool, payload: Option<usize>, mask: Option<[u8; 4]>) -> Run {
    use crate::ws::tests::frame;
    let unframed = |framed: Vec<u8>| framed[2..].to_vec();
    let upgrade = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n".to_vec();
    let switching = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec();
    let mut packets = alloc::vec![
        tcp_packet_on(1111, 1_000, &upgrade),
        tcp_packet_reverse(9_000, &switching),
    ];
    let (mut low, mut high) = (1_000 + upgrade.len() as u32, 9_000 + switching.len() as u32);
    for wire in [init_datagram(false, &[]), open_datagram(false)] {
        let f = frame(true, 0x2, &wire, None);
        packets.push(tcp_packet_on(1111, low, &f));
        low += f.len() as u32;
    }
    for wire in [init_datagram(true, &[]), open_datagram(true)] {
        let f = frame(true, 0x2, &wire, None);
        packets.push(tcp_packet_reverse(high, &f));
        high += f.len() as u32;
    }
    for k in 0..n {
        let f = frame(true, 0x2, &unframed(unit_of(k, payload)), mask);
        packets.push(tcp_packet_on(1111, low, &f));
        low += f.len() as u32;
    }
    file_run(pcap_of(&packets), lent, &[])
}

fn scouting(n: usize, lent: bool) -> Run {
    let asker = [192, 168, 1, 5];
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for k in 0..n {
        packets.push(match k % 3 {
            0 => udp_packet(asker, 43210, SCOUT_GROUP, 7446, &scout_message()),
            1 => udp_packet([192, 168, 1, 9], 7447, asker, 43210, &hello_with_locators()),
            _ => {
                let mut p = scout_message();
                p.push(0xEE);
                udp_packet(asker, 43210, SCOUT_GROUP, 7446, &p)
            }
        });
    }
    file_run(pcap_of(&packets), lent, &[])
}

fn tls(n: usize, _lent: bool) -> Run {
    use crate::datagram_tests::framed_keepalive;
    let record = |content_type: u8, payload: &[u8]| {
        let mut out = alloc::vec![content_type, 0x03, 0x03];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    };
    let hello = {
        let mut body = alloc::vec![0x03u8, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.resize(0x30, 0);
        let mut handshake = alloc::vec![0x01u8, 0x00, 0x00, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut out = alloc::vec![0x16u8, 0x03, 0x01];
        out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        out.extend_from_slice(&handshake);
        out
    };
    let stream_of = |seed: usize| -> Vec<u8> {
        let mut stream = Vec::new();
        for k in 0..n {
            let s = ((seed + k) % 0x80) as u8;
            let unit = match k % 3 {
                0 => framed_keepalive()[2..].to_vec(),
                1 => framed_frame(s)[2..].to_vec(),
                _ => {
                    let mut batch = framed_keepalive()[2..].to_vec();
                    batch.extend_from_slice(&framed_frame(s)[2..]);
                    batch
                }
            };
            stream.extend_from_slice(&(unit.len() as u16).to_le_bytes());
            stream.extend_from_slice(&unit);
        }
        stream
    };
    let records_of = |stream: &[u8]| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let (mut at, mut k) = (0usize, 0usize);
        while at < stream.len() {
            let end = (at + [5, 13, 3, 21][k % 4]).min(stream.len());
            let mut inner = alloc::vec![crate::tls::CT_APPLICATION_DATA];
            inner.extend_from_slice(&stream[at..end]);
            out.push(record(0x17, &inner));
            (at, k) = (end, k + 1);
        }
        out
    };
    let (low, high) = (records_of(&stream_of(1)), records_of(&stream_of(60)));
    let mut packets: Vec<Vec<u8>> = alloc::vec![tcp_packet_on(1111, 1_000, &hello)];
    let (mut seq_low, mut seq_high) = (1_000 + hello.len() as u32, 9_000u32);
    for i in 0..low.len().max(high.len()) {
        if let Some(r) = low.get(i) {
            packets.push(tcp_packet_on(1111, seq_low, r));
            seq_low += r.len() as u32;
        }
        if let Some(r) = high.get(i) {
            packets.push(tcp_packet_reverse(seq_high, r));
            seq_high += r.len() as u32;
        }
    }
    Box::new(move || {
        let mut d = Dissection::new();
        for (i, packet) in packets.iter().enumerate() {
            d.push_packet(LINKTYPE_ETHERNET, i, packet);
        }
        let summary = d.decrypt_with(&mut PlainOpener);
        assert_eq!(summary.decrypted, 1, "the flow opens");
        d.finish();
        d
    })
}

fn quic_datagrams(n: usize, _lent: bool) -> Run {
    let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    let opening = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &keepalive);
    let plaintexts: Vec<Vec<u8>> = (0..n)
        .map(|k| {
            let mut unit: Vec<u8> = keepalive.repeat(k % 3);
            unit.extend_from_slice(&frame_carrying(&push(
                sender_space(0, Some("quic/dg")),
                &[k as u8; 7],
            )));
            unit
        })
        .collect();
    Box::new(move || {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &opening);
        let flow = d.datagram_flows()[0].flow;
        for (k, plaintext) in plaintexts.iter().enumerate() {
            let direction = if k % 4 == 3 {
                Direction::B
            } else {
                Direction::A
            };
            d.feed_quic_datagram(flow, direction, k + 1, plaintext);
        }
        d.finish();
        d
    })
}

fn quic_stream(n: usize, _lent: bool) -> Run {
    let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    let stream_of = |seed: u8| -> Vec<u8> {
        let mut stream = Vec::new();
        for k in 0..n {
            let mut body: Vec<u8> = keepalive.repeat(k % 3);
            body.extend_from_slice(&frame_carrying(&push(
                sender_space(0, Some("quic/stream")),
                &[seed ^ k as u8; 11],
            )));
            stream.extend_from_slice(&(body.len() as u16).to_le_bytes());
            stream.extend_from_slice(&body);
        }
        stream
    };
    let streams = [stream_of(0x10), stream_of(0x80)];
    let opening = udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &keepalive);
    Box::new(move || {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &opening);
        let flow = d.datagram_flows()[0].flow;
        let mut at = [0usize; 2];
        while at[0] < streams[0].len() || at[1] < streams[1].len() {
            for (seat, direction) in [Direction::A, Direction::B].into_iter().enumerate() {
                let end = (at[seat] + 1_400).min(streams[seat].len());
                if at[seat] < end {
                    d.feed_quic_stream(flow, direction, 4, false, &streams[seat][at[seat]..end]);
                    at[seat] = end;
                }
            }
        }
        d.finish();
        d
    })
}

#[cfg(feature = "fixtures")]
fn udp_chains(n: usize, lent: bool) -> Run {
    file_run(crate::fixtures::chain_sequence_capture(n / 2), lent, &[])
}

#[cfg(feature = "fixtures")]
fn tcp_chains(n: usize, lent: bool) -> Run {
    file_run(
        crate::fixtures::stream_chain_sequence_capture(n / 2),
        lent,
        &[],
    )
}

/// What a case's capture must have produced for the figures to be about its kind.
#[derive(Clone, Copy)]
enum Expect {
    /// A message list of this origin that holds rows.
    List(fn(&MessageListOrigin) -> bool),
    /// A datagram flow whose scouting list holds rows.
    Scouting,
}

impl Expect {
    fn met(self, d: &Dissection) -> bool {
        match self {
            Expect::List(is) => d
                .message_lists_with_origin()
                .any(|(_, origin, rows)| is(&origin) && !rows.is_empty()),
            Expect::Scouting => d.datagram_flows().iter().any(|f| !f.scouting().is_empty()),
        }
    }
}

/// One kind of list, how to make a capture of it, and what it is held to.
struct Case {
    name: &'static str,
    build: fn(usize, bool) -> Run,
    /// Whether the lent door is a different door for this kind. A recovered
    /// plaintext and a decrypted flow are in no container.
    lendable: bool,
    expect: Expect,
    /// Bytes per row the handed dissection may hold: the measured value plus 10%,
    /// rounded up to a whole byte. A ceiling that moved is a decision to be
    /// recorded where the measured value is, not a number to raise until the case
    /// passes.
    ceiling: f64,
    /// The same, lent. Equal to `ceiling` where the lent door changes nothing for
    /// this kind (a serial line logs a copy either way).
    ceiling_lent: f64,
}

fn is_stream(o: &MessageListOrigin) -> bool {
    matches!(o, MessageListOrigin::Stream)
}

/// The measured bytes per row of each kind, handed and lent, on the fixtures
/// above at `UNITS` and twice that (the allocator's figure, which the report
/// equals):
///
/// | kind                | handed | lent   | what its rows are                    |
/// |---------------------|--------|--------|--------------------------------------|
/// | udp                 |  60.1  |  49.2  | one Push a datagram                  |
/// | tcp                 | 101.1  |  90.2  | one Frame a segment                  |
/// | serial              |  68.4  |  68.4  | batches of one to three              |
/// | websocket           | 150.3  | 139.4  | one message a frame                  |
/// | tls                 | 121.9  | (none) | records of 9 to 27 bytes             |
/// | scouting            |  57.3  |  41.0  | a SCOUT, a HELLO, a SCOUT with tail  |
/// | quic datagram       |  60.1  | (none) | recovered plaintext                  |
/// | quic stream         |  79.1  | (none) | recovered plaintext                  |
/// | udp fragment chains | 134.9  | 113.0  | two fragments a chain                |
/// | tcp fragment chains | 175.9  | 154.0  | two fragments a chain                |
///
/// The handshake is a fixed cost and is not in a slope. Each of these includes the
/// SN verdict class a row carries in its flags: before that class, a capture that
/// began after the handshake (so no ring to measure a step against) kept every row's
/// verdict in a map, and udp read 241 and tcp 284.
///
/// A fragment row costs about 78 bytes beyond a plain row: its fate (a class in a
/// log, and the joined message in another where its chain completed) and the chain
/// it belongs to (outcome and identity, in a log of its own). It read 322 and 366
/// when those were three B-tree maps (an 88-byte slot holding a fate that owned a
/// buffer, and a node's header around every entry), and reads 135 and 179 as logs
/// that keep their keys in order and drop their front a chunk at a time. What is
/// left of it is per FRAGMENT, and a fragment exists because its message did not
/// fit a batch, so on a real capture it is amortised over a row of hundreds to
/// thousands of bytes; the fixture's are twelve.
fn cases() -> Vec<Case> {
    let mut cases = alloc::vec![
        Case {
            name: "udp",
            build: udp,
            lendable: true,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::Datagram)),
            ceiling: 67.0,
            ceiling_lent: 55.0,
        },
        Case {
            name: "tcp",
            build: tcp,
            lendable: true,
            expect: Expect::List(is_stream),
            ceiling: 112.0,
            ceiling_lent: 100.0,
        },
        Case {
            name: "serial",
            build: serial,
            lendable: true,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::Serial)),
            ceiling: 76.0,
            ceiling_lent: 76.0,
        },
        Case {
            name: "websocket",
            build: websocket,
            lendable: true,
            expect: Expect::List(is_stream),
            ceiling: 166.0,
            ceiling_lent: 154.0,
        },
        Case {
            name: "tls",
            build: tls,
            lendable: false,
            expect: Expect::List(is_stream),
            ceiling: 135.0,
            ceiling_lent: 135.0,
        },
        Case {
            name: "scouting",
            build: scouting,
            lendable: true,
            expect: Expect::Scouting,
            ceiling: 64.0,
            ceiling_lent: 46.0,
        },
        Case {
            name: "quic datagram",
            build: quic_datagrams,
            lendable: false,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::QuicDatagram)),
            ceiling: 67.0,
            ceiling_lent: 67.0,
        },
        Case {
            name: "quic stream",
            build: quic_stream,
            lendable: false,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::QuicStream(_))),
            ceiling: 88.0,
            ceiling_lent: 88.0,
        },
    ];
    #[cfg(feature = "fixtures")]
    cases.extend([
        Case {
            name: "udp fragment chains",
            build: udp_chains,
            lendable: true,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::Datagram)),
            ceiling: 152.0,
            ceiling_lent: 128.0,
        },
        Case {
            name: "tcp fragment chains",
            build: tcp_chains,
            lendable: true,
            expect: Expect::List(is_stream),
            ceiling: 194.0,
            ceiling_lent: 173.0,
        },
    ]);
    cases
}

/// The cases that cover each kind of list the type names. Exhaustive, with no
/// wildcard: a kind added to [`MessageListOrigin`] does not compile until it is
/// given a case here.
fn kinds_of(origin: MessageListOrigin) -> &'static [&'static str] {
    match origin {
        MessageListOrigin::Stream => &["tcp", "websocket", "tls"],
        MessageListOrigin::Datagram => &["udp"],
        MessageListOrigin::QuicStream(_) => &["quic stream"],
        MessageListOrigin::QuicDatagram => &["quic datagram"],
        MessageListOrigin::Serial => &["serial"],
    }
}

/// The kinds of list that are not a [`MessageListOrigin`], named by hand because
/// the type that holds them (a field of a datagram flow) cannot be matched on.
const OTHER_KINDS: &[&str] = &["scouting"];

fn rows_of(d: &Dissection) -> usize {
    d.message_lists_with_origin()
        .map(|(_, _, rows)| rows.len())
        .sum::<usize>()
        + d.datagram_flows()
            .iter()
            .map(|f| f.scouting().len())
            .sum::<usize>()
}

/// What one run of a case found.
struct Sample {
    rows: usize,
    held: isize,
    reported: usize,
    leaked: isize,
    populated: bool,
    /// The report itself, which holds no allocation: formatted only when a case
    /// fails, because a string made here would be counted as left behind.
    memory: crate::DissectionMemory,
    /// Live allocations by size that the dissection added, for the failure message.
    by_size: [i64; SIZES],
}

fn sample(run: &Run, expect: Expect) -> Sample {
    let base = outstanding();
    let before = live_now();
    let d = run();
    let held = outstanding() - base;
    let after = live_now();
    let memory = d.memory();
    let sample = Sample {
        rows: rows_of(&d),
        held,
        reported: memory.total(),
        leaked: 0,
        populated: expect.met(&d),
        memory,
        by_size: core::array::from_fn(|at| after[at] - before[at]),
    };
    drop(d);
    Sample {
        leaked: outstanding() - base,
        ..sample
    }
}

/// The allocation sizes that grew between the two captures, most bytes first: what
/// a failure prints so that "a structure is unreported" says which one. A node of
/// a map is a size of its own, and so is a record's copy of its bytes.
fn growth_by_size(small: &Sample, large: &Sample) -> alloc::string::String {
    let mut grown: Vec<(usize, i64)> = (0..SIZES)
        .map(|size| (size, large.by_size[size] - small.by_size[size]))
        .filter(|(_, count)| *count != 0)
        .collect();
    // A slot's bytes: its size, or the low end of its range, times the count.
    grown.sort_by_key(|(slot, count)| -(slot_low(*slot) as i64 * count.abs()));
    let top: Vec<alloc::string::String> = grown
        .iter()
        .map(|(slot, count)| alloc::format!("{count} of {}", slot_name(*slot)))
        .collect();
    alloc::format!(
        "the live allocations that grew between the two captures, most bytes first \
         (from {EXACT} B up, a sixteenth of a power of two is one size): {}",
        top.join(", ")
    )
}

/// Bytes per row between a capture of `UNITS` rows and one of twice that, for the
/// allocator and for the report.
fn slopes(small: &Sample, large: &Sample) -> (f64, f64) {
    let rows = (large.rows - small.rows) as f64;
    (
        (large.held - small.held) as f64 / rows,
        (large.reported as f64 - small.reported as f64) / rows,
    )
}

fn check(
    name: &str,
    door: &str,
    expect: Expect,
    ceiling: f64,
    build: fn(usize, bool) -> Run,
) -> Vec<alloc::string::String> {
    let mut findings: Vec<alloc::string::String> = Vec::new();
    let lent = door == "lent";
    // One run before the two that are read, dropped: what a first use of the
    // library makes once and keeps (a table built on demand) is not what a
    // dissection holds, and a leak a dissection makes would still show in both
    // that follow.
    drop(build(UNITS / 10, lent)());
    let (small, large) = (
        sample(&build(UNITS, lent), expect),
        sample(&build(2 * UNITS, lent), expect),
    );
    assert!(
        small.populated && large.populated,
        "{name} ({door}): the capture produced no rows of this kind"
    );
    assert!(
        large.rows > small.rows + UNITS / 2,
        "{name} ({door}): {} rows then {}: the capture did not grow with the count",
        small.rows,
        large.rows
    );
    assert_eq!(small.leaked, 0, "{name} ({door}): bytes left after a drop");
    assert_eq!(large.leaked, 0, "{name} ({door}): bytes left after a drop");
    let (allocated, reported) = slopes(&small, &large);
    std::eprintln!(
        "{name} ({door}): {} then {} rows; allocator {allocated:.2} B/row, report {reported:.2} B/row",
        small.rows,
        large.rows
    );
    if allocated > ceiling {
        findings.push(alloc::format!(
            "{name} ({door}): {allocated:.2} B per row, over the ceiling of {ceiling}. It \
             reports {:?}; {}",
            large.memory,
            growth_by_size(&small, &large)
        ));
    }
    // EXACT: the bytes the dissection added going from the smaller capture to the
    // larger are the bytes it reports adding, to the byte. Nothing in the report is a
    // model, so a difference is a structure that grows with the rows and is not
    // counted, and the allocation sizes that grew say which.
    let added = large.held - small.held;
    let reported_added = large.reported as isize - small.reported as isize;
    if added != reported_added {
        findings.push(alloc::format!(
            "{name} ({door}): the dissection added {added} bytes ({allocated:.2} B per row) \
             and reports {reported_added} ({reported:.2}): {} bytes are held and not counted. \
             It reports {:?} for the smaller capture and {:?} for the larger; {}",
            added - reported_added,
            small.memory,
            large.memory,
            growth_by_size(&small, &large)
        ));
    }
    findings
}

/// Every kind of list a dissection has is a case, and every case is a kind.
#[test]
fn every_kind_of_list_has_a_case_and_every_case_a_kind() {
    let names: Vec<&str> = cases().iter().map(|c| c.name).collect();
    let mut named: Vec<&str> = Vec::new();
    for origin in [
        MessageListOrigin::Stream,
        MessageListOrigin::Datagram,
        MessageListOrigin::QuicStream(0),
        MessageListOrigin::QuicDatagram,
        MessageListOrigin::Serial,
    ] {
        named.extend_from_slice(kinds_of(origin));
    }
    named.extend_from_slice(OTHER_KINDS);
    for kind in &named {
        assert!(names.contains(kind), "no case for the kind of list {kind}");
    }
    for case in &names {
        assert!(
            named.contains(case) || case.ends_with("fragment chains"),
            "the case {case} is for no kind of list the type names"
        );
    }
}

/// Each kind, handed and lent where the door differs, held to its ceiling and
/// against the report.
#[test]
fn every_kind_of_list_holds_what_it_reports_and_no_more_than_its_ceiling() {
    // Every case is read and every finding is reported together, so one run says
    // all that is wrong and not the first.
    let mut findings: Vec<alloc::string::String> = Vec::new();
    for case in cases() {
        let (name, expect) = (case.name, case.expect);
        findings.extend(check(name, "handed", expect, case.ceiling, case.build));
        if case.lendable {
            findings.extend(check(name, "lent", expect, case.ceiling_lent, case.build));
        }
    }
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}

/// The bytes after a Frame's header that a row's unit carries, which the sweep
/// varies and the cases above hold at four.
const PAYLOADS: [usize; 3] = [16, 256, 4096];

/// A kind whose rows' unit carries a payload the sweep can size, and how many
/// times the unit's bytes it may hold as that payload grows.
///
/// A multiple is a bound and not a measurement: it is what the kind's structure
/// is built to hold, so a kind that comes to hold more (a second copy, a buffer
/// that doubles past its bytes) fails here, and a kind that comes to hold less
/// has its bound lowered in the same commit.
struct Sized {
    name: &'static str,
    build: fn(usize, bool, Option<usize>) -> Run,
    expect: Expect,
    /// Per byte the unit grows, the bytes the LENT door's row may grow by: none
    /// for a kind that reads its units where the container lends them, and one
    /// copy and a chunk's tail for a kind that keeps a changed form of them.
    lent_copies: f64,
    /// Per byte the unit grows, the bytes the handed door holds beyond the lent
    /// door: the copy it owns. Every owned copy is a log of chunks, which holds
    /// the bytes and a chunk's tail (a buffer that grows would hold up to twice
    /// them, and did, for a TCP stream, before its kept bytes were a log).
    handed_copies: f64,
}

fn sized_kinds() -> [Sized; 4] {
    [
        Sized {
            name: "udp",
            build: udp_of,
            expect: Expect::List(|o| matches!(o, MessageListOrigin::Datagram)),
            lent_copies: 0.0,
            handed_copies: 1.1,
        },
        Sized {
            name: "tcp",
            build: tcp_of,
            expect: Expect::List(is_stream),
            lent_copies: 0.0,
            handed_copies: 1.1,
        },
        Sized {
            name: "websocket",
            build: websocket_of,
            expect: Expect::List(is_stream),
            // An unmasked single-frame payload is the stream's own bytes: the
            // list keeps where it stands and reads it from the stream.
            lent_copies: 0.0,
            handed_copies: 1.1,
        },
        Sized {
            name: "websocket (masked)",
            build: websocket_masked_of,
            expect: Expect::List(is_stream),
            // A masked payload is XORed in the stream under a key that stands
            // before it: the list keeps where it stands and unmasks it as it
            // reads, so it costs nothing beyond the stream either.
            lent_copies: 0.0,
            handed_copies: 1.1,
        },
    ]
}

/// What a capture of `UNITS` rows and of twice that hold, for the row count they
/// differ by.
fn growth(kind: &Sized, lent: bool, payload: usize) -> (usize, isize, isize) {
    let (small, large) = (
        sample(&(kind.build)(UNITS, lent, Some(payload)), kind.expect),
        sample(&(kind.build)(2 * UNITS, lent, Some(payload)), kind.expect),
    );
    assert!(
        small.populated && large.populated,
        "{} ({payload} B): the capture produced no rows of this kind",
        kind.name
    );
    (
        large.rows - small.rows,
        large.held - small.held,
        large.reported as isize - small.reported as isize,
    )
}

/// The heap a row costs, against the size of the unit it came from.
///
/// The cases above hold a unit at four bytes, where a row's own entry is most of
/// what it costs and a copy of the unit hardly shows. A unit of kilobytes is where
/// a structure that copies it, or copies it twice, or holds twice its bytes in a
/// buffer that doubled, shows. For each kind and door, at each size:
///
/// * the report equals the allocator, to the byte, as at the cases' size;
/// * what the row costs beyond the smallest unit's is within what the kind's
///   structure is built to hold of the unit's bytes (see [`Sized`]): nothing on the
///   lent door of a kind that reads its units where they are, and one copy on the
///   handed door.
#[test]
fn what_a_row_costs_does_not_follow_the_size_of_its_unit() {
    let mut findings: Vec<alloc::string::String> = Vec::new();
    for kind in sized_kinds() {
        // Bytes per row, by door, at each payload.
        let mut per_row = [[0f64; PAYLOADS.len()]; 2];
        for (door_at, lent) in [false, true].into_iter().enumerate() {
            let door = if lent { "lent" } else { "handed" };
            for (at, payload) in PAYLOADS.into_iter().enumerate() {
                let (rows, held, reported) = growth(&kind, lent, payload);
                std::eprintln!(
                    "{} ({door}) unit of {payload} B: {:.2} B/row held, {:.2} reported",
                    kind.name,
                    held as f64 / rows as f64,
                    reported as f64 / rows as f64
                );
                if held != reported {
                    findings.push(alloc::format!(
                        "{} ({door}) unit of {payload} B: holds {held} B more at twice the \
                         rows and reports {reported}",
                        kind.name
                    ));
                }
                per_row[door_at][at] = held as f64 / rows as f64;
            }
        }
        let [handed, lent] = per_row;
        for (at, payload) in PAYLOADS.into_iter().enumerate().skip(1) {
            // The unit's own bytes the row's unit gained over the smallest.
            let gained = (payload - PAYLOADS[0]) as f64;
            let lent_grew = lent[at] - lent[0];
            if lent_grew > kind.lent_copies * gained {
                findings.push(alloc::format!(
                    "{} (lent) unit of {payload} B: a row holds {lent_grew:.1} B more than at \
                     {} B, over {} times the {gained} B the unit gained",
                    kind.name,
                    PAYLOADS[0],
                    kind.lent_copies
                ));
            }
            let owned = (handed[at] - lent[at]) - (handed[0] - lent[0]);
            if owned < gained || owned > kind.handed_copies * gained {
                findings.push(alloc::format!(
                    "{} (handed) unit of {payload} B: a row holds {owned:.1} B for the copy it \
                     owns beyond the lent door's, where the {gained} B the unit gained is the \
                     least and {} times it the most",
                    kind.name,
                    kind.handed_copies
                ));
            }
        }
    }
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}
