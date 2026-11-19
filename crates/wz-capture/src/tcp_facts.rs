// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHAT A TCP CONNECTION DID UNDER ITS ZENOH SESSION: the receive windows, the
//! acknowledgements, the kinds of retransmission, and each attempt to connect.
//!
//! Much of what a zenoh user sees as a stall or a delay is TCP's: a receiver
//! that closed its window, a sender held at the window's edge, segments resent
//! after a timeout, a small segment waiting for a delayed acknowledgement, a
//! connection refused or never answered. The reassembler counts retransmitted
//! and overlapping bytes per direction (`crate::tcp::StreamAnomalies`) and
//! reads no acknowledgement; this module reads every segment's header beside it
//! and keeps, per direction:
//!
//! * the spans of a ZERO WINDOW: from the first segment advertising a window of
//!   0 to the next advertising more;
//! * WINDOW FULL: a data segment whose end reaches the edge of the window the
//!   peer last advertised, scaled by the shift both SYNs agreed (RFC 7323), and
//!   `None` where the capture lacks a SYN, since the scale is then unknown;
//! * DUPLICATE ACKS: a segment with no data, no SYN, FIN or RST, acknowledging
//!   what the direction's previous acknowledgement did with the same window,
//!   while the peer has data outstanding;
//! * RETRANSMISSIONS by kind, as the definitions Wireshark's TCP analysis uses
//!   draw them: SPURIOUS when the peer had already acknowledged the data, FAST
//!   when the peer sent two or more duplicate acknowledgements of its start and
//!   the last within 20 ms, TIMEOUT otherwise; a keep-alive (one byte or none
//!   just below the next sequence number) is none of them;
//! * the gap from a SMALL segment (shorter than the receiver's stated maximum
//!   segment size, 536 when the SYN was not seen) to the acknowledgement that
//!   covers it, as its median and maximum: Nagle's algorithm meeting a delayed
//!   acknowledgement shows as gaps near 40 ms or 200 ms;
//!
//! and per connection ATTEMPT: how many SYNs it took and how far apart, what
//! answered (a SYN/ACK, a RST, or nothing the capture saw), the two intervals of
//! the handshake, and whether the attempt reused a four-tuple an earlier
//! attempt of the capture had used.
//!
//! # Where the handshake's time was measured
//!
//! Both intervals are taken at the tap. A tap beside the opener measures the
//! round trip in SYN to SYN/ACK and almost nothing in SYN/ACK to ACK; a tap
//! beside the acceptor the reverse. Both are written, so a reader sees which
//! side the tap stood on from which one is large.
//!
//! Counted at ingest, so a retention ceiling does not move it, and bounded:
//! each list holds a fixed number and counts what it left out.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::link::Segment;

/// Retransmission events, and zero-window spans, one direction keeps.
pub const EVENTS_HELD: usize = 64;
/// Connection attempts a flow keeps.
pub const ATTEMPTS_HELD: usize = 8;
/// SYN-to-SYN gaps an attempt keeps.
pub const SYN_GAPS_HELD: usize = 8;
/// Small segments awaiting their acknowledgement, per direction.
pub const PENDING_HELD: usize = 64;
/// Acknowledgement gaps one direction keeps for its median.
pub const GAPS_HELD: usize = 4096;
/// How recent the last duplicate acknowledgement must be for a retransmission
/// to be fast.
pub const FAST_RETRANSMIT_NS: u64 = 20_000_000;
/// The maximum segment size a receiver is held to when its SYN was not seen
/// (RFC 9293, section 3.7.1).
pub const DEFAULT_MSS: u16 = 536;

/// `a` before `b` in sequence space.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a` at or before `b` in sequence space.
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// The kind of a retransmission. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retransmit {
    /// Resent with no sign the peer asked for it: a timer ran out.
    Timeout,
    /// Resent after the peer's duplicate acknowledgements of it.
    Fast,
    /// Resent although the peer had already acknowledged it.
    Spurious,
}

impl Retransmit {
    /// The word this kind is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Retransmit::Timeout => "timeout",
            Retransmit::Fast => "fast",
            Retransmit::Spurious => "spurious",
        }
    }

    fn index(self) -> usize {
        match self {
            Retransmit::Timeout => 0,
            Retransmit::Fast => 1,
            Retransmit::Spurious => 2,
        }
    }

    /// Every kind, from an exhaustive match.
    pub fn all() -> [Retransmit; 3] {
        let one = |r: Retransmit| match r {
            Retransmit::Timeout => Retransmit::Timeout,
            Retransmit::Fast => Retransmit::Fast,
            Retransmit::Spurious => Retransmit::Spurious,
        };
        [
            one(Retransmit::Timeout),
            one(Retransmit::Fast),
            one(Retransmit::Spurious),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|r| r.name()).collect();
        words.sort_unstable();
        words
    }
}

/// What answered a connection attempt. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynAnswer {
    /// A SYN/ACK.
    SynAck,
    /// A RST: no listener, or a filter.
    Rst,
    /// Nothing the capture saw.
    None,
}

impl SynAnswer {
    /// The word this answer is written as.
    pub const fn name(self) -> &'static str {
        match self {
            SynAnswer::SynAck => "syn_ack",
            SynAnswer::Rst => "rst",
            SynAnswer::None => "none",
        }
    }

    /// Every word, sorted, from an exhaustive match.
    pub fn names() -> Vec<&'static str> {
        let one = |a: SynAnswer| match a {
            SynAnswer::SynAck => SynAnswer::SynAck,
            SynAnswer::Rst => SynAnswer::Rst,
            SynAnswer::None => SynAnswer::None,
        };
        let mut words: Vec<&'static str> = [
            one(SynAnswer::SynAck),
            one(SynAnswer::Rst),
            one(SynAnswer::None),
        ]
        .iter()
        .map(|a| a.name())
        .collect();
        words.sort_unstable();
        words
    }
}

/// Where a moment of the connection was: its capture-global packet and the
/// capture's clock there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moment {
    /// The packet.
    pub packet: usize,
    /// The capture's instant, nanoseconds, when the packet had one.
    pub at_ns: Option<u64>,
}

/// One retransmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Its kind.
    pub kind: Retransmit,
    /// The segment that resent.
    pub at: Moment,
}

/// One span of a zero window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// The first segment that advertised 0.
    pub start: Moment,
    /// The next segment that advertised more, `None` while the window stayed 0.
    pub end: Option<Moment>,
}

/// One attempt to open the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The opener's direction is `a`.
    pub opener_is_a: bool,
    /// The first SYN.
    pub first_syn: Moment,
    /// The last SYN, the one an answer is measured from.
    last_syn: Moment,
    /// The SYNs the attempt took, its retries included.
    pub syns: u32,
    /// The gaps between successive SYNs, the first few.
    pub syn_gaps_ns: Vec<u64>,
    /// The opener's initial sequence number.
    isn: u32,
    /// What answered.
    pub answer: SynAnswer,
    /// The segment that answered.
    pub answered_at: Option<Moment>,
    /// The acceptor's initial sequence number, from its SYN/ACK.
    acceptor_isn: Option<u32>,
    /// The last SYN to its answer, at the tap.
    pub syn_to_answer_ns: Option<u64>,
    /// The SYN/ACK to the opener's acknowledgement of it, at the tap.
    pub answer_to_ack_ns: Option<u64>,
    /// An earlier attempt of the capture had used this four-tuple.
    pub port_reuse: bool,
}

/// What one direction of a connection did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Half {
    /// Its SYN was seen.
    pub saw_syn: bool,
    /// The Window Scale its SYN offered.
    pub offered_scale: Option<u8>,
    /// The maximum segment size its SYN stated.
    pub mss: Option<u16>,
    /// The spans of a zero window, the first few.
    pub zero_spans: Vec<Span>,
    /// Every span of a zero window.
    pub zero_count: u64,
    /// Data segments that reached the edge of the peer's window; `None` while
    /// the scale is unknown.
    pub window_full: Option<u64>,
    /// Duplicate acknowledgements.
    pub dup_acks: u64,
    /// The last acknowledgement seen.
    pub last_ack: Option<Moment>,
    /// Retransmissions by kind: timeout, fast, spurious.
    pub retransmits: [u64; 3],
    /// The retransmissions, the first few.
    pub events: Vec<Event>,
    /// The retransmissions and zero-window spans past the lists' bound.
    pub more: u64,
    /// Small-segment acknowledgement gaps, nanoseconds, the first few thousand.
    pub gaps: Vec<u64>,
    /// Gaps past that bound.
    pub gaps_more: u64,
    next_seq: Option<u32>,
    ack: Option<u32>,
    window: Option<u16>,
    zero_open: bool,
    dup_run: u32,
    dup_last_ns: Option<u64>,
    pending: VecDeque<(u32, u64)>,
}

impl Half {
    /// The gap median and maximum, nanoseconds.
    pub fn gap_median_max(&self) -> Option<(u64, u64)> {
        let mut sorted = self.gaps.clone();
        sorted.sort_unstable();
        let max = *sorted.last()?;
        Some((sorted[sorted.len() / 2], max))
    }

    fn record(&mut self, kind: Retransmit, at: Moment) {
        self.retransmits[kind.index()] += 1;
        if self.events.len() < EVENTS_HELD {
            self.events.push(Event { kind, at });
        } else {
            self.more += 1;
        }
    }
}

/// What one TCP flow did, `a` then `b`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFacts {
    halves: [Half; 2],
    attempts: Vec<Attempt>,
    attempts_more: u64,
    /// Whether the most recent attempt is the one held last (false when it
    /// was past the bound).
    current_held: bool,
}

impl TcpFacts {
    /// Direction `a`'s facts, then `b`'s.
    pub fn halves(&self) -> &[Half; 2] {
        &self.halves
    }

    /// The connection attempts, the first few.
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }

    /// Attempts past that bound.
    pub fn attempts_more(&self) -> u64 {
        self.attempts_more
    }

    /// The shift the windows direction `d` (0 for `a`) advertises are read
    /// under: the one its SYN offered when both SYNs offered one, 0 when both
    /// SYNs were seen and either offered none, `None` when a SYN was not seen.
    pub fn window_scale(&self, d: usize) -> Option<u8> {
        self.scale(d)
    }

    /// The shift `d`'s windows are scaled by: the one its SYN offered when both
    /// SYNs offered one, 0 when both SYNs were seen and either offered none,
    /// `None` when a SYN was not seen.
    fn scale(&self, d: usize) -> Option<u8> {
        let [a, b] = &self.halves;
        if !(a.saw_syn && b.saw_syn) {
            return None;
        }
        match (a.offered_scale, b.offered_scale) {
            (Some(_), Some(_)) => self.halves[d].offered_scale.map(|s| s.min(14)),
            _ => Some(0),
        }
    }

    fn current(&mut self) -> Option<&mut Attempt> {
        if self.current_held {
            self.attempts.last_mut()
        } else {
            None
        }
    }

    /// One segment of the flow, travelling from `low` (`a_to_b`) or not, at the
    /// capture's `at_ns`.
    pub fn observe(&mut self, a_to_b: bool, s: &Segment<'_>, at_ns: Option<u64>) {
        let d = usize::from(!a_to_b);
        let p = 1 - d;
        let at = Moment {
            packet: s.packet_index,
            at_ns,
        };
        let since = |from: Option<u64>| match (from, at_ns) {
            (Some(f), Some(t)) if t >= f => Some(t - f),
            _ => None,
        };
        let len = s.payload.len() as u32;

        // The handshake.
        if s.syn && s.tcp.ack.is_none() {
            let retry = self.current().is_some_and(|c| {
                c.opener_is_a == a_to_b && c.isn == s.seq && c.answer == SynAnswer::None
            });
            if retry {
                let c = self.current().expect("held");
                c.syns += 1;
                if c.syn_gaps_ns.len() < SYN_GAPS_HELD {
                    if let Some(gap) = since(c.last_syn.at_ns) {
                        c.syn_gaps_ns.push(gap);
                    }
                }
                c.last_syn = at;
            } else {
                let port_reuse = !self.attempts.is_empty() || self.attempts_more > 0;
                if port_reuse {
                    // A new connection on the same four-tuple: its sequence
                    // spaces are new.
                    self.halves = Default::default();
                }
                let attempt = Attempt {
                    opener_is_a: a_to_b,
                    first_syn: at,
                    last_syn: at,
                    syns: 1,
                    syn_gaps_ns: Vec::new(),
                    isn: s.seq,
                    answer: SynAnswer::None,
                    answered_at: None,
                    acceptor_isn: None,
                    syn_to_answer_ns: None,
                    answer_to_ack_ns: None,
                    port_reuse,
                };
                if self.attempts.len() < ATTEMPTS_HELD {
                    self.attempts.push(attempt);
                    self.current_held = true;
                } else {
                    self.attempts_more += 1;
                    self.current_held = false;
                }
            }
        }
        if s.syn {
            let h = &mut self.halves[d];
            h.saw_syn = true;
            h.offered_scale = s.tcp.window_scale;
            h.mss = s.tcp.mss;
        }
        let acceptor = self
            .current()
            .is_some_and(|c| c.opener_is_a != a_to_b && c.answer == SynAnswer::None);
        if acceptor && (s.rst || (s.syn && s.tcp.ack.is_some())) {
            let c = self.current().expect("held");
            c.answer = if s.rst {
                SynAnswer::Rst
            } else {
                SynAnswer::SynAck
            };
            c.answered_at = Some(at);
            c.syn_to_answer_ns = since(c.last_syn.at_ns);
            if s.syn {
                c.acceptor_isn = Some(s.seq);
            }
        }
        if let (Some(ack), false) = (s.tcp.ack, s.syn) {
            if let Some(c) = self.current() {
                if c.opener_is_a == a_to_b
                    && c.answer == SynAnswer::SynAck
                    && c.answer_to_ack_ns.is_none()
                    && c.acceptor_isn.map(|i| i.wrapping_add(1)) == Some(ack)
                {
                    c.answer_to_ack_ns = since(c.answered_at.and_then(|m| m.at_ns));
                }
            }
        }

        // The acknowledgement and the window this segment advertises.
        if let Some(ack) = s.tcp.ack {
            if !s.syn && !s.rst {
                let window = s.tcp.window;
                let h = &mut self.halves[d];
                if window == 0 {
                    if !h.zero_open {
                        h.zero_open = true;
                        h.zero_count += 1;
                        if h.zero_spans.len() < EVENTS_HELD {
                            h.zero_spans.push(Span {
                                start: at,
                                end: None,
                            });
                        } else {
                            h.more += 1;
                        }
                    }
                } else if h.zero_open {
                    h.zero_open = false;
                    if h.zero_spans.len() as u64 == h.zero_count {
                        if let Some(span) = h.zero_spans.last_mut() {
                            span.end = Some(at);
                        }
                    }
                }
            }
            let peer_outstanding = self.halves[p].next_seq.is_some_and(|n| seq_lt(ack, n));
            let h = &mut self.halves[d];
            let duplicate = len == 0
                && !s.syn
                && !s.fin
                && !s.rst
                && h.ack == Some(ack)
                && h.window == Some(s.tcp.window)
                && peer_outstanding;
            if duplicate {
                h.dup_acks += 1;
                h.dup_run += 1;
                h.dup_last_ns = at_ns;
            } else if h.ack != Some(ack) {
                h.dup_run = 0;
            }
            h.ack = Some(ack);
            h.window = Some(s.tcp.window);
            h.last_ack = Some(at);
            // The peer's small segments this acknowledgement covers.
            let peer = &mut self.halves[p];
            while let Some(&(end, sent)) = peer.pending.front() {
                if !seq_le(end, ack) {
                    break;
                }
                peer.pending.pop_front();
                if let Some(gap) = at_ns.and_then(|t| t.checked_sub(sent)) {
                    if peer.gaps.len() < GAPS_HELD {
                        peer.gaps.push(gap);
                    } else {
                        peer.gaps_more += 1;
                    }
                }
            }
        }

        // The data this segment carries.
        let occupies = len + u32::from(s.syn) + u32::from(s.fin);
        if occupies == 0 {
            return;
        }
        let end = s.seq.wrapping_add(occupies);
        let scale_p = self.scale(p);
        let (peer_ack, peer_window, peer_dup_run, peer_dup_last, peer_mss) = {
            let q = &self.halves[p];
            (q.ack, q.window, q.dup_run, q.dup_last_ns, q.mss)
        };
        let h = &mut self.halves[d];
        let mut resent = false;
        if len > 0 {
            if let Some(next) = h.next_seq {
                let keepalive = len <= 1 && s.seq == next.wrapping_sub(1);
                if seq_lt(s.seq, next) && !keepalive {
                    resent = true;
                    let kind = if peer_ack.is_some_and(|a| seq_le(end, a)) {
                        Retransmit::Spurious
                    } else if peer_dup_run >= 2
                        && peer_ack == Some(s.seq)
                        && peer_dup_last
                            .zip(at_ns)
                            .is_some_and(|(dup, t)| t >= dup && t - dup <= FAST_RETRANSMIT_NS)
                    {
                        Retransmit::Fast
                    } else {
                        Retransmit::Timeout
                    };
                    h.record(kind, at);
                }
            }
            // The window's edge, under the peer's scale.
            match (scale_p, peer_ack, peer_window) {
                (Some(shift), Some(ack), Some(window)) => {
                    let edge = u64::from(window) << shift;
                    let full = u64::from(end.wrapping_sub(ack)) >= edge && edge > 0;
                    let count = h.window_full.get_or_insert(0);
                    if full {
                        *count += 1;
                    }
                }
                (Some(_), _, _) => {
                    h.window_full.get_or_insert(0);
                }
                _ => {}
            }
            let small = len < u32::from(peer_mss.unwrap_or(DEFAULT_MSS));
            if small && !resent && h.pending.len() < PENDING_HELD {
                if let Some(t) = at_ns {
                    h.pending.push_back((end, t));
                }
            }
        }
        // A `match`, not `is_none_or`, which is newer than this workspace's
        // MSRV (`crates/Cargo.toml`).
        let advances = match h.next_seq {
            Some(n) => seq_lt(n, end),
            None => true,
        };
        if advances {
            h.next_seq = Some(end);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::link::{Checksums, Endpoint, IpFacts, LinkKind, TcpHeader, Tunnel};

    /// Connections that between them write every key and every word of a
    /// flow's `tcp`: an answered handshake with a zero window, each kind of
    /// retransmission and a small segment's gap; a refused attempt after a
    /// retried SYN; and an attempt nothing answered, reusing the port. Its one reader is the
    /// document's test (`fields_json`), which is behind `dissect`.
    #[cfg(feature = "dissect")]
    pub(crate) fn every_word() -> alloc::vec::Vec<TcpFacts> {
        let mut answered = TcpFacts::default();
        handshake(&mut answered);
        let zero = S {
            seq: 501,
            ack: Some(101),
            window: 0,
            packet: 3,
            ..S::default()
        };
        feed(&mut answered, zero, 1_000);
        feed(
            &mut answered,
            S {
                window: 500,
                packet: 4,
                ..zero
            },
            2_000,
        );
        let data = |seq: u32, len: usize, packet: usize| S {
            a_to_b: true,
            seq,
            ack: Some(501),
            window: 502,
            len,
            packet,
            ..S::default()
        };
        let ack = |n: u32, packet: usize| S {
            seq: 501,
            ack: Some(n),
            window: 500,
            packet,
            ..S::default()
        };
        feed(&mut answered, data(101, 10, 5), 3_000);
        feed(&mut answered, data(111, 100, 6), 4_000);
        feed(&mut answered, ack(111, 7), 40_000_000);
        feed(&mut answered, ack(111, 8), 40_100_000);
        feed(&mut answered, ack(111, 9), 40_200_000);
        feed(&mut answered, data(111, 100, 10), 41_000_000);
        feed(&mut answered, ack(211, 11), 42_000_000);
        feed(&mut answered, data(111, 100, 12), 43_000_000);
        feed(&mut answered, data(211, 100, 13), 44_000_000);
        feed(&mut answered, data(211, 100, 14), 400_000_000);

        let mut refused = TcpFacts::default();
        let syn = S {
            a_to_b: true,
            seq: 100,
            syn: true,
            ..S::default()
        };
        feed(&mut refused, syn, 0);
        feed(&mut refused, S { packet: 1, ..syn }, 1_000_000_000);
        let rst = S {
            rst: true,
            ack: Some(101),
            packet: 2,
            ..S::default()
        };
        feed(&mut refused, rst, 1_000_100_000);
        feed(
            &mut refused,
            S {
                seq: 7000,
                packet: 3,
                ..syn
            },
            2_000_000_000,
        );
        alloc::vec![answered, refused]
    }

    const PAYLOAD: [u8; 1500] = [0u8; 1500];

    /// The parts of one segment a test varies.
    #[derive(Clone, Copy, Default)]
    struct S {
        a_to_b: bool,
        seq: u32,
        syn: bool,
        fin: bool,
        rst: bool,
        ack: Option<u32>,
        window: u16,
        scale: Option<u8>,
        mss: Option<u16>,
        len: usize,
        packet: usize,
    }

    fn feed(f: &mut TcpFacts, s: S, at_ns: u64) {
        let flow = crate::link::flow_key(
            Endpoint::new(&[10, 0, 0, 1], 43210),
            Endpoint::new(&[10, 0, 0, 2], 7447),
            LinkKind::Tcp,
        );
        let segment = Segment {
            flow,
            from_low: s.a_to_b,
            seq: s.seq,
            syn: s.syn,
            fin: s.fin,
            rst: s.rst,
            payload: &PAYLOAD[..s.len],
            packet_index: s.packet,
            checksums: Checksums {
                ip: None,
                transport: None,
                tunnel: None,
            },
            tunnel: Tunnel::none(),
            ip: IpFacts::default(),
            tcp: TcpHeader {
                ack: s.ack,
                window: s.window,
                window_scale: s.scale,
                mss: s.mss,
            },
        };
        f.observe(s.a_to_b, &segment, Some(at_ns));
    }

    /// The opener's SYN, the acceptor's SYN/ACK and the opener's ACK, both
    /// offering a scale: the attempt is answered, both intervals are taken and
    /// each direction reads its own shift.
    fn handshake(f: &mut TcpFacts) {
        let syn = S {
            a_to_b: true,
            seq: 100,
            syn: true,
            window: 64240,
            scale: Some(7),
            mss: Some(1460),
            ..S::default()
        };
        feed(f, syn, 0);
        let syn_ack = S {
            seq: 500,
            syn: true,
            ack: Some(101),
            window: 65160,
            scale: Some(8),
            mss: Some(1400),
            packet: 1,
            ..S::default()
        };
        feed(f, syn_ack, 180_000);
        let ack = S {
            a_to_b: true,
            seq: 101,
            ack: Some(501),
            window: 502,
            packet: 2,
            ..S::default()
        };
        feed(f, ack, 220_000);
    }

    #[test]
    fn an_answered_handshake_takes_both_intervals_and_each_directions_scale() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        let a = &f.attempts()[0];
        assert_eq!(a.answer, SynAnswer::SynAck);
        assert_eq!(a.syns, 1);
        assert_eq!(a.syn_to_answer_ns, Some(180_000));
        assert_eq!(a.answer_to_ack_ns, Some(40_000));
        assert!(!a.port_reuse);
        assert_eq!(f.window_scale(0), Some(7));
        assert_eq!(f.window_scale(1), Some(8));
        assert_eq!(f.halves()[1].mss, Some(1400));
    }

    #[test]
    fn a_refused_and_retried_attempt_says_so_and_a_lone_syn_is_unanswered() {
        let syn = S {
            a_to_b: true,
            seq: 100,
            syn: true,
            ..S::default()
        };
        let mut f = TcpFacts::default();
        feed(&mut f, syn, 0);
        feed(&mut f, S { packet: 1, ..syn }, 1_000_000_000);
        let rst = S {
            rst: true,
            ack: Some(101),
            packet: 2,
            ..S::default()
        };
        feed(&mut f, rst, 1_000_300_000);
        let a = &f.attempts()[0];
        assert_eq!((a.syns, a.answer), (2, SynAnswer::Rst));
        assert_eq!(a.syn_gaps_ns, alloc::vec![1_000_000_000]);
        assert_eq!(a.syn_to_answer_ns, Some(300_000), "from the last SYN");

        let mut lone = TcpFacts::default();
        feed(&mut lone, syn, 0);
        assert_eq!(lone.attempts()[0].answer, SynAnswer::None);
    }

    #[test]
    fn a_second_syn_of_another_isn_reuses_the_port() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        let again = S {
            a_to_b: true,
            seq: 9000,
            syn: true,
            packet: 3,
            ..S::default()
        };
        feed(&mut f, again, 5_000_000);
        assert_eq!(f.attempts().len(), 2);
        assert!(f.attempts()[1].port_reuse);
        assert_eq!(
            f.window_scale(0),
            None,
            "the new connection's SYNs are not both seen"
        );
    }

    #[test]
    fn a_zero_window_is_a_span_from_its_first_advertisement_to_the_next_open_one() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        let zero = S {
            seq: 501,
            ack: Some(101),
            window: 0,
            packet: 5,
            ..S::default()
        };
        feed(&mut f, zero, 1_000);
        feed(&mut f, S { packet: 6, ..zero }, 2_000);
        feed(
            &mut f,
            S {
                window: 1000,
                packet: 8,
                ..zero
            },
            3_000,
        );
        let b = &f.halves()[1];
        assert_eq!(b.zero_count, 1);
        assert_eq!(b.zero_spans[0].start.packet, 5);
        assert_eq!(b.zero_spans[0].end.map(|m| m.packet), Some(8));
    }

    #[test]
    fn each_kind_of_retransmission_is_told_apart() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        let data = |seq: u32, packet: usize| S {
            a_to_b: true,
            seq,
            ack: Some(501),
            window: 502,
            len: 100,
            packet,
            ..S::default()
        };
        feed(&mut f, data(101, 10), 1_000_000);
        feed(&mut f, data(201, 11), 1_100_000);
        let ack = |n: u32, packet: usize| S {
            seq: 501,
            ack: Some(n),
            window: 500,
            packet,
            ..S::default()
        };
        feed(&mut f, ack(101, 12), 2_000_000);
        feed(&mut f, ack(101, 13), 2_100_000);
        feed(&mut f, ack(101, 14), 2_200_000);
        assert_eq!(f.halves()[1].dup_acks, 2);
        // Resent within 20 ms of the second duplicate: fast.
        feed(&mut f, data(101, 15), 3_000_000);
        // The peer acknowledges all of it; resending it again is spurious.
        feed(&mut f, ack(301, 16), 4_000_000);
        feed(&mut f, data(101, 17), 5_000_000);
        // New data, then resent with no duplicate acknowledgement: a timeout.
        feed(&mut f, data(301, 18), 6_000_000);
        feed(&mut f, data(301, 19), 300_000_000);
        let a = &f.halves()[0];
        assert_eq!(a.retransmits, [1, 1, 1], "timeout, fast, spurious");
        assert_eq!(
            a.events
                .iter()
                .map(|e| (e.kind, e.at.packet))
                .collect::<Vec<_>>(),
            alloc::vec![
                (Retransmit::Fast, 15),
                (Retransmit::Spurious, 17),
                (Retransmit::Timeout, 19),
            ]
        );
    }

    #[test]
    fn the_window_edge_is_read_under_the_scale_and_unknown_without_the_syns() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        // `b` advertises 1 under its shift of 8: 256 bytes.
        feed(
            &mut f,
            S {
                seq: 501,
                ack: Some(101),
                window: 1,
                packet: 3,
                ..S::default()
            },
            1,
        );
        let fill = S {
            a_to_b: true,
            seq: 101,
            ack: Some(501),
            window: 502,
            len: 256,
            packet: 4,
            ..S::default()
        };
        feed(&mut f, fill, 2);
        assert_eq!(f.halves()[0].window_full, Some(1));

        let mut joined = TcpFacts::default();
        feed(&mut joined, S { len: 0, ..fill }, 0);
        feed(&mut joined, S { packet: 5, ..fill }, 1);
        assert_eq!(joined.window_scale(0), None);
        assert_eq!(joined.halves()[0].window_full, None, "unstated, not zero");
    }

    #[test]
    fn a_small_segment_and_its_acknowledgement_give_a_gap() {
        let mut f = TcpFacts::default();
        handshake(&mut f);
        let small = S {
            a_to_b: true,
            seq: 101,
            ack: Some(501),
            window: 502,
            len: 10,
            packet: 3,
            ..S::default()
        };
        feed(&mut f, small, 1_000_000);
        feed(
            &mut f,
            S {
                seq: 501,
                ack: Some(111),
                window: 500,
                packet: 4,
                ..S::default()
            },
            41_000_000,
        );
        assert_eq!(
            f.halves()[0].gap_median_max(),
            Some((40_000_000, 40_000_000))
        );
    }

    #[test]
    fn the_words_are_the_declared_families() {
        assert_eq!(Retransmit::names(), crate::doc_revision::TCP_RETRANSMIT_R78);
        assert_eq!(SynAnswer::names(), crate::doc_revision::TCP_SYN_ANSWER_R78);
    }
}
