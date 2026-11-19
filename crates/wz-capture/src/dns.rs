// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHETHER A ZENOH ENDPOINT'S NAME RESOLVED: the DNS questions a capture
//! carried and what answered them.
//!
//! An endpoint named by host (`tcp/router.local:7447`) is looked up before any
//! session can start. When the name does not resolve, no SYN follows and the
//! capture holds no zenoh at all: the cause is only in the lookup. This reads
//! the A, AAAA and SRV questions of every UDP datagram on port 53 (DNS, RFC
//! 1035) and 5353 (multicast DNS, RFC 6762) and pairs each with its response:
//! its rcode and the addresses, or SRV targets and ports, it named.
//!
//! The datagrams are read beside the path every UDP datagram takes, as the
//! ICMP messages are (`crate::control`): a flow on those ports is still a
//! datagram flow, and what it says about names is read here as well.
//!
//! # Pairing
//!
//! A DNS response answers the query of the same id sent from the endpoint it
//! is addressed to, to the endpoint it came from, about the same question.
//! A query sent again before an answer (the same id, endpoints and question)
//! is counted as a resend of that query, not as a new one. A multicast DNS
//! response is addressed to the group and its id is usually 0, so it answers
//! the oldest unanswered multicast query whose question one of its records
//! names; a response that answers none is counted as unmatched.

use alloc::string::String;
use alloc::vec::Vec;

use crate::link::Endpoint;

/// How many queries a capture keeps.
pub const QUERIES_HELD: usize = 256;
/// How many records one query keeps from its answer.
pub const RECORDS_HELD: usize = 16;

/// The UDP port of DNS.
pub const DNS_PORT: u32 = 53;
/// The UDP port of multicast DNS.
pub const MDNS_PORT: u32 = 5353;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
/// Labels a name may chain through before it is refused: RFC 1035 section
/// 2.3.4 limits a name to 255 bytes, so 128 labels, and a compression loop
/// would otherwise not end.
const MAX_LABELS: usize = 128;

/// A question's type. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    /// An IPv4 address.
    A,
    /// An IPv6 address.
    Aaaa,
    /// A service's target and port.
    Srv,
}

impl QueryType {
    fn of(t: u16) -> Option<Self> {
        match t {
            TYPE_A => Some(QueryType::A),
            TYPE_AAAA => Some(QueryType::Aaaa),
            TYPE_SRV => Some(QueryType::Srv),
            _ => None,
        }
    }

    /// The word this type is written as.
    pub const fn name(self) -> &'static str {
        match self {
            QueryType::A => "a",
            QueryType::Aaaa => "aaaa",
            QueryType::Srv => "srv",
        }
    }

    /// Every type, from an exhaustive match.
    pub fn all() -> [QueryType; 3] {
        let one = |t: QueryType| match t {
            QueryType::A | QueryType::Aaaa | QueryType::Srv => t,
        };
        [one(QueryType::A), one(QueryType::Aaaa), one(QueryType::Srv)]
    }

    /// Every word, sorted.
    #[cfg(test)]
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|t| t.name()).collect();
        words.sort_unstable();
        words
    }
}

/// A response's rcode (RFC 1035 section 4.1.1, RFC 6895 section 2.3). The
/// closed set the documents write; the number is written beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    /// 0: the name exists.
    NoError,
    /// 1: the server could not read the query.
    FormErr,
    /// 2: the server failed.
    ServFail,
    /// 3: the name does not exist.
    NxDomain,
    /// 4: the server does not do this kind of query.
    NotImp,
    /// 5: the server refused.
    Refused,
    /// Any other number.
    Other,
}

impl Rcode {
    /// The rcode a header's low four bits state.
    pub fn of(number: u8) -> Self {
        match number {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            _ => Rcode::Other,
        }
    }

    /// The word this rcode is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Rcode::NoError => "noerror",
            Rcode::FormErr => "formerr",
            Rcode::ServFail => "servfail",
            Rcode::NxDomain => "nxdomain",
            Rcode::NotImp => "notimp",
            Rcode::Refused => "refused",
            Rcode::Other => "other",
        }
    }

    /// Every word, sorted, from [`Self::of`] over every number a header can
    /// state.
    #[cfg(test)]
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = (0..16u8).map(|n| Self::of(n).name()).collect();
        words.sort_unstable();
        words.dedup();
        words
    }
}

/// One capture packet and its instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moment {
    /// The packet's index in the capture.
    pub packet: usize,
    /// Its capture instant, `None` for a packet with no clock.
    pub at_ns: Option<u64>,
}

/// One record an answer named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The address of an A or AAAA record.
    pub addr: Option<Endpoint>,
    /// The target of an SRV record.
    pub target: Option<String>,
    /// The port of an SRV record.
    pub port: Option<u16>,
    /// Its time to live, in seconds.
    pub ttl_s: u32,
}

/// One question and what answered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The name asked about.
    pub name: String,
    /// Its type.
    pub qtype: QueryType,
    /// Asked by multicast DNS.
    pub mdns: bool,
    /// The endpoint that asked.
    pub asker: Endpoint,
    /// The endpoint asked: a server, or the multicast group.
    pub server: Endpoint,
    /// The query's first packet.
    pub query: Moment,
    /// How many times it was sent.
    pub sent: u32,
    /// The response, when one came.
    pub answer: Option<Moment>,
    /// The response's rcode number.
    pub rcode: Option<u8>,
    /// The records it named that are about this question's name or its SRV
    /// targets, the first [`RECORDS_HELD`].
    pub records: Vec<Record>,
    /// Records past that bound.
    pub records_more: u64,
    id: u16,
}

/// Every DNS question a capture carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsPlane {
    queries: Vec<Query>,
    more: u64,
    unmatched: u64,
}

/// What one DNS message holds, read once.
struct Message {
    id: u16,
    response: bool,
    rcode: u8,
    question: Option<(String, u16)>,
    records: Vec<(String, u16, u32, Rdata)>,
}

enum Rdata {
    Addr(Vec<u8>),
    Srv { port: u16, target: String },
    Other,
}

impl DnsPlane {
    /// Whether a UDP datagram between these ports may be DNS.
    pub fn reads(source_port: u32, destination_port: u32) -> bool {
        [DNS_PORT, MDNS_PORT].contains(&source_port)
            || [DNS_PORT, MDNS_PORT].contains(&destination_port)
    }

    /// One UDP datagram from `from` to `to`.
    pub fn observe(&mut self, from: Endpoint, to: Endpoint, payload: &[u8], at: Moment) {
        let Some(m) = parse(payload) else {
            return;
        };
        let mdns = from.port == MDNS_PORT || to.port == MDNS_PORT;
        if m.response {
            self.answer(&m, from, to, mdns, at);
        } else {
            self.ask(m, from, to, mdns, at);
        }
    }

    /// The queries, in the order they were first sent.
    pub fn queries(&self) -> &[Query] {
        &self.queries
    }

    /// Queries past [`QUERIES_HELD`].
    pub fn more(&self) -> u64 {
        self.more
    }

    /// Responses that answered no query the capture held.
    pub fn unmatched(&self) -> u64 {
        self.unmatched
    }

    fn ask(&mut self, m: Message, from: Endpoint, to: Endpoint, mdns: bool, at: Moment) {
        let Some((name, t)) = m.question else {
            return;
        };
        let Some(qtype) = QueryType::of(t) else {
            return;
        };
        let again = self.queries.iter_mut().rev().find(|q| {
            q.answer.is_none()
                && q.id == m.id
                && q.asker == from
                && q.server == to
                && q.qtype == qtype
                && q.name.eq_ignore_ascii_case(&name)
        });
        if let Some(q) = again {
            q.sent += 1;
            return;
        }
        if self.queries.len() >= QUERIES_HELD {
            self.more += 1;
            return;
        }
        self.queries.push(Query {
            name,
            qtype,
            mdns,
            asker: from,
            server: to,
            query: at,
            sent: 1,
            answer: None,
            rcode: None,
            records: Vec::new(),
            records_more: 0,
            id: m.id,
        });
    }

    fn answer(&mut self, m: &Message, from: Endpoint, to: Endpoint, mdns: bool, at: Moment) {
        let names = |q: &Query, record: &str, t: u16| {
            q.name.eq_ignore_ascii_case(record) && QueryType::of(t) == Some(q.qtype)
        };
        let found = self.queries.iter_mut().find(|q| {
            if q.answer.is_some() || q.mdns != mdns {
                return false;
            }
            if mdns {
                m.records.iter().any(|(name, t, _, _)| names(q, name, *t))
            } else {
                q.id == m.id
                    && q.asker == to
                    && q.server == from
                    && m.question
                        .as_ref()
                        .is_some_and(|(name, t)| names(q, name, *t))
            }
        });
        let Some(q) = found else {
            self.unmatched += 1;
            return;
        };
        q.answer = Some(at);
        q.rcode = Some(m.rcode);
        // The question's own records, and the addresses of the targets its
        // SRV records name, which a server sends in the same message.
        let mut wanted: Vec<String> = alloc::vec![q.name.clone()];
        for (name, _, _, data) in &m.records {
            if let (true, Rdata::Srv { target, .. }) = (q.name.eq_ignore_ascii_case(name), data) {
                wanted.push(target.clone());
            }
        }
        for (name, _, ttl, data) in &m.records {
            if !wanted.iter().any(|w| w.eq_ignore_ascii_case(name)) {
                continue;
            }
            let record = match data {
                Rdata::Addr(bytes) => Record {
                    addr: Some(Endpoint::new(bytes, 0)),
                    target: None,
                    port: None,
                    ttl_s: *ttl,
                },
                Rdata::Srv { port, target } => Record {
                    addr: None,
                    target: Some(target.clone()),
                    port: Some(*port),
                    ttl_s: *ttl,
                },
                Rdata::Other => continue,
            };
            if q.records.len() < RECORDS_HELD {
                q.records.push(record);
            } else {
                q.records_more += 1;
            }
        }
    }
}

/// A cursor over one message, which names point back into.
struct Reader<'b> {
    msg: &'b [u8],
    at: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.msg.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from(self.u16()?) << 16 | u32::from(self.u16()?))
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let bytes = self.msg.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(bytes)
    }

    /// A name, following compression pointers (RFC 1035 section 4.1.4).
    fn name(&mut self) -> Option<String> {
        let mut out = String::new();
        let mut at = self.at;
        let mut jumped = false;
        for _ in 0..MAX_LABELS {
            let len = *self.msg.get(at)?;
            match len & 0xC0 {
                0x00 if len == 0 => {
                    if !jumped {
                        self.at = at + 1;
                    }
                    return Some(out);
                }
                0x00 => {
                    let label = self.msg.get(at + 1..at + 1 + usize::from(len))?;
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(&String::from_utf8_lossy(label));
                    at += 1 + usize::from(len);
                }
                0xC0 => {
                    let low = *self.msg.get(at + 1)?;
                    if !jumped {
                        self.at = at + 2;
                        jumped = true;
                    }
                    at = usize::from(len & 0x3F) << 8 | usize::from(low);
                }
                _ => return None,
            }
        }
        None
    }
}

/// One DNS message: its header, its first question and every resource record.
fn parse(payload: &[u8]) -> Option<Message> {
    let mut r = Reader {
        msg: payload,
        at: 0,
    };
    let id = r.u16()?;
    let flags = r.u16()?;
    // A standard query or its response; any other opcode is not a lookup.
    if (flags >> 11) & 0xF != 0 {
        return None;
    }
    let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
    let mut question = None;
    for i in 0..counts[0] {
        let name = r.name()?;
        let t = r.u16()?;
        r.u16()?;
        if i == 0 {
            question = Some((name, t));
        }
    }
    let mut records = Vec::new();
    let total = usize::from(counts[1]) + usize::from(counts[2]) + usize::from(counts[3]);
    for _ in 0..total {
        let name = r.name()?;
        let t = r.u16()?;
        r.u16()?;
        let ttl = r.u32()?;
        let len = usize::from(r.u16()?);
        let end = r.at.checked_add(len)?;
        let data = match (t, len) {
            (TYPE_A, 4) | (TYPE_AAAA, 16) => Rdata::Addr(r.take(len)?.to_vec()),
            (TYPE_SRV, 7..) => {
                r.take(4)?;
                let port = r.u16()?;
                let target = r.name()?;
                Rdata::Srv { port, target }
            }
            _ => Rdata::Other,
        };
        if end > payload.len() {
            return None;
        }
        r.at = end;
        records.push((name, t, ttl, data));
    }
    Some(Message {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xF) as u8,
        question,
        records,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    fn name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A query for `qname` of type `t`.
    pub(crate) fn query(id: u16, qname: &str, t: u16) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&name(qname));
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out
    }

    /// The response to [`query`] with `rcode` and `records`, each `(type,
    /// rdata)` about the question's name, written with a compression pointer
    /// to it.
    pub(crate) fn response(
        id: u16,
        qname: &str,
        t: u16,
        rcode: u8,
        records: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&name(qname));
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        for (rt, data) in records {
            out.extend_from_slice(&[0xC0, 12]);
            out.extend_from_slice(&rt.to_be_bytes());
            out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    pub(crate) const CLIENT: [u8; 4] = [10, 0, 0, 1];
    pub(crate) const RESOLVER: [u8; 4] = [10, 0, 0, 53];

    fn ends() -> (Endpoint, Endpoint) {
        (Endpoint::new(&CLIENT, 40_000), Endpoint::new(&RESOLVER, 53))
    }

    fn at(packet: usize) -> Moment {
        Moment {
            packet,
            at_ns: Some(packet as u64 * 1_000),
        }
    }

    /// A plane holding every word a document writes: an answered A query, an
    /// NXDOMAIN AAAA one, an unanswered SRV one, and every rcode.
    pub(crate) fn every_word() -> DnsPlane {
        let (c, s) = ends();
        let mut p = DnsPlane::default();
        p.observe(c, s, &query(1, "router.local", TYPE_A), at(0));
        p.observe(
            s,
            c,
            &response(1, "router.local", TYPE_A, 0, &[(TYPE_A, vec![10, 0, 0, 2])]),
            at(1),
        );
        p.observe(c, s, &query(2, "_zenoh._tcp.local", TYPE_SRV), at(2));
        for (i, rcode) in (1..=6u8).enumerate() {
            let id = 10 + i as u16;
            p.observe(c, s, &query(id, "missing.local", TYPE_AAAA), at(3 + 2 * i));
            p.observe(
                s,
                c,
                &response(id, "missing.local", TYPE_AAAA, rcode, &[]),
                at(4 + 2 * i),
            );
        }
        p
    }

    #[test]
    fn an_nxdomain_names_the_name_that_did_not_resolve() {
        let (c, s) = ends();
        let mut p = DnsPlane::default();
        p.observe(c, s, &query(7, "router.lan", TYPE_A), at(0));
        p.observe(c, s, &query(7, "router.lan", TYPE_A), at(1));
        p.observe(s, c, &response(7, "router.lan", TYPE_A, 3, &[]), at(2));
        let [q] = p.queries() else {
            panic!("one query: {:?}", p.queries());
        };
        assert_eq!(q.name, "router.lan");
        assert_eq!(q.sent, 2, "the resend is counted on the query");
        assert_eq!(q.answer, Some(at(2)));
        assert_eq!(q.rcode.map(Rcode::of), Some(Rcode::NxDomain));
        assert!(q.records.is_empty());
    }

    #[test]
    fn an_answer_names_its_addresses_and_an_unasked_one_is_unmatched() {
        let (c, s) = ends();
        let mut p = DnsPlane::default();
        p.observe(c, s, &query(1, "router.local", TYPE_A), at(0));
        // Another id, or from another server: not this query's answer.
        p.observe(s, c, &response(2, "router.local", TYPE_A, 0, &[]), at(1));
        p.observe(
            Endpoint::new(&[10, 0, 0, 54], 53),
            c,
            &response(1, "router.local", TYPE_A, 0, &[]),
            at(2),
        );
        assert_eq!(p.unmatched(), 2);
        p.observe(
            s,
            c,
            &response(1, "router.local", TYPE_A, 0, &[(TYPE_A, vec![10, 0, 0, 2])]),
            at(3),
        );
        let q = &p.queries()[0];
        assert_eq!(q.answer, Some(at(3)));
        assert_eq!(q.records[0].addr, Some(Endpoint::new(&[10, 0, 0, 2], 0)));
        assert_eq!(q.records[0].ttl_s, 60);
    }

    #[test]
    fn an_srv_answer_names_its_target_port_and_the_targets_address() {
        let (c, s) = ends();
        let mut p = DnsPlane::default();
        p.observe(c, s, &query(3, "_zenoh._tcp.local", TYPE_SRV), at(0));
        let mut srv = vec![0, 0, 0, 0];
        srv.extend_from_slice(&7447u16.to_be_bytes());
        srv.extend_from_slice(&name("router.local"));
        let mut answer = response(3, "_zenoh._tcp.local", TYPE_SRV, 0, &[(TYPE_SRV, srv)]);
        // The target's address in the additional section, its name written out.
        answer[11] = 1;
        answer.extend_from_slice(&name("router.local"));
        answer.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 2]);
        p.observe(s, c, &answer, at(1));
        let q = &p.queries()[0];
        assert_eq!(q.records.len(), 2, "{:?}", q.records);
        assert_eq!(q.records[0].target.as_deref(), Some("router.local"));
        assert_eq!(q.records[0].port, Some(7447));
        assert_eq!(q.records[1].addr, Some(Endpoint::new(&[10, 0, 0, 2], 0)));
    }

    #[test]
    fn a_multicast_answer_is_paired_by_the_name_it_names() {
        let asker = Endpoint::new(&CLIENT, MDNS_PORT);
        let group = Endpoint::new(&[224, 0, 0, 251], MDNS_PORT);
        let mut p = DnsPlane::default();
        p.observe(asker, group, &query(0, "router.local", TYPE_A), at(0));
        // Answered by another host, to the group, with no question section
        // (RFC 6762 section 6): an authoritative response of one A record.
        let mut answer = vec![0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        answer.extend_from_slice(&name("router.local"));
        answer.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 2]);
        p.observe(
            Endpoint::new(&[10, 0, 0, 2], MDNS_PORT),
            group,
            &answer,
            at(1),
        );
        let q = &p.queries()[0];
        assert!(q.mdns);
        assert_eq!(q.answer, Some(at(1)), "{:?}", p);
        assert_eq!(q.records[0].addr, Some(Endpoint::new(&[10, 0, 0, 2], 0)));
    }

    #[test]
    fn queries_past_the_bound_and_other_types_are_counted_or_left() {
        let (c, s) = ends();
        let mut p = DnsPlane::default();
        p.observe(c, s, &query(1, "x", 16), at(0));
        assert!(
            p.queries().is_empty(),
            "a TXT question is not a lookup of an endpoint"
        );
        for id in 0..QUERIES_HELD as u16 + 2 {
            p.observe(c, s, &query(id, "x", TYPE_A), at(usize::from(id)));
        }
        assert_eq!(p.queries().len(), QUERIES_HELD);
        assert_eq!(p.more(), 2);
    }

    /// THE CLAIM, through a capture: a name that resolved and the SYN that
    /// followed to its address, and a name that did not.
    #[cfg(all(feature = "fixtures", feature = "dissect"))]
    #[test]
    fn a_capture_names_an_nxdomain_and_links_an_answer_to_the_syn_after_it() {
        use crate::fixtures::{pcap_of, tcp_segment_flagged, udp_datagram};
        const ROUTER: [u8; 4] = [10, 0, 0, 2];
        let packets = vec![
            udp_datagram(CLIENT, 40_001, RESOLVER, 53, &query(9, "nope.lan", TYPE_A)),
            udp_datagram(
                RESOLVER,
                53,
                CLIENT,
                40_001,
                &response(9, "nope.lan", TYPE_A, 3, &[]),
            ),
            udp_datagram(
                CLIENT,
                40_002,
                RESOLVER,
                53,
                &query(10, "router.lan", TYPE_A),
            ),
            udp_datagram(
                RESOLVER,
                53,
                CLIENT,
                40_002,
                &response(10, "router.lan", TYPE_A, 0, &[(TYPE_A, ROUTER.to_vec())]),
            ),
            tcp_segment_flagged(CLIENT, 40_000, ROUTER, 7447, 1_000, 0x02, &[]),
        ];
        let file = pcap_of(&packets);
        let d = crate::Dissection::from_capture(&file).expect("the capture reads");
        assert_eq!(d.dns().queries().len(), 2);
        let doc = crate::fields_json::fields_json(&d, &file, None, None);
        assert!(
            doc.contains(
                "{\"name\":\"nope.lan\",\"qtype\":\"a\",\"mdns\":false,\
                 \"asker\":{\"addr\":\"10.0.0.1\",\"port\":40001},\
                 \"server\":{\"addr\":\"10.0.0.53\",\"port\":53},\"query_packet\":0,"
            ),
            "{doc}"
        );
        assert!(
            doc.contains(
                "\"answered\":true,\"answer_packet\":1,\"answer_ns\":1000001000,\
                 \"rcode\":\"nxdomain\",\"rcode_number\":3,\"addresses\":[]"
            ),
            "{doc}"
        );
        assert!(
            doc.contains(
                "\"addresses\":[{\"addr\":\"10.0.0.2\",\"target\":null,\"port\":null,\
                 \"ttl_s\":60,\"connected\":{\"syn_packet\":4,\"port\":7447}}]"
            ),
            "{doc}"
        );
    }

    #[test]
    fn a_truncated_or_looping_message_is_not_read() {
        let full = response(1, "router.local", TYPE_A, 0, &[(TYPE_A, vec![10, 0, 0, 2])]);
        for cut in 0..full.len() {
            assert!(parse(&full[..cut]).is_none(), "cut at {cut}");
        }
        // A name whose pointer points at itself.
        let mut looping = query(1, "a", TYPE_A);
        looping.truncate(12);
        looping.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(parse(&looping).is_none());
    }
}
