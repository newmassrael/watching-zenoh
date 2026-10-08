// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VERDICT of a selector over the rows of the field document, and
//! nothing else.
//!
//! # What was missing, in the consumer's numbers
//!
//! A consumer narrowing a message list with a selector needs, per row, only
//! the four coordinates that join the row to a record and the word the
//! selector said about it. The only door that gave it was the field document,
//! which renders every row's whole tree, carried state and session verdicts
//! beside those five values. Measured by the consumer on a synthetic capture
//! of 25,360 rows: the door took 171 ms, the document was 58 MB, and reading
//! it took the consumer 1.5 s — paid on every chip toggle, against the 0.1 to
//! 0.2 s its own evaluator had taken before it was retired in favour of this
//! library's.
//!
//! This document is those five values per row. The verdict is the SAME one
//! (`row_verdict_of` in `fields_json` is called by both renderers), the
//! coordinates are the SAME ones, and the rows are the field document's rows in
//! the same order, with the two differences stated below.
//!
//! # The order of the rows
//!
//! Rows are grouped by flow, stream flows first and then datagram flows, each
//! flow's scouting rows after its transport rows. Within a stream flow they are
//! in CAPTURE order since revision 3: the packet that carried the row's first
//! byte, then its place in that packet, which is
//! [`crate::FlowDissection::capture_order`] and is the order the field document
//! writes the same flow's `messages` in. It was the order the session decoded
//! the messages in before, which is the order their last bytes arrived in, and
//! the two parted whenever a message completed after one that began later. A
//! datagram flow's rows were always in capture order: a datagram is one packet.
//!
//! The key is total, so the order is deterministic and never depends on how many
//! `drain` calls the rows' records arrived in or on any hashing: no two rows of
//! a flow share a packet and a place.
//!
//! # Where its rows differ from the field document's
//!
//! Both are the field document's limitation and not this one's.
//!
//! * The field document renders a datagram row only when it can re-read the
//!   packet from the capture container and the second read agrees with the
//!   first. This document does not need the packet at all — the verdict is
//!   decided by the record plane, not by a re-walk of the bytes — so it has a
//!   row for every frame the dissection framed, and takes no container. A
//!   handle fed by `push`, which has no container, therefore gets datagram
//!   verdicts here that it cannot get from the field document.
//! * Neither renders a recovered QUIC stream or a serial line: those lists have
//!   no row in the field document, and this one is the field document's rows.
//!
//! # An empty selector is the identity, here as everywhere
//!
//! It asks nothing, so it says nothing: rows carry their coordinates and no
//! `selected` key. That is the field document's rule for the same argument,
//! and the rule a consumer already holds for every census plane; a verdict
//! document that answered `yes` to everything under an empty selector would be
//! the one door in the family where "no selector" and "the selector that
//! matches all" differ.
//!
//! # What a row says under a selector, and which rows say nothing
//!
//! A row's `kind` is the kind of what it carries, from the classifier every
//! plane shares: a `Push` is `put` or `del`; a `Request` is its body's kind
//! (`query` for every request upstream sends, because its request body has the
//! one variant `Query`:
//! `commons/zenoh-protocol/src/zenoh/mod.rs` @ `pub enum RequestBody`
//! and its reader refuses any other message id:
//! `commons/zenoh-codec/src/zenoh/mod.rs` @ `id::QUERY => RequestBody::Query`
//! while a request this reader decodes with a put or a del body takes that
//! kind); a `Response` is `reply` whatever the reply carries, or `err`.
//!
//! A `ResponseFinal` has no kind of its own. It FOLLOWS ITS EXCHANGE: it closes
//! the `Request` with the same request id, and it answers every selector as that
//! request does, so `kind == query` is `yes` on it and `kind == put` is `no`
//! when the request was a query. A `Request` and its `ResponseFinal` are one
//! exchange judged once, so the outcome terms (`replies`, `closed`,
//! `completion`) decide on those two rows and on no other.
//!
//! A `ResponseFinal` whose request the capture does not hold (it began
//! mid-exchange) is `unjudged`, not `no`: nothing was asked of it. So are `Init`,
//! `Open`, `Close`, `KeepAlive`, `Declare` and `Interest`, which carry no kind,
//! keyexpr or payload, under every selector.
//!
//! These rows used to read `unjudged` under every selector, because the verdict
//! was a by-product of the walk that inspects payloads and a `Query`, a `Del`
//! and a `ResponseFinal` have none. The exchange plane counted seven queries in
//! a capture whose seven request rows said `unjudged`; the two planes now agree
//! for any selector, on a capture where each row carries one record: the `yes`
//! request rows are the exchange plane's `requests` and the `yes` closes its
//! `completed`. See [`crate::fields_json`]'s `RowJudgement` for who judges which
//! record.
//!
//! # The ceilings
//!
//! `dropped_by_limits` is the SAME group the field document and the census
//! carry, for the reason the field document gives: a row the walk never reached
//! is ABSENT rather than unmatched, and a consumer counting "three matched"
//! needs to be told the list it counted in was made short.

use alloc::string::String;
use core::fmt::Write as _;

use crate::census_json::dir_name;
use crate::fields_json::{judged_by, row_verdict_of, RenderedLists, RowCoordinates, RowVerdict};

/// One row: the coordinates a record joins on, and the selector's word when a
/// selector was asked.
///
/// `list_id` is `None` for a list the caller does not number, and then the row
/// carries no coordinate keys at all, on the field document's own rule that a
/// key is never invented. `verdict` is `None` when no selector was asked.
fn push_row(
    direction: &str,
    list_id: Option<u64>,
    anchor: u64,
    batch_index: u64,
    verdict: Option<RowVerdict>,
    first: &mut bool,
    out: &mut String,
) {
    if !*first {
        out.push(',');
    }
    *first = false;
    let _ = write!(out, "{{\"direction\":\"{direction}\"");
    if let Some(list_id) = list_id {
        let _ = write!(
            out,
            ",\"list_id\":{list_id},\"anchor\":{anchor},\"batch_index\":{batch_index}"
        );
    }
    if let Some(verdict) = verdict {
        let _ = write!(out, ",\"selected\":\"{}\"", verdict.word());
    }
    out.push('}');
}

/// The selector's verdict over every row of the field document, with each row
/// carrying the coordinates of a record door that shares this dissection.
///
/// `coordinates` is the caller's numbering, exactly as
/// `fields_json_where_coordinated` takes it: this crate renders rows and does
/// not mint the ids a handle in another crate publishes.
pub fn selection_json_where_coordinated(
    d: &crate::Dissection,
    filter: &crate::filter::Filter,
    coordinates: &dyn RowCoordinates,
) -> String {
    let grouping = crate::node::session_grouping(d);
    // No question, no walk: an empty selector is the identity and judges nothing,
    // so it pays nothing either. The rule lives in `judged_by`, which the field
    // document asks too.
    let verdicts = judged_by(d, filter, &grouping);
    let lists = RenderedLists::of(d);
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTION, &mut out);
    out.push_str(",\"rows\":[");
    let mut first = true;

    for (i, flow) in d.flows().iter().enumerate() {
        let list = lists.stream.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        // CAPTURE order, the field document's own: see
        // `FlowDissection::capture_order`. One function orders the rows of both
        // documents, so "the same rows in the same order" is a property of the
        // code and not of two walks agreeing.
        for position in flow.capture_order() {
            let frame = &flow.frames[position];
            let verdict = match (verdicts.as_ref(), list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            push_row(
                dir_name(frame.direction),
                list_id,
                frame.stream_offset as u64,
                frame.batch_index as u64,
                verdict,
                &mut first,
                &mut out,
            );
        }
    }

    for (i, flow) in d.datagram_flows().iter().enumerate() {
        let list = lists.datagram.get(i).copied();
        let list_id = list.and_then(|l| coordinates.list_id(l));
        for frame in &flow.frames {
            let verdict = match (verdicts.as_ref(), list) {
                (Some(census), Some(list)) => Some(row_verdict_of(census, list, frame)),
                _ => None,
            };
            // `stream_offset` names the PACKET on a datagram link, the only anchor
            // there is, as the field document's own row says.
            push_row(
                dir_name(frame.direction),
                list_id,
                frame.stream_offset as u64,
                frame.batch_index as u64,
                verdict,
                &mut first,
                &mut out,
            );
        }
        // The scouting list, after the transport rows exactly as the field
        // document orders them. A scouting message carries no payload for the
        // record plane to judge, so under a selector it is unjudged BY
        // CONSTRUCTION and says so directly, on the field document's argument.
        let scouting_id = coordinates.scouting_list_id(&flow.flow);
        for datagram in &flow.scouting {
            let verdict = match (verdicts.as_ref(), list) {
                (Some(_), Some(_)) => Some(RowVerdict::Unjudged),
                _ => None,
            };
            push_row(
                dir_name(datagram.direction),
                scouting_id,
                datagram.packet_index as u64,
                0,
                verdict,
                &mut first,
                &mut out,
            );
        }
    }

    out.push_str("],\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

/// The captures and the reading of them that the rows below are held to.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datagram_tests::{
        frame_carrying, init_datagram, open_datagram, sender_space, udp_packet,
    };
    use crate::exchange::tests::{
        declare_kexpr, has_suffix, request_put, request_query, response_final, response_reply,
    };
    use crate::fields_json::RowCoordinates;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use alloc::vec::Vec;
    use wz_codecs::wire_const::FLAG_N_N;
    use wz_codecs::wireexpr::Wireexpr;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// A numbering that numbers every list, standing in for a handle's.
    struct EveryListNumbered;

    impl RowCoordinates for EveryListNumbered {
        fn list_id(&self, list: usize) -> Option<u64> {
            Some(list as u64)
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            None
        }
    }

    fn key(literal: &'static str) -> Wireexpr<'static> {
        sender_space(0, Some(literal))
    }

    /// A `Push` carrying a `MsgDel` under `keyexpr`.
    fn push_del(keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgDel(
                wz_codecs::msg_del::MsgDel::default(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// A `Response` whose `Reply` carries a `MsgDel` rather than a put.
    fn response_reply_del(request_id: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::response::Response {
            header: wz_codecs::response::Response::default().header | n,
            request_id,
            keyexpr,
            body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
                body: wz_codecs::reply::ReplyVariant::CodecZenohMsgDel(
                    wz_codecs::msg_del::MsgDel::default(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// The transport `Close`, bare.
    fn close_wire() -> Vec<u8> {
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_CLOSE];
        wire.extend_from_slice(&wz_codecs::close::Close { reason: 0x01 }.encode_to_vec());
        wire
    }

    /// One packet of the contract capture, in capture order: what it is called
    /// here, who sent it (`true` is the low address, direction A), and the record
    /// or transport message it carries.
    ///
    /// Every network record is framed in its OWN transport frame, so a row and a
    /// record are the same thing in this capture and a row's word is that one
    /// record's. The fold over several records in one row is a different
    /// claim, tested where a row is built to carry several.
    fn packets() -> Vec<(&'static str, bool, Vec<u8>)> {
        let framed = |record: Vec<u8>| frame_carrying(&record);
        alloc::vec![
            ("init-syn", true, init_datagram(false, &[])),
            ("init-ack", false, init_datagram(true, &[])),
            ("open-syn", true, open_datagram(false)),
            ("open-ack", false, open_datagram(true)),
            (
                "keepalive",
                true,
                alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE]
            ),
            ("declare", true, framed(declare_kexpr(1, "demo/declared"))),
            ("query-7", true, framed(request_query(7, key("demo/q")))),
            (
                "reply-7",
                false,
                framed(response_reply(7, key("demo/q"), b"answer"))
            ),
            ("final-7", false, framed(response_final(7))),
            (
                "push-put",
                true,
                framed(crate::datagram_tests::push(key("demo/p"), b"v"))
            ),
            ("push-del", true, framed(push_del(key("demo/p")))),
            (
                "request-put-8",
                true,
                framed(request_put(8, key("demo/p"), b"v"))
            ),
            ("final-8", false, framed(response_final(8))),
            // Two exchanges of DIFFERENT kinds open together and close in the
            // opposite order, then two more close in the order they opened: a
            // close that took its kind from the oldest exchange open, or from
            // the latest, would swap one of the pairs.
            ("query-9", true, framed(request_query(9, key("demo/q")))),
            (
                "request-put-10",
                true,
                framed(request_put(10, key("demo/p"), b"v"))
            ),
            ("final-10", false, framed(response_final(10))),
            ("final-9", false, framed(response_final(9))),
            ("query-12", true, framed(request_query(12, key("demo/q")))),
            (
                "request-put-13",
                true,
                framed(request_put(13, key("demo/p"), b"v"))
            ),
            ("final-12", false, framed(response_final(12))),
            ("final-13", false, framed(response_final(13))),
            // The request this final answers is not in the capture.
            ("final-99", false, framed(response_final(99))),
            // A query nothing closes, answered by a reply that carries a del.
            ("query-11", true, framed(request_query(11, key("demo/q")))),
            (
                "reply-del-11",
                false,
                framed(response_reply_del(11, key("demo/q")))
            ),
            ("close", true, close_wire()),
        ]
    }

    /// The names of [`packets`], in order.
    pub(crate) fn labels() -> Vec<&'static str> {
        packets().into_iter().map(|(label, _, _)| label).collect()
    }

    /// The capture: one UDP conversation, a packet every 10 ms, and the file
    /// those packets make (the field document re-reads it).
    pub(crate) fn mixed_session_with_file() -> (Dissection, Vec<u8>) {
        let wires: Vec<Vec<u8>> = packets()
            .into_iter()
            .map(|(_, from_low, wire)| {
                if from_low {
                    udp_packet(LOW, 43210, HIGH, 7447, &wire)
                } else {
                    udp_packet(HIGH, 7447, LOW, 43210, &wire)
                }
            })
            .collect();
        let rows: Vec<(u32, u32, &[u8])> = wires
            .iter()
            .enumerate()
            .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
            .collect();
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &rows);
        let d = Dissection::from_capture(&file).expect("the capture reads");
        (d, file)
    }

    /// The selection document's word for every row of `d`, one letter each:
    /// `Y` yes, `N` no, `?` undecided, `U` unjudged.
    pub(crate) fn letters(d: &Dissection, selector: &str) -> String {
        let filter = crate::filter::Filter::parse(selector).expect("the selector parses");
        let doc = selection_json_where_coordinated(d, &filter, &EveryListNumbered);
        doc.split("\"selected\":\"")
            .skip(1)
            .map(|rest| match rest.split('"').next() {
                Some("yes") => 'Y',
                Some("no") => 'N',
                Some("undecided") => '?',
                Some("unjudged") => 'U',
                other => panic!("{selector}: an unknown word {other:?} in {doc}"),
            })
            .collect()
    }

    /// Say which packets differ, by name, rather than leaving two strings of
    /// letters to be lined up by eye.
    fn assert_rows(selector: &str, expected: &str, got: &str) {
        let names = labels();
        assert_eq!(
            expected.chars().count(),
            names.len(),
            "{selector}: the table must have one letter per packet"
        );
        assert_eq!(
            got.chars().count(),
            names.len(),
            "{selector}: one row per packet, or the capture is not the one the table describes: {got}"
        );
        let wrong: Vec<String> = names
            .iter()
            .zip(expected.chars().zip(got.chars()))
            .filter(|(_, (want, have))| want != have)
            .map(|(name, (want, have))| alloc::format!("{name}: wanted {want}, got {have}"))
            .collect();
        assert!(
            wrong.is_empty(),
            "{selector}: {wrong:#?}\n  wanted {expected}\n  got    {got}"
        );
    }

    /// THE REPRODUCTION, AND THE KIND CONTRACT ROW BY ROW.
    ///
    /// Each line is one selector over the one capture above, and each letter is
    /// the packet of the same position in [`packets`]: the first six are the
    /// transport and the declaration, which carry no kind and stay `U` under
    /// every selector, and the last is the `Close`.
    ///
    /// The consumer's defect is the `Y` at `query-7`: the row was `U`, with every
    /// request and every close of a query, a `Push` carrying a del, and a `Reply`
    /// carrying one. The `N` at `final-8` is the other half of the contract: a
    /// close FOLLOWS ITS EXCHANGE, so under `kind == query` the close of a put
    /// exchange is `no`, not unjudged.
    #[test]
    fn a_request_a_response_final_and_every_reply_are_judged_by_the_kind_they_carry() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("kind == query", "UUUUUUYNYNNNNYNNYYNYNUYNU"),
            ("kind == put", "UUUUUUNNNYNYYNYYNNYNYUNNU"),
            ("kind == del", "UUUUUUNNNNYNNNNNNNNNNUNNU"),
            ("not kind == put", "UUUUUUYYYNYNNYNNYYNYNUYYU"),
            ("kind == reply", "UUUUUUNYNNNNNNNNNNNNNUNYU"),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// A CLOSE ANSWERS EVERY FIELD AS THE EXCHANGE IT TERMINATES DOES, not only
    /// `kind`.
    ///
    /// A `ResponseFinal` names no keyexpr and no kind, so under `key ==` it could
    /// only ever have been unjudged or wrongly `no`; it carries the exchange's
    /// verdict instead, and the exchange's `dir` is its requester's, as it is on
    /// the exchange plane (`crate::exchange::OpenExchange::direction`). The
    /// replies are records and answer for themselves: `reply-7` is `N` under
    /// `dir == a` because B sent it, while `final-7`, B's close of A's query, is
    /// `Y`.
    #[test]
    fn a_response_final_answers_every_field_as_the_exchange_it_terminates() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("key == demo/p", "UUUUUUNNNYYYYNYYNNYNYUNNU"),
            ("dir == a", "UUUUUUYNYYYYYYYYYYYYYUYNU"),
            ("kind == query or kind == del", "UUUUUUYNYNYNNYNNYYNYNUYNU"),
            (
                "kind == query and key == demo/p",
                "UUUUUUNNNNNNNNNNNNNNNUNNU",
            ),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// THE OUTCOME TERMS DECIDE ON THE ROWS OF AN EXCHANGE AND ONLY THERE.
    ///
    /// `replies`, `closed` and `completion` are properties of how an exchange
    /// turned out, so the two rows that are its ends can answer them and a
    /// record cannot: a `Push` and a `Reply` read `?` under `replies == 0`, the
    /// word for "the capture does not carry what deciding needs", and not `N`.
    /// `query-11` is unclosed and `final-99` is an orphan: the first is `Y`
    /// under `closed == no`, and the second has no exchange to be an end of.
    #[test]
    fn the_outcome_terms_decide_on_the_rows_of_an_exchange_and_nowhere_else() {
        let (d, _) = mixed_session_with_file();
        for (selector, expected) in [
            ("replies == 0", "UUUUUUN?N??YYYYYYYYYYUN?U"),
            ("closed == no", "UUUUUUN?N??NNNNNNNNNNUY?U"),
            (
                "kind == query and replies == 0",
                "UUUUUUNNNNNNNYNNYYNYNUNNU",
            ),
        ] {
            assert_rows(selector, expected, &letters(&d, selector));
        }
    }

    /// A `Request` with a `Del` body, which no zenoh peer sends (upstream's
    /// request body is a query and nothing else) and this reader's codec
    /// decodes, so the dissection classifies it by its body.
    fn request_del(rid: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let n = if has_suffix(&keyexpr) { FLAG_N_N } else { 0 };
        wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | n,
            rid,
            keyexpr,
            body: wz_codecs::request::RequestVariant::CodecZenohMsgDel(
                wz_codecs::msg_del::MsgDel::default(),
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// What a generated packet is to the exchange plane.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Role {
        /// The `Request` that opens an exchange.
        Request,
        /// A `ResponseFinal` that closes an exchange the capture opened.
        Close,
        /// A `ResponseFinal` whose request the capture never carried.
        Orphan,
        /// A record that is no end of an exchange: a push or a reply.
        Other,
    }

    /// A small deterministic generator, so a failing capture is rebuilt by its
    /// seed.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// What `crate::exchange::tests::dissect` takes: for each record, who sent
    /// it, when, and its bytes.
    type Records = Vec<(bool, Option<u64>, Vec<u8>)>;

    /// A capture of forty network records chosen by `seed`, with what each one is
    /// to the exchange plane.
    ///
    /// Requests of the three kinds on a few keys, request ids drawn from a
    /// small range so one is sometimes opened again before it closed (the first
    /// exchange is then judged unclosed), replies and closes for open exchanges,
    /// closes of exchanges that were never opened, and pushes. Some exchanges are
    /// left open when the capture ends.
    fn generated(seed: u64) -> (Records, Vec<Role>) {
        let keys = ["demo/a", "demo/b", "other/c"];
        let mut rng = Lcg(seed);
        // Which of the request ids 1..=6 an exchange is open under.
        let mut is_open = [false; 7];
        let mut records = Vec::new();
        let mut roles = Vec::new();
        for step in 0..40u64 {
            let at = Some(1_000 + step * 7);
            let pick = rng.below(10);
            let open: Vec<u64> = (1..=6).filter(|rid| is_open[*rid as usize]).collect();
            if pick <= 3 {
                let rid = 1 + rng.below(6);
                let at_key = key(keys[rng.below(3) as usize]);
                let wire = match rng.below(3) {
                    0 => request_query(rid, at_key),
                    1 => request_put(rid, at_key, b"v"),
                    _ => request_del(rid, at_key),
                };
                is_open[rid as usize] = true;
                records.push((true, at, wire));
                roles.push(Role::Request);
            } else if pick <= 5 && !open.is_empty() {
                let rid = open[rng.below(open.len() as u64) as usize];
                let at_key = key(keys[rng.below(3) as usize]);
                records.push((false, at, response_reply(rid, at_key, b"r")));
                roles.push(Role::Other);
            } else if pick <= 7 && !open.is_empty() {
                let rid = open[rng.below(open.len() as u64) as usize];
                is_open[rid as usize] = false;
                records.push((false, at, response_final(rid)));
                roles.push(Role::Close);
            } else if pick == 8 {
                records.push((false, at, response_final(90 + rng.below(5))));
                roles.push(Role::Orphan);
            } else {
                let at_key = key(keys[rng.below(3) as usize]);
                let wire = if rng.below(2) == 0 {
                    crate::datagram_tests::push(at_key, b"p")
                } else {
                    push_del(at_key)
                };
                records.push((true, at, wire));
                roles.push(Role::Other);
            }
        }
        (records, roles)
    }

    /// THE TWO PLANES COUNT THE SAME EXCHANGES, FOR ANY SELECTOR, ON ANY CAPTURE.
    ///
    /// The invariant that was broken: the exchange plane counted seven queries in
    /// a capture whose seven request rows the row plane left unjudged. Held on the
    /// capture the contract tests read and on forty generated ones, against
    /// selectors on the kind, the key, the direction and the outcome:
    ///
    /// * the `yes` rows of `Request` records are `ExchangeTable::requests`, and
    ///   their `no` and `undecided` rows are `Selection::rejected` and
    ///   `Selection::undecided`;
    /// * the `yes` rows of closing `ResponseFinal` records are
    ///   `ExchangeTable::completed`;
    /// * a `ResponseFinal` the capture never opened is `unjudged`, not `no`.
    ///
    /// The count of ROWS and the count of EXCHANGES agree here because each
    /// packet carries one record. A row built to carry several folds them, and
    /// `a_row_carrying_a_push_and_a_request_folds_what_both_planes_said` holds
    /// that.
    #[test]
    fn the_row_plane_and_the_exchange_plane_count_the_same_exchanges_for_any_selector() {
        let selectors = [
            "kind == query",
            "kind == put",
            "kind == del",
            "not kind == put",
            "kind == reply",
            "key == demo/a",
            "key == demo/**",
            "dir == a",
            "dir == b",
            "kind == query and key == demo/b",
            "kind == query or kind == del",
            "replies == 0",
            "replies >= 1",
            "closed == no",
            "closed == yes",
            "kind == put and completion >= 14",
            "bytes > 0",
            "first_reply >= 0",
        ];
        let mut captures: Vec<(Dissection, Vec<Role>)> = Vec::new();
        for seed in 0..40 {
            let (records, roles) = generated(seed);
            captures.push((crate::exchange::tests::dissect(&records), roles));
        }
        let mut closes_counted = 0usize;
        let mut unclosed_counted = 0usize;
        let mut orphans_seen = 0usize;
        let mut undecided_counted = 0usize;
        for (seed, (d, roles)) in captures.iter().enumerate() {
            for selector in selectors {
                let filter = crate::filter::Filter::parse(selector).expect("parses");
                let table = crate::exchange::exchanges_where(d, &filter);
                let rows: Vec<char> = letters(d, selector).chars().collect();
                assert_eq!(rows.len(), roles.len(), "seed {seed}: one row per record");

                let count = |role: Role, word: char| {
                    rows.iter()
                        .zip(roles)
                        .filter(|(have, is)| **is == role && **have == word)
                        .count()
                };
                assert_eq!(
                    count(Role::Request, 'Y'),
                    table.requests(),
                    "seed {seed}, {selector}: yes request rows against exchanges counted"
                );
                assert_eq!(
                    count(Role::Request, 'N'),
                    table.selection().rejected,
                    "seed {seed}, {selector}: no request rows against exchanges rejected"
                );
                assert_eq!(
                    count(Role::Request, '?'),
                    table.selection().undecided,
                    "seed {seed}, {selector}: undecided request rows against exchanges undecided"
                );
                assert_eq!(
                    count(Role::Close, 'Y'),
                    table.completed(),
                    "seed {seed}, {selector}: yes close rows against exchanges completed"
                );
                assert_eq!(
                    count(Role::Orphan, 'U'),
                    roles.iter().filter(|r| **r == Role::Orphan).count(),
                    "seed {seed}, {selector}: an orphan close is unjudged under every selector"
                );
                closes_counted += table.completed();
                unclosed_counted += table.unclosed();
                undecided_counted += table.selection().undecided;
                orphans_seen += count(Role::Orphan, 'U');
            }
        }
        // Anti-vacuity: the population exercised closed exchanges, exchanges the
        // capture never closed, orphans, and a selector the exchange plane could
        // not decide; the equalities above were not satisfied by zeros.
        assert!(
            closes_counted > 100,
            "closed exchanges counted: {closes_counted}"
        );
        assert!(
            unclosed_counted > 50,
            "unclosed exchanges counted: {unclosed_counted}"
        );
        assert!(orphans_seen > 100, "orphan closes judged: {orphans_seen}");
        assert!(
            undecided_counted > 0,
            "undecided exchanges: {undecided_counted}"
        );
    }

    /// The same equalities on the capture the contract tests read, which has the
    /// shapes a generator draws only by chance: a close that follows another
    /// exchange's close, two exchanges of different kinds open together, and a
    /// `Reply` that carries a `Del`.
    #[test]
    fn the_two_planes_agree_on_the_contract_capture_too() {
        let (d, _) = mixed_session_with_file();
        let roles: Vec<Role> = labels()
            .into_iter()
            .map(|label| match label {
                l if l.starts_with("query-") || l.starts_with("request-put-") => Role::Request,
                "final-99" => Role::Orphan,
                l if l.starts_with("final-") => Role::Close,
                _ => Role::Other,
            })
            .collect();
        for selector in [
            "kind == query",
            "kind == put",
            "kind == del",
            "key == demo/p",
            "dir == a",
            "replies == 0",
            "closed == no",
        ] {
            let filter = crate::filter::Filter::parse(selector).expect("parses");
            let table = crate::exchange::exchanges_where(&d, &filter);
            let rows: Vec<char> = letters(&d, selector).chars().collect();
            let count = |role: Role| {
                rows.iter()
                    .zip(&roles)
                    .filter(|(have, is)| **is == role && **have == 'Y')
                    .count()
            };
            assert_eq!(count(Role::Request), table.requests(), "{selector}");
            assert_eq!(count(Role::Close), table.completed(), "{selector}");
        }
    }

    /// A ROW THAT CARRIES RECORDS OF BOTH PLANES FOLDS WHAT BOTH SAID.
    ///
    /// One frame holding a `Push` (judged as a record) and a `Request` (judged as
    /// an exchange), so the row has a verdict from each plane. Any yes makes the
    /// row yes, all no makes it no, and anything else is undecided: the rule the
    /// consumer set, applied across the two planes as it is within one.
    ///
    /// The last two lines are the ones that need both: `replies == 1` is `no` for
    /// the request and unknown for the push, and a fold that dropped the
    /// exchange's `no` (or the push's unknown) would call the row `N` (or `Y`).
    #[test]
    fn a_row_carrying_a_push_and_a_request_folds_what_both_planes_said() {
        let mut record = crate::datagram_tests::push(key("demo/p"), b"v");
        record.extend_from_slice(&request_query(5, key("demo/q")));
        let d = crate::exchange::tests::dissect(&[(true, Some(1_000), record)]);
        for (selector, expected) in [
            ("kind == put", "Y"),
            ("kind == query", "Y"),
            ("kind == del", "N"),
            ("key == nothing/here", "N"),
            ("replies == 0", "Y"),
            ("replies == 1", "?"),
            ("closed == yes", "?"),
        ] {
            assert_eq!(letters(&d, selector), expected, "{selector}");
        }
    }
}
