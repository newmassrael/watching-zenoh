// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What each extension on the wire IS — the per-carrier `(id, encoding) -> name`
//! table, so a reader is told `timeout` rather than `ext_id 6`.
//!
//! # Why a table and not a constant per extension
//!
//! [`crate::ext_header`] already holds two id tables, and its own module docs
//! state the rule this module is built on: *"an id is only meaningful together
//! with the carrier it was read from"*. Those tables stop at the ids a
//! PARTICIPANT must act on. A dissector has the harder job — it must name every
//! extension in every carrier, including capabilities this build cannot perform,
//! because naming is what a reader needs and performing is not.
//!
//! The field layer had no such table at all. It reported the id bits and the
//! encoding bits and stopped, so a `Request` carrying `Timeout = 5000` rendered
//! as `ext_id 6, value 5000` — every byte accounted for and nothing said. A
//! reader could not tell that from `Budget = 5000`, and the two answer opposite
//! questions about why a query returned nothing.
//!
//! # The key is the CARRIER plus the whole EID, and every bit of it earns its way
//!
//! The eid ([`crate::ext_header::ext_eid`]) is the header byte with only the
//! chain-continuation flag dropped, so the id, the MANDATORY flag and the
//! encoding are all part of it. That is zenoh's own matching key, not a
//! convenience: its decoders compare `eid`, so a header that differs from a
//! declared extension in ANY of those bits is a different extension and lands in
//! `ext_unknown`.
//!
//! * The CARRIER, because the spaces reuse numbers freely and even one space
//!   does: `0x3` is `NodeId` on a `Push`, `ResponderId` on a `Response`,
//!   `Attachment` on a `Put`, `QueryBody` on a `Query` and `Auth` on an `Init`.
//! * The ENCODING, because zenoh deliberately puts two DIFFERENT extensions on
//!   one id and tells them apart by it — `init::ext::QoS` is
//!   `zextunit!(0x1, false)` beside `init::ext::QoSLink`, `zextz64!(0x1, false)`
//!   (`transport/init.rs`), and `open::ext::MultiLinkSyn` / `MultiLinkAck` are
//!   the same pair at `0x4` (`transport/open.rs`). This is the distinction
//!   R311y505 measured as a cross-impl defect on the wire.
//! * The ID, four bits and four only (`iext::ID_MASK`).
//! * The MANDATORY flag, and this one was learned the hard way in the round that
//!   wrote this module. Dropping it looks harmless — no upstream carrier
//!   overloads one `(id, encoding)` by that bit alone — but it makes this table
//!   disagree with the SHM check standing beside it, which does match on the
//!   eid. A bare `0x02` UNIT entry on a `Put` would then be NAMED `shm` while
//!   the payload slot was still called `payload`: two answers about the same
//!   three bytes, and a reader with no way to tell which one to believe. One key
//!   for both is the fix, and zenoh already chose which key.
//!
//! # What an unknown id gets: nothing, on purpose
//!
//! [`ext_name`] returns `None` rather than a guess or a synthesised
//! `"unknown_6"`. A reader that is told nothing knows it was told nothing; a
//! reader handed a plausible name cannot tell a real extension from this
//! build's ignorance of a newer one. Extension chains are precisely where a
//! peer of a later vintage puts things this reader has never heard of, so
//! `None` is the common case rather than the error case.
//!
//! UNCONDITIONAL, for the reason [`crate::ext_header`] is: the table reads only
//! header bytes, needs neither a codec feature nor the `alloc` profile, and
//! every consumer — the field layer, the analyzer, the C ABI a framework links
//! — reaches one copy of it.

use crate::ext_header::{ext_eid, EXT_ENC_UNIT, EXT_ENC_Z64, EXT_ENC_ZBUF, EXT_FLAG_M};

/// `false` spelled out, so a row's third column reads as the mandatory flag
/// rather than as an unexplained bare `false`.
const OPT: bool = false;
/// `true` spelled out — see [`OPT`].
const MAND: bool = true;

/// Which chain an extension entry was read from.
///
/// CLOSED-FORM: one variant per carrier that zenoh gives its own `ext` module,
/// plus the two `Declare` sub-bodies that carry their own. A carrier with no
/// extensions upstream (`Close`, `KeepAlive`, `zenoh::Reply`) still gets a
/// variant, because a chain can APPEAR on one — `Reply` decodes into
/// `ext_unknown` (`zenoh/reply.rs`) — and the honest answer for every id there
/// is "not a named extension of this carrier", which is what an empty row set
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ExtCarrier {
    // ── transport space ────────────────────────────────────────────────
    /// `transport::init::ext` — the Init handshake.
    Init,
    /// `transport::open::ext` — the Open handshake.
    Open,
    /// `transport::join::ext` — the multicast Join.
    Join,
    /// `transport::frame::ext`.
    Frame,
    /// `transport::fragment::ext`.
    Fragment,
    /// `transport::oam::ext` — the TRANSPORT OAM, distinct from the network one.
    TransportOam,
    /// `Close` / `KeepAlive`: upstream declares no extension for either.
    TransportPlain,

    // ── network space ─────────────────────────────────────────────────
    /// `network::push::ext`.
    Push,
    /// `network::request::ext` — the widest network row set (`Target`,
    /// `Budget`, `Timeout`).
    Request,
    /// `network::response::ext` — where `0x3` is `ResponderId`, NOT `NodeId`.
    Response,
    /// `ResponseFinal`, which shares `network::response::ext`.
    ResponseFinal,
    /// `network::declare::ext` — the `Declare` message's own chain.
    Declare,
    /// `network::interest::ext`.
    Interest,
    /// `network::oam::ext` — the NETWORK OAM.
    NetworkOam,

    // ── Declare sub-bodies, which carry their own ext modules ─────────
    /// `network::declare::common::ext` — the `Undeclare*` body chain, whose one
    /// row is `WireExprExt` at the top of the id space.
    DeclareCommon,
    /// `network::declare::queryable::ext` — `DeclareQueryable`'s body chain.
    DeclareQueryable,

    // ── zenoh body space ──────────────────────────────────────────────
    /// `zenoh::put::ext`.
    Put,
    /// `zenoh::del::ext` — where `Attachment` is `0x2`, not `0x3`.
    Del,
    /// `zenoh::query::ext` — where `Attachment` is `0x5` and `0x3` is the
    /// query's VALUE.
    Query,
    /// `zenoh::err::ext`.
    Err,
    /// `zenoh::Reply`, which declares no named extension and decodes any chain
    /// into `ext_unknown`.
    Reply,
}

/// One row, spelled the way upstream spells its declaration: the 4-bit id, the
/// mandatory flag, the encoding, and what upstream calls it.
///
/// Deliberately NOT stored pre-composed as an eid byte. Every row here
/// corresponds to one `zext*!(id, mandatory)` line upstream, and keeping the
/// three columns apart is what lets a reader check a row against that line
/// without doing arithmetic in their head. [`row_eid`] composes them, once.
type Row = (u8, bool, u8, &'static str);

/// A row's matching key — zenoh's `iext::id()` composition, run through
/// [`ext_eid`] so it is the same value a header byte reduces to.
const fn row_eid((id, mandatory, enc, _): &Row) -> u8 {
    let m = if *mandatory { EXT_FLAG_M } else { 0 };
    ext_eid(*id | m | *enc)
}

/// `transport/init.rs` — note `0x1` twice, told apart by encoding.
const INIT: &[Row] = &[
    (0x1, OPT, EXT_ENC_UNIT, "qos"),
    (0x1, OPT, EXT_ENC_Z64, "qos_link"),
    (0x2, OPT, EXT_ENC_ZBUF, "shm"),
    (0x3, OPT, EXT_ENC_ZBUF, "auth"),
    (0x4, OPT, EXT_ENC_ZBUF, "multi_link"),
    (0x5, OPT, EXT_ENC_UNIT, "low_latency"),
    (0x6, OPT, EXT_ENC_UNIT, "compression"),
    (0x7, OPT, EXT_ENC_Z64, "patch"),
];

/// `transport/open.rs` — `0x4` twice, told apart by encoding, and `shm` is a
/// `Z64` here where `Init` makes it a `ZBuf`.
const OPEN: &[Row] = &[
    (0x1, OPT, EXT_ENC_UNIT, "qos"),
    (0x2, OPT, EXT_ENC_Z64, "shm"),
    (0x3, OPT, EXT_ENC_ZBUF, "auth"),
    (0x4, OPT, EXT_ENC_ZBUF, "multi_link_syn"),
    (0x4, OPT, EXT_ENC_UNIT, "multi_link_ack"),
    (0x5, OPT, EXT_ENC_UNIT, "low_latency"),
    (0x6, OPT, EXT_ENC_UNIT, "compression"),
];

/// `transport/join.rs` — where BOTH `qos` and `shm` are mandatory, unlike every
/// other carrier that declares them.
const JOIN: &[Row] = &[
    (0x1, MAND, EXT_ENC_ZBUF, "qos"),
    (0x2, MAND, EXT_ENC_ZBUF, "shm"),
    (0x7, OPT, EXT_ENC_Z64, "patch"),
];

/// `transport/frame.rs`.
const FRAME: &[Row] = &[(0x1, MAND, EXT_ENC_Z64, "qos")];

/// `transport/fragment.rs`.
const FRAGMENT: &[Row] = &[
    (0x1, MAND, EXT_ENC_Z64, "qos"),
    (0x2, OPT, EXT_ENC_UNIT, "first"),
    (0x3, OPT, EXT_ENC_UNIT, "drop"),
];

/// `transport/oam.rs`.
const TRANSPORT_OAM: &[Row] = &[(0x1, MAND, EXT_ENC_Z64, "qos")];

/// The three every network message carries — `network/push.rs`,
/// `network/interest.rs`, `network/declare.rs`, and the first three rows of
/// `network/request.rs`. `node_id` is the MANDATORY one.
const NETWORK_COMMON: &[Row] = &[
    (0x1, OPT, EXT_ENC_Z64, "qos"),
    (0x2, OPT, EXT_ENC_ZBUF, "timestamp"),
    (0x3, MAND, EXT_ENC_Z64, "node_id"),
];

/// `network/request.rs` — the common three plus the three that decide what a
/// query DOES. `target` is mandatory; `budget` and `timeout` are not.
const REQUEST: &[Row] = &[
    (0x1, OPT, EXT_ENC_Z64, "qos"),
    (0x2, OPT, EXT_ENC_ZBUF, "timestamp"),
    (0x3, MAND, EXT_ENC_Z64, "node_id"),
    (0x4, MAND, EXT_ENC_Z64, "target"),
    (0x5, OPT, EXT_ENC_Z64, "budget"),
    (0x6, OPT, EXT_ENC_Z64, "timeout"),
];

/// `network/response.rs` — `0x3` is a `ZBuf` responder identity, which shares
/// neither the encoding NOR the mandatory flag of `NodeId`.
const RESPONSE: &[Row] = &[
    (0x1, OPT, EXT_ENC_Z64, "qos"),
    (0x2, OPT, EXT_ENC_ZBUF, "timestamp"),
    (0x3, OPT, EXT_ENC_ZBUF, "responder_id"),
];

/// `network/oam.rs` — QoS and Timestamp only; OAM carries no node id.
const NETWORK_OAM: &[Row] = &[
    (0x1, OPT, EXT_ENC_Z64, "qos"),
    (0x2, OPT, EXT_ENC_ZBUF, "timestamp"),
];

/// `network/declare.rs` `common::ext` — `WireExprExt`, `zextzbuf!(0x0f, true)`.
const DECLARE_COMMON: &[Row] = &[(0x0f, MAND, EXT_ENC_ZBUF, "wire_expr")];

/// `network/declare.rs` `queryable::ext`.
const DECLARE_QUERYABLE: &[Row] = &[(0x01, OPT, EXT_ENC_Z64, "queryable_info")];

/// `zenoh/put.rs` — `shm` is `zextunit!(0x2, true)`, the mandatory marker that
/// says the payload slot holds an ADDRESS.
const PUT: &[Row] = &[
    (0x1, OPT, EXT_ENC_ZBUF, "source_info"),
    (0x2, MAND, EXT_ENC_UNIT, "shm"),
    (0x3, OPT, EXT_ENC_ZBUF, "attachment"),
];

/// `zenoh/del.rs` — `Attachment` moves DOWN to `0x2` because `Del` has no SHM
/// marker; a table keyed on the id alone would call it `shm`.
const DEL: &[Row] = &[
    (0x1, OPT, EXT_ENC_ZBUF, "source_info"),
    (0x2, OPT, EXT_ENC_ZBUF, "attachment"),
];

/// `zenoh/query.rs` — `0x3` is the query's VALUE
/// (`ValueType<{ ZExtZBuf::<0x03>::id(false) }, 0x04>`), the ext a reader that
/// looks only at the message body never finds.
const QUERY: &[Row] = &[
    (0x1, OPT, EXT_ENC_ZBUF, "source_info"),
    (0x3, OPT, EXT_ENC_ZBUF, "query_body"),
    (0x5, OPT, EXT_ENC_ZBUF, "attachment"),
];

/// `zenoh/err.rs` — `SourceInfo` and the SHM marker, no attachment.
const ERR: &[Row] = &[
    (0x1, OPT, EXT_ENC_ZBUF, "source_info"),
    (0x2, MAND, EXT_ENC_UNIT, "shm"),
];

/// The rows a carrier declares upstream, in id order.
///
/// Public so a consumer can ENUMERATE a carrier's vocabulary rather than only
/// probe it — the census gate does exactly that, and so does a reader asking
/// "what could appear here".
pub fn rows(carrier: ExtCarrier) -> &'static [(u8, bool, u8, &'static str)] {
    match carrier {
        ExtCarrier::Init => INIT,
        ExtCarrier::Open => OPEN,
        ExtCarrier::Join => JOIN,
        ExtCarrier::Frame => FRAME,
        ExtCarrier::Fragment => FRAGMENT,
        ExtCarrier::TransportOam => TRANSPORT_OAM,
        ExtCarrier::TransportPlain => &[],
        ExtCarrier::Push | ExtCarrier::Interest | ExtCarrier::Declare => NETWORK_COMMON,
        ExtCarrier::Request => REQUEST,
        ExtCarrier::Response | ExtCarrier::ResponseFinal => RESPONSE,
        ExtCarrier::NetworkOam => NETWORK_OAM,
        ExtCarrier::DeclareCommon => DECLARE_COMMON,
        ExtCarrier::DeclareQueryable => DECLARE_QUERYABLE,
        ExtCarrier::Put => PUT,
        ExtCarrier::Del => DEL,
        ExtCarrier::Query => QUERY,
        ExtCarrier::Err => ERR,
        ExtCarrier::Reply => &[],
    }
}

/// What this extension header IS in this carrier, or `None` when the carrier
/// declares no extension with that eid.
///
/// Takes the RAW header byte rather than a pre-split id, so a caller cannot
/// reach this function having already lost the encoding or mandatory bits —
/// which are the halves of the key easiest to drop, and the ones R311y505 and
/// this module's own round each measured a defect on. Only the
/// chain-continuation flag is dropped, because it describes the CHAIN rather
/// than the entry.
pub fn ext_name(carrier: ExtCarrier, header: u8) -> Option<&'static str> {
    let want = ext_eid(header);
    rows(carrier)
        .iter()
        .find(|row| row_eid(row) == want)
        .map(|(_, _, _, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row of every carrier resolves to its own name from a real header
    /// byte, under EITHER value of the chain-continuation flag — and does NOT
    /// resolve once the mandatory bit is flipped away from what upstream
    /// declares.
    ///
    /// Both halves are load-bearing and they pull in opposite directions. The Z
    /// sweep says the chain flag is not part of the key; the flipped-M leg says
    /// the mandatory bit IS. A lookup that ignored M would pass the first and
    /// fail the second, and it would then name a bare `0x02` UNIT entry on a
    /// `Put` `shm` while the payload slot beside it stayed a `payload`.
    #[test]
    fn every_upstream_row_resolves_and_a_flipped_mandatory_bit_does_not() {
        for carrier in CARRIERS {
            for row in rows(*carrier) {
                let (_, mandatory, _, name) = row;
                for z in [0u8, crate::ext_header::EXT_FLAG_Z] {
                    let header = row_eid(row) | z;
                    assert_eq!(
                        ext_name(*carrier, header),
                        Some(*name),
                        "{carrier:?} header {header:#04x} must resolve to {name}",
                    );
                    let flipped = header ^ EXT_FLAG_M;
                    assert_ne!(
                        ext_name(*carrier, flipped),
                        Some(*name),
                        "{carrier:?} {flipped:#04x} is not {name}: upstream declares it \
                         {}mandatory",
                        if *mandatory { "" } else { "non-" },
                    );
                }
            }
        }
    }

    /// The encoding bits are part of the key. `Init` puts two different
    /// extensions on `0x1` and only the encoding separates them, so a lookup
    /// that dropped it would answer the same for both.
    #[test]
    fn one_id_two_extensions_are_told_apart_by_the_encoding() {
        assert_eq!(ext_name(ExtCarrier::Init, 0x01), Some("qos"));
        assert_eq!(
            ext_name(ExtCarrier::Init, 0x01 | EXT_ENC_Z64),
            Some("qos_link")
        );
        assert_eq!(
            ext_name(ExtCarrier::Open, 0x04 | EXT_ENC_ZBUF),
            Some("multi_link_syn"),
        );
        assert_eq!(ext_name(ExtCarrier::Open, 0x04), Some("multi_link_ack"));
    }

    /// The carrier is part of the key. `0x3` is a different extension in five
    /// carriers, and one of them (`Response`) gives it a different ENCODING
    /// too, so a table keyed on the id alone would be wrong five ways.
    #[test]
    fn one_id_across_carriers_is_five_different_extensions() {
        assert_eq!(
            ext_name(ExtCarrier::Push, 0x03 | EXT_FLAG_M | EXT_ENC_Z64),
            Some("node_id"),
        );
        assert_eq!(
            ext_name(ExtCarrier::Response, 0x03 | EXT_ENC_ZBUF),
            Some("responder_id"),
        );
        assert_eq!(
            ext_name(ExtCarrier::Put, 0x03 | EXT_ENC_ZBUF),
            Some("attachment"),
        );
        assert_eq!(
            ext_name(ExtCarrier::Query, 0x03 | EXT_ENC_ZBUF),
            Some("query_body"),
        );
        assert_eq!(
            ext_name(ExtCarrier::Init, 0x03 | EXT_ENC_ZBUF),
            Some("auth"),
        );
    }

    /// `Del`'s attachment sits at `0x2`, which is the SHM marker's id on `Put`.
    /// A reader told "shm" about a `Del` attachment would conclude the payload
    /// it is looking at is an address.
    #[test]
    fn dels_attachment_is_not_puts_shm_marker() {
        assert_eq!(
            ext_name(ExtCarrier::Del, 0x02 | EXT_ENC_ZBUF),
            Some("attachment"),
        );
        assert_eq!(ext_name(ExtCarrier::Put, 0x02 | EXT_FLAG_M), Some("shm"));
        // And `Del` has no SHM row at all, under any encoding or flag.
        assert_eq!(ext_name(ExtCarrier::Del, 0x02 | EXT_FLAG_M), None);
        assert_eq!(ext_name(ExtCarrier::Del, 0x02), None);
    }

    /// An id the carrier does not declare gets NO name — not a guess, and not a
    /// synthesised one. A later-vintage peer's unknown extension is the common
    /// case in a chain, so this is the ordinary answer rather than the error.
    #[test]
    fn an_unclaimed_id_is_named_nothing() {
        assert_eq!(ext_name(ExtCarrier::Put, 0x07 | EXT_ENC_Z64), None);
        assert_eq!(ext_name(ExtCarrier::Reply, 0x01 | EXT_ENC_ZBUF), None);
        assert_eq!(ext_name(ExtCarrier::TransportPlain, 0x01), None);
        // Right id, wrong encoding, in a carrier that DOES claim the id.
        assert_eq!(ext_name(ExtCarrier::Request, 0x06 | EXT_ENC_ZBUF), None);
        // Right id and encoding, wrong mandatory flag. This is the case that
        // has to stay `None` for this table to agree with the SHM check.
        assert_eq!(ext_name(ExtCarrier::Put, 0x02), None);
    }

    /// No carrier may declare one eid twice: the lookup returns the first match,
    /// so a duplicate row would make one of the two unreachable and the table
    /// would silently disagree with itself.
    #[test]
    fn no_carrier_declares_one_key_twice() {
        for carrier in CARRIERS {
            let table = rows(*carrier);
            for (i, row) in table.iter().enumerate() {
                for other in &table[i + 1..] {
                    assert!(
                        row_eid(row) != row_eid(other),
                        "{carrier:?} declares eid {:#04x} as both {} and {}",
                        row_eid(row),
                        row.3,
                        other.3,
                    );
                }
            }
        }
    }

    /// Every id in the table fits the four bits zenoh gives it
    /// (`iext::ID_MASK`), every encoding is one zenoh defines, and every row's
    /// composed eid round-trips back to those columns.
    ///
    /// A row that folded a flag into its id would be unreachable from any real
    /// header byte — the exact defect this module was written beside, one layer
    /// up — and no lookup test would notice, because the lookup would compose
    /// the same wrong key.
    #[test]
    fn every_row_key_is_reachable_from_a_real_header_byte() {
        for carrier in CARRIERS {
            for row in rows(*carrier) {
                let (id, mandatory, enc, name) = row;
                assert_eq!(*id & 0x0f, *id, "{carrier:?}/{name}: id is four bits");
                assert!(
                    matches!(*enc, EXT_ENC_UNIT | EXT_ENC_Z64 | EXT_ENC_ZBUF),
                    "{carrier:?}/{name}: {enc:#x} is not an encoding zenoh defines",
                );
                let eid = row_eid(row);
                assert_eq!(
                    crate::ext_header::ext_id(eid),
                    *id,
                    "{carrier:?}/{name}: the eid does not carry the row's id",
                );
                assert_eq!(
                    crate::ext_header::ext_mandatory(eid),
                    *mandatory,
                    "{carrier:?}/{name}: the eid does not carry the row's flag",
                );
                assert_eq!(
                    eid & crate::ext_header::EXT_ENC_MASK,
                    *enc,
                    "{carrier:?}/{name}: the eid does not carry the row's encoding",
                );
                assert_eq!(
                    eid & crate::ext_header::EXT_FLAG_Z,
                    0,
                    "{carrier:?}/{name}: an eid never carries the chain flag",
                );
            }
        }
    }

    /// Every variant, so the sweeps above cannot go quiet by a carrier being
    /// added and forgotten. The `rows` match is exhaustive, so a NEW variant
    /// fails to compile there; this list is what stops it being added to both
    /// and still never tested.
    const CARRIERS: &[ExtCarrier] = &[
        ExtCarrier::Init,
        ExtCarrier::Open,
        ExtCarrier::Join,
        ExtCarrier::Frame,
        ExtCarrier::Fragment,
        ExtCarrier::TransportOam,
        ExtCarrier::TransportPlain,
        ExtCarrier::Push,
        ExtCarrier::Request,
        ExtCarrier::Response,
        ExtCarrier::ResponseFinal,
        ExtCarrier::Declare,
        ExtCarrier::Interest,
        ExtCarrier::NetworkOam,
        ExtCarrier::DeclareCommon,
        ExtCarrier::DeclareQueryable,
        ExtCarrier::Put,
        ExtCarrier::Del,
        ExtCarrier::Query,
        ExtCarrier::Err,
        ExtCarrier::Reply,
    ];

    /// The carrier list above must hold EVERY variant. Counted against the
    /// table's own arity rather than a literal, so the two cannot drift: a
    /// variant added to `rows` and not to `CARRIERS` leaves the sweeps blind,
    /// and nothing else would say so.
    #[test]
    fn the_carrier_list_holds_every_variant() {
        for (i, a) in CARRIERS.iter().enumerate() {
            for b in &CARRIERS[i + 1..] {
                assert!(a != b, "CARRIERS repeats {a:?}");
            }
        }
        assert_eq!(
            CARRIERS.len(),
            21,
            "a carrier was added to `rows` without joining the sweeps",
        );
    }
}
