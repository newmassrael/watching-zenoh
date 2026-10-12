// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Control messages written from the caller's own text, with nothing built on a
//! heap: a `Declare`, an `Interest` or a `ResponseFinal` as the codec's BORROWED
//! view over the keyexpr the caller holds, ready to be encoded straight into the
//! slot its link lends (fixed-memory step S9d).
//!
//! # What this replaces
//!
//! The `build_*` families ([`crate::declare_build`], [`crate::interest_build`],
//! [`crate::response_final_build`]) make the codec's OWNED mirror of each message:
//! a `DeclareOwned` whose keyexpr suffix is a `String`, whose envelope extension
//! chain is a `Vec`, which is then encoded and dropped. That is one to four
//! allocations per control message sent, measured by
//! `wz-session-lwip`'s `slot_control_records`, and it is built for the one purpose
//! of being turned back into the borrowed view that owns `encode`
//! (`try_as_borrowed`). A Put has been written the short way since step S4
//! (`send_push_literal`, under `tx-lend-only`): the borrowed `Push` is composed in
//! place over the caller's `&str` and `&[u8]`. This module is that, for the control
//! plane, and it is the writer side of what step S9d did for the reader side
//! (`driver_loop::InPlaceRecord` lends the control records a peer sends).
//!
//! # One definition of every byte
//!
//! A writer here and the owned builder it mirrors must put the same bytes on the
//! wire for every input, and nothing but a test can say so, so each constant that
//! both read is shared rather than restated: the Declare envelope header
//! ([`crate::declare_build`]), the `Interest` and `InterestBody` header composition
//! ([`crate::interest_build`]), the `ext_qos` entry and the declare QoS
//! ([`crate::declare_ext_qos`]), the queryable-info packing
//! ([`crate::queryable_info`]) and the `ext_keyexpr` inner header
//! ([`crate::declare_ext_keyexpr`]). What is restated is only what the owned
//! builders themselves state inline (the `N` flag on a declaration with a suffix,
//! the message ids), and the `lent_control` tests hold every writer byte-equal to
//! its builder across the inputs the builders accept.
//!
//! # What a caller owns
//!
//! A writer returns a value that borrows the caller's text for its lifetime `'a`
//! and holds its (fixed) extension chain inline; it is encoded with
//! `encode(sink)` and carries `MAX_ENCODED_BYTES` like every borrowed codec. The
//! one writer that needs a buffer of its own is the retraction that NAMES its
//! keyexpr ([`NamedKeyexpr`](crate::lent_control::NamedKeyexpr)): the extension's
//! body is `[inner header | VLE id |
//! suffix]`, bytes that are not contiguous in anything the caller holds, so the
//! caller makes the body first, in an array on its stack, and the writer borrows
//! it.
//!
//! # Refusals
//!
//! Nothing here allocates, truncates or falls back. A keyexpr longer than the
//! link's lent slot is refused by the ENCODE (`CodecError::BufferOverflow` from
//! the lent sink), which the session counts; a keyexpr longer than a
//! `NamedKeyexpr` holds is refused by its constructor
//! (`CodecError::BufferOverflow`). The writers that mirror a builder with an
//! `assert!` on a zero mapping id keep it, for the same reason the builder has it
//! (id `0` is the literal-keyexpr sentinel, and a declaration of it has no
//! meaning), and say so.

#[cfg(feature = "codec-declare")]
use sce_forge_runtime::codec::{CodecError, SceSink, SliceSink};
use sce_forge_runtime::heapless::Vec as HeaplessVec;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::interest::Interest;
use wz_codecs::interest_body::InterestBody;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

#[cfg(feature = "declare-final")]
use wz_codecs::decl_final::DeclFinal;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_kexpr::DeclKexpr;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_queryable::DeclQueryable;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_subscriber::DeclSubscriber;
#[cfg(feature = "codec-declare")]
use wz_codecs::decl_token::DeclToken;
#[cfg(feature = "codec-declare")]
use wz_codecs::declare::{Declare, DeclareVariant};
#[cfg(feature = "codec-declare")]
use wz_codecs::ext_zbuf::ExtZbuf;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_kexpr::UndeclKexpr;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_queryable::UndeclQueryable;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_subscriber::UndeclSubscriber;
#[cfg(feature = "codec-declare")]
use wz_codecs::undecl_token::UndeclToken;
#[cfg(feature = "codec-declare")]
use wz_codecs::wire_const;
#[cfg(feature = "codec-declare")]
use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

use crate::declare_ext_qos::{QOS_DECLARE, QOS_EXT_HEADER};
use crate::interest_build::{interest_body_header, interest_header, InterestKinds};
use crate::sample::QosLevel;

/// The chain a control message carries when it carries one extension: the one
/// entry, in the codec's own fixed-capacity list. The capacity of that list is
/// eight, so one entry always fits and the push cannot fail.
fn chain_of<'a>(entry: ExtEntry<'a>) -> HeaplessVec<ExtEntry<'a>, 8> {
    let mut chain = HeaplessVec::new();
    // One entry in a list of eight.
    let _ = chain.push(entry);
    chain
}

/// An `ext_qos` entry carrying `qos`: `zextz64!(0x1, false)`, terminal (no
/// chain-continuation bit, since it is the only entry). The borrowed twin of
/// [`crate::declare_ext_qos::qos_ext`].
pub(crate) fn qos_entry<'a>(qos: QosLevel) -> ExtEntry<'a> {
    ExtEntry {
        header: QOS_EXT_HEADER,
        body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
            value: u64::from(qos.raw),
        }),
    }
}

/// What the `Z` bit of a message header says about its chain: set when the
/// message carries one. The same rule as
/// [`crate::ext_nodeid::sync_header_z`], over a header that starts clear.
pub(crate) const fn with_z(header: u8) -> u8 {
    header | crate::ext_nodeid::MESSAGE_FLAG_Z
}

// ── Declare ──────────────────────────────────────────────────────────────────

/// The body of an `ext_keyexpr` extension, made in an array on the caller's
/// stack: `[inner header | VLE(mapping id) | suffix]`, the bytes
/// [`crate::declare_ext_keyexpr::build_ext_wireexpr`] makes in a `Vec`. A
/// retraction that NAMES the key it retracts (`undeclare_*_naming`) borrows it.
///
/// The body is written through the codec's own sink (`SliceSink`), so the VLE is
/// the one every generated codec writes and not a second implementation of it.
#[cfg(feature = "codec-declare")]
#[derive(Clone)]
pub struct NamedKeyexpr {
    body: [u8; NAMED_KEYEXPR_BYTES],
    len: usize,
}

/// The longest `ext_keyexpr` body a [`NamedKeyexpr`] holds: the inner header, a
/// VLE id (at most nine bytes) and a suffix of at most
/// [`crate::caps::MAX_KEYEXPR_BYTES`], the longest keyexpr a session keeps text
/// for.
#[cfg(feature = "codec-declare")]
pub const NAMED_KEYEXPR_BYTES: usize = 1 + 9 + crate::caps::MAX_KEYEXPR_BYTES;

#[cfg(feature = "codec-declare")]
impl NamedKeyexpr {
    /// The body for the key `mapping_id` + `suffix` (`0` + the whole keyexpr names
    /// a literal). `CodecError::BufferOverflow` when `suffix` is longer than
    /// [`crate::caps::MAX_KEYEXPR_BYTES`]: the refusal of a key this session holds
    /// no text for, never a truncated one.
    pub fn new(mapping_id: u64, suffix: &str) -> Result<Self, CodecError> {
        // The bound is on the suffix, whatever the id's VLE costs: a key is
        // refused by what it IS, not by how wide the id beside it happens to be.
        if suffix.len() > crate::caps::MAX_KEYEXPR_BYTES {
            return Err(CodecError::BufferOverflow);
        }
        let mut body = [0u8; NAMED_KEYEXPR_BYTES];
        let mut sink = SliceSink::new(&mut body);
        let has_suffix = if suffix.is_empty() {
            0
        } else {
            crate::declare_ext_keyexpr::INNER_HAS_SUFFIX
        };
        sink.write_u8(crate::declare_ext_keyexpr::INNER_IS_LOCAL | has_suffix)?;
        sink.write_vle_u64(mapping_id)?;
        sink.write_bytes(suffix.as_bytes())?;
        let len = sink.position();
        Ok(Self { body, len })
    }

    /// The body for a LITERAL keyexpr (mapping id `0`), the form a sourced
    /// retraction carries.
    pub fn literal(keyexpr: &str) -> Result<Self, CodecError> {
        Self::new(0, keyexpr)
    }

    /// The extension entry, borrowing this body. The borrowed twin of the entry
    /// [`crate::declare_ext_keyexpr::build_ext_wireexpr`] makes.
    fn entry(&self) -> ExtEntry<'_> {
        ExtEntry {
            header: crate::declare_ext_keyexpr::KEYEXPR_EXT_HEADER,
            body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                value_len: self.len as u64,
                value: &self.body[..self.len],
            }),
        }
    }
}

/// The `Declare` envelope around `body`: the header every `declare_build` builder
/// emits (`N_MID_DECLARE | Z`, plus `I` when it answers an interest) and the one
/// `ext_qos` entry of [`QOS_DECLARE`].
#[cfg(feature = "codec-declare")]
fn envelope<'a>(interest_id: Option<u64>, body: DeclareVariant<'a>) -> Declare<'a> {
    let mut header = crate::declare_ext_qos::DECLARE_ENVELOPE_HEADER;
    if interest_id.is_some() {
        header |= wire_const::FLAG_N_DECLARE_I;
    }
    Declare {
        header,
        interest_id,
        extensions: Some(chain_of(qos_entry(QOS_DECLARE))),
        body,
    }
}

/// The `Local`-arm wireexpr every id-based declaration, and every restricted
/// interest, names its keyexpr with.
pub(crate) fn local<'a>(mapping_id: u64, suffix: Option<&'a str>) -> Wireexpr<'a> {
    Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix,
        }),
    }
}

/// The `Nonlocal`-arm wireexpr, which names an id of the PEER's table.
#[cfg(feature = "codec-declare")]
fn nonlocal<'a>(mapping_id: u64, suffix: Option<&'a str>) -> Wireexpr<'a> {
    Wireexpr {
        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
            id: mapping_id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix,
        }),
    }
}

/// The `N` flag of a declaration header: a suffix follows the id.
#[cfg(feature = "codec-declare")]
const fn n_flag(suffix: Option<&str>) -> u8 {
    if suffix.is_some() {
        wire_const::FLAG_D_N
    } else {
        0
    }
}

/// `Declare(DeclKexpr)`: bind `mapping_id` to `suffix` in the peer's table.
/// [`crate::declare_build::build_declare_kexpr`], written in place.
///
/// Panics if `mapping_id == 0`, as the builder does: id zero is the
/// literal-keyexpr sentinel and a declaration of it has no table semantics.
#[cfg(feature = "codec-declare")]
pub fn declare_kexpr(mapping_id: u64, suffix: &str) -> Declare<'_> {
    assert!(
        mapping_id != 0,
        "declare_kexpr requires a non-zero mapping id; id=0 is the literal-keyexpr sentinel",
    );
    envelope(
        None,
        DeclareVariant::CodecZenohDeclKexpr(DeclKexpr {
            header: wire_const::D_MID_KEXPR | wire_const::FLAG_D_N,
            id: mapping_id,
            keyexpr: local(0, Some(suffix)),
            extensions: None,
        }),
    )
}

/// `Declare(DeclSubscriber)` on `(keyexpr_mapping_id, keyexpr_suffix)`.
/// [`crate::declare_build::build_declare_subscriber`], written in place.
#[cfg(feature = "codec-declare")]
pub fn declare_subscriber(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare<'_> {
    envelope(
        None,
        DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
            header: wire_const::D_MID_SUBSCRIBER | n_flag(keyexpr_suffix),
            id: subscriber_id,
            keyexpr: local(keyexpr_mapping_id, keyexpr_suffix),
            extensions: None,
        }),
    )
}

/// `Declare(DeclQueryable)` on `(keyexpr_mapping_id, keyexpr_suffix)`, carrying
/// `info` as the `ext_info` extension when it is not the default (the
/// omit-on-default rule of [`crate::queryable_info::set_queryable_info`]).
/// [`crate::declare_build::build_declare_queryable`] followed by
/// [`crate::declare_build::set_declare_queryable_info`], written in place.
#[cfg(feature = "codec-declare")]
pub fn declare_queryable(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
    info: crate::queryable_info::QueryableInfo,
) -> Declare<'_> {
    let mut header = wire_const::D_MID_QUERYABLE | n_flag(keyexpr_suffix);
    let packed = crate::queryable_info::pack(info);
    let extensions = (packed != 0).then(|| {
        header = with_z(header);
        chain_of(ExtEntry {
            header: crate::queryable_info::QUERYABLE_INFO_EXT_HEADER,
            body: ExtEntryVariant::CodecZenohExtZint(ExtZint { value: packed }),
        })
    });
    envelope(
        None,
        DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
            header,
            id: queryable_id,
            keyexpr: local(keyexpr_mapping_id, keyexpr_suffix),
            extensions,
        }),
    )
}

/// `Declare(DeclToken)` on `(keyexpr_mapping_id, keyexpr_suffix)`.
/// [`crate::declare_build::build_declare_token`], written in place.
#[cfg(feature = "codec-declare")]
pub fn declare_token(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare<'_> {
    envelope(
        None,
        DeclareVariant::CodecZenohDeclToken(DeclToken {
            header: wire_const::D_MID_TOKEN | n_flag(keyexpr_suffix),
            id: token_id,
            keyexpr: local(keyexpr_mapping_id, keyexpr_suffix),
            extensions: None,
        }),
    )
}

/// `Declare(DeclSubscriber)` naming an id of the PEER's table (the `Nonlocal`
/// arm). [`crate::declare_build::build_declare_subscriber_nonlocal`], written in
/// place; panics on a zero mapping id as the builder does.
#[cfg(feature = "codec-declare")]
pub fn declare_subscriber_nonlocal(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare<'_> {
    assert!(
        keyexpr_mapping_id != 0,
        "declare_subscriber_nonlocal requires a non-zero mapping id",
    );
    envelope(
        None,
        DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
            header: wire_const::D_MID_SUBSCRIBER | n_flag(keyexpr_suffix),
            id: subscriber_id,
            keyexpr: nonlocal(keyexpr_mapping_id, keyexpr_suffix),
            extensions: None,
        }),
    )
}

/// `Declare(DeclQueryable)` naming an id of the peer's table.
/// [`crate::declare_build::build_declare_queryable_nonlocal`], written in place;
/// panics on a zero mapping id as the builder does.
#[cfg(feature = "codec-declare")]
pub fn declare_queryable_nonlocal(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare<'_> {
    assert!(
        keyexpr_mapping_id != 0,
        "declare_queryable_nonlocal requires a non-zero mapping id",
    );
    envelope(
        None,
        DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
            header: wire_const::D_MID_QUERYABLE | n_flag(keyexpr_suffix),
            id: queryable_id,
            keyexpr: nonlocal(keyexpr_mapping_id, keyexpr_suffix),
            extensions: None,
        }),
    )
}

/// `Declare(DeclToken)` naming an id of the peer's table.
/// [`crate::declare_build::build_declare_token_nonlocal`], written in place;
/// panics on a zero mapping id as the builder does.
#[cfg(feature = "codec-declare")]
pub fn declare_token_nonlocal(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Declare<'_> {
    assert!(
        keyexpr_mapping_id != 0,
        "declare_token_nonlocal requires a non-zero mapping id",
    );
    envelope(
        None,
        DeclareVariant::CodecZenohDeclToken(DeclToken {
            header: wire_const::D_MID_TOKEN | n_flag(keyexpr_suffix),
            id: token_id,
            keyexpr: nonlocal(keyexpr_mapping_id, keyexpr_suffix),
            extensions: None,
        }),
    )
}

/// `Declare(UndeclKexpr)`: drop `mapping_id` from the peer's table.
/// [`crate::declare_build::build_undeclare_kexpr`], written in place.
#[cfg(feature = "codec-declare")]
pub fn undeclare_kexpr<'a>(mapping_id: u64) -> Declare<'a> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclKexpr(UndeclKexpr {
            header: wire_const::D_MID_UNDECL_KEXPR,
            id: mapping_id,
            extensions: None,
        }),
    )
}

/// `Declare(UndeclSubscriber)` of `subscriber_id`.
/// [`crate::declare_build::build_undeclare_subscriber`], written in place.
#[cfg(feature = "codec-declare")]
pub fn undeclare_subscriber<'a>(subscriber_id: u64) -> Declare<'a> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
            header: wire_const::D_MID_UNDECL_SUBSCRIBER,
            id: subscriber_id,
            extensions: None,
        }),
    )
}

/// `Declare(UndeclQueryable)` of `queryable_id`.
/// [`crate::declare_build::build_undeclare_queryable`], written in place.
#[cfg(feature = "codec-declare")]
pub fn undeclare_queryable<'a>(queryable_id: u64) -> Declare<'a> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable {
            header: wire_const::D_MID_UNDECL_QUERYABLE,
            id: queryable_id,
            extensions: None,
        }),
    )
}

/// `Declare(UndeclToken)` of `token_id`.
/// [`crate::declare_build::build_undeclare_token`], written in place.
#[cfg(feature = "codec-declare")]
pub fn undeclare_token<'a>(token_id: u64) -> Declare<'a> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclToken(UndeclToken {
            header: wire_const::D_MID_UNDECL_TOKEN,
            id: token_id,
            extensions: None,
        }),
    )
}

/// `Declare(UndeclSubscriber)` of `subscriber_id` that also NAMES the key it was
/// held on, as `ext_keyexpr` (`key`). With `id == 0` and
/// [`NamedKeyexpr::literal`] it is the sourced retraction of
/// [`crate::declare_build::build_undeclare_subscriber_with_keyexpr`]; with a real
/// id and [`NamedKeyexpr::new`] it is
/// [`crate::declare_build::build_undeclare_subscriber_on_wire`].
#[cfg(feature = "codec-declare")]
pub fn undeclare_subscriber_naming(subscriber_id: u64, key: &NamedKeyexpr) -> Declare<'_> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
            header: with_z(wire_const::D_MID_UNDECL_SUBSCRIBER),
            id: subscriber_id,
            extensions: Some(chain_of(key.entry())),
        }),
    )
}

/// `Declare(UndeclQueryable)` that also names its key; see
/// [`undeclare_subscriber_naming`].
#[cfg(feature = "codec-declare")]
pub fn undeclare_queryable_naming(queryable_id: u64, key: &NamedKeyexpr) -> Declare<'_> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable {
            header: with_z(wire_const::D_MID_UNDECL_QUERYABLE),
            id: queryable_id,
            extensions: Some(chain_of(key.entry())),
        }),
    )
}

/// `Declare(UndeclToken)` that also names its key; see
/// [`undeclare_subscriber_naming`].
#[cfg(feature = "codec-declare")]
pub fn undeclare_token_naming(token_id: u64, key: &NamedKeyexpr) -> Declare<'_> {
    envelope(
        None,
        DeclareVariant::CodecZenohUndeclToken(UndeclToken {
            header: with_z(wire_const::D_MID_UNDECL_TOKEN),
            id: token_id,
            extensions: Some(chain_of(key.entry())),
        }),
    )
}

/// `Declare(DeclFinal)`, the terminator of a declaration burst.
/// [`crate::declare_build::build_declare_final`], written in place.
#[cfg(feature = "declare-final")]
pub fn declare_final<'a>() -> Declare<'a> {
    envelope(
        None,
        DeclareVariant::CodecZenohDeclFinal(DeclFinal {
            header: wire_const::D_MID_FINAL,
            extensions: None,
        }),
    )
}

/// Stamp `declare` as the answer to the interest `interest_id`: the `I` flag and
/// the id. [`crate::declare_build`]'s private stamp, over the borrowed form.
#[cfg(feature = "codec-declare")]
pub fn answering(mut declare: Declare<'_>, interest_id: u64) -> Declare<'_> {
    declare.header |= wire_const::FLAG_N_DECLARE_I;
    declare.interest_id = Some(interest_id);
    declare
}

/// The reply to a liveliness-token interest for one held token: a `DeclToken` of
/// id `0` on the literal `keyexpr`, answering `interest_id`.
/// [`crate::declare_build::build_declare_token_reply`], written in place.
#[cfg(feature = "codec-declare")]
pub fn declare_token_reply(interest_id: u64, keyexpr: &str) -> Declare<'_> {
    answering(declare_token(0, 0, Some(keyexpr)), interest_id)
}

/// [`declare_token_reply`] with a non-zero token id, the id a later FUTURE push of
/// the same keyexpr reuses. [`crate::declare_build::build_declare_token_reply_with_id`].
#[cfg(feature = "codec-declare")]
pub fn declare_token_reply_with_id(interest_id: u64, token_id: u64, keyexpr: &str) -> Declare<'_> {
    answering(declare_token(token_id, 0, Some(keyexpr)), interest_id)
}

/// The reply to a subscriber interest: a `DeclSubscriber` of id `0` on the literal
/// `keyexpr`. [`crate::declare_build::build_declare_subscriber_reply`].
#[cfg(feature = "codec-declare")]
pub fn declare_subscriber_reply(interest_id: u64, keyexpr: &str) -> Declare<'_> {
    answering(declare_subscriber(0, 0, Some(keyexpr)), interest_id)
}

/// [`declare_subscriber_reply`] with a non-zero id.
/// [`crate::declare_build::build_declare_subscriber_reply_with_id`].
#[cfg(feature = "codec-declare")]
pub fn declare_subscriber_reply_with_id(
    interest_id: u64,
    subscriber_id: u64,
    keyexpr: &str,
) -> Declare<'_> {
    answering(
        declare_subscriber(subscriber_id, 0, Some(keyexpr)),
        interest_id,
    )
}

/// The reply to a queryable interest: a `DeclQueryable` of id `0` on the literal
/// `keyexpr`, carrying the queryable's `info`.
/// [`crate::declare_build::build_declare_queryable_reply`].
#[cfg(feature = "codec-declare")]
pub fn declare_queryable_reply(
    interest_id: u64,
    keyexpr: &str,
    info: crate::queryable_info::QueryableInfo,
) -> Declare<'_> {
    answering(declare_queryable(0, 0, Some(keyexpr), info), interest_id)
}

/// [`declare_queryable_reply`] with a non-zero id.
/// [`crate::declare_build::build_declare_queryable_reply_with_id`].
#[cfg(feature = "codec-declare")]
pub fn declare_queryable_reply_with_id(
    interest_id: u64,
    queryable_id: u64,
    keyexpr: &str,
    info: crate::queryable_info::QueryableInfo,
) -> Declare<'_> {
    answering(
        declare_queryable(queryable_id, 0, Some(keyexpr), info),
        interest_id,
    )
}

/// The terminator of an interest response: a `DeclFinal` answering `interest_id`.
/// [`crate::declare_build::build_declare_final_reply`], written in place.
#[cfg(feature = "declare-final")]
pub fn declare_final_reply<'a>(interest_id: u64) -> Declare<'a> {
    answering(declare_final(), interest_id)
}

// ── Interest ─────────────────────────────────────────────────────────────────

/// An `Interest` asking for `kinds` on `(keyexpr_mapping_id, keyexpr_suffix)`,
/// CURRENT and/or FUTURE, optionally aggregated.
/// [`crate::interest_build::build_interest_kinds_with_aggregate`], written in
/// place; with the three flags it is every `build_interest_*` that asks a keyexpr
/// (`subscribers`, `queryables`, the liveliness `get` and `subscriber`, `kinds`).
pub fn interest<'a>(
    interest_id: u64,
    kinds: InterestKinds,
    current: bool,
    future: bool,
    aggregate: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&'a str>,
) -> Interest<'a> {
    Interest {
        header: interest_header(current, future),
        interest_id,
        body: Some(InterestBody {
            header: interest_body_header(kinds, Some(keyexpr_suffix.is_some()), aggregate),
            keyexpr: Some(local(keyexpr_mapping_id, keyexpr_suffix)),
        }),
        extensions: None,
    }
}

/// An `Interest` with no keyexpr: every declaration of `kinds` is asked for
/// (`R`, `N` and `M` clear).
/// [`crate::interest_build::build_interest_propagated`] without a keyexpr, but
/// with no `ext_qos` (see [`interest_propagated`]).
pub fn interest_unrestricted<'a>(
    interest_id: u64,
    kinds: InterestKinds,
    current: bool,
    future: bool,
    aggregate: bool,
) -> Interest<'a> {
    Interest {
        header: interest_header(current, future),
        interest_id,
        body: Some(InterestBody {
            header: interest_body_header(kinds, None, aggregate),
            keyexpr: None,
        }),
        extensions: None,
    }
}

/// An `Interest` carrying the declare `ext_qos` ([`QOS_DECLARE`]), the shape the
/// liveliness SUBSCRIBER and every propagated interest send: `interest` with the
/// extension attached and the header's `Z` set.
/// [`crate::interest_build::build_interest_liveliness_subscriber`] and
/// [`crate::interest_build::build_interest_propagated`], written in place.
pub fn interest_propagated(mut interest: Interest<'_>) -> Interest<'_> {
    interest.header = with_z(interest.header);
    interest.extensions = Some(chain_of(qos_entry(QOS_DECLARE)));
    interest
}

/// The `Interest` that cancels `interest_id` (no body).
/// [`crate::interest_build::build_interest_final`], written in place.
pub fn interest_final<'a>(interest_id: u64) -> Interest<'a> {
    Interest {
        header: interest_header(false, false),
        interest_id,
        body: None,
        extensions: None,
    }
}

/// [`interest_final`] carrying the declare `ext_qos`: the cancel a propagating
/// broker sends. [`crate::interest_build::build_interest_final_propagated`].
pub fn interest_final_propagated<'a>(interest_id: u64) -> Interest<'a> {
    interest_propagated(interest_final(interest_id))
}

// ── ResponseFinal ────────────────────────────────────────────────────────────

/// A `ResponseFinal` closing the reply stream of `request_id`, carrying `qos` as
/// `ext_qos` unless it is the default (the omit-on-default rule of
/// [`crate::declare_ext_qos::set_response_final_qos`]).
/// [`crate::response_final_build::build_response_final`], written in place.
#[cfg(feature = "codec-response-final")]
pub fn response_final<'a>(
    request_id: u64,
    qos: QosLevel,
) -> wz_codecs::response_final::ResponseFinal<'a> {
    let (header, extensions) = if qos == QosLevel::DEFAULT {
        (0x1A, None)
    } else {
        (with_z(0x1A), Some(chain_of(qos_entry(qos))))
    };
    wz_codecs::response_final::ResponseFinal {
        header,
        request_id,
        extensions,
    }
}

/// Every writer against the builder it mirrors: the same bytes for every input the
/// builder takes, decoded back to the record the builder made, and the refusals.
/// Each comparison is also pinned to a non-empty, non-trivial subject (the matrix
/// is asserted to have run), so a writer that always returned the same message
/// would be caught by the first row that differs and not pass an empty loop.
#[cfg(all(
    test,
    feature = "codec-declare",
    feature = "declare-final",
    feature = "codec-response-final"
))]
mod tests {
    use super::*;
    use crate::declare_build as owned;
    use crate::interest_build as ibuild;
    use crate::queryable_info::QueryableInfo;
    use alloc::vec::Vec;
    use wz_codecs::declare::DeclareOwned;
    use wz_codecs::interest::InterestOwned;

    /// The bytes of an owned `Declare`, through the borrowed view that owns encode.
    fn owned_declare(declare: &DeclareOwned) -> Vec<u8> {
        declare.try_as_borrowed().expect("a view").encode_to_vec()
    }

    fn owned_interest(interest: &InterestOwned) -> Vec<u8> {
        interest.try_as_borrowed().expect("a view").encode_to_vec()
    }

    /// `(mapping id, suffix)` of every shape a declaration names a keyexpr by:
    /// a literal, an alias alone, an alias with a suffix, an empty suffix, a
    /// multi-byte VLE id and a long suffix.
    fn keys() -> [(u64, Option<&'static str>); 6] {
        [
            (0, Some("a/b")),
            (5, None),
            (7, Some("x/y/**")),
            (0, Some("")),
            (300, Some("k")),
            (
                u64::MAX,
                Some("a/very/long/keyexpr/chunk/that/runs/on/and/on/and/on"),
            ),
        ]
    }

    const IDS: [u64; 4] = [0, 1, 127, 1 << 40];

    fn infos() -> [QueryableInfo; 3] {
        [
            QueryableInfo::DEFAULT,
            QueryableInfo::local(true),
            QueryableInfo {
                complete: false,
                distance: 9,
            },
        ]
    }

    #[test]
    fn a_declaration_is_written_as_its_builder_writes_it() {
        let mut compared = 0usize;
        for id in IDS {
            for (mapping, suffix) in keys() {
                assert_eq!(
                    declare_subscriber(id, mapping, suffix).encode_to_vec(),
                    owned_declare(&owned::build_declare_subscriber(id, mapping, suffix).unwrap()),
                    "subscriber {id} {mapping} {suffix:?}"
                );
                assert_eq!(
                    declare_token(id, mapping, suffix).encode_to_vec(),
                    owned_declare(&owned::build_declare_token(id, mapping, suffix).unwrap()),
                    "token {id} {mapping} {suffix:?}"
                );
                for info in infos() {
                    let mut built = owned::build_declare_queryable(id, mapping, suffix).unwrap();
                    owned::set_declare_queryable_info(&mut built, info);
                    assert_eq!(
                        declare_queryable(id, mapping, suffix, info).encode_to_vec(),
                        owned_declare(&built),
                        "queryable {id} {mapping} {suffix:?} {info:?}"
                    );
                    compared += 1;
                }
                if mapping != 0 {
                    assert_eq!(
                        declare_subscriber_nonlocal(id, mapping, suffix).encode_to_vec(),
                        owned_declare(
                            &owned::build_declare_subscriber_nonlocal(id, mapping, suffix).unwrap()
                        ),
                        "nonlocal subscriber {id} {mapping} {suffix:?}"
                    );
                    assert_eq!(
                        declare_queryable_nonlocal(id, mapping, suffix).encode_to_vec(),
                        owned_declare(
                            &owned::build_declare_queryable_nonlocal(id, mapping, suffix).unwrap()
                        ),
                        "nonlocal queryable {id} {mapping} {suffix:?}"
                    );
                    assert_eq!(
                        declare_token_nonlocal(id, mapping, suffix).encode_to_vec(),
                        owned_declare(
                            &owned::build_declare_token_nonlocal(id, mapping, suffix).unwrap()
                        ),
                        "nonlocal token {id} {mapping} {suffix:?}"
                    );
                }
                compared += 2;
            }
            assert_eq!(
                undeclare_subscriber(id).encode_to_vec(),
                owned_declare(&owned::build_undeclare_subscriber(id))
            );
            assert_eq!(
                undeclare_queryable(id).encode_to_vec(),
                owned_declare(&owned::build_undeclare_queryable(id))
            );
            assert_eq!(
                undeclare_token(id).encode_to_vec(),
                owned_declare(&owned::build_undeclare_token(id))
            );
            compared += 3;
            if id != 0 {
                for suffix in ["a/b", "", "x/y/z/w"] {
                    assert_eq!(
                        declare_kexpr(id, suffix).encode_to_vec(),
                        owned_declare(&owned::build_declare_kexpr(id, suffix).unwrap()),
                        "kexpr {id} {suffix:?}"
                    );
                    compared += 1;
                }
                assert_eq!(
                    undeclare_kexpr(id).encode_to_vec(),
                    owned_declare(&owned::build_undeclare_kexpr(id))
                );
                compared += 1;
            }
        }
        assert_eq!(
            declare_final().encode_to_vec(),
            owned_declare(&owned::build_declare_final())
        );
        assert!(compared > 100, "the matrix ran: {compared} comparisons");
    }

    #[test]
    fn an_answer_to_an_interest_is_written_as_its_builder_writes_it() {
        for interest_id in [0u64, 1, 4242] {
            assert_eq!(
                declare_token_reply(interest_id, "live/a").encode_to_vec(),
                owned_declare(&owned::build_declare_token_reply(interest_id, "live/a").unwrap())
            );
            assert_eq!(
                declare_token_reply_with_id(interest_id, 9, "live/a").encode_to_vec(),
                owned_declare(
                    &owned::build_declare_token_reply_with_id(interest_id, 9, "live/a").unwrap()
                )
            );
            assert_eq!(
                declare_subscriber_reply(interest_id, "s/a").encode_to_vec(),
                owned_declare(&owned::build_declare_subscriber_reply(interest_id, "s/a").unwrap())
            );
            assert_eq!(
                declare_subscriber_reply_with_id(interest_id, 3, "s/a").encode_to_vec(),
                owned_declare(
                    &owned::build_declare_subscriber_reply_with_id(interest_id, 3, "s/a").unwrap()
                )
            );
            for info in infos() {
                assert_eq!(
                    declare_queryable_reply(interest_id, "q/a", info).encode_to_vec(),
                    owned_declare(
                        &owned::build_declare_queryable_reply(interest_id, "q/a", info).unwrap()
                    ),
                    "{info:?}"
                );
                assert_eq!(
                    declare_queryable_reply_with_id(interest_id, 6, "q/a", info).encode_to_vec(),
                    owned_declare(
                        &owned::build_declare_queryable_reply_with_id(interest_id, 6, "q/a", info)
                            .unwrap()
                    ),
                    "{info:?}"
                );
            }
            assert_eq!(
                declare_final_reply(interest_id).encode_to_vec(),
                owned_declare(&owned::build_declare_final_reply(interest_id))
            );
        }
        // The I flag and the id are what the stamp adds, and they are on the wire.
        let bytes = declare_final_reply(77).encode_to_vec();
        assert_eq!(
            bytes[0] & wire_const::FLAG_N_DECLARE_I,
            wire_const::FLAG_N_DECLARE_I
        );
        assert_ne!(bytes, declare_final().encode_to_vec());
    }

    #[test]
    fn a_retraction_that_names_its_key_is_written_as_its_builder_writes_it() {
        for keyexpr in ["demo/data", "a", "x/y/z/**"] {
            let key = NamedKeyexpr::literal(keyexpr).unwrap();
            assert_eq!(
                undeclare_subscriber_naming(0, &key).encode_to_vec(),
                owned_declare(&owned::build_undeclare_subscriber_with_keyexpr(keyexpr).unwrap()),
                "{keyexpr}"
            );
            assert_eq!(
                undeclare_queryable_naming(0, &key).encode_to_vec(),
                owned_declare(&owned::build_undeclare_queryable_with_keyexpr(keyexpr).unwrap()),
                "{keyexpr}"
            );
            assert_eq!(
                undeclare_token_naming(0, &key).encode_to_vec(),
                owned_declare(&owned::build_undeclare_token_with_keyexpr(keyexpr).unwrap()),
                "{keyexpr}"
            );
        }
        for (id, mapping, suffix) in [
            (1u64, 7u64, "tail"),
            (9, 7, ""),
            (1 << 33, 300, "k/l"),
            (5, u64::MAX, "z"),
        ] {
            let key = NamedKeyexpr::new(mapping, suffix).unwrap();
            assert_eq!(
                undeclare_subscriber_naming(id, &key).encode_to_vec(),
                owned_declare(
                    &owned::build_undeclare_subscriber_on_wire(id, mapping, suffix).unwrap()
                ),
                "{id} {mapping} {suffix:?}"
            );
            assert_eq!(
                undeclare_queryable_naming(id, &key).encode_to_vec(),
                owned_declare(
                    &owned::build_undeclare_queryable_on_wire(id, mapping, suffix).unwrap()
                ),
                "{id} {mapping} {suffix:?}"
            );
            assert_eq!(
                undeclare_token_naming(id, &key).encode_to_vec(),
                owned_declare(&owned::build_undeclare_token_on_wire(id, mapping, suffix).unwrap()),
                "{id} {mapping} {suffix:?}"
            );
        }
    }

    #[test]
    fn a_key_past_what_a_named_keyexpr_holds_is_refused_and_one_at_the_bound_is_not() {
        let at_bound = "k".repeat(crate::caps::MAX_KEYEXPR_BYTES);
        let past_bound = "k".repeat(crate::caps::MAX_KEYEXPR_BYTES + 1);
        // Even the widest id (nine VLE bytes) leaves room for a suffix at the bound.
        let key = NamedKeyexpr::new(u64::MAX, &at_bound).expect("at the bound");
        assert_eq!(
            undeclare_token_naming(1, &key).encode_to_vec(),
            owned_declare(&owned::build_undeclare_token_on_wire(1, u64::MAX, &at_bound).unwrap())
        );
        assert_eq!(
            NamedKeyexpr::new(u64::MAX, &past_bound).err(),
            Some(CodecError::BufferOverflow),
            "past the bound is refused, not cut"
        );
        assert_eq!(
            NamedKeyexpr::literal(&past_bound).err(),
            Some(CodecError::BufferOverflow)
        );
    }

    #[test]
    fn an_interest_is_written_as_its_builder_writes_it() {
        use crate::interest_build::InterestKinds as K;
        let kinds = [
            K::SUBSCRIBERS,
            K::QUERYABLES,
            K::TOKENS,
            K::SUBSCRIBERS | K::QUERYABLES,
        ];
        let mut compared = 0usize;
        for interest_id in [0u64, 3, 1 << 20] {
            for kind in kinds {
                for current in [false, true] {
                    for future in [false, true] {
                        for aggregate in [false, true] {
                            for (mapping, suffix) in keys() {
                                assert_eq!(
                                    interest(interest_id, kind, current, future, aggregate, mapping, suffix)
                                        .encode_to_vec(),
                                    owned_interest(
                                        &ibuild::build_interest_kinds_with_aggregate(
                                            interest_id, kind, current, future, aggregate, mapping,
                                            suffix
                                        )
                                        .unwrap()
                                    ),
                                    "{interest_id} {kind:?} c={current} f={future} a={aggregate} {mapping} {suffix:?}"
                                );
                                compared += 1;
                            }
                        }
                    }
                }
                // The propagated form: CURRENT always, FUTURE on request, the
                // declare ext_qos attached; with and without a keyexpr.
                for aggregate in [false, true] {
                    for current_future in [false, true] {
                        assert_eq!(
                            interest_propagated(interest(
                                interest_id,
                                kind,
                                true,
                                current_future,
                                aggregate,
                                4,
                                Some("p/**")
                            ))
                            .encode_to_vec(),
                            owned_interest(
                                &ibuild::build_interest_propagated(
                                    interest_id,
                                    kind,
                                    aggregate,
                                    current_future,
                                    Some((4, Some("p/**")))
                                )
                                .unwrap()
                            )
                        );
                        assert_eq!(
                            interest_propagated(interest_unrestricted(
                                interest_id,
                                kind,
                                true,
                                current_future,
                                aggregate
                            ))
                            .encode_to_vec(),
                            owned_interest(
                                &ibuild::build_interest_propagated(
                                    interest_id,
                                    kind,
                                    aggregate,
                                    current_future,
                                    None
                                )
                                .unwrap()
                            )
                        );
                        compared += 2;
                    }
                }
            }
            for history in [false, true] {
                assert_eq!(
                    interest_propagated(interest(
                        interest_id,
                        K::TOKENS,
                        history,
                        true,
                        false,
                        0,
                        Some("live/**")
                    ))
                    .encode_to_vec(),
                    owned_interest(
                        &ibuild::build_interest_liveliness_subscriber(
                            interest_id,
                            history,
                            0,
                            Some("live/**")
                        )
                        .unwrap()
                    )
                );
                compared += 1;
            }
            assert_eq!(
                interest(
                    interest_id,
                    K::TOKENS,
                    true,
                    false,
                    false,
                    0,
                    Some("live/**")
                )
                .encode_to_vec(),
                owned_interest(
                    &ibuild::build_interest_liveliness_get(interest_id, 0, Some("live/**"))
                        .unwrap()
                )
            );
            assert_eq!(
                interest_final(interest_id).encode_to_vec(),
                owned_interest(&ibuild::build_interest_final(interest_id))
            );
            assert_eq!(
                interest_final_propagated(interest_id).encode_to_vec(),
                owned_interest(&ibuild::build_interest_final_propagated(interest_id))
            );
            compared += 3;
        }
        assert!(compared > 500, "the matrix ran: {compared} comparisons");
    }

    #[test]
    fn a_response_final_is_written_as_its_builder_writes_it() {
        use crate::qos::{CongestionControl, Priority};
        let levels = [
            QosLevel::DEFAULT,
            QosLevel::from_parts(Priority::Control, CongestionControl::Block, false),
            QosLevel::from_parts(Priority::DataHigh, CongestionControl::Drop, true),
        ];
        for request_id in [0u64, 7, 1 << 50] {
            for qos in levels {
                let built = crate::response_final_build::build_response_final(request_id, qos);
                assert_eq!(
                    response_final(request_id, qos).encode_to_vec(),
                    built.try_as_borrowed().expect("a view").encode_to_vec(),
                    "{request_id} {qos:?}"
                );
            }
        }
        // The default level writes no extension and the others do: the pair is what
        // makes the equality above mean something.
        assert_ne!(
            response_final(1, levels[0]).encode_to_vec(),
            response_final(1, levels[1]).encode_to_vec()
        );
    }

    /// What is written decodes to the message it describes, field by field, and
    /// not merely to the same bytes as the builder: the id, the keyexpr the peer
    /// resolves, the completeness it reads off the info extension, and the QoS of
    /// the envelope.
    #[test]
    fn what_is_written_decodes_to_the_message_it_describes() {
        use wz_codecs::declare::{Declare as DeclareView, DeclareOwnedVariant};
        use wz_codecs::interest::Interest as InterestView;
        let declare = declare_queryable(4, 9, Some("q/k"), QueryableInfo::local(true));
        let bytes = declare.encode_to_vec();
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&bytes);
        let decoded = DeclareView::decode(&mut cursor)
            .expect("decodes")
            .try_into_owned()
            .expect("owns");
        assert_eq!(decoded.interest_id, None);
        assert_eq!(
            crate::declare_ext_qos::read_declare_qos(&decoded),
            QOS_DECLARE,
            "the envelope carries the declare QoS"
        );
        let DeclareOwnedVariant::CodecZenohDeclQueryable(queryable) = &decoded.body else {
            panic!("a DeclQueryable, got {:?}", decoded.body);
        };
        assert_eq!(queryable.id, 4);
        assert_eq!(
            crate::wireexpr_resolve::id_and_suffix(&queryable.keyexpr.body),
            (9, Some("q/k"))
        );
        assert!(
            crate::queryable_info::read_queryable_info(queryable.extensions.as_ref()).complete,
            "the completeness rides the info extension"
        );

        let interest = interest_propagated(interest(
            8,
            InterestKinds::SUBSCRIBERS,
            true,
            true,
            false,
            2,
            Some("i/**"),
        ));
        let bytes = interest.encode_to_vec();
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&bytes);
        let decoded = InterestView::decode(&mut cursor)
            .expect("decodes")
            .try_into_owned()
            .expect("owns");
        assert_eq!(decoded.interest_id, 8);
        assert!(decoded.c() && decoded.f() && decoded.z());
        assert_eq!(
            crate::declare_ext_qos::read_interest_qos(&decoded),
            QOS_DECLARE,
            "the propagated interest carries the declare QoS"
        );
        let body = decoded.body.as_ref().expect("a body");
        assert!(body.su() && !body.qu() && !body.to() && !body.ag());
        let keyexpr = body.keyexpr.as_ref().expect("a keyexpr");
        assert_eq!(
            crate::wireexpr_resolve::id_and_suffix(&keyexpr.body),
            (2, Some("i/**"))
        );
    }

    #[test]
    #[should_panic(expected = "non-zero mapping id")]
    fn a_zero_mapping_id_is_refused_as_the_builder_refuses_it() {
        let _ = declare_kexpr(0, "a");
    }
}
