// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared `ext_keyexpr` declaration-extension codec — the SSOT for the
//! `_z_decl_ext_keyexpr` keyexpr extension a SOURCED `UndeclareSubscriber`
//! carries (P4 routing, c3c-3 debt A1 — subscription lifecycle).
//!
//! zenoh identifies a SOURCED subscription by its KEYEXPR, not a `SubscriberId`
//! (`id == 0`, "Sourced subscriptions do not use ids" — zenoh
//! `hat/linkstate_peer/pubsub.rs` `send_sourced_subscription_to_net_children` /
//! `send_forget_sourced_subscription_to_net_children`). The `DeclareSubscriber`
//! carries the keyexpr in its body `wire_expr`; the `UndeclareSubscriber` —
//! whose body is only `{ id }` — carries it in the optional `ext_wire_expr`
//! extension (zenoh `UndeclareSubscriber { id, ext_wire_expr }`), so a transit
//! linkstate peer can resolve WHICH interest to withdraw. This module is the
//! build / read seam for that one extension.
//!
//! Wire (zenoh-pico `_z_decl_ext_keyexpr_encode`,
//! `src/protocol/codec/declarations.c:38-50`): a ZBuf-encoded ext entry, header
//! `ENC_ZBUF (0x40) | FLAG_M (0x10) | id (0x0f) = 0x5f` (plus `FLAG_Z (0x80)`
//! when another ext follows), whose ZBuf body is
//! `[inner_header | id VLE | suffix bytes]` with
//! `inner_header = (is_local ? 2 : 0) | (has_suffix ? 1 : 0)`. The wz ext-entry
//! ZBUF arm carries the body as opaque bytes — the established wz extension
//! pattern (qos / timestamp / attachment all host-interpret their ZBuf body,
//! mirroring zenoh-pico's `_z_..._decode_extensions` callbacks); this module
//! builds / parses those bytes host-side.
//!
//! MVP scope (honest): LITERAL keyexpr only (mapping id 0 + suffix, is_local),
//! matching the rest of the linkstate-peer HAT (literal-only, exact-match). An
//! aliased (`id != 0`) keyexpr — a multi-byte inner id VLE — reads back as
//! `None`, the same tracked deferral as the data / declare `literal_keyexpr`
//! seams. The keyexpr length is NOT capped: this module is gated on `alloc`,
//! where the SCE owned `SceBytes` carrier is an unbounded `Vec<u8>` (R311nq);
//! the `ExtZbuf` `0x20`-element const is the NO-alloc `heapless` bound only,
//! which this full-node routing module never instantiates. `build` stays
//! fallible purely by `owned_bytes`'s profile-generic signature.

use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

use crate::ext_nodeid::{ext_id, EXT_ENC_ZBUF, EXT_FLAG_M};

/// The `ext_keyexpr` extension id — zenoh `_z_decl_ext_keyexpr`, ext id `0x0f`.
pub const KEYEXPR_EXT_ID: u8 = 0x0f;
/// The `ext_keyexpr` header with no further extension following:
/// `id (0x0f) | M (0x10) | ZBuf (0x40)` = `0x5f`. The chain-continuation
/// `FLAG_Z` (0x80) is layered on by [`ext_nodeid::apply_chain_z_bits`] when the
/// entry is not the last in a chain — the shared per-entry `Z` SSOT.
pub const KEYEXPR_EXT_HEADER: u8 = KEYEXPR_EXT_ID | EXT_FLAG_M | EXT_ENC_ZBUF;

/// Inner-body flag (zenoh `_z_wireexpr_is_local`): the keyexpr was rooted in the
/// SENDER's own mapping table. A freshly built literal keyexpr (mapping 0) is
/// local.
const INNER_IS_LOCAL: u8 = 0x02;
/// Inner-body flag (zenoh `kelen != 0`): a suffix string follows the id.
const INNER_HAS_SUFFIX: u8 = 0x01;

/// Build the `ext_keyexpr` extension entry for a LITERAL keyexpr — the keyexpr
/// a sourced `UndeclareSubscriber` retracts. Mirrors zenoh-pico
/// `_z_decl_ext_keyexpr_encode` for a local literal (mapping id 0): the ZBuf
/// body is `[inner_header | VLE(0) | suffix bytes]`. Fallible only by the
/// profile-generic `owned_bytes` signature; on the `alloc` carrier this module
/// is gated to, the owned ZBuf is unbounded (R311nq `SceBytes`), so a literal
/// keyexpr is never length-rejected.
pub fn build_ext_keyexpr(literal: &str) -> Result<ExtEntryOwned, CodecError> {
    // ZBuf body: [inner_header, mapping-id VLE (literal sentinel 0 = 1 byte),
    // suffix bytes]. is_local + has_suffix for a freshly built literal keyexpr.
    let mut body: Vec<u8> = Vec::with_capacity(2 + literal.len());
    body.push(INNER_IS_LOCAL | INNER_HAS_SUFFIX);
    body.push(0x00);
    body.extend_from_slice(literal.as_bytes());
    let value_len = body.len() as u64;
    // alloc carrier: `owned_bytes` is the unbounded `SceBytes` Vec (R311nq), so
    // no length cap; the `?` covers only the profile-generic signature.
    let value = crate::codec_owned::owned_bytes(&body)?;
    Ok(ExtEntryOwned {
        header: KEYEXPR_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned { value_len, value }),
    })
}

/// Read the LITERAL keyexpr from an `ext_keyexpr` extension in `exts`. `None`
/// when absent, when the entry is not a ZBuf body, or when the keyexpr is
/// aliased (a non-zero inner mapping id) rather than a literal — the
/// linkstate-peer HAT is literal-only in the MVP, the same deferral as the data
/// / declare `literal_keyexpr` seams. Borrows the suffix out of the ext body (no
/// allocation), so the caller can look it up directly in the interest table.
pub fn read_ext_keyexpr(exts: Option<&Vec<ExtEntryOwned>>) -> Option<&str> {
    let exts = exts?;
    for ext in exts {
        if ext_id(ext.header) != KEYEXPR_EXT_ID {
            continue;
        }
        let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body else {
            continue;
        };
        // [inner_header, mapping-id VLE, suffix]. Literal MVP: the id is the
        // single byte 0x00 (mapping 0); a non-zero / multi-byte VLE is an alias.
        let body = z.value.as_slice();
        let Some((&inner_header, rest)) = body.split_first() else {
            continue;
        };
        let Some((&id_byte, suffix)) = rest.split_first() else {
            continue;
        };
        if inner_header & INNER_HAS_SUFFIX == 0 || id_byte != 0x00 {
            continue; // no suffix, or an aliased mapping id → literal-only defer
        }
        return core::str::from_utf8(suffix).ok();
    }
    None
}

/// Decode the leading zenoh VLE (varint) `u64` from `bytes`, returning the value
/// and the bytes after it. `None` on truncation or an over-long encoding (a VLE
/// wider than a `u64`). The inner mapping-id of an `ext_keyexpr` ZBuf body is
/// VLE-encoded — a literal is the single byte `0x00`, an alias is the sender's
/// (multi-byte-capable) mapping id.
fn decode_vle(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        let byte = *bytes.get(i)?;
        i += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[i..]));
        }
        shift += 7;
        if shift >= 64 {
            return None; // malformed: a VLE wider than a u64
        }
    }
}

/// Resolve the keyexpr an `ext_keyexpr` extension carries against a peer mapping
/// `table` (c3c-3 B1b) — the
/// [`resolve_wireexpr`](crate::wireexpr_resolve::resolve_wireexpr) analogue for
/// the `UndeclareSubscriber` ext form. `id == 0` is the literal suffix verbatim;
/// `id != 0` is `table[id] + suffix`. `None` when the ext is absent / malformed,
/// or when an aliased id has no table entry (the peer referenced a mapping it
/// never declared on this link). Unlike [`read_ext_keyexpr`] (literal-only) this
/// resolves an ALIASED ext, so a transit linkstate peer can withdraw the right
/// interest for an aliased undeclare (the withdrawal twin of the declare side's
/// `resolve_wireexpr`).
pub fn resolve_ext_keyexpr(
    exts: Option<&Vec<ExtEntryOwned>>,
    table: &HashMap<u64, String>,
) -> Option<String> {
    let exts = exts?;
    for ext in exts {
        if ext_id(ext.header) != KEYEXPR_EXT_ID {
            continue;
        }
        let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body else {
            continue;
        };
        // [inner_header, mapping-id VLE, suffix].
        let body = z.value.as_slice();
        let (&inner_header, rest) = body.split_first()?;
        let (id, suffix_bytes) = decode_vle(rest)?;
        let suffix = if inner_header & INNER_HAS_SUFFIX != 0 {
            core::str::from_utf8(suffix_bytes).ok()?
        } else {
            ""
        };
        return Some(if id == 0 {
            String::from(suffix)
        } else {
            let mut out = table.get(&id)?.clone();
            out.push_str(suffix);
            out
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn build_emits_pico_ext_keyexpr_shape() {
        let ext = build_ext_keyexpr("demo/sub").expect("build literal ext");
        // header = id 0x0f | M 0x10 | ZBuf 0x40 = 0x5f (terminal: chain-Z layered
        // on by apply_chain_z_bits only when another ext follows).
        assert_eq!(ext.header, 0x5f);
        let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body else {
            panic!("ext_keyexpr must be a ZBuf-bodied ext");
        };
        // ZBuf body: inner_header 0x03 (local + suffix), VLE(id 0) = 0x00, then
        // the literal suffix bytes.
        let mut expected = vec![0x03u8, 0x00];
        expected.extend_from_slice(b"demo/sub");
        assert_eq!(z.value.as_slice(), expected.as_slice());
        assert_eq!(z.value_len, expected.len() as u64);
    }

    #[test]
    fn read_recovers_the_built_literal() {
        let ext = build_ext_keyexpr("demo/sub").unwrap();
        assert_eq!(read_ext_keyexpr(Some(&vec![ext])), Some("demo/sub"));
    }

    #[test]
    fn read_absent_or_other_ext_is_none() {
        assert_eq!(read_ext_keyexpr(None), None);
        // A non-keyexpr ext id (0x03 ext_nodeid-shaped) is skipped.
        let other = ExtEntryOwned {
            header: 0x33,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint {
                value: 5,
            }),
        };
        assert_eq!(read_ext_keyexpr(Some(&vec![other])), None);
    }

    #[test]
    fn read_aliased_mapping_is_none_literal_only() {
        // An aliased keyexpr (inner mapping id != 0) is the literal-only MVP
        // deferral — read as None rather than mis-resolved.
        let aliased = ExtEntryOwned {
            header: KEYEXPR_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 3,
                value: crate::codec_owned::owned_bytes(&[0x03, 0x07, b'x']).unwrap(),
            }),
        };
        assert_eq!(read_ext_keyexpr(Some(&vec![aliased])), None);
    }

    #[test]
    fn build_and_read_round_trip_a_long_keyexpr() {
        // The alloc owned carrier (SceBytes, R311nq) is unbounded, so a keyexpr
        // past the no-alloc 32-element heapless bound still round-trips — there
        // is no length cap on this full-node routing profile.
        let long = "x".repeat(45);
        let ext = build_ext_keyexpr(&long).expect("alloc carrier is unbounded");
        assert_eq!(read_ext_keyexpr(Some(&vec![ext])), Some(long.as_str()));
    }

    #[test]
    fn resolve_recovers_a_literal_with_an_empty_table() {
        // id == 0 resolves to the suffix verbatim, no table lookup (B1b).
        let ext = build_ext_keyexpr("demo/sub").unwrap();
        let table = HashMap::new();
        assert_eq!(
            resolve_ext_keyexpr(Some(&vec![ext]), &table),
            Some(String::from("demo/sub"))
        );
    }

    #[test]
    fn resolve_composes_an_aliased_ext_via_the_table() {
        // Aliased ext: inner_header 0x03 (local + suffix), VLE id 0x07, suffix "x".
        // table{7 -> "demo/"} resolves it to "demo/x" (table base + per-msg suffix).
        let aliased = ExtEntryOwned {
            header: KEYEXPR_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 3,
                value: crate::codec_owned::owned_bytes(&[0x03, 0x07, b'x']).unwrap(),
            }),
        };
        let mut table = HashMap::new();
        table.insert(7u64, String::from("demo/"));
        assert_eq!(
            resolve_ext_keyexpr(Some(&vec![aliased]), &table),
            Some(String::from("demo/x"))
        );
    }

    #[test]
    fn resolve_an_unknown_alias_is_none() {
        // An aliased id with no table entry (never declared on this link) is None.
        let aliased = ExtEntryOwned {
            header: KEYEXPR_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 3,
                value: crate::codec_owned::owned_bytes(&[0x03, 0x09, b'x']).unwrap(),
            }),
        };
        let table = HashMap::new();
        assert_eq!(resolve_ext_keyexpr(Some(&vec![aliased]), &table), None);
    }
}
