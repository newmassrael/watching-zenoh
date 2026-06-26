// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zid <-> zenoh `ZenohId` Display hex — the SSOT for rendering a
//! length-trimmed wire zid as the string zenoh prints, and parsing it back.
//!
//! FOUNDATIONAL (always-on under `alloc`, no cfg toggle): the recipe is a
//! property of the zenoh `ZenohId` type, not of any one subsystem. It was
//! first authored inside the `storage-replication` track (the digest / aligner
//! keyexprs render the replica zid through `ZenohId`'s `Display`), but the
//! admin space (`@/<zid>/<whatami>`, §5.23) and any future surface that prints a
//! zid needs the identical recipe, so it lives here and `storage_replication`
//! re-exports it (keeping every existing call site + cross-impl test intact).

use alloc::string::String;
use alloc::vec::Vec;

/// Normalise a (length-trimmed) `zid` to the full 16-byte little-endian array
/// uhlc's `ID` canonically holds (`[u8; 16]`, `uhlc-0.8.1/src/id.rs:58-59`;
/// `ID::to_le_bytes` returns the full `[u8; 16]`, id.rs:84). wz's wire /
/// [`crate::sample::TimestampHint`] `zid` is those LE bytes with trailing zero
/// high bytes dropped (zenoh-pico `_z_id_len`); zero-padding back to 16
/// reproduces the canonical id exactly. The SSOT zid encoding shared by the
/// newer-wins ordering key, the replication event fingerprint, and the
/// `ZenohId` Display hex below — so "which is newer", "is this the same event",
/// and "what string names this zid" all agree on the id bytes. A `zid` longer
/// than 16 (malformed input) is truncated to 16, matching uhlc's fixed id width.
pub fn zid_to_le_array(zid: &[u8]) -> [u8; 16] {
    let mut zid16 = [0u8; 16];
    let n = zid.len().min(16);
    zid16[..n].copy_from_slice(&zid[..n]);
    zid16
}

/// Render a length-trimmed wire `zid` as the string zenoh prints for it.
///
/// zenoh fills its keyexprs via `keformat`'s `set<S: Display>` (key_expr
/// `format/mod.rs:487-493`), so the zid is rendered through its
/// [`Display`](core::fmt::Display): `ZenohId` -> `ZenohIdProto`
/// (`zenoh-protocol` `core/mod.rs:191-192`) -> uhlc `ID` Display
/// (`uhlc-0.8.1/src/id.rs:281-291`) = the **16-byte little-endian id read as a
/// `u128`, printed big-endian hex, with a single leading zero stripped**. So
/// the printed string is the zid bytes *reversed* (LE->`u128`->BE hex), NOT a
/// naive per-byte hex of the wire order. This single function is the only place
/// that recipe lives.
pub fn zid_to_zenoh_hex(zid: &[u8]) -> String {
    let id = u128::from_le_bytes(zid_to_le_array(zid));
    let s = alloc::format!("{id:02x}");
    let stripped = s.strip_prefix('0').unwrap_or(s.as_str());
    stripped.into()
}

/// The inverse of [`zid_to_zenoh_hex`]: parse the lowercase hex back to the
/// length-trimmed zid bytes ([`crate::sample::TimestampHint::zid`] form), or
/// `None` if it is not a `<= 16`-byte id. zenoh `ZenohIdProto::from_str`
/// (`core/mod.rs:168-183`).
pub fn zenoh_hex_to_zid(hex: &str) -> Option<Vec<u8>> {
    let id = u128::from_str_radix(hex, 16).ok()?;
    let bytes = id.to_le_bytes();
    let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    Some(bytes[..trimmed_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn le_array_zero_pads_and_truncates() {
        assert_eq!(zid_to_le_array(&[0x01, 0x02]), {
            let mut a = [0u8; 16];
            a[0] = 0x01;
            a[1] = 0x02;
            a
        });
        // Over-long input is truncated to the uhlc 16-byte width.
        let long: Vec<u8> = (0..20).collect();
        assert_eq!(
            &zid_to_le_array(&long)[..],
            &(0..16).collect::<Vec<u8>>()[..]
        );
    }

    #[test]
    fn hex_renders_le_reversed_with_leading_zero_stripped() {
        // 0x01 (one wire byte) -> u128 0x0000..01 -> "1" (leading zero of the
        // even-width "01" stripped). The recipe reverses LE, not per-byte hex.
        assert_eq!(zid_to_zenoh_hex(&[0x01]), "1");
        assert_eq!(zid_to_zenoh_hex(&[0xab]), "ab");
        // Two bytes [0x01, 0x02] = LE u128 0x0201 -> "201".
        assert_eq!(zid_to_zenoh_hex(&[0x01, 0x02]), "201");
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        for zid in [vec![0x01u8], vec![0x01, 0x02, 0x03], vec![0xff; 16]] {
            let hex = zid_to_zenoh_hex(&zid);
            assert_eq!(zenoh_hex_to_zid(&hex).as_deref(), Some(zid.as_slice()));
        }
        assert_eq!(zenoh_hex_to_zid("not-hex"), None);
    }
}
