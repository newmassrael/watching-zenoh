// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2824 (§5.23) — which sub-key a config write names in a node's config
//! space, decided with no allocator.
//!
//! This is the membership decision `adminspace::AdminConfigWriteSpace::subkey`
//! made, moved here unchanged so that the MCU's config-write surface
//! (`admin_connect`) answers the same question with the same code. Its
//! justification — upstream's three gates, the positional reading of
//! `@/${zid:*}/${whatami:*}/config/${key:**}`, and the measured, one-way
//! divergence on a `**` in a one-chunk slot — stays on that method, which now
//! delegates here.
//!
//! The only change is the chunk buffer: a `BoundedVec` of
//! `keyexpr_match::MAX_KEYEXPR_CHUNKS` instead of a `Vec`. That is the rule
//! `keyexpr_match` already applies to every keyexpr scan in this crate —
//! unbounded on the `alloc` backing, so the AP answers exactly as before, and
//! a key deeper than the bound is not this node's on a no-heap MCU.

use crate::bounded::BoundedVec;
use crate::keyexpr_match::{keyexpr_intersects_target, MAX_KEYEXPR_CHUNKS};

/// The number of chunks in front of an admin config-write sub-key:
/// `@` / `<zid>` / `<whatami>` / `config`. Upstream states the same four as a
/// format, `@/${zid:*}/${whatami:*}/config/${key:**}`
/// (`zenoh/src/net/runtime/adminspace.rs` @ `CONFIG_FORMAT`), whose `${..:*}`
/// specs are ONE-CHUNK specs — which is why the count is a constant and the
/// sub-key starts at a fixed index rather than wherever a scan finds `config`.
pub const ADMIN_CONFIG_SPACE_PREFIX_CHUNKS: usize = 4;

/// The trailing chunk that turns this node's config prefix into the SUBSCRIPTION
/// pattern upstream declares (`adminspace.rs:350-353`).
pub const ADMIN_CONFIG_WRITE_PATTERN_TAIL: &str = "**";

/// Why a keyexpr names no sub-key of a node's config space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSpaceRefusal {
    /// Not in the space, or not in the format, or an empty sub-key.
    NotInSpace,
    /// A `**` where the format has a one-chunk spec: the sub-key is
    /// underdetermined. See `AdminConfigWriteSpace::subkey`.
    AmbiguousSpaceAddress,
}

/// Write a node's config-write subscription pattern,
/// `@/<zid>/<whatami>/config/**`, into `out`.
pub fn write_config_space_pattern(
    out: &mut dyn core::fmt::Write,
    zid_hex: &str,
    whatami: &str,
) -> core::fmt::Result {
    out.write_str("@/")?;
    out.write_str(zid_hex)?;
    out.write_str("/")?;
    out.write_str(whatami)?;
    out.write_str("/config/")?;
    out.write_str(ADMIN_CONFIG_WRITE_PATTERN_TAIL)
}

/// The sub-key `keyexpr` names in the config space whose subscription
/// pattern is `pattern` (as [`write_config_space_pattern`] writes it).
pub fn subkey_in_config_space<'k>(
    pattern: &str,
    keyexpr: &'k str,
) -> Result<&'k str, ConfigSpaceRefusal> {
    let mut chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for chunk in keyexpr.split('/') {
        if chunks.push(chunk).is_err() {
            return Err(ConfigSpaceRefusal::NotInSpace);
        }
    }
    // GATE 1 — upstream's set-semantics membership test. This also rejects
    // an empty chunk in the arriving key (`keyexpr_intersects_target` ->
    // `target_chunks_well_formed`), which is the non-canonical shape
    // upstream never receives because its wire expression was validated.
    if !keyexpr_intersects_target(pattern, &chunks) {
        return Err(ConfigSpaceRefusal::NotInSpace);
    }
    // GATE 2a — a `**` where the format writes a one-chunk spec. Checked
    // BEFORE the positional read so the refusal reported is the true reason.
    for slot in 1..ADMIN_CONFIG_SPACE_PREFIX_CHUNKS - 1 {
        if chunks.get(slot) == Some(&ADMIN_CONFIG_WRITE_PATTERN_TAIL) {
            return Err(ConfigSpaceRefusal::AmbiguousSpaceAddress);
        }
    }
    // GATE 2b — the format read positionally. The `@` and `config` literals
    // are read out of the space's OWN pattern, so there is no second spelling
    // of either to drift.
    let mut own = pattern.split('/');
    let own_root = own.next();
    let own_config = own.nth(ADMIN_CONFIG_SPACE_PREFIX_CHUNKS - 2);
    if chunks.len() <= ADMIN_CONFIG_SPACE_PREFIX_CHUNKS
        || Some(chunks[0]) != own_root
        || Some(chunks[ADMIN_CONFIG_SPACE_PREFIX_CHUNKS - 1]) != own_config
    {
        return Err(ConfigSpaceRefusal::NotInSpace);
    }
    // GATE 3 — non-empty. The sub-key is a contiguous SUFFIX of the input,
    // so it is returned as a slice and costs no allocation.
    let mut offset = 0usize;
    for chunk in chunks.iter().take(ADMIN_CONFIG_SPACE_PREFIX_CHUNKS) {
        offset += chunk.len() + 1;
    }
    let sub_key = &keyexpr[offset..];
    if sub_key.is_empty() {
        return Err(ConfigSpaceRefusal::NotInSpace);
    }
    Ok(sub_key)
}
