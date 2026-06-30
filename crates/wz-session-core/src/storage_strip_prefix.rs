// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 storage strip-prefix — the key-prefix strip/restore a storage MANAGER
//! applies so a storage holds keys RELATIVE to a mount point. The wz mirror of
//! zenoh's `strip_prefix` / `prefix`
//! (`plugins/zenoh-plugin-storage-manager/src/lib.rs:429,475`): on store, a key
//! `<prefix>/<rest>` is stored as `<rest>` (prefix removed); on read-back the
//! prefix is re-prepended. Closes the R311wt aligner strip_prefix gap at the
//! LOGIC level.
//!
//! LOGIC ONLY this round (the R311y57 [`crate::storage_manager::StorageManager`]
//! does not yet apply it): zenoh's `Storage::put` takes `key: Option<OwnedKeyExpr>`
//! so it can store the exact-prefix-match value under a NONE key; wz's §5.11
//! [`crate::storage_backend::StorageBackend::put`] takes `key: &str` (no Option),
//! so wiring strip into the manager's live put/get path needs a §5.11 backend
//! Option-key change — a documented follow-up. This module is the faithful
//! strip/restore capability the future storage service applies; [`strip_prefix`]
//! returning `Ok(None)` is exactly the case that backend change must carry.

use crate::keyexpr_prefix::{strip_nonwild_prefix, NonWildError, NonWildKeyExpr};
use alloc::string::String;

/// Why [`strip_prefix`] rejected a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripError {
    /// The configured prefix contains a wildcard (`*` / `**`). zenoh rejects a
    /// wild strip_prefix (`lib.rs:438`); a storage-config check should normally
    /// prevent it ever reaching here.
    WildPrefix,
    /// The key is not prefixed by the configured prefix (zenoh `lib.rs:455`).
    NotPrefixed,
}

impl core::fmt::Display for StripError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StripError::WildPrefix => write!(f, "strip_prefix contains a wildcard"),
            StripError::NotPrefixed => write!(f, "key is not under the strip_prefix"),
        }
    }
}

/// Strip `prefix` from `key`, the store-side transform — zenoh `strip_prefix`
/// (`lib.rs:429`):
/// - `prefix = None` → `Ok(Some(key))` (no prefix configured; key untouched).
/// - `key == prefix` exactly → `Ok(None)` (the value sits AT the mount point,
///   stored under the "none"/empty key — zenoh's `Ok(None)`).
/// - `key` under `<prefix>/…` → `Ok(Some(remainder))`.
/// - `prefix` wild → `Err(WildPrefix)`; `key` not under `prefix` → `Err(NotPrefixed)`.
///
/// The match is at a CHUNK boundary (`<prefix>/`), not a bare string prefix:
/// `home2/x` is NOT under `home`.
///
/// R311y105 — a thin adapter over the shared [`keyexpr_prefix`] SSOT
/// ([`crate::keyexpr_prefix`]): the non-wild validation and the chunk-boundary
/// strip both come from there (a concrete stored key is the wildcard-free
/// special case of the namespace wild-target strip). This module keeps only the
/// storage-specific Option semantics: the exact-mount-point `Ok(None)` and the
/// [`StripError`] classification.
pub fn strip_prefix(prefix: Option<&str>, key: &str) -> Result<Option<String>, StripError> {
    match prefix {
        None => Ok(Some(String::from(key))),
        Some(prefix) => {
            // Non-wildness is now the typed `NonWildKeyExpr` gate (one SSOT,
            // replacing the open-coded `.contains('*')`). For every WELL-FORMED
            // keyexpr (non-empty, no leading/trailing slash, no empty `//`
            // chunk) this adapter is byte-identical to the prior open-coded
            // strip. The only divergences are on DEGENERATE config / keys an
            // empty prefix or a trailing-slash prefix produced under the old
            // code — all unreachable via the sole caller
            // (`storage_state::with_strip_prefix`, whose prefix defaults to
            // `None` and whose key is a real keyexpr, `.ok()`-collapsed). An
            // empty prefix is mapped to `NotPrefixed` (it has no chunk to be
            // under), the closest of the two `StripError` arms.
            let nonwild = match NonWildKeyExpr::new(prefix) {
                Ok(nonwild) => nonwild,
                Err(NonWildError::Wild) => return Err(StripError::WildPrefix),
                Err(NonWildError::Empty) => return Err(StripError::NotPrefixed),
            };
            // The value AT the mount point is stored under the "none"/empty key
            // (zenoh `Ok(None)`). The shared strip returns `None` for an empty
            // suffix (a keyexpr cannot be empty), so the exact-match mount point
            // is the storage-specific case handled here, ahead of the core call.
            if key == prefix {
                return Ok(None);
            }
            match strip_nonwild_prefix(key, nonwild) {
                Some(rest) if !rest.is_empty() => Ok(Some(String::from(rest))),
                _ => Err(StripError::NotPrefixed),
            }
        }
    }
}

/// Re-prepend `prefix` to a stored `stripped` key, the read-side inverse — zenoh
/// `prefix` (`lib.rs:475`):
/// - `(Some p, Some s)` → `<p>/<s>`.
/// - `(Some p, None)` → `<p>` (the exact-prefix-match: the value was stored at the
///   mount point, so its full key IS the prefix).
/// - `(None, Some k)` → `<k>` (no prefix configured).
/// - `(None, None)` → `None` (degenerate both-empty; zenoh bails — wz returns
///   `None` as a non-panicking kernel signal the caller treats as "no key").
pub fn restore_prefix(prefix: Option<&str>, stripped: Option<&str>) -> Option<String> {
    match (prefix, stripped) {
        (Some(p), Some(s)) => {
            let mut out = String::with_capacity(p.len() + 1 + s.len());
            out.push_str(p);
            out.push('/');
            out.push_str(s);
            Some(out)
        }
        (Some(p), None) => Some(String::from(p)),
        (None, Some(k)) => Some(String::from(k)),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    #[test]
    fn no_prefix_passes_key_through() {
        assert_eq!(strip_prefix(None, "a/b/c"), Ok(Some("a/b/c".to_string())));
    }

    #[test]
    fn key_under_prefix_is_stripped() {
        assert_eq!(
            strip_prefix(Some("home/kitchen"), "home/kitchen/temp"),
            Ok(Some("temp".to_string()))
        );
        assert_eq!(
            strip_prefix(Some("a"), "a/b/c"),
            Ok(Some("b/c".to_string()))
        );
    }

    #[test]
    fn key_equal_to_prefix_strips_to_none() {
        // zenoh Ok(None): the value sits AT the mount point (the exact-match case
        // the future backend Option-key change must carry).
        assert_eq!(strip_prefix(Some("home/kitchen"), "home/kitchen"), Ok(None));
    }

    #[test]
    fn key_not_under_prefix_errs() {
        // A bare string prefix that is not a CHUNK prefix must NOT match.
        assert_eq!(
            strip_prefix(Some("home"), "home2/x"),
            Err(StripError::NotPrefixed)
        );
        assert_eq!(
            strip_prefix(Some("home"), "away/x"),
            Err(StripError::NotPrefixed)
        );
    }

    #[test]
    fn wild_prefix_errs() {
        assert_eq!(
            strip_prefix(Some("home/*"), "home/x/y"),
            Err(StripError::WildPrefix)
        );
        assert_eq!(
            strip_prefix(Some("home/**"), "home/x"),
            Err(StripError::WildPrefix)
        );
    }

    #[test]
    fn restore_inverts_strip() {
        // Round-trip: restore(p, strip(p, key)) == key, for a key under OR at p.
        let p = Some("home/kitchen");
        for key in ["home/kitchen/temp", "home/kitchen"] {
            let stripped = strip_prefix(p, key).unwrap();
            assert_eq!(
                restore_prefix(p, stripped.as_deref()),
                Some(key.to_string())
            );
        }
        // No prefix configured: restore(None, Some(k)) == k.
        assert_eq!(restore_prefix(None, Some("a/b")), Some("a/b".to_string()));
        // Degenerate both-None -> None.
        assert_eq!(restore_prefix(None, None), None);
    }
}
