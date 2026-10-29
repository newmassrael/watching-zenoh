// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where the documents wz serves that upstream does not are keyed.
//!
//! Every such document lives under one root, [`WZ_EXTENSION_ROOT`], outside upstream's `@/`
//! admin namespace: a query for upstream's admin space (`@/**`) cannot intersect any key under
//! it, so upstream's answers are the bytes they were before wz added a document. The keys are
//! here, and not with the admin space's code, so that a host that serves one of them without
//! the rest of the admin space (a pico node serving its resource snapshot) names the key from
//! one place and cannot spell it differently from the host that serves the same document
//! through the full admin space.

use alloc::string::String;

/// The root of the keys wz serves that upstream does not. Outside `@/`, so a query for upstream's
/// admin space (`@/**`) cannot intersect any key under it and upstream's answers are the bytes
/// they were before wz added one.
pub const WZ_EXTENSION_ROOT: &str = "wz";

/// `wz/@/<zid>/<document>`: the key of a document of the node `zid_hex`. The `@` chunk is verbatim,
/// as upstream's admin root is: a wildcard never stands for it, so `wz/**` reaches nothing here
/// and a client asks for the `@` space on purpose.
fn document_key(zid_hex: &str, document: &str) -> String {
    let mut key = String::from(WZ_EXTENSION_ROOT);
    key.push_str("/@/");
    key.push_str(zid_hex);
    key.push('/');
    key.push_str(document);
    key
}

/// The key the capacity report is served at: `wz/@/<zid>/capacity`.
pub fn capacity_report_key(zid_hex: &str) -> String {
    document_key(zid_hex, "capacity")
}

/// The key the node's resource snapshot is served at: `wz/@/<zid>/snapshot`.
pub fn snapshot_key(zid_hex: &str) -> String {
    document_key(zid_hex, "snapshot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documents_are_keyed_under_the_wz_root_by_the_nodes_zid() {
        assert_eq!(capacity_report_key("a1b2"), "wz/@/a1b2/capacity");
        assert_eq!(snapshot_key("a1b2"), "wz/@/a1b2/snapshot");
        assert!(capacity_report_key("x").starts_with(WZ_EXTENSION_ROOT));
    }
}
