// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-answerer.toml by scripts/lib/wz_node.py --emit slot-answerer.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-answerer";
/// The one endpoint the node dials, as a locator.
pub const ROUTER: &str = "tcp/192.168.1.10:7447";
/// Whether that endpoint is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 2;
pub const DOCUMENTS: [(&str, usize); 2] = [("lab/doc/small", 256), ("lab/doc/large", 4096)];
