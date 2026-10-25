// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-answerer.toml by scripts/lib/wz_node.py --emit slot-answerer.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-answerer";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "8af6a4d6460c8c0bea42ed876b509ac3bbbe060c31a12b4ade397b483f0391fe";
/// The one endpoint the node dials, as a locator.
pub const ROUTER: &str = "tcp/192.168.1.10:7447";
/// Whether that endpoint is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 2;
pub const DOCUMENTS: [(&str, usize); 2] = [("lab/doc/small", 256), ("lab/doc/large", 4096)];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The most bytes any subscription keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 1;
/// The queryables that answer from a subscription: (key, index into `SUBSCRIPTIONS`).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).
pub const PUBLISHERS: usize = 0;
pub const PUBLISHED: [(&str, u32, usize); 0] = [];
