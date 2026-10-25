// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-reporter.toml by scripts/lib/wz_node.py --emit slot-reporter.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-reporter";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "6ed28a962b15aa69b149df5169e887d97f75b2db9d95f6931a2b727e3866e9bb";
/// The one endpoint the node dials, as a locator.
pub const ROUTER: &str = "tcp/127.0.0.1:17472";
/// Whether that endpoint is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 0;
pub const DOCUMENTS: [(&str, usize); 0] = [];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The most bytes any subscription keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 1;
/// The queryables that answer from a subscription: (key, index into `SUBSCRIPTIONS`).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).
pub const PUBLISHERS: usize = 1;
pub const PUBLISHED: [(&str, u32, usize); 1] = [("lab/out/beat", 200, 8)];
