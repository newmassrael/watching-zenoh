// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-asker.toml by scripts/lib/wz_node.py --emit slot-asker.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-asker";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "46b6b79350dc8e8f796790d6e1b5a14f896d9e315b476290d604d51cda15e08a";
/// The routers the node dials, as locators.
pub const DIALS: usize = 1;
pub const DIALED: [&str; 1] = ["tcp/127.0.0.1:17473"];
/// Whether a dialled endpoint is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// Whether the node listens, the locator it listens on (empty when it does not), the address
/// and port that locator names, and how many sessions a peer opened it holds at once.
pub const LISTENS: bool = false;
pub const LISTEN: &str = "";
pub const LISTEN_ADDR: [u8; 4] = [0, 0, 0, 0];
pub const LISTEN_PORT: u16 = 0;
pub const ACCEPTS: usize = 0;
/// The sessions the node holds at most: the ones it dials and the ones a peer opened.
pub const SESSIONS: usize = DIALS + ACCEPTS;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 0;
pub const DOCUMENTS: [(&str, usize); 0] = [];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The queriers the node runs: (key, the period and the timeout in milliseconds, the bytes of a
/// reply each keeps).
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 0;
pub const TOKEN_KEYS: [&str; 0] = [];
pub const QUERIERS: usize = 1;
pub const QUERIED: [(&str, u32, u32, usize); 1] = [("lab/ask/val", 500, 1000, 32)];
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 1;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 32;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 1;
pub const MIRRORED: [(&str, usize); 1] = [("lab/ask/val", 0)];
/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).
pub const PUBLISHERS: usize = 0;
pub const PUBLISHED: [(&str, u32, usize); 0] = [];
