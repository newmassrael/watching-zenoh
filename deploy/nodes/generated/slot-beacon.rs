// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-beacon.toml by scripts/lib/wz_node.py --emit slot-beacon.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-beacon";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "5b3a93c590022a18af3bea9c4f4c79e76ee73e802b1be83db8a3090931c1d55c";
/// The routers the node dials, as locators.
pub const DIALS: usize = 1;
pub const DIALED: [&str; 1] = ["tcp/127.0.0.1:17474"];
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
pub const DOCS: usize = 1;
pub const DOCUMENTS: [(&str, usize); 1] = [("lab/beacon/info", 16)];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The queriers the node runs: (key, the period and the timeout in milliseconds, the bytes of a
/// reply each keeps).
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 4;
pub const TOKEN_KEYS: [&str; 4] = ["lab/alive/a", "lab/alive/b", "lab/alive/c", "lab/alive/d"];
pub const QUERIERS: usize = 0;
pub const QUERIED: [(&str, u32, u32, usize); 0] = [];
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 0;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 1;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).
pub const PUBLISHERS: usize = 0;
pub const PUBLISHED: [(&str, u32, usize); 0] = [];
