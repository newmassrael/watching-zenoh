// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from the node declaration slot-asker.toml (DECLARATION_SHA256 below) by
// scripts/lib/wz_node.py. Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-asker";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "3d9ee24fae81fc53d2cf615d055187440126f3f494b6217d29943842e176add7";
/// The routers the node dials, as locators.
pub const DIALS: usize = 1;
pub const DIALED: [&str; 1] = ["tcp/127.0.0.1:17473"];
/// The peers the node holds by their zid beside the router it dials, each as the sixteen bytes
/// of the zid and the locator it may be found at (decision D7, the third transport).
pub const PEERS: usize = 0;
pub const PEER_NODES: [([u8; 16], &str); 0] = [];
/// Whether a dialled endpoint or a peer is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// Whether the node listens, the locator it listens on (empty when it does not) and how many
/// sessions a peer opened it holds at once.
pub const LISTENS: bool = false;
pub const LISTEN: &str = "";
pub const ACCEPTS: usize = 0;
/// The sessions the node holds at most: the ones it dials, the peers it holds by their zid and
/// the ones a peer opened.
pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;
/// Whether the node is a member of a multicast group.
pub const GROUPS: usize = 0;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 0;
pub const DOCUMENTS: [(&str, usize); 0] = [];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 0;
pub const TOKEN_KEYS: [&str; 0] = [];
/// The queriers the node runs.
pub const QUERIERS: usize = 1;
/// The queriers: (key, the period and the timeout in milliseconds, the bytes of a reply each
/// keeps).
pub const QUERIED: [(&str, u32, u32, usize); 1] = [("lab/ask/val", 500, 1000, 32)];
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 1;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 32;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 1;
pub const MIRRORED: [(&str, usize); 1] = [("lab/ask/val", 0)];
/// The publishers: (key, when its puts are due, the bytes of each put and the fill they are
/// made with, or `None` for a document of that many bytes).
pub const PUBLISHERS: usize = 0;
pub const PUBLISHED: [(&str, wz_session_mcu::slot_publisher::Process, usize, Option<wz_session_mcu::slot_publisher::Fill>); 0] = [];
