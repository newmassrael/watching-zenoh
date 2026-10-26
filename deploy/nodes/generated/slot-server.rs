// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from the node declaration slot-server.toml (DECLARATION_SHA256 below) by
// scripts/lib/wz_node.py. Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-server";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "cad8853e46c49f987c80d6b909aca023987e156bca3ddaefbeb5dcfa91494c69";
/// The routers the node dials, as locators.
pub const DIALS: usize = 0;
pub const DIALED: [&str; 0] = [];
/// The peers the node holds by their zid beside the router it dials, each as the sixteen bytes
/// of the zid and the locator it may be found at (decision D7, the third transport).
pub const PEERS: usize = 0;
pub const PEER_NODES: [([u8; 16], &str); 0] = [];
/// Whether a dialled endpoint or a peer is `tls/`, which the node's `tls` feature must be built for.
pub const TLS: bool = false;
/// Whether the node listens, the locator it listens on (empty when it does not), the address
/// and port that locator names, and how many sessions a peer opened it holds at once.
pub const LISTENS: bool = true;
pub const LISTEN: &str = "tcp/127.0.0.1:17475";
pub const LISTEN_ADDR: [u8; 4] = [127, 0, 0, 1];
pub const LISTEN_PORT: u16 = 17475;
pub const ACCEPTS: usize = 2;
/// The sessions the node holds at most: the ones it dials, the peers it holds by their zid and
/// the ones a peer opened.
pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;
/// Whether the node is a member of a multicast group, the locator of the group (empty when it
/// is not), the address and port that locator names, the hop limit of what it sends and how
/// many members of the group it tracks at once.
pub const GROUPS: usize = 0;
pub const GROUP: &str = "";
pub const GROUP_ADDR: [u8; 4] = [0, 0, 0, 0];
pub const GROUP_PORT: u16 = 0;
pub const GROUP_TTL: u8 = 1;
pub const MEMBERS: usize = 0;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 2;
pub const DOCUMENTS: [(&str, usize); 2] = [("lab/server/small", 16), ("lab/server/large", 256)];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 0;
pub const SUBSCRIPTIONS: [(&str, usize); 0] = [];
/// The queriers the node runs: (key, the period and the timeout in milliseconds, the bytes of a
/// reply each keeps).
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 0;
pub const TOKEN_KEYS: [&str; 0] = [];
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
