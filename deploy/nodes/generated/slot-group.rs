// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from deploy/nodes/slot-group.toml by scripts/lib/wz_node.py --emit slot-group.
// Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-group";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "f18f465859a7c002476aa746bb1f6f3e9eba843550695f3cbf8678b185433e9d";
/// The routers the node dials, as locators.
pub const DIALS: usize = 0;
pub const DIALED: [&str; 0] = [];
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
/// Whether the node is a member of a multicast group, the locator of the group (empty when it
/// is not), the address and port that locator names, the hop limit of what it sends and how
/// many members of the group it tracks at once.
pub const GROUPS: usize = 1;
pub const GROUP: &str = "udp/224.0.0.224:7490";
pub const GROUP_ADDR: [u8; 4] = [224, 0, 0, 224];
pub const GROUP_PORT: u16 = 7490;
pub const GROUP_TTL: u8 = 1;
pub const MEMBERS: usize = 8;
/// The queryables the node declares, and the documents they answer with: (key, bytes).
pub const DOCS: usize = 0;
pub const DOCUMENTS: [(&str, usize); 0] = [];
/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).
pub const SUBSCRIBERS: usize = 1;
pub const SUBSCRIPTIONS: [(&str, usize); 1] = [("lab/group/in", 64)];
/// The queriers the node runs: (key, the period and the timeout in milliseconds, the bytes of a
/// reply each keeps).
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 0;
pub const TOKEN_KEYS: [&str; 0] = [];
pub const QUERIERS: usize = 0;
pub const QUERIED: [(&str, u32, u32, usize); 0] = [];
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 1;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 64;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).
pub const PUBLISHERS: usize = 1;
pub const PUBLISHED: [(&str, u32, usize); 1] = [("lab/group/beat", 200, 8)];
