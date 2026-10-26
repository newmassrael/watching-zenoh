// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from the node declaration slot-group.toml (DECLARATION_SHA256 below) by
// scripts/lib/wz_node.py. Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-group";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "13f6ecbc280a530089ee4e5852bf4136542d77c8b609e27cfec5617d8d2283d0";
/// The routers the node dials, as locators.
pub const DIALS: usize = 0;
pub const DIALED: [&str; 0] = [];
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
pub const GROUPS: usize = 1;
/// The locator of the group, the address and port it names, the hop limit of what the node
/// sends and how many members of the group it tracks at once.
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
/// The liveliness tokens the node declares on every session, by key.
pub const TOKENS: usize = 0;
pub const TOKEN_KEYS: [&str; 0] = [];
/// The queriers the node runs.
pub const QUERIERS: usize = 0;
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 1;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 64;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, when its puts are due, the bytes of each put and the fill they are
/// made with, or `None` for a document of that many bytes).
pub const PUBLISHERS: usize = 1;
pub const PUBLISHED: [(&str, wz_session_mcu::slot_publisher::Process, usize, Option<wz_session_mcu::slot_publisher::Fill>); 1] = [("lab/group/beat", wz_session_mcu::slot_publisher::Process::Periodic { gap_nanos: 200000000 }, 8, None)];
/// The replays: (key, timing, the declared gap in milliseconds, the speed as written, the
/// ceiling of a gap in milliseconds, the first of its samples, how many).
pub const REPLAYS: usize = 0;
pub const REPLAYED: [(&str, wz_session_mcu::slot_replay::Timing, u64, &str, u64, usize, usize); 0] = [];
/// The replays' samples, each replay's together: (key, bytes, capture time in milliseconds,
/// mutation).
pub const REPLAY_SAMPLES: [(&str, &[u8], Option<u64>, wz_session_mcu::slot_replay::Mutation); 0] = [];
