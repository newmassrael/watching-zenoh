// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// GENERATED from the node declaration slot-subject.toml (DECLARATION_SHA256 below) by
// scripts/lib/wz_node.py. Do not edit: a change is made in the declaration and generated again.

pub const NODE_ID: &str = "slot-subject";
/// The digest of the declaration file this was generated from; the node's facts note carries it.
pub const DECLARATION_SHA256: &str = "0632f2b97e01bc44842e72f5ae5cb2e7dd8479beb47970860343838c6f3e8c74";
/// The routers the node dials, as locators.
pub const DIALS: usize = 0;
pub const DIALED: [&str; 0] = [];
/// The peers the node holds by their zid beside the router it dials, each as the sixteen bytes
/// of the zid and the locator it may be found at (decision D7, the third transport).
pub const PEERS: usize = 1;
pub const PEER_NODES: [([u8; 16], &str); 1] = [([195, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "tls/127.0.0.1:17477")];
/// Whether a dialled endpoint, a peer or the listening endpoint is `tls/`, which the node's
/// `tls` feature must be built for.
pub const TLS: bool = true;
/// The secure sessions the node holds at once, which its channel's arena is sized for: a
/// `tls` router it dials, its peers and the sessions its `tls` listener takes.
pub const SECURE_SESSIONS: usize = 1;
/// The files of the identity the device was provisioned with (its certificate chain and the
/// certificate's private key, PEM), or `None` for a node that makes its own key when it starts.
pub const IDENTITY: Option<(&core::ffi::CStr, &core::ffi::CStr)> = Some((c"/etc/wz/slot-subject.crt", c"/etc/wz/slot-subject.key"));
/// Whether the node names a commander: it binds the lifecycle verbs in band (decision D12),
/// which the node's `verbs` feature must be built for.
pub const VERBS: bool = false;
/// Whether the node listens, the locator it listens on (empty when it does not) and how many
/// sessions a peer opened it holds at once.
pub const LISTENS: bool = false;
pub const LISTEN: &str = "";
pub const ACCEPTS: usize = 0;
/// Whether the listening locator is `tls/`, which the node's `listen-tls` feature must be
/// built for.
pub const LISTEN_TLS: bool = false;
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
pub const QUERIERS: usize = 2;
/// The queriers: (key, the period and the timeout in milliseconds, the bytes of a reply each
/// keeps).
pub const QUERIED: [(&str, u32, u32, usize); 2] = [("@/c3/client/session/status/d4", 500, 2000, 256), ("@/c3/client/session/close/d4", 500, 2000, 256)];
/// The cells that keep a latest value: the subscriptions' and then the queriers'.
pub const CELLS: usize = 2;
/// The most bytes any cell keeps: the size of every cell the node holds.
pub const SAMPLE_MAX: usize = 256;
/// The queryables that answer from a cell: (key, index into the cells).
pub const MIRRORS: usize = 0;
pub const MIRRORED: [(&str, usize); 0] = [];
/// The publishers: (key, when its puts are due, the bytes of each put and the fill they are
/// made with, or `None` for a document of that many bytes).
pub const PUBLISHERS: usize = 0;
pub const PUBLISHED: [(&str, wz_session_mcu::slot_publisher::Process, usize, Option<wz_session_mcu::slot_publisher::Fill>); 0] = [];
/// The replays: (key, timing, the declared gap in milliseconds, the speed as written, the
/// ceiling of a gap in milliseconds, the first of its samples, how many).
pub const REPLAYS: usize = 0;
pub const REPLAYED: [(&str, wz_session_mcu::slot_replay::Timing, u64, &str, u64, usize, usize); 0] = [];
/// The replays' samples, each replay's together: (key, bytes, capture time in milliseconds,
/// mutation).
pub const REPLAY_SAMPLES: [(&str, &[u8], Option<u64>, wz_session_mcu::slot_replay::Mutation); 0] = [];
