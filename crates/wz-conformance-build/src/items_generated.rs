// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-conformance-items.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The questions a conformance statement answers (docs/build-configuration.md, decision C15),
//! in the declaration's order, and where a build script finds each answer.

/// `format` of the statement.
pub const FORMAT: &str = "wz-conformance-statement";
/// `format_version` of the statement.
pub const FORMAT_VERSION: u32 = 2;
/// The declaration's `catalog_version`.
pub const CATALOG_VERSION: u32 = 2;

/// Each capability and the ABIs that export it: its cargo feature in those crates has its id.
pub const CAPABILITIES: &[(&str, &[&str])] = &[
    ("link-udp", &["core", "pico", "c"]),
    ("timestamping", &["core", "c"]),
    ("scout", &["core", "pico", "c"]),
    ("peer", &["core", "pico", "c"]),
    ("multicast-transport", &["core", "pico", "c"]),
    ("multicast-declarations", &["core", "pico"]),
    ("raweth-transport", &["core", "pico"]),
    ("query", &["core", "pico", "c"]),
    ("queryable", &["core", "pico", "c"]),
    ("liveliness", &["core", "pico", "c"]),
    ("liveliness-get", &["core", "pico", "c"]),
    ("advanced", &["core", "pico", "c"]),
    ("clock-source", &["core", "pico", "c"]),
    ("event-ring", &["core", "pico", "c"]),
    ("supervision", &["core", "pico", "c"]),
    ("resource-snapshot", &["core", "pico", "c"]),
    ("pool-monitor", &["core"]),
    ("declarations-synced-event", &["core"]),
    ("remote-declaration-watch", &["core"]),
    ("group", &["core", "c"]),
    ("gossip", &["core", "pico", "c"]),
    ("router-node", &["core", "c"]),
    ("unstable-api", &["core", "pico"]),
    ("connectivity", &["core", "pico"]),
    ("admin-space", &["core", "pico"]),
    ("local-subscriber", &["core", "pico"]),
    ("local-queryable", &["core", "pico"]),
    ("multi-thread", &["core", "pico"]),
    ("transport_tls", &["core", "c"]),
    ("transport_quic", &["core", "c"]),
    ("transport_quic_datagram", &["core", "c"]),
    ("transport_ws", &["core", "c"]),
    ("transport_unixsock-stream", &["core", "c"]),
    ("transport_multilink", &["core", "c"]),
    ("auth_pubkey", &["core", "c"]),
    ("e2e-sender", &["core", "c"]),
    ("identity-make", &["core", "c"]),
    ("lifecycle-doors", &["core", "c"]),
    ("transport_compression", &["core", "c"]),
    ("auth_usrpwd", &["core", "c"]),
    ("interceptors", &["core", "c"]),
];

/// Each layout switch that is not a capability (`wz_config.arm_switches`) and the ABIs whose
/// crate has it as a feature: it selects the arm of the C types a program allocates.
pub const ARM: &[(&str, &[&str])] = &[
    ("zenoh-c-shared-memory", &["c"]),
    ("zenoh-c-no-unstable-api", &["c"]),
];

/// Each limit, the environment name a build states it by, and its default.
pub const LIMITS: &[(&str, &str, u64)] = &[
    ("MAX_KEYEXPR_BYTES", "WZ_LIMIT_MAX_KEYEXPR_BYTES", 256),
    ("MAX_SUBSCRIPTIONS", "WZ_LIMIT_MAX_SUBSCRIPTIONS", 16),
    ("MATCH_MEMO_SLOTS", "WZ_LIMIT_MATCH_MEMO_SLOTS", 8),
    (
        "MATCH_MEMO_FIXED_SLOTS",
        "WZ_LIMIT_MATCH_MEMO_FIXED_SLOTS",
        0,
    ),
    ("MATCH_MEMO_KEY_BYTES", "WZ_LIMIT_MATCH_MEMO_KEY_BYTES", 64),
    ("DELIVERY_LANE_EVENTS", "WZ_LIMIT_DELIVERY_LANE_EVENTS", 64),
    ("DELIVERY_LANE_BYTES", "WZ_LIMIT_DELIVERY_LANE_BYTES", 65536),
    (
        "DELIVERY_LANE_CALLBACKS",
        "WZ_LIMIT_DELIVERY_LANE_CALLBACKS",
        256,
    ),
    ("MAX_QUERYABLES", "WZ_LIMIT_MAX_QUERYABLES", 16),
    ("MAX_PENDING_QUERIES", "WZ_LIMIT_MAX_PENDING_QUERIES", 16),
    ("MAX_DECL_OBSERVERS", "WZ_LIMIT_MAX_DECL_OBSERVERS", 8),
    (
        "MAX_LIVELINESS_SUBSCRIPTIONS",
        "WZ_LIMIT_MAX_LIVELINESS_SUBSCRIPTIONS",
        8,
    ),
    ("MAX_LOCAL_TOKENS", "WZ_LIMIT_MAX_LOCAL_TOKENS", 8),
    (
        "MAX_PENDING_LIVELINESS_GETS",
        "WZ_LIMIT_MAX_PENDING_LIVELINESS_GETS",
        8,
    ),
    ("MAX_PENDING_DECLARES", "WZ_LIMIT_MAX_PENDING_DECLARES", 32),
    (
        "MAX_INBOUND_SUB_INTERESTS",
        "WZ_LIMIT_MAX_INBOUND_SUB_INTERESTS",
        16,
    ),
    (
        "MAX_PEER_KEYEXPR_ALIASES",
        "WZ_LIMIT_MAX_PEER_KEYEXPR_ALIASES",
        16,
    ),
    ("MAX_REMOTE_DECLS", "WZ_LIMIT_MAX_REMOTE_DECLS", 16),
    ("MAX_PENDING_REPLIES", "WZ_LIMIT_MAX_PENDING_REPLIES", 8),
    ("MAX_PENDING_FINALS", "WZ_LIMIT_MAX_PENDING_FINALS", 8),
    (
        "MAX_REPLY_PAYLOAD_BYTES",
        "WZ_LIMIT_MAX_REPLY_PAYLOAD_BYTES",
        1024,
    ),
    (
        "MAX_ADMIN_REPLY_BYTES",
        "WZ_LIMIT_MAX_ADMIN_REPLY_BYTES",
        1024,
    ),
    ("MAX_ADMIN_LOCATORS", "WZ_LIMIT_MAX_ADMIN_LOCATORS", 4),
    (
        "MAX_ADMIN_SESSION_LINKS",
        "WZ_LIMIT_MAX_ADMIN_SESSION_LINKS",
        2,
    ),
    ("MAX_MULTICAST_REPLIES", "WZ_LIMIT_MAX_MULTICAST_REPLIES", 8),
    ("MAX_TASKS", "WZ_LIMIT_MAX_TASKS", 8),
    ("MAX_TIMERS", "WZ_LIMIT_MAX_TIMERS", 16),
    ("MAX_LOCATOR_LEN", "WZ_LIMIT_MAX_LOCATOR_LEN", 64),
    ("MAX_STATIC_CONNECT", "WZ_LIMIT_MAX_STATIC_CONNECT", 8),
    ("MAX_PEER_NODES", "WZ_LIMIT_MAX_PEER_NODES", 0),
    (
        "QUERIER_MAX_PENDING_QUERIES",
        "WZ_LIMIT_QUERIER_MAX_PENDING_QUERIES",
        0,
    ),
    (
        "TX_NO_PROGRESS_WINDOW_US",
        "WZ_LIMIT_TX_NO_PROGRESS_WINDOW_US",
        1000000,
    ),
    ("TX_EXPIRY_CLOSE_AFTER", "WZ_LIMIT_TX_EXPIRY_CLOSE_AFTER", 0),
    (
        "DATAGRAM_FRAGMENT_BURST",
        "WZ_LIMIT_DATAGRAM_FRAGMENT_BURST",
        8,
    ),
    (
        "DATAGRAM_FRAGMENT_GAP_US",
        "WZ_LIMIT_DATAGRAM_FRAGMENT_GAP_US",
        1000,
    ),
    (
        "QUERY_PARAMETERS_MAX_BYTES",
        "WZ_LIMIT_QUERY_PARAMETERS_MAX_BYTES",
        0,
    ),
    (
        "QUERY_ATTACHMENT_MAX_BYTES",
        "WZ_LIMIT_QUERY_ATTACHMENT_MAX_BYTES",
        0,
    ),
    ("HANDSHAKE_INIT_MS", "WZ_LIMIT_HANDSHAKE_INIT_MS", 2000),
    ("HANDSHAKE_OPEN_MS", "WZ_LIMIT_HANDSHAKE_OPEN_MS", 2000),
    (
        "HANDSHAKE_COOKIE_BYTES",
        "WZ_LIMIT_HANDSHAKE_COOKIE_BYTES",
        128,
    ),
    ("PICO_TX_QUEUE_SIZE", "WZ_LIMIT_PICO_TX_QUEUE_SIZE", 8),
    ("SNAPSHOT_PERIOD_MS", "WZ_LIMIT_SNAPSHOT_PERIOD_MS", 1000),
    (
        "SNAPSHOT_HISTOGRAM_BUCKETS",
        "WZ_LIMIT_SNAPSHOT_HISTOGRAM_BUCKETS",
        24,
    ),
    (
        "SUPERVISION_CHECKPOINTS",
        "WZ_LIMIT_SUPERVISION_CHECKPOINTS",
        4,
    ),
    ("EVENT_RING_SLOTS", "WZ_LIMIT_EVENT_RING_SLOTS", 64),
    ("EVENT_RECORD_ARGS", "WZ_LIMIT_EVENT_RECORD_ARGS", 4),
    ("CLOCK_SOURCES", "WZ_LIMIT_CLOCK_SOURCES", 1),
    (
        "CLOCK_MAX_FORWARD_STEP_MS",
        "WZ_LIMIT_CLOCK_MAX_FORWARD_STEP_MS",
        500,
    ),
    (
        "DECLARATION_SYNC_BURST_MESSAGES",
        "WZ_LIMIT_DECLARATION_SYNC_BURST_MESSAGES",
        8,
    ),
    (
        "DECLARATION_SYNC_FINAL_TIMEOUT_MS",
        "WZ_LIMIT_DECLARATION_SYNC_FINAL_TIMEOUT_MS",
        1000,
    ),
    (
        "DECLARATION_SYNC_INTERVAL_MS",
        "WZ_LIMIT_DECLARATION_SYNC_INTERVAL_MS",
        10,
    ),
    (
        "PICO_UNICAST_BATCH_BYTES",
        "WZ_LIMIT_PICO_UNICAST_BATCH_BYTES",
        2048,
    ),
    (
        "PICO_MULTICAST_BATCH_BYTES",
        "WZ_LIMIT_PICO_MULTICAST_BATCH_BYTES",
        2048,
    ),
    ("PICO_LEASE_MS", "WZ_LIMIT_PICO_LEASE_MS", 10000),
    (
        "PICO_SOCKET_TIMEOUT_MS",
        "WZ_LIMIT_PICO_SOCKET_TIMEOUT_MS",
        100,
    ),
    (
        "PICO_CONNECT_TIMEOUT_MS",
        "WZ_LIMIT_PICO_CONNECT_TIMEOUT_MS",
        10000,
    ),
    ("PICO_FRAG_MAX_BYTES", "WZ_LIMIT_PICO_FRAG_MAX_BYTES", 4096),
    (
        "PICO_ACCEPT_TIMEOUT_MS",
        "WZ_LIMIT_PICO_ACCEPT_TIMEOUT_MS",
        1000,
    ),
    (
        "PICO_KEEPALIVES_PER_LEASE",
        "WZ_LIMIT_PICO_KEEPALIVES_PER_LEASE",
        3,
    ),
];

/// Each policy, the environment name a build states it by, the values it may take (`off`
/// and `on` for a bool), and upstream's value, which a build that states none runs.
pub const POLICIES: &[(&str, &str, &[&str], &str)] = &[
    (
        "multicast-loopback",
        "WZ_POLICY_MULTICAST_LOOPBACK",
        &["os-default", "on", "off"],
        "os-default",
    ),
    (
        "tx-no-progress-deadline",
        "WZ_POLICY_TX_NO_PROGRESS_DEADLINE",
        &["off", "on"],
        "off",
    ),
    (
        "tx-expiry-keeps-session",
        "WZ_POLICY_TX_EXPIRY_KEEPS_SESSION",
        &["off", "on"],
        "off",
    ),
    (
        "declaration-sync-pacing",
        "WZ_POLICY_DECLARATION_SYNC_PACING",
        &["off", "on"],
        "off",
    ),
    (
        "datagram-fragment-pacing",
        "WZ_POLICY_DATAGRAM_FRAGMENT_PACING",
        &["off", "on"],
        "off",
    ),
    (
        "multicast-link-requires-iface",
        "WZ_POLICY_MULTICAST_LINK_REQUIRES_IFACE",
        &["off", "on"],
        "off",
    ),
    (
        "entity-timestamp-opt-in",
        "WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN",
        &["off", "on"],
        "off",
    ),
    (
        "reply-auto-timestamp",
        "WZ_POLICY_REPLY_AUTO_TIMESTAMP",
        &["off", "on"],
        "off",
    ),
    (
        "subscriber-overload",
        "WZ_POLICY_SUBSCRIBER_OVERLOAD",
        &["block", "reject", "keep-latest"],
        "block",
    ),
    ("key-set", "WZ_POLICY_KEY_SET", &["open", "closed"], "open"),
    (
        "sn-resolution",
        "WZ_POLICY_SN_RESOLUTION",
        &["bits-32", "bits-8", "bits-16", "bits-64"],
        "bits-32",
    ),
    (
        "supervision-after-expiry",
        "WZ_POLICY_SUPERVISION_AFTER_EXPIRY",
        &["latch", "rearm"],
        "latch",
    ),
    (
        "event-ring-full",
        "WZ_POLICY_EVENT_RING_FULL",
        &["overwrite-oldest", "drop-newest"],
        "overwrite-oldest",
    ),
    (
        "clock-quality-stamping",
        "WZ_POLICY_CLOCK_QUALITY_STAMPING",
        &["always", "trusted-only"],
        "always",
    ),
    (
        "routing-face-drive",
        "WZ_POLICY_ROUTING_FACE_DRIVE",
        &["task-per-face", "one-task"],
        "task-per-face",
    ),
    (
        "routing-table-sharing",
        "WZ_POLICY_ROUTING_TABLE_SHARING",
        &["rwlock", "snapshot"],
        "rwlock",
    ),
];
