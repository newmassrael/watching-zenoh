// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-conformance-items.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The questions a conformance statement answers (a build states what it is, from
//! the configuration it was built with), in the declaration's order, and where a
//! build script finds each answer.

/// `format` of the statement.
pub const FORMAT: &str = "wz-conformance-statement";
/// `format_version` of the statement.
pub const FORMAT_VERSION: u32 = 3;
/// The declaration's `catalog_version`.
pub const CATALOG_VERSION: u32 = 2;

/// The features of the pico ABI's crate that run its sessions on the cooperative engine, when
/// the tokio engine is not in the build; every other build runs them on the tokio engine.
pub const COOP_ENGINE_FEATURES: &[&str] = &["engine-coop", "os-posix", "os-windows", "os-zephyr"];
/// The features that build a library for a platform other than a host, each with its word.
pub const PLATFORM_FEATURES: &[(&str, &str)] = &[("os-zephyr", "zephyr")];

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
    ("session-memory", &["core", "pico"]),
    ("declarations-synced-event", &["core", "pico"]),
    ("remote-declaration-watch", &["core", "pico"]),
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
    ("e2e-sender", &["core", "pico", "c"]),
    ("e2e-receiver", &["core", "pico"]),
    ("e2e-sender-demux", &["core", "pico"]),
    ("instance-key", &["core", "pico"]),
    ("config-verdict", &["core", "c"]),
    ("identity-make", &["core", "c"]),
    ("lifecycle-doors", &["core", "c"]),
    ("segment-sender", &["core", "pico", "c"]),
    ("e2e-supervision", &["core", "pico"]),
    ("replay-cache", &["core", "pico"]),
    ("message-catalog", &["core", "pico"]),
    ("message-payload", &["core", "pico"]),
    ("app-transport", &["core", "pico"]),
    ("time-base", &["core", "pico", "c"]),
    ("object-pool", &["core", "pico"]),
    ("object-pool-region", &["core", "pico"]),
    ("shared-key-ids", &["core", "pico", "c"]),
    ("rx-callback-offload", &["core", "c"]),
    ("switch-doors", &["core", "c"]),
    ("config-policy", &["core", "pico"]),
    ("conformance-digest", &["core", "pico"]),
    ("config-document", &["core", "pico"]),
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
    ("KEY_ARENA_BYTES", "WZ_LIMIT_KEY_ARENA_BYTES", 97152),
    ("MAX_SUBSCRIPTIONS", "WZ_LIMIT_MAX_SUBSCRIPTIONS", 100),
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
    ("MAX_QUERYABLES", "WZ_LIMIT_MAX_QUERYABLES", 100),
    ("MAX_PENDING_QUERIES", "WZ_LIMIT_MAX_PENDING_QUERIES", 16),
    ("LINK_NOTED_REQUESTS", "WZ_LIMIT_LINK_NOTED_REQUESTS", 16),
    ("MAX_DECL_OBSERVERS", "WZ_LIMIT_MAX_DECL_OBSERVERS", 8),
    (
        "MAX_LIVELINESS_SUBSCRIPTIONS",
        "WZ_LIMIT_MAX_LIVELINESS_SUBSCRIPTIONS",
        8,
    ),
    ("MAX_LOCAL_TOKENS", "WZ_LIMIT_MAX_LOCAL_TOKENS", 8),
    ("MAX_PUBLISHERS", "WZ_LIMIT_MAX_PUBLISHERS", 100),
    ("MAX_QUERIERS", "WZ_LIMIT_MAX_QUERIERS", 16),
    (
        "MAX_MATCHING_LISTENERS",
        "WZ_LIMIT_MAX_MATCHING_LISTENERS",
        16,
    ),
    (
        "MAX_DECLARED_KEYEXPRS",
        "WZ_LIMIT_MAX_DECLARED_KEYEXPRS",
        332,
    ),
    ("HELD_SESSIONS", "WZ_LIMIT_HELD_SESSIONS", 4),
    ("HELD_SAMPLES", "WZ_LIMIT_HELD_SAMPLES", 18),
    ("HELD_REPLIES", "WZ_LIMIT_HELD_REPLIES", 18),
    ("HELD_QUERIES", "WZ_LIMIT_HELD_QUERIES", 18),
    ("HELD_PAYLOADS", "WZ_LIMIT_HELD_PAYLOADS", 32),
    ("HELD_CONFIGS", "WZ_LIMIT_HELD_CONFIGS", 8),
    ("HELD_HELLOS", "WZ_LIMIT_HELD_HELLOS", 16),
    ("HELD_PAYLOAD_BYTES", "WZ_LIMIT_HELD_PAYLOAD_BYTES", 131072),
    ("CONFIG_ENTRIES", "WZ_LIMIT_CONFIG_ENTRIES", 32),
    ("MAX_SCOUT_HELLOS", "WZ_LIMIT_MAX_SCOUT_HELLOS", 16),
    ("SCOUT_HELLO_LOCATORS", "WZ_LIMIT_SCOUT_HELLO_LOCATORS", 8),
    (
        "CONFIG_DOCUMENT_DEPTH",
        "WZ_LIMIT_CONFIG_DOCUMENT_DEPTH",
        16,
    ),
    ("CONFIG_TEXT_BYTES", "WZ_LIMIT_CONFIG_TEXT_BYTES", 16384),
    (
        "MAX_PENDING_LIVELINESS_GETS",
        "WZ_LIMIT_MAX_PENDING_LIVELINESS_GETS",
        8,
    ),
    ("MAX_PENDING_DECLARES", "WZ_LIMIT_MAX_PENDING_DECLARES", 101),
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
    ("MAX_SHARED_KEY_IDS", "WZ_LIMIT_MAX_SHARED_KEY_IDS", 256),
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
    ("MAX_TASKS", "WZ_LIMIT_MAX_TASKS", 16),
    ("MAX_TIMERS", "WZ_LIMIT_MAX_TIMERS", 16),
    ("MAX_TICKERS", "WZ_LIMIT_MAX_TICKERS", 16),
    ("MAX_LOCATOR_LEN", "WZ_LIMIT_MAX_LOCATOR_LEN", 64),
    ("MAX_STATIC_CONNECT", "WZ_LIMIT_MAX_STATIC_CONNECT", 8),
    ("MAX_PEER_NODES", "WZ_LIMIT_MAX_PEER_NODES", 0),
    ("MAX_FACES", "WZ_LIMIT_MAX_FACES", 1000),
    ("MAX_ACCEPT_PENDING", "WZ_LIMIT_MAX_ACCEPT_PENDING", 100),
    ("RX_POOL_BUFFERS", "WZ_LIMIT_RX_POOL_BUFFERS", 4),
    ("TX_POOL_SLOTS", "WZ_LIMIT_TX_POOL_SLOTS", 4),
    (
        "SESSION_MAX_PEER_KEYEXPR_ALIASES",
        "WZ_LIMIT_SESSION_MAX_PEER_KEYEXPR_ALIASES",
        16016,
    ),
    (
        "SESSION_MAX_REMOTE_DECLS",
        "WZ_LIMIT_SESSION_MAX_REMOTE_DECLS",
        16016,
    ),
    (
        "SESSION_MAX_INBOUND_SUB_INTERESTS",
        "WZ_LIMIT_SESSION_MAX_INBOUND_SUB_INTERESTS",
        16016,
    ),
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
    (
        "HANDSHAKE_COOKIE_BYTES",
        "WZ_LIMIT_HANDSHAKE_COOKIE_BYTES",
        176,
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
    (
        "E2E_SUPERVISED_STREAMS",
        "WZ_LIMIT_E2E_SUPERVISED_STREAMS",
        32,
    ),
    (
        "APP_LINK_QUEUE_BYTES",
        "WZ_LIMIT_APP_LINK_QUEUE_BYTES",
        262144,
    ),
    ("EVENT_RING_SLOTS", "WZ_LIMIT_EVENT_RING_SLOTS", 64),
    ("EVENT_RECORD_ARGS", "WZ_LIMIT_EVENT_RECORD_ARGS", 4),
    ("CLOCK_SOURCES", "WZ_LIMIT_CLOCK_SOURCES", 1),
    ("E2E_SENDER_SLOTS", "WZ_LIMIT_E2E_SENDER_SLOTS", 8),
    ("REPLAY_DEPTH_MAX", "WZ_LIMIT_REPLAY_DEPTH_MAX", 32),
    (
        "MESSAGE_CATALOG_ENTRIES",
        "WZ_LIMIT_MESSAGE_CATALOG_ENTRIES",
        64,
    ),
    ("INSTANCE_KEY_FIELDS", "WZ_LIMIT_INSTANCE_KEY_FIELDS", 2),
    (
        "INSTANCES_PER_MESSAGE",
        "WZ_LIMIT_INSTANCES_PER_MESSAGE",
        32,
    ),
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
        "DECLARATION_SYNC_RX_NO_PROGRESS_MS",
        "WZ_LIMIT_DECLARATION_SYNC_RX_NO_PROGRESS_MS",
        0,
    ),
    (
        "DECLARATION_SYNC_RETRY_INTERVAL_MS",
        "WZ_LIMIT_DECLARATION_SYNC_RETRY_INTERVAL_MS",
        0,
    ),
    (
        "DECLARATION_SYNC_TX_NO_PROGRESS_MS",
        "WZ_LIMIT_DECLARATION_SYNC_TX_NO_PROGRESS_MS",
        0,
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
        "reliable-gap-reconnect",
        "WZ_POLICY_RELIABLE_GAP_RECONNECT",
        &[
            "off",
            "until-declarations-synced",
            "always",
            "until-declarations-synced-when-begun",
        ],
        "off",
    ),
    (
        "entity-link-restriction",
        "WZ_POLICY_ENTITY_LINK_RESTRICTION",
        &["off", "on"],
        "off",
    ),
    (
        "targeted-query",
        "WZ_POLICY_TARGETED_QUERY",
        &["off", "on"],
        "off",
    ),
    (
        "publisher-admission-retry",
        "WZ_POLICY_PUBLISHER_ADMISSION_RETRY",
        &["off", "on"],
        "off",
    ),
    (
        "multi-route-atomic-tx",
        "WZ_POLICY_MULTI_ROUTE_ATOMIC_TX",
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
        "e2e-supervision-notify",
        "WZ_POLICY_E2E_SUPERVISION_NOTIFY",
        &["status-only", "last-value"],
        "status-only",
    ),
    (
        "replay-reply-shape",
        "WZ_POLICY_REPLAY_REPLY_SHAPE",
        &["frame-per-sample", "segmented"],
        "frame-per-sample",
    ),
    (
        "replay-serve-holds-sends",
        "WZ_POLICY_REPLAY_SERVE_HOLDS_SENDS",
        &["off", "on"],
        "off",
    ),
    (
        "replay-live-before-answer",
        "WZ_POLICY_REPLAY_LIVE_BEFORE_ANSWER",
        &["deliver", "hold-back"],
        "deliver",
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
    (
        "reassembly-pool-overflow",
        "WZ_POLICY_REASSEMBLY_POOL_OVERFLOW",
        &["reject", "diagnostic-event", "oldest-wins"],
        "reject",
    ),
    (
        "link-tie-order",
        "WZ_POLICY_LINK_TIE_ORDER",
        &["zid-number", "zid-bytes"],
        "zid-number",
    ),
    (
        "query-unanswerable-final",
        "WZ_POLICY_QUERY_UNANSWERABLE_FINAL",
        &["none", "empty-final"],
        "none",
    ),
    (
        "zid-derivation",
        "WZ_POLICY_ZID_DERIVATION",
        &["random", "address-ports"],
        "random",
    ),
    (
        "handshake-stray-message",
        "WZ_POLICY_HANDSHAKE_STRAY_MESSAGE",
        &["fail", "ignore", "ignore-and-replay"],
        "fail",
    ),
    (
        "handshake-cookie",
        "WZ_POLICY_HANDSHAKE_COOKIE",
        &["stateless", "fixed"],
        "stateless",
    ),
    (
        "key-wire-form",
        "WZ_POLICY_KEY_WIRE_FORM",
        &["declared", "shared", "literal"],
        "declared",
    ),
];
