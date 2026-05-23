# Feature inventory — composable framework atomic + preset catalog

**Status.** R301 entry. First-pass catalog of ~142 atomic features
across 19 domains plus 6 initial semver-named presets. Materializes
the composable-framework north star (R267 ratify, R299+ refined) by
naming the contract every future SCXML / Rust crate must conform to
when emitting a per-cargo-feature subset of zenoh's full feature
catalog.

**Scope.** This document defines the *names* and *3-test verdicts*
for atomic features + the *named contracts* for presets. The actual
emission mechanism (`<sce:requires feature="X"/>` SCXML attribute,
`Cargo.toml::[features]` table, etc.) is referenced as the R302+
open carry — §7 and §8 below are placeholders.

**Inputs (normative).** zenoh upstream 1.5.0 (vendored at
`~/.cargo/git/checkouts/zenoh-*/49c8a53/`); zenoh-pico
(`~/zenoh-pico/`); zenoh-cpp public API shape as the cross-feature
consistency anchor; current wz-runtime-tokio / wz-codecs /
wz-runtime-core / sources/{algorithms,codecs,session,links}
implementation snapshot at HEAD `5f2b3cc` (R300 close).

**Outputs.** ~142 atomic feature names following the
`<domain>-<capability>` convention, with each entry labelled
*active* (implemented in wz at R300) or *reserved* (roadmap, not
yet implemented but plausibility-confirmed against upstream). 6
preset names following the `preset-<target>-<level>` convention.
3-test definitions (Footprint / Plausibility / Coherence). Conflict
policy: silently ALLOW (cargo monotone-additive semantics).

**Non-outputs.** Cargo feature edges (which features imply which
others), SCXML feature-gate grammar, build-time evaluation flow,
inspect-tool design — all deferred to R302+. This document is the
**naming** contract, not the **mechanism** contract.

---

## §1 Purpose

The composable-framework north star (R267 ratify) defines wz's
unique value over zenoh / zenoh-pico / zenoh-cpp as the ability to
emit an *arbitrary user-selected subset* of zenoh's full feature
catalog. zenoh ships one fixed binary; wz authors SCXML once and
emits per-cargo-feature combinations à la Linux kconfig / Zephyr
project config / Buildroot / NixOS USE flag.

That ambition rests on a contract every future SCXML and Rust crate
must conform to: each feature is named under a convention, each
feature stands on its own (Coherence), and the catalog is fixed at
spec time so feature edges can be reasoned about ahead of build
time. This document establishes that contract.

Two layers of abstraction (R299+ refined):

1. **Atomic features** — the smallest unit that can be turned on or
   off. ~142 of them. Naming `<domain>-<capability>`. Each must
   pass the Footprint + Plausibility + Coherence three-test.
2. **Presets** — semver-versioned named contracts that bundle atomic
   features. Naming `preset-<target>-<level>`. The initial six
   below cover the common deploy shapes.

Atomic features are the units that build correctness reasons about;
presets are the units that downstream projects depend on.

## §2 Naming convention

### §2.1 Atomic features

Atomic feature names follow `<domain>-<capability>` strict kebab-
case, ASCII-only, no version suffix in the name. Maximum three
segments (a `<domain>-<capability>` may extend to
`<domain>-<capability>-<modifier>` where the modifier disambiguates
a closely related sibling, e.g. `transport-link-udp` vs
`transport-link-tcp` where `link` is the modifier subdivision of
the `transport` domain).

Domains in this catalog: `transport`, `locator`, `scouting`,
`session`, `link`, `keyexpr`, `declare`, `pubsub`, `query`,
`liveliness`, `storage`, `codec`, `runtime`, `platform`, `routing`,
`access`, `attachment`, `time`, `encoding`. Future additions
require an explicit R-round ratification.

Capability segments are nouns (the thing being offered) or
qualified nouns (e.g. `wildcard-double` distinguishing `**` from
`*`); not verbs.

### §2.2 Presets

Preset names follow `preset-<target>-<level>` strict kebab-case.
Target is the deploy shape (`mcu`, `ap`, `zenoh-cpp` for the
upstream-parity bundle). Level is the maturity tier
(`minimal`, `extended`, `client`, `router`, `full`).

Presets carry a separate semver string in their definition
(`preset-mcu-minimal v0.1.0`); a *contract* is the (name × semver)
pair. Adding an atomic feature to an existing preset version
without changing semver is a breaking-change anti-pattern; the
contract is what downstream depends on.

## §3 Three-test definitions

Every atomic feature in §5 must pass all three tests before
landing. The tests are independent — failing any one rejects the
candidate as an atomic feature (it must be split, merged, renamed,
or accepted as a non-atomic preset-only concept).

### §3.1 Footprint

**Test.** The feature contributes a *measurable*, *bounded*, and
*isolatable* footprint when enabled — measurable in at least one
of: lines of code (LOC) added to the codegen output, binary size
delta (bytes) under `--release`, RAM delta under a representative
workload.

**Active features** (already implemented in wz at R300) get an
empirical measurement from the current code. **Reserved features**
get an estimated upper bound from the corresponding zenoh /
zenoh-pico module size; the estimate becomes empirical once the
feature lands.

A feature whose footprint cannot be bounded (e.g. a
configuration-only knob that pulls in no extra code) is not atomic
— it belongs in a preset's parameterization, not in the catalog.

### §3.2 Plausibility

**Test.** The feature is *named* and *implemented* somewhere in
the upstream surface — zenoh (Rust), zenoh-pico (C), or zenoh-cpp
(C++ public API). The citation is a file-path + symbol/section
reference, not a vague "this exists somewhere".

The plausibility test prevents the catalog from drifting into
hypothetical-future-state names. Every reserved feature in §5 has
a citation; if upstream removes the feature, the citation is
invalidated and the entry moves to deprecated.

### §3.3 Coherence

**Test.** Turning the feature off cleanly removes its footprint
without breaking unrelated features. The dependency edge from
this feature to others is *named* (in inventory) or *empty* (no
edge needed).

Coherence is the hard test for atomicity. A feature that
silently requires another feature to be on (without naming the
edge) is *not* atomic — it's a fragment of a larger atomic unit
that must be merged or renamed. Conversely, a feature whose
turning-off breaks a sibling without a named edge violates
Coherence and rejects.

## §4 Conflict policy

**Conflicts between atomic features are silently ALLOWED.** This
respects cargo's monotone-additive feature-flag semantics:
enabling more features must never break a build that succeeds
with fewer features.

Conflict *detection* is not a build-time error. It is surfaced by
the planned `cargo wz-config inspect` tool (R302+ open carry)
informationally — "you enabled feature A and feature B, which the
catalog says are mutually-exclusive in practice; pick one". The
tool emits a warning but the build proceeds; the user's choice
wins.

Rationale: cargo features are not designed for mutual exclusion.
Forcing one would make wz incompatible with downstream projects
that pull in multiple wz consumers with different feature sets.

## §5 Atomic feature catalog

Each subsection below enumerates atomic features in one domain.
Status labels: `active` (implemented in wz at R300, citation
points at wz source) / `reserved` (zenoh upstream has it,
wz roadmap, citation points at upstream).

The inventory primitive (R273 5th-entity surface) stores the
structured per-feature record (id / status / section_ref / source
/ reason) in the atomic store; the markdown body below is the
human-readable enumeration.

### §5.1 Transport

Transport-layer atomic features cover the unicast/multicast
session shape, link kinds, fragmentation, batching, and
session-level extensions. 16 entries.

- `transport-unicast` — point-to-point session (active, wz)
- `transport-multicast` — N-peer session (reserved, zenoh-pico)
- `transport-lowlatency` — no-fragmentation low-latency mode
  (reserved, zenoh)
- `transport-link-udp` — UDP link adapter (active, wz lwip + tokio)
- `transport-link-tcp` — TCP link adapter (active, wz tokio)
- `transport-link-tls` — TLS-wrapped link (reserved, zenoh)
- `transport-link-quic` — QUIC link (reserved, zenoh)
- `transport-link-ws` — WebSocket link (reserved, zenoh)
- `transport-link-serial` — serial-port link (reserved, zenoh-pico)
- `transport-link-vsock` — VM socket link (reserved, zenoh)
- `transport-link-unixsock` — Unix domain socket (reserved, zenoh)
- `transport-fragmentation` — fragment + reassemble (active, wz)
- `transport-batching` — TX batch buffer (active, wz)
- `transport-shm` — shared-memory zero-copy (reserved, zenoh)
- `transport-compression` — Z_EXT_COMPRESSION (reserved, zenoh)
- `transport-keepalive` — KeepAlive frame emit (active, wz)

### §5.2 Locator

Locator strings encode endpoint addresses; one feature per
transport-protocol-prefix the locator parser must accept. 9
entries.

- `locator-udp` — `udp/host:port` parsing (active, wz)
- `locator-tcp` — `tcp/host:port` parsing (active, wz)
- `locator-tls` — `tls/host:port` (reserved, zenoh)
- `locator-quic` — `quic/host:port` (reserved, zenoh)
- `locator-ws` — `ws/host:port` (reserved, zenoh)
- `locator-serial` — `serial/dev` (reserved, zenoh-pico)
- `locator-vsock` — `vsock/cid:port` (reserved, zenoh)
- `locator-unixsock` — `unixsock-stream/path` (reserved, zenoh)
- `locator-iface` — `?iface=eth0` scope qualifier (reserved, zenoh)

### §5.3 Scouting

Scouting-layer atomic features cover the three discovery modes
(active / passive / static) and their configuration knobs. 6
entries.

- `scouting-active` — active SCOUT/HELLO exchange (active, wz)
- `scouting-passive` — passive listen for HELLO (reserved, OQ-W23)
- `scouting-static` — config-file static peer list (reserved, zenoh)
- `scouting-multicast` — UDP multicast SCOUT (reserved, zenoh-pico)
- `scouting-gossip` — router-side peer gossip (reserved, zenoh)
- `scouting-autoconnect` — auto-connect on HELLO (reserved, zenoh)

### §5.4 Session

Session-FSM-level atomic features. Includes the protocol
extension carrier flags (extauth/extqos/extcompression/extshm). 9
entries.

- `session-unicast-open` — initiator role (active, wz)
- `session-unicast-accept` — acceptor role (active, wz partial)
- `session-multicast` — multicast session FSM (reserved,
  zenoh-pico)
- `session-resumable` — resumable session per OQ-Q14 (reserved,
  zenoh)
- `session-extauth` — Z_EXT_AUTH extension (reserved, zenoh)
- `session-extqos` — Z_EXT_QOS priority (reserved, zenoh)
- `session-extcompression` — Z_EXT_COMPRESSION (reserved, zenoh)
- `session-extshm` — Z_EXT_SHM (reserved, zenoh)
- `session-stateless-accept` — cookie-hmac stateless accept (OQ-W15
  ratified, reserved)

### §5.5 Link

Link-layer atomic features above the OS adapter and below the
session FSM — framing, flow control, TX cache. 5 entries.

- `link-frame` — Frame envelope codec (active, wz)
- `link-fragment` — Fragment envelope codec (active, wz)
- `link-batching` — batch multiple messages per frame (active, wz)
- `link-tx-cache` — TX retransmit cache (reserved, zenoh)
- `link-flow-control` — backpressure signalling (reserved, zenoh)

### §5.6 Keyexpr

Key expression atomic features cover the literal / wildcard
patterns, canonicalization, intersection, includes, and the
declare-side alias mapping. 8 entries.

- `keyexpr-literal` — literal-only patterns (active, wz)
- `keyexpr-wildcard-single` — `*` segment wildcard (active, wz)
- `keyexpr-wildcard-double` — `**` multi-segment wildcard (active,
  wz with R299 documented divergence pins)
- `keyexpr-canon` — canonicalization (active, wz at R221)
- `keyexpr-intersect` — pattern intersect (active, wz at R297)
- `keyexpr-includes` — pattern includes (active, wz at R299)
- `keyexpr-mapping` — KexprMappingTable alias storage (active, wz)
- `keyexpr-dollar-star` — `$*` non-greedy single-segment (active,
  wz)

### §5.7 Declare flow

DECLARE-side atomic features cover keyexpr alias declarations,
the four subject types (subscriber / queryable / token /
publisher-side declare_final), and DECLARE/UNDECLARE pairings. 7
entries.

- `declare-keyexpr` — DECLARE-KEXPR alias (active, wz)
- `declare-subscriber` — DECLARE-SUBSCRIBER (active, wz)
- `declare-queryable` — DECLARE-QUERYABLE (active, wz)
- `declare-token` — DECLARE-TOKEN (active, wz)
- `declare-final` — DECLARE-FINAL push (active, wz partial)
- `declare-interest` — Z_INTEREST extension (active, wz partial)
- `declare-undeclare` — UNDECLARE-\* pair (active, wz)

### §5.8 Pubsub

Publisher / subscriber atomic features. Encoding, timestamp,
source-info, attachment, congestion-control, priority, express,
loop-allow are all atomic publisher options. 11 entries.

- `pubsub-put` — Put sample emit (active, wz)
- `pubsub-delete` — Delete sample emit (active, wz)
- `pubsub-sample` — Sample receive surface (active, wz)
- `pubsub-encoding` — Encoding header field (active, wz)
- `pubsub-timestamp` — Timestamp field (active, wz)
- `pubsub-source-info` — SourceInfo extension (reserved, zenoh)
- `pubsub-attachment` — sample attachment bytes (reserved, zenoh)
- `pubsub-congestion-control` — Block/Drop policy (reserved, zenoh)
- `pubsub-priority` — 8-level priority (reserved, zenoh)
- `pubsub-express` — express bit (reserved, zenoh)
- `pubsub-allow-loop` — allow local loopback (reserved, zenoh)

### §5.9 Query

Query (zenoh "get") atomic features. Includes the queryable side
of the protocol, the consolidation modes, the target selection
modes, and the per-query attachment / source-info /
selector-parameter knobs. 10 entries.

- `query-get` — get() initiator (active, wz)
- `query-queryable` — Queryable surface (active, wz)
- `query-reply` — Reply emit (active, wz)
- `query-reply-err` — ReplyErr variant (reserved, zenoh)
- `query-target` — Best/All/AllComplete (active, wz)
- `query-consolidation` — None/Monotonic/Latest/Auto (active, wz)
- `query-selector-parameters` — `?k=v` query selector params
  (reserved, zenoh)
- `query-attachment` — query attachment bytes (reserved, zenoh)
- `query-source-info` — query SourceInfo (reserved, zenoh)
- `query-timeout` — per-query timeout (active, wz)

### §5.10 Liveliness

Liveliness atomic features cover token assertion + subscriber +
history-on-subscribe. 5 entries.

- `liveliness-token` — assert liveliness token (active, wz)
- `liveliness-subscriber` — liveliness subscriber (active, wz)
- `liveliness-get` — querier on liveliness (reserved, zenoh)
- `liveliness-history` — Z_EXT_HISTORY on liveliness (reserved,
  zenoh)
- `liveliness-historical-samples` — historical samples on
  liveliness subscribe (reserved, zenoh)

### §5.11 Storage

Storage backend atomic features — replication, history-extension,
aligner protocol. 4 entries.

- `storage-backend` — zenoh-backend-traits surface (reserved,
  zenoh-backend-traits)
- `storage-replication` — replication protocol (reserved, zenoh
  storage-replication)
- `storage-history` — Z_EXT_HISTORY emit (reserved, zenoh)
- `storage-aligner` — aligner protocol (reserved, zenoh)

### §5.12 Codec

Wire-message codec atomic features — one per top-level message
that the wire emits. 16 entries. Each maps to a
`sources/codecs/<name>.scxml` (active when SCXML lands at the
current vendor pin).

- `codec-scout` — SCOUT (active, wz)
- `codec-hello` — HELLO (active, wz)
- `codec-init-syn` — INIT-SYN (active, wz via init_body)
- `codec-init-ack` — INIT-ACK (active, wz via init_body)
- `codec-open-syn` — OPEN-SYN (active, wz via open_body)
- `codec-open-ack` — OPEN-ACK (active, wz via open_body)
- `codec-close` — CLOSE (active, wz)
- `codec-keep-alive` — KEEP_ALIVE (active, wz)
- `codec-join` — JOIN (active, wz)
- `codec-frame` — FRAME (active, wz)
- `codec-fragment` — FRAGMENT (active, wz)
- `codec-declare` — DECLARE outer (active, wz)
- `codec-push` — PUSH (active, wz)
- `codec-request` — REQUEST (active, wz)
- `codec-response` — RESPONSE (active, wz)
- `codec-response-final` — RESPONSE-FINAL (active, wz)

### §5.13 Runtime

Runtime adapter atomic features — async-executor + zero-copy
mechanisms. 6 entries.

- `runtime-tokio` — tokio executor (active, wz)
- `runtime-tokio-uring` — tokio + io_uring fixed buffers (reserved,
  RFC §9.5 row 3)
- `runtime-lwip` — lwIP MCU bare-metal (reserved, wz-runtime-lwip
  Phase W skeleton)
- `runtime-async-std` — async-std executor (reserved, zenoh)
- `runtime-no-std` — `#![no_std]` core lib (reserved, zenoh-pico)
- `runtime-zero-copy` — pool-slot RxFrame zero-copy (reserved, RFC
  §5.E)

### §5.14 Platform

Platform-OS atomic features — gates the `platform.os` build matrix
in deploy.yaml. 7 entries.

- `platform-linux` — Linux baseline (active, wz tokio)
- `platform-qnx` — QNX-native (reserved, OQ-W20)
- `platform-bare-metal` — MCU bare-metal C11 (reserved, RFC
  §5.J.4)
- `platform-windows` — Windows tokio (reserved, zenoh)
- `platform-macos` — macOS tokio (reserved, zenoh)
- `platform-freertos` — FreeRTOS (reserved, zenoh-pico)
- `platform-zephyr` — Zephyr RTOS (reserved, zenoh-pico)

### §5.15 Routing

Routing atomic features — client / peer / router modes plus
routing-table options. 6 entries.

- `routing-client` — client mode (active, wz)
- `routing-peer` — peer mode (reserved, zenoh)
- `routing-router` — router mode (reserved, zenoh)
- `routing-routes` — router routing tables (reserved, zenoh)
- `routing-failover` — failover brokering (reserved, zenoh)
- `routing-static-routes` — config-file static routes (reserved,
  zenoh)

### §5.16 Access control

Access-control atomic features — ACL, downsampling, quota, and
the three auth methods supported by Z_EXT_AUTH. 6 entries.

- `access-acl` — ACL plugin (reserved, zenoh-acl)
- `access-downsampling` — downsampling plugin (reserved, zenoh)
- `access-quota` — per-key quota (reserved, zenoh)
- `access-extauth-usrpwd` — username/password auth (reserved,
  zenoh)
- `access-extauth-pubkey` — RSA pubkey auth (reserved, zenoh)
- `access-extauth-jwt` — JWT auth (reserved, zenoh)

### §5.17 Attachment

Sample/Query attachment atomic features. 2 entries.

- `attachment-bytes` — opaque-bytes attachment (reserved, zenoh)
- `attachment-encoding-aware` — encoding-tagged attachment
  (reserved, zenoh)

### §5.18 Time

Timestamp source atomic features. 4 entries.

- `time-ntp64` — 64-bit NTP timestamp (active, wz)
- `time-hlc` — hybrid logical clock (reserved, zenoh-uhlc)
- `time-system-clock` — wall-clock fallback (active, wz)
- `time-timestamp-source` — pluggable timestamp source (reserved,
  zenoh)

### §5.19 Encoding

Payload encoding atomic features — the `Encoding` field
discriminator values. 7 entries.

- `encoding-empty` — empty/raw (active, wz)
- `encoding-utf8` — `text/plain` UTF-8 (active, wz)
- `encoding-bytes` — `application/octet-stream` (active, wz)
- `encoding-json` — `application/json` (reserved, zenoh)
- `encoding-cbor` — `application/cbor` (reserved, zenoh)
- `encoding-protobuf` — `application/protobuf` (reserved, zenoh)
- `encoding-mime` — RFC 6838 full MIME (reserved, zenoh)

## §6 Presets

Each preset is a semver-versioned named contract bundling a fixed
set of atomic features. Downstream projects depend on the
*(name, version)* pair; the contents at a given version do not
change. New atomic features land in a new preset version (e.g.
`preset-mcu-minimal v0.2.0`) — see §2.2.

### §6.1 preset-mcu-minimal v0.1.0

The smallest viable MCU deployment — zenoh-pico client-mode
parity at minimum footprint. Targets bare-metal MCU with lwIP +
UDP + minimal pubsub.

Includes: `platform-bare-metal`, `runtime-lwip`, `runtime-no-std`,
`transport-unicast`, `transport-link-udp`, `transport-keepalive`,
`locator-udp`, `scouting-active`, `session-unicast-open`,
`link-frame`, `link-fragment`, `link-batching`, `keyexpr-literal`,
`keyexpr-canon`, `declare-keyexpr`, `declare-subscriber`,
`declare-undeclare`, `pubsub-put`, `pubsub-sample`,
`encoding-empty`, `encoding-utf8`, `encoding-bytes`,
`codec-scout`, `codec-hello`, `codec-init-syn`, `codec-init-ack`,
`codec-open-syn`, `codec-open-ack`, `codec-close`,
`codec-keep-alive`, `codec-frame`, `codec-fragment`,
`codec-declare`, `codec-push`, `routing-client`, `time-ntp64`.

### §6.2 preset-mcu-extended v0.1.0

MCU deployment + query + liveliness + wildcards. Targets MCU
projects that need request/response and presence detection on top
of preset-mcu-minimal.

Includes: everything in preset-mcu-minimal plus
`keyexpr-wildcard-single`, `keyexpr-wildcard-double`,
`keyexpr-intersect`, `keyexpr-includes`, `keyexpr-mapping`,
`declare-queryable`, `declare-token`, `pubsub-delete`,
`pubsub-encoding`, `pubsub-timestamp`, `query-get`,
`query-queryable`, `query-reply`, `query-target`,
`query-consolidation`, `query-timeout`, `liveliness-token`,
`liveliness-subscriber`, `codec-request`, `codec-response`,
`codec-response-final`, `transport-fragmentation`,
`time-system-clock`.

### §6.3 preset-ap-client v0.1.0

Linux AP deploying in client mode. Tokio executor, full pubsub +
query + liveliness, TCP + UDP transports, but no router-side
features.

Includes: `platform-linux`, `runtime-tokio`, `routing-client`,
`transport-unicast`, `transport-link-udp`, `transport-link-tcp`,
`transport-fragmentation`, `transport-batching`,
`transport-keepalive`, `locator-udp`, `locator-tcp`,
`scouting-active`, `session-unicast-open`,
`session-unicast-accept`, `link-frame`, `link-fragment`,
`link-batching`, `keyexpr-literal`, `keyexpr-wildcard-single`,
`keyexpr-wildcard-double`, `keyexpr-canon`, `keyexpr-intersect`,
`keyexpr-includes`, `keyexpr-mapping`, `keyexpr-dollar-star`,
`declare-keyexpr`, `declare-subscriber`, `declare-queryable`,
`declare-token`, `declare-final`, `declare-interest`,
`declare-undeclare`, `pubsub-put`, `pubsub-delete`,
`pubsub-sample`, `pubsub-encoding`, `pubsub-timestamp`,
`query-get`, `query-queryable`, `query-reply`, `query-target`,
`query-consolidation`, `query-timeout`, `liveliness-token`,
`liveliness-subscriber`, `codec-scout`, `codec-hello`,
`codec-init-syn`, `codec-init-ack`, `codec-open-syn`,
`codec-open-ack`, `codec-close`, `codec-keep-alive`, `codec-join`,
`codec-frame`, `codec-fragment`, `codec-declare`, `codec-push`,
`codec-request`, `codec-response`, `codec-response-final`,
`encoding-empty`, `encoding-utf8`, `encoding-bytes`, `time-ntp64`,
`time-system-clock`.

### §6.4 preset-ap-router v0.1.0

Linux AP deploying in router mode. preset-ap-client +
router-side features + gossip + routing tables.

Includes: everything in preset-ap-client plus `routing-router`,
`routing-routes`, `routing-failover`, `routing-static-routes`,
`scouting-passive`, `scouting-static`, `scouting-multicast`,
`scouting-gossip`, `scouting-autoconnect`, `session-multicast`,
`transport-multicast`, `transport-lowlatency`,
`session-resumable`, `session-extqos`.

### §6.5 preset-ap-full v0.1.0

preset-ap-router + all transport link kinds + all auth methods +
attachment + advanced encodings. The "kitchen sink" Linux deploy.

Includes: everything in preset-ap-router plus
`transport-link-tls`, `transport-link-quic`, `transport-link-ws`,
`transport-link-vsock`, `transport-link-unixsock`,
`transport-shm`, `transport-compression`, `locator-tls`,
`locator-quic`, `locator-ws`, `locator-vsock`, `locator-unixsock`,
`locator-iface`, `session-extauth`, `session-extcompression`,
`session-extshm`, `session-stateless-accept`, `link-tx-cache`,
`link-flow-control`, `pubsub-source-info`, `pubsub-attachment`,
`pubsub-congestion-control`, `pubsub-priority`, `pubsub-express`,
`pubsub-allow-loop`, `query-reply-err`,
`query-selector-parameters`, `query-attachment`,
`query-source-info`, `liveliness-get`, `liveliness-history`,
`liveliness-historical-samples`, `access-acl`,
`access-downsampling`, `access-quota`, `access-extauth-usrpwd`,
`access-extauth-pubkey`, `access-extauth-jwt`,
`attachment-bytes`, `attachment-encoding-aware`,
`encoding-json`, `encoding-cbor`, `encoding-protobuf`,
`encoding-mime`, `runtime-tokio-uring`, `runtime-zero-copy`,
`time-hlc`, `time-timestamp-source`.

### §6.6 preset-zenoh-cpp v0.1.0

Cross-feature consistency anchor. The atomic feature set that
matches zenoh-cpp's public API shape as exposed today. This
preset defines what "full zenoh-cpp parity" means in atomic-
feature terms; the project's first-milestone target.

Includes: same as preset-ap-full except for the MCU/embedded-
flavor subset — explicitly excludes `runtime-lwip`,
`runtime-no-std`, `platform-bare-metal`, `platform-freertos`,
`platform-zephyr`, `transport-link-serial`, `locator-serial`. All
other atomic features active.

## §7 Cargo feature emission mechanism

R302+ open carry. The Cargo.toml::[features] table layout, the
default feature set, the feature-implication edges, and the
`#[cfg(feature = ...)]` gate placement in emitted Rust source are
all deferred. The R302 candidate work is to design this surface.

Reference points for the future design:
- Linux kconfig — declarative menus + select/depends edges
- Zephyr west config — overlay + per-board defaults
- Buildroot — package-graph + per-package config
- NixOS USE flags — propagation + override

## §8 SCE feature gate mechanism

R302+ open carry. The SCXML attribute (`<sce:requires
feature="X"/>` or similar) that lets SCXML authors gate generated
output by an atomic feature flag is deferred. The R302 candidate
work is to ratify the attribute shape against SCE codegen.

Initial sketch (subject to ratify):
- `<sce:requires feature="<atomic-feature-name>"/>` — element
  is emitted only if the feature is enabled
- `<sce:requires preset="<preset-name>"/>` — element is emitted
  only if any preset including the named atomic is enabled
- Combinable via boolean operators (and/or/not)

The mechanism design depends on SCE codegen support; this is the
first cross-repo deliverable on the composable-framework track.

## §9 Change log

ChangelogEntry records appended via the Mnemosyne
`append_changelog_entry_v2` primitive (R273+ atomic ledger
surface). The R301 entry is the registration round; subsequent
entries record catalog additions / preset version bumps / 3-test
re-evaluations.

The legacy date-based prose entries used elsewhere in the
workspace do not apply to this doc — feature_inventory.md is
born after the atomic ledger surface landed.
