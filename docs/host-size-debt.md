# The pico host libraries against zenoh-pico: where the bytes are

The breakdown behind store debt `debt-pico-host-size-ceiling` (docs/upstream-parity.md, decision
D9): what the pico C ABI host library (`libwz_capi_pico.so`, the Windows DLL) carries that
zenoh-pico built as the same build does not, plane by plane, with the way a build that does not need
a plane leaves it out. Decision D9's rule holds throughout: wz is to be smaller than zenoh-pico, a
case that is no WIN is paid largest ratio first, behaviour does not change, and no budget or row
move clears a LOSS.

Every figure below is labelled. **Measured** figures are the committed readings of
`deploy/pico_host_ceiling.json` (2026-11-21, one toolchain for every row) or a reading a case note
of `scripts/lib/capability_cost_gate.py` records with its symbol diff. **Estimates** are from
reading the code and say so; each names the `nm` scope that turns it into a measurement
(section 6).

## 1. The order of payment

The ratio is wz text over zenoh-pico text, both built in one run (D9 rule 1). Largest first:

| case | ratio | wz text | pico text |
|------|------:|--------:|----------:|
| `pico-default` | 7.7712 | 4,718,596 | 607,197 |
| `pico-peer` | 7.7582 | 3,224,282 | 415,599 |
| `pico-client-udp` | 5.1047 | 2,057,617 | 403,086 |
| `pico-client` | 4.9905 | 1,989,401 | 398,645 |
| `pico-client-small` | 4.0838 | 1,627,962 | 398,645 |
| `pico-client-coop-admin-space` | 3.1574 | 1,402,968 | 444,356 |
| `pico-client-coop-local-queryable` | 3.1166 | 1,372,000 | 440,232 |
| `pico-client-coop-query` | 3.0977 | 1,355,836 | 437,696 |
| `pico-peer-coop` | 2.8365 | 1,178,807 | 415,599 |
| `pico-client-coop-unstable` | 2.8212 | 1,142,449 | 404,952 |
| `pico-client-coop-connectivity` | 2.7572 | 1,212,769 | 439,863 |
| `pico-client-coop-scout` | 2.7161 | 1,114,853 | 410,463 |
| `pico-client-coop-local` | 2.558 | 1,037,194 | 405,486 |
| `pico-client-coop` | 2.5569 | 1,030,646 | 403,086 |

The tokio cases lead by far. The cooperative cases sit between 2.56 and 3.16.

## 2. What the paired cases say (measured)

Two cases that differ by one capability give that capability's cost on both sides, read in the same
run. The last column is how many bytes wz spends for each byte pico spends on the same plane.

| plane | cases | wz | pico | wz / pico |
|-------|-------|---:|-----:|----------:|
| panic unwinding (release vs capi-small) | `pico-client-small` -> `pico-client` | +361,439 | +0 | - |
| UDP unicast link (tokio) | `pico-client` -> `pico-client-udp` | +68,216 | +4,441 | 15.4 |
| tokio engine over cooperative (same features) | `pico-client-coop` -> `pico-client-udp` | +1,026,971 | +0 | - |
| unstable API (coop) | `pico-client-coop` -> `pico-client-coop-unstable` | +111,803 | +1,866 | 59.9 |
| local subscriber (coop) | `pico-client-coop` -> `pico-client-coop-local` | +6,548 | +2,400 | 2.7 |
| connectivity over unstable (coop) | `pico-client-coop-unstable` -> `pico-client-coop-connectivity` | +70,320 | +34,911 | 2.0 |
| query + queryable (coop) | `pico-client-coop` -> `pico-client-coop-query` | +325,190 | +34,610 | 9.4 |
| local queryable over query (coop) | `pico-client-coop-query` -> `pico-client-coop-local-queryable` | +16,164 | +2,536 | 6.4 |
| admin space, with queryable and unstable (coop) | `pico-client-coop` -> `pico-client-coop-admin-space` | +372,322 | +41,270 | 9.0 |
| scout (coop) | `pico-client-coop` -> `pico-client-coop-scout` | +84,207 | +7,377 | 11.4 |
| peer over scout (coop) | `pico-client-coop-scout` -> `pico-peer-coop` | +63,954 | +5,136 | 12.5 |
| peer with scout (tokio) | `pico-client-udp` -> `pico-peer` | +1,166,665 | +12,513 | 93.2 |
| the rest of the default (tokio) | `pico-peer` -> `pico-default` | +1,494,314 | +191,598 | 7.8 |

Read together:

- **The tokio engine is half of every tokio case.** The same feature set reads 2,057,617 on the
  tokio engine and 1,030,646 on the cooperative one, against one zenoh-pico. pico has no runtime of
  its own to compare it with; its single-threaded arm is what the cooperative engine already is.
- **Unwinding is 18 percent of a tokio client.** `pico-client-small` is `pico-client` built with
  `panic = "abort"` (`crates/Cargo.toml`, profile `capi-small`). zenoh-pico is C and has no
  unwind tables or landing pads to compare with.
- **The tokio peer is the worst plane by ratio: 93 bytes for each of pico's.** `peer` with the
  scouting it implies costs 1,166,665 on the tokio engine and 148,161 on the cooperative one (scout
  84,207 plus peer 63,954) for the same pico switches (`Z_FEATURE_UNICAST_PEER`,
  `Z_FEATURE_SCOUTING`). Section 4 names what the tokio peer links that pico's peer has not.
- **On the cooperative engine the query plane (9.4) and the unstable API (59.9) are the outliers.**
  Connectivity (2.0) and the local subscriber (2.7) are near pico.

## 3. Is the comparison like for like? (the switches, feature by feature)

`wz_config.pico_reference` sets every `Z_FEATURE_*` switch from the case's resolved features:
`always` rows on, `never` rows off, `maps` rows on exactly when the build has the mapped feature.
Resolving every pico case's features through `crates/wz-capi-pico/Cargo.toml` and mapping them
through the `[[upstream_switch]]` rows of `deploy/wz-config.toml`:

- Every capability of every case that has a pico switch is on in the reference exactly when it is
  on in wz. The features left over are engine plumbing (`std`, `engine-tokio`, `engine-coop`,
  `serial-drive-own-thread`, `rx-busy-poll`), which name no plane pico could have, and
  `liveliness-get`, which pico has where it has both the liveliness and the query plane.
- **`pico-default` carries `gossip`, a plane pico has none of** (`crates/wz-capi-pico/Cargo.toml`:
  `gossip = ["engine-tokio", "peer", "wz-capi-core/gossip"]`, in `default`). The reference cannot
  have it, so the comparison holds wz's default to pico with one more plane on wz's side. Worse,
  the plane is dead in this library: `z_open` hands the engine `gossip: None` in every build
  (`crates/wz-capi-pico/src/session.rs`, `OpenStance`), so the bytes buy nothing. Decision Q3.

At the engine, under the capabilities, two more planes are linked that the pico ABI never starts:

- **The session's own scouting.** `wz-capi-core`'s `scout` and `peer` compile the session-level
  scouting node (`scouting_node.rs`: the re-scouting windows, autoconnect to what a Hello names,
  `connect_first`) and the Scout responder (`scouting_responder.rs` and the runtime's
  `scouting_responder`), reached in `drive.rs` through `OpenStance::scouting`. The pico ABI sets
  that field to `None` (`session.rs`: "pico's open looks once, before the open, and its session
  answers no Scout"), and zenoh-pico sends no Hello at all (`vendor/zenoh-pico/src/protocol/definitions/transport.c`
  @ `_z_scouting_message_t _z_s_msg_make_hello(` is defined and called nowhere in pico's `src`).
  The behaviour matches pico; the bytes do not. The `pico-peer` and `pico-default` cases even
  `require` the `RESPONDER` pattern, so the gate asserts the dead plane is linked. Reduction R2.
- **The gossip plane**, as above.

Neither is a mismatch of the switches; both are planes the pico ABI links and cannot reach. They
belong to the reduction list, not to the reference.

The two builds are also built alike: zenoh-pico's `Release` is `-O3`
(`vendor/zenoh-pico/CMakeLists.txt` @ `add_compile_options(-pipe -O3)`), wz's release profile is
`opt-level = 3` with thin LTO and one codegen unit.

## 4. The planes of the tokio cases

For each: what it is, whether zenoh-pico's same build has it, and how a build that does not need
it leaves it out.

| plane | in pico's build | how a build leaves it out | status |
|-------|-----------------|---------------------------|--------|
| tokio runtime, the drive thread and its runtime, the face loop (`wz-capi-core`, `wz-runtime-tokio`, `tokio`) | no runtime; the single-threaded arm is a stepped session | `engine-coop` instead of `engine-tokio` (measured 1,026,971 on the client) | decision Q1 |
| unwind tables, landing pads, `catch_unwind` around every door (`ffi::guarded`) | none (C) | profile `capi-small` (`panic = "abort"`; measured 361,439 on the client) | decision Q2 |
| the standard library's panic hook and backtrace symbolizer (`std::backtrace_rs`, `gimli`, `addr2line`, `miniz_oxide`, `rustc_demangle`) | none | only a toolchain that builds `std` with `panic_immediate_abort`, or a host layer without `std`; `panic = "abort"` alone still runs the hook | estimate 150,000 to 350,000 in every case, tokio and cooperative; decision Q5 |
| `log` call sites: 226 in `wz-runtime-tokio`, 21 in `wz-session-core`, 8 in `wz-routing-graph`, 7 in `wz-host-net` | compiled out: the reference defines no `ZENOH_DEBUG` (`vendor/zenoh-pico/include/zenoh-pico/utils/logging.h` @ `#define _Z_DEBUG(...) (void)(0)`) | `log`'s static level; no crate this library links installs a logger (`set_logger` appears in none), so every site is dead at run time | estimate 40,000 to 100,000 on the tokio cases; decision Q4 |
| the session's own scouting and the Scout responder (`scouting_node`, `scouting_responder`, the runtime's `scouting_autoconnect`, `wz-routing-graph`'s `AutoConnect`) | no responder; one look before the open | reachable only from `OpenStance::scouting`, which the pico ABI sets to `None`: R2 | estimate 30,000 to 90,000 on `pico-peer` and `pico-default` |
| gossip (`gossip_plane`, the runtime's `routing-gossip`) | none | the pico ABI sets `OpenStance::gossip` to `None` in every build | decision Q3; `pico-default` only |
| accept loop and the inbound handshake (`accept_loop`, `routing-accept`, which also turns on `codec-request` in a build without the query plane) | a lone listener | needed by `peer`; the cooperative engine's listener costs 63,954 for the same role | the tokio engine's own cost, Q1 |
| the multicast transport (open-debt item 913) | yes (`Z_FEATURE_MULTICAST_TRANSPORT`) | `multicast-transport` off; `pico-default` read 4,216,542 with it and 3,790,610 without (case note, measured) | owned by item 913 |
| the query plane | yes | its own features; on the cooperative engine 9.4 times pico's. The case notes of 2026-11-03 put the growth of that day in `decode_one_record` (1,438 to 18,628, the borrowed-to-owned conversions of every arm) and the views' `decode_into`; whether moving those conversions out of the decoder gives any of it back is the carry those notes left | R4 |
| the unstable API's `wz_ext_config_device_requires` (`device_requires.rs` over `wz_session_core::facilities`) | none (a wz door) | it reads endpoints with `parse_any_locator`, the grammar of every scheme the tree knows, where the cooperative engine dials with `wz_session_mcu::dial::parse_locator`; the three `unstable-api` cooperative cases grew about 110,000 when the door came (case note, attributed by feature set, not by symbol) | decision Q6 |
| the statechart runtime's BasicHTTP processor (`sce-rust-runtime`'s `http-send`, a default) | none | `default-features = false` with `std` and `macrostep-diagnostics`: R1, landed | small, under 5,000 |

The generated codecs and machines (SCE) are in both engines alike and are the session's own logic;
their cost is followed by the SCE pin notes of the gate, not here.

## 5. Reductions

Each changes no behaviour of the pico ABI. A case it should move is named with the reason; the
reading is the main session's (section 6).

- **R1, landed (`build(runtime): Take the statechart runtime without its HTTP processor`).**
  `wz-runtime-tokio` took `sce-rust-runtime` with its defaults, which include the BasicHTTP event
  processor. No machine under `sources/` sends over HTTP and no crate registers the processor's
  transport (`set_http_send_callback` is called nowhere). Every statechart engine loses a boxed
  callback slot and its drop; a BasicHTTP send, which no machine makes, is refused as SCXML 6.2
  refuses an unsupported type instead of being handed to a callback that is not there. Should move
  every tokio case down slightly (estimate: under 5,000 each), the cooperative cases not at all.
  A build that unifies another crate taking the runtime's defaults (the `wz` facade, the demo, the
  integration tests) keeps the processor, as before.
- **R2, ready (pure linkage, not yet landed): the session's own scouting behind its own feature.**
  A `wz-capi-core` feature for the session-level scouting node and the responder, in
  `wz-capi-core`'s `default` and forwarded by `wz-capi-c`'s `scout`, so the zenoh-c ABI and
  the Rust API keep them; the pico ABI does not name it. `OpenStance::scouting` stays in every
  build with `scout` (the pico ABI's literal names it, and a field that came and went with a
  feature the pico ABI cannot see would break a build that unifies both ABIs, the reason
  `node_policy.rs` gives for its own type), and its type has no value without the feature (an
  uninhabited `ScoutingPlan`), so `None` is the only thing it can hold. The consuming sites in
  `drive.rs` (`client_scouting`, `connect_first`, `bound_responder`, the scouting branches of
  `drive_peer` and `drive_client`), `drive/router_node.rs` and `open_plan.rs` move from
  `scout` / `peer` to the new feature; `Advertised` and `LateLocators` stay with `peer`
  (every peer build records where it listens through them). About fifty `cfg` sites in four files:
  it is to be done where each feature set can be compiled as it is edited. The gate's
  `require=(..., RESPONDER, ...)` of `pico-peer` and `pico-default` then becomes a `forbid`
  if no responder symbol is left (`LateLocators` lives in the runtime's `scouting_responder`
  module and may keep the pattern matching). Should move `pico-peer` and `pico-default`.
- **R3, a measurement first: monomorphised copies on the tokio engine.** The case notes record one
  such win (2026-11-16: the face loop compiled once, `face_drive_loop_core`, gave back 73,916 of
  `pico-peer`) and name more candidates by symbol (`drive_phase_on`, `drive_connect_phase_on`,
  `timeout_on<TokioTime>`, `bind_listener`, `bind_listeners`, the drive closures). The
  instance counts of `footprint_attribution.py` say which are copied; each copy folded is its own
  commit.
- **R4, a measurement first: the query plane on the cooperative engine** (the carry of the
  2026-11-03 note above).

## 6. How to measure

On one host, before and after a change, the ratio and the row to commit:

```
python3 scripts/lib/capability_cost_gate.py --measure pico-default pico-peer pico-client-udp pico-client
python3 scripts/lib/capability_cost_gate.py --measure pico-client-small pico-client-coop pico-client-coop-unstable pico-client-coop-query
```

The attribution of a plane, from two builds of the gate's own commands
(`cargo build --release -p wz-capi-pico [--no-default-features --features <case>]` in `crates/`,
the library copied out of `crates/target/release/` after each), by owning scope:

```
python3 scripts/lib/footprint_attribution.py --old <a.so> --new <b.so> \
  --scope '(^|[^_])tokio::' --scope 'wz_runtime_tokio::' --scope 'wz_capi_core::' \
  --scope 'wz_session_core::' --scope 'wz_codecs::' --scope 'wz_capi_pico::' \
  --scope 'backtrace_rs|gimli|addr2line|miniz_oxide|rustc_demangle' \
  --scope 'as core::fmt::(Debug|Display)>::fmt' --scope '(^|::)log::' \
  --scope 'scouting_node|scouting_responder|scouting_autoconnect|AutoConnect' \
  --scope 'gossip_plane|GossipPlane|routing_graph'
```

The pairs that turn the estimates of section 4 into measurements: `pico-client-coop` against
`pico-client-udp` (the tokio engine), `pico-client-udp` against `pico-peer` (the tokio peer,
the scouting node, the responder), `pico-peer` against `pico-default` (gossip, multicast, the
rest), and a single build read with `--old` and `--new` the same file for the absolute size of a
scope (the std symbolizer, `log`, the `Debug` impls).

## 7. Decisions for the owner

Each is a change of what the library is or does; the estimates are from the readings above or from
code, as labelled.

- **Q1. The cooperative engine as the host library's default.** Measured: the same features read
  5.10 on the tokio engine and 2.56 on the cooperative one; the peer 7.76 and 2.84. `pico-default`
  can follow only when the cooperative engine carries what that build needs (the multi-threaded
  arm, the advanced plane, liveliness, the multicast group's whole surface); until then the tokio
  build would stay, under its own name.
- **Q2. `panic = "abort"` for the shipped host library.** Measured on the client: 4.99 to 4.08. A
  panic in a door then ends the process where `ffi::guarded` returns an error code today; a panic
  on a tokio worker ends it where the runtime contains it today. On the cooperative cases the same
  share is an estimate (2.56 to about 2.1).
- **Q3. `gossip` out of the pico ABI's default, or the pico ABI made to gossip.** The plane is
  linked and never started (`gossip: None`), so leaving it out changes no behaviour; keeping the
  feature with a meaning means the ABI's open must give the engine a policy. The comparison of
  `pico-default` is like for like only without it. Estimate: the gossip plane's scope in
  `pico-default` (section 6).
- **Q4. `log`'s static level for the C ABI libraries.** No logger can be installed through the pico
  ABI, so every site is dead at run time; but `log`'s level features unify across one build, so a
  binary built with the library in one command (the demo, the tests) would lose its log lines too.
  The alternative is wz's own macro over `log` behind a feature only the C ABI libraries name.
  Estimate: 40,000 to 100,000 on the tokio cases, little on the cooperative ones.
- **Q5. The standard library's panic and backtrace machinery.** Present in every case; leaving it
  out needs a toolchain that builds `std` (`panic_immediate_abort`) or a host layer without
  `std`, which the cooperative engine's MCU build already is. Estimate 150,000 to 350,000 per
  case, the largest single item of the cooperative cases if it reads so.
- **Q6. `wz_ext_config_device_requires` read with the build's own locator grammar.** The door
  would then answer an endpoint the build cannot dial with the refusal `z_open` gives it, as its
  documentation says it answers, and stop linking every scheme's parser. That changes the door's
  answer for such endpoints (today: a requirement with the endpoint listed as unknown). Estimate:
  up to 110,000 on the three `unstable-api` cooperative cases (`-unstable` 2.82 to about 2.55).
