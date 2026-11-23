# Which slice reads each crate

Every crate under `crates/` is either read by a census slice or left out with a
reason. A crate that is in neither place is a crate the census has not looked at,
and nobody can tell from the slices alone. `scripts/lib/logic_census_coverage_gate.py`
holds this table to the tracked tree: a crate with no row, a row naming no crate,
a slice that does not name its crate, and an exclusion without a reason are each
a failure. The files of the crates a slice reads are held one level down, in
`files.md`.

The `Where` column holds the slices that read the crate (`S1, S2`), or
`excluded: <kind>`, where the kind is one of `test`, `build`, `binding`,
`example`, `analyzer`, `measurement` and `facade`.

| Crate | Where | Reason |
|---|---|---|
| `freertos-sys` | excluded: binding | FFI declarations of the FreeRTOS kernel; the scheduler it binds is the platform, and S9 reads the wz runtime over it. |
| `lwip-sys` | excluded: binding | FFI declarations of lwIP; S9 reads the wz session and links over it. |
| `wz` | excluded: facade | The top-level facade: re-exports and the preset feature catalogue, no logic of its own. |
| `wz-abi-stamp` | excluded: build | Writes and reads the ABI stamp an artifact carries as an ELF note; no protocol runs through it. |
| `wz-access-control` | S6 | |
| `wz-admin` | S6 | |
| `wz-analyze` | excluded: analyzer | The analyzer's offline reports; its place in the migration is the open point of section 8. |
| `wz-ap-demo` | S10 | |
| `wz-ap-demo-app` | S10 | |
| `wz-app-frame` | S10, S11 | |
| `wz-auth` | S6 | |
| `wz-capi-c` | S8 | |
| `wz-capi-coop` | S7 | |
| `wz-capi-core` | S7 | |
| `wz-capi-dissect` | excluded: analyzer | The C ABI of the analyzer's dissection; follows `wz-capture`. |
| `wz-capi-pico` | S7, S12 | |
| `wz-capi-pico-ext` | excluded: binding | The doors of `wz-capi-pico`'s additional features compiled again as a library of their own over the core library's C ABI: its sources are `wz-capi-pico`'s door files, which S12 reads there, and an import declaration of the core (`src/core_view.rs`). |
| `wz-capi-port` | S7 | |
| `wz-capi-replay` | excluded: analyzer | The C ABI of capture replay; follows `wz-replay`. |
| `wz-capture` | excluded: analyzer | The analyzer (pcap reading, dissection, flow verdicts); its place in the migration is the open point of section 8. |
| `wz-cdylib-build` | excluded: build | Build-script helper that links the C ABI libraries. |
| `wz-codecs` | S9 | |
| `wz-codecs-test-support` | excluded: test | Helpers for the generated codecs' tests. |
| `wz-codegen-build` | excluded: build | The build-script door that spawns `sce-codegen`; it produces the generated code and holds none of the protocol. |
| `wz-conformance-build` | excluded: build | Builds the conformance proformas into the test suite. |
| `wz-conformance-suite` | excluded: test | The conformance requirements and proformas, read and held to their formats. |
| `wz-e2e-admin-probe` | excluded: test | An end-to-end test binary. |
| `wz-e2e-declare-observer` | excluded: test | An end-to-end test binary. |
| `wz-e2e-harness` | excluded: test | Scaffolding shared by the end-to-end test binaries. |
| `wz-e2e-liveliness` | excluded: test | An end-to-end test binary. |
| `wz-e2e-liveliness-token` | excluded: test | An end-to-end test binary. |
| `wz-e2e-pubsub` | excluded: test | An end-to-end test binary. |
| `wz-e2e-queryable` | excluded: test | An end-to-end test binary. |
| `wz-e2e-silent-peer` | excluded: test | An end-to-end test binary. |
| `wz-e2e-zget` | excluded: test | An end-to-end test binary. |
| `wz-eth-lan865x` | S9 | |
| `wz-eth-mac-cyt4bf` | S9 | |
| `wz-eth-mac-lan9118` | S9 | |
| `wz-ext-pubsub` | S6, S10 | |
| `wz-fuzz` | excluded: test | Fuzz targets over the C ABI and over the network ingress, with the packages of its own workspace (`coop-engine`, `ingress-common`, `pico-ext`, `session-heap`, `session-slot`): harnesses that drive the doors and the decoders, no logic of their own. |
| `wz-host-interop-tests` | excluded: test | Router interop tests for macOS and Windows hosts. |
| `wz-host-net` | S9 | |
| `wz-host-sync` | S9 | |
| `wz-integration-tests` | excluded: test | The merged integration test binaries. |
| `wz-link-lwip` | S9 | |
| `wz-mcu-clock` | S9 | |
| `wz-mcu-multicast-e2e` | S9 | |
| `wz-mcu-session-acceptor` | S9 | |
| `wz-mcu-stack` | excluded: measurement | Paints and reads back the stack of the bare-metal deploy binaries; a measurement, not protocol. |
| `wz-mesh-client` | S10 | |
| `wz-node-time` | S9 | |
| `wz-oa-tc6` | S9 | |
| `wz-packet-fixtures` | excluded: test | Checksum arithmetic for hand-laid test packets. |
| `wz-packet-socket` | S9 | |
| `wz-plugin-abi` | S10 | |
| `wz-plugin-example` | excluded: example | An example plugin of the plugin ABI. |
| `wz-replay` | excluded: analyzer | Capture replay; its place in the migration follows `wz-capture`. |
| `wz-rest` | S10 | |
| `wz-routing-graph` | S4 | |
| `wz-runtime-coop` | S5, S10, S12 | |
| `wz-runtime-core` | S9 | |
| `wz-runtime-freertos` | S9 | |
| `wz-runtime-posix` | S9 | |
| `wz-runtime-tokio` | S4, S5, S10, S12 | |
| `wz-runtime-tokio-multicast-tests` | excluded: test | Multicast tests of the tokio runtime. |
| `wz-runtime-tokio-test-support` | excluded: test | Helpers for the tokio runtime's tests. |
| `wz-runtime-zephyr` | S9 | |
| `wz-session-core` | S1, S2, S3, S10, S11, S12 | |
| `wz-session-core-test-support` | excluded: test | Helpers for the session core's tests. |
| `wz-session-lwip` | S9 | |
| `wz-session-mcu` | S5, S10 | |
| `wz-session-wire-fixtures` | excluded: test | Wire fixtures for the session tests. |
| `wz-spi-scb` | S9 | |
| `wz-statechart-bridge` | S9 | |
| `wz-storage` | S6 | |
| `wz-switchboard-codegen` | S10 | |
| `wz-switchboard-example` | excluded: example | An example of the switchboard. |
| `wz-switchboard-schema` | S10 | |
| `wz-tls-mbedtls` | S9 | |
| `wz-tls-pem` | S9 | |
| `wz-tls-record` | S9 | |
| `wz-volume-abi` | S10 | |
| `wz-volume-example` | excluded: example | An example storage volume of the volume ABI. |
| `wz-workload` | S10 | |
| `wz-zenoh` | S6 | |
| `wz-zenoh-buffers` | S6 | |
| `wz-zenoh-codec` | S6 | |
| `wz-zenoh-collections` | S6 | |
| `wz-zenoh-config` | S6 | |
| `wz-zenoh-core` | S6 | |
| `wz-zenoh-keyexpr` | S6 | |
| `wz-zenoh-macros` | S6 | |
| `wz-zenoh-protocol` | S6 | |
| `wz-zenoh-result` | S6 | |
| `wz-zenoh-runtime` | S6 | |
| `wz-zenoh-shm` | S6 | |
| `wz-zenoh-sync` | S6 | |
| `wz-zenoh-task` | S6 | |
| `wz-zenoh-util` | S6 | |
| `zenoh-pico-sys` | excluded: binding | FFI bindings to the vendored zenoh-pico, used as the wire-interop oracle. |
| `zephyr-sys` | excluded: binding | FFI declarations of Zephyr; S9 reads the wz runtime over it. |
