# The C ABI presets: one engine, no heap after open

Status: decision record (owner, 2026-11-21: "cost not counted, the long-term correct structure, the
textbook and final one"). It states the measured facts the decision rests on, the decision, what
it costs, what was rejected and why, and the phases that carry it out, each with the gate and the
ratchet that hold it. It is a design note, not a specification; the atomic store does not parse it.
The pool design, the inventory of every heap use on the path and the units of the conversion are
in `docs/c-abi-no-heap-pools.md`.

## 1. Context: what is measured

Every figure here is a committed reading or a reading a gate prints; an estimate says so.

- **The tokio engine is half of every tokio case.** One feature set, two engines, one zenoh-pico,
  read on one host in one run (`deploy/pico_host_ceiling.json`, 2026-11-21, one toolchain):
  `pico-client-udp` (tokio engine) 2,057,617 bytes of text, `pico-client-coop` (cooperative
  engine) 1,030,646, zenoh-pico built as the same build 403,086. Ratios 5.1047 and 2.5569. The
  same tree read the cooperative client at 1,012,762 on another host while zenoh-pico read alike
  (the 1.77 percent spread behind the gate's tolerance, `scripts/lib/capability_cost_gate.py`,
  `RATIO_TOLERANCE`). The peer reads 7.76 on tokio and 2.84 on the cooperative engine.
- **The no-heap kit images already beat zenoh-pico.** The same session code (`wz-session-core`,
  `wz-runtime-coop`, `wz-session-mcu`) built without `std` and without an allocator is the kit's
  fixed client, and Layer Qzk reads every cell WIN against zenoh-pico built in the same run
  (`docs/upstream-parity.md`, D8 item 6): text 144,820 against 147,912, flash 3,188 under, static
  RAM 9,333 under, the stack objects 3,456 under; the heap client's storage block 7,712 against
  the reference's heap peak of 9,280. An image is not a library (LTO drops what it does not call;
  a C library carries every symbol it exports), so this is not the library's figure. It shows
  that the engine's logic, without `std` and without a heap, is smaller than zenoh-pico's.
- **Two engines keep two copies of the rules, and they drift.** The session, transport and
  routing rules are implemented twice behind the port: once in the tokio engine (`wz-capi-core`
  over `wz-runtime-tokio`), once in the cooperative engine (`wz-capi-coop` over the shared
  session code). `docs/capi-pico-on-coop-engine.md` records the cost: the mutual-dial race is
  held on each engine by its own rule, and a cooperative node against a tokio peer that races it
  is not held (the two keep different rules, and a race can close both links until the next
  redial). The tokio engine also does the work of pico's single-threaded arm on its own schedule,
  where pico does it inside `zp_read` and `zp_spin_once` (same note, section 2).
- **A failed allocation ends the process.** Both engines take memory from the heap as a session
  runs. `crates/wz-capi-pico/tests/allocation_faults.rs:78` states it for every build:
  `MEMORY_TAKEN_AT_OPEN` is false, a failed allocation ends in Rust's allocation-failure handler,
  and every message allocates; the instrument measures and prints, and asserts only what holds of
  every build. pico answers the same failure with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`.
- **The fixed-memory pieces exist, apart.** The handle objects of the pico ABI can come from
  fixed pools (`object-pool`, `crates/wz-capi-pico/src/object_pool.rs`), but only once the program
  reserves them, from the heap or a region it hands over, and the bytes a payload carries, the
  configs, key expressions, strings, encodings and closures stay on the heap in either build (that
  module's doc). The session core has a whole fixed-memory profile (`session-slot`), which the
  MCU images use and the C ABI does not.
- **Performance against zenoh-pico is not measured yet.** The W over P table of the host
  performance matrix (`deploy/pico_perf_ceiling.json`, D10) has 85 rows and every one is null:
  no row has a committed reading. No claim of speed is made here.

## 2. Decision

- **E1. One sans-I/O engine for every C ABI preset.** The pico drop-in, and the zenoh-c drop-in
  after it, run on the cooperative engine (`wz-capi-coop` over `wz-session-core`,
  `wz-runtime-coop` and `wz-session-mcu`), which is the single implementation of the session,
  transport and routing rules. The engine takes bytes and time and gives bytes; it owns no socket,
  thread or clock. The tokio engine stops being an engine of the C libraries. tokio survives as an
  optional adapter of the Rust API preset (`wz-zenoh`), whose futures become executor-agnostic.
- **E2. Execution drivers are thin and interchangeable.** (A) Caller-driven: `zp_read`,
  `zp_spin_once`, `zp_send_keep_alive` step the engine, as pico's single-threaded arm and an MCU
  loop do. (B) A driver thread over the OS's readiness, for a host library in pico's
  multi-threaded arm (`zp_start_read_task`, `zp_start_lease_task`): callbacks on a background
  thread, as pico's are. (C) The async adapter, for the Rust API. A driver holds no rule of the
  protocol; two drivers over one engine behave alike by construction. The router preset later runs
  one cooperative engine per core with its faces partitioned among them (thread-per-core, nothing
  shared).
- **E3. No heap in the C ABI presets.** All memory a session uses is reserved when it opens, sized
  from the limits it opens under (the configuration document's `wz/limits` over the build's
  limits, which it may only lower: decision Q2), so no allocation happens after open: the
  rule of the functional-safety coding standards that nothing is allocated after
  initialisation. An exhausted pool answers with the code pico
  already has for it (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `Z_ERR_SYSTEM_OUT_OF_MEMORY` in
  `crates/wz-capi-pico/src/result.rs`) or, where pico refuses a value, the code pico gives for that
  value; no ABI changes. There is one form of each C ABI: no second, heap-backed form beside the
  no-heap one. The Rust API preset may allocate: its API types are `Vec` and `String`.
- **E4. The host libraries are the MCU build plus an OS layer.** The Linux `.so` and the Windows
  DLL become the same `no_std` build as the MCU images over an OS layer (`wz-runtime-posix`
  already covers Linux and Winsock), so `std` leaves the C libraries. pico's platform exports
  (`z_malloc`, `z_free`, the clocks, the mutexes) keep forwarding to the C library, as pico
  defines them; the library itself never calls them for its own memory.
- **E5. One engine is verified once, and deterministically.** Because the engine takes bytes and
  time, a deterministic simulation lane drives it from a seed. Every upstream suite (zenoh-pico's
  tests, zenoh-c's tests, the Z8 examples) is graded on the single engine before the tokio engine
  path of the C libraries is deleted.
- **E6. The end state is WIN, held by gates, approached by ratchets** (owner addition,
  2026-11-21: the cooperative engine must beat zenoh-pico in size AND in performance; a ratio of 2
  is not acceptable). Two end-state gates, both existing:
  1. **Size:** every pico-ABI case built the cooperative way reads a D9 ratio at most 1.0, and
     the row is locked at WIN (`deploy/pico_host_ceiling.json`, `docs/upstream-parity.md` D9).
  2. **Performance:** every cell of the host performance matrix reads WIN and its row is locked
     (`deploy/pico_perf_ceiling.json`, `scripts/host-bench/perf_matrix.py --gate`, D10).

  Until then each row is a ratchet that only falls toward WIN; a phase below that moves a row
  commits the tighter row in its own round (D9 rule 4, D10 rule 2). The completeness scoreboard's
  criterion (d), `no-allocation-in-operation` (D11, `docs/completeness-scoreboard.md`), is
  extended from the MCU images to the C ABI host libraries.

- **E7. The releases, and the end state that closes them** (owner, 2026-11-21). The PoC release
  of 2026-12-01 is phase P1 (section 6): the cooperative engine, with `std` and the heap. The
  `no_std`, no-heap release follows phases P2 to P4. The end state is gated, each gate locked
  once met: D9, every pico-ABI case at a ratio of at most 1.0, locked at WIN; D10, every cell of
  the host performance matrix WIN, locked; D12, the allocations a session makes after its open,
  0 in every family of the P2 ratchet and locked there.

## 3. Consequences

What is gained: one copy of every rule; a session that cannot fail for memory once it is open; a
worst-case memory figure that is the reservation itself, not an estimate; the host library and
the MCU image measured as one build; a test lane that replays a failure from its seed.

What is lost, stated:

- **Tables no longer grow lazily.** A session pays at open for every row its limits allow, used or
  not. A deployer who states large limits pays for them in memory at every open; the worst-memory
  report says how much before anything runs.
- **What exceeds a configured limit is refused, never grown into.** A payload larger than the
  largest message a link reassembles (`PICO_FRAG_MAX_BYTES`), a key longer than
  `MAX_KEYEXPR_BYTES`, a declaration past its table, a sample that finds the delivery lane full,
  a reply past `MAX_PENDING_REPLIES`: each is refused with its code or counted where no call can
  be told. zenoh-pico on a host grows several of these while its allocator gives.
- **A limit may not be unbounded in a C ABI build.** A limit that sizes a pool and is stated
  `unbounded` (or whose build default is the no-bound 0: `QUERY_PARAMETERS_MAX_BYTES`,
  `QUERY_ATTACHMENT_MAX_BYTES`, `QUERIER_MAX_PENDING_QUERIES`) is refused at open with
  `Z_ERR_CONFIG_INVALID_VALUE`, as `object_pool.rs` already refuses a pool of no bound. The pico
  preset states a finite default for each (decision Q3, section 7).
- **A panic ends the process.** A `no_std` library does not unwind; the doors' `catch_unwind`
  (`ffi::guarded`) answering an error code goes. Memory and the wire are refused by code, not by
  panic, so what is left to panic is a defect.
- **The tokio engine's knobs go with it.** `serial-drive-own-thread` and `rx-busy-poll` mean
  nothing on the cooperative engine; capabilities only the tokio engine has are ported or leave
  the pico preset (phase P3).
- **What the deployer must configure.** Every limit of `docs/c-abi-no-heap-pools.md` section 4
  that sizes a pool, either in the build (Kconfig, the defaults of `deploy/wz-config.toml`) or in
  the configuration document's `wz/limits`, within the build's ceiling where the limit has one.
  The new limits that section names are added to `deploy/wz-config.toml` by the units that need
  them.

## 4. Rejected alternatives

- **Keep two engines.** Every rule twice: the race the two engines disagree on (section 1) is the
  class, not an instance, and each fix is made twice or lands once and drifts. The tokio engine is
  also half of every tokio case's text; no reduction inside it reaches the cooperative engine's
  figure for the same features.
- **tokio everywhere.** A runtime the MCU cannot carry and pico's single-threaded arm cannot
  honour (pico's contract has the work done inside `zp_read`); it keeps the heap and the threads
  the safety rule forbids, and its size is the measured 5.10 of the client.
- **A heap-backed C ABI with a second, no-heap form.** Two forms of one ABI are two products to
  test and two sets of failure behaviour (one ends the process, one returns a code), and the
  heap form is the one that would be shipped by default and the no-heap one the one that rots.
  The decision is one form. The Rust API preset is not a C ABI and keeps its heap.
- **A `std` host library.** `std` brings its panic machinery and backtrace symbolizer
  (estimated 150,000 to 350,000 bytes per case, `docs/host-size-debt.md` on its branch,
  decision Q5), unwinding, and a global allocator that every crate reaches; a host library built
  that way is not the MCU build, so the two are measured, tested and certified apart. The OS
  layer the host needs already exists without `std` (`wz-runtime-posix`).

## 5. Size and performance: what each phase removes

The cooperative client's 2.5569 (1,030,646 over 403,086, 627,560 bytes over pico), by what takes it
away. Measured is a committed reading or a case note of the gate; an estimate is labelled with its
source and the `footprint_attribution.py` scope that turns it into a measurement
(`docs/host-size-debt.md`, section 6, on the branch `debt-host-size-1`, read-only here).

| what | bytes | basis | removed by |
|------|------:|-------|-----------|
| unwind tables, landing pads, `catch_unwind` at every door | about 187,000 | estimate: the 18.2 percent the tokio client measured (`pico-client` 1,989,401 to `pico-client-small` 1,627,962, 361,439 bytes) applied to the cooperative client | P4 (a `no_std` library cannot unwind), or earlier by a `panic = "abort"` shipped profile once the no-panic gate holds (decision Q5) |
| `std`'s panic hook and backtrace symbolizer (`backtrace_rs`, `gimli`, `addr2line`, `miniz_oxide`, `rustc_demangle`) | 150,000 to 350,000 | estimate (`host-size-debt.md` Q5); `panic = "abort"` alone keeps it | P4 |
| the allocator's growth paths and the collections (`RawVec` growth, B-trees, `hashbrown`, deques, the drop glue of boxed trait objects, text built with `format!`) | not estimated | no reading; scope `alloc::\|hashbrown\|btree\|as core::fmt::(Debug\|Display)` before and after | P2 |
| `log` call sites (21 in `wz-session-core`) | small | estimate (`host-size-debt.md` Q4) | a static level for the C libraries (open question) |
| the engine, the generated codecs and machines, the ABI layer | the rest | measured only as the remainder | the D9 debt loop, symbol by symbol |

Projection, an estimate and not a reading: after P4 the client is 1,030,646 less 337,000 to
537,000, that is 493,646 to 693,646 bytes, a ratio of 1.22 to 1.72. **No phase is expected to cross
1.0 alone, and P4 is the largest single step.** On the upper estimates 90,560 bytes remain over
zenoh-pico after P4, to be taken by P2's share (not estimated) and the D9 debt loop; on the lower
estimates 290,560 remain. So the earliest the cooperative client is expected to read 1.0 or under
is the end of P4 with P2 complete, on the upper estimates; on the lower ones it is the D9 debt loop
(rule 5) on the engine's own symbols after P4. The MCU image's WIN (section 1) is the evidence that
the logic fits; the remainder is what a library exports and an image drops, and its first reading
is the first thing P4 measures.

The planes over the base client are outliers of their own, measured from paired cases
(`host-size-debt.md` section 2), and a case of a plane crosses 1.0 only when the plane does:

| plane (cooperative) | wz bytes | pico bytes | wz / pico | what removes it |
|---------------------|--------:|----------:|----------:|-----------------|
| unstable API | +111,803 | +1,866 | 59.9 | not a phase: the device-requirements door reads endpoints with every scheme's parser (`host-size-debt.md` Q6, estimate up to 110,000); a reduction of its own, before P1 |
| peer over scout | +63,954 | +5,136 | 12.5 | P2 (the face and admission tables in the arena), then the debt loop |
| scout | +84,207 | +7,377 | 11.4 | P2 (the Hellos to a borrowed buffer), then the debt loop |
| query and queryable | +325,190 | +34,610 | 9.4 | P2 in part: the case notes of 2026-11-03 put that growth in `decode_one_record`'s borrowed-to-owned conversions, which the in-place forms of P2 replace (unit U3 of the pool note); the rest by the debt loop (R4) |
| admin space, with queryable and unstable | +372,322 | +41,270 | 9.0 | P2 (the admin rows of the fixed profile, `adminspace-fixed`), and the unstable-API reduction above |
| local queryable over query | +16,164 | +2,536 | 6.4 | the debt loop |
| local subscriber | +6,548 | +2,400 | 2.7 | the debt loop |
| connectivity over unstable | +70,320 | +34,911 | 2.0 | the debt loop |

Performance has no reading to break down (section 1). What each phase is expected to change, none
of it measured: P1 moves the W arm of the matrix to the cooperative library; P2 removes the
allocations each message makes today (the traffic count of `allocation_faults.rs` is the reading
before and after); P4 changes no path a message takes. The end state is every row of
`deploy/pico_perf_ceiling.json` locked at WIN; a row is first filled by a run, never by hand
(D10 rule 5).

## 6. Migration

Each phase has a gate that judges it and a ratchet that keeps what it took. A ratchet's row only
moves toward its target, and a reading under it is committed as the tighter row. The PoC release of
2026-12-01 is P1; the `no_std`, no-heap release follows P2 to P4; the gates of E7 close the end
state.

- **P1. The package on the cooperative engine (`std`).** The shipped pico library (the Linux
  `.so`, the Windows DLL of `scripts/lib/pico_windows_package.py`) is built on the cooperative
  engine for every capability it carries: the pico base of `deploy/wz-config.toml` names
  `engine-coop` where it names `engine-tokio` today, and a capability only the tokio engine has
  is out of the package until P3 brings it. Gate: the package's case in
  `capability_cost_gate.py` and its D9 row; zenoh-pico's API tests (Layer Z) and Layer C1co on
  the package build. Ratchet: the case's D9 row.
- **P2. The no-heap ratchet.** Allocations after open are counted per operation family by a
  test allocator (the instrument of `allocation_faults.rs`), on the cooperative package build.
  The gate is `scripts/lib/no_heap_ratchet_gate.py` over `deploy/no_heap_ratchet.json`, built by
  its own worker: one row per family, the count may only fall, target 0, and a family at 0 is
  locked. The conversion is the units of `docs/c-abi-no-heap-pools.md` section 6, one family at a
  time. P2 ends when every row is locked at 0; `MEMORY_TAKEN_AT_OPEN` then holds for the build and
  the assertions of `allocation_faults.rs` (a named error for every failed allocation, nothing
  left behind, no allocation in traffic) become part of the gate.
- **P3. The cooperative engine's coverage ratchet.** The features of `wz-capi-pico` whose
  closure selects `engine-tokio`, read from `crates/wz-capi-pico/Cargo.toml`; the count may only
  fall, target 0. Today ten: `default` (it names `engine-tokio` itself), `gossip`,
  `serial-drive-own-thread`, `rx-busy-poll`, `transport-link-unixpipe`, `transport-link-quic`,
  `transport-link-tls`, `transport-link-ws`, `transport-link-serial`, `raweth-transport`. What
  each becomes: `default` names `engine-coop` (P1); `gossip` is linked and never started in
  the pico ABI (`gossip: None` in every build, `host-size-debt.md` Q3), leaves the pico
  preset's default and becomes an opt-in the cooperative engine starts (decision Q7);
  `serial-drive-own-thread` and `rx-busy-poll` are knobs of the tokio engine and retire with it;
  `transport-link-tls` (rustls on the tokio engine) gives way to `tls-mbedtls`, the cooperative
  engine's channel over the same `Z_CONFIG_TLS_*` keys (L6 of `docs/capi-pico-on-coop-engine.md`); `transport-link-ws`,
  `transport-link-serial` and `raweth-transport` become link drivers of the cooperative runtime;
  `transport-link-unixpipe` and `transport-link-quic`, wz's own links on the pico ABI, become
  link drivers of the cooperative runtime too, opt-in in the pico preset (decision Q6). The
  ratchet is a row of `deploy/no_heap_ratchet.json` or a table of its own, whichever the gate's
  worker chooses; it is counted from the manifest, never written by hand.
- **P4. The `no_std` host library, Linux then Windows.** The cooperative build without `std`
  over `wz-runtime-posix`: the os seam of section 5a of `docs/upstream-parity.md` (thread
  identity, spawn, sleep, the clock) answered by the OS layer, the lock the port's `sync::Lock`,
  thread-locals from the OS. No `#[global_allocator]` and no `extern crate alloc` in the graph,
  judged by `scripts/lib/no_allocator_link_gate.py` with the host libraries as rows. Gate: that
  link gate, the D9 rows (the largest single fall, section 5), the Layer Z and C1co legs on the
  `no_std` build. Ratchet: the D9 rows and the link gate's table.
- **P5. The tokio engine path of the C libraries is deleted.** Preconditions: P3 at 0, and every
  upstream suite graded on the cooperative engine: zenoh-pico's API tests, zenoh-c's tests (Layer
  C1cc) once `wz-capi-c` has made its own P1 to P4 with its own coverage rows, and the Z8
  examples once the Rust API runs on the engine through driver (C). Then `engine-tokio`,
  `wz-capi-core`'s place under the C ABIs and the tokio pico cases with their D9 rows go in one
  change (the ceiling refuses a row left for a case that is gone).
- **P6. The deterministic simulation lane.** The engine over the in-memory network
  (`wz-session-mcu`'s `MemoryNetwork`) and a clock the lane moves (`time-base`), every choice
  (delivery order, loss, a partition, a peer's restart, a pool at its limit) drawn from a seed.
  Gate: a lane of N seeds per run, with the property that one seed gives one trace; a seed that
  fails is committed as a regression case. Ratchet: the seed count and the fault kinds covered
  only grow.
- **P7. The router, thread-per-core.** One cooperative engine per core, the faces partitioned
  among them, nothing shared but the rings between cores (`docs/parallel-faces-design.md`,
  `docs/router-data-plane-scaling.md`). Gate: the router's cells of the performance matrices.

## 7. Decisions of the owner (2026-11-21)

The questions this record left open, decided. Each keeps its number, so a reference to it in
`docs/c-abi-no-heap-pools.md` still reads, and each is restated there where it bites.

- **Q1. The objects made before any session live in process pools the library reserves at its
  first call.** A config, bytes, strings, encodings, closures and channels are made by a pico
  program before `z_open` and outlive `z_close`. The library reserves its process pools once,
  at the first call a program makes into it, sized from the build's limits, so that call is the
  initialisation after which nothing is allocated. No reservation door is required; one
  (`wz_ext_object_pool_reserve`, `_place`) may be offered beside it, for a program that places
  the memory itself. Reason: the drop-in contract. An existing pico program runs unchanged, and
  no pico program calls a door pico does not have.
- **Q2. The document's `wz/limits` may only lower a build value, never raise it.** Reason: the
  build fixes the worst-case memory, which is the basis a certification is made on; the
  document chooses within it. A host library is configured without a rebuild inside that bound,
  and the MCU images keep the build as their ceiling as before.
- **Q3. Every limit that sizes a pool is finite in the pico preset.** The limits unbounded today
  (`QUERY_PARAMETERS_MAX_BYTES`, `QUERY_ATTACHMENT_MAX_BYTES`, `QUERIER_MAX_PENDING_QUERIES`)
  and each new limit of the pool note take, in the pico preset, zenoh-pico's own compile-time
  constant where pico has one, cited as `vendor/zenoh-pico/<file>` @ the `#define`, and
  otherwise a value stated with its reason. Reason: a pool of no bound cannot be reserved
  (section 3), and pico's own constant makes the preset hold what pico holds wherever pico bounds
  the same thing.
- **Q4. A full delivery lane is zenoh's congestion control.** Reliable, blocking traffic applies
  backpressure: the engine stops reading the link while the lane is full, so the transport's
  own flow control carries the wait back to the sender. Drop-policy and best-effort traffic is
  dropped and counted. Reason: this is what a message's congestion control already states in
  zenoh (`block` holds the sender, `drop` drops), so the lane keeps that meaning rather than
  adding a third one.
- **Q5. `panic = "abort"` comes with a no-panic gate.** The shipped profile switches to abort
  only once a gate proves the shipped C library's panic paths absent: a link-time check that no
  panic entry is reachable from the exported doors. Until then the library unwinds and the
  doors' `catch_unwind` (`ffi::guarded`) stays. Reason: with abort, a panic that reaches a door
  ends the process where it returns an error code today; the gate makes "no door panics" a
  measured property before the unwinding share of section 5 is taken.
- **Q6. Every link moves to the cooperative engine.** `unixpipe`, `quic`, `ws`, `serial`, `tls`
  and raw Ethernet become link drivers of the cooperative runtime. The pico preset's default
  enables zenoh-pico's own set of links; the others are opt-in. Reason: wz is a framework and
  zenoh-pico is one of its presets, so a link pico lacks is a capability of wz that the preset
  leaves off, not one that leaves wz because upstream lacks it.
- **Q7. `gossip` is off in the pico preset's default and becomes a working opt-in on the
  cooperative engine.** Reason: in the pico ABI it is linked and never started today
  (`gossip: None` in every build, `host-size-debt.md` Q3), which is code paid for and not run.
  As an opt-in it is started and does what it states; off, it is not linked.
