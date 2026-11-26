# Winning RSS: the resident set of a perf-matrix process against zenoh-pico

Status: design, lane "rss" of the win budget. It counts, from the code, the build and the built
artifacts, what each process of the host performance matrix (`scripts/host-bench/perf_matrix.py`,
`docs/pico-perf-matrix.md`) holds resident, for arm W (`libwz_capi_pico`) and arm P (zenoh-pico
built as the same build), ranks the differences, and names the structure that removes each. The
heap half is `heap.md` and `std-heap.md`, the code-size half `text.md`; this file reads them
as parts of one figure, the peak resident set.

## 1. What is measured

The matrix reads each process's peak resident set, VmHWM of `/proc/self/status`, which the probe
prints as its last line (`perf_probe.c`, `print_usage`), and gates the sum of the two processes
of a cell. The idle-machine run of int206 (2026-11-26) reads W over P at 1.25 to 1.31 in every
cell: 1.23 to 1.27 over tcp, 1.29 to 1.31 over a multicast group. The figure has no breakdown,
so the rows below are counts, and section 6 names the reading that turns each into a measured
one (`PERF_SMAPS`, which this lane adds).

VmHWM counts every page mapped into the process and present: anonymous pages written (the heap,
the session's arena, thread stacks, the relocated data of each library) and file pages the
process touched (each library's code, read-only data and symbol tables, and the program's own).
A file page is counted though the page cache shares it: VmHWM is not PSS. A read fault on a
file mapping maps the pages around it that the page cache holds too (`fault_around_bytes`,
64 KiB by default), so a library whose code is run here and there across its text is resident
nearly whole, not by the pages its run executes alone.

The probe, libc and the loader are the same in both arms; the library is what differs, and the
memory it reserves, maps and starts. The absolute VmHWM of either arm is not in the run's summary; the
parity run of 2026-11-25 read 4,888 KiB for zenoh-pico's pub/sub pair (`std-heap.md` section 1),
about 2,444 KiB a process, and at 1.25 to 1.31 the gap is then about 610 to 760 KiB a process.
That derivation joins two runs and is an estimate: cell R0 measures it.

## 2. The libraries, read from the built artifacts

Read with `size -A`, `readelf -lW` and `nm -S` from the perf matrix's own copies of the
two libraries (`pico-compare/perf/lib-W` and `lib-P` of the run of 2026-11-25 09:33, the
build `reference.json` records: arm W on the cooperative engine without `std`, profile
`capi-nostd`, packed relocations, unwind tables discarded; arm P with the same feature
switches, linked as the size gate links its reference). The current tree builds the same
features; its sizes differ by what landed since, which cell R1 reads again.

| loaded segment | arm W | arm P | W - P |
|---|---:|---:|---:|
| R: headers, `.dynsym`, `.dynstr`, `.gnu.hash`, relocations | 55,560 | 159,688 | -104,128 |
| R E: `.text`, `.plt` | 1,140,561 (`.text` 1,140,467) | 339,865 (`.text` 297,289, `.plt` and `.plt.sec` 42,480) | +800,696 |
| R: `.rodata` | 64,340 | 5,648 | +58,692 |
| RW: `.data.rel.ro`, `.got`, `.data`, `.bss` (memory size) | 66,088 (RELRO 46,496: `.data.rel.ro` 36,560, `.got` 9,376; `.data` 10,600, `.bss` 8,992) | 12,912 (RELRO 1,808; `.got.plt` 10,640) | +53,176 |
| **every segment** | **1,326,549** | **518,113** | **+808,436** |

The RW segment is private: the loader writes every page that holds a relocation target, so the
RELRO pages are resident and dirty in each process; `.data` is resident where it is read or
written, `.bss` where it is written.

One more library is mapped into arm W's process alone: the probe built against
`libwz_capi_pico.so` lists `libgcc_s.so.1` among its needed libraries (`readelf -d`), and the
probe of arm P does not. The library leaves one symbol of the compiler's runtime undefined,
`_Unwind_Resume` (`nm -D --undefined-only`): the prebuilt `core` and `alloc` are compiled to
unwind and their cleanup paths call it, and LTO keeps the reference. The C compiler links
`libgcc_s` as needed and it is needed for that one name, so every program of the library maps
a 187,120-byte library (`.text` 142,453) whose code nothing in it runs: the loader reads its
headers and symbol tables (every lookup of the process searches its hash table), relocates its
GOT and runs its initialiser.

### 2.1 What arm W's text is

`nm -S` of the same library, every text symbol's size summed by the crate its name begins with
(1,133,407 of the 1,140,467 bytes are symbols; a generic is counted at the crate that defines it):

| crate | bytes | | crate | bytes |
|---|---:|---|---|---:|
| `wz_session_core` | 351,770 | | `alloc` | 46,152 |
| `wz_capi_coop` (of it `engine` 166,491) | 185,284 | | `wz_session_mcu` (the group drive) | 29,202 |
| `wz_capi_pico` | 92,659 | | `wz_runtime_posix` | 21,383 |
| `core` | 92,164 | | `sce_rust_runtime` | 19,522 |
| the C doors (unmangled `z_`, `ze_`, `zp_`, `wz_` names) | 84,175 | | `sha2` | 12,332 |
| `wz_codecs` | 67,240 | | `wz_host_sync`, `wz_capi_port` | 9,633 |
| `wz_ext_pubsub` | 50,559 | | `wz_runtime_coop` | 48,258 |

By what a perf run never calls, by symbol name (the groups overlap the crate rows): names with
`advanced` 100,974; `liveliness` or `token` 32,506; `scout` 26,414; the connectivity and
link and transport event listeners 20,699; float formatting (`flt2dec`, `float`) 15,726;
`sha2` and the digest 13,540. The probe declares a publisher and a subscriber and puts; none of
these runs in it.

This is not the size gate's case. `text.md` reads the client preset (`pico-client-coop-nostd`,
235,152 bytes against 170,500, 1.38); the matrix builds the crate's default features (advanced,
connectivity, liveliness and its get, the multicast transport, peer, query, queryable, scouting,
the config policy, the conformance digest, the unstable API), 1,140,467 against 297,289: 3.84.

### 2.2 Which build each arm is: pico's switches in wz's features

The crate's default features are the Kconfig defaults, not zenoh-pico's own default build, and the
reference zenoh-pico of that run was built with each switch the declaration answers set from those
features (`wz_config.pico_reference`), so arm P carried the advanced publisher and subscriber, the
unstable API and the connectivity events too, which pico's default build does not, and arm W carried
three planes of its own no pico switch has. Read from `vendor/zenoh-pico/cmake/feature_config.cmake`
(pico's defaults), the declaration's `upstream_switch` rows (`deploy/wz-config.toml`) and
`configs/zenoh-pico_defconfig` (zenoh-pico's preset in wz, generated from the same declaration):

| `Z_FEATURE_` switch | pico default | class | wz feature | preset (W, and P from it) | crate default (the run read above) |
|---|---:|---|---|---:|---:|
| `UNSTABLE_API` | 0 | maps | `unstable-api` | 0 | 1 |
| `CONNECTIVITY` | 0 | maps | `connectivity` | 0 | 1 |
| `ADVANCED_PUBLICATION`, `ADVANCED_SUBSCRIPTION` | 0 | maps | `advanced` | 0 | 1 |
| `QUERY`, `QUERYABLE` | 1 | maps | `query`, `queryable` | 1 | 1 |
| `LIVELINESS` | 1 | maps | `liveliness` (and `liveliness-get`, which pico's switch includes) | 1 | 1 |
| `MULTI_THREAD` | 1 | maps | `multi-thread` | 1 | 1 |
| `SCOUTING` | 1 | maps | `scout` | 1 | 1 |
| `LINK_UDP_UNICAST` | 1 | maps | `link-udp` | 1 | 1 |
| `MULTICAST_TRANSPORT`, `LINK_UDP_MULTICAST` | 1 | maps | `multicast-transport` | 1 | 1 |
| `UNICAST_PEER` | 1 | maps | `peer` | 1 | 1 |
| `LINK_WS`, `LINK_SERIAL`, `LINK_TLS`, `RAWETH_TRANSPORT` | 0 | maps | `transport-link-ws`, `-serial`, `-tls`, `raweth-transport` | 0 | 0 |
| `LOCAL_SUBSCRIBER`, `LOCAL_QUERYABLE`, `MULTICAST_DECLARATIONS`, `ADMIN_SPACE` | 0 | maps | `local-subscriber`, `local-queryable`, `multicast-declarations`, `admin-space` | 0 | 0 |
| `PUBLICATION`, `SUBSCRIPTION`, `INTEREST`, `FRAGMENTATION`, `ENCODING_VALUES`, `LINK_TCP`, `UNICAST_TRANSPORT`, `TCP_NODELAY`, `SESSION_CHECK`, `BATCHING`, `MATCHING`, `AUTO_RECONNECT` | 1 | always | in every build | 1 | 1 |
| `RX_CACHE` | 0 | always | the match memo, in every build | 1 | 1 |
| `LINK_BLUETOOTH`, `LINK_SERIAL_USB` | 0 | never | none | 0 | 0 |
| `BATCH_TX_MUTEX`, `BATCH_PEER_MUTEX` | 0 | n/a | none: pico's own locking | 0 | 0 |
| no switch | | | `config-policy`, `conformance-digest`, `device-requires` (wz's own planes) | off | on |

So the preset is pico's default build on every switch but `RX_CACHE`, which wz holds in every
build, and the crate default is it plus the six rows that differ. The one declaration of the preset
is `deploy/wz-config.toml` (`upstream_on`, `upstream_off`), emitted as
`configs/zenoh-pico_defconfig` and resolved by `wz_config.pico_bench_configuration`; the perf
matrix (`perf_matrix.py reference` and `wz-arm`, `wz_config.preset_named_features`), the instruction
counts (`pico-compare.sh subprofile`, `opprofile`) and the parity matrix (`preset-arm`) all read it
there, and `wz_config.py --selftest` holds the perf matrix's list to the parity's. The size gate's
`pico-*` cases are a third thing: each names its own narrower list (`pico-client-coop-nostd` is
`os-host,link-udp`, a client) with a budget of its own, and its reference is derived from that list
by the same rule, so its ratio compares like with like already.

By name (section 2.1), the preset takes out of arm W `advanced` (100,974 bytes), the connectivity
listeners (20,699) and the config policy's, the conformance digest's and the device requirements' doors,
and out of arm P pico's advanced publisher and subscriber; liveliness and scouting stay in both, since
pico's default build has them. The bytes named digest stay too: they are the acceptor's cookie MAC, not
the conformance digest (section 5.1).

## 3. Table W: what an arm W process holds resident, by component

| component | count from the code and the build | resident (estimate) | source |
|---|---|---:|---|
| library text pages | 1,140,561 B mapped | most of it: the run executes the open, the declarations, put, the read and the close, spread over every 64 KiB window of the text | section 2 |
| library symbol tables and headers | 55,560 B | the parts the loader reads | section 2 |
| library `.rodata` | 64,340 B | where read | section 2 |
| library RW (relocated, dirty) | 46,496 B RELRO, 10,600 `.data`, 8,992 `.bss` | about 50 to 66 KiB | section 2 |
| `libgcc_s.so.1` | 187,120 B file, `.text` 142,453 | its headers, hash and dynamic tables, the GOT page, and the window around its initialiser: tens of KiB | section 2 |
| session arena | 290,304 B reserved for `z_sub`, 185,488 for `z_put` (massif, 2026-11-25, `heap.md` 1); mapped as fresh pages (`wz_host_sync::pages::reserve`), told it is zero (`Arena::over_zeroed`) | the rows the open and the run write | `heap.md` 5 and 7 |
| process pools | 78,160 B (`Reserved::built`), slots taken by a high-water mark (`Pool::fresh`); payload blocks of `LARGEST_BLOCK` = the larger of `PICO_FRAG_MAX_BYTES`, both batch sizes and `MAX_KEYEXPR_BYTES`, plus the block head | the slots and blocks taken | `process_pool.rs` |
| face supervisor | 7,568 B (`LinkSupervisor::new`), a second allocation | whole | `heap.md` 5.7 |
| threads | the caller's, and one read thread (`CoopEngine::start_read_task`, `os::spawn` over `pthread_create` with the default attributes: 8 MiB reserved) | the frames the read writes; the read's bound is proven at a few KiB (stack bound gate) | `wz-host-sync/src/unix.rs` |
| C library heap | the arena below the mmap threshold, the probe's stdio buffer (4,096 B, both arms) | as written | `no_std_host.rs` (`c_heap`) |
| per-thread malloc arenas | none: nothing is allocated after the open on any thread (`allocation_faults.rs`) | 0 | `std-heap.md` S4 |

## 4. Table P: what an arm P process holds resident, by component

| component | count from the code and the build | resident (estimate) | source |
|---|---|---:|---|
| library text pages | 339,865 B mapped | nearly all of it | section 2 |
| library symbol tables and headers | 159,688 B: zenoh-pico exports its internals and calls them through the PLT | the parts the loader reads; the bind of every call through `.got.plt` | section 2 |
| library `.rodata` | 5,648 B | | section 2 |
| library RW | 12,912 B | about 12 KiB | section 2 |
| session and transport | `_z_session_t` (`api.c` @ `z_malloc(sizeof(_z_session_t))`), one read and one write buffer of the batch size per transport (`Z_BATCH_UNICAST_SIZE` 2,048, `Z_BATCH_MULTICAST_SIZE` 2,048, `cmake/feature_config.cmake`), a peer per accepted link, a defragmentation buffer of `Z_FRAG_MAX_SIZE` (4,096) only when a first fragment arrives | about 17 KB peak for `z_sub`, 15 KB for `z_put` (`heap.md` 1) | `heap.md` 2 |
| per message | a sample and the subscription cache's entry, built and freed by the read task each message (`std-heap.md` 1.1) | the chunks they reuse | |
| threads | the caller's, the read task and the lease task (`zp_start_read_task`, `zp_start_lease_task`, default attributes) | two stacks' written frames | `vendor/zenoh-pico/src/system/unix/system.c` |
| per-thread malloc arenas | the read task allocates, so glibc gives it an arena of its own (64 MiB reserved, written as used) | its top chunk's pages | `std-heap.md` S4 |

## 5. The differences, largest first, and the structure of each

| row | W - P (count) | structure that removes it | files | lane | state |
|---|---:|---|---|---|---|
| R1 library text pages | +800,696 B mapped | (a0) both arms built as zenoh-pico's preset (section 2.2), so neither carries a plane pico's default build has not; (a) the text lane's areas (`text.md`), read here on the bench's features, where the gap is 3.84 and not 1.38: the engine (`wz_capi_coop::engine` 166 KB) and the session core (352 KB) carry the doors of every default capability; (b) code a run never calls kept off the pages it does: the doors of the capabilities a program may not use (advanced, liveliness, scouting, connectivity, the conformance digest, about 190 KB by name in section 2.1) laid out together, apart from the open, put and read, so their 64 KiB windows are never faulted (GNU ld already puts `.text.unlikely.*` first; a `#[cold]` door is placed there); (c) float formatting and the digest out of the no_std form | `text.md`; the door modules of `wz-capi-pico`; `wz-capi-pico-lib` link script; (a0) `wz_config.py`, `perf_matrix.py` | text, rss | (a0) **landed in this lane**, R1 read again on it; (b) and (c): cell R3 first, since which windows a run faults is read, not counted |
| R2 `.rodata` | +58,692 B on the crate default's build; +10,234 B and +8 KiB resident a process on the preset's (section 5.3) | the jump tables of short matches lowered to compares, the encoding constants' states folded into their views, the errno match of the accept as a set; the bytes count only where they cross a page (section 5.3) | `.cargo/capi-nostd.toml`; `wz-capi-pico` `encoding.rs`; `wz-runtime-posix` `stream.rs` | rss, text | designed, section 5.3; measured first |
| R3 RW, relocated | +53,176 B on the crate default's build; +21,480 B and +20 KiB resident a process on the preset's (section 5.3) | fewer pointers the library holds to itself: the link drivers dispatched over the build's closed set, not through vtables; the limits' and the encodings' names as offsets into one string, so their tables carry no pointer | `wz-runtime-coop`, `wz-capi-coop` (the links); `wz-session-core` `limit_binding.rs` and the generator of `limits_generated.rs`; `wz-codecs` `encoding_ids.rs` | rss, text | designed, section 5.3; measured first |
| R4 `libgcc_s.so.1` | its mapped pages, W only | define `_Unwind_Resume` in the library as a local symbol that aborts, as `rust_eh_personality` is: the library is `panic = "abort"`, its personality aborts and its unwind tables are discarded, so no landing pad is ever entered and the name is never called; with it defined, the C compiler's as-needed link of `libgcc_s` drops the library, and the size gate refuses the name undefined | `wz-capi-pico/src/lib.rs` (`c_library_runtime!`), `scripts/lib/capability_cost_gate.py` | rss | **landed in this lane** |
| R5 session arena and pools | rows written by the open | `heap.md` H1 to H7 (counts from the open's config, smaller rows, one pool across faces, dedup, no round), with rss-zero's fresh pages so an empty row is never written | `heap.md` | heap | in the heap lanes |
| R6 face supervisor | +7,568 B | gone with the link tasks (`heap.md` 5.7) | | heap | in the heap lanes |
| R7 symbol tables | -104,128 B | none: wz exports only its doors | | | a win |
| R8 threads and malloc arenas | W holds one thread and no arena fewer | none | | | a win |

R1 is the gap: about 0.8 MB mapped against an estimated 0.6 to 0.76 MB measured. If fault-around
makes most of the text resident, R1 alone accounts for the figure, and the other rows move it by
tens of KiB each. That is why R1's split between (a), (b) and (c) waits for cell R3: the size of
a run's resident text is what the layout changes, and only the run's own page map says it.

### 5.1 The preset's run, part by part (R0 read, 2026-11-26)

The first run of both arms as zenoh-pico's preset with `PERF_SMAPS=1` (3 repetitions, idle host) reads W
over P at 1.14 to 1.16 in every cell, from 1.25 to 1.31 on the crate default's build: comparing like with
like alone took that much. Summed over the two processes of a cell, in KiB, W against P: the library 1,668
against 856 (1.95), anonymous 272 against 108 (2.5), the main thread's stack 76 against 48, the brk heap 44
against 40, libc 2,952 against 3,208 (W ahead: pico calls more of libc), the rollup's private dirty 560
against 340. Arm W's library text is resident whole: 191 of 191 pages in every role (`resident-text`), so
its resident text is its text size, and R1 is the text lane's work and nothing a layout of it can take.

**What the preset still carries that no run calls.** Of section 2.1's groups the run holds 30,552 bytes
named liveliness or token, 22,880 named scout and 13,773 named digest. Liveliness and scouting are
capabilities of pico's default build (`Z_FEATURE_LIVELINESS`, `Z_FEATURE_SCOUTING`, section 2.2) and stay.
The digest is not the conformance digest, which the preset leaves out (arm W names no
`conformance-digest`): it is the HMAC-SHA256 of the acceptor's cookie (`wz_session_core::accept_cookie`,
`signing_key::compute_hmac_sha256_full` 1,108 bytes, `sha2::sha256::compress256` 11,596 and its SHA-NI form
`digest_blocks` 947), which a listener mints in its InitAck and checks in the OpenSyn so that it can carry the
negotiated state there. zenoh-pico answers an InitSyn with an empty cookie
(`src/transport/unicast/transport.c`, `_z_t_msg_make_init_ack(mode, *local_zid, cookie)` with
`_z_slice_null()`). Leaving the MAC out would leave the acceptor's state unauthenticated, a change of the
handshake's guarantee, so it is a decision of its own and not a build switch this lane may flip
(section 5.2).

**Anonymous memory, W - P = +164 KiB**, read per process from the mappings of the tcp round trip cell
(`perf.json`, `smaps_client` and `smaps_server`); the other cells read the same within 4 KiB a part:

| part | W dialer | W listener | P dialer | P listener | W - P | what it is, counted |
|---|---:|---:|---:|---:|---:|---|
| session arena (one mapping of fresh pages, `os::HostPages`) | 60 mapped, 48 resident | 160 mapped, 112 resident | none | none | +160 | the rows `ArenaPlan::of` lays out at the preset's limits (`WZ_LIMITS_ZENOH_PICO`): the dialer one face, the listener a face set and link buffers for each of `max_faces` and `accept_pending`; a row the open never writes is never resident (`Arena::over_zeroed`), so the resident part is the rows the open writes, the places it constructs (engine, runtime, planes, rooms, link cells) and the tables a face takes |
| library `.bss` past its last file page | 8 | 8 | 0 | 0 | +16 | 7,440 bytes: `wz_host_sync::RECORDS` 5,120 (the thread records), the scout window's buffer 2,048 and the callback table 144, with the critical section's words (`wz_runtime_coop::cs::host_sys` `LOCK`, `DEPTH`, `OWNER`) on the second page, written by every critical section, so both pages are dirty |
| the read thread's malloc arena | 0 | 0 | 4 | 8 | -12 | pico's read task allocates, so glibc gives it an arena of its own; wz allocates nothing after the open (section 4) |
| the read thread's stack (8 MiB mapped) | 12 | 12 | 12 | 12 | 0 | |
| libc's and the loader's own (52, 8 and 8 KiB mappings) | 36 | 36 | 36 | 36 | 0 | the listener's 8 KiB one lies against the arena and is read inside the 168 KiB mapping smaps shows |

**The main thread's stack, W - P = +28 KiB** (W 40 and 36, P 24 and 24): the pages of the caller's stack
the open touches. Counted from the run's own library (`objdump -d`, each function's frame from its
prologue, the deepest chain of direct calls): `z_open` 2,400 bytes, then `CoopEngine::assemble` 8,464,
`lend_session` 6,272, `RegistryOf::new` 2,448 and `PeerPools::lent` 400, 20,048 bytes in all; a
declaration reaches 7,648 (`SlotObserverOf::drain_declare_replies` 5,360 of it), a put 3,496, the close
4,624. The open's chain is five pages of stack, against the probe's and libc's own 24 KiB that both arms
share.

**What takes them, largest first.**

| row | KiB (two processes) | structure | state |
|---|---:|---|---|
| A1 arena pages the listener's open writes | 112 + 48 | the sets of the faces not yet accepted built when a face first takes their place, not at the open: `RegistryOf::new` builds the dial face's set and reserves one span for the rows of every other place (`SpareSets::reserved`, `Arena::split_off`), which nothing writes; `add_face` builds the set of the place it takes from that span (`engine/registry/adding.rs`), passing a place a tomb kept on the way, and rebuilds the index of the gets' deadlines over the sets built (`DueIndex::rebuild`). The arena is still reserved to its ceiling, so a face that comes is never refused for memory; what moves is which pages are written. The rows judged one by one, largest first, are in section 5.1.1 | **landed in this lane**; R5's page map reads it |
| A2 the open's stack | 28 | `assemble` and `lend_session` build `SessionLent` and the plan in their frames and return them by value. The plan's list of rows (`ArenaPlan::rows`, `ARENA_ROWS` rows of 24 bytes), which only a report reads, is left out of the open's plan: `OpenPlan` is `ArenaPlan<0>`, which lays out every sum and every layer's rows and lists none, so `lend_session`'s frame holds no table of rows and its walk writes none (text falls with the stores); a region's plan is taken on without its list (`ArenaPlan::take_on`). The values the open builds in its frames and moves (`Core` in `assemble`, `SessionLent` out of `lend_session`) stay: writing them field by field where they live cost text in the sessions lane, so only a value whose bytes are measured to dominate a frame is a candidate | the list **landed in this lane**, the frames read again on the merged build (`objdump -d`, as section 5.1 counted them) |
| A3 `.bss` | 16 | the words every critical section writes laid beside the first thread record, the one the read thread's spawn takes: `wz_host_sync::process_section`, a reentrant lock in one 128-byte-aligned static with the records (`ProcessWords`), which `wz_runtime_coop::cs::host_sys` enters, so the two writes lie on one page; the scout window's buffer and the callback table stay where the linker puts them, and R0 reads whether either is written | **landed in this lane**, R0 reads it |
| A4 the read thread's malloc arena | -12 | none | a win |

#### 5.1.1 A1: the rows of R5's report, largest first

R5's report of the preset (the plan of a listener at the preset's limits, `WZ_LIMITS_ZENOH_PICO`, 237,792
bytes of rows; the loopback listener of the same run reserved 163,312) against what the open writes in each
row, read from the code. The arena of a host's session is the system's fresh pages (`HostPages`,
`Arena::over_zeroed`), so a row is resident only where something writes it; a row lent and not written
costs nothing until it is used.

| row (listener, at the limits) | bytes | written by the open | what A1 changes |
|---|---:|---|---|
| session tables | 56,272 | no: `SessionTables::lent` lends each table's columns over the span as it lies (`SlotMap::lent_from`, `BoundedVec::lent_over`) | nothing; a declaration writes its own row |
| peer tables | 10 x 5,152 | each set lent at the open writes its key-composing row as its rows are lent (`ComposeRow::lent`, which pushes one `KeyexprRow`, with `storage-profile`), so a page or two of each face's span is written for faces that may never come | the dial face's alone at the open; each other one when a face first takes its place |
| publisher, queryable, subscriber places | 24,000, 24,000, 11,200 | no: tables of byte cells over zeroed memory are lent as they lie (`Arena::lend_byte_cells`) | nothing; a declaration writes its place |
| reassembly buffers | 12,288 | no: byte cells, as above | nothing |
| face tables | 11 x 760 | every set written whole where it lies (`FaceTables::rowless_in`: the gets, the due row, the peer's tables by `init_in`), then its handles (`keep_rows_in`, `limit_to`) | the dial face's set alone at the open, 760 bytes; 7,600 bytes of the eleven not written until faces come |
| peer pools (declarations, aliases, interests) | 4,944, 1,040, 784 | each pool's state at its head (`RawSpace::lent_pool` writes `PoolState`) | nothing: the pools are the session's, lent at the open |

By the count, A1 leaves unwritten at the open the ten spare sets' 7,600 bytes of the face tables and,
with `storage-profile`, a page or two of each spare face's 5,152-byte span: of the order of ten pages,
40 KiB, of the listener's 112. That is an estimate from the code; R5's page map of the merged build reads
it. The rows the count leaves written (the engine, runtime and plane places, the link cells and rooms, the
pools' heads, the dial face's set) are the open's own and stay.

**Whether A2's `ROWS` default made a second copy of the plan's walk.** By the code it does not: an open
lays out `OpenPlan`, which is `ArenaPlan<0>` in a build with `runtime-plan` and the listed plan without it,
and no other path of the library reaches the generic walk (`count`, `lay_out`, `put`, `lay_out_open`,
`SessionArena::reserve`) with the other `ROWS`: `ArenaPlan::planned` of the listed plan is reached by
`ArenaRegion::of`, a constant evaluated when a build without `runtime-plan` is compiled, and the region
path of an open with `runtime-plan` takes a region's plan on (`take_on::<0, ARENA_ROWS>`) and walks none.
The +422 of `sessions` against int206, read by the size ledger on its case (`pico-client-coop-nostd`, a
client with no `runtime-plan`), is A2 and nothing else: `ArenaPlan<30>::blank` +234, a body int206 did not
keep, and `lend_session` +188; the renamed `put`, `put_table`, `settled` and `refuse` net to 0. A1 moved no
symbol of that build (its sets are a listener's), and no base difference shows: int206 is the base this
lane merged. In that build the open's plan is the listed one, which lists no rows there, so A2 gained it
nothing: `take_on` stored the region's plan field by field, the blank plan the open made stayed live and
its making was kept, where int206's `clone_from` stored the plan whole and the making was dropped.
`take_on` now builds the plan apart and stores it whole, so the open of that build is int206's again; the
ledger reads whether it is.

### 5.2 The acceptor's cookie MAC: a smaller one that keeps its guarantee (design; the owner's decision)

Nothing of this section is implemented: each candidate below but C1 changes what the handshake proves
or how, which is the owner's decision.

**What the MAC proves now.** Under `handshake-cookie = stateless` (the default, `deploy/wz-config.toml`)
the acceptor mints in its InitAck the state it negotiated from the InitSyn (`AcceptCookieState` of
`wz_session_core::accept_cookie`: the nonce, whatami, `sn_res`, batch size, zid and the extension
outcomes) followed by `HMAC-SHA256(key, payload)[..16]` (`COOKIE_TAG_BYTES`,
`signing_key::cookie_payload_tag`), the key 32 bytes or more drawn from the session's entropy
(`SigningKey::from_entropy`). At the OpenSyn it checks the tag in constant time over the whole payload
before it parses a field (`cookie_payload_tag_verify`, `verify_truncated_left`), then the carried nonce
against the one it drew at this handshake's InitAck and holds (`SessionActions::cookie_valid`,
`draw_cookie_nonce`), and spends that nonce on admission (`admit_open_syn`). The guarantee: an OpenSyn is
admitted only when it echoes a cookie this acceptor minted in this handshake, and the negotiated state the
session runs on is bytes this acceptor minted. A peer that sends a cookie it altered (a larger batch, an
extension it was refused) is refused.

**What links SHA-256 in the preset's library.** By the code: `sha2` is called in the pico C library's graph
from `wz_session_core::signing_key` (the HMAC, and `hmac_key_block`, which hashes a key longer than the
block) and from `credential_identity::zid_from_spki_der`, which only a TLS or QUIC link's credential
reaches (`peer_credential_zid`; no link of the preset has one); `wz_capi_pico::conformance` is built only
with `conformance-digest`, which the preset leaves out; the Open body's `initial_sn` takes no hash on a host
(`initial-sn-compact`, which `os-host` selects, so Keccak is not linked either); the usrpwd method's
HMAC-SHA3 is `wz-auth`'s, outside this graph. By the symbols: the preset's run (section 5.1, `nm -S` of
`lib-W`) names `signing_key::compute_hmac_sha256_full` 1,108 bytes, `sha2::sha256::compress256` 11,596 (the
unrolled software form) and `digest_blocks` 947 (the SHA-NI form `sha2` picks at run time), 13,651 in all.
No library of the current tree was at hand to read again (the builds run off this machine); R1's next
`nm -S -C lib-W/libwz_capi_pico.so | grep -E 'sha2|hmac|signing_key|credential_identity|keccak'` confirms
that the cookie is their one caller. So the 13.7 KB are the cookie's alone.

**What upstream and pico do.** zenoh 1.10.2 (the tree `upstream_root()` resolves on this machine, the
oracle store's clone of 1.10.2) encrypts its cookie and authenticates nothing:
`io/zenoh-transport/src/unicast/establishment/cookie.rs` @ `let encrypted = self.cipher.encrypt(buff, self.prng);`
is AES-128 applied block by block with random padding (`commons/zenoh-crypto/src/cipher.rs` @
`self.inner.encrypt_block(block);`), one key for the process (`io/zenoh-transport/src/manager.rs` @
`let cipher = BlockCipher::new(key);`), and the only check of what comes back is the nonce its accept task
holds (`io/zenoh-transport/src/unicast/establishment/accept.rs` @ `if input.cookie_nonce != cookie.nonce {`).
Blocks of one cookie can be replaced by blocks of another the same process minted, and a block altered
decrypts to bytes nobody checks, so upstream's binding is the 64-bit nonce and its state is confidential
but not authenticated. zenoh-pico sends an empty cookie and holds its state (section 5.1). wz's HMAC is
the strongest of the three, and none of the candidates below is weaker than upstream's.

**How strong a tag must be.** The key never leaves the acceptor, so a forger can test a guess only online:
one InitSyn, one InitAck and one OpenSyn per guess, against a nonce drawn for that handshake and spent when
it admits, each handshake held to `MAX_ACCEPT_PENDING` at once and to the accept's timeout. The tags it
sees are of cookies minted for its own handshakes, which a PRF tells it nothing about for any other
payload. For a keyed PRF with a t-bit tag a forgery then succeeds with probability 2^-t per handshake
(plus the PRF's distinguishing advantage): at a million handshakes a second, 2^64 guesses take about
585,000 years, so a 64-bit tag is far from the attack's reach and a 128-bit one leaves no margin to
argue about.

**C1, landed in this lane.** `wz-session-core`'s `sha256-compact` turns on `sha2`'s `force-soft-compact`
and `wz-capi-pico`'s `os-host` selects it, as it selects `initial-sn-compact`; `[profile.capi-small.package.sha2]`
and `[profile.capi-nostd.package.sha2]` build the crate at `opt-level = "s"` (`crates/Cargo.toml`), the
profiles the C libraries are built with, and every other profile keeps its level. The proof is unchanged: the
same HMAC-SHA256 truncated to 128 bits, the same key, the same checks, so the same cookie bytes; the RFC 4231
vectors of `signing_key`'s tests are what says so on a build with the feature (`cargo test -p
wz-session-core --features sha256-compact signing_key::`). The size ledger cannot read it: its case,
`pico-client-coop-nostd`, is a client: its session machine has no accepting role, so the open holds no cookie
key (`link_params` in `wz-capi-coop`'s `engine.rs`), the MAC is not linked, and 0 there is the expected
reading. What has the acceptor is a build with `peer` (`listen`):
the size gate's `pico-peer-coop` and `pico-peer` (`capi-nostd`, `os-host`), whose totals read it, and arm W
of the perf matrix, built as the preset on `pico-client-coop-nostd`'s profile. Expected there:
`sha2::sha256::compress256` (11,596, unrolled) and the SHA-NI `digest_blocks` (947) leave with the
run-time detection that picks between them, and one rolled compression of the order of 0.5 to 1 KB takes their
place beside the 256 bytes of round constants in `.rodata`: about 11 to 12 KB of text less, the HMAC's 1,108
unchanged. A mint and a check each run four or five compressions, rolled; the handshake's time is not the
matrix's. What stays for the owner is C2 to C4.

| | cookie | guarantee against C0 | forgery per online attempt | text (estimate; the size ledger measures) | changes |
|---|---|---|---|---:|---|
| C0, now | carried state + HMAC-SHA256 truncated to 128 bits | | 2^-128 | 13,651 | |
| C1 | the same, SHA-256 compiled small: `sha2`'s `force-soft-compact` (sha2 0.10.9 `src/sha256.rs` @ `if #[cfg(feature = "force-soft-compact")] {`, the rolled 64-round loop of `soft_compact.rs`), turned on by a feature of `wz-session-core` that `os-host` selects as it selects `initial-sn-compact`, and `opt-level = "s"` for the `sha2` package in the C library's profiles, as `wz-app-schema` has | identical, bit for bit (the RFC 4231 vectors of `signing_key`'s tests hold) | 2^-128 | about 2,000 (the HMAC and one rolled compression; the unrolled and SHA-NI forms leave) | none on the wire; the four or five compressions of a mint and of a check run rolled, microseconds a handshake; a graph that builds the analyzer's TLS key schedule beside `os-host` in one cargo invocation would share the slower form, so the feature stays off every other graph |
| C2 | carried state + SipHash-2-4 (Aumasson and Bernstein, 2012) under 128 bits of the key, spelled in `wz-session-core` as `initial_sn.rs` spells its sponge | the same binding and the same authentication, by a PRF with a 64-bit tag | 2^-64 | about 400 | the cookie 8 bytes shorter; the key read as 128 bits |
| C3 | carried state + KMAC128 (NIST SP 800-185) over Keccak-f[1600] | the same, 128-bit tag | 2^-128 | about 2,500 (the permutation, 2.2 KB, is not linked on a host now) | a second construction beside the MCU acceptor's `initial_sn` sponge, which would share it there |
| C4 | held state + a 128-bit random token: the acceptor keeps what it negotiated, as it already does under `fixed`, and the cookie is 16 bytes drawn from the session's entropy at the InitAck, compared in constant time with the held copy and spent on admission | the same binding (only the holder of this handshake's InitAck can echo it); the state is authenticated by never leaving the acceptor | 2^-128 | 0 of the 13,651 left in a build whose domain leaves `stateless` out | the acceptor holds the negotiated slots through the handshake, bounded by `MAX_ACCEPT_PENDING` as under `fixed`: the property `accept_cookie` bought (carried, not held) is given up, while the session object and the nonce are held across the handshake either way (`cookie_valid`); a third value of `handshake-cookie` or a new form of `stateless`, an opaque cookie that upstream's and pico's dialers echo as they echo any |

**Recommendation.** C1 first: it moves no guarantee and no byte of the wire, and the ledger reads what it
takes. The rest of the gap, C1's remainder, is then the owner's choice between C4 (no MAC; the acceptor
holds a few tens of bytes for each handshake in flight, as pico and `fixed` do, and keeps `stateless`'s
binding), C2 (the smallest MAC, a 64-bit tag) and C3 (a 128-bit tag at about C1's size). Each is a
change to the handshake's proof, so none is a build switch this lane flips.

### 5.3 R2 and R3 on the preset's build: what the read-only data and the relocated data are

Read from the run of 2026-11-26 16:15 (`perf-runs/host-20261126T071557`, a build of 031e54507, before this lane's
A1 and A3, arm W the preset's): `readelf -SW`, `readelf -lW` and `readelf -rW` of `lib-W` and `lib-P`, `nm -S -C`,
the words of `.data.rel.ro` read with `readelf -x` and each relocated word named by the section and symbol it
points at, the jump tables of `.rodata` found by the code that addresses them (`objdump -d`), and the
per-mapping figures of the same run's `perf.json` (`smaps_client`, `smaps_server`).

**What the run holds of them.** In every cell read (tcp round trip, multicast throughput, both roles), each
mapping of these segments is resident whole:

| segment | W bytes | W resident | P bytes | P resident | W - P resident |
|---|---:|---:|---:|---:|---:|
| `.rodata` (`r--p`) | 15,818 | 16 KiB of 16 | 5,584 | 8 KiB of 8 | +8 |
| RELRO (`r--p` after the loader's writes): `.data.rel.ro` 17,896, `.got` 632, `.dynamic` 496, init and fini arrays 16 | 19,040 | 20 KiB, all dirty | 1,680 (`.data.rel.ro` 64, `.got` 1,056) | 4 KiB | +16 |
| `.data` and the `.bss` on its pages (`rw-p`); P: `.got.plt` 8,880 and `.data` 472 | 6,024 + 7,440 | 8 KiB file, 8 KiB anonymous | 9,360 | 12 KiB | +4 |
| **together** | | **52 KiB** | | **24 KiB** | **+28 KiB a process** |

So R2 and R3 are +28 KiB a process, 56 of a cell's two, against the crate default's build's +58,692 and
+53,176 bytes (section 2): the preset took most of them. Two facts set how they can shrink:

- A segment this small is resident whole (fault-around maps every page of the mapping the page cache holds),
  so a table moved from RELRO into `.rodata` is counted in both as before; only bytes deleted count, and only
  where they cross a page. RELRO ends on a page (the linker places its start so: `0xce5a0 + 0x4a60 =
  0xd3000`), so it is `ceil(bytes / 4096)` pages: 19,040 B are 5, and 4 need 2,656 B fewer, 3 need 6,752 B
  fewer. `.rodata` starts on a page: 15,818 B are 4, with 566 B to the fourth page's end, and 3 need 3,530 B
  fewer.
- The relocations are not the cost: the 951 relative relocations of W take 304 bytes packed (`.relr.dyn`,
  `pack-relative-relocs`), against P's 1,107 `JUMP_SLOT` and 132 `GLOB_DAT` (pico calls its own exports
  through its PLT, R7). The cost is the pages they make dirty: 948 of W's lie in `.data.rel.ro`, spread over
  all five of its pages.

**R2, `.rodata`, +10,234 B, +2 pages.**

| what is large | W bytes | pico | structure that removes it | expected |
|---|---:|---|---|---:|
| R2.1 jump tables: 179 tables of the code's `match`es, 120 of 4 or 5 entries (2,064 B), 140 of fewer than 8 (2,608 B); no panic location and no format string is among them, nor anywhere in `.data.rel.ro` | 4,840 | 820 | a match of fewer than 8 arms lowered to compares, not to a table: `-C llvm-args=-min-jump-table-entries=8` beside `force-unwind-tables=no` (`crates/.cargo/capi-nostd.toml:28`), for the host library without `std` alone. A 4-arm table costs 16 bytes of `.rodata` and its dispatch (bound check, `lea`, `movslq`, `add`, `jmp`) about as much text as the compares that replace it; that is a count, and the size ledger and the instruction counts read it | -2.6 KB |
| R2.2 the accept's errno match, one of R2.1's tables though not one R2.1 takes: 110 entries, `EAGAIN` (11) to `EHOSTUNREACH` (113), for three outcomes (`crates/wz-runtime-posix/src/stream.rs:228-251`) | 440 | none (pico returns the error) | the errnos that mean "no connection now" as one constant set of bits tested by the errno, the exhaustion group as a second; the outcomes unchanged | -0.4 KB |
| R2.3 the well-known encodings' states (`wz_capi_pico::encoding::STATES`, `encoding.rs:722`), 53 of 32 bytes, each a constant's view's target | 1,696 | pico's 53 constants are 40 bytes each, self-contained, in its `.rodata` | each constant's state in its own view: a `z_loaned_encoding_t` is a handle and 32 bytes the C side never reads (`encoding.rs:388-391`), so the view of a constant can hold the state its handle points at, and `VIEWS` is the one table. The state must then have no padding (a view is copied as five pointers), and `is_constant` (`encoding.rs:316`) tests the views' range | -1.7 KB |
| R2.4 constants the compiler materialises and copies from: initial values and switch tables of `read_declare` 754, `open_request` 699, `z_open` 698, `LinkSession` 573, the router session task's poll 472, `Reserved::stage` 427, `read_response_final` 356, SCE's machines' data reached through slices about 890, and smaller | 5,853 | a C initialiser is stores in the code | none as a rule: each is the compiler's trade of text for data; a site where a value is built from a template it then overwrites is a text-lane item, read per site | 0 here |
| R2.5 names: the limits' ids and the held values' (about 1,700, read by the limits key, `config_limits.rs:4-18`), the encodings' (about 760; pico has the same) | 2,821, with the smaller strings | 947 | none: the key's vocabulary and the encodings' wire names | 0 |
| R2.6 the integer formatting's digit pairs (200), `core::unicode`'s white space map (256), the link names `TCP` and `UDP` (144) | 600 | libc's | with R1 (c), the formatting out of the no_std form | < 0.6 KB |

R2.1, R2.2 and R2.3 together, about 4.7 KB, take `.rodata` to 3 pages: -4 KiB a process.

**R3, the relocated data, +21,480 B, +5 pages (RELRO +4, `.data` and `.bss` +1).**

| what is large | W bytes | pico | structure that removes it | expected |
|---|---:|---|---|---:|
| R3.1 vtables: 718 pointers to code (5,744 B) and each vtable's size and alignment words. By trait: `BoxedLinkDriver` 112 slots, `ReplyView` 107, `SessionDatagramLink` 75, `QueryView` 49, `TxBuf` 49, SCE's `MainLoop` 43 and `Behaviour` 42, drop glue 31, `WireWrite` 28, `ReplyOut` 19, `GroupTransport` 17, `EventSink` 16, `SampleView` 14 | about 7,500 (and about 110 vtables' size and alignment words) | pico's function pointers (a link's `_z_link_t` operations, a callback's closure) are written into heap objects at run time, none in RELRO | (a) the links: the coop runtime's drivers (the TCP stream driver, the UDP drivers over a socket and over a port peer; `BoxedLinkDriver`, `crates/wz-session-core/src/link.rs:823`, `SessionDatagramLink`, `GroupTransport`, the listeners) are a set the build closes (`IpLinks`), so a call on one is a match over that set, not an indirect call through a table of every method of every driver: 213 slots. (b) The views (`ReplyView`, `QueryView`, `SampleView`, `ReplyOut`, the sinks) stay: they keep one body of each C door for every message type, which is text the size lane won. (c) SCE's machines' dispatch is SCE's (its runtime) | (a) about -1.8 KB; text measured |
| R3.2 the session limits' table (`SESSION_LIMITS`, `crates/wz-session-core/src/limits_generated.rs:3879`): 70 rows of 72 bytes (`LimitRow`, `limit_binding.rs:847-859`), each holding its id as a `&'static str`, so all 70 are relocated. It is read only by a config that states the limits key (`config_limits::state_over`), yet dirty in every process | 5,040 | none | the ids as offsets into one string of every id, which the generator emits beside the table (`wz_config.py --emit rust-limit-snapshots`), read through the snapshot type (an associated constant of the names), so a row holds no pointer and lies in `.rodata`; the row packed (the word as a `u16`, the capacity without its own tag), about 48 bytes | -5,040 RELRO, +3.4 KB `.rodata` |
| R3.3 the encodings: `ENCODING_ID_TO_STR` (`crates/wz-codecs/src/encoding_ids.rs:41`), 53 `&str` (848 B, 53 relocations), and `VIEWS` (2,120 B), whose 53 handles point into `STATES` | 2,968 | `ENCODING_VALUES_ID_TO_STR` 424 B in `.data`, 53 relocations (8-byte `char *`) | the names as one string and 54 `u16` ends, built when the library is compiled from the one table (no second transcription; `lookup_id` and the readers walk the ends); `VIEWS` stays relocated (the C side is handed an address), with R2.3's states inside it | -848 RELRO, +108 `.rodata` |
| R3.4 `.data`: the process pools' reservation (`process_pool.rs:1399`, 4,720 B) is there for three words, each stage's `None` (`0xff..ff`, a niche of `Pools`, `process_pool.rs:1037`); the scout window's table (`scout.rs:141`, 1,256 B) for five bytes | 5,976 | `.data` 472 | a stage slot whose empty value is zero (an enum with an explicit tag), and the table's initial counts at zero, so both lie in `.bss`: the file loses them and a page of them nobody writes is not resident. The first open lays every stage (`Reserved::stage`), so the reservation stays written; the window's table and its buffer (`.bss`, 2,048) are written only by a scout | 0 to -4 KiB, by where the linker lays them |
| R3.5 `.bss`: the thread records (5,120), the scout window's buffer (2,048), the critical section's words | 7,440 | 8 | A3 (landed after this run): the section's words beside the first record | the next run reads it |
| R3.6 the remaining slices: the held values' ids (8), the locator's config keys (8), the whatami names (8), SCE's tables' `&[u16]` (about 24) | about 770 | | with R3.2's form where a table is read only by name | small |
| R3.7 `.got`, `.dynamic` | 1,128 | 1,256 with `.got.plt` 8,880 | none: W calls its own code directly (R7) | 0 |

R3.2 alone takes RELRO to 4 pages but costs `.rodata` its fifth (566 B of room), so it pays only beside R2's
items. With R2.1, R2.2, R2.3, R3.1 (a), R3.2 and R3.3, `.rodata` is about 14.5 KB (4 pages, as now) and RELRO
about 11.4 KB (3 pages): -8 KiB a process. Without R3.2, `.rodata` is about 11.2 KB (3 pages) and RELRO about
16.4 KB, a few bytes past 4 pages, so R3.6 decides between -4 and -8. R3.4 and A3 may each take one page of
`.data` and `.bss` more. Of the +28 KiB, 12 to 20 stay: R2.4, R2.5, R3.1 (b) and (c), the written `.bss`.

**Order, and why nothing of it lands in this round.** Each item alone moves no page, so the perf matrix
cannot tell any of them from noise, and two of them move code by an amount only a build reads (R2.1's
compares, R3.1's matches). The order: R2.1 measured first (one line; the size ledger's text and `.rodata`, the
instruction counts), since its sign decides whether `.rodata` has room for R3.2; then R3.2 and R3.3 with
R2.3 (`.rodata` neutral, RELRO -1 page); then R3.1 (a) (RELRO -1 page). R2.2 and R3.4 are local and go with
whichever lands first. The cell that reads each is R0's per-mapping figures, the `r--p` and `rw-p` mappings of
`lib-W` above.

#### 5.3.1 R2.3: the padding of a constant's state, read before the state moves into its view

**What a view is read as.** `z_loaned_encoding_t` is `handle` and `_pad: [*mut c_void; 4]`
(`crates/wz-capi-pico/src/encoding.rs`). Rust reads the four words by value in one place,
`z_encoding_take_from_loaned`, which copies `(*src)._pad` into the destination; a C program copies a view
as bytes, which the language does not judge. Once a constant's state lies in those four words, a byte of
padding inside the state is read as part of a pointer, and an uninitialised byte read at a pointer's type
is undefined behaviour whatever the file holds there: to the compiler a static's padding is uninitialised,
however the linker fills it.

**The state as it was** (`EncodingState`, `repr(Rust)`; `Block` is a `NonNull<BlockHead>`, so
`Option<Block>` is one word whose `None` is null and holds no padding of its own):

| field | 64-bit | 32-bit |
|---|---:|---:|
| `packed_id: u32` | 4 | 4 |
| `schema_start: *const u8` | 8 | 4 |
| `schema_len: usize` | 8 | 4 |
| `_block: Option<Block>` | 8 | 4 |
| the fields together | 28 | 16 |
| the state's size | 32 | 16 |
| **padding** | **4** | **0** |

So on a 64-bit target the state carried four bytes of padding beside `packed_id`, and folding it into the
view as it was would have made `take_from_loaned`'s copy read them. On a 32-bit target it carried none.

**What the change makes of it.** The state is `repr(C)` with `_fill: [u8; size_of::<usize>() - 4]`, zero,
after `packed_id`: 32 bytes of fields in 32 on 64-bit, 16 in 16 on 32-bit, each the size it had, so a held
encoding's slot does not grow. Three assertions evaluated when the library is compiled hold it (beside
`STATE_FILL`): the state's size is the sum of its fields' sizes, and a constant's view (`ConstantView`,
`repr(C)`, the handle and then the state) has the size and the alignment of `z_loaned_encoding_t` (40 and 8
on 64-bit, 20 and 4 on 32-bit). The handle is first in both, so the loaned pointer handed to C is the
view's address and reads the same handle.

**The other reads of a constant's view.** `encoding_view` reads the handle alone (`handle_ref`).
`take_from_loaned` handed a constant would go on to write a null over a read-only static: a C program has
no right to take from a constant (zenoh-pico's constants are `const` objects too), so its first read is the
only one the padding concerned, and it now reads initialised words. The handle points at the state inside
its own view: the static's initialiser takes the address of a field of itself (`addr_of!(VIEWS[id].state)`),
which reads nothing of it. `is_constant` tests whether a state's address lies in `VIEWS`, the one table.

#### 5.3.2 The size ledger's reading of the rows, and the rows taken back

Read on the size ledger's case (`pico-client-coop-nostd`) at bb00b495c, every row committed, against the
same case at d1f048a89, before the first of them; both against origin/main 73eb00092, so the difference of
the two readings is the rows' (`nm -S -C` by owner and by symbol). Text, bytes:

| part | before the rows | with every row | the rows |
|---|---:|---:|---:|
| `sessions` | -649 | -175 | +474 |
| `doors` | -516 | -386 | +130 |
| `transport` | -82 | +51 | +133 |
| `driver` | -209 | -243 | -34 |
| `keyexpr` | -292 | -392 | -100 |
| `codec` | -259 | -272 | -13 |
| `language` | -1,579 | -1,544 | +35 |
| unclassified | 0 | +5 | +5 |
| **together** | **-3,586** | **-2,956** | **+630** |

By row, from the symbols each one changes:

| row | text on the ledger's case | what reads it | judged |
|---|---:|---|---|
| R2.1 | about +300, the rest: the compares of `judge_entry` +129, `UnicastLink::input` +78, SCE's `first_enabled_transition` of four machines +135, the control readers' `read_control_in_place` and `dispatch_copied` about +90, the coop engine's `drive_link`, `send_on_links` and `link_turn` +67, against `CanonWalk::next` -100 and `read_push` -251 | at most -2.6 KB of `.rodata`, which crosses a page only beside R2.2 and R2.3 and was not read | taken back |
| R3.3 | about +200 by owner (`encoding_ids` +150, `encoding_hint` +55), +264 by symbol (`ref_from_bytes` +126, `z_encoding_to_string` +138): the walk of the `u16` ends where a slice of `&str` was indexed | -848 RELRO, no page by itself | taken back |
| R3.2 | +113 by owner (`limit_binding` +79, `config_limits` +34), `position_named` out of line +87 | -5,040 RELRO, +3.4 KB `.rodata`; alone it trades a RELRO page for a `.rodata` one (section 5.3) | taken back |
| R3.4, the pools' stage | +28 by symbol (`lay_stage` +33, `give_back` -3, `Reserved::stage` -2): the tag the enum writes and reads where `Option`'s niche was the value itself | 4,720 B of `.data` to `.bss`, a page or none by the linker's layout, and the first open writes them anyway | taken back |
| R3.4, the scout table | 0: the case is a client that does not scout | -1,256 B of `.data` | kept |
| R2.3 | about 0 (`encoding` -34, the `_fill` word written by `store_encoding`, `HeldEncoding::write_at` and the two sample marshals +33) | -1,696 B of `.rodata` | kept |
| R2.2 | 0: the case does not accept | -440 B of `.rodata` in a build that listens | kept |

**The rule this applies.** A row that grows the ledger's text is taken back until R0's per-mapping figures read
a page it takes: the text is resident in every process and counted by the size gate, while a table moved out of
`.rodata` or RELRO counts only where it crosses a page (section 5.3), and none of these rows crosses one alone.
What stays, R2.2, R2.3 and the scout table, takes about 2.1 KB of `.rodata` (4 pages still: 3 need 3,530 B
fewer) and 1,256 B of `.data`; by section 5.3's arithmetic it moves no page of `.rodata` or RELRO, and the next
run of R0 reads the `rw-p` mapping. R2.1's flag returns only with a reading of the preset's `.rodata` on a page
boundary that the text it costs is weighed against; R3.2 and R3.3 return in a form whose readers are no larger
than the indexing of a slice of `&str` they replace, measured on the ledger before they land.

## 6. Measurement cells

- **R0, the absolute figure and its parts.** `PERF_SMAPS=1` in the matrix's environment makes
  each probe read `/proc/self/smaps_rollup` and every mapping of `/proc/self/smaps` once its
  role has run and before it closes its session (the arena and the pools still mapped), and
  print them before its last line (`perf_probe smaps rollup ...`, `perf_probe smaps region ...`).
  `perf_matrix.py` sums the resident KiB of both processes of a cell by component
  (`smaps_library_kib`, `smaps_libgcc_s_kib`, `smaps_heap_kib`, `smaps_anonymous_kib`, ...,
  `SMAPS_CLASSES`) into the cell's figures, so the summary and `report.txt` print each one with
  W over P, and keeps each side's mappings in `perf.json` (`smaps_client`, `smaps_server`).
  The anonymous mappings are listed one by one with their size, so the arena (its reserved
  size), a thread's stack (8 MiB and a guard page) and a malloc arena (64 MiB) are told apart.
- **R1, the libraries of the current tree.** Section 2's table again on the run's `lib-W` and
  `lib-P`, with `nm -S` by crate: first on the preset's build (section 2.2; `reference.json` says
  `wz_preset`), then after the text lanes land. The committed ceiling tables
  (`deploy/pico_perf_ceiling.json`, `deploy/pico_perf_ceiling_windows.json`) state the build their rows
  are filled from (`preset` `zenoh-pico`), every row null until a run of the preset fills it, and the gate
  refuses a run of the crate default's build, whose record names no preset, against them.
- **R2, R4 landed.** `readelf -d` of `perf_probe_W` lists no `libgcc_s`, and R0's
  `smaps_libgcc_s_kib` of arm W reads 0.
- **R3, the run's resident text.** Which pages of the library's text a run holds: with
  `PERF_SMAPS=1` the probe also prints, for each executable mapping of a file, the pages of it
  present in its page table (`/proc/self/pagemap`, `perf_probe smaps pages ... map=`), which the
  runner keeps on the region (`page_map`, `present_pages`). `perf_matrix.py resident-text
  <run>/perf.json <perf>/lib-W/libwz_capi_pico.so` names each present page by the text symbols on
  it (`nm -S -C` of the run's own copy, its pages placed by the library's executable segment):
  for each role of the arm, the resident bytes of each crate and of each plane a run never calls
  (section 2.1's groups), of the bytes it has (`lib-P` and arm `P` read zenoh-pico the same way).
  Resident bytes of a plane the run never calls are fault-around's, which is what (b) can take; the
  page map does not tell a page the run executed from one fault-around brought in beside it, so the
  bytes of the planes it does call bound the rest from above.
- **R5, the arena's written rows.** Which rows of the session arena a run writes (section 5.1, A1): the
  page map R3 reads of each executable mapping read of the arena's mapping too, against the row report of
  the same open, built as the preset is, at its limits (`WZ_LIMITS_ZENOH_PICO`), each present page named by
  the rows that lie on it. The report, one command from the one resolver:

  ```
  env $(python3 -I scripts/lib/wz_config.py --original-env zenoh-pico) \
    cargo test -p wz-capi-pico --lib --no-default-features \
    --features "$(python3 -I scripts/lib/wz_config.py --print-preset-features coop)" \
    the_arena_a_listening_session_opens_by_row_measured -- --ignored --nocapture
  ```

## 7. What this lane landed

- This design.
- R0's probe and runner (`PERF_SMAPS`; `perf_probe.c`, `perf_matrix.py` with its selftest), and
  R3's page map of each executable mapping.
- R3's naming of the present pages (`perf_matrix.py resident-text`, with its selftest).
- R1 (a0): the perf matrix builds both arms as zenoh-pico's preset (`wz_config.preset_named_features`,
  section 2.2), from the declaration the parity matrix and the instruction counts read.
- The preset axis of the gate (`preset` of a table, `record.preset` of a run, `wz_preset` of a build's
  record and of a Windows plan), and every bench of the pico library on the preset: the cargo words and
  `config.h` of the rtt, thr, nodrop, profile and tids modes (`bench_cargo_args`, `--bench-config-h`), the
  batch arm and its references (`batch_control.py`), the Windows plan (`windows_plan`).
- Section 5.1: the preset's run read part by part, its anonymous memory and stack counted, levers A1 to A3.
- R4: `_Unwind_Resume` defined in the library, `libgcc_s` no longer mapped by its programs,
  held by the size gate's `pico-client-coop-nostd` case (`forbid_undefined`).
- R5's report as one command (`wz_config.py --print-preset-features`, section 6).
- A2's first part: the open's plan lists no rows (`OpenPlan`). A3: the process's critical section beside
  the first thread record (`wz_host_sync::process_section`).
- Section 5.2: the cookie MAC's candidates, for the owner's decision.
- A1: the set of each face but the dial role's built when a face first takes its place, from a span the
  open reserves and writes nothing of (`SpareSets`, `Arena::split_off`, `DueIndex::rebuild`); section 5.1.1
  judges R5's rows, largest first, and answers whether A2 made a second copy of the walk.
- C1: SHA-256 compiled small in the C libraries (`sha256-compact` under `os-host`, `sha2` at `opt-level = "s"`
  in `capi-small` and `capi-nostd`), section 5.2.
- Section 5.3: R2 and R3 read part by part on the preset's run, and the bundle that crosses their pages.
- R2 and R3's rows that do not grow the size ledger's text (section 5.3.2): R2.2 (the accept's errnos as bit
  sets), R2.3 (each constant's state in its view, its padding read first, section 5.3.1) and R3.4's scout
  table (made in place per window). R2.1 (the jump table floor), R3.2 (a limit row's id as offsets), R3.3
  (the encoding names as one string) and R3.4's pool stage (a tag of zero) were committed and taken back:
  each grew the text with no page read. R3.1 (a) stays a design.
