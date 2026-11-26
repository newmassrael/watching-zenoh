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
| R1 library text pages | +800,696 B mapped | (a) the text lane's areas (`text.md`), read here on the bench's features, where the gap is 3.84 and not 1.38: the engine (`wz_capi_coop::engine` 166 KB) and the session core (352 KB) carry the doors of every default capability; (b) code a run never calls kept off the pages it does: the doors of the capabilities a program may not use (advanced, liveliness, scouting, connectivity, the conformance digest, about 190 KB by name in section 2.1) laid out together, apart from the open, put and read, so their 64 KiB windows are never faulted (GNU ld already puts `.text.unlikely.*` first; a `#[cold]` door is placed there); (c) float formatting and the digest out of the no_std form | `text.md`; the door modules of `wz-capi-pico`; `wz-capi-pico-lib` link script | text, rss | (b) and (c): cell R3 first, since which windows a run faults is read, not counted |
| R2 `.rodata` | +58,692 B | no message text in the no_std form beyond what a door returns; constant tables (`sha2`'s round constants, float formatting's) leave with their code | | text | count, R1 |
| R3 RW, relocated | +53,176 B | fewer pointers the library holds to itself: each vtable, string slice and panic location in `.data.rel.ro` is a relocation the loader writes, so a page of them is dirty in every process (`c-abi-size-diet.md` T5) | | text | count |
| R4 `libgcc_s.so.1` | its mapped pages, W only | define `_Unwind_Resume` in the library as a local symbol that aborts, as `rust_eh_personality` is: the library is `panic = "abort"`, its personality aborts and its unwind tables are discarded, so no landing pad is ever entered and the name is never called; with it defined, the C compiler's as-needed link of `libgcc_s` drops the library, and the size gate refuses the name undefined | `wz-capi-pico/src/lib.rs` (`c_library_runtime!`), `scripts/lib/capability_cost_gate.py` | rss | **landed in this lane** |
| R5 session arena and pools | rows written by the open | `heap.md` H1 to H7 (counts from the open's config, smaller rows, one pool across faces, dedup, no round), with rss-zero's fresh pages so an empty row is never written | `heap.md` | heap | in the heap lanes |
| R6 face supervisor | +7,568 B | gone with the link tasks (`heap.md` 5.7) | | heap | in the heap lanes |
| R7 symbol tables | -104,128 B | none: wz exports only its doors | | | a win |
| R8 threads and malloc arenas | W holds one thread and no arena fewer | none | | | a win |

R1 is the gap: about 0.8 MB mapped against an estimated 0.6 to 0.76 MB measured. If fault-around
makes most of the text resident, R1 alone accounts for the figure, and the other rows move it by
tens of KiB each. That is why R1's split between (a), (b) and (c) waits for cell R3: the size of
a run's resident text is what the layout changes, and only the run's own page map says it.

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
  `lib-P`, with `nm -S` by crate, after the text lanes land.
- **R2, R4 landed.** `readelf -d` of `perf_probe_W` lists no `libgcc_s`, and R0's
  `smaps_libgcc_s_kib` of arm W reads 0.
- **R3, the run's resident text.** Which pages of the library's text a run holds: with
  `PERF_SMAPS=1` the probe also prints, for each executable mapping of a file, the pages of it
  present in its page table (`/proc/self/pagemap`, `perf_probe smaps pages ... map=`), which the
  runner keeps on the region (`page_map`, `present_pages`). Each present page named by the
  symbols it holds (`nm -S` of the run's `lib-W`) says how much of R1 is pages a run executes
  and how much fault-around brought in, and so how much (b) can take; that naming is the next step
  of this lane.

## 7. What this lane landed

- This design.
- R0's probe and runner (`PERF_SMAPS`; `perf_probe.c`, `perf_matrix.py` with its selftest), and
  R3's page map of each executable mapping.
- R4: `_Unwind_Resume` defined in the library, `libgcc_s` no longer mapped by its programs,
  held by the size gate's `pico-client-coop-nostd` case (`forbid_undefined`).
