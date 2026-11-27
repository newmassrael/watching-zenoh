# Migration lane base-rss: the resident set of a perf process against zenoh-pico, part by part

Status: design of the RSS lane (branch `base-rss`). Nothing here was built, run or measured by this
lane: every figure is read from the document it cites or derived from those readings, and says so.
A cell with no reading says **measure** and section 7 names the command that fills it. The earlier
design of this area is `docs/win-budget/rss.md` (cells R0 to R5, levers A1 to A3, rows R1 to R8);
this note pairs its readings with zenoh-pico's part by part, judges each difference as form or work
under the owner's ruling of 2026-11-27, and orders what is left by bytes.

## 1. What is measured, and the scenario

The figure this lane is judged by is the host performance matrix (`scripts/pico-compare.sh perf`,
`scripts/host-bench/perf_matrix.py`, the probe `scripts/host-bench/perf_probe.c`,
`docs/pico-perf-matrix.md`):

- **Arms.** W is `libwz_capi_pico` built as zenoh-pico's preset (`configs/zenoh-pico_defconfig`,
  resolved by `wz_config.preset_named_features`) on the cooperative engine without `std` (profile
  `capi-nostd`). P is zenoh-pico at the pin (1.10.2) built with the switches the same declaration
  answers and linked as the size gate links its reference (`rss.md` section 2.2).
- **Cells.** Each cell is two processes of the probe: `rtt` a ping and a pong, `thr` a publisher and
  a subscriber, each one peer session, over `tcp` or a UDP multicast group, with batching `off` or
  `on`, at 8, 64 or 1,024 bytes of payload: 24 cells. `deploy/pico_perf_ceiling.json` has an
  `rss_kib` row for each, every one null: no run of the preset has filled the table.
- **Figure.** A process's peak resident set, VmHWM of `/proc/self/status`, which the probe prints as
  its last line; a cell's `rss_kib` is its two processes' sum. VmHWM counts every present page, file
  pages included, and a read fault on a file mapping maps the 64 KiB window around it that the page
  cache holds (fault-around), so a library whose run executes code in every window of its text
  holds that text whole however few of its bytes run.
- **Parts.** With `PERF_SMAPS=1` each probe prints its mappings once its role has run and before it
  closes (cell R0), and the runner sums them by part (`SMAPS_CLASSES`: library, libc, loader,
  `libgcc_s`, other libraries, program, heap, stack, anonymous, kernel, other).

A second reading exists and is not this lane's figure: the parity matrix (`scripts/pico-compare.sh
parity pico`, `scripts/host-bench/parity.py`) runs zenoh-pico's example programs under a launcher
that reads each one's maxrss (`scripts/host-bench/fork_rss.c`). It read `rss_kib_pubsub` 5,774 KiB
against 4,888, 1.18, on 2026-11-25, before the limits fix (`std-heap.md` section 1).

## 2. The cells

R0's run of 2026-11-26 (3 repetitions, idle host, both arms the preset; `rss.md` section 5.1) read W
over P at 1.14 to 1.16 in every cell; the ledger's round that landed the RSS lane records 1.15 (1.31
on the crate default's build). No absolute figure of a cell is committed.

| transport | workload | batching | sizes | W over P | absolute KiB, W and P |
|---|---|---|---|---:|---|
| tcp | rtt | off, on | 8, 64, 1,024 | 1.14 to 1.16 | **measure** (M1) |
| tcp | thr | off, on | 8, 64, 1,024 | 1.14 to 1.16 | **measure** (M1) |
| multicast | rtt | off, on | 8, 64, 1,024 | 1.14 to 1.16 | **measure** (M1) |
| multicast | thr | off, on | 8, 64, 1,024 | 1.14 to 1.16 | **measure** (M1) |

R0 read the tcp round trip cell part by part; the other cells read the same within 4 KiB a part.
R0 predates what the RSS lane landed after it (A1, A3, C1, and the rows `rss.md` section 5.3.2 kept),
so the current tree's figures are M1's.

## 3. The parts, wz against zenoh-pico

KiB, a cell's two processes summed, R0 of 2026-11-26 unless the row says otherwise. Kind: **form** is
the same work held in another shape (where code lies, when a row is written); **work** is a behaviour
one side has and the other has not.

| part | wz | zenoh-pico | wz - pico | what each holds | kind | reading |
|---|---:|---:|---:|---|---|---|
| **library, every mapping** | 1,668 | 856 | +812 | | | R0 `smaps_library_kib` |
| text (`r-xp`) | 1,528 (191 of 191 pages a process) | **measure** | | W: code runs in every 64 KiB window of the text, so all of it is present (`resident-text`, `rss.md` 5.1); P: neither its text size on the preset nor what its run holds of it is read | form (where code lies, L1) and work (how much code, L2) | R0, R3; M2, M3 |
| headers, dynamic symbols and relocations (first `r--p`) | 52 (derived: the library less its other rows) | with P's text, 808 (derived) | | W exports its doors alone; P exports its internals (159,688 B of these tables against W's 55,560 on the crate default's build, `rss.md` section 2) | form; W ahead (R7) | M3 |
| `.rodata` | 32 (16 of 16 a process) | 16 (8 of 8) | +16 | 15,818 B against 5,584: jump tables, the encodings' states, constants the compiler copies from, names (`rss.md` 5.3, R2) | form | R0 |
| RELRO, dirty | 40 (20 a process) | 8 | +32 | 19,040 B against 1,680: 718 vtable slots, the session limits' 70 ids, the encodings' names (`rss.md` 5.3, R3) | form | R0 |
| `.data`, file pages | 16 | 24 | -8 | W 6,024 B (the process pools' reservation, the scout table); P `.got.plt` 8,880 and `.data` 472 | form | R0 |
| **anonymous** | 272 | 108 | +164 | | | R0 `smaps_anonymous_kib` |
| session arena | 160 (dialer 48 of 60 mapped, listener 112 of 160) | none | +160 | W: the rows the open writes in fresh pages (`ArenaPlan::of` at `WZ_LIMITS_ZENOH_PICO`, `heap.md` 5); P keeps its session on the brk heap | form; a row written only for a behaviour pico lacks is work (L3) | R0; R5 (M4) |
| library `.bss` past its last file page | 16 | 0 | +16 | 7,440 B: 64 thread records (5,120, `wz_host_sync` `ProcessWords`), the scout window's buffer 2,048, the callback table 144, the critical section's words | form | R0 |
| the second thread's stack | 24 (12 a process) | 24 | 0 | the read thread, the executor thread | | R0 |
| the second thread's malloc arena | 0 | 12 (4 and 8) | -12 | P's executor thread allocates a sample and a cache entry per message, so glibc gives it an arena of its own; W allocates nothing after the open | work, P's; W ahead | R0 |
| libc's and the loader's own | 72 | 72 | 0 | | | R0 |
| **brk heap** (`[heap]`) | 44 | 40 | +4 | W: the probe's stdio buffer (4,096 B, both arms), the process pools' slots taken by a high-water mark, libc's own; P: its session, a read and a write buffer of 2,048 B a transport, the peer, and each message's sample and cache entry, freed after it | form | R0; bytes and blocks M5 |
| **main thread's stack** (`[stack]`) | 76 (40 and 36) | 48 (24 and 24) | +28 | W: the open's deepest chain 20,048 B (`z_open` 2,400, `CoopEngine::assemble` 8,464, `lend_session` 6,272, `RegistryOf::new` 2,448, `PeerPools::lent` 400), a declaration 7,648, a put 3,496, the close 4,624 (`rss.md` 5.1), beside the probe's and libc's 24 KiB both arms share | form | R0 |
| **threads** | 2 a process | 2 a process | 0 | W: the caller and the read thread (`CoopEngine::start_read_task`, default attributes, 8 MiB reserved), which steps the session, its lease and keep-alive included; `zp_start_lease_task` is a no-op (`crates/wz-capi-pico/src/session.rs`). P: the caller and one background executor (`vendor/zenoh-pico/include/zenoh-pico/runtime/runtime.h` @ `return _z_background_executor_start(runtime, task_attr);`) that runs the read, lease, keep-alive and peer tasks as futures (`vendor/zenoh-pico/src/net/session.c` @ `tasks[_Z_TRANSPORT_TASK_LEASE] = _zp_unicast_lease_task_fn;`), started by an open with no options (`vendor/zenoh-pico/src/api/api.c` @ `options->auto_start_read_task = true;`) | equal | R0's anonymous mappings by size |
| **TLS** | 0 expected | 0 expected | 0 | W: no `thread_local!` in the preset's graph by the code (the sites are a host lock without the system's lock, the tokio engine, debug and test code); P: no `__thread` in zenoh-pico's sources. libc's static TLS and thread control block lie in each thread's stack mapping, counted in the stack rows | none | M3 |
| **libc** | 2,952 | 3,208 | -256 | the pages of libc each run calls; P calls more of it (`malloc` and `free` per message, its mutex: `std-heap.md` 1.1) | W ahead | R0 |
| **loader** | **measure** | **measure** | | W's symbol tables are smaller and its relative relocations packed (304 B of `.relr.dyn` against P's 1,107 `JUMP_SLOT` and 132 `GLOB_DAT`, `rss.md` 5.3) | expected W ahead | M1 |
| **`libgcc_s.so.1`** | 0 | 0 | 0 | R4: `_Unwind_Resume` is defined in the library, so its programs no longer map it | landed | M1, M3 |
| **the probe, the kernel's pages, other** | **measure** | **measure** | | the same source in both arms | | M1 |
| **the parts read, together** | 5,012 | 4,260 | +752 | | | |

**Check.** With P's pair at about 4,888 KiB (the parity run's figure, other programs: an estimate),
+752 is 1.15: the parts read explain the ratio, and the parts not read (loader, probe, kernel) are
equal within it. M1 reads both absolutes in one run.

**What the gap is.** The library's text and tables together are +772 (+812 less the data rows' +40),
more than the whole +752; anonymous memory is +164, the main stack +28, the brk heap +4, and libc
pays back 256. Of the library, R0 read W's text present whole while P's preset text is not read, so
the text row's wz - pico is at least 1,528 less twice P's text pages, which M3 reads.

**What R0 does not yet hold.** Landed after it, each by `rss.md`'s estimate: A1 about -40 (the
listener's spare face sets left unwritten), C1 about 11 KB less of the library's text
(SHA-256 rolled: -8 to -12 a process, -16 to -24 a cell, if its pages fall), A3 0 to -8, the rows of
5.3.2 0. M1 reads them.

**An earlier note corrected.** `rss.md` section 4 gives zenoh-pico a read task and a lease task, and its
row R8 gives W one thread fewer. zenoh-pico 1.10.2 runs both as futures of one executor thread
(the citations of the threads row), and an open with no options leaves the lease task flag off
(`vendor/zenoh-pico/src/api/api.c` @ `options->auto_start_lease_task = false;`): two threads in each
arm. W's margin there is P's second malloc arena (-12), not a thread.

## 4. Form and work under the owner's ruling (2026-11-27)

The ruling: a behaviour zenoh-pico does not have is a Kconfig switch, one per behaviour (a
`[[capability]]` of `deploy/wz-config.toml` with `upstream_off = ["zenoh-pico"]`, as `tx-probe` and
`tx-expiry-run` are), off in the zenoh-pico preset; a behaviour visible on the wire included, since the
preset's contract is zenoh-pico's on the wire too. Applied to what this run holds:

| what wz does in the run | zenoh-pico | kind | switch |
|---|---|---|---|
| seals the acceptor's InitAck cookie: the negotiated state carried in the cookie with HMAC-SHA-256 truncated to 128 bits, under a key drawn at the open (`handshake-cookie = stateless`) | sends an empty cookie and holds its state (`vendor/zenoh-pico/src/transport/unicast/transport.c` @ `_z_transport_message_t iam = _z_t_msg_make_init_ack(mode, *local_zid, cookie);`, the cookie `_z_slice_null()`) | work, on the wire | the policy's own Kconfig switch: `WZ_POLICY_HANDSHAKE_COOKIE` and its domain's `WZ_POLICY_HANDSHAKE_COOKIE_ALLOWS_STATELESS` and `WZ_POLICY_HANDSHAKE_COOKIE_ALLOWS_FIXED` (`deploy/Kconfig.policies`). `fixed` is pico's behaviour (the session's configured cookie, empty unless stated, the negotiated state held to the OpenSyn), but the declaration names no zenoh-pico value of a policy, so the preset keeps the default, `stateless`. L6 |
| the send that declines to wait, the run of expiries, the fragment credit, the held wait | none | work | already off in the preset (`configs/zenoh-pico_defconfig`) |
| reserves its tables at the open from the preset's limits and writes some rows there | allocates each thing when it first exists | form: no allocation after the open is wz's contract | none; L3 writes a row when it is first taken |
| the match memo (zenoh-pico's `RX_CACHE`, 0 in its default build) | matches every message | form: nothing on the wire, and it lowers the receive's instructions | none: off, the receive would cost more |
| the limits key (`ZEXT_CONFIG_LIMITS_KEY`) | grows its lists on the heap | form: a session that takes no memory after its open is told its counts before it | none |
| the process pools, the thread records | `malloc` per use | form | none |
| lease and keep-alive in the read thread's turn | futures of its executor | the same work | none |
| no allocation per message, no second malloc arena | `malloc` and `free` per message | work, P's | W ahead |
| the rest of the text the run executes | | **measure**: a plane whose code W's run executes and of which P's run executes nothing is a behaviour, judged in this table and given its switch | M6 |

## 5. The steps, largest first

Needed: -752 a cell at R0. Each step lands only when the RSS falls (M1), no size case grows (the size
ledger's `--explain` of `pico-client-coop-nostd`; the capability cost gate's `pico-peer-coop` and
`pico-peer` totals) and the receive's instructions do not grow (`ir-receive.md`, cell M7).

| step | part | kind | expected, a cell | the checks | state |
|---|---|---|---:|---|---|
| L1 the run's code in one place | text | form | from 1,528 to at most 2 x (ceil(E / 64 KiB) + 1) x 64 KiB, E the bytes a run executes | size: the same bytes, moved by alignment alone; receive: the same instructions; RSS: R0's library part and R3's present pages, none past the run's section | branch `rss-2` (`2fa657f50e`, `8d968c5da5`), not on origin/main: `run-text.ld`, `run --trace-text`, `run-text`; the list is empty until its cell R6 is read |
| L2 executed text cut | text | work and form | 4 KiB in each of the two processes for each page of executed code taken out; before L1, for each page of any code | the size lane's (`size.md`) | the size lane |
| L3 rows written when first taken | anonymous | form | the rest of +160 after A1's about -40, row by row | text of the first-use writes; no test per message on the receive | R5's report first (M4) |
| L4 the open's frames | main stack | form | up to -28 | text per frame, A2's rule (`rss.md` 5.1) | design |
| L5 `rss.md` R2 and R3 | `.rodata`, RELRO | form | up to -16 | `rss.md` 5.3.2's rule: no row that grows the size ledger's text | designed there |
| L6 zenoh-pico's cookie in its preset | text | work | less than one page of the library's text in each process (both map it), up to -8: `compute_hmac_sha256_full` 1,108 B, the rolled compression (about 0.5 to 1 KB) and its 256 B of round constants out, the held state's code in | `pico-peer-coop` and `pico-peer` read the net; `pico-client-coop-nostd` has no acceptor; the receive is untouched | design |
| L7 `.bss` past the file | anonymous | form | 0 to -8 | | A3 landed; R0 reads it |

**L1 decides the lane.** Laid together, E executed bytes span at most ceil(E / 64 KiB) + 1 windows, and
no window of the rest of the text is faulted. L1 alone covers the 752 when a process's text falls to
at most (1,528 - 752) / 2 = 388 KiB, six windows: when a run executes at most 320 KiB of W's 764 KiB
of text. After L1 a byte of code no run executes costs no resident page, so L2's resident gain is
the executed code it takes, and the order of L1 and L2 changes only which of them a reading credits.
The same layout of zenoh-pico is not built: P is the reference as zenoh-pico builds itself.

**L6, the one work row.** The behaviour has its Kconfig switch already: the policy and the bools of
its domain. One switch per behaviour, so no capability is added beside it; what is missing is
zenoh-pico's value of the policy in the declaration, which a limit has (`[limit.pico_preset]`, emitted
under `WZ_LIMITS_ZENOH_PICO`) and a policy has not. The design: a policy states the value of
zenoh-pico's preset the same way, `handshake-cookie` states `fixed`, and the generator writes it into
`configs/zenoh-pico_defconfig` with the policy's domain narrowed to it. A build with no door that
selects a policy then holds `fixed` as a constant (a domain of one value is held in no byte), so the
stateless branch and what only it calls (the MAC, its key) are dead and expected not to be linked;
M3's `nm` reads it. The preset's acceptor sends the empty cookie and holds the negotiated state, as
zenoh-pico does; a build that states `stateless`, or has `policy-selection`, is as now. `rss.md`
section 5.2 left the change of the handshake's proof to the owner, and the ruling settles it for the
preset. Its files: `deploy/wz-config.toml` (the policy's zenoh-pico value), `scripts/lib/wz_config.py`
(the defconfig and its self-test), `configs/zenoh-pico_defconfig` (regenerated), and a test of the
pico ABI that a build at the preset's value opens an acceptor whose InitAck cookie is empty, admits an
OpenSyn that echoes it, and refuses one whose cookie differs.

## 6. The first step

No step is certain without a reading, so none is implemented here:

- L1's gain is set by E, which no reading has given, and its tools are `rss-2`'s: landing them moves
  nothing until the list is made from a trace (`rss-2`'s cell R6).
- L6's bytes are the MAC's less the held state's code, both read only on a build, and its
  generator change is checked by the declaration's own self-tests and `--check`, which this lane
  cannot run.
- L3, L4, L5 and L7 each wait on a page reading (R5, R0).

The first step is the readings: M1 to M5 on the current tree, then M6 once `rss-2` lands.

## 7. The readings the main session runs

- **M1, every part of every cell.** `PERF_SMAPS=1 bash scripts/pico-compare.sh perf`. The summary and
  `report.txt` print each cell's `smaps_<part>_kib` with W over P; `perf.json` keeps each side's
  mappings (`smaps_client`, `smaps_server`), the anonymous ones with their size (the arena, 8 MiB
  stacks, 64 MiB malloc arenas). Fills section 2's absolutes and section 3's loader, probe and
  kernel rows.
- **M2, the text each arm holds, by symbol.**

  ```
  python3 -I scripts/host-bench/perf_matrix.py resident-text <run>/perf.json <perf>/lib-W/libwz_capi_pico.so
  python3 -I scripts/host-bench/perf_matrix.py resident-text <run>/perf.json <perf>/lib-P/libzenohpico.so P
  ```

- **M3, the segments.** `readelf -lW` of `<perf>/lib-W/libwz_capi_pico.so` and
  `<perf>/lib-P/libzenohpico.so` (each loaded segment's size, and a `TLS` segment or none),
  `readelf -d <perf>/bin/perf_probe_W` (no `libgcc_s`), and `nm -S -C` of each by crate as `rss.md`
  section 2.1 reads them.
- **M4, the arena's rows** (`rss.md` cell R5, the preset's plan at its limits):

  ```
  env $(python3 -I scripts/lib/wz_config.py --original-env zenoh-pico) \
    cargo test -p wz-capi-pico --lib --no-default-features \
    --features "$(python3 -I scripts/lib/wz_config.py --print-preset-features coop)" \
    the_arena_a_listening_session_opens_by_row_measured -- --ignored --nocapture
  ```

- **M5, heap bytes and blocks.** `bash scripts/pico-compare.sh parity pico`: `heap_peak.so` writes
  each program's peak bytes and the count of blocks it obtained; the run's `heap_peak_pubsub` is the
  pair's peak. Neither counts the allocator's own overhead, which M1's `[heap]` and malloc arena
  mappings show.
- **M6, the executed text (after `rss-2` lands).** Its cell R6: `perf_matrix.py run --trace-text`,
  `run-text` of `lib-P` (E of P, nothing written) and of `lib-W` (E of W, the list written), then M1
  and M2 again on the library linked by the list.
