# The pico ABI performance matrix: how to run it and how to read it

`scripts/pico-compare.sh perf` measures the pico C ABI on a host: round-trip latency, throughput,
CPU and peak memory, for each transport a pico program opens and with batching off and on, against
zenoh-pico built as the same build and, when the environment names one, against an external library of
the pico API. It writes one machine-readable file per run and judges it by the gate of section 5. This
page says what a run does, how to start one, how to read what it leaves and how the gate holds it. It
holds no figure: a figure enters the repository only from a run that was made, with the run's record
beside it.

## 1. What is measured

**One program, two or three libraries.** `scripts/host-bench/perf_probe.c` uses only the zenoh-pico C
API and is compiled from the same source for each arm:

| arm | library | headers | carries |
|---|---|---|---|
| P | zenoh-pico at the submodule's pin, built as the same build (below) | that build's own (`include` of the export with the `config.h` its CMake generated) | tcp, multicast |
| W | `wz-capi-pico`, release, default features | the zenoh-pico-sys headers of that build with the `config.h` of its feature list (`wz_config.py --pico-config-h`) | tcp, udp, multicast |
| W (program transport) | `wz-capi-pico`, release, default features and `app-transport` | the same, for that feature list | the program transport |
| X | an external library of the pico API, named by the environment (below); measured only when named | its own, with its own `config.h` | tcp, udp, multicast |

The program-transport cell is measured on its own build because a capability that is off adds
nothing to a build, so the default build is the one the other transports are measured on.

**The same build.** Arm P is the build `scripts/lib/capability_cost_gate.py` measures the size of:
every `Z_FEATURE_*` switch the declaration (`deploy/wz-config.toml`) answers is set from that answer
for `wz-capi-pico`'s default features (`wz_config.pico_reference`), the rest keep pico's defaults,
Release, shared. `perf_matrix.py reference` asks the gate's own builder for it, so the library timed
here and the library whose size the gate prints are one build, built under the gate's build rule
(`build_env`: no path of the host and the commit's time in its bytes) and found again by the same
key (pin, compiler, switches, and the rule's C flags and epoch). A switch pico built otherwise than asked is listed in the run's record.

**Arm X, an external library of the pico API.** A library this repository does not hold, such as a
deployment's own build of a library of the pico API, is measured by the same program when the
environment names it, in the way the application-plane oracle lane takes a deployment's party
(`docs/app-plane-oracle.md`): the repository holds the mechanism only, and the library, its name, its
paths and its figures stay outside it.

| variable | what it names |
|---|---|
| `WZ_PERF_EXTERNAL_LIB` | the shared library |
| `WZ_PERF_EXTERNAL_INCLUDE` | its include directory: `zenoh-pico.h` and its own `zenoh-pico/config.h` |
| `WZ_PERF_EXTERNAL_CC_ARGS` | optional words added to the probe's compile and link (a library it needs, a define) |
| `WZ_PERF_EXTERNAL_NAME` | optional; a label written in the run's local result file only |
| `WZ_PERF_EXTERNAL_TABLE` | the table of W over X the gate judges by, a file outside the repository (section 5) |

The probe is compiled against those headers and linked against the library where it lies, with its
directory as the run path. The run's record holds the label and the SHA-256 of the library and of its
`config.h`, so a result says which build it timed. With the two first variables unset, or a probe that
did not build against the library (`build-probe-X.log` says why), arm X is NOT-MEASURED with that
reason: the run measures P and W, and the gate prints that arm X was not measured. It never passes in
its place. A variable that names no file, or headers without their `config.h`, is refused before
anything is built. Arm X is asked for udp as wz is: a library that accepts streams only loses those
cells, and the gate records that (section 5).

**The transports**, each in peer mode, on the loopback interface:

| transport | server side | client side |
|---|---|---|
| tcp | listens on `tcp/127.0.0.1:<port>` | connects to it |
| udp | listens on `udp/127.0.0.1:<port>` | connects to it |
| multicast | joins `udp/224.0.0.224:<port>#iface=lo` | joins the same group |
| program | listens on a `tcp/` locator over the program's own transport | dials it over the same |

The program transport is the wz door through which a program gives a session its own network stack
(`wz_ext_transport_*`, declared in `crates/wz-capi-core/include/wz_ext.h`). In the probe it is an
AF_UNIX stream in the abstract namespace, one reading thread per link, and a send that never blocks
(it answers would-block and reports the link writable when the socket has room again). zenoh-pico has
no such door, so arm P's program cells are recorded as not applicable, with that reason, and arm X's
alike.

A pico peer listening on a `udp/` unicast locator binds the socket, but its accept task takes streams
only, so a peer dialling it never completes its handshake: the dialling session's open fails with
-120, the handshake's receive timeout. Arm P's udp cells are therefore recorded as not applicable,
with that reason, as its program cells are. The accept task of a listening pico peer:

`vendor/zenoh-pico/src/transport/unicast/accept.c` @ `_z_tcp_accept(`

**The workloads**, at each payload size (default 8, 64 and 1024 bytes, each below pico's default
unicast batch of 2048 bytes, so no message is fragmented):

`vendor/zenoh-pico/cmake/feature_config.cmake` @ `set(BATCH_UNICAST_SIZE 2048`


- **rtt.** `pong` answers every sample of `perf/ping` with the same payload on `perf/pong`. `ping`
  puts the payload with a sequence number in its first eight bytes and spins until the answer that
  carries the number arrives, as upstream's `z_ping` waits; a round trip not answered within the
  timeout (default 100 ms) is lost. 20,000 round trips are counted after a 3 s warm-up. A run that
  loses more than a tenth of them stops early and says so.
- **thr.** `pub` puts the payload as fast as the session takes it (congestion control block);
  `sub` counts the samples and payload bytes it is handed. From its first sample `sub` waits the
  warm-up, then reads its count and its CPU at the start and at the end of a 5 s window. `pub` puts
  for the warm-up, the window and 3 s more, and both print the monotonic times of their spans.

**Before the first counted put.** The client side (`ping`, `pub`) declares its publisher one second
after its open, as upstream's `z_pub_thr` does, then waits for a peer, and on tcp, udp and the
program transport until its publisher matches the server side's subscriber
(`z_publisher_get_matching_status`, `perf_probe -M`). The reason is the reference: a zenoh-pico
publisher sends a put only while its write filter knows of a subscriber, and returns success for a
put it did not send, so a loop that starts before the subscriber's declaration arrives counts puts
that went nowhere. The put path that skips the send:

`vendor/zenoh-pico/src/api/api.c` @ `!_z_write_filter_active(&pub->_filter)`

A group of the pico preset carries no declarations and sends every put, so on multicast the client
waits for the peer's JOIN only. Both arms run the same arguments.

**Batching.** With batching off every put leaves as the session sends it. With batching on, `pub`
puts in cycles of one millisecond: each cycle opens a batch window (`zp_batch_start`) and closes it
at its end (`zp_batch_stop`, which sends what the window holds), and a batch that fills inside a cycle
leaves when it fills. `pub` reports the windows it opened as `batch_cycles`. `ping` and `pong` open
and close one window around each put, the close flushing it. A round trip with batching on is
therefore the cost of the window on the path, not a delay waiting for a batch to fill.

The rule is the one both libraries' transmit paths state: a full batch is sent when the next message
does not fit, and a window's remainder when the window is flushed or closed. In zenoh-pico:

`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_transport_tx_batch_overflow(`

wz's batch window states the same (an overflow drains it, as an express put does). Upstream's
`z_pub_thr` holds one window for its whole loop instead. A run of an earlier version of this probe
that did the same left the reference's subscriber with nothing in its window while the publisher
went on putting, although by its code a full batch should have left; why is not known, and the
cycle does not explain it. The cycle is the shape `scripts/host-bench/paced_pub.c` (`-b`) measured
both libraries in, and it is the same for both arms. A held window remains a question for the
reference, to be answered by a run that holds one, not a figure of this matrix.

## 2. The figures

| figure | workload | what it is | better |
|---|---|---|---|
| `rtt_p50_us`, `rtt_p90_us`, `rtt_p99_us` | rtt | percentiles of the counted round trips, by nearest rank, microseconds | lower |
| `rtt_mean_us`, `rtt_min_us`, `rtt_max_us` | rtt | mean and extremes of the same | lower |
| `round_trips`, `lost` | rtt | round trips counted, and those not answered in the timeout | higher, lower |
| `ping_cpu_ns_per_rtt` | rtt | ping's process CPU from its first put to its last answer, per round trip (warm-up included in both) | lower |
| `pong_cpu_ns_per_rtt` | rtt | pong's process CPU from the first ping to the stop ping sends, per answer | lower |
| `msgs_per_s`, `bytes_per_s` | thr | samples and payload bytes delivered in the window, per second | higher |
| `offered_msgs_per_s`, `put_failed` | thr | the rate pub's puts returned, and the puts that failed | higher, lower |
| `cpu_ns_per_msg_pub` | thr | pub's process CPU over its loop, per put | lower |
| `cpu_ns_per_msg_sub` | thr | sub's process CPU over the window, per sample delivered | lower |
| `cpu_ns_per_msg` | thr | the two above, summed: the CPU a delivered message cost both sides | lower |
| `cpu_user_s_*`, `cpu_sys_s_*` | both | each process's whole user and system CPU (`getrusage` of the reaped child), client and server | lower |
| `rss_kib_client`, `rss_kib_server`, `rss_kib` | both | each process's peak resident set, and their sum | lower |

The process CPU of a figure per round trip or per message is read by the process itself
(`CLOCK_PROCESS_CPUTIME_ID`, all its threads) at the edges of its own span, so time a process spent
waiting before or after the workload is not in it. `ping`'s figure includes its own spin and is the
client's cost, not the library's alone; `pong`'s and the throughput figures are callback- and
loop-driven and carry no spin of the probe's.

## 3. Running it

On a build host, through `bx`, as the other modes of `pico-compare.sh` are run; pc2 is the host with
`perf` enabled, should a run want a profile next to it:

```sh
bx --host pc2 -- bash scripts/pico-compare.sh perf 3 8,64,1024
```

The two arguments are the repetitions (default 3) and the payload sizes (default `8,64,1024`). The
mode builds everything it runs: the reference (cached by the cost gate's key under the artifact root),
`wz-capi-pico` twice in release, and the probe three times into `target/pico-compare/perf/bin`. With
`PICO_CMP_NO_BUILD=1` it runs the programs already there.

| variable | default | what it sets |
|---|---|---|
| `PICO_CMP_PERF_TRANSPORTS` | `tcp,udp,multicast,program` | the transports |
| `PICO_CMP_PERF_BATCHING` | `off,on` | batching off, on, or both |
| `PICO_CMP_PERF_WORKLOADS` | `rtt,thr` | the workloads |
| `PICO_CMP_CLIENT_CPUS` | `4-7` | the CPUs ping and pub are pinned to |
| `PICO_CMP_SERVER_CPUS` | `8-11` | the CPUs pong and sub are pinned to |
| `PICO_CMP_PINGS` | `20000` | the round trips counted per rtt cell |
| `WZ_PERF_EXTERNAL_*` | unset | arm X and its table (section 1, section 5) |

The pinning defaults to the parity matrix's (`docs/upstream-parity.md` section 5b). On the host a
run is made on, name CPUs that are idle and that do not share a physical core across the two sides.

**Picking idle CPUs on a shared host such as pc2.** Other jobs run there, and a cell whose pinned CPUs
were busy is run again and finally lost ("the pinned CPUs were used by something else in 6 runs").
Ask the host which CPUs are idle now, right before the run, and pass what it suggests:

```sh
bx --host pc2 -- python3 scripts/host-bench/perf_matrix.py idle-cpus 10 4
```

It samples `/proc/stat` for 10 seconds, prints each CPU's busy share and its physical core
(`/sys/devices/system/cpu/cpu<N>/topology`), and ends with one line of the two variables: at least
four CPUs a side, whole cores only, the least busy cores first, so the two sides never share a core.
Copy that line in front of the run in the same `bx` call:

```sh
bx --host pc2 -- env PICO_CMP_CLIENT_CPUS=<...> PICO_CMP_SERVER_CPUS=<...> bash scripts/pico-compare.sh perf 3
```

What was idle for ten seconds may not stay idle for the run; the run's own check of every cell is
what decides, and `foreign_share` in each measured cell says what it saw. When many cells are still
lost that way, run at a quieter time, or narrow the run so it ends sooner. On a hybrid CPU the busy
share does not tell a performance core from an efficiency core; both arms run on the same CPUs, so
the comparison stays fair, but the absolute figures belong to the cores named in the record.

A full run is every transport, both batching settings, both workloads and three sizes, for both arms,
three times: 288 cells, of which the 72 of arm P on udp and the program transport are not applicable; arm X
adds as many again, its program cells not applicable. Narrow it with the variables above when a question
needs fewer; the gate then reports the rows the run did not measure (section 5). The selftest of the reader
and of the gate runs anywhere and builds nothing:

```sh
python3 scripts/host-bench/perf_matrix.py --selftest
```

## 4. Reading a run

A run is left in `target/pico-compare/perf-runs/host-<UTC time>/` under the artifact root:

- `perf.json`: the result, schema `wz-pico-perf/1`;
- `report.txt`: the summary as text, one block per transport, batching, workload and size;
- `cells.jsonl`: one line per cell, written as each ends, so a run that was stopped is still read;
- `r<rep>-<arm>-<transport>-<b|n>-<workload>-<size>.<role>.out`: what each program printed (`b` with
  batching, `n` without).

`perf.json` holds:

| key | what |
|---|---|
| `schema` | `wz-pico-perf/1` |
| `record` | the tree and whether it had changes, host, kernel, CPU model, thread count, compilers, pinning, sizes, repetitions, round trips, warm-up, window, timeout, the foreign-use limit, start and end time, `builds`: the reference's pin, toolchain, switches and any switch pico built otherwise, and the wz features of both wz builds, and `external`: arm X's `status` (`built` with its label, paths and digests, or `not-measured` with `why`) |
| `metrics` | each figure and which way it is better (`lower` or `higher`) |
| `cells` | every cell: `arm`, `transport`, `batching`, `workload`, `size`, `rep`, `status`, and `figures` and `foreign_share` when measured or `why` when not |
| `summary` | per transport, batching, workload and size: for each arm the measured and lost repetitions and the median of each figure, `w_over_p`, W's median over P's for each figure both arms have, and `w_over_x` alike when the run has arm X |

**Status.** `measured`: the cell gave its figures while its CPUs were free. `lost`: it did not, and
`why` says what its programs printed (a transport the arm could not open, no peer in ten seconds, a
throughput window that did not lie inside the publisher's loop, nothing delivered). A lost cell is not
retried: what an arm cannot do it cannot do again. `not-applicable`: the arm has no such transport.

**A throughput cell that delivered nothing** says which side stopped. The publisher reports when it was
first seen to match no subscriber (looked at every 100 ms) and the peers it listed at its end; the
subscriber reports when its count last grew (looked at every 10 ms) and its peers at its end. A
publisher that lost its match or its peer put into nothing, since a zenoh-pico put with no subscriber or
no peer returns success and sends nothing; its put count then runs far past what the link can carry. A
publisher that still matched at its end, beside a subscriber whose count stopped growing, points at the
receiving side. The send path that sends to the peer list only when it is not empty:

`vendor/zenoh-pico/src/transport/common/tx.c` @ `!_z_transport_peer_unicast_slist_is_empty(zn->_tp._transport._unicast._peers)`

A run on a build host lost every throughput cell of arm P on tcp with batching on, and some with it
off, with put counts no tcp loopback carries in the time, while arm P on multicast and arm W on tcp
delivered; the next run's `why` says which side stopped. Until it does, the cell stays a lost cell of
the reference, not a cell it does not have.

**Validity.** A cell counts only when the CPUs it was pinned to were used by nothing else while it
ran: their busy time (`/proc/stat`) less the CPU of the two processes, over the CPU seconds the cell
had, at most 10 percent (`nodrop.py`'s rule). A disturbed cell is run again, up to six times, and
`foreign_share` records what the accepted run had. A cell disturbed in all six is run once more after
the last repetition (`second_pass` in its record), because a shared host is busy in stretches: in the
run above, nearly every cell of the first repetition was disturbed, far past the limit, and those of
the second were not, which is the host's other runs coming and going, not the first repetition's start,
warm-up or ports. `bx` reserves cores for a run and admits others beside it, while the matrix pins eight
CPUs, so a run on a host other runs share meets them on its pinned CPUs; run it where nothing else is
admitted while it lasts.

**Ratios.** `w_over_p` divides medians. For a figure whose better direction is `lower`, a ratio below
1 is wz ahead; for `higher`, above 1. A ratio of medians is a reading of one run on one host; it is not a
verdict. The verdict is the gate's (section 5): the parity matrix's bootstrap interval
(`scripts/lib/kit_compare.py`) over the run's repetitions. Three repetitions are the least it reads, and
with three the interval is wide: a cell is WIN only when every repetition of wz beats every repetition of
the reference, near enough. More repetitions narrow it.

**What a run is not.** One host, the loopback interface, peer mode, one publisher and one
subscriber. The multicast group is on `lo`; a group on a real interface is not measured here. A
program-transport figure is wz with the probe's stream under it, so it holds the probe's own reading
thread and copies. `ping` copies its payload into a new buffer for each round trip, in both arms
alike. The peak RSS of a process covers its whole life, open and close included.

## 5. The gate

Every run of `scripts/pico-compare.sh perf` ends by judging itself:

```sh
python3 scripts/host-bench/perf_matrix.py --gate <run>/perf.json --table deploy/pico_perf_ceiling.json
```

and the mode exits with the gate's status. The rule is decision D10 of `docs/upstream-parity.md`: a
ratchet, a lock and a debt loop over every cell, of W over P always and of W over X when the run
measured arm X.

**What a row is.** A row is one figure of one cell: transport, batching, workload, size and figure, keyed
`<transport>/<off|on>/<workload>/<size>/<figure>` (`tcp/off/rtt/8/rtt_p50_us`). The figures held are
`rtt_p50_us`, `rtt_p99_us`, `pong_cpu_ns_per_rtt` and `rss_kib` of a round-trip cell, and
`msgs_per_s`, `cpu_ns_per_msg` and `rss_kib` of a throughput cell. `ping_cpu_ns_per_rtt` is not held,
since it holds the probe's own spin while it waits and is the round trip again; the two sides of
`cpu_ns_per_msg` are held as their sum.

**What a row reads.** The COST RATIO of the figure: wz's over the reference's for a figure better when
lower, the reference's over wz's for one better when higher (a rate), so that below 1 is wz ahead in
every row. It is the ratio of the medians of each arm's measured repetitions, with the bootstrap 95%
interval of `scripts/lib/kit_compare.py`, and its verdict is D1's: WIN when the whole interval is below 1,
LOSS when it is above, TIE otherwise. A repetition the host disturbed is no repetition. Any other lost
repetition of wz fails the cell's rows: what wz could not do once is a defect, not noise. Fewer than three
measured repetitions of either arm give no interval, and the row is not measured. A reference that lost
every repetition leaves the cell without a ratio.

**The table.** A JSON object: `schema` `wz-pico-perf-ceiling/1`, `pair` (`W/P` or `W/X`),
`tolerance`, and `rows`, one per row key, each of four shapes:

| row | holds |
|---|---|
| `{"locked": true}` | the cell is WIN, and only a WIN passes; no tolerance |
| `{"ratio_at_most": R}` | the ratchet: the upper end of the interval may not exceed R times one plus `tolerance` |
| `{"reference_lost": "<why>"}` | the reference lost every repetition when the row was written; passes while it still does |
| `null` | not filled: a failure, whose sentence prints the row this run writes |

A cell the run has and the table has no row for fails: the population cannot grow without a row. A key
written twice, a row of another shape or a tolerance outside `[0, 1)` is refused.

**What the gate prints.** Every row that did not simply pass, with its sentence; the rows to write, each
replacing the row of its key: a null or missing row filled from the reading (a WIN locked at once, any
other ratio a ratchet at the upper end of its interval rounded up to three decimals), the lock of a
ratcheted row that read a WIN, and the tighter value of a ratchet whose reading came in under it; and the
cells that are not WIN, the largest upper end first: the debts, in the order D10 pays them. A table moves
only by the rows the gate prints for a run, committed with the run's record.

**Exit status.**

| exit | meaning |
|---|---|
| 0 | every row of every pair asked was judged and held |
| 1 | a row failed: worse than its ratchet, a locked cell not WIN, a missing or null row, a repetition wz lost, a reference that measures a cell its row says it lost, or arm X measured with no table of it |
| 2 | an input was refused: the result or a table unreadable or malformed, or a table of W over X inside the repository |
| 3 | nothing failed, but something asked was not measured: a row the run did not measure (a narrowed run), too few repetitions, or arm X |

**W over P.** The table is committed: `deploy/pico_perf_ceiling.json`. Its rows are exactly the rows of
the default matrix (every transport arm P has, both batchings, both workloads, sizes 8, 64 and 1024), which
Layer C0 holds (`perf_matrix.py --check-table`) with the gate's selftest, on every hosted run. Its rows
are null until a run on a quiet host fills them, as above.

**W over X.** The table holds the external library's figures, so it lives outside the repository: the gate
reads it from `--external-table` or `WZ_PERF_EXTERNAL_TABLE`, and refuses one inside this checkout or the
main checkout of a worktree. A run that measured arm X is judged against it; with no table named, or the
file not there yet, the gate fails and prints the whole table the run writes, to be kept where the
variable points. A run that did not measure arm X prints `W/X: NOT-MEASURED` and why; it exits 3 unless
`--without-external` says the question is W over P alone. `pico-compare.sh perf` passes that flag when
`WZ_PERF_EXTERNAL_LIB` is unset, so the repository's runs, which have no external library, are judged on
W over P and still print that arm X was not measured; with the variable set, an arm X that did not build
exits 3.

**Filling the table.** On a quiet host, all transports, both batchings, both workloads, the default sizes,
at least three repetitions:

```sh
bx --host <quiet host> -- env PICO_CMP_CLIENT_CPUS=<...> PICO_CMP_SERVER_CPUS=<...> \
    bash scripts/pico-compare.sh perf 3
```

The gate fails on the null rows and prints them filled; paste them into `deploy/pico_perf_ceiling.json`,
run `python3 scripts/host-bench/perf_matrix.py --gate <run>/perf.json --table deploy/pico_perf_ceiling.json`
again over the same result to see it pass, and commit the table with the run's record. With
`WZ_PERF_EXTERNAL_LIB`, `WZ_PERF_EXTERNAL_INCLUDE` and `WZ_PERF_EXTERNAL_TABLE` set as well, the same run
prints the W over X table to keep outside the repository.

**Where it runs.** Each run of the matrix judges itself, and Layer C0 holds the gate's selftest and the
committed table's population on every hosted run. The matrix itself is not a layer of
`scripts/run-ci.sh`: every layer there is run by the hosted workflow (`scripts/lib/unwired_lane_lint.py`),
and a hosted runner can neither pin two sides of four CPUs that share no core nor keep them free of other
work, which section 4's validity check requires. The host that runs it is one nothing else is admitted to
while it lasts.
