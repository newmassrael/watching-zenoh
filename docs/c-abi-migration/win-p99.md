# Windows lane (win-p99): the round trip's tail against zenoh-pico's

Status: attribution measured on pc3-win (Windows 11 x64, Intel Core Ultra 7 155H, timer resolution 1 ms
set by another process, power plan Balanced), 2026-11-28. One change is on branch `win-p99-1128`
(the bench, section 2); the structural fix of section 4 is designed and was tried, and its first form
regressed, so it is not on the branch (section 4.3). Every figure below is a reading of this lane, and
says which.

## 1. What the ceilings say

`deploy/pico_perf_ceiling_windows.json` holds, for each row, `ratio_at_most`: the upper end of the
bootstrap 95% interval of W over P over the medians of three repetitions (`perf_matrix.py`,
`fill_row`: `ceil3(reading.hi)`), from run `windows-20261127T074002` of package 41988298bc. The
tcp p99 rows of 2.42 to 2.96 are those upper ends, not ratios: the point ratios of that run are

| row | P p99 (us, 3 reps) | W p99 (us, 3 reps) | W/P of the medians | ceiling |
|---|---|---|---:|---:|
| tcp/off/rtt/8 | 163.3, 172.1, 65.3 | 108.2, 127.0, 158.0 | 0.778 | 2.42 |
| tcp/off/rtt/64 | 62.0, 160.6, 158.1 | 77.4, 63.9, 159.9 | 0.490 | 2.58 |
| tcp/off/rtt/1024 | 96.5, 121.1, 175.9 | 76.5, 174.1, 154.7 | 1.277 | 1.805 |
| tcp/on/rtt/8 | 61.0, 149.3, 164.4 | 65.0, 158.2, 159.0 | 1.060 | 2.607 |
| tcp/on/rtt/64 | 91.0, 60.7, 167.7 | 159.5, 179.8, 141.3 | 1.753 | 2.963 |
| tcp/on/rtt/1024 | 168.4, 104.5, 147.6 | 161.9, 133.2, 74.2 | 0.902 | 1.55 |
| multicast/on/rtt/1024 | 325.3, 313.3, 319.8 | 337.9, 335.4, 467.5 | 1.057 | 1.493 |

Each arm's repetitions fall in two modes, about 60 to 110 us and 150 to 180 us, in both arms; with
three repetitions a side the interval spans both modes and its upper end is 1.5 to 3.0. The same
holds of the other rows named in the brief: `multicast/off/thr/1024/msgs_per_s` (point 1.078,
ceiling 1.455) and `tcp/*/rtt/*/pong_cpu_ns_per_rtt` (point 1.068 to 1.101, ceilings 1.14 to 1.24).

## 2. The modes are the host's, and the gate now refuses a busy host

**The run's host was busy.** The run's `cells.jsonl` records each cell's foreign share (the pinned
CPUs' busy time less the cell's two processes, `perf_matrix.ps1` `Invoke-Timed`): 0.2 to 1.1% for
the tcp round-trip cells, under a limit of 10% (`nodrop.FOREIGN_LIMIT`, which the Windows plan
took over). A cell above about 0.6% was in the slow mode in every case but two.

**A quiet host has one mode, and W's tail is P's.** The same package and the same runner
(`perf_matrix.ps1 -Mode run`, client on CPUs 2 to 5, server on 6 to 9), two runs on 2026-11-28:

| reading | P p99 (us) | W p99 (us) | foreign share |
|---|---|---|---|
| tcp rtt, 12 cells x 2 reps, package 41988298bc | 59.4 to 64.5 | 60.4 to 66.6 | 0.03 to 0.48% |
| tcp rtt, 6 cells x 2 reps, package 99c88e8372 | 60.5 to 97.1 | 61.1 to 73.7 | 0 to 0.55% |

Per-sample histograms (`perf_probe -H FILE`, below), tcp/off/rtt/8, three repetitions a side,
quiet host: p99 W 59.2, 60.2, 61.4 against P 60.2, 61.4, 60.3 us; p99.9 W 80.8 to 87.5 against P
97.4 to 111.7 us; W's longest 128 to 452 us, P's 199 to 289 us.

**The slow mode is reproduced by disturbance alone.** `hog.exe` (one thread on each of CPUs 2 to 9,
busy 20 us every 1 ms, at normal priority) gives tcp/off/rtt/8 p99 of W 127 to 134 and P 141 to
156 us, the run's slow mode, in both arms.

**The change** (commit 5216857c9a): `windows-plan` states a foreign-use limit of 0.2%
(`WINDOWS_FOREIGN_LIMIT`; Linux keeps nodrop's), so a cell read on a busier host is run again (up
to `max_runs`); the gate refuses a reading whose record states a looser limit than its platform's
(`limit_said`), so the ceilings of run `windows-20261127T074002` can be neither re-filled nor
judged from it; each cell records its interrupt and DPC share beside its foreign share
(`irq_share`), which the foreign share leaves out by construction; and `report.txt` says per row
and arm the largest share of each its repetitions had. The limit's derivation: of 96 cells of the two
quiet runs above, 94 shared 0.17% or less and two 0.48% and 0.55% (p99 65.5 and 69.3 us, the two
highest W readings of those runs); the busy run's cells shared 0.2 to 1.1%.

`perf_probe -H FILE` writes each counted round trip as `<start_ns> <rtt_ns>`, in the order made,
so a tail is read as a histogram and in time.

Not built or run here: `perf_matrix.py selftest` (the lane may not run the gate scripts; the
selftest has a new expectation for `limit_said`); the changed `perf_matrix.ps1` ran on pc3-win for
the runs of this section.

## 3. Rows that a quiet host does not move

- **multicast p50 and p99** (`multicast/*/rtt/*`): package 41988298bc had W +8 us at p50 (274.8
  against 266.6 us, quiet host, three repetitions of off/1024 and on/1024), carried into p99. At
  99c88e8372 (S1 and S2 of `win-perf.md` on main) the gap is gone: off/1024 p50 W 264.5 to 264.9
  against P 264.6 to 290.6; on/1024 W 266.9 to 268.5 against P 265.8 to 268.4; the runner's 24
  multicast cells of 2026-11-28 have W p50 263.7 to 267.8 against P 264.8 to 266.3 and p99 305 to
  333 against 309 to 328 us.
- **multicast thr 1024 B msgs_per_s**: about 5,100 to 5,500 messages a second in both arms with
  batching off; each put costs some 180 us of the publisher's CPU in both arms (`win-perf.md`
  section 1): the adapter's send, not either library. Not re-measured here beyond the full run of
  section 6.
- **pong CPU** (`tcp/*/rtt/*/pong_cpu_ns_per_rtt`): W 34.3 to 34.9 us a round trip against P 30.8 to
  33.4 us on a quiet host (three repetitions of tcp/off/rtt/8, package 99c88e8372): the +1.5 to +3.5 us of `win-perf.md` section 2 (S3, S5),
  not a tail.

## 4. The one tail that is W's: the session lock held across the socket send

### 4.1 What the trace shows

`xperf -on PROC_THREAD+LOADER+CSWITCH+DISPATCHER -stackwalk CSwitch+ReadyThread` over one
tcp/off/rtt/8 cell of package 99c88e8372 (the Windows Performance Toolkit already on pc3-win), each
wz frame resolved with the package's PDB:

- **ping's read task waits on the session's lock.** It wakes from `WSAPoll` with the answer, and in
  `read_quiet` (`crates/wz-capi-coop/src/engine/direct.rs` @ `let Some(held) = self.live() else {`,
  the pass that reads the clock and asks whether the session owes anything) takes the session's lock
  (`CoreLock::lock`, `RawLock::lock_contended`, `WaitOnAddress`). The thread that readies it is
  ping's main thread, the one that put the ping.
- **the main thread holds that lock inside `WSASend`.** Its stack where it is preempted is the
  loopback send in `afd.sys` and `tcpip.sys`: the put sends under the session's lock
  (`put_leg`, the planned plain put: `send_on_links(&core.0, ...)`), and on Windows' loopback the
  peer's answer arrives while that system call has not returned.
- **quiet host:** 280 such waits in about 58,000 round trips (0.5%), p50 41, p90 152, p99 460 us:
  the size of the p99-to-p99.9 band.
- **under disturbance** (`hog.exe` 2 ms every 40 ms): when the main thread is preempted inside
  `WSASend` (a quantum end, `WrQuantumEnd`, about 544 us), the read task waits for all of it: 29
  waits of 515 us, so W's p99.9 is 567 to 569 us in three of three repetitions against P's 258 to
  408 us, and W has 36 to 40 round trips over 0.5 ms against P's 5 to 17. zenoh-pico's read thread
  takes no lock its put holds (its put holds the transport's transmit mutex only).

This is the one mechanism found that makes W's tail longer than P's on the same host. It is also a
candidate for the run's W-only `rtt_max_us` of about 4.39 ms (13 of 18 W tcp repetitions, P at most
1.9 ms): a longer preemption of the sending thread under the run's foreign load would hold the read
for as long. That maximum was not reproduced on a quiet host or under the two disturbances tried.

### 4.2 The fix's design

A blocking put that holds its face alone is sent with that face's send place held and nothing of the
session, as a put by options already is (`publish_alone`) and as zenoh-pico's blocking put sends
under its transmit lock alone. The planned plain put, the steady state of `z_publisher_put`, does
not take that path: `put_leg` sends it under the session's lock. The change routes it there: the
plan's key is re-lent by the put's own text (`PlannedPut::key_on`), the session is let go of, and
the leg is sent by the face's send place (`send_leg_alone`).

### 4.3 Its first form regressed, and is kept aside

Commit 456b5798ac (branch `win-p99-1128-alone-wip`, not merged) is that change. Built into the
preset package on pc3-win it removed the read's lock waits (0 against 280 in the same trace) but,
quiet host, tcp/off/rtt/8, three repetitions against the base package in the same runs:

| package | p50 (us) | p99 (us) | p99.9 (us) | round trips over 0.5 ms |
|---|---|---|---|---|
| 99c88e8372 | 47.8 to 48.2 | 61.7 to 65.6 | 82.5 to 87.1 | 0 |
| 456b5798ac | 47.9 to 48.0 | 60.1 to 62.9 | 2,008 to 2,011 | 26 to 32 |

A CPU profile (`xperf -on PROFILE -stackwalk Profile`) shows both read tasks spinning in
`read_quiet`: `WSAPoll` (`direct.rs` @ `let ready = self.rooms.waits().wait_ready(waits, left_ms);`)
and `WindowsTcpSocket::try_read` answering `WSAEWOULDBLOCK` through `step_pump` (pong's read task
11,729 samples in `try_read` against 462 before), so the read task spends its quantum, is preempted
at its end by the spinning main thread on the same CPU, and waits a whole quantum (about 2 ms) ready
to run. The answers pong gave in the same window fell from about 81,000 to 51,000 to 60,000. Which
fact the read loop reads as input held, or as due at once, after a leg written outside the session is
what remains to find; the change lands only with it.

## 5. Recipe

On pc3-win, under `C:\wzperf\win-p99`: `build-pkg.sh <ref> <name> <bundle>` (Git Bash) builds
the preset package of a commit carried in a git bundle; `buildw.bat <package dir> <bin dir>` builds
perf_probe against it beside the P probe; `m.ps1 -Bin <bin dir> -Transport tcp -Size 8 -Reps 3
[-Hog <mask>,<busy_us>,<period_ms>]` runs ping and pong pinned as the runner pins them and keeps
each round trip (`-H`); `trace.ps1` and `ptrace.ps1` wrap one such cell in `xperf` (context
switches with stacks; CPU samples with stacks), and `analyze.py`, `prof2.py` read the dump.

## 6. Re-measuring every Windows row

A full run (`perf_matrix.ps1 -Mode run`, 3 repetitions, tcp, udp and multicast, both batchings,
both workloads, three sizes) of package 99c88e8372 under the 0.2% limit was started on pc3-win with
this lane's runner (`C:\wzperf\win-p99\work-base\runs`, log `C:\wzperf\win-p99\full.log`), on a
plan whose package fields and limit were set by hand. Its rows are not read here: the table is
re-filled from a run whose plan `windows-plan` of this tree writes, judged by
`python3 scripts/host-bench/perf_matrix.py --gate <run>/perf.json --without-external` on Linux.
