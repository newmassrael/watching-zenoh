# The MCU speed matrix: how to run it and how to read it

Layer Qzk holds the kit images under zenoh-pico's on size, cell by cell: text, flash, static RAM, the stack
objects and the storage block, each a WIN or a failure (docs/upstream-parity.md D8). Nothing held their
speed. This page is the matrix that does: the same program on the same emulated MCU, once over zenoh-pico
and once over wz, measured per message and held row by row by the rules of the host matrix
(docs/pico-perf-matrix.md, decision D10 of docs/upstream-parity.md). It holds no figure: a figure enters the
repository only as a row the gate printed for a run, with the run beside it.

## 1. What is measured

**One program, two libraries.** deploy/zephyr-mcu-speed/src/main.c uses only the zenoh-pico C API and is
built in two arms:

| arm | library | how the image is built |
|---|---|---|
| P | zenoh-pico at the submodule's pin | the Zephyr module its tree is (vendor/zenoh-pico/zephyr) |
| W | wz's pico C ABI without std, on the cooperative engine over Zephyr's sockets | the staticlib of deploy/zephyr-capi-pico/rust without its board's MAC, the program compiled against zenoh-pico's own headers |

The feature switches of both arms come from one list in deploy/zephyr-mcu-speed/CMakeLists.txt: arm P
states them as the module's Kconfig symbols, written from the list into a fragment of its build, and arm W
as the header's switches. They are the planes of the pico C ABI image (deploy/zephyr-capi-pico) with
publication, subscription and matching on, so the program compiles to the same header in both arms.
Each arm is built in pico's two threading arms: `st`, where the program steps the
session (`zp_spin_once()`), and `mt`, where the session's read and lease tasks run beside it
(`Z_FEATURE_MULTI_THREAD`). Four images in all, on one board, one kernel configuration (prj.conf) and one
network stack.

**The board and the emulator.** The images are built for `mps2/an385` and run on QEMU's
mps2-an385 machine (Cortex-M3), the board the Zephyr lanes already boot with Zephyr's own Ethernet driver
and sockets (Layer Qza). QEMU runs with `-icount shift=0,align=off,sleep=on`:

- **Instructions are counted, not timed.** Under -icount the guest's clock advances 2^shift nanoseconds per
  instruction it executes, so the cycles the kernel's counter shows while a thread runs are a count of the
  instructions that thread ran. Zephyr's runtime statistics (`CONFIG_THREAD_RUNTIME_STATS`) add up
  the counter over every thread but the idle thread, so the busy cycles of a span are the instructions the
  guest ran in it, the network stack's threads and the library's tasks with the program's. That figure is
  the emulator's and does not move with the host's load: the same work gives the same count.
- **Why shift 0.** At one instruction a nanosecond the emulated core is faster than QEMU emulates it, so a
  busy guest's clock runs behind the host's and no lease the guest holds runs out early; and the busy
  nanoseconds are the instructions themselves.
- **Why the guest sleeps in real time.** The host peer answers in real time. With `sleep=off` an idle guest
  jumps to its next deadline at once, while a datagram from the host is still on its way: its receive
  timeouts and its leases would fire where a board's would not. With `sleep=on` an idle guest waits as long as
  the host takes.
- **Why not native_sim.** Zephyr's native simulator runs the image as a host process: its instructions are
  the host's, its cycle counter is the host's clock, and its network is the host's through a TAP device. It
  measures the host, not an MCU.
- **Why not the kit.** The kit lane's board is real silicon with a cycle counter, and a lab day measures it
  (`scripts/kit-lane.sh compare` already does for the GET turnaround). The matrix wants every push held, so it runs
  where a hosted runner can run it; the kit stays the witness of what the emulator cannot see (below).

So an instruction count is exact and repeatable, and a time is the guest's own work at one instruction a
nanosecond plus the real time the host side took: the same router, the same probe and the same emulated
network for both arms.

**The network.** Each cell boots an image under QEMU's user network (`-nic user,model=lan9118`). The image
is a client of a zenohd router on the host, reached at 10.0.2.2 over UDP; the host probe
(scripts/host-bench/perf_probe.c, built against zenoh-pico on the host) is a peer of the same router over
TCP. Both arms meet the same router and the same probe.

**The cell.** One arm, threading arm, workload and payload size in one repetition, and one boot. The cell is
the image's command line (QEMU's semihosting arguments, read by the image with `SEMIHOST_GET_CMDLINE`), so one
image runs every cell of its arm. The protocol is the host matrix's (perf/ping, perf/pong, perf/stop,
perf/thr, a sequence number in the first eight bytes):

- **put.** The probe subscribes. The image declares its publisher and waits until it matches the probe's
  subscriber (below), then puts 2,000 samples as fast as the session takes them, congestion control BLOCK. The busy
  instructions are counted over the loop and the 200 ms after it, in which the network stack sends what
  the loop left it.
- **sub.** The image subscribes; once it says READY the probe puts as fast as its session takes them, after
  its publisher matches. From the image's first sample it waits 500 ms, then counts over a 2,000 ms window.
- **rtt.** The probe answers perf/ping on perf/pong. The image times 500 round trips after 50, each waited
  for up to 200 ms; in the multi-threaded arm the program sleeps on a semaphore the answer gives, in the
  single-threaded arm it steps the session until the answer comes. A run that loses more than a tenth of
  its round trips is lost.

A publisher waits for its match before the first counted put because zenoh-pico's put returns success
and sends nothing while its write filter knows of no subscriber, so a loop started before the probe's
declaration arrived would count puts that went nowhere. The put path that skips the send:

`vendor/zenoh-pico/src/api/api.c` @ `!_z_write_filter_active(&pub->_filter)`

After its workload every image reports every thread's stack high-water mark (Zephyr paints the stacks,
`CONFIG_INIT_STACKS`) and the kernel heap's peak, which both libraries allocate from. Default sizes 8, 64 and
1,024 bytes.

## 2. The figures

| figure | workload | what it is | better | held |
|---|---|---|---|---|
| `instr_per_put` | put | busy instructions over the loop and its tail, per put that returned success | lower | yes |
| `put_msgs_per_s` | put | puts that returned success per second of the guest's clock over the loop | higher | yes |
| `delivered_share` | put | what the probe was handed, over the puts | higher | no |
| `put_failed` | put | puts that returned an error | lower | no |
| `instr_per_sample` | sub | busy instructions over the window, per sample delivered in it | lower | yes |
| `sub_msgs_per_s`, `sub_bytes_per_s` | sub | samples and payload bytes delivered per second of the window | higher | samples |
| `rtt_p50_us`, `rtt_p99_us` | rtt | percentiles of the counted round trips, by nearest rank, microseconds of the guest's clock | lower | yes |
| `rtt_p90_us`, `rtt_mean_us`, `rtt_min_us`, `rtt_max_us` | rtt | the same | lower | no |
| `instr_per_rtt` | rtt | busy instructions over the counted round trips, per round trip attempted | lower | yes |
| `stack_bytes` | every | the sum of every thread's stack high-water mark after the workload | lower | yes |
| `heap_peak_bytes` | every | the kernel heap's peak over the boot | lower | yes |

The stacks are summed because the two arms run different threads: pico's multi-threaded arm runs a read
task and a lease task beside the program, and wz's runs its read task, so one thread's mark compared with
another's says nothing; the network stack's threads are in both sums alike. The share the probe got of a
put loop is read and not held: a datagram QEMU's user network drops is the network's, and both arms send
into the same one. Read it beside `put_msgs_per_s` before calling a rate a gain.

## 3. Running it

On a machine with the Zephyr toolchain (the one the Qz lanes use), QEMU, cmake, a C compiler and a zenohd,
through `bx` so it is placed on one that has them:

```sh
bx --checks ci -- python3 scripts/lib/runci_plan.py --only Qzs
```

which runs the lane as a hosted job runs it (section 6), or the matrix itself with its own arguments:

```sh
bx -- bash scripts/mcu-speed.sh --board mps2/an385 --qemu-machine mps2-an385 --reps 3
```

| argument or variable | default | what it sets |
|---|---|---|
| `--board` | mps2/an385 | the board, one of `BOARDS` in scripts/host-bench/mcu_speed.py |
| `--qemu-machine` | the board's | refused unless it is the board's own machine |
| `--reps` | 3 | repetitions, the least the gate reads |
| `--sizes` | 8,64,1024 | payload sizes, 8 to 1,024 bytes |
| `--no-build` | builds | run the images and probe already under target/mcu-speed |
| after `--` | | more options of `mcu_speed.py run` (`--threads`, `--workloads`, `--puts`, `--window-ms`, `--round-trips`, ...) |
| `WZ_ZEPHYR_VENV`, `WZ_ZEPHYR_BASE` | under ~/zephyrproject | the Zephyr workspace |
| `WZ_ZENOHD_BIN` | the oracle under the artifact root | the router |
| `WZ_QZS_REPS` | 3 | the lane's repetitions |

The script builds everything it runs under target/mcu-speed of the artifact root: the host probe (zenoh-pico
from a copy of the submodule, so the submodule is only read), then the four images (`west build -p always`);
it runs the cells and ends with the gate, whose exit is its own. The selftest of the reader and the gate
runs anywhere and builds nothing:

```sh
python3 scripts/host-bench/mcu_speed.py --selftest
```

**How long.** Not measured yet; the first run says. By the parts: the host probe about a minute; each arm P
image a minute or two; the first arm W image the longest, its staticlib built with LTO for the core, and the
second a rebuild of the crate whose feature moved. A run of the default matrix is 2 arms x 2 threading arms
x 3 workloads x 3 sizes x 3 repetitions = 108 boots: a put or round-trip cell a few seconds, a throughput
cell longer, since its window is 2 s of the guest's clock and a guest kept busy by the probe runs slower
than that in real time. The hosted job that runs the lane allows two hours for it and Qza together.

## 4. Reading a run

A run is left in target/mcu-speed/runs/<UTC time>/ under the artifact root, and target/mcu-speed/last-run
names it:

- mcu-speed.json: the result, schema `wz-mcu-speed/1`;
- report.txt: each arm's medians per threading arm, workload and size, and W over P;
- cells.jsonl: one line per cell, written as each ends;
- r<rep>-<arm>-<threads>-<workload>-<size>.console and .probe: what the image and the probe printed;
- zenohd.log: the router's output.

mcu-speed.json holds `record` (the platform the gate checks: board, QEMU machine and core, the -icount shift;
the tree, QEMU's and zenohd's versions, the parameters), `metrics` (each figure and which way it is better),
`cells` (each with `status`, and `figures` or `why`) and `summary`.

**Status.** `measured`: the image printed its result and memory lines. `lost`: it did not, and `why` says what
it or the run saw (the image's FAIL line and its reason, no READY in 60 s, no DONE in 300 s, nothing
delivered). There is no disturbed cell as on the host: no other work shares the emulated core.

**The image's lines.** `MCU-SPEED BOOT` (arm, threading arm), `MCU-SPEED READY`, one `MCU-SPEED RESULT` line of
cycles (the counter's rate is on it), one `MCU-SPEED STACK` line per thread, `MCU-SPEED MEMORY`, then
`MCU-SPEED DONE`, or `MCU-SPEED FAIL why=<reason>`. Nothing is printed while a span is measured. The host turns
cycles into instructions and microseconds with the counter's rate and the -icount shift the run recorded.

## 5. The gate

```sh
python3 scripts/host-bench/mcu_speed.py --gate <run>/mcu-speed.json --table deploy/pico_perf_ceiling_mcu.json
```

Every rule is the host matrix's (docs/pico-perf-matrix.md section 5), from the same code
(`perf_matrix.py`'s reading, judge and printing):

- **A row** is one held figure of one cell, keyed `<machine>/<threads>/<workload>/<size>/<figure>`
  (`mps2-an385/st/rtt/64/instr_per_rtt`). It reads the COST RATIO, wz's over zenoh-pico's for a figure better
  lower and the reverse for one better higher, so below 1 is wz ahead in every row: the ratio of the medians
  with its bootstrap 95% interval over at least three repetitions of each arm, WIN when the whole interval
  is below 1, LOSS when above, TIE otherwise. An instruction count repeats, so its interval is narrow and
  its verdict clean; a time carries the host side's real time and its interval is as wide as that varied.
- **Any lost repetition of wz fails its rows.** A reference that lost every repetition leaves its rows with
  no ratio, and a row that says so passes while it still does.
- **The table**, deploy/pico_perf_ceiling_mcu.json: schema `wz-pico-perf-ceiling-mcu/1`, pair W/P, the
  `platform` its rows are read on, a tolerance, and one row per held figure of the default matrix, each
  `{"locked": true}`, `{"ratio_at_most": R}`, `{"reference_lost": "..."}` or null. A run on another platform is
  refused against it: an instruction count of one core or shift is not another's. Layer C0 holds the table's
  shape and population (`--check-table`) with the gate's selftest on every hosted run.
- **What it prints:** every row that did not simply pass, the rows to write (a null row filled from the
  reading, a WIN locked, a ratchet tightened), and the rows that are not WIN, largest upper end first: the
  debts, in the order D10 pays them.
- **Exit:** 0 every row held, 1 a row failed (worse than its ratchet, a lock not WIN, a null or missing
  row, a repetition wz lost), 2 an input refused, 3 nothing failed but a row was not measured.

**Filling the table.** The rows are null until a run fills them, and a null row fails, so the lane fails
until then. Run the matrix with the defaults, paste the rows the gate prints into the table, run the gate
again over the same result to see it pass, and commit the table with the run's record.

## 6. Where it runs

Layer Qzs of scripts/run-ci.sh, on the hosted `zephyr-admin` job after Qza, which provisions the Zephyr
toolchain, QEMU and zenohd; `WZ_QZ_REQUIRE` and `WZ_QA_REQUIRE` make a missing one a failure there. Unlike the
host matrix it can be a hosted lane: what it holds tightest are instruction counts and memory, which a
neighbour on the runner does not move. In the fleet, `runci_plan.py` asks QEMU, cmake and a C compiler of the
machine that takes the unit, and the Zephyr tools of bx.toml (their `needed_by` names the Qz lanes) place it
on a machine with the SDK and the workspace.

## 7. What a run is not

- **Not a cycle count.** QEMU models no pipeline, cache, wait state or bus: an instruction is one tick,
  whatever it is. A library that runs fewer instructions wins here; one that runs more but cheaper ones
  (fewer loads from flash, fewer cache misses) would win on silicon and not here. The kit is the witness of
  that, and the lab's compare runs read it.
- **Not the kit's core.** The board is a Cortex-M3 at the emulator's one instruction a nanosecond; the kit is
  a Cortex-M7 at 350 MHz with caches. A ratio is the comparable figure, an absolute is the emulator's.
- **Not a lossless network.** QEMU's user network and the router are the path, and a datagram dropped there
  is lost to both arms alike; the share the probe got says how much.
- **One client, one router, one probe,** UDP unicast, no batching window, payloads under the batch, so no
  fragment.
