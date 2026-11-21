# The AP superiority matrix

`scripts/host-bench/ap_matrix.py` holds the application-processor presets of wz against upstream
zenoh, in every aspect this page names, as a ratchet and a debt loop: decision D13 of
`docs/upstream-parity.md`. The committed table is `deploy/ap_superiority.json`. The mechanism is the
pico performance matrix's (D10, `docs/pico-perf-matrix.md` section 5): the reading of a figure, its
verdict and the ratchet are imported from `scripts/host-bench/perf_matrix.py`, not copied.

## 1. What is asked

The owner's direction of 2026-11-21: once the C ABI presets run on one cooperative engine with no heap
after open (`docs/c-abi-engine-and-memory.md` on its branch), the AP presets must also beat upstream
zenoh in every aspect: performance, size and memory, and completeness. "Every aspect" is a list of
cells, each a row a gate judges; a cell with no row, or a row no run has measured, makes no claim.

## 2. The pairs and the arms

Each pair is measured on one host in one run. Its two arms alternate by repetition (U W, W U, ...), so
a drift of the host falls on both alike.

| pair | arm W (wz) | arm U (upstream) | held constant |
|---|---|---|---|
| `router` | the wz router preset: `wz-ap-demo --config <document>`, built with `routing-router,zenoh-config` over its default features, with upstream's release profile | `zenohd -c <document>` at `UPSTREAM_VERSION` | the document (a router on the loopback, multicast scouting off, the router it dials); the programs around the router are upstream's examples built against upstream zenoh in both arms |
| `api` | upstream's example programs built against `wz-zenoh` (the family patched in, `wz-capi-core` with the `zenoh` preset's features) | the same sources built against upstream zenoh | one generated package (`z8_upstream_suite.py examples`): upstream's sources, manifest, `Cargo.lock` and release profile, one compiler; a cell through a router runs zenohd in both arms |

The programs are upstream's `z_put`, `z_sub`, `z_get`, `z_queryable`, `z_pub_thr`, `z_sub_thr`,
`z_ping` and `z_pong` of the pinned tree, the parity matrix's set (section 5b of
`docs/upstream-parity.md`).

## 3. The cells

A cell is `<pair>/<workload>/<topology>/<parameter>`; a row is a cell and one figure. Topologies:
`p2p` (two peers on the loopback), `r1` (two clients of one router), `r2` (a client of each of two
linked routers), `bin` (a file). `ap_matrix.py cells` lists them with their kind.

| workload | cells | parameter | figures (better) | method |
|---|---|---|---|---|
| `thr` | api p2p, api r1, router r1 | payload 8, 1024, 65536 B (the last fragmented) | `msgs_per_s` (higher), `cpu_ns_per_msg` (lower), `rss_kib` (lower) | `z_sub_thr` then `z_pub_thr`; after the warm-up, each report of the subscriber in the window (at least 5); the figure is their median. CPU over the window from `/proc/<pid>/stat`, per delivered message: the router's in the router pair, both programs' in the API pair. Peak RSS of the same processes (`getrusage`) |
| `lat` | api p2p, api r1, router r1 | payload 8, 1024 B | `rtt_p50_us`, `rtt_p99_us` (lower) | `z_pong` then `z_ping`: `--pings` round trips after its own warm-up; nearest-rank percentiles of what it printed |
| `fanout` | router r1, api r1 | subscribers 1, 16, 128 | as `thr`, 8 B | one `z_pub_thr`, N `z_sub_thr`; the figure is the sum of the subscribers' medians |
| `multihop` | router r2 | 8 B | `msgs_per_s`, `rtt_p50_us`, `rtt_p99_us` | the publisher (pinger) on the first router, the subscriber (ponger) on the second |
| `scaling` | router r1 | router cores 1, 2, 4, 8 | `msgs_per_s` | the router pinned to the first C CPUs of its side, C publishers and C subscribers; a host whose router side has fewer CPUs records the cell as skipped, no arm's loss |
| `flows` | router r1 | 1,000 keys, mixed rates | `msgs_per_s`, `rtt_p99_us` | no harness yet (section 8) |
| `query` | api p2p, api r1, router r1 | | `query_rtt_p50_us`, `query_rtt_p99_us` (lower), `queries_per_s` (higher) | no harness yet |
| `churn` | api r1, router r1 | | `tokens_per_s` (higher) | no harness yet |
| `open` | api p2p, api r1 | | `open_us` (lower) | 20 runs of `z_put` per repetition; each open timed from its line before `zenoh::open` to its line after it, as the lines arrive; the figure is their median |
| `idle` | router r1, api p2p | | `rss_kib` (lower) | the router alone, or one `z_sub` peer, left 5 s; `VmRSS` |
| `heap` | router r1, api p2p | 1024 B | `heap_peak_kib` (lower) | the `thr` cell again with `heap_peak.so` preloaded into the router (router pair) or both programs (API pair), in runs of their own |
| `size` | router bin, api bin | | `stripped_bytes` (lower) | `strip --strip-unneeded` of the router, and of `z_put` (the smallest client program) |
| `complete` | see section 6 | | `shortfall` (lower) | read from the tree, no run |

The defaults of a run: 5 repetitions (3 at the least), a 3 s warm-up, a 10 s window, 20,000 round trips,
the client side on CPUs 4-7, the server side on 8-11, the router side on 12-19; the run states them in
its record.

## 4. The verdict and the noise rule

- **A row of time, CPU or memory** reads D10's cost ratio: wz's median over upstream's when the figure is
  better lower, upstream's over wz's when better higher, so below 1 is wz ahead in every row. Its
  interval is the bootstrap 95% interval of the ratio of the medians of each arm's repetitions
  (`kit_compare.bootstrap_ratio`, seeded). D1: WIN when the whole interval is below 1, LOSS when above,
  TIE otherwise. Fewer than 3 measured repetitions of an arm give no interval (NOT-MEASURED).
- **A timed repetition is valid** only when the pinned CPUs were used by nothing else (`nodrop.py`'s
  rule, at most 10 percent foreign); it is run again up to six times, and a repetition disturbed in all
  six is run once more after the last repetition. A disturbed repetition is no repetition. Any other
  repetition wz lost fails its rows: what wz could not do once is a defect. A cell upstream lost in every
  repetition is a `reference_lost` row.
- **A size** is one figure per build: the ratio is exact, WIN when wz is smaller; the table's tolerance
  covers the spread between hosts.
- **A completeness row** reads a shortfall, a count of upstream's items wz does not meet, held toward 0.

## 5. The table and the ratchet

`deploy/ap_superiority.json`: `schema` `wz-ap-superiority/1`, `tolerance` 0.05, and `rows`, one per
row of the matrix, each `{"held": H, "debt": D}`:

| H | holds |
|---|---|
| `null` | not filled. NOT-MEASURED while no run measured it, never a pass; a failure that prints the row once a run does |
| `{"locked": true}` | only a WIN (a shortfall of 0) passes, with no tolerance |
| `{"ratio_at_most": R}` | the upper end of the interval may not exceed R times one plus the tolerance; a reading under it prints the tighter row, a WIN prints the lock |
| `{"shortfall_at_most": N}` | a completeness figure may not exceed N; a lower one prints the tighter row, 0 prints the lock |
| `{"reference_lost": WHY}` | upstream lost every repetition when the row was written; fails once it measures again |

D is the open-debt item of every row that is not locked (decision D5): `debt-<id>` of the store's
inventory, or `debt-TBD` until one is filed. A row that is filled and not locked fails while it keeps the
placeholder, as the pico host ceiling does (`capability_cost_gate.py`). A lock drops the placeholder.

Every cell starts null. The rows are exactly the population of the matrix, and a cell added to the matrix
without its row fails (`--check-table`, Layer C0, with the selftest). `--check-table` also holds each
filled completeness row to the figure the tree states at that commit, since those figures need no run.

| command | does |
|---|---|
| `ap_matrix.py --selftest` | every rule of the gate and every reader of the runner, on synthetic input |
| `ap_matrix.py --check-table [TABLE]` | the table's shape, its population, the debt rule, the filled completeness rows |
| `ap_matrix.py --gate READING [--table TABLE]` | a run judged: exit 0 every row held, 1 a row failed, 2 an input refused, 3 a row not measured |
| `ap_matrix.py --fill READING [--table TABLE] [--write]` | the rows the reading writes (fill, tighten, lock), written with `--write`; a row moves only toward WIN |
| `ap_matrix.py run --cells SEL --run DIR` | builds, measures, writes `DIR/reading.json` and judges it |

The gate prints, after the rows that did not simply pass: the rows to write, the debts (rows not WIN,
largest ratio first, with their debt ids), the completeness rows short of upstream, and the cells with
no harness. A full run exits 3 while any cell has no harness: such a cell is a debt, never a pass.

## 6. Completeness

| row | the figure | read from |
|---|---|---|
| `api/complete/z8-tests/0/shortfall` | files of upstream's `zenoh/tests` and of its ecosystem crate that neither pass against wz-zenoh nor run no test upstream either (`fail`, `no-compile`, `unmeasured`) | `docs/z8-expected.tsv`, the table `z8_expectation_gate.py` grades Z8's runs against |
| `api/complete/z8-examples/0/shortfall` | scenarios of upstream's example programs that do not show the same on wz-zenoh as on upstream | `docs/z8-examples-expected.tsv` |
| `router/complete/config-keys/0/shortfall` | keys of zenohd's configuration the wz reader does not honour | `UNHONOURED_UPSTREAM_CONFIG_KEYS` in `crates/wz-runtime-tokio/src/zenoh_config.rs`, read by `deepenable_audit.rust_const`; Layer Z's `upstream_carries_the_surface.py` holds that the list names keys zenohd carries |
| `router/complete/plugin-storage-manager/0/shortfall` | what zenohd's storage manager configuration does that the wz router does not | no harness yet |
| `router/complete/plugin-rest/0/shortfall` | the same for the REST plugin | no harness yet |

The test and scenario figures count against upstream passing its own suites on its own crates; Z8's
control arm (`Z8_STOCK`) is what shows a host where it does not.

## 7. Decisions and their reasons

- **Two pairs, not one stack.** A cell of the whole stack (wz clients through a wz router against
  upstream's clients through zenohd) cannot say which preset a difference belongs to. Each pair changes
  one side and holds the other at upstream's.
- **The router arm's features are stated in this module** (`ROUTER_FEATURES`). `deploy/wz-config.toml`
  declares three originals (`zenoh`, `zenoh-c`, `zenoh-pico`) and no zenohd original, so no defconfig
  derives the router preset the way `wz_config.py --original-features` derives the others. A generated
  zenohd preset is owed, and with it this constant goes (debt-TBD).
- **One profile rule for size.** zenohd is built by `scripts/build-zenohd.sh` in upstream's workspace with
  upstream's `[profile.release]` (fat LTO, one codegen unit, `panic = "abort"`); the wz router is built
  with the same values, read from the pinned tree's manifest and given as `CARGO_PROFILE_RELEASE_*`, into a
  target directory of its own. The API arms already share upstream's profile through the generated
  package. Both sizes are of stripped files. The two routers' compilers differ (zenohd is built with the
  toolchain its release pins), and the record says which.
- **The upstream tree is `upstream_root()`'s and no other.** `resolve_upstream` refuses a run when that
  resolver finds nothing, or a tree not at `UPSTREAM_VERSION`. zenohd is provisioned as Layer Z
  provisions it (`build-zenohd.sh`, keyed by version in the oracle store) with `ZENOHD_VERSION` set to
  `UPSTREAM_VERSION`, and refused unless `zenohd --version` names that version.
- **No `run-ci.sh` layer for the measuring run.** Every `run_layer` must be wired into a hosted
  workflow (`unwired_lane_lint.py`, and `runci_plan.py` refuses a lane no hosted step runs), and the
  figures of this matrix are a quiet host's, which a hosted runner is not (D10 item 7). The measuring run
  is therefore a command run through `bx` on a host chosen for it, as `scripts/pico-compare.sh perf` is;
  the selftest and the table run in Layer C0 on every hosted run.
- **Not in the pre-push round-fed list.** That list runs `scripts/lib/<name>` only, and its twin
  `perf_matrix.py` is held in Layer C0 alone; the same holds here.
- **Fan-out and scaling use processes.** Upstream's programs subscribe and publish on one key; N
  subscribers are N processes, and C publishers to C subscribers on one key load the router with C x C
  deliveries. The client sides must be at least as wide as the router side for the 8-core cell to read the
  router rather than the programs; the record states the pinning.

## 8. Debts with no harness

| cells | what is owed |
|---|---|
| `router/flows/r1/1000` | a load program written against the zenoh API and compiled against each crate, driving a thousand keys at mixed rates (it exposes the load balance of a thread-per-core router) |
| `*/query/*` | a looping getter written against the zenoh API: upstream's `z_get` makes one query and exits |
| `*/churn/*` | a program that declares and undeclares liveliness tokens in a loop |
| `router/complete/plugin-*` | a harness that starts the storage manager and REST plugin configurations zenohd accepts on the wz router and compares what each accepts and serves |

Each of these rows is NOT-MEASURED in every run and is listed by the gate as a debt.

## 9. Running it

On a quiet host chosen at that moment by `bx --explain-choice` (the owner's rule: no host is pinned to a
lane), both pairs in one run, the three sides pinned on whole cores the host has idle:

```sh
bx --host <chosen> -- python3 scripts/host-bench/ap_matrix.py run --cells all \
    --run target/ap-matrix/runs/<time> --reps 5 \
    --client-cpus <...> --server-cpus <...> --router-cpus <...>
```

One pair alone is `--cells 'router/*'` or `--cells 'api/*'`. A run builds both API arms, provisions
zenohd and builds the wz router before it measures; `--bin-dir <run>/bin` measures again with the
programs of an earlier run. The gate's output names the null rows filled from the reading; commit them
with `ap_matrix.py --fill <run>/reading.json --write` together with the run's record, and replace each
`debt-TBD` of a row that is not locked with the store's `debt-<id>`.
