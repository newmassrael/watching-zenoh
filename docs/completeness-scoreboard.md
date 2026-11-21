# The completeness scoreboard

The owner's decision of 2026-11-21: wz's architecture is to be more complete than zenoh-pico's,
and than a deployment's own pico-compatible build, judged by four criteria and held by a gate in
ratchet form. A figure may not get worse, each shortfall is a registered debt, and a criterion
that is met is locked.

The gate is `scripts/lib/completeness_gate.py`, run by Layer C0 (`--selftest`, then
`--check`). Its table is `deploy/completeness_ratchet.json`. `docs/upstream-parity.md` D9
records the decision.

    python3 scripts/lib/completeness_gate.py --report     # the board, one screen
    python3 scripts/lib/completeness_gate.py --check      # the figures against the table
    python3 scripts/lib/completeness_gate.py --selftest   # the gate against its fixtures

## The four criteria

| | Criterion | Figures | Read from |
|---|---|---|---|
| (a) | Upstream's own tests, run against wz, pass at least as many programs as against the original library | `a.pico-api.shortfall`, `a.pico-api.wz-passes`, `a.zenoh-c.shortfall`, `a.zenoh-c.wz-passes` | the test files the lanes run (`pico_upstream_api_tests_on_wz` and `pico_local_delivery_upstream_tests_on_wz` in Layer Z, `zenoh_c_upstream_api_tests_on_wz` in Layer C1cc) and the lanes' count guards in `scripts/run-ci.sh` |
| (b) | A deployment's feature catalogue is accepted whole, each feature as a switch that is off by default | accepted / listed, local only | the catalogue document `WZ_FEATURE_CATALOGUE` names, and `deploy/wz-config.toml` |
| (c) | Upstream debt is zero | `c.partial-atoms`, `c.logic-census-unplaced` | `depth_axis_census.partial_atoms()` (the inventory's PARTIAL atoms) and `logic_census_coverage_gate.coverage()` |
| (d) | The structural contracts are enforced | `d.contracts-unenforced` | the gates each contract names, and whether a lane of `scripts/run-ci.sh` runs each |

### (a) Upstream tests on wz

Nothing is run. Each test file declares the upstream programs it runs on wz (the entries of its
`upstream_tests!` invocation, or a test calling `run_upstream_test("<program>")`), and the
programs wz cannot link (`pinned("<program>", ..., Control::...)`) with what the control does
with each: `RunsBesideAZenohd` (the original library passes it) or `CannotLink` (neither
does). The lane's whole-file count guard (`wz_test_args wz-integration-tests <file>` and the
`_runci_guarded_test` after it) must equal the number of declarations, or the reading is
refused: the guard is what makes the lane red when one of those programs stops passing.

- **wz passes**: the programs the files run on wz. A record that may not fall.
- **original passes**: those, and every pinned program the control runs.
- **shortfall**: original passes minus wz passes. The criterion is met at 0.

Where the tree holds upstream's programs (`vendor/zenoh-pico/tests/z_api_*_test.c`), the files'
declarations must cover them exactly: a program upstream adds at a pin bump has to be classified
before the board reads again. zenoh-c's programs come from the oracle checkout, which Layer C0
does not have; its file's module comment names the programs left out and why.

### (b) A deployment's feature catalogue

A generic mechanism: the catalogue, its contents and its results stay outside this repository.
`WZ_FEATURE_CATALOGUE` names a JSON document:

    {
      "features": [
        {"feature": "<the deployment's name for it>", "switch": "capability:<id>"},
        {"feature": "...", "switch": "policy:<id>"},
        {"feature": "...", "switch": "policy:<id>=<value>"},
        {"feature": "...", "switch": "limit:<ID>"},
        {"feature": "...", "switch": null}
      ],
      "ratchet": {"accepted": 3, "read": "2026-11-21"}
    }

A feature is accepted when its switch exists in `deploy/wz-config.toml` and a build that names
nothing leaves it off:

- a capability that is off by default for every ABI that exports it (`default = "off"`);
- a bool policy (its default is off, upstream's behaviour; the feature is `on`), or a choice
  policy with a named value that exists and is not the default;
- a limit whose default is 0, the value that bounds nothing.

A feature with no switch, or a switch that does not exist or is on by default, is a shortfall,
listed by `--report` with the reason. The document's own `ratchet` is the floor of its
accepted count: fewer fails `--check`, more prints the value to write into the document. With
the variable unset the criterion is NOT-MEASURED, which is how hosted CI reads it.

### (c) Upstream debt

`c.partial-atoms` counts the inventory atoms graded PARTIAL (preset and debt entries excluded),
exactly the set `depth_axis_census.py` reads. `c.logic-census-unplaced` counts the findings
of the logic census's coverage gate: a crate or a file under `crates/` that no slice of
`docs/zenoh-logic-as-sce-kinds/` places and no exclusion names. That gate already fails on any
such finding, so the figure is locked at 0.

### (d) Structural contracts

| Contract | What holds | Gates (the text a lane runs it by) |
|---|---|---|
| `layer-direction` | the session core names no crate above it, and the pico ABI's core none of its extension doors | `scripts/lib/layer_direction_gate.py` (C0) |
| `hourglass-c-abi` | each C ABI crate exports a C surface only, its symbol set graded against the upstream library and its ABI pinned | `feature_public_surface_census.py` (C0), `pico_abi_symbol_census`, `zenoh_c_abi_symbol_census`, `capi_c_abi_pin.py` (C1ch), `abi_stamp_gate.py` |
| `no-allocation-in-operation` | an MCU image links no allocator, and a session of the MCU profile allocates nothing once it is open | `no_allocator_link_gate.py` (C0), `session_slot_allocations`, `rx_frame_allocations`, `tx_allocations` (C1m) |
| `lock-order` | no two of the runtime's locks are taken in both orders; a debug build stops the thread that closes a cycle | `crates/wz-runtime-tokio/src/sync/lock_order.rs`, armed by `WZ_LOCK_ORDER=panic` (Layer S) |

A gate is live when its file exists and a non-comment line of `scripts/run-ci.sh` that names it
sits in a function a dispatched lane (`run_layer <id> <function>`) reaches, directly or through
the functions it calls. A contract with one dead gate is unenforced; `--check` names the gate.
The list is `CONTRACTS` in the gate: a contract, or a gate of one, is added there, with its row
here.

## The ratchet

Each row of `deploy/completeness_ratchet.json` has a `state`:

- `locked`: the criterion is met; the figure must equal its `target`.
- `ratchet`: the figure may move only the way `better` (`lower` or `higher`) names. A
  row short of its `target` names its `debt`: a `debt-<id>` the store's inventory holds,
  or `pending:<slug>` until the item is filed.
- `local`: criterion (b), whose figure is never committed.

`value` is the figure at the reading of `read`. A figure worse than its row fails `--check`;
a better one passes and prints the row to commit, with the new value and date; a figure that
reaches its target asks for the row to be locked. A figure with no row, or a row the gate does not
read, fails: the table and the gate move in the same commit.

## The board as seeded (2026-11-21)

The values the table was written with, read from the files named above. The run of `--report`
on the merged tree is the reading that counts.

| Figure | Value | State | Where it comes from |
|---|---|---|---|
| `a.pico-api.wz-passes` | 15 | ratchet | 13 programs of `upstream_tests!` and the 2 session-local programs, of zenoh-pico's 18 `z_api_*_test.c` |
| `a.pico-api.shortfall` | 2 | ratchet, `pending:completeness-pico-api-shortfall` | `z_api_source_info_test` and `z_api_admin_space_test` run on the original and reach its private `_z_*` helpers, which wz does not export; `z_api_timestamp_test` links against neither library of the integration arm |
| `a.zenoh-c.wz-passes` | 24 | ratchet | the 24 programs of the lane's `upstream_tests!` |
| `a.zenoh-c.shortfall` | 0 | locked | the control runs the same 24 |
| (b) | NOT-MEASURED | local | no catalogue in the tree |
| `c.partial-atoms` | 2 | ratchet, `pending:completeness-partial-atoms` | `api-compat-rust`, `session-close-ingress` |
| `c.logic-census-unplaced` | 0 | locked | the coverage gate passes on main |
| `d.contracts-unenforced` | 0 | locked | every gate of the four contracts is wired into a lane |

## What the board does not claim

That a lane passed: (a) reads what a lane's guard requires and (d) that a gate is wired; each
lane's own run is its verdict. That the contract list is complete: it is the list the owner named,
and it grows by an entry in `CONTRACTS`.
