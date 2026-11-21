# Layer Cmut: how complete the tests are, measured by mutating the code they test

A test suite can run every line of a module and still depend on none of its branches. Layer Cmut
asks the question coverage cannot: when the code is changed, does a test fail? Each scope of
`deploy/mutation_ratchet.json` is a crate and files of it. cargo-mutants changes those files one
mutant at a time (a function body replaced by a value of its type, an operator swapped, a match arm
deleted), in a copy of the cargo workspace, and runs the crate's own tests against each change.
`scripts/lib/mutation_ratchet_gate.py` then holds each scope's counts to the row committed for it.

Layer C0mut does the same for one function, the analyzer's verdict legs
(`scripts/lib/verdict_leg_mutation.py`). Layer Cmut is the general form: any crate, any file a scope
names.

## Running it

```
bash scripts/install-cargo-mutants.sh                                   # the pinned tool, once
WZ_CMUT_PART=session-core-sequence bash scripts/run-ci.sh --layer Cmut  # one scope
bash scripts/run-ci.sh --layer Cmut                                     # every scope in turn
bx --checks ci -- python3 scripts/lib/runci_plan.py --only Cmut         # a fleet unit per scope
```

| Variable | Default | What it does |
|---|---|---|
| `WZ_CMUT_PART` | unset | the one scope to run; unset, every scope runs in turn |
| `WZ_CMUT_JOBS` | 1 | how many mutants cargo-mutants builds at once, each in a copy of its own |
| `WZ_RUN_LAYER_CMUT` | unset | `1` runs the lane in a full sweep, which otherwise skips it |

The lane is opt-in, as Layer S is: a scope takes hours, so a full `bash scripts/run-ci.sh` skips it
unless it is asked for. On a build machine the tool is `[tools.cargo-mutants]` of `bx.toml`, built
by the same installer; a machine without it is not given a unit of the lane.

**Hosted, it runs nightly** (`.github/workflows/mutation.yml`, 04:41 UTC, and by hand from the
Actions tab), one job a scope, never on a push. The scopes are read from the table by the
workflow's first job, so a new scope runs the next night with no edit of the workflow. What a push
pays for is the table itself: Layer C0 runs the gate's `--selftest` and `--declared` (every scope
well formed, its files present, disjoint and hand-written, every row consistent with its counts).
Each night uploads every scope's `mutants.out` directory, red or green.

## What it prints, and how to read it

For each scope, one line of counts and one line for each missed mutant:

```
  Cmut <scope>: caught <n>, missed <n>, unviable <n>, timeout <n>, kill rate <caught/(caught+missed)>
    missed: crates/<crate>/src/<file>.rs:<line>:<column>: <the change> in <the function>
```

- **caught**: a test failed under the change. The change is noticed.
- **missed**: every test passed under the change. Nothing notices it, which is a test that does
  not exist.
- **unviable**: the change does not build. It measures nothing.
- **timeout**: the tests did not end in time (the scope's `timeout_multiplier` times how long the
  unmutated tests took). Counted, not graded: a machine's speed moves it.
- **kill rate**: caught / (caught + missed).

Then the verdict. The scope FAILS when its kill rate is below its row's, when its missed count is
above its row's (even at the same rate: the scope grew by code no test reaches), or when its row is
null. A null row has never been measured, and the failure prints the row the run measured and the
two commands that fill it. A run that is better passes and prints
`mutation-ratchet TIGHTER (commit it): scopes.<scope>.row = {...}`.

A run is refused, not read, when the unmutated tests failed in the copy (cargo-mutants exits 4),
when a scope that ran left no mutant in its outcomes, when a mutant lies in a file no scope declares,
when one mutant is counted twice, or when the outcomes were written by another cargo-mutants than the
table pins.

The outcomes of a run are under `target/cmut/<scope>/out/mutants.out/` (under the artifact root
when `WZ_ARTIFACT_ROOT` is set): `outcomes.json`, which the gate reads, and a log of each mutant's
build and tests.

## Paying a missed mutant

A missed line names a place and a change that no test of the crate can tell from the code as it is.

1. Read the change at that place, and decide what behaviour it breaks. That behaviour is what the
   missing test asserts: an edge (the boundary the swapped operator moves), a value (the one the
   replaced body returns instead), or a branch (the arm that was deleted).
2. Write the test in the crate, beside the module's own tests. Check it the way the mutant does:
   make the change by hand, see the test fail, take the change back.
3. Run the scope again. The missed line is gone, and the gate prints the tighter row.
4. Commit the test and the row together, so the row never claims a test that is not in the tree.

When a mutant changes nothing anyone could observe, the code it changes is usually redundant, and
the repair is to remove the redundancy rather than to add a test. When it is truly equivalent (no
input can tell the two apart), it stays counted as missed: the row carries it, and the commit that
sets that row names it. There is no list of mutants to skip, since a skip list is an exemption the
gate could not hold.

## The table

```
{
  "cargo_mutants_version": "<the pin>",
  "scopes": {
    "<scope>": {
      "package": "<crate>",
      "files": ["crates/<crate>/src/<file>.rs", ...],
      "timeout_multiplier": 3,
      "why": "<what the scope measures and why these files>",
      "row": null | {"caught": C, "missed": M, "unviable": U, "timeout": T, "kill_rate": R}
    }
  }
}
```

A scope's files are hand-written sources of its package: a file under `src/` of the crate, never a
`*_generated.rs` file (a test it lacks is owed by the source it is generated from), and never in two
scopes. The oracle is the package's own suite, as cargo-mutants runs it by default: the package's
unit and integration tests at its default features. A test in another crate that would catch a
mutant does not count here, which is the point: the scope measures the crate's own suite.

The first scopes, chosen because each holds protocol decisions whose failure a peer sees and whose
tests live in the same crate:

| Scope | Files | What it holds |
|---|---|---|
| `session-core-sequence` | `sn.rs`, `wrapping_ticks.rs`, `stream_window.rs` | the sequence-number ring, a tick span over a wrapping counter, stream framing |
| `session-core-establishment` | `accept_state.rs`, `handshake_stray.rs`, `link_admission.rs` | what an acceptor's cookie carries, a handshake's stray message, which of two links stays |
| `session-core-liveness` | `lease.rs`, `retry_period.rs`, `admission_retry.rs` | the lease deadline, the redial period, a publish offered again |
| `codecs-hand-written` | `vle.rs`, `whatami.rs`, `encoding_ids.rs` of wz-codecs | the part of the codec crate not generated from `sources/codecs` |
| `capi-pico-doors` | `encoding.rs`, `string_array.rs`, `zid.rs` of wz-capi-pico | door glue whose edge cases a C program relies on |

Every row starts null and is filled by the first measured run. A scope is sized to end well inside a
hosted job's 340 minutes; one that comes near it is split in the table, since a scope is the unit of
distribution.

**Adding a scope**: add the object with `"row": null`, run it once, commit its row. **Lowering a
row** (code with caught mutants deleted, say): only in a commit whose message says why.

**Moving the pin**: another cargo-mutants version generates other mutants of the same code, so the
rows are only comparable with runs of their own version, and the gate refuses outcomes that state
another. Move `cargo_mutants_version`, run every scope, and commit the new rows in the same commit;
`[tools.cargo-mutants]` rebuilds the tool from the new pin.

## Why a scope and not a shard

cargo-mutants can split one run into shards (`--shard k/n`), each taking the mutants at its
positions in the list of all of them. One mutant added anywhere moves every later one to another
shard, so a shard's counts are not comparable from one run to the next and no shard can be held to a
row. A scope is stable: its files are named. So the unit of distribution is the scope, one fleet
unit and one nightly job each (`WZ_CMUT_PART`), and a scope that grows too long is split into two
scopes, each with its own row.

## Why a copy, and what surrounds it

cargo-mutants never mutates the checkout here (`--in-place` is not used): it copies the cargo
workspace, `crates/`, and builds the copy. The workspace reaches files outside itself by relative
path (wz-codecs includes `../../out/wz-codecs/*.rs`, and path dependencies go into `vendor/sce`),
which a bare copy would not find. The lane therefore makes the copy inside a directory holding a link
to every other top-level entry of the checkout (`out`, `vendor`, `deploy`, `rust-toolchain.toml`,
`.cargo`, ...), so that from the copy `..` is what it is from `crates/`, and points cargo-mutants'
temporary directory at it. Each copy builds in a target directory of its own: the lane clears any
target directory a caller chose, which every copy would otherwise share.
