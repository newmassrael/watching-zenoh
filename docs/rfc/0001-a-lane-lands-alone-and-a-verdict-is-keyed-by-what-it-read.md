# RFC 0001 A lane lands alone, and a verdict is keyed by what it read

**Status**: proposal, 2026-11-26. The owner's instruction for this design: «land 도 비용 무시하고 가장
장기적으로 궁극적인 방법으로, 학술적으로 교과서적으로 나누게 설계하고 병렬로 진행해». It is the first
document of `docs/rfc/`; the numbering follows the bx repository's (four digits, then the rule the
document states). Like every file under `docs/` it is a design note, not parsed by the atomic store.
Line citations are at `add7382f4`. What bx has to change is written as a boundary and points at the bx
RFC that owns it (section 6.5); this document does not decide bx's design.

It extends `docs/verdicts-in-the-fleet.md` (where the full gate gives its verdict) and the queue of bx
RFC 0024 (one integrator per branch). It changes neither: it says what a landing unit is, what a
verdict is keyed by, which lanes a change needs, and which stage judges what.

## 1. Summary

- **Invariant.** Every value `main` takes was judged green, on its own tree, by the gate set that tree
  declares (the Not Rocket Science Rule). bx RFC 0024 already enforces this for the commit it pushes;
  this document makes it cheap enough to hold at the rate this repository lands (section 3).
- **The landing unit is one lane**: one worker branch, at most 20 commits and 8 directly changed
  crates (the 90th percentile of the last 80 landings). A larger lane lands as a chain of prefixes,
  front first, each cut at a commit whose impacted lanes are green. Hand-made integration branches
  (`intNNN`) are retired: the queue's speculative prefix stack is the integration branch, computed
  and judged by machine (sections 3.2 to 3.5).
- **A verdict is a function of a digest.** For each gate lane L and tree t, D(L, t) hashes the lane's
  definition, its environment and the content of every tracked file L can read: the cargo dependency
  closure of the packages it builds, the files it reads outside cargo, the submodule pointers in that
  closure. Equal digest, equal verdict, for lanes declared deterministic. A pass is reused; a failure
  never is (section 4).
- **Test selection is digest inequality.** A change needs exactly the lanes whose digest it changes. The
  forward map (file, owning crate, reverse dependency closure, lanes, legs) is how the digest is defined
  and how a plan is explained; it is derived from `cargo metadata`, the lane bodies of
  `scripts/run-ci.sh` and the leg table of `scripts/lib/nondefault-tests-gate.sh`, never written by hand
  (section 5).
- **Lanes have a determinism class**: D (a function of its digest), E (a function of its digest and of a
  machine environment not yet in the key) and S (a statistic: wall time, host buffers, scheduling). Only
  D and E gate a landing; only D is reused across machines; S never is (section 5.5).
- **The queue speculates on digests.** bx RFC 0024 4.7b already judges the queue's prefixes at once and
  lands the longest green one. With content-addressed verdicts a prefix pays only for the lanes whose
  digest its newest unit moved. Culprits are attributed first by digest (the units that changed the
  failing lane's inputs), then by bisection where bisection is sound (section 6).
- **Each question is judged once, at one stage** (author, submit, queue, integrate and push, post-merge).
  A later stage reads the earlier verdict by key; only post-merge re-executes, and only as an audit of
  the key, never as admission (section 7).
- **Flakes are classified, not retried away.** A failure is re-run only to classify it; a lane whose
  verdict varies at one digest is compared with its base (with and without the change) and is either the
  unit's defect or quarantined by a unit of its own, released after a stress sample and two consecutive
  green main runs, the rule `deploy/soft_jobs.json` already holds (section 8).
- **One round per landing unit** (section 9), and a staged migration with a check and a rollback for
  each stage (section 10). The gate-ledger lane now in progress is stages M1 (in part), M2 and M3.

## 2. What was measured

- **The int206 landing (2026-11-26).** The integration branch held 135 commits and 23 merges ahead of
  `origin/main` (`git rev-list --count origin/main..add7382f4`, and with `--merges`), the work of more
  than ten lanes. Its layer gates ran for the first time at integration, and every repair re-ran a
  hand-chained 37-step gate (size ledger, capability cost, `wz_config`, citations, limit reads, layers
  C1nh, C1st, C1co, C1bf, census, crate tests, clippy) from the start, 50 to 80 minutes each time,
  although a few steps had been red. The session guard that now refuses a hand-chained whole gate (rule
  V2, a Claude Code hook outside this tree) records the measurement.
- **The landings before it.** The last 80 merges on the first-parent line of `origin/main`
  (2026-11-25 to 2026-11-26) carried, per merge: commits median 4, 90th percentile 18, maximum 70;
  directly changed crates (distinct `crates/<name>/` directories in the diff) median 2, 90th percentile
  8, maximum 15; files median 7, 90th percentile 55. int206 is an outlier of that population by an order
  of magnitude.
- **Two lanes green, their merge red.** `docs/hosted-red-acks.md:58` reads hosted reds of "bundle tests
  that two branches each kept green and their merge broke". A semantic conflict is invisible to each
  lane's own gate and is what gating the combined tree before it lands exists to catch.
- **Receipts that overwrote each other.** A first receipt store (`scripts/verify-once.sh`, pre-push gate
  2c4) was removed on 2026-10-19 because the receipts "lived in one directory shared by every session,
  so a session's verification overwrote another's, and a push that had passed every lane was refused"
  (`.githooks/pre-push:472-477`, commit `be54b846c`). Its lane table was a hand-written trigger list
  whose own comment said "A miss found on a hosted run belongs HERE"
  (`git show be54b846c^:scripts/lib/verify_lanes.json`). Both defects are structural: a store keyed by
  session or by commit races, and a hand-written population under-reports.
- **Hand-derived populations under-report.** `scripts/lib/changed_crate_packages.py:20-45` records two
  measured re-derivations of a gate's population (a crate set, 10 of 25; a count-guard
  selection, 10 of 33), both silently low; its rule is
  "call the gate's own entry point; never recompute its population".
- **The queue would not drain on whole-gate verdicts.** The whole set took 13,074 s and 26,303 s of wall
  clock over the fleet, against a load λT of 2 to 4 on an average day and about 11 on the busiest, and
  speculation does not help while each candidate runs the whole set
  (`docs/verdicts-in-the-fleet.md:109-116`). This is why `[land]` declares no `checks` and a window of
  1 (`bx.toml:400-438`).

## 3. The invariant and the landing unit

### 3.1 The invariant

Let main take the values v_0, v_1, .... For a tree t let G(t) be the gate set t declares: the D and E
lanes of its lane declaration (section 5.5) minus the entries of its quarantine list (section 8.3).

> **I (main is green).** For every k, every lane L in G(v_k) has a pass verdict for D(L, v_k).

- G is read from the tree under judgment, not from the target. A unit that changes the gate set (adds a
  lane, moves a lane's inputs, quarantines a test) is judged by the set it introduces, the way Zuul runs
  a change's own job configuration speculatively. A unit cannot make itself green by deleting a gate
  silently: the lane declaration is a tracked file whose changes are units with rounds (section 9), and
  the declaration gate (section 5.4) refuses a `run_layer` row with no declaration.
- bx RFC 0024 theorem 1 supplies the other half: the integrator pushes only the candidate it judged, by
  compare-and-swap on the remote value. I is that theorem plus this document's definition of "judged".
- What I does not cover is stated, not hidden: S lanes (section 5.5) and the platform legs only hosted
  runners can run (macOS and Windows in `.github/workflows/platform.yml`) are post-merge audits until
  the fleet can run them (section 7).

### 3.2 The unit

A **landing unit** is one lane: one worker branch, submitted as one item with `bash scripts/land.sh`,
carrying one round descriptor (section 9). Units that cannot land apart are declared together with bx's
co-landing (`bx --land --land-with <item>`, bx RFC 0024 4.7b), which keeps each its own unit and round
and lands them in one push.

### 3.3 The size bound

| bound | value | measured from |
|---|---|---|
| commits of the unit, without the derived ledger commit | at most 20 | 90th percentile 18 of the last 80 landings (section 2) |
| directly changed crates | at most 8 | 90th percentile 8 of the same population |
| impacted lanes (section 5) | not bounded, reported | the queue's cost model reads it (section 6.4) |

Why a bound, and why there. A unit that fails returns everything in it, and every speculative prefix
above it is rebuilt (bx RFC 0024 4.7b). If a unit is red with probability p, the expected landings per
judgment of a window of W units is the sum over k = 1..W of (1 - p)^k (bx RFC 0024 2.6). p grows with
the size of the unit, so the queue's throughput falls as units grow; small batches are the textbook
remedy (Forsgren, Humble and Kim, "Accelerate", 2018). The 90th percentile refuses the outliers the queue
is measured to suffer from (int206) and not the work it already carries. The values are declared in a
tracked file of this repository (`scripts/lib/land_unit.toml`, stage M4), not in `bx.toml`, whose keys
are bx's (`bx.toml:22-23`). They are re-read from `bx --land-queue --stats` and the first-parent history
at each review, and moved only by a unit with a round.

A unit over a bound is refused by `scripts/land.sh` with the split the next section computes. A unit
whose commits genuinely cannot be cut (a format change and every reader of it) is declared indivisible
with a reason (`land.sh --indivisible <reason>`, recorded in its round descriptor); the reason is read at
review and counted in the stats.

### 3.4 Prefix-first splitting

A lane branch c_1..c_n on base b that exceeds a bound lands as a chain of prefixes:

1. **Cut points.** i is a cut point when the tree of c_i is green on the lanes impacted by b..c_i
   (section 5) at the author stage. Receipts make this cheap: a lane whose digest at c_i equals its
   digest at an earlier green cut is not run again.
2. **The front prefix.** The first unit is b..c_i for the largest cut point i within both bounds. It is
   submitted at once with its own descriptor (`land.sh` commits the descriptor on top of c_i).
3. **The rest.** c_(i+1)..c_n is rebased onto the first unit and split the same way. Its items may be
   submitted before the first lands: bx removes from an item the commits an earlier item of the same
   candidate, or one already landed, carries (bx RFC 0024 4.5, revision of 2026-11-25), so stacked
   prefixes are well-formed items.
4. **Order.** A later prefix never lands before an earlier one; the queue's order and its prefix
   candidates give this (bx RFC 0024 theorem 2).
5. **No cut point within the bounds** means the commits depend on each other across the cut: the author
   restructures, or declares the span indivisible (3.3). A cut that is not green is never submitted to
   learn whether it is; the author stage is where that is known, for the price of a cache lookup.

This is the trunk-based "land what is done, keep the rest local": the front of a lane reaches `main` and
the other lanes while its back is still being written, and a failure returns at most one prefix.

### 3.5 Integration branches are retired

An integration branch (`intNNN`) is a speculative stack built by hand: lanes merged on one branch, judged
once at the end. It has the cost of a batch (one red returns all of it, and finding which lane is red is
manual) and none of the queue's mechanism (no receipts, no prefix candidates, no culprit rule). The
queue's prefix stack is the same structure computed by machine: P_i is `main` with units 1..i placed on
it (bx RFC 0024 4.7b, structure 1). The standing rule "Finished work merges into ONE integration branch;
the preflight runs ONCE there" (`CLAUDE.md:90-97`, owner, 2026-10-09) was the right answer while a verdict
was a whole-gate run. Once verdicts are keyed by content it becomes "each lane lands alone and the queue
integrates"; the rule's text changes at stage M4 (section 10), by the owner's decision.

## 4. Verdicts addressed by content

### 4.1 Words

- **Lane**: one row `run_layer <id> <function>` of the dispatch table of `scripts/run-ci.sh`
  (`scripts/run-ci.sh:29988-30183`, 194 rows; the runner is `run_layer` at `scripts/run-ci.sh:1163`).
  A lane is what `bx --checks ci` hands out as a unit (`scripts/lib/runci_plan.py`).
- **Part**: one unit of a lane the planner cuts (`PARTED_LANES`, `scripts/lib/runci_plan.py:301`), run as
  `runci_plan.py --layer <lane> --part <part>`.
- **Leg**: one row of a lane's own table, the unit of selection inside a lane: a row
  `package|scope|features|filter|handed-off` of `LEGS` (`scripts/lib/nondefault-tests-gate.sh:125-160`),
  one feature set of a feature matrix, one crate of a per-crate lane.
- **Layer**: the family a lane belongs to by its id (C0, C1, E, Q, ...). A layer is a name for reading,
  not a unit of judgment.

A verdict is given per lane, part or leg, whichever is the finest the lane can run alone. Section 5.6
says why finer is better and how a lane is cut.

### 4.2 The digest

    D(L, t) = H( "wz-lane-digest/2" || spec(L, t) || env(L, t) || M(L, t) )

H is SHA-256 over a canonical serialization (sorted keys, length-prefixed fields).

| component | what it holds | why |
|---|---|---|
| spec(L, t) | lane id, part or leg, the unit's argv and the env keys the planner carries (`runci_plan.py` reads them from the hosted job), the definitions the lane runs from `scripts/run-ci.sh` (its function, every function it calls, transitively, and the code outside the functions, each without comments; `lane_digest.py`, "The dispatch script") and the blob of every script it sources or calls, the lane's class and declaration entry | a changed lane definition is a different question; an old pass must not answer it, and a change to another lane's function asks this lane nothing new |
| env(L, t) | the image digest once the tree declares one (bx RFC 0034); until then: `rust-toolchain.toml`, the output of `rustc -vV` and `cargo -V`, the tool-store entries the unit asks for (`[tools.*]`, `needed_by`), the oracle pins (`scripts/zenoh-c-oracle.pin`, `UPSTREAM_VERSION`); for an E lane also the machine's identity | the verdict depends on the tools; a key without them is the defect `bx.toml:389-394` names |
| M(L, t) | the sorted list of (path, mode, git blob id) of every tracked path in inputs(L, t), and (path, commit) of each submodule gitlink in the closure | git already addresses content; the digest is computed from the commit's tree object, never from a working directory |

The time, the machine (for D lanes), the session, the commit id and the branch are not in the key. Two
commits with the same inputs share a verdict, which is what lets a rebased unit and a speculative
candidate reuse what an earlier tree proved.

### 4.3 The inputs of a lane

    inputs(L, t) = workspace(L, t) ∪ ⋃_{p ∈ pkgs(L)} files(closure_t(p, feats(L, p))) ∪ glob_t(decl(L))

- **pkgs(L) and feats(L, p)** are read from the lane's own commands: the `-p`, `--manifest-path`,
  `--features`, `--no-default-features` and `--workspace` of each cargo call in its body, and for a leg
  its row. A cargo call whose package set cannot be read (a computed argument) makes the lane opaque
  (section 5.4). `--workspace` means every member.
- **closure_t(p, f)** is the resolved dependency graph of `cargo metadata --format-version 1 --locked
  --offline` run in `crates/` (the workspace is declared there, `bx.toml:27-38`) with the feature set f:
  every package reachable from p by normal and build edges, plus p's own dev-dependencies and their
  normal and build closure. Dev edges are not transitive: a dependency's dev-dependencies are not built
  when p is tested, and including them would only widen the selection.
- **files(closure)** are the tracked files under each local package's manifest directory, the path
  dependencies into submodules (`vendor/sce`, `vendor/zenoh-pico`, `vendor/lwip` and the others of
  `.gitmodules`) as their gitlink commit, and for registry packages their entry in `crates/Cargo.lock`
  (name, version, checksum). Projecting the lock file onto the closure, rather than hashing the whole
  file, keeps a dependency bump from moving the digest of lanes that do not build it.
- **workspace(L, t)** is what every cargo call of the lane reads besides packages: `crates/Cargo.toml`
  (its `[patch]`, `[profile]` and `[workspace.dependencies]`), `rust-toolchain.toml`, and the cargo
  configuration files the call loads (the default ones under `.cargo/` and `crates/.cargo/`, and those
  it names with `--config`, such as `crates/.cargo/capi-nostd.toml`).
- **The dispatch script** is an input of a lane as the definitions it runs (the spec row of 4.2), as a
  build key holds a target's own rule and not the whole build file. It is a file input, whole, only where
  the lane reads it as data (a script that opens it, another lane run whole) or where the reader cannot
  split it into functions; `--explain` says which. A script's reads are taken from the code a run with
  the options its call sites spell can reach: `run_layer` runs `lane_decline_read.py --read` for every
  lane, and only Layer C0 runs its `--audit`, which reads the whole script.
- **decl(L)** are globs the lane reads outside cargo: its fixtures, TSV and JSON tables, the store for
  the A family (`docs/.atomic/**`), the workflows for a lane that reads them, generated trees a crate
  includes (`out/**` of `[actions.regen-codegen]`, `bx.toml:351-354`) and the files a build script reads
  outside its crate. They are declared per lane (section 5.4), never derived from a lane's name.

### 4.4 Soundness: declared covers read

A digest is sound for a D lane when inputs(L, t) contains every tracked file the lane reads. Then equal
digests give equal verdicts, because the lane is by its class a function of what it reads and what it
reads is equal. An input set may be larger than what is read (that costs selections), never smaller (that
reuses a pass the change could have broken). Three mechanisms hold the inclusion, in the manner of
Bazel's sandboxed, declared-input actions and the constructive traces of "Build Systems à la Carte"
(Mokhov, Mitchell and Peyton Jones, 2018):

1. **Traced audit.** A lane is run under bx's read tracing (bx RFC 0003 9a; `bx.toml:367` shows the form,
   "a read outside this list is what `bx --action file-round --trace` names"), and every tracked path it
   opened that is not in inputs(L, t) is an undeclared input. A C0 gate (`lane_input_closure`, stage M1)
   runs this for every lane whose declaration or body changed, and on a schedule for all; an undeclared
   input fails it with the lane and the path. bx RFC 0046 (section 1, item 4) reports the same at
   planning time.
2. **Sampled re-check.** A cached pass is re-executed at a rate (bx RFC 0020 9; for actions one in
   sixteen, `BX_ACTION_RECHECK`, bx RFC 0003 9). A different verdict blocks the key and is reported, which
   is also how a lane declared in the wrong class is found.
3. **Audit against an independent run.** Post-merge (section 7) hosted CI judges the same tree on other
   machines. A lane whose hosted verdict differs from the fleet verdict for the same digest has an
   environment input missing from env(L, t), an undeclared file input, or the wrong class; it is filed as
   a key defect.

### 4.5 The receipt store

Two classes, by who executed the lane, not by stage:

| class | where | written by | read by | holds |
|---|---|---|---|---|
| **fleet verdict** | bx RFC 0020's site result cache (the REAPI action cache) | fleet executions only; the server enforces it by the machine's identity (bx RFC 0020 8) | the author stage, the queue, the hook | passes only (bx RFC 0020 1) |
| **author receipt** | `$(git rev-parse --git-common-dir)/wz-receipts/`, shared by every worktree of a clone, never tracked, never pushed | `scripts/verify-once.sh` on a workstation or a slot | the author stage of the same clone, `verify-once.sh --plan` | passes and failures, marked author |

The author receipt store is content addressed and append only:

- A receipt is written at `<lane>/<digest[0:2]>/<digest>/<receipt-id>.json`, where receipt-id is the
  SHA-256 of the record. It is written to a temporary name in the same directory and published with
  `link(2)`, which fails if the name exists; nothing renames over a receipt or edits one. Two sessions
  that verified different trees write different keys; two that verified the same inputs write two
  receipts of one key, which say the same thing. The overwrite of 2026-10-19 (section 2) cannot occur.
- Nothing is deleted except by age, a whole digest directory at once, and never one a running plan
  named (bx RFC 0032's rule, "nothing a lock names is deleted").

A receipt holds:

| field | content |
|---|---|
| `schema`, `lane`, `part_or_leg`, `class` | the question |
| `digest`, `manifest` | D(L, t), and the blob id of the serialized M(L, t), spec and env, so an auditor recomputes the digest from the record alone |
| `argv` | the unit's command |
| `verdict`, `exit`, `ran` | pass, fail or unmeasured (bx RFC 0037 1); the exit status; the number of tests or checks executed, which must be positive for a pass (the zero-population rule of `scripts/lib/nondefault-tests-gate.sh:51`) |
| `log_sha256`, `log_ref` | the hash of the full log and where it is kept (a file of the store's `logs/` named by that hash) |
| `executor` | `fleet` with the machine's key fingerprint and the bx job id, or `author` with a random clone id and no host name (as bx RFC 0024 4.3a keeps an installation's values out of public records) |
| `tools` | the env(L, t) values as read |
| `started`, `ended` | informational, part of no key |
| `commit` | the commit the tree came from, informational; the key is the digest |

### 4.6 Forgery and contamination

| threat | defence |
|---|---|
| a pass written by hand, or by a run that did not happen | the queue and the hook read fleet verdicts only; a client has no write operation and the server checks the machine's identity (bx RFC 0020 1 and 8). An author receipt can let an author skip a local run, never let a candidate land |
| a receipt from a dirty or untracked tree | the digest is computed from a commit's tree object; `verify-once.sh` refuses to write when the run's checkout differs from that tree (`git status --porcelain` not empty); a fleet slot receives tracked files and the recorded submodules only (`bx.toml:8-16`) |
| a receipt overwritten or reordered | content-addressed names, `link(2)` publication, no rename, no edit (4.5) |
| an incomplete key | traced audit, sampled re-check, hosted audit (4.4) |
| a tool or oracle changed under the same tree | env(L, t) is in the key; an E lane is keyed by machine until the image is (bx RFC 0034) |
| a pass that ran nothing | `ran > 0` is part of a pass |
| a lane definition changed and an old pass reused | spec(L, t) holds the lane body and the scripts it calls |
| a nondeterministic lane recorded as a pass | S lanes are never reused; a D lane found nondeterministic by a re-check has its key blocked and enters section 8 |
| a log replaced after the fact | `log_sha256` in the record; a fleet record is signed with the machine key in the form bx RFC 0033 gives the record store |

### 4.7 Never reused

A failure (cheap to ask again, expensive to believe when stale), an unmeasured result, an S lane, an E
lane on another machine, any receipt whose recomputed digest differs from its key, and any verdict of a
lane whose declaration gate is red.

## 5. Test impact analysis

### 5.1 Selection is digest inequality

For a unit with base b and tip t the lanes to run are

    Sel(t) = { L ∈ G(t) : no pass is stored for D(L, t) }

and, when b's verdicts are stored, Sel(t) is the set of lanes with D(L, t) ≠ D(L, b), plus any lane b
itself had not passed. There is no second selection algorithm to keep in agreement with the key: the
digest is the selection oracle, as a hit in Bazel's remote cache is. Google's TAP selects by the build
graph for the same reason ("Taming Google-Scale Continuous Testing", 2017): a dependency edge is a fact,
a trigger list is a guess.

The forward map below is how inputs(L, t) is computed and how `verify-once.sh --plan` explains why a lane
was selected. It is one function in one module (`scripts/lib/lane_digest.py`, stage M1) that the author
stage, the planner and the audit call; nothing recomputes it (the rule of
`scripts/lib/changed_crate_packages.py:45`).

### 5.2 From a changed file to its owner

- A path under a cargo package's manifest directory belongs to that package (`cargo metadata`
  `packages[].manifest_path`, the deepest one containing the path; nested packages are their own).
- `crates/Cargo.toml`, `crates/Cargo.lock`, the cargo configuration files and `rust-toolchain.toml`
  belong to the workspace; their effect is computed per closure (4.3), not as "everything".
- A submodule gitlink belongs to the packages with a path dependency into it, and to the lanes whose
  declaration names it (the pico interop lanes build `vendor/zenoh-pico` themselves).
- Any other path (scripts, docs, workflows, the store, `deploy/`, `bx.toml`) belongs to no package and is
  matched against spec(L) (the scripts a lane calls) and decl(L) (the files a lane reads).

### 5.3 The reverse closure

The packages a change reaches are the reverse transitive closure of the owners over the resolved graph,
with these edges:

| edge | reverse closure | reason |
|---|---|---|
| normal dependency | transitive | the dependent compiles against it |
| build dependency, proc macro | transitive | the dependent's build runs it |
| dev dependency | one step: the dependent's tests, not its dependents | dev edges are not built for dependents |
| path into a submodule | transitive from the gitlink | the submodule's sources are compiled |
| intra-doc link | one step, for documentation lanes only | `scripts/lib/doclink_dependents.py`, held both ways by Layer C0d (`scripts/run-ci.sh:6150-6168`) |

The feature set matters: a package reached only through a feature the lane does not enable is not in
that lane's closure. That is why the closure is computed per (package, feature set) of the lane, not once
for the workspace.

### 5.4 From packages to lanes, legs and layers

- **Lane bodies.** `runci_plan.py` already reads the dispatch table and each lane's function
  (`lane_bodies`); `lane_digest.py` reads the cargo calls in it (4.3) and the scripts it sources or
  runs. A lane is selected when its closure contains a reached package or its spec or declaration
  contains a changed path.
- **Leg tables.** A lane that runs a table runs a leg per row; a leg's closure is its row's package and
  features. Selection inside such a lane is per leg, so a change to one crate runs the legs of that crate
  and of its reverse closure, not the table. The table of `nondefault-tests-gate.sh` is the first
  (`LEGS`, `scripts/lib/nondefault-tests-gate.sh:160`, its row format at `:125-158`); its sharding by
  position (`WZ_LEGS_SHARD`, `:2794-2795`) gives way to selection by leg.
- **The declaration.** Every lane has one entry in a tracked declaration (`scripts/lib/lanes.toml`,
  stage M1): its class (5.5), the reasons of an E or S class, decl(L), and an explicit package set when
  its cargo calls cannot be read. A gate in Layer C0 holds the declaration to the dispatch table the way
  `scripts/lib/soft_job_gate.py` holds `deploy/soft_jobs.json` to the workflows: UNDECLARED (a lane with
  no entry), ORPHAN (an entry with no lane), DUPLICATE, FIELD.
- **Opaque lanes.** A lane whose inputs cannot be determined (an undeclared package set, a body that
  computes what it runs) is opaque: always selected, never reused. Opaqueness is the safe default and a
  debt each such lane carries in its entry; the audit counts them.

### 5.5 Determinism classes

| class | definition | reused | gates a landing | examples in this tree |
|---|---|---|---|---|
| D | the verdict is a function of D(L, t) | anywhere | yes | the crate test lanes, the static C0 gates, size ledgers measured with a pinned toolchain |
| E | a function of D(L, t) and of a machine environment not yet in the key: oracles provisioned per machine (`bx.toml:389-394`) | on the same machine with the same tool-store entries | yes | the interop lanes against the zenohd, zenoh-c and zenoh-pico oracles; the Qz lanes on the Zephyr SDK |
| S | a statistic: it reads wall time, host socket buffers, the scheduler, multicast interfaces, the core count | never | no; judged by a declared sample after the merge and on a schedule | Layer M, the opt-in environment-flaky lane, and Layer S, the opt-in stress lane (`scripts/run-ci.sh:376-377`); the throughput and performance differentials |

- A lane is S when its verdict compares a measured time or rate to a bound, reads a value the host sets
  (a socket buffer size, an interface list) or depends on interleaving it does not control. Its entry
  names which: `nondet = ["wall-clock", "host-buffers", "scheduler", "interfaces", "cores"]`.
- An E lane becomes D when the image that carries its oracles is in the key (stage M5); the class moves
  in the declaration, by a unit.
- A D lane whose re-check disagrees (4.4) is not reclassified by machine: it enters section 8 with its
  evidence, and the owning session decides between a fix and a change of class.
- bx RFC 0037 asks every test to be a function of code and declared inputs; S is not an exception to that
  rule for tests. It is the class of measurements, which are verdicts of a different kind and keep their
  own acceptance rule.

### 5.6 Granularity

A digest is only as narrow as its unit. A fail-fast aggregate lane reads the union of what its steps
read, so its digest moves on nearly every change and nothing is reused; it also hides later steps behind
the first failure (`scripts/lib/round_fed_gate_reach.py:20`: hosted Layer C0 "had already died at 14s on
an unrelated" lint). The cure is the one `PARTED_LANES` applies to Qzk and Cmut: a lane whose steps are
independent lists its parts and runs one part per unit, each with its own declaration. The static gates
the int206 repairs chained by hand (section 2) are the first candidates: each becomes a part with its own
inputs, so a change to a capability's cost re-runs the capability cost gate and not the citation gate.

## 6. The queue: speculative gating

### 6.1 What bx does, and what digests add

bx RFC 0024 4.7b judges the queue as prefixes. P_i is the target R with units 1..i placed and derived; all
prefixes up to the bound k = `window_max` are judged at once, longest first; the longest green prefix
lands at once; a failed prefix decides nothing by itself; the front unit returns only when every prefix
containing it has failed, with the reason of its own prefix P_1. This is Zuul's dependent pipeline (each
item judged on the assumption that those ahead of it land), bors's batch (the longest prefix is the
batch) and the outcome tree of Uber's SubmitQueue ("Keeping Master Green at Scale", 2019) restricted to
its all-land path.

What this repository adds is the cost model. P_i and P_(i-1) differ by one unit, so for every lane L

    D(L, P_i) = D(L, P_(i-1))   whenever inputs(L, ·) does not meet the unit's change

and the lane is a cache hit (bx RFC 0024 2.6, its last two bullets). Judging P_i costs the selection of its
newest unit against its predecessor, not the whole gate. SubmitQueue's "independent changes" is the same
fact computed from a build graph; here it is an equality of hashes.

### 6.2 A rebase moves only the digests it touches

A unit authored on base b and judged at P_i has, for each lane, D(L, P_i) = D(L, tip) exactly when the
files of inputs(L) are equal in both trees, that is, when nothing that landed between b and P_(i-1)
touched L's inputs. Then the author stage's fleet verdict is the queue's verdict, and the queue runs
nothing for L. When the bases differ in L's inputs, L runs once on P_i, and that run is exactly the
semantic-conflict check `docs/hosted-red-acks.md:58` lacked (two lanes green apart, red together).

### 6.3 Finding the culprit

When a prefix P_k fails, its failing lanes are known by name. Attribution proceeds in this order:

1. **By digest.** For a failing lane L, the units that can have caused it are those whose placement moved
   its digest: { j ≤ k : D(L, P_j) ≠ D(L, P_(j-1)) }. The digests of every prefix are computed when the
   prefixes are made, so this costs no run. For a D lane with one such unit, that unit is the culprit,
   since P_0 = R is green on L by invariant I. This is the usual case for small units.
2. **By bisection, where it is sound.** With several candidate units, the culprit is found by binary
   search over the prefixes that differ in L's inputs, judging only L. Bisection assumes the outcome is
   monotone in the prefix (once red, red in every longer prefix), which bx RFC 0024 4.7b (structure 7)
   rejects in general because a later unit may repair an earlier red (outcomes F F F F P). It is sound in
   the case this repository can tell apart: restricted to one D lane L, with R green on L by invariant I,
   and with no candidate after the first red one touching L's inputs again, L's outcome is monotone over
   the candidates. Bisection is therefore used to name a culprit in the report and to order which prefixes
   beyond the window are judged next. The decision to return a unit remains bx's rule (every prefix
   containing it failed), which is correct with or without monotonicity.
3. **Inside a unit, for the author.** A returned unit is bisected over its own commits on the failing lanes
   only (author receipts per commit make each step a lookup or one lane run), and the first commit that
   turns L red is reported with the return. This is diagnosis; the verdict was already given.

### 6.4 The window

`[land] window_max` is 1 today because a candidate ran the whole hook and the cores are shared
(`bx.toml:419-422`). With content-addressed verdicts a speculative prefix costs its selection, and the
window is set from the measured load ρ = λT/E of `bx --land-queue --stats` (bx RFC 0024 4.7): raised until
ρ < 1 holds on the busiest measured day, bounded by the integrator's worktrees in the disk budget (bx RFC
0006). bx removed the multiplicative decrease (bx RFC 0024 4.7b, structure 3), so the window is a choice
of capacity, not a control loop.

### 6.5 The boundary with bx

| needed | state | bx RFC |
|---|---|---|
| verdicts kept under content keys, written only by the fleet, sampled re-check | built | 0020 |
| the image in the key; the signature on it | not yet built | 0034 (stage 2), 0033 (stage 3) |
| per-unit `inputs` declarations honoured by the check planner; a unit with undeclared reads reported | partly built | 0020 (section 10), 0046 (section 1, item 4) |
| prefix candidates, longest green prefix, culprit only when all prefixes containing it failed, co-landing, moving an item to the front | built | 0024 4.7b |
| a digest-attributed culprit report and a bisection order for prefixes beyond the window (6.3, items 1 and 2) | to be proposed to bx | an amendment of 0024 4.7b, numbered by bx |
| the hook reads which lines the integrator already judged | built in bx; this tree does not read it yet | 0024 4.6a and 12 (`BX_LAND_PRE_PUSH_VERDICT`) |
| a set loses only what failed; the fleet shared fairly between speculative and other runs | built | 0046 |
| a test's verdict is a function of code and declared inputs; only unmeasured is retried | adopted | 0037 |

This repository owns the lane declaration and its gate, `lane_digest.py`, the author receipt store and
`verify-once.sh`, the unit bounds and the split, the quarantine list and its gate, `scripts/land.sh`, the
pre-push hook, and the reading of the post-merge audit.

## 7. The stages, and what each judges

| stage | runs where, on what | judges | does not judge | reads | on failure |
|---|---|---|---|---|---|
| **author** | the session's worktree, on the lane tip; lanes in the fleet with `bx --checks ci`, or locally | the unit's bounds (3.3); Sel(tip) for D and E lanes; the tests the unit changed, run repeatedly (bx RFC 0037 5.5); the commit hooks (`cargo fmt`, `Cargo.toml` and `Cargo.lock` pairing, schema pin, `validate-workspace`); the round descriptor (`file-round.sh --check`) | other units (the queue's); publication (the push's); S lanes; platform legs | fleet verdicts, author receipts | nothing is submitted; the author fixes or splits |
| **submit** | the item push to `refs/bx-land/main/items/<id>` | the public gates over what the item publishes: vocabulary, home paths, identity (gate 0q, `.githooks/pre-push:114-174`) | the repository's gates (the integrator judges the candidate) | none | the item is not published |
| **queue** | the integrator, on prefix P_i | G(P_i) by digest: hits reused, misses run in the fleet; the derive action (`file-round`) on the candidate | bounds; publication; S lanes; platform legs | fleet verdicts only | that prefix fails; culprit by 6.3 and bx RFC 0024 4.7b (structure 6) |
| **integrate and push** | the pre-push hook on the integrator's landing push | one writer (gate 0p, `.githooks/pre-push:176`); publication (0, 0b, 0b2, 0c); schema pin (1); the store with the filed round (2, `:382`); claim audit (2b); the previous hosted verdict and its acknowledgement row (2c, `:479`); citation form (2f) | lanes (it reads the queue's verdicts by key) | the verdict file of the judgment run | `hook-refused`, a failure of that prefix (bx RFC 0024 4.7b, structure 8) |
| **post-merge** | hosted CI on the new `main` (`.github/workflows/ci.yml:49-50`, `platform.yml`), the scheduled clean-room run, S lanes, sampled re-checks | an audit: the platform legs only hosted runners have; S lanes by their sample rule; agreement of hosted and fleet verdicts for one digest | admission; it never moves `main` back | everything | a debt item, paid in a round of its own; never an automatic revert (below) |

**Each question is judged once.** Every gate has exactly one owning stage; another stage may read its
verdict by key and may not re-execute it as admission. The hook's split between what it runs and what it
defers is already held by a gate (`hook_default_region_gate.py`, `.githooks/pre-push:22-24`); the owning
stage becomes a column of that table. Two re-executions remain, and neither is an admission:

- The integrator judges a candidate by running the hook (`git hook run`), and the landing push runs the
  hook again. The second run reads the verdict file of the first (`BX_LAND_PRE_PUSH_VERDICT`, bx RFC 0024
  4.6a) and skips each line already judged. Until this tree reads that file (stage M6), the lane step of
  the second run is all cache hits: the same answer, at the price of a lookup.
- Post-merge re-runs on other machines. Its result does not decide admission; it measures whether the key
  is complete (4.4) and judges what the fleet cannot run. As the fleet takes legs over, the per-push
  hosted jobs give way to the scheduled clean-room run (`docs/verdicts-in-the-fleet.md:129-131`).

**Why no automatic revert.** Under invariant I a post-merge red means one of three things: a platform leg
or an S lane outside G, an incomplete key, or a flake. Removing the unit fixes none of them: a revert is
itself a unit that has to pass the queue, it can conflict with the units landed after it, and it removes
the evidence the audit needs. The repository's standing rule is to read the red at the start of the next
round and pay it as a round of its own, the acknowledgement being a row of `docs/hosted-red-acks.md` in
the item that proceeds over it (`CLAUDE.md:81-82`, `docs/hosted-red-acks.md:1-16`; gate 2c reads the
row). A post-merge red that is a key defect also blocks the key (bx RFC 0020 9) and files the undeclared
input against the lane's declaration.

## 8. Flakes

### 8.1 Definition

A lane is flaky at digest d when two executions of the same unit at d give different verdicts (bx RFC 0037
1). For a D lane that contradicts its class; the remedy is to find which input or interleaving was not
controlled. The policy below keeps `main` green and the queue moving while that is done; it does not make
the flake disappear from view.

### 8.2 Re-execution is for classification

- **Unmeasured** (the environment ended the run: a machine lost, a reservation bx estimated exceeded) is
  re-run, as bx does (bx RFC 0024 4.5, 0037 1). It is not a verdict.
- **Fail** is never re-run into a pass. When a D or E lane fails at d, the unit's verdict is fail unless
  the classification below proves the failure is not the unit's.
- **Classification**, cost ignored, by the integrator for a queue failure and by `verify-once.sh` for an
  author one:

| step | sample | outcome |
|---|---|---|
| 1. repeat at d | 4 more runs on distinct machines, 5 in all | 5 of 5 fail: a deterministic failure, and the unit fails |
| 2. compare with the base, with and without the change (Chromium's commit queue retries a failing test without the patch for this reason) | 5 runs of L at the base digest d_0 = D(L, P_(i-1)), with the observation log of d_0 | the base fails too, now or in the log: a pre-existing flake (8.3) |
| 3. a sequential test, when the base showed no failure | runs at d and d_0 alternately, up to 60 each, under Wald's sequential probability ratio test (1945) on the two failure rates with α = β = 0.01 | the change raised the failure rate: the unit's defect, and it fails; the rates do not differ: a pre-existing flake (8.3); no decision at 60: the unit returns `unmeasured` with the samples, and the lane is marked suspect in the observation log |

Sixty runs detect a failure rate of 5 % with probability 1 - 0.95^60 ≈ 0.954. Every execution is appended
to an observation log keyed by digest (the author receipt store holds failures; the fleet's verdict cache
holds passes only), so a later classification starts from the samples already taken.

### 8.3 Quarantine

- **A tracked list**, `deploy/quarantine.json`, beside `deploy/soft_jobs.json` and held by a gate of the
  same shape (`scripts/lib/soft_job_gate.py`): one entry per quarantined lane, part, leg or test filter,
  with `why` (the classification's evidence: digests and samples), `debt` (the register item that owns the
  fix), `declared`, `expires` (at most 90 days ahead, `MAX_TERM_DAYS`, `scripts/lib/soft_job_gate.py:116`),
  `stress_runs` and `promote_after_green`.
- **The finest grain**: a test filter when the lane can skip one test, a leg when not, the whole lane only
  when nothing finer exists.
- **An entry is a unit.** A classification that ends in 8.3 makes a quarantine item and moves it to the
  front of the queue (`bx --land-move <item> --front`, bx RFC 0024 4.7b); the failed candidate is judged
  again on the new base, whose tree holds the entry. G(t) stays a function of the tree, and the quarantine
  is visible in the ledger.
- **A quarantined unit still runs**, on every candidate and after every merge, as an observation that never
  gates (the `observe_only` of `deploy/soft_jobs.json`), and every result goes to the observation log.
- **Expiry turns Layer C0 red** on its date, as for a soft job (`EXPIRED` in
  `scripts/lib/soft_job_gate.py`): a quarantine is a debt with a date, not a place to forget a test. A
  renewal states a reason and extends by at most 90 days.

### 8.4 Release

An entry is removed by a unit when all three hold:

1. a fix landed whose round names the entry's debt item;
2. a stress sample at the fixed digest passed `stress_runs` consecutive executions (60 by default: a 5 %
   failure rate survives that with probability below 5 %);
3. the unit then read green on `promote_after_green` consecutive main runs, 2 by default: the value and the
   rule `deploy/soft_jobs.json:11` and `scripts/lib/soft_job_gate.py:39-40` and `:81-84` apply to soft
   jobs, which become gates once their instances read green on that many consecutive main runs.

The stress sample comes first because two consecutive greens alone pass a 10 % flake with probability
0.81; the consecutive greens are kept because the stress sample runs on one digest, and the main runs
show the unit on the trees that follow.

## 9. The ledger

- **One round per landing unit.** `scripts/land.sh` writes the unit's round as a descriptor
  (`scripts/land.sh:113-139`) and refuses a second descriptor in the tree (`:117-120`); the integrator
  files it with the number the store gives it on the candidate (`[actions.file-round]`,
  `bx.toml:356-378`; `scripts/file-round.sh:21-23`: the number "is a function of the candidate's tree").
  This document makes the descriptor mandatory: a unit without one is refused by `land.sh` (stage M4). The
  derived ledger commit is not a unit.
- **Filing follows queue order.** bx places and derives the units of a prefix one by one (bx RFC 0024
  4.7b, structure 1), so each unit's descriptor is the only one pending when its derive runs, and the
  number follows the queue's order even after a `--land-move`. `file-round.sh` files every pending
  descriptor in name order (`scripts/file-round.sh:31-33`); with one descriptor per unit that order has one
  element. A unit carrying two descriptors, which only a hand-made integration branch produces, is refused
  at the author stage.
- **A prefix is a unit**, so each prefix of a split lane (3.4) has its own round, whose prose describes that
  prefix only.
- **Verification by address.** The lane-gate step of `land.sh` writes the unit's verification from its
  receipts: lane, digest, verdict, executor class. The round then names content an auditor can recompute,
  instead of a sentence saying that tests passed.
- **Quarantine, release and the repayment of a hosted red** are units with rounds like any other, the last
  with its acknowledgement row (section 7).

## 10. Migration

Each stage is one or more units of its own, lands alone and is verified on its own. "Rollback" says what
undoing the stage leaves.

| stage | content | verification | rollback |
|---|---|---|---|
| **M0** | this document | review | revert the file; nothing reads it |
| **M1** | `scripts/lib/lanes.toml` (one entry per lane: class, decl, packages, nondet) and its UNDECLARED, ORPHAN, DUPLICATE, FIELD gate in C0; `scripts/lib/lane_digest.py` (4.2, 4.3, 5.2 to 5.4) with `--explain`; `lane_input_closure`, the traced audit (4.4) | selftests both ways, as C0d does: a real edge must widen (`wz-session-core` reaches `wz-runtime-tokio`), a leaf must stay alone (`wz-ap-demo`); dev edges stay one step; a digest is unchanged by an edit outside the lane's inputs and changed by one inside; a replay of the last 80 landings: for every hosted red they caused, the red lane is in the causing unit's selection | remove the files; no stage consumes them yet |
| **M2** | the author receipt store (4.5) and `scripts/verify-once.sh` revived on it: `--changed` (Sel against the receipts), `--only-red` (the lanes whose latest receipt for this digest failed), `--all --reason <text>` (every lane; the reason goes into each receipt), `--plan` | two writers of one digest at once leave two receipts and lose none; a dirty checkout writes none; a receipt whose recomputed digest differs is ignored and reported; the session guard that refuses a hand-chained whole gate names this script as the way past | delete the script; receipts are advisory and no admission reads them |
| **M3** | the lane-gate step of `scripts/land.sh`: before submitting, run Sel(tip) through `verify-once.sh --changed`, refuse on a red, write the round's verification from the receipts (9) | land three units through it (a crate change, a script change, a docs change) and compare each selection with `--explain`; a unit with a red lane is refused before submission | revert the step; `land.sh` submits as before and the queue still judges |
| **M4** | unit bounds in `scripts/lib/land_unit.toml`, refused by `land.sh` with the computed split (3.4); `land.sh --split` producing the prefix chain; one descriptor per unit mandatory; the change of the `CLAUDE.md` rule "merges into ONE integration branch" (the owner's decision) | a week of landings: the share of units within the bounds, the queue's wait (`bx --land-queue --stats`), integration branches made (target: none) | set the bounds to no limit; the descriptor rule stays (it is the ledger's) |
| **M5** | the image (bx RFC 0034 stage 2, 0033 stage 3); `[checks.ci] cache = true`, each unit carrying its `inputs` from `lane_digest.py`; E lanes move to D | sampled agreement: on 50 digests the fleet verdict equals a fresh execution on another machine (bx RFC 0048's judgment from a sample), and the hosted audit shows no key defect for two weeks | `cache = false`: every unit runs, and verdicts are correct and slow |
| **M6** | the hook's lane step: a push to `main` asks `bx --checks ci` (the form `docs/verdicts-in-the-fleet.md:117-128` chose); the hook reads `BX_LAND_PRE_PUSH_VERDICT`; `window_max` raised from the measured ρ | ρ < 1 on the busiest day of a week; no `hook-refused` that the judgment passed; the landing push's hook adds no lane run | `window_max = 1` and the hook's lane step off, one line each |
| **M7** | `deploy/quarantine.json` and its gate; classification (8.2) in `verify-once.sh` and in the integrator's reading; the observation log | selftests of the gate (EXPIRED, the release conditions); a synthetic flaky lane (failing one run in four at one digest) is classified pre-existing on a base that shares it and as the unit's defect on a base that does not | empty the list; failures are failures, as today |
| **M8** | bx's amendment for digest-attributed culprits and the bisection order beyond the window (6.3, 6.5) | bx's tests; here, a queue of synthetic units whose culprit is named without a run | bx's switch |
| **M9** | the server's rule that only the integrator's identity moves `main` (bx RFC 0024 4.12), after a week of a single writer with ρ < 1 (`docs/verdicts-in-the-fleet.md:136-139`); the per-push hosted Linux jobs narrowed to the scheduled clean-room run (stage 5 of that document) | a `git push` to `main` from a session is refused by the server; the hosted audit still reads the platform legs | remove the ruleset; restore the workflow trigger |

M1 to M4 need nothing from bx and proceed as parallel lanes; M1 and M2 share only the interface of the
digest function, which M1 defines first. M5 waits on bx RFC 0034 and 0033. M6 needs M5 for its cost to
fall, though its reading of the verdict file does not. M7 needs M2's store for its log.

**The gate-ledger lane**, in progress beside this document, is the first cut of M1 (its layer lanes: the
lane set and their inputs), M2 (content-addressed receipts; `verify-once.sh` with `--changed`,
`--only-red` and `--all --reason`) and M3 (the lane-gate step of `land.sh`). To be those stages it holds
what sections 4 and 5 require: receipts keyed by D(L, t), not by commit or by a HEAD fingerprint (the shape
of `run-ci.sh --resume`, `scripts/run-ci.sh:369-375`, which invalidates on any edit); inputs derived from
`cargo metadata` and the lane bodies, not from a trigger list; publication by `link(2)` with no overwrite;
no receipt from a dirty tree; and author receipts never read as an admission. Where it differs, the
difference is a follow-up unit of M1 to M3, not a reason to hold it.

## 11. Alternatives not taken

- **A hand-written trigger table** (the removed `verify_lanes.json`). It under-reports by construction; its
  own header asked hosted reds to fill it in. Derived inputs with a traced audit replace it.
- **Receipts keyed by commit, by session or by working-tree fingerprint.** Keyed by commit, nothing
  survives a rebase and every speculative prefix is new; by session, two sessions overwrite or ignore each
  other (the 2026-10-19 defect); by fingerprint, an edit anywhere invalidates every lane.
- **Predictive test selection** (Machalica et al., "Predictive Test Selection", 2019). A learned model is
  unsound for admission: a skipped lane that would have failed reaches `main`. It may order which of the
  selected lanes start first.
- **Retry until green.** It launders a flake into a pass and teaches the gate nothing (bx RFC 0037 1).
- **Batch and bisect only** (bors). Superseded by prefix candidates (bx RFC 0024 4.7b, structure 7); kept
  here only where it is sound (6.3).
- **A wider window without content keys.** Each speculative candidate would run the whole set again, and
  the queue would not drain (`docs/verdicts-in-the-fleet.md:109-116`).
- **Automatic revert after a post-merge red.** Section 7.
- **Integration branches as the batching mechanism.** Section 3.5.

## 12. Open questions and risks

- **Feature unification.** Cargo unifies features over the packages of one invocation, so a package's
  build in a `--workspace` call can differ from its build under `-p`. The closure is computed per invocation
  from the lane's argv for that reason; a lane whose invocations cannot be read is opaque.
- **Build scripts that read outside their crate** (`lwip-sys` reading `vendor/lwip`, generated trees under
  `out/`) are inputs only the trace finds; the first M1 audit is expected to report several.
- **The environment before the image.** Until M5 most interop lanes are E and are reused only on one
  machine, so the cost falls less than it will after M5.
- **Hosted and fleet disagreeing for reasons outside the key** (runner kernels, core counts). The audit
  classifies each disagreement as a key defect or an environment class before it blocks a key; a lane that
  disagrees for environment reasons is E or S, and its declaration says so.
- **The values of the bounds** are a measured percentile of two days of landings and are re-read at each
  review. Work that is larger by nature (a pin move across the workspace) is the case the indivisible
  declaration exists for, and its count is watched.
- **Bisection's monotonicity** holds per lane under invariant I and fails when a later unit touching the
  same inputs repairs an earlier red; bx's return rule stays the decision for that reason.

## 13. References

- G. Hoare, "The Not Rocket Science Rule Of Software Engineering", 2014. bors and homu (the Rust project).
- OpenStack Zuul, "Project Gating" and "Dependent Pipeline" documentation (living documentation).
- S. Ananthanarayanan et al., "Keeping Master Green at Scale", EuroSys 2019.
- A. Memon et al., "Taming Google-Scale Continuous Testing", ICSE-SEIP 2017.
- Chromium, "Commit Queue" documentation, and the try recipes' retry with and without the patch (living
  documentation).
- Bazel, "Remote Caching" and "Hermeticity" documentation (living documentation).
- E. Dolstra, "The Purely Functional Software Deployment Model", 2006 (Nix).
- A. Mokhov, N. Mitchell, S. Peyton Jones, "Build Systems à la Carte", ICFP 2018.
- J. Micco, "Flaky Tests at Google and How We Mitigate Them", 2016.
- Q. Luo et al., "An Empirical Analysis of Flaky Tests", FSE 2014.
- M. Machalica et al., "Predictive Test Selection", ICSE-SEIP 2019.
- A. Wald, "Sequential Tests of Statistical Hypotheses", Annals of Mathematical Statistics, 1945.
- N. Forsgren, J. Humble, G. Kim, "Accelerate", 2018.
- bx RFC 0003, 0004, 0006, 0020, 0024, 0032, 0033, 0034, 0037, 0046, 0048 (the bx repository).
