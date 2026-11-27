# Verdicts in the fleet

Where this tree's full gate gives its verdict, and the order in which it moves
there. Decided 2026-11-05 under the owner's instruction to choose the most
correct long-term structure regardless of cost.

## The defect

Hosted CI was the only place the full gate ran, and it gave almost no verdicts.

- Run 41939089182 queued its 44 jobs at 00:22 and was still running at 05:45.
  Its jobs waited up to 163 minutes for a runner.
- The workflow's concurrency group keeps one running run and replaces the
  pending one. The seven CI runs created behind it (rounds 4247 to 4254) each
  ran zero jobs.
- Sampled every 20 minutes from 00:20 to 05:20, the hosted jobs running on the
  account were 19 to 21 each time. That is the plan's cap of 20. Another
  repository of the account held 13 to 19 of those slots; this one held 1 to 7.

So the runner pool is shared by every repository of the account, and how fast
this tree is judged is decided outside it. A red found that way surfaced rounds
after the commit that caused it, and most commits were never judged at all.

The `ubuntu-22.04` image being deprecated (actions/runner-images#14254) was
suspected first and is not the cause: `ubuntu-latest` jobs of the other
repository queued the same way. The deprecation is still real. Brownouts start
2027-03-23 and the image retires 2027-04-17. Stage 2 below removes the
dependency.

## The structure

**Every commit `main` points at was judged, before it got there, on its own
tree, by the whole gate.** This is the Not Rocket Science Rule (G. Hoare,
2014; bors, Zuul, Uber's SubmitQueue). The gate runs on the build fleet, whose
capacity this tree's owner decides.

The fleet already holds the parts, each decided in bx under the same
instruction:

| Part | bx RFC | State on 2026-11-14, read from bx's code |
|---|---|---|
| A set of checks spread over the machines, unit by unit | 0004 | built |
| A unit's pass kept under the content of its inputs, so an unchanged unit is not run again | 0020 | stages 1-6 built |
| The image a unit runs in, declared by the tree and part of the key | 0034 | adopted, its stage 2 not built: a `bx.toml` has no `[image]` and a check set or unit no `image` |
| The record store the image lives in | 0032 | its primary built (`bx-fleet` `store.rs`), with `[records]` for a tree whose locks it keeps (0058) |
| The image accepted only under a key the tree pins | 0033 | its signing stage (3, `[image] trust`) not built |
| One integrator per branch that lands only what its gates judged, in queue order, speculatively | 0024 | built; this tree's integrator runs and `scripts/land.sh` submits to it |

The integrator is serial and lands in queue order. Taken together, these give
two properties: a unit whose inputs did not change costs a cache hit, and a red
cannot reach `main`.

Hosted CI keeps what the fleet cannot judge: the macOS and Windows legs
(`platform.yml`). It also runs a scheduled clean-room run of the same image,
which checks the image's hermeticity rather than judging a commit.

## Stages

Each stage is its own round and lands on its own.

1. **The gate as a set of units** (round of this document). `[checks.ci]` in
   `bx.toml` and its planner `scripts/lib/runci_plan.py`. A unit is one lane of
   `scripts/run-ci.sh`, run the way a hosted job runs it. Verdicts are not kept
   yet, because a lane's oracles are provisioned per machine and so are not in
   the key. Measured: lanes A, C0b, D and L passed as units on three machines.
2. **The image.** An image on `ubuntu-24.04` that carries every oracle a lane
   now gets from its machine: the apt set, the Rust pins, zenohd, zenoh-c and
   zenoh-pico at their pins, the Zephyr SDK, the arm compilers, qemu and the
   pinned mnemosyne-cli.
   - This tree's own tool builds it, pushes it to the fleet's record store (bx
     RFC 0032) and signs it with a key pinned in the tree (RFC 0033).
   - The tree holds only the lock: one line per key ending in the OCI index
     digest, the format of RFC 0034 4.1.1.
   - `bx.toml` names that lock in `[image]` (lock, select, repository, trust).
   - Then `cache = true` goes on `[checks.ci]`. It is sound only once every
     input of a verdict is in the key, either inside the image or read from
     the tree. A unit that still needs a machine-only layer declares
     `image = "none"` and keeps no verdict.
   - This waits on bx: RFC 0034's stage 2 (the `[image]` declaration, a unit
     run in the image's root filesystem, the digest in the key) and RFC
     0033's stage 3 (the signature checked against the pinned key). The
     record store it pushes to (RFC 0032) has its primary.
3. **The whole set, green, in the fleet.** `bx --checks ci` passes all lanes.
   Wall clock and machine time are measured against the hosted run.
   - First run (2026-11-06): 180 units, 160 pass. The tree reds were repaid
     on their own. Six other failures came from a unit that ran the lane bare,
     without the provisioning lines its hosted job runs first. A unit is now
     `runci_plan.py --layer <id>`, which runs those lines and the lane under
     the job's env; the six pass.
   - Each unit now states what the lane fails without (`needs`, `packages`,
     `capabilities`, read from the armed-oracle census and the lane's use of
     the namespace sandbox), and bx places it only where that is present.
     C1bn and C1bs (the latter through the sandbox) pass there.
   - U no longer reads the network. The releases API's answer is an input the
     tree carries (`scripts/lib/upstream_releases.json`, written by
     `upstream_release_distance.py --fetch`, with the sha256 of its body), and
     the lane judges the pins against it on any machine. Whether upstream has
     published since is not a verdict on a commit: `--watch` judges it on a
     schedule in `upstream-watch.yml`, outside the check set.
   - Left, fleet provisioning: C1cc needs valgrind beyond the one machine that
     has it.
4. **Judged before landing.** RFC 0024 is built and is `main`'s one writer:
   `scripts/land.sh` submits to the queue, and its integrator judges each
   candidate with this tree's pre-push hook, run for the landing push's own
   line. RFC 0024 spells "judged by the whole gate" two ways: `[land] checks
   = "ci"`, or the hook itself asking `bx --checks ci` for a push to `main`.
   Its 4.11 dropped the first draft's `gate` command, which this stage once
   named. Neither is declared yet, for two reasons that stage 2 removes:
   - **The queue would not drain.** With nothing kept, every candidate runs
     the whole set. Stage 3 measured 13,074 s and 26,303 s of wall clock for
     it over the whole fleet. From 2026-11-07 to 2026-11-14 about 98 landings
     filed a round on `main`, 3 to 37 a day (the ledger commits there). That
     is a load λT of about 2 to 4 on an average day and up to about 11 on the
     busiest, and a queue with λT above 1 grows without end; speculation does
     not help, since each speculative candidate runs the whole set again.
     `bx --land-queue --stats` reports the measured value.
   - **One question, asked twice.** With `checks` set the hook does not judge
     the candidate and still runs on the landing push, so a candidate the set
     passed can come back `hook-refused` after hours. With the hook asking
     `bx --checks ci`, the set runs for the judgement and again for the
     landing push, unless the second run finds the first one's verdicts
     kept. RFC 0024 3.6 chooses the hook form for that reason: the judgement
     and the push ask one question under one key.
   So the hook form needs kept verdicts (stage 2), and a load below 1 also
   needs each lane to declare the files its verdict reads (`inputs`), so that
   a candidate which does not reach a lane finds its verdict kept. Then the
   hook's push to `main` asks `bx --checks ci`, `[land]` keeps judging by the
   hook, and the queue's measured load decides the window.
5. **Hosted CI narrowed.** The per-push Linux jobs of `ci.yml` give way to the
   scheduled clean-room run. `platform.yml` stays.

## Hosted runs on main until stage 5

Measured 2026-11-27 (UTC), because the five newest `CI` runs on `main` had all
ended `cancelled` and the question was whether the workflow cancels them.

- It does not. `ci.yml` and `platform.yml` group by workflow and ref with
  `cancel-in-progress: false`. Run 45909596193 (CI, 61a9fcee17) entered the
  group at 23:42 and at 01:10 had 11 of its 68 jobs done, 2 running and 55
  waiting for a runner. Every run created behind it (48dba85264, 52e388a62c,
  ab08ef71d1, 97be171dc4) waited pending and was replaced by the next landing,
  with zero jobs run (run 45918353357: `total_count` 0). 5bb80bcd7a is the one
  pending now, and it runs when 61a9fcee17's run ends. Platform shows the same
  shape.
- So the cancelled runs are the group replacing a waiting run, and the cause is
  that landings arrive faster than runs finish. From 13:20 to 00:52, 22 CI runs
  were created on `main`, about 1.9 an hour. The two that graded in that span
  took 8 h 47 min (45798145950, 72ce26dae9) and 4 h 51 min (45879236459,
  d99bf406e9) from creation to their last job.

What each choice costs, with those numbers.

| Group on `main` | Runs per burst | Which commits are graded | Holds at 1.9 landings an hour |
|---|---|---|---|
| Per commit, never cancelling (R311y706) | one per landing | every one, in time | no: see below |
| Per ref, cancelling in progress (R311y619) | every run started, all but the last cut | none while landings keep coming (R311y701 to R311y703) | no |
| Per ref, never cancelling (now) | the one in flight and the newest | the newest commit when the run in flight ends; it contains every landing since the last graded one | yes |

- Per commit does not give more verdicts here, it gives none. A run of 72 jobs
  used 1,083 and 1,208 job-minutes (runs 45798145950 and 45879236459). At 1.9
  landings an hour that is about 2,100 to 2,300 job-minutes an hour, 34 to 38
  runners busy without pause, against an account pool of 20 that another
  repository already holds most of (measured 2026-11-05, above). The load
  `λT` is at least 9 to 17 with `T` the measured 4.9 to 8.8 hours, and a queue
  above 1 grows without end: each run waits longer than the one before it.
- Cancelling in progress throws away the hours a run already spent and, under a
  steady stream of landings, leaves no commit graded at all.
- Never cancelling grades by range. As long as `main` only moves forward, the
  graded commit descends from every commit landed since the previous graded
  one, and every hosted job judges the whole tree at its sha, so each landing
  is covered by the next graded run. What it costs is stated: a red is
  attributable to a range (up to about ten landings in the span above) and
  needs a bisect, and the verdict arrives up to two run lengths after the
  landing. A replaced run costs nothing: it ran no job.

How it is read and held.

- Pre-push gate 2c (`scripts/lib/previous-run-gate.sh`) steps over a run whose
  jobs say it was replaced (`hosted_cancelled_kind.py`) and grades the newest
  finished run on the commit's history; a run cancelled after it started is
  amber or red, never a replacement.
- `scripts/lib/workflow_cache_save_gate.py` (rule 4) fails a workflow that a
  push to `main` starts when its group is not keyed by `github.ref`, when
  `cancel-in-progress` is anything but `false`, or when a job has a group of
  its own, which would replace a waiting job of an earlier run.
- A verdict for each landed commit is stage 4's, judged in the fleet before the
  landing, not the hosted group's: how many hosted runners this tree gets is
  decided outside it.

## What this does not decide

- How the account's hosted slots are shared between repositories. Once stage 5
  lands, this tree no longer needs them for its verdict.
- The server's rule that only the integrator's identity moves `main` (RFC
  0024 4.12 and 10.4). The owner sets it once the queue has been the only
  writer for a week with its load below 1; until then gate 0p is the only
  thing that keeps a second writer out.
- Where the integrator runs and with which identity (RFC 0024 13a.2 and
  13a.3). Those are bx's and the fleet's.
