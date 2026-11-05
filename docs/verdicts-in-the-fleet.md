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

| Part | bx RFC | State on 2026-11-05 |
|---|---|---|
| A set of checks spread over the machines, unit by unit | 0004 | built |
| A unit's pass kept under the content of its inputs, so an unchanged unit is not run again | 0020 | stages 1-6 built |
| The image a unit runs in, declared by the tree and part of the key | 0034 | adopted; its stage 2 waits on 0032 (the record store) and 0033 (signing), neither built |
| One integrator per branch that lands only what its gates judged, in queue order, speculatively | 0024 | proposed, not built |

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
   - This waits on RFCs 0032 and 0033, which are not built.
3. **The whole set, green, in the fleet.** `bx --checks ci` passes all lanes.
   Wall clock and machine time are measured against the hosted run.
4. **Judged before landing.** `scripts/land.sh` already holds the clone's push
   lock, so it is already a serial integrator for this machine. It runs
   `bx --checks ci` on the rebased candidate and pushes only a pass, which is
   RFC 0024's interim `gate` form. When RFC 0024 is built, `bx --land` takes
   over the queue, adds speculation and the recovery rules, and land.sh becomes
   its client. The declaration it will read is `[land] checks = "ci"`. Its
   saving (an unchanged lane is not run again on a re-land) comes from the
   kept verdicts of stage 2.
5. **Hosted CI narrowed.** The per-push Linux jobs of `ci.yml` give way to the
   scheduled clean-room run. `platform.yml` stays.

## What this does not decide

- How the account's hosted slots are shared between repositories. Once stage 5
  lands, this tree no longer needs them for its verdict.
- RFC 0024 section 13: the integrator's server-enforced status, the queue's
  place in the fleet, and the speculation depth. Those are bx's decisions.
