# Hosted-red acknowledgements

Every time a push proceeded over a **red** hosted run via `WZ_ACK_RED`, it is
recorded here. One row per acknowledgement.

## Why this file exists

`scripts/lib/previous-run-gate.sh` reads the previous push's hosted verdict and,
when it is red, requires `WZ_ACK_RED=<run id>` to proceed. That escape is
deliberate — the gate's own docstring gives the reason: *"A gate that simply
refused while the previous run is red would make the FIX unpushable, which is
the one push that must always work."*

But the acknowledgement only ever **printed**. It wrote nothing, so the fact
that a push had published over a red survived exactly as long as the terminal
scrollback. Open-debt item 695 named that as its third done-when — *a place
comes into being where the fact remains* — and warned that without it "the same
shape returns next window". It did: R2496 and R2497 each acknowledged the same
run, and the only trace was prose each round chose to write by hand.

⚠ **An acknowledgement is not a repayment.** A row here says a push went out
over a red, not that the red was paid. The paying is a round of its own, and the
row should name the debt item that owns it.

## How to add a row

Add the row in the same commit as the work being pushed, before the push that
uses the ack. Keep the columns exact — `run` is the hosted run id the gate
printed, `commit` is the tip being replaced (the sha the run graded), and
`debt` is the register item that owns the red.

| round | run | commit | failing steps | debt | paid |
|---|---|---|---|---|---|
| R2496 | `34393145847` | `0df6bfeb` | C0 binary-dep · C0 (armed) provenance · C1bt wz-capture | 709 | R2498 |
| R2497 | `34393145847` | `0df6bfeb` | C0 binary-dep · C0 (armed) provenance · C1bt wz-capture | 709 | R2498 |
| R2535 | `34465003136` | `6b112827` | C0 sn-res-words selftest (two jobs, one cause) · C1ce census `unstable` row | 717 | R2535 |
| R2568 | `34611269702` | `efada3a9` | E z_info drop-in link · Z same (two jobs, one cause) · A4 cross-impl accessor · C0 gate-provenance | 721 | |
| R2570 | `34640784537` | `85c21c02` | C1bn feature-gate-diagnostic · C0 lane-reach · A+B C0 (armed) provenance · E6 peer mesh | 721 | |
| R2574 | `34659495427` | `df7369ec` | C0 python-floor lint, `facade_forward_gate` imports `tomllib` (two jobs, one cause) | — | R2574 |

## What the rows above say

Both acknowledgements name the **same run**, which is the shape item 695
described: a red that survives a window gets re-acknowledged rather than paid,
once per push, with nothing accumulating. The `paid` column is what closes the
loop — R2498 committed the repair for both causes and R2499 the successor red,
and run `34416404276` on `2d07dbde` confirmed the two named causes green on
hosted CI.

⚠ A row whose `paid` column is empty is an outstanding acknowledgement. That is
the number this file exists to make countable.

R2535's row is the shape the file was built for rather than the shape it
warns about: the push it covers CARRIES both repairs — `d039d425` for the
`sn-res-words` cause and this round's commit for the census row — so the `paid`
column is empty only because no hosted run has graded them yet. The round that
reads run `34465003136`'s successor fills it in, and an empty column that
survives that reading means the repair did not hold.

R2540 did that reading, and it is why the column now says `R2535` rather than a
later round: the repairs were already IN the push the row covers, so the round
that carried them is the round that paid. Run `34479239610` on `787f00ed` — the
first successor — came back `success` with all 21 jobs green, including the two
that own the named causes (`default-off builds + gate provenance (Layers C0,
C1cf)` for `sn-res-words`, and `§5.27 api-compat-c (C1ce + arms gate)` for the
census row); runs `34483441810` and `34486390529` repeated it. A whole-run
`success` is what makes those readings safe to quote here: this lane is
fail-fast, so a green leg proves nothing when an earlier leg aborted, and only a
run that reached the end proves the later ones ran at all.

⚠ R2568 SUPERSEDES THE COUNT BELOW: it is ONE, not zero. Its row is the first
outstanding acknowledgement since R2540, and the paragraph that follows was
written when R2540 was the tip. The sentence is kept rather than rewritten
because the reasoning in it is still the reasoning; only the number moved.

⚠ The outstanding-acknowledgement count this file exists to make countable is
therefore ZERO as of R2540. That is a statement about ACKNOWLEDGEMENTS, not
about hosted CI: R2540 measured two ratchets left red by R2539 (open-debt item
720) which no row here covers, because no push has yet been made over them under
an ack. A row appears when a push USES an ack, and a red nobody has pushed over
is the register's business rather than this file's.

## R2568's row

The four failing jobs on run `34611269702` reduce to THREE causes, and all three
are repaired in `7ee6b475`, which this push carries: an unregistered
foreign-oracle accessor (Layer A4), an unsanctioned provenance token (Layer C0,
`gate-provenance: FAIL` in that job's log), and a `z_info.c` link failure seen
twice — Layers E and Z are the same defect against two different peers, 34
undefined references to the `Z_FEATURE_CONNECTIVITY` family.

⚠ The failing STEP name does not name the failing gate. The API reports
`Layer C0 — binary-dep test`, and the gate that actually failed inside it was
`gate-provenance`. Attributing from step names alone misreads this file's
`failing steps` column; read the job log.

The red dates to R2562, established by walking the runs backwards rather than by
reading HEAD: `34593867110` (R2560) green, `34599628250` (R2561) red only on
`Provision Zephyr`, `34603271323` (R2562) the first appearance of Layer E. R2562
set `Z_FEATURE_CONNECTIVITY=1` on the primary pico arm to obtain one witness,
and that flag made upstream `z_info.c` reference symbols wz does not export.

The `debt` column names **721**, an item R2568 had to CREATE. No existing item
owned the class: 687 is `CLOSED (R2421)` and the changed-crate mechanism is the
diagnosis written inside that closed item's body — which is exactly why this red
survived four hosted runs with nobody prompted.

⚠ `paid` is EMPTY deliberately. The repair was verified by READING the guards:
`z_info.c` guards connectivity at two sites, the in-`main` one sits after the
`z_info_peers_zid` section, and the two failing tests assert the Peers/Routers
zid bucket split, which is the section a CONNECTIVITY=0 header set keeps. That
is an argument, not a hosted verdict. The round that reads this run's successor
fills the column in, and an empty column that survives that reading means the
repair did not hold.

## R2570's reading of R2568's row, and its own row

R2568's `paid` column stays EMPTY, and that is the reading rather than an
omission: run `34640784537` on `85c21c02` — the successor R2568 nominated —
came back `failure`, so the run as a whole did not go green.

But the reading is not "the repair did not hold", because the causes moved.
R2568 named three, and they are separable in the successor:

- **The `z_info` link failure is GONE.** It was the loudest of the three (34
  undefined references to the `Z_FEATURE_CONNECTIVITY` family, in Layers E and
  Z) and the successor's interop job shows `Built target z_info` with a
  27352-byte binary. The whole `demo-spawning e2e lanes (Layers E + E3..E6u)`
  job, red on the run R2568 acknowledged, is GREEN on the successor. That repair
  held.
- **`C0 gate-provenance` still reds**, now surfacing as the `validate + codegen`
  job's own `Layer C0 (armed) — gate provenance citations resolve` step.
- **The cross-impl job still reds**, at `Layer E6 — peer mesh` (rc=1, 23s)
  rather than at the link failure it died on before.

And one cause is NEW, arriving between the two runs rather than surviving from
the first: `Layer C1bn` reds on `feature-gate-diagnostic: FAIL — wz-runtime-tokio
/ access-extauth-usrpwd is both probed and declared to gate no public path, and
those cannot both be true`. That names R2567's atom, so it belongs to the same
arc rather than to the round that found it.

⚠ THE ROW ABOVE IS R2570's ACKNOWLEDGEMENT, not a claim about its own work. The
round pushed an atom promotion (`scouting-static` PARTIAL → COMPLETE) over the
four reds listed, having run the lanes its change owns locally. Its `debt` column
says 721 for the same reason R2568's does — that item owns the class in which a
red survives a window because nothing local can see it — and, like every row
here, an acknowledgement is not a repayment.

⚠ R2574's ROW IS THE UNUSUAL ONE: its `paid` is filled by the SAME round, and its
`debt` is a dash rather than a number, because neither column means what the
others mean here. The red was not a class this register already owns and not a
red that survived a window nothing local could see — it was CAUSED by the push
two rounds earlier, which added `scripts/lib/facade_forward_gate.py` to Layer C0
reading manifests with `tomllib`, stdlib only from python 3.11 against a 3.10
runner floor. R2574 fixed the cause (the gate now asks `cargo metadata`, so it
parses no manifest format at all) and verified it with the lint that caught it:
135 scripts scanned against 3.10, 0 findings. So the acknowledgement exists only
because gate 2c reads the PREVIOUS run's conclusion, which is immutable — a
repaired cause cannot turn a finished run green, and no amount of fixing removes
the need for the ack.

⚠⚠ WHAT THAT `paid` DOES NOT CLAIM, recorded because this layer's shape makes
the overclaim easy. Layer C0 is fail-fast and the python-floor lint sits at
`scripts/run-ci.sh:2026` while the gate that tripped it sits at `:2703`, with 104
script-gate invocations between them. Every one of those was UNRUN on that push —
including the new gate itself, which has therefore never executed in CI. `paid`
here means the named cause is fixed and independently re-measured. It does not
mean Layer C0 is green, and the next hosted run is the first evidence either
way.
