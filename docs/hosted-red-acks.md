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

⚠ The outstanding-acknowledgement count this file exists to make countable is
therefore ZERO as of R2540. That is a statement about ACKNOWLEDGEMENTS, not
about hosted CI: R2540 measured two ratchets left red by R2539 (open-debt item
720) which no row here covers, because no push has yet been made over them under
an ack. A row appears when a push USES an ack, and a red nobody has pushed over
is the register's business rather than this file's.
