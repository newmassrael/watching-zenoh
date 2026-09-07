#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2394 (no register item) — how many atoms are still GRADED against a zenoh
this tree no longer pins, as a number a command produces rather than one a
session remembers.

The citation is `no register item` for the reason `debt_plane_census.py` and
`config_key_fixture_gate.py` both give for theirs: the item this answers for --
unregistered open-debt item 675 -- lives in the agent-memory register, which has
no store id for `gate_provenance_lint.py` to resolve. Naming "nothing" is a real
answer; the item is named in prose throughout this header.

## The defect

An atom's inventory `reason` opens with its grade -- `PARTIAL:` or `COMPLETE:`
-- and then says what that grade was measured against. A large share of them say
`1.5.0`. The tree's pin is not 1.5.0 and has not been for some time: the oracle
pin (`scripts/build-zenohd.sh`) and the upstream checkout the citation gates
resolve against are both 1.10.0.

A `PARTIAL` graded two versions back is merely stale -- it says work remains,
and work does remain. A `COMPLETE` graded two versions back is a false
statement: it asserts parity with an upstream that has since moved, and it is
asserted about the upstream this tree exists to replace. R2394 measured one and
the measurement refuted it inside ten minutes -- `access-downsampling` was
COMPLETE against 1.5.0 while the pin's downsampling filter reads Put and Del
through separate selector bits that wz's three-variant mirror could not express.

## Why a RATCHET and not a red

The honest repair is per-atom: re-measure against the pin, write down what the
re-measurement changed, then move the declaration. That is a round's work each,
and there are dozens. A gate that turned all of them red at once would stop the
tree, and a gate that stops the tree gets switched off -- this register has the
precedent. So the budget starts at what the population MEASURED on the landing
commit and may only go down.

The direction that matters is UP. A new atom graded against 1.5.0, or an old one
whose re-write reintroduces the declaration, is the drift this exists to catch,
and it is caught the moment it lands rather than whenever someone next counts.

Both directions FAIL, which is this tree's established ratchet shape (see
`store_reason_citation_gate.py`):

  * ABOVE the budget -- an atom was graded against the stale version. Repair the
    GRADING, never the budget.
  * BELOW the budget -- a round re-measured one. Lower the budget in that SAME
    commit, so the number can never quietly drift away from what it counts.

## WHAT THE COUNT IS, and what it is NOT (R2396)

It is the number of graded atoms that do NOT DECLARE a pin measurement. That is
not the same as the number never measured at the pin, and the difference was
found by this gate's SECOND customer rather than reasoned out in advance.

`declare-token` was in the population, and R2383 had already re-measured it at
the pin and written the result into the reason -- in its own words, before this
marker existed. Measured at that commit, 14 of the 60 are in that position:
their prose asserts a pin reading somewhere, in a spelling no regex can be
trusted to grade, because "mentions 1.10.0" is exactly the substitution this
gate exists to refuse.

So the number over-states the WORK and states the DECLARATION exactly, which is
the honest thing for it to measure: prose cannot be graded, a declaration can.

### What the MARKER means, measured (R2401)

It means a round re-read THE CLAIMS IT NAMED at the pin. It does NOT mean every
clause of that reason was verified, and the gap is not small. Deriving each
declared atom's citation set from the store, classified against the checkout's
own top-level directories:

    atom                  rooted   wz   ROOT-LESS   (line-form)
    declare-token              1    2          13           12
    declare-subscriber         1    2          13           12
    declare-interest           2    0           7            7
    routing-namespace          0    3           5            4
    scouting-responder         1    0           2            1

EVERY rooted citation in all five resolves at the pin. So an audit asking "are
the citations dead" reports clean, and the unread clauses hide entirely in the
root-less set -- which does not even distinguish a wz path from an upstream one
(`declare_build.rs` and `api/session.rs` sit side by side in those lists). That
ambiguity is why the owner's 2026-09-01 decision bans line numbers on upstream
claims, and why the source gate keeps a bare budget at all.

A round that trusts this marker to SKIP a clause must derive that atom's claim
set itself rather than inherit the declaring round's choice -- which is the
failure the marker was invented to make impossible, reappearing one level up.
R2394 is the proof it happens: it stamped three clauses it never read, and R2401
found them true. Right, not known to be right.
Paying one of the 14 is therefore cheaper than paying a fresh one -- but it is
NOT a stamp, and `declare-token` is the proof. Both of the pin claims R2383
wrote cited a path that does not exist at the pin (one repository-name segment
too many), so the round that stamped the marker had to read the pin to find the
claims true and the citations dead. A round that had trusted the prose would
have propagated two dead citations; a round that had read the citation gate's
"unresolved" finding as a verdict on the CLAIM would have re-opened a grade that
is correct. Verify, then declare.

## What it derives rather than declares

The population is read out of the store: every `inventory_entries` value whose
`reason` begins with a grade tag and mentions the stale version. Nothing here
lists atom ids, so an atom renamed or added is inside the count by construction.

A population that collapses to zero REASONS is a reader that stopped matching
the store, not a store that stopped making claims, and it FAILS -- the "a
population of zero reports green" trap this tree has paid for more than once.
The zero that legitimately ends this gate is a zero STALE count against a
non-zero graded population, and only that pair is reported as done.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = ROOT / "docs/.atomic/workspace.atomic.json"

#: The version an atom must no longer be graded against. This is deliberately a
#: LITERAL rather than "whatever is not the pin": the question is not "does the
#: reason mention some version" but "does it still declare the one the tree has
#: moved off", and only a named string answers that without re-reading prose.
STALE_VERSION = "1.5.0"

#: The marker a round writes when it has re-measured an atom AGAINST THE PIN.
#:
#: The first draft of this gate had no such marker and asked only "does the
#: reason mention 1.5.0". That predicate FAILED ON ITS OWN FIRST CUSTOMER, which
#: is how it was found: R2394 re-measured `access-downsampling`, refuted its
#: COMPLETE grade, built the missing kind and rewrote the reason -- and the
#: count did not move, because an honest re-measurement has to NAME the version
#: it refuted in order to say what changed. A predicate that counts the record
#: of the repair as the debt punishes exactly the rounds that pay it, and the
#: only way to satisfy it would have been to delete the history.
#:
#: So the discriminator is not "which version numbers appear" but "has a round
#: DECLARED that this atom's grade was re-measured at the pin". `transport-stats`
#: had already coined the phrase for its own re-declaration in R2371, so this
#: adopts it rather than inventing a second spelling.
#:
#: THE RESIDUE, STATED RATHER THAN HIDDEN: a marker is a declaration, and this
#: gate cannot tell a declaration backed by a measurement from one that is not.
#: What it does stop is the cheap bulk edit the register warned about -- a
#: substitution of the version string across every reason clears nothing here,
#: because the marker is per-atom prose naming the round that measured it, and
#: the ratchet below forces the budget down in that same commit.
PIN_DECLARED = "PIN RE-DECLARED"

#: The grade tags an inventory reason opens with. A reason that opens with
#: neither is not a grading claim at all (the store also carries `debt-` items,
#: whose reasons are register prose), so it is outside the population.
GRADE_TAGS = ("PARTIAL", "COMPLETE")

#: The HEAD of a reason: its first word, whatever punctuation follows.
#:
#: R2418 (open-debt item 686) — THE POPULATION USED TO TURN ON A COLON, and that
#: is how this gate's own completion condition could be reached while false.
#: The test was `reason.startswith(("PARTIAL:", "COMPLETE:"))`, so a reason
#: heading `PARTIAL (BUILT R311y506, ...)` or `COMPLETE (R2351; was PARTIAL)`
#: was not a grading claim as far as this file could tell. NINE atoms head that
#: way -- three `PARTIAL (`, six `COMPLETE (` -- and FOUR of the nine name the
#: stale version with no pin marker, so they were stale gradings this ratchet
#: could not count. Two of those four are COMPLETE, which is the half the
#: register item calls sharper: a completion asserted against an upstream two
#: versions gone, with no instrument able to object.
#:
#: ⚠ THE FIRST DRAFT OF THE FIX WAS WRONG AND WAS MEASURED BEFORE LANDING.
#: `depth_axis_census.HEAD_TAG` looks like the thing to share, but it is a
#: FIRST-WORD EXTRACTOR, not a grade test: used as this population's predicate
#: it admits 214 reasons rather than 141, including atoms that were never graded
#: at all (`FOUNDATIONAL`, `PHANTOM`, `OUT-OF-SCOPE`, `BEYOND-PICO` heads). The
#: census pairs that regex with `head.group(1).upper() == "PARTIAL"` and it is
#: the PAIR that decides. This mirrors that pair for both grades.
#:
#: The provenance of the spelling, which the fix does not need but a reader
#: does: five of the six `COMPLETE (` reasons read `(R23NN; was PARTIAL)`, from
#: R2350-R2354. One round-family introduced the form, which is why the escape
#: arrived in a batch rather than one atom at a time -- a re-grading round moved
#: the head and silently left this population.
GRADE_HEAD = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)")


def _is_graded(reason: str) -> bool:
    """Whether `reason` opens with a GRADE, punctuation-insensitively.

    One predicate rather than a spelling, so a reason that heads
    `COMPLETE (R2351; was PARTIAL)` is inside the population exactly as
    `COMPLETE:` is. The comparison is on the FIRST WORD alone: anything after it
    is that reason's own prose, and grading it would re-admit prose as the thing
    being measured -- the defect `PIN_DECLARED` above already replaced once.
    """
    return _grade_head(reason) in GRADE_TAGS


def _grade_head(reason: str) -> str:
    """The reason's grade as ONE upper-cased word, or `""` when it has none.

    R2422 — extracted so the population predicate and the PARTIAL/COMPLETE split
    cannot drift apart again. They already did once: `_is_graded` stopped
    splitting on a colon at R2418 and the split did not, which reported every
    paren-headed atom in the population as COMPLETE. A shape read in two places
    is a shape that will be read two ways, so there is now one reader.
    """
    head = GRADE_HEAD.match(reason)
    return head.group(1).upper() if head else ""


#: Seeded at what `--count` PRINTS for this commit's PARENT: 61.
#:
#: Derived, not remembered. 62 graded reasons name the stale version there; one
#: of them, `transport-stats`, already carries the pin marker because R2371
#: re-declared it, which leaves 61 in the population.
#:
#: 61 -> 60 (R2394). The round re-measured `access-downsampling` against the pin,
#: found the refutation described above, BUILT the missing kind rather than
#: re-tagging, and re-declared that atom -- this ratchet's "removed one"
#: direction. The split was 43 PARTIAL / 17 COMPLETE after the move.
#:
#: 60 -> 59 (R2396). `declare-token`, and it is the case that taught this gate
#: what its own number MEANS -- see WHAT THE COUNT IS BELOW. R2383 had already
#: re-measured that atom at the pin and written the result down; what was
#: missing was the DECLARATION, not the measurement. This round re-verified both
#: of its claims by reading the pin -- the envelope writes ext_qos only when it
#: differs from DEFAULT and counts it into the header's Z flag, and the body's
#: extension chain is still consumed while that flag rides -- found them true,
#: repaired the two dead paths they cited, and stamped the marker. The split was
#: 43 PARTIAL / 16 COMPLETE after the move.
#:
#: 59 -> 58 (R2398). `declare-subscriber`, the sibling `declare-token` shares an
#: R2383 correction block with. Its two dead paths were PREDICTED from that
#: shared block and then CHECKED rather than assumed -- the right order, because
#: R2383's own closing paragraph warns that a shared block is not a shared
#: verdict, and `declare-keyexpr` proves it by sharing the block and staying
#: PARTIAL. Both pin claims re-read, the tree-side witness re-RUN rather than
#: cited: 535 tests pass where that reason still records 530, so the frozen
#: count had drifted by five. The split was 43 PARTIAL / 15 COMPLETE.
#:
#: 58 -> 57 (R2399). `declare-interest`, and it is the FIRST of these moves on a
#: PARTIAL rather than a COMPLETE: the grade does not change, only the
#: declaration and two dead paths. Both had a `zenoh/` segment that does not
#: belong before `commons/`, and repairing them is what let the two claims be
#: re-read at the pin -- `AGGREGATE` still has no upstream producer, and the
#: Interest codec still writes ext_nodeid only when it differs from DEFAULT.
#:
#: ⚠ THE OBVIOUS GENERALISATION IS FALSE and was measured before being acted on.
#: `zenoh/` is a REAL upstream directory: the pinned checkout holds `zenoh/` and
#: `commons/` as SIBLINGS at its root, so 19 of the 21 distinct citations rooted
#: at `zenoh/` in this store are correct exactly as written. Only a `zenoh/` placed
#: before `commons/` is wrong. Strip that segment ONLY when the full path misses
#: and the stripped one hits; a bulk edit breaks nineteen to fix two. A third
#: state resolves neither way -- the `router.rs` under `zenoh/src/net/routing/`,
#: cited by
#: `router-multicast-faces` -- and that is upstream restructuring under a stale
#: grading, needing a re-measurement rather than a path edit.
#:
#: The split was 42 PARTIAL / 15 COMPLETE.
#:
#: 57 -> 56 (R2400). `routing-namespace`, and this one was chosen to REFUTE
#: rather than to be cheap: a COMPLETE grade resting entirely on one round's
#: arm-for-arm walk of a 283-line upstream module. The re-measurement came back
#: NEGATIVE -- at the pin the module is 286 lines, every function in it was read,
#: and what that walk recorded is still what upstream does. wz mirrors the whole
#: ingress mechanism structure by structure, incomplete-declaration map and all
#: four blocked-id sets included.
#:
#: A NEGATIVE RESULT IS A MEASUREMENT. This is the first move here that reads an
#: atom NOBODY had read at the pin -- the previous three moved atoms whose prose
#: already asserted a pin reading -- so it costs a full walk and buys the same
#: one count. That is the honest price of the remaining population, and a round
#: that only takes the cheap ones will leave the expensive ones unread.
#:
#: The split was 42 PARTIAL / 14 COMPLETE.
#:
#: 56 -> 55 (R2401). `scouting-responder`, a second expensive-half read. The
#: grade HOLDS -- upstream's source-election rule is unchanged at the pin -- but
#: one MECHANISM clause under it has rotted: the reason justifies wz dropping a
#: socket whose address cannot be read by calling that upstream's own filter, and
#: at the pin the socket type carries its interface address as an EAGER field, so
#: no such filter exists at election time. A rotted justification under a
#: conclusion that still holds is the same shape as a dead path, and is recorded
#: rather than dropped.
#:
#: ⚠ THE SAME ROUND AUDITED ITS OWN FIRST MOVE, and found the gap this gate's
#: docstring warns about. R2394 declared `access-downsampling` on the strength of
#: the one claim it re-read and BUILT for, and carried three subsidiary clauses
#: forward unread. All three were read at the pin in R2401 and all three HOLD, so
#: the declaration was correct -- but it was under-verified when made, and the
#: difference between "right" and "known to be right" is what the marker is for.
#: The atom now carries that provenance itself.
#:
#: The split was 42 PARTIAL / 13 COMPLETE.
#:
#: 55 -> 54 (R2402). `declare-final`, chosen by a criterion R2401's audit forced:
#: an atom whose claim set is small enough to read TO THE END, so its marker
#: means the strong thing. All four of its upstream claims were read, not merely
#: resolved, and all four hold. The fourth is an ABSENCE -- pico's write-filter
#: switch has no case for a FINAL -- and was tested by counting the token that
#: must not appear, because an anchor can only witness presence.
#:
#: The split was 42 PARTIAL / 12 COMPLETE.
#:
#: 54 -> 53 (R2403). `runtime-tokio`, and what kept it in the population was a
#: SPELLING: it already said its grade was re-measured at the pin, but wrote
#: "PIN RE-DECLARATION" where this gate reads the exact token below. Measured,
#: not declared. Re-verified on a full reading before the token was stamped --
#: all six anchored upstream claims resolve and the load-bearing one was read for
#: substance, five subsystems with rx at two workers, the rest at one, fifty
#: blocking threads.
#:
#: ⚠ THE SPELLING IS EXACT ON PURPOSE, and the population shows what that costs
#: and buys. One atom near-missed the token; SEVEN more assert a pin reading in a
#: third spelling ("measured against the pin"). Widening the pattern to catch
#: them is the wrong repair -- it would re-admit prose as the thing being graded,
#: which is the defect the marker replaced. Each is paid by reading its claims
#: and stamping the one token.
#:
#: The split was 42 PARTIAL / 11 COMPLETE.
#:
#: 53 -> 52 (R2405). `access-extauth-usrpwd`, the second atom kept in the
#: population by a SPELLING alone: R2339 re-measured it at the pin and wrote so
#: in a third phrasing. Verified in FULL before stamping -- all five upstream
#: anchors still resolve and all three wz-side clauses still hold, the last of
#: them an ABSENCE (no crate defines either user-mutation verb), checked by
#: counting definitions across the crate tree rather than by resolving an anchor.
#: Tag untouched at PARTIAL; the residual clauses are confirmed, not withdrawn.
#:
#: The split was 41 PARTIAL / 11 COMPLETE.
#:
#: 52 -> 51 (R2406). `ext-pubsub-serde-codec`, taken from the NEVER-READ half and
#: taken for refutation odds rather than cheapness: a serialization-format atom
#: is where a version move would land on the wire, and every residual in it has
#: the form "upstream has X, wz does not", which a move can void from either
#: side. None was voided -- all six subjects still exist upstream, so the gap
#: list is confirmed rather than trimmed, and the wire residual is still
#: API-reachable because the length wrapper is still a public struct with both
#: halves implemented on it.
#:
#: The split was 41 PARTIAL / 10 COMPLETE.
#:
#: 51 -> 49 (R2407 + R2408, two atoms in one commit).
#:
#: `transport-link-unixpipe` (R2407) is the THIRD atom held here by a spelling
#: alone, and it was declared across a round boundary on purpose: R2406 verified
#: its four upstream anchors and REFUSED to stamp on that basis, because its
#: prose carries a clause retracted as stale only after eight atoms shared it.
#: Its population claim was then checked by its own instrument rather than
#: re-counted -- the link-config-keys gate reproduces the eight-key figure the
#: reason states.
#:
#: `rest-sse-subscribe` (R2408) is THE FIRST RESIDUAL THIS SWEEP REFUTED. It
#: claimed upstream undeclares and terminates an SSE stream on a ten-second
#: write timeout; neither mechanism exists at the pin -- no such duration and no
#: undeclare anywhere in that plugin. Upstream subscribes through a FIFO handler
#: that BLOCKS when full, so the divergence survives with a different shape:
#: block versus drop-newest, not terminate versus drop-newest. Four atoms in a
#: row had confirmed their residuals before this one refuted its, which is why a
#: run of confirmations is not evidence that re-measuring is ceremonial.
#:
#: The split was 40 PARTIAL / 9 COMPLETE.
#:
#: 49 -> 48 (R2408). `router-multicast-faces`, and the FIRST move here that
#: shipped PRODUCT CODE rather than a declaration. Its third residual said the
#: multicast egress core was gated on the wrong feature, so turning the atom off
#: did not remove the plane; measured before the edit, a build without the atom's
#: feature compiled the whole plane. Every gate site in the router forwarder now
#: names the atom's own feature. Safe by construction -- that feature implies the
#: one it replaces, so it is strictly a narrowing -- and RIGHT by discriminator:
#: the production caller was already gated on the atom's feature, so the callee
#: was the half that disagreed.
#:
#: The split was 39 PARTIAL / 9 COMPLETE.
#:
#: 48 -> 45 (R2409 + R2410 + R2411, three atoms in one commit).
#:
#: `time-hlc` (R2409): all four upstream claims hold, but one had to be chased
#: past a FAILED first check -- the reason quotes the auto-stamp expression with
#: one field missing, so a needle on it MISSES while the capability is intact one
#: level deeper. A miss is a question, not an answer; reading that first check as
#: a refutation would have discarded a residual upstream still has.
#:
#: `scouting-static` (R2410): a THIRD membership cause for this population. Not a
#: stale grading and not a missing declaration -- a version label naming an
#: upstream the atom never graded against. Its header says "vs zenoh-pico / zenoh
#: 1.5.0" while every residual measures against pico and it holds zero anchored
#: zenoh claims. Its pico line ranges are still ACCURATE, because a vendored
#: submodule moves only when this tree bumps it: the citation rot this sweep kept
#: finding is a property of citing an independently moving upstream.
#:
#: `session-extauth` (R2411): the cheapest full reading left, and cheap for a
#: reusable reason -- a prior round had already restated its upstream halves as
#: NEEDLES, so all six are commands rather than judgements. An atom whose claims
#: are anchored can be re-verified end to end in one pass; one carrying the same
#: claims as line numbers cannot be verified at all without re-deriving them.
#:
#: The split was 36 PARTIAL / 9 COMPLETE.
#:
#: 45 -> 43 (R2412 + R2413, two atoms in one commit).
#:
#: `declare-keyexpr` (R2412) is the FIRST READING on this seam rather than a
#: missing declaration -- its text never names the pinned version at all -- and
#: it was still the cheapest available, because a previous round had converted
#: its upstream halves to ANCHORED form. Eleven claims, all resolving in one
#: pass: the largest anchored set re-verified here, at less cost than atoms a
#: third its size whose claims are line numbers. Its residual is wz-side and
#: BUILDABLE BUT NOT SMALL -- the wire-expression arm is a type-level refinement
#: made in the codec's SCXML source, so closing it is a codegen change.
#:
#: `access-acl` (R2413) is the sixth spelling variant. Both clauses hold on both
#: halves, and the cross-atom CHAIN is now verified end to end: the username
#: subject axis cannot be built until the usrpwd handshake keeps that value, and
#: R2405 confirmed at the pin that wz's accept path discards it. A reader
#: deciding what to build starts at the handshake atom, not this one.
#:
#: The split was 35 PARTIAL / 8 COMPLETE.
#:
#: 43 -> 41 (R2414 + R2415, two atoms in one commit), and this pair marks an
#: INFLECTION worth planning around: of the 43 atoms in the population when the
#: round began, FORTY-ONE carried zero anchored claims. The cheap, mechanically
#: checkable ones are now spent. What is left carries its claims as line-form or
#: root-less prose, which a reader must judge rather than a command settle, so
#: the per-atom cost of every remaining round is structurally higher.
#:
#: `routing-router` (R2414) needed THREE KINDS of test for seven claims: an
#: anchor resolved for a presence claim, three absences COUNTED TO ZERO (the
#: withdrawn failover-brokering capability, which an anchor cannot witness), and
#: three wz-side reads. It also demonstrates the line-number argument inside a
#: single reason: its HEADER places a mapping at three digits where it now sits
#: at four, six thousand lines later, while the CORRECTION cites the same fact by
#: needle and is unaffected.
#:
#: `liveliness-history` (R2415): five claims across BOTH references, all holding,
#: and its last standing clause is parity that must NOT be built -- replaying
#: locally held tokens would diverge from zenoh and pico alike. A residual saying
#: "do not fix this" is worth as much as one saying what to build, and is the
#: kind a re-measurement can silently invert if nobody re-reads it.
#:
#: The split was 34 PARTIAL / 7 COMPLETE.
#:
#: THE R-NUMBERS ABOVE ARE NOT LEDGER ENTRY IDS. The four labels R2412..R2415
#: name ATOMS, two to a commit, while the ledger filed those two commits as
#: `Round 2410` and `Round 2411`; a reader cannot resolve "R2414" to any entry.
#: The ledger is this workspace's SSOT for round numbers (CLAUDE.md), so from
#: here the provenance below cites the ENTRY ID and nothing else.
#:
#: 41 -> 40 (ledger `Round 2412`, one atom).
#:
#: `locator-iface` is the first COMPLETE atom taken after that inflection, and
#: it shows what the inflection actually costs. Its seven upstream claims were
#: written root-less, so the store citation gate had never graded ONE of them --
#: the atom contributed zero to every bucket, anchored and defective alike. A
#: grade two versions old could therefore sit here with no instrument able to
#: object, which is the mechanism this whole item exists to close and not merely
#: an untidy spelling. Re-measured at the pin the grade HOLDS, and the round's
#: product is the conversion: fourteen anchored citations where there were none.
#:
#: THE RE-MEASUREMENT FOUND ONE CLAIM STATED BACKWARDS. The reason listed `ws`
#: inside a clause about honouring the locator tail the way upstream does; at
#: the pin upstream honours it on NEITHER ws arm, so wz does MORE there. A
#: clause that reads as parity while naming an extension is the failure mode a
#: later reader cannot detect, because both halves are individually true.
#:
#: It also confirms the citation-rot shape from the other direction. The quic
#: route MOVED crates -- upstream consolidated quic socket construction into a
#: module shared by quic and quic-datagram, the same one-SSOT choice wz made at
#: y454 -- so the old location no longer finds it while the fact is unchanged. A
#: needle survives that move; a path with a line number does not.
#:
#: The split is 34 PARTIAL / 6 COMPLETE.
#:
#: R2414 moved it to 39 by re-declaring `adminspace-metrics`, and this one paid
#: in PRODUCT rather than in prose. Re-measured at the pin, the metrics leg had
#: drifted on FIVE axes at once, four of them in bytes a foreign consumer reads:
#: the ENCODING (the pin's `application/openmetrics-text; version=1.0.0;
#: charset=utf-8`, predefined id 15 plus schema, where wz sent text/plain), the
#: TYPE (`info`, not `gauge`), the SAMPLE NAME (`zenoh_build_info`, not
#: `zenoh_build`), the LABELS (`local_id` and `local_whatami` beside `version`),
#: and the missing `# EOF` terminator. All five are fixed.
#:
#: THE ORDERING RULE THE ROUND HAD TO FIND BEFORE WRITING THE CODE. OpenMetrics
#: ends at `# EOF`, and this node appends its transport-stats block AFTER the
#: build-info block -- so copying upstream's literal, terminator included, into
#: `metrics_text` would have buried the counters behind the end of the document.
#: The terminator is its own function the caller appends last, and the
#: composition test runs with transport-stats ON, the only configuration where
#: that ordering can be wrong.
#:
#: AND A DEFECT IN THE ROUND'S OWN PREVIOUS WORK, found by auditing it rather
#: than by a test. R2413's surface manifest rendered every encoding name through
#: a two-arm helper whose else-branch answered `application/json`, and its gate
#: built BOTH the declared and the observed name through that helper -- so this
#: very change would have left both sides agreeing on a wrong name: green gate,
#: lying document. Measured with the old helper restored and both sides moved:
#: the manifest gate reported ok while an outside test failed. The helper now
#: derives from the encoding module's id/MIME SSOT.
#:
#: The split is 33 PARTIAL / 6 COMPLETE.
#:
#: R2415 moved it to 38 by re-declaring `adminspace-core`, and what that
#: re-measure retracted is the sharpest instance of this item's whole argument.
#: `AdminLocalData::to_json`'s own doc asserted it "matches those bytes exactly"
#: against upstream. Graded against 1.5.0 and never rechecked, that assertion is
#: FALSE at the pin -- and it is a falsehood no gate can catch, because a reader
#: has no reason to doubt a doc comment that names byte-exactness. A stale grade
#: does not merely age; it keeps asserting.
#:
#: FOUR FIELDS, FOUR DIFFERENT SITUATIONS, and the finding is that they are not
#: one gap: `shm` was never missing (wz negotiates it and simply did not report
#: it -- closed here, in the alphabetical slot upstream's BTreeMap emits);
#: `region` is upstream's own recent addition with no wz analogue, an honest
#: ABSENCE that must not be written up as parity; `weight` is router-tier and
#: was already named as a follow-up; `metadata` is a config-surface question.
#:
#: AND THE ROUND WAS TAUGHT BY A GREEN CONTROL. The wiring passed every test --
#: and so did replacing it with a constant. Nothing tied the runtime's value to
#: the session's negotiation, so a field that always reports the same thing was
#: indistinguishable from one that reports nothing. The fix was the missing
#: witness, not deleting the probe: with the wiring 8 pass, with the constant 7
#: pass and exactly the new test fails. The forwarder host, reachable only from
#: wz-ap-demo, took its witness in Layer E12 instead -- and that leg is scoped in
#: its own comment to EMISSION, since a pico client negotiates no SHM.
#:
#: The split is 32 PARTIAL / 6 COMPLETE.
#:
#: 38 -> 37 (ledger `Round 2417`) by re-declaring `transport-multicast`, and it
#: is the first move here whose membership cause is an EXEMPTION rather than a
#: version string. That atom's closing sentence read "the parity target is pico
#: rather than zenoh -- this reason declares no zenoh 1.5.0 and so owes no pin
#: re-measurement", and the only occurrence of the stale version in the whole
#: reason was inside that denial. So this population has a FOURTH membership
#: cause beside the three R2410 recorded: a reason that names the version only
#: to argue it is not measured against it.
#:
#: THE EXEMPTION IS FALSE AT THE PIN, which is why the count could move at all.
#: `io/zenoh-transport/src/multicast/` is a 2153-line multicast transport whose
#: subjects are exactly that atom's -- a JOIN beacon on a `join_interval`
#: timer, lease-driven peer expiry through `close::reason::EXPIRED`, a Close on
#: teardown, and a per-peer receive record. An atom is not exempt from one
#: reference because a second reference is closer to it, and an exemption is a
#: grading claim that no instrument in this tree could object to -- item 675's
#: whole argument, arriving as a clause instead of as a number.
#:
#: AND THE RE-MEASUREMENT REFUTED TWO SENTENCES IN THE PRODUCT CODE, not in the
#: reason. The multicast reassembly ingest asserted that "a multicast Join
#: advertises no `0x7` ext and there is no per-peer Init exchange to take a
#: `min()` over", and that upstream's marker gate reads "the manager config
#: rather than a per-peer negotiation". Both references carry the extension ON
#: THE JOIN by name, and both hold the negotiated `min()` as a field of the
#: per-peer record. A comment that names an ABSENT protocol feature is the
#: sharpest form of R2415's finding: a reader has no reason to doubt it, and no
#: gate can read it.
#:
#: The round's product is the four seams that were missing under it: the beacon
#: announces this node's level, the QoS ext carries the chain-MORE bit when the
#: Patch ext follows, the announced level is read by WALKING the chain (it sits
#: second on a qos beacon and first on a non-qos one, so a positional reader
#: finds it in one beacon shape of two), and the negotiated `min(CURRENT,
#: announced)` is a per-peer slot field that arms the chain-boundary rules per
#: fragment. Seven control probes, one of which found a hole in the round's own
#: wire-level witness -- a marker-less fixture cannot tell a discarded marker
#: from an absent one -- which was closed rather than noted.
#:
#: The grade STAYS COMPLETE, and the residual the re-measurement opened is
#: filed as register item 684 against a different atom: wz's multicast emit
#: builds its whole fragment chain before a byte leaves, so it can never send
#: the `0x3 Drop` the round's RX half now honours. That is the fragment EMIT's
#: gap, which `transport-fragmentation` claims as its subject; holding
#: `transport-multicast` PARTIAL for it would double-count one gap across two
#: atoms, which is the rule that atom's own text states.
#:
#: The split is 32 PARTIAL / 5 COMPLETE.
#:
#: 37 -> 41 (ledger `Round 2418`, open-debt item 686) — AND THIS IS THE ONE MOVE
#: IN THIS FILE'S HISTORY THAT GOES UP. Every entry above moves it DOWN, because
#: down is a round paying an atom; the failure message a few lines below says in
#: so many words never to raise it. Read it anyway, because the message cannot
#: tell these two apart:
#:
#:   * the tree got WORSE — an atom was graded against the stale version. Repair
#:     the grading. The budget does not move.
#:   * the GATE started SEEING — the population predicate was repaired, so atoms
#:     that were always stale are now counted. Nothing about the tree changed.
#:
#: This is the second. `_is_graded` above replaced a colon-sensitive
#: `startswith` test, which had been silently excluding nine reasons whose head
#: reads `PARTIAL (` or `COMPLETE (`. FOUR of the nine are stale, so the count
#: rises by exactly four and the graded population by exactly nine: 37 -> 41 of
#: 132 -> 141. Both deltas were derived BEFORE the edit landed and are the
#: check on it.
#:
#: The four that entered, named so a later round cannot mistake them for new
#: debt: `session-extqos` and `storage-mgr-dynamic-volume-loading` (PARTIAL),
#: `storage-aligner` and `storage-replication` (COMPLETE). The last two are the
#: reason item 686 is ranked critical rather than ordinary — a COMPLETE graded
#: two versions back is a false statement, and these two carried it where this
#: gate could not look.
#:
#: ⚠ WHAT THIS MOVE DOES NOT CLAIM. It does not pay any of the four down; it
#: makes them countable. Item 675's own done condition is "the derived
#: population is 0", and before this commit that zero was reachable while four
#: stale gradings sat outside the derivation — the completion condition was
#: false-reachable, which is the whole of item 686.
#:
#: ⚠⚠ AND THE CONTROL PROBE FOUND THE MIRROR OF THE SAME BLIND SPOT, in the
#: DOWN direction, which the paragraph above only claimed for UP. Restoring the
#: old colon-sensitive predicate takes the count to 37 of 132 and this gate
#: reports "37 < 41 -- this commit re-measured an atom against the pin". No atom
#: was re-measured; the POPULATION was narrowed. So neither direction's message
#: can distinguish a round paying an atom from a round moving the predicate, and
#: a future edit to `_is_graded` will be told the wrong story by this file's own
#: output. The discriminator is the graded TOTAL beside the stale count: an atom
#: paid down moves the stale count alone (41/141 -> 40/141), while a predicate
#: change moves BOTH (37/132 vs 41/141). That pair is printed on every run for
#: exactly this reason; read both numbers, never the stale one alone.
#:
#: The split is 32 PARTIAL / 9 COMPLETE.
#:
#: 41 -> 40 (ledger `Round 2419`) by re-declaring `storage-aligner`, and it is
#: the FIRST atom paid out of the nine the R2418 predicate repair made visible.
#: The stale count moved ALONE (41 -> 40, graded holding at 141), which is the
#: discriminator written into the note above: an atom paid down moves one
#: number, a predicate change moves both.
#:
#: ITS MEMBERSHIP CAUSE WAS A LABEL, NOT A STALE GRADE, which is R2410's third
#: cause and R2396's finding about what this count means. The single `1.5.0` in
#: that whole reason names THIS MACHINE'S ORACLE BINARY (open debt 638), not the
#: upstream the atom was measured against. It was already graded at the pin and
#: lacked only the declaration.
#:
#: THE ROUND'S PRODUCT IS A CORRECTED COUNT, not a relabelling. That reason
#: claimed "Seven cases in storage_state tests
#: aligner::wildcard_align::wildcard_production" and the module holds EIGHT, so
#: its "reds 6 of 7" is really 6 OF 8. Read from the binary (`running 8 tests`),
#: not counted over the file -- and the first attempt reported `running 0 tests`
#: at rc=0, because that module needs `storage-mgr-wildcard-updates` on top of
#: `storage-aligner`. rc=0 with zero tests is a dead probe, never an absence.
#:
#: All four of its probes were RE-RUN rather than inherited: red sets of 8 are
#: 6 / 1 / 1 / 1, the last three singletons and PAIRWISE DISJOINT, so the sites
#: really are separated. Two cases survive every probe, one of them the negative
#: guard the reason itself predicted would. The three upstream citations all
#: resolve at the pin, checkable only because a prior round wrote them as
#: `path` @ `needle` instead of line numbers.
#:
#: The split is 32 PARTIAL / 8 COMPLETE.
#:
#: R2420 40 -> 39, `storage-replication` -- the sibling COMPLETE of the pair
#: R2418 exposed, and the SECOND consecutive round whose membership cause was a
#: LABEL. Both `1.5.0` occurrences in that reason are one clause plus its own
#: CORRECTION quoting it, and both name the ORACLE BINARY (open debt 638); R2354
#: had already re-read the Digest shape, the `diff` algorithm and the bincode
#: framing at the pin. Every upstream claim was re-read again here and none had
#: moved -- the struct, `DigestDiff`, the retain-on-`other` diff walk, the whole
#: publisher schedule, `determine_action`, bincode 1.3.3, xxhash-rust 0.8.
#:
#: WHAT THE RE-READ FOUND WAS THE FOUNDATION, NOT THE CONCLUSION. That atom's
#: cross-impl claim rests on one captured literal, `ZENOHD_CONFIG_FINGERPRINT`,
#: and TWO checks pin it while BOTH read only wz -- the Layer Z assertion, and
#: `config_fingerprint_recipe_matches_zenoh_field_order`, whose own doc calls
#: itself "a recipe lock, not an independent oracle". An upstream field added,
#: reordered or widened leaves both green. The lock locks the lock, so the round
#: built `replication_fingerprint_recipe_gate.py` to open the upstream side.
#:
#: ⚠ AND ITS FIRST DIAGNOSIS WAS FALSE INSIDE THE HOUR: "cargo test cannot fail
#: on a recipe drift" is refuted by a probe -- swapping wz's `hot` and `warm`
#: reds that test (`running 444 tests`, 1 failed). The wz half had an instrument
#: all along; the claim shrank to the half that had none, and the probes that
#: red BOTH instruments were written up as discriminating nothing.
#:
#: The split was reported as 32 PARTIAL / 7 COMPLETE. It was 33/6 -- see below.
#:
#: 39 -> 38 (R2422). `session-extqos`, the third membership-by-LABEL in a row and
#: the third of the four atoms R2418 made countable. Its single `1.5.0` is
#: "CROSS-IMPL PROVEN vs a live zenohd 1.5.0", the ORACLE BINARY again (open debt
#: 638); every P= and C= claim in it cites the source with no version at all. So
#: the DECLARATION was missing, not the measurement -- but the round was not free,
#: and what it cost bought two findings.
#:
#: THE REFUTATION WAS IN PRODUCT CODE, and it is R2417's class exactly: the atom's
#: own SSOT module opened by asserting wz "EMITS the presence-only UNIT form",
#: that the QoSLink priority-range semantics "are deferred", and that the module
#: "is the codec LAYER only". All three are refuted by the SECOND HALF OF THE SAME
#: FILE -- the emit-form chooser, the z64 body codec, and the two containment
#: merges -- and one item doc still said wz "never emits QoSLink ... yet". A stale
#: grading asserting a protocol ABSENCE in a comment, outliving the rounds that
#: built the thing it denies. Seventeen of that atom's upstream citations were
#: re-read one by one and FOURTEEN were wrong at the pin, none of them graded by
#: anything: the ext pair moved when `RegionName` was inserted above it, both
#: `link.reconfigure` sites moved, the egress select moved, the acceptor's
#: src-endpoint seed moved, and the TCP link crate MOVED PATH. All seventeen are
#: now anchored.
#:
#: AND THE ROUND FOUND THIS FILE'S OWN RESIDUAL OF ITEM 686, by tripping over it:
#: the PARTIAL/COMPLETE split still split on the colon R2418 removed from the
#: population, so every paren-headed atom was tallied as COMPLETE and `--list`
#: printed a parenthetical where a grade belongs. Repaired with one shared head
#: extractor; the true split at this budget is 33 PARTIAL / 5 COMPLETE, and every
#: split figure the R2418..R2421 notes recorded understated PARTIAL. The COUNTS
#: those rounds ratcheted were always right -- only the split was wrong.
#:
#: 38 -> 37 (R2423). `rest-http-bridge`, and it moved as a SIDE EFFECT of paying
#: open-debt item 688 rather than as a sweep pick -- the item's own text told the
#: round to check whether the two §5.26 atoms still declared 1.5.0 and to move the
#: declaration with a measurement if so, because they sit on the seam it was
#: closing. Its sibling `rest-sse-subscribe` needed nothing; R2408 had already
#: re-declared it.
#:
#: BOTH STILL-OPEN RESIDUALS CONFIRMED AT THE PIN, which is the outcome this
#: ratchet is least often used for and the one worth recording. The adminspace
#: status leg is still upstream:
#: `plugins/zenoh-plugin-rest/src/lib.rs` @ `fn adminspace_getter<'a>(`
#: and so is the config surface:
#: `plugins/zenoh-plugin-rest/src/config.rs` @ `pub work_thread_num: usize,`
#: (each kept on ONE line: this file's `#:` continuation prefix is not one the
#: anchor parser can step over, so a citation split across two of them silently
#: degrades to the BARE form and spends that budget -- measured here, by doing
#: it).
#: The atom stays PARTIAL on both. Nothing was discharged; only the DECLARATION
#: moved, from a version this tree does not pin to the one it does.
#:
#: WHAT THE RE-MEASUREMENT ACTUALLY CHANGED, and it is not in the residual list:
#: the atom's A4 line claimed `rest-http-bridge` was "PROVEN both directions" by
#: the zenohd-interop oracle, and at the pin that leg was RED -- an HTTP PUT into
#: wz's bridge answered 500. So the stale half was not the residuals it grades
#: but the PROOF it rests on. The cause was two layers below this atom (a sealed
#: writer queue the F2 send gate could not see, R2423's own subject), and the
#: bridge's share of it was that its 500 discarded the typed error where upstream
#: puts it in the body. Both are now recorded on the atom.
#:
#: ⚠ THE LESSON, filed here because this ratchet is what makes it findable: an A4
#: "PROVEN" line is a claim about a RUN, and it decays with nothing editing the
#: atom. Neither §5.26 reason was wrong when written -- the tree moved underneath
#: them, and only re-running the oracle said so. A grading-pin sweep that only
#: re-reads the RESIDUALS will not catch this class; the proof line needs running.
#: 37 -> 36 (R2425). `session-reconnect`, and the first atom in this series whose
#: re-measurement changed what a residual MEANS rather than whether it holds.
#: Four residuals, each re-measured at the pin instead of re-worded:
#:
#:   * re-scout and multi-locator failover needed no upstream read at all -- the
#:     atom's OWN later stratum (R2376) already answers them and ships the
#:     mechanism. A reader hitting the earlier clause first believes the gap is
#:     open; it closed thirty lines below, which is the hazard of grading an
#:     accreted reason by its first matching sentence.
#:   * "no exponential backoff" is FALSE as written. Upstream still grows its
#:     delay and its shipped default doubles to a ceiling, but wz has the
#:     mechanism too (R311y526) under upstream's own field names. Only the
#:     DEFAULT differs -- wz ships a factor of 1.0, a constant delay, chosen for
#:     pico parity. A chosen default, not a missing capability.
#:   * "no multicast reconnect" is a SHARED ABSENCE: upstream joins the group at
#:     construction only and nothing re-establishes a lost multicast transport,
#:     while unicast does have retry. So it is not a divergence, and listing it
#:     as one overstated wz's gap.
#:
#: ⚠ THE METHOD IS THE PART WORTH COPYING, because three of this round's own
#: first readings were wrong and each was wrong the SAME way -- one half measured
#: and the other assumed. "One residual" was four; "the line rotted" was intact;
#: "the residual is live" was already implemented in wz. A residual names two
#: sides, so count the implementers on BOTH before writing the sentence.
#:
#: ⚠ And the multicast half nearly produced a fourth: `reconnect` appears nowhere
#: in upstream's transport layer, so a term search returns an invalid negative
#: rather than an absence. It was settled by reading the JOIN SITE.
#:
#: A CITATION DEFECT FOUND WHILE MEASURING, of the ungraded kind: the backoff
#: clause cited its upstream module without the `commons/` root, and upstream
#: keeps `zenoh/` and `commons/` as siblings, so the path resolved under no root
#: and sat in no budget -- present, wrong, and invisible to every anchor gate.
#: 36 -> 35 (R2426). `query-target`, and here the VERDICT was the cheap half: the
#: claim its close criterion rests on still holds at the pin, almost verbatim --
#: upstream's queryable filter applies the completeness term as its own
#: unconditional conjunct while `local` gates only the locality term. What the
#: re-measurement actually bought was the CITATION FORM.
#:
#: Both halves of the old pointer were defective, and in ways this tree grades
#: differently. The LINE had rotted far down the file, which is rot WITHIN a file
#: and the one class an anchor-only gate structurally cannot catch. And the PATH
#: began at `src`, while upstream keeps `zenoh/` and `commons/` as siblings -- so
#: it resolved under no root and therefore sat in NO BUDGET. That is worth
#: separating from "a weak citation": an unrooted citation is UNGRADED, and an
#: ungraded citation is indistinguishable from a passing one, which is why two of
#: these can sit in a COMPLETE atom for versions without anything objecting.
#:
#: The replacement needle occurs exactly ONCE in that file, which is what makes
#: the line-to-anchor conversion sound rather than merely tidier -- an anchor on
#: a needle with several matches would resolve while naming the wrong site.
#:
#: ⚠ The stale pointers are NOT requoted in the new block, deliberately: the
#: store-reason census counts citation OCCURRENCES, so quoting a defective
#: citation in order to correct it ADDS one. R2360 paid for that; this round
#: declined to re-pay it.
BUDGET = 35

#: A reader that matches nothing has stopped matching the store. Well below the
#: real graded population (MEASURED at the landing commit: 312 inventory
#: entries, of which 132 open with a grade tag), so it fires on a broken reader
#: rather than on a tree that legitimately paid the debt down.
MIN_GRADED = 40


def graded_reasons(store: dict) -> list[tuple[str, str]]:
    """Every (atom id, reason) whose reason opens with a grade tag.

    Derived from the store's own inventory rather than from any list here, so an
    atom added or renamed is inside the population without an edit.
    """
    out: list[tuple[str, str]] = []
    for atom_id, entry in sorted((store.get("inventory_entries") or {}).items()):
        if not isinstance(entry, dict):
            continue
        reason = entry.get("reason") or ""
        if _is_graded(reason):
            out.append((atom_id, reason))
    return out


def stale(reasons: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """The graded reasons that name the stale version and carry no pin marker.

    Returns (atom id, grade, first line of the declaring context) so a failure
    names what to re-measure rather than only how many there are.
    """
    out: list[tuple[str, str, str]] = []
    for atom_id, reason in reasons:
        if STALE_VERSION not in reason:
            continue
        # An atom a round has RE-MEASURED at the pin is out of the population
        # even though it still names the version it was re-measured off; see
        # PIN_DECLARED for why the naive predicate counted the repair as debt.
        if PIN_DECLARED in reason:
            continue
        # R2422 — THE SPLIT USED TO TURN ON THE SAME COLON THE POPULATION DID.
        #
        # R2418 (item 686) stopped `_is_graded` splitting on `":"` and admitted
        # nine paren-headed reasons, but this line kept `reason.split(":", 1)[0]`
        # — so for `PARTIAL (BUILT R311y506, ...)` the "grade" became the whole
        # run of text up to the reason's first colon, which equals neither tag.
        # Those rows therefore failed the `== "PARTIAL"` test and were tallied as
        # COMPLETE, and `--list` printed a sixty-character parenthetical where an
        # atom's grade belongs. The COUNT was always right; the SPLIT was not,
        # and the split is what item 675's own text ranks the work by, calling
        # COMPLETE the sharper half. Measured here: 32/6 reported, 33/5 true,
        # with `storage-mgr-dynamic-volume-loading` the surviving mislabelled row
        # — so every figure the R2418..R2421 entries recorded for the SPLIT
        # understated PARTIAL by however many paren-headed atoms were in the
        # population at the time. One head extractor, used by both.
        grade = _grade_head(reason)
        where = ""
        for m in re.finditer(re.escape(STALE_VERSION), reason):
            start = max(0, m.start() - 60)
            where = " ".join(reason[start : m.end() + 20].split())
            break
        out.append((atom_id, grade, where))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--count",
        action="store_true",
        help="print the stale count alone and exit 0; the SSOT for the budget",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="print every stale atom with its grade, newest budget move first",
    )
    args = ap.parse_args()

    try:
        store = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  grading-pin-ratchet: FAIL cannot read the store: {exc}")
        return 1

    reasons = graded_reasons(store)
    if len(reasons) < MIN_GRADED:
        print(
            f"  grading-pin-ratchet: FAIL only {len(reasons)} graded reason(s) "
            f"found, below the {MIN_GRADED} floor -- this reader has stopped "
            f"matching the store, which is not the same as the debt being paid"
        )
        return 1

    rows = stale(reasons)
    count = len(rows)

    # R2422 — EVERY ROW'S GRADE MUST BE ONE OF THE TWO TAGS, or this reader is
    # reporting a split it cannot compute.
    #
    # This exists because the split silently disagreed with the population for
    # four rounds and nothing could say so: `stale()` read the grade with the
    # colon split R2418 had already removed from `_is_graded`, so a paren-headed
    # reason yielded a sixty-character "grade" that equalled neither tag, failed
    # the `== "PARTIAL"` test, and was tallied as COMPLETE. A printed number is
    # not graded by being printed. This is the guard the repair earns: it FAILS on
    # the pre-repair reader (`storage-mgr-dynamic-volume-loading` is the live
    # witness) and passes on the shared extractor, so the two readings can never
    # drift apart again without a red.
    ungraded = [(a, g) for a, g, _ in rows if g not in GRADE_TAGS]
    if ungraded:
        print(
            f"  grading-pin-ratchet: FAIL {len(ungraded)} row(s) carry a grade "
            f"that is neither {GRADE_TAGS[0]} nor {GRADE_TAGS[1]}, so the split "
            f"below would be counted wrong: "
            + ", ".join(f"{a} -> {g[:40]!r}" for a, g in ungraded[:3])
            + ". The population predicate and the split must read the reason's "
            f"grade through the SAME extractor (`_grade_head`)."
        )
        return 1

    if args.count:
        print(count)
        return 0

    if args.list:
        for atom_id, grade, where in sorted(rows, key=lambda r: (r[1], r[0])):
            print(f"  {grade:9} {atom_id}")
            if where:
                print(f"            ...{where}")

    partial = sum(1 for _, g, _ in rows if g == "PARTIAL")
    complete = count - partial
    print(
        f"  grading-pin-ratchet: {count} graded reason(s) still declare "
        f"{STALE_VERSION} (PARTIAL {partial} / COMPLETE {complete}) of "
        f"{len(reasons)} graded, budget {BUDGET}"
    )

    if count > BUDGET:
        print(
            f"  grading-pin-ratchet: FAIL {count} > {BUDGET} -- an atom is "
            f"graded against {STALE_VERSION}, which the tree does not pin. "
            f"Re-measure it against the pin and move its declaration; do NOT "
            f"raise the budget, and do NOT substitute the version string, "
            f"which makes the claim true only in its letters. Run with --list "
            f"to see which atoms are in the population."
        )
        return 1

    if count < BUDGET:
        print(
            f"  grading-pin-ratchet: FAIL {count} < {BUDGET} -- this commit "
            f"re-measured an atom against the pin, which is the direction this "
            f"ratchet is for. Lower BUDGET to {count} in "
            f"scripts/lib/grading_pin_ratchet.py, in this same commit, and say "
            f"in the note above which atom moved and what the re-measurement "
            f"changed."
        )
        return 1

    if count == 0:
        print(
            "  grading-pin-ratchet: DONE -- every graded atom declares the pin. "
            "This gate now asserts by machine what open-debt item 675 asked for."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
