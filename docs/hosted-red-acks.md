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

⚠ **R2641 broke that ordering and the row above is the evidence**: the push went
out, the ack printed, and the row was written afterwards. The cost is not
bookkeeping neatness — a row written after the fact is a row that depends on
someone remembering, which is the exact failure this file was built to end. It
is recorded rather than quietly back-dated. And writing it late has a shape of
its own: the follow-up push needs an ack too, so the repair is TWO rows in one
commit — the one that was missed, and the one the next push will use — which is
why the ordering rule says *before*.

| round | run | commit | failing steps | debt | paid |
|---|---|---|---|---|---|
| R2496 | `34393145847` | `0df6bfeb` | C0 binary-dep · C0 (armed) provenance · C1bt wz-capture | 709 | R2498 |
| R2497 | `34393145847` | `0df6bfeb` | C0 binary-dep · C0 (armed) provenance · C1bt wz-capture | 709 | R2498 |
| R2535 | `34465003136` | `6b112827` | C0 sn-res-words selftest (two jobs, one cause) · C1ce census `unstable` row | 717 | R2535 |
| R2568 | `34611269702` | `efada3a9` | E z_info drop-in link · Z same (two jobs, one cause) · A4 cross-impl accessor · C0 gate-provenance | 721 | |
| R2570 | `34640784537` | `85c21c02` | C1bn feature-gate-diagnostic · C0 lane-reach · A+B C0 (armed) provenance · E6 peer mesh | 721 | |
| R2574 | `34659495427` | `df7369ec` | C0 python-floor lint, `facade_forward_gate` imports `tomllib` (two jobs, one cause) | — | R2574 |
| R2576 | `34692815062` | `d21f7a16` | C0 gate-provenance, `netns-topology.sh` carries no citation (two jobs, one cause) | — | R2576 |
| R2577 | `34697207229` | `cb57df67` | C0 hook-gate-boundary, `gate 2z` hid its commands in an array expansion (two jobs, one cause) | — | R2577 |
| R2578 | `34701444387` | `f394e114` | C0 prose-dep-graph, a witness header's dependency clause took a pronoun subject (two jobs, one cause) | — | R2578 |
| R2585 | `34713345823` | `dbc20e6f` | C0 skip-token naming, two R2581 `zenohd` legs carried no token (two C0 jobs) · E ran the same two legs without zenohd (three jobs, one cause) | — | R2585 |
| R2639 | `34921831690` | `951d23cf` | C1ac quic e2e, `EXPIRY_MAX_SLEEP` dead under quic-without-unicast · Z oracle-pin, `zenohd-unixpipe` and `zenohd-vsock` answer `1211779c` against pin 1.10.1 (two jobs, two causes) | — | |
| R2639 | `34919206483` | `0ddc4f26` | same two jobs, same two causes — read individually, not assumed | — | |
| R2641 | `34922821640` | `96b2dedd` | the same run the R2639 row names, re-read at this push rather than inherited: Z zenohd interop (the oracle-pin red) · C1ac quic link e2e (R2638's `EXPIRY_MAX_SLEEP` fix is in and unverified) | — | |
| R2641 | `34922821640` | `96b2dedd` | the follow-up push that carries this ledger repair, refused by the same run a third time because the queue has not started a job since 05:35Z — the run for the graded tip (`34967102042`) is itself queued | — | |
| R2642 | `34922821640` | `96b2dedd` | a fourth refusal by the same run, and the row is written BEFORE the push this time, which is what the ordering rule above asks; the queue has still started no job, so `34967638510` for the previous tip is queued too | — | |
| R2657 | `35058755117` | `d084b42b` | ONE red job, item 755's standing zenohd pin, and this makes FIVE consecutive runs reduced to that single cause. Two of them are read together here because they verify this seam's last two rounds: `35056847159` (`6eaf5f62`, R2655) is the one that matters most, because it carries the new `pubsub-delete` demo feature, the widened E7b2 lane and the DELETE e2e leg — so the wire witness for `publish_delete` and the intent-queue drain is green on CI and not only on this machine; `35058755117` (`d084b42b`, R2656) then grades the interceptor retention restructure. ⚠ Read from the jobs: each run's own conclusion still says `failure`, and a reader who stopped at that word would conclude the opposite of what these two say | 755 | — |
| R2658 | `35067974395` | `f27edeb5` | ⛔⛔ THE ROW ABOVE IS WRONG ABOUT THE CAUSE, and this row is the correction rather than a repeat. Read step-by-step (`.steps[] \| select(.conclusion=="failure")`) across five runs, the cause CHANGED at R2655: `35051065695` (R2653) and `35053431232` (R2654) died at "Ensure the unixpipe zenohd ANSWERS at the pin", which is item 755; `35056847159` (R2655), `35058755117` (R2656) and `35067974395` (R2657) died at "Layer E7b — router-connect-reconcile", which is not item 755 and is R2655's own. The job NAME is identical in all five, so "the same red again" was the previous round's conclusion carried forward, not an observation. ⚠ THE SECOND HALF OF THE ROW ABOVE INVERTS: it says R2655's DELETE e2e witness "is green on CI", and that lane (E7b2) has never run on CI at all — E7b is fail-fast and dies before it. The actual defect is lane MEMBERSHIP derived twice: R2655's `wz_router_hat_config_key_delete_restores_the_default_over_the_wire` matched none of E7b's three `--skip` fragments so it ran there, against a binary with no `router-config-mutate`, and matched none of E7b2's positive filters so its own lane never selected it. This push makes both lanes name what they run (`--exact`), with the residual class registered as open debt 762 | 762 | R2658 |
| R2660 | `35082162927` | `7f1c6a70` | ⭐ THE E7b CHAIN IS CLOSED AND THIS RUN IS THE EVIDENCE. Read per step: `27 Layer E7b` **success**, `28 Layer E7b2` **success** — E7b2 executed for the FIRST TIME EVER, so R2655's DELETE-over-the-wire witness is finally graded on CI rather than only locally. The sole failure is `43 Ensure the unixpipe zenohd ANSWERS at the pin (R2647)`, which is item 755's standing red. ⛔⛔ AND THE STEP NUMBERS CORRECT THE CAUSALITY THIS LEDGER HAS BEEN ASSUMING: the pin is step 43 and E7b is step 27, so during `35056847159`/`35058755117`/`35067974395` the job died at 27 and NEVER REACHED 43 — item 755 was HIDDEN BEHIND the E7b red the whole time, and repairing E7b is what exposed it. A fail-fast lane's first repair replaces the subject; it does not green the lane. So this is not a new cause and not a regression: it is the older one, visible again | 755 | — |
| R2661 | `35088338233` | `58b56d0e` | ONE red job, ONE red step, read per step: `43 Ensure the unixpipe zenohd ANSWERS at the pin (R2647)` — everything before it green, so the E7b/E7b2 repair holds on a SECOND run over a different tree, which is the independent confirmation the R2660 row could not give itself. ⛔⛔ AND THIS ROW CORRECTS A NUMBER THIS LEDGER HAS BEEN COPYING. COUNTED, not estimated: of 37 rows, 18 name the zenohd pin red in their own text, and **13 of those 18 cite open debt item 755**. Item 755 is gate 2c's `cancelled`-is-not-supersession classification and has nothing to do with an oracle binary; the item that OWNS this step is **758**, "CI trusts a RESTORED cache artifact without reading it", whose body quotes `oracle-pin-gate: STALE target/zenohd-unixpipe` verbatim. The R2647 and R2649 rows had it right (`758, 755`); the rows after them dropped the 758 and kept the 755, three of them written by me AFTER I had written the lesson against exactly this. ⚠ AND 755 IS NOT ALWAYS WRONG HERE, which a reader acting on this row must not lose: the R2643 / R2644 / R2645 rows cite it for a CANCELLED run, which is precisely its subject. The defect is those 13, not the citation itself. (To re-count: split rows on UNESCAPED `|` — this file escapes a `|` inside backticks — then separate by whether a row's own text names the pin.) ⚠ THE FIX IS NOT "CHECK THE NUMBER". A `debt` cell is an UNVERIFIABLE citation: `gate_provenance_lint` asks only whether a cited item EXISTS, and 755 exists — it is simply about something else, so no gate can catch this and none will. The repair is to write down something a reader can RE-DERIVE, which is why every row from R2660 on names the failing STEP: a step name comes back from `gh api .../jobs` for that run, and an item number comes back from nothing. Frozen rows are corrected by a new row, never rewritten | 758 | — |
| R2662 | `35101414755` | `cb9be180` | ONE red job of 21, ONE red step, read per step: `26 Layer E7` **success**, `27 Layer E7b` **success**, `28 Layer E7b2` **success**, `43 Ensure the unixpipe zenohd ANSWERS at the pin (R2647)` **failure**, and `47`, its vsock twin, **skipped** behind it. Third consecutive run whose only failure is step 43, so the E7b/E7b2 repair is settled on a third independent tree. ⛔⛔ AND THIS ROW REFUTES THE DIAGNOSIS ITEM 758 IS FILED ON, from this run's own log rather than from the item. 758 says a POISONED CACHE ENTRY is restored and never read; R2647 built the reader; this run shows the reader REBUILDING and landing on the same answer — `REBUILD target/zenohd-unixpipe -- binary says 1211779c, pin says 1.10.1`, then `FAIL -- still STALE after a rebuild`. A rebuild from the pinned source that reproduces the same version string is not a poisoned restore. The run's three provisioning lines say what it is instead: the DEFAULT oracle builds from `target/zenohd-build/zenoh-src`, the tree `build-zenohd.sh` clones itself at `--branch 1.10.1`, and answers `zenohd v1.10.1`; the VARIANT builds from the cargo git checkout, a detached tree that fetches no tags, and answers `zenohd v1211779c` — the pinned commit's own short sha. BOTH pass that script's `checkout_version != ZENOHD_VERSION` assert, so both ARE 1.10.1 and only one of them can SAY so. ⇒ the gate compares a `git describe` answer against a semver pin, a variant cannot produce a semver, and `ensure_zenohd_at_pin.py`'s repair loop therefore cannot converge on ANY host — no cache-key bump reaches this, and the same shape is why Layer C0 cannot go green on a developer machine that has the checkout. The base is `build-zenohd.sh`'s source preference, which gives the four oracles TWO identities while that script's own comment claims "one oracle identity"; it is not the grader and not the cache. ⚠ 758's refutation of the older source-preference diagnosis was HALF right and the halves are worth keeping apart: the variants are not OFF-PIN, which is what it disproved, but the source preference is still causal — through what the binary can SAY, not through what it IS. Amended under 758 rather than refiled, because it is the same seam. Not this round's: this push touches no oracle, no pin and no workflow | 758 | |
| R2663 | `35101414755` | `cb9be180` | the SAME run the row above diagnoses, re-acked for a TIMING reason rather than a new reading: the run for this push's parent tip (`35120942782`, `f153149f`) is still `queued`, so gate 2c falls back to the newest COMPLETED verdict, which is still this one. Nothing new is claimed about it -- the mechanism is the one the row above derives, and this push changes only `docs/.atomic/workspace.atomic.json`, so it touches no oracle, no pin and no workflow and cannot move the verdict either way. ⚠ The reading to look for in `35120942782` when it completes is whether step 43 is STILL the sole failure on a fourth consecutive tree; if it is, that is further confirmation the cause is structural (build order, not a poisoned cache) rather than a cache that one more run might shake loose | 758 | |
| R2664 | `35101414755` | `cb9be180` | the same run a THIRD time, and the reason is queue timing rather than a new reading -- which is worth saying plainly because three rows naming one run could otherwise read as three verdicts. BOTH newer runs are `in_progress` at this push: `35120942782` (`f153149f`) and `35123307120` (`4c94b1fb`), so gate 2c falls back to the newest COMPLETED verdict, which is still this one. Nothing about it has been re-read or re-claimed; the mechanism stands as the R2662 row derives it. ⚠ What those two runs will settle when they land is the thing to look for, and neither can be inferred from this row: `35123307120` is the FIRST hosted run over a tree where `adminspace-write` is COMPLETE, so it grades the re-grade and the two census pins that moved with it; and if step 43 is still the sole failure on both, that is a fourth and fifth consecutive tree confirming the pin red is structural -- build order, not a cache -- rather than something a rebuild might shake loose | 758 | |
| R2665 | `35120942782` | `f153149f` | A NEW verdict, read per step rather than inherited, and it is the confirmation the R2664 row said to look for: 20 of 21 jobs green, ONE failed job, ONE failed step -- `43 Ensure the unixpipe zenohd ANSWERS at the pin (R2647)`. That makes FOUR consecutive runs reduced to this single cause, across trees that touch no oracle, no pin and no workflow. A stale cache does not survive that; a structural cause does, which is what this push acts on. ⭐ AND THIS PUSH IS THE FIRST THAT SHOULD CHANGE IT: the repair edits `scripts/build-zenohd.sh`, which all three zenohd cache keys hash, so the next run rebuilds every oracle from source rather than restoring one. ⚠ Read that run per step too, and do NOT read a green as a healthy lane -- step 43 has been the wall for five runs, so step 47 (the vsock twin) and everything after it have been SKIPPED throughout and have never been graded. If step 43 is still red, the cause is NOT the one this round repaired and the next diagnosis must start from the new message: this item has had three diagnoses already, and the two earlier ones were refuted by measurement rather than by argument | 758 | R2665 (placed, awaiting a hosted verdict) |
| R2665 | `35123307120` | `4c94b1fb` | THE ACK TARGET MOVED WHILE THIS ROUND WORKED, which is the case `WZ_ACK_RED` is per-run for: the row above acks `35120942782`, and by the time the hook ran, `35123307120` had completed and become the newest verdict, so gate 2c refused the push naming the older id. Read per step like the others: 20 of 21 jobs green, ONE failed job, `43 Ensure the unixpipe zenohd ANSWERS at the pin (R2647)` — the FIFTH consecutive run reduced to that single cause. ⭐⭐ AND THIS RUN IS THE ONE THAT MATTERS BEYOND THE PIN, which is why it is read rather than waved through as "same red again": it is the FIRST hosted run over a tree where atom `adminspace-write` is COMPLETE, and therefore the first to grade the R2663 re-grade together with the two `depth_axis_census` pins that moved with it (`PIN_REACHED` 30->29, `PIN_WZ_CITATIONS` 204->180). Everything except step 43 is green, so the re-grade, the per-reason attribution and both pin moves are verified HOSTED and not merely locally. ⚠ The pin red itself is unchanged and is not this round's; the repair for it is in the very push this row unblocks, and it rebinds all three zenohd cache keys, so the NEXT run is the first that can answer differently | 758 | R2665 (placed, awaiting a hosted verdict) |
| R2666 | `35123307120` | `4c94b1fb` | the same run a second time, for queue timing and with NOTHING new claimed about it — the R2665 row above is the reading. Both newer runs are `in_progress` at this push (`35125259804` for `33874974`, and `35127742496` for `923564d6`), so gate 2c falls back to this one. ⭐ `35127742496` IS THE ONE TO READ NEXT and it is not just another tick: it is the first run whose tree carries the R2665 repair, which edits `scripts/build-zenohd.sh` and therefore rebinds all three zenohd cache keys, so every oracle rebuilds from source instead of restoring. That makes it the first run in six that can answer step 43 differently. ⚠ Read it PER STEP and do not read a green as a healthy lane: step 43 has been the wall since R2660, so step 47 (the vsock twin) and everything after it have been SKIPPED throughout and have never been graded once. A green at 43 means the lane finally RUNS what is behind it, which is new surface, not proven surface | 758 | R2665 (placed, awaiting a hosted verdict) |
| R2669 | `35129771719` | `7a18f7bf` | ⭐⭐⭐ THE STEP NAME CHANGED, AND THAT CLOSES 758. For six consecutive runs this job died at `43 Ensure the unixpipe zenohd ANSWERS at the pin`. Read per step, this run and `35127742496` before it both show `42`-`47` ALL SUCCESS — including 43 and including `47`, the vsock twin, which had been SKIPPED on every one of those six and never graded once — and the failure has moved to `48 Layer Z — zenohd (zenoh-full) interop`. The repair landed in `923564d6` edits `scripts/build-zenohd.sh`, which all three zenohd cache keys hash, so every oracle rebuilt from source instead of restoring a binary that could not name the pin. ⭐ THE SIZE OF WHAT THE WALL WAS HIDING, from the lane's own line: `reached 28 of 78 guarded leg(s); 50 did not run`, against R2647's measurement of 1 of 78 while the wall stood. So one step going green returned TWENTY-SEVEN legs of the only lane that grades wz against the canonical Rust implementation. ⚠ AND THE FIRST LEG IT RELEASED WAS RED, which the R2666 row said to expect and not to read as a regression: `zenohd_reports_back_every_value_the_emitted_config_carried` asserted `"drop_future_timestamp":null` while wz emits `false` and zenohd resolves `false` — the interop AGREED and only the expected literal was wrong, because that expectation had been written against an oracle no run could reach and had never once executed. Repaired in R2669. ⛔ THE REMAINING RED AT 48 IS NOT 758's AND MUST NOT BE ACKED AS IT: 758's subject was an oracle that could not name the pin, and that is measurably gone; step 48 is the surface BEHIND the wall, 50 legs of which have still never run. Expect more of these and read each as an assertion getting its first subject, diagnosed from BOTH sides of the log — it carries what wz emitted AND what zenohd resolved | 758 closed; 48 is new surface | R2669 |
| R2670 | `35129771719` | `7a18f7bf` | the SAME run the row above reads, re-acked because gate 2c grades the newest COMPLETED run and the newer one (`35141489558`, `492bd2cf`) was still `in_progress` at this push — its own line says 19 of 21 jobs completed with 2 running. NOTHING NEW IS CLAIMED about the verdict; what this round adds is the ATTRIBUTION TEST, run rather than inherited, because "same red again" is the one reading this ledger has been burned by. Measured: `3eeec7e6`, the `build-zenohd.sh` repair, IS an ancestor of `7a18f7bf`, so the pin wall was already down in this run's own tree and the red cannot be 758's — which is precisely what makes step 48 the surface BEHIND the wall rather than the wall. Read from the log per step: one red job of 21, one red step, and the panic is `zenohd_reports_back_every_value_the_emitted_config_carried` asserting `"timestamping":{"drop_future_timestamp":null,"enabled":true}` while the log's own two halves AGREE the other way — wz emits `false` and zenohd resolves `false`. ⭐ The repair is `8805e9a4`, which POSTDATES `7a18f7bf`, so this run could not have carried it and `35141489558` is the first tree that can answer differently. ⚠ Read that one per step too and do not read a green as a healthy lane: 50 of 78 guarded legs have still never executed once, so each one that goes red is an assertion getting its first subject | 48 is new surface, not 758 | 8805e9a4 (landed, awaiting a hosted verdict) |
| R2671 | `35141489558` | `492bd2cf` | ⭐⭐⭐ THE STEP CHANGED AGAIN, AND THIS ONE CONFIRMS 758 IS DEAD. Read per step, not inherited: one red job of 21, and `Layer Z — zenohd (zenoh-full) interop` is **success** here where it failed on the row above. That is the `"drop_future_timestamp"` literal repair (`8805e9a4`) landing exactly as the R2670 row predicted it would, so the Layer Z arc that ran from R2660 is closed on a hosted verdict rather than on an argument. THE NEW RED IS `Layer M — multicast loopback + wz<->pico multicast interop (R311y421)`, and it is NOT a regression — it is surface that had never executed. The two runs side by side say so without inference: `35129771719` had Layer Z **failure** and Layer M **skipped**; this run has Layer Z **success** and Layer M **failure**. Layer M ran for the first time and was red on that first run, which is the same shape the wall hid at 48 and the reason the R2670 row said to expect more of these. ATTRIBUTION MEASURED, NOT ASSUMED: the failure is `crates/wz-runtime-tokio/tests/scouting_multicast_loopback.rs` @ `scout should resolve the peer locator from the Hello`, and running that binary with the LANE'S OWN flags (`--features scouting-active,transport-link-tls … -- --ignored`) gives **6 passed** here; the tree that redded (`492bd2cf`) also predates this round's reconcile work entirely. So the discriminator is the ENVIRONMENT — the runner's multicast stack against this machine — and a local green must not be read as a fix. Registered as open-debt item 774 with `@from: 758`, because the wall is why it is visible at all. ⚠ Still do not read the lane as healthy: Layer Z now RUNS what was behind it, which is new surface rather than proven surface | 774 (new; 758 confirmed closed) | |
| R2673 | `35151172285` | `be57a84b` | the same `Layer M — multicast loopback + wz<->pico multicast interop (R311y421)` step, on a tree that PREDATES the repair, so this row acknowledges it rather than re-diagnosing it. ⛔⛔ AND IT CORRECTS THE ROW ABOVE, which is why it says more than "same red": that row named the discriminator as THE ENVIRONMENT — the runner's multicast stack against this machine — and that is FALSE. The panic had already printed the answer and I had stopped reading before it: `left: Discovered("udp/127.0.0.1:7448")` against `right: …:7447`. The Hello ARRIVED. It was another test's. `scout_discovers_peer_locator_over_multicast` bound the file's compiled-in default while a sibling test's CONTROL arm deliberately sprays a Hello carrying a different locator at that exact group and port — the sibling's whole claim being that a node which ignored its config and stayed on the default would hear it, so THAT arm cannot move or it passes vacuously. A local green was scheduling luck, not evidence. ⭐ THE BASE WAS THAT NOTHING ASSIGNED THOSE ADDRESSES: a multicast group is machine-wide and cargo runs test functions AND test binaries concurrently, so two files reasoning about their own siblings by hand — one comment said "distinct from 7449 / 7450" while holding a port its own file-mate used — is a convention with no enforcement. R2672 built `scripts/lib/multicast_address_collision_gate.py` (population globbed from `crates/*/tests/*.rs`, any address bound by two tests refused, unresolvable binds printed, a zero population FAILING) and moved four addresses it named; the repair landed in `870f802f`, so run `35155038841` is the first tree that can answer differently. ⚠ Read that one per step: Layer Z has been green since `492bd2cf`, so what is behind it keeps running for the first time and each new red there is an assertion getting its first subject, not a regression | 774 closed | 870f802f (landed, awaiting a hosted verdict) |
| R2674 | `35158267503` | `1fe4e1ca` | ⛔⛔ THIS RED IS MINE, and naming that is the point of the row. ONE red job of 21, ONE red step, and it is a NEW one: `Layer C1bp — §5.22 dynamic plugin loading, end to end`. The e2e barrier waits for the literal `plugin 'wz_example' Started` and the host printed `plugin 'libwz_plugin_example' Started` — the FILE STEM. R2673's declare/load split keyed the registry slot by the operator-supplied declared name (which the storage host derives from the path's stem) and the host then logged that KEY as the plugin's identity. ⭐ THE KEY BEING THE DECLARED NAME IS CORRECT and stays: a failed `dlopen` never yields an id, so a slot keyed by the library's id would make its identity depend on the very outcome the Declared state exists to record. What was wrong is treating the key and the PLUGIN'S OWN IDENTITY as one fact. Upstream keeps them apart — `PluginStatusRec` carries a declared `name` beside the plugin's `id` — and wz's `AdminPlugin` already does too, so `admin_records` reports the library's id correctly and ONLY the host's log diverged. Repair: `load_declared` returns the library's id on success and the host prints that; registered as open-debt item 775, critical, and paid in its own round because ledger `Round 2674` is frozen and describes the liveliness work. ⛔⛔⛔ AND IT HIDES TWO LAYERS BEHIND IT: C1bp is fail-fast, so `Layer Z — zenohd (zenoh-full) interop` and `Layer M — multicast loopback + wz<->pico multicast interop (R311y421)` are both **skipped** on this run. Read that as UNGRADED, never as green. The consequence to carry: R2672's multicast-collision repair STILL has no hosted verdict — the run for `870f802f`, the first tree to carry it, was CANCELLED (superseded by the next push), and this run died before reaching M. Fixing 775 is what unblocks both verdicts | 775 (new, mine); 774's verdict still pending | |
| R2676 | `35169104102` | `3c7cb27f` | ⭐⭐⭐ THE SAME STEP, A DIFFERENT TEST, AND THAT IS THE WHOLE READING. `Layer C1bp — §5.22 dynamic plugin loading, end to end` is red again, one red job of 21 and one red step, exactly as the row above — and inheriting that row would have been wrong twice over. Read per TEST, not per step: the barrier the R2674 row repaired, `plugin 'wz_example' Started`, PASSED here (`test result: ok. 1 passed` at 01:19:31, the invocation immediately before). What failed is the NEGATIVE leg, `wz_plugin_non_plugin_shared_object_is_refused_and_the_node_survives`, at `wz_plugin_dynamic_loading_pico.rs:316`: "the host never reported the refusal within 15s". ⛔⛔ THIS RED IS ALSO MINE, and the host is not the part that is wrong — its log in the failure transcript reads `plugin 'libc.so' stays Declared — load failed: libc.so.6 exports no wz_plugin_entry`, i.e. it refused a non-plugin and stayed up, which is precisely what the test is about. What broke is the WORDING: the barrier waits for the literal `plugin load failed`, and R2673 (`acb2c332`) rewrote that warn line and dropped the phrase. ATTRIBUTION MEASURED, NOT ASSUMED: `git log -S'plugin load failed'` shows `cb2c9365` introducing the producer and the needle in ONE commit, and `acb2c332` as the only commit to touch the producer since. ⭐ THE BASE IS THAT ONE STRING LIVES IN TWO CRATES WITH NOTHING TYING THEM, and it cannot be tied cheaply: `wz-ap-demo` has only a `[[bin]]` target and `wz-integration-tests` does not depend on it at all, because spawning the built binary by path is what makes it a binary-dep e2e. So the answer is a GATE over needles-without-producers, not a dependency edge — registered as open-debt item 777, critical. ⚠ AND THE SIZING OF THAT GATE IS ALREADY MEASURED AS HARD: a producer literal is a FORMAT string, so a needle crosses interpolations (`plugin 'wz_example' Started` against `plugin '{id}' Started`) and containment cannot decide it. A sweep written this round with a permissive template arm classified 164 of 164 literal needles as TEMPLATE and reported ORPHAN 0 on a tree that provably has one; that instrument is recorded as wrong rather than quoted. This push pays the INSTANCE (the warn leads with `plugin load failed` and keeps the slot state after it) and leaves the class to 777. ⛔⛔⛔ THE TWO LAYERS ARE STILL HIDDEN: `Layer Z — zenohd (zenoh-full) interop` and `Layer M — multicast loopback + wz<->pico multicast interop (R311y421)` are both **skipped** here, read from the step conclusions rather than inferred. So R2672's multicast-collision repair has now gone THREE runs without a verdict — cancelled, then C1bp, then C1bp again | 777 (new, mine); 774's verdict still pending | 775 confirmed fixed (its barrier passed here) |
| R2659 | `35067974395` | `f27edeb5` | The SAME run the R2658 row diagnoses, re-acked because gate 2c grades the most recent COMPLETED run and `35082162927` — the run for R2658's own tip `7f1c6a70`, which carries the E7b/E7b2 repair — is still `in_progress` at this push. Nothing new is claimed here: the cause remains R2655's lane-selection defect at Layer E7b, and this push is the round AFTER the one that fixed it, so the first evidence either way is `35082162927` itself. ⚠ Read it per step rather than by conclusion: E7b2 has never executed on any hosted run, so its appearance with a result of its own is the thing to look for | 762 | R2658 |
| R2656 | `35053431232` | `36eb6a92` | ONE red job, the THIRD run running whose only failure is item 755's standing zenohd pin. This run grades R2654 — the sink-carrying runtime write, `ConfigSinks`, and the two named refusals — so the widened write path is verified hosted rather than only unit-tested. ⚠ The reading is a STREAK now and that is worth naming rather than repeating: three consecutive runs reduced to one cause means the acknowledgement ledger is carrying one debt and not a queue, which is the state it was built to make visible. It also means a FOURTH cause appearing would be this round's, with nothing to hide behind | 755 | — |
| R2655 | `35051065695` | `9524662a` | ONE red job, the SECOND run running whose only failure is the standing one: `target/zenohd-unixpipe -- still STALE after a rebuild: binary says 1211779c, pin says 1.10.1`, item 755's, unchanged and not this round's. This run grades R2653 — the round-fed seed widened to a gate NAMING one tracked file, and the four gates that widening wired into pre-push — so those are verified hosted rather than merely selftested, and the two jobs R2652's gate-name grammar had redded (Layers A+B, C0/C1cf) stay green with four more gates running inside the hook. ⚠ Read from the jobs, not the conclusion: the run still reports `failure` because item 755 is still open, and a reader who stopped at that word would have learned nothing about what this round verified | 755 | — |
| R2654 | `35050041956` | `c008c879` | ONE red job, and the reading is mostly about what is GREEN. This run grades the five `access_control` keys and the gate-name grammar, and of the four jobs that redded on `ae171dc8` only the cross-impl one is still red — `target/zenohd-unixpipe -- still STALE after a rebuild: binary says 1211779c, pin says 1.10.1`, item 755's standing red, unchanged and not this round's. So R2652's two causes are PAID AND VERIFIED HOSTED rather than merely repaired locally: Layers A+B and C0/C1cf are green, which is the gate-name grammar, and C1bn is green, which is `the_three_refusals_are_kept_distinct`. ⚠ Read from the jobs rather than from the run's conclusion: a run whose only failure is a standing red still reports `failure`, and a reader who stopped at that word would have learned nothing about the four jobs that changed | 755 | R2652 (causes 1 and 2), verified here |
| R2653 | `35043547382` | `ae171dc8` | the same run a second time, and for the TIMING reason the R2652 rows below record rather than a new reading: the run for the tip this push replaces (`35050041956`, `c008c8797aac`) was still IN PROGRESS when the hook ran, so gate 2c falls back to the newest COMPLETED verdict, which is this one. Its three causes are unchanged and two of them were PAID by that very run's tree — the gate-name grammar and `the_three_refusals_are_kept_distinct` — so this ack is about a verdict that has not arrived, not about a defect that has not moved. ⚠ The debt is paid by `35050041956` coming back, never by another row here; the carry says so, and this round's own subject is the reason the grammar red could not be seen locally in the first place | 755 | R2652 (causes 1 and 2) |
| R2652 | `35043547382` | `ae171dc8` | FOUR red jobs, THREE causes, each read from its own job log rather than inherited from the row below. (1) Layers A+B and (4) Layers C0/C1cf die on ONE line, `hook-gate-boundary FAIL: gate 2d2 ... is not a gate` — that gate's name grammar is digits-then-letters, so `2d2` parsed as `2d` and then failed a word boundary against the `2`. MINE, from the round that added the gate, and PAID in this push by widening the grammar and its attribution mark together, with a red-first selftest arm. ⚠ Not a lucky catch: this gate reads ONE tracked file and so falls outside the round-fed class, which is why no local gate could see it — carried as the repair to derive next. (2) Layer C1bn dies on `the_three_refusals_are_kept_distinct`, which asserted `downsampling` is an unhonoured key AFTER R2651 honoured it. Also mine, also PAID here, and the fixture is derived from the registry now instead of spelled. (3) the cross-impl job is the unixpipe zenohd pin answering `1211779c` against pin 1.10.1 — item 755's standing red, unchanged and not this round's. ⚠ Read individually: every `lane-reach` and `test-discipline` FAIL line in those logs is a SELFTEST arm with its own `ok` beside it, and counting them as findings would have manufactured six | 755 | R2652 (causes 1 and 2) |
| R2652 | `35035721708` | `4e0c2115` | the same run a second time, and for a TIMING reason rather than a new reading: the run for the current tip (`35041176567`, `31fa2bdf`) is still QUEUED, so gate 2c falls back to the newest COMPLETED verdict, which is this one. Its two steps are unchanged — the A5 membership red was paid in `9ef5c3c1` (this run grades a tree that predates it) and the unixpipe zenohd pin is item 755's standing red. Nothing here has been re-read as new; the debt is paid by `35041176567` coming back, not by another row | 755 | |
| R2651 | `35035721708` | `4e0c2115` | the newest verdict, and it is TWO steps, both already understood — which is itself the finding: `Layer C1y` is GONE from this run, so the 216-against-217 count guard R2650 moved is paid and the hosted lane says so. What remains: (1) `Layer A5 — preset-ap-full membership`, which this push PAYS in `9ef5c3c1` — the run grades `4e0c2115`, a tree that predates the fix, so the red is real and the debt is not; and (2) the unixpipe zenohd pin step, item 755's standing red, unchanged and not this atom's. No new finding in either | 755 | |
| R2651 | `35033310697` | `52d34672` | THREE findings, read from the jobs rather than inherited. (1) the unixpipe zenohd pin step FAILS again — same reading as the row below, item 755's and not this atom's. (2) `Layer C1y` fails on the 216-against-217 count guard, which is MINE and was already paid in `4e0c2115`: this run grades a tree that predates that fix, so the red is real and the debt is not. (3) `Layer A5 — preset-ap-full membership` FAILS, and that one is mine and was UNPAID: declaring the demo feature `router-config-mutate` obliges a membership decision, and without it the AP-full binary compiles the capability in and cannot reach it from argv. Paid in this push by naming it in `preset-ap-full` beside `router-connect-reconcile`, the other intent of the same config-write plane. ⚠ A5 is a gate the operating notes say to run every session and I did not run it when I added the feature — a hosted-only obligation that a local green cannot show | 755 | |
| R2650 | `35030245790` | `579e620d` | the FIRST verdict on the repair, and it is TWO findings. (1) `Ensure the unixpipe zenohd ANSWERS at the pin (R2647)` FAILS, and the script is right: the binary answers `1211779c` against pin `1.10.1`, and it is STILL stale after the rebuild the script triggers — so the repair made the staleness VISIBLE without curing it. Before R2647 that step was a bare `test -x` presence check, so these lanes ran against an unverified oracle and reported green; refusing is correct, and the cost is that the cross-impl job is now blocked rather than misleading. The rebuild not moving the answer is the next thing to read, and it is item 755's, not this atom's. (2) `Layer C1y` FAILS on a count guard at 216 that prints 217 — R2648's Del witness, which this leg compiles in because it keeps default features. THAT ONE IS MINE and is paid in this push, along with the reason the pre-push gate never saw it | 755 | |
| R2649 | `34996365804` | `c6747ae3` | the same run a THIRD time, and for a reason worth separating from the two below: the repair DID land (`579e620d` is on origin), and its own run `35030245790` was still `in_progress` when this push started, so gate 2c falls back to the newest COMPLETED verdict, which is still this one. Nothing about it has changed or been re-read — it grades a tree that predates the repair. This ack is therefore about TIMING, not about a new finding, and the debt is paid by `35030245790` coming back green, never by another row here | 758, 755 | |
| R2647 | `34996365804` | `c6747ae3` | the same run a second time, for the push that carries the REPAIR: `ensure_zenohd_at_pin.py` plus the three provisioning steps and the three rebound cache keys. The ack is still an ack — the red is paid when a hosted run comes back green with the poisoned entries abandoned, not when this lands | 758, 755 | |
| R2646 | `34996365804` | `c6747ae3` | the graded target MOVED while the hook ran — this run finished mid-push and became the newest verdict, which is the case R2640 made `WZ_ACK_RED` a comma list for. Read on its own rather than inherited from the row below: same `oracle-pin-gate` FAIL, same two stale variants, same 77 of 78 legs unreached. It grades `c6747ae3`, which predates every commit in this push | 755 | |
| R2646 | `34977306103` | `ca83325f` | the queue finally produced a REAL verdict rather than another cancellation, and it is the known one: Layer Z `oracle-pin-gate` FAIL, `zenohd-unixpipe` and `zenohd-vsock` answering `1211779c` against pin 1.10.1, covering 77 of 78 guarded legs. Read from the job log rather than inherited from the R2639 rows that name the same cause. Not this round's: the diff touches no oracle binary and no pin | 755 | |
| R2645 | `34972948515` | `1e213f0e` | the same cancelled run, a third time. The queue has started nothing since: the run for the previous tip (`34985703272`) is still queued, so this history's newest verdict remains the cancellation | 755 | |
| R2644 | `34972948515` | `1e213f0e` | the same cancelled run R2643 acknowledged, a second time: the run for the pushed tip (`34977306103`) is itself queued, so this history has still produced no verdict at all. Same reading as the row below — AMBER because it graded nothing, and a later green subsumes it because no lane here is change-set selected | 755 | |
| R2643 | `34972948515` | `1e213f0e` | **CANCELLED, not failed** — the first such row here. It was `queued` at this round's start and was cancelled during it, by the account-wide sweep of superseded queued runs. AMBER is right because a cancelled run graded NOTHING; and because every one of this repo's 20 hosted jobs grades the tree at its sha (0 are change-set selected), a later green subsumes it, so this ack records a lost ATTRIBUTION rather than an unpaid verdict | 755 | |
| R2639 | `34922821640` | `96b2dedd` | same two jobs, same two causes — read individually, not assumed | — | |

⚠ The three rows above are ONE push. The gate now grades the newest FINISHED
run on the history, and the queue was draining while the hook ran, so the id it
named moved between the refusal and the retry. `WZ_ACK_RED` therefore takes the
comma-separated list of the runs that were actually read. Each id is still
written out; none of them covers a run nobody looked at.

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

⚠ THE R2576 ROW ACKNOWLEDGES ONE RUN AND THE PUSH PAYS TWO CAUSES, which is
worth separating because gate 2c only ever reads the immediately previous run.
`34692815062` died at 25s on the provenance citation and `34690849417` before it
died at 212s on `depth_axis_census`'s unpaid pins -- two rounds, two causes, and
in BOTH cases a fail-fast Layer C0 reported one defect while hiding whatever sat
behind it. R2576 pays both and, more to the point, puts twenty-seven of the
thirty gates that read the atomic store or the gate corpus into pre-push gate
2z, so this particular shape -- a hosted-only gate whose subject a commit moved
without being able to see it -- cannot produce a third round's red in silence.

⚠⚠⚠ IT PRODUCED A THIRD ONE ANYWAY, and the R2578 row is it. The sentence above
is correct about the shape and wrong about the reach, because "the thirty gates
that read the atomic store or the gate corpus" was never the population -- it
was the two corpora R2576's two instances happened to share. `prose_dep_graph`
reads `crates/`, sat outside that set, and refused a header R2576 itself had
written; two hosted runs died on it before anyone read them. R2578 re-derives
the population from the CLASS -- a gate is round-fed when it enumerates TRACKED
files -- which takes it from 30 modules to 91 and gate 2z from 20 members to 62.
The honest reading of this row is therefore NOT "the gate failed": it is that a
population written as a list of known subjects reports a clean surface over the
subject it does not have, and the only fix is to state the class and derive the
list from it.
