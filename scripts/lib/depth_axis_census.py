#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2218 (no register item) — WHAT THE 86 PARTIAL GRADES ACTUALLY SAY, as three
numbers a command produces rather than a sentence somebody wrote once.

Answers item 200 of the unregistered register, which lives outside this
repository -- the position `debt_plane_census.py` and `armed_oracle_census.py`
already record for themselves. Item 200 reads:

    the BREADTH is closed and there is NO INSTRUMENT for the DEPTH ... the only
    tool is the A3 grade, which only a whole-surface re-audit overturns and no
    round does one ... so 85 is a BOOKKEEPING CONVENTION rather than the amount
    of work left.

## THE ITEM'S SHARPEST SENTENCE DID NOT REPRODUCE, and that is this file's
## first finding

Three hypotheses were probed before anything was built, and all three failed:

  * "PARTIAL is an unexamined label" -- FALSE. Every one of the 74 PARTIAL
    atoms an executing test reaches names a RESIDUAL in its own reason. Not one
    is a bare grade.
  * "the residual statements have rotted" -- FALSE. Those reasons carry 1003
    file citations; 409 resolve uniquely to a tracked wz path and NOT ONE has a
    line number past its file's end.
  * "the depth axis has no instrument at all" -- FALSE for configuration.
    `every_honoured_key_is_classified_by_what_proves_its_effect` already
    partitions all 37 honoured keys into wire / no-sink / argv-only, and its
    own doc says it was built for exactly this complaint.

⚠ A probe of the whole set found a defect in ITSELF first, and the shape is
worth carrying: matching a citation to a wz file by BASENAME resolved
`zenoh-config/src/lib.rs` onto `crates/wz-statechart-bridge/src/lib.rs` and
reported 87 out-of-bounds lines that were pure artefact. Suffix matching on the
full cited path gives 0. A loose matcher does not fail loudly; it produces a
confident wrong number.

## So what IS missing, and what this file is

Nothing measured any of the above. The numbers were true and unwatched, which
is the state item 200 describes even though its diagnosis of WHY was wrong. So
this is the depth census in the shape item 200 itself named as the next
instrument -- y842's config census applied one axis over: a denominator the
tree derives, a numerator it derives, and the remainder pinned as a SET.

⛔ A THIRD AXIS WAS BUILT AND THEN REMOVED, and the removal is the sharper
lesson. It asked whether each PARTIAL reason NAMES A RESIDUAL, and on its first
run it flagged `platform-macos` and `platform-windows`. Reading them showed the
flag was the axis's fault: both reasons are dense with state -- each carries a
CORRECTION recording that its own blocker turned out to be FALSE -- and they
merely spell it in words the axis had not been given. That axis was a KEYWORD
SWEEP wearing a gate's clothes, and open-debt item 190 already records that a
keyword sweep is structurally a FLOOR. A vocabulary of accepted words is an
exemption list with the polarity reversed, so it went out rather than growing.
What it noticed is worth a reader's attention and is recorded in the ledger as
an observation, which is where an unmeasured thing belongs.

Two axes, each a partition with no exempt bucket:

  REACH     Every PARTIAL atom, by whether an executing test names a symbol its
            own `cfg` gates -- `atom_test_graph`'s derivation, which
            `audit-catalog-status.sh` already trusts for COMPLETE and has never
            asked of PARTIAL. Three classes: reached, owned-but-unreached, and
            no-owned-symbol (the derivation declining to answer, which is
            counted rather than hidden).

  CITATION  Every wz-path file citation in a PARTIAL reason resolves to exactly
            one tracked file, and any line number it carries is inside that
            file. Upstream citations are counted apart and NOT judged -- R2215
            measured why nothing here can judge them: the vendored trees are
            submodules whose contents are not tracked files, and `.gitmodules`
            does not name zenoh at all.

## The pins, and why every one of them is two-directional

Each axis is pinned at what it measures today and the pin is enforced in BOTH
directions, on `C1bz`'s contract: a count that rises is something this change
added, and one that falls is something it repaired -- which lowers the pin in
that same commit. A one-directional pin is a number nobody has to keep true.

⚠ The pins are NOT a pass. A PARTIAL atom an executing test reaches is one
whose grade rests on its stated residual and on nothing else, and that is 74 of
86. Moving one of those to COMPLETE is the work; this file makes the size of it
a number, which is all item 200 asked for and all this can honestly give.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import atom_test_graph  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = "docs/.atomic/workspace.atomic.json"

# The inventory holds three kinds under one prefix space. An ATOM is defined by
# exclusion, exactly as `inventory_kinds.is_atom` defines it -- restated here
# rather than imported because that module reaches the store through
# `mnemosyne-cli`, and this gate reads the tracked file so Layer C0 needs no
# binary. The two prefixes are the same two.
PRESET_PREFIX = "preset-"
DEBT_PREFIX = "debt-"

# The head token of a reason is its TAG. Taken from `inventory_kinds`'s own
# rule: a tag is a SLOT, never a word that happens to occur later -- a reason
# routinely discusses the grades it does not carry.
HEAD_TAG = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)")

# A file citation, with an optional line. The path may carry directories, and
# it MUST, for the reason the header gives: a bare basename matched against
# this tree resolves an upstream file onto an unrelated wz one.
CITATION = re.compile(r"\b((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:rs|c|h))(?::(\d+))?")

# R2218 — pinned at what the tree measures today. Two-directional; see header.
#
# R2219 — 74 -> 73, and it is the first time this pin has moved for the reason
# the header says it should: `scouting-responder` left PARTIAL for COMPLETE
# because its ONE named residual was CLOSED, not relabelled. Upstream elects the
# reply's source socket by longest-octet match against the asker
# (`get_best_match`, zenoh `net/runtime/orchestrator.rs:1113-1134`) and wz
# answered from the group socket it received on; it now elects, the demo binds
# the sockets to elect from, and a Layer M leg watches two askers on two
# addresses each get the nearer one. The total falls with it, 86 -> 85.
#
# R2220 — 73 -> 72, the second move, for the same reason: `routing-namespace`'s
# residual was ONE named axis (the per-message-type diff against upstream
# `net/routing/namespace.rs`), that diff was walked arm for arm, and the two
# gaps it found were CLOSED rather than re-described. The total falls with it,
# 85 -> 84, and the citation pin below falls because that reason's two wz
# citations left the PARTIAL corpus with it.
# R2333 — 407 -> 405 and 86 -> 85, and NEITHER move is this round's own work.
# The measurement moved in R2332 (`transport-stats cited a zenoh file gone at
# the pin`), which re-cited that atom's reason and did not move the pins with
# it; the ratchet caught it exactly as designed, on the next run. The pins move
# here because this is the commit that publishes that one.
#
# What left, read out of the two revisions rather than inferred: the reason
# dropped `wz-session-core/src/stats.rs` for the repo-rooted
# `crates/wz-session-core/src/stats.rs` (still one wz citation, so no move from
# that pair), dropped the four line-form citations `drive.rs:76`,
# `session_actions.rs:1426`, `stats.rs:34` and `stats.rs:50`, and gained two
# rooted UPSTREAM paths (read as upstream, not judged) plus a bare `stats.rs`.
# Two wz citations and one ambiguous one net out of the corpus.
#
# Those two upstream paths are deliberately NOT spelled here. Writing them would
# make this comment itself an upstream citation in bare form, which is the
# R2241 class -- `upstream_citation_anchor_gate.py` counted exactly that and
# redded on 60 -> 62 while this note was being written. A gate's own prose is
# tracked text like any other; the repair is to stop making the claim, not to
# re-anchor a claim this file has no reason to make.
# R2337 — 405 -> 408, and unlike R2333 this move IS the round's own work.
# `routing-router`'s reason gained an appended CORRECTION that re-measures its
# four residual clauses against the pin, and three of them cite a wz file to say
# so: the run-mode table that maps the star router to the Peer wire value, the
# module declaration that puts the dual-mesh forwarder behind its sibling
# feature, and the arm that selects the no-op forwarder without `routing-routes`.
# Three clauses that HOLD, each now naming the line that shows it. The fourth
# clause was withdrawn and cites upstream only, so it moves nothing here.
#
# The withdrawn clause's upstream paths are deliberately NOT spelled here, for
# the reason the R2333 note above gives: a gate's own prose is tracked text, and
# writing them would make this comment a bare upstream citation. That is the
# R2241 class, and it has now recurred five times; the repair is to not make the
# claim. PIN_AMBIGUOUS does not move -- the three additions are all rooted at
# `crates/`, so none of them is ambiguous.
# R2340 — 408 -> 409, one citation, from `access-acl`'s appended CORRECTION.
# Its two `WHAT REMAINS` clauses were re-measured against the pin and both hold;
# the wz half of the subject-axis clause is the access-control crate's own
# module doc, which states the missing axes about itself in three places, so the
# correction cites that file to show the claim rather than assert it. The other
# clause's wz half is a Cargo feature list, which is not a citation, and every
# upstream half is anchored and reads as upstream -- so one citation, not five.
#
# PIN_AMBIGUOUS does not move, and that is worth a sentence because the first
# draft of this correction moved it. That draft wrote the crate's file as a bare
# `lib.rs`, which matches many tracked files and is counted as ambiguous rather
# than guessed at, and it shortened an upstream path to `interceptor/mod.rs:133`
# -- which resolves to a WZ file, so the atom would have been recorded citing wz
# code for a claim about zenoh. Both were repaired in the prose (full paths, one
# each way) rather than absorbed by moving the pins to match, which is the same
# repair the R2333 and R2337 notes above chose for the R2241 class: when a
# sentence makes a claim the gate reads differently than the author meant, fix
# the sentence.
# R2341 — 409 -> 415, six citations, from `session-extauth`'s appended
# CORRECTION. Its three residual clauses were re-measured against the pin and
# all three hold; the wz half of each is a claim about THIS tree, so the
# correction names the files that carry it -- the dispatch module and the two
# method modules for "no runtime credential mutation" and "no identity slot",
# and the session actions for the second. Six occurrences across five files,
# every one a file the sentence is actually about.
#
# PIN_AMBIGUOUS does not move, and once again the first draft would have moved
# something it should not: it wrote zenoh's interceptor path shortened to
# `interceptor/access_control.rs:210`, which resolves to the WZ file of that
# name -- the identical mistake R2340's note above records, made again one round
# later while writing about citation rot. It was caught BEFORE the store was
# touched, by running this file's own classifier over the draft, which is the
# step R2340's carry added to the procedure. That step has now paid for itself
# on its first use; the repair was again in the sentence, not in a pin.
# R2342 — 415 -> 416, ONE citation, from `router-multicast-faces`'s appended
# CORRECTION. Its third clause is a claim about this tree alone (the multicast
# egress core is gated on the transport feature rather than on the atom's own,
# so turning the atom off leaves the plane in place), and the correction names
# the file that carries it. Everything else that correction adds is upstream.
#
# Worth recording for whoever reads that atom next: the four line numbers the
# clause cites have ALL drifted, and this file's own wz-citation check cannot
# see it. The check asks whether a cited line is past the end of its file; the
# file is 13060 lines and the four are at :527, :542, :2736 and :2757, so every
# one of them resolves, is in range, and points at something else. That is the
# same rot R2339-R2341 measured in UPSTREAM citations, here in wz ones -- which
# is worth saying explicitly, because "415 wz citation(s) resolve and none
# points past its file's end" is a true sentence that sounds like more than it
# is.
# R2343 — 416 -> 418, two citations, from `router-multicast-faces`'s appended
# CORRECTION, which WITHDRAWS its mis-scoped-gate residual. The withdrawal rests
# on where the egress plane is exercised, so the correction names the forwarder
# that carries the calls and the integration file that gates itself without the
# atom. Both are wz files the sentence is about; nothing upstream moved.
#
# This is the first round in this run that withdraws a clause rather than
# confirming one, and the first whose correction adds no upstream anchor --
# the claim is about this tree alone, so `ANCHORED_FLOOR` does not move either.
# R2344 — 418 -> 419, ONE citation, from `router-multicast-faces`'s appended
# CORRECTION recording that its last two residuals are ORDERED rather than
# siblings. The wz half of that argument is the ACL enforcer's subject
# early-return, so the correction names the file that carries it; the two
# upstream halves are anchored and read as upstream.
# R2350 — 72 -> 70 and 419 -> 408, and only HALF of that is this round's work.
# The two components were measured separately, at e697fab0 and here, rather
# than inferred from one delta:
#
#   R2349 moved reached 72 -> 71 and citations 419 -> 416 by anchoring six
#   rotted zenoh citations and fencing a scope, and did not move the pins with
#   it. The ratchet caught it exactly as designed, on the next push. The pins
#   move here because this is the commit that publishes that one — the R2333
#   shape.
#
#   R2350 moves reached 71 -> 70 and citations 416 -> 408. Both are ONE atom
#   leaving the corpus: `storage-history` went PARTIAL -> COMPLETE because its
#   single named residual was CLOSED, not relabelled (a History::All delete is
#   now a versioned tombstone, so history survives it and an out-of-order older
#   put is stored without resurrecting the key). Its reason carried EIGHT
#   citations that resolve to a tracked wz file — storage_backend.rs:120,
#   storage_state.rs:310, storage_history.rs:91, storage_state.rs:436,
#   storage_service.rs:657, storage_history.rs:125, storage_history.rs:34 and
#   tests/wz_storage_history_serves_pico_zget.rs — and all eight left the
#   PARTIAL corpus with the atom, the same way R2220's two did. The total falls
#   with it, 83 -> 82.
# R2351 — 70 -> 69 and 408 -> 403, ONE atom leaving the corpus and nothing else.
# `storage-aligner` went PARTIAL -> COMPLETE because all three of its residual
# clauses resolved: the named AV5 residual was IMPLEMENTED (a registered
# wildcard update is now derived as a replication event, fed to BOTH the digest
# and the aligner, and answerable on retrieval), and the other two were REFUTED
# by measurement (the "stale" kernel doc had already been corrected; Layer C1z
# is hosted, ci.yml runs it).
#
# The delta was PRE-COMPUTED with this file's own classifier before the store
# was touched — `citation_audit` over the single atom returned (wz 5,
# ambiguous 0, upstream 1) and `reach_partition` placed it in `reached` — and
# then re-measured after, which is what the two numbers below record. Doing it
# in that order is the R2340 step: the same run that grades the corpus can
# grade a draft, so a pin move stops being a guess about a delta. It also
# separates the components the R2350 way: this round edited no other atom's
# reason, so the whole of both moves is this one atom, and PARTIAL falls 82 ->
# 81 with it.
# R2352 — 69 -> 68 and 403 -> 402, again ONE atom leaving the corpus and
# nothing else. `storage-mgr-wildcard-updates` went PARTIAL -> COMPLETE: its one
# named residual (dispatch-on-override-kind) was IMPLEMENTED — the backend op
# now dispatches on the INCOMING kind while the value and timestamp come from
# the override, so a concrete Put shadowed by a wildcard-delete materializes as
# upstream's empty-payload put rather than as a tombstone — and the
# JUSTIFICATION that clause carried was REFUTED at the pin: upstream logs that
# event as a plain Put and stores a put, so it is consistent in the very place
# the clause called it inconsistent.
#
# The two components are SEPARATED, not inferred from the total. The reason's
# citation TOKENS are byte-identical before and after (measured: the same four
# `path:line` tokens in both), so neither move comes from editing prose — the
# whole of both is the atom leaving the population, carrying its single wz
# citation (`storage_state.rs:515-551`; its other three tokens are upstream or
# root-less and were never in this count). PARTIAL falls 81 -> 80 with it.
# R2353 — 68 -> 67 and 402 -> 399, ONE atom leaving the corpus.
# `transport-link-unixsock` went PARTIAL -> COMPLETE: its last residual (no
# cross-process flock lock-file lifecycle, and no `del_listener`) was
# IMPLEMENTED — `bind_unixsock` now takes an exclusive non-blocking `flock` on
# `{path}.lock` BEFORE it unlinks a stale socket, and the new owning
# `UnixsockListener` unlinks the socket on close/drop — while the entry's
# "LOCAL-ONLY: lane C1aa absent from ci.yml" clause was REFUTED by measurement
# (ci.yml has carried that lane since R311y413).
#
# The components are SEPARATED, not inferred from the total, and the citation
# half was measured with THIS module's own regex against the pre-change reason
# rather than eyeballed: that reason held four citation tokens, of which
# `unicast.rs` is upstream (0 candidates) and `unixsock_pipeline.rs:94`,
# `session_open.rs:816-819` and a bare `session_open.rs` each resolve to one
# tracked file — exactly the 3 this move drops. The reason's own tokens are
# UNCHANGED by the rewrite (the historical prose is preserved verbatim), so
# neither move comes from editing prose. PARTIAL falls 80 -> 79 with it.
# R2354 — 67 -> 66 and 399 -> 393, ONE atom leaving the corpus.
# `storage-replication` went PARTIAL -> COMPLETE: its one REMAINING clause (the
# recompute-not-incremental-log divergence) was IMPLEMENTED — the digest is now
# read off a `ReplicationLog` whose `(interval, sub-interval)` buckets the write
# paths keep XOR-maintained, instead of being rebuilt from the stored set every
# publication cycle.
#
# The components are SEPARATED and were measured BEFORE the reason was
# rewritten, with this module's own `reach_partition` and `citation_audit` run
# against the pre-change entry rather than inferred from the total: the atom sat
# in `reached` (so that count loses exactly 1) and its reason held ELEVEN
# citation tokens, of which 6 resolve to one tracked wz file and 5 read as
# upstream — exactly the 399 -> 393 and the unpinned 533 -> 528 this move makes,
# with no token left unaccounted for. The round's appended prose adds no
# `path:line` token at all (upstream claims are written in the anchored ``path`
# @ `needle`` form), so neither move comes from editing prose. PARTIAL falls
# 79 -> 78 with it.
# R2357 — `declare-queryable` left the PARTIAL population (COMPLETE), so these
# three fall with it and NOT because any prose was edited: reached 66 -> 65 (it
# was one of the atoms an executing test reached), wz citations 393 -> 384 and
# ambiguous 83 -> 85 -> 83, all of them citations that entry carried. PARTIAL
# falls 78 -> 77 with it. Its residuals were each discharged and re-checked by
# command -- the Mapping-bit witness passes with its negative control, the
# ext_qos tests red under a mutation of the extension id, the distance clause
# was already rejected by measurement, and the QUERYABLES-interest consequence
# is owned by `declare-interest` and stays open there.
# R2359 — `liveliness-history` left the PARTIAL population (COMPLETE), so these
# three fall WITH the atom and not because any prose was edited. Measured with
# this module's OWN `reach_partition` and `citation_audit` against the entry as
# it stood BEFORE the reason was rewritten, the discipline R2354 records above:
# the atom sat in `reached` (so that count loses exactly 1) and its reason
# carried 7 citations resolving to one tracked wz file plus 2 ambiguous ones —
# exactly the 384 -> 377 and 83 -> 81 this move makes. The 11 upstream-read
# tokens it also carried leave the unpinned total (522 -> 511). Nothing the
# round APPENDED can move these: the census reads PARTIAL entries only, so a
# COMPLETE atom's reason is outside the population by construction. PARTIAL
# falls 77 -> 76 with it.
# Its last standing clause was closed as PARITY by re-measuring both references
# at the pin (zenoh and pico each replay REMOTE tokens only), and the round
# closed a gap no clause had named — a historical delivery reaching a
# future-only subscriber — damage-bound by two separable probes.
# R2361 — 377 -> 380, and NOTHING ELSE MOVES. `transport-link-serial` stays
# PARTIAL, so its reason stays in this population; the round re-measured its
# three "STILL PARTIAL" clauses and the correction it appended cites three
# TRACKED wz files it had not cited before (`serial_pipeline.rs`,
# `session_open.rs`, and the pico-serial interop test). Derived with this
# module's OWN `citation_audit` over that atom alone, before and after: wz
# 2 -> 5, ambiguous 0 -> 0, upstream 3 -> 6 -- so the +3 here is exactly this
# atom's and the ambiguous pin is untouched.
#
# The correction also names three files that are NOT tracked and so land in the
# unpinned upstream bucket rather than here: the zenoh serial link, and two
# zenoh-pico paths. The pico ones look tracked and are not -- `vendor/zenoh-pico`
# is a SUBMODULE, so `git ls-files` yields the gitlink and never the files under
# it. Worth writing down, because a pico citation reads as upstream to this gate
# while reading as in-tree to a person.
#
# ⚠ R2360 pushed this gate RED and this round paid it, by DELETION rather than by
# moving the ambiguous pin: that round's correction requoted the stale citation
# `<lib file>:400-414` in order to say it was stale, and a requote is another
# OCCURRENCE -- one whose bare filename end-matches many tracked crates, so it
# landed in the ambiguous bucket (81 -> 82). The requote is gone and the count is
# 81 again. The lesson is the standing one: to correct a citation, describe it;
# do not reproduce it in citable form.
# R2362 — `ext-pubsub-serde-codec` goes PARTIAL -> COMPLETE, so its reason
# leaves this population entirely and takes its citations with it. PARTIAL
# falls 76 -> 75; REACHED falls 64 -> 63, because that is the bucket the atom
# sat in. Its citation contribution was measured with THIS module's own
# `citation_audit` over that atom alone, BEFORE the reason was rewritten: wz 3,
# ambiguous 0, upstream 9 — so wz citations fall 380 -> 377 and the ambiguous
# pin does not move, which is exactly what the run then printed. UNREACHED and
# NO_SYMBOL are untouched.
#
# The round closed the atom's LAST residual clauses: the format's `VarInt` was
# routed through the PROTOCOL varint SSOT and diverged from upstream's LEB128
# above 2^63 (reachable, because `VarInt` is public `Serialize` surface), and
# six type/hook families upstream carries had no wz counterpart. The instrument
# is a derived-population gate over both serialization modules rather than a
# reading of the residual prose, for the reason this file exists at all.
# R2363 — `transport-link-unixpipe` goes PARTIAL -> COMPLETE, so its reason
# leaves this population and takes its citations with it, while the SAME round
# ADDS a residual to `transport-link-serial`, which stays PARTIAL. The two move
# in opposite directions and the net is what the pins record, so both halves are
# measured separately with this module's own `citation_audit` rather than read
# off the net: the retiring unixpipe reason carried wz 4 / ambiguous 0, and the
# serial reason goes wz 5 -> 8 (ambiguous 0 both ways). 377 - 4 + 3 = 376, which
# is what the run then printed. PARTIAL falls 75 -> 74 and REACHED 63 -> 62,
# because REACHED is the bucket unixpipe sat in; UNREACHED, NO_SYMBOL and the
# ambiguous pin are untouched.
#
# The round built the atom's one live residual -- zenoh's `file_mask` locator
# config key, which wz wrote as a literal 0o600 and read nowhere -- and its
# other two clauses were re-measured and found already dead. The instrument is
# `upstream_link_config_keys_gate.py`, which derives the population this
# residual belonged to (every key an upstream link crate declares in its own
# `pub mod config`) rather than grading the one key that was noticed; that
# derivation is what found the serial residual this round had to add.
# R2364 — `runtime-coop` goes PARTIAL -> COMPLETE, so its reason leaves this
# population and takes its citations with it. Only ONE atom moves this round
# (none gained a residual), so the net IS the single half; it was still
# measured with this module's own `citation_audit` over that atom alone,
# against the PRE-rewrite reason read out of `HEAD`, rather than subtracted
# off the totals: wz 3, ambiguous 0, upstream 0. 376 - 3 = 373, which is what
# the run then printed. PARTIAL falls 74 -> 73. The bucket that empties is
# NO_SYMBOL, 10 -> 9 -- `runtime-coop` had no symbol this derivation could
# own, which is itself the honest record of what the atom was: an executor
# whose residual was a MISSING call site, and a call site that does not exist
# has nothing for a symbol derivation to name. REACHED, UNREACHED and the
# ambiguous pin are untouched.
#
# The round closed the atom's sole residual -- "the zenoh session can never
# ride this executor" -- by adding a !Send task pool (`CoopLocalSet`) beside
# the `Runtime` contract rather than by weakening it, and the spawn call site
# the residual counted as zero now exists. The instrument is a test that
# witnesses the session holding a live slot in the pool and advancing one
# iteration per executor pass, with three compiled control probes, because
# "it is spawned" is a claim about SCHEDULING that a passing smoke over the
# old synchronous driver would have reported green either way.
# R2365 — NO reason prose moves this round, so the citation pins hold at 373 /
# 81. What moves is the DERIVATION under all three reach buckets:
# `atom_test_graph` gained ARM 3, which credits a feature with the API of the
# in-tree crates only IT pulls. A feature whose whole implementation is an
# optional dependency writes no `#[cfg]`, so ARM 1 saw nothing and the atom
# landed in NO_SYMBOL for a property of the instrument rather than of the atom.
#
# ⚠ That is a correction to what R2364 wrote four paragraphs above. It read
# `runtime-coop`'s empty bucket as "the honest record of what the atom was --
# a residual that was a MISSING call site, and a call site that does not exist
# has nothing for a symbol derivation to name". The call site did exist by
# then; the derivation could not see the crate it lives in. The bucket was
# measuring the reader.
#
# SIX atoms leave NO_SYMBOL, 9 -> 3: `api-compat-c`, `api-compat-pico`,
# `rest-http-bridge` and `runtime-tokio` land in REACHED because a lane already
# names their crates' API, and `platform-freertos` / `platform-zephyr` land in
# UNREACHED because nothing does. A seventh atom,
# `storage-mgr-dynamic-volume-loading`, moves UNREACHED -> REACHED: it owned
# cfg symbols no test named, and its exclusive crate's API is named.
# So REACHED 62 -> 67 (+4 from no-symbol, +1 from unreached), UNREACHED 2 -> 3
# (-1 out, +2 in), NO_SYMBOL 9 -> 3. Each bucket is derived, not netted.
#
# The three that REMAIN in NO_SYMBOL are the honest residue and name their own
# reason: `declare-final` gates a seam whose cfg is an `any(..)` arm it does
# not own, and `platform-macos` / `platform-windows` forward to no crate at
# all. None of the three is a dep-forwarding feature, so ARM 3 does not reach
# them and must not appear to.
PIN_REACHED = 67
PIN_UNREACHED = 3
PIN_NO_SYMBOL = 3
PIN_WZ_CITATIONS = 373
PIN_AMBIGUOUS = 81


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.split("\0") if p]


def partial_atoms() -> dict[str, str]:
    """`{atom id: reason}` for every atom the inventory grades PARTIAL.

    Read from the TRACKED store rather than through `mnemosyne-cli`: the file
    is the SSOT either way and reading it keeps this gate runnable wherever
    Layer C0 runs, with no binary to install first.
    """
    try:
        data = json.loads((ROOT / STORE).read_text())
    except (OSError, ValueError) as exc:
        raise Fatal(f"the inventory store {STORE} could not be read ({exc})") from exc
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict):
        raise Fatal(f"{STORE} holds no `inventory_entries` mapping.")
    out: dict[str, str] = {}
    for eid, entry in entries.items():
        if eid.startswith(PRESET_PREFIX) or eid.startswith(DEBT_PREFIX):
            continue
        reason = (entry or {}).get("reason") or ""
        head = HEAD_TAG.match(reason)
        if head and head.group(1).upper() == "PARTIAL":
            out[eid] = reason
    if not out:
        raise Fatal(
            "no atom is graded PARTIAL. Every axis below would report zero of "
            "zero, which reads exactly like a clean surface."
        )
    return out


def reach_partition(reasons: dict[str, str]) -> dict[str, list[str]]:
    """PARTIAL atoms split by whether an executing test reaches their code.

    The join is `atom_test_graph`'s and is not re-derived here: that module
    evaluates each `cfg` as a BOOLEAN so an `any(..)` OR-contributor does not
    count as owning shared plumbing, and resolves the gated symbol before
    looking for test references. `audit-catalog-status.sh` already trusts it
    for COMPLETE; this asks it the question nobody asked of PARTIAL.
    """
    graph = atom_test_graph.graph()
    out: dict[str, list[str]] = {"reached": [], "unreached": [], "no_symbol": []}
    for atom in sorted(reasons):
        owned, referenced = graph.get(atom, (set(), set()))
        if not owned:
            out["no_symbol"].append(atom)
        elif referenced:
            out["reached"].append(atom)
        else:
            out["unreached"].append(atom)
    return out


def citation_audit(
    reasons: dict[str, str], paths: list[str]
) -> tuple[int, int, int, list[str]]:
    """(wz citations, ambiguous, upstream, findings).

    A citation resolves when exactly one tracked path ENDS WITH the cited path.
    Several candidates is ambiguity and is counted, never guessed at; none is
    read as upstream and left unjudged, which is the honest verdict R2215
    measured rather than a shrug.
    """
    unique = ambiguous = upstream = 0
    findings: list[str] = []
    for atom in sorted(reasons):
        for match in CITATION.finditer(reasons[atom]):
            cited, line = match.group(1), match.group(2)
            if cited in paths:
                candidates = [cited]
            else:
                candidates = [p for p in paths if p.endswith("/" + cited)]
            if not candidates:
                upstream += 1
                continue
            if len(candidates) > 1:
                ambiguous += 1
                continue
            unique += 1
            if line is None:
                continue
            try:
                length = len((ROOT / candidates[0]).read_text(errors="replace").split("\n"))
            except OSError:
                findings.append(
                    f"{atom}: cites `{cited}:{line}` and that tracked file cannot be read"
                )
                continue
            if int(line) > length:
                findings.append(
                    f"{atom}: cites `{cited}:{line}` and {candidates[0]} has "
                    f"{length} line(s) -- the residual points past the end of "
                    f"its own evidence."
                )
    return unique, ambiguous, upstream, findings


def run() -> int:
    reasons = partial_atoms()
    paths = tracked()
    reach = reach_partition(reasons)
    unique, ambiguous, upstream, findings = citation_audit(reasons, paths)

    print(
        f"depth-axis-census: {len(reasons)} atom(s) graded PARTIAL -- "
        f"{len(reach['reached'])} reached by an executing test, "
        f"{len(reach['unreached'])} owned but unreached, "
        f"{len(reach['no_symbol'])} with no symbol the derivation can own"
    )
    print(
        f"  citations: {unique} resolve to one tracked wz file, "
        f"{ambiguous} ambiguous, {upstream} read as upstream and NOT judged "
        f"(R2215: this tree holds no oracle for them)"
    )

    for label, actual, pin in (
        ("reached", len(reach["reached"]), PIN_REACHED),
        ("unreached", len(reach["unreached"]), PIN_UNREACHED),
        ("no-symbol", len(reach["no_symbol"]), PIN_NO_SYMBOL),
        ("wz citations", unique, PIN_WZ_CITATIONS),
        ("ambiguous citations", ambiguous, PIN_AMBIGUOUS),
    ):
        if actual != pin:
            direction = "rose" if actual > pin else "fell"
            findings.append(
                f"{label}: {actual} against a pin of {pin} -- the count {direction}. "
                f"A pin moves in the commit that moves the measurement, and the "
                f"commit says which atom and why."
            )
    if findings:
        print("depth-axis-census: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(
        f"  {unique} wz citation(s) resolve and none points past its file's end"
    )
    return 0


def selftest() -> int:
    def fail(message: str) -> int:
        print(f"depth-axis-census: SELFTEST FAIL -- {message}", file=sys.stderr)
        return 1

    # The head tag is a SLOT. A reason that DISCUSSES another grade must not be
    # read as carrying it -- the defect `inventory_kinds` records for itself.
    if HEAD_TAG.match("COMPLETE: mentions PARTIAL later").group(1) != "COMPLETE":
        return fail("the head tag was read from the wrong token")
    if HEAD_TAG.match("PARTIAL: F=x").group(1) != "PARTIAL":
        return fail("a plain PARTIAL head did not read as one")

    # ⚠ THE MATCHER CONTROL, and it is the trap this round fell into first.
    # A cited upstream path must NOT resolve onto a wz file that merely shares
    # its basename.
    paths = ["crates/wz-statechart-bridge/src/lib.rs", "crates/wz-capture/src/agg.rs"]
    reasons = {"probe": "RESIDUAL vs zenoh: zenoh-config/src/lib.rs:362 differs"}
    unique, ambiguous, upstream, findings = citation_audit(reasons, paths)
    if (unique, upstream) != (0, 1) or findings:
        return fail(
            f"an upstream path resolved onto a wz file: unique={unique} "
            f"upstream={upstream} findings={findings}"
        )

    # A real wz citation resolves, and one past the end is a finding.
    real = "crates/wz-capture/src/agg.rs"
    length = len((ROOT / real).read_text(errors="replace").split("\n"))
    good = {"probe": f"RESIDUAL: see {real}:1 for the seam"}
    unique, _amb, _up, findings = citation_audit(good, [real])
    if unique != 1 or findings:
        return fail(f"a real wz citation did not resolve cleanly: {findings}")
    bad = {"probe": f"RESIDUAL: see {real}:{length + 500} for the seam"}
    _u, _a, _p, findings = citation_audit(bad, [real])
    if not findings:
        return fail("a citation past the end of its file produced no finding")

    # An AMBIGUOUS citation is counted, never guessed at: two tracked files
    # ending in the cited path is exactly the state the basename matcher
    # resolved by picking one.
    twin = ["crates/a/src/lib.rs", "crates/b/src/lib.rs"]
    _u, amb, _p, findings = citation_audit({"probe": "RESIDUAL: src/lib.rs:1"}, twin)
    if amb != 1 or findings:
        return fail(f"an ambiguous citation was resolved instead of counted: {amb}")

    print("depth-axis-census: selftest OK (8 derivations driven)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="what the PARTIAL grades say, as numbers rather than a sentence"
    )
    parser.add_argument("--selftest", action="store_true", help="drive each derivation")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        return run()
    except Fatal as exc:
        print(f"depth-axis-census: FAIL -- {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
